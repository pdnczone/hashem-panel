package main

// Hashem Pro nudge (Buy License): a calm, rate-limited popup. The first one appears
// a few seconds into the first visit after install (fresh: never shown);
// later ones only after a tunnel has been healthy for a while. All pacing state lives on the
// server (support.json) so phones, desktops and several tabs stay in sync and
// the popup can never be spammed: a claim atomically pushes the next window
// out, so only one tab on one device wins it.

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	supportURL = "https://pdnczone.com"

	// How long to stay quiet after each outcome.
	supportAfterShown  = 7 * 24 * time.Hour  // shown (or dismissed with ×/Later)
	supportAfterSnooze = 30 * 24 * time.Hour // "don't remind me this month"
	supportAfterDonate = 90 * 24 * time.Hour // clicked Buy License (older panels sent "donate")

	// Seconds of continuously healthy tunnel before the popup may appear.
	supportDelaySeconds = 30
)

type supportState struct {
	NextShowAt  int64  `json:"next_show_at"` // unix seconds; 0 = never shown
	LastShownAt int64  `json:"last_shown_at"`
	LastAction  string `json:"last_action,omitempty"`
	Shown       int    `json:"shown"`
	Donated     int    `json:"donated"`
}

var supportMu sync.Mutex

func supportPath() string { return filepath.Join(configDir, "support.json") }

// loadSupportLocked reads the state; a missing/corrupt file means "fresh".
func loadSupportLocked() supportState {
	var st supportState
	if b, err := os.ReadFile(supportPath()); err == nil {
		_ = json.Unmarshal(b, &st)
	}
	return st
}

func saveSupportLocked(st supportState) {
	_ = os.MkdirAll(configDir, 0700)
	tmp := supportPath() + ".tmp"
	if err := os.WriteFile(tmp, mustJSON(st), 0600); err == nil {
		_ = os.Rename(tmp, supportPath())
	}
}

// supportClaim returns true when the popup is due and, in the same critical
// section, reserves the next window so concurrent callers get false.
func supportClaim(now time.Time) bool {
	supportMu.Lock()
	defer supportMu.Unlock()
	st := loadSupportLocked()
	if now.Unix() < st.NextShowAt {
		return false
	}
	st.NextShowAt = now.Add(supportAfterShown).Unix()
	st.LastShownAt = now.Unix()
	st.LastAction = "shown"
	st.Shown++
	saveSupportLocked(st)
	return true
}

// supportRecord stores the user's decision. Unknown actions are rejected.
func supportRecord(action string, now time.Time) bool {
	var d time.Duration
	switch action {
	case "close":
		d = supportAfterShown
	case "snooze":
		d = supportAfterSnooze
	case "buy", "donate":
		d = supportAfterDonate
	default:
		return false
	}
	supportMu.Lock()
	defer supportMu.Unlock()
	st := loadSupportLocked()
	st.NextShowAt = now.Add(d).Unix()
	st.LastAction = action
	if action == "buy" || action == "donate" {
		st.Donated++
	}
	saveSupportLocked(st)
	return true
}

// handleSupport: GET -> static info (url, delay); POST {action} where action is
// claim | close | snooze | buy (donate: older panels). claim answers {"show":bool}.
func handleSupport(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		supportMu.Lock()
		st := loadSupportLocked()
		supportMu.Unlock()
		writeJSON(w, map[string]any{
			"url": supportURL, "delay_s": supportDelaySeconds,
			"next_show_at": st.NextShowAt, "due": time.Now().Unix() >= st.NextShowAt,
			"fresh": st.Shown == 0,
		})
		return
	}
	var body struct {
		Action string `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeAPIError(w, r, "E-SUPPORT-01", "")
		return
	}
	now := time.Now()
	if body.Action == "claim" {
		writeJSON(w, map[string]any{"show": supportClaim(now), "url": supportURL})
		return
	}
	if !supportRecord(body.Action, now) {
		writeAPIError(w, r, "E-SUPPORT-02", "")
		return
	}
	writeJSON(w, map[string]any{"status": "ok"})
}
