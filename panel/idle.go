package main

import (
	"encoding/json"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Idle session timeout (off by default). The UI polls constantly, so idleness
// cannot be inferred from requests alone: the browser marks requests made
// while the user is actually active with X-User-Active: 1, and only those (and
// login) refresh the session's activity clock.

const (
	idleMinMinutes = 5
	idleMaxMinutes = 24 * 60
)

var (
	idleMu     sync.Mutex
	lastActive = map[string]time.Time{}
)

func idleTimeout() time.Duration {
	mu.Lock()
	m := cfg.IdleTimeoutMin
	mu.Unlock()
	if m <= 0 {
		return 0
	}
	return time.Duration(m) * time.Minute
}

// touchSession marks activity for a session token.
func touchSession(tok string) {
	idleMu.Lock()
	lastActive[tok] = timeNow()
	idleMu.Unlock()
}

// sessionIdleExpired reports whether tok has been inactive longer than the
// configured timeout and, if so, forgets it. A token never seen since start
// (e.g. after a panel restart) gets a fresh clock instead of being kicked.
func sessionIdleExpired(tok string, active bool) bool {
	d := idleTimeout()
	if d == 0 {
		return false
	}
	now := timeNow()
	idleMu.Lock()
	defer idleMu.Unlock()
	last, seen := lastActive[tok]
	if !seen {
		lastActive[tok] = now
		return false
	}
	if now.Sub(last) > d {
		delete(lastActive, tok)
		return true
	}
	if active {
		lastActive[tok] = now
	}
	return false
}

func dropIdle(tok string) {
	idleMu.Lock()
	delete(lastActive, tok)
	idleMu.Unlock()
}

// GET/POST /api/session-settings {idle_minutes}
func handleSessionSettingsGet(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	m := cfg.IdleTimeoutMin
	mu.Unlock()
	writeJSON(w, map[string]any{"idle_minutes": m, "min": idleMinMinutes, "max": idleMaxMinutes})
}

func handleSessionSettingsPost(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IdleMinutes int `json:"idle_minutes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeAPIError(w, r, "E-AUTH-03", "")
		return
	}
	m := body.IdleMinutes
	if m != 0 && (m < idleMinMinutes || m > idleMaxMinutes) {
		writeAPIError(w, r, "E-AUTH-12", "")
		return
	}
	mu.Lock()
	cfg.IdleTimeoutMin = m
	saveCfg()
	mu.Unlock()
	LogSecurityAudit("idle_timeout_changed", cfg.Username, clientIP(r), "minutes="+strconv.Itoa(m))
	writeJSON(w, map[string]any{"status": "ok", "idle_minutes": m})
}
