package main

// The watchdog, tunnel by tunnel (Hashem Pro).
//
// The watchdog ran only in hashem.sh, once a minute, and looked at one tunnel:
// the first one (gre-tunnel, or the first record of peers.json) and the frps
// unit. On a hub with several foreign servers an outage of any other tunnel
// raised no alert and restarted nothing; one state for the whole server meant
// a message could not say which tunnel was down, and one tunnel coming back
// hid another that was still down. A hub whose tunnels were all Backhaul was
// taken for a foreign server, so its restart touched nothing.
//
// Now the panel does it on an Iran server, from the snapshot every page
// shows, so the watchdog and the dashboard agree:
//
//   - every tunnel has its own state; a tunnel that is not healthy (no control
//     session, its service stopped or its GRE gone) for the failure threshold
//     is down, and the message names it and says why;
//   - with auto-restart on, only that tunnel's broken parts are restarted (its
//     GRE unit when GRE does not answer, its relay unit when it is stopped or
//     holds no session), then again after 3, 6, 12 and up to 30 minutes while
//     it stays down; a tunnel a carrier swap or Autopilot is working on is left
//     alone;
//   - the recovery message says how long it was down;
//   - every tunnel there is when the watchdog starts is watched at once, also
//     one that is already down; a tunnel added later is watched once it has
//     been up, so one being set up raises nothing.
//
// The panel writes watchdog_panel.json while it does this; hashem.sh's timer
// then leaves the tunnel check to it and still runs the backups, the restart
// schedule and Auto-Pool. On a foreign server, or when the panel is not
// running, hashem.sh checks as before.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type wdLink struct {
	Key         string    `json:"key"`
	ID          int       `json:"id"`
	Name        string    `json:"name"`
	Remote      string    `json:"remote,omitempty"`
	State       string    `json:"state"` // up | down | waiting (not up yet)
	Why         string    `json:"why,omitempty"`
	LastUp      int64     `json:"last_up,omitempty"`
	DownSince   int64     `json:"down_since,omitempty"`
	Alerted     bool      `json:"alerted,omitempty"`
	Restarts    int       `json:"restarts,omitempty"`
	LastRestart int64     `json:"last_restart,omitempty"`
	LastAction  string    `json:"last_action,omitempty"`
	outSince    time.Time // when it stopped being healthy (memory only)
}

type wdPanelFile struct {
	At    int64    `json:"at"` // unix seconds of the last tick
	Links []wdLink `json:"links"`
}

var wd = struct {
	sync.Mutex
	links     map[string]*wdLink
	loaded    bool
	lastWrite time.Time
}{links: map[string]*wdLink{}}

// Seams for tests.
var (
	wdNow     = time.Now
	wdSendFn  = wdSendReal
	wdRestart = func(unit string) error {
		out, err := runCmdTimeout(45*time.Second, "systemctl", "restart", unit)
		if err != nil {
			return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	wdAsync = func(f func()) { go f() }
)

const (
	wdBackoffFirst = 3 * time.Minute
	wdBackoffMax   = 30 * time.Minute
	wdWriteEvery   = 30 * time.Second // watchdog_panel.json, the heartbeat hashem.sh reads
	wdUpSaveEvery  = 10 * time.Minute
)

func wdPanelPath() string { return filepath.Join(configDir, "watchdog_panel.json") }

// wdNeed is how long a tunnel has to be out before it counts as down: the
// failure threshold, in checks of interval_sec (2 x 60 s by default).
func wdNeed(c watchdogConfig) time.Duration {
	d := time.Duration(c.FailThreshold*c.IntervalSec) * time.Second
	if d < time.Minute {
		d = time.Minute
	}
	return d
}

// wdBackoff is the pause after the n-th restart of a tunnel.
func wdBackoff(n int) time.Duration {
	d := wdBackoffFirst
	for i := 1; i < n && d < wdBackoffMax; i++ {
		d *= 2
	}
	if d > wdBackoffMax {
		d = wdBackoffMax
	}
	return d
}

// wdKey names what a tunnel is, so its state follows it. The first tunnel is
// keyed on its relay unit: its foreign address and ports are read from its
// live GRE interface and its frps, and both are gone exactly when it is down.
// A peer is keyed on its record.
func wdKey(l peerLive, s *HubSnapshot) string {
	if l.ID == mainTunnelID {
		svc := l.FrpsSvc
		if svc == "" && s != nil {
			svc = s.Local.FrpSvc
		}
		return "main|" + svc
	}
	return fmt.Sprintf("%d|%s|%d", l.ID, l.RemotePub, l.FrpPort)
}

func wdName(l peerLive) string {
	n := strings.TrimSpace(l.Name)
	if n == "" {
		n = fmt.Sprintf("peer-%d", l.ID)
	}
	if l.RemotePub != "" && !strings.Contains(n, l.RemotePub) {
		n += " (" + l.RemotePub + ")"
	}
	return n
}

// wdBusy: a carrier swap or an Autopilot run is moving this tunnel.
func wdBusy(id int) bool {
	swapJobsMu.Lock()
	j := swapJobs[id]
	running := j != nil && j.State == "running"
	swapJobsMu.Unlock()
	if running {
		return true
	}
	ap.mu.Lock()
	defer ap.mu.Unlock()
	return ap.running && ap.runID == id
}

// wdActive: the panel watches the tunnels on this server.
func wdActive(s *HubSnapshot, c watchdogConfig) bool {
	if !c.Enabled || !hasPro(proWatchdog) || s == nil {
		return false
	}
	return strings.Contains(strings.ToLower(s.Local.Role), "iran") || len(s.Peers) > 0
}

// watchdogOnSnapshot is called after every snapshot build.
func watchdogOnSnapshot(s *HubSnapshot) {
	c := loadWatchdogConfig()
	now := wdNow()
	wd.Lock()
	if !wdActive(s, c) {
		if len(wd.links) > 0 || wd.loaded {
			wd.links, wd.loaded = map[string]*wdLink{}, false
			_ = os.Remove(wdPanelPath())
		}
		wd.Unlock()
		return
	}
	// First run (this version just started, or the watchdog was just turned
	// on): every tunnel there is now is watched at once, also one that is
	// already down. Tunnels added later are watched once they have been up.
	seed := false
	if !wd.loaded {
		seed = !wdLoadLocked()
	}
	need := wdNeed(c)
	seen := map[string]bool{}
	var msgs []string
	var restarts []func()
	dirty := false
	for _, l := range apLinks(s) {
		k := wdKey(l, s)
		seen[k] = true
		st := wd.links[k]
		if st == nil {
			st = &wdLink{Key: k, ID: l.ID}
			if seed {
				st.LastUp = now.Unix()
			}
			wd.links[k] = st
			dirty = true
		}
		// a first tunnel that is down has lost its address: keep the last one
		if l.RemotePub != "" || st.Name == "" {
			st.Name, st.Remote = wdName(l), l.RemotePub
		}
		switch {
		case l.HealthState == "":
			continue // not measured yet
		case l.HealthState == stateHealthy:
			if st.Alerted {
				mins := int(now.Sub(time.Unix(st.DownSince, 0)).Minutes() + 0.5)
				if mins < 1 {
					mins = 1
				}
				msgs = append(msgs, fmt.Sprintf("🟢 Tunnel RECOVERED: %s (was down %dm)", st.Name, mins))
			}
			if st.State != "up" || now.Sub(time.Unix(st.LastUp, 0)) > wdUpSaveEvery {
				dirty = true
			}
			st.State, st.Why, st.LastUp = "up", "", now.Unix()
			st.DownSince, st.Alerted, st.Restarts, st.LastRestart, st.outSince = 0, false, 0, 0, time.Time{}
			continue
		}
		// not healthy
		if st.LastUp == 0 {
			st.State, st.Why = "waiting", "not connected yet since it was added"
			continue
		}
		if st.outSince.IsZero() {
			st.outSince = now
		}
		st.Why = reasonsText(l.Reasons)
		if now.Sub(st.outSince) < need {
			continue
		}
		if st.State != "down" {
			st.State, st.DownSince = "down", st.outSince.Unix()
			dirty = true
		}
		if !st.Alerted {
			st.Alerted = true
			what := "alert only, auto-restart is off"
			if c.AutoRestart {
				what = "restarting it"
			}
			why := ""
			if st.Why != "" {
				why = ": " + st.Why
			}
			msgs = append(msgs, fmt.Sprintf("🔴 Tunnel DOWN: %s%s (%s)", st.Name, why, what))
		}
		if !c.AutoRestart || wdBusy(l.ID) {
			continue
		}
		if st.LastRestart > 0 && now.Sub(time.Unix(st.LastRestart, 0)) < wdBackoff(st.Restarts) {
			continue
		}
		units := wdUnitsToRestart(l, s)
		if len(units) == 0 {
			continue
		}
		st.Restarts++
		st.LastRestart = now.Unix()
		st.LastAction = "restarted " + strings.Join(units, ", ")
		dirty = true
		name := st.Name
		restarts = append(restarts, func() { wdRestartUnits(name, units) })
	}
	for k := range wd.links {
		if !seen[k] {
			delete(wd.links, k)
			dirty = true
		}
	}
	if dirty || now.Sub(wd.lastWrite) >= wdWriteEvery {
		wdSaveLocked(now)
	}
	wd.Unlock()
	if len(msgs) > 0 {
		text := strings.Join(msgs, "\n")
		wdAsync(func() { _ = wdSendFn(text) })
	}
	for _, f := range restarts {
		wdAsync(f)
	}
}

// wdUnitsToRestart are the broken parts of tunnel l: its GRE unit when GRE is
// missing or does not answer, and its relay unit when it is stopped or holds
// no session. A per-tunnel relay serves only this foreign server, so
// restarting it never cuts the others.
func wdUnitsToRestart(l peerLive, s *HubSnapshot) []string {
	var units []string
	if !l.NoGre {
		gif := l.GreIf
		if gif == "" && l.ID == mainTunnelID {
			gif = "gre-tunnel"
		}
		if gif != "" && gif != "none" && (!l.GreUp || !l.PingOK) {
			units = append(units, gif+".service")
		}
	}
	svc := l.FrpsSvc
	if svc == "" && l.ID == mainTunnelID && s != nil {
		svc = s.Local.FrpSvc
	}
	if svc != "" && (!l.FrpUp || !l.Linked) {
		units = append(units, svc)
	}
	return units
}

func wdRestartUnits(name string, units []string) {
	var failed []string
	for _, u := range units {
		if err := wdRestart(u); err != nil {
			failed = append(failed, u+": "+err.Error())
		}
	}
	if len(failed) > 0 {
		recordError("E-ACTION-03", "watchdog", "restart of "+name+" failed: "+strings.Join(failed, "; "))
		return
	}
	LogSecurityAudit("watchdog_restart", "watchdog", "127.0.0.1", name+": "+strings.Join(units, ", "))
}

// wdSendReal sends text through the panel's Telegram bot (tgroute.go).
func wdSendReal(text string) error {
	if !tgAlertReady() {
		return nil // alerts are not set up: the restarts still run
	}
	host, _ := os.Hostname()
	if host == "" {
		host = "server"
	}
	err := sendTelegram(loadWatchdogConfig(), "[Hashem "+host+"] "+text)
	if err != nil {
		recordError("E-WD-02", "watchdog", "telegram failed: "+err.Error())
	}
	return err
}

// wdLoadLocked reads what the panel knew before it restarted. It reports
// whether there was such a file.
func wdLoadLocked() bool {
	wd.loaded = true
	data, err := os.ReadFile(wdPanelPath())
	if err != nil {
		return false
	}
	var f wdPanelFile
	if json.Unmarshal(data, &f) != nil {
		return false
	}
	for i := range f.Links {
		l := f.Links[i]
		if l.DownSince > 0 {
			l.outSince = time.Unix(l.DownSince, 0)
		}
		wd.links[l.Key] = &l
	}
	return true
}

func wdSaveLocked(now time.Time) {
	f := wdPanelFile{At: now.Unix(), Links: wdLinksLocked()}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return
	}
	_ = os.MkdirAll(configDir, 0700)
	if atomicWriteFile(wdPanelPath(), append(data, '\n'), 0600) == nil {
		wd.lastWrite = now
	}
}

func wdLinksLocked() []wdLink {
	out := make([]wdLink, 0, len(wd.links))
	for _, l := range wd.links {
		out = append(out, *l)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// watchdogPanelResult is the panel's own check for the Watchdog tab, in the
// form hashem.sh prints ("WATCHDOG status=... detail=..."), and whether the
// panel watches the tunnels now.
func watchdogPanelResult() (string, []wdLink, bool) {
	wd.Lock()
	defer wd.Unlock()
	if !wd.loaded || wdNow().Sub(wd.lastWrite) > 3*wdWriteEvery {
		return "", nil, false
	}
	links := wdLinksLocked()
	var down []string
	up := 0
	for _, l := range links {
		switch l.State {
		case "down":
			d := l.Name
			if l.Why != "" {
				d += ": " + l.Why
			}
			down = append(down, d)
		case "up":
			up++
		}
	}
	if len(down) > 0 {
		return fmt.Sprintf("WATCHDOG status=down fails=%d detail=%s", len(down), strings.Join(down, "; ")), links, true
	}
	return fmt.Sprintf("WATCHDOG status=up fails=0 detail=%d of %d tunnels up, each one watched by the panel", up, len(links)), links, true
}

// watchdogSendsTunnels: the panel's watchdog watches the tunnels and has
// someone to tell, so alerts.go leaves tunnel events out of its Telegram copy.
func watchdogSendsTunnels() bool {
	if !tgAlertReady() {
		return false
	}
	_, _, active := watchdogPanelResult()
	return active
}
