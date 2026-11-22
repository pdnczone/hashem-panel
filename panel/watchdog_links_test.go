package main

import (
	"os"
	"strings"
	"testing"
	"time"
)

type wdHarness struct {
	clock    time.Time
	sent     []string
	restarts []string
}

func newWDHarness(t *testing.T, autoRestart bool) *wdHarness {
	t.Helper()
	restore := withTempConfigDir(t)
	h := &wdHarness{clock: time.Date(2026, 11, 22, 10, 0, 0, 0, time.Local)}
	oNow, oSend, oRestart, oAsync := wdNow, wdSendFn, wdRestart, wdAsync
	wdNow = func() time.Time { return h.clock }
	wdSendFn = func(text string) error { h.sent = append(h.sent, text); return nil }
	wdRestart = func(unit string) error { h.restarts = append(h.restarts, unit); return nil }
	wdAsync = func(f func()) { f() }
	wd.Lock()
	wd.links, wd.loaded, wd.lastWrite = map[string]*wdLink{}, false, time.Time{}
	wd.Unlock()
	c := loadWatchdogConfig()
	c.Enabled, c.AutoRestart, c.IntervalSec, c.FailThreshold = true, autoRestart, 60, 2
	if err := saveWatchdogConfig(c); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		wdNow, wdSendFn, wdRestart, wdAsync = oNow, oSend, oRestart, oAsync
		wd.Lock()
		wd.links, wd.loaded = map[string]*wdLink{}, false
		wd.Unlock()
		restore()
	})
	return h
}

func wdPeer(id int, name, remote, state string) peerLive {
	l := peerLive{peerRecord: peerRecord{ID: id, Name: name, RemotePub: remote, FrpPort: 7000 + id,
		GreIf: "gre-t" + string(rune('0'+id)), FrpsSvc: "frps-" + string(rune('0'+id))}, HealthState: state}
	if state == stateHealthy {
		l.FrpUp, l.GreUp, l.Linked, l.PingOK = true, true, true, true
	} else {
		l.FrpUp, l.GreUp = true, true // service runs, GRE is up, no session: a blocked path
	}
	return l
}

func (h *wdHarness) tick(peers ...peerLive) {
	watchdogOnSnapshot(&HubSnapshot{At: h.clock, Local: tunnelStatus{Role: "iran (server)"}, Peers: peers})
}

// The watchdog watched the first tunnel only: an outage of the third foreign
// server of a hub raised nothing. Each tunnel is now watched on its own, and
// the message names it.
func TestWatchdogWatchesEveryTunnel(t *testing.T) {
	apLicense(t, true)
	h := newWDHarness(t, true)
	h.tick(wdPeer(2, "de", "198.51.100.2", stateHealthy), wdPeer(3, "nl", "198.51.100.3", stateHealthy))
	h.clock = h.clock.Add(time.Minute)
	h.tick(wdPeer(2, "de", "198.51.100.2", stateHealthy), wdPeer(3, "nl", "198.51.100.3", stateDegraded))
	if len(h.sent) != 0 || len(h.restarts) != 0 {
		t.Fatalf("out for less than the threshold: sent %v restarted %v", h.sent, h.restarts)
	}
	h.clock = h.clock.Add(2 * time.Minute)
	h.tick(wdPeer(2, "de", "198.51.100.2", stateHealthy), wdPeer(3, "nl", "198.51.100.3", stateDegraded))
	if len(h.sent) != 1 || !strings.Contains(h.sent[0], "DOWN") || !strings.Contains(h.sent[0], "nl (198.51.100.3)") || strings.Contains(h.sent[0], "de") {
		t.Fatalf("one DOWN message naming the tunnel: %v", h.sent)
	}
	// only that tunnel's relay: GRE answers? no ping here, so its GRE too
	if strings.Join(h.restarts, " ") != "gre-t3.service frps-3" {
		t.Fatalf("restarted %v, want that tunnel's GRE and relay only", h.restarts)
	}
	// still down a minute later: no second message, no restart inside the pause
	h.clock = h.clock.Add(time.Minute)
	h.tick(wdPeer(2, "de", "198.51.100.2", stateHealthy), wdPeer(3, "nl", "198.51.100.3", stateDegraded))
	if len(h.sent) != 1 || len(h.restarts) != 2 {
		t.Fatalf("inside the pause: sent %v restarted %v", h.sent, h.restarts)
	}
	// after the pause: restarted again
	h.clock = h.clock.Add(3 * time.Minute)
	h.tick(wdPeer(2, "de", "198.51.100.2", stateHealthy), wdPeer(3, "nl", "198.51.100.3", stateDegraded))
	if len(h.restarts) != 4 {
		t.Fatalf("after the pause the tunnel is restarted again: %v", h.restarts)
	}
	// it comes back: one RECOVERED message with how long
	h.clock = h.clock.Add(time.Minute)
	h.tick(wdPeer(2, "de", "198.51.100.2", stateHealthy), wdPeer(3, "nl", "198.51.100.3", stateHealthy))
	if len(h.sent) != 2 || !strings.Contains(h.sent[1], "RECOVERED: nl") || !strings.Contains(h.sent[1], "was down") {
		t.Fatalf("recovery: %v", h.sent)
	}
	// the hashem.sh timer leaves the tunnels to the panel while it writes this
	if _, err := os.Stat(wdPanelPath()); err != nil {
		t.Fatalf("watchdog_panel.json: %v", err)
	}
	res, links, ok := watchdogPanelResult()
	if !ok || !strings.Contains(res, "status=up") || len(links) != 2 {
		t.Fatalf("panel result %q %v %v", res, links, ok)
	}
}

func TestWatchdogAlertOnlyAndNeverUpTunnels(t *testing.T) {
	apLicense(t, true)
	h := newWDHarness(t, false)
	h.tick(wdPeer(5, "fi", "198.51.100.5", stateHealthy)) // the first run
	// a tunnel added later that has never been up (being set up): nothing
	h.tick(wdPeer(5, "fi", "198.51.100.5", stateHealthy), wdPeer(4, "new", "198.51.100.4", stateDegraded))
	h.clock = h.clock.Add(10 * time.Minute)
	h.tick(wdPeer(5, "fi", "198.51.100.5", stateHealthy), wdPeer(4, "new", "198.51.100.4", stateDegraded))
	if len(h.sent) != 0 {
		t.Fatalf("a tunnel never up must raise nothing: %v", h.sent)
	}
	// auto-restart off: the message says so and nothing is restarted
	h.tick(wdPeer(5, "fi", "198.51.100.5", stateHealthy))
	h.clock = h.clock.Add(time.Minute)
	h.tick(wdPeer(5, "fi", "198.51.100.5", stateDown))
	h.clock = h.clock.Add(3 * time.Minute)
	h.tick(wdPeer(5, "fi", "198.51.100.5", stateDown))
	if len(h.sent) != 1 || !strings.Contains(h.sent[0], "alert only") || len(h.restarts) != 0 {
		t.Fatalf("alert only: sent %v restarted %v", h.sent, h.restarts)
	}
	res, _, ok := watchdogPanelResult()
	if !ok || !strings.Contains(res, "status=down") || !strings.Contains(res, "fi") {
		t.Fatalf("panel result %q", res)
	}
}

// Without the license or with the watchdog off the panel does nothing, and
// hashem.sh keeps checking (no heartbeat file).
func TestWatchdogOffOrUnlicensed(t *testing.T) {
	apLicense(t, false)
	h := newWDHarness(t, true)
	h.tick(wdPeer(2, "de", "198.51.100.2", stateHealthy))
	h.clock = h.clock.Add(5 * time.Minute)
	h.tick(wdPeer(2, "de", "198.51.100.2", stateDown))
	if len(h.sent) != 0 || len(h.restarts) != 0 {
		t.Fatalf("unlicensed: sent %v restarted %v", h.sent, h.restarts)
	}
	if _, err := os.Stat(wdPanelPath()); !os.IsNotExist(err) {
		t.Fatalf("no heartbeat without the license: %v", err)
	}
}

// The user's case: a tunnel that is already down when this version first
// starts (or when the watchdog is turned on) is watched at once.
func TestWatchdogFirstRunWatchesATunnelAlreadyDown(t *testing.T) {
	apLicense(t, true)
	h := newWDHarness(t, true)
	h.tick(wdPeer(3, "nl", "198.51.100.3", stateDegraded))
	h.clock = h.clock.Add(3 * time.Minute)
	h.tick(wdPeer(3, "nl", "198.51.100.3", stateDegraded))
	if len(h.sent) != 1 || !strings.Contains(h.sent[0], "DOWN: nl") || len(h.restarts) == 0 {
		t.Fatalf("already down at the first run: sent %v restarted %v", h.sent, h.restarts)
	}
}

// The first FRP tunnel's address comes from its live GRE interface: when it
// goes fully down the address is gone too. Its state must follow it anyway.
func TestWatchdogFirstTunnelKeepsItsStateWhenItLosesItsAddress(t *testing.T) {
	apLicense(t, true)
	h := newWDHarness(t, true)
	up := &peerLive{peerRecord: peerRecord{ID: mainTunnelID, Name: "Tunnel · 198.51.100.9", RemotePub: "198.51.100.9", FrpPort: 7000},
		FrpUp: true, GreUp: true, Linked: true, PingOK: true, HealthState: stateHealthy}
	down := &peerLive{peerRecord: peerRecord{ID: mainTunnelID, Name: "Tunnel"}, HealthState: stateDown}
	snap := func(m *peerLive) *HubSnapshot {
		return &HubSnapshot{At: h.clock, Local: tunnelStatus{Role: "iran (server)", FrpSvc: "frps"}, Main: m}
	}
	watchdogOnSnapshot(snap(up))
	h.clock = h.clock.Add(time.Minute)
	watchdogOnSnapshot(snap(down))
	h.clock = h.clock.Add(3 * time.Minute)
	watchdogOnSnapshot(snap(down))
	if len(h.sent) != 1 || !strings.Contains(h.sent[0], "198.51.100.9") {
		t.Fatalf("DOWN naming the first tunnel with its last address: %v", h.sent)
	}
	if strings.Join(h.restarts, " ") != "gre-tunnel.service frps" {
		t.Fatalf("restarted %v, want gre-tunnel.service and frps", h.restarts)
	}
}

func TestWatchdogUnitsToRestart(t *testing.T) {
	// GRE answers, relay runs, no session: only the relay
	l := peerLive{peerRecord: peerRecord{ID: 2, GreIf: "gre-t2", FrpsSvc: "frps-2"}, FrpUp: true, GreUp: true, PingOK: true}
	if u := wdUnitsToRestart(l, nil); strings.Join(u, " ") != "frps-2" {
		t.Fatalf("relay only: %v", u)
	}
	// Backhaul without GRE: never a GRE unit
	l = peerLive{peerRecord: peerRecord{ID: 3, GreIf: "none", FrpsSvc: "backhaul-server-3", NoGre: true}, GreUp: true}
	if u := wdUnitsToRestart(l, nil); strings.Join(u, " ") != "backhaul-server-3" {
		t.Fatalf("no GRE: %v", u)
	}
	// the first tunnel: its units come from the local status
	m := peerLive{peerRecord: peerRecord{ID: mainTunnelID}}
	s := &HubSnapshot{Local: tunnelStatus{FrpSvc: "frps"}}
	if u := wdUnitsToRestart(m, s); strings.Join(u, " ") != "gre-tunnel.service frps" {
		t.Fatalf("first tunnel: %v", u)
	}
	if wdBackoff(1) != 3*time.Minute || wdBackoff(2) != 6*time.Minute || wdBackoff(10) != 30*time.Minute {
		t.Fatal("backoff")
	}
}
