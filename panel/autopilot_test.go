package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func apIDs(cs []carrierChoice) string {
	var out []string
	for _, c := range cs {
		out = append(out, c.ID())
	}
	return strings.Join(out, " ")
}

func apLicense(t *testing.T, on bool) {
	t.Helper()
	activeLicenseMu.Lock()
	old := activeLicense
	activeLicense = nil
	if on {
		activeLicense = &LicensePayload{Customer: "test", MachineHash: getMachineHash(), ExpiresAt: time.Now().Add(time.Hour).Unix()}
	}
	activeLicenseMu.Unlock()
	t.Cleanup(func() { activeLicenseMu.Lock(); activeLicense = old; activeLicenseMu.Unlock() })
}

func TestAutopilotGate(t *testing.T) {
	now := time.Date(2026, 11, 12, 14, 0, 0, 0, time.Local)
	c := defaultAutopilotConfig()
	up := peerLive{peerRecord: peerRecord{ID: 2, Engine: "frp"}, FrpUp: true}
	seen := func() *apTunnelState { return &apTunnelState{LastUp: now.Add(-time.Hour).Unix()} }
	long := now.Add(-10 * time.Minute)

	if why := apGate(c, now, up, seen(), long); why != "" {
		t.Fatalf("a tunnel down for 10 minutes that was up before must be acted on, got %q", why)
	}
	cases := []struct {
		name string
		c    autopilotConfig
		l    peerLive
		ts   *apTunnelState
		down time.Time
		want string
	}{
		{"not down long enough", c, up, seen(), now.Add(-2 * time.Minute), "down for 2 of 5"},
		{"never seen up", c, up, &apTunnelState{}, long, "not been up yet"},
		{"service stopped here", c, peerLive{peerRecord: up.peerRecord}, seen(), long, "not running"},
		{"xray tunnel", c, peerLive{peerRecord: peerRecord{ID: 2, Engine: "xray"}, FrpUp: true}, seen(), long, "no carrier to swap"},
		{"cooldown", c, up, &apTunnelState{LastUp: 1, LastRun: now.Add(-10 * time.Minute).Unix()}, long, "next run in"},
		{"daily limit", c, up, &apTunnelState{LastUp: 1, Runs: []int64{now.Unix() - 100, now.Unix() - 200, now.Unix() - 300, now.Unix() - 400, now.Unix() - 500, now.Unix() - 600}}, long, "the limit"},
	}
	skip := c
	skip.Skip = []int{2}
	cases = append(cases, struct {
		name string
		c    autopilotConfig
		l    peerLive
		ts   *apTunnelState
		down time.Time
		want string
	}{"skipped tunnel", skip, up, seen(), long, "left alone"})
	quiet := c
	quiet.QuietFrom, quiet.QuietTo = 22, 16 // over midnight, 14:00 is inside
	cases = append(cases, struct {
		name string
		c    autopilotConfig
		l    peerLive
		ts   *apTunnelState
		down time.Time
		want string
	}{"quiet hours", quiet, up, seen(), long, "quiet hours"})
	for _, tc := range cases {
		if why := apGate(tc.c, now, tc.l, tc.ts, tc.down); !strings.Contains(why, tc.want) {
			t.Errorf("%s: want %q in the reason, got %q", tc.name, tc.want, why)
		}
	}
	// runs older than a day do not count
	old := &apTunnelState{LastUp: 1, Runs: []int64{now.Unix() - 90000, now.Unix() - 90001, now.Unix() - 90002, now.Unix() - 90003, now.Unix() - 90004, now.Unix() - 90005}}
	if why := apGate(c, now, up, old, long); why != "" {
		t.Errorf("runs older than 24 hours must not count, got %q", why)
	}
}

func TestAutopilotQuietHours(t *testing.T) {
	at := func(h int) time.Time { return time.Date(2026, 1, 1, h, 30, 0, 0, time.Local) }
	c := autopilotConfig{QuietFrom: 9, QuietTo: 17}
	if !apQuiet(c, at(9)) || !apQuiet(c, at(16)) || apQuiet(c, at(17)) || apQuiet(c, at(8)) {
		t.Error("09-17 covers 09:30 and 16:30, not 08:30 or 17:30")
	}
	c = autopilotConfig{QuietFrom: 23, QuietTo: 6}
	if !apQuiet(c, at(23)) || !apQuiet(c, at(2)) || apQuiet(c, at(6)) || apQuiet(c, at(12)) {
		t.Error("23-06 covers 23:30 and 02:30, not 06:30 or 12:30")
	}
	if apQuiet(autopilotConfig{}, at(3)) {
		t.Error("equal hours mean no quiet hours")
	}
}

func TestAutopilotCandidates(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	all := func(string) bool { return true }
	c := defaultAutopilotConfig()
	frp := swapTunnel{ID: 2, Current: carrierChoice{"frp", "tcp"}, GreOK: true}

	got := apCandidates(frp, c, nil, now, all, true)
	if len(got) == 0 || got[0].ID() != "backhaul:tcpmux" {
		t.Fatalf("a GRE tunnel that is down leaves GRE first, got %s", apIDs(got))
	}
	if strings.Contains(" "+apIDs(got)+" ", " frp:tcp ") {
		t.Error("the current carrier is not a candidate")
	}
	if !strings.Contains(apIDs(got), "frp:kcp") || !strings.Contains(apIDs(got), "gre-backhaul:tcpmux") {
		t.Errorf("GRE carriers stay possible, after the others: %s", apIDs(got))
	}

	noGre := swapTunnel{ID: 3, Current: carrierChoice{"backhaul", "tcpmux"}}
	if got := apIDs(apCandidates(noGre, c, nil, now, all, true)); strings.Contains(got, "frp:") || strings.Contains(got, "gre-backhaul") {
		t.Errorf("a tunnel without GRE gets no GRE carrier: %s", got)
	}

	if got := apIDs(apCandidates(frp, c, nil, now, all, false)); strings.Contains(got, "backhaul") {
		t.Errorf("without the Backhaul license an FRP tunnel is not moved to Backhaul: %s", got)
	}
	if got := apIDs(apCandidates(frp, c, nil, now, func(b string) bool { return b == "frps" }, true)); strings.Contains(got, "backhaul") {
		t.Errorf("no Backhaul binary, no Backhaul carrier: %s", got)
	}

	only := c
	only.Carriers = []string{"backhaul:wssmux", "frp:kcp"}
	if got := apIDs(apCandidates(frp, only, nil, now, all, true)); got != "backhaul:wssmux frp:kcp" {
		t.Errorf("only the allowed carriers, got %q", got)
	}

	failed := map[string]int64{"backhaul:tcpmux": now.Add(-time.Hour).Unix(), "backhaul:wssmux": now.Add(-7 * time.Hour).Unix()}
	got = apCandidates(frp, c, failed, now, all, true)
	if got[0].ID() != "backhaul:wssmux" || got[len(got)-1].ID() != "backhaul:tcpmux" {
		t.Errorf("a carrier that failed an hour ago goes last, one that failed 7 hours ago is fresh again: %s", apIDs(got))
	}
}

func TestAutopilotRank(t *testing.T) {
	cands := []carrierChoice{{"backhaul", "tcpmux"}, {"backhaul", "wssmux"}, {"backhaul", "udp"}, {"frp", "kcp"}, {"gre-backhaul", "tcp"}}
	checks := []ptCheck{
		{ID: "bh-tcpmux", Status: "fail"},
		{ID: "bh-wssmux", Status: "ok", Mbps: 40, RTTMs: 90},
		{ID: "bh-udp", Status: "ok", Mbps: 85, RTTMs: 70},
		{ID: "gre", Status: "fail"},
		{ID: "frp-kcp", Status: "ok", Mbps: 200},
	}
	got, note := apRank(cands, checks, true)
	if apIDs(got) != "backhaul:udp backhaul:wssmux" {
		t.Errorf("blocked transports and GRE carriers behind a blocked GRE are dropped, fastest first: %s", apIDs(got))
	}
	if !strings.Contains(note, "2 of 5") {
		t.Errorf("note: %q", note)
	}
	// a wrapped GRE link: the plain GRE row says nothing, the carriers stay as unknown, last
	got, _ = apRank(cands, checks, false)
	if apIDs(got) != "backhaul:udp backhaul:wssmux frp:kcp gre-backhaul:tcp" {
		t.Errorf("wrapped GRE: %s", apIDs(got))
	}
	// GRE gets through: GRE carriers are proven too
	checks[3].Status = "ok"
	got, _ = apRank(cands, checks, true)
	if got[0].ID() != "frp:kcp" || len(got) != 4 {
		t.Errorf("with GRE open: %s", apIDs(got))
	}
	// nothing measured (the foreign server never joined): everything stays
	if got, _ := apRank(cands, nil, true); len(got) != len(cands) {
		t.Errorf("no rows: %s", apIDs(got))
	}
}

func TestAutopilotConfigClean(t *testing.T) {
	c, err := cleanAutopilotConfig(autopilotConfig{DownMinutes: 0, CooldownMin: 1, MaxPerDay: 500, QuietFrom: 30,
		Carriers: []string{"frp:ws", "FRP:websocket", "nope:x"}, Skip: []int{-1, 3}})
	if err == nil {
		t.Error("a value out of range is reported")
	}
	if c.DownMinutes != 5 || c.CooldownMin != 30 || c.MaxPerDay != 6 || c.QuietFrom != 0 {
		t.Errorf("out-of-range values fall back to the defaults: %+v", c)
	}
	if strings.Join(c.Carriers, ",") != "frp:websocket" || len(c.Skip) != 1 {
		t.Errorf("carriers are normalised and unknown ones dropped: %+v", c)
	}
	if _, err := cleanAutopilotConfig(defaultAutopilotConfig()); err != nil {
		t.Errorf("the defaults are valid: %v", err)
	}
}

// apHarness wires the seams: a tunnel on frp:tcp whose swaps are scripted.
type apHarness struct {
	swaps    []string
	notes    []apEvent
	swapRes  map[string]string // carrier -> state ("ok" when missing)
	pingErr  error
	testErr  error
	checks   []ptCheck
	linked   bool
	tests    int
	clock    time.Time
	resolved swapTunnel
}

func newAPHarness(t *testing.T) *apHarness {
	t.Helper()
	h := &apHarness{swapRes: map[string]string{}, clock: time.Date(2026, 11, 12, 14, 0, 0, 0, time.Local),
		resolved: swapTunnel{ID: 2, Name: "kish", Current: carrierChoice{"frp", "tcp"}, GreOK: true}}
	oR, oP, oS, oPing, oL, oN, oA, oNow := apResolve, apPathTestFn, apSwapFn, apPingFn, apLinkedFn, apNotifyFn, apAsync, apNow
	oBins := engineBinDirs
	bin := t.TempDir()
	for _, b := range []string{"frps", "backhaul"} {
		if err := os.WriteFile(bin+"/"+b, []byte("#!/bin/sh\n"), 0755); err != nil {
			t.Fatal(err)
		}
	}
	engineBinDirs = []string{bin}
	apNow = func() time.Time { return h.clock }
	apAsync = func(f func()) { f() }
	apResolve = func(int) (swapTunnel, error) { return h.resolved, nil }
	apPingFn = func(swapTunnel) error { return h.pingErr }
	apLinkedFn = func(swapTunnel) bool { return h.linked }
	apPathTestFn = func(swapTunnel) ([]ptCheck, error) { h.tests++; return h.checks, h.testErr }
	apSwapFn = func(_ swapTunnel, to carrierChoice) (string, string) {
		h.swaps = append(h.swaps, to.ID())
		if s := h.swapRes[to.ID()]; s != "" {
			return s, "did not connect"
		}
		h.resolved.Current = to
		return "ok", ""
	}
	apNotifyFn = func(e apEvent) { h.notes = append(h.notes, e) }
	ap.mu.Lock()
	ap.st, ap.downSince, ap.wait, ap.running = &apState{}, map[int]time.Time{}, map[int]string{}, false
	ap.mu.Unlock()
	_ = os.Remove(autopilotStatePath())
	c := defaultAutopilotConfig()
	c.Enabled = true
	if err := saveAutopilotConfig(c); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		apResolve, apPathTestFn, apSwapFn, apPingFn, apLinkedFn, apNotifyFn, apAsync, apNow = oR, oP, oS, oPing, oL, oN, oA, oNow
		engineBinDirs = oBins
		_ = os.Remove(autopilotConfigPath())
		_ = os.Remove(autopilotStatePath())
		ap.mu.Lock()
		ap.st, ap.downSince, ap.wait, ap.running = nil, map[int]time.Time{}, map[int]string{}, false
		ap.mu.Unlock()
	})
	return h
}

func (h *apHarness) tick(state string) {
	autopilotOnSnapshot(&HubSnapshot{At: h.clock, Local: tunnelStatus{Role: "iran"},
		Peers: []peerLive{{peerRecord: peerRecord{ID: 2, Name: "kish", Engine: "frp"}, FrpUp: true, HealthState: state}}})
}

func (h *apHarness) lastEvent(t *testing.T) apEvent {
	t.Helper()
	ap.mu.Lock()
	defer ap.mu.Unlock()
	if len(ap.st.Events) == 0 {
		t.Fatal("no Autopilot event was recorded")
	}
	return ap.st.Events[len(ap.st.Events)-1]
}

func TestAutopilotMovesADownTunnelToTheBestCarrier(t *testing.T) {
	apLicense(t, true)
	h := newAPHarness(t)
	h.checks = []ptCheck{{ID: "bh-tcpmux", Status: "fail"}, {ID: "bh-wssmux", Status: "ok", Mbps: 30}, {ID: "bh-udp", Status: "ok", Mbps: 60},
		{ID: "bh-wsmux", Status: "fail"}, {ID: "bh-ws", Status: "fail"}, {ID: "bh-wss", Status: "fail"}, {ID: "bh-tcp", Status: "fail"}, {ID: "gre", Status: "fail"}}

	h.tick(stateHealthy)
	h.clock = h.clock.Add(time.Minute)
	h.tick(stateDown)
	h.clock = h.clock.Add(3 * time.Minute)
	h.tick(stateDown)
	if len(h.swaps) != 0 {
		t.Fatalf("down for 3 minutes is not 5: nothing may be swapped yet, got %v", h.swaps)
	}
	h.clock = h.clock.Add(3 * time.Minute)
	h.tick(stateDown)
	if strings.Join(h.swaps, " ") != "backhaul:udp" {
		t.Fatalf("the fastest carrier that got through is taken, got %v", h.swaps)
	}
	e := h.lastEvent(t)
	if e.Kind != "switched" || e.From != "frp:tcp" || e.To != "backhaul:udp" || !strings.Contains(e.Text, "2 of 17") {
		t.Errorf("event: %+v", e)
	}
	if len(h.notes) != 1 {
		t.Errorf("one message is sent, got %d", len(h.notes))
	}
	// still down right after: the cooldown holds
	h.clock = h.clock.Add(5 * time.Minute)
	h.tick(stateDown)
	if len(h.swaps) != 1 {
		t.Errorf("no second run inside the cooldown, got %v", h.swaps)
	}
}

func TestAutopilotTriesTheNextCarrierAndRemembersFailures(t *testing.T) {
	apLicense(t, true)
	h := newAPHarness(t)
	h.testErr = errors.New("the foreign panel is older than Autopilot: update it")
	h.swapRes["backhaul:tcpmux"] = "reverted"
	h.tick(stateHealthy)
	h.tick(stateDown)
	h.clock = h.clock.Add(6 * time.Minute)
	h.tick(stateDown)
	if strings.Join(h.swaps, " ") != "backhaul:tcpmux backhaul:wssmux" {
		t.Fatalf("without a path test the carriers are tried in order, got %v", h.swaps)
	}
	if e := h.lastEvent(t); e.Kind != "switched" || !strings.Contains(e.Text, "path test skipped") {
		t.Errorf("event: %+v", e)
	}
	ap.mu.Lock()
	failed := ap.st.Tunnels[2].Failed["backhaul:tcpmux"]
	runs := len(ap.st.Tunnels[2].Runs)
	ap.mu.Unlock()
	if failed == 0 || runs != 1 {
		t.Errorf("the failed carrier is remembered and the run counted: failed=%d runs=%d", failed, runs)
	}
}

func TestAutopilotGivesUpAfterThreeCarriers(t *testing.T) {
	apLicense(t, true)
	h := newAPHarness(t)
	c := loadAutopilotConfig()
	c.PathTest = false
	_ = saveAutopilotConfig(c)
	for _, id := range []string{"backhaul:tcpmux", "backhaul:wssmux", "backhaul:wsmux", "backhaul:wss"} {
		h.swapRes[id] = "reverted"
	}
	h.tick(stateHealthy)
	h.tick(stateDown)
	h.clock = h.clock.Add(6 * time.Minute)
	h.tick(stateDown)
	if len(h.swaps) != apMaxTries || h.tests != 0 {
		t.Fatalf("at most %d carriers per run and no path test when it is off: swaps=%v tests=%d", apMaxTries, h.swaps, h.tests)
	}
	if e := h.lastEvent(t); e.Kind != "failed" || len(h.notes) != 1 {
		t.Errorf("a failed run is recorded and reported: %+v notes=%d", e, len(h.notes))
	}
}

func TestAutopilotLeavesTheTunnelAlone(t *testing.T) {
	// the foreign panel cannot be reached: nothing is changed, the run is not counted, no message
	apLicense(t, true)
	h := newAPHarness(t)
	h.pingErr = errors.New("dial tcp: i/o timeout")
	h.tick(stateHealthy)
	h.tick(stateDown)
	h.clock = h.clock.Add(6 * time.Minute)
	h.tick(stateDown)
	if len(h.swaps) != 0 || h.tests != 0 || len(h.notes) != 0 {
		t.Fatalf("an unreachable foreign panel: swaps=%v tests=%d notes=%d", h.swaps, h.tests, len(h.notes))
	}
	if e := h.lastEvent(t); e.Kind != "skipped" {
		t.Errorf("event: %+v", e)
	}
	ap.mu.Lock()
	runs := len(ap.st.Tunnels[2].Runs)
	ap.mu.Unlock()
	if runs != 0 {
		t.Errorf("a skipped run does not use the daily limit, got %d", runs)
	}
	// the path test finds nothing: no swap
	h.pingErr = nil
	h.checks = []ptCheck{{ID: "gre", Status: "fail"}}
	for _, tr := range backhaulTransports {
		h.checks = append(h.checks, ptCheck{ID: "bh-" + tr, Status: "fail"})
	}
	h.clock = h.clock.Add(40 * time.Minute)
	h.tick(stateDown)
	if len(h.swaps) != 0 {
		t.Errorf("no carrier got through the path test: nothing to swap to, got %v", h.swaps)
	}
	if e := h.lastEvent(t); e.Kind != "failed" {
		t.Errorf("event: %+v", e)
	}
	// the tunnel came back while the path was tested
	h.checks = []ptCheck{{ID: "bh-tcpmux", Status: "ok"}}
	h.linked = true
	h.clock = h.clock.Add(40 * time.Minute)
	h.tick(stateDown)
	if len(h.swaps) != 0 {
		t.Errorf("a tunnel that came back by itself is not swapped, got %v", h.swaps)
	}
	if e := h.lastEvent(t); e.Kind != "recovered" {
		t.Errorf("event: %+v", e)
	}
}

func TestAutopilotNeedsTheLicenseTheIranSideAndATunnelSeenUp(t *testing.T) {
	apLicense(t, false)
	h := newAPHarness(t)
	run := func() {
		h.tick(stateHealthy)
		h.tick(stateDown)
		h.clock = h.clock.Add(6 * time.Minute)
		h.tick(stateDown)
	}
	run()
	if len(h.swaps) != 0 || h.tests != 0 {
		t.Fatalf("without a license Autopilot does nothing: swaps=%v tests=%d", h.swaps, h.tests)
	}
	apLicense(t, true)
	// a foreign server never runs it
	autopilotOnSnapshot(&HubSnapshot{Local: tunnelStatus{Role: "foreign"}, Main: &peerLive{FrpUp: true, HealthState: stateDown}})
	ap.mu.Lock()
	n := len(ap.downSince)
	ap.mu.Unlock()
	if n != 0 {
		t.Error("the foreign side does not track tunnels for Autopilot")
	}
	// a tunnel that was never up (still being set up) is left alone
	h.tick(stateDown)
	h.clock = h.clock.Add(6 * time.Minute)
	h.tick(stateDown)
	if len(h.swaps) != 0 {
		t.Fatalf("a tunnel never seen up is not swapped, got %v", h.swaps)
	}
	run()
	if len(h.swaps) != 1 {
		t.Errorf("with a license, on the Iran side, after the tunnel was up: one swap, got %v", h.swaps)
	}
}

func TestAutopilotAPI(t *testing.T) {
	apLicense(t, false)
	_ = os.Remove(autopilotConfigPath())
	t.Cleanup(func() { _ = os.Remove(autopilotConfigPath()) })
	post := func(body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		handleAutopilotPost(w, httptest.NewRequest("POST", "/api/autopilot", strings.NewReader(body)))
		return w
	}
	if w := post(`{"enabled": true}`); w.Code == http.StatusOK || !strings.Contains(w.Body.String(), "E-LIC-01") {
		t.Fatalf("turning Autopilot on needs the license: %d %s", w.Code, w.Body.String())
	}
	if loadAutopilotConfig().Enabled {
		t.Fatal("a refused request must not be saved")
	}
	apLicense(t, true)
	if w := post(`{"enabled": true, "down_minutes": 1}`); w.Code == http.StatusOK {
		t.Errorf("an out-of-range value is refused: %s", w.Body.String())
	}
	if w := post(`{"enabled": true, "down_minutes": 8, "carriers": ["backhaul:wssmux"]}`); w.Code != http.StatusOK {
		t.Fatalf("a valid request: %d %s", w.Code, w.Body.String())
	}
	if c := loadAutopilotConfig(); !c.Enabled || c.DownMinutes != 8 || c.CooldownMin != 30 || len(c.Carriers) != 1 {
		t.Errorf("saved: %+v", c)
	}
	apLicense(t, false)
	if w := post(`{"enabled": false}`); w.Code != http.StatusOK || loadAutopilotConfig().Enabled {
		t.Errorf("turning it off never needs a license: %d", w.Code)
	}
	if loadAutopilotConfig().DownMinutes != 8 {
		t.Error("fields not sent keep their value")
	}
}

// The real swap under Autopilot: a carrier that does not connect is undone on
// both servers before the next one is tried.
func TestAutopilotRunsTheRealSwapWithItsRollback(t *testing.T) {
	apLicense(t, true)
	h := newAPHarness(t)
	rec := swapStubs(t)
	rec.linked["backhaul:wssmux"] = true
	apSwapFn = apSwapReal
	tun := testTunnel()
	apResolve = func(int) (swapTunnel, error) { return tun, nil }
	c := loadAutopilotConfig()
	c.PathTest = false
	_ = saveAutopilotConfig(c)

	h.tick(stateHealthy)
	h.tick(stateDown)
	h.clock = h.clock.Add(6 * time.Minute)
	h.tick(stateDown)

	if got := strings.Join(rec.local, ","); got != "backhaul:tcpmux,frp:tcp,backhaul:wssmux" {
		t.Errorf("this server: tcpmux, back to frp:tcp, then wssmux; got %s", got)
	}
	if got := strings.Join(rec.foreign, ","); got != "backhaul:tcpmux,frp:tcp,backhaul:wssmux" {
		t.Errorf("the foreign server follows every step, got %s", got)
	}
	if e := h.lastEvent(t); e.Kind != "switched" || e.To != "backhaul:wssmux" {
		t.Errorf("event: %+v", e)
	}
}

func TestAutopilotPathTestJoinOnTheForeignServer(t *testing.T) {
	post := func(body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		handlePeerPathTestJoin(w, httptest.NewRequest("POST", "/api/peer/pathtest-join", strings.NewReader(body)))
		return w
	}
	apLicense(t, false)
	if w := post(`{"action":"join","code":"HPT1-x"}`); !strings.Contains(w.Body.String(), "E-LIC-01") {
		t.Errorf("joining a path test is Pro on the foreign server too: %d %s", w.Code, w.Body.String())
	}
	if w := post(`{"action":"stop"}`); w.Code != http.StatusOK {
		t.Errorf("stop never needs a license: %d", w.Code)
	}
	apLicense(t, true)
	if w := post(`{"action":"join","code":"not-a-code"}`); !strings.Contains(w.Body.String(), "E-PATHTEST-01") {
		t.Errorf("a damaged code is refused: %d %s", w.Code, w.Body.String())
	}
	if w := post(`{"action":"reboot"}`); w.Code == http.StatusOK {
		t.Error("an unknown action is refused")
	}
	if ptActive() != nil {
		t.Error("no session may be left running")
	}
}

func TestAutopilotPathTestStopsItsHubWhenTheForeignPanelIsOlder(t *testing.T) {
	apLicense(t, true)
	old := swapCall
	t.Cleanup(func() { swapCall = old; ptStop() })
	var calls []string
	swapCall = func(_ swapTunnel, _, path string, payload any, _ time.Duration) ([]byte, error) {
		m, _ := payload.(map[string]string)
		calls = append(calls, path+" "+m["action"])
		if m["action"] == "join" && !strings.HasPrefix(m["code"], ptCodePrefix) {
			t.Errorf("the foreign server is sent the hub's code, got %q", m["code"])
		}
		return nil, errors.New("foreign panel answered HTTP 404: page not found")
	}
	_, err := apPathTestReal(swapTunnel{ID: 2, RemotePub: "192.0.2.9", LocalPub: "192.0.2.1"})
	if err == nil || !strings.Contains(err.Error(), "older than Autopilot") {
		t.Fatalf("an older foreign panel is named as the reason, got %v", err)
	}
	if ptActive() != nil {
		t.Error("the hub this run started must be stopped")
	}
	if len(calls) != 2 || !strings.HasSuffix(calls[0], " join") || !strings.HasSuffix(calls[1], " stop") {
		t.Errorf("calls: %v", calls)
	}
	apLicense(t, false)
	if _, err := apPathTestReal(swapTunnel{ID: 2}); err == nil {
		t.Error("without the path test's license no test is started")
	}
}
