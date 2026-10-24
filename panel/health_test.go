package main

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestComputeHealthTable(t *testing.T) {
	u := func(v uint64) *uint64 { return &v }
	f := false
	cases := []struct {
		name     string
		s        LinkSignals
		state    string
		filtered bool
		kind     string
		ms       float64
		reason   string
	}{
		{"session+icmp ok: tcp wins", LinkSignals{ServiceActive: true, Session: true, TCPRTTms: 40, ICMPOK: true, ICMPms: 5, ICMPFresh: true, GreIfUp: true},
			stateHealthy, false, "tcp", 40, "session"},
		{"session, icmp dead: healthy + filtered", LinkSignals{ServiceActive: true, Session: true, TCPRTTms: 38.04, ICMPFresh: true, GreIfUp: true},
			stateHealthy, true, "tcp", 38, "filtered"},
		{"session, icmp never measured: healthy, not tagged", LinkSignals{ServiceActive: true, Session: true, TCPRTTms: 38},
			stateHealthy, false, "tcp", 38, "session"},
		{"session without rtt, connect rtt", LinkSignals{Session: true, ConnectRTTms: 12},
			stateHealthy, false, "tcp", 12, "session"},
		{"session without any rtt, icmp", LinkSignals{Session: true, ICMPOK: true, ICMPms: 7, ICMPFresh: true},
			stateHealthy, false, "icmp", 7, "session"},
		{"session, no latency at all", LinkSignals{Session: true},
			stateHealthy, false, "", -1, "session"},
		{"service+gre+icmp, no session", LinkSignals{ServiceActive: true, GreIfUp: true, ICMPOK: true, ICMPms: 3, ICMPFresh: true},
			stateHealthy, false, "icmp", 3, "answers ping"},
		{"service+gre, no session, icmp dead", LinkSignals{ServiceActive: true, GreIfUp: true, ICMPFresh: true},
			stateDegraded, false, "", -1, "no client holds a control session"},
		{"service only", LinkSignals{ServiceActive: true},
			stateDegraded, false, "", -1, "GRE interface is not up"},
		{"gre only", LinkSignals{GreIfUp: true, TrafficFlowing: true, Rx: u(1), Tx: u(2)},
			stateDegraded, false, "", -1, "tunnel service is not active"},
		{"gre only reasons include traffic", LinkSignals{GreIfUp: true, TrafficFlowing: true},
			stateDegraded, false, "", -1, "traffic is still flowing"},
		{"degraded with connect rtt", LinkSignals{ServiceActive: true, GreIfUp: true, ConnectRTTms: 20},
			stateDegraded, false, "tcp", 20, "answers TCP"},
		{"nothing", LinkSignals{}, stateDown, false, "", -1, "not active"},
		{"reverse icmp failing is a reason only", LinkSignals{Session: true, TCPRTTms: 9, ReverseICMP: &f},
			stateHealthy, false, "tcp", 9, "reverse-path"},
	}
	for _, c := range cases {
		h := ComputeHealth(c.s)
		if h.State != c.state || h.ICMPFiltered != c.filtered || h.LatencyKind != c.kind || h.LatencyMs != c.ms {
			t.Errorf("%s: got %+v", c.name, h)
		}
		if len(h.Reasons) == 0 || !strings.Contains(strings.Join(h.Reasons, "|"), c.reason) {
			t.Errorf("%s: reasons %q must mention %q", c.name, h.Reasons, c.reason)
		}
	}
}

// A live session is never down/degraded and always has a tcp latency when the
// kernel reported an RTT, whatever ICMP does.
func TestSessionAlwaysHealthyWithTCPLatency(t *testing.T) {
	for _, icmpOK := range []bool{true, false} {
		for _, fresh := range []bool{true, false} {
			for _, gre := range []bool{true, false} {
				for _, svc := range []bool{true, false} {
					h := ComputeHealth(LinkSignals{Session: true, TCPRTTms: 25, ICMPOK: icmpOK, ICMPms: 4, ICMPFresh: fresh, GreIfUp: gre, ServiceActive: svc})
					if h.State != stateHealthy || h.LatencyKind != "tcp" || h.LatencyMs != 25 {
						t.Fatalf("icmp=%v fresh=%v gre=%v svc=%v: %+v", icmpOK, fresh, gre, svc, h)
					}
				}
			}
		}
	}
}

func TestFleetHealthIsThinWrapper(t *testing.T) {
	l := mkLive(1, true, true, false, "")
	l.Linked = true
	if fleetHealth(l) != fleetOK {
		t.Fatal("linked + dead ping must be OK")
	}
	l.HealthState = stateDegraded // published (debounced) state wins
	if fleetHealth(l) != fleetDeg {
		t.Fatal("published state must be honoured")
	}
}

func raw(state string) LinkHealth { return LinkHealth{State: state, Reasons: []string{"r-" + state}} }

func TestDebounceFirstObservationImmediate(t *testing.T) {
	d := newHealthDebouncer()
	if s, r := d.observe(1, raw(stateDown)); s != stateDown || r[0] != "r-down" {
		t.Fatalf("first observation must publish immediately: %s %v", s, r)
	}
}

func TestDebounceFlappingDoesNotFlip(t *testing.T) {
	d := newHealthDebouncer()
	d.observe(1, raw(stateHealthy))
	for i := 0; i < 20; i++ {
		in := stateDegraded
		if i%2 == 1 {
			in = stateHealthy
		}
		if s, _ := d.observe(1, raw(in)); s != stateHealthy {
			t.Fatalf("flap step %d flipped to %s", i, s)
		}
	}
}

func TestDebounceTwoConsecutiveFlip(t *testing.T) {
	d := newHealthDebouncer()
	d.observe(1, raw(stateHealthy))
	if s, r := d.observe(1, raw(stateDown)); s != stateHealthy || r[0] != "r-healthy" {
		t.Fatalf("one sample must not flip and must keep old reasons: %s %v", s, r)
	}
	if s, r := d.observe(1, raw(stateDown)); s != stateDown || r[0] != "r-down" {
		t.Fatalf("second agreeing sample must flip: %s %v", s, r)
	}
	// candidate changes mid-way: counter restarts
	d.observe(1, raw(stateHealthy)) // pending healthy (1)
	d.observe(1, raw(stateDegraded))
	if s, _ := d.observe(1, raw(stateHealthy)); s != stateDown {
		t.Fatalf("non-consecutive agreement must not flip, got %s", s)
	}
	if s, _ := d.observe(1, raw(stateHealthy)); s != stateHealthy {
		t.Fatalf("two consecutive must flip, got %s", s)
	}
}

func TestDebouncePerPeerAndPrune(t *testing.T) {
	d := newHealthDebouncer()
	d.observe(1, raw(stateHealthy))
	d.observe(2, raw(stateDown))
	d.observe(1, raw(stateDown))
	if s, _ := d.observe(2, raw(stateDown)); s != stateDown {
		t.Fatal("peers must not influence each other")
	}
	d.prune(map[int]bool{2: true})
	if s, _ := d.observe(1, raw(stateDegraded)); s != stateDegraded {
		t.Fatal("pruned peer is a new first observation")
	}
}

func TestFleetLossIgnoresHealthyWithoutLatency(t *testing.T) {
	h := []fleetSample{{1, 10, fleetOK}, {2, -1, fleetOK}, {3, -1, fleetDown}, {4, -1, fleetDeg}}
	st := fleetCompute(h)
	if st.LossPct != 50 {
		t.Fatalf("healthy sample without latency is not loss: %+v", st)
	}
	if st.AvgMs != 10 {
		t.Fatalf("latency avg must ignore missing samples: %+v", st)
	}
}

func TestFleetRecordUsesUnifiedLatency(t *testing.T) {
	resetFleet()
	fleetLoad = syncOnceReset()
	l := mkLive(1, true, true, false, "")
	l.Linked, l.LatencyMs, l.LatencyKind, l.HealthState = true, 41.5, "tcp", stateHealthy
	fleetRecord([]peerLive{l}, time.Now())
	fleetMu.Lock()
	got := fleetHist[1][0]
	fleetMu.Unlock()
	if got.Ms != 41.5 || got.S != fleetOK {
		t.Fatalf("sample must carry tcp latency for an ICMP-dead healthy link: %+v", got)
	}
}

func TestFleetNodeCarriesHealthFields(t *testing.T) {
	resetFleet()
	fleetLoad = syncOnceReset()
	rec := peerRecord{ID: 4, Name: "x"}
	live := map[int]peerLive{4: {peerRecord: rec, GreUp: true, FrpUp: true, Linked: true, HealthState: stateHealthy,
		ICMPFiltered: true, ICMPMs: -1, LatencyMs: 33, LatencyKind: "tcp", Reasons: []string{"control session is established"}, SnapshotAgeMs: 1200}}
	n := fleetSnapshot([]peerRecord{rec}, live)[0]
	if n.HealthState != "healthy" || !n.ICMPFilt || n.ICMPOK || n.ICMPMs != -1 || n.SnapAgeMs != 1200 || len(n.Reasons) != 1 {
		t.Fatalf("new fields wrong: %+v", n)
	}
	b, _ := json.Marshal(n)
	for _, k := range []string{`"health_state"`, `"icmp_filtered"`, `"icmp_ok"`, `"icmp_ms"`, `"reasons"`, `"snapshot_age_ms"`, `"ping_ok"`, `"ping_ms"`, `"latency_kind"`, `"health"`} {
		if !strings.Contains(string(b), k) {
			t.Errorf("missing JSON field %s", k)
		}
	}
}

func dashboardOf(t *testing.T, snap *HubSnapshot) map[string]any {
	t.Helper()
	snapPtr.Store(snap)
	defer snapPtr.Store(nil)
	rr := httptest.NewRecorder()
	handleDashboard(rr, httptest.NewRequest("GET", "/api/dashboard", nil))
	if rr.Code != 200 {
		t.Fatalf("dashboard %d: %s", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("X-Snapshot-Age-Ms") == "" {
		t.Fatal("X-Snapshot-Age-Ms header missing")
	}
	var d map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &d); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestDashboardSingleTunnelFrpLiveIcmpDeadIsHealthy(t *testing.T) {
	st := tunnelStatus{Role: "foreign (client)", FrpUp: true, FrpSvc: "frpc", BindPort: 7000}
	st.Gre.Exists = true
	d := dashboardOf(t, &HubSnapshot{At: time.Now(), Local: st, LocalSession: true, LocalRTT: 55})
	if d["health"] != "HEALTHY" || d["health_state"] != "healthy" || d["latency_kind"] != "tcp" || d["latency_ms"].(float64) != 55 {
		t.Fatalf("FRP-live + ICMP-dead must be HEALTHY with tcp latency: %v %v %v", d["health"], d["latency_kind"], d["latency_ms"])
	}
	if d["ping_ok"] != false {
		t.Fatal("legacy ping_ok keeps its meaning")
	}
	// no session, no ping: degraded; nothing up: down
	d = dashboardOf(t, &HubSnapshot{At: time.Now(), Local: st})
	if d["health"] != "DEGRADED" || len(d["reasons"].([]any)) == 0 {
		t.Fatalf("no session + no ping must be DEGRADED with reasons: %v", d)
	}
	d = dashboardOf(t, &HubSnapshot{At: time.Now(), Local: tunnelStatus{}})
	if d["health"] != "DOWN" {
		t.Fatalf("nothing up must be DOWN: %v", d["health"])
	}
	// old rule still holds: gre + frp + ping, no session
	st.PingOK, st.PingMs = true, "9ms"
	if d = dashboardOf(t, &HubSnapshot{At: time.Now(), Local: st}); d["health"] != "HEALTHY" {
		t.Fatalf("gre+frp+ping must stay HEALTHY: %v", d["health"])
	}
}

func TestInterfaceFixesNeverRestartsOnSilentPing(t *testing.T) {
	restarts := 0
	restart := func() error { restarts++; return nil }
	st := tunnelStatus{FrpUp: true}
	st.Gre.Exists, st.Gre.PeerIP = true, "198.51.100.9"
	notes := interfaceFixes(st, restart)
	if restarts != 0 {
		t.Fatal("healthy GRE with silent ICMP must not be restarted")
	}
	if len(notes) != 1 || notes[0] != "ICMP not answering: not restarting gre-tunnel (see Reverse Path diagnosis)" {
		t.Fatalf("note missing: %v", notes)
	}
	// ping fine: nothing to do
	st.PingOK = true
	if n := interfaceFixes(st, restart); restarts != 0 || len(n) != 0 {
		t.Fatalf("unexpected: %d %v", restarts, n)
	}
	// missing interface still restarts
	st = tunnelStatus{}
	if n := interfaceFixes(st, restart); restarts != 1 || len(n) != 1 {
		t.Fatalf("missing GRE must restart once: %d %v", restarts, n)
	}
}
