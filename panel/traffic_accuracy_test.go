package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The bugs behind wrong totals and speeds, one test each.

// Two samplers shared the traffic state: the snapshot handed in a
// /proc/net/dev read seconds before the recorder's fresh one. Processed after
// it, every counter looked lower, was taken for a reset and each interface's
// whole counter was added again.
func TestTrafficSampleIgnoresOutOfOrderReading(t *testing.T) {
	resetTrafficState(t)
	const gb = 1 << 30
	t0 := time.Unix(1_800_000_000, 0)
	at := func(s int) time.Time { return t0.Add(time.Duration(s) * time.Second) }
	dev := func(rx uint64) string { return devLines(map[string][2]uint64{"gre-a": {rx, 0}}) }

	trafficSample(dev(5*gb), 0, 0, false, at(0))
	trafficSample(dev(5*gb+1000), 0, 0, false, at(5))
	m := trafficSample(dev(5*gb+400), 0, 0, false, at(3)) // the stale one
	if got := m["down"].(uint64); got != 1000 {
		t.Fatalf("down = %d after a stale reading, want 1000 (it used to add the whole 5 GB counter)", got)
	}
	m = trafficSample(dev(5*gb+3000), 0, 0, false, at(10))
	if got := m["down"].(uint64); got != 3000 {
		t.Fatalf("down = %d, want 3000", got)
	}
}

// Speed is bytes over the time between the two readings, not between two
// calls.
func TestTrafficSpeedUsesReadingTime(t *testing.T) {
	resetTrafficState(t)
	t0 := time.Unix(1_800_000_000, 0)
	dev := func(rx, tx uint64) string { return devLines(map[string][2]uint64{"gre-a": {rx, tx}}) }
	trafficSample(dev(0, 0), 0, 0, false, t0)
	m := trafficSample(dev(5_000_000, 1_000_000), 0, 0, false, t0.Add(5*time.Second))
	if d, u := m["speed_down"].(float64), m["speed_up"].(float64); d != 1_000_000 || u != 200_000 {
		t.Fatalf("speed = %v down / %v up, want 1000000 / 200000", d, u)
	}
	// carrier counters move in the same reading
	trafficSample(dev(5_000_000, 1_000_000), 100, 0, true, t0.Add(10*time.Second))
	m = trafficSample(dev(5_000_000, 1_000_000), 2_100, 0, true, t0.Add(12*time.Second))
	if d := m["speed_down"].(float64); d != 1000 {
		t.Fatalf("carrier speed = %v, want 1000", d)
	}
}

// What an interface moves while the panel is stopped (an update) counts: its
// last raw counters are kept on disk.
func TestTrafficCountsWhilePanelWasDown(t *testing.T) {
	resetTrafficState(t)
	t0 := time.Unix(1_800_000_000, 0)
	dev := func(rx uint64) string { return devLines(map[string][2]uint64{"gre-a": {rx, 0}, "gre-b": {7, 0}}) }
	trafficSample(dev(1000), 0, 0, false, t0)
	trafficSample(dev(1500), 9, 9, true, t0.Add(5*time.Second))
	trafficStateMu.Lock()
	saveTrafficStateLocked()
	// the panel restarts
	trafficStateInit, lifetimeUp, lifetimeDown, lastRawIf, lastSampleAt, lastReadAt = false, 0, 0, nil, time.Time{}, time.Time{}
	trafficStateMu.Unlock()

	m := trafficSample(dev(4500), 0, 0, true, t0.Add(60*time.Second))
	if got := m["down"].(uint64); got != 3500 {
		t.Fatalf("down = %d, want 3500 (500 before the restart, 3000 while stopped)", got)
	}
	var st persistentTrafficState
	b, _ := os.ReadFile(trafficStateFile())
	_ = json.Unmarshal(b, &st)
	if _, ok := st.LastIf["gre-a"]; !ok {
		t.Fatalf("per-interface counters not saved: %s", b)
	}
}

func TestBackhaulTag(t *testing.T) {
	d := "/etc/backhaul"
	for path, want := range map[string]string{
		d + "/config.toml":                                  "backhaul-server",
		d + "/server.toml":                                  "backhaul-server",
		d + "/client.toml":                                  "backhaul-client",
		d + "/server-3.toml":                                "backhaul-server-3",
		d + "/client-h2.toml":                               "backhaul-client-h2",
		d + "/udp/backhaul-server-3.toml":                   "backhaul-server-3",
		d + "/udp/backhaul-server.toml":                     "backhaul-server",
		d + "/udp/backhaul-udp-server-3.toml":               "backhaul-server-3",
		d + "/udp/backhaul-client.toml":                     "backhaul-client",
		filepath.Join(d, "udp", "backhaul-udp-client.toml"): "backhaul-client",
	} {
		if got := backhaulTag(path); got != want {
			t.Errorf("%s: %q, want %q", path, got, want)
		}
	}
}

func TestBagherCarrierEnds(t *testing.T) {
	cfg := defaultSSHFwdConfig()
	if bagherCarrierEnds(cfg) != nil {
		t.Fatal("Bagher off: nothing to count")
	}
	cfg.Enabled, cfg.Role, cfg.RemoteHost, cfg.RemoteSSHPort = true, "iran", "198.51.100.1", 2222
	cfg.Links = []BagherLink{{ID: 2, RemoteHost: "198.51.100.2"}, {ID: 4, RemoteHost: "198.51.100.4", RemoteSSHPort: 22}}
	got := bagherCarrierEnds(cfg)
	want := []carrierEnd{{Port: 2222, Remote: "198.51.100.1", Tag: "bagher-1"}, {Port: 2222, Remote: "198.51.100.2", Tag: "bagher-2"},
		{Port: 22, Remote: "198.51.100.4", Tag: "bagher-4"}}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("end %d: %+v, want %+v", i, got[i], want[i])
		}
	}
	// the foreign server counts its sshd only for the Iran server
	fo := defaultSSHFwdConfig()
	fo.Enabled, fo.Role, fo.RemoteHost = true, "foreign", "203.0.113.5"
	if e := bagherCarrierEnds(fo); len(e) != 1 || e[0] != (carrierEnd{Port: 22, From: "203.0.113.5", Tag: "bagher-1"}) {
		t.Fatalf("foreign end: %+v", e)
	}
	r := carrierRules(bagherCarrierEnds(fo), "eth0")
	for _, line := range []string{"-A HASHEM_ACCT_IN -i eth0 -s 203.0.113.5/32 -p tcp --dport 22", "-A HASHEM_ACCT_OUT -o eth0 -d 203.0.113.5/32 -p tcp --sport 22"} {
		if !strings.Contains(r, line+"\n") {
			t.Fatalf("missing %q in\n%s", line, r)
		}
	}
}

// iptables-save prints the rules with "-m tcp" and /32 added; each one must
// be traced back to its end.
func TestAcctRuleKey(t *testing.T) {
	for _, c := range []struct {
		rule string
		in   bool
		want acctKey
	}{
		{"-A HASHEM_ACCT_IN -i eth0 -p tcp -m tcp --dport 3080", true, acctKey{Listen: true, Port: 3080}},
		{"-A HASHEM_ACCT_OUT -o eth0 -p udp -m udp --sport 3080", false, acctKey{Listen: true, Port: 3080}},
		{"-A HASHEM_ACCT_IN -i eth0 -s 203.0.113.5/32 -p tcp -m tcp --dport 22", true, acctKey{Listen: true, Port: 22, Peer: "203.0.113.5"}},
		{"-A HASHEM_ACCT_OUT -o eth0 -d 203.0.113.5/32 -p tcp -m tcp --sport 22", false, acctKey{Listen: true, Port: 22, Peer: "203.0.113.5"}},
		{"-A HASHEM_ACCT_IN -i eth0 -s 198.51.100.1/32 -p tcp -m tcp --sport 2222", true, acctKey{Port: 2222, Peer: "198.51.100.1"}},
		{"-A HASHEM_ACCT_OUT -o eth0 -d 198.51.100.1/32 -p tcp -m tcp --dport 2222", false, acctKey{Port: 2222, Peer: "198.51.100.1"}},
	} {
		if got, ok := acctRuleKey(c.rule, c.in); !ok || got != c.want {
			t.Errorf("%s: %+v %v, want %+v", c.rule, got, ok, c.want)
		}
	}
}

// Each Backhaul unit and Bagher link gets its own counters, from the same
// iptables-save read as the total.
func TestCarrierTagCounters(t *testing.T) {
	oldDir, oldCfg, oldRunner := backhaulDir, configDir, runner
	backhaulDir, configDir = t.TempDir(), t.TempDir()
	_ = os.WriteFile(filepath.Join(backhaulDir, "server.toml"), []byte("[server]\nbind_addr = \"0.0.0.0:3080\"\n"), 0o600)
	_ = os.WriteFile(filepath.Join(backhaulDir, "server-3.toml"), []byte("[server]\nbind_addr = \"0.0.0.0:3090\"\n"), 0o600)
	cfg := defaultSSHFwdConfig()
	cfg.Enabled, cfg.Role, cfg.RemoteHost = true, "iran", "198.51.100.1"
	sshFwdMu.Lock()
	_ = saveSSHFwdConfigLocked(cfg)
	sshFwdMu.Unlock()
	save := "*filter\n:HASHEM_ACCT_IN - [0:0]\n:HASHEM_ACCT_OUT - [0:0]\n" +
		"[1:100] -A INPUT -j HASHEM_ACCT_IN\n[1:100] -A OUTPUT -j HASHEM_ACCT_OUT\n" +
		"[1:1000] -A HASHEM_ACCT_IN -p tcp -m tcp --dport 3080\n[1:10] -A HASHEM_ACCT_IN -p udp -m udp --dport 3080\n" +
		"[1:2000] -A HASHEM_ACCT_OUT -p tcp -m tcp --sport 3080\n" +
		"[1:300] -A HASHEM_ACCT_IN -p tcp -m tcp --dport 3090\n[1:400] -A HASHEM_ACCT_OUT -p tcp -m tcp --sport 3090\n" +
		"[1:50] -A HASHEM_ACCT_IN -s 198.51.100.1/32 -p tcp -m tcp --sport 22\n[1:60] -A HASHEM_ACCT_OUT -d 198.51.100.1/32 -p tcp -m tcp --dport 22\nCOMMIT\n"
	runner = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "iptables-save" {
			return []byte(save), nil
		}
		return nil, nil // iptables-restore / iptables -C: accepted
	}
	reset := func() {
		carrierState.Lock()
		carrierState.at, carrierState.lastFailed = time.Time{}, time.Time{}
		carrierState.Unlock()
	}
	t.Cleanup(func() {
		backhaulDir, configDir, runner = oldDir, oldCfg, oldRunner
		carrierState.Lock()
		carrierState.sig, carrierState.at, carrierState.tags, carrierState.ok = "", time.Time{}, nil, false
		carrierState.rx, carrierState.tx, carrierState.raw = 0, 0, nil
		carrierState.Unlock()
	})
	reset()
	carrierState.Lock()
	carrierState.rx, carrierState.tx, carrierState.tags, carrierState.raw = 0, 0, nil, nil
	carrierState.Unlock()
	readCarrierCounters() // builds the chains: counters start at 0
	reset()
	rx, tx, ok := readCarrierCounters()
	if !ok || rx != 1360 || tx != 2460 {
		t.Fatalf("total %d/%d %v, want 1360/2460", rx, tx, ok)
	}
	tags := carrierTagCounters()
	for tag, want := range map[string][2]uint64{"backhaul-server": {1010, 2000}, "backhaul-server-3": {300, 400}, "bagher-1": {50, 60}} {
		if tags[tag] != want {
			t.Errorf("%s = %v, want %v (all: %v)", tag, tags[tag], want, tags)
		}
	}
}

// The base tunnel and Backhaul peers without GRE get their own counters, so
// the Tunnel tab can show their speeds.
func TestLinkCountersFromSnapshot(t *testing.T) {
	v := &hostView{dev: map[string]devCounters{"gre-tunnel": {rx: 700, tx: 800}, "gre-p2": {rx: 5, tx: 6}},
		carrierOK: true, carrierRx: 99, carrierTx: 98,
		carrierTags: map[string][2]uint64{"backhaul-server-3": {30, 40}, "bagher-1": {11, 12}, "bagher-2": {1, 2}}}
	m := mainTunnelFrom(tunnelStatus{Role: "iran", FrpUp: true, Gre: greState{Exists: true}}, v)
	if m == nil || m.Rx == nil || *m.Rx != 700 || *m.Tx != 800 {
		t.Fatalf("main tunnel counters: %+v", m)
	}
	if rx, tx := localTraffic(tunnelStatus{FrpSvc: "backhaul-server-3"}, v); rx == nil || *rx != 30 || *tx != 40 {
		t.Fatal("a Backhaul base tunnel without GRE: its unit's counters")
	}
	if rx, tx := localTraffic(tunnelStatus{}, v); rx == nil || *rx != 12 || *tx != 14 {
		t.Fatalf("Bagher only: the sum of its links, got %v", rx)
	}
	if rx, _ := v.carrierTraffic("backhaul-server-9"); rx != nil {
		t.Fatal("unknown unit: no counters")
	}
}

func TestSpoofInterfaceIsATunnel(t *testing.T) {
	if !isTunnelInterface(spoofIface) {
		t.Fatal("the Spoof tunnel's WireGuard interface carries tunnel traffic")
	}
}

// Audit T1: a stale reading inside the first second of a speed window (the
// window moves lastSampleAt only after a second) was taken for a reset of
// every interface and its whole counter was counted again.
func TestTrafficStaleReadingInsideSpeedWindow(t *testing.T) {
	resetTrafficState(t)
	const gb = 1 << 30
	t0 := time.Unix(1_800_000_000, 0)
	dev := func(rx uint64) string { return devLines(map[string][2]uint64{"gre-a": {rx, 0}}) }
	trafficSample(dev(5*gb), 0, 0, false, t0)
	trafficSample(dev(5*gb+1000), 0, 0, false, t0.Add(600*time.Millisecond))
	m := trafficSample(dev(5*gb+400), 0, 0, false, t0.Add(300*time.Millisecond))
	if got := m["down"].(uint64); got != 1000 {
		t.Fatalf("down = %d after a stale reading inside the window, want 1000", got)
	}
	m = trafficSample(dev(5*gb+1000), 0, 0, false, t0.Add(600*time.Millisecond)) // the same reading again
	if got := m["down"].(uint64); got != 1000 {
		t.Fatalf("down = %d after the same reading twice, want 1000", got)
	}
}

// Audit T3: the 30 s flush wrote traffic_state.json before the first
// reading had loaded it, with zero totals: the saved lifetime was lost.
func TestTrafficFlushBeforeFirstSampleKeepsState(t *testing.T) {
	resetTrafficState(t)
	st := persistentTrafficState{LifetimeUp: 4000, LifetimeDown: 9000, LastIf: map[string][2]uint64{"gre-a": {100, 100}}}
	b, _ := json.Marshal(st)
	if err := os.WriteFile(trafficStateFile(), b, 0600); err != nil {
		t.Fatal(err)
	}
	flushHistoryIfDirty() // the panel is slow to take its first reading
	m := trafficSample(devLines(map[string][2]uint64{"gre-a": {150, 100}}), 0, 0, false, time.Now())
	if got := m["down"].(uint64); got != 9050 {
		t.Fatalf("down = %d, want 9050 (9000 saved + 50 moved)", got)
	}
}

// Audit T6: with no state file the totals come from traffic.json, read
// under its own lock (it raced the history recorder).
func TestTrafficStateFallsBackToHistory(t *testing.T) {
	resetTrafficState(t)
	up, down := uint64(70), uint64(80)
	histMu.Lock()
	histCached = []trafficPoint{{T: 1, Up: &up, Down: &down}}
	histMu.Unlock()
	m := trafficSample(devLines(map[string][2]uint64{"gre-a": {1, 1}}), 0, 0, false, time.Now())
	if m["up"].(uint64) != 70 || m["down"].(uint64) != 80 {
		t.Fatalf("totals %v/%v, want 70/80 from the history", m["up"], m["down"])
	}
}

// Audit T4: a sold tunnel inside GRE is the customer's traffic, billed on
// its own: never the seller's tunnel traffic.
func TestTrafficSkipsCustomersGRE(t *testing.T) {
	for _, name := range []string{"hcg3x1", "hcg12x2"} {
		if isTunnelInterface(name) {
			t.Errorf("isTunnelInterface(%q): a customer's GRE counted as this server's tunnel", name)
		}
	}
	if !isTunnelInterface("gre-tunnel") {
		t.Error("gre-tunnel is a tunnel")
	}
}

// Correctness review: a carrier reading that failed once made the next good
// one a new baseline, and what the carriers moved in between was lost.
func TestTrafficCarrierFailedReadingKeepsBaseline(t *testing.T) {
	resetTrafficState(t)
	t0 := time.Unix(1_800_000_000, 0)
	dev := devLines(map[string][2]uint64{"gre-a": {10, 10}})
	trafficSample(dev, 1000, 0, true, t0)
	trafficSample(dev, 0, 0, false, t0.Add(5*time.Second)) // iptables-save failed
	m := trafficSample(dev, 1500, 0, true, t0.Add(10*time.Second))
	if got := m["down"].(uint64); got != 500 {
		t.Fatalf("down = %d, want 500 (moved while one reading failed)", got)
	}
}
