package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func up(v uint64) *uint64 { return &v }

func res(dir, layer string, ok bool) ProbeResult {
	return ProbeResult{Layer: layer, Direction: dir, OK: ok}
}

// cleanSnap is a hub with nothing wrong locally.
func cleanSnap() LocalSnapshot {
	return LocalSnapshot{GreIf: "gre-t1", InnerLocal: "10.10.1.1", GreMTU: 1380,
		RPFilterAll: 2, RPFilterDefault: 2, RPFilterIface: 2, IPForward: true,
		FwChecked: true, ConntrackKnown: true,
		RouteKnown: true, RouteBackViaGre: true, SrcAddrOnReply: "10.10.1.1"}
}

func okBoth() []ProbeResult {
	return []ProbeResult{
		res(DirHubToSpoke, LayerICMPGre64, true), res(DirHubToSpoke, LayerICMPGre1300, true),
		res(DirSpokeToHub, LayerICMPGre64, true), res(DirSpokeToHub, LayerICMPGre1300, true),
	}
}

// reverseFail: hub->spoke works, spoke->hub ICMP over GRE fails.
func reverseFail(extra ...ProbeResult) []ProbeResult {
	r := []ProbeResult{
		res(DirHubToSpoke, LayerICMPGre64, true), res(DirHubToSpoke, LayerICMPGre1300, true),
		res(DirSpokeToHub, LayerICMPGre64, false),
	}
	return append(r, extra...)
}

func TestRevPathClassifier(t *testing.T) {
	snap := func(f func(*LocalSnapshot)) LocalSnapshot { s := cleanSnap(); f(&s); return s }
	cases := []struct {
		name   string
		m      ProbeMatrix
		s      LocalSnapshot
		want   Verdict
		fixAut bool
	}{
		{"healthy both ways", ProbeMatrix{Results: okBoth()}, cleanSnap(), VerdictHealthy, false},
		{"rp_filter strict", ProbeMatrix{Results: reverseFail(), HubRxDelta: up(7)},
			snap(func(s *LocalSnapshot) { s.RPFilterAll, s.RPFilterIface = 1, 0 }), VerdictRPFilter, true},
		{"rp_filter strict on iface only", ProbeMatrix{Results: reverseFail(), HubRxDelta: up(7)},
			snap(func(s *LocalSnapshot) { s.RPFilterAll, s.RPFilterIface = 0, 1 }), VerdictRPFilter, true},
		{"source selection", ProbeMatrix{Results: reverseFail(), HubRxDelta: up(3)},
			snap(func(s *LocalSnapshot) { s.SrcAddrOnReply = "203.0.113.5" }), VerdictSrcSelect, true},
		{"no return route", ProbeMatrix{Results: reverseFail(), HubRxDelta: up(3)},
			snap(func(s *LocalSnapshot) { s.RouteBackViaGre = false }), VerdictNoReturnRoute, true},
		{"firewall drops proto 47", ProbeMatrix{Results: reverseFail(), HubRxDelta: up(3)},
			snap(func(s *LocalSnapshot) { s.InputDropsProto47 = true }), VerdictFwInput, true},
		{"mtu black hole", ProbeMatrix{Results: []ProbeResult{
			res(DirHubToSpoke, LayerICMPGre64, true), res(DirHubToSpoke, LayerICMPGre1300, false),
			res(DirSpokeToHub, LayerICMPGre64, true), res(DirSpokeToHub, LayerICMPGre1300, true)}},
			cleanSnap(), VerdictMTUBlackhole, true},
		{"conntrack invalid", ProbeMatrix{Results: reverseFail(), HubRxDelta: up(3)},
			snap(func(s *LocalSnapshot) { s.ConntrackInvalidRising = true }), VerdictConntrackInvalid, true},
		{"isp drops icmp one way", ProbeMatrix{Results: reverseFail(
			res(DirSpokeToHub, LayerICMPPublic, false), res(DirSpokeToHub, LayerTCPCtrlInner, true))},
			cleanSnap(), VerdictISPICMPOneWay, false},
		{"isp blocks gre", ProbeMatrix{Results: reverseFail(res(DirSpokeToHub, LayerTCPCtrlPublic, true)), HubRxDelta: up(0)},
			cleanSnap(), VerdictISPGreBlock, false},
		{"cloud security group", ProbeMatrix{Results: []ProbeResult{
			res(DirHubToSpoke, LayerICMPGre64, false), res(DirHubToSpoke, LayerICMPPublic, true)},
			HubRxDelta: up(0), HubTxDelta: up(5), SpokeRxDelta: up(0)},
			cleanSnap(), VerdictCloudSG, false},

		// ambiguous input must never produce a guess
		{"unknown: no data", ProbeMatrix{}, cleanSnap(), VerdictUnknown, false},
		{"unknown: two local causes", ProbeMatrix{Results: reverseFail(), HubRxDelta: up(3)},
			snap(func(s *LocalSnapshot) { s.RPFilterAll, s.RPFilterIface = 1, 1; s.InputDropsProto47 = true }), VerdictUnknown, false},
		{"unknown: reverse fails, counters unmeasured", ProbeMatrix{Results: reverseFail()},
			cleanSnap(), VerdictUnknown, false},
		{"unknown: rx moved but hub is clean", ProbeMatrix{Results: reverseFail(), HubRxDelta: up(9)},
			cleanSnap(), VerdictUnknown, false},
		{"unknown: directions disagree", ProbeMatrix{Results: []ProbeResult{
			res(DirHubToSpoke, LayerICMPGre64, true), res(DirHubToSpoke, LayerICMPGre1300, false),
			res(DirSpokeToHub, LayerICMPGre64, false)}, HubRxDelta: up(3)},
			snap(func(s *LocalSnapshot) { s.RPFilterAll, s.RPFilterIface = 1, 1 }), VerdictUnknown, false},
		{"unknown: hub-only probe is fine but rp_filter strict", ProbeMatrix{Results: []ProbeResult{
			res(DirHubToSpoke, LayerICMPGre64, true), res(DirHubToSpoke, LayerICMPGre1300, true)}},
			snap(func(s *LocalSnapshot) { s.RPFilterAll, s.RPFilterIface = 1, 1 }), VerdictUnknown, false},
		{"unknown: tcp ok over inner, icmp cause unclear", ProbeMatrix{Results: reverseFail(
			res(DirSpokeToHub, LayerTCPCtrlInner, true))},
			cleanSnap(), VerdictUnknown, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := classifyRevPath(c.m, c.s)
			if got.Verdict != c.want {
				t.Fatalf("verdict=%s want %s (conf=%s) evidence=%v", got.Verdict, c.want, got.Confidence, got.Evidence)
			}
			if got.AutoFixable != c.fixAut {
				t.Fatalf("auto_fixable=%v want %v", got.AutoFixable, c.fixAut)
			}
			if got.Verdict == VerdictUnknown && (got.SuggestedFix != "" || got.AutoFixable || got.Confidence != "low") {
				t.Fatalf("UNKNOWN must not suggest a fix: %+v", got)
			}
			if len(got.Evidence) == 0 {
				t.Fatal("evidence must not be empty")
			}
			if again := classifyRevPath(c.m, c.s); fmt.Sprint(again) != fmt.Sprint(got) {
				t.Fatal("classifier is not deterministic")
			}
		})
	}
}

func TestRevPathHubOnlyHealthyIsLowConfidence(t *testing.T) {
	m := ProbeMatrix{Results: []ProbeResult{
		res(DirHubToSpoke, LayerICMPGre64, true), res(DirHubToSpoke, LayerICMPGre1300, true),
		{Layer: LayerICMPGre64, Direction: DirUnprobed}}}
	d := classifyRevPath(m, cleanSnap())
	if d.Verdict != VerdictHealthy || d.Confidence != "low" {
		t.Fatalf("got %+v", d)
	}
	if !strings.Contains(strings.Join(d.Evidence, " "), "not probed") {
		t.Fatalf("must ask for spoke-side data: %v", d.Evidence)
	}
}

func TestRevPathParsers(t *testing.T) {
	if parseIntFile("2\n") != 2 || parseIntFile("x") != -1 || parseIntFile("") != -1 {
		t.Fatal("parseIntFile")
	}
	if mtu := parseLinkMTU("7: gre-t1@NONE: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1380 qdisc noqueue state UNKNOWN\\    link/gre 1.2.3.4 peer 5.6.7.8"); mtu != 1380 {
		t.Fatalf("mtu=%d", mtu)
	}
	src, dev := parseRouteGet("10.10.1.2 dev gre-t1 src 10.10.1.1 uid 0 \n    cache")
	if src != "10.10.1.1" || dev != "gre-t1" {
		t.Fatalf("route get: %q %q", src, dev)
	}
	src, dev = parseRouteGet("10.10.1.2 via 192.0.2.1 dev eth0 src 192.0.2.50 uid 0")
	if src != "192.0.2.50" || dev != "eth0" {
		t.Fatalf("route get via: %q %q", src, dev)
	}
	dev0 := "Inter-|   Receive                                                |  Transmit\n face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n" +
		"    lo: 100 5 0 0 0 0 0 0 100 5 0 0 0 0 0 0\n gre-t1: 5000 40 0 0 0 0 0 0 7000 55 0 0 0 0 0 0\n"
	if rx, tx, ok := parseNetDevPackets(dev0, "gre-t1"); !ok || rx != 40 || tx != 55 {
		t.Fatalf("netdev %d %d %v", rx, tx, ok)
	}
	if _, _, ok := parseNetDevPackets(dev0, "gre-t9"); ok {
		t.Fatal("missing iface must be !ok")
	}
	if rtt := parsePingRTT("64 bytes from 10.10.1.2: icmp_seq=1 ttl=64 time=12.3 ms"); rtt != 12.3 {
		t.Fatalf("rtt=%v", rtt)
	}
	ct := "entries  searched found new invalid ignore delete\n00000010 00000000 00000005 00000000 0000000a 00000000 00000000\n00000010 00000000 00000005 00000000 00000002 00000000 00000000\n"
	if n, ok := parseConntrackInvalid(ct); !ok || n != 12 {
		t.Fatalf("conntrack invalid=%d %v", n, ok)
	}
	if _, ok := parseConntrackInvalid("garbage"); ok {
		t.Fatal("garbage must be !ok")
	}
}

const iptDropGre = `*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
-A INPUT -p gre -j DROP
-A INPUT -p icmp -j DROP
-A FORWARD -p tcp --dport 22 -j ACCEPT
COMMIT
*nat
-A INPUT -p 47 -j DROP
COMMIT
`

const iptPolicyDropOpen = `*filter
:INPUT DROP [0:0]
:FORWARD ACCEPT [0:0]
-A INPUT -i lo -j ACCEPT
-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
COMMIT
`

const iptPolicyDropAllowed = `*filter
:INPUT DROP [0:0]
:FORWARD ACCEPT [0:0]
-A INPUT -i gre-t1 -j ACCEPT
-A INPUT -p icmp -j ACCEPT
COMMIT
`

func TestRevPathParseIptablesSave(t *testing.T) {
	cases := []struct {
		name, in   string
		d47, dICMP bool
	}{
		{"explicit drops", iptDropGre, true, true},
		{"policy drop without accepts", iptPolicyDropOpen, true, true},
		{"policy drop with gre iface + icmp accept", iptPolicyDropAllowed, false, false},
		{"empty", "", false, false},
		{"nat table is ignored", "*nat\n-A INPUT -p 47 -j DROP\nCOMMIT\n", false, false},
	}
	for _, c := range cases {
		a, b := parseIptablesSave(c.in, "gre-t1")
		if a != c.d47 || b != c.dICMP {
			t.Errorf("%s: got (%v,%v) want (%v,%v)", c.name, a, b, c.d47, c.dICMP)
		}
	}
}

// ---- collectors with a stub host: read-only guarantee ----

// forbiddenCmd reports commands that would change system state.
func forbiddenCmd(name string, args []string) bool {
	a := " " + strings.Join(args, " ") + " "
	switch name {
	case "sysctl":
		return strings.Contains(a, " -w ") || strings.Contains(a, "=") || strings.Contains(a, " -p ")
	case "iptables", "ip6tables", "nft", "ebtables", "ipset":
		return true // only iptables-save is allowed
	case "systemctl":
		for _, w := range []string{" restart ", " stop ", " start ", " reload ", " enable ", " disable ", " kill ", " daemon-reload "} {
			if strings.Contains(a, w) {
				return true
			}
		}
	case "ip":
		for _, w := range []string{" add ", " del ", " delete ", " replace ", " change ", " set ", " flush ", " append "} {
			if strings.Contains(a, w) {
				return true
			}
		}
	case "tee", "rm", "mv", "cp", "sh", "bash", "modprobe", "conntrack", "tc":
		return true
	}
	return false
}

func TestRevPathForbiddenCmdCatchesWrites(t *testing.T) {
	bad := [][]string{
		{"sysctl", "-w", "net.ipv4.conf.all.rp_filter=2"}, {"iptables", "-A", "INPUT", "-j", "ACCEPT"},
		{"iptables", "-I", "INPUT"}, {"iptables", "-D", "INPUT"}, {"ip", "route", "replace", "10.0.0.0/30", "dev", "x"},
		{"ip", "route", "add", "x"}, {"ip", "route", "del", "x"}, {"systemctl", "restart", "gre-tunnel"},
		{"systemctl", "stop", "frps"}, {"ip", "link", "set", "x", "mtu", "1300"},
	}
	for _, c := range bad {
		if !forbiddenCmd(c[0], c[1:]) {
			t.Errorf("checker missed write command %v", c)
		}
	}
	good := [][]string{{"ip", "route", "get", "10.0.0.1"}, {"ip", "-o", "link", "show", "x"}, {"iptables-save"},
		{"ping", "-c", "1", "10.0.0.1"}, {"ss", "-Htin", "state", "established"}, {"systemctl", "is-active", "x"}}
	for _, c := range good {
		if forbiddenCmd(c[0], c[1:]) {
			t.Errorf("checker flagged read command %v", c)
		}
	}
}

// fakeHost installs a stub runner and a fixture /proc, and records every call.
type fakeHost struct {
	mu    sync.Mutex
	calls []string
	pings atomic.Int64
}

func newFakeHost(t *testing.T, iptables string) *fakeHost {
	t.Helper()
	h := &fakeHost{}
	proc := t.TempDir()
	write := func(rel, content string) {
		p := filepath.Join(proc, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("sys/net/ipv4/conf/all/rp_filter", "1\n")
	write("sys/net/ipv4/conf/default/rp_filter", "1\n")
	write("sys/net/ipv4/conf/gre-t1/rp_filter", "0\n")
	write("sys/net/ipv4/ip_forward", "1\n")
	write("net/dev", "Inter-|\n face |\n gre-t1: 5000 40 0 0 0 0 0 0 7000 55 0 0 0 0 0 0\n")
	write("net/stat/nf_conntrack", "entries searched found new invalid ignore delete\n00000010 00000000 00000005 00000000 00000001 00000000 00000000\n")
	oldProc, oldRunner := procRoot, runner
	procRoot = proc
	runner = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		h.mu.Lock()
		h.calls = append(h.calls, name+" "+strings.Join(args, " "))
		h.mu.Unlock()
		if forbiddenCmd(name, args) {
			t.Errorf("revpath issued a WRITE command: %s %v", name, args)
			return nil, fmt.Errorf("forbidden")
		}
		switch name {
		case "ip":
			if len(args) > 1 && args[0] == "-o" {
				return []byte("7: gre-t1@NONE: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1380 qdisc noqueue\\    link/gre"), nil
			}
			if len(args) > 1 && args[0] == "route" {
				return []byte("10.10.1.2 dev gre-t1 src 10.10.1.1 uid 0"), nil
			}
		case "iptables-save":
			if iptables == "" {
				return nil, fmt.Errorf("executable file not found")
			}
			return []byte(iptables), nil
		case "ping":
			h.pings.Add(1)
			return []byte("64 bytes from x: icmp_seq=1 ttl=64 time=1.5 ms"), nil
		case "ss":
			return []byte("0 0 10.10.1.1:7001 10.10.1.2:50000\n\t cubic rtt:3.5/1 \n"), nil
		}
		return nil, fmt.Errorf("unexpected command %s", name)
	}
	t.Cleanup(func() {
		procRoot, runner = oldProc, oldRunner
		revPathMu.Lock()
		revPathCache = map[int]*revPathEntry{}
		revPathMu.Unlock()
	})
	return h
}

func testPeer() peerRecord {
	return peerRecord{ID: 1, Name: "t1", GreIf: "gre-t1", LocalGre: "10.10.1.1/30", PeerGre: "10.10.1.2",
		RemotePub: "198.51.100.7", FrpPort: 7001}
}

func TestRevPathCollectLocalSnapshot(t *testing.T) {
	newFakeHost(t, iptDropGre)
	s := collectLocalSnapshot(testPeer())
	if s.RPFilterAll != 1 || s.RPFilterDefault != 1 || s.RPFilterIface != 0 || !s.rpStrict() {
		t.Fatalf("rp_filter: %+v", s)
	}
	if !s.IPForward || s.GreMTU != 1380 || s.InnerLocal != "10.10.1.1" {
		t.Fatalf("basics: %+v", s)
	}
	if !s.RouteKnown || !s.RouteBackViaGre || s.SrcAddrOnReply != "10.10.1.1" {
		t.Fatalf("route: %+v", s)
	}
	if !s.FwChecked || !s.InputDropsProto47 || !s.FwDropsICMP {
		t.Fatalf("firewall: %+v", s)
	}
	if !s.ConntrackKnown || s.ConntrackInvalidRising {
		t.Fatalf("first conntrack read must not be 'rising': %+v", s)
	}
}

func TestRevPathCollectorsDegradeWithoutIptables(t *testing.T) {
	newFakeHost(t, "")
	s := collectLocalSnapshot(testPeer())
	if s.FwChecked || s.InputDropsProto47 || s.FwDropsICMP {
		t.Fatalf("missing iptables-save must leave firewall unknown, got %+v", s)
	}
	procRoot = t.TempDir() // no /proc files at all
	s = collectLocalSnapshot(testPeer())
	if s.RPFilterAll != -1 || s.RPFilterIface != -1 || s.ConntrackKnown {
		t.Fatalf("missing proc files must read as unknown: %+v", s)
	}
}

func TestRevPathDiagnosePeerIsReadOnly(t *testing.T) {
	h := newFakeHost(t, iptPolicyDropAllowed)
	e := diagnosePeer(testPeer())
	if len(h.calls) == 0 {
		t.Fatal("expected probes to run through the runner")
	}
	for _, c := range h.calls {
		name := strings.Fields(c)[0]
		switch name {
		case "ip", "ping", "iptables-save", "ss":
		default:
			t.Errorf("unexpected command in revpath: %s", c)
		}
	}
	// hub->spoke answered; spoke side unprobed => never a confident verdict
	if e.Diagnosis.Verdict == VerdictUnknown && e.Diagnosis.Confidence != "low" {
		t.Fatalf("diag: %+v", e.Diagnosis)
	}
	if !e.Matrix.ok(DirHubToSpoke, LayerICMPGre64) || !e.Matrix.ok(DirSpokeToHub, LayerTCPCtrlInner) {
		t.Fatalf("matrix: %+v", e.Matrix.Results)
	}
	if r, ok := e.Matrix.get(DirSpokeToHub, LayerICMPGre64); ok {
		t.Fatalf("spoke ICMP must stay unprobed, got %+v", r)
	}
	sawPlaceholder := false
	for _, r := range e.Matrix.Results {
		if r.Direction == DirUnprobed {
			sawPlaceholder = true
		}
	}
	if !sawPlaceholder {
		t.Fatal("unprobed layers must be marked")
	}
}

func TestRevPathStandalonePeerNotProbed(t *testing.T) {
	h := newFakeHost(t, "")
	p := testPeer()
	p.NoGre = true
	e := diagnosePeer(p)
	if len(h.calls) != 0 || e.Diagnosis.Verdict != VerdictUnknown {
		t.Fatalf("calls=%v diag=%+v", h.calls, e.Diagnosis)
	}
}

func writePeersFile(t *testing.T, ps ...peerRecord) {
	t.Helper()
	b, _ := json.Marshal(map[string]any{"peers": ps})
	if err := os.WriteFile(peersFile(), b, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(peersFile()) })
}

func TestRevPathCacheAndNoFanOut(t *testing.T) {
	h := newFakeHost(t, "")
	writePeersFile(t, testPeer())

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); revPathRefresh(nil, false) }()
	}
	wg.Wait()
	first := h.pings.Load()
	if first == 0 || first > 3 {
		t.Fatalf("20 concurrent GETs must collapse into one probe run (<=3 pings), got %d", first)
	}
	revPathRefresh(nil, false)
	if h.pings.Load() != first {
		t.Fatal("fresh cache must not probe again")
	}
	revPathRefresh([]int{1}, true)
	if h.pings.Load() <= first {
		t.Fatal("forced refresh must probe again")
	}

	// stale entries are refreshed
	revPathMu.Lock()
	revPathCache[1].checkedAt = time.Now().Add(-2 * revPathTTL)
	revPathMu.Unlock()
	before := h.pings.Load()
	revPathRefresh(nil, false)
	if h.pings.Load() <= before {
		t.Fatal("stale cache must be refreshed")
	}
}

func TestRevPathHandlers(t *testing.T) {
	newFakeHost(t, "")
	writePeersFile(t, testPeer())

	rec := httptest.NewRecorder()
	handleRevPathGet(rec, httptest.NewRequest("GET", "/api/revpath", nil))
	var out struct {
		Peers    []revPathEntry `json:"peers"`
		ReadOnly bool           `json:"read_only"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || len(out.Peers) != 1 || !out.ReadOnly {
		t.Fatalf("GET: %v %s", err, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	handleRevPathRun(rec, httptest.NewRequest("POST", "/api/revpath/run", strings.NewReader(`{"peer_id":1}`)))
	if rec.Code != 200 {
		t.Fatalf("run: %d %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	handleRevPathRun(rec, httptest.NewRequest("POST", "/api/revpath/run", strings.NewReader(`{"peer_id":99}`)))
	if rec.Code != 404 {
		t.Fatalf("unknown peer: %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	handleRevPathRun(rec, httptest.NewRequest("POST", "/api/revpath/run", strings.NewReader(`{}`)))
	if rec.Code != 400 {
		t.Fatalf("missing id: %d", rec.Code)
	}
}
