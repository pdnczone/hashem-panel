package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// clusterFixture isolates the cluster state and swaps every host seam.
type clusterFixture struct {
	t       *testing.T
	snap    *HubSnapshot
	pings   map[string]float64
	icmpOK  bool
	applied []string
	binds   map[string]string // svc -> addr the fake relay listens on
	bindLog []string
	mu      sync.Mutex
}

func newClusterFixture(t *testing.T, licensed bool) *clusterFixture {
	t.Helper()
	if licensed {
		withPro(t)
	} else {
		setTestLicense(t, nil)
	}
	old := configDir
	configDir = t.TempDir()
	oldProc := procNetRoot
	procNetRoot = t.TempDir()
	f := &clusterFixture{t: t, pings: map[string]float64{}, icmpOK: true, binds: map[string]string{}, snap: &HubSnapshot{At: time.Now()}}
	saved := []any{lbSnapshot, lbApply, lbClear, lbAddrs, lbBind, lbIsBound, lbForget, lbHubForward, lbPinger}
	lbSnapshot = func() *HubSnapshot { return f.snap }
	lbApply = func(text string, _ []string) error {
		f.mu.Lock()
		f.applied = append(f.applied, text)
		f.mu.Unlock()
		return nil
	}
	lbClear = func([]string) { f.mu.Lock(); f.applied = append(f.applied, ""); f.mu.Unlock() }
	lbAddrs = func([]string) error { return nil }
	lbBind = func(svc, addr string) (bool, error) {
		f.bindLog = append(f.bindLog, svc+"="+addr)
		if addr == "" {
			delete(f.binds, svc)
		} else {
			f.binds[svc] = addr
		}
		return true, nil
	}
	lbIsBound = func(svc, addr string) bool { return f.binds[svc] == addr && addr != "" }
	lbForget = func(string) {}
	lbPinger = func(ts []string, _ time.Duration) (map[string]float64, bool) {
		out := map[string]float64{}
		for _, x := range ts {
			v, ok := f.pings[x]
			if !ok {
				v = -1
			}
			out[x] = v
		}
		return out, f.icmpOK
	}
	resetClusterState()
	t.Cleanup(func() {
		configDir, procNetRoot = old, oldProc
		lbSnapshot = saved[0].(func() *HubSnapshot)
		lbApply = saved[1].(func(string, []string) error)
		lbClear = saved[2].(func([]string))
		lbAddrs = saved[3].(func([]string) error)
		lbBind = saved[4].(func(string, string) (bool, error))
		lbIsBound = saved[5].(func(string, string) bool)
		lbForget = saved[6].(func(string))
		lbHubForward = saved[7].(func(ClusterConfig, LBPool) string)
		lbPinger = saved[8].(func([]string, time.Duration) (map[string]float64, bool))
		resetClusterState()
	})
	return f
}

func resetClusterState() {
	clusterMu.Lock()
	clusterCache, clusterMod = nil, time.Time{}
	clusterMu.Unlock()
	clusterRT = newClusterRuntime()
	clusterEvMu.Lock()
	clusterEvs, clusterEvOK = nil, false
	clusterEvMu.Unlock()
	meshMu.Lock()
	meshState = map[string]*hubRT{}
	meshMu.Unlock()
}

// peer adds a hub-side link (frps-N) to the fake snapshot.
func (f *clusterFixture) peer(id, ctrl int, remote string, ports ...int) {
	f.snap.Peers = append(f.snap.Peers, peerLive{peerRecord: peerRecord{ID: id, Name: fmt.Sprintf("de-%d", id),
		RemotePub: remote, FrpPort: ctrl, FrpsSvc: fmt.Sprintf("frps-%d", id), PeerGre: fmt.Sprintf("10.0.%d.2", id), Ports: ports},
		HealthState: stateHealthy})
}

// procV4 encodes an IPv4 socket address the way /proc/net/tcp prints it.
func procV4(ip string, port int) string {
	var a [4]int
	fmt.Sscanf(ip, "%d.%d.%d.%d", &a[0], &a[1], &a[2], &a[3])
	return fmt.Sprintf("%02X%02X%02X%02X:%04X", a[3], a[2], a[1], a[0], port)
}

// sockets writes a fake /proc/net/tcp: listeners "addr:port" and sessions
// "localport>remoteip" (local address 10.0.0.1) or "addr:port>remoteip".
func (f *clusterFixture) sockets(listen []string, sessions []string) {
	var b strings.Builder
	b.WriteString("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n")
	n := 0
	for _, l := range listen {
		var ip string
		var port int
		i := strings.LastIndex(l, ":")
		ip = l[:i]
		fmt.Sscanf(l[i+1:], "%d", &port)
		fmt.Fprintf(&b, "%4d: %s %s 0A 00000000:00000000 00:00000000 00000000     0        0 %d 1\n", n, procV4(ip, port), procV4("0.0.0.0", 0), 1000+n)
		n++
	}
	for _, s := range sessions {
		var lp int
		parts := strings.SplitN(s, ">", 2)
		local := parts[0]
		if !strings.Contains(local, ":") {
			local = "10.0.0.1:" + local
		}
		i := strings.LastIndex(local, ":")
		fmt.Sscanf(local[i+1:], "%d", &lp)
		fmt.Fprintf(&b, "%4d: %s %s 01 00000000:00000000 00:00000000 00000000     0        0 %d 1\n", n, procV4(local[:i], lp), procV4(parts[1], 40000+n), 1000+n)
		n++
	}
	if err := os.WriteFile(filepath.Join(procNetRoot, "tcp"), []byte(b.String()), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

func (f *clusterFixture) lastRules() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.applied) == 0 {
		return ""
	}
	return f.applied[len(f.applied)-1]
}

// ---- pure parts ----

func TestParseProcNet(t *testing.T) {
	v4 := "  sl  local_address rem_address   st\n   0: 024DFEA9:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1\n" +
		"   1: 0100007F:1B59 0201000A:9C40 01 00000000:00000000 00:00000000 00000000     0        0 2 1\n"
	got := parseProcNet(v4, "tcp")
	if len(got) != 2 || got[0].Local.String() != "169.254.77.2:443" || got[0].State != sockListen {
		t.Fatalf("v4: %+v", got)
	}
	if got[1].Remote.String() != "10.0.1.2:40000" || got[1].State != sockEstablished {
		t.Fatalf("v4 session: %+v", got[1])
	}
	// IPv4-mapped IPv6 (::ffff:169.254.77.3) is reported as plain IPv4
	v6 := "header\n   0: 0000000000000000FFFF0000034DFEA9:01BB 00000000000000000000000000000000:0000 0A 0:0 0:0 0 0 0 3 1\n"
	g6 := parseProcNet(v6, "tcp")
	if len(g6) != 1 || g6[0].Local.String() != "169.254.77.3:443" {
		t.Fatalf("v6: %+v", g6)
	}
	if len(parseProcNet("x\n   0: zz:01 00:00 0A\n", "tcp")) != 0 {
		t.Fatal("garbage parsed")
	}
}

func TestICMPEchoChecksum(t *testing.T) {
	b := icmpEcho(0x4853, 7)
	if b[0] != 8 || icmpChecksum(b) != 0 {
		t.Fatalf("echo packet does not verify: % x", b)
	}
}

func TestLBAddrAndConf(t *testing.T) {
	cases := map[string]string{"frps": "169.254.77.1", "backhaul-server": "169.254.77.1", "frps-1": "169.254.77.2",
		"frps-9": "169.254.77.10", "backhaul-server-3": "169.254.77.4", "frpc": "", "frps-x": "", "frps-251": ""}
	for svc, want := range cases {
		if got := lbAddrFor(svc); got != want {
			t.Errorf("lbAddrFor(%s) = %q, want %q", svc, got, want)
		}
	}
	if p, e := lbConfFor("backhaul-server-3"); !strings.HasSuffix(p, "server-3.toml") || e != "backhaul" {
		t.Errorf("backhaul conf: %s %s", p, e)
	}
	if p, e := lbConfFor("frps"); !strings.HasSuffix(p, "frps.toml") || e != "frp" {
		t.Errorf("frps conf: %s %s", p, e)
	}
}

func TestFrpsWithBind(t *testing.T) {
	conf := "bindAddr = \"0.0.0.0\"\nbindPort = 7000\nkcpBindPort = 7000\nauth.token = \"x\"\n"
	bound := frpsWithBind(conf, "169.254.77.2")
	if !strings.Contains(bound, "bindPort = 7000\nproxyBindAddr = \"169.254.77.2\"\nkcpBindPort") {
		t.Fatalf("not after bindPort:\n%s", bound)
	}
	if frpsWithBind(bound, "169.254.77.2") != bound {
		t.Fatal("not idempotent")
	}
	if frpsWithBind(bound, "") != conf {
		t.Fatalf("unbind did not restore:\n%s", frpsWithBind(bound, ""))
	}
	// a stale hand-written bind is replaced, never doubled
	two := frpsWithBind("proxyBindAddr = \"127.0.0.1\"\n"+conf, "169.254.77.3")
	if strings.Count(two, "proxyBindAddr") != 1 || !strings.Contains(two, "169.254.77.3") {
		t.Fatalf("got:\n%s", two)
	}
	// no bindPort line: top level, before any table
	top := frpsWithBind("auth.token = \"x\"\n\n[webServer]\nport = 1\n", "169.254.77.4")
	if strings.Index(top, "proxyBindAddr") > strings.Index(top, "[webServer]") {
		t.Fatalf("inside a table:\n%s", top)
	}
}

func TestBackhaulWithBind(t *testing.T) {
	v2 := "[listener]\nbind_addr = \"0.0.0.0:3080\"\n\n[ports]\nmapping = [\n    \"443\",\n    \"2083=8443\",\n    \"10000-10010\",\n    \"1.2.3.4:80=80\",\n]\n"
	b := backhaulWithBind(v2, "169.254.77.5")
	for _, want := range []string{`"169.254.77.5:443"`, `"169.254.77.5:2083=8443"`, `"169.254.77.5:10000-10010"`, `"1.2.3.4:80=80"`, `bind_addr = "0.0.0.0:3080"`} {
		if !strings.Contains(b, want) {
			t.Errorf("missing %s in\n%s", want, b)
		}
	}
	if backhaulWithBind(b, "169.254.77.5") != b {
		t.Error("not idempotent")
	}
	if backhaulWithBind(b, "") != v2 {
		t.Errorf("unbind:\n%s", backhaulWithBind(b, ""))
	}
	// v1 single-line array, and a move to another private address
	v1 := "[server]\nbind_addr = \"0.0.0.0:3080\"\nports = [\"443\", \"0.0.0.0:8443=443\"]\n"
	m := backhaulWithBind(backhaulWithBind(v1, "169.254.77.2"), "169.254.77.3")
	if !strings.Contains(m, `["169.254.77.3:443", "169.254.77.3:8443=443"]`) {
		t.Fatalf("v1:\n%s", m)
	}
}

func members(ms ...lbMemberState) []lbMemberState { return ms }

func mem(link, prio, weight int, up, listening bool, lat float64) lbMemberState {
	return lbMemberState{LBMember: LBMember{Link: link, Priority: prio, Weight: weight}, Addr: fmt.Sprintf("169.254.77.%d", link+1),
		Up: up, Listening: listening, LatencyMs: lat}
}

func TestLBPickTargets(t *testing.T) {
	fo := LBPool{Port: 443, Proto: "tcp", Mode: lbFailover}
	ts, st := lbPickTargets(fo, members(mem(1, 1, 1, true, true, 50), mem(2, 0, 1, true, true, 90)), nil)
	if st != poolOK || len(ts) != 1 || ts[0].Link != 2 || ts[0].Share != 1 {
		t.Fatalf("failover takes the lowest priority: %v %+v", st, ts)
	}
	ts, st = lbPickTargets(fo, members(mem(1, 1, 1, true, true, 50), mem(2, 0, 1, false, true, 90)), nil)
	if st != poolDegraded || ts[0].Link != 1 {
		t.Fatalf("failover moves off a down member: %v %+v", st, ts)
	}
	d := mem(2, 0, 1, true, true, 90)
	d.Drain = true
	ts, _ = lbPickTargets(fo, members(mem(1, 1, 1, true, true, 50), d), nil)
	if ts[0].Link != 1 {
		t.Fatalf("a drained member takes no new connections: %+v", ts)
	}
	ts, st = lbPickTargets(fo, members(mem(1, 0, 1, false, true, -1), mem(2, 1, 1, false, false, -1)), nil)
	if st != poolFailOpen || len(ts) != 1 || ts[0].Link != 1 {
		t.Fatalf("fail-open uses the members that still listen: %v %+v", st, ts)
	}
	if _, st = lbPickTargets(fo, members(mem(1, 0, 1, true, false, -1)), nil); st != poolDown {
		t.Fatalf("nothing listening: %v", st)
	}
	off := fo
	off.Disabled = true
	if _, st = lbPickTargets(off, members(mem(1, 0, 1, true, true, 1)), nil); st != poolOff {
		t.Fatalf("disabled: %v", st)
	}

	bal := LBPool{Port: 443, Proto: "both", Mode: lbBalance}
	ts, _ = lbPickTargets(bal, members(mem(1, 0, 3, true, true, 1), mem(2, 0, 1, true, true, 1)), nil)
	if len(ts) != 2 || math.Abs(ts[0].Share-0.75) > 1e-9 || math.Abs(ts[1].Share-0.25) > 1e-9 {
		t.Fatalf("balance shares by weight: %+v", ts)
	}
}

func TestLBLatencyHysteresis(t *testing.T) {
	p := LBPool{Port: 443, Proto: "tcp", Mode: lbLatency}
	rt := &lbPoolRT{Current: -1, Better: -1}
	ts, _ := lbPickTargets(p, members(mem(1, 0, 1, true, true, 80), mem(2, 0, 1, true, true, 100)), rt)
	if ts[0].Link != 1 {
		t.Fatalf("first pick is the fastest: %+v", ts)
	}
	// link 2 becomes clearly faster: it takes over only after lbLatencyStreak ticks
	for i := 1; i < lbLatencyStreak; i++ {
		ts, _ = lbPickTargets(p, members(mem(1, 0, 1, true, true, 80), mem(2, 0, 1, true, true, 40)), rt)
		if ts[0].Link != 1 {
			t.Fatalf("switched after %d ticks", i)
		}
	}
	ts, _ = lbPickTargets(p, members(mem(1, 0, 1, true, true, 80), mem(2, 0, 1, true, true, 40)), rt)
	if ts[0].Link != 2 {
		t.Fatalf("did not switch: %+v", ts)
	}
	// a small difference never moves it back
	for i := 0; i < 3*lbLatencyStreak; i++ {
		ts, _ = lbPickTargets(p, members(mem(1, 0, 1, true, true, 36), mem(2, 0, 1, true, true, 40)), rt)
	}
	if ts[0].Link != 2 {
		t.Fatal("flapped on a 4 ms difference")
	}
	// the current one going down moves at once
	ts, _ = lbPickTargets(p, members(mem(1, 0, 1, true, true, 36), mem(2, 0, 1, false, true, 40)), rt)
	if ts[0].Link != 1 {
		t.Fatal("did not leave a down member")
	}
}

func TestLBStickyBuckets(t *testing.T) {
	three := []lbTarget{{Link: 1, Weight: 1}, {Link: 2, Weight: 1}, {Link: 3, Weight: 2}}
	b3 := lbStickyBuckets(three)
	count := map[int]int{}
	for _, i := range b3 {
		count[three[i].Link]++
	}
	if count[3] < count[1] || count[3] < count[2] || count[1] == 0 || count[2] == 0 {
		t.Fatalf("weights not respected: %v", count)
	}
	// link 2 leaves: only its users move
	two := []lbTarget{{Link: 1, Weight: 1}, {Link: 3, Weight: 2}}
	b2 := lbStickyBuckets(two)
	for b := range b3 {
		was := three[b3[b]].Link
		if was != 2 && two[b2[b]].Link != was {
			t.Fatalf("bucket %d moved from link %d although it was not on the leaving link", b, was)
		}
	}
}

func TestLBRulesText(t *testing.T) {
	plan := lbPlan{
		Pools: []lbPoolPlan{
			{Port: 443, Proto: "both", Mode: lbBalance, Targets: []lbTarget{{Link: 1, Addr: "169.254.77.2", Port: 443, Weight: 1}, {Link: 2, Addr: "169.254.77.3", Port: 8443, Weight: 3}}},
			{Port: 8080, Proto: "tcp", Mode: lbSticky, Targets: []lbTarget{{Link: 1, Addr: "169.254.77.2", Port: 8080, Weight: 1}, {Link: 2, Addr: "169.254.77.3", Port: 8080, Weight: 1}, {Link: 3, Addr: "169.254.77.4", Port: 8080, Weight: 1}}},
			{Port: 9000, Proto: "tcp", Mode: lbFailover, State: poolDown},
		},
		Pass:    []lbPortRange{{Proto: "tcp", From: 2083, To: 2083, Addr: "169.254.77.2"}, {Proto: "udp", From: 5000, To: 5010, Addr: "169.254.77.3"}},
		Forward: []lbForward{{Port: 9000, Proto: "tcp", To: "5.6.7.8"}},
	}
	txt := lbRulesText(plan)
	for _, want := range []string{
		"*nat\n:HASHEM-LB-ENTRY - [0:0]\n:HASHEM-LB - [0:0]\n",
		"-A HASHEM-LB-ENTRY -d 169.254.77.0/24 -j RETURN",
		"-A HASHEM-LB -p tcp --dport 443 -j HLB-T443",
		"-A HASHEM-LB -p udp --dport 443 -j HLB-U443",
		"-A HLB-T443 -m statistic --mode random --probability 0.25000 -p tcp -j DNAT --to-destination 169.254.77.2:443",
		"-A HLB-T443 -p tcp -j DNAT --to-destination 169.254.77.3:8443",
		"-A HASHEM-LB -p tcp --dport 2083 -j DNAT --to-destination 169.254.77.2\n",
		"-A HASHEM-LB -p udp --dport 5000:5010 -j DNAT --to-destination 169.254.77.3\n",
		"-A HASHEM-LB -p tcp --dport 9000 -j DNAT --to-destination 5.6.7.8:9000",
		"-A HASHEM-LB-POST -d 5.6.7.8 -p tcp --dport 9000 -j MASQUERADE",
		"-A HASHEM-LB-FWD -d 5.6.7.8 -m conntrack --ctstate DNAT -j ACCEPT",
		"-A HASHEM-LB-FILTER -d 169.254.77.0/24 -m conntrack --ctstate DNAT -j ACCEPT",
		"-A HASHEM-LB-FILTER -d 169.254.77.0/24 ! -i lo -j DROP",
	} {
		if !strings.Contains(txt, want) {
			t.Errorf("missing %q", want)
		}
	}
	// pools jump before pass-through ports
	if strings.Index(txt, "HLB-T443\n") > strings.Index(txt, "--dport 2083") {
		t.Error("pass-through before pools")
	}
	if strings.Contains(txt, "HLB-T9000") {
		t.Error("a pool with no target got a chain")
	}
	// sticky: every rule has at most 10 ranges, and every bucket is covered once
	covered := map[string]int{}
	for _, l := range strings.Split(txt, "\n") {
		if !strings.Contains(l, "--u32") {
			continue
		}
		spec := strings.Split(strings.Split(l, `"12&0x3F=`)[1], `"`)[0]
		rs := strings.Split(spec, ",")
		if len(rs) > 10 {
			t.Fatalf("u32 test with %d ranges", len(rs))
		}
		for _, r := range rs {
			var a, b int
			if n, _ := fmt.Sscanf(r, "%d:%d", &a, &b); n == 2 {
				for x := a; x <= b; x++ {
					covered[fmt.Sprint(x)]++
				}
			} else {
				covered[r]++
			}
		}
	}
	if len(covered) != lbBuckets {
		t.Fatalf("sticky covers %d buckets", len(covered))
	}
	for k, n := range covered {
		if n != 1 {
			t.Fatalf("bucket %s in %d rules", k, n)
		}
	}
	if got := lbChainsIn(txt); strings.Join(got, ",") != "HLB-T443,HLB-U443,HLB-T8080" {
		t.Errorf("chains: %v", got)
	}
}

func TestLBPassRanges(t *testing.T) {
	listen := map[int]map[string][]int{
		1: {"tcp": {443, 2083, 2084, 2085, 9000}, "udp": {443}},
		2: {"tcp": {443, 9000}},
	}
	addrs := map[int]string{1: "169.254.77.2", 2: "169.254.77.3"}
	r, warn := lbPassRanges(listen, addrs, map[string]bool{"tcp/443": true, "udp/443": true})
	want := []lbPortRange{{"tcp", 2083, 2085, "169.254.77.2", 1}, {"tcp", 9000, 9000, "169.254.77.2", 1}}
	if fmt.Sprint(r) != fmt.Sprint(want) {
		t.Fatalf("ranges %v", r)
	}
	if len(warn) != 1 || !strings.Contains(warn[0], "tcp port 9000") {
		t.Fatalf("warnings %v", warn)
	}
}

func TestLinkHealthDebounce(t *testing.T) {
	h := LBHealth{}.norm()
	now := time.Now()
	rt := &lbLinkRT{LatencyMs: -1}
	step := func(session bool, ms float64, icmp bool) int {
		now = now.Add(time.Second)
		return rt.lbObserve(now, session, ms, icmp, h)
	}
	if step(true, 20, true); !rt.Up {
		t.Fatal("first good check: up")
	}
	// ping stops answering on a link that answered: out after Fall checks
	if step(true, -1, true) != 0 || step(true, -1, true) != 0 {
		t.Fatal("went down too early")
	}
	if step(true, -1, true) != -1 || rt.Up || !strings.Contains(rt.Reason, "ping") {
		t.Fatalf("not down after %d: %+v", h.Fall, rt)
	}
	if step(true, 22, true) != 0 || step(true, 21, true) != 0 || step(true, 20, true) != 1 {
		t.Fatal("rise")
	}
	if rt.LatencyMs <= 0 {
		t.Fatal("latency not tracked")
	}
	// a link whose ICMP never answered (filtered) is judged by the session only
	rt2 := &lbLinkRT{LatencyMs: -1}
	for i := 0; i < 10; i++ {
		now = now.Add(time.Second)
		rt2.lbObserve(now, true, -1, true, h)
	}
	if !rt2.Up {
		t.Fatal("filtered ICMP took a working link out")
	}
	for i := 0; i < h.Fall; i++ {
		now = now.Add(time.Second)
		rt2.lbObserve(now, false, -1, true, h)
	}
	if rt2.Up || !strings.Contains(rt2.Reason, "not connected") {
		t.Fatalf("lost session: %+v", rt2)
	}
	// when ICMP cannot be used at all (no raw socket), lost pings never count
	rt3 := &lbLinkRT{LatencyMs: -1}
	rt3.lbObserve(now, true, 10, true, h)
	for i := 0; i < 5; i++ {
		now = now.Add(time.Second)
		rt3.lbObserve(now, true, -1, false, h)
	}
	if !rt3.Up {
		t.Fatal("unusable ICMP took a link out")
	}
}

// ---- the loop ----

func TestClusterTickFailover(t *testing.T) {
	f := newClusterFixture(t, true)
	f.peer(1, 7001, "1.1.1.1", 443, 2083)
	f.peer(2, 7002, "2.2.2.2", 443)
	f.peer(3, 7003, "3.3.3.3", 8443) // not part of the pool
	f.pings = map[string]float64{"10.0.1.2": 30, "10.0.2.2": 60}
	f.sockets([]string{"169.254.77.2:443", "169.254.77.2:2083", "169.254.77.3:443"}, []string{"7001>10.0.1.2", "7002>10.0.2.2"})
	if err := saveClusterConfig(ClusterConfig{Version: 2, NodeID: "hub-a", Health: LBHealth{}.norm(),
		Pools: []LBPool{{Port: 443, Proto: "tcp", Mode: lbFailover, Members: []LBMember{{Link: 1, Weight: 1, Priority: 0}}}}}); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tick := func() { now = now.Add(time.Second); clusterTick(now) }
	tick()

	// link 2 has port 443 too: it joined the pool by itself
	c := loadClusterConfig()
	if len(c.Pools[0].Members) != 2 || c.Pools[0].Members[1].Link != 2 || c.Pools[0].Members[1].Remote != "2.2.2.2" {
		t.Fatalf("auto-join: %+v", c.Pools[0].Members)
	}
	// both relays moved to their private addresses; link 3 stayed public
	if f.binds["frps-1"] != "169.254.77.2" || f.binds["frps-2"] != "169.254.77.3" || f.binds["frps-3"] != "" {
		t.Fatalf("binds %v", f.binds)
	}
	tick()
	r := f.lastRules()
	if !strings.Contains(r, "-A HLB-T443 -p tcp -j DNAT --to-destination 169.254.77.2:443") {
		t.Fatalf("traffic not on link 1:\n%s", r)
	}
	if !strings.Contains(r, "--dport 2083 -j DNAT --to-destination 169.254.77.2\n") {
		t.Fatalf("link 1's other port not passed through:\n%s", r)
	}

	// link 1 stops answering ping: out after Fall checks, traffic on link 2
	delete(f.pings, "10.0.1.2")
	tick()
	tick()
	if !strings.Contains(f.lastRules(), "169.254.77.2:443") {
		t.Fatal("left before Fall checks")
	}
	tick()
	r = f.lastRules()
	if !strings.Contains(r, "-A HLB-T443 -p tcp -j DNAT --to-destination 169.254.77.3:443") {
		t.Fatalf("no failover:\n%s", r)
	}
	ev := clusterEvents(10)
	if !strings.Contains(fmt.Sprint(ev), "de-1 is down") || !strings.Contains(fmt.Sprint(ev), "traffic goes to de-2") {
		t.Fatalf("events %v", ev)
	}

	// back after Rise checks
	f.pings["10.0.1.2"] = 31
	tick()
	tick()
	tick()
	if !strings.Contains(f.lastRules(), "-A HLB-T443 -p tcp -j DNAT --to-destination 169.254.77.2:443") {
		t.Fatalf("did not return to link 1:\n%s", f.lastRules())
	}

	// the status API shows the pool and the links
	rr := httptest.NewRecorder()
	handleClusterStatus(rr, httptest.NewRequest("GET", "/api/cluster/status", nil))
	var st struct {
		Pools []clusterPoolView `json:"pools"`
		Links []lbLinkView      `json:"links"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if len(st.Pools) != 1 || st.Pools[0].State != poolOK || len(st.Pools[0].Status) != 2 || st.Pools[0].Status[0].Share != 1 {
		t.Fatalf("status pools %+v", st.Pools)
	}
	if len(st.Links) != 3 || !st.Links[0].Bound || st.Links[2].Bound || len(st.Links[0].ListenTCP) != 2 {
		t.Fatalf("status links %+v", st.Links)
	}

	// removing the pool gives the relays their public ports back and clears the rules
	c = loadClusterConfig()
	c.Pools = nil
	_ = saveClusterConfig(c)
	now = now.Add(10 * time.Second)
	clusterTick(now)
	if f.binds["frps-1"] != "" || f.binds["frps-2"] != "" {
		t.Fatalf("still bound: %v", f.binds)
	}
	clusterTick(now.Add(time.Second))
	if f.lastRules() != "" {
		t.Fatalf("rules not cleared: %q", f.lastRules())
	}
}

func TestClusterRemovedMemberStaysOut(t *testing.T) {
	f := newClusterFixture(t, true)
	f.peer(1, 7001, "1.1.1.1", 443)
	f.peer(2, 7002, "2.2.2.2", 443)
	_ = saveClusterConfig(ClusterConfig{Version: 2, NodeID: "hub-a", Health: LBHealth{}.norm(),
		Pools: []LBPool{{Port: 443, Proto: "tcp", Mode: lbBalance}}})
	clusterTick(time.Now())
	if n := len(loadClusterConfig().Pools[0].Members); n != 2 {
		t.Fatalf("members %d", n)
	}
	if code, msg := lbMemberChange(lbMemberReq{Port: 443, Proto: "tcp", Link: 2, Action: "remove"}); code != "" {
		t.Fatal(code, msg)
	}
	clusterTick(time.Now().Add(time.Second))
	p := loadClusterConfig().Pools[0]
	if len(p.Members) != 1 || !hasInt(p.Excluded, 2) {
		t.Fatalf("removed member came back: %+v", p)
	}
	if code, _ := lbMemberChange(lbMemberReq{Port: 443, Proto: "tcp", Link: 2, Action: "add", Weight: 2}); code != "" {
		t.Fatal(code)
	}
	p = loadClusterConfig().Pools[0]
	if len(p.Members) != 2 || hasInt(p.Excluded, 2) || p.Members[1].Weight != 2 {
		t.Fatalf("re-add: %+v", p)
	}
}

// ---- API ----

func postJSON(h http.HandlerFunc, body string) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	h(rr, httptest.NewRequest("POST", "/x", strings.NewReader(body)))
	return rr
}

func TestClusterPoolAPI(t *testing.T) {
	f := newClusterFixture(t, true)
	f.peer(1, 7001, "1.1.1.1", 443)
	f.peer(2, 7002, "2.2.2.2", 443)
	if rr := postJSON(handleClusterPool, `{"port":443,"proto":"both","mode":"sticky","name":"vless","members":[{"link":1},{"link":2,"weight":3}]}`); rr.Code != 200 {
		t.Fatalf("create: %d %s", rr.Code, rr.Body)
	}
	c := loadClusterConfig()
	if len(c.Pools) != 1 || c.Pools[0].Members[0].Weight != 1 || c.Pools[0].Members[1].Remote != "2.2.2.2" {
		t.Fatalf("saved %+v", c.Pools)
	}
	for body, code := range map[string]string{
		`{"port":443,"proto":"tcp","members":[]}`:           "E-CLUSTER-03", // overlaps "both"
		`{"port":7001,"proto":"tcp"}`:                       "E-CLUSTER-03", // a control port
		`{"port":7003,"proto":"tcp"}`:                       "E-CLUSTER-03", // the WSS front of 7001
		`{"port":0}`:                                        "E-CLUSTER-02",
		`{"port":8443,"mode":"random"}`:                     "E-CLUSTER-02",
		`{"port":8443,"members":[{"link":9}]}`:              "E-CLUSTER-04",
		`{"port":8443,"members":[{"link":1},{"link":1}]}`:   "E-CLUSTER-02",
		`{"port":8443,"members":[{"link":1,"weight":500}]}`: "E-CLUSTER-02",
		`not json`: "E-CLUSTER-01",
	} {
		rr := postJSON(handleClusterPool, body)
		if !strings.Contains(rr.Body.String(), code) {
			t.Errorf("%s: want %s, got %d %s", body, code, rr.Code, rr.Body)
		}
	}
	// changing the port of an existing pool
	if rr := postJSON(handleClusterPool, `{"orig_port":443,"orig_proto":"both","port":8443,"proto":"tcp","mode":"failover","members":[{"link":1}]}`); rr.Code != 200 {
		t.Fatalf("move: %s", rr.Body)
	}
	if c = loadClusterConfig(); len(c.Pools) != 1 || c.Pools[0].Port != 8443 {
		t.Fatalf("after move %+v", c.Pools)
	}
	if rr := postJSON(handleClusterMember, `{"port":8443,"link":1,"action":"drain"}`); rr.Code != 200 || !loadClusterConfig().Pools[0].Members[0].Drain {
		t.Fatalf("drain: %s", rr.Body)
	}
	if rr := postJSON(handleClusterMember, `{"port":8443,"link":1,"action":"set","priority":5,"link_port":9443}`); rr.Code != 200 {
		t.Fatalf("set: %s", rr.Body)
	}
	if m := loadClusterConfig().Pools[0].Members[0]; m.Priority != 5 || m.Port != 9443 {
		t.Fatalf("set saved %+v", m)
	}
	if rr := postJSON(handleClusterMember, `{"port":1,"link":1,"action":"drain"}`); !strings.Contains(rr.Body.String(), "E-CLUSTER-05") {
		t.Fatalf("unknown pool: %s", rr.Body)
	}
	if rr := postJSON(handleClusterSettings, `{"health":{"interval_ms":50,"fall":2,"rise":9},"hub_forward":false}`); rr.Code != 200 {
		t.Fatal(rr.Body)
	}
	if c = loadClusterConfig(); c.Health.IntervalMs != 1000 || c.Health.Fall != 2 || c.Health.Rise != 9 || c.HubForward {
		t.Fatalf("settings %+v", c)
	}
	if rr := postJSON(handleClusterPoolDelete, `{"port":8443}`); rr.Code != 200 || len(loadClusterConfig().Pools) != 0 {
		t.Fatalf("delete: %s", rr.Body)
	}
	if rr := postJSON(handleClusterPoolDelete, `{"port":8443}`); !strings.Contains(rr.Body.String(), "E-CLUSTER-05") {
		t.Fatal("delete twice")
	}
	// lb-ports tells hashem.sh which ports a new peer may claim
	_ = postJSON(handleClusterPool, `{"port":443,"proto":"both","members":[]}`)
	if data, _ := os.ReadFile(lbPooledPortsFile()); string(data) != "443/tcp\n443/udp\n" {
		t.Fatalf("lb-ports %q", data)
	}
}

func TestClusterNeedsLicense(t *testing.T) {
	newClusterFixture(t, false)
	for _, h := range []http.HandlerFunc{handleClusterPool, handleClusterPoolDelete, handleClusterMember, handleClusterSettings,
		handleClusterJoinCode, handleClusterHubAdd, handleClusterHubDelete, handleClusterDNS, handleClusterJoinHub, handleClusterLeaveHub} {
		if rr := postJSON(h, `{}`); rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "E-LIC-01") {
			t.Errorf("unlicensed change allowed: %d %s", rr.Code, rr.Body)
		}
	}
	rr := httptest.NewRecorder()
	handleClusterStatus(rr, httptest.NewRequest("GET", "/x", nil))
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"licensed":false`) {
		t.Fatalf("status: %d %s", rr.Code, rr.Body)
	}
}

func TestClusterUpgradeFromV1(t *testing.T) {
	newClusterFixture(t, true)
	v1 := `{"enabled":true,"node_id":"iran-42","cluster_secret":"s3cret","public_ip":"5.5.5.5","balancing_mode":"wrr",
	"nodes":{"iran-7":{"id":"iran-7","name":"tehran-2","api_url":"http://6.6.6.6:7777/x","public_ip":"6.6.6.6"}},
	"foreign_nodes":{"fn_1":{"id":"fn_1","public_ip":"9.9.9.9"}}}`
	if err := os.WriteFile(clusterConfigFile(), []byte(v1), 0o600); err != nil {
		t.Fatal(err)
	}
	c := loadClusterConfig()
	if c.Version != 2 || c.NodeID != "iran-42" || c.Secret != "s3cret" || c.PublicIP != "5.5.5.5" || len(c.Hubs) != 1 || c.Hubs[0].PublicIP != "6.6.6.6" {
		t.Fatalf("upgrade %+v", c)
	}
	if len(c.Pools) != 0 || !strings.Contains(fmt.Sprint(clusterEvents(5)), "outside the tunnel") {
		t.Fatalf("the old foreign list must go, with a note: %v", clusterEvents(5))
	}
}

func TestClusterCLIChangeIsSeen(t *testing.T) {
	newClusterFixture(t, true)
	_ = saveClusterConfig(defaultClusterConfig())
	_ = loadClusterConfig()
	// another process (gre-panel cluster ...) rewrites the file
	c := defaultClusterConfig()
	c.Pools = []LBPool{{Port: 443, Proto: "tcp", Mode: lbFailover}}
	data, _ := json.Marshal(c)
	time.Sleep(20 * time.Millisecond)
	_ = os.WriteFile(clusterConfigFile(), data, 0o600)
	future := time.Now().Add(2 * time.Second)
	_ = os.Chtimes(clusterConfigFile(), future, future)
	if len(loadClusterConfig().Pools) != 1 {
		t.Fatal("the running panel kept its old copy")
	}
}

// ---- mesh ----

func signedReq(t *testing.T, path, secret string, b meshBeat) *http.Request {
	t.Helper()
	body, _ := json.Marshal(b)
	r := httptest.NewRequest("POST", path, bytes.NewReader(body))
	meshSetSig(r.Header, secret, body)
	return r
}

func TestMeshSignVerify(t *testing.T) {
	h := http.Header{}
	body := []byte(`{"id":"x"}`)
	meshSetSig(h, "k1", body)
	now := time.Now()
	if err := meshVerify("k1", h, body, now); err != nil {
		t.Fatal(err)
	}
	if err := meshVerify("k1", h, body, now); err == nil || !strings.Contains(err.Error(), "replayed") {
		t.Fatalf("replay accepted: %v", err)
	}
	h2 := http.Header{}
	meshSetSig(h2, "k1", body)
	if err := meshVerify("k2", h2, body, now); err == nil {
		t.Fatal("wrong secret accepted")
	}
	h3 := http.Header{}
	meshSetSig(h3, "k1", body)
	if err := meshVerify("k1", h3, []byte(`{"id":"y"}`), now); err == nil {
		t.Fatal("changed body accepted")
	}
	h4 := http.Header{}
	meshSetSig(h4, "k1", body)
	if err := meshVerify("k1", h4, body, now.Add(5*time.Minute)); err == nil || !strings.Contains(err.Error(), "clock") {
		t.Fatalf("stale request accepted: %v", err)
	}
	if err := meshVerify("k1", http.Header{}, body, now); err == nil {
		t.Fatal("unsigned accepted")
	}
}

func TestMeshJoinCodeRoundTrip(t *testing.T) {
	newClusterFixture(t, true)
	c := defaultClusterConfig()
	c.PublicIP = "5.5.5.5"
	_ = saveClusterConfig(c)
	code, err := meshJoinCode(loadClusterConfig())
	if err != nil {
		t.Fatal(err)
	}
	mc, err := parseMeshCode(code)
	if err != nil || mc.ID != c.NodeID || mc.IP != "5.5.5.5" || len(mc.Secret) != 64 || mc.Secret != loadClusterConfig().Secret {
		t.Fatalf("%v %+v", err, mc)
	}
	for _, bad := range []string{"", "hsh1_x", "hc1_!!", "hc1_" + "e30"} {
		if _, err := parseMeshCode(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
	if _, err := meshAddHub(code); err == nil || !strings.Contains(err.Error(), "own code") {
		t.Fatalf("own code: %v", err)
	}
}

func TestMeshHandler(t *testing.T) {
	newClusterFixture(t, true)
	c := defaultClusterConfig()
	c.NodeID, c.PublicIP, c.Secret = "hub-a", "5.5.5.5", strings.Repeat("ab", 32)
	_ = saveClusterConfig(c)
	mux := http.NewServeMux()
	mountMeshRoutes(mux)
	serve := func(r *http.Request) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, r)
		return rr
	}
	b := meshBeat{ID: "hub-b", Name: "tehran-2", IP: "6.6.6.6", Port: 7777, Healthy: true,
		Pools: map[string]meshPoolState{"tcp/443": {State: poolOK, Healthy: 2, Members: 2}}}
	// unsigned or wrongly signed: a plain 404
	if rr := serve(signedReq(t, "/_hc/beat", "wrong", b)); rr.Code != 404 {
		t.Fatalf("bad secret: %d", rr.Code)
	}
	// an unknown hub cannot beat its way in
	if rr := serve(signedReq(t, "/_hc/beat", c.Secret, b)); rr.Code != 404 {
		t.Fatalf("unknown beat: %d", rr.Code)
	}
	rr := serve(signedReq(t, "/_hc/hello", c.Secret, b))
	if rr.Code != 200 {
		t.Fatalf("hello: %d %s", rr.Code, rr.Body)
	}
	if err := meshVerify(c.Secret, rr.Header(), rr.Body.Bytes(), time.Now()); err != nil {
		t.Fatalf("answer not signed: %v", err)
	}
	var ans meshBeat
	_ = json.Unmarshal(rr.Body.Bytes(), &ans)
	if ans.ID != "hub-a" || len(ans.Hubs) != 1 || ans.Hubs[0].ID != "hub-b" {
		t.Fatalf("answer %+v", ans)
	}
	hubs := loadClusterConfig().Hubs
	if len(hubs) != 1 || hubs[0].URL != "http://6.6.6.6:7777" {
		t.Fatalf("hubs %+v", hubs)
	}
	// its pool is healthy: a pool here with no member forwards to it
	if to := meshForwardTarget(loadClusterConfig(), LBPool{Port: 443, Proto: "tcp"}); to != "6.6.6.6" {
		t.Fatalf("forward target %q", to)
	}
	if to := meshForwardTarget(loadClusterConfig(), LBPool{Port: 443, Proto: "both"}); to != "" {
		t.Fatalf("udp is not healthy there: %q", to)
	}
	// a hub that forwards itself is never a target (no loops)
	b.Pools["tcp/443"] = meshPoolState{State: poolForward}
	_ = serve(signedReq(t, "/_hc/beat", c.Secret, b))
	if to := meshForwardTarget(loadClusterConfig(), LBPool{Port: 443, Proto: "tcp"}); to != "" {
		t.Fatalf("forward loop: %q", to)
	}
	// bye removes it
	b.Bye = true
	_ = serve(signedReq(t, "/_hc/beat", c.Secret, b))
	if len(loadClusterConfig().Hubs) != 0 {
		t.Fatal("bye ignored")
	}
}

func TestClusterTickForwardsToHub(t *testing.T) {
	f := newClusterFixture(t, true)
	f.peer(1, 7001, "1.1.1.1", 443)
	f.sockets([]string{"169.254.77.2:443"}, nil) // link 1 has no session: down
	lbHubForward = func(ClusterConfig, LBPool) string { return "6.6.6.6" }
	_ = saveClusterConfig(ClusterConfig{Version: 2, NodeID: "hub-a", Health: LBHealth{}.norm(), HubForward: true,
		Pools: []LBPool{{Port: 443, Proto: "tcp", Mode: lbFailover, Members: []LBMember{{Link: 1, Weight: 1}}}}})
	now := time.Now()
	for i := 0; i < 2; i++ {
		now = now.Add(time.Second)
		clusterTick(now)
	}
	r := f.lastRules()
	if !strings.Contains(r, "--dport 443 -j DNAT --to-destination 6.6.6.6:443") || strings.Contains(r, "HLB-T443 -p tcp -j DNAT") {
		t.Fatalf("not forwarded:\n%s", r)
	}
	if st := clusterRT.plans["tcp/443"].State; st != poolForward {
		t.Fatalf("state %s", st)
	}
}

// ---- DNS ----

func TestCloudflareSync(t *testing.T) {
	type rec struct{ ID, Content string }
	var mu sync.Mutex
	recs := []rec{{"r1", "5.5.5.5"}, {"r2", "6.6.6.6"}, {"r3", "9.9.9.9"}} // 9.9.9.9 is not a hub
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(403)
			_, _ = io.WriteString(w, `{"success":false,"errors":[{"message":"Invalid API Token"}]}`)
			return
		}
		switch {
		case r.Method == "GET" && r.URL.Path == "/zones":
			if r.URL.Query().Get("name") == "example.com" {
				_, _ = io.WriteString(w, `{"success":true,"result":[{"id":"z1"}]}`)
				return
			}
			_, _ = io.WriteString(w, `{"success":true,"result":[]}`)
		case r.Method == "GET" && r.URL.Path == "/zones/z1/dns_records":
			out := []map[string]any{}
			for _, x := range recs {
				if (r.URL.Query().Get("type") == "AAAA") == strings.Contains(x.Content, ":") {
					out = append(out, map[string]any{"id": x.ID, "content": x.Content, "proxied": false})
				}
			}
			b, _ := json.Marshal(map[string]any{"success": true, "result": out})
			_, _ = w.Write(b)
		case r.Method == "POST":
			var in map[string]any
			_ = json.NewDecoder(r.Body).Decode(&in)
			if in["proxied"] != false || in["type"] != dnsRecordType(in["content"].(string)) {
				t.Errorf("create %v", in)
			}
			recs = append(recs, rec{fmt.Sprintf("r%d", len(recs)+1), in["content"].(string)})
			_, _ = io.WriteString(w, `{"success":true,"result":{}}`)
		case r.Method == "DELETE":
			id := filepath.Base(r.URL.Path)
			out := recs[:0]
			for _, x := range recs {
				if x.ID != id {
					out = append(out, x)
				}
			}
			recs = out
			_, _ = io.WriteString(w, `{"success":true,"result":{}}`)
		}
	}))
	defer srv.Close()
	old := cfAPI
	cfAPI = srv.URL
	defer func() { cfAPI = old }()

	d := DNSConfig{Token: "tok", Name: "vpn.example.com", TTL: 60}
	hubs := map[string]bool{"5.5.5.5": true, "6.6.6.6": true, "7.7.7.7": true}
	// hub 6.6.6.6 died, 7.7.7.7 joined
	if _, err := cfSyncA(d, []string{"5.5.5.5", "7.7.7.7"}, hubs); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, x := range recs {
		got = append(got, x.Content)
	}
	if strings.Join(got, ",") != "5.5.5.5,9.9.9.9,7.7.7.7" {
		t.Fatalf("records %v (9.9.9.9 is not ours and must stay)", got)
	}
	// IPv6 hubs get AAAA records, beside the A ones
	hubs["2001:db8::5"], hubs["2001:db8::6"] = true, true
	recs = append(recs, rec{"r9", "2001:db8::6"}) // hub 2001:db8::6 died
	if _, err := cfSyncA(d, []string{"5.5.5.5", "7.7.7.7", "2001:db8::5"}, hubs); err != nil {
		t.Fatal(err)
	}
	got = nil
	for _, x := range recs {
		got = append(got, x.Content)
	}
	if strings.Join(got, ",") != "5.5.5.5,9.9.9.9,7.7.7.7,2001:db8::5" {
		t.Fatalf("records with IPv6 %v", got)
	}
	d.Token = "bad"
	if _, err := cfSyncA(d, []string{"5.5.5.5"}, hubs); err == nil || !strings.Contains(err.Error(), "Invalid API Token") || strings.Contains(err.Error(), "bad") {
		t.Fatalf("token error %v", err)
	}
	d.Token, d.Name = "tok", "vpn.other.org"
	if _, err := cfSyncA(d, nil, hubs); err == nil || !strings.Contains(err.Error(), "no Cloudflare zone") {
		t.Fatalf("zone error %v", err)
	}
}

func TestValidDNSName(t *testing.T) {
	for n, ok := range map[string]bool{"vpn.example.com": true, "a.b": true, "x": false, "-a.com": false, "a..com": false, "A.com": false, "a_b.com": false} {
		if validDNSName(n) != ok {
			t.Errorf("%s: %v", n, !ok)
		}
	}
}

func TestDNSLeaderIsLowestReachableID(t *testing.T) {
	newClusterFixture(t, true)
	c := defaultClusterConfig()
	c.NodeID, c.PublicIP = "hub-b", "5.5.5.5"
	c.DNS = DNSConfig{Enabled: true, Name: "vpn.example.com"}
	c.Hubs = []HubPeer{{ID: "hub-a", PublicIP: "6.6.6.6"}, {ID: "hub-c", PublicIP: "7.7.7.7"}}
	meshMu.Lock()
	meshState["hub-a"] = &hubRT{Up: true, Beat: meshBeat{ID: "hub-a", Healthy: true, DNS: "vpn.example.com"}}
	meshState["hub-c"] = &hubRT{Up: true, Beat: meshBeat{ID: "hub-c", Healthy: false, DNS: "vpn.example.com"}}
	meshMu.Unlock()
	ips, leader := dnsHealthyIPs(c)
	if leader || strings.Join(ips, ",") != "6.6.6.6" {
		t.Fatalf("hub-a leads; unhealthy hub-c and this hub (no links) are out: %v %v", ips, leader)
	}
	meshMu.Lock()
	meshState["hub-a"].Up = false
	meshMu.Unlock()
	if _, leader = dnsHealthyIPs(c); !leader {
		t.Fatal("hub-a is unreachable: hub-b leads")
	}
}

// A healthy hub's IPv6 from its beat joins the record set (AAAA); an
// unhealthy hub's does not.
func TestDNSHealthyIPsIPv6(t *testing.T) {
	newClusterFixture(t, true)
	old := meshIP6
	meshIP6 = func() string { return "" }
	t.Cleanup(func() { meshIP6 = old })
	c := defaultClusterConfig()
	c.NodeID, c.PublicIP = "hub-b", "5.5.5.5"
	c.DNS = DNSConfig{Enabled: true, Name: "vpn.example.com"}
	c.Hubs = []HubPeer{{ID: "hub-a", PublicIP: "6.6.6.6"}, {ID: "hub-c", PublicIP: "7.7.7.7"}}
	meshMu.Lock()
	meshState["hub-a"] = &hubRT{Up: true, Beat: meshBeat{ID: "hub-a", Healthy: true, IP6: "2001:db8::a"}}
	meshState["hub-c"] = &hubRT{Up: true, Beat: meshBeat{ID: "hub-c", Healthy: false, IP6: "2001:db8::c"}}
	meshMu.Unlock()
	if ips, _ := dnsHealthyIPs(c); strings.Join(ips, ",") != "2001:db8::a,6.6.6.6" {
		t.Fatalf("records %v", ips)
	}
	// a hub with pools keeps IPv6 users away: no AAAA for it
	meshMu.Lock()
	meshState["hub-a"].Beat.Pools = map[string]meshPoolState{"tcp/443": {State: poolOK}}
	meshMu.Unlock()
	if ips, _ := dnsHealthyIPs(c); strings.Join(ips, ",") != "6.6.6.6" {
		t.Fatalf("records with a pool %v", ips)
	}
}

func TestJoinedHubsView(t *testing.T) {
	f := newClusterFixture(t, true)
	f.snap.Local = tunnelStatus{Role: "foreign (client)", RemotePub: "5.5.5.5", FrpSvc: "frpc", FrpUp: true, BindPort: 7000}
	f.snap.LocalSession = true
	_ = os.WriteFile(hubsFile(), []byte(`{"hubs":[{"id":2,"name":"hub-2","iran_pub":"6.6.6.6","svc":"frpc-h2","port":7100,"iran_gre":"10.9.0.1"}]}`), 0o600)
	f.sockets(nil, nil)
	_ = os.WriteFile(filepath.Join(procNetRoot, "tcp"), []byte("h\n   0: 0200000A:9C40 0100090A:1BBC 01 0:0 0:0 0 0 0 1 1\n"), 0o644)
	oldRunner := runner
	runner = func(_ context.Context, name string, args ...string) ([]byte, error) { return []byte("active\n"), nil }
	defer func() { runner = oldRunner }()
	joinedMu.Lock()
	joinedAt = time.Time{}
	joinedMu.Unlock()
	v := joinedHubsView()
	if len(v) != 2 || !v[0].First || v[0].IranPub != "5.5.5.5" || !v[1].Active || !v[1].Session {
		t.Fatalf("%+v", v)
	}
}

func TestMeshViewFlagsVersionDrift(t *testing.T) {
	newClusterFixture(t, true)
	c := defaultClusterConfig()
	c.Hubs = []HubPeer{{ID: "same"}, {ID: "other"}, {ID: "old"}, {ID: "never"}}
	seen := time.Now()
	meshMu.Lock()
	meshState["same"] = &hubRT{Up: true, LastSeen: seen, Beat: meshBeat{Version: panelVersion}}
	meshState["other"] = &hubRT{Up: true, LastSeen: seen, Beat: meshBeat{Version: panelVersion + "-x"}}
	meshState["old"] = &hubRT{Up: true, LastSeen: seen, Beat: meshBeat{}} // predates the version field
	meshState["never"] = &hubRT{Err: "timeout"}                           // no heartbeat yet: unknown, not different
	meshMu.Unlock()
	t.Cleanup(func() {
		meshMu.Lock()
		for _, h := range c.Hubs {
			delete(meshState, h.ID)
		}
		meshMu.Unlock()
	})
	want := map[string]bool{"same": false, "other": true, "old": true, "never": false}
	for _, v := range meshView(c) {
		if v.VersionDiffers != want[v.ID] {
			t.Errorf("hub %s: version_differs=%v, want %v", v.ID, v.VersionDiffers, want[v.ID])
		}
	}
}
