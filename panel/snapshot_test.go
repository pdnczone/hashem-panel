package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// stubHost is a fake host behind the runner seam. It counts every command so
// tests can assert exactly how much forking a tick or a request costs.
type stubHost struct {
	mu       sync.Mutex
	calls    map[string]int
	ss       string
	pingOK   bool
	pingFail map[string]bool
	block    chan struct{} // when set, `ss` blocks until closed
	n        int
}

func (h *stubHost) count(k string) {
	h.mu.Lock()
	h.calls[k]++
	h.mu.Unlock()
}

func (h *stubHost) get(k string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.calls[k]
}

func (h *stubHost) total() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, v := range h.calls {
		n += v
	}
	return n
}

func (h *stubHost) reset() {
	h.mu.Lock()
	h.calls = map[string]int{}
	h.mu.Unlock()
}

func (h *stubHost) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	key := name
	if len(args) > 0 {
		key += ":" + args[0]
	}
	if name == "ping" {
		key += ":" + args[len(args)-1]
	}
	h.count(key)
	switch name {
	case "ss":
		if h.block != nil {
			select {
			case <-h.block:
			case <-ctx.Done():
			}
		}
		h.mu.Lock()
		defer h.mu.Unlock()
		return []byte(h.ss), nil
	case "ip":
		switch args[0] {
		case "tunnel":
			return []byte("gre0: gre/ip remote any local any\n"), nil
		case "-o":
			var b strings.Builder
			for i := 1; i <= h.n; i++ {
				fmt.Fprintf(&b, "6: gre-t%d    inet 10.20.%d.1/30 scope global gre-t%d\\       valid_lft forever\n", i, i, i)
			}
			return []byte(b.String()), nil
		}
	case "systemctl":
		if args[0] == "is-active" {
			var b strings.Builder
			bad := false
			for _, u := range args[1:] {
				if strings.HasPrefix(u, "frps-") {
					b.WriteString("active\n")
				} else {
					b.WriteString("inactive\n")
					bad = true
				}
			}
			if bad {
				return []byte(b.String()), fmt.Errorf("exit status 3")
			}
			return []byte(b.String()), nil
		}
	case "ping":
		h.mu.Lock()
		fail := h.pingFail[args[len(args)-1]] || !h.pingOK
		h.mu.Unlock()
		if fail {
			return []byte("100% packet loss"), fmt.Errorf("exit status 1")
		}
		return []byte("64 bytes"), nil
	}
	return nil, fmt.Errorf("stubHost: unexpected %s %v", name, args)
}

func sessionLine(i int) string {
	return fmt.Sprintf("0 0 192.0.2.10:%d 198.51.100.%d:4%04d\n\t cubic rtt:%d.5/1.0\n", 7000+i, i, i, 10+i)
}

// newStubHost installs n peers (peers.json), a stub procRoot and the runner.
func newStubHost(t *testing.T, n int) *stubHost {
	t.Helper()
	h := &stubHost{calls: map[string]int{}, pingFail: map[string]bool{}, n: n}
	var peers []peerRecord
	for i := 1; i <= n; i++ {
		peers = append(peers, peerRecord{ID: i, Name: fmt.Sprintf("p%d", i), RemotePub: fmt.Sprintf("198.51.100.%d", i),
			FrpPort: 7000 + i, LocalGre: fmt.Sprintf("10.20.%d.1/30", i), PeerGre: fmt.Sprintf("10.20.%d.2", i),
			GreIf: fmt.Sprintf("gre-t%d", i), FrpsSvc: fmt.Sprintf("frps-%d", i), Ports: []int{8000 + i}})
	}
	if err := os.WriteFile(peersFile(), mustJSON(map[string]any{"peers": peers}), 0o600); err != nil {
		t.Fatal(err)
	}
	proc := t.TempDir()
	_ = os.MkdirAll(filepath.Join(proc, "net"), 0o755)
	dev := "Inter-|   Receive\n face |bytes\n"
	for i := 1; i <= n; i++ {
		dev += fmt.Sprintf("  gre-t%d: 100 1 0 0 0 0 0 0 200 1 0 0 0 0 0 0\n", i)
	}
	_ = os.WriteFile(filepath.Join(proc, "net/dev"), []byte(dev), 0o644)
	oldProc, oldRunner, oldPubTime := procRoot, runner, pubIPTime
	procRoot, runner = proc, h.run
	pubIPMu.Lock()
	pubIPVal, pubIPTime = "", time.Now() // a recent failed lookup: no ip route get
	pubIPMu.Unlock()
	resetSnapshotState()
	resetExecStats()
	t.Cleanup(func() {
		snapPool.wait()
		procRoot, runner, pubIPTime = oldProc, oldRunner, oldPubTime
		resetSnapshotState()
		_ = os.Remove(peersFile())
	})
	return h
}

func TestSnapshotTickCommandsIndependentOfPeerCount(t *testing.T) {
	for _, n := range []int{1, 6, 20} {
		h := newStubHost(t, n)
		h.ss = sessionLine(1)
		if !snapshotTick() {
			t.Fatal("tick skipped")
		}
		h.reset() // first tick also fills one-off caches (frp_since, public ip)
		snapshotTick()
		want := map[string]int{"ss:-Htin": 1, "ip:tunnel": 1, "ip:-o": 1, "systemctl:is-active": 1}
		for k, v := range want {
			if got := h.get(k); got != v {
				t.Errorf("N=%d: %s ran %d times per tick, want %d", n, k, got, v)
			}
		}
		if got := h.total(); got != 4 {
			t.Errorf("N=%d: %d host commands per tick, want 4: %v", n, got, h.calls)
		}
		if h.get("ping:-c:") != 0 {
			t.Error("a tick must never ping")
		}
		s := snapPtr.Load()
		if len(s.Peers) != n || !s.Peers[0].Linked || s.Peers[0].LatencyKind != "tcp" || s.Peers[0].LatencyMs != 11.5 {
			t.Errorf("N=%d: peer 1 must be linked with tcp latency: %+v", n, s.Peers[0])
		}
		snapPool.wait()
	}
}

func TestHandlersNeverForkAndTickCostIsConstant(t *testing.T) {
	h := newStubHost(t, 6)
	h.ss = sessionLine(1) + sessionLine(2)
	snapshotTick()
	h.reset()
	snapshotTick()
	perTick := h.total()
	if perTick == 0 {
		t.Fatal("a tick must run host commands")
	}
	snapPool.wait()

	// collector paused: 200 concurrent requests across the polling handlers
	h.reset()
	dialCalls := 0
	var dmu sync.Mutex
	prev := dialFn
	dialFn = func(string, string, time.Duration) (net.Conn, error) {
		dmu.Lock()
		dialCalls++
		dmu.Unlock()
		return nil, fmt.Errorf("must not dial")
	}
	defer func() { dialFn = prev }()
	var wg sync.WaitGroup
	hs := []func(w *httptest.ResponseRecorder){
		func(w *httptest.ResponseRecorder) {
			handleDashboard(w, httptest.NewRequest("GET", "/api/dashboard", nil))
		},
		func(w *httptest.ResponseRecorder) { handleFleet(w, httptest.NewRequest("GET", "/api/fleet", nil)) },
		func(w *httptest.ResponseRecorder) { handlePeersGet(w, httptest.NewRequest("GET", "/api/peers", nil)) },
		func(w *httptest.ResponseRecorder) { handleStatus(w, httptest.NewRequest("GET", "/api/status", nil)) },
	}
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rr := httptest.NewRecorder()
			hs[i%len(hs)](rr)
			if rr.Code != 200 || rr.Header().Get("X-Snapshot-Age-Ms") == "" {
				t.Errorf("handler %d: code %d, age header %q", i%len(hs), rr.Code, rr.Header().Get("X-Snapshot-Age-Ms"))
			}
		}(i)
	}
	wg.Wait()
	if got := h.total(); got != 0 {
		t.Fatalf("handlers forked %d commands while the collector was paused: %v", got, h.calls)
	}
	dmu.Lock()
	if dialCalls != 0 {
		t.Fatalf("handlers dialed %d times", dialCalls)
	}
	dmu.Unlock()

	// the next tick costs exactly what a tick cost before, regardless of the 200 requests
	snapshotTick()
	if got := h.total(); got != perTick {
		t.Fatalf("tick cost %d commands after request load, want %d: %v", got, perTick, h.calls)
	}
}

func TestSnapshotResponsesCarryAge(t *testing.T) {
	h := newStubHost(t, 2)
	h.ss = sessionLine(1)
	snapshotTick()
	time.Sleep(20 * time.Millisecond)
	rr := httptest.NewRecorder()
	handleFleet(rr, httptest.NewRequest("GET", "/api/fleet", nil))
	var body struct {
		Age   int64  `json:"snapshot_age_ms"`
		At    string `json:"snapshot_at"`
		Nodes []struct {
			Age     int64    `json:"snapshot_age_ms"`
			State   string   `json:"health_state"`
			Reasons []string `json:"reasons"`
		} `json:"nodes"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Age < 20 || body.At == "" || len(body.Nodes) != 2 || body.Nodes[0].Age < 20 || body.Nodes[0].State != "healthy" || len(body.Nodes[1].Reasons) == 0 {
		t.Fatalf("age/state fields wrong: %+v", body)
	}
	if rr.Header().Get("X-Snapshot-Age-Ms") == "" {
		t.Fatal("header missing")
	}
}

func TestFirstRequestBuildsOnceWithinCap(t *testing.T) {
	h := newStubHost(t, 2)
	h.ss = sessionLine(1)
	rr := httptest.NewRecorder()
	handlePeersGet(rr, httptest.NewRequest("GET", "/api/peers", nil))
	if snapPtr.Load() == nil || h.get("ss:-Htin") != 1 {
		t.Fatalf("first request must trigger one synchronous build (ss ran %d)", h.get("ss:-Htin"))
	}
	handlePeersGet(httptest.NewRecorder(), httptest.NewRequest("GET", "/api/peers", nil))
	if h.get("ss:-Htin") != 1 {
		t.Fatal("second request must not build again")
	}
}

func TestFirstRequestCapAndNoPileUp(t *testing.T) {
	h := newStubHost(t, 1)
	h.block = make(chan struct{})
	oldWait := snapFirstWait
	snapFirstWait = 60 * time.Millisecond
	defer func() { snapFirstWait = oldWait }()
	start := time.Now()
	s := currentSnapshot()
	if !s.At.IsZero() || time.Since(start) > time.Second {
		t.Fatalf("slow first build must return the empty snapshot after the cap: %+v in %v", s, time.Since(start))
	}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); currentSnapshot() }()
	}
	wg.Wait()
	if time.Since(start) > time.Second {
		t.Fatal("concurrent first requests must not queue on the slow build")
	}
	if h.get("ss:-Htin") != 1 {
		t.Fatalf("only one build may run, ss ran %d", h.get("ss:-Htin"))
	}
	close(h.block)
	deadline := time.Now().Add(2 * time.Second)
	for snapPtr.Load() == nil && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if snapPtr.Load() == nil {
		t.Fatal("the build must still complete and publish")
	}
	rr := httptest.NewRecorder()
	handleDashboard(rr, httptest.NewRequest("GET", "/api/dashboard", nil))
	if rr.Code != 200 {
		t.Fatalf("dashboard on an empty snapshot must still answer: %d", rr.Code)
	}
}

func TestSkippedTicksAreCounted(t *testing.T) {
	newStubHost(t, 1)
	snapBuilding.Store(true)
	if snapshotTick() {
		t.Fatal("tick must be skipped while the previous one runs")
	}
	snapshotTick()
	snapBuilding.Store(false)
	if snapSkipped.Load() != 2 {
		t.Fatalf("skipped=%d", snapSkipped.Load())
	}
	snapshotTick()
	rr := httptest.NewRecorder()
	handleSelfStats(rr, httptest.NewRequest("GET", "/api/selfstats", nil))
	var st struct {
		Snapshot snapStatsJSON `json:"snapshot"`
		Samplers []samplerJSON `json:"samplers"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if !st.Snapshot.Ready || st.Snapshot.SkippedTicks != 2 || st.Snapshot.Ticks != 1 || st.Snapshot.AgeMs < 0 {
		t.Fatalf("selfstats snapshot section wrong: %+v", st.Snapshot)
	}
	seen := map[string]bool{}
	for _, s := range st.Samplers {
		seen[s.Name] = true
	}
	for _, n := range []string{"snapshot", "snapshot.ss", "snapshot.ip_tunnel", "snapshot.ip_addr", "snapshot.systemctl", "snapshot.netdev", "snapshot.peers", "snapshot.traffic"} {
		if !seen[n] {
			t.Errorf("sampler %q missing from selfstats", n)
		}
	}
}

func TestICMPBackgroundPolicy(t *testing.T) {
	h := newStubHost(t, 2)
	h.pingOK = true
	h.ss = sessionLine(1) // peer 1 has a live session, peer 2 does not
	snapshotTick()
	snapPool.wait()
	if h.get("ping:-c:10.20.1.2")+h.get("ping:-c:10.20.2.2") != 0 {
		t.Fatal("snapshot ticks must not ping")
	}
	t0 := time.Now()
	passes := []time.Duration{0, 4 * time.Second, 30 * time.Second, 59 * time.Second}
	for _, d := range passes {
		snapIcmp.pass(t0.Add(d))
		snapPool.wait()
	}
	if got := h.get("ping:-c:10.20.2.2"); got != 1 {
		t.Fatalf("peer without session must be pinged once in the first minute, got %d", got)
	}
	if got := h.get("ping:-c:10.20.1.2"); got != 0 {
		t.Fatalf("peer with a live session must never be pinged, got %d", got)
	}
	snapIcmp.pass(t0.Add(75 * time.Second)) // 4s + 60s + at most 5s jitter later
	snapPool.wait()
	if got := h.get("ping:-c:10.20.2.2"); got != 2 {
		t.Fatalf("ICMP must repeat after a minute, got %d", got)
	}
	// the cached result is used by the next snapshot, no new ping needed
	h.reset()
	snapshotTick()
	p := snapPtr.Load().Peers
	if !p[1].PingOK || !p[1].ICMPKnown || h.get("ping:-c:10.20.2.2") != 0 {
		t.Fatalf("cached ICMP must be reused: %+v", p[1])
	}
	if p[0].ICMPKnown {
		t.Fatal("never-pinged live-session peer has no ICMP measurement")
	}
}

func TestICMPFilteredTagOnLiveSession(t *testing.T) {
	h := newStubHost(t, 1)
	h.pingOK = false
	// no session yet: ICMP runs once and fails
	snapshotTick()
	now := time.Now()
	snapIcmp.pass(now.Add(5 * time.Second)) // first sight only schedules (jittered)
	snapIcmp.pass(now.Add(10 * time.Second))
	snapPool.wait()
	h.ss = sessionLine(1)
	snapshotTick()
	snapshotTick() // the published state follows after two agreeing snapshots
	p := snapPtr.Load().Peers[0]
	if p.HealthState != "healthy" || !p.ICMPFiltered || p.PingOK || p.LatencyKind != "tcp" || !p.FrpOnly {
		t.Fatalf("live session + dead ICMP must be healthy, tagged, tcp latency: %+v", p)
	}
	rr := httptest.NewRecorder()
	handleDashboard(rr, httptest.NewRequest("GET", "/api/dashboard", nil))
	var d struct {
		Health   string `json:"health"`
		Filtered bool   `json:"icmp_filtered"`
		Lat      string `json:"latency_kind"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &d)
	if d.Health != "HEALTHY" || !d.Filtered || d.Lat != "tcp" {
		t.Fatalf("dashboard rollup must agree: %+v", d)
	}
}

func TestConnectProbeFeedsNextSnapshot(t *testing.T) {
	h := newStubHost(t, 2)
	h.ss = sessionLine(1) // peer 2: service active, no session
	var mu sync.Mutex
	var dialed []string
	prev := dialFn
	dialFn = func(network, addr string, d time.Duration) (net.Conn, error) {
		mu.Lock()
		dialed = append(dialed, addr)
		mu.Unlock()
		return nil, &net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
	}
	defer func() { dialFn = prev }()
	snapshotTick()
	snapPool.wait()
	snapshotTick()
	p := snapPtr.Load().Peers
	mu.Lock()
	defer mu.Unlock()
	if len(dialed) != 1 || dialed[0] != "10.20.2.2:7002" {
		t.Fatalf("only the session-less peer is probed, once: %v", dialed)
	}
	if p[1].LatencyKind != "tcp" || p[1].HealthState != "degraded" || !strings.Contains(strings.Join(p[1].Reasons, "|"), "answers TCP") {
		t.Fatalf("probe RTT must give a tcp latency without faking a session: %+v", p[1])
	}
	if p[1].Linked {
		t.Fatal("a connect probe never sets Linked")
	}
}

func TestSnapshotDebouncesPublishedState(t *testing.T) {
	h := newStubHost(t, 1)
	h.ss = sessionLine(1)
	snapshotTick()
	state := func() string { return snapPtr.Load().Peers[0].HealthState }
	if state() != "healthy" {
		t.Fatal("first observation publishes immediately")
	}
	h.mu.Lock()
	h.ss = ""
	h.mu.Unlock()
	snapshotTick()
	if state() != "healthy" {
		t.Fatal("one disagreeing snapshot must not flip the state")
	}
	h.mu.Lock()
	h.ss = sessionLine(1)
	h.mu.Unlock()
	snapshotTick() // flap back
	h.mu.Lock()
	h.ss = ""
	h.mu.Unlock()
	snapshotTick()
	if state() != "healthy" {
		t.Fatal("flapping must not flip the state")
	}
	snapshotTick()
	if state() != "degraded" {
		t.Fatalf("two consecutive snapshots must flip, got %s", state())
	}
	// fleet records the published level
	if fleetHealth(snapPtr.Load().Peers[0]) != fleetDeg {
		t.Fatal("fleetHealth must follow the published state")
	}
}

func TestParsers(t *testing.T) {
	m := parseAddrShow("1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever\n" +
		"5: gre-tunnel    inet 10.10.0.1/30 scope global gre-tunnel\\       valid_lft forever\n" +
		"6: gre-t2@NONE    inet 10.20.2.1/30 scope global gre-t2\\       valid_lft forever\n" +
		"7: eth0    inet 192.0.2.1/24 brd 192.0.2.255 scope global eth0\n7: eth0    inet 192.0.2.9/24 scope global secondary eth0\n")
	if m["gre-tunnel"] != "10.10.0.1/30" || m["gre-t2"] != "10.20.2.1/30" || m["eth0"] != "192.0.2.1/24" || len(m) != 4 {
		t.Fatalf("addr parse wrong: %v", m)
	}
	a, ok := parseIsActive([]string{"a", "b", "c"}, "active\ninactive\nactive\n")
	if !ok || !a["a"] || a["b"] || !a["c"] {
		t.Fatalf("is-active parse wrong: %v %v", a, ok)
	}
	if _, ok := parseIsActive([]string{"a", "b"}, "active\n"); ok {
		t.Fatal("line count mismatch must be reported")
	}
	d := parseNetDev("Inter-|\n face |\n  gre-t1: 100 1 0 0 0 0 0 0 200 1 0 0 0 0 0 0\n    lo: 5 1 0 0 0 0 0 0 6 1 0 0 0 0 0 0\n")
	if d["gre-t1"] != (devCounters{100, 200}) || d["lo"] != (devCounters{5, 6}) {
		t.Fatalf("netdev parse wrong: %v", d)
	}
}

func TestActiveConnsStreamsLargeTables(t *testing.T) {
	proc := t.TempDir()
	_ = os.MkdirAll(filepath.Join(proc, "net"), 0o755)
	old := procRoot
	procRoot = proc
	defer func() { procRoot = old }()
	write := func(name string, total, estab int) {
		var b strings.Builder
		b.WriteString("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n")
		for i := 0; i < total; i++ {
			st := "0A"
			if i < estab {
				st = "01"
			}
			fmt.Fprintf(&b, "%4d: 0100007F:%04X 0100007F:%04X %s 00000000:00000000 00:00000000 00000000     0        0 %d 1 0000000000000000 100 0 0 10 0\n", i, 1000+i%60000, 2000+i%60000, st, i)
		}
		if err := os.WriteFile(filepath.Join(proc, "net", name), []byte(b.String()), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("tcp", 300000, 120000)
	write("tcp6", 50000, 7000)
	write("udp", 1000, 3)
	got, ok := activeConns().(int)
	if !ok || got != 127003 {
		t.Fatalf("activeConns=%v want 127003 (missing udp6 is fine)", activeConns())
	}
	procRoot = t.TempDir()
	if activeConns() != nil {
		t.Fatal("no /proc/net files must give null, like a failed ss did")
	}
}

func TestWorkPoolBoundsConcurrencyAndDedupes(t *testing.T) {
	p := newWorkPool(3)
	var mu sync.Mutex
	cur, peak := 0, 0
	release := make(chan struct{})
	for i := 0; i < 12; i++ {
		p.submit(fmt.Sprint("k", i), time.Second, func() {
			mu.Lock()
			cur++
			if cur > peak {
				peak = cur
			}
			mu.Unlock()
			<-release
			mu.Lock()
			cur--
			mu.Unlock()
		})
	}
	p.submit("k0", time.Second, func() { t.Error("duplicate key must be dropped while queued") })
	time.Sleep(50 * time.Millisecond)
	close(release)
	p.wait()
	if peak != 3 {
		t.Fatalf("pool of 3 ran %d at once", peak)
	}
}

func TestWorkPoolHardTimeout(t *testing.T) {
	p := newWorkPool(1)
	block := make(chan struct{})
	defer close(block)
	start := time.Now()
	p.submit("slow", 50*time.Millisecond, func() { <-block })
	p.wait()
	if time.Since(start) > time.Second {
		t.Fatal("a stuck task must be abandoned at its timeout")
	}
}

func TestJitterIsStableAndBounded(t *testing.T) {
	for _, k := range []string{"a", "10.20.1.2", "x"} {
		if jitter(k, 3*time.Second) != jitter(k, 3*time.Second) || jitter(k, 3*time.Second) >= 3*time.Second {
			t.Fatalf("jitter(%q) unstable or out of range", k)
		}
	}
	if jitter("10.20.1.2", time.Hour) == jitter("10.20.2.2", time.Hour) {
		t.Fatal("different peers must get different offsets")
	}
}
