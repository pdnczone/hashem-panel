package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// pipeDial returns a dialFn whose far end runs serve; every dial is counted and
// its address recorded.
func pipeDial(t *testing.T, serve func(c net.Conn)) (*atomic.Int32, *[]string) {
	t.Helper()
	var n atomic.Int32
	var mu sync.Mutex
	var addrs []string
	prev := dialFn
	dialFn = func(network, addr string, timeout time.Duration) (net.Conn, error) {
		n.Add(1)
		mu.Lock()
		addrs = append(addrs, addr)
		mu.Unlock()
		if serve == nil {
			return nil, errors.New("connection refused")
		}
		a, b := net.Pipe()
		go func() { defer b.Close(); serve(b) }()
		return a, nil
	}
	t.Cleanup(func() { dialFn = prev })
	return &n, &addrs
}

func withBinaries(t *testing.T, names ...string) {
	t.Helper()
	dir := t.TempDir()
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	oldDirs, oldExtra := engineBinDirs, backhaulExtraBins
	engineBinDirs, backhaulExtraBins = []string{dir}, nil
	t.Cleanup(func() { engineBinDirs, backhaulExtraBins = oldDirs, oldExtra })
}

func banner(c net.Conn)   { _, _ = c.Write([]byte("SSH-2.0-test\r\n")) }
func echo(c net.Conn)     { b := make([]byte, 64); n, _ := c.Read(b); _, _ = c.Write(b[:n]) }
func silent(c net.Conn)   { _, _ = io.Copy(io.Discard, c) }
func slamShut(c net.Conn) {}

func okTarget() thTarget {
	return thTarget{id: 1, name: "p1", engine: "frp", role: "peer", unit: "frps-1", svcUp: true, linked: true,
		latMs: 12.5, latKind: "tcp", ctrlPort: 7001, ports: []int{8001}, hosts: []string{"127.0.0.1"}}
}

func TestTunnelHealthVerdicts(t *testing.T) {
	withBinaries(t, "frps", "backhaul")
	cases := []struct {
		name    string
		mod     func(*thTarget)
		serve   func(net.Conn)
		verdict string
		layers  TunnelLayers
		reason  string
	}{
		{"pass banner", nil, banner, VerdictPass, TunnelLayers{layerOK, layerOK, layerOK}, "banner"},
		{"pass echo", nil, echo, VerdictPass, TunnelLayers{layerOK, layerOK, layerOK}, "data path OK on port 8001"},
		{"pass held open", nil, silent, VerdictPass, TunnelLayers{layerOK, layerOK, layerOK}, "held open"},
		{"data fail while session live", nil, slamShut, VerdictFail, TunnelLayers{layerOK, layerOK, layerFail}, "data probe on port 8001 failed"},
		{"data dial refused", nil, nil, VerdictFail, TunnelLayers{layerOK, layerOK, layerFail}, "data probe"},
		{"service down", func(x *thTarget) { x.svcUp, x.linked = false, false }, banner, VerdictFail, TunnelLayers{layerFail, layerSkipped, layerSkipped}, "frps-1 is configured but not active"},
		{"session absent, peer pings", func(x *thTarget) { x.linked, x.icmpOK = false, true }, banner, VerdictFail, TunnelLayers{layerOK, layerFail, layerSkipped}, "session expected but absent"},
		{"session absent, cached tcp probe", func(x *thTarget) { x.linked, x.probeCached = false, true }, banner, VerdictFail, TunnelLayers{layerOK, layerFail, layerSkipped}, "peer answers TCP"},
		{"nothing answers", func(x *thTarget) { x.linked = false }, nil, VerdictUnreachable, TunnelLayers{layerOK, layerUnknown, layerSkipped}, "peer not answering on any path — cannot tell engine health"},
		{"binary missing frp", func(x *thTarget) { x.unit = "frpc" }, banner, VerdictFail, TunnelLayers{layerFail, layerSkipped, layerSkipped}, "engine binary missing (frpc"},
		{"control port only", func(x *thTarget) { x.ports = nil }, banner, VerdictPass, TunnelLayers{layerOK, layerOK, layerSkipped}, "no forwarded port to probe — control port only"},
		{"control port only unreachable", func(x *thTarget) { x.ports = nil }, nil, VerdictFail, TunnelLayers{layerOK, layerOK, layerFail}, "control port only"},
		{"backhaul ok", func(x *thTarget) { x.engine, x.unit = "backhaul", "frps-2" }, echo, VerdictPass, TunnelLayers{layerOK, layerOK, layerOK}, ""},
		{"live session, no address", func(x *thTarget) { x.hosts = nil }, echo, VerdictUnreachable, TunnelLayers{layerOK, layerOK, layerUnknown}, "no address to probe"},
		{"no unit configured", func(x *thTarget) { x.svcUp, x.linked, x.unit = false, false, "" }, banner, VerdictFail, TunnelLayers{layerFail, layerSkipped, layerSkipped}, "no tunnel service configured"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pipeDial(t, c.serve)
			tg := okTarget()
			if c.mod != nil {
				c.mod(&tg)
			}
			e := checkTunnel(tg, "now")
			if e.Verdict != c.verdict || e.Layers != c.layers || !strings.Contains(e.Reason, c.reason) {
				t.Fatalf("got %s %+v %q; want %s %+v containing %q", e.Verdict, e.Layers, e.Reason, c.verdict, c.layers, c.reason)
			}
		})
	}
}

func TestTunnelHealthBackhaulBinaryMissing(t *testing.T) {
	withBinaries(t, "frps") // no backhaul
	pipeDial(t, banner)
	tg := okTarget()
	tg.engine = "gre-backhaul"
	e := checkTunnel(tg, "now")
	if e.Verdict != VerdictFail || e.Layers.Service != layerFail || !strings.Contains(e.Reason, "engine binary missing (backhaul") {
		t.Fatalf("got %s %+v %q", e.Verdict, e.Layers, e.Reason)
	}
}

// A host that connects but slams shut must not mask a healthy second host.
func TestTunnelHealthMultiHostFallback(t *testing.T) {
	withBinaries(t, "frps")
	prev := dialFn
	calls := 0
	dialFn = func(network, addr string, timeout time.Duration) (net.Conn, error) {
		calls++
		if strings.HasSuffix(addr, ":8001") && calls == 1 {
			a, b := net.Pipe()
			b.Close() // immediate close, no input
			return a, nil
		}
		a, b := net.Pipe()
		go func() { defer b.Close(); echo(b) }()
		return a, nil
	}
	defer func() { dialFn = prev }()
	tg := okTarget()
	tg.hosts = []string{"10.0.0.1", "10.0.0.2"}
	e := checkTunnel(tg, "now")
	if e.Verdict != VerdictPass {
		t.Fatalf("second host must rescue the probe: got %s %q", e.Verdict, e.Reason)
	}
	if calls != 2 {
		t.Fatalf("both hosts must be tried, got %d dials", calls)
	}
}

func TestTunnelHealthEngineDerivation(t *testing.T) {
	for _, c := range []struct {
		declared, unit string
		gre            bool
		want           string
	}{
		{"", "frps", false, "frp"}, {"", "backhaul-server", false, "backhaul"}, {"", "backhaul-client", true, "gre-backhaul"},
		{"gre-backhaul", "frps-1", false, "gre-backhaul"}, {"weird", "frps-2", false, "frp"},
	} {
		if got := thEngine(c.declared, c.unit, c.gre); got != c.want {
			t.Errorf("thEngine(%q,%q,%v)=%q want %q", c.declared, c.unit, c.gre, got, c.want)
		}
	}
}

func liveSnapshot(peers ...peerLive) *HubSnapshot {
	return &HubSnapshot{At: time.Now(), Peers: peers}
}

func peerFor(id int, svc, engine string, up, linked bool, ports ...int) peerLive {
	return peerLive{peerRecord: peerRecord{ID: id, Name: "p" + string(rune('0'+id)), FrpsSvc: svc, Engine: engine, FrpPort: 7000 + id, RemotePub: "198.51.100." + string(rune('0'+id)), Ports: ports},
		FrpUp: up, Linked: linked, LatencyMs: -1}
}

func installSnapshot(t *testing.T, s *HubSnapshot) {
	t.Helper()
	resetSnapshotState()
	resetTunnelHealth()
	snapPtr.Store(s)
	t.Cleanup(func() { resetSnapshotState(); resetTunnelHealth() })
}

func TestTunnelHealthRunMixedFleet(t *testing.T) {
	withBinaries(t, "frps", "backhaul")
	pipeDial(t, banner)
	main := peerFor(mainTunnelID, "frps", "frp", true, true, 443)
	s := liveSnapshot(
		peerFor(1, "frps-1", "frp", true, true, 8001),
		peerFor(2, "backhaul-server", "backhaul", false, false, 8002),
		peerFor(3, "frps-3", "frp", true, false, 8003), // no session, but its host answers TCP
	)
	s.Main = &main
	s.Local.FrpSvc = "frps"
	installSnapshot(t, s)

	res := tunnelHealthRefresh(true)
	if len(res.Tunnels) != 4 {
		t.Fatalf("want 4 tunnels (base + 3 peers), got %d", len(res.Tunnels))
	}
	by := map[int]TunnelHealthEntry{}
	for _, e := range res.Tunnels {
		by[e.ID] = e
	}
	if by[mainTunnelID].Verdict != VerdictPass || by[mainTunnelID].Role != "hub" {
		t.Errorf("base: %+v", by[mainTunnelID])
	}
	if by[1].Verdict != VerdictPass || by[1].Engine != "frp" {
		t.Errorf("p1: %+v", by[1])
	}
	if by[2].Verdict != VerdictFail || by[2].Engine != "backhaul" || by[2].Layers.Service != layerFail {
		t.Errorf("p2: %+v", by[2])
	}
	if by[3].Verdict != VerdictFail || by[3].Layers.Session != layerFail {
		t.Errorf("p3: %+v", by[3])
	}
	if res.SnapshotAgeMs < 0 {
		t.Errorf("snapshot age %d", res.SnapshotAgeMs)
	}
}

func TestTunnelHealthUnreachablePeerEndToEnd(t *testing.T) {
	withBinaries(t, "frps")
	dials, _ := pipeDial(t, nil) // everything refused
	installSnapshot(t, liveSnapshot(peerFor(1, "frps-1", "frp", true, false, 8001)))
	res := tunnelHealthRefresh(true)
	if len(res.Tunnels) != 1 || res.Tunnels[0].Verdict != VerdictUnreachable {
		t.Fatalf("got %+v", res.Tunnels)
	}
	if dials.Load() == 0 {
		t.Fatal("expected a connect probe before declaring UNREACHABLE")
	}
}

func TestTunnelHealthCacheTTLAndForce(t *testing.T) {
	withBinaries(t, "frps")
	dials, _ := pipeDial(t, banner)
	installSnapshot(t, liveSnapshot(peerFor(1, "frps-1", "frp", true, true, 8001)))

	first := tunnelHealthRefresh(false)
	n := dials.Load()
	for i := 0; i < 5; i++ {
		if got := tunnelHealthRefresh(false); got != first {
			t.Fatal("fresh cache must be reused")
		}
	}
	if dials.Load() != n {
		t.Fatalf("repeated GETs re-probed: %d -> %d", n, dials.Load())
	}
	if forced := tunnelHealthRefresh(true); forced == first || dials.Load() == n {
		t.Fatal("forced refresh must re-probe")
	}
	tunnelHealthMu.Lock()
	tunnelHealthLast.checkedAt = time.Now().Add(-2 * tunnelHealthTTL)
	tunnelHealthMu.Unlock()
	before := dials.Load()
	tunnelHealthRefresh(false)
	if dials.Load() == before {
		t.Fatal("expired cache must be refreshed")
	}
}

func TestTunnelHealthNoSnapshotNotCached(t *testing.T) {
	resetSnapshotState()
	resetTunnelHealth()
	snapGaveUp.Store(time.Now().UnixNano()) // currentSnapshot returns the empty snapshot
	defer resetSnapshotState()
	res := tunnelHealthRefresh(true)
	if len(res.Tunnels) != 0 || res.SnapshotAgeMs != -1 {
		t.Fatalf("got %+v", res)
	}
	if tunnelHealthCached() != nil {
		t.Fatal("a result made without a snapshot must not be cached")
	}
}

func TestTunnelHealthConcurrentRunsCollapse(t *testing.T) {
	withBinaries(t, "frps")
	dials, _ := pipeDial(t, banner)
	installSnapshot(t, liveSnapshot(peerFor(1, "frps-1", "frp", true, true, 8001)))
	// Eight forced callers queue behind the run lock; the first one's run
	// (started after all of them arrived) serves everybody.
	tunnelHealthRun.Lock()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); tunnelHealthRefresh(true) }()
	}
	time.Sleep(100 * time.Millisecond)
	tunnelHealthRun.Unlock()
	wg.Wait()
	if got := dials.Load(); got != 1 { // one peer, one data probe, one run
		t.Fatalf("8 queued forced runs dialed %d times, want 1", got)
	}
}

func TestTunnelHealthHandlersAndNoFork(t *testing.T) {
	withBinaries(t, "frps")
	pipeDial(t, echo)
	installSnapshot(t, liveSnapshot(peerFor(1, "frps-1", "frp", true, true, 8001)))
	var forks atomic.Int32
	prev := runner
	runner = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		forks.Add(1)
		return nil, errors.New("must not fork")
	}
	defer func() { runner = prev }()

	rr := httptest.NewRecorder()
	handleTunnelHealthGet(rr, httptest.NewRequest("GET", "/api/tunnel-health?cached=1", nil))
	var empty tunnelHealthResult
	if err := json.Unmarshal(rr.Body.Bytes(), &empty); err != nil || len(empty.Tunnels) != 0 || !strings.Contains(rr.Body.String(), `"tunnels":[]`) {
		t.Fatalf("cached-only GET before any run: %s", rr.Body.String())
	}

	rr = httptest.NewRecorder()
	handleTunnelHealthRun(rr, httptest.NewRequest("POST", "/api/tunnel-health/run", nil))
	var got struct {
		Tunnels []map[string]any `json:"tunnels"`
		Checked string           `json:"checked"`
		Age     int64            `json:"snapshot_age_ms"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil || len(got.Tunnels) != 1 || got.Checked == "" {
		t.Fatalf("run: %v %s", err, rr.Body.String())
	}
	for _, k := range []string{"id", "name", "engine", "role", "verdict", "latency_ms", "latency_kind", "layers", "reason", "checked"} {
		if _, ok := got.Tunnels[0][k]; !ok {
			t.Errorf("tunnel JSON missing %q", k)
		}
	}
	rr = httptest.NewRecorder()
	handleTunnelHealthGet(rr, httptest.NewRequest("GET", "/api/tunnel-health", nil))
	if !strings.Contains(rr.Body.String(), `"verdict":"PASS"`) {
		t.Fatalf("GET: %s", rr.Body.String())
	}
	if forks.Load() != 0 {
		t.Fatalf("tunnel health forked %d host commands", forks.Load())
	}
}

func TestTunnelHealthRoutingPolicy(t *testing.T) {
	for _, p := range []string{"/api/tunnel-health", "/api/tunnel-health/run"} {
		if !isLongRunning(httptest.NewRequest("GET", p, nil)) {
			t.Errorf("GET %s must be exempt from the write deadline", p)
		}
	}
	if !isLongRunning(httptest.NewRequest("POST", "/api/tunnel-health/run", nil)) {
		t.Error("POST run must be exempt (non-GETs are)")
	}
	b, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`"GET "+base+"/api/tunnel-health", requireAuth(handleTunnelHealthGet)`,
		`"POST "+base+"/api/tunnel-health/run", requireAuth(requireCSRF(handleTunnelHealthRun))`,
	} {
		if !strings.Contains(string(b), want) {
			t.Errorf("main.go missing route %s", want)
		}
	}
}

// The engine-switch hook must be fire-and-forget and gated by the auto-run flag.
func TestTunnelHealthSwitchHook(t *testing.T) {
	b, err := os.ReadFile("tunnel.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "\tgo runTunnelHealthOnce()\n\n\treturn outMsg.String(), nil") {
		t.Error("switchTunnelEngine must `go runTunnelHealthOnce()` just before its success return")
	}
	resetTunnelHealth()
	start := time.Now()
	runTunnelHealthOnce() // flag is off in tests: returns at once, writes nothing
	if time.Since(start) > time.Second || tunnelHealthCached() != nil {
		t.Fatal("runTunnelHealthOnce must be inert while tunnelHealthAutoRun is false")
	}
	if _, err := switchTunnelEngine("invalid_engine", "tcp"); err == nil {
		t.Fatal("invalid engine must still be rejected")
	}
}
