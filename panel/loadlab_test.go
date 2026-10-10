package main

// Load lab: measures what the panel does under N fake spokes and C polling
// browsers, entirely in-process (stub command runner + httptest + temp dirs).
// Skipped unless HASHEM_LOADLAB=1. Run with a generous timeout:
//
//	HASHEM_LOADLAB=1 go test -count=1 -timeout 30m -run LoadLab -v ./...
//
// Knobs: HASHEM_LOADLAB_SECS (cell length, default 8), HASHEM_LOADLAB_SS_LINES
// (established sockets on the fake hub, default 20000), HASHEM_LOADLAB_PING_MS
// (how long a dropped ICMP probe blocks, default 2000 like ping -W 2),
// HASHEM_LOADLAB_OUT (CSV path), HASHEM_LOADLAB_N / _C (comma lists).
//
// Not modelled: real fork/exec cost (the stub returns instantly, so the
// numbers understate it), kernel conntrack/GRE load, frps CPU, RAM pressure,
// lossy client links, browsers whose setInterval overlaps slow requests.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type labScenario struct {
	n       int
	clients int
	dropped bool // ICMP dropped: ping blocks then fails
	ssLines int
}

type labResult struct {
	sc                       labScenario
	secs                     float64
	routes                   map[string]routeJSON
	livePeers, fleetTick     samplerJSON
	calls                    map[string]uint64
	gBase, gPeak, gAfter     int
	heapBase, heapPeak       uint64
	fdBase, fdPeak, fdAfter  int
	completed, inflightAtEnd int64
	oldestInflightMs         float64
}

// labHost is the fake kernel/host behind the stub runner.
type labHost struct {
	sc      labScenario
	stop    context.Context
	pingDur time.Duration
	ssTin   []byte
	ssTun   []byte
	mu      sync.Mutex
	calls   map[string]uint64
}

func (h *labHost) count(k string) {
	h.mu.Lock()
	h.calls[k]++
	h.mu.Unlock()
}

func labSocketTables(n, m int) (tin, tun []byte) {
	var a, b strings.Builder
	b.WriteString("Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port\n")
	for i := 1; i <= n; i++ {
		fmt.Fprintf(&a, "0 0 10.20.%d.1:%d 10.20.%d.2:%d\n\t cubic wscale:7,7 rto:204 rtt:%d.5/2.1 mss:1328 cwnd:10\n", i, 7000+i, i, 40000+i, 10+i)
		fmt.Fprintf(&b, "tcp ESTAB 0 0 10.20.%d.1:%d 10.20.%d.2:%d\n", i, 7000+i, i, 40000+i)
	}
	for j := 0; j < m; j++ {
		l := fmt.Sprintf("192.0.2.10:%d 203.0.113.%d:%d", 20000+j%10000, j%250+1, 1024+j%60000)
		fmt.Fprintf(&a, "0 0 %s\n\t cubic wscale:7,7 rto:204 rtt:%d.25/9.5 ato:40 mss:1448 cwnd:10 bytes_sent:%d\n", l, 30+j%200, j*13)
		fmt.Fprintf(&b, "tcp ESTAB 0 0 %s\n", l)
	}
	return []byte(a.String()), []byte(b.String())
}

func (h *labHost) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	key := name
	if len(args) > 0 {
		key += ":" + args[0]
	}
	h.count(key)
	switch name {
	case "ip":
		if len(args) >= 2 && args[0] == "tunnel" {
			var b strings.Builder
			b.WriteString("gre0: gre/ip remote any local any ttl inherit nopmtudisc\ngre-tunnel: gre/ip remote 198.51.100.200 local 192.0.2.10 ttl inherit\n")
			for i := 1; i <= h.sc.n; i++ {
				fmt.Fprintf(&b, "gre-t%d: gre/ip remote 198.51.100.%d local 192.0.2.10 ttl inherit\n", i, i)
			}
			return []byte(b.String()), nil
		}
		if len(args) >= 5 && args[0] == "-4" {
			dev := args[4]
			if dev == "gre-tunnel" {
				return []byte("5: gre-tunnel: <POINTOPOINT,NOARP,UP>\n    inet 10.10.0.1/30 scope global gre-tunnel\n"), nil
			}
			var i int
			if _, err := fmt.Sscanf(dev, "gre-t%d", &i); err == nil {
				return []byte(fmt.Sprintf("6: %s: <POINTOPOINT,NOARP,UP>\n    inet 10.20.%d.1/30 scope global %s\n", dev, i, dev)), nil
			}
		}
	case "systemctl":
		if len(args) == 2 && args[0] == "is-active" {
			if args[1] == "frps" || strings.HasPrefix(args[1], "frps-") {
				return []byte("active\n"), nil
			}
			return []byte("inactive\n"), fmt.Errorf("exit status 3")
		}
	case "ss":
		if len(args) > 0 && args[0] == "-Htin" {
			return h.ssTin, nil
		}
		return h.ssTun, nil
	case "ping":
		if h.sc.dropped {
			select {
			case <-time.After(h.pingDur):
			case <-ctx.Done():
			case <-h.stop.Done():
			}
			return []byte("100% packet loss"), fmt.Errorf("exit status 1")
		}
		return []byte("64 bytes from x: icmp_seq=1 ttl=64 time=1.2 ms"), nil
	}
	return nil, fmt.Errorf("labHost: unexpected command %s %v", name, args)
}

func envInt(name string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(name)); err == nil && v >= 0 {
		return v
	}
	return def
}

func envIntList(name string, def []int) []int {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	var out []int
	for _, s := range strings.Split(v, ",") {
		if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil && n > 0 {
			out = append(out, n)
		}
	}
	return out
}

func labWritePeers(t *testing.T, n int) {
	var peers []peerRecord
	for i := 1; i <= n; i++ {
		peers = append(peers, peerRecord{ID: i, Name: fmt.Sprintf("spoke-%d", i), LocalPub: "192.0.2.10",
			RemotePub: fmt.Sprintf("198.51.100.%d", i), FrpPort: 7000 + i, LocalGre: fmt.Sprintf("10.20.%d.1/30", i),
			PeerGre: fmt.Sprintf("10.20.%d.2", i), GreIf: fmt.Sprintf("gre-t%d", i), FrpsSvc: fmt.Sprintf("frps-%d", i), Ports: []int{8000 + i}})
	}
	if err := os.WriteFile(peersFile(), mustJSON(map[string]any{"peers": peers}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func labMux(base string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+base+"/api/dashboard", requireAuth(handleDashboard))
	mux.HandleFunc("GET "+base+"/api/fleet", requireAuth(handleFleet))
	mux.HandleFunc("GET "+base+"/api/peers", requireAuth(handlePeersGet))
	mux.HandleFunc("GET "+base+"/api/selfstats", requireAuth(handleSelfStats))
	return metricsMiddleware(securityMiddleware(mux))
}

func runLabCell(t *testing.T, sc labScenario, secs int, pingDur time.Duration, tin, tun []byte) labResult {
	labWritePeers(t, sc.n)
	stop, cancelStop := context.WithCancel(context.Background())
	host := &labHost{sc: sc, stop: stop, pingDur: pingDur, ssTin: tin, ssTun: tun, calls: map[string]uint64{}}
	oldRunner := runner
	runner = host.run
	defer func() { runner = oldRunner }()
	resetExecStats()
	resetRouteStats()
	resetSamplerStats()
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	base := runtime.NumGoroutine()
	ps0 := readProcStats()

	srv := httptest.NewServer(labMux("/" + cfg.BasePath))
	token := newSessionToken()
	addSession(token)
	var completed, inflight atomic.Int64
	starts := sync.Map{}

	clientCtx, cancelClients := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	cl := &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: 4}}
	poll := func(path string) {
		defer wg.Done()
		for clientCtx.Err() == nil {
			req, _ := http.NewRequestWithContext(clientCtx, "GET", srv.URL+"/"+cfg.BasePath+path, nil)
			req.AddCookie(&http.Cookie{Name: "gre_session", Value: token})
			id := new(int)
			starts.Store(id, time.Now())
			inflight.Add(1)
			resp, err := cl.Do(req)
			inflight.Add(-1)
			starts.Delete(id)
			if err == nil {
				_, _ = readAll(resp)
				completed.Add(1)
			}
			select {
			case <-time.After(50 * time.Millisecond):
			case <-clientCtx.Done():
			}
		}
	}
	for c := 0; c < sc.clients; c++ {
		for _, p := range []string{"/api/dashboard", "/api/fleet", "/api/peers"} {
			wg.Add(1)
			go poll(p)
		}
	}

	// fleet sampler equivalent (15s real -> 150ms), same body as startFleetSampler
	tickDone := make(chan struct{})
	go func() {
		defer close(tickDone)
		tick := func() {
			defer func(t time.Time) { recordSampler("fleetSampler", time.Since(t)) }(time.Now())
			peers := livePeers()
			if m := mainTunnelLive(); m != nil {
				peers = append([]peerLive{*m}, peers...)
			}
			fleetRemember(peers)
			fleetRecord(peers, time.Now())
		}
		tk := time.NewTicker(150 * time.Millisecond)
		defer tk.Stop()
		for {
			tick()
			select {
			case <-tk.C:
			case <-clientCtx.Done():
				return
			}
		}
	}()

	// peak sampler
	var peakMu sync.Mutex
	gPeak, fdPeak, heapPeak := base, ps0.OpenFDs, ps0.HeapAlloc
	peakDone := make(chan struct{})
	go func() {
		defer close(peakDone)
		tk := time.NewTicker(100 * time.Millisecond)
		defer tk.Stop()
		for {
			select {
			case <-tk.C:
				g := runtime.NumGoroutine()
				var m runtime.MemStats
				runtime.ReadMemStats(&m)
				fd := readProcStats().OpenFDs
				peakMu.Lock()
				if g > gPeak {
					gPeak = g
				}
				if fd > fdPeak {
					fdPeak = fd
				}
				if m.HeapAlloc > heapPeak {
					heapPeak = m.HeapAlloc
				}
				peakMu.Unlock()
			case <-clientCtx.Done():
				return
			}
		}
	}()

	time.Sleep(time.Duration(secs) * time.Second)

	// snapshot BEFORE aborting stubs so cancelled work is not recorded as fast
	res := labResult{sc: sc, secs: float64(secs), routes: map[string]routeJSON{}, calls: map[string]uint64{}}
	for _, r := range routeSnapshot() {
		res.routes[strings.TrimPrefix(r.Route, "/{base}")] = r
	}
	for _, s := range samplerSnapshot() {
		switch s.Name {
		case "livePeers":
			res.livePeers = s
		case "fleetSampler":
			res.fleetTick = s
		}
	}
	host.mu.Lock()
	for k, v := range host.calls {
		res.calls[k] = v
	}
	host.mu.Unlock()
	res.completed = completed.Load()
	res.inflightAtEnd = inflight.Load()
	starts.Range(func(_, v any) bool {
		if age := ms(time.Since(v.(time.Time))); age > res.oldestInflightMs {
			res.oldestInflightMs = age
		}
		return true
	})

	cancelStop()
	cancelClients()
	wg.Wait()
	<-tickDone
	<-peakDone
	srv.CloseClientConnections()
	srv.Close()
	cl.CloseIdleConnections()

	// leak check: goroutines must return to baseline once everything stopped
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) && (inFlight.Load() != 0 || runtime.NumGoroutine() > base+5) {
		time.Sleep(100 * time.Millisecond)
	}
	runtime.GC()
	ps1 := readProcStats()
	peakMu.Lock()
	res.gBase, res.gPeak, res.gAfter = base, gPeak, ps1.Goroutines
	res.heapBase, res.heapPeak = ps0.HeapAlloc, heapPeak
	res.fdBase, res.fdPeak, res.fdAfter = ps0.OpenFDs, fdPeak, ps1.OpenFDs
	peakMu.Unlock()
	if inFlight.Load() != 0 {
		t.Errorf("%+v: %d requests still in flight after stop", sc, inFlight.Load())
	}
	if res.gAfter > base+5 {
		t.Errorf("%+v: goroutine leak: baseline %d, after %d", sc, base, res.gAfter)
	}
	if base >= 0 && res.fdBase >= 0 && res.fdAfter > res.fdBase+5 {
		t.Errorf("%+v: fd leak: baseline %d, after %d", sc, res.fdBase, res.fdAfter)
	}
	return res
}

func readAll(resp *http.Response) (int64, error) {
	defer resp.Body.Close()
	var n int64
	buf := make([]byte, 32<<10)
	for {
		k, err := resp.Body.Read(buf)
		n += int64(k)
		if err != nil {
			return n, nil
		}
	}
}

var labCSVHeader = []string{"N", "clients", "icmp", "ss_lines", "secs",
	"dash_n", "dash_p50_ms", "dash_p95_ms", "dash_p99_ms",
	"fleet_n", "fleet_p50_ms", "fleet_p95_ms", "fleet_p99_ms",
	"peers_n", "peers_p50_ms", "peers_p95_ms", "peers_p99_ms",
	"livepeers_runs", "livepeers_avg_ms", "livepeers_max_ms", "fleet_tick_avg_ms", "fleet_tick_max_ms",
	"ip_per_min", "systemctl_per_min", "ss_tin_per_min", "ss_tun_per_min", "ping_per_min",
	"goroutines_base", "goroutines_peak", "goroutines_after", "heap_base_mb", "heap_peak_mb", "fd_base", "fd_peak", "fd_after",
	"completed_reqs", "inflight_at_end", "oldest_inflight_ms"}

func (r labResult) csvRow() []string {
	f := func(v float64) string { return strconv.FormatFloat(v, 'f', 1, 64) }
	icmp := "ok"
	if r.sc.dropped {
		icmp = "dropped"
	}
	perMin := func(prefix string) string {
		var n uint64
		for k, v := range r.calls {
			if strings.HasPrefix(k, prefix) {
				n += v
			}
		}
		return f(float64(n) * 60 / r.secs)
	}
	row := []string{strconv.Itoa(r.sc.n), strconv.Itoa(r.sc.clients), icmp, strconv.Itoa(r.sc.ssLines), f(r.secs)}
	for _, p := range []string{"/api/dashboard", "/api/fleet", "/api/peers"} {
		x := r.routes[p]
		row = append(row, strconv.FormatUint(x.Count, 10), f(x.P50Ms), f(x.P95Ms), f(x.P99Ms))
	}
	row = append(row, strconv.FormatUint(r.livePeers.Runs, 10), f(r.livePeers.AvgDurationMs), f(r.livePeers.MaxDurationMs),
		f(r.fleetTick.AvgDurationMs), f(r.fleetTick.MaxDurationMs),
		perMin("ip:"), perMin("systemctl:"), perMin("ss:-Htin"), perMin("ss:-tun"), perMin("ping:"),
		strconv.Itoa(r.gBase), strconv.Itoa(r.gPeak), strconv.Itoa(r.gAfter),
		f(float64(r.heapBase)/1e6), f(float64(r.heapPeak)/1e6),
		strconv.Itoa(r.fdBase), strconv.Itoa(r.fdPeak), strconv.Itoa(r.fdAfter),
		strconv.FormatInt(r.completed, 10), strconv.FormatInt(r.inflightAtEnd, 10), f(r.oldestInflightMs))
	return row
}

func TestLoadLab(t *testing.T) {
	if os.Getenv("HASHEM_LOADLAB") != "1" {
		t.Skip("set HASHEM_LOADLAB=1 to run the load lab")
	}
	labLowerPriority()
	oldProcs := runtime.GOMAXPROCS(1) // never starve a live host: one P, nice 19
	defer runtime.GOMAXPROCS(oldProcs)
	oldMem := debug.SetMemoryLimit(768 << 20)
	defer debug.SetMemoryLimit(oldMem)
	// Any exec that bypasses the stub (direct exec.Command in handlers) fails
	// fast: nothing on the host is ever invoked.
	t.Setenv("PATH", t.TempDir())

	oldCfg := cfg
	cfg.BasePath = "labbase"
	defer func() { cfg = oldCfg }()
	secs := envInt("HASHEM_LOADLAB_SECS", 8)
	m := envInt("HASHEM_LOADLAB_SS_LINES", 20000)
	pingDur := time.Duration(envInt("HASHEM_LOADLAB_PING_MS", 2000)) * time.Millisecond
	ns := envIntList("HASHEM_LOADLAB_N", []int{1, 3, 6, 10, 20})
	cs := envIntList("HASHEM_LOADLAB_C", []int{1, 3, 10})

	var scenarios []labScenario
	for _, n := range ns {
		for _, c := range cs {
			for _, dropped := range []bool{false, true} {
				scenarios = append(scenarios, labScenario{n: n, clients: c, dropped: dropped, ssLines: m})
			}
		}
	}
	// baseline without a loaded socket table: isolates the ss cost
	scenarios = append(scenarios, labScenario{n: 6, clients: 3, ssLines: 0}, labScenario{n: 6, clients: 3, dropped: true, ssLines: 0})

	tables := map[int][2][]byte{}
	var rows [][]string
	var results []labResult
	for _, sc := range scenarios {
		tb, ok := tables[sc.ssLines+sc.n*1000000]
		if !ok {
			a, b := labSocketTables(sc.n, sc.ssLines)
			tb = [2][]byte{a, b}
			tables[sc.ssLines+sc.n*1000000] = tb
		}
		cell := secs
		if sc.dropped {
			// a dropped-ICMP request takes ~(N+3) blocking pings; give it a
			// chance to finish at small N (capped to keep the lab bounded)
			if need := int(time.Duration(sc.n+3) * pingDur / time.Second); need > cell {
				cell = min(need, 20)
			}
		}
		r := runLabCell(t, sc, cell, pingDur, tb[0], tb[1])
		results = append(results, r)
		rows = append(rows, r.csvRow())
		t.Logf("N=%-2d C=%-2d icmp=%-7v ss=%-5d | dash p50/p95/p99=%6.0f/%6.0f/%6.0f ms (n=%d) fleet p95=%5.1f peers p95=%6.0f | livePeers avg/max=%6.0f/%6.0f ms | inflight@end=%d oldest=%.0fms | G %d->%d->%d FD %d->%d->%d heap %.0f->%.0fMB",
			sc.n, sc.clients, !sc.dropped, sc.ssLines,
			r.routes["/api/dashboard"].P50Ms, r.routes["/api/dashboard"].P95Ms, r.routes["/api/dashboard"].P99Ms, r.routes["/api/dashboard"].Count,
			r.routes["/api/fleet"].P95Ms, r.routes["/api/peers"].P95Ms, r.livePeers.AvgDurationMs, r.livePeers.MaxDurationMs,
			r.inflightAtEnd, r.oldestInflightMs, r.gBase, r.gPeak, r.gAfter, r.fdBase, r.fdPeak, r.fdAfter,
			float64(r.heapBase)/1e6, float64(r.heapPeak)/1e6)
	}

	out := os.Getenv("HASHEM_LOADLAB_OUT")
	if out == "" {
		out = filepath.Join(t.TempDir(), "loadlab.csv")
	}
	var sb strings.Builder
	sb.WriteString(strings.Join(labCSVHeader, ",") + "\n")
	for _, row := range rows {
		sb.WriteString(strings.Join(row, ",") + "\n")
	}
	if err := os.WriteFile(out, []byte(sb.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("CSV written to %s", out)
}
