package main

// Self-stats for profiling the panel itself (GET /api/selfstats). Pure
// observation: nothing here changes tunnel, health or system state.

import (
	"net/http"
	"net/http/pprof"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	routeRingSize = 512
	maxRoutes     = 64 // bounds label cardinality against path scanners
)

// ---- per-sampler timings ----

type samplerStat struct {
	runs     uint64
	total    time.Duration
	last     time.Duration
	max      time.Duration
	lastUnix int64
}

var (
	samplerMu    sync.Mutex
	samplerStats = map[string]*samplerStat{}
)

// recordSampler notes one run of a background sampler / expensive collector.
func recordSampler(name string, d time.Duration) {
	samplerMu.Lock()
	defer samplerMu.Unlock()
	s := samplerStats[name]
	if s == nil {
		s = &samplerStat{}
		samplerStats[name] = s
	}
	s.runs++
	s.total += d
	s.last = d
	if d > s.max {
		s.max = d
	}
	s.lastUnix = time.Now().Unix()
}

type samplerJSON struct {
	Name           string  `json:"name"`
	LastDurationMs float64 `json:"last_duration_ms"`
	AvgDurationMs  float64 `json:"avg_duration_ms"`
	MaxDurationMs  float64 `json:"max_duration_ms"`
	Runs           uint64  `json:"runs"`
	LastRunUnix    int64   `json:"last_run_unix"`
}

func samplerSnapshot() []samplerJSON {
	samplerMu.Lock()
	defer samplerMu.Unlock()
	res := make([]samplerJSON, 0, len(samplerStats))
	for n, s := range samplerStats {
		res = append(res, samplerJSON{n, ms(s.last), ms(s.total) / float64(s.runs), ms(s.max), s.runs, s.lastUnix})
	}
	sort.Slice(res, func(i, j int) bool { return res[i].Name < res[j].Name })
	return res
}

func resetSamplerStats() {
	samplerMu.Lock()
	samplerStats = map[string]*samplerStat{}
	samplerMu.Unlock()
}

// ---- HTTP route latency ----

type routeRing struct {
	buf   [routeRingSize]time.Duration
	n     int // total observed
	count uint64
}

var (
	routeMu    sync.Mutex
	routeStats = map[string]*routeRing{}
	inFlight   atomic.Int64
)

// routeLabel hides the secret base path and bounds label cardinality.
func routeLabel(path string) string {
	base := "/" + cfg.BasePath
	if cfg.BasePath == "" || (path != base && !strings.HasPrefix(path, base+"/")) {
		return "other"
	}
	return "/{base}" + strings.TrimPrefix(path, base)
}

func observeRoute(label string, d time.Duration) {
	routeMu.Lock()
	defer routeMu.Unlock()
	r := routeStats[label]
	if r == nil {
		if len(routeStats) >= maxRoutes {
			label = "other"
			r = routeStats[label]
		}
		if r == nil {
			r = &routeRing{}
			routeStats[label] = r
		}
	}
	r.buf[r.n%routeRingSize] = d
	r.n++
	r.count++
}

// metricsMiddleware times requests per route. It does not wrap the
// ResponseWriter (WebSocket hijack / streaming keep working) and skips
// upgrade requests, whose lifetime is not a latency.
func metricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isWebSocketUpgrade(r) {
			next.ServeHTTP(w, r)
			return
		}
		inFlight.Add(1)
		start := time.Now()
		defer func() {
			inFlight.Add(-1)
			observeRoute(routeLabel(r.URL.Path), time.Since(start))
		}()
		next.ServeHTTP(w, r)
	})
}

type routeJSON struct {
	Route string  `json:"route"`
	Count uint64  `json:"count"`
	P50Ms float64 `json:"p50_ms"`
	P95Ms float64 `json:"p95_ms"`
	P99Ms float64 `json:"p99_ms"`
}

func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	i := int(float64(len(sorted))*p+0.5) - 1
	if i < 0 {
		i = 0
	}
	if i >= len(sorted) {
		i = len(sorted) - 1
	}
	return sorted[i]
}

func routeSnapshot() []routeJSON {
	routeMu.Lock()
	defer routeMu.Unlock()
	res := make([]routeJSON, 0, len(routeStats))
	for label, r := range routeStats {
		n := r.n
		if n > routeRingSize {
			n = routeRingSize
		}
		s := make([]time.Duration, n)
		copy(s, r.buf[:n])
		sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
		res = append(res, routeJSON{label, r.count, ms(percentile(s, 0.50)), ms(percentile(s, 0.95)), ms(percentile(s, 0.99))})
	}
	sort.Slice(res, func(i, j int) bool { return res[i].Route < res[j].Route })
	return res
}

func resetRouteStats() {
	routeMu.Lock()
	routeStats = map[string]*routeRing{}
	routeMu.Unlock()
}

// ---- process stats ----

type procStats struct {
	Goroutines  int     `json:"goroutines"`
	HeapAlloc   uint64  `json:"heap_alloc_bytes"`
	HeapSys     uint64  `json:"heap_sys_bytes"`
	NumGC       uint32  `json:"num_gc"`
	LastGCPause float64 `json:"last_gc_pause_ms"`
	RSSBytes    int64   `json:"rss_bytes"`
	OpenFDs     int     `json:"open_fds"`
	UptimeSec   float64 `json:"uptime_s"`
}

// readVmRSS parses VmRSS (kB) out of /proc/self/status content; -1 if absent.
func readVmRSS(status string) int64 {
	for _, line := range strings.Split(status, "\n") {
		if v, ok := strings.CutPrefix(line, "VmRSS:"); ok {
			f := strings.Fields(v)
			if len(f) > 0 {
				if kb, err := strconv.ParseInt(f[0], 10, 64); err == nil {
					return kb * 1024
				}
			}
		}
	}
	return -1
}

func readProcStats() procStats {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	p := procStats{
		Goroutines: runtime.NumGoroutine(),
		HeapAlloc:  ms.HeapAlloc,
		HeapSys:    ms.HeapSys,
		NumGC:      ms.NumGC,
		RSSBytes:   -1,
		OpenFDs:    -1,
		UptimeSec:  time.Since(panelStartedAt).Seconds(),
	}
	if ms.NumGC > 0 {
		p.LastGCPause = float64(ms.PauseNs[(ms.NumGC+255)%256]) / 1e6
	}
	if b, err := os.ReadFile("/proc/self/status"); err == nil {
		p.RSSBytes = readVmRSS(string(b))
	}
	if ents, err := os.ReadDir("/proc/self/fd"); err == nil {
		p.OpenFDs = len(ents)
	}
	return p
}

type selfStats struct {
	Process  procStats      `json:"process"`
	InFlight int64          `json:"http_in_flight"`
	Routes   []routeJSON    `json:"routes"`
	Exec     []execStatJSON `json:"exec"`
	Samplers []samplerJSON  `json:"samplers"`
	Snapshot snapStatsJSON  `json:"snapshot"`
}

func collectSelfStats() selfStats {
	return selfStats{
		Process:  readProcStats(),
		InFlight: inFlight.Load(),
		Routes:   routeSnapshot(),
		Exec:     execSnapshot(),
		Samplers: samplerSnapshot(),
		Snapshot: snapshotStats(),
	}
}

func handleSelfStats(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, collectSelfStats())
}

// ---- optional pprof ----

func debugEnabled() bool {
	return os.Getenv("HASHEM_PPROF") == "1" || cfg.DebugEnabled
}

// pprofHandler serves /debug/pprof/* (path already stripped of the base).
func pprofHandler(w http.ResponseWriter, r *http.Request) {
	switch strings.TrimPrefix(r.URL.Path, "/debug/pprof/") {
	case "cmdline":
		pprof.Cmdline(w, r)
	case "profile":
		pprof.Profile(w, r)
	case "symbol":
		pprof.Symbol(w, r)
	case "trace":
		pprof.Trace(w, r)
	default:
		pprof.Index(w, r)
	}
}

// mountDebug registers pprof behind the normal session auth; no-op unless
// HASHEM_PPROF=1 or debug_enabled is set.
func mountDebug(mux *http.ServeMux, base string) {
	if !debugEnabled() {
		return
	}
	mux.HandleFunc("GET "+base+"/debug/pprof/", requireAuth(http.StripPrefix(base, http.HandlerFunc(pprofHandler)).ServeHTTP))
}
