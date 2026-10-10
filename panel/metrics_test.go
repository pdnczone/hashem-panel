package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMetricsRouteLabelHidesBase(t *testing.T) {
	old := cfg
	cfg.BasePath = "s3cretBase"
	defer func() { cfg = old }()
	cases := map[string]string{
		"/s3cretBase/api/fleet": "/{base}/api/fleet",
		"/s3cretBase/":          "/{base}/",
		"/s3cretBase":           "/{base}",
		"/s3cretBaseX/api":      "other",
		"/wp-login.php":         "other",
	}
	for in, want := range cases {
		if got := routeLabel(in); got != want {
			t.Errorf("routeLabel(%q)=%q want %q", in, got, want)
		}
	}
}

func TestMetricsPercentilesAndRing(t *testing.T) {
	resetRouteStats()
	defer resetRouteStats()
	for i := 1; i <= 1000; i++ {
		observeRoute("/r", time.Duration(i)*time.Millisecond)
	}
	var r routeJSON
	for _, x := range routeSnapshot() {
		if x.Route == "/r" {
			r = x
		}
	}
	if r.Count != 1000 {
		t.Fatalf("count=%d", r.Count)
	}
	// ring keeps the last 512 samples: 489..1000 ms
	if r.P50Ms < 700 || r.P50Ms > 760 || r.P99Ms < 990 || r.P95Ms > r.P99Ms || r.P50Ms > r.P95Ms {
		t.Fatalf("percentiles off: %+v", r)
	}
}

func TestMetricsRouteCardinalityBounded(t *testing.T) {
	resetRouteStats()
	defer resetRouteStats()
	for i := 0; i < maxRoutes*3; i++ {
		observeRoute("/x"+string(rune('a'+i%26))+strings.Repeat("y", i), time.Millisecond)
	}
	if n := len(routeSnapshot()); n > maxRoutes+1 {
		t.Fatalf("routes=%d", n)
	}
}

func TestMetricsMiddlewareInFlightAndLabel(t *testing.T) {
	resetRouteStats()
	defer resetRouteStats()
	old := cfg
	cfg.BasePath = "bp"
	defer func() { cfg = old }()
	release := make(chan struct{})
	entered := make(chan struct{})
	h := metricsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		<-release
	}))
	done := make(chan struct{})
	go func() {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/bp/api/x", nil))
		close(done)
	}()
	<-entered
	if inFlight.Load() != 1 {
		t.Fatalf("in-flight=%d", inFlight.Load())
	}
	close(release)
	<-done
	if inFlight.Load() != 0 {
		t.Fatalf("in-flight after=%d", inFlight.Load())
	}
	found := false
	for _, r := range routeSnapshot() {
		if r.Route == "/{base}/api/x" && r.Count == 1 {
			found = true
		}
		if strings.Contains(r.Route, "bp/") {
			t.Fatalf("secret base leaked: %s", r.Route)
		}
	}
	if !found {
		t.Fatalf("route not recorded: %+v", routeSnapshot())
	}
}

func TestMetricsSamplerAndSelfStatsJSON(t *testing.T) {
	resetSamplerStats()
	defer resetSamplerStats()
	recordSampler("s", 30*time.Millisecond)
	recordSampler("s", 10*time.Millisecond)
	rec := httptest.NewRecorder()
	handleSelfStats(rec, httptest.NewRequest("GET", "/api/selfstats", nil))
	var got selfStats
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Process.Goroutines < 1 || got.Process.HeapAlloc == 0 {
		t.Fatalf("process: %+v", got.Process)
	}
	if len(got.Samplers) != 1 || got.Samplers[0].Runs != 2 || got.Samplers[0].MaxDurationMs < 29 || got.Samplers[0].LastDurationMs > 20 {
		t.Fatalf("samplers: %+v", got.Samplers)
	}
}

func TestMetricsVmRSS(t *testing.T) {
	if got := readVmRSS("Name:\tx\nVmRSS:\t  2048 kB\n"); got != 2048*1024 {
		t.Fatalf("rss=%d", got)
	}
	if readVmRSS("nothing") != -1 {
		t.Fatal("missing VmRSS must be -1")
	}
}

func TestMetricsSelfStatsRequiresAuth(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /bp/api/selfstats", requireAuth(handleSelfStats))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", "/bp/api/selfstats", nil))
	if rec.Code == http.StatusOK {
		t.Fatal("selfstats must not be reachable without a session")
	}
}

func TestMetricsPprofOffByDefault(t *testing.T) {
	t.Setenv("HASHEM_PPROF", "")
	old := cfg
	cfg.DebugEnabled = false
	defer func() { cfg = old }()
	mux := http.NewServeMux()
	mountDebug(mux, "/bp")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", "/bp/debug/pprof/", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("pprof must be unmounted by default, got %d", rec.Code)
	}
	t.Setenv("HASHEM_PPROF", "1")
	mux = http.NewServeMux()
	mountDebug(mux, "/bp")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", "/bp/debug/pprof/", nil))
	if rec.Code == http.StatusNotFound || rec.Code == http.StatusOK {
		t.Fatalf("pprof must be mounted and auth-gated, got %d", rec.Code)
	}
}
