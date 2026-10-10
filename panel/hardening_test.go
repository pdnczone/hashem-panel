package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestServerLimitsValues(t *testing.T) {
	srv := &http.Server{}
	applyServerLimits(srv)
	if srv.ReadTimeout != 30*time.Second || srv.WriteTimeout != 60*time.Second || srv.MaxHeaderBytes != 1<<20 {
		t.Fatalf("limits wrong: %v %v %v", srv.ReadTimeout, srv.WriteTimeout, srv.MaxHeaderBytes)
	}
	if maxInFlight != 64 {
		t.Fatal("in-flight cap must be 64")
	}
}

// Real net/http server with the production limits, except the write timeout is
// shortened so the test does not wait a minute.
func TestHardeningWriteTimeoutCutsSlowHandlerButNotExempt(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		_, _ = io.WriteString(w, "late")
	})
	mux.HandleFunc("/exempt", func(w http.ResponseWriter, r *http.Request) {
		exemptDeadlines(w, false)
		time.Sleep(500 * time.Millisecond)
		_, _ = io.WriteString(w, "late but fine")
	})
	mux.HandleFunc("/api/doctor", func(w http.ResponseWriter, r *http.Request) { // listed long-running route
		time.Sleep(500 * time.Millisecond)
		_, _ = io.WriteString(w, "doctor")
	})
	ts := httptest.NewUnstartedServer(inflightLimiter(mux))
	applyServerLimits(ts.Config)
	ts.Config.WriteTimeout = 200 * time.Millisecond
	ts.Start()
	defer ts.Close()

	if resp, err := http.Get(ts.URL + "/slow"); err == nil {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("handler past the write timeout must be cut, got %q", b)
	}
	for path, want := range map[string]string{"/exempt": "late but fine", "/api/doctor": "doctor"} {
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatalf("%s must be exempt from the write timeout: %v", path, err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(b) != want {
			t.Fatalf("%s body %q", path, b)
		}
	}
}

func TestHardeningMaxHeaderBytes(t *testing.T) {
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	applyServerLimits(ts.Config)
	ts.Start()
	defer ts.Close()
	req, _ := http.NewRequest("GET", ts.URL, nil)
	big := make([]byte, 2<<20)
	for i := range big {
		big[i] = 'a'
	}
	req.Header.Set("X-Big", string(big))
	resp, err := http.DefaultClient.Do(req)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
			t.Fatalf("oversized headers must be refused, got %d", resp.StatusCode)
		}
	}
}

func TestInflightLimiter(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, 200)
	mux := http.NewServeMux()
	mux.HandleFunc("/work", func(w http.ResponseWriter, r *http.Request) {
		started <- struct{}{}
		<-release
		_, _ = io.WriteString(w, "done")
	})
	mux.HandleFunc("/api/selfstats", func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "stats") })
	ts := httptest.NewServer(inflightLimiter(mux))
	defer ts.Close()
	defer func() { // never leave blocked handlers behind on failure
		select {
		case <-release:
		default:
			close(release)
		}
	}()

	var wg sync.WaitGroup
	codes := make(chan int, maxInFlight)
	for i := 0; i < maxInFlight; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := http.Get(ts.URL + "/work")
			if err != nil {
				codes <- -1
				return
			}
			resp.Body.Close()
			codes <- resp.StatusCode
		}()
	}
	for i := 0; i < maxInFlight; i++ {
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatalf("only %d of %d requests started", i, maxInFlight)
		}
	}
	// the 65th is refused with 503 + Retry-After and the usual JSON error shape
	resp, err := http.Get(ts.URL + "/work")
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&body)
	resp.Body.Close()
	if resp.StatusCode != 503 || resp.Header.Get("Retry-After") != "2" || body["error_code"] != "E-SYS-02" || body["error"] == "" || body["hint"] == "" {
		t.Fatalf("65th request: %d retry=%q body=%v", resp.StatusCode, resp.Header.Get("Retry-After"), body)
	}
	if resp.Header.Get("Content-Type") != "application/json" {
		t.Fatal("503 body must be JSON")
	}
	// selfstats stays reachable while the panel is saturated
	resp, err = http.Get(ts.URL + "/api/selfstats")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(b) != "stats" {
		t.Fatalf("selfstats must bypass the limiter: %d %q", resp.StatusCode, b)
	}
	if got := inflightNow.Load(); got != maxInFlight {
		t.Fatalf("in-flight counter %d, want %d (selfstats and rejects must not count)", got, maxInFlight)
	}
	close(release)
	wg.Wait()
	close(codes)
	for c := range codes {
		if c != 200 {
			t.Fatalf("admitted request failed: %d", c)
		}
	}
	if got := inflightNow.Load(); got != 0 {
		t.Fatalf("counter must return to 0, got %d", got)
	}
	// capacity is back
	resp, err = http.Get(ts.URL + "/api/selfstats")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("after release: %v", err)
	}
	resp.Body.Close()
}

func TestInflightLimiterIgnoresWebSocketUpgrades(t *testing.T) {
	release := make(chan struct{})
	var mu sync.Mutex
	entered := 0
	h := inflightLimiter(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		entered++
		mu.Unlock()
		<-release
	}))
	var wg sync.WaitGroup
	for i := 0; i < maxInFlight+20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest("GET", "/api/term/ws", nil)
			req.Header.Set("Connection", "Upgrade")
			req.Header.Set("Upgrade", "websocket")
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code == 503 {
				t.Error("websocket upgrade must never be limited")
			}
		}()
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := entered
		mu.Unlock()
		if n == maxInFlight+20 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := inflightNow.Load(); got != 0 {
		t.Errorf("upgrades must not be counted, counter=%d", got)
	}
	// ...and they do not consume capacity for normal requests either
	rr := httptest.NewRecorder()
	ok := inflightLimiter(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	ok.ServeHTTP(rr, httptest.NewRequest("GET", "/api/dashboard", nil))
	if rr.Code != 200 {
		t.Errorf("normal request while upgrades are open: %d", rr.Code)
	}
	close(release)
	wg.Wait()
	mu.Lock()
	if entered != maxInFlight+20 {
		t.Errorf("only %d upgrades reached the handler", entered)
	}
	mu.Unlock()
}

func TestRouteClassification(t *testing.T) {
	old := cfg.BasePath
	cfg.BasePath = "secret"
	defer func() { cfg.BasePath = old }()
	mk := func(method, path string) *http.Request { return httptest.NewRequest(method, path, nil) }
	for _, c := range []struct {
		r      *http.Request
		long   bool
		stream bool
	}{
		{mk("GET", "/secret/api/dashboard"), false, false},
		{mk("GET", "/secret/api/fleet"), false, false},
		{mk("GET", "/secret/api/logs?svc=frps"), true, false},
		{mk("GET", "/secret/api/doctor"), true, false},
		{mk("GET", "/secret/api/update/channel"), true, false},
		{mk("POST", "/secret/api/setup"), true, false},
		{mk("POST", "/secret/api/benchmark/run"), true, false},
		{mk("GET", "/secret/api/term/ws"), false, true},
		{mk("GET", "/secret/debug/pprof/profile"), false, true},
		{mk("GET", "/secret/api/peers"), false, false},
	} {
		if isLongRunning(c.r) != c.long || isStreamRoute(c.r) != c.stream {
			t.Errorf("%s %s: long=%v stream=%v", c.r.Method, c.r.URL.Path, isLongRunning(c.r), isStreamRoute(c.r))
		}
	}
}

func TestPanelChainServesSecurityHeaders(t *testing.T) {
	rr := httptest.NewRecorder()
	panelChain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(rr, httptest.NewRequest("GET", "/x", nil))
	if rr.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatal("security middleware must stay in the chain")
	}
}
