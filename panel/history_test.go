package main

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func hpU64(v uint64) *uint64 { return &v }

func TestHistoryRateLimitsAndThroughput(t *testing.T) {
	h := &histStore{links: map[string]*histRing{}}
	t0 := time.Unix(1_700_000_000, 0)
	h.recordSample("a", t0, stateHealthy, 10, hpU64(1000), hpU64(500))
	h.recordSample("a", t0.Add(5*time.Second), stateHealthy, 11, hpU64(2000), hpU64(900)) // inside 30s: dropped
	h.recordSample("a", t0.Add(30*time.Second), stateDown, -1, hpU64(4000), hpU64(1100))
	s := h.series("a", 0)
	if len(s) != 2 {
		t.Fatalf("want 2 points (30s spacing), got %d", len(s))
	}
	if s[0].RxBps != 0 || s[0].State != 2 {
		t.Errorf("first point has no rate: %+v", s[0])
	}
	if s[1].RxBps != 100 || s[1].TxBps != 20 || s[1].State != 0 || s[1].Ms != -1 {
		t.Errorf("rates over 30s wrong: %+v", s[1])
	}
}

func TestHistoryCounterResetGivesNoNegativeRate(t *testing.T) {
	h := &histStore{links: map[string]*histRing{}}
	t0 := time.Unix(1_700_000_000, 0)
	h.recordSample("a", t0, stateHealthy, 1, hpU64(9000), hpU64(9000))
	h.recordSample("a", t0.Add(30*time.Second), stateHealthy, 1, hpU64(10), hpU64(10)) // interface re-created
	if s := h.series("a", 0); s[1].RxBps != 0 || s[1].TxBps != 0 {
		t.Errorf("counter reset must not yield a rate: %+v", s[1])
	}
}

func TestHistoryRingKeepsNewestInOrder(t *testing.T) {
	h := &histStore{links: map[string]*histRing{}}
	t0 := time.Unix(1_700_000_000, 0)
	n := histPoints + 10
	for i := 0; i < n; i++ {
		h.recordSample("a", t0.Add(time.Duration(i)*histEvery), stateHealthy, float64(i), nil, nil)
	}
	s := h.series("a", 0)
	if len(s) != histPoints {
		t.Fatalf("ring must cap at %d, got %d", histPoints, len(s))
	}
	if s[0].Ms != 10 || s[len(s)-1].Ms != float64(n-1) {
		t.Errorf("order wrong: first=%v last=%v", s[0].Ms, s[len(s)-1].Ms)
	}
	for i := 1; i < len(s); i++ {
		if s[i].T <= s[i-1].T {
			t.Fatal("points must be chronological")
		}
	}
}

func TestHistoryLinkCapAndSince(t *testing.T) {
	h := &histStore{links: map[string]*histRing{}}
	now := time.Unix(1_700_000_000, 0)
	for i := 0; i < maxLinks+20; i++ {
		h.recordSample("l"+string(rune('A'+i%26))+string(rune('a'+i/26)), now, stateHealthy, 1, nil, nil)
	}
	if len(h.names()) != maxLinks {
		t.Errorf("link count must be capped at %d, got %d", maxLinks, len(h.names()))
	}
	h.recordSample("x", now, stateHealthy, 1, nil, nil)
	if len(h.series("x", now.Unix()+1)) != 0 {
		t.Error("since filter must exclude older points")
	}
}

func TestPrometheusOutput(t *testing.T) {
	snap := &HubSnapshot{At: time.Now(), LocalSession: true, Peers: []peerLive{
		{peerRecord: peerRecord{ID: 2, Name: `ir "one"`}, HealthState: stateHealthy, LatencyMs: 12.5, LatencyKind: "tcp", Rx: hpU64(100), Tx: hpU64(200)},
		{peerRecord: peerRecord{ID: 3}, HealthState: stateDown, LatencyMs: -1},
	}}
	out := renderPrometheus(snap)
	for _, want := range []string{
		`hashem_link_state{link="ir \"one\""} 2`,
		`hashem_link_state{link="peer-3"} 0`,
		`hashem_link_latency_ms{link="ir \"one\"",kind="tcp"} 12.5`,
		`hashem_link_rx_bytes_total{link="ir \"one\""} 100`,
		`hashem_local_session 1`,
		"# TYPE hashem_link_state gauge",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, `link="peer-3",kind`) {
		t.Error("unknown latency must be omitted")
	}
}

func TestMetricsEndpointAuth(t *testing.T) {
	old := cfg
	defer func() { cfg = old }()
	get := func(auth string) int {
		req := httptest.NewRequest("GET", "/metrics", nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		rr := httptest.NewRecorder()
		handleMetrics(rr, req)
		return rr.Code
	}
	cfg.MetricsToken = ""
	if get("Bearer anything") != 404 {
		t.Error("disabled endpoint must 404")
	}
	cfg.MetricsToken = "s3cr3t-token"
	if get("") != 401 || get("Bearer wrong") != 401 {
		t.Error("missing/wrong token must 401")
	}
	if get("Bearer s3cr3t-token") != 200 {
		t.Error("right token must 200")
	}
}

func TestMetricsTokenRotateDisable(t *testing.T) {
	old := cfg
	defer func() { cfg = old }()
	do := func(body string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		handleMetricsTokenPost(rr, httptest.NewRequest("POST", "/x", strings.NewReader(body)))
		return rr
	}
	rr := do(`{"action":"rotate"}`)
	if rr.Code != 200 || len(cfg.MetricsToken) < 32 || !strings.Contains(rr.Body.String(), cfg.MetricsToken) {
		t.Fatalf("rotate: %d %s", rr.Code, rr.Body.String())
	}
	g := httptest.NewRecorder()
	handleMetricsTokenGet(g, httptest.NewRequest("GET", "/x", nil))
	if strings.Contains(g.Body.String(), cfg.MetricsToken) {
		t.Error("GET must never reveal the token")
	}
	if do(`{"action":"disable"}`); cfg.MetricsToken != "" {
		t.Error("disable must clear the token")
	}
	if do(`{"action":"x"}`).Code == 200 {
		t.Error("unknown action must fail")
	}
}
