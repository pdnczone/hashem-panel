package main

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// In-memory per-link history (latency, state, throughput) sampled from the
// shared snapshot, plus a Prometheus text endpoint. No extra host commands:
// everything comes from the snapshot the collector already built.

const (
	histEvery  = 30 * time.Second // one point per link per 30 s
	histPoints = 2880             // 24 h
	maxLinks   = 64               // bounds memory/label cardinality
)

type histPoint struct {
	T     int64   `json:"t"`
	State int     `json:"state"` // 2 healthy, 1 degraded, 0 down
	Ms    float64 `json:"ms"`    // latency, -1 unknown
	RxBps float64 `json:"rx_bps"`
	TxBps float64 `json:"tx_bps"`
}

type histRing struct {
	pts   []histPoint
	next  int
	full  bool
	lastT int64
	rx    uint64
	tx    uint64
	haveC bool
}

func (r *histRing) add(p histPoint) {
	if len(r.pts) < histPoints {
		r.pts = append(r.pts, p)
		return
	}
	r.pts[r.next] = p
	r.next = (r.next + 1) % histPoints
	r.full = true
}

func (r *histRing) ordered() []histPoint {
	if !r.full {
		return append([]histPoint(nil), r.pts...)
	}
	return append(append([]histPoint(nil), r.pts[r.next:]...), r.pts[:r.next]...)
}

type histStore struct {
	mu    sync.Mutex
	links map[string]*histRing
}

var linkHist = &histStore{links: map[string]*histRing{}}

func stateNum(s string) int {
	switch s {
	case stateHealthy:
		return 2
	case stateDegraded:
		return 1
	}
	return 0
}

// recordSample stores one point for a link. rx/tx are cumulative byte counters
// (nil when unknown); rates are derived from consecutive samples.
func (h *histStore) recordSample(name string, now time.Time, state string, ms float64, rx, tx *uint64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	r := h.links[name]
	if r == nil {
		if len(h.links) >= maxLinks {
			return
		}
		r = &histRing{}
		h.links[name] = r
	}
	t := now.Unix()
	if r.lastT != 0 && now.Sub(time.Unix(r.lastT, 0)) < histEvery {
		return
	}
	p := histPoint{T: t, State: stateNum(state), Ms: ms}
	if rx != nil && tx != nil {
		if r.haveC && r.lastT != 0 && t > r.lastT && *rx >= r.rx && *tx >= r.tx {
			dt := float64(t - r.lastT)
			p.RxBps = float64(*rx-r.rx) / dt
			p.TxBps = float64(*tx-r.tx) / dt
		}
		r.rx, r.tx, r.haveC = *rx, *tx, true
	}
	r.lastT = t
	r.add(p)
}

func (h *histStore) series(name string, since int64) []histPoint {
	h.mu.Lock()
	defer h.mu.Unlock()
	r := h.links[name]
	if r == nil {
		return nil
	}
	var out []histPoint
	for _, p := range r.ordered() {
		if p.T >= since {
			out = append(out, p)
		}
	}
	return out
}

func (h *histStore) names() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := make([]string, 0, len(h.links))
	for k := range h.links {
		n = append(n, k)
	}
	sort.Strings(n)
	return n
}

func linkName(l peerLive) string {
	if l.Name != "" {
		return l.Name
	}
	return fmt.Sprintf("peer-%d", l.ID)
}

// historyOnSnapshot is called after every snapshot build.
func historyOnSnapshot(s *HubSnapshot) {
	now := time.Now()
	alive := map[string]bool{}
	for _, l := range s.All() {
		n := linkName(l)
		alive[n] = true
		linkHist.recordSample(n, now, l.HealthState, l.LatencyMs, l.Rx, l.Tx)
	}
	linkHist.mu.Lock() // drop links that no longer exist
	for k := range linkHist.links {
		if !alive[k] {
			delete(linkHist.links, k)
		}
	}
	linkHist.mu.Unlock()
}

// GET /api/history?link=NAME&hours=1..24
func handleHistoryGet(w http.ResponseWriter, r *http.Request) {
	hours := 1
	if v, err := strconv.Atoi(r.URL.Query().Get("hours")); err == nil && v >= 1 && v <= 24 {
		hours = v
	}
	since := time.Now().Add(-time.Duration(hours) * time.Hour).Unix()
	if name := r.URL.Query().Get("link"); name != "" {
		writeJSON(w, map[string]any{"link": name, "hours": hours, "points": linkHist.series(name, since)})
		return
	}
	writeJSON(w, map[string]any{"links": linkHist.names(), "every_sec": int(histEvery.Seconds()), "max_hours": 24})
}

// ---- Prometheus ----

func promEsc(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return strings.ReplaceAll(s, `"`, `\"`)
}

func renderPrometheus(s *HubSnapshot) string {
	var b strings.Builder
	b.WriteString("# HELP hashem_link_state Link health: 2 healthy, 1 degraded, 0 down.\n# TYPE hashem_link_state gauge\n")
	all := s.All()
	for _, l := range all {
		fmt.Fprintf(&b, "hashem_link_state{link=\"%s\"} %d\n", promEsc(linkName(l)), stateNum(l.HealthState))
	}
	b.WriteString("# HELP hashem_link_latency_ms Latency of the link in milliseconds (absent when unknown).\n# TYPE hashem_link_latency_ms gauge\n")
	for _, l := range all {
		if l.LatencyMs >= 0 {
			fmt.Fprintf(&b, "hashem_link_latency_ms{link=\"%s\",kind=\"%s\"} %g\n", promEsc(linkName(l)), promEsc(l.LatencyKind), l.LatencyMs)
		}
	}
	b.WriteString("# HELP hashem_link_rx_bytes_total Bytes received over the link interface.\n# TYPE hashem_link_rx_bytes_total counter\n")
	for _, l := range all {
		if l.Rx != nil {
			fmt.Fprintf(&b, "hashem_link_rx_bytes_total{link=\"%s\"} %d\n", promEsc(linkName(l)), *l.Rx)
		}
	}
	b.WriteString("# HELP hashem_link_tx_bytes_total Bytes sent over the link interface.\n# TYPE hashem_link_tx_bytes_total counter\n")
	for _, l := range all {
		if l.Tx != nil {
			fmt.Fprintf(&b, "hashem_link_tx_bytes_total{link=\"%s\"} %d\n", promEsc(linkName(l)), *l.Tx)
		}
	}
	b.WriteString("# HELP hashem_local_session 1 when this machine's own tunnel session is up.\n# TYPE hashem_local_session gauge\n")
	v := 0
	if s.LocalSession {
		v = 1
	}
	fmt.Fprintf(&b, "hashem_local_session %d\n", v)
	b.WriteString("# HELP hashem_snapshot_age_ms Age of the snapshot these values come from.\n# TYPE hashem_snapshot_age_ms gauge\n")
	fmt.Fprintf(&b, "hashem_snapshot_age_ms %d\n", s.AgeMs())
	return b.String()
}

// handleMetrics serves Prometheus text. It is OFF (404) until a metrics token
// is configured; scrapers authenticate with "Authorization: Bearer <token>".
func handleMetrics(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	tok := cfg.MetricsToken
	mu.Unlock()
	if tok == "" {
		http.NotFound(w, r)
		return
	}
	got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(tok)) != 1 {
		w.Header().Set("WWW-Authenticate", `Bearer realm="hashem-metrics"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = w.Write([]byte(renderPrometheus(currentSnapshot())))
}

// GET/POST /api/metrics-token {action: "rotate"|"disable"} — token shown once on rotate.
func handleMetricsTokenGet(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	on := cfg.MetricsToken != ""
	mu.Unlock()
	writeJSON(w, map[string]any{"enabled": on})
}

func handleMetricsTokenPost(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Action string `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeAPIError(w, r, "E-WD-01", "invalid request")
		return
	}
	switch body.Action {
	case "rotate":
		t := randomToken(40)
		mu.Lock()
		cfg.MetricsToken = t
		saveCfg()
		mu.Unlock()
		LogSecurityAudit("metrics_token_rotated", cfg.Username, clientIP(r), "prometheus scrape token rotated")
		writeJSON(w, map[string]any{"enabled": true, "token": t})
	case "disable":
		mu.Lock()
		cfg.MetricsToken = ""
		saveCfg()
		mu.Unlock()
		LogSecurityAudit("metrics_disabled", cfg.Username, clientIP(r), "prometheus endpoint disabled")
		writeJSON(w, map[string]any{"enabled": false})
	default:
		writeAPIError(w, r, "E-WD-01", "action must be rotate or disable")
	}
}
