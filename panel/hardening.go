package main

// HTTP server hardening (moderate): read/write timeouts, a header size cap and a
// global in-flight limit. Long-running and streaming routes are exempt from the
// write deadline via exemptDeadlines, and upgrades (the terminal WebSocket) are
// neither limited nor timed.

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

const (
	serverReadTimeout  = 30 * time.Second
	serverWriteTimeout = 60 * time.Second
	serverMaxHeader    = 1 << 20
	maxInFlight        = 64
)

// applyServerLimits sets the shared read/write/header limits on a panel server.
func applyServerLimits(srv *http.Server) {
	srv.ReadTimeout = serverReadTimeout
	srv.WriteTimeout = serverWriteTimeout
	srv.MaxHeaderBytes = serverMaxHeader
}

// exemptDeadlines lifts the server write deadline (and, for streams, the read
// deadline) for the current request. Call it at the start of any handler that
// can legitimately run or stream past serverWriteTimeout. A writer that does not
// support deadlines is left alone.
func exemptDeadlines(w http.ResponseWriter, read bool) {
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{})
	if read {
		_ = rc.SetReadDeadline(time.Time{})
	}
}

// longRunningGET lists GET routes (relative to the base path) that shell out,
// download or stream and may outlive the write timeout. Every non-GET request is
// treated the same way: mutations run installer scripts.
var longRunningGET = []string{
	"/api/logs", "/api/doctor", "/api/update", "/api/version", "/api/releases", "/api/benchmark",
	"/api/watchdog/backup-download", "/api/support", "/api/revpath", "/api/tls", "/api/perf",
	"/api/dial", "/api/rescue", "/api/carrier", "/api/peer",
}

func isLongRunning(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return true
	}
	rel := relPath(r.URL.Path)
	for _, p := range longRunningGET {
		if rel == p || strings.HasPrefix(rel, p+"/") {
			return true
		}
	}
	return false
}

// relPath strips the secret base path.
func relPath(path string) string {
	base := "/" + cfg.BasePath
	if cfg.BasePath != "" && (path == base || strings.HasPrefix(path, base+"/")) {
		return strings.TrimPrefix(path, base)
	}
	return path
}

// isStreamRoute is a route whose lifetime is not a request latency (profiles,
// terminal): no deadlines and not counted by the in-flight limiter.
func isStreamRoute(r *http.Request) bool {
	rel := relPath(r.URL.Path)
	return isWebSocketUpgrade(r) || strings.HasPrefix(rel, "/debug/pprof/") || strings.HasPrefix(rel, "/api/term/ws")
}

var inflightNow atomic.Int64

// inflightLimiter caps concurrent requests at maxInFlight and answers 503 with
// Retry-After beyond that. /api/selfstats and stream routes are exempt, so an
// overloaded panel can still be diagnosed and the terminal keeps working.
func inflightLimiter(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isStreamRoute(r) {
			exemptDeadlines(w, true)
			next.ServeHTTP(w, r)
			return
		}
		if isLongRunning(r) {
			exemptDeadlines(w, false)
		}
		if relPath(r.URL.Path) == "/api/selfstats" {
			next.ServeHTTP(w, r)
			return
		}
		if inflightNow.Add(1) > maxInFlight {
			inflightNow.Add(-1)
			writeBusy(w)
			return
		}
		defer inflightNow.Add(-1)
		next.ServeHTTP(w, r)
	})
}

// writeBusy is the 503 answer, same JSON shape as writeAPIError but not logged
// to the error journal (an overload would flood it).
func writeBusy(w http.ResponseWriter) {
	info := errCatalog["E-SYS-02"]
	w.Header().Set("Retry-After", "2")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(info.Status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error_code": "E-SYS-02", "error": info.Msg, "hint": info.Hint})
}

// panelChain wraps the panel mux in the full middleware stack.
func panelChain(mux http.Handler) http.Handler {
	return inflightLimiter(metricsMiddleware(securityMiddleware(mux)))
}
