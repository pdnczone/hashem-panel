package main

import (
	"os"
	"strings"
	"testing"
)

// The C2.7 polling policy lives in index.html with no JS harness; this
// string guard keeps its load-bearing pieces from being silently removed.
// Counts are minimums: several loops legitimately repeat the same guard.
func TestIndexPollingPolicy(t *testing.T) {
	b, err := os.ReadFile("index.html")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for want, min := range map[string]int{
		"function makePoller(fn, baseMs)":              1, // hidden-pause + backoff core
		"Math.min(60000, baseMs * Math.pow(2, fails))": 1, // exponential backoff cap 60s
		"if (document.hidden) return;":                 2, // never poll a hidden tab
		"if (running) { schedule(); return; }":         1, // no overlapping requests
		"visibilitychange":                             2, // resume on return
		"if (document.hidden) return; // C2.7":         1, // support popup guard
		"function renderRevPath(entries)":              1, // reverse-path cards
		"function revFix(peerId, apply)":               1, // dry-run / apply buttons
		"docRevPathBox":                                2, // card container (markup + render)
		"function renderTunnelHealth(res)":             1, // Tunnel Health rows
		"function runTunnelHealthClick()":              1, // "Test all tunnels" button
		"/api/tunnel-health?cached=1":                  1, // open = cached read, never probes
		"/api/tunnel-health/run":                       1, // on-demand POST
		"tunnelHealthCard":                             1, // card markup
		"id=\"thRunBtn\"":                              1, // button markup
	} {
		if got := strings.Count(s, want); got < min {
			t.Errorf("%q found %d times, want at least %d", want, got, min)
		}
	}
}
