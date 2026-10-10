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
	} {
		if got := strings.Count(s, want); got < min {
			t.Errorf("%q found %d times, want at least %d", want, got, min)
		}
	}
}
