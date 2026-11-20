package main

import (
	"os"
	"strings"
	"testing"
	"time"
)

// Sentinel's status.json reaches the panel as Health: fresh, stale after three
// intervals (15 minutes at least), and ignored when it is missing, of another
// schema, or too big.
func TestReadSentinelHealth(t *testing.T) {
	if err := os.MkdirAll(sentinelDir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(sentinelStatusPath()) })
	now := time.Unix(1_800_000_000, 0)
	write := func(s string) {
		if err := os.WriteFile(sentinelStatusPath(), []byte(s), 0o640); err != nil {
			t.Fatal(err)
		}
	}

	_ = os.Remove(sentinelStatusPath())
	if readSentinelHealth(now) != nil {
		t.Fatal("no file must give nil")
	}

	write(`{"schema":1,"generated_at":1799999990,"sentinel_version":"1.4.0","interval":30,
	  "counts":{"up":7,"down":2,"slow":1},"total":11,"enabled":10,
	  "worst":[{"name":"DE Reality","state":"down","down_since":1799990000,"last_error_plain":"No answer before the timeout"}],
	  "avg_latency_ms":114.5,"last_check_at":1799999990,"telegram_configured":true,"pending_alerts":0}`)
	h := readSentinelHealth(now)
	if h == nil || h.Stale || h.Counts["down"] != 2 || h.Total != 11 || len(h.Worst) != 1 ||
		h.Worst[0].DownSince == nil || *h.AvgLatencyMs != 114.5 || h.SentinelVersion != "1.4.0" {
		t.Fatalf("fresh file read wrong: %+v", h)
	}
	if h := readSentinelHealth(now.Add(14 * time.Minute)); h == nil || h.Stale {
		t.Fatal("30 s interval: still fresh within 15 minutes")
	}
	if h := readSentinelHealth(now.Add(16 * time.Minute)); h == nil || !h.Stale {
		t.Fatal("30 s interval: stale after 15 minutes")
	}

	write(`{"schema":1,"generated_at":1799990000,"interval":3600,"counts":{},"worst":[]}`)
	if h := readSentinelHealth(now); h == nil || h.Stale {
		t.Fatal("hourly checks: 10 000 s old is within three intervals")
	}

	write(`{"schema":2,"generated_at":1799999990}`)
	if readSentinelHealth(now) != nil {
		t.Fatal("another schema must be ignored")
	}
	write(`{"schema":1,"generated_at":1799999990,"worst":[],"pad":"` + strings.Repeat("x", 300<<10) + `"}`)
	if readSentinelHealth(now) != nil {
		t.Fatal("a file over 256 KB must be ignored")
	}
	write(`not json`)
	if readSentinelHealth(now) != nil {
		t.Fatal("broken JSON must be ignored")
	}
}
