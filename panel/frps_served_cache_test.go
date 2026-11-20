package main

import (
	"slices"
	"testing"
	"time"
)

// The listener scan behind syncFrpsServed walks every process, so the
// snapshot reads it at most once per frpsServedTTL.
func TestFrpsServedCached(t *testing.T) {
	orig := syncFrpsServed
	t.Cleanup(func() {
		syncFrpsServed = orig
		frpsServedCache.Lock()
		frpsServedCache.svc, frpsServedCache.at, frpsServedCache.ports = "", time.Time{}, nil
		frpsServedCache.Unlock()
	})
	calls := 0
	ports := []int{1051, 1052}
	syncFrpsServed = func(svc string) []int { calls++; return slices.Clone(ports) }

	t0 := time.Unix(1_700_000_000, 0)
	if got := frpsServedCached("frps", t0); !slices.Equal(got, []int{1051, 1052}) || calls != 1 {
		t.Fatalf("first read: %v, %d calls", got, calls)
	}
	ports = []int{1051, 1052, 1053}
	// every 5 s tick inside the TTL reuses the answer
	for i := 1; i < 6; i++ {
		if got := frpsServedCached("frps", t0.Add(time.Duration(i)*5*time.Second)); len(got) != 2 {
			t.Fatalf("tick %d: %v", i, got)
		}
	}
	if calls != 1 {
		t.Fatalf("scanned %d times inside the TTL", calls)
	}
	// after the TTL a new port shows
	if got := frpsServedCached("frps", t0.Add(frpsServedTTL)); len(got) != 3 || calls != 2 {
		t.Fatalf("after TTL: %v, %d calls", got, calls)
	}
	// another unit is read at once
	frpsServedCached("frps-2", t0.Add(frpsServedTTL+time.Second))
	if calls != 3 {
		t.Fatalf("other unit: %d calls", calls)
	}
	// a caller changing the slice does not change the cache
	got := frpsServedCached("frps-2", t0.Add(frpsServedTTL+2*time.Second))
	got[0] = 9
	if again := frpsServedCached("frps-2", t0.Add(frpsServedTTL+3*time.Second)); again[0] == 9 {
		t.Fatal("cache shared its slice")
	}
}
