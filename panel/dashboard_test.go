package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestIsTunnelInterface(t *testing.T) {
	tests := []struct {
		name     string
		expected bool
	}{
		{"lo", false},
		{"gre0", false},
		{"gretap0", false},
		{"erspan0", false},
		{"eth0", false},
		{"ens5", false},
		{"enp0s5", false},
		{"docker0", false},
		{"veth1234", false},
		{"br-test", false},
		{"dummy0", false},
		{"gre-tunnel", true},
		{"gre-t2", true},
		{"gre-t3", true},
		{"tun0", true},
		{"tun1", true},
		{"tun-backhaul", true},
	}

	for _, tt := range tests {
		got := isTunnelInterface(tt.name)
		if got != tt.expected {
			t.Errorf("isTunnelInterface(%q) = %v; want %v", tt.name, got, tt.expected)
		}
	}
}

func TestCompactHistoryLocked(t *testing.T) {
	histMu.Lock()
	defer histMu.Unlock()

	now := time.Now().Unix()
	var sample []trafficPoint

	// 1. Points older than 90 days (should be dropped)
	for i := int64(95 * 86400); i > 90*86400; i -= 100 {
		sample = append(sample, trafficPoint{T: now - i})
	}

	// 2. Points between 7d and 90d (should be 5-minute buckets = 300s)
	// Align base to a 300s bucket boundary so all 10 points fall in the same bucket
	base7d := ((now - 10*86400) / 300) * 300
	for i := int64(0); i < 10; i++ {
		sample = append(sample, trafficPoint{T: base7d + i*10})
	}

	// 3. Points between 24h and 7d (should be 1-minute buckets = 60s)
	// Align base to a 60s bucket boundary so all 5 points fall in the same bucket
	base2d := ((now - 2*86400) / 60) * 60
	for i := int64(0); i < 5; i++ {
		sample = append(sample, trafficPoint{T: base2d + i*5})
	}

	// 4. Points within last 24h (all kept)
	baseRecent := now - 1000
	for i := int64(0); i < 5; i++ {
		sample = append(sample, trafficPoint{T: baseRecent + i*5})
	}

	histCached = sample
	histLoaded = true
	compactHistoryLocked(now)

	// Older than 90d must be 0
	for _, p := range histCached {
		if p.T < now-90*86400 {
			t.Errorf("found point older than 90d: %d", p.T)
		}
	}

	// From the 10 points in the same 5m bucket, only 1 should remain
	count5m := 0
	for _, p := range histCached {
		if p.T >= base7d && p.T < base7d+300 {
			count5m++
		}
	}
	if count5m != 1 {
		t.Errorf("expected 1 point for 5m bucket, got %d", count5m)
	}

	// From the 5 points in the same 1m bucket, only 1 should remain
	count1m := 0
	for _, p := range histCached {
		if p.T >= base2d && p.T < base2d+60 {
			count1m++
		}
	}
	if count1m != 1 {
		t.Errorf("expected 1 point for 1m bucket, got %d", count1m)
	}

	// All 5 recent points must be preserved
	countRecent := 0
	for _, p := range histCached {
		if p.T >= baseRecent {
			countRecent++
		}
	}
	if countRecent != 5 {
		t.Errorf("expected 5 recent points, got %d", countRecent)
	}
}

func TestTrafficHistoryDownsampling(t *testing.T) {
	now := time.Now().Unix()
	var sample []trafficPoint
	for i := 0; i < 1000; i++ {
		up := uint64(i * 100)
		down := uint64(i * 200)
		sample = append(sample, trafficPoint{
			T:    now - 1000 + int64(i),
			Up:   &up,
			Down: &down,
		})
	}

	histMu.Lock()
	histCached = sample
	histLoaded = true
	histMu.Unlock()

	out := trafficHistory("1h")
	if len(out) != 240 {
		t.Fatalf("expected 240 points, got %d", len(out))
	}

	// Check that the last point in out is exactly the newest point in sample
	lastIn := sample[len(sample)-1]
	lastOut := out[len(out)-1]
	if lastOut.T != lastIn.T {
		t.Errorf("last point T mismatch: got %d, want %d", lastOut.T, lastIn.T)
	}
	if *lastOut.Up != *lastIn.Up || *lastOut.Down != *lastIn.Down {
		t.Errorf("last point values mismatch")
	}
}

func TestLoadHistoryCleansNulls(t *testing.T) {
	tmpDir := t.TempDir()
	oldDir := configDir
	configDir = tmpDir
	defer func() { configDir = oldDir }()

	rawJSON := `[{"t":1000,"up":null,"down":null,"total":null},{"t":1005,"up":100,"down":200,"total":300},{"t":1010,"up":null,"down":null,"total":null}]`
	if err := os.WriteFile(filepath.Join(tmpDir, "traffic.json"), []byte(rawJSON), 0600); err != nil {
		t.Fatal(err)
	}

	histMu.Lock()
	histLoaded = false
	histCached = nil
	histMu.Unlock()

	cleaned := loadHistory()
	if len(cleaned) != 3 {
		t.Fatalf("expected 3 points, got %d", len(cleaned))
	}
	for i, pt := range cleaned {
		if pt.Up == nil || pt.Down == nil || pt.Total == nil {
			t.Errorf("point %d has nil counters: up=%v, down=%v, total=%v", i, pt.Up, pt.Down, pt.Total)
		}
	}
	if *cleaned[1].Up != 100 || *cleaned[2].Up != 100 {
		t.Errorf("expected cleaned[2].Up to carry forward 100, got %d", *cleaned[2].Up)
	}
}

// With no tunnel interface and no carrier the main NIC is not counted: it
// carries the whole server's traffic (the panel used to show it as tunnel
// traffic, and to count it while a GRE interface was being recreated).
func TestGreTrafficNoNICFallback(t *testing.T) {
	resetTrafficState(t)
	nic := func(rx, tx uint64) string {
		return devLines(map[string][2]uint64{"lo": {100000, 100000}, "ens5": {rx, tx}})
	}
	greTrafficFrom(nic(50000000, 80000000))
	m := greTrafficFrom(nic(55000000, 85000000))
	if m["up"].(uint64) != 0 || m["down"].(uint64) != 0 {
		t.Fatalf("the main NIC must not count as tunnel traffic: %v", m)
	}
	if _, ok := m["speed_up"].(float64); !ok {
		t.Fatalf("speed_up must be a float64: %T", m["speed_up"])
	}
}

// devLines builds /proc/net/dev text: name -> {received, transmitted}.
func devLines(ifs map[string][2]uint64) string {
	s := "Inter-|   Receive |  Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets\n"
	for name, c := range ifs {
		s += fmt.Sprintf("  %s: %d 1 0 0 0 0 0 0 %d 1 0 0 0 0 0 0\n", name, c[0], c[1])
	}
	return s
}

func resetTrafficState(t *testing.T) {
	t.Helper()
	old := configDir
	configDir = t.TempDir()
	histMu.Lock()
	histLoaded, histCached = true, nil
	histMu.Unlock()
	trafficStateMu.Lock()
	trafficStateInit, lifetimeUp, lifetimeDown, lastRawUp, lastRawDown, lastRawIf = false, 0, 0, 0, 0, nil
	lastSampleAt, lastReadAt, speedDeltaUp, speedDeltaDown, currentSpeedUp, currentSpeedDown = time.Time{}, time.Time{}, 0, 0, 0, 0
	trafficStateMu.Unlock()
	t.Cleanup(func() { configDir = old })
}

// The throughput chart spiked to tens of GB/s whenever the tunnel interface
// went away (the source switched to the main NIC) or one of several tunnels
// dropped (the smaller sum counted as a counter reset). Only real bytes count.
func TestGreTrafficNoSpikeOnSourceChange(t *testing.T) {
	resetTrafficState(t)
	const gb = 1 << 30
	down := func(m map[string]any) uint64 { return m["down"].(uint64) }

	greTrafficFrom(devLines(map[string][2]uint64{"gre-a": {2 * gb, gb}, "gre-b": {gb, gb}}))
	m := greTrafficFrom(devLines(map[string][2]uint64{"gre-a": {2*gb + 100, gb}, "gre-b": {gb + 50, gb}}))
	if got := down(m); got != 150 {
		t.Fatalf("two tunnels: down = %d, want 150", got)
	}
	// gre-b drops: the smaller sum is not a counter reset.
	m = greTrafficFrom(devLines(map[string][2]uint64{"gre-a": {2*gb + 200, gb}}))
	if got := down(m); got != 250 {
		t.Fatalf("one tunnel dropped: down = %d, want 250", got)
	}
	// No tunnel interface: the panel falls back to the main NIC; its counter is only a baseline.
	m = greTrafficFrom(devLines(map[string][2]uint64{"lo": {5, 5}, "ens5": {500 * gb, 400 * gb}}))
	if got := down(m); got != 250 {
		t.Fatalf("switch to main NIC: down = %d, want 250", got)
	}
	// The tunnel comes back recreated (counter from zero).
	greTrafficFrom(devLines(map[string][2]uint64{"gre-a": {10, 0}}))
	m = greTrafficFrom(devLines(map[string][2]uint64{"gre-a": {30, 0}}))
	if got := down(m); got != 270 {
		t.Fatalf("tunnel back: down = %d, want 270", got)
	}
	// Same interface recreated between two samples: the new counter is real traffic.
	m = greTrafficFrom(devLines(map[string][2]uint64{"gre-a": {7, 0}}))
	if got := down(m); got != 277 {
		t.Fatalf("counter reset: down = %d, want 277", got)
	}
}
