package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestHistoryRoundTripKeepsRecentDropsOld(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	h := &histStore{links: map[string]*histRing{}}
	h.recordSample("a", now.Add(-26*time.Hour), stateHealthy, 5, nil, nil) // too old
	h.recordSample("a", now.Add(-2*time.Hour), stateDown, -1, nil, nil)
	h.recordSample("a", now.Add(-time.Hour), stateHealthy, 7, nil, nil)
	h.recordSample("b", now.Add(-30*time.Hour), stateHealthy, 1, nil, nil) // whole link too old

	f := filepath.Join(t.TempDir(), "history.json")
	if err := h.save(f, now); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(f); st.Mode().Perm() != 0600 {
		t.Errorf("history file mode %v, want 0600", st.Mode().Perm())
	}
	if _, err := os.Stat(f + ".tmp"); err == nil {
		t.Error("temp file must not be left behind")
	}

	h2 := &histStore{links: map[string]*histRing{}}
	if n := h2.load(f, now); n != 2 {
		t.Fatalf("loaded %d points, want 2", n)
	}
	s := h2.series("a", 0)
	if len(s) != 2 || s[0].State != 0 || s[1].Ms != 7 {
		t.Fatalf("series after reload: %+v", s)
	}
	if len(h2.series("b", 0)) != 0 {
		t.Error("link with only expired points must not come back")
	}
}

func TestHistoryLoadResumesWithoutBogusRate(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	h := &histStore{links: map[string]*histRing{}}
	h.recordSample("a", now.Add(-time.Hour), stateHealthy, 1, hpU64(100), hpU64(100))
	f := filepath.Join(t.TempDir(), "h.json")
	_ = h.save(f, now)

	h2 := &histStore{links: map[string]*histRing{}}
	h2.load(f, now)
	// after a restart the byte counters may have reset: first new sample must have no rate
	h2.recordSample("a", now, stateHealthy, 1, hpU64(5_000_000), hpU64(5_000_000))
	s := h2.series("a", 0)
	if last := s[len(s)-1]; last.RxBps != 0 || last.TxBps != 0 {
		t.Errorf("first sample after reload must not invent a rate: %+v", last)
	}
}

func TestHistoryLoadIgnoresGarbage(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	dir := t.TempDir()
	for name, content := range map[string]string{
		"corrupt.json": "{not json", "future.json": `{"v":99,"links":{"a":[{"t":1}]}}`, "empty.json": "",
	} {
		f := filepath.Join(dir, name)
		_ = os.WriteFile(f, []byte(content), 0600)
		h := &histStore{links: map[string]*histRing{}}
		if n := h.load(f, now); n != 0 || len(h.links) != 0 {
			t.Errorf("%s: loaded %d", name, n)
		}
	}
	if (&histStore{links: map[string]*histRing{}}).load(filepath.Join(dir, "missing.json"), now) != 0 {
		t.Error("missing file = nothing loaded")
	}
}

func TestHistoryLoadRejectsBadTimestamps(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	body := `{"v":1,"links":{"a":[{"t":` + itoa(now.Unix()-100) + `,"state":2,"ms":1},{"t":` + itoa(now.Unix()-200) + `,"state":2,"ms":2},{"t":` + itoa(now.Unix()+99999) + `,"state":2,"ms":3}]}}`
	f := filepath.Join(t.TempDir(), "h.json")
	_ = os.WriteFile(f, []byte(body), 0600)
	h := &histStore{links: map[string]*histRing{}}
	if n := h.load(f, now); n != 1 {
		t.Fatalf("only the first in-order, non-future point should load, got %d", n)
	}
}

func TestHistoryLoadDoesNotOverwriteLiveData(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	src := &histStore{links: map[string]*histRing{}}
	src.recordSample("a", now.Add(-time.Hour), stateDown, 9, nil, nil)
	f := filepath.Join(t.TempDir(), "h.json")
	_ = src.save(f, now)

	live := &histStore{links: map[string]*histRing{}}
	live.recordSample("a", now, stateHealthy, 1, nil, nil)
	live.load(f, now)
	if s := live.series("a", 0); len(s) != 1 || s[0].State != 2 {
		t.Errorf("fresh in-memory data must win: %+v", s)
	}
}

func TestHistoryPersistenceStopsAndFlushes(t *testing.T) {
	old := configDir
	configDir = t.TempDir()
	defer func() { configDir = old }()
	linkHist.mu.Lock()
	saved := linkHist.links
	linkHist.links = map[string]*histRing{}
	linkHist.mu.Unlock()
	defer func() { linkHist.mu.Lock(); linkHist.links = saved; linkHist.mu.Unlock() }()

	linkHist.recordSample("zz", time.Now(), stateHealthy, 3, nil, nil)
	stop := make(chan struct{})
	startHistoryPersistence(stop)
	close(stop)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(histFile()); err == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("stop must flush history to disk")
}

func itoa(n int64) string {
	b := []byte{}
	neg := n < 0
	if neg {
		n = -n
	}
	for {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
		if n == 0 {
			break
		}
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}
