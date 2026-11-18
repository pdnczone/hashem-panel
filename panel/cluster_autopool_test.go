package main

import (
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// A second foreign server on a port one tunnel serves: with pool_on_clash the
// panel makes the failover pool first, so the order of Setup does not matter.
func TestAutoPoolForClash(t *testing.T) {
	f := newClusterFixture(t, true)
	f.peer(1, 7001, "198.51.100.1", 443, 2083)

	made, err := autoPoolForClash([]int{443})
	if err != nil || len(made) != 1 {
		t.Fatalf("made %v, err %v", made, err)
	}
	p := made[0]
	if p.Port != 443 || p.Mode != lbFailover || p.Proto != "both" || len(p.Members) != 1 || p.Members[0].Link != 1 {
		t.Fatalf("pool: %+v", p)
	}
	if got := loadClusterConfig().Pools; len(got) != 1 || got[0].Port != 443 {
		t.Fatalf("saved pools: %+v", got)
	}
	// the clash is gone now: a second tunnel may take the port
	if c := peerPortClash([]int{443}, -1); c != "" {
		t.Fatalf("port still clashes: %s", c)
	}
	// nothing more to do the second time
	if again, err := autoPoolForClash([]int{443}); err != nil || len(again) != 0 {
		t.Fatalf("second call made %v (%v)", again, err)
	}
	// a port no tunnel serves is not this function's business
	if none, err := autoPoolForClash([]int{8443}); err != nil || len(none) != 0 {
		t.Fatalf("free port made %v (%v)", none, err)
	}
}

func TestAutoPoolNeedsTheClusterLicense(t *testing.T) {
	f := newClusterFixture(t, false)
	f.peer(1, 7001, "198.51.100.1", 443)
	made, err := autoPoolForClash([]int{443})
	if err != nil || len(made) != 0 {
		t.Fatalf("an unlicensed hub made %v (%v)", made, err)
	}
	if len(loadClusterConfig().Pools) != 0 {
		t.Fatal("a pool was saved without the license")
	}
}

func TestAutoPoolBackhaulStartsAsTCP(t *testing.T) {
	f := newClusterFixture(t, true)
	f.snap.Peers = append(f.snap.Peers, peerLive{peerRecord: peerRecord{ID: 2, Name: "bh", RemotePub: "198.51.100.2",
		FrpPort: 7002, FrpsSvc: "backhaul-server-2", Ports: []int{443}}, HealthState: stateHealthy})
	made, err := autoPoolForClash([]int{443})
	if err != nil || len(made) != 1 || made[0].Proto != "tcp" {
		t.Fatalf("made %+v (%v)", made, err)
	}
}

func TestUndoAutoPools(t *testing.T) {
	f := newClusterFixture(t, true)
	f.peer(1, 7001, "198.51.100.1", 443, 2083)
	made, _ := autoPoolForClash([]int{443, 2083})
	if len(made) != 2 {
		t.Fatalf("made %v", made)
	}
	undoAutoPools(made[:1])
	got := loadClusterConfig().Pools
	if len(got) != 1 || got[0].Port != 2083 {
		t.Fatalf("after undo: %+v", got)
	}
}

// The new tunnel's relay listens on a private address from the start, so the
// installer must not run until the old relay has moved behind the pool.
func TestWaitPoolsBound(t *testing.T) {
	f := newClusterFixture(t, true)
	f.peer(1, 7001, "198.51.100.1", 443)
	made, _ := autoPoolForClash([]int{443})
	old := autoPoolWait
	autoPoolWait = 300 * time.Millisecond
	defer func() { autoPoolWait = old }()

	var bound atomic.Bool
	lbIsBound = func(string, string) bool { return bound.Load() } // restored by the fixture
	err := waitPoolsBound(made)                                   // the relay is not behind the pool
	if err == nil || !strings.Contains(err.Error(), "did not move behind") {
		t.Fatalf("a relay that never rebinds: %v", err)
	}
	go func() {
		time.Sleep(100 * time.Millisecond)
		bound.Store(true)
	}()
	autoPoolWait = 5 * time.Second
	if err := waitPoolsBound(made); err != nil {
		t.Fatalf("a relay that rebinds: %v", err)
	}
	if err := waitPoolsBound(nil); err != nil {
		t.Fatal(err)
	}
}
