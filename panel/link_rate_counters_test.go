package main

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

func cnt(v uint64) *uint64 { return &v }

// The base tunnel's counters: the hub's main link, else (a foreign server)
// its own tunnel's. /api/status and /api/dashboard send the same ones.
func TestMainCounters(t *testing.T) {
	hub := &HubSnapshot{Main: &peerLive{Rx: cnt(10), Tx: cnt(20)}, LocalRx: cnt(1), LocalTx: cnt(2)}
	if rx, tx := mainCounters(hub); *rx != 10 || *tx != 20 {
		t.Fatalf("hub: %d %d", *rx, *tx)
	}
	foreign := &HubSnapshot{LocalRx: cnt(3), LocalTx: cnt(4)}
	if rx, tx := mainCounters(foreign); *rx != 3 || *tx != 4 {
		t.Fatalf("foreign: %d %d", *rx, *tx)
	}
	noCounters := &HubSnapshot{Main: &peerLive{}, LocalRx: cnt(5), LocalTx: cnt(6)}
	if rx, tx := mainCounters(noCounters); *rx != 5 || *tx != 6 {
		t.Fatalf("main without counters: %d %d", *rx, *tx)
	}
}

func TestBagherCounters(t *testing.T) {
	s := &HubSnapshot{CarrierTags: map[string][2]uint64{"bagher-1": {1, 2}, "bagher-3": {3, 4}, "frps": {9, 9}}}
	got := bagherCounters(s)
	if len(got) != 2 || got["bagher-1"] != [2]uint64{1, 2} || got["bagher-3"] != [2]uint64{3, 4} {
		t.Fatalf("got %v", got)
	}
	if got := bagherCounters(&HubSnapshot{}); len(got) != 0 {
		t.Fatalf("none: %v", got)
	}
}

// The Dashboard gets the base tunnel's and Bagher's counters with its own
// poll (every 5 s), next to counters_at, instead of only the 15 s /api/status.
func TestDashboardSendsLinkCounters(t *testing.T) {
	prev := snapPtr.Load()
	t.Cleanup(func() { snapPtr.Store(prev) })
	snapPtr.Store(&HubSnapshot{Main: &peerLive{Rx: cnt(1000), Tx: cnt(2000)},
		CarrierTags: map[string][2]uint64{"bagher-1": {7, 8}}})
	rr := httptest.NewRecorder()
	handleDashboard(rr, httptest.NewRequest("GET", "/api/dashboard", nil))
	var d map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &d); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if d["main_rx"] != float64(1000) || d["main_tx"] != float64(2000) {
		t.Fatalf("main counters: %v %v", d["main_rx"], d["main_tx"])
	}
	if bc, _ := d["bagher_counters"].(map[string]any); bc == nil || bc["bagher-1"] == nil {
		t.Fatalf("bagher counters: %v", d["bagher_counters"])
	}
}
