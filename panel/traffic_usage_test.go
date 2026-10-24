package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func up64(v uint64) *uint64 { return &v }

func newUsage() *usageStore { return &usageStore{links: map[string]*usageLink{}} }

var t0 = time.Date(2026, 10, 11, 12, 0, 30, 0, time.UTC)

func TestUsageDelta(t *testing.T) {
	cases := []struct {
		prev, cur uint64
		have      bool
		want      uint64
	}{
		{0, 500, false, 0},   // no baseline: nothing attributed
		{100, 150, true, 50}, // normal forward movement
		{100, 100, true, 0},  // idle
		{1000, 40, true, 40}, // counter reset: new value is the traffic since reset
		{1000, 0, true, 0},   // reset to zero with no traffic yet
	}
	for _, c := range cases {
		if got := usageDelta(c.prev, c.cur, c.have); got != c.want {
			t.Errorf("usageDelta(%d,%d,%v)=%d want %d", c.prev, c.cur, c.have, got, c.want)
		}
	}
}

func TestUsageAccumulatesPerMinuteAndDay(t *testing.T) {
	s := newUsage()
	s.observe("p1", "alpha", t0, up64(1000), up64(2000))                     // baseline only
	s.observe("p1", "alpha", t0.Add(10*time.Second), up64(1100), up64(2300)) // +100/+300 same minute
	s.observe("p1", "alpha", t0.Add(70*time.Second), up64(1150), up64(2300)) // +50/0 next minute
	l := s.links["p1"]
	if len(l.Points) != 2 {
		t.Fatalf("want 2 minute points, got %d: %+v", len(l.Points), l.Points)
	}
	if l.Points[0].Rx != 100 || l.Points[0].Tx != 300 {
		t.Errorf("first minute = %+v", l.Points[0])
	}
	if l.Points[1].Rx != 50 || l.Points[1].Tx != 0 {
		t.Errorf("second minute = %+v", l.Points[1])
	}
	if d := l.Days["2026-10-11"]; d.Rx != 150 || d.Tx != 300 {
		t.Errorf("day total = %+v", d)
	}
}

func TestUsageSurvivesRawCounterReset(t *testing.T) {
	s := newUsage()
	s.observe("p1", "a", t0, up64(10_000), up64(10_000))
	s.observe("p1", "a", t0.Add(60*time.Second), up64(10_500), up64(10_100)) // +500/+100
	// interface recreated / host rebooted: raw counters restart near zero
	s.observe("p1", "a", t0.Add(120*time.Second), up64(30), up64(5))
	s.observe("p1", "a", t0.Add(180*time.Second), up64(80), up64(9)) // +50/+4
	d := s.links["p1"].Days["2026-10-11"]
	if d.Rx != 500+30+50 || d.Tx != 100+5+4 {
		t.Fatalf("totals must not drop on reset: %+v", d)
	}
}

func TestUsageGapDoesNotSpikeWhenCountersReturn(t *testing.T) {
	s := newUsage()
	s.observe("p1", "a", t0, up64(1000), up64(1000))
	s.observe("p1", "a", t0.Add(60*time.Second), nil, nil) // interface briefly absent
	s.observe("p1", "a", t0.Add(120*time.Second), up64(1040), up64(1010))
	d := s.links["p1"].Days["2026-10-11"]
	if d.Rx != 40 || d.Tx != 10 {
		t.Fatalf("gap must keep the baseline, got %+v", d)
	}
}

func TestUsageRenameKeepsHistory(t *testing.T) {
	s := newUsage()
	s.observe("p2", "old-name", t0, up64(0), up64(0))
	s.observe("p2", "old-name", t0.Add(60*time.Second), up64(100), up64(0))
	s.observe("p2", "new-name", t0.Add(120*time.Second), up64(150), up64(0))
	l := s.links["p2"]
	if l.Name != "new-name" || l.Days["2026-10-11"].Rx != 150 {
		t.Fatalf("rename must keep data under the same key: %+v", l)
	}
}

func TestUsagePrunesAfterSevenDays(t *testing.T) {
	s := newUsage()
	s.observe("p1", "a", t0, up64(0), up64(0))
	s.observe("p1", "a", t0.Add(60*time.Second), up64(100), up64(100))
	later := t0.Add(7*24*time.Hour + 2*time.Minute)
	s.prune(later)
	if l := s.links["p1"]; l != nil && len(l.Points) != 0 {
		t.Fatalf("points older than 7 days must be dropped: %+v", l.Points)
	}
	// data inside the window survives
	s2 := newUsage()
	s2.observe("p1", "a", t0, up64(0), up64(0))
	s2.observe("p1", "a", t0.Add(60*time.Second), up64(100), up64(100))
	s2.prune(t0.Add(6 * 24 * time.Hour))
	if len(s2.links["p1"].Points) != 1 {
		t.Fatal("data younger than 7 days must be kept")
	}
}

func TestUsagePersistAndReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic_peers.json")
	s := newUsage()
	s.observe("main", "Tunnel", t0, up64(500), up64(500))
	s.observe("main", "Tunnel", t0.Add(60*time.Second), up64(800), up64(650))
	s.observe("p1", "alpha", t0, up64(0), up64(0))
	s.observe("p1", "alpha", t0.Add(60*time.Second), up64(10), up64(20))
	if err := s.save(path, t0.Add(61*time.Second)); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(path); err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("file must exist with mode 0600: %v %v", st, err)
	}
	// "restart": a fresh store reads the file and continues from the saved baseline
	r := newUsage()
	if n := r.load(path, t0.Add(2*time.Minute)); n != 2 {
		t.Fatalf("loaded %d links, want 2", n)
	}
	r.observe("main", "Tunnel", t0.Add(120*time.Second), up64(900), up64(700))
	d := r.links["main"].Days["2026-10-11"]
	if d.Rx != 300+100 || d.Tx != 150+50 {
		t.Fatalf("restart must not lose the interval or the history: %+v", d)
	}
}

func TestUsageCorruptFileIsQuarantinedNotFatal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic_peers.json")
	if err := os.WriteFile(path, []byte("{not json"), 0600); err != nil {
		t.Fatal(err)
	}
	s := newUsage()
	if n := s.load(path, t0); n != 0 {
		t.Fatalf("corrupt file must load nothing, got %d", n)
	}
	if _, err := os.Stat(path + ".bad"); err != nil {
		t.Fatal("corrupt file should be kept as .bad for inspection")
	}
}

func TestUsageSaveIsAtomic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic_peers.json")
	s := newUsage()
	s.observe("p1", "a", t0, up64(0), up64(0))
	s.observe("p1", "a", t0.Add(60*time.Second), up64(5), up64(5))
	if err := s.save(path, t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + ".tmp"); err == nil {
		t.Fatal("temp file must not be left behind")
	}
	var d usageDisk
	b, _ := os.ReadFile(path)
	if json.Unmarshal(b, &d) != nil || d.Version != usageFileVer {
		t.Fatalf("saved file must be valid JSON of the current version: %s", b)
	}
}

func TestUsageTotalAndSeriesWindow(t *testing.T) {
	s := newUsage()
	s.observe("main", "Tunnel", t0, up64(0), up64(0))
	s.observe("main", "Tunnel", t0.Add(60*time.Second), up64(100), up64(10))
	s.observe("p1", "alpha", t0, up64(0), up64(0))
	s.observe("p1", "alpha", t0.Add(60*time.Second), up64(40), up64(5))
	all := s.all(t0.Add(2*time.Minute), time.Hour, 60)
	if len(all) != 3 || all[0].Key != usageTotalKey {
		t.Fatalf("want total + 2 links, total first: %+v", all)
	}
	if all[0].Rx != 140 || all[0].Tx != 15 {
		t.Fatalf("total = %d/%d, want 140/15", all[0].Rx, all[0].Tx)
	}
	if all[1].Key != usageMainKey || all[2].Key != "p1" {
		t.Fatalf("order must be total, main, peers by id: %s %s", all[1].Key, all[2].Key)
	}
	// a window that excludes the data
	out := s.all(t0.Add(3*time.Hour), time.Hour, 60)
	if out[0].Rx != 0 || len(out[0].Points) != 0 {
		t.Fatalf("data outside the window must not count: %+v", out[0])
	}
}

func TestUsageBucketize(t *testing.T) {
	pts := []usagePoint{{T: 0, Rx: 1}, {T: 60, Rx: 2}, {T: 3600, Rx: 4}}
	got := bucketize(pts, 0, 3600)
	if len(got) != 2 || got[0].Rx != 3 || got[1].Rx != 4 {
		t.Fatalf("bucketize = %+v", got)
	}
}

func TestUsageKeyIsStableByID(t *testing.T) {
	if usageKey(peerLive{peerRecord: peerRecord{ID: 0}}) != usageMainKey {
		t.Fatal("id 0 is the main tunnel")
	}
	if usageKey(peerLive{peerRecord: peerRecord{ID: 7, Name: "x"}}) != "p7" {
		t.Fatal("peers are keyed by id, not name")
	}
}

func TestUsageOnSnapshotFeedsLedger(t *testing.T) {
	old := trafficUsage
	trafficUsage = newUsage()
	defer func() { trafficUsage = old }()
	mk := func(rx, tx uint64) *HubSnapshot {
		return &HubSnapshot{Peers: []peerLive{{peerRecord: peerRecord{ID: 3, Name: "w1"}, Rx: up64(rx), Tx: up64(tx)}}}
	}
	usageOnSnapshot(mk(100, 100))
	usageOnSnapshot(mk(160, 130))
	d := trafficUsage.links["p3"].Days[dayOf(time.Now().Unix())]
	if d.Rx != 60 || d.Tx != 30 {
		t.Fatalf("snapshot hook must record deltas: %+v", d)
	}
}

func TestUsageAPIReturnsJSON(t *testing.T) {
	old := trafficUsage
	trafficUsage = newUsage()
	defer func() { trafficUsage = old }()
	now := time.Now()
	trafficUsage.observe("p1", "alpha", now.Add(-time.Minute), up64(0), up64(0))
	trafficUsage.observe("p1", "alpha", now, up64(1234), up64(99))

	rec := httptest.NewRecorder()
	handleUsageGet(rec, httptest.NewRequest(http.MethodGet, "/api/traffic/usage?range=24h", nil))
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	var out struct {
		KeepDays int           `json:"keep_days"`
		Links    []usageSeries `json:"links"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.KeepDays != 7 || len(out.Links) != 2 || out.Links[1].Name != "alpha" || out.Links[1].Rx != 1234 {
		t.Fatalf("unexpected payload: %s", rec.Body.String())
	}
	if len(out.Links[0].Days) == 0 {
		t.Fatal("per-day totals must be present")
	}
}

func TestUsageRangeWindows(t *testing.T) {
	if w, _ := usageRange("1h"); w != time.Hour {
		t.Fatal("1h")
	}
	if w, _ := usageRange("garbage"); w != usageKeep {
		t.Fatal("unknown range defaults to the full 7 days")
	}
}

func TestUsageConcurrentObserveAndSave(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.json")
	s := newUsage()
	done := make(chan struct{})
	go func() {
		for i := 0; i < 200; i++ {
			_ = s.save(path, time.Now())
		}
		close(done)
	}()
	for i := 0; i < 2000; i++ {
		s.observe("p1", "a", time.Now(), up64(uint64(i*10)), up64(uint64(i*5)))
	}
	<-done
}

func TestUsageRouteIsAdminOnly(t *testing.T) {
	// the route is registered as requireAuth(handleUsageGet); without a session
	// cookie it must be refused and must not leak the ledger.
	h := requireAuth(handleUsageGet)
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/api/traffic/usage", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated request got %d, want 401", rec.Code)
	}
	if strings := rec.Body.String(); len(strings) > 0 && json.Valid(rec.Body.Bytes()) {
		var m map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &m)
		if _, leaked := m["links"]; leaked {
			t.Fatal("ledger leaked to an unauthenticated caller")
		}
	}
}

const devSample = `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 111 1 0 0 0 0 0 0 111 1 0 0 0 0 0 0
  ens5: 9999 1 0 0 0 0 0 0 8888 1 0 0 0 0 0 0
gre-tunnel: 1000 5 0 0 0 0 0 0 2000 6 0 0 0 0 0 0
gre-p2: 300 5 0 0 0 0 0 0 400 6 0 0 0 0 0 0
`

func TestTunnelRawTotalsSumsOnlyTunnelInterfaces(t *testing.T) {
	rx, tx := tunnelRawTotals(devSample)
	if rx == nil || tx == nil {
		t.Fatal("gre-* interfaces must be found")
	}
	if *rx != 1300 || *tx != 2400 {
		t.Fatalf("got %d/%d, want 1300/2400 (lo and ens5 excluded)", *rx, *tx)
	}
	if a, b := tunnelRawTotals("garbage"); a != nil || b != nil {
		t.Fatal("no tunnel interface => nil, so no bogus baseline is stored")
	}
}

func TestUsageHostSeriesOnSpoke(t *testing.T) {
	old := trafficUsage
	trafficUsage = newUsage()
	defer func() { trafficUsage = old }()
	// a spoke has no peers and no main tunnel, only the raw interface counters
	usageOnSnapshot(&HubSnapshot{DevData: devSample})
	next := `gre-tunnel: 1500 5 0 0 0 0 0 0 2100 6 0 0 0 0 0 0
`
	usageOnSnapshot(&HubSnapshot{DevData: next})
	l := trafficUsage.links[usageHostKey]
	if l == nil {
		t.Fatal("host series must exist on a spoke")
	}
	d := l.Days[dayOf(time.Now().Unix())]
	// Per interface: gre-tunnel moved 1000->1500 rx and 2000->2100 tx; gre-p2
	// vanished and counts nothing. The old raw sum (1300->1500, 2400->2100)
	// booked rx +200 and took the smaller tx sum for a reset: tx +2100.
	if d.Rx != 500 || d.Tx != 100 {
		t.Fatalf("delta = %d/%d, want 500/100", d.Rx, d.Tx)
	}
}

// A new interface (a peer added) brings its existing counter: a baseline,
// not traffic. The raw sum counted it in full.
func TestUsageHostNewInterfaceIsBaseline(t *testing.T) {
	old := trafficUsage
	trafficUsage = newUsage()
	defer func() { trafficUsage = old }()
	usageOnSnapshot(&HubSnapshot{DevData: devLines(map[string][2]uint64{"gre-tunnel": {1000, 2000}})})
	usageOnSnapshot(&HubSnapshot{DevData: devLines(map[string][2]uint64{"gre-tunnel": {1010, 2020}, "gre-p9": {77777, 88888}})})
	both := devLines(map[string][2]uint64{"gre-tunnel": {1010, 2020}, "gre-p9": {77787, 88898}})
	usageOnSnapshot(&HubSnapshot{DevData: both, CarrierOK: true, CarrierRx: 500, CarrierTx: 600})
	usageOnSnapshot(&HubSnapshot{DevData: both, CarrierOK: true, CarrierRx: 540, CarrierTx: 660})
	d := trafficUsage.links[usageHostKey].Days[dayOf(time.Now().Unix())]
	// gre-tunnel +10/+20, gre-p9 +10/+10 after its baseline, carrier +40/+60 after its baseline
	if d.Rx != 60 || d.Tx != 90 {
		t.Fatalf("host = %d/%d, want 60/90", d.Rx, d.Tx)
	}
}

func TestUsageTotalNotDoubleCountedOnHub(t *testing.T) {
	s := newUsage()
	for _, k := range []string{usageMainKey, "p1", usageHostKey} {
		s.observe(k, k, t0, up64(0), up64(0))
	}
	s.observe(usageMainKey, "Tunnel", t0.Add(60*time.Second), up64(100), up64(10))
	s.observe("p1", "alpha", t0.Add(60*time.Second), up64(40), up64(5))
	s.observe(usageHostKey, "host", t0.Add(60*time.Second), up64(140), up64(15)) // raw sum of both
	all := s.all(t0.Add(2*time.Minute), time.Hour, 60)
	if all[0].Rx != 140 || all[0].Tx != 15 {
		t.Fatalf("hub total must be 140/15 (not doubled): %d/%d", all[0].Rx, all[0].Tx)
	}
}

func TestUsageTotalOnSpokeIsHost(t *testing.T) {
	s := newUsage()
	s.observe(usageHostKey, "host", t0, up64(0), up64(0))
	s.observe(usageHostKey, "host", t0.Add(60*time.Second), up64(70), up64(9))
	all := s.all(t0.Add(2*time.Minute), time.Hour, 60)
	if all[0].Rx != 70 || all[0].Tx != 9 {
		t.Fatalf("spoke total must come from the host series: %d/%d", all[0].Rx, all[0].Tx)
	}
}

// A link whose own counter reads nothing (FRP-only spoke) must not pull the
// total below what the tunnel interfaces carried.
func TestUsageTotalNeverBelowHost(t *testing.T) {
	s := newUsage()
	for _, k := range []string{usageMainKey, usageHostKey} {
		s.observe(k, k, t0, up64(0), up64(0))
	}
	s.observe(usageMainKey, "Tunnel", t0.Add(60*time.Second), nil, nil)
	s.observe(usageHostKey, "host", t0.Add(60*time.Second), up64(5000), up64(700))
	all := s.all(t0.Add(2*time.Minute), time.Hour, 60)
	if all[0].Rx != 5000 || all[0].Tx != 700 || len(all[0].Points) == 0 {
		t.Fatalf("total must follow the host series when the links count less: %+v", all[0])
	}
}
