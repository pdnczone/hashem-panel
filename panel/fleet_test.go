package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func resetFleet() {
	fleetMu.Lock()
	fleetHist = map[int][]fleetSample{}
	fleetDirty = false
	fleetMu.Unlock()
	_ = os.Remove(fleetPath())
	resetSnapshotState()
}

func mkLive(id int, gre, frp, ping bool, ms string) peerLive {
	return peerLive{peerRecord: peerRecord{ID: id, Name: "n"}, GreUp: gre, FrpUp: frp, PingOK: ping, PingMs: ms}
}

func TestParsePingMs(t *testing.T) {
	cases := map[string]float64{"12ms": 12, " 3.5ms ": 3.5, "": -1, "abc": -1, "-2ms": -1}
	for in, want := range cases {
		if got := parsePingMs(in); got != want {
			t.Errorf("parsePingMs(%q)=%v want %v", in, got, want)
		}
	}
}

func TestFleetHealthLevels(t *testing.T) {
	if fleetHealth(mkLive(1, true, true, true, "5ms")) != fleetOK {
		t.Fatal("all up must be OK")
	}
	if fleetHealth(mkLive(1, true, false, false, "")) != fleetDeg {
		t.Fatal("one leg must be degraded")
	}
	if fleetHealth(mkLive(1, true, true, false, "")) != fleetDeg {
		t.Fatal("legs up but no ping must be degraded")
	}
	if fleetHealth(mkLive(1, false, false, false, "")) != fleetDown {
		t.Fatal("nothing up must be down")
	}
}

func TestFleetStats(t *testing.T) {
	h := []fleetSample{{1, 10, fleetOK}, {2, 30, fleetOK}, {3, -1, fleetDown}, {4, 20, fleetDeg}}
	st := fleetCompute(h)
	if st.AvgMs != 20 || st.MinMs != 10 || st.MaxMs != 30 {
		t.Fatalf("latency stats wrong: %+v", st)
	}
	if st.LossPct != 25 || st.UpPct != 75 {
		t.Fatalf("loss/up wrong: %+v", st)
	}
	if z := fleetCompute(nil); z.Samples != 0 || z.UpPct != 0 {
		t.Fatalf("empty: %+v", z)
	}
}

func TestFleetRecordTrimsPrunesAndPersists(t *testing.T) {
	resetFleet()
	fleetLoad = syncOnceReset()
	now := time.Unix(1_800_000_000, 0)
	for i := 0; i < fleetKeepSamples+25; i++ {
		fleetRecord([]peerLive{mkLive(1, true, true, true, "9ms"), mkLive(2, false, false, false, "")}, now.Add(time.Duration(i)*time.Second))
	}
	fleetMu.Lock()
	n1, n2 := len(fleetHist[1]), len(fleetHist[2])
	fleetMu.Unlock()
	if n1 != fleetKeepSamples || n2 != fleetKeepSamples {
		t.Fatalf("ring not capped: %d %d", n1, n2)
	}
	fleetRecord([]peerLive{mkLive(1, true, true, true, "9ms")}, now)
	fleetMu.Lock()
	_, has2 := fleetHist[2]
	fleetSaveLocked()
	fleetMu.Unlock()
	if has2 {
		t.Fatal("removed peer history must be pruned")
	}
	// reload from disk
	fleetMu.Lock()
	fleetHist = map[int][]fleetSample{}
	fleetMu.Unlock()
	fleetLoad = syncOnceReset()
	fleetMu.Lock()
	fleetLoadLocked()
	got := len(fleetHist[1])
	fleetMu.Unlock()
	if got != fleetKeepSamples {
		t.Fatalf("persisted history lost: %d", got)
	}
}

func TestFleetEndpointNoSecrets(t *testing.T) {
	resetFleet()
	fleetLoad = syncOnceReset()
	recs := []peerRecord{{ID: 1, Name: "Germany", RemotePub: "5.75.195.15", Token: "SUPERSECRETTOKEN", Engine: "frp", Ports: []int{7091}}}
	live := map[int]peerLive{1: {peerRecord: recs[0], GreUp: true, FrpUp: true, PingOK: true, PingMs: "42ms"}}
	fleetRecord([]peerLive{live[1]}, time.Now())
	nodes := fleetSnapshot(recs, live)
	if len(nodes) != 1 || nodes[0].Health != "healthy" || nodes[0].PingMs != 42 || len(nodes[0].History) != 1 {
		t.Fatalf("snapshot wrong: %+v", nodes)
	}
	rr := httptest.NewRecorder()
	handleFleet(rr, httptest.NewRequest(http.MethodGet, "/api/fleet", nil))
	if rr.Code != 200 || strings.Contains(rr.Body.String(), "SUPERSECRETTOKEN") || strings.Contains(strings.ToLower(rr.Body.String()), "token") {
		t.Fatalf("fleet payload must never contain tokens: %s", rr.Body.String())
	}
}

func TestFleetSnapshotDownWithoutLive(t *testing.T) {
	resetFleet()
	fleetLoad = syncOnceReset()
	recs := []peerRecord{{ID: 7, Name: ""}}
	nodes := fleetSnapshot(recs, nil)
	if nodes[0].Name != "peer-7" || nodes[0].Health != "down" || nodes[0].PingMs != -1 || nodes[0].Ports == nil {
		t.Fatalf("defaults wrong: %+v", nodes[0])
	}
}

func TestFleetSaveIsAtomicAndOnlyWhenDirty(t *testing.T) {
	resetFleet()
	fleetLoad = syncOnceReset()
	if fleetFlushIfDirty() {
		t.Fatal("nothing recorded: no write")
	}
	if _, err := os.Stat(fleetPath()); err == nil {
		t.Fatal("clean state must not create the file")
	}
	fleetRecord([]peerLive{mkLive(1, true, true, true, "9ms")}, time.Now())
	if !fleetFlushIfDirty() {
		t.Fatal("dirty state must be written")
	}
	if _, err := os.Stat(fleetPath() + ".tmp"); err == nil {
		t.Fatal("temp file must be renamed away")
	}
	first, err := os.Stat(fleetPath())
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	if fleetFlushIfDirty() {
		t.Fatal("second flush without new samples must be a no-op")
	}
	if again, _ := os.Stat(fleetPath()); !again.ModTime().Equal(first.ModTime()) {
		t.Fatal("file must not be rewritten when clean")
	}
	// on-disk format unchanged: {"<id>": [{"t","ms","s"}]}
	b, _ := os.ReadFile(fleetPath())
	if !strings.Contains(string(b), `"1": [`) || !strings.Contains(string(b), `"ms"`) {
		t.Fatalf("format changed: %s", b)
	}
}
