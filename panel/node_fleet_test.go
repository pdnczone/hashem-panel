package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// nodeFleetFake: dashboards, watchdog backups, updates and customers, on
// top of nodeTunTest's servers 0 (central), 1 and 2.
func nodeFleetFake(t *testing.T, f *nodeTunFake, dash map[int]string, extra func(id int, path string) (int, []byte, bool)) {
	t.Helper()
	inner := nodeAPIFn
	nodeAPIFn = func(ctx context.Context, id int, method, path string, body any) (int, []byte, error) {
		p, _, _ := strings.Cut(path, "?")
		if extra != nil {
			if st, b, ok := extra(id, path); ok {
				return st, b, nil
			}
		}
		if p == "/api/dashboard" {
			return 200, []byte(dash[id]), nil
		}
		return inner(ctx, id, method, path, body)
	}
}

func TestNodeFleetOverviewCountsOnce(t *testing.T) {
	f := nodeTunTest(t)
	// a tunnel 1 (Iran) -> 2 (foreign); the central (0) is a foreign server of another Iran
	f.plans[1].Peers = []setupPlanPeer{{ID: 4, RemotePub: "192.0.2.7"}}
	f.plans[2].Uplinks = []setupPlanUplink{{Hub: 1, IranPub: "198.51.100.1"}}
	dash := map[int]string{
		0: `{"role":"foreign","health_state":"healthy","traffic":{"up":10,"down":20,"speed_up":1,"speed_down":2}}`,
		1: `{"role":"iran","health_state":"healthy","peer_count":1,"traffic":{"up":100,"down":200,"speed_up":5,"speed_down":6}}`,
		2: `{"role":"foreign","health_state":"degraded","traffic":{"up":200,"down":100,"speed_up":6,"speed_down":5}}`,
	}
	nodeFleetFake(t, f, dash, nil)
	v := nodeFleetOverview(context.Background())
	if len(v.Servers) != 3 || v.Online != 3 {
		t.Fatalf("servers: %+v", v)
	}
	// 2's traffic is the same bytes as 1's: counted once, at 1
	if v.Totals["up"] != 110 || v.Totals["down"] != 220 || v.Totals["speed_down"] != 8 {
		t.Fatalf("totals: %v", v.Totals)
	}
	for _, s := range v.Servers {
		if (s.ID == 2) == s.Counted {
			t.Fatalf("counted: %+v", s)
		}
		if s.ID == 2 && s.Health != "degraded" {
			t.Fatalf("health: %+v", s)
		}
	}
}

func TestNodeAlertsKeptForCentral(t *testing.T) {
	nodeAlerts.Lock()
	nodeAlerts.seq, nodeAlerts.events = 0, nil
	nodeAlerts.Unlock()
	nodeAlertTrk = newAlertTracker()
	nodeLinkState.Lock()
	old := nodeLinkState.Connected
	nodeLinkState.Connected = true
	nodeLinkState.Unlock()
	t.Cleanup(func() {
		nodeLinkState.Lock()
		nodeLinkState.Connected = old
		nodeLinkState.Unlock()
	})
	now := time.Now()
	nodeAlertsObserve(now, []linkSnap{{Name: "de", State: stateHealthy}}) // primes
	nodeAlertsObserve(now.Add(time.Minute), []linkSnap{{Name: "de", State: stateDown, Why: "no answer"}})
	raw, _ := nodeAlertsSince(json.RawMessage(`{"since":-1}`))
	var res struct {
		Seq    uint64           `json:"seq"`
		Events []nodeAlertEvent `json:"events"`
	}
	_ = json.Unmarshal(raw, &res)
	if res.Seq != 1 || len(res.Events) != 0 {
		t.Fatalf("start: %+v", res)
	}
	raw, _ = nodeAlertsSince(json.RawMessage(`{"since":0}`))
	_ = json.Unmarshal(raw, &res)
	if len(res.Events) != 1 || res.Events[0].Link != "de" || res.Events[0].To != stateDown {
		t.Fatalf("events: %+v", res)
	}
	raw, _ = nodeAlertsSince(json.RawMessage(`{"since":1}`))
	_ = json.Unmarshal(raw, &res)
	if len(res.Events) != 0 {
		t.Fatalf("seen already: %+v", res)
	}
}

func TestNodeFleetUpdateStopsOnFailure(t *testing.T) {
	f := nodeTunTest(t)
	old := nodeUpdateWait
	nodeUpdateWait = 2 * time.Second
	t.Cleanup(func() { nodeUpdateWait = old })
	nodesMu.Lock()
	nodeFindLocked(1).Info.Version = "v1"
	nodeFindLocked(2).Info.Version = "v1"
	nodesMu.Unlock()
	var asked []int
	nodeFleetFake(t, f, nil, func(id int, path string) (int, []byte, bool) {
		if path != "/api/update" {
			return 0, nil, false
		}
		asked = append(asked, id)
		if id == 1 { // it restarts on v2
			go func() {
				time.Sleep(100 * time.Millisecond)
				nodesMu.Lock()
				nodeFindLocked(1).Info.Version = "v2"
				nodesMu.Unlock()
			}()
			return 200, []byte(`{"status":"ok"}`), true
		}
		return 500, []byte(`{"error_code":"E-UPDATE-04","error":"download failed"}`), true
	})
	j := nodeTunRun(t, "update", 1, 2, func(j *nodeTunJob) error { return nodeFleetUpdate(context.Background(), j, []int{1, 2, 1}) })
	if j.State != "failed" || !strings.Contains(j.Log, "back on") || !strings.Contains(j.Log, "download failed") || len(asked) != 2 {
		t.Fatalf("job %+v asked %v", j, asked)
	}
	// a node that does not come back stops the rest
	asked = nil
	nodeFleetFake(t, f, nil, func(id int, path string) (int, []byte, bool) {
		if path == "/api/update" {
			asked = append(asked, id)
			return 200, []byte(`{"status":"ok"}`), true
		}
		return 0, nil, false
	})
	nodesMu.Lock()
	nodeFindLocked(1).Info.Version = "v2"
	nodesMu.Unlock()
	if j := nodeTunRun(t, "update", 1, 2, func(j *nodeTunJob) error { return nodeFleetUpdate(context.Background(), j, []int{1, 2}) }); j.State != "failed" ||
		!strings.Contains(j.Log, "did not come back") || len(asked) != 1 {
		t.Fatalf("not back: %+v %v", j, asked)
	}
}

func TestNodeBackupPull(t *testing.T) {
	f := nodeTunTest(t)
	nodeFleetFake(t, f, nil, func(id int, path string) (int, []byte, bool) {
		switch {
		case path == "/api/watchdog":
			return 200, []byte(`{"backups":[{"name":"hashem-2026-10-30.enc","time":"2026-10-30 01:00:00"},{"name":"hashem-2026-10-31.enc","time":"2026-10-31 01:00:00"},{"name":"../evil.enc","time":"2099-01-01 00:00:00"}]}`), true
		case strings.HasPrefix(path, "/api/watchdog/backup-download?f="):
			if !strings.HasSuffix(path, "hashem-2026-10-31.enc") {
				t.Errorf("asked for %s", path)
			}
			return 200, []byte("ENCRYPTED"), true
		}
		return 0, nil, false
	})
	name, err := nodeBackupPull(context.Background(), 1)
	if err != nil || name != "hashem-2026-10-31.enc" {
		t.Fatalf("pull: %q %v", name, err)
	}
	if b, _ := os.ReadFile(filepath.Join(nodeBackupDir(1), name)); string(b) != "ENCRYPTED" {
		t.Fatalf("kept: %q", b)
	}
	if name, _ := nodeBackupPull(context.Background(), 1); name != "" {
		t.Fatal("kept twice")
	}
	if l := nodeBackupsList(); len(l) != 1 || l[0].Node != 1 {
		t.Fatalf("list: %+v", l)
	}
	// older than 14 days: dropped
	old := time.Now().Add(-15 * 24 * time.Hour)
	_ = os.Chtimes(filepath.Join(nodeBackupDir(1), name), old, old)
	nodeBackupPrune(nodeBackupDir(1))
	if l := nodeBackupsList(); len(l) != 0 {
		t.Fatalf("not pruned: %+v", l)
	}
	for n, ok := range map[string]bool{"a.enc": true, "../a.enc": false, "a/b.enc": false, "a.txt": false, "a b.enc": false} {
		if nodeBackupName(n) != ok {
			t.Errorf("name %q", n)
		}
	}
	w := httptest.NewRecorder()
	handleNodeBackupGet(w, httptest.NewRequest("GET", "/x/api/nodes/backup?node=1&f=..%2Fnodes.json", nil))
	if w.Code == 200 {
		t.Fatal("a path out of the backups")
	}
}

func TestNodeFleetCustomers(t *testing.T) {
	f := nodeTunTest(t)
	nodeFleetFake(t, f, nil, func(id int, path string) (int, []byte, bool) {
		if path != "/api/customers" {
			return 0, nil, false
		}
		switch id {
		case 0:
			return 200, []byte(`{"customers":[{"id":1,"name":"a","token":"secret"}]}`), true
		case 1:
			return 402, []byte(`{"error_code":"E-LIC-01","error":"Customers is a Hashem Pro feature"}`), true
		}
		return 200, []byte(`{"customers":[{"id":3,"name":"c","cut":"expired"}]}`), true
	})
	list, errs := nodeFleetCustomers(context.Background())
	if len(list) != 2 || list[0].Server != 0 || list[1].Server != 2 || list[1].Cut != "expired" || len(errs) != 0 {
		t.Fatalf("list %+v errs %v", list, errs)
	}
	b, _ := json.Marshal(list)
	if strings.Contains(string(b), "secret") {
		t.Fatal("a customer's token in the list")
	}
	_ = http.StatusOK
}

// A second element or function of the same name hides the first: the page
// then drives the wrong card (it happened with the nodes overview).
func TestUINoDuplicateNames(t *testing.T) {
	html, _ := os.ReadFile("index.html")
	seen := map[string]bool{}
	for _, m := range regexp.MustCompile(` id="([^"]+)"`).FindAllStringSubmatch(string(html), -1) {
		if seen[m[1]] {
			t.Errorf("index.html: id %q twice", m[1])
		}
		seen[m[1]] = true
	}
	js, _ := os.ReadFile("app.js")
	seen = map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^(?:async )?function ([A-Za-z0-9_$]+)|^(?:const|let|var) ([A-Za-z0-9_$]+)`).FindAllStringSubmatch(string(js), -1) {
		n := m[1] + m[2]
		if seen[n] {
			t.Errorf("app.js: %q declared twice", n)
		}
		seen[n] = true
	}
}
