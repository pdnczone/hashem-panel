package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const syncTestSecret = "0123456789abcdef0123456789abcdef"

// syncSigned is a request signed by another hub of the cluster.
func syncSigned(t *testing.T, path string, body any) *http.Request {
	t.Helper()
	raw, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, meshRoutePrefix+path, bytes.NewReader(raw))
	meshSetSig(r.Header, syncTestSecret, raw)
	return r
}

// syncHub sets this hub up: its id, the cluster secret and one linked hub.
func syncHub(t *testing.T, linkedIP string) {
	t.Helper()
	if _, err := updateClusterConfig(func(c *ClusterConfig) error {
		c.NodeID, c.Name, c.Secret = "hub-self", "tehran", syncTestSecret
		c.Hubs = []HubPeer{{ID: "hub-a", Name: "mashhad", URL: "http://203.0.113.9:7778", PublicIP: linkedIP}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func syncMux() *http.ServeMux {
	mux := http.NewServeMux()
	mountMeshRoutes(mux)
	return mux
}

func TestMeshTunnelsAnswer(t *testing.T) {
	newClusterFixture(t, true)
	syncHub(t, "203.0.113.9")
	old := syncLocalTunnels
	syncLocalTunnels = func() []syncTunnel {
		return []syncTunnel{{Name: "de", Remote: "198.51.100.1", Engine: "frp", Ports: []int{443}, PeerGre: "10.10.10.1"}}
	}
	defer func() { syncLocalTunnels = old }()
	if _, err := updateClusterConfig(func(c *ClusterConfig) error {
		c.Pools = []LBPool{{Port: 443, Proto: "both", Mode: lbFailover}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	syncMux().ServeHTTP(rec, syncSigned(t, "/tunnels", map[string]string{"id": "hub-a"}))
	if rec.Code != 200 {
		t.Fatalf("a linked hub got %d", rec.Code)
	}
	if err := meshVerify(syncTestSecret, rec.Header(), rec.Body.Bytes(), time.Now()); err != nil {
		t.Fatalf("the answer is not signed: %v", err)
	}
	var got syncList
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Tunnels) != 1 || got.Tunnels[0].Remote != "198.51.100.1" || len(got.Pools) != 1 || got.Pools[0].Port != 443 {
		t.Fatalf("answer: %+v", got)
	}
	if bytes.Contains(rec.Body.Bytes(), []byte("token")) {
		t.Fatal("the list must carry no token")
	}

	// unsigned, unknown hub, and the hub itself all get a bare 404
	for name, r := range map[string]*http.Request{
		"unsigned": httptest.NewRequest(http.MethodPost, meshRoutePrefix+"/tunnels", strings.NewReader(`{"id":"hub-a"}`)),
		"unknown":  syncSigned(t, "/tunnels", map[string]string{"id": "hub-x"}),
		"self":     syncSigned(t, "/tunnels", map[string]string{"id": "hub-self"}),
	} {
		rec := httptest.NewRecorder()
		syncMux().ServeHTTP(rec, r)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s: got %d, want 404", name, rec.Code)
		}
	}
}

func TestMeshDeliver(t *testing.T) {
	newClusterFixture(t, true)
	syncHub(t, "203.0.113.9")
	if err := os.WriteFile(filepath.Join(configDir, "peers.json"), []byte(`{"peers":[{"id":3,"name":"de","remote_pub":"198.51.100.1","ports":[443]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	oldTun := syncLocalTunnels
	syncLocalTunnels = func() []syncTunnel {
		return []syncTunnel{{Name: "de", Remote: "198.51.100.1", Engine: "frp", Ports: []int{443}}}
	}
	defer func() { syncLocalTunnels = oldTun }()
	var calls []map[string]string
	var calledID int
	old := syncPeerCall
	defer func() { syncPeerCall = old }()
	answer := []byte(`{"status":"ok"}`)
	var answerErr error
	syncPeerCall = func(id int, p map[string]string) ([]byte, error) {
		calledID = id
		calls = append(calls, p)
		return answer, answerErr
	}
	good := MakeBundle("203.0.113.9", 7001, "10.11.0.2", "10.11.0.1", "tok", []int{443})
	elsewhere := MakeBundle("192.0.2.77", 7001, "10.11.0.2", "10.11.0.1", "tok", []int{443})
	moreports := MakeBundle("203.0.113.9", 7001, "10.11.0.2", "10.11.0.1", "tok", []int{443, 9090, 22})
	seal := func(b string) string {
		t.Helper()
		x, err := syncSeal(syncTestSecret, b)
		if err != nil {
			t.Fatal(err)
		}
		return x
	}

	ask := func(remote, bundle string) syncDeliverAns {
		t.Helper()
		rec := httptest.NewRecorder()
		syncMux().ServeHTTP(rec, syncSigned(t, "/deliver", syncDeliverReq{ID: "hub-a", Remote: remote, Bundle: bundle, Name: "mashhad"}))
		if rec.Code != 200 {
			t.Fatalf("got %d: %s", rec.Code, rec.Body.String())
		}
		var a syncDeliverAns
		if err := json.Unmarshal(rec.Body.Bytes(), &a); err != nil {
			t.Fatal(err)
		}
		return a
	}

	if a := ask("198.51.100.1", seal(good)); !a.OK || a.Status != "ok" || calledID != 3 || len(calls) != 1 || calls[0]["bundle"] != good {
		t.Fatalf("good: %+v, id %d, calls %v", a, calledID, calls)
	}
	// a bundle sent in the clear is refused: it must be sealed
	calls = nil
	if a := ask("198.51.100.1", good); a.OK || len(calls) != 0 {
		t.Fatalf("an unsealed bundle was accepted: %+v", a)
	}
	// a bundle that does not name the hub that asked goes nowhere
	if a := ask("198.51.100.1", seal(elsewhere)); a.OK || !strings.Contains(a.Error, "not the hub that asked") || len(calls) != 0 {
		t.Fatalf("a bundle for another address: %+v, calls %v", a, calls)
	}
	// a bundle that would publish other ports of the foreign server goes nowhere
	if a := ask("198.51.100.1", seal(moreports)); a.OK || !strings.Contains(a.Error, "other ports") || len(calls) != 0 {
		t.Fatalf("a bundle with extra ports: %+v, calls %v", a, calls)
	}
	// a foreign server this hub has no tunnel to
	if a := ask("198.51.100.99", seal(good)); a.OK || !strings.Contains(a.Error, "no tunnel to") || len(calls) != 0 {
		t.Fatalf("unknown foreign server: %+v", a)
	}
	// an older foreign panel answers 404: tell the user what to do
	answerErr = errors.New("foreign panel answered HTTP 404: ")
	if a := ask("198.51.100.1", seal(good)); a.OK || !strings.Contains(a.Error, "hashem update") {
		t.Fatalf("older foreign panel: %+v", a)
	}
}

func TestSyncSeal(t *testing.T) {
	sealed, err := syncSeal(syncTestSecret, "hsh1_secret-token")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sealed, "hsh1_") || strings.Contains(sealed, "secret-token") {
		t.Fatalf("the bundle shows through: %s", sealed)
	}
	if got, err := syncOpen(syncTestSecret, sealed); err != nil || got != "hsh1_secret-token" {
		t.Fatalf("open: %q %v", got, err)
	}
	if _, err := syncOpen("another-cluster-secret-0123456789", sealed); err == nil {
		t.Fatal("a hub with another secret opened it")
	}
	if _, err := syncOpen(syncTestSecret, sealed[:len(sealed)-3]); err == nil {
		t.Fatal("a cut bundle opened")
	}
}

func TestPeerJoinHubAlreadyServed(t *testing.T) {
	newClusterFixture(t, true)
	hub := MakeBundle("203.0.113.9", 7001, "10.11.0.2", "10.11.0.1", "tok", []int{443})
	data := `{"hubs":[{"id":2,"name":"mashhad","iran_pub":"203.0.113.9","engine":"frp","svc":"frpc-h2","port":7001}]}`
	if err := os.WriteFile(hubsFile(), []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	joinedMu.Lock()
	joinedAt = time.Time{}
	joinedMu.Unlock()
	rec := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]string{"bundle": hub, "name": "mashhad"})
	handlePeerJoinHub(rec, httptest.NewRequest(http.MethodPost, "/_hp/api/peer/join-hub", bytes.NewReader(body)))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"already"`) {
		t.Fatalf("got %d %s", rec.Code, rec.Body.String())
	}
}

func TestPeerJoinHubNeedsTheClusterLicense(t *testing.T) {
	newClusterFixture(t, false)
	joinedMu.Lock()
	joinedAt = time.Time{}
	joinedMu.Unlock()
	hub := MakeBundle("203.0.113.9", 7001, "10.11.0.2", "10.11.0.1", "tok", []int{443})
	rec := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]string{"bundle": hub})
	handlePeerJoinHub(rec, httptest.NewRequest(http.MethodPost, "/_hp/api/peer/join-hub", bytes.NewReader(body)))
	if rec.Code == 200 || !strings.Contains(rec.Body.String(), "E-LIC-01") {
		t.Fatalf("an unlicensed foreign server joined: %d %s", rec.Code, rec.Body.String())
	}
}

func TestSyncGrePair(t *testing.T) {
	l, p := syncGrePair(nil)
	if l != defaultIranGRE || p != defaultForeignGRE {
		t.Fatalf("first pair: %s %s", l, p)
	}
	// the other hub's tunnel uses the default pair: the copy takes another one
	l, p = syncGrePair(nil, defaultIranGRE, defaultForeignGRE)
	if l == defaultIranGRE || p == defaultForeignGRE || l == "" {
		t.Fatalf("pair next to the default: %s %s", l, p)
	}
	l2, _ := syncGrePair([]string{l}, defaultIranGRE, defaultForeignGRE)
	if l2 == l {
		t.Fatal("a pair this hub uses was handed out again")
	}
}

// fakeSyncHub is the other hub: it answers /tunnels and /deliver, signed.
type fakeSyncHub struct {
	mu      sync.Mutex
	list    syncList
	deliver func(syncDeliverReq) syncDeliverAns
	got     []syncDeliverReq
	pull    func() (int, syncPullAns) // nil: an old hub without /pull (404)
	state   func() syncState
	pulled  int
}

func (f *fakeSyncHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body := make([]byte, 1<<16)
	n, _ := r.Body.Read(body)
	body = body[:n]
	if meshVerify(syncTestSecret, r.Header, body, time.Now()) != nil {
		http.NotFound(w, r)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	switch strings.TrimPrefix(r.URL.Path, meshRoutePrefix) {
	case "/tunnels":
		meshAnswer(w, syncTestSecret, f.list)
	case "/deliver":
		var q syncDeliverReq
		_ = json.Unmarshal(body, &q)
		if plain, err := syncOpen(syncTestSecret, q.Bundle); err == nil {
			q.Bundle = plain // the test reads what the other hub would have opened
		}
		f.got = append(f.got, q)
		meshAnswer(w, syncTestSecret, f.deliver(q))
	case "/pull":
		if f.pull == nil {
			http.NotFound(w, r)
			return
		}
		f.pulled++
		_, ans := f.pull()
		meshAnswer(w, syncTestSecret, ans)
	case "/syncstate":
		if f.state == nil {
			http.NotFound(w, r)
			return
		}
		meshAnswer(w, syncTestSecret, f.state())
	default:
		http.NotFound(w, r)
	}
}

// syncFresh starts a test with no copy remembered (startHubSync does this).
func syncFresh(t *testing.T) {
	t.Helper()
	syncUpdate(func(s *syncState) { *s = syncState{Steps: []syncStep{}} })
	t.Cleanup(func() { syncUpdate(func(s *syncState) { *s = syncState{} }) })
}

func TestRunHubSync(t *testing.T) {
	newClusterFixture(t, true)
	syncFresh(t)
	fake := &fakeSyncHub{
		list: syncList{
			Tunnels: []syncTunnel{
				{Name: "de", Remote: "198.51.100.1", Engine: "frp", FRPTransport: "tcp", Ports: []int{443, 2083}, LocalGre: "10.10.10.2", PeerGre: "10.10.10.1"},
				{Name: "fi", Remote: "198.51.100.2", Engine: "frp", Ports: []int{8443}},
				{Name: "nl", Remote: "198.51.100.3", Engine: "frp", Ports: []int{9443}},
			},
			Pools: []syncPool{{Port: 443, Proto: "both", Mode: lbFailover}, {Port: 55000, Proto: "tcp", Mode: lbFailover}},
		},
		deliver: func(q syncDeliverReq) syncDeliverAns {
			if q.Remote == "198.51.100.3" {
				return syncDeliverAns{Error: "the foreign server is offline"}
			}
			return syncDeliverAns{OK: true, Status: "ok"}
		},
	}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	syncHub(t, "203.0.113.9")
	if _, err := updateClusterConfig(func(c *ClusterConfig) error {
		c.Hubs[0].URL = srv.URL
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// this hub already has a tunnel to the second foreign server
	if err := os.WriteFile(filepath.Join(configDir, "peers.json"), []byte(`{"peers":[{"id":1,"name":"fi","remote_pub":"198.51.100.2","ports":[8443]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}

	var made []setupRequest
	var removed []int
	oPlan, oSetup, oRemove := syncPlan, syncSetup, syncRemove
	defer func() { syncPlan, syncSetup, syncRemove = oPlan, oSetup, oRemove }()
	syncPlan = func(string, int) setupPlan {
		return setupPlan{Public: "192.0.2.10", Exists: true, RelayPort: 7002, GreUsed: []string{"10.11.0.2", "10.11.0.1"},
			Peers: []setupPlanPeer{{ID: 1}}}
	}
	nextID := 10
	syncSetup = func(b setupRequest) (string, int, error) {
		made = append(made, b)
		nextID++
		if b.RemotePub == "198.51.100.1" { // the first tunnel really exists afterwards: its ports make the pool
			_ = os.WriteFile(filepath.Join(configDir, "peers.json"),
				[]byte(`{"peers":[{"id":1,"name":"fi","remote_pub":"198.51.100.2","ports":[8443]},{"id":11,"name":"de","remote_pub":"198.51.100.1","ports":[443,2083]}]}`), 0o600)
		}
		return MakeBundle("192.0.2.10", b.FrpPort, b.LocalGre, b.PeerGre, "tok", []int{443}), nextID, nil
	}
	syncRemove = func(id int) error { removed = append(removed, id); return nil }

	c := loadClusterConfig()
	if err := runHubSync(c, c.Hubs[0], false); err != nil {
		t.Fatal(err)
	}
	s := syncSnapshot()
	states := map[string]string{}
	for _, st := range s.Steps {
		states[st.Remote] = st.State
	}
	if states["198.51.100.1"] != "done" || states["198.51.100.2"] != "skipped" || states["198.51.100.3"] != "failed" {
		t.Fatalf("steps: %+v", s.Steps)
	}
	if len(made) != 2 {
		t.Fatalf("made %d tunnels, want 2 (the known one is skipped): %+v", len(made), made)
	}
	b := made[0]
	if b.Role != "add-peer" || b.RemotePub != "198.51.100.1" || b.Ports != "443, 2083" || b.FrpPort != 7002 || !b.Autogen || !b.PoolOnClash || b.FRPTransport != "tcp" || b.Engine != "" {
		t.Fatalf("setup body: %+v", b)
	}
	if b.LocalGre == "10.10.10.2" || b.LocalGre == "10.11.0.2" || b.PeerGre == "10.10.10.1" || b.PeerGre == "10.11.0.1" {
		t.Fatalf("GRE pair collides with the other hub's or this hub's: %s %s", b.LocalGre, b.PeerGre)
	}
	// the bundle sent to the other hub is the one setup made, with this hub's name
	if len(fake.got) != 2 || fake.got[0].Name != "tehran" || !strings.HasPrefix(fake.got[0].Bundle, "hsh1_192.0.2.10_") || fake.got[0].ID != "hub-self" {
		t.Fatalf("delivered: %+v", fake.got)
	}
	// a foreign server that did not join leaves no tunnel behind
	if len(removed) != 1 || removed[0] != nextID {
		t.Fatalf("removed %v, want only the last tunnel %d", removed, nextID)
	}
	if !strings.Contains(s.Steps[len(s.Steps)-1].Detail, "removed again") && !strings.Contains(findStep(s, "198.51.100.3").Detail, "removed again") {
		t.Fatalf("the failure does not say the tunnel was removed: %+v", findStep(s, "198.51.100.3"))
	}
	// the pool of the other hub is made here for a port this hub serves, and not for one it does not
	if len(s.Pools) != 1 || s.Pools[0] != 443 {
		t.Fatalf("pools made: %v", s.Pools)
	}
}

func findStep(s syncState, remote string) syncStep {
	for _, st := range s.Steps {
		if st.Remote == remote {
			return st
		}
	}
	return syncStep{}
}

func TestRunHubSyncFirstTunnelOfAHub(t *testing.T) {
	newClusterFixture(t, true)
	syncFresh(t)
	fake := &fakeSyncHub{
		list:    syncList{Tunnels: []syncTunnel{{Name: "de", Remote: "198.51.100.1", Engine: "backhaul", Transport: "tcpmux", Ports: []int{443}, RawPorts: []string{"443", "2083=8443"}}}},
		deliver: func(syncDeliverReq) syncDeliverAns { return syncDeliverAns{OK: true, Status: "ok"} },
	}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	syncHub(t, "203.0.113.9")
	_, _ = updateClusterConfig(func(c *ClusterConfig) error { c.Hubs[0].URL = srv.URL; return nil })
	var got setupRequest
	oPlan, oSetup := syncPlan, syncSetup
	defer func() { syncPlan, syncSetup = oPlan, oSetup }()
	syncPlan = func(string, int) setupPlan { return setupPlan{Public: "192.0.2.10", RelayPort: 7001} } // no tunnel yet
	syncSetup = func(b setupRequest) (string, int, error) {
		got = b
		return MakeBundle("192.0.2.10", b.FrpPort, "", "", "tok", []int{443}), 0, nil
	}
	c := loadClusterConfig()
	if err := runHubSync(c, c.Hubs[0], false); err != nil {
		t.Fatal(err)
	}
	if got.Role != "iran" || got.Engine != "backhaul" || got.Transport != "tcpmux" || got.Ports != "443, 2083=8443" || got.LocalGre != "" {
		t.Fatalf("a hub with no tunnel makes its first one, with Backhaul's ports as written and no GRE: %+v", got)
	}
	if st := findStep(syncSnapshot(), "198.51.100.1"); st.State != "done" {
		t.Fatalf("step: %+v", st)
	}
}

// A foreign server that already serves a hub at this address keeps dialing
// that one: the tunnel just made here (new token) would never be used.
func TestRunHubSyncAlreadyJoinedIsAFailure(t *testing.T) {
	newClusterFixture(t, true)
	syncFresh(t)
	fake := &fakeSyncHub{
		list:    syncList{Tunnels: []syncTunnel{{Name: "de", Remote: "198.51.100.1", Engine: "frp", Ports: []int{443}}}},
		deliver: func(syncDeliverReq) syncDeliverAns { return syncDeliverAns{OK: true, Status: "already"} },
	}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	syncHub(t, "203.0.113.9")
	_, _ = updateClusterConfig(func(c *ClusterConfig) error { c.Hubs[0].URL = srv.URL; return nil })
	var removed []int
	oPlan, oSetup, oRemove := syncPlan, syncSetup, syncRemove
	defer func() { syncPlan, syncSetup, syncRemove = oPlan, oSetup, oRemove }()
	syncPlan = func(string, int) setupPlan { return setupPlan{Public: "192.0.2.10", Exists: true, RelayPort: 7001} }
	syncSetup = func(b setupRequest) (string, int, error) {
		return MakeBundle("192.0.2.10", b.FrpPort, b.LocalGre, b.PeerGre, "tok", []int{443}), 5, nil
	}
	syncRemove = func(id int) error { removed = append(removed, id); return nil }
	c := loadClusterConfig()
	if err := runHubSync(c, c.Hubs[0], false); err != nil {
		t.Fatal(err)
	}
	st := findStep(syncSnapshot(), "198.51.100.1")
	if st.State != "failed" || !strings.Contains(st.Detail, "earlier join") || len(removed) != 1 || removed[0] != 5 {
		t.Fatalf("step %+v, removed %v", st, removed)
	}
}

// The installer can fail after it made the tunnel: what this copy added is removed.
func TestRunHubSyncHalfMadeTunnelIsRemoved(t *testing.T) {
	newClusterFixture(t, true)
	syncFresh(t)
	fake := &fakeSyncHub{
		list:    syncList{Tunnels: []syncTunnel{{Name: "de", Remote: "198.51.100.1", Engine: "frp", Ports: []int{443}}}},
		deliver: func(syncDeliverReq) syncDeliverAns { return syncDeliverAns{OK: true, Status: "ok"} },
	}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	syncHub(t, "203.0.113.9")
	_, _ = updateClusterConfig(func(c *ClusterConfig) error { c.Hubs[0].URL = srv.URL; return nil })
	var removed []int
	oPlan, oSetup, oRemove := syncPlan, syncSetup, syncRemove
	defer func() { syncPlan, syncSetup, syncRemove = oPlan, oSetup, oRemove }()
	syncPlan = func(string, int) setupPlan { return setupPlan{Public: "192.0.2.10", Exists: true, RelayPort: 7001} }
	syncSetup = func(b setupRequest) (string, int, error) {
		_ = os.WriteFile(filepath.Join(configDir, "peers.json"), []byte(`{"peers":[{"id":8,"name":"de","remote_pub":"198.51.100.1","ports":[443]}]}`), 0o600)
		return "", 0, errors.New("the installer stopped half-way")
	}
	syncRemove = func(id int) error { removed = append(removed, id); return nil }
	c := loadClusterConfig()
	if err := runHubSync(c, c.Hubs[0], false); err != nil {
		t.Fatal(err)
	}
	st := findStep(syncSnapshot(), "198.51.100.1")
	if st.State != "failed" || len(removed) != 1 || removed[0] != 8 || len(fake.got) != 0 {
		t.Fatalf("step %+v, removed %v, delivered %d", st, removed, len(fake.got))
	}
}

func TestStartHubSyncRefusesTwoAtOnce(t *testing.T) {
	newClusterFixture(t, true)
	syncHub(t, "203.0.113.9")
	syncUpdate(func(s *syncState) { s.Running = true })
	defer syncUpdate(func(s *syncState) { *s = syncState{} })
	if err := startHubSync("hub-a", true); err == nil || !strings.Contains(err.Error(), "already running") {
		t.Fatalf("second copy: %v", err)
	}
	syncUpdate(func(s *syncState) { s.Running = false })
	if err := startHubSync("hub-zzz", true); err == nil {
		t.Fatal("an unknown hub started a copy")
	}
}

// twoWay sets a run up where this hub has the tunnels in mine and the other
// hub (the fake) the ones in its list.
func twoWay(t *testing.T, mine []syncTunnel, fake *fakeSyncHub) (ClusterConfig, func()) {
	t.Helper()
	newClusterFixture(t, true)
	syncFresh(t)
	srv := httptest.NewServer(fake)
	syncHub(t, "203.0.113.9")
	_, _ = updateClusterConfig(func(c *ClusterConfig) error { c.Hubs[0].URL = srv.URL; return nil })
	oldT, oldPoll := syncLocalTunnels, syncPollEvery
	syncLocalTunnels = func() []syncTunnel { return mine }
	syncPollEvery = time.Millisecond
	return loadClusterConfig(), func() { srv.Close(); syncLocalTunnels, syncPollEvery = oldT, oldPoll }
}

// The button works whichever hub it is pressed on: the other hub has no
// tunnel and this one has, so the other hub is asked to copy this one's.
func TestRunHubSyncTwoWayAsksTheEmptyHubToCopy(t *testing.T) {
	polls := 0
	fake := &fakeSyncHub{
		pull: func() (int, syncPullAns) { return 200, syncPullAns{OK: true, Started: 4242} },
		state: func() syncState {
			polls++
			st := syncState{Started: 4242, Hub: "hub-self", Running: polls < 3}
			st.Steps = []syncStep{{Name: "de", Remote: "198.51.100.1", State: "done", Detail: "serves it now"}}
			return st
		},
	}
	c, done := twoWay(t, []syncTunnel{{Name: "de", Remote: "198.51.100.1", Engine: "frp", Ports: []int{443}}}, fake)
	defer done()
	if err := runHubSync(c, c.Hubs[0], true); err != nil {
		t.Fatalf("the other hub being empty is not an error when this one has tunnels: %v", err)
	}
	s := syncSnapshot()
	if fake.pulled != 1 || len(s.Other) != 1 || s.Other[0].State != "done" || s.OtherErr != "" || len(s.Steps) != 0 {
		t.Fatalf("pulled %d, state %+v", fake.pulled, s)
	}
}

// A copy that is another one (older Started) is not taken for the asked one.
func TestRunHubSyncTwoWayIgnoresAnotherCopyOnThePeer(t *testing.T) {
	polls := 0
	fake := &fakeSyncHub{
		pull: func() (int, syncPullAns) { return 200, syncPullAns{OK: true, Started: 500} },
		state: func() syncState {
			polls++
			if polls < 3 {
				return syncState{Started: 100, Hub: "hub-self", Running: false, Steps: []syncStep{{Name: "old", State: "done"}}}
			}
			return syncState{Started: 500, Hub: "hub-self", Steps: []syncStep{{Name: "de", Remote: "198.51.100.1", State: "done"}}}
		},
	}
	c, done := twoWay(t, []syncTunnel{{Name: "de", Remote: "198.51.100.1", Engine: "frp", Ports: []int{443}}}, fake)
	defer done()
	if err := runHubSync(c, c.Hubs[0], true); err != nil {
		t.Fatal(err)
	}
	s := syncSnapshot()
	if len(s.Other) != 1 || s.Other[0].Name != "de" {
		t.Fatalf("other: %+v", s.Other)
	}
}

// Both hubs already serve the same foreign servers: nothing is asked, and the
// answer says so instead of calling it an error.
func TestRunHubSyncTwoWayAlreadyEqual(t *testing.T) {
	same := syncTunnel{Name: "de", Remote: "198.51.100.1", Engine: "frp", Ports: []int{443}}
	fake := &fakeSyncHub{
		list: syncList{Tunnels: []syncTunnel{same}},
		pull: func() (int, syncPullAns) { return 200, syncPullAns{OK: true, Started: 1} },
	}
	c, done := twoWay(t, []syncTunnel{same}, fake)
	defer done()
	if err := os.WriteFile(filepath.Join(configDir, "peers.json"), []byte(`{"peers":[{"id":1,"name":"de","remote_pub":"198.51.100.1","ports":[443]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runHubSync(c, c.Hubs[0], true); err != nil {
		t.Fatal(err)
	}
	s := syncSnapshot()
	if fake.pulled != 0 || !strings.Contains(s.Info, "already serve the same") {
		t.Fatalf("pulled %d, info %q, state %+v", fake.pulled, s.Info, s)
	}
}

func TestRunHubSyncTwoWayNeitherHasATunnel(t *testing.T) {
	c, done := twoWay(t, nil, &fakeSyncHub{})
	defer done()
	err := runHubSync(c, c.Hubs[0], true)
	if err == nil || !strings.Contains(err.Error(), "add a foreign server") {
		t.Fatalf("error: %v", err)
	}
}

// One way (the old behavior) keeps the plain answer when the other hub is empty.
func TestRunHubSyncOneWayEmptyPeer(t *testing.T) {
	c, done := twoWay(t, []syncTunnel{{Name: "de", Remote: "198.51.100.1", Engine: "frp", Ports: []int{443}}}, &fakeSyncHub{})
	defer done()
	err := runHubSync(c, c.Hubs[0], false)
	if err == nil || !strings.Contains(err.Error(), "has no tunnel to copy") {
		t.Fatalf("error: %v", err)
	}
}

// Nothing was made on either side and the other hub could not be asked: the
// run fails, so the page shows a failure and not "tunnels synced".
func TestRunHubSyncTwoWayOldPeerIsAFailure(t *testing.T) {
	c, done := twoWay(t, []syncTunnel{{Name: "de", Remote: "198.51.100.1", Engine: "frp", Ports: []int{443}}}, &fakeSyncHub{list: syncList{Version: "v3.1.5"}})
	defer done()
	err := runHubSync(c, c.Hubs[0], true)
	if err == nil || !strings.Contains(err.Error(), "hashem update") || !strings.Contains(err.Error(), "v3.1.5") {
		t.Fatalf("error: %v", err)
	}
	if s := syncSnapshot(); s.Info != "" || len(s.Steps) != 0 || len(s.Other) != 0 {
		t.Fatalf("state: %+v", s)
	}
}

// The other hub restarted in the middle of its copy and forgot it: this hub
// stops waiting and says so.
func TestRunHubSyncTwoWayPeerForgotTheCopy(t *testing.T) {
	fake := &fakeSyncHub{
		pull:  func() (int, syncPullAns) { return 200, syncPullAns{OK: true, Started: 900} },
		state: func() syncState { return syncState{} },
	}
	c, done := twoWay(t, []syncTunnel{{Name: "de", Remote: "198.51.100.1", Engine: "frp", Ports: []int{443}}}, fake)
	defer done()
	old := syncLostWait
	syncLostWait = 20 * time.Millisecond
	defer func() { syncLostWait = old }()
	err := runHubSync(c, c.Hubs[0], true)
	if err == nil || !strings.Contains(err.Error(), "no longer shows the copy") {
		t.Fatalf("error: %v", err)
	}
}

// The other hub is busy with its own copy: it says so and nothing is hidden.
func TestRunHubSyncTwoWayPeerBusy(t *testing.T) {
	fake := &fakeSyncHub{pull: func() (int, syncPullAns) {
		return 200, syncPullAns{Error: "a copy of tunnels is already running here: wait for it to end"}
	}}
	c, done := twoWay(t, []syncTunnel{{Name: "de", Remote: "198.51.100.1", Engine: "frp", Ports: []int{443}}}, fake)
	defer done()
	err := runHubSync(c, c.Hubs[0], true)
	if err == nil || !strings.Contains(err.Error(), "already running") || !strings.Contains(syncSnapshot().OtherErr, "already running") {
		t.Fatalf("error %v, state %+v", err, syncSnapshot())
	}
}

// /_hc/pull starts a one-way copy from the asking hub, and /_hc/syncstate shows it.
func TestMeshPullStartsAOneWayCopy(t *testing.T) {
	newClusterFixture(t, true)
	syncFresh(t)
	syncHub(t, "203.0.113.9")
	// the asking hub is unreachable: the job fails fast, but it did start
	rec := httptest.NewRecorder()
	syncMux().ServeHTTP(rec, syncSigned(t, "/pull", map[string]string{"id": "hub-a"}))
	var ans syncPullAns
	if err := json.Unmarshal(rec.Body.Bytes(), &ans); err != nil || !ans.OK || ans.Started == 0 {
		t.Fatalf("pull answer %d %s", rec.Code, rec.Body.String())
	}
	deadline := time.Now().Add(20 * time.Second)
	for syncSnapshot().Running && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	rec = httptest.NewRecorder()
	syncMux().ServeHTTP(rec, syncSigned(t, "/syncstate", map[string]string{"id": "hub-a"}))
	var st syncState
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil || st.Started != ans.Started || st.Both {
		t.Fatalf("syncstate %d %s", rec.Code, rec.Body.String())
	}
	// a stranger gets nothing
	rec = httptest.NewRecorder()
	syncMux().ServeHTTP(rec, syncSigned(t, "/pull", map[string]string{"id": "hub-zzz"}))
	if rec.Code != 404 {
		t.Fatalf("an unknown hub got %d", rec.Code)
	}
}

// The first FRP tunnel of an Iran hub has its ports on the foreign server:
// they are read from what its frps listens on, without its own ports.
func TestFrpsServedPorts(t *testing.T) {
	ls := []xrayListener{
		{Proto: "tcp", Port: 34173, PID: 7}, // bindPort
		{Proto: "udp", Port: 34174, PID: 7}, // kcpBindPort
		{Proto: "tcp", Port: 5002, PID: 7},
		{Proto: "tcp", Port: 5001, PID: 7},
		{Proto: "udp", Port: 5001, PID: 7},
		{Proto: "tcp", Port: 7778, PID: 9}, // the panel
	}
	got := frpsServedPorts(ls, 7, map[int]bool{34173: true, 34174: true})
	if len(got) != 2 || got[0] != 5001 || got[1] != 5002 {
		t.Fatalf("ports %v", got)
	}
}

// A tunnel whose ports are not known is a failed step that says why, not a
// tunnel that silently does not exist.
func TestRunHubSyncUnknownPorts(t *testing.T) {
	fake := &fakeSyncHub{list: syncList{Tunnels: []syncTunnel{{Name: "Tunnel · 198.51.100.1", Remote: "198.51.100.1", Engine: "frp"}}}}
	c, done := twoWay(t, nil, fake)
	defer done()
	if err := runHubSync(c, c.Hubs[0], true); err != nil {
		t.Fatal(err)
	}
	st := findStep(syncSnapshot(), "198.51.100.1")
	if st.State != "failed" || !strings.Contains(st.Detail, "foreign server connected") || len(fake.got) != 0 {
		t.Fatalf("step %+v", st)
	}
}
