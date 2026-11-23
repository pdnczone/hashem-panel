package main

// Five Iran hubs: linking from any hub of the cluster, delivering a copy
// through any hub a foreign server serves, GRE pairs no hub uses yet.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const hubsSecretB = "fedcba9876543210fedcba9876543210"

// fakeHub is another Iran hub: it checks the signature with secret and
// answers what answer returns, signed.
func fakeHub(t *testing.T, secret string, answer func(path string, body []byte) any) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if meshVerify(secret, r.Header, body, time.Now()) != nil {
			http.NotFound(w, r)
			return
		}
		v := answer(strings.TrimPrefix(r.URL.Path, meshRoutePrefix), body)
		if v == nil {
			http.NotFound(w, r)
			return
		}
		meshAnswer(w, secret, v)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// A hub that already has a cluster links a new hub whose code carries the new
// hub's own secret: the new hub takes the cluster's secret (it used to be
// "already linked with other hubs under another secret; remove them first",
// so a third hub could only be linked one way round).
func TestMeshAdoptLetsAThirdHubIn(t *testing.T) {
	newClusterFixture(t, true)
	// this process is the NEW hub (C): its own secret, no hub yet
	if _, err := updateClusterConfig(func(c *ClusterConfig) error {
		c.NodeID, c.Name, c.Secret = "hub-c", "tabriz", hubsSecretB
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(syncMux())
	defer srv.Close()

	a := ClusterConfig{NodeID: "hub-a", Name: "tehran", Secret: syncTestSecret, Hubs: []HubPeer{{ID: "hub-b"}}}
	if err := meshAdopt(a, meshCode{ID: "hub-c", URL: srv.URL, Secret: hubsSecretB}); err != nil {
		t.Fatalf("adopt: %v", err)
	}
	if got := loadClusterConfig().Secret; got != syncTestSecret {
		t.Fatalf("the new hub has secret %q, want the cluster's", got)
	}

	// a hub that is in a cluster of its own does not leave it
	if _, err := updateClusterConfig(func(c *ClusterConfig) error {
		c.Secret = hubsSecretB
		c.Hubs = []HubPeer{{ID: "hub-z", URL: "http://192.0.2.99:1"}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	err := meshAdopt(a, meshCode{ID: "hub-c", URL: srv.URL, Secret: hubsSecretB})
	if err == nil || !strings.Contains(err.Error(), "already linked with other hubs") {
		t.Fatalf("a hub in another cluster: %v", err)
	}
	if loadClusterConfig().Secret != hubsSecretB {
		t.Fatal("the secret of a hub in another cluster was changed")
	}

	// a wrong secret (an old code) is a bare 404, told as "older panel or new code"
	err = meshAdopt(a, meshCode{ID: "hub-c", URL: srv.URL, Secret: "00000000000000000000000000000000"})
	if err == nil || !strings.Contains(err.Error(), "Show Join Code") {
		t.Fatalf("a stale code: %v", err)
	}
}

// The hub that added a new one by its code names the rest of the cluster in
// its hello; the new hub links with each that answers as itself.
func TestMeshMeetLinksTheRestOfTheCluster(t *testing.T) {
	newClusterFixture(t, true)
	if _, err := updateClusterConfig(func(c *ClusterConfig) error {
		c.NodeID, c.Name, c.Secret = "hub-c", "tabriz", syncTestSecret
		c.Hubs = []HubPeer{{ID: "hub-a", Name: "tehran", URL: "http://192.0.2.1:1"}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	hellos := 0
	b := fakeHub(t, syncTestSecret, func(path string, _ []byte) any {
		mu.Lock()
		hellos++
		mu.Unlock()
		return meshBeat{ID: "hub-b", Name: "mashhad", IP: "192.0.2.2", Version: panelVersion}
	})
	liar := fakeHub(t, syncTestSecret, func(string, []byte) any { return meshBeat{ID: "hub-x"} })
	meshMeet([]HubPeer{
		{ID: "hub-a", URL: "http://192.0.2.1:1"}, // known already: not asked again
		{ID: "hub-c", URL: "http://192.0.2.3:1"}, // itself
		{ID: "hub-b", Name: "mashhad", URL: b.URL},
		{ID: "hub-d", URL: liar.URL}, // answers as another hub: not kept
	})
	c := loadClusterConfig()
	ids := []string{}
	for _, h := range c.Hubs {
		ids = append(ids, h.ID)
	}
	if strings.Join(ids, ",") != "hub-a,hub-b" {
		t.Fatalf("hubs after meet: %v", ids)
	}
	if hellos != 1 {
		t.Fatalf("hub-b was asked %d times", hellos)
	}
}

// A foreign server takes "serve this hub too" only from a hub it already
// serves (an older one only from its first hub): when the asked hub cannot
// hand the bundle over, the next linked hub does.
func TestSyncDeliverTriesEveryHub(t *testing.T) {
	newClusterFixture(t, true)
	var mu sync.Mutex
	var order []string
	mk := func(name string, ans syncDeliverAns) *httptest.Server {
		return fakeHub(t, syncTestSecret, func(path string, body []byte) any {
			if path != "/deliver" {
				return nil
			}
			mu.Lock()
			order = append(order, name)
			mu.Unlock()
			return ans
		})
	}
	a := mk("a", syncDeliverAns{Error: "the foreign server 198.51.100.1 did not take the request from this hub", Retry: true})
	b := mk("b", syncDeliverAns{Error: "this hub has no tunnel to 198.51.100.1"}) // a hub from before Retry
	d := mk("d", syncDeliverAns{OK: true, Status: "ok"})
	e := mk("e", syncDeliverAns{OK: true, Status: "ok"})
	hubs := []HubPeer{{ID: "hub-a", Name: "a", URL: a.URL}, {ID: "hub-b", Name: "b", URL: b.URL},
		{ID: "hub-d", Name: "d", URL: d.URL}, {ID: "hub-e", Name: "e", URL: e.URL}}
	if _, err := updateClusterConfig(func(c *ClusterConfig) error {
		c.NodeID, c.Name, c.Secret, c.Hubs = "hub-c", "tabriz", syncTestSecret, hubs
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	c := loadClusterConfig()
	ans, err := syncDeliver(c, hubs[0], "198.51.100.1", "hsh1_x")
	if err != nil || !ans.OK {
		t.Fatalf("deliver: %+v %v", ans, err)
	}
	if strings.Join(order, ",") != "a,b,d" {
		t.Fatalf("asked %v, want a,b,d", order)
	}

	// join-hub ran on the foreign server and failed: no other hub is asked
	order = nil
	f := mk("f", syncDeliverAns{Error: "foreign panel answered HTTP 500: join-hub failed"})
	hubs2 := []HubPeer{{ID: "hub-f", Name: "f", URL: f.URL}, {ID: "hub-d", Name: "d", URL: d.URL}}
	_, _ = updateClusterConfig(func(c *ClusterConfig) error { c.Hubs = hubs2; return nil })
	if _, err := syncDeliver(loadClusterConfig(), hubs2[0], "198.51.100.1", "hsh1_x"); err == nil || !strings.Contains(err.Error(), "join-hub failed") {
		t.Fatalf("a failed join: %v", err)
	}
	if strings.Join(order, ",") != "f" {
		t.Fatalf("after a failed join asked %v", order)
	}
}

// The hub answering /deliver says when another hub may try.
func TestMeshDeliverSaysRetry(t *testing.T) {
	newClusterFixture(t, true)
	syncHub(t, "203.0.113.9")
	oldTun := syncLocalTunnels
	syncLocalTunnels = func() []syncTunnel { return nil }
	defer func() { syncLocalTunnels = oldTun }()
	sealed, _ := syncSeal(syncTestSecret, MakeBundle("203.0.113.9", 7001, "10.11.0.2", "10.11.0.1", "tok", []int{443}))
	rec := httptest.NewRecorder()
	syncMux().ServeHTTP(rec, syncSigned(t, "/deliver", syncDeliverReq{ID: "hub-a", Remote: "198.51.100.1", Bundle: sealed}))
	var a syncDeliverAns
	_ = json.Unmarshal(rec.Body.Bytes(), &a)
	if a.OK || !a.Retry || !strings.Contains(a.Error, "no tunnel") {
		t.Fatalf("no tunnel here: %+v", a)
	}

	syncLocalTunnels = func() []syncTunnel {
		return []syncTunnel{{Name: "de", Remote: "198.51.100.1", Engine: "frp", Ports: []int{443}}}
	}
	if err := writePeers([]peerRecord{{ID: 2, RemotePub: "198.51.100.1", Ports: []int{443}}}); err != nil {
		t.Fatal(err)
	}
	old := syncPeerCall
	defer func() { syncPeerCall = old }()
	for _, c := range []struct {
		err   error
		retry bool
	}{
		{fmt.Errorf("foreign panel answered HTTP 404: 404 page not found"), true},
		{fmt.Errorf("dial tcp 198.51.100.1:7777: connect: connection refused"), true},
		{fmt.Errorf("foreign panel answered HTTP 500: {\"error\":\"join-hub failed\"}"), false},
	} {
		syncPeerCall = func(int, map[string]string) ([]byte, error) { return nil, c.err }
		rec := httptest.NewRecorder()
		syncMux().ServeHTTP(rec, syncSigned(t, "/deliver", syncDeliverReq{ID: "hub-a", Remote: "198.51.100.1", Bundle: sealed}))
		var a syncDeliverAns
		_ = json.Unmarshal(rec.Body.Bytes(), &a)
		if a.OK || a.Retry != c.retry {
			t.Fatalf("%v: %+v", c.err, a)
		}
	}
}

// Copying from hub A, the pairs hub B already uses with the same foreign
// server are taken too: the foreign server would otherwise drop GRE for the
// new hub ("already used here") and the new hub's GRE never came up.
func TestSyncGreSkipsOtherHubsPairs(t *testing.T) {
	newClusterFixture(t, true)
	b := fakeHub(t, syncTestSecret, func(path string, _ []byte) any {
		if path != "/tunnels" {
			return nil
		}
		return syncList{Tunnels: []syncTunnel{{Remote: "198.51.100.1", LocalGre: "10.11.0.2", PeerGre: "10.11.0.1"},
			{Remote: "198.51.100.7", LocalGre: "10.14.0.2", PeerGre: "10.14.0.1"}}}
	})
	down := HubPeer{ID: "hub-z", URL: "http://127.0.0.1:1"} // does not answer: left out
	a := HubPeer{ID: "hub-a", URL: "http://127.0.0.1:1"}
	c := ClusterConfig{NodeID: "hub-c", Secret: syncTestSecret, Hubs: []HubPeer{a, {ID: "hub-b", URL: b.URL}, down}}
	want := []syncTunnel{{Remote: "198.51.100.1", LocalGre: "10.10.10.2", PeerGre: "10.10.10.1"}}
	taken := syncOtherHubsGre(c, a, want)
	got := taken["198.51.100.1"]
	if strings.Join(got, ",") != "10.10.10.2,10.10.10.1,10.11.0.2,10.11.0.1" {
		t.Fatalf("taken for the foreign server: %v", got)
	}
	l, p := syncGrePair(nil, got...)
	if l != "10.12.0.2" || p != "10.12.0.1" {
		t.Fatalf("pair %s/%s, want 10.12.0.2/10.12.0.1", l, p)
	}
}

// The foreign server takes join-hub and update from its first hub (Peer Link
// secret) and from every hub it joined later (that hub's token), nothing else.
func TestServedHubTokensGuard(t *testing.T) {
	newClusterFixture(t, true)
	dir := configDir
	frp := filepath.Join(dir, "frpc-h2.toml")
	bh := filepath.Join(dir, "client-h3.toml")
	_ = os.WriteFile(frp, []byte("serverAddr = \"192.0.2.2\"\nauth.method = \"token\"\nauth.token = \"tok-of-hub-two-0123456\"\n"), 0600)
	_ = os.WriteFile(bh, []byte("[client]\nremote_addr = \"192.0.2.3:3080\"\n[security]\ntoken = \"tok-of-hub-three-012345\"\n"), 0600)
	short := filepath.Join(dir, "frpc-h4.toml")
	_ = os.WriteFile(short, []byte("auth.token = \"short\"\n"), 0600)
	hubs, _ := json.Marshal(map[string]any{"hubs": []map[string]any{
		{"id": 2, "svc": "frpc-h2", "conf": frp, "engine": "frp"},
		{"id": 3, "svc": "backhaul-client-h3", "conf": bh, "engine": "backhaul"},
		{"id": 4, "svc": "frpc-h4", "conf": short, "engine": "frp"},
	}})
	_ = os.WriteFile(hubsFile(), hubs, 0600)
	got := servedHubTokens()
	if strings.Join(got, ",") != "tok-of-hub-two-0123456,tok-of-hub-three-012345" {
		t.Fatalf("tokens: %v", got)
	}
	pc := loadPeerConfig()
	pc.PeerSecret = "first-hub-secret-0123456789"
	_ = savePeerConfig(pc)

	mux := http.NewServeMux()
	mountPeerRoutes(mux, "/x")
	ask := func(path, secret string) int {
		r := httptest.NewRequest(http.MethodPost, peerRoutePrefix+path, bytes.NewReader([]byte(`{"check":true}`)))
		if secret != "" {
			r.Header.Set("X-Peer-Secret", secret)
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, r)
		return rec.Code
	}
	for _, s := range []string{"first-hub-secret-0123456789", "tok-of-hub-two-0123456", "tok-of-hub-three-012345"} {
		if c := ask("/api/peer/update", s); c != 200 {
			t.Fatalf("update with %s: %d", s, c)
		}
	}
	for _, s := range []string{"", "short", "tok-of-hub-two", "nope-nope-nope-nope-nope"} {
		if c := ask("/api/peer/update", s); c != 404 {
			t.Fatalf("update with %q: %d, want 404", s, c)
		}
	}
	// a hub token opens join-hub and update only, not the other peer routes
	if c := ask("/api/peer/apply-carrier", "tok-of-hub-two-0123456"); c != 404 {
		t.Fatalf("apply-carrier with a hub token: %d", c)
	}
	// join-hub passes the guard with a hub token (the bundle is then refused)
	if c := ask("/api/peer/join-hub", "tok-of-hub-two-0123456"); c == 404 {
		t.Fatal("join-hub refused a hub's token")
	}
}

// Five Iran hubs, one foreign server: the fifth hub copies from a hub that is
// not the foreign server's first; the copy gets there through the first, and
// takes a GRE pair none of the other four uses.
func TestFiveHubsOneForeignServer(t *testing.T) {
	newClusterFixture(t, true)
	const remote = "198.51.100.1"
	pairs := map[string][2]string{"a": {"10.10.10.2", "10.10.10.1"}, "b": {"10.11.0.2", "10.11.0.1"},
		"c": {"10.12.0.2", "10.12.0.1"}, "d": {"10.13.0.2", "10.13.0.1"}}
	var mu sync.Mutex
	delivered := ""
	var hubs []HubPeer
	for _, n := range []string{"a", "b", "c", "d"} {
		n := n
		srv := fakeHub(t, syncTestSecret, func(path string, body []byte) any {
			switch path {
			case "/tunnels":
				p := pairs[n]
				return syncList{Tunnels: []syncTunnel{{Name: "de", Remote: remote, Engine: "frp", Ports: []int{443}, LocalGre: p[0], PeerGre: p[1]}}}
			case "/deliver":
				if n != "a" { // only the first hub's Peer Link opens on an older foreign server
					return syncDeliverAns{Error: "the foreign server " + remote + " did not take the request from this hub", Retry: true}
				}
				mu.Lock()
				delivered = n
				mu.Unlock()
				return syncDeliverAns{OK: true, Status: "ok"}
			}
			return nil
		})
		hubs = append(hubs, HubPeer{ID: "hub-" + n, Name: n, URL: srv.URL, PublicIP: "192.0.2." + fmt.Sprint(len(hubs)+1)})
	}
	if _, err := updateClusterConfig(func(c *ClusterConfig) error {
		c.NodeID, c.Name, c.Secret, c.Hubs = "hub-e", "e", syncTestSecret, hubs
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var made setupRequest
	oldSetup, oldPlan, oldRemove := syncSetup, syncPlan, syncRemove
	defer func() { syncSetup, syncPlan, syncRemove = oldSetup, oldPlan, oldRemove }()
	syncPlan = func(string, int) setupPlan { return setupPlan{Public: "192.0.2.5", RelayPort: 7005} }
	syncSetup = func(b setupRequest) (string, int, error) {
		made = b
		return MakeBundle("192.0.2.5", 7005, b.LocalGre, b.PeerGre, "tok", []int{443}), 9, nil
	}
	syncRemove = func(int) error { t.Fatal("the tunnel was removed again"); return nil }
	oldTun := syncLocalTunnels
	syncLocalTunnels = func() []syncTunnel { return nil }
	defer func() { syncLocalTunnels = oldTun }()

	syncJob.Lock()
	syncJob.s = syncState{Running: true, Steps: []syncStep{}}
	syncJob.Unlock()
	c := loadClusterConfig()
	if err := runHubSync(c, hubs[3], false); err != nil { // copied from hub d
		t.Fatal(err)
	}
	st := syncSnapshot()
	if len(st.Steps) != 1 || st.Steps[0].State != "done" {
		t.Fatalf("steps: %+v", st.Steps)
	}
	if delivered != "a" {
		t.Fatalf("delivered through %q, want the first hub a", delivered)
	}
	if made.LocalGre != "10.14.0.2" || made.PeerGre != "10.14.0.1" {
		t.Fatalf("GRE pair %s/%s, want 10.14.0.2/10.14.0.1 (none of the four hubs' pairs)", made.LocalGre, made.PeerGre)
	}
}
