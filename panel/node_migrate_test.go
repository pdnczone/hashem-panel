package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// nodeMigrateTest: a standalone Iran panel with its first tunnel (token
// "main-token") and peer 3 (token "peer3-token").
func nodeMigrateTest(t *testing.T) string {
	t.Helper()
	central := nodeTestCentral(t)
	if err := savePeerConfig(PeerConfig{Role: "master", PeerSecret: "main-token"}); err != nil {
		t.Fatal(err)
	}
	oldFT := firstTunnelInfo
	firstTunnelInfo = func() firstTunnel { return firstTunnel{Exists: true, Side: "iran", RemotePub: "192.0.2.10"} }
	t.Cleanup(func() { firstTunnelInfo = oldFT })
	peers := `{"peers":[{"id":3,"name":"de-3","remote_pub":"192.0.2.30","token":"peer3-token","gre_if":"gre-t3","frps_svc":"frps-3"}]}`
	if err := os.WriteFile(filepath.Join(configDir, "peers.json"), []byte(peers), 0600); err != nil {
		t.Fatal(err)
	}
	return central
}

// the offer route as the foreign server reaches it
func nodeMigrateOfferCall(t *testing.T, central, token string) *httptest.ResponseRecorder {
	t.Helper()
	u, _ := url.Parse(central)
	r := httptest.NewRequest("GET", "/_hp/api/peer/node-offer", nil)
	r.Host = u.Host
	r.Header.Set("X-Peer-Secret", token)
	w := httptest.NewRecorder()
	requireTunnelSecretHidden(handlePeerNodeOffer)(w, r)
	return w
}

func TestNodeMigrateOfferAndJoin(t *testing.T) {
	central := nodeMigrateTest(t)
	self, _ := nodeSelfLoad()
	v := nodeMigrateView(self)
	if v == nil || v["offer"] != true || len(v["peers"].([]nodeMigratePeer)) != 2 {
		t.Fatalf("the offer card: %v", v)
	}
	// no migration open: nothing, and a wrong token: nothing
	if w := nodeMigrateOfferCall(t, central, "peer3-token"); w.Code != http.StatusNotFound {
		t.Fatalf("before the move: %d", w.Code)
	}
	if err := nodeMigrateAction(self, "migrate-start"); err != nil {
		t.Fatal(err)
	}
	if self, _ = nodeSelfLoad(); self.Role != nodeRoleCentral {
		t.Fatal("not a central after the move started")
	}
	if w := nodeMigrateOfferCall(t, central, "wrong"); w.Code != http.StatusNotFound {
		t.Fatalf("a wrong token: %d", w.Code)
	}
	w := nodeMigrateOfferCall(t, central, "peer3-token")
	var o nodeMigrateOffer
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &o) != nil || o.URL != central || o.MAC != o.mac("peer3-token") {
		t.Fatalf("the offer: %d %s", w.Code, w.Body)
	}
	if strings.Contains(w.Body.String(), "peer3-token") || strings.Contains(w.Body.String(), o.secret("peer3-token")) {
		t.Fatal("the token or the join secret is in the offer")
	}
	// a second offer replaces the first: one open invite per foreign server
	w2 := nodeMigrateOfferCall(t, central, "peer3-token")
	nodesMu.Lock()
	n := 0
	for _, iv := range nodesF.Invites {
		if iv.Peer == "peer:3" {
			n++
		}
	}
	nodesMu.Unlock()
	if n != 1 {
		t.Fatalf("%d open offers for one server", n)
	}
	_ = json.Unmarshal(w2.Body.Bytes(), &o)

	// an offer made with another token is refused by the foreign server
	nd := t.TempDir()
	forged := o
	forged.MAC = forged.mac("other-token")
	fb, _ := json.Marshal(forged)
	c := nodeHelper(t, nd, "migrate", string(fb), 0)
	c.Env = append(c.Env, "NODE_HELPER_TOKEN=peer3-token")
	if out, err := c.CombinedOutput(); err == nil || !strings.Contains(string(out), "not made with this tunnel's token") {
		t.Fatalf("a forged offer: %v\n%s", err, out)
	}
	// a central at another address than where the Iran panel answered
	c = nodeHelper(t, nd, "migrate", string(fb2(o)), 0)
	c.Env = append(c.Env, "NODE_HELPER_TOKEN=peer3-token", "NODE_HELPER_REACHED=192.0.2.250")
	if out, err := c.CombinedOutput(); err == nil || !strings.Contains(string(out), "where the Iran panel answered") {
		t.Fatalf("another address: %v\n%s", err, out)
	}
	// the real one: it joins, under the peer's name
	ob, _ := json.Marshal(o)
	c = nodeHelper(t, nd, "migrate", string(ob), 0)
	c.Env = append(c.Env, "NODE_HELPER_TOKEN=peer3-token")
	if out, err := c.CombinedOutput(); err != nil || !strings.Contains(string(out), "OK "+central) {
		t.Fatalf("join by the offer: %v\n%s", err, out)
	}
	nodesMu.Lock()
	var rec nodeRecord
	for _, r := range nodesF.Nodes {
		rec = r
	}
	nodesMu.Unlock()
	if rec.Peer != "peer:3" || rec.Name != "de-3" {
		t.Fatalf("the node: %+v", rec)
	}
	for _, p := range nodeMigratePeers() {
		if p.Key == "peer:3" && p.Joined != rec.ID {
			t.Fatalf("peer 3 not shown as joined: %+v", p)
		}
	}
	// joined: no more offers for it, and the foreign server never joins by itself again
	if w := nodeMigrateOfferCall(t, central, "peer3-token"); w.Code != http.StatusNotFound {
		t.Fatalf("an offer after joining: %d", w.Code)
	}
	if _, err := os.Stat(filepath.Join(nd, "node_migrated")); err != nil {
		t.Fatal("no marker on the foreign server")
	}
	_ = os.Remove(filepath.Join(nd, "node.json"))
	c = nodeHelper(t, nd, "migrate", string(ob), 0)
	c.Env = append(c.Env, "NODE_HELPER_TOKEN=peer3-token")
	if out, _ := c.CombinedOutput(); !strings.Contains(string(out), "OK \n") {
		t.Fatalf("joined again by itself: %s", out)
	}
	// stop: the open offers go
	if err := nodeMigrateAction(self, "migrate-stop"); err != nil {
		t.Fatal(err)
	}
	if w := nodeMigrateOfferCall(t, central, "main-token"); w.Code != http.StatusNotFound {
		t.Fatalf("after stop: %d", w.Code)
	}
}

// Without a saved Peer Link or a first tunnel there is no "main" server to move.
func TestNodeMigratePeersOnlyReal(t *testing.T) {
	nodeMigrateTest(t)
	firstTunnelInfo = func() firstTunnel { return firstTunnel{} } // the first tunnel was removed
	for _, p := range nodeMigratePeers() {
		if p.Key == "main" {
			t.Fatal("a first tunnel without its setup record")
		}
	}
	_ = os.Remove(filepath.Join(configDir, "peers.json"))
	_ = os.Remove(peerConfigFile())
	if ps := nodeMigratePeers(); len(ps) != 0 {
		t.Fatalf("made-up servers: %+v", ps)
	}
}

func fb2(o nodeMigrateOffer) []byte { b, _ := json.Marshal(o); return b }

func TestNodeMigrateLaterNever(t *testing.T) {
	nodeMigrateTest(t)
	self := nodeSelf{}
	if err := nodeMigrateAction(self, "migrate-later"); err != nil {
		t.Fatal(err)
	}
	if v := nodeMigrateView(self); v["offer"] != false {
		t.Fatal("offered again right after Not now")
	}
	st := nodeMigrateLoad()
	st.LaterUntil = 1 // a week passed
	_ = nodeMigrateSave(st)
	if v := nodeMigrateView(self); v["offer"] != true {
		t.Fatal("not offered after the week")
	}
	_ = nodeMigrateAction(self, "migrate-never")
	if v := nodeMigrateView(self); v["offer"] != false || v["never"] != true {
		t.Fatalf("after Don't ask again: %v", v)
	}
	if v := nodeMigrateView(nodeSelf{Role: nodeRoleNode}); v != nil {
		t.Fatal("a node is offered the move")
	}
}

// The move closes by itself: after its 7 days, or when every foreign server
// has joined; a server that joined once is not offered again after removal.
func TestNodeMigrateWindow(t *testing.T) {
	central := nodeMigrateTest(t)
	self := nodeSelf{}
	if err := nodeMigrateAction(self, "migrate-start"); err != nil {
		t.Fatal(err)
	}
	self, _ = nodeSelfLoad()
	st := nodeMigrateLoad()
	st.OpenedAt = time.Now().Add(-8 * 24 * time.Hour).Unix()
	_ = nodeMigrateSave(st)
	if w := nodeMigrateOfferCall(t, central, "peer3-token"); w.Code != http.StatusNotFound {
		t.Fatalf("after 7 days: %d", w.Code)
	}
	if v := nodeMigrateView(self); v["open"] != false || v["offer"] != false || nodeMigrateLoad().Open {
		t.Fatalf("not closed: %v", v)
	}
	// open again; peer 3 joined once and was removed since: no offer for it
	_ = nodeMigrateAction(self, "migrate-start")
	nodesMu.Lock()
	nodesF.Migrated = append(nodesF.Migrated, "peer:3")
	nodesMu.Unlock()
	if w := nodeMigrateOfferCall(t, central, "peer3-token"); w.Code != http.StatusNotFound {
		t.Fatalf("a server that joined once: %d", w.Code)
	}
	if w := nodeMigrateOfferCall(t, central, "main-token"); w.Code != 200 {
		t.Fatalf("the other server: %d", w.Code)
	}
	// every server joined: closed
	nodesMu.Lock()
	nodesF.Migrated = append(nodesF.Migrated, "main")
	nodesMu.Unlock()
	if v := nodeMigrateView(self); v["open"] != false {
		t.Fatalf("all joined, still open: %v", v)
	}
}

// A server that joined by the move gets no license copy until approved.
func TestNodeMigrateHeldNoLicense(t *testing.T) {
	nodeTestCentral(t)
	oldLic, oldKey := activeLicense, cfg.LicenseKey
	t.Cleanup(func() {
		activeLicenseMu.Lock()
		activeLicense = oldLic
		activeLicenseMu.Unlock()
		mu.Lock()
		cfg.LicenseKey = oldKey
		mu.Unlock()
	})
	activeLicenseMu.Lock()
	activeLicense = &LicensePayload{Customer: "test", ExpiresAt: time.Now().Add(time.Hour).Unix()}
	activeLicenseMu.Unlock()
	mu.Lock()
	cfg.LicenseKey = "central-key"
	mu.Unlock()
	nodesMu.Lock()
	nodesF.Nodes = append(nodesF.Nodes, nodeRecord{ID: 1, Name: "moved", Key: "K1", Peer: "main", Held: true})
	nodesMu.Unlock()
	// a held node: returns before any call (the session has no connection)
	nodeLicenseSync(&nodeSession{id: 1}, nodeInfo{Proto: 1, License: nodeLicense{Reported: true}})
	nodesMu.Lock()
	pushed := nodeFindLocked(1).LicensePushed
	nodesMu.Unlock()
	if pushed != "" {
		t.Fatal("a held node got the key")
	}
}

// The offer is only on the Peer Link route, not under the panel's base path.
func TestNodeMigrateOfferRouteOnly(t *testing.T) {
	mux := http.NewServeMux()
	mountPeerRoutes(mux, "/base")
	r := httptest.NewRequest("GET", "/base/api/peer/node-offer", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code == 200 {
		t.Fatalf("served under the base path: %d", w.Code)
	}
	if _, pattern := mux.Handler(httptest.NewRequest("GET", peerRoutePrefix+"/api/peer/node-offer", nil)); !strings.Contains(pattern, "node-offer") {
		t.Fatalf("not on the Peer Link route: %q", pattern)
	}
}

// A foreign server looks for an offer for 14 days after it first looks, or
// after `node move`; not forever.
func TestNodeMigrateWatchWindow(t *testing.T) {
	old := configDir
	configDir = t.TempDir()
	t.Cleanup(func() { configDir = old })
	now := time.Now()
	if !nodeMigrateWatching(now) {
		t.Fatal("the first look")
	}
	if !nodeMigrateWatching(now.Add(13 * 24 * time.Hour)) {
		t.Fatal("within 14 days")
	}
	if nodeMigrateWatching(now.Add(15 * 24 * time.Hour)) {
		t.Fatal("after 14 days")
	}
	_ = os.WriteFile(nodeMigrateWatchFile(), []byte(strconv.FormatInt(now.Add(-20*24*time.Hour).Unix(), 10)), 0600)
	if nodeMigrateWatching(now) {
		t.Fatal("an old start")
	}
	if err := nodeMigrateWatchReset(); err != nil || !nodeMigrateWatching(now) {
		t.Fatal("node move")
	}
	_ = os.WriteFile(nodeMigrateWatchFile(), []byte("garbage"), 0600)
	if nodeMigrateWatching(now) {
		t.Fatal("a bad file means not looking")
	}
}

// A list that could not be read does not close the move as "all joined".
func TestNodeMigrateEmptyListKeepsOpen(t *testing.T) {
	nodeMigrateTest(t)
	st := nodeMigrateState{Open: true, OpenedAt: time.Now().Unix()}
	if !nodeMigrateCloseLocked(&st, nil) || !st.Open {
		t.Fatal("closed on an empty list")
	}
}

// A node that joined by the move cannot be opened before it is approved.
func TestNodeMigrateHeldNoView(t *testing.T) {
	nodeTestInvite(t, nodeTestCentral(t), "x")
	nodesMu.Lock()
	nodesF.Nodes = append(nodesF.Nodes, nodeRecord{ID: 5, Name: "moved", Key: "K5", Held: true})
	nodesMu.Unlock()
	sess := newSessionToken()
	addSession(sess)
	t.Cleanup(func() { dropSession(sess) })
	r := httptest.NewRequest("POST", "/x/api/nodes", strings.NewReader(`{"action":"view","id":5}`))
	r.AddCookie(&http.Cookie{Name: "gre_session", Value: sess})
	w := httptest.NewRecorder()
	handleNodesPost(w, r)
	if w.Code == 200 || !strings.Contains(w.Body.String(), "approve") {
		t.Fatalf("a held node's view: %d %s", w.Code, w.Body)
	}
}
