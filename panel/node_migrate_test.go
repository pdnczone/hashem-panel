package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
