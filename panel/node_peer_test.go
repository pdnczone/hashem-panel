package main

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const nodePeerTestSecret = "peer-secret-of-the-tunnel"

// nodePeerTestRoute is a Peer Link route as the real ones are guarded: the
// secret in the header or a bare 404.
func nodePeerTestRoute(m *http.ServeMux, who string) {
	m.HandleFunc("POST "+peerRoutePrefix+"/api/peer/echo", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Peer-Secret") != nodePeerTestSecret {
			http.NotFound(w, r)
			return
		}
		b, _ := io.ReadAll(r.Body)
		writeJSON(w, map[string]any{"who": who, "from": ClientIP(r), "relayed": nodeRelayed(r), "body": string(b)})
	})
}

func TestNodePeerPathAndCheck(t *testing.T) {
	for p, want := range map[string]bool{
		"/api/peer/ping":                 true,
		"/api/peer/swap-status?id=3":     true,
		"/api/peer/":                     true,
		"/api/status":                    false,
		"/api/peer/../login":             false,
		"/api/peer//x":                   false,
		"/x/api/peer/ping":               false,
		"/api/peer/ping#x":               false,
		"/api/peer/ping\r\nX-Injected:1": false,
		"":                               false,
	} {
		if got := nodePeerPathOK(p); got != want {
			t.Errorf("nodePeerPathOK(%q) = %v, want %v", p, got, want)
		}
	}
	ok := nodePeerReq{Method: "POST", Path: "/api/peer/ping"}
	if err := nodePeerCheck(ok); err != nil {
		t.Errorf("a plain peer call was refused: %v", err)
	}
	for _, bad := range []nodePeerReq{
		{Method: "DELETE", Path: "/api/peer/ping"},
		{Method: "POST", Path: "/api/setup"},
		{Method: "POST", Path: "/api/peer/ping", Body: make([]byte, nodePeerBodyMax+1)},
	} {
		if nodePeerCheck(bad) == nil {
			t.Errorf("%s %s (%d bytes) passed", bad.Method, bad.Path, len(bad.Body))
		}
	}
}

// What arrives over the channel meets the Peer Link's own guard: the secret
// decides, and the call is never marked as relayed by the central.
func TestNodePeerServe(t *testing.T) {
	old := nodeRelayMux
	defer func() { nodeRelayMux = old }()
	m := http.NewServeMux()
	nodePeerTestRoute(m, "me")
	m.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, "the panel") })
	nodeRelayMux = func() http.Handler { return m }
	serve := func(q nodePeerReq) (nodeHTTPRes, error) {
		b, _ := json.Marshal(q)
		raw, err := nodePeerServe(b)
		var res nodeHTTPRes
		if err == nil {
			_ = json.Unmarshal(raw, &res)
		}
		return res, err
	}
	res, err := serve(nodePeerReq{From: "203.0.113.5", Method: "POST", Path: "/api/peer/echo", Secret: nodePeerTestSecret, Body: []byte("hi")})
	if err != nil || res.Status != 200 || !strings.Contains(string(res.Body), `"from":"203.0.113.5"`) ||
		!strings.Contains(string(res.Body), `"relayed":false`) || !strings.Contains(string(res.Body), `"body":"hi"`) {
		t.Fatalf("a peer call with the secret: %v %d %s", err, res.Status, res.Body)
	}
	if res, err := serve(nodePeerReq{From: "203.0.113.5", Method: "POST", Path: "/api/peer/echo", Secret: "wrong"}); err != nil || res.Status != 404 {
		t.Errorf("a wrong secret: %v %d %s", err, res.Status, res.Body)
	}
	for _, q := range []nodePeerReq{
		{From: "203.0.113.5", Method: "POST", Path: "/api/status", Secret: nodePeerTestSecret},
		{From: "203.0.113.5", Method: "POST", Path: "/api/peer/../x", Secret: nodePeerTestSecret},
		{From: "", Method: "POST", Path: "/api/peer/echo", Secret: nodePeerTestSecret},
		{From: "not-an-ip", Method: "POST", Path: "/api/peer/echo", Secret: nodePeerTestSecret},
	} {
		if res, err := serve(q); err == nil {
			t.Errorf("%+v was served: %d %s", q, res.Status, res.Body)
		}
	}
}

func TestNodePeerTarget(t *testing.T) {
	nodeTestCentral(t)
	pubIPMu.Lock()
	oldV, oldT := pubIPVal, pubIPTime
	pubIPVal, pubIPTime = "203.0.113.9", time.Now()
	pubIPMu.Unlock()
	defer func() { pubIPMu.Lock(); pubIPVal, pubIPTime = oldV, oldT; pubIPMu.Unlock() }()
	nodesMu.Lock()
	nodesLoadLocked()
	nodesF.Nodes = []nodeRecord{
		{ID: 1, Name: "a", Key: "k1", Addr: "198.51.100.1", Info: nodeInfo{PublicIP: "198.51.100.1"}},
		{ID: 2, Name: "b", Key: "k2", Addr: "10.0.0.2", Info: nodeInfo{PublicIP: "198.51.100.2"}},
		{ID: 3, Name: "held", Key: "k3", Addr: "198.51.100.3", Held: true},
	}
	_ = nodesSaveLocked()
	nodesMu.Unlock()
	for _, c := range []struct {
		ip     string
		except int
		want   int
	}{
		{"198.51.100.2", 1, 2},  // by its reported public IP
		{"10.0.0.2", 1, 2},      // by where it connected from
		{"198.51.100.1", 1, -1}, // never back to the asker
		{"198.51.100.3", 1, -1}, // not approved yet
		{"203.0.113.9", 1, 0},   // the central itself
		{"203.0.113.9", 0, -1},  // the central does not call itself
		{"192.0.2.77", 1, -1},
		{"nope", 1, -1},
	} {
		if got := nodePeerTarget(c.ip, c.except); got != c.want {
			t.Errorf("nodePeerTarget(%s, except %d) = %d, want %d", c.ip, c.except, got, c.want)
		}
	}
}

// Node A asks its central; the call reaches the central's own Peer Link, or
// node B's, with the address the central saw A at. The central reaches B the
// same way. A server that is not the central's gets no route.
func TestNodePeerOverChannel(t *testing.T) {
	central := nodeTestCentral(t)
	pubIPMu.Lock()
	oldV, oldT := pubIPVal, pubIPTime
	pubIPVal, pubIPTime = "203.0.113.9", time.Now()
	pubIPMu.Unlock()
	defer func() { pubIPMu.Lock(); pubIPVal, pubIPTime = oldV, oldT; pubIPMu.Unlock() }()
	oldMux := nodeRelayMux
	defer func() { nodeRelayMux = oldMux }()
	cm := http.NewServeMux()
	nodePeerTestRoute(cm, "central")
	nodeRelayMux = func() http.Handler { return cm }

	start := func(name, ask, secret string) (string, func()) {
		dir := t.TempDir()
		if out, err := nodeHelper(t, dir, "join", nodeTestInvite(t, central, name), 0).CombinedOutput(); err != nil {
			t.Fatalf("join %s: %v\n%s", name, err, out)
		}
		c := nodeHelper(t, dir, "serve", "", 20*time.Second)
		c.Env = append(c.Env, "NODE_HELPER_ASK="+ask, "NODE_HELPER_SECRET="+secret)
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		return dir, func() { _ = c.Process.Kill(); _ = c.Wait() }
	}
	result := func(dir string) string {
		var out string
		nodeTestWait(t, "the ask's answer", func() bool {
			b, err := os.ReadFile(filepath.Join(dir, "ask-result"))
			out = string(b)
			return err == nil && out != ""
		})
		return out
	}

	// B first: it only serves. Its address on the central is 127.0.0.1; give
	// it a public IP of its own so A's ask can name it.
	_, stopB := start("b", "", "")
	defer stopB()
	nodeTestWait(t, "node b online", func() bool { return nodeSessionFor(1) != nil })
	nodesMu.Lock()
	nodeFindLocked(1).Info.PublicIP = "198.51.100.2"
	nodeFindLocked(1).Addr = "198.51.100.2"
	_ = nodesSaveLocked()
	nodesMu.Unlock()

	// the central itself reaches B over B's channel
	st, data, ok := peerChannelCall([]string{"198.51.100.2"}, "POST", "/api/peer/echo", nodePeerTestSecret, []byte("c"), 10*time.Second)
	if !ok || st != 200 || !strings.Contains(string(data), `"who":"helper"`) || !strings.Contains(string(data), `"from":"203.0.113.9"`) {
		t.Fatalf("central to node b: ok=%v %d %s", ok, st, data)
	}
	if _, _, ok := peerChannelCall([]string{"192.0.2.77"}, "POST", "/api/peer/echo", nodePeerTestSecret, nil, 5*time.Second); ok {
		t.Error("the central found a route to a server that is not its node")
	}

	// A asks for B
	dirA, stopA := start("a", "198.51.100.2", nodePeerTestSecret)
	if got := result(dirA); !strings.HasPrefix(got, "true 200 ") || !strings.Contains(got, `"who":"helper"`) || !strings.Contains(got, `"from":"127.0.0.1"`) {
		t.Fatalf("node a to node b: %s", got)
	}
	stopA()

	// A asks for the central itself
	dirA, stopA = start("a2", "203.0.113.9", nodePeerTestSecret)
	if got := result(dirA); !strings.HasPrefix(got, "true 200 ") || !strings.Contains(got, `"who":"central"`) || !strings.Contains(got, `"relayed":false`) {
		t.Fatalf("node a to the central: %s", got)
	}
	stopA()

	// the wrong secret gets the Peer Link's 404, as on a direct call
	dirA, stopA = start("a3", "203.0.113.9", "wrong")
	if got := result(dirA); !strings.HasPrefix(got, "true 404 ") {
		t.Fatalf("node a with a wrong secret: %s", got)
	}
	stopA()

	// a server outside this central: no route, so the caller goes direct
	dirA, stopA = start("a4", "192.0.2.77", nodePeerTestSecret)
	defer stopA()
	if got := result(dirA); !strings.HasPrefix(got, "false 0 ") {
		t.Fatalf("node a to an unknown server: %s", got)
	}
}
