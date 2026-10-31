package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// nodeTestCentral makes this process a fresh central in its own config dir
// and serves the channel; it returns the central's URL.
func nodeTestCentral(t *testing.T) string {
	t.Helper()
	old := configDir
	configDir = t.TempDir()
	nodesMu.Lock()
	nodesOK, nodesF, nodesEr = false, nodesFile{}, ""
	for id, s := range nodeSessions {
		s.close()
		delete(nodeSessions, id)
	}
	nodesMu.Unlock()
	nodeKeyMu.Lock()
	nodeKeyPriv, nodeCertTLS = nil, nil
	nodeKeyMu.Unlock()
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+nodeLinkPath, handleNodeLink)
	srv := httptest.NewServer(mux)
	t.Cleanup(func() {
		srv.Close()
		nodesMu.Lock()
		for id, s := range nodeSessions {
			s.close()
			delete(nodeSessions, id)
		}
		nodesOK = false
		nodesMu.Unlock()
		nodeKeyMu.Lock()
		nodeKeyPriv, nodeCertTLS = nil, nil
		nodeKeyMu.Unlock()
		configDir = old
	})
	return srv.URL
}

func nodeTestInvite(t *testing.T, central, name string) string {
	t.Helper()
	self, _ := nodeSelfLoad()
	code, _, err := nodeNewInvite(self, name, central)
	if err != nil {
		t.Fatal(err)
	}
	return code.String()
}

// nodeHelper runs this test binary as a node with its own config dir:
// cmd "join" (code) or "serve" (until removed, refused or timeout).
func nodeHelper(t *testing.T, dir, cmd, code string, wait time.Duration) *exec.Cmd {
	t.Helper()
	c := exec.Command(os.Args[0], "-test.run=^TestNodeHelperProcess$")
	c.Env = append(os.Environ(), "NODE_HELPER=1", "NODE_HELPER_DIR="+dir, "NODE_HELPER_CMD="+cmd,
		"NODE_HELPER_CODE="+code, "NODE_HELPER_WAIT="+wait.String())
	return c
}

// TestNodeHelperProcess is the node, in a child process (see nodeHelper).
func TestNodeHelperProcess(t *testing.T) {
	if os.Getenv("NODE_HELPER") != "1" {
		t.Skip("helper")
	}
	configDir = os.Getenv("NODE_HELPER_DIR")
	nodeInfoFn = func() nodeInfo {
		return nodeInfo{Proto: nodeProto, Version: "helper-v1", Hostname: "helper", MachineHash: getMachineHash(), CPUPct: -1,
			License: nodeLicense{Reported: os.Getenv("NODE_HELPER_LIC") == "1"}}
	}
	if os.Getenv("NODE_HELPER_FAST") == "1" {
		nodeLabFast()
	}
	// the node's panel, as far as the relay tests need it
	cfg.BasePath = "x"
	nodeRelayMux = func() http.Handler {
		m := http.NewServeMux()
		m.HandleFunc("GET /x/api/status", requireAuth(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Snapshot-Age-Ms", "7")
			writeJSON(w, map[string]any{"relayed": nodeRelayed(r), "q": r.URL.RawQuery})
		}))
		m.HandleFunc("POST /x/api/license", requireAuth(requireCSRF(func(w http.ResponseWriter, r *http.Request) {
			var b struct{ Key string }
			_ = json.NewDecoder(r.Body).Decode(&b)
			_ = os.WriteFile(filepath.Join(configDir, "got-key"), []byte(b.Key), 0600)
			writeJSON(w, map[string]string{"status": "ok"})
		})))
		m.HandleFunc("GET /x/api/logs", requireAuth(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write(make([]byte, nodeRelayBodyMax+1))
		}))
		m.HandleFunc("GET /x/api/access", requireAuth(func(w http.ResponseWriter, r *http.Request) { writeJSON(w, "secret") }))
		return m
	}
	switch os.Getenv("NODE_HELPER_CMD") {
	case "loop":
		wait, _ := time.ParseDuration(os.Getenv("NODE_HELPER_WAIT"))
		go startNodeLoop()
		time.Sleep(wait)
	case "join":
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		s, err := nodeJoin(ctx, os.Getenv("NODE_HELPER_CODE"), "helper node")
		if err != nil {
			os.Stdout.WriteString("ERR " + err.Error() + "\n")
			os.Exit(3)
		}
		os.Stdout.WriteString("OK " + s.Central + "\n")
	case "serve":
		wait, _ := time.ParseDuration(os.Getenv("NODE_HELPER_WAIT"))
		done := make(chan string, 1)
		go func() {
			s, _ := nodeSelfLoad()
			done <- nodeRunOnce(s)
		}()
		select {
		case r := <-done:
			os.Stdout.WriteString("RESULT " + r + "\n")
		case <-time.After(wait):
			os.Stdout.WriteString("RESULT timeout\n")
		}
	}
	os.Exit(0)
}

func nodeTestWait(t *testing.T, what string, ok func() bool) {
	t.Helper()
	end := time.Now().Add(15 * time.Second)
	for time.Now().Before(end) {
		if ok() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestNodeJoinServeRemove(t *testing.T) {
	central := nodeTestCentral(t)
	code := nodeTestInvite(t, central, "")
	if self, _ := nodeSelfLoad(); self.Role != nodeRoleCentral {
		t.Fatalf("the first invite makes this panel a central, role %q", self.Role)
	}
	nd := t.TempDir()
	out, err := nodeHelper(t, nd, "join", code, 0).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "OK "+central) {
		t.Fatalf("join: %v\n%s", err, out)
	}
	var ns nodeSelf
	data, _ := os.ReadFile(filepath.Join(nd, "node.json"))
	if json.Unmarshal(data, &ns) != nil || ns.Role != nodeRoleNode || ns.ID != 1 || ns.Name != "helper node" {
		t.Fatalf("node.json: %s", data)
	}
	if fi, err := os.Stat(filepath.Join(nd, "node.key")); err != nil || fi.Mode().Perm() != 0600 {
		t.Fatalf("node.key: %v %v", fi, err)
	}
	nodesMu.Lock()
	n, invites := len(nodesF.Nodes), len(nodesF.Invites)
	nodesMu.Unlock()
	if n != 1 || invites != 0 {
		t.Fatalf("central: %d nodes, %d invites left", n, invites)
	}

	// the code is single use
	out, _ = nodeHelper(t, t.TempDir(), "join", code, 0).CombinedOutput()
	if !strings.Contains(string(out), "not valid") {
		t.Fatalf("second use of a code: %s", out)
	}

	// the node connects; the central gets its info over the channel
	srv := nodeHelper(t, nd, "serve", "", 20*time.Second)
	var buf strings.Builder
	srv.Stdout = &buf
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	nodeTestWait(t, "the node's info", func() bool {
		nodesMu.Lock()
		defer nodesMu.Unlock()
		r := nodeFindLocked(1)
		return r != nil && r.Info.Version == "helper-v1" && nodeSessions[1] != nil
	})
	s := nodeSessionFor(1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	_, err = s.call(ctx, "no-such-method", nil)
	cancel()
	if err == nil || !strings.Contains(err.Error(), "update it") {
		t.Fatalf("unknown method: %v", err)
	}

	// removed on the central: the node is told and goes standalone
	nodesMu.Lock()
	nodesF.Nodes = nil
	nodesMu.Unlock()
	nodeKick(1)
	_ = srv.Wait()
	if !strings.Contains(buf.String(), "RESULT bye") {
		t.Fatalf("serve after removal: %s", buf.String())
	}
	if _, err := os.Stat(filepath.Join(nd, "node.json")); !os.IsNotExist(err) {
		t.Fatalf("node.json after removal: %v", err)
	}

	// an old node the central does not know is refused, and says so in node.json
	_ = nodeSelfSaveAt(nd, ns)
	out, _ = nodeHelper(t, nd, "serve", "", 10*time.Second).CombinedOutput()
	if !strings.Contains(string(out), "RESULT refused") {
		t.Fatalf("unknown node: %s", out)
	}
	data, _ = os.ReadFile(filepath.Join(nd, "node.json"))
	if !strings.Contains(string(data), `"refused"`) {
		t.Fatalf("node.json after refusal: %s", data)
	}
}

func nodeSelfSaveAt(dir string, s nodeSelf) error {
	b, _ := json.Marshal(s)
	return os.WriteFile(filepath.Join(dir, "node.json"), b, 0600)
}

func TestNodeLeaveDropsIt(t *testing.T) {
	central := nodeTestCentral(t)
	nd := t.TempDir()
	if out, err := nodeHelper(t, nd, "join", nodeTestInvite(t, central, "n"), 0).CombinedOutput(); err != nil {
		t.Fatalf("join: %v\n%s", err, out)
	}
	srv := nodeHelper(t, nd, "serve", "", 20*time.Second)
	var buf strings.Builder
	srv.Stdout = &buf
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	nodeTestWait(t, "the node online", func() bool { return nodeSessionFor(1) != nil })
	if err := os.Remove(filepath.Join(nd, "node.json")); err != nil {
		t.Fatal(err)
	}
	nodeTestWait(t, "the central to drop the node", func() bool {
		nodesMu.Lock()
		defer nodesMu.Unlock()
		return len(nodesF.Nodes) == 0
	})
	_ = srv.Wait()
	var nf nodesFile
	data, _ := os.ReadFile(nodesPath())
	if json.Unmarshal(data, &nf) != nil || len(nf.Nodes) != 0 {
		t.Fatalf("nodes.json after leave: %s", data)
	}
}

func TestNodeWrongCentralKey(t *testing.T) {
	central := nodeTestCentral(t)
	c, err := parseNodeCode(nodeTestInvite(t, central, ""))
	if err != nil {
		t.Fatal(err)
	}
	// another key in the code: the server that answers is not the one pinned
	c.Key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	out, _ := nodeHelper(t, t.TempDir(), "join", c.String(), 0).CombinedOutput()
	if !strings.Contains(string(out), "does not match") {
		t.Fatalf("wrong pinned key: %s", out)
	}
	nodesMu.Lock()
	n := len(nodesF.Nodes)
	nodesMu.Unlock()
	if n != 0 {
		t.Fatalf("a node was added through a mismatched key")
	}
}

func TestNodeLinkHiddenUnlessCentral(t *testing.T) {
	central := nodeTestCentral(t) // standalone: no node.json yet
	resp, err := http.Get(central + nodeLinkPath)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("standalone link: %d", resp.StatusCode)
	}
	_ = nodeSelfSave(nodeSelf{Role: nodeRoleCentral})
	resp, err = http.Get(central + nodeLinkPath) // not a websocket
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("plain GET on a central: %d", resp.StatusCode)
	}
}

func TestNodeInviteExpiryAndLimits(t *testing.T) {
	nodeTestCentral(t)
	now := time.Now()
	nodesMu.Lock()
	defer nodesMu.Unlock()
	nodesLoadLocked()
	c, _, err := nodeInviteLocked("a", "http://1.2.3.4:8080", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := nodeEnrollLocked(c.Secret, "K1", "", "", now.Add(nodeInviteTTL+time.Second)); err == nil {
		t.Fatal("an expired code was taken")
	}
	c, _, _ = nodeInviteLocked("named", "http://1.2.3.4:8080", now)
	id, err := nodeEnrollLocked(c.Secret, "K1", "from-node", "1.1.1.1", now)
	if err != nil || id != 1 || nodesF.Nodes[0].Name != "named" {
		t.Fatalf("enroll: %d %v %+v", id, err, nodesF.Nodes)
	}
	c, _, _ = nodeInviteLocked("", "http://1.2.3.4:8080", now)
	if id, err := nodeEnrollLocked(c.Secret, "K1", "", "", now); err != nil || id != 1 {
		t.Fatalf("the same key joining again keeps its id: %d %v", id, err)
	}
	for i := 0; i < nodeInvitesMax; i++ {
		if _, _, err := nodeInviteLocked("", "http://1.2.3.4:8080", now); err != nil {
			t.Fatalf("invite %d: %v", i, err)
		}
	}
	if _, _, err := nodeInviteLocked("", "http://1.2.3.4:8080", now); err == nil {
		t.Fatal("more open codes than the cap")
	}
	if !strings.Contains(string(mustJSON(nodesF)), nodesF.Invites[0].Hash) || strings.Contains(string(mustJSON(nodesF)), c.Secret) {
		t.Fatal("nodes.json must keep the hash of a code, never the code")
	}
}

func TestNodeCodeAndURL(t *testing.T) {
	for in, want := range map[string]string{
		"1.2.3.4:8080":           "http://1.2.3.4:8080",
		"http://1.2.3.4:8080/":   "http://1.2.3.4:8080",
		"https://hub.example.ir": "https://hub.example.ir",
		"http://[2001:db8::1]:9": "http://[2001:db8::1]:9",
	} {
		if got, err := nodeCentralURL(in); err != nil || got != want {
			t.Errorf("nodeCentralURL(%q) = %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "ftp://x", "http://x/panel", "http://u:p@x", "http://x:0", "http://x:99999", "http://x?a=1"} {
		if _, err := nodeCentralURL(bad); err == nil {
			t.Errorf("nodeCentralURL(%q) passed", bad)
		}
	}
	if nodeLinkURL("https://a:1") != "wss://a:1"+nodeLinkPath || nodeLinkURL("http://a:1") != "ws://a:1"+nodeLinkPath {
		t.Error("link URL")
	}
	c := nodeCode{URL: "http://1.2.3.4:8080", Key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", Secret: strings.Repeat("s", 32)}
	got, err := parseNodeCode("  " + c.String() + "\n")
	if err != nil || got != c {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	for _, bad := range []string{"hsh1_x", "hn1.!!", "hn1." + strings.Repeat("A", 10)} {
		if _, err := parseNodeCode(bad); err == nil {
			t.Errorf("parseNodeCode(%q) passed", bad)
		}
	}
	cmd := nodeJoinCommand(c, "it's", true)
	if !strings.HasPrefix(cmd, "bash <(curl -fsSL "+nodeInstallURL+") node-join '") || !strings.Contains(cmd, `--name 'it'\''s'`) {
		t.Fatalf("install command: %s", cmd)
	}
	ssh := nodeSSHCommand("n", true)
	if !strings.HasPrefix(ssh, "sudo -n bash -c '") || !strings.Contains(ssh, "command -v hashem") ||
		strings.Contains(ssh, "hn1.") || !strings.Contains(ssh, "node-join -") {
		t.Fatalf("ssh command (the code goes on stdin, never in it): %s", ssh)
	}
}

func TestNodeNames(t *testing.T) {
	if _, err := nodeCleanName("<script>"); err == nil {
		t.Error("angle brackets passed")
	}
	if _, err := nodeCleanName(strings.Repeat("ن", nodeNameMax+1)); err == nil {
		t.Error("long name passed")
	}
	if n, err := nodeCleanName("  سرور آلمان 1 "); err != nil || n != "سرور آلمان 1" {
		t.Errorf("persian name: %q %v", n, err)
	}
}

func TestNodeRolesAPI(t *testing.T) {
	nodeTestCentral(t)
	post := func(body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		handleNodesPost(w, httptest.NewRequest("POST", "/api/nodes", strings.NewReader(body)))
		return w
	}
	if w := post(`{"action":"remove","id":1}`); w.Code != http.StatusConflict {
		t.Fatalf("remove on a standalone panel: %d %s", w.Code, w.Body)
	}
	w := post(`{"action":"invite","name":"de-1","url":"5.6.7.8:8080"}`)
	var inv map[string]any
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &inv) != nil || !strings.HasPrefix(inv["command"].(string), "hashem node-join 'hn1.") {
		t.Fatalf("invite: %d %s", w.Code, w.Body)
	}
	if inv["url"] != "http://5.6.7.8:8080" {
		t.Fatalf("invite url: %v", inv["url"])
	}
	if w := post(`{"action":"join","code":"x"}`); w.Code != http.StatusConflict {
		t.Fatalf("a central joining another: %d", w.Code)
	}
	nodesMu.Lock()
	nodesF.Nodes = append(nodesF.Nodes, nodeRecord{ID: 7, Name: "x", Key: "K"})
	nodesMu.Unlock()
	if w := post(`{"action":"leave"}`); w.Code != http.StatusConflict {
		t.Fatalf("a central with nodes leaving: %d", w.Code)
	}
	if w := post(`{"action":"rename","id":7,"name":"y"}`); w.Code != 200 {
		t.Fatalf("rename: %d %s", w.Code, w.Body)
	}
	if w := post(`{"action":"remove","id":7}`); w.Code != 200 {
		t.Fatalf("remove: %d %s", w.Code, w.Body)
	}
	if w := post(`{"action":"remove","id":7}`); w.Code != http.StatusNotFound {
		t.Fatalf("remove again: %d", w.Code)
	}
	if w := post(`{"action":"leave"}`); w.Code != 200 {
		t.Fatalf("leave: %d %s", w.Code, w.Body)
	}
	if s, _ := nodeSelfLoad(); s.Role != "" {
		t.Fatalf("role after leave: %q", s.Role)
	}
	gw := httptest.NewRecorder()
	handleNodesGet(gw, httptest.NewRequest("GET", "/api/nodes", nil))
	if !strings.Contains(gw.Body.String(), `"role":"standalone"`) || strings.Contains(gw.Body.String(), `"key":"`) {
		t.Fatalf("get: %s", gw.Body)
	}
}

func TestNodeSSHValidation(t *testing.T) {
	for _, req := range []nodeRequest{
		{Host: "a b", Password: "x"},
		{Host: "1.2.3.4", Port: 70000, Password: "x"},
		{Host: "1.2.3.4", User: "Root;rm", Password: "x"},
		{Host: "1.2.3.4", HostKey: "SHA256:x"},
		{Host: "1.2.3.4", SSHKey: "not a key", HostKey: "SHA256:x"},
	} {
		if _, err := nodeSSHStart(nodeSelf{}, req); err == nil || nodeErrCode(err) != "E-NODE-01" {
			t.Errorf("%+v: %v", req, err)
		}
	}
}

// nodeLabFast shortens the channel's timers for the labs.
func nodeLabFast() {
	nodeHandshakeTO, nodeInfoEvery, nodeCallTO, nodeIdleTO = 3*time.Second, time.Second, 2*time.Second, 4*time.Second
	nodeRefusedRetry, nodeBackoffMax = 2*time.Second, 2*time.Second
}

// The first frame is capped before anything is known about the peer, and
// the buffer grows with the data, not with the size the header claims.
func TestNodeFrameCaps(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() {
		_, _ = b.Write([]byte{0x01, 0, 0, 0}) // claims 16 MiB
		_, _ = b.Write([]byte("{"))
	}()
	nc := &nodeConn{c: a}
	if _, err := nc.recv(2*time.Second, nodeFirstMax); err == nil || !strings.Contains(err.Error(), "bad frame size") {
		t.Fatalf("an oversized first frame: %v", err)
	}
}

func TestNodePreAuthLimits(t *testing.T) {
	for i := 0; i < nodePreAuthIP; i++ {
		if !nodePreAuthTake("198.51.100.9") {
			t.Fatalf("take %d", i)
		}
	}
	if nodePreAuthTake("198.51.100.9") {
		t.Fatal("more half-open links from one address than the cap")
	}
	for i := 0; i < nodePreAuthIP; i++ {
		nodePreAuthDone("198.51.100.9")
	}
	if !nodePreAuthTake("198.51.100.9") {
		t.Fatal("the slots came back")
	}
	nodePreAuthDone("198.51.100.9")
	nodePreAuth.Lock()
	n := nodePreAuth.n
	nodePreAuth.Unlock()
	if n != 0 {
		t.Fatalf("leak: %d", n)
	}
}

func TestNodeInfoClean(t *testing.T) {
	long := strings.Repeat("ن", 500)
	i := nodeInfoClean(nodeInfo{Hostname: long, Version: long, License: nodeLicense{Features: make([]string, 100)}})
	if len(i.Hostname) > 128 || len(i.Version) > 64 || len(i.License.Features) != 32 || !utf8.ValidString(i.Hostname) {
		t.Fatalf("not capped: %d %d %d", len(i.Hostname), len(i.Version), len(i.License.Features))
	}
}

// Correctness review: a removed node's id is never given to the next one,
// a list the central cannot read is retried (and never answered "unknown"),
// and changes the CLI makes to nodes.json reach the service.
func TestNodeListReloadAndIDs(t *testing.T) {
	nodeTestCentral(t)
	now := time.Now()
	nodesMu.Lock()
	nodesLoadLocked()
	c, _, _ := nodeInviteLocked("", "http://1.2.3.4:8080", now)
	id1, _ := nodeEnrollLocked(c.Secret, "K1", "", "", now)
	nodesF.Nodes = nil // removed
	c, _, _ = nodeInviteLocked("", "http://1.2.3.4:8080", now)
	id2, _ := nodeEnrollLocked(c.Secret, "K2", "", "", now)
	if id1 != 1 || id2 != 2 {
		t.Fatalf("ids %d then %d: a removed node's id was given again", id1, id2)
	}
	_ = nodesSaveLocked()
	nodesMu.Unlock()

	// the CLI (another process) clears the invites on disk
	time.Sleep(20 * time.Millisecond)
	_ = os.WriteFile(nodesPath(), []byte(`{"nodes":[],"next_id":3}`), 0600)
	future := time.Now().Add(time.Second)
	_ = os.Chtimes(nodesPath(), future, future)
	nodesMu.Lock()
	nodesLoadLocked()
	n, next := len(nodesF.Nodes), nodesF.NextID
	nodesMu.Unlock()
	if n != 0 || next != 3 {
		t.Fatalf("the service kept its old list: %d nodes, next %d", n, next)
	}

	// a damaged file: an error, kept as is, read again once fixed
	_ = os.WriteFile(nodesPath(), []byte(`{bad`), 0600)
	_ = os.Chtimes(nodesPath(), future.Add(time.Second), future.Add(time.Second))
	nodesMu.Lock()
	nodesLoadLocked()
	er := nodesEr
	saveErr := nodesSaveLocked()
	nodesMu.Unlock()
	if er == "" || saveErr == nil {
		t.Fatalf("a damaged nodes.json: err %q, save %v", er, saveErr)
	}
	if b, _ := os.ReadFile(nodesPath()); string(b) != `{bad` {
		t.Fatal("a damaged nodes.json was written over")
	}
	_ = os.WriteFile(nodesPath(), []byte(`{"nodes":[{"id":5,"name":"x","key":"K5"}]}`), 0600)
	nodesMu.Lock()
	nodesLoadLocked()
	er, n = nodesEr, len(nodesF.Nodes)
	nodesMu.Unlock()
	if er != "" || n != 1 {
		t.Fatalf("fixed file not read again: %q %d", er, n)
	}
}

func TestNodeWriteFileAtomic(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.json")
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func(i int) {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 50; j++ {
				_ = writeFile0600(p, []byte(strings.Repeat(string(rune('a'+i)), 1000)))
			}
		}(i)
	}
	for i := 0; i < 8; i++ {
		<-done
	}
	b, _ := os.ReadFile(p)
	if len(b) != 1000 || strings.Count(string(b), string(b[:1])) != 1000 {
		t.Fatalf("mixed or short file after concurrent writes: %d bytes", len(b))
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0600 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
	left, _ := filepath.Glob(p + ".*.tmp")
	if len(left) != 0 {
		t.Fatalf("temp files left: %v", left)
	}
}

func TestNodeSSHCommandChecksVersion(t *testing.T) {
	cmd := nodeSSHCommand("n", false)
	if !strings.Contains(cmd, `hashem help 2>/dev/null | grep -q '\''node-join.*code | ->'\''`) || !strings.Contains(cmd, nodeInstallURL) {
		t.Fatalf("an old Hashem must go through the installer: %s", cmd)
	}
}

func TestNodePreAuthIPv6ByPrefix(t *testing.T) {
	for i := 0; i < nodePreAuthIP; i++ {
		if !nodePreAuthTake(fmt.Sprintf("2001:db8:1:2::%x", i+1)) {
			t.Fatalf("take %d", i)
		}
	}
	if nodePreAuthTake("2001:db8:1:2::ffff") {
		t.Fatal("another address of the same /64 got past the cap")
	}
	if !nodePreAuthTake("2001:db8:1:3::1") {
		t.Fatal("another /64 was blocked")
	}
	nodePreAuthDone("2001:db8:1:3::1")
	for i := 0; i < nodePreAuthIP; i++ {
		nodePreAuthDone(fmt.Sprintf("2001:db8:1:2::%x", i+1))
	}
	nodePreAuth.Lock()
	n := nodePreAuth.n
	nodePreAuth.Unlock()
	if n != 0 {
		t.Fatalf("leak: %d", n)
	}
}

func TestNodeRelayAllowed(t *testing.T) {
	for p, want := range map[string]bool{
		"/api/status": true, "/api/dashboard": true, "/api/customers/export.csv": true, "/api/license": true,
		"/api/term/ws": false, "/api/login": false, "/api/access": false, "/api/password": false, "/api/2fa/setup": false,
		"/api/nodes": false, "/api/node/1/status": false, "/api/peer/handshake": false, "/api/session-settings": false,
		"/api/status/../access": false, "/api//access": false, "/api/status%2f..": false, "/status": false, "/api/tls/ip": false,
	} {
		if got := nodeRelayAllowed(p); got != want {
			t.Errorf("nodeRelayAllowed(%q) = %v, want %v", p, got, want)
		}
	}
}

// Only the channel can mark a request as relayed: a request with no
// session is refused however it is dressed up.
func TestNodeRelayedOnlyFromContext(t *testing.T) {
	h := requireAuth(func(w http.ResponseWriter, r *http.Request) { writeJSON(w, "in") })
	r := httptest.NewRequest("GET", "/x/api/status", nil)
	r.Header.Set("X-Hashem-Node", "1")
	r.Header.Set("X-Relayed", "central")
	w := httptest.NewRecorder()
	h(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("a request without a session: %d", w.Code)
	}
	w = httptest.NewRecorder()
	h(w, r.WithContext(context.WithValue(r.Context(), nodeRelayKey, "admin")))
	if w.Code != 200 {
		t.Fatalf("a relayed request: %d", w.Code)
	}
	c := requireCSRF(func(w http.ResponseWriter, r *http.Request) { writeJSON(w, "in") })
	w = httptest.NewRecorder()
	c(w, httptest.NewRequest("POST", "/x/api/limits", strings.NewReader("{}")))
	if w.Code == 200 {
		t.Fatal("a POST without a session or token got through")
	}
}

func TestNodeRelayEndToEnd(t *testing.T) {
	central := nodeTestCentral(t)
	nd := t.TempDir()
	if out, err := nodeHelper(t, nd, "join", nodeTestInvite(t, central, "r"), 0).CombinedOutput(); err != nil {
		t.Fatalf("join: %v\n%s", err, out)
	}
	srv := nodeHelper(t, nd, "serve", "", 20*time.Second)
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Process.Kill(); _ = srv.Wait() }()
	nodeTestWait(t, "the node online", func() bool { return nodeSessionFor(1) != nil })
	relay := func(method, id, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "/c/api/node/"+id+"/"+path, strings.NewReader(body))
		if i := strings.Index(path, "?"); i >= 0 {
			r.SetPathValue("path", path[:i])
		} else {
			r.SetPathValue("path", path)
		}
		r.SetPathValue("id", id)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handleNodeRelay(w, r)
		return w
	}
	w := relay("GET", "1", "status?range=1h", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"relayed":true`) || !strings.Contains(w.Body.String(), `"q":"range=1h"`) ||
		w.Header().Get("X-Snapshot-Age-Ms") != "7" || w.Header().Get("X-Hashem-Node") != "1" {
		t.Fatalf("relayed GET: %d %s %v", w.Code, w.Body, w.Header())
	}
	if w := relay("POST", "1", "license", `{"key":"k1"}`); w.Code != 200 {
		t.Fatalf("relayed POST: %d %s", w.Code, w.Body)
	}
	if b, _ := os.ReadFile(filepath.Join(nd, "got-key")); string(b) != "k1" {
		t.Fatalf("the node's handler did not run: %q", b)
	}
	if w := relay("GET", "1", "access", ""); w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), "secret") {
		t.Fatalf("a path that is not relayed: %d %s", w.Code, w.Body)
	}
	if w := relay("GET", "1", "logs", ""); w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), "bigger than") {
		t.Fatalf("an answer over the cap: %d %s", w.Code, w.Body)
	}
	if w := relay("GET", "9", "status", ""); w.Code != http.StatusNotFound {
		t.Fatalf("an unknown node: %d", w.Code)
	}
	nodesMu.Lock()
	nodesF.Nodes = append(nodesF.Nodes, nodeRecord{ID: 9, Name: "off", Key: "K9"})
	nodesMu.Unlock()
	if w := relay("GET", "9", "status", ""); w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), "offline") {
		t.Fatalf("an offline node: %d %s", w.Code, w.Body)
	}
}

func TestNodeLicensePlan(t *testing.T) {
	k := "payload.sig"
	h := nodeKeyHash(k)
	none := nodeInfo{MachineHash: "m1"}
	own := nodeInfo{MachineHash: "m1", License: nodeLicense{Active: true, KeyHash: "ownkey"}}
	copied := nodeInfo{MachineHash: "m1", License: nodeLicense{Active: true, KeyHash: h}}
	old := nodeInfo{MachineHash: "m1", License: nodeLicense{Active: true, KeyHash: "oldcopy"}}
	for _, c := range []struct {
		name, key, machine string
		info               nodeInfo
		pushed, want       string
	}{
		{"an unlocked key goes to a node without one", k, "", none, "", "push"},
		{"a key for any machine (*)", k, "*", none, "", "push"},
		{"locked to this node's machine", k, "M1", none, "", "push"},
		{"locked to another machine: not sent", k, "m2", none, "", ""},
		{"the node has its own key: left alone", k, "", own, "", ""},
		{"the node has the same key already", k, "", copied, h, ""},
		{"a renewal replaces the copy the central gave", k, "", old, "oldcopy", "push"},
		{"the central's key removed: the copy goes too", "", "", copied, h, "remove"},
		{"the central's key removed: a node's own key stays", "", "", own, h, ""},
		{"no key anywhere", "", "", none, "", ""},
	} {
		if got := nodeLicensePlan(c.key, c.machine, c.info, c.pushed); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

// The central's key reaches a node without one, through the node's own
// /api/license (here a stand-in that records what it got).
func TestNodeLicenseCopied(t *testing.T) {
	central := nodeTestCentral(t)
	oldLic, oldKey := activeLicense, cfg.LicenseKey
	t.Cleanup(func() {
		activeLicenseMu.Lock()
		activeLicense = oldLic
		activeLicenseMu.Unlock()
		mu.Lock()
		cfg.LicenseKey = oldKey
		mu.Unlock()
		nodeLicTried.Lock()
		nodeLicTried.at = map[int]time.Time{}
		nodeLicTried.Unlock()
	})
	activeLicenseMu.Lock()
	activeLicense = &LicensePayload{Customer: "test", MachineHash: "", ExpiresAt: time.Now().Add(time.Hour).Unix()}
	activeLicenseMu.Unlock()
	mu.Lock()
	cfg.LicenseKey = "central-key"
	mu.Unlock()
	nd := t.TempDir()
	if out, err := nodeHelper(t, nd, "join", nodeTestInvite(t, central, "l"), 0).CombinedOutput(); err != nil {
		t.Fatalf("join: %v\n%s", err, out)
	}
	srv := nodeHelper(t, nd, "serve", "", 20*time.Second)
	srv.Env = append(srv.Env, "NODE_HELPER_LIC=1")
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Process.Kill(); _ = srv.Wait() }()
	nodeTestWait(t, "the key on the node", func() bool {
		b, _ := os.ReadFile(filepath.Join(nd, "got-key"))
		return string(b) == "central-key"
	})
	nodeTestWait(t, "the central to remember it pushed it", func() bool {
		nodesMu.Lock()
		defer nodesMu.Unlock()
		r := nodeFindLocked(1)
		return r != nil && r.LicensePushed == nodeKeyHash("central-key")
	})
}
