package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// withPeerLink isolates configDir and the parts of cfg the peer code reads.
func withPeerLink(t *testing.T, c PeerConfig) {
	t.Helper()
	oldDir, oldBase, oldPort := configDir, cfg.BasePath, cfg.Port
	configDir = t.TempDir()
	cfg.BasePath, cfg.Port = "localbase", 7777
	t.Cleanup(func() { configDir, cfg.BasePath, cfg.Port = oldDir, oldBase, oldPort })
	if err := savePeerConfig(c); err != nil {
		t.Fatal(err)
	}
}

// H1: a wrong path that ends in the catch-all redirect to the login page must
// count as a failure, not as a connected peer.
func TestSendToPeerRejectsRedirectToHTML(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login/" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html>login</html>"))
			return
		}
		http.Redirect(w, r, "/login/", http.StatusFound)
	}))
	defer srv.Close()
	withPeerLink(t, PeerConfig{Role: "master", PeerSecret: "s3cret", PeerURL: srv.URL, AutoPilotExplicit: true})

	if _, err := sendToPeer("/api/peer/ping", "POST", map[string]string{}); err == nil {
		t.Fatal("redirect to an HTML page was treated as success")
	}
	if loadPeerConfig().IsConnected {
		t.Fatal("peer marked connected after a failed call")
	}
}

// H1: the fixed peer prefix is tried first; the peer's own base path (not
// ours) is the fallback for older peers.
func TestSendToPeerAddressesPeerNotLocalBasePath(t *testing.T) {
	var mu sync.Mutex
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		if r.URL.Path == "/peerbase/api/peer/ping" {
			_, _ = w.Write([]byte(`{"status":"pong"}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	withPeerLink(t, PeerConfig{Role: "master", PeerSecret: "s3cret", PeerURL: srv.URL, PeerBasePath: "peerbase", AutoPilotExplicit: true})

	if _, err := sendToPeer("/api/peer/ping", "POST", map[string]string{}); err != nil {
		t.Fatalf("sendToPeer: %v", err)
	}
	if len(paths) < 2 || paths[0] != peerRoutePrefix+"/api/peer/ping" {
		t.Fatalf("expected fixed prefix first, got %v", paths)
	}
	for _, p := range paths {
		if strings.HasPrefix(p, "/localbase/") {
			t.Fatalf("used this panel's own base path for the peer: %v", paths)
		}
	}
}

// H1: the handshake records the caller's base path and port, and answers
// with ours.
func TestPeerHandshakeExchangesBasePathAndPort(t *testing.T) {
	withPeerLink(t, PeerConfig{Role: "master", PeerSecret: "s3cret", AutoPilotExplicit: true})
	body := `{"role":"worker","public_ip":"203.0.113.7","panel_port":8123,"internal_ip":"10.10.10.2","base_path":"/workerbase/"}`
	rr := httptest.NewRecorder()
	handlePeerHandshake(rr, httptest.NewRequest("POST", "/x", strings.NewReader(body)))
	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad response %q", rr.Body.String())
	}
	if resp["base_path"] != "localbase" || resp["panel_port"] != float64(7777) {
		t.Fatalf("handshake reply lacks our base path/port: %v", resp)
	}
	c := loadPeerConfig()
	if c.PeerBasePath != "workerbase" || c.InternalPort != 8123 || c.PeerURL != "http://203.0.113.7:8123" {
		t.Fatalf("peer address not recorded: %+v", c)
	}
}

// H1: the fixed prefix needs the peer secret and otherwise looks like
// nothing is there (404, never 401/405/redirect).
func TestPeerFixedPrefixRoutes(t *testing.T) {
	withPeerLink(t, PeerConfig{Role: "worker", PeerSecret: "s3cret", AutoPilotExplicit: true})
	mux := http.NewServeMux()
	mountPeerRoutes(mux, "/localbase")
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/localbase/", http.StatusFound) })

	do := func(method, path, secret string) int {
		req := httptest.NewRequest(method, path, bytes.NewReader([]byte(`{}`)))
		if secret != "" {
			req.Header.Set("X-Peer-Secret", secret)
		}
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		return rr.Code
	}
	if c := do("POST", peerRoutePrefix+"/api/peer/ping", "s3cret"); c != http.StatusOK {
		t.Fatalf("ping with secret: %d", c)
	}
	if c := do("POST", peerRoutePrefix+"/api/peer/ping", ""); c != http.StatusNotFound {
		t.Fatalf("ping without secret: %d, want 404", c)
	}
	if c := do("POST", peerRoutePrefix+"/api/peer/ping", "wrong"); c != http.StatusNotFound {
		t.Fatalf("ping with wrong secret: %d, want 404", c)
	}
	if c := do("GET", peerRoutePrefix+"/api/peer/handshake", ""); c != http.StatusNotFound {
		t.Fatalf("wrong method: %d, want 404", c)
	}
	if c := do("POST", "/localbase/api/peer/ping", "s3cret"); c != http.StatusOK {
		t.Fatalf("base-path route still needed for old peers: %d", c)
	}
}

// M13: a status update must not overwrite settings saved in the meantime.
func TestPeerStatusUpdateKeepsConcurrentEdits(t *testing.T) {
	withPeerLink(t, PeerConfig{Role: "master", PeerSecret: "old", AutoPilotExplicit: true})
	edited := loadPeerConfig()
	edited.PeerSecret = "new"
	edited.AutoPilotEnabled = true
	if err := savePeerConfig(edited); err != nil {
		t.Fatal(err)
	}
	markPeerSeen()
	_ = updatePeerConfig(func(c *PeerConfig) { c.LatencyMs = 12 })
	c := loadPeerConfig()
	if c.PeerSecret != "new" || !c.AutoPilotEnabled || !c.IsConnected || c.LatencyMs != 12 {
		t.Fatalf("status update clobbered the admin's edit: %+v", c)
	}
}

// H1: a pasted panel URL keeps its base path separately.
func TestPeerConfigPostSplitsBasePathFromURL(t *testing.T) {
	withPeerLink(t, PeerConfig{Role: "master", PeerSecret: "s3cret", AutoPilotExplicit: true})
	rr := httptest.NewRecorder()
	handlePeerConfigPost(rr, httptest.NewRequest("POST", "/x", strings.NewReader(`{"peer_url":"http://198.51.100.4:9090/abcdEFgh1234/"}`)))
	if rr.Code != http.StatusOK {
		t.Fatalf("save: %d %s", rr.Code, rr.Body.String())
	}
	c := loadPeerConfig()
	if c.PeerURL != "http://198.51.100.4:9090" || c.PeerBasePath != "abcdEFgh1234" {
		t.Fatalf("got url=%q base=%q", c.PeerURL, c.PeerBasePath)
	}
}

// M8: private and CGNAT addresses are never reported as the public IP.
func TestPublicIPSkipsPrivateAddresses(t *testing.T) {
	for _, ip := range []string{"10.0.0.5", "172.20.1.1", "192.168.1.1", "100.64.0.1", "100.127.255.254", "127.0.0.1"} {
		if !isPrivateIP(ip) {
			t.Errorf("%s should be private", ip)
		}
	}
	for _, ip := range []string{"100.128.0.1", "198.51.100.22"} {
		if isPrivateIP(ip) {
			t.Errorf("%s should be public", ip)
		}
	}

	oldDir := configDir
	configDir = t.TempDir()
	t.Cleanup(func() { configDir = oldDir })
	_ = os.WriteFile(filepath.Join(configDir, "setup.json"), []byte(`{"local_public":"10.1.2.3"}`), 0600)
	if v := savedPublicIP(); v != "" {
		t.Fatalf("private setup.json address accepted: %q", v)
	}
	_ = os.WriteFile(filepath.Join(configDir, "setup.json"), []byte(`{"local_public":"198.51.100.22"}`), 0600)
	if v := savedPublicIP(); v != "198.51.100.22" {
		t.Fatalf("savedPublicIP = %q", v)
	}

	calls := 0
	oldLookup := externalIPLookup
	externalIPLookup = func() string { calls++; return "198.51.100.9" }
	extIPMu.Lock()
	extIPVal, extIPTime = "", extIPTime.AddDate(-1, 0, 0)
	extIPMu.Unlock()
	t.Cleanup(func() {
		externalIPLookup = oldLookup
		extIPMu.Lock()
		extIPVal = ""
		extIPMu.Unlock()
	})
	if externalPublicIPCached() != "198.51.100.9" || externalPublicIPCached() != "198.51.100.9" || calls != 1 {
		t.Fatalf("external lookup not cached (calls=%d)", calls)
	}
}
