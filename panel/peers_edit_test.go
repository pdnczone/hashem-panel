package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---- PATCH /api/peers body parsing (accepts the shapes the UI and CLI send) ----

func TestPeerPatchID(t *testing.T) {
	for body, want := range map[string]int{
		`{"id":3}`: 3, `{"id":"4"}`: 4, `{"id":" 5 "}`: 5, `{"id":""}`: 0, `{}`: 0,
	} {
		var p peerPatchRequest
		if err := json.Unmarshal([]byte(body), &p); err != nil || p.ID != want {
			t.Errorf("%s -> id=%d err=%v want %d", body, p.ID, err, want)
		}
	}
	for _, bad := range []string{`{"id":"abc"}`, `{"id":true}`, `{"id":[1]}`} {
		var p peerPatchRequest
		if err := json.Unmarshal([]byte(bad), &p); err == nil {
			t.Errorf("%s must be rejected", bad)
		}
	}
}

func TestPeerPatchPortsShapes(t *testing.T) {
	cases := map[string]struct {
		nums []int
		raws []string
	}{
		`{"ports":[443,2083]}`:        {[]int{443, 2083}, []string{"443", "2083"}},
		`{"ports":"443, 2083"}`:       {[]int{443, 2083}, []string{"443", "2083"}},
		`{"ports":"8080=80, 443"}`:    {[]int{443}, []string{"8080=80", "443"}},
		`{"ports":["443","8080=80"]}`: {nil, nil}, // checked loosely below
		`{"ports":""}`:                {[]int{}, []string{}},
		`{"ports":"  ,  "}`:           {nil, nil},
	}
	for body, want := range cases {
		var p peerPatchRequest
		if err := json.Unmarshal([]byte(body), &p); err != nil {
			t.Errorf("%s: %v", body, err)
			continue
		}
		if p.Ports == nil {
			t.Errorf("%s: ports must be set (even if empty)", body)
			continue
		}
		if want.nums != nil && len(*p.Ports) != len(want.nums) {
			t.Errorf("%s: nums %v want %v", body, *p.Ports, want.nums)
		}
		if want.raws != nil && (p.RawPorts == nil || strings.Join(*p.RawPorts, "|") != strings.Join(want.raws, "|")) {
			t.Errorf("%s: raws %v want %v", body, p.RawPorts, want.raws)
		}
	}
	var none peerPatchRequest
	_ = json.Unmarshal([]byte(`{"id":2,"name":"x"}`), &none)
	if none.Ports != nil {
		t.Error("absent ports must stay nil (= leave ports unchanged)")
	}
	var null peerPatchRequest
	_ = json.Unmarshal([]byte(`{"ports":null}`), &null)
	if null.Ports != nil {
		t.Error("null ports must stay nil")
	}
}

func TestPeerPatchScalarFields(t *testing.T) {
	var p peerPatchRequest
	err := json.Unmarshal([]byte(`{"id":2,"name":"n","remote_pub":"1.2.3.4","carrier":"gre","engine":"frp","transport":"tcp","proxy_protocol":"v2","frp_transport":"quic","use_encryption":true,"use_compression":false}`), &p)
	if err != nil || p.Name != "n" || p.RemotePub != "1.2.3.4" || p.Carrier != "gre" || p.Engine != "frp" ||
		p.ProxyProtocol != "v2" || p.FRPTransport != "quic" || p.UseEncryption == nil || !*p.UseEncryption ||
		p.UseCompression == nil || *p.UseCompression {
		t.Fatalf("%+v err=%v", p, err)
	}
}

// ---- peers.json registry ----

func withPeersFile(t *testing.T, content string) {
	t.Helper()
	old := configDir
	configDir = t.TempDir()
	t.Cleanup(func() { configDir = old })
	if content != "" {
		if err := os.WriteFile(filepath.Join(configDir, "peers.json"), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLoadPeersAndFindPeer(t *testing.T) {
	withPeersFile(t, `{"peers":[{"id":2,"name":"a"},{"id":5,"name":"b"}]}`)
	if got := loadPeers(); len(got) != 2 {
		t.Fatalf("loadPeers: %v", got)
	}
	if p := findPeer(5); p == nil || p.Name != "b" {
		t.Errorf("findPeer(5)=%v", p)
	}
	if findPeer(9) != nil {
		t.Error("unknown id must be nil")
	}
	// the returned record is a copy: mutating it must not leak into later reads
	p := findPeer(2)
	p.Name = "changed"
	if findPeer(2).Name != "a" {
		t.Error("findPeer must return a copy")
	}
}

func TestLoadPeersTolerantOfBadFiles(t *testing.T) {
	withPeersFile(t, "")
	if loadPeers() != nil {
		t.Error("missing file = no peers")
	}
	withPeersFile(t, "{not json")
	if loadPeers() != nil || findPeer(1) != nil {
		t.Error("corrupt file must not panic and yields no peers")
	}
}

func TestPeerUnitNamesUseRegistryOverrides(t *testing.T) {
	withPeersFile(t, `{"peers":[{"id":3,"frps_svc":"frps-custom","gre_if":"gre-x","peer_gre":"10.10.30.2"}]}`)
	if peerFrpsSvc(3) != "frps-custom" || peerGreSvc(3) != "gre-x.service" || peerPingTarget(3) != "10.10.30.2" {
		t.Errorf("registry overrides ignored: %s %s %s", peerFrpsSvc(3), peerGreSvc(3), peerPingTarget(3))
	}
}

func TestHandlePeersGetRejectsBadID(t *testing.T) {
	rr := httptest.NewRecorder()
	handlePeersGet(rr, httptest.NewRequest("GET", "/api/peers?id=abc", nil))
	if rr.Code == http.StatusOK {
		t.Errorf("non-numeric id must fail: %d", rr.Code)
	}
}

func TestHandlePeersPostIsNotCreationPath(t *testing.T) {
	rr := httptest.NewRecorder()
	handlePeersPost(rr, httptest.NewRequest("POST", "/api/peers", strings.NewReader(`{}`)))
	if rr.Code == http.StatusOK {
		t.Error("creation must go through /api/setup, not /api/peers POST")
	}
}

// ---- systemd unit endpoint rewrite ----

func TestUpdateServiceRemoteIP(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "gre.service")
	unit := "[Service]\nExecStart=/sbin/ip tunnel add g mode gre remote 1.1.1.1 local 2.2.2.2\nExecStop=/sbin/ip tunnel del g\n"
	_ = os.WriteFile(f, []byte(unit), 0644)

	updateServiceRemoteIP(f, "1.1.1.1", "9.9.9.9")
	b, _ := os.ReadFile(f)
	if !strings.Contains(string(b), "remote 9.9.9.9 local 2.2.2.2") || strings.Contains(string(b), "1.1.1.1") {
		t.Errorf("known old IP not replaced: %s", b)
	}

	updateServiceRemoteIP(f, "", "7.7.7.7") // unknown old IP: regex fallback
	b, _ = os.ReadFile(f)
	if !strings.Contains(string(b), "remote 7.7.7.7") {
		t.Errorf("regex fallback failed: %s", b)
	}
	if !strings.Contains(string(b), "local 2.2.2.2") {
		t.Error("local address must be untouched")
	}

	updateServiceRemoteIP(filepath.Join(dir, "missing.service"), "a", "b") // must not panic
}

// L15: only the exact old address is rewritten, not addresses containing it.
func TestUpdateServiceRemoteIPExactMatch(t *testing.T) {
	f := filepath.Join(t.TempDir(), "gre.service")
	unit := "ExecStart=/sbin/ip tunnel add g mode gre remote 1.2.3.4 local 1.2.3.45\nExecStartPost=/bin/ping -c1 1.2.3.4\n"
	_ = os.WriteFile(f, []byte(unit), 0644)
	updateServiceRemoteIP(f, "1.2.3.4", "9.9.9.9")
	b, _ := os.ReadFile(f)
	want := "ExecStart=/sbin/ip tunnel add g mode gre remote 9.9.9.9 local 1.2.3.45\nExecStartPost=/bin/ping -c1 9.9.9.9\n"
	if string(b) != want {
		t.Fatalf("got:\n%s\nwant:\n%s", b, want)
	}
}

// H3: editing an FRP peer's ports on Iran must not write [[proxies]] into
// its frps config (frps rejects them) nor restart frps.
func TestEditPeerDirectLeavesFrpsConfigAlone(t *testing.T) {
	withPeersFile(t, `{"peers":[{"id":2,"name":"p2","ports":[8080],"gre_if":"gre-t2","frps_svc":"frps-2"}]}`)
	oldFrp := frpDir
	frpDir = t.TempDir()
	t.Cleanup(func() { frpDir = oldFrp })
	frps := "bindPort = 7001\nauth.token = \"tok\"\n"
	path := filepath.Join(frpDir, "frps-2.toml")
	_ = os.WriteFile(path, []byte(frps), 0600)

	peer := findPeer(2)
	ports := []int{9090}
	warning, err := editPeerDirect(peer, peerPatchRequest{ID: 2, Ports: &ports})
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); string(b) != frps {
		t.Fatalf("frps config modified:\n%s", b)
	}
	if !strings.Contains(warning, "foreign server") {
		t.Errorf("expected a hint to apply ports on the foreign server, got %q", warning)
	}
	if p := findPeer(2); p == nil || len(p.Ports) != 1 || p.Ports[0] != 9090 {
		t.Fatalf("ports not saved to peers.json: %+v", p)
	}
}

func TestMaxPeersDefaultAndOverride(t *testing.T) {
	t.Setenv("GRE_MAX_PEERS", "")
	if maxPeers() != 10 {
		t.Fatalf("default max peers = %d, want 10", maxPeers())
	}
	t.Setenv("GRE_MAX_PEERS", "3")
	if maxPeers() != 3 {
		t.Fatalf("GRE_MAX_PEERS override ignored")
	}
}
