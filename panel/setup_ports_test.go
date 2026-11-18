package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestRewriteTomlPorts(t *testing.T) {
	initial := `bindAddr = "0.0.0.0"
bindPort = 7000
auth.token = "secret123"

[[proxies]]
name = "tcp_80"
type = "tcp"
localIP = "127.0.0.1"
localPort = 80
remotePort = 80

[[proxies]]
name = "udp_80"
type = "udp"
localIP = "127.0.0.1"
localPort = 80
remotePort = 80
`

	updated := rewriteTomlPorts(initial, []int{443, 2083})

	if !strings.Contains(updated, "bindPort = 7000") {
		t.Errorf("expected header preserved, got:\n%s", updated)
	}
	if !strings.Contains(updated, "auth.token = \"secret123\"") {
		t.Errorf("expected auth preserved, got:\n%s", updated)
	}
	if strings.Contains(updated, "tcp_80") || strings.Contains(updated, "remotePort = 80") {
		t.Errorf("expected old port 80 removed, got:\n%s", updated)
	}
	if !strings.Contains(updated, "name = \"tcp_443\"") || !strings.Contains(updated, "remotePort = 443") {
		t.Errorf("expected port 443 present, got:\n%s", updated)
	}
	if !strings.Contains(updated, "name = \"udp_443\"") {
		t.Errorf("expected udp_443 present, got:\n%s", updated)
	}
	if !strings.Contains(updated, "name = \"tcp_2083\"") || !strings.Contains(updated, "remotePort = 2083") {
		t.Errorf("expected port 2083 present, got:\n%s", updated)
	}
	if !strings.Contains(updated, "name = \"udp_2083\"") {
		t.Errorf("expected udp_2083 present, got:\n%s", updated)
	}
}

func TestHandlePeersPatchValidation(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		wantStatus int
		wantCode   string
	}{
		{
			name:       "invalid json",
			body:       `{bad`,
			wantStatus: http.StatusBadRequest,
			wantCode:   "E-PEER-07",
		},
		{
			name:       "negative id",
			body:       `{"id": -1, "ports": [443]}`,
			wantStatus: http.StatusBadRequest,
			wantCode:   "E-PEER-07",
		},
		{
			name:       "empty ports",
			body:       `{"id": 1, "ports": []}`,
			wantStatus: http.StatusBadRequest,
			wantCode:   "E-PEER-07",
		},
		{
			name:       "invalid port number low",
			body:       `{"id": 1, "ports": [0]}`,
			wantStatus: http.StatusBadRequest,
			wantCode:   "E-PEER-07",
		},
		{
			name:       "invalid port number high",
			body:       `{"id": 1, "ports": [70000]}`,
			wantStatus: http.StatusBadRequest,
			wantCode:   "E-PEER-07",
		},
		{
			name:       "peer not found",
			body:       `{"id": 9999, "ports": [443]}`,
			wantStatus: http.StatusBadRequest,
			wantCode:   "E-PEER-05",
		},
		{
			name:       "no fields to update",
			body:       `{"id": 1}`,
			wantStatus: http.StatusBadRequest,
			wantCode:   "E-PEER-07",
		},
		{
			name:       "invalid remote IP format",
			body:       `{"id": 1, "remote_pub": "not-an-ip"}`,
			wantStatus: http.StatusBadRequest,
			wantCode:   "E-PEER-07",
		},
		{
			name:       "invalid carrier mode",
			body:       `{"id": 1, "carrier": "unknown_carrier"}`,
			wantStatus: http.StatusBadRequest,
			wantCode:   "E-PEER-07",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("PATCH", "/api/peers", bytes.NewBufferString(tc.body))
			w := httptest.NewRecorder()
			handlePeersPatch(w, req)

			if w.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d (body: %s)", w.Code, tc.wantStatus, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), tc.wantCode) {
				t.Errorf("body %s does not contain code %s", w.Body.String(), tc.wantCode)
			}
		})
	}
}

func TestHandlePeersPatchFullUpdate(t *testing.T) {
	oldConfigDir := configDir
	tmpDir := t.TempDir()
	configDir = tmpDir
	defer func() { configDir = oldConfigDir }()

	// Write initial peers.json
	initialPeers := `{
  "peers": [
    {
      "id": 1,
      "name": "germany-old",
      "local_pub": "1.2.3.4",
      "remote_pub": "198.51.100.1",
      "frp_port": 25000,
      "local_gre": "10.10.10.2",
      "peer_gre": "10.10.10.1",
      "ports": [80],
      "token": "testtok123",
      "gre_if": "gre-t1",
      "frps_svc": "frps"
    },
    {
      "id": 2,
      "name": "finland-peer",
      "local_pub": "1.2.3.4",
      "remote_pub": "198.51.100.99",
      "frp_port": 25001,
      "local_gre": "10.10.20.2",
      "peer_gre": "10.10.20.1",
      "ports": [8080],
      "token": "testtok456",
      "gre_if": "gre-t2",
      "frps_svc": "frps-2"
    }
  ]
}`
	if err := os.WriteFile(peersFile(), []byte(initialPeers), 0600); err != nil {
		t.Fatalf("failed to write mock peers.json: %v", err)
	}

	// 1. Successful full update of peer 1
	patchBody := `{
		"id": 1,
		"name": "germany-new",
		"remote_pub": "198.51.100.50",
		"carrier": "fou:443",
		"ports": [443, 2083]
	}`
	req := httptest.NewRequest("PATCH", "/api/peers", bytes.NewBufferString(patchBody))
	w := httptest.NewRecorder()
	handlePeersPatch(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("patch failed: status %d, body %s", w.Code, w.Body.String())
	}

	// Verify peers.json was updated
	updated := loadPeers()
	if len(updated) != 2 {
		t.Fatalf("expected 2 peers, got %d", len(updated))
	}
	p1 := updated[0]
	if p1.Name != "germany-new" {
		t.Errorf("expected name 'germany-new', got %q", p1.Name)
	}
	if p1.RemotePub != "198.51.100.50" {
		t.Errorf("expected remote_pub '198.51.100.50', got %q", p1.RemotePub)
	}
	if p1.Carrier != "fou:443" {
		t.Errorf("expected carrier 'fou:443', got %q", p1.Carrier)
	}
	if len(p1.Ports) != 2 || p1.Ports[0] != 443 || p1.Ports[1] != 2083 {
		t.Errorf("expected ports [443, 2083], got %v", p1.Ports)
	}

	// 2. Reject duplicate IP clash with peer 2
	clashIPBody := `{
		"id": 1,
		"remote_pub": "198.51.100.99"
	}`
	req2 := httptest.NewRequest("PATCH", "/api/peers", bytes.NewBufferString(clashIPBody))
	w2 := httptest.NewRecorder()
	handlePeersPatch(w2, req2)
	if w2.Code != http.StatusConflict || !strings.Contains(w2.Body.String(), "E-PEER-03") {
		t.Errorf("expected 409 E-PEER-03 for IP clash, got status %d body %s", w2.Code, w2.Body.String())
	}

	// 3. Reject port clash with peer 2
	clashPortBody := `{
		"id": 1,
		"ports": [8080]
	}`
	req3 := httptest.NewRequest("PATCH", "/api/peers", bytes.NewBufferString(clashPortBody))
	w3 := httptest.NewRecorder()
	handlePeersPatch(w3, req3)
	if w3.Code != http.StatusConflict || !strings.Contains(w3.Body.String(), "E-PEER-02") {
		t.Errorf("expected 409 E-PEER-02 for port clash, got status %d body %s", w3.Code, w3.Body.String())
	}
}

// M14: rewriting the port list keeps per-proxy options such as PROXY
// protocol and encryption instead of dropping them.
func TestRewriteTomlPortsKeepsProxyOptions(t *testing.T) {
	src := `serverAddr = "10.10.10.1"
serverPort = 7000

[[proxies]]
name = "tcp_443"
type = "tcp"
localIP = "127.0.0.1"
localPort = 443
remotePort = 443
transport.proxyProtocolVersion = "v2"
transport.useEncryption = true

[[proxies]]
name = "udp_443"
type = "udp"
localIP = "127.0.0.1"
localPort = 443
remotePort = 443
`
	out := rewriteTomlPorts(src, []int{443, 8443})
	if strings.Count(out, `transport.proxyProtocolVersion = "v2"`) != 2 {
		t.Fatalf("proxy protocol not kept on both tcp proxies:\n%s", out)
	}
	if strings.Count(out, "transport.useEncryption = true") != 2 {
		t.Fatalf("encryption not kept:\n%s", out)
	}
	if strings.Count(out, "[[proxies]]") != 4 || !strings.Contains(out, `name = "udp_8443"`) {
		t.Fatalf("unexpected proxy set:\n%s", out)
	}
	udp := out[strings.Index(out, `name = "udp_443"`):]
	udp = udp[:strings.Index(udp, "[[proxies]]")]
	if strings.Contains(udp, "proxyProtocolVersion") {
		t.Fatalf("tcp-only option copied onto a udp proxy:\n%s", udp)
	}
	if !strings.HasPrefix(out, "serverAddr = \"10.10.10.1\"\nserverPort = 7000\n") {
		t.Fatalf("header not kept:\n%s", out)
	}
}

// FRP forwards a port to the same port on the other server, so a range is
// read as every port it covers; before, "1051-1060" kept only 1051 (or, in
// Setup, nothing at all) without a word.
func TestExpandPortList(t *testing.T) {
	for _, c := range []struct {
		in   string
		want []int
		bad  []string
	}{
		{"443", []int{443}, nil},
		{"443, 1051-1053 2083", []int{443, 1051, 1052, 1053, 2083}, nil},
		{"1051-1053,1052,443,443", []int{1051, 1052, 1053, 443}, nil},
		{"0443\t1051-1052\n", []int{443, 1051, 1052}, nil},
		{"2083=8443, 127.0.0.1:443, 1060-1051, 0, 70000, x, 443", []int{443}, []string{"2083=8443", "127.0.0.1:443", "1060-1051", "0", "70000", "x"}},
		{"", nil, nil},
	} {
		got, bad, err := expandPortList(c.in)
		if err != nil || !slices.Equal(got, c.want) || strings.Join(bad, "|") != strings.Join(c.bad, "|") {
			t.Errorf("expandPortList(%q) = %v, bad %q, err %v; want %v, bad %q", c.in, got, bad, err, c.want, c.bad)
		}
	}
	if got, _, err := expandPortList("1-1000"); err != nil || len(got) != maxForwardPorts {
		t.Errorf("1-1000: %d ports, err %v", len(got), err)
	}
	if got, _, err := expandPortList("1-65535"); err == nil || len(got) != maxForwardPorts {
		t.Errorf("1-65535 must stop at %d with an error: %d ports, err %v", maxForwardPorts, len(got), err)
	}
	// the lenient reader skips what it cannot use and keeps the rest
	if got := parsePorts("443, 1051-1053, 8080=80"); !slices.Equal(got, []int{443, 1051, 1052, 1053}) {
		t.Errorf("parsePorts = %v", got)
	}
}

func TestNumericPortsFor(t *testing.T) {
	raw := []string{"443", "1051-1053", "127.0.0.1:2096", "10000-10002=443"}
	if got := numericPortsFor("frp", raw); !slices.Equal(got, []int{443, 1051, 1052, 1053, 2096, 10000, 10001, 10002}) {
		t.Errorf("frp: %v", got)
	}
	if got := numericPortsFor("", raw); !slices.Equal(got, []int{443, 1051, 1052, 1053, 2096, 10000, 10001, 10002}) {
		t.Errorf("no engine is frp: %v", got)
	}
	// Backhaul keeps the range in its own config: the first port names it
	for _, eng := range []string{"backhaul", "gre-backhaul"} {
		if got := numericPortsFor(eng, raw); !slices.Equal(got, []int{443, 1051, 2096, 10000}) {
			t.Errorf("%s: %v", eng, got)
		}
	}
}

func TestFRPPortEntryErr(t *testing.T) {
	for entry, ok := range map[string]bool{"443": true, "1051-1060": true, "2083=8443": false, "127.0.0.1:443": false, "1060-1051": false} {
		err := frpPortEntryErr(entry)
		if (err == nil) != ok {
			t.Errorf("%q: %v", entry, err)
		}
		if err != nil && !strings.Contains(err.Error(), "Backhaul") {
			t.Errorf("%q: the error should point to Backhaul: %v", entry, err)
		}
	}
}

// Edit Tunnel on an FRP peer: a range is stored as written and every port of
// it is forwarded; a mapping is refused with the reason. A Backhaul peer
// keeps its ranges and mappings as before.
func TestHandlePeersPatchFRPRanges(t *testing.T) {
	old := configDir
	configDir = t.TempDir()
	defer func() { configDir = old }()
	doc := `{"peers": [
  {"id": 2, "name": "de", "local_pub": "1.2.3.4", "remote_pub": "198.51.100.2", "frp_port": 25002, "ports": [443],
   "token": "tok2", "gre_if": "gre-t2", "frps_svc": "frps-2"},
  {"id": 3, "name": "nl", "local_pub": "1.2.3.4", "remote_pub": "198.51.100.3", "frp_port": 25003, "ports": [8443],
   "token": "tok3", "gre_if": "none", "frps_svc": "backhaul-server-3", "engine": "backhaul", "no_gre": true, "raw_ports": ["8443"]}
]}`
	if err := os.WriteFile(peersFile(), []byte(doc), 0600); err != nil {
		t.Fatal(err)
	}
	patch := func(body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		handlePeersPatch(w, httptest.NewRequest("PATCH", "/api/peers", bytes.NewBufferString(body)))
		return w
	}
	peer := func(id int) peerRecord {
		for _, p := range loadPeers() {
			if p.ID == id {
				return p
			}
		}
		t.Fatalf("peer %d is gone", id)
		return peerRecord{}
	}

	if w := patch(`{"id": 2, "raw_ports": ["1051-1053", "443"]}`); w.Code != http.StatusOK {
		t.Fatalf("frp range: %d %s", w.Code, w.Body.String())
	}
	if p := peer(2); !slices.Equal(p.Ports, []int{1051, 1052, 1053, 443}) || strings.Join(p.RawPorts, ",") != "1051-1053,443" {
		t.Errorf("frp peer: ports %v raw %q", p.Ports, p.RawPorts)
	}

	for _, raw := range []string{`["2083=8443"]`, `["127.0.0.1:443"]`} {
		w := patch(`{"id": 2, "raw_ports": ` + raw + `}`)
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "E-PEER-07") || !strings.Contains(w.Body.String(), "Backhaul") {
			t.Errorf("frp %s: %d %s", raw, w.Code, w.Body.String())
		}
	}
	if w := patch(`{"id": 2, "raw_ports": ["1-2000"]}`); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "more than") {
		t.Errorf("frp oversized range: %d %s", w.Code, w.Body.String())
	}
	if p := peer(2); !slices.Equal(p.Ports, []int{1051, 1052, 1053, 443}) {
		t.Errorf("a refused patch changed the peer: %v", p.Ports)
	}

	if w := patch(`{"id": 3, "raw_ports": ["10000-10002", "2083=8443", "127.0.0.1:2096=2096"]}`); w.Code != http.StatusOK {
		t.Fatalf("backhaul: %d %s", w.Code, w.Body.String())
	}
	if p := peer(3); !slices.Equal(p.Ports, []int{10000, 2083, 2096}) {
		t.Errorf("backhaul peer: ports %v", p.Ports)
	}
}

// Swapping a Backhaul tunnel with a range onto FRP forwards the whole range,
// not just its first port, and the peer record says so.
func TestSwapToFRPForwardsWholeRange(t *testing.T) {
	sw := swapTunnel{Raw: []string{"443", "1051-1053"}}
	sw.Ports = extractNumericPorts(sw.Raw)
	if got := sw.portsFor("frp"); !slices.Equal(got, []int{443, 1051, 1052, 1053}) {
		t.Errorf("to frp: %v", got)
	}
	if got := sw.portsFor("backhaul"); !slices.Equal(got, []int{443, 1051}) {
		t.Errorf("to backhaul: %v", got)
	}
	if got := (swapTunnel{Ports: []int{443}}).portsFor("frp"); !slices.Equal(got, []int{443}) {
		t.Errorf("no raw entries: %v", got)
	}
	p := peerRecord{Engine: "backhaul", RawPorts: portList{"1051-1053"}, Ports: []int{1051}}
	recordCarrier(&p, carrierChoice{Engine: "frp", Transport: "tcp"}, "frps-2")
	if !slices.Equal(p.Ports, []int{1051, 1052, 1053}) {
		t.Errorf("peer record after the swap: %v", p.Ports)
	}
}

// Edit Peer moves a tunnel to another address of this server: it must be
// one of its own IPv4 addresses, the first tunnel is Setup's, and the reply
// says what the foreign server has to change.
func TestHandlePeersPatchLocalPub(t *testing.T) {
	old, oldHas := configDir, serverHasAddr
	configDir = t.TempDir()
	serverHasAddr = func(ip string) bool {
		return ip == "198.51.100.9" || ip == "1.2.3.4" || ip == "127.0.0.1" || ip == "169.254.1.1"
	}
	defer func() { configDir, serverHasAddr = old, oldHas }()
	doc := `{"peers": [{"id": 2, "name": "tr", "local_pub": "1.2.3.4", "remote_pub": "198.51.100.2", "frp_port": 25002,
  "ports": [443], "token": "tok2", "gre_if": "gre-t2", "frps_svc": "frps-2", "local_gre": "10.11.0.2", "peer_gre": "10.11.0.1"}]}`
	if err := os.WriteFile(peersFile(), []byte(doc), 0600); err != nil {
		t.Fatal(err)
	}
	patch := func(body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		handlePeersPatch(w, httptest.NewRequest("PATCH", "/api/peers", bytes.NewBufferString(body)))
		return w
	}
	for body, why := range map[string]string{
		`{"id": 2, "local_pub": "203.0.113.5"}`:  "not an address of this server",
		`{"id": 2, "local_pub": "2001:db8::1"}`:  "IPv4",
		`{"id": 2, "local_pub": "nope"}`:         "IPv4",
		`{"id": 2, "local_pub": "127.0.0.1"}`:    "cannot carry a tunnel",
		`{"id": 2, "local_pub": "0.0.0.0"}`:      "cannot carry a tunnel",
		`{"id": 2, "local_pub": "169.254.1.1"}`:  "cannot carry a tunnel",
		`{"id": 0, "local_pub": "198.51.100.9"}`: "set by Setup",
	} {
		w := patch(body)
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), why) {
			t.Errorf("%s: %d %s", body, w.Code, w.Body.String())
		}
	}
	w := patch(`{"id": 2, "local_pub": "198.51.100.9"}`)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "198.51.100.9") || !strings.Contains(w.Body.String(), "foreign server") {
		t.Fatalf("move: %d %s", w.Code, w.Body.String())
	}
	if p := loadPeers()[0]; p.LocalPub != "198.51.100.9" || p.RemotePub != "198.51.100.2" {
		t.Errorf("peer record: %+v", p)
	}
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if b, _ := resp["bundle"].(string); !strings.HasPrefix(b, "hsh1_198.51.100.9_") {
		t.Errorf("the bundle must carry the new address: %q", b)
	}
}

func TestUpdateServiceLocalIP(t *testing.T) {
	f := filepath.Join(t.TempDir(), "gre-t2.service")
	unit := "ExecStart=/sbin/ip tunnel add gre-t2 mode gre local 1.2.3.4 remote 1.2.3.45 ttl 255\n"
	_ = os.WriteFile(f, []byte(unit), 0644)
	updateServiceLocalIP(f, "1.2.3.4", "198.51.100.9")
	if b, _ := os.ReadFile(f); string(b) != strings.Replace(unit, "local 1.2.3.4 ", "local 198.51.100.9 ", 1) {
		t.Errorf("exact: %s", b)
	}
	// the record did not know the old address: the "local" argument
	_ = os.WriteFile(f, []byte(unit), 0644)
	updateServiceLocalIP(f, "", "198.51.100.9")
	if b, _ := os.ReadFile(f); !strings.Contains(string(b), "local 198.51.100.9 remote 1.2.3.45") {
		t.Errorf("fallback: %s", b)
	}
}
