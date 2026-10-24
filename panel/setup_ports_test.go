package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
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
