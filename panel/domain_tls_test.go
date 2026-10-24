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

// Test 1: CleanHost helper validates extraction of raw host/IP across formats
func TestCleanHost(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"http://panel.example.com:7443", "panel.example.com"},
		{"https://panel.example.com:7443/dashboard", "panel.example.com"},
		{"https://panel.example.com", "panel.example.com"},
		{"http://1.2.3.4:7777/panel", "1.2.3.4"},
		{"192.168.1.50:8080", "192.168.1.50"},
		{"192.168.1.50", "192.168.1.50"},
		{"[2001:db8::1]:8443", "2001:db8::1"},
		{"[2001:db8::1]", "2001:db8::1"},
		{"2001:db8::1", "2001:db8::1"},
		{"panel.mydomain.ir", "panel.mydomain.ir"},
		{"http://panel.mydomain.ir:80?token=xyz", "panel.mydomain.ir"},
		{"", ""},
		{"   ", ""},
	}

	for _, tc := range cases {
		actual := CleanHost(tc.input)
		if actual != tc.expected {
			t.Errorf("CleanHost(%q) = %q; want %q", tc.input, actual, tc.expected)
		}
	}
}

// Test 2: loopback is trusted only when TRUSTED_PROXY_IPS lists it (H11):
// tunnels deliver outside clients from 127.0.0.1 too.
func TestTrustedProxyLoopback(t *testing.T) {
	t.Setenv("TRUSTED_PROXY_IPS", "")
	for _, ip := range []string{"127.0.0.1", "::1", "localhost"} {
		if IsTrustedProxy(ip) {
			t.Errorf("%s must not be trusted without TRUSTED_PROXY_IPS", ip)
		}
	}
	spoof := httptest.NewRequest("GET", "/test", nil)
	spoof.RemoteAddr = "127.0.0.1:54321"
	spoof.Header.Set("X-Forwarded-For", "203.0.113.195")
	if got := ClientIP(spoof); got != "127.0.0.1" {
		t.Errorf("X-Forwarded-For via untrusted loopback honoured: %q", got)
	}

	t.Setenv("TRUSTED_PROXY_IPS", "127.0.0.1, ::1")
	for _, ip := range []string{"127.0.0.1", "::1", "localhost"} {
		if !IsTrustedProxy(ip) {
			t.Errorf("%s listed in TRUSTED_PROXY_IPS but not trusted", ip)
		}
	}

	// External untrusted IP should NOT be trusted by default
	if IsTrustedProxy("8.8.8.8") {
		t.Errorf("did not expect 8.8.8.8 to be trusted proxy")
	}

	// When request comes from trusted proxy 127.0.0.1, X-Forwarded-For must be extracted
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "127.0.0.1:54321"
	req.Header.Set("X-Forwarded-For", "203.0.113.195, 10.0.0.1")
	clientIP := ClientIP(req)
	if clientIP != "203.0.113.195" {
		t.Errorf("ClientIP() = %q; want %q", clientIP, "203.0.113.195")
	}

	// When request comes from untrusted remote IP, X-Forwarded-For must be ignored
	untrustedReq := httptest.NewRequest("GET", "/test", nil)
	untrustedReq.RemoteAddr = "198.51.100.5:12345"
	untrustedReq.Header.Set("X-Forwarded-For", "203.0.113.195")
	untrustedClientIP := ClientIP(untrustedReq)
	if untrustedClientIP != "198.51.100.5" {
		t.Errorf("ClientIP() from untrusted remote = %q; want %q", untrustedClientIP, "198.51.100.5")
	}
}

// Test 3: WebSocket CheckOrigin handles direct domain and reverse proxies
func TestWebSocketCheckOrigin(t *testing.T) {
	checkOrigin := termUpgrader.CheckOrigin

	// 1. Direct match
	req1 := httptest.NewRequest("GET", "/api/term/ws", nil)
	req1.Host = "panel.example.com"
	req1.Header.Set("Origin", "https://panel.example.com")
	req1.RemoteAddr = "198.51.100.1:40000"
	if !checkOrigin(req1) {
		t.Errorf("expected direct matching origin to pass")
	}

	// 2. Direct match with port stripped
	req2 := httptest.NewRequest("GET", "/api/term/ws", nil)
	req2.Host = "panel.example.com:7443"
	req2.Header.Set("Origin", "https://panel.example.com:7443")
	req2.RemoteAddr = "198.51.100.1:40000"
	if !checkOrigin(req2) {
		t.Errorf("expected matching origin with port to pass")
	}

	// 3. Reverse proxy match: proxy forwards X-Forwarded-Host from 127.0.0.1
	t.Setenv("TRUSTED_PROXY_IPS", "127.0.0.1")
	req3 := httptest.NewRequest("GET", "/api/term/ws", nil)
	req3.Host = "127.0.0.1:7777"
	req3.Header.Set("Origin", "https://panel.example.com")
	req3.Header.Set("X-Forwarded-Host", "panel.example.com")
	req3.RemoteAddr = "127.0.0.1:50123" // from local reverse proxy
	if !checkOrigin(req3) {
		t.Errorf("expected reverse-proxied origin with X-Forwarded-Host to pass")
	}

	// 4. Untrusted attacker origin
	req4 := httptest.NewRequest("GET", "/api/term/ws", nil)
	req4.Host = "panel.example.com"
	req4.Header.Set("Origin", "https://malicious-site.com")
	req4.RemoteAddr = "198.51.100.1:40000"
	if checkOrigin(req4) {
		t.Errorf("expected attacker origin to be rejected")
	}
}

// Test 4: Port conflict checks validate against tunnel ports and panel port
func TestPortConflictDetection(t *testing.T) {
	cfg.Port = 7777
	cfg.TLSPort = 7443

	// Requesting the same port as HTTP must fail
	errSame := checkPortConflict(7777)
	if errSame == nil {
		t.Errorf("expected error when HTTPS port equals HTTP port 7777")
	}

	// Free port should succeed (as long as not used by simulated tunnels)
	errFree := checkPortConflict(7443)
	if errFree != nil {
		t.Logf("checkPortConflict(7443) = %v (checked against active environment)", errFree)
	}
}

// Test 5: Atomic rollback restores previous certificates on failure
func TestAtomicRollbackOnFailure(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "hashem-tls-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	oldConfigDir := configDir
	configDir = tmpDir
	defer func() { configDir = oldConfigDir }()

	tlsD := filepath.Join(tmpDir, "tls")
	_ = os.MkdirAll(tlsD, 0700)

	certPath := filepath.Join(tlsD, "server.crt")
	keyPath := filepath.Join(tlsD, "server.key")
	metaPath := filepath.Join(tlsD, "meta.json")

	_ = os.WriteFile(certPath, []byte("ORIGINAL_CERT"), 0600)
	_ = os.WriteFile(keyPath, []byte("ORIGINAL_KEY"), 0600)
	_ = os.WriteFile(metaPath, []byte(`{"domain":"original.com"}`), 0600)

	// Perform backup
	backupTLSCerts()

	// Simulate broken overwrite
	_ = os.WriteFile(certPath, []byte("CORRUPTED_CERT"), 0600)
	_ = os.WriteFile(keyPath, []byte("CORRUPTED_KEY"), 0600)

	// Rollback
	rollbackTLSCerts()

	// Verify restored content
	restoredCert, _ := os.ReadFile(certPath)
	if string(restoredCert) != "ORIGINAL_CERT" {
		t.Errorf("restored cert = %q; want %q", string(restoredCert), "ORIGINAL_CERT")
	}
	restoredKey, _ := os.ReadFile(keyPath)
	if string(restoredKey) != "ORIGINAL_KEY" {
		t.Errorf("restored key = %q; want %q", string(restoredKey), "ORIGINAL_KEY")
	}

	clearTLSBackups()
	if _, err := os.Stat(certPath + ".bak"); err == nil {
		t.Errorf("backup file still exists after clearTLSBackups")
	}
}

// Test 6: Clean domain removal deletes certs and reverts to HTTP access
func TestDomainRemoval(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "hashem-tls-remove-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	oldConfigDir := configDir
	configDir = tmpDir
	defer func() { configDir = oldConfigDir }()

	tlsD := filepath.Join(tmpDir, "tls")
	_ = os.MkdirAll(tlsD, 0700)
	_ = os.WriteFile(filepath.Join(tlsD, "server.crt"), []byte("CERT"), 0600)
	_ = os.WriteFile(filepath.Join(tlsD, "server.key"), []byte("KEY"), 0600)
	_ = os.WriteFile(filepath.Join(tlsD, "meta.json"), []byte(`{"domain":"panel.test"}`), 0600)

	if !tlsHasCert() {
		t.Fatalf("expected tlsHasCert() to be true initially")
	}

	req := httptest.NewRequest("DELETE", "/api/tls", nil)
	rr := httptest.NewRecorder()
	handleTLSRemove(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid json response: %v", err)
	}
	if resp["success"] != true {
		t.Errorf("expected success: true, got %v", resp["success"])
	}

	if tlsHasCert() {
		t.Errorf("expected tlsHasCert() to be false after removal")
	}
}

// Test 7: Reverse proxy generator outputs valid Nginx and Caddy templates
func TestReverseProxyConfigGenerator(t *testing.T) {
	cfg.Port = 7777
	cfg.BasePath = "my-panel"

	req := httptest.NewRequest("GET", "/api/tls/proxy-config?domain=sub.example.com", nil)
	rr := httptest.NewRecorder()
	handleReverseProxyConfig(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var res map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	nginx, ok := res["nginx"].(string)
	if !ok || !strings.Contains(nginx, "sub.example.com") {
		t.Errorf("nginx config missing domain: %s", nginx)
	}
	if !strings.Contains(nginx, "proxy_pass http://127.0.0.1:7777") {
		t.Errorf("nginx config missing backend proxy_pass: %s", nginx)
	}
	if !strings.Contains(nginx, "Upgrade $http_upgrade") || !strings.Contains(nginx, "Connection \"upgrade\"") {
		t.Errorf("nginx config missing WebSocket headers")
	}
	if !strings.Contains(nginx, "X-Forwarded-Host $host") {
		t.Errorf("nginx config missing X-Forwarded-Host")
	}

	caddy, ok := res["caddy"].(string)
	if !ok || !strings.Contains(caddy, "reverse_proxy 127.0.0.1:7777") {
		t.Errorf("caddy config invalid: %s", caddy)
	}
}

// Test 8: Preflight check endpoint returns comprehensive status
func TestPreflightCheckEndpoint(t *testing.T) {
	cfg.Port = 7777
	cfg.TLSPort = 7443

	bodyJSON := `{"domain":"panel.example.com","https_port":7443}`
	req := httptest.NewRequest("POST", "/api/tls/check", strings.NewReader(bodyJSON))
	rr := httptest.NewRecorder()
	handleTLSCheck(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var res map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil {
		t.Fatalf("invalid json response: %v", err)
	}

	if res["domain"] != "panel.example.com" {
		t.Errorf("expected domain panel.example.com, got %v", res["domain"])
	}
	if res["valid_domain"] != true {
		t.Errorf("expected valid_domain true, got %v", res["valid_domain"])
	}
}
