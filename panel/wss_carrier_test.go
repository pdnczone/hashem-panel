package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestWSSConfigDefaultsAndLoadSave(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "hashem_wss_test_*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	oldConfigDir := configDir
	configDir = tmpDir
	defer func() { configDir = oldConfigDir }()

	cfg := defaultWSSConfig()
	if cfg.ListenPort != 8443 {
		t.Errorf("expected default listen port 8443, got %d", cfg.ListenPort)
	}
	if cfg.LocalBridgeUDP != 19998 {
		t.Errorf("expected default local bridge UDP 19998, got %d", cfg.LocalBridgeUDP)
	}

	cfg.ListenPort = 9443
	cfg.SNI = "cdn.example.com"
	if err := saveWSSConfig(cfg); err != nil {
		t.Fatalf("saveWSSConfig failed: %v", err)
	}

	loaded := loadWSSConfig()
	if loaded.ListenPort != 9443 {
		t.Errorf("expected loaded port 9443, got %d", loaded.ListenPort)
	}
	if loaded.SNI != "cdn.example.com" {
		t.Errorf("expected SNI 'cdn.example.com', got '%s'", loaded.SNI)
	}
}

func TestSelfSignedCertGeneration(t *testing.T) {
	cert, err := generateSelfSignedCert("speedtest.net")
	if err != nil {
		t.Fatalf("generateSelfSignedCert failed: %v", err)
	}
	if len(cert.Certificate) == 0 {
		t.Errorf("expected at least one certificate in chain")
	}
	if cert.PrivateKey == nil {
		t.Errorf("expected private key to be generated")
	}
}

func TestWSSCarrierStartStop(t *testing.T) {
	cfg := defaultWSSConfig()
	cfg.Enabled = true

	if err := startWSSCarrier(cfg); err != nil {
		t.Fatalf("startWSSCarrier failed: %v", err)
	}

	st := getWSSStatus()
	if !st.Running {
		t.Errorf("expected WSS carrier to be reported as running")
	}

	if err := stopWSSCarrier(); err != nil {
		t.Fatalf("stopWSSCarrier failed: %v", err)
	}

	st = getWSSStatus()
	if st.Running {
		t.Errorf("expected WSS carrier to be stopped")
	}
}

func TestCarrierWSSIntegration(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "hashem_carrier_wss_test_*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	oldConfigDir := configDir
	configDir = tmpDir
	defer func() { configDir = oldConfigDir }()
	// set_mode below starts the WSS server goroutine, which reads configDir;
	// stop it before configDir is restored (defers run last-in first-out).
	defer func() { _ = stopWSSCarrier() }()

	cfg := defaultCarrierConfig()
	foundWSS := false
	for _, c := range cfg.Candidates {
		if c == "wss:8443" {
			foundWSS = true
			break
		}
	}
	if !foundWSS {
		t.Errorf("expected 'wss:8443' in default candidates, got: %v", cfg.Candidates)
	}

	// Test POST /api/carrier with action: "set_mode", mode: "wss:8443"
	body, _ := json.Marshal(carrierPostRequest{
		Action: "set_mode",
		Mode:   "wss:8443",
	})
	req := httptest.NewRequest("POST", "/api/carrier", bytes.NewReader(body))
	w := httptest.NewRecorder()
	handleCarrierPost(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify status includes WSS
	reqGet := httptest.NewRequest("GET", "/api/carrier", nil)
	wGet := httptest.NewRecorder()
	handleCarrierGet(wGet, reqGet)

	var resp carrierStatusResponse
	if err := json.Unmarshal(wGet.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode carrier status: %v", err)
	}
	if resp.Active != "wss:8443" {
		t.Errorf("expected active carrier 'wss:8443', got '%s'", resp.Active)
	}
}

// M-02: browser-originated WebSocket upgrades to the carrier must be refused.
func TestWSSOriginPolicy(t *testing.T) {
	r := httptest.NewRequest("GET", "/tunnel-stream", nil)
	if !wssOriginAllowed(r) {
		t.Fatal("non-browser client (no Origin) must be allowed")
	}
	r.Header.Set("Origin", "https://evil.example")
	if wssOriginAllowed(r) {
		t.Fatal("cross-site browser Origin must be rejected")
	}
	if !wssTokenEqual("abc", "abc") || wssTokenEqual("abc", "abd") || wssTokenEqual("", "abc") {
		t.Fatal("token compare wrong")
	}
}

// Changing the WSS port keeps the carrier names on the new port, and an empty
// SNI clears the old one.
func TestCarrierSetWSSPortAndSNI(t *testing.T) {
	oldConfigDir := configDir
	configDir = t.TempDir()
	defer func() { configDir = oldConfigDir }()
	defer func() { _ = stopWSSCarrier() }()

	post := func(body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		handleCarrierPost(w, httptest.NewRequest("POST", "/api/carrier", strings.NewReader(body)))
		return w
	}
	if w := post(`{"action":"set_mode","mode":"wss:8443"}`); w.Code != http.StatusOK {
		t.Fatalf("set_mode: %d %s", w.Code, w.Body.String())
	}
	if w := post(`{"action":"set_wss","wss_port":9443,"wss_sni":"example.com"}`); w.Code != http.StatusOK {
		t.Fatalf("set_wss: %d %s", w.Code, w.Body.String())
	} else if strings.Contains(w.Body.String(), "auth_token") {
		t.Fatalf("set_wss response leaks the auth token: %s", w.Body.String())
	}
	cfg := loadCarrierConfig()
	if cfg.ActiveCarrier != "wss:9443" || cfg.WSSPort != 9443 || !reflect.DeepEqual(cfg.Candidates, []string{"direct", "wss:9443"}) {
		t.Fatalf("carrier not moved to the new port: %+v", cfg)
	}
	if w := loadWSSConfig(); w.ListenPort != 9443 || w.SNI != "example.com" {
		t.Fatalf("wss config: %+v", w)
	}
	if w := post(`{"action":"set_wss","wss_sni":""}`); w.Code != http.StatusOK {
		t.Fatalf("clear sni: %d", w.Code)
	}
	if w := loadWSSConfig(); w.SNI != "" || w.ListenPort != 9443 {
		t.Fatalf("empty SNI must clear it and keep the port: %+v", w)
	}
	if w := post(`{"action":"set_wss","wss_port":70000}`); w.Code != http.StatusBadRequest {
		t.Fatalf("port 70000: want 400, got %d", w.Code)
	}
}

// The other server's WSS address can be IPv6 (WSS over IPv6) or a name; it is
// kept bracketed with the WSS port, and junk is refused.
func TestCarrierSetWSSRemoteIPv6(t *testing.T) {
	oldConfigDir := configDir
	configDir = t.TempDir()
	defer func() { configDir = oldConfigDir }()
	defer func() { _ = stopWSSCarrier() }()

	post := func(body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		handleCarrierPost(w, httptest.NewRequest("POST", "/api/carrier", strings.NewReader(body)))
		return w
	}
	for in, want := range map[string]string{
		"2001:db8::2": "[2001:db8::2]:9443", "[2001:db8::3]": "[2001:db8::3]:9443",
		"203.0.113.10": "203.0.113.10:9443", "tunnel.example.com": "tunnel.example.com:9443",
	} {
		if w := post(`{"action":"set_wss","wss_port":9443,"wss_remote":"` + in + `"}`); w.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", in, w.Code, w.Body.String())
		}
		if got := loadWSSConfig().RemoteAddr; got != want {
			t.Fatalf("%s: remote %q, want %q", in, got, want)
		}
		if h := wssRemoteHost(loadWSSConfig().RemoteAddr); h != strings.Trim(in, "[]") {
			t.Fatalf("%s: shown as %q", in, h)
		}
	}
	for _, bad := range []string{"a b", "x;rm -rf /", "-oProxy"} {
		if w := post(`{"action":"set_wss","wss_remote":"` + bad + `"}`); w.Code != http.StatusBadRequest {
			t.Fatalf("%q: want 400, got %d", bad, w.Code)
		}
	}
}
