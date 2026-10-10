package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
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
