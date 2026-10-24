package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestPeerConfigDefaultsAndLoadSave(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "hashem_peer_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	oldConfigDir := configDir
	configDir = tmpDir
	defer func() { configDir = oldConfigDir }()

	// 1. Default config
	c := loadPeerConfig()
	if c.Role == "" || c.PeerSecret == "" {
		t.Errorf("expected default role and secret, got role=%q secret=%q", c.Role, c.PeerSecret)
	}
	if c.AutoPilotEnabled {
		t.Errorf("expected autopilot disabled by default")
	}

	// 2. Modify and Save
	c.PeerURL = "http://1.2.3.4:8080"
	c.InternalIP = "10.10.10.1"
	c.Role = "master"
	c.AutoPilotThreshold = 25.0
	if err := savePeerConfig(c); err != nil {
		t.Fatalf("savePeerConfig failed: %v", err)
	}

	// 3. Reload
	loaded := loadPeerConfig()
	if loaded.PeerURL != "http://1.2.3.4:8080" || loaded.InternalIP != "10.10.10.1" || loaded.AutoPilotThreshold != 25.0 {
		t.Errorf("loaded config mismatch: %+v", loaded)
	}
}

func TestPeerAuthMiddleware(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "hashem_peer_auth_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	oldConfigDir := configDir
	configDir = tmpDir
	defer func() { configDir = oldConfigDir }()

	c := loadPeerConfig()
	c.PeerSecret = "super-secret-peer-key-12345"
	_ = savePeerConfig(c)

	handler := requirePeerAuth(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"authorized"}`))
	})

	// Case 1: Unauthorized (no header)
	req1 := httptest.NewRequest("POST", "/api/peer/ping", nil)
	rr1 := httptest.NewRecorder()
	handler(rr1, req1)
	if rr1.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401 for missing secret, got %d", rr1.Code)
	}

	// Case 2: Wrong secret
	req2 := httptest.NewRequest("POST", "/api/peer/ping", nil)
	req2.Header.Set("X-Peer-Secret", "wrong-secret")
	rr2 := httptest.NewRecorder()
	handler(rr2, req2)
	if rr2.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401 for wrong secret, got %d", rr2.Code)
	}

	// Case 3: Valid X-Peer-Secret
	req3 := httptest.NewRequest("POST", "/api/peer/ping", nil)
	req3.Header.Set("X-Peer-Secret", "super-secret-peer-key-12345")
	rr3 := httptest.NewRecorder()
	handler(rr3, req3)
	if rr3.Code != http.StatusOK {
		t.Errorf("expected status 200 for valid X-Peer-Secret, got %d", rr3.Code)
	}

	// Case 4: Valid Authorization Bearer
	req4 := httptest.NewRequest("POST", "/api/peer/ping", nil)
	req4.Header.Set("Authorization", "Bearer super-secret-peer-key-12345")
	rr4 := httptest.NewRecorder()
	handler(rr4, req4)
	if rr4.Code != http.StatusOK {
		t.Errorf("expected status 200 for valid Bearer token, got %d", rr4.Code)
	}
}

func TestPeerEndpoints(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "hashem_peer_endpoints_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	oldConfigDir := configDir
	configDir = tmpDir
	defer func() { configDir = oldConfigDir }()

	// 1. Ping
	reqPing := httptest.NewRequest("POST", "/api/peer/ping", nil)
	rrPing := httptest.NewRecorder()
	handlePeerPing(rrPing, reqPing)
	if rrPing.Code != http.StatusOK {
		t.Fatalf("handlePeerPing returned status %d", rrPing.Code)
	}

	// 2. Handshake
	hsBody, _ := json.Marshal(PeerHandshakeRequest{
		Role:       "worker",
		PublicIP:   "9.9.9.9",
		PanelPort:  8080,
		InternalIP: "10.10.10.1",
	})
	reqHS := httptest.NewRequest("POST", "/api/peer/handshake", bytes.NewReader(hsBody))
	rrHS := httptest.NewRecorder()
	handlePeerHandshake(rrHS, reqHS)
	if rrHS.Code != http.StatusOK {
		t.Fatalf("handlePeerHandshake returned status %d", rrHS.Code)
	}

	// Verify handshake saved peer public URL
	c := loadPeerConfig()
	if c.PeerURL != "http://9.9.9.9:8080" || !c.IsConnected {
		t.Errorf("expected PeerURL to be updated, got %+v", c)
	}

	// 3. Status
	reqSt := httptest.NewRequest("GET", "/api/peer/status", nil)
	rrSt := httptest.NewRecorder()
	handlePeerStatus(rrSt, reqSt)
	if rrSt.Code != http.StatusOK {
		t.Fatalf("handlePeerStatus returned status %d", rrSt.Code)
	}

	// 4. Config Update (Web Admin)
	enable := true
	upBody, _ := json.Marshal(PeerConfigUpdateRequest{
		PeerURL:            "http://8.8.8.8:8080",
		PeerSecret:         "new-secret-xyz",
		AutoPilotEnabled:   &enable,
		AutoPilotThreshold: 15.0,
	})
	reqUp := httptest.NewRequest("POST", "/api/peer/config", bytes.NewReader(upBody))
	rrUp := httptest.NewRecorder()
	handlePeerConfigPost(rrUp, reqUp)
	if rrUp.Code != http.StatusOK {
		t.Fatalf("handlePeerConfigPost returned status %d", rrUp.Code)
	}

	c = loadPeerConfig()
	if c.PeerURL != "http://8.8.8.8:8080" || c.PeerSecret != "new-secret-xyz" || c.AutoPilotThreshold != 15.0 {
		t.Errorf("peer config not updated properly: %+v", c)
	}
}

func TestSendToPeerDualPath(t *testing.T) {
	// Start mock peer server
	receivedSecret := ""
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedSecret = r.Header.Get("X-Peer-Secret")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"pong"}`))
	}))
	defer mockServer.Close()

	tmpDir, err := os.MkdirTemp("", "hashem_peer_send_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	oldConfigDir := configDir
	configDir = tmpDir
	defer func() { configDir = oldConfigDir }()

	c := loadPeerConfig()
	c.PeerURL = mockServer.URL
	c.InternalIP = "" // force public URL path
	c.PeerSecret = "test-secret-456"
	_ = savePeerConfig(c)

	res, err := sendToPeer("/api/peer/ping", "POST", map[string]string{"ping": "1"})
	if err != nil {
		t.Fatalf("sendToPeer failed: %v", err)
	}
	if !bytes.Contains(res, []byte("pong")) {
		t.Errorf("expected pong response, got: %s", string(res))
	}
	if receivedSecret != "test-secret-456" {
		t.Errorf("expected secret 'test-secret-456', got %q", receivedSecret)
	}
}
