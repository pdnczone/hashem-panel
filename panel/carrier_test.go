package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestCarrierDefaultsAndLoadSave(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "carrier-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	oldConfigDir := configDir
	configDir = tmpDir
	defer func() { configDir = oldConfigDir }()

	// Default when file is missing
	def := loadCarrierConfig()
	if def.Mode != "direct" {
		t.Fatalf("expected mode=direct, got %s", def.Mode)
	}
	if def.ActiveCarrier != "direct" {
		t.Fatalf("expected active_carrier=direct, got %s", def.ActiveCarrier)
	}
	if def.FOUPort1 != 443 || def.FOUPort2 != 55555 {
		t.Fatalf("expected fou_port1=443, fou_port2=55555, got %d, %d", def.FOUPort1, def.FOUPort2)
	}

	// Save and reload
	def.ActiveCarrier = "fou:443"
	def.SwitchCount = 1
	if err := saveCarrierConfig(def); err != nil {
		t.Fatal(err)
	}

	loaded := loadCarrierConfig()
	if loaded.ActiveCarrier != "fou:443" {
		t.Fatalf("expected active_carrier=fou:443, got %s", loaded.ActiveCarrier)
	}
	if loaded.SwitchCount != 1 {
		t.Fatalf("expected switch_count=1, got %d", loaded.SwitchCount)
	}
}

func TestCarrierAPIEndpoints(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "carrier-api-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	oldConfigDir := configDir
	configDir = tmpDir
	defer func() { configDir = oldConfigDir }()

	// Initial GET
	req := httptest.NewRequest("GET", "/api/carrier", nil)
	w := httptest.NewRecorder()
	handleCarrierGet(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp carrierStatusResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Mode != "direct" || resp.ActiveCarrier != "direct" || resp.Active != "direct" {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if len(resp.FouPorts) != 2 || resp.FouPorts[0] != 443 || resp.FouPorts[1] != 55555 {
		t.Fatalf("unexpected fou_ports: %+v", resp.FouPorts)
	}

	// POST cycle_next
	postBody, _ := json.Marshal(carrierPostRequest{Action: "cycle_next"})
	req = httptest.NewRequest("POST", "/api/carrier", bytes.NewReader(postBody))
	w = httptest.NewRecorder()
	handleCarrierPost(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 on cycle_next, got %d", w.Code)
	}

	var postResp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &postResp); err != nil {
		t.Fatal(err)
	}
	if postResp["status"] != "ok" {
		t.Fatalf("expected status=ok, got %+v", postResp)
	}

	// Verify carrier changed
	cfg := loadCarrierConfig()
	if cfg.ActiveCarrier != "wss:8443" {
		t.Fatalf("expected active_carrier=wss:8443 after cycle, got %s", cfg.ActiveCarrier)
	}

	// POST set-ports
	portsBody, _ := json.Marshal(carrierPostRequest{Action: "set-ports", FouPorts: []int{8443, 60000}})
	req = httptest.NewRequest("POST", "/api/carrier", bytes.NewReader(portsBody))
	w = httptest.NewRecorder()
	handleCarrierPost(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 on set-ports, got %d", w.Code)
	}
	cfg = loadCarrierConfig()
	if cfg.FOUPort1 != 8443 || cfg.FOUPort2 != 60000 {
		t.Fatalf("expected ports 8443, 60000, got %d, %d", cfg.FOUPort1, cfg.FOUPort2)
	}
}
