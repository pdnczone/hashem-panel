package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPerfDefaultsAndLoadSave(t *testing.T) {
	tmpDir := t.TempDir()
	oldConfigDir := configDir
	configDir = tmpDir
	defer func() { configDir = oldConfigDir }()

	// 1. Missing file: default values must match requirements
	def := loadPerfConfig()
	if def.ProxyEncryption || def.ProxyCompression {
		t.Fatalf("expected enc/comp off by default, got %+v", def)
	}
	if !def.AutoPool {
		t.Fatalf("expected auto_pool=true by default")
	}

	// 2. Save custom config and verify file mode + values
	custom := perfConfig{
		ProxyEncryption:  true,
		ProxyCompression: true,
		AutoPool:         false,
		FRPPoolCount:     40,
		FRPMaxPool:       80,
	}
	if err := savePerfConfig(custom); err != nil {
		t.Fatalf("savePerfConfig failed: %v", err)
	}
	info, err := os.Stat(perfConfigPath())
	if err != nil {
		t.Fatalf("stat on perf.json failed: %v", err)
	}
	if runtime.GOOS != "windows" {
		if perm := info.Mode().Perm(); perm != 0600 {
			t.Fatalf("expected perf.json perm 0600, got %o", perm)
		}
	}
	if loaded := loadPerfConfig(); loaded != custom {
		t.Fatalf("expected %+v, got %+v", custom, loaded)
	}

	// 3. Partial config: missing fields keep defaults, a missing auto_pool key means ON
	if err := os.WriteFile(perfConfigPath(), []byte(`{"proxy_encryption": true}`), 0600); err != nil {
		t.Fatal(err)
	}
	partial := loadPerfConfig()
	if !partial.ProxyEncryption {
		t.Fatalf("expected proxy_encryption=true")
	}
	if !partial.AutoPool {
		t.Fatalf("missing auto_pool key must default to true")
	}
	if partial.FRPPoolCount != 20 {
		t.Fatalf("expected default poolCount 20, got %d", partial.FRPPoolCount)
	}

	// explicit false stays false
	if err := os.WriteFile(perfConfigPath(), []byte(`{"auto_pool": false}`), 0600); err != nil {
		t.Fatal(err)
	}
	if loadPerfConfig().AutoPool {
		t.Fatalf("explicit auto_pool=false must be honoured")
	}
}

func TestPerfLegacyKeysIgnoredAndDropped(t *testing.T) {
	tmpDir := t.TempDir()
	oldConfigDir := configDir
	configDir = tmpDir
	defer func() { configDir = oldConfigDir }()

	legacy := `{"proxy_encryption": true, "force_tls": true, "chaff_profile": "mid", "dpi_enabled": true,
		"dpi_rate": "5/sec", "dpi_burst": 9, "auto_tune": true, "tuning_profile": "x", "tcp_mux": true,
		"frp_pool_count": 33, "frp_max_pool": 99}`
	if err := os.WriteFile(perfConfigPath(), []byte(legacy), 0600); err != nil {
		t.Fatal(err)
	}
	c := loadPerfConfig()
	if !c.ProxyEncryption || c.FRPPoolCount != 33 || c.FRPMaxPool != 99 || c.TCPMux == nil || !*c.TCPMux {
		t.Fatalf("known keys lost while ignoring legacy ones: %+v", c)
	}
	if !c.AutoPool {
		t.Fatalf("auto_pool must default to true for old files")
	}
	if err := savePerfConfig(c); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(perfConfigPath())
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"force_tls", "chaff_profile", "dpi_enabled", "dpi_rate", "dpi_burst", "auto_tune", "tuning_profile"} {
		if _, ok := m[k]; ok {
			t.Fatalf("legacy key %q survived a save", k)
		}
	}
	if m["auto_pool"] != true {
		t.Fatalf("auto_pool should be written as true, got %v", m["auto_pool"])
	}
}

func TestEffectivePoolValues(t *testing.T) {
	tmpDir := t.TempDir()
	oldConfigDir := configDir
	configDir = tmpDir
	defer func() { configDir = oldConfigDir }()
	t.Setenv("HASHEM_SCRIPT", filepath.Join(tmpDir, "missing.sh")) // force the file-based fallback

	// auto, no state yet
	pool, maxPool := effectivePoolValues()
	if pool != 20 || maxPool < 30 {
		t.Fatalf("auto defaults: pool=%d max=%d", pool, maxPool)
	}

	// auto follows the state file; maxPool is lifted to 1.5x pool
	if err := os.WriteFile(autoPoolStatePath(), []byte(`{"pool": 100, "max_pool": 120}`), 0600); err != nil {
		t.Fatal(err)
	}
	pool, maxPool = effectivePoolValues()
	if pool != 100 || maxPool != 150 {
		t.Fatalf("auto from state: pool=%d max=%d", pool, maxPool)
	}

	// manual ignores the state file
	if err := savePerfConfig(perfConfig{AutoPool: false, FRPPoolCount: 50, FRPMaxPool: 400}); err != nil {
		t.Fatal(err)
	}
	pool, maxPool = effectivePoolValues()
	if pool != 50 || maxPool != 400 {
		t.Fatalf("manual: pool=%d max=%d", pool, maxPool)
	}
}

func TestRescueTomlUsesEffectivePool(t *testing.T) {
	tmpDir := t.TempDir()
	oldConfigDir := configDir
	configDir = tmpDir
	defer func() { configDir = oldConfigDir }()
	t.Setenv("HASHEM_SCRIPT", filepath.Join(tmpDir, "missing.sh"))
	if err := savePerfConfig(perfConfig{AutoPool: false, FRPPoolCount: 64, FRPMaxPool: 200}); err != nil {
		t.Fatal(err)
	}
	if got := rescueOriginFrpcToml(7000, "tok", "sec", nil); !strings.Contains(got, "transport.poolCount = 64\n") {
		t.Fatalf("origin frpc ignored effective pool:\n%s", got)
	}
	if got := rescueFrpsToml(7000, "tok"); !strings.Contains(got, "transport.maxPoolCount = 200\n") {
		t.Fatalf("rescue frps ignored effective maxPool:\n%s", got)
	}
}

func TestPerfEnvOverrides(t *testing.T) {
	tmpDir := t.TempDir()
	oldConfigDir := configDir
	configDir = tmpDir
	defer func() { configDir = oldConfigDir }()

	if err := savePerfConfig(defaultPerfConfig()); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PERF_ENC", "1")
	t.Setenv("PERF_COMP", "1")

	eff, over := effectivePerfConfig()
	if !eff.ProxyEncryption || !over["proxy_encryption"] {
		t.Fatalf("PERF_ENC override failed")
	}
	if !eff.ProxyCompression || !over["proxy_compression"] {
		t.Fatalf("PERF_COMP override failed")
	}
}

func TestPerfAPIEndpoints(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "perf-api-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	oldConfigDir := configDir
	configDir = tmpDir
	defer func() { configDir = oldConfigDir }()

	// 1. GET /api/perf
	req := httptest.NewRequest("GET", "/api/perf", nil)
	rr := httptest.NewRecorder()
	handlePerfGet(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/perf returned %d: %s", rr.Code, rr.Body.String())
	}
	var resp perfStatusResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if !resp.AutoPool || resp.EffectivePool < 20 || resp.EffectiveMaxPool < resp.EffectivePool {
		t.Fatalf("unexpected defaults in GET response: %+v", resp)
	}

	// 2. POST /api/perf action=update
	tTrue := true
	tFalse := false
	updateBody := perfPostRequest{
		Action:           "update",
		ProxyEncryption:  &tTrue,
		ProxyCompression: &tFalse,
		AutoPool:         &tFalse,
	}
	bData, _ := json.Marshal(updateBody)
	req = httptest.NewRequest("POST", "/api/perf", bytes.NewReader(bData))
	rr = httptest.NewRecorder()
	handlePerfPost(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("POST update returned %d: %s", rr.Code, rr.Body.String())
	}

	updated := loadPerfConfig()
	if !updated.ProxyEncryption || updated.ProxyCompression || updated.AutoPool {
		t.Fatalf("update was not saved properly: %+v", updated)
	}

	// 3. POST /api/perf invalid action
	req = httptest.NewRequest("POST", "/api/perf", bytes.NewReader([]byte(`{"action":"invalid-action"}`)))
	rr = httptest.NewRecorder()
	handlePerfPost(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid action, got %d", rr.Code)
	}
}
