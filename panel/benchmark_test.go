package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestBenchmarkScoring(t *testing.T) {
	// Case 1: Perfect connection (0% loss, 15ms RTT, 1ms jitter)
	s1 := calculateScore(0, 15, 1)
	if s1 < 90 {
		t.Errorf("expected high score >= 90 for perfect connection, got %d", s1)
	}

	// Case 2: Moderate loss (10% loss, 60ms RTT, 5ms jitter)
	s2 := calculateScore(10, 60, 5)
	if s2 >= s1 {
		t.Errorf("expected score with loss (%d) to be lower than perfect (%d)", s2, s1)
	}

	// Case 3: Complete down (100% loss)
	s3 := calculateScore(100, 0, 0)
	if s3 != 0 {
		t.Errorf("expected score 0 for 100%% loss, got %d", s3)
	}

	// Status determination
	if determineStatus(95, 0) != "healthy" {
		t.Errorf("expected healthy status for 95 score")
	}
	if determineStatus(65, 0) != "good" {
		t.Errorf("expected good status for 65 score")
	}
	if determineStatus(45, 0) != "warning" {
		t.Errorf("expected warning status for 45 score")
	}
	if determineStatus(10, 0) != "critical" {
		t.Errorf("expected critical status for 10 score")
	}
	if determineStatus(0, 100) != "down" {
		t.Errorf("expected down status for 100%% loss")
	}
}

func TestBenchmarkExecutionAndEndpoints(t *testing.T) {
	withPro(t)
	tmpDir, err := os.MkdirTemp("", "hashem_bench_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	oldConfigDir := configDir
	configDir = tmpDir
	defer func() { configDir = oldConfigDir }()

	// 1. Run Carrier Benchmark directly
	rep := runCarrierBenchmark()
	if rep == nil {
		t.Fatalf("expected non-nil benchmark report")
	}
	if len(rep.Metrics) == 0 {
		t.Fatalf("expected carrier metrics in benchmark report")
	}
	if rep.BestCarrier == "" {
		t.Fatalf("expected a best carrier to be recommended")
	}

	// Verify metrics include direct, wss, and frp transports
	hasDirect, hasWSS, hasFRP := false, false, false
	for _, m := range rep.Metrics {
		if m.ID == "direct" {
			hasDirect = true
		}
		if m.Type == "wss" {
			hasWSS = true
		}
		if strings.HasPrefix(m.ID, "frp:") || m.Type == "frp_tcp" || m.Type == "frp_kcp" {
			hasFRP = true
		}
	}
	if !hasDirect || !hasWSS || !hasFRP {
		t.Errorf("missing standard candidate types: direct=%v, wss=%v, frp=%v", hasDirect, hasWSS, hasFRP)
	}

	// 2. GET /api/benchmark
	reqGet := httptest.NewRequest("GET", "/api/benchmark", nil)
	rrGet := httptest.NewRecorder()
	handleBenchmarkGet(rrGet, reqGet)
	if rrGet.Code != http.StatusOK {
		t.Fatalf("handleBenchmarkGet returned %d", rrGet.Code)
	}

	var loadedRep BenchmarkReport
	if err := json.Unmarshal(rrGet.Body.Bytes(), &loadedRep); err != nil {
		t.Fatalf("failed to parse benchmark JSON response: %v", err)
	}
	if len(loadedRep.Metrics) == 0 {
		t.Errorf("expected loaded metrics from GET /api/benchmark")
	}

	// 3. POST /api/benchmark/run
	reqRun := httptest.NewRequest("POST", "/api/benchmark/run", nil)
	rrRun := httptest.NewRecorder()
	handleBenchmarkRun(rrRun, reqRun)
	if rrRun.Code != http.StatusOK {
		t.Fatalf("handleBenchmarkRun returned %d", rrRun.Code)
	}

	// 4. POST /api/benchmark/autopilot
	enable := true
	thresh := 30.0
	reqAPBody, _ := json.Marshal(BenchmarkAutoPilotRequest{
		Enabled:   &enable,
		Threshold: &thresh,
	})
	reqAP := httptest.NewRequest("POST", "/api/benchmark/autopilot", bytes.NewReader(reqAPBody))
	rrAP := httptest.NewRecorder()
	handleBenchmarkAutoPilot(rrAP, reqAP)
	if rrAP.Code != http.StatusOK {
		t.Fatalf("handleBenchmarkAutoPilot returned %d", rrAP.Code)
	}

	pcfg := loadPeerConfig()
	if !pcfg.AutoPilotEnabled || pcfg.AutoPilotThreshold != 30.0 {
		t.Errorf("autopilot config not updated: %+v", pcfg)
	}

	// 5. POST /api/benchmark/apply
	reqApplyBody, _ := json.Marshal(BenchmarkApplyRequest{
		Carrier: "direct",
	})
	reqApply := httptest.NewRequest("POST", "/api/benchmark/apply", bytes.NewReader(reqApplyBody))
	rrApply := httptest.NewRecorder()
	handleBenchmarkApply(rrApply, reqApply)
	if rrApply.Code != http.StatusOK {
		t.Fatalf("handleBenchmarkApply returned %d: %s", rrApply.Code, rrApply.Body.String())
	}
}

func TestBenchmarkAllSevenProtocolsAndCustomTarget(t *testing.T) {
	withPro(t)
	tmpDir, err := os.MkdirTemp("", "hashem_bench_protos_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	oldConfigDir := configDir
	configDir = tmpDir
	defer func() { configDir = oldConfigDir }()

	// Test with custom TargetHost
	req := BenchmarkRunRequest{
		TargetHost:   "127.0.0.1",
		TargetRole:   "iran",
		FrpPort:      7000,
		WssPort:      8443,
		SshPort:      22,
		BackhaulPort: 3080,
	}

	rep := runCarrierBenchmark(req)
	if rep == nil {
		t.Fatalf("expected non-nil report")
	}

	typesFound := make(map[string]bool)
	for _, m := range rep.Metrics {
		typesFound[m.Type] = true
	}

	expected := []string{"gre", "frp_tcp", "frp_kcp", "frp_quic", "wss", "backhaul", "bagher"}
	for _, exp := range expected {
		if !typesFound[exp] {
			t.Errorf("missing active protocol %s in benchmark candidates (found: %+v)", exp, typesFound)
		}
	}

	// Verify handler accepts JSON body with TargetHost
	body, _ := json.Marshal(req)
	reqAPI := httptest.NewRequest("POST", "/api/benchmark/run", bytes.NewReader(body))
	rrAPI := httptest.NewRecorder()
	handleBenchmarkRun(rrAPI, reqAPI)
	if rrAPI.Code != http.StatusOK {
		t.Fatalf("handleBenchmarkRun with custom target failed: %d", rrAPI.Code)
	}
}

// A second run while one is in progress, before any report exists, answered
// nil and the page got "null".
func TestBenchmarkWhileRunningNeverNil(t *testing.T) {
	old := configDir
	configDir = t.TempDir()
	benchmarkMu.Lock()
	prev := lastBenchmarkReport
	lastBenchmarkReport = nil
	benchmarkMu.Unlock()
	benchmarkRunning.Store(true)
	t.Cleanup(func() {
		benchmarkRunning.Store(false)
		configDir = old
		benchmarkMu.Lock()
		lastBenchmarkReport = prev
		benchmarkMu.Unlock()
	})
	if rep := runCarrierBenchmark(); rep == nil || rep.Metrics == nil {
		t.Fatalf("want an empty report, got %#v", rep)
	}
}
