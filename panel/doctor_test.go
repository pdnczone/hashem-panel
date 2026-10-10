package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDoctorEndpoints(t *testing.T) {
	prev := applyFixesFn
	applyFixesFn = func() map[string]any { return map[string]any{"applied": []string{}} }
	defer func() { applyFixesFn = prev }()
	// 1. GET /api/doctor
	req := httptest.NewRequest("GET", "/api/doctor", nil)
	rr := httptest.NewRecorder()
	handleDoctorGet(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/doctor returned status %d: %s", rr.Code, rr.Body.String())
	}

	var rep doctorReport
	if err := json.Unmarshal(rr.Body.Bytes(), &rep); err != nil {
		t.Fatalf("failed to parse doctor report JSON: %v", err)
	}

	if rep.Score < 0 || rep.Score > 100 {
		t.Errorf("expected score 0..100, got %d", rep.Score)
	}
	if rep.Rating == "" {
		t.Errorf("expected rating to be populated")
	}

	// 2. POST /api/doctor action=run
	bodyRun := doctorPostRequest{Action: "run"}
	data, _ := json.Marshal(bodyRun)
	reqRun := httptest.NewRequest("POST", "/api/doctor", bytes.NewReader(data))
	rrRun := httptest.NewRecorder()
	handleDoctorPost(rrRun, reqRun)

	if rrRun.Code != http.StatusOK {
		t.Fatalf("POST /api/doctor action=run returned %d", rrRun.Code)
	}

	// 3. POST /api/doctor action=fix
	bodyFix := doctorPostRequest{Action: "fix"}
	dataFix, _ := json.Marshal(bodyFix)
	reqFix := httptest.NewRequest("POST", "/api/doctor", bytes.NewReader(dataFix))
	rrFix := httptest.NewRecorder()
	handleDoctorPost(rrFix, reqFix)

	if rrFix.Code != http.StatusOK {
		t.Fatalf("POST /api/doctor action=fix returned %d", rrFix.Code)
	}
}

func TestScoreAndRating(t *testing.T) {
	rep := runFullDiagnostics()
	if rep.Timestamp == "" {
		t.Errorf("expected timestamp in doctor report")
	}
	if rep.KernelAudit.CongestionAlg == "" {
		t.Errorf("expected congestion algorithm to be detected")
	}
}
