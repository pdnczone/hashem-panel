package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestSentinel_LifecycleAPI(t *testing.T) {
	// 1. Test GET /api/sentinel
	req := httptest.NewRequest("GET", "/api/sentinel", nil)
	rr := httptest.NewRecorder()

	handleSentinelGet(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from GET /api/sentinel, got %d", rr.Code)
	}

	var status SentinelConfig
	if err := json.Unmarshal(rr.Body.Bytes(), &status); err != nil {
		t.Fatalf("failed decoding json response: %v", err)
	}

	// 2. Test POST /api/sentinel install rejection when unlicensed
	activeLicenseMu.Lock()
	activeLicense = nil
	licenseCheckedAt = time.Now()
	activeLicenseMu.Unlock()

	bodyInstall := bytes.NewBufferString(`{"action":"install"}`)
	reqPost := httptest.NewRequest("POST", "/api/sentinel", bodyInstall)
	rrPost := httptest.NewRecorder()

	handleSentinelPost(rrPost, reqPost)
	if rrPost.Code == http.StatusOK {
		t.Errorf("expected POST /api/sentinel install to fail without license, got 200 OK")
	}

	// 3. Test POST /api/sentinel install rejection on foreign server
	activeLicenseMu.Lock()
	activeLicense = &LicensePayload{
		Customer:  "test-user",
		Features:  []string{"sentinel"},
		ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
	}
	licenseCheckedAt = time.Now()
	activeLicenseMu.Unlock()

	bodyInvalid := bytes.NewBufferString(`{"action":"invalid_action"}`)
	reqInvalid := httptest.NewRequest("POST", "/api/sentinel", bodyInvalid)
	rrInvalid := httptest.NewRecorder()

	handleSentinelPost(rrInvalid, reqInvalid)
	if rrInvalid.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request on invalid action, got %d", rrInvalid.Code)
	}

	// 4. Test POST /api/sentinel set_locality missing is_iran
	bodyLocMissing := bytes.NewBufferString(`{"action":"set_locality"}`)
	reqLocMissing := httptest.NewRequest("POST", "/api/sentinel", bodyLocMissing)
	rrLocMissing := httptest.NewRecorder()
	handleSentinelPost(rrLocMissing, reqLocMissing)
	if rrLocMissing.Code != http.StatusBadRequest {
		t.Errorf("expected 400 on set_locality without is_iran, got %d", rrLocMissing.Code)
	}

	// 5. Test POST /api/sentinel set_locality = false
	bodyLocForeign := bytes.NewBufferString(`{"action":"set_locality","is_iran":false}`)
	reqLocForeign := httptest.NewRequest("POST", "/api/sentinel", bodyLocForeign)
	rrLocForeign := httptest.NewRecorder()
	handleSentinelPost(rrLocForeign, reqLocForeign)
	if rrLocForeign.Code != http.StatusOK {
		t.Errorf("expected 200 on set_locality=false, got %d", rrLocForeign.Code)
	}

	stForeign := GetSentinelStatus()
	if stForeign.IsIran != false {
		t.Errorf("expected IsIran=false, got is_iran=%v", stForeign.IsIran)
	}

	// Eligibility succeeds with sentinel license regardless of server locality
	okElig, _ := CheckSentinelEligibility("iran (server)", "IR")
	if !okElig {
		t.Errorf("expected eligibility to succeed with sentinel feature")
	}

	// 6. Test POST /api/sentinel set_locality = true (Iran server)
	bodyLocIran := bytes.NewBufferString(`{"action":"set_locality","is_iran":true}`)
	reqLocIran := httptest.NewRequest("POST", "/api/sentinel", bodyLocIran)
	rrLocIran := httptest.NewRecorder()
	handleSentinelPost(rrLocIran, reqLocIran)
	if rrLocIran.Code != http.StatusOK {
		t.Errorf("expected 200 on set_locality=true, got %d", rrLocIran.Code)
	}

	stIran := GetSentinelStatus()
	if stIran.IsIran != true {
		t.Errorf("expected IsIran=true, got is_iran=%v", stIran.IsIran)
	}

	okEligIran, _ := CheckSentinelEligibility("unknown", "XX")
	if !okEligIran {
		t.Errorf("expected eligibility to succeed when user confirmed Iran server")
	}

	// Clean up config file so other tests start clean
	_ = os.Remove(sentinelConfigPath())
}
