package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSentinelEligibility_LicenseGating(t *testing.T) {
	_ = os.Remove(sentinelConfigPath())
	t.Cleanup(func() { _ = os.Remove(sentinelConfigPath()) })

	// 1. Without sentinel feature
	activeLicenseMu.Lock()
	activeLicense = &LicensePayload{
		Customer:  "test-basic",
		Features:  []string{"base_tunnel"},
		ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
	}
	licenseCheckedAt = time.Now()
	activeLicenseMu.Unlock()

	ok, reason := CheckSentinelEligibility("iran (server)", "IR")
	if ok {
		t.Errorf("expected eligibility failure without 'sentinel' feature, got ok=true")
	}
	if !strings.Contains(reason, "license") && !strings.Contains(reason, "License") {
		t.Errorf("expected license-related failure reason, got: %s", reason)
	}

	// 2. With sentinel feature
	activeLicenseMu.Lock()
	activeLicense = &LicensePayload{
		Customer:  "test-pro",
		Features:  []string{"sentinel"},
		ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
	}
	licenseCheckedAt = time.Now()
	activeLicenseMu.Unlock()

	okSentinel, _ := CheckSentinelEligibility("foreign (client)", "DE")
	if !okSentinel {
		t.Errorf("expected eligibility with sentinel feature to succeed regardless of region")
	}

	// 3. With sentinel feature on Iran role
	okIran, _ := CheckSentinelEligibility("iran (server)", "XX")
	if !okIran {
		t.Errorf("expected Iran role to be eligible")
	}

	// 4. With sentinel feature on verified Iran server (country = IR)
	okCountry, _ := CheckSentinelEligibility("standalone", "IR")
	if !okCountry {
		t.Errorf("expected Iran country code to be eligible")
	}

	// 5. With wildcard license
	activeLicenseMu.Lock()
	activeLicense = &LicensePayload{
		Customer:  "test-enterprise",
		Features:  []string{"*"},
		ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
	}
	licenseCheckedAt = time.Now()
	activeLicenseMu.Unlock()

	okWildcard, _ := CheckSentinelEligibility("iran (backhaul)", "IR")
	if !okWildcard {
		t.Errorf("expected wildcard license to be eligible")
	}
}

// The panel passes --port to the bundled installer; the installer and app.py
// must actually honor it, otherwise the reported port is wrong.
func TestSentinel_BundleHonorsPort(t *testing.T) {
	dir := t.TempDir()
	if err := extractEmbeddedSentinel(dir); err != nil {
		t.Fatalf("extract bundle: %v", err)
	}
	inst, err := os.ReadFile(filepath.Join(dir, "install.sh"))
	if err != nil {
		t.Fatalf("install.sh missing from bundle: %v", err)
	}
	if !strings.Contains(string(inst), "--port)") || !strings.Contains(string(inst), "SENTINEL_PORT") {
		t.Errorf("install.sh does not handle --port / SENTINEL_PORT")
	}
	app, err := os.ReadFile(filepath.Join(dir, "app.py"))
	if err != nil {
		t.Fatalf("app.py missing from bundle: %v", err)
	}
	if !strings.Contains(string(app), `os.getenv("SENTINEL_PORT"`) {
		t.Errorf("app.py does not read SENTINEL_PORT")
	}
	if strings.Contains(string(inst), "\r") || strings.Contains(string(app), "\r") {
		t.Errorf("bundle scripts must use LF line endings")
	}
}

func TestSentinel_ConcurrentInstallRejected(t *testing.T) {
	activeLicenseMu.Lock()
	activeLicense = &LicensePayload{Customer: "t", Features: []string{"sentinel"}, ExpiresAt: time.Now().Add(time.Hour).Unix()}
	licenseCheckedAt = time.Now()
	activeLicenseMu.Unlock()

	sentinelInstallMu.Lock()
	defer sentinelInstallMu.Unlock()

	rr := httptest.NewRecorder()
	handleSentinelPost(rr, httptest.NewRequest("POST", "/api/sentinel", strings.NewReader(`{"action":"install"}`)))
	if rr.Code != http.StatusConflict {
		t.Fatalf("expected 409 while an install is running, got %d", rr.Code)
	}

	// Status must not block behind the install lock.
	done := make(chan struct{})
	go func() { GetSentinelStatus(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("GetSentinelStatus blocked while install lock was held")
	}
}

func TestSentinel_UnlicensedInstallIs403(t *testing.T) {
	activeLicenseMu.Lock()
	activeLicense = nil
	licenseCheckedAt = time.Now()
	activeLicenseMu.Unlock()

	rr := httptest.NewRecorder()
	handleSentinelPost(rr, httptest.NewRequest("POST", "/api/sentinel", strings.NewReader(`{"action":"install"}`)))
	if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "E-SENTINEL-01") {
		t.Fatalf("expected 403 E-SENTINEL-01, got %d %s", rr.Code, rr.Body.String())
	}
}

func TestSentinel_RandomPortAllocation(t *testing.T) {
	port, err := PickRandomSentinelPort(30000, 39999)
	if err != nil {
		t.Fatalf("failed picking random port: %v", err)
	}
	if port < 30000 || port > 39999 {
		t.Errorf("port %d outside expected range [30000, 39999]", port)
	}
}
