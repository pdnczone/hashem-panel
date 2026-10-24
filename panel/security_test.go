package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPasswordStrengthValidation(t *testing.T) {
	cases := []struct {
		name    string
		pw      string
		wantErr bool
	}{
		{"empty", "", true},
		{"short", "Ab1!abcd", true},           // 8 chars
		{"eleven chars", "Abcdef123!@", true}, // 11 chars
		{"no uppercase", "abcdefgh12345!@#", true},
		{"no lowercase", "ABCDEFGH12345!@#", true},
		{"no digit", "Abcdefghijklm!@#", true},
		{"no symbol", "Abcdefgh12345678", true},
		{"common weak password", "password12345", true},
		{"common admin", "admin12345678", true},
		{"valid strong NIST password", "P@ssw0rdSecure!2026", false},
		{"valid generated style", "Xk9#mP2$vL5*qR8!", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePasswordStrength(tc.pw)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error for %q, got nil", tc.pw)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.pw, err)
			}
		})
	}
}

func TestSecureRandomPassword(t *testing.T) {
	for i := 0; i < 20; i++ {
		pw := SecureRandomPassword(16)
		if len(pw) < 16 {
			t.Fatalf("generated password too short: %s", pw)
		}
		if err := ValidatePasswordStrength(pw); err != nil {
			t.Fatalf("generated password failed strength test: %s, err: %v", pw, err)
		}
	}
}

func TestTrustedProxyAndClientIP(t *testing.T) {
	orig := os.Getenv("TRUSTED_PROXY_IPS")
	defer os.Setenv("TRUSTED_PROXY_IPS", orig)

	// Case 1: No trusted proxies configured -> Spoofed XFF ignored
	os.Unsetenv("TRUSTED_PROXY_IPS")
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "203.0.113.50:54321"
	req.Header.Set("X-Forwarded-For", "198.51.100.1")
	if ip := ClientIP(req); ip != "203.0.113.50" {
		t.Fatalf("expected direct IP 203.0.113.50, got %s (spoofing not blocked!)", ip)
	}

	// Case 2: Trusted proxies configured (127.0.0.1 and 10.0.0.0/8)
	os.Setenv("TRUSTED_PROXY_IPS", "127.0.0.1, 10.0.0.0/8")

	// Direct request from untrusted external IP with spoofed XFF
	reqUntrusted := httptest.NewRequest("GET", "/test", nil)
	reqUntrusted.RemoteAddr = "192.0.2.1:12345"
	reqUntrusted.Header.Set("X-Forwarded-For", "198.51.100.1")
	if ip := ClientIP(reqUntrusted); ip != "192.0.2.1" {
		t.Fatalf("expected untrusted host 192.0.2.1, got %s", ip)
	}

	// Request from trusted proxy 127.0.0.1 with XFF
	reqTrusted := httptest.NewRequest("GET", "/test", nil)
	reqTrusted.RemoteAddr = "127.0.0.1:40000"
	reqTrusted.Header.Set("X-Forwarded-For", "198.51.100.1, 127.0.0.1")
	if ip := ClientIP(reqTrusted); ip != "198.51.100.1" {
		t.Fatalf("expected forwarded client IP 198.51.100.1, got %s", ip)
	}

	// Request from trusted CIDR proxy 10.2.3.4 with X-Real-IP
	reqCIDR := httptest.NewRequest("GET", "/test", nil)
	reqCIDR.RemoteAddr = "10.2.3.4:50000"
	reqCIDR.Header.Set("X-Real-IP", "198.51.100.2")
	if ip := ClientIP(reqCIDR); ip != "198.51.100.2" {
		t.Fatalf("expected forwarded real IP 198.51.100.2, got %s", ip)
	}
}

func TestCSRFTokenGenerationAndValidation(t *testing.T) {
	sessionTok := "test-session-token-123456789"
	csrf := GenerateCSRFToken(sessionTok)
	if csrf == "" {
		t.Fatal("empty CSRF token generated")
	}

	if !ValidateCSRFToken(sessionTok, csrf) {
		t.Fatal("expected valid CSRF token to pass validation")
	}

	if ValidateCSRFToken(sessionTok, "forged-csrf-token") {
		t.Fatal("forged CSRF token should have failed validation")
	}

	if ValidateCSRFToken("another-session", csrf) {
		t.Fatal("CSRF token should not match a different session")
	}

	if ValidateCSRFToken("", csrf) || ValidateCSRFToken(sessionTok, "") {
		t.Fatal("empty session or candidate should fail validation")
	}
}

func TestCSRFMiddleware(t *testing.T) {
	handlerCalled := false
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	wrapped := requireCSRF(testHandler)

	// 1. GET requests should pass through without CSRF token
	handlerCalled = false
	getReq := httptest.NewRequest("GET", "/api/peers", nil)
	rec := httptest.NewRecorder()
	wrapped(rec, getReq)
	if !handlerCalled || rec.Code != http.StatusOK {
		t.Fatalf("GET request failed CSRF check: called=%v, code=%d", handlerCalled, rec.Code)
	}

	// 2. State-changing request without session cookie -> 401
	handlerCalled = false
	postReqNoCookie := httptest.NewRequest("POST", "/api/peers", strings.NewReader(`{}`))
	rec = httptest.NewRecorder()
	wrapped(rec, postReqNoCookie)
	if handlerCalled || rec.Code != http.StatusUnauthorized {
		t.Fatalf("POST without cookie should fail 401, got code=%d", rec.Code)
	}

	// 3. State-changing request with session cookie but missing X-CSRF-Token -> 403 (E-AUTH-08)
	sessionTok := "mock-session-token"
	handlerCalled = false
	postReqNoCSRF := httptest.NewRequest("POST", "/api/peers", strings.NewReader(`{}`))
	postReqNoCSRF.AddCookie(&http.Cookie{Name: "gre_session", Value: sessionTok})
	rec = httptest.NewRecorder()
	wrapped(rec, postReqNoCSRF)
	if handlerCalled || rec.Code != http.StatusForbidden {
		t.Fatalf("POST without CSRF token should return 403, got code=%d", rec.Code)
	}

	// 4. State-changing request with invalid X-CSRF-Token -> 403
	handlerCalled = false
	postReqBadCSRF := httptest.NewRequest("POST", "/api/peers", strings.NewReader(`{}`))
	postReqBadCSRF.AddCookie(&http.Cookie{Name: "gre_session", Value: sessionTok})
	postReqBadCSRF.Header.Set("X-CSRF-Token", "invalid-token")
	rec = httptest.NewRecorder()
	wrapped(rec, postReqBadCSRF)
	if handlerCalled || rec.Code != http.StatusForbidden {
		t.Fatalf("POST with bad CSRF token should return 403, got code=%d", rec.Code)
	}

	// 5. State-changing request with valid X-CSRF-Token -> 200 OK
	validCSRF := GenerateCSRFToken(sessionTok)
	handlerCalled = false
	postReqValid := httptest.NewRequest("POST", "/api/peers", strings.NewReader(`{}`))
	postReqValid.AddCookie(&http.Cookie{Name: "gre_session", Value: sessionTok})
	postReqValid.Header.Set("X-CSRF-Token", validCSRF)
	rec = httptest.NewRecorder()
	wrapped(rec, postReqValid)
	if !handlerCalled || rec.Code != http.StatusOK {
		t.Fatalf("POST with valid CSRF token should succeed, got called=%v code=%d", handlerCalled, rec.Code)
	}

	// 6. Login endpoint should be exempt from CSRF
	handlerCalled = false
	loginReq := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{}`))
	rec = httptest.NewRecorder()
	wrapped(rec, loginReq)
	if !handlerCalled || rec.Code != http.StatusOK {
		t.Fatalf("/api/login should be exempt from CSRF check, got called=%v code=%d", handlerCalled, rec.Code)
	}
}

func TestHandlePasswordSecurity(t *testing.T) {
	tmpDir := t.TempDir()
	origConfigDir := configDir
	configDir = tmpDir
	defer func() { configDir = origConfigDir }()

	// Setup initial config
	currentPass := "CurrentSec!2026P@ss"
	h := sha256.Sum256([]byte(currentPass))
	cfg = panelConfig{
		Username: "admin",
		PassHash: hex.EncodeToString(h[:]),
		Port:     7777,
		BasePath: "testpanel",
	}
	saveCfg()

	// 1. Wrong current password -> Reject with E-AUTH-07
	badCurrentReq := map[string]string{
		"current_password": "WrongPassword123!",
		"new_password":     "NewSec!2026Password",
	}
	body, _ := json.Marshal(badCurrentReq)
	req := httptest.NewRequest("POST", "/api/password", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	handlePassword(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for wrong current password, got %d (body: %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "E-AUTH-07") {
		t.Fatalf("expected E-AUTH-07 error code, got %s", rec.Body.String())
	}

	// 2. Correct current password, but weak new password -> Reject with E-AUTH-04
	weakNewReq := map[string]string{
		"current_password": currentPass,
		"new_password":     "short1!",
	}
	body, _ = json.Marshal(weakNewReq)
	req = httptest.NewRequest("POST", "/api/password", bytes.NewReader(body))
	rec = httptest.NewRecorder()
	handlePassword(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for weak new password, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "E-AUTH-04") {
		t.Fatalf("expected E-AUTH-04 error code, got %s", rec.Body.String())
	}

	// 3. Correct current password and strong new password -> Success
	newStrongPass := "StrongNew!Password2026#"
	validReq := map[string]string{
		"current_password": currentPass,
		"new_password":     newStrongPass,
	}
	body, _ = json.Marshal(validReq)
	req = httptest.NewRequest("POST", "/api/password", bytes.NewReader(body))
	rec = httptest.NewRecorder()
	handlePassword(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for valid password change, got %d (body: %s)", rec.Code, rec.Body.String())
	}

	// Verify plaintext file panel.pass was NOT created
	passFile := filepath.Join(tmpDir, "panel.pass")
	if _, err := os.Stat(passFile); !os.IsNotExist(err) {
		t.Fatalf("CRITICAL SECURITY FLAW (CWE-256): panel.pass plaintext file was created on disk!")
	}

	// Verify password hash was updated
	if ok, _ := verifyPassword(cfg.PassHash, newStrongPass); !ok || isLegacyHash(cfg.PassHash) {
		t.Fatalf("expected pass hash to be updated")
	}
}

func TestChecksumVerification(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "checksum-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	content := "secure-binary-content-for-testing"
	_, _ = tmpFile.WriteString(content)
	_ = tmpFile.Close()

	expectedHashBytes := sha256.Sum256([]byte(content))
	expectedHashHex := hex.EncodeToString(expectedHashBytes[:])

	// Correct hash should succeed
	if err := VerifyFileSHA256(tmpFile.Name(), expectedHashHex); err != nil {
		t.Fatalf("expected checksum verification to pass, got: %v", err)
	}

	// Corrupted/tampered hash should fail
	if err := VerifyFileSHA256(tmpFile.Name(), "0000000000000000000000000000000000000000000000000000000000000000"); err == nil {
		t.Fatal("expected checksum verification to fail for bad hash, got nil")
	}

	// Test ParseChecksumManifest
	manifestText := `
# Checksum file
` + expectedHashHex + `  test-binary.tar.gz
` + expectedHashHex + ` *another-binary.exe
`
	manifest := ParseChecksumManifest(manifestText)
	if manifest["test-binary.tar.gz"] != expectedHashHex {
		t.Fatalf("manifest parse failed for test-binary.tar.gz: got %s", manifest["test-binary.tar.gz"])
	}
	if manifest["another-binary.exe"] != expectedHashHex {
		t.Fatalf("manifest parse failed for another-binary.exe: got %s", manifest["another-binary.exe"])
	}
}
