package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// RFC 6238 Appendix B vectors (SHA-1, secret "12345678901234567890"), last 6 digits.
func TestTOTPRFC6238Vectors(t *testing.T) {
	secret := b32.EncodeToString([]byte("12345678901234567890"))
	vec := map[int64]string{59: "287082", 1111111109: "081804", 1111111111: "050471", 1234567890: "005924", 2000000000: "279037"}
	for ts, want := range vec {
		got, err := totpAt(secret, ts)
		if err != nil || got != want {
			t.Errorf("t=%d got %q err=%v want %q", ts, got, err, want)
		}
	}
}

func TestVerifyTOTPSkewAndReplay(t *testing.T) {
	totpLastStep = 0
	secret := newTOTPSecret()
	now := time.Unix(1_700_000_000, 0)
	code, _ := totpAt(secret, now.Unix())
	prev, _ := totpAt(secret, now.Unix()-30)
	far, _ := totpAt(secret, now.Unix()-120)
	if verifyTOTP(secret, far, now, false) {
		t.Error("code 4 steps old must be rejected")
	}
	if !verifyTOTP(secret, prev, now, false) {
		t.Error("previous step must be accepted (clock skew)")
	}
	if !verifyTOTP(secret, code, now, true) {
		t.Fatal("current code must verify")
	}
	if verifyTOTP(secret, code, now, true) {
		t.Error("same code must not verify twice (replay)")
	}
	if verifyTOTP(secret, "12345", now, false) || verifyTOTP(secret, "abcdef", now, false) {
		t.Error("malformed codes must fail")
	}
}

func TestRecoveryCodesSingleUse(t *testing.T) {
	old := cfg
	defer func() { cfg = old }()
	plain, hashed := newRecoveryCodes()
	if len(plain) != recoveryCount || len(hashed) != recoveryCount {
		t.Fatal("wrong count")
	}
	cfg.RecoveryHashes = hashed
	if !useRecoveryCode(strings.ToUpper(plain[0])) {
		t.Error("recovery code (case-insensitive) must work once")
	}
	if useRecoveryCode(plain[0]) {
		t.Error("recovery code must be single-use")
	}
	if len(cfg.RecoveryHashes) != recoveryCount-1 {
		t.Error("used code must be removed")
	}
	if strings.Contains(strings.Join(hashed, ""), strings.ReplaceAll(plain[1], "-", "")) {
		t.Error("plaintext must not be stored")
	}
}

func TestTOTPURI(t *testing.T) {
	u := totpURI("ABC234", "admin", "Hashem")
	for _, w := range []string{"otpauth://totp/Hashem:admin", "secret=ABC234", "issuer=Hashem", "period=30"} {
		if !strings.Contains(u, w) {
			t.Errorf("uri %q missing %q", u, w)
		}
	}
}

// ---- login flow ----

func twoFALab(t *testing.T) (secret string) {
	t.Helper()
	oldCfg, oldNow := cfg, timeNow
	t.Cleanup(func() { cfg, timeNow = oldCfg, oldNow })
	resetLockoutState()
	totpLastStep = 0
	secret = newTOTPSecret()
	cfg.Username = "admin"
	cfg.PassHash = hashPassword("Correct-Horse-Battery-9!")
	cfg.TOTPEnabled, cfg.TOTPSecret = true, secret
	_, cfg.RecoveryHashes = newRecoveryCodes()
	return
}

func loginReq(pass, code string) *httptest.ResponseRecorder {
	b, _ := json.Marshal(map[string]string{"username": "admin", "password": pass, "code": code})
	rr := httptest.NewRecorder()
	handleLogin(rr, httptest.NewRequest("POST", "/api/login", bytes.NewReader(b)))
	return rr
}

func TestLoginRequiresSecondFactorWhenEnabled(t *testing.T) {
	secret := twoFALab(t)
	timeNow = func() time.Time { return time.Unix(1_700_000_000, 0) }

	if rr := loginReq("Correct-Horse-Battery-9!", ""); rr.Code != 403 || !strings.Contains(rr.Body.String(), "E-AUTH-09") {
		t.Fatalf("missing code must ask for 2FA, got %d %s", rr.Code, rr.Body.String())
	}
	if rr := loginReq("Correct-Horse-Battery-9!", "000000"); rr.Code == 200 {
		t.Fatal("wrong code must not log in")
	}
	if rr := loginReq("wrong-password", "000000"); rr.Code == 200 {
		t.Fatal("wrong password must not log in")
	}
	code, _ := totpAt(secret, 1_700_000_000)
	if rr := loginReq("Correct-Horse-Battery-9!", code); rr.Code != 200 {
		t.Fatalf("valid password+code must log in, got %d %s", rr.Code, rr.Body.String())
	}
	if rr := loginReq("Correct-Horse-Battery-9!", code); rr.Code == 200 {
		t.Fatal("replayed code must not log in twice")
	}
}

func TestLoginWithRecoveryCode(t *testing.T) {
	twoFALab(t)
	plain, hashed := newRecoveryCodes()
	cfg.RecoveryHashes = hashed
	if rr := loginReq("Correct-Horse-Battery-9!", plain[0]); rr.Code != 200 {
		t.Fatalf("recovery code must log in, got %d %s", rr.Code, rr.Body.String())
	}
	if rr := loginReq("Correct-Horse-Battery-9!", plain[0]); rr.Code == 200 {
		t.Fatal("recovery code must be single-use")
	}
}

func TestLoginWithout2FAUnchanged(t *testing.T) {
	twoFALab(t)
	cfg.TOTPEnabled = false
	if rr := loginReq("Correct-Horse-Battery-9!", ""); rr.Code != 200 {
		t.Fatalf("2FA off must keep plain login, got %d %s", rr.Code, rr.Body.String())
	}
}

func TestWrongSecondFactorCountsTowardLockout(t *testing.T) {
	twoFALab(t)
	for i := 0; i < loginMaxFails; i++ {
		loginReq("Correct-Horse-Battery-9!", "111111")
	}
	if rr := loginReq("Correct-Horse-Battery-9!", "111111"); !strings.Contains(rr.Body.String(), "locked") {
		t.Fatalf("code brute force must lock out, got %s", rr.Body.String())
	}
}

func TestEnrolAndDisableFlow(t *testing.T) {
	oldCfg, oldNow := cfg, timeNow
	t.Cleanup(func() { cfg, timeNow = oldCfg, oldNow })
	resetLockoutState()
	totpLastStep = 0
	cfg.Username, cfg.PassHash = "admin", hashPassword("Correct-Horse-Battery-9!")
	cfg.TOTPEnabled, cfg.TOTPSecret, cfg.RecoveryHashes = false, "", nil
	timeNow = func() time.Time { return time.Unix(1_700_000_000, 0) }

	rr := httptest.NewRecorder()
	handle2FASetup(rr, httptest.NewRequest("POST", "/api/2fa/setup", nil))
	var setup struct{ Secret, URI string }
	_ = json.Unmarshal(rr.Body.Bytes(), &setup)
	if setup.Secret == "" || cfg.TOTPEnabled {
		t.Fatal("setup must return a secret and not enable yet")
	}
	post := func(h http.HandlerFunc, v any) *httptest.ResponseRecorder {
		b, _ := json.Marshal(v)
		rr := httptest.NewRecorder()
		h(rr, httptest.NewRequest("POST", "/x", bytes.NewReader(b)))
		return rr
	}
	if rr := post(handle2FAEnable, map[string]string{"code": "000000"}); rr.Code == 200 || cfg.TOTPEnabled {
		t.Fatal("wrong confirmation code must not enable 2FA")
	}
	code, _ := totpAt(setup.Secret, 1_700_000_000)
	rr = post(handle2FAEnable, map[string]string{"code": code})
	if rr.Code != 200 || !cfg.TOTPEnabled || len(cfg.RecoveryHashes) != recoveryCount {
		t.Fatalf("enable failed: %d %s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), setup.Secret) {
		t.Error("enable response must not echo the secret")
	}
	// disable needs password + a fresh valid factor
	if rr := post(handle2FADisable, map[string]string{"password": "nope", "code": code}); rr.Code == 200 || !cfg.TOTPEnabled {
		t.Fatal("wrong password must not disable")
	}
	timeNow = func() time.Time { return time.Unix(1_700_000_000+90, 0) }
	code2, _ := totpAt(setup.Secret, 1_700_000_090)
	if rr := post(handle2FADisable, map[string]string{"password": "Correct-Horse-Battery-9!", "code": code2}); rr.Code != 200 || cfg.TOTPEnabled || cfg.TOTPSecret != "" {
		t.Fatalf("disable failed: %d %s", rr.Code, rr.Body.String())
	}
}
