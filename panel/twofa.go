package main

import (
	"encoding/json"
	"net/http"
	"sync"
)

// Handlers for optional TOTP 2FA. Enrolment is two-step so a typo can never
// lock the admin out: setup returns a secret (kept in memory only), and the
// secret is persisted only after a valid code proves the app is configured.

var (
	pendingMu     sync.Mutex
	pendingSecret string
)

// GET /api/2fa — status only; never returns the secret.
func handle2FAStatus(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	on, left := cfg.TOTPEnabled, len(cfg.RecoveryHashes)
	mu.Unlock()
	writeJSON(w, map[string]any{"enabled": on, "recovery_left": left})
}

// POST /api/2fa/setup — start enrolment; returns secret + otpauth URI.
func handle2FASetup(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	on := cfg.TOTPEnabled
	user := cfg.Username
	mu.Unlock()
	if on {
		writeAPIError(w, r, "E-AUTH-10", "2FA is already enabled; disable it first to re-enrol")
		return
	}
	s := newTOTPSecret()
	pendingMu.Lock()
	pendingSecret = s
	pendingMu.Unlock()
	writeJSON(w, map[string]any{"secret": s, "uri": totpURI(s, user, "Hashem")})
}

// POST /api/2fa/enable {code} — confirm enrolment; returns recovery codes once.
func handle2FAEnable(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeAPIError(w, r, "E-AUTH-03", "")
		return
	}
	pendingMu.Lock()
	s := pendingSecret
	pendingMu.Unlock()
	if s == "" {
		writeAPIError(w, r, "E-AUTH-10", "start setup first")
		return
	}
	if !verifyTOTP(s, body.Code, timeNow(), true) {
		LogSecurityAudit("2fa_enable_rejected", cfg.Username, clientIP(r), "bad confirmation code")
		writeAPIError(w, r, "E-AUTH-11", "")
		return
	}
	plain, hashed := newRecoveryCodes()
	mu.Lock()
	cfg.TOTPSecret, cfg.TOTPEnabled, cfg.RecoveryHashes = s, true, hashed
	saveCfg()
	mu.Unlock()
	pendingMu.Lock()
	pendingSecret = ""
	pendingMu.Unlock()
	LogSecurityAudit("2fa_enabled", cfg.Username, clientIP(r), "totp enabled")
	writeJSON(w, map[string]any{"status": "ok", "recovery_codes": plain})
}

// POST /api/2fa/disable {password, code} — needs the password AND a valid second factor.
func handle2FADisable(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeAPIError(w, r, "E-AUTH-03", "")
		return
	}
	ip := clientIP(r)
	if checkLocked(ip) {
		writeAPIError(w, r, "E-AUTH-02", "Too many failed attempts. Temporarily locked.")
		return
	}
	if ok, _ := verifyPassword(cfg.PassHash, body.Password); !ok || !checkSecondFactor(body.Code) {
		recordLoginFailure(ip)
		LogSecurityAudit("2fa_disable_rejected", cfg.Username, ip, "bad password or code")
		writeAPIError(w, r, "E-AUTH-07", "password or code incorrect")
		return
	}
	mu.Lock()
	cfg.TOTPEnabled, cfg.TOTPSecret, cfg.RecoveryHashes = false, "", nil
	saveCfg()
	mu.Unlock()
	LogSecurityAudit("2fa_disabled", cfg.Username, ip, "totp disabled")
	writeJSON(w, map[string]string{"status": "ok"})
}
