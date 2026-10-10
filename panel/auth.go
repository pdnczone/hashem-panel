package main

// Auth: cookie session + login/logout/password.
// Session token = sha256(nonce + pass_hash); nonce is generated at startup
// (see main.go). Changing the password invalidates all sessions.

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	mu    sync.Mutex
	nonce [32]byte
)

const (
	loginFailWindow = 15 * time.Minute
	loginLockoutDur = 15 * time.Minute
	loginMaxFails   = 5
	// repeat offenders: every further lockout doubles, up to maxLockoutDur;
	// strikes are forgotten after strikeDecay without a new lockout.
	maxLockoutDur = 24 * time.Hour
	strikeDecay   = 24 * time.Hour
)

type lockStrike struct {
	n    int
	last time.Time
}

type ipAttempts struct {
	fails       []time.Time
	lockedUntil time.Time
}

var (
	attemptMu   sync.Mutex
	attempts    = map[string]*ipAttempts{}
	lockStrikes = map[string]*lockStrike{}
)

// lockoutFor returns the lockout length for the n-th consecutive lockout.
func lockoutFor(n int) time.Duration {
	if n < 1 {
		return loginLockoutDur
	}
	d := loginLockoutDur
	for i := 1; i < n; i++ {
		d *= 2
		if d >= maxLockoutDur {
			return maxLockoutDur
		}
	}
	return d
}

// lockRemaining reports how long ip stays locked (0 when not locked).
func lockRemaining(ip string) time.Duration {
	attemptMu.Lock()
	defer attemptMu.Unlock()
	if a, ok := attempts[ip]; ok {
		if d := time.Until(a.lockedUntil); d > 0 {
			return d
		}
	}
	return 0
}

func clientIP(r *http.Request) string {
	return ClientIP(r)
}

func pruneAttemptsLocked(now time.Time) {
	for ip, st := range lockStrikes { // bound memory: forget decayed strikes
		if now.Sub(st.last) > strikeDecay {
			delete(lockStrikes, ip)
		}
	}
	cutoff := now.Add(-loginFailWindow)
	for ip, a := range attempts {
		if now.Before(a.lockedUntil) {
			continue
		}
		n := 0
		for _, t := range a.fails {
			if t.After(cutoff) {
				a.fails[n] = t
				n++
			}
		}
		a.fails = a.fails[:n]
		if len(a.fails) == 0 {
			delete(attempts, ip)
		}
	}
}

func checkLocked(ip string) bool {
	attemptMu.Lock()
	defer attemptMu.Unlock()
	now := time.Now()
	pruneAttemptsLocked(now)
	a, ok := attempts[ip]
	if !ok {
		return false
	}
	return now.Before(a.lockedUntil)
}

func recordLoginFailure(ip string) {
	attemptMu.Lock()
	now := time.Now()
	pruneAttemptsLocked(now)
	a, ok := attempts[ip]
	if !ok {
		a = &ipAttempts{}
		attempts[ip] = a
	}
	a.fails = append(a.fails, now)
	shouldLog := false
	if len(a.fails) >= loginMaxFails && (a.lockedUntil.IsZero() || !now.Before(a.lockedUntil)) {
		st := lockStrikes[ip]
		if st == nil || now.Sub(st.last) > strikeDecay {
			st = &lockStrike{}
			lockStrikes[ip] = st
		}
		st.n++
		st.last = now
		a.lockedUntil = now.Add(lockoutFor(st.n))
		shouldLog = true
	}
	attemptMu.Unlock()

	if shouldLog {
		recordError("E-AUTH-02", "login", "brute-force lockout for IP "+ip+" (5 failures, strike escalates)")
		LogSecurityAudit("lockout_triggered", "unknown", ip, "5 failed attempts within window")
	}
}

func recordLoginSuccess(ip string) {
	attemptMu.Lock()
	delete(attempts, ip)
	delete(lockStrikes, ip)
	attemptMu.Unlock()
}

func isRequestHTTPS(r *http.Request) bool {
	if r == nil {
		return false
	}
	if r.TLS != nil {
		return true
	}
	remoteHost, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		remoteHost = strings.Trim(r.RemoteAddr, "[]")
	}
	if IsTrustedProxy(remoteHost) {
		proto := r.Header.Get("X-Forwarded-Proto")
		if strings.EqualFold(proto, "https") {
			return true
		}
	}
	return false
}

func sessionCookie(r *http.Request, value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     "gre_session",
		Value:    value,
		Path:     "/" + cfg.BasePath + "/",
		HttpOnly: true,
		Secure:   isRequestHTTPS(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	}
}

func csrfCookie(r *http.Request, value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     "gre_csrf",
		Value:    value,
		Path:     "/" + cfg.BasePath + "/",
		HttpOnly: false, // Accessible to frontend scripts to include in X-CSRF-Token header
		Secure:   isRequestHTTPS(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	}
}

func authed(r *http.Request) bool {
	c, err := r.Cookie("gre_session")
	if err != nil || c.Value == "" {
		return false
	}
	// server-side random session ids (survive restarts, 24h absolute expiry)
	return validSession(c.Value)
}

func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("gre_session")
		if err != nil || c.Value == "" {
			writeAPIError(w, r, "E-AUTH-01", "")
			return
		}
		if !authed(r) {
			writeAPIError(w, r, "E-AUTH-06", "")
			return
		}
		next(w, r)
	}
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if checkLocked(ip) {
		w.Header().Set("Retry-After", strconv.Itoa(int(lockRemaining(ip).Seconds())+1))
		writeAPIError(w, r, "E-AUTH-02", "Too many failed attempts. Temporarily locked.")
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeAPIError(w, r, "E-AUTH-03", "")
		return
	}
	passOK, upgrade := verifyPassword(cfg.PassHash, body.Password)
	if subtle.ConstantTimeCompare([]byte(body.Username), []byte(cfg.Username)) != 1 || !passOK {
		recordLoginFailure(ip)
		LogSecurityAudit("login_failed", body.Username, ip, "invalid credentials")
		writeAPIError(w, r, "E-AUTH-02", "")
		return
	}
	recordLoginSuccess(ip)
	if upgrade { // transparent migration: legacy SHA-256 / weak argon2 params -> current argon2id
		mu.Lock()
		cfg.PassHash = hashPassword(body.Password)
		saveCfg()
		mu.Unlock()
		LogSecurityAudit("password_hash_upgraded", cfg.Username, ip, "re-hashed with argon2id")
	}
	tok := newSessionToken()
	addSession(tok) // persistent: survives restarts, 24h absolute expiry

	csrfTok := GenerateCSRFToken(tok)
	http.SetCookie(w, sessionCookie(r, tok, 86400))
	http.SetCookie(w, csrfCookie(r, csrfTok, 86400))

	LogSecurityAudit("login_success", cfg.Username, ip, "authenticated successfully")
	writeJSON(w, map[string]string{
		"status":     "ok",
		"csrf_token": csrfTok,
	})
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("gre_session"); err == nil {
		dropSession(c.Value)
	}
	http.SetCookie(w, sessionCookie(r, "", -1))
	http.SetCookie(w, csrfCookie(r, "", -1))
	LogSecurityAudit("logout", cfg.Username, clientIP(r), "logged out")
	writeJSON(w, map[string]string{"status": "ok"})
}

func handlePassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
		Password        string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeAPIError(w, r, "E-AUTH-04", "invalid request body")
		return
	}

	ip := clientIP(r)

	// Verify current password
	if okCur, _ := verifyPassword(cfg.PassHash, body.CurrentPassword); !okCur {
		recordLoginFailure(ip)
		LogSecurityAudit("password_change_rejected", cfg.Username, ip, "incorrect current password")
		writeAPIError(w, r, "E-AUTH-07", "current password does not match")
		return
	}

	targetPass := strings.TrimSpace(body.NewPassword)
	if targetPass == "" {
		targetPass = strings.TrimSpace(body.Password)
	}

	// Password strength validation (NIST 800-63B)
	if err := ValidatePasswordStrength(targetPass); err != nil {
		LogSecurityAudit("password_change_rejected", cfg.Username, ip, "strength check failed: "+err.Error())
		writeAPIError(w, r, "E-AUTH-04", err.Error())
		return
	}

	mu.Lock()
	cfg.PassHash = hashPassword(targetPass)
	_ = os.WriteFile(cfgPath(), mustJSON(cfg), 0600)
	// CWE-256: Plaintext passwords are NEVER stored on disk!
	if _, err := rand.Read(nonce[:]); err != nil {
		mu.Unlock()
		writeAPIError(w, r, "E-AUTH-05", "")
		return
	}
	mu.Unlock()

	// Invalidate all existing sessions
	dropAllSessions()

	tok := newSessionToken()
	addSession(tok) // Keep the changer logged in with a fresh session
	csrfTok := GenerateCSRFToken(tok)

	http.SetCookie(w, sessionCookie(r, tok, 86400))
	http.SetCookie(w, csrfCookie(r, csrfTok, 86400))

	LogSecurityAudit("password_changed", cfg.Username, ip, "password changed successfully")
	writeJSON(w, map[string]string{
		"status":     "ok",
		"csrf_token": csrfTok,
	})
}
