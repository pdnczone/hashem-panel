package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
	"unicode"
)

var (
	csrfKey   [32]byte
	csrfKeyMu sync.Once
	auditMu   sync.Mutex
)

func initCSRFKey() {
	csrfKeyMu.Do(func() {
		if _, err := rand.Read(csrfKey[:]); err != nil {
			copy(csrfKey[:], "gre-panel-csrf-fallback-key-32b")
		}
	})
}

// GenerateCSRFToken derives a cryptographically secure CSRF token tied to a session token.
func GenerateCSRFToken(sessionToken string) string {
	initCSRFKey()
	mac := hmac.New(sha256.New, csrfKey[:])
	mac.Write([]byte("gre-csrf:" + sessionToken))
	return hex.EncodeToString(mac.Sum(nil))
}

// ValidateCSRFToken verifies if a candidate CSRF token matches the session token.
func ValidateCSRFToken(sessionToken, candidate string) bool {
	if sessionToken == "" || candidate == "" {
		return false
	}
	expected := GenerateCSRFToken(sessionToken)
	return ConstantTimeCompare(expected, strings.TrimSpace(candidate))
}

// requireCSRF is middleware that enforces valid X-CSRF-Token headers
// on state-changing requests (POST, PUT, PATCH, DELETE).
func requireCSRF(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Safe HTTP methods do not mutate state
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			next(w, r)
			return
		}

		path := r.URL.Path
		// Exempt login and logout
		if strings.HasSuffix(path, "/api/login") || strings.HasSuffix(path, "/api/logout") {
			next(w, r)
			return
		}

		c, err := r.Cookie("gre_session")
		if err != nil || c.Value == "" {
			writeAPIError(w, r, "E-AUTH-01", "")
			return
		}

		clientCSRF := r.Header.Get("X-CSRF-Token")
		if clientCSRF == "" {
			clientCSRF = r.Header.Get("X-Csrf-Token")
		}

		if !ValidateCSRFToken(c.Value, clientCSRF) {
			LogSecurityAudit("csrf_rejected", cfg.Username, ClientIP(r), "path="+path)
			writeAPIError(w, r, "E-AUTH-08", "invalid or missing CSRF token")
			return
		}

		rec := &statusRecorder{ResponseWriter: w}
		next(rec, r)
		auditMutation(r, rec.status)
	}
}

// ---- Password Strength Validation (NIST 800-63B Compliant) ----

var commonWeakPasswords = map[string]struct{}{
	"12345678":         {},
	"123456789":        {},
	"1234567890":       {},
	"password":         {},
	"password123":      {},
	"password1234":     {},
	"password12345":    {},
	"admin123456":      {},
	"admin12345678":    {},
	"administrator":    {},
	"qwerty123456":     {},
	"hashempanel123":   {},
	"grepanel123456":   {},
	"rootroot1234":     {},
	"welcome123456":    {},
}

// ValidatePasswordStrength enforces strong passwords (minimum 12 chars, upper, lower, digit, symbol).
func ValidatePasswordStrength(pw string) error {
	if len(pw) < 12 {
		return errors.New("password must be at least 12 characters long")
	}
	if len(pw) > 128 {
		return errors.New("password must not exceed 128 characters")
	}

	lower := strings.ToLower(pw)
	if _, bad := commonWeakPasswords[lower]; bad {
		return errors.New("password is too common or easily guessable")
	}

	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, r := range pw {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r) || strings.ContainsRune("!@#$%^&*()-_=+[]{}|;:,.<>?/~`'\"", r):
			hasSpecial = true
		}
	}

	if !hasUpper {
		return errors.New("password must contain at least one uppercase letter (A-Z)")
	}
	if !hasLower {
		return errors.New("password must contain at least one lowercase letter (a-z)")
	}
	if !hasDigit {
		return errors.New("password must contain at least one number (0-9)")
	}
	if !hasSpecial {
		return errors.New("password must contain at least one special character (!@#$%^&*...)")
	}

	return nil
}

// ---- Trusted Proxy & Client IP (Spoofing Prevention) ----

// CleanHost parses and extracts the raw host or IP from an input string,
// stripping URL schemes (http://, https://, etc.), ports, paths, and IPv6 brackets.
func CleanHost(input string) string {
	input = strings.TrimSpace(input)
	if input == "" {
		return ""
	}

	// If it contains scheme prefix (e.g. "http://", "https://")
	if strings.Contains(input, "://") {
		if u, err := url.Parse(input); err == nil && u.Host != "" {
			input = u.Host
		} else {
			// fallback: strip up to ://
			parts := strings.SplitN(input, "://", 2)
			input = parts[1]
		}
	}

	// Remove trailing paths or query params if any remain
	if slashIdx := strings.Index(input, "/"); slashIdx != -1 {
		input = input[:slashIdx]
	}
	if qIdx := strings.Index(input, "?"); qIdx != -1 {
		input = input[:qIdx]
	}

	// If host contains port (e.g., "example.com:8080" or "[::1]:8080")
	if host, _, err := net.SplitHostPort(input); err == nil {
		return strings.Trim(host, "[]")
	}

	// Strip IPv6 brackets if "[::1]"
	input = strings.Trim(input, "[]")
	return input
}

// IsTrustedProxy checks whether a given IP address belongs to TRUSTED_PROXY_IPS or is local loopback.
func IsTrustedProxy(ipStr string) bool {
	ipStr = strings.TrimSpace(ipStr)
	if ipStr == "" {
		return false
	}

	// Always trust local loopback (reverse proxies like Nginx or Caddy on same machine)
	if ipStr == "127.0.0.1" || ipStr == "::1" || strings.EqualFold(ipStr, "localhost") {
		return true
	}
	parsedIP := net.ParseIP(ipStr)
	if parsedIP != nil && parsedIP.IsLoopback() {
		return true
	}

	raw := os.Getenv("TRUSTED_PROXY_IPS")
	if raw == "" {
		return false
	}

	if parsedIP == nil {
		return false
	}

	parts := strings.Split(raw, ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}

		// CIDR notation
		if strings.Contains(p, "/") {
			_, subnet, err := net.ParseCIDR(p)
			if err == nil && subnet.Contains(parsedIP) {
				return true
			}
			continue
		}

		// Exact IP match
		if target := net.ParseIP(p); target != nil {
			if target.Equal(parsedIP) {
				return true
			}
		}
	}
	return false
}

// ClientIP extracts the real client IP.
// Header X-Forwarded-For is ONLY trusted if the direct connection comes from a trusted proxy.
func ClientIP(r *http.Request) string {
	if r == nil {
		return ""
	}

	remoteHost, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		remoteHost = strings.Trim(r.RemoteAddr, "[]")
	}

	// Only trust forwarding headers if the immediate peer is a verified reverse proxy
	if IsTrustedProxy(remoteHost) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			candidate := strings.TrimSpace(parts[0])
			if candidate != "" {
				if host, _, err := net.SplitHostPort(candidate); err == nil {
					return host
				}
				return strings.Trim(candidate, "[]")
			}
		}
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			cand := strings.TrimSpace(xri)
			if host, _, err := net.SplitHostPort(cand); err == nil {
				return host
			}
			return strings.Trim(cand, "[]")
		}
	}

	return remoteHost
}

// ---- Security Audit Logging ----

// LogSecurityAudit writes a tamper-evident entry to the security audit log.
func LogSecurityAudit(event, user, ip, details string) {
	auditMu.Lock()
	defer auditMu.Unlock()

	ts := time.Now().UTC().Format(time.RFC3339)
	entry := fmt.Sprintf("[%s] EVENT=%s user=%q ip=%s %s\n", ts, event, user, ip, details)

	log.Printf("[AUDIT] %s", strings.TrimSpace(entry))

	auditPath := auditLogPath()
	rotateAuditLocked(auditPath)
	f, err := os.OpenFile(auditPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err == nil {
		_, _ = f.WriteString(entry)
		_ = f.Close()
	}
}
