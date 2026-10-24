package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func legacyHash(pw string) string {
	h := sha256.Sum256([]byte(pw))
	return hex.EncodeToString(h[:])
}

func TestHashPasswordArgon2idSalted(t *testing.T) {
	a, b := hashPassword("Correct-Horse-9!"), hashPassword("Correct-Horse-9!")
	if a == b {
		t.Fatal("hashes of same password must differ (random salt)")
	}
	if !strings.HasPrefix(a, "argon2id$") || isLegacyHash(a) {
		t.Fatalf("unexpected format: %s", a)
	}
	if ok, up := verifyPassword(a, "Correct-Horse-9!"); !ok || up {
		t.Fatalf("verify good: ok=%v upgrade=%v", ok, up)
	}
	if ok, _ := verifyPassword(a, "wrong"); ok {
		t.Fatal("wrong password accepted")
	}
}

func TestVerifyPasswordLegacyAndGarbage(t *testing.T) {
	if ok, up := verifyPassword(legacyHash("OldPass!2026x"), "OldPass!2026x"); !ok || !up {
		t.Fatalf("legacy must verify and request upgrade: ok=%v up=%v", ok, up)
	}
	for _, bad := range []string{"", "x", "argon2id$", "argon2id$v=19$m=999999999,t=1,p=1$AA$AA", "argon2id$v=19$m=8,t=99,p=1$AA$AA", "argon2id$v=19$m=19456,t=2,p=1$!!$!!"} {
		if ok, _ := verifyPassword(bad, "x"); ok {
			t.Fatalf("garbage hash %q accepted", bad)
		}
	}
}

func setupAuthCfg(t *testing.T, stored string) {
	t.Helper()
	old, oldDir := cfg, configDir
	configDir = t.TempDir()
	cfg = panelConfig{Username: "admin", PassHash: stored, Port: 7777, BasePath: "p"}
	saveCfg()
	t.Cleanup(func() { cfg, configDir = old, oldDir })
	attemptMu.Lock()
	attempts = map[string]*ipAttempts{}
	attemptMu.Unlock()
}

func login(t *testing.T, user, pw string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]string{"username": user, "password": pw})
	req := httptest.NewRequest("POST", "/api/login", bytes.NewReader(body))
	req.RemoteAddr = "203.0.113.9:1234"
	rec := httptest.NewRecorder()
	handleLogin(rec, req)
	return rec
}

// M-03: a legacy SHA-256 panel.json must still log in and be upgraded in place.
func TestLoginUpgradesLegacyHash(t *testing.T) {
	setupAuthCfg(t, legacyHash("OldPass!2026x"))
	rec := login(t, "admin", "OldPass!2026x")
	if rec.Code != http.StatusOK {
		t.Fatalf("legacy login failed: %d %s", rec.Code, rec.Body.String())
	}
	if isLegacyHash(cfg.PassHash) || !strings.HasPrefix(cfg.PassHash, "argon2id$") {
		t.Fatalf("hash not upgraded: %s", cfg.PassHash)
	}
	if rec := login(t, "admin", "OldPass!2026x"); rec.Code != http.StatusOK {
		t.Fatalf("login after upgrade failed: %d", rec.Code)
	}
	if rec := login(t, "admin", "nope"); rec.Code == http.StatusOK {
		t.Fatal("bad password accepted")
	}
}

// M-03: session cookie must be random, not derivable from panel.json contents.
func TestSessionTokenNotDerivableFromHash(t *testing.T) {
	setupAuthCfg(t, legacyHash("OldPass!2026x"))
	rec := login(t, "admin", "OldPass!2026x")
	var tok string
	for _, c := range rec.Result().Cookies() {
		if c.Name == "gre_session" {
			tok = c.Value
		}
	}
	if len(tok) != 64 {
		t.Fatalf("unexpected token %q", tok)
	}
	// old scheme: sha256(nonce || PassHash) — must not authenticate anymore
	forged := sha256.Sum256(append(nonce[:], []byte(cfg.PassHash)...))
	req := httptest.NewRequest("GET", "/api/status", nil)
	req.AddCookie(&http.Cookie{Name: "gre_session", Value: hex.EncodeToString(forged[:])})
	if authed(req) {
		t.Fatal("derived legacy cookie still authenticates")
	}
	req2 := httptest.NewRequest("GET", "/api/status", nil)
	req2.AddCookie(&http.Cookie{Name: "gre_session", Value: tok})
	if !authed(req2) {
		t.Fatal("real session token rejected")
	}
	a, b := newSessionToken(), newSessionToken()
	if a == b {
		t.Fatal("session tokens must be unique per login")
	}
}

func TestRotateNonce(t *testing.T) {
	mu.Lock()
	old := nonce
	mu.Unlock()
	rotateNonce()
	mu.Lock()
	current := nonce
	mu.Unlock()
	if subtle.ConstantTimeCompare(old[:], current[:]) == 1 {
		t.Fatal("rotateNonce must alter nonce entropy")
	}
}

func TestVerifyPasswordDollarPrefixAndWhitespace(t *testing.T) {
	orig := hashPassword("SecretP@ss123")
	withDollar := "$" + orig
	withWhitespace := "  \n" + withDollar + " 	\n"

	ok, up := verifyPassword(withWhitespace, "SecretP@ss123")
	if !ok {
		t.Fatal("verifyPassword failed for dollar prefix and whitespace")
	}
	if !up {
		t.Fatal("dollar prefix should request upgrade to canonical format")
	}

	// Plaintext fallback
	okPlain, upPlain := verifyPassword("SimplePlainPass", "SimplePlainPass")
	if !okPlain || !upPlain {
		t.Fatal("plaintext should verify and request upgrade")
	}
}

func TestLoginWhitespaceAndCaseInsensitiveUser(t *testing.T) {
	setupAuthCfg(t, hashPassword("SecretP@ss123"))

	// Test user with whitespace and different case
	rec := login(t, "  Admin  ", "SecretP@ss123")
	if rec.Code != http.StatusOK {
		t.Fatalf("login failed for user with whitespace/case: %d %s", rec.Code, rec.Body.String())
	}
}

// C2: the stored hash itself must never be accepted as the password.
func TestVerifyPasswordRejectsHashAsPassword(t *testing.T) {
	argon := hashPassword("Correct-Horse-9!")
	for _, stored := range []string{argon, "$" + argon, legacyHash("OldPass!2026x"), "$2a$10$abcdefghijklmnopqrstuv"} {
		if ok, _ := verifyPassword(stored, stored); ok {
			t.Fatalf("hash %q accepted as its own password", stored)
		}
	}
}

// L20: a password with surrounding spaces must verify against its own hash.
func TestHashPasswordTrimMatchesVerify(t *testing.T) {
	h := hashPassword("  Spaced-Pass-1 ")
	if ok, _ := verifyPassword(h, "  Spaced-Pass-1 "); !ok {
		t.Fatal("password with surrounding spaces rejected")
	}
}
