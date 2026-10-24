package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSecurityMiddlewareHeaders(t *testing.T) {
	h := securityMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/x", nil))
	want := map[string]string{
		"X-Frame-Options":        "DENY",
		"X-Content-Type-Options": "nosniff",
		"Referrer-Policy":        "same-origin",
		"Permissions-Policy":     "camera=(), microphone=(), geolocation=()",
	}
	for k, v := range want {
		if got := rec.Header().Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	csp := rec.Header().Get("Content-Security-Policy")
	for _, part := range []string{"default-src 'self'", "connect-src 'self' ws: wss:", "frame-ancestors 'none'", "form-action 'self'", "base-uri 'self'"} {
		if !strings.Contains(csp, part) {
			t.Errorf("CSP missing %q: %s", part, csp)
		}
	}
	if rec.Header().Get("Strict-Transport-Security") != "" {
		t.Error("HSTS must not be set on plain HTTP")
	}
	if rec.Body.String() != "ok" {
		t.Errorf("GET body altered: %q", rec.Body.String())
	}

	// HTTPS request gets HSTS.
	req := httptest.NewRequest("GET", "https://example.com/x", nil)
	req.TLS = &tls.ConnectionState{}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Header().Get("Strict-Transport-Security") == "" {
		t.Error("HSTS missing on HTTPS request")
	}
}

func TestSecurityMiddlewareBodyLimit(t *testing.T) {
	h := securityMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var v map[string]any
		if err := json.NewDecoder(r.Body).Decode(&v); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))

	big := `{"a":"` + strings.Repeat("x", maxRequestBodyBytes+10) + `"}`
	for _, m := range []string{"POST", "PUT", "PATCH", "DELETE"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(m, "/x", strings.NewReader(big)))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s oversize: code %d, want 400", m, rec.Code)
		}
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/x", strings.NewReader(`{"a":"small"}`)))
	if rec.Code != http.StatusOK {
		t.Errorf("small POST: code %d, want 200", rec.Code)
	}

	// GET bodies are not limited/affected.
	g := securityMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := readAllCount(r)
		if n != len(big) {
			http.Error(w, "truncated", 500)
		}
	}))
	rec = httptest.NewRecorder()
	g.ServeHTTP(rec, httptest.NewRequest("GET", "/x", strings.NewReader(big)))
	if rec.Code != http.StatusOK {
		t.Errorf("GET with large body affected: %d", rec.Code)
	}

	// WebSocket upgrade requests are not capped.
	ws := securityMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := readAllCount(r)
		if n != len(big) {
			http.Error(w, "truncated", 500)
		}
	}))
	req := httptest.NewRequest("POST", "/x", strings.NewReader(big))
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	rec = httptest.NewRecorder()
	ws.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("websocket upgrade body was capped: %d", rec.Code)
	}
}

func readAllCount(r *http.Request) (int, error) {
	buf := make([]byte, 32*1024)
	total := 0
	for {
		n, err := r.Body.Read(buf)
		total += n
		if err != nil {
			if err.Error() == "EOF" {
				return total, nil
			}
			return total, err
		}
	}
}

func TestPeerTLSPinning(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("pong"))
	}))
	defer srv.Close()
	leaf := srv.Certificate().Raw
	sum := sha256.Sum256(leaf)
	fp := hex.EncodeToString(sum[:])

	dial := func(c *PeerConfig) error {
		tr := &http.Transport{TLSClientConfig: peerTLSConfig(c)}
		defer tr.CloseIdleConnections()
		resp, err := (&http.Client{Transport: tr}).Get(srv.URL)
		if err != nil {
			return err
		}
		_ = resp.Body.Close()
		return nil
	}

	// First use: pin and persist.
	c := loadPeerConfig()
	c.TLSFingerprint = ""
	if err := dial(&c); err != nil {
		t.Fatalf("first use should succeed: %v", err)
	}
	if c.TLSFingerprint != fp {
		t.Fatalf("fingerprint not stored: %q want %q", c.TLSFingerprint, fp)
	}
	if got := loadPeerConfig().TLSFingerprint; got != fp {
		t.Fatalf("fingerprint not persisted: %q", got)
	}

	// Match.
	c2 := loadPeerConfig()
	if err := dial(&c2); err != nil {
		t.Fatalf("matching pin should succeed: %v", err)
	}

	// Mismatch.
	c3 := loadPeerConfig()
	c3.TLSFingerprint = strings.Repeat("ab", 32)
	err := dial(&c3)
	if err == nil || !strings.Contains(err.Error(), "fingerprint mismatch") {
		t.Fatalf("expected fingerprint mismatch error, got %v", err)
	}
	if c3.TLSFingerprint != strings.Repeat("ab", 32) {
		t.Error("pin must not be overwritten on mismatch")
	}
}
