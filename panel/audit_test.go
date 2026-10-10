package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestMutationIsAuditedWithStatusNoBody(t *testing.T) {
	_ = os.Remove(auditLogPath())
	tok := "sess-audit-1"
	h := requireCSRF(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})
	req := httptest.NewRequest("POST", "/p/api/action", strings.NewReader(`{"token":"SUPERSECRET"}`))
	req.AddCookie(&http.Cookie{Name: "gre_session", Value: tok})
	req.Header.Set("X-CSRF-Token", GenerateCSRFToken(tok))
	h(httptest.NewRecorder(), req)
	b, _ := os.ReadFile(auditLogPath())
	log := string(b)
	if !strings.Contains(log, "EVENT=api_mutation") || !strings.Contains(log, "method=POST path=/p/api/action status=418") {
		t.Fatalf("mutation not audited correctly:\n%s", log)
	}
	if strings.Contains(log, "SUPERSECRET") {
		t.Fatal("request body must never be written to the audit log")
	}
}

func TestSafeMethodsAreNotAudited(t *testing.T) {
	_ = os.Remove(auditLogPath())
	h := requireCSRF(func(w http.ResponseWriter, r *http.Request) {})
	h(httptest.NewRecorder(), httptest.NewRequest("GET", "/p/api/status", nil))
	if b, _ := os.ReadFile(auditLogPath()); strings.Contains(string(b), "api_mutation") {
		t.Fatal("GET must not be audited")
	}
}

func TestAuditRotation(t *testing.T) {
	p := auditLogPath()
	_ = os.Remove(p)
	_ = os.Remove(p + ".1")
	big := strings.Repeat("x", auditMaxBytes+10)
	if err := os.WriteFile(p, []byte(big), 0o600); err != nil {
		t.Fatal(err)
	}
	LogSecurityAudit("rotation_probe", "u", "127.0.0.1", "d")
	if fi, err := os.Stat(p + ".1"); err != nil || fi.Size() < int64(auditMaxBytes) {
		t.Fatalf("old log should move to .1: %v", err)
	}
	if fi, _ := os.Stat(p); fi == nil || fi.Size() > 1024 {
		t.Fatal("fresh log expected after rotation")
	}
	_ = os.Remove(p + ".1")
}

func TestAuditEndpointNewestFirstFilteredRedacted(t *testing.T) {
	_ = os.Remove(auditLogPath())
	LogSecurityAudit("login_failed", "bob", "1.1.1.1", "first")
	LogSecurityAudit("api_mutation", "admin", "2.2.2.2", "token=abcdef123456 second")
	rr := httptest.NewRecorder()
	handleAuditGet(rr, httptest.NewRequest("GET", "/api/audit?n=10", nil))
	body := rr.Body.String()
	if strings.Index(body, "second") > strings.Index(body, "first") {
		t.Errorf("newest must come first: %s", body)
	}
	if strings.Contains(body, "abcdef123456") {
		t.Errorf("secrets must be redacted: %s", body)
	}
	rr = httptest.NewRecorder()
	handleAuditGet(rr, httptest.NewRequest("GET", "/api/audit?q=login_failed", nil))
	if strings.Contains(rr.Body.String(), "second") || !strings.Contains(rr.Body.String(), "bob") {
		t.Errorf("filter wrong: %s", rr.Body.String())
	}
}
