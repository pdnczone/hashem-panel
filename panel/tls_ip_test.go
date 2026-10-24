package main

// Step 3 RED: self-signed TLS for IP access — local CA + server cert with
// IP SAN, 825-day validity, CA downloadable for browser/OS install,
// regenerate on demand. Tunnels never touched.
import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func postIPCert(t *testing.T, body string) (int, map[string]any) {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	handleTLSIPPost(rr, req)
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return rr.Code, out
}

func TestIPCertValidation(t *testing.T) {
	if code, _ := postIPCert(t, `{bad`); code != 400 {
		t.Errorf("bad json = %d, want 400", code)
	}
	if code, _ := postIPCert(t, `{"ip":"not-an-ip"}`); code != 400 {
		t.Errorf("garbage ip = %d, want 400", code)
	}
	if code, _ := postIPCert(t, `{"ip":"example.com"}`); code != 400 {
		t.Errorf("domain instead of IP = %d, want 400", code)
	}
	if code, _ := postIPCert(t, `{}`); code != 400 {
		t.Errorf("empty body without server IP context must be 400 in tests")
	}
}

func TestIPCertIssue(t *testing.T) {
	code, out := postIPCert(t, `{"ip":"203.0.113.7"}`)
	if code != 200 {
		t.Fatalf("issue = %d %+v, want 200", code, out)
	}
	// server cert + key installed
	certPEM, err := os.ReadFile(tlsCertFile())
	if err != nil {
		t.Fatal("server.crt must exist after issue")
	}
	if _, err := os.Stat(tlsKeyFile()); err != nil {
		t.Fatal("server.key must exist after issue")
	}
	// CA file exists and is a CA
	caPEM, err := os.ReadFile(tlsCAFile())
	if err != nil {
		t.Fatal("CA file must exist for browser install")
	}
	blk, _ := pem.Decode(caPEM)
	ca, err := x509.ParseCertificate(blk.Bytes)
	if err != nil || !ca.IsCA {
		t.Fatalf("CA file must parse as a CA cert: %v", err)
	}
	// server cert has the IP SAN and 825-day validity
	blk, _ = pem.Decode(certPEM)
	leaf, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(leaf.IPAddresses) != 1 || leaf.IPAddresses[0].String() != "203.0.113.7" {
		t.Errorf("server cert must carry the IP SAN, got %v", leaf.IPAddresses)
	}
	days := int(leaf.NotAfter.Sub(leaf.NotBefore).Hours() / 24)
	if days != 825 {
		t.Errorf("validity = %d days, want 825 (browser maximum)", days)
	}
	// server cert verifies against the CA
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
		t.Errorf("server cert must verify against local CA: %v", err)
	}
	// meta records IP mode
	m := tlsMetaLoad()
	if m == nil || m.Domain != "203.0.113.7" {
		t.Errorf("meta = %+v, want IP as domain", m)
	}
	if out["tls_status"] != "valid" {
		t.Errorf("status = %+v, want valid", out)
	}
	cleanupTLSFiles(t)
	_ = os.Remove(tlsCAFile())
}

func TestIPCertRegenerateRotatesServerCert(t *testing.T) {
	if code, _ := postIPCert(t, `{"ip":"198.51.100.9"}`); code != 200 {
		t.Fatal("first issue failed")
	}
	first, _ := os.ReadFile(tlsCertFile())
	firstCA, _ := os.ReadFile(tlsCAFile())
	time.Sleep(1100 * time.Millisecond) // serial + timestamps must differ
	if code, _ := postIPCert(t, `{"ip":"198.51.100.9","regenerate":true}`); code != 200 {
		t.Fatal("regenerate failed")
	}
	second, _ := os.ReadFile(tlsCertFile())
	secondCA, _ := os.ReadFile(tlsCAFile())
	if string(first) == string(second) {
		t.Error("regenerate must rotate the server certificate")
	}
	if string(firstCA) != string(secondCA) {
		t.Error("regenerate must keep the same CA (browsers already trust it)")
	}
	cleanupTLSFiles(t)
	_ = os.Remove(tlsCAFile())
}

func TestIPCertGetCA(t *testing.T) {
	if code, _ := postIPCert(t, `{"ip":"192.0.2.5"}`); code != 200 {
		t.Fatal("issue failed")
	}
	rr := httptest.NewRecorder()
	handleTLSIPCAGet(rr, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rr.Code != 200 {
		t.Fatalf("CA download = %d, want 200", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); !strings.Contains(ct, "certificate") && !strings.Contains(ct, "pem") {
		t.Errorf("CA download content-type = %q", ct)
	}
	blk, _ := pem.Decode(rr.Body.Bytes())
	if blk == nil {
		t.Fatal("CA download must be PEM")
	}
	if _, err := x509.ParseCertificate(blk.Bytes); err != nil {
		t.Errorf("downloaded CA must parse: %v", err)
	}
	cleanupTLSFiles(t)
	_ = os.Remove(tlsCAFile())
}
