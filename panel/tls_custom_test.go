package main

// Step 2 RED: custom certificate install (paste PEM / upload files / server
// path) with X509KeyPair validation, atomic backup/rollback, in-process HTTPS
// reload. Tunnels never touched.
import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// testCertPEM generates a throwaway self-signed cert+key for tests.
func testCertPEM(t *testing.T, cn string) (certPEM, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}))
	return certPEM, keyPEM
}

type testMultipart struct {
	buf *bytes.Buffer
	w   *multipart.Writer
}

func newMultipartWriter() *testMultipart {
	buf := &bytes.Buffer{}
	return &testMultipart{buf: buf, w: multipart.NewWriter(buf)}
}

func addMultipartFile(t *testing.T, m *testMultipart, field, name, content string) {
	t.Helper()
	fw, err := m.w.CreateFormFile(field, name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
}

func (m *testMultipart) close()              { _ = m.w.Close() }
func (m *testMultipart) contentType() string { return m.w.FormDataContentType() }

func postCustomCert(t *testing.T, body string, contentType string) (int, map[string]any) {
	t.Helper()
	rr := httptest.NewRecorder()
	// NOTE: multipart bodies are assembled as strings here; PEM is ASCII-safe.
	req := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	handleTLSCustomPost(rr, req)
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return rr.Code, out
}

func TestCustomCertValidation(t *testing.T) {
	if code, _ := postCustomCert(t, `{bad`, "application/json"); code != 400 {
		t.Errorf("bad json = %d, want 400", code)
	}
	// garbage PEM
	if code, _ := postCustomCert(t, `{"cert":"not-a-cert","key":"not-a-key"}`, "application/json"); code != 400 {
		t.Errorf("garbage PEM = %d, want 400", code)
	}
	// cert without key
	cert, _ := testCertPEM(t, "panel.example.com")
	if code, _ := postCustomCert(t, `{"cert":`+jsonStr(cert)+`}`, "application/json"); code != 400 {
		t.Errorf("missing key = %d, want 400", code)
	}
	// mismatched key
	_, otherKey := testCertPEM(t, "other.example.com")
	body, _ := json.Marshal(map[string]string{"cert": cert, "key": otherKey})
	if code, _ := postCustomCert(t, string(body), "application/json"); code != 400 {
		t.Errorf("mismatched key = %d, want 400", code)
	}
	// nonexistent server path
	if code, _ := postCustomCert(t, `{"cert_path":"/nonexistent/x.crt","key_path":"/nonexistent/x.key"}`, "application/json"); code != 400 {
		t.Errorf("missing files = %d, want 400", code)
	}
	// both paste and path = ambiguous
	payload, _ := json.Marshal(map[string]string{"cert": cert, "key": otherKey, "cert_path": "/x", "key_path": "/y"})
	if code, _ := postCustomCert(t, string(payload), "application/json"); code != 400 {
		t.Errorf("paste+path = %d, want 400", code)
	}
}

func TestCustomCertInstallPaste(t *testing.T) {
	cert, key := testCertPEM(t, "panel.example.com")
	body, _ := json.Marshal(map[string]string{"cert": cert, "key": key, "label": "my-cert"})
	code, out := postCustomCert(t, string(body), "application/json")
	if code != 200 {
		t.Fatalf("install = %d %+v, want 200", code, out)
	}
	if _, err := os.Stat(tlsCertFile()); err != nil {
		t.Fatal("server.crt must exist after install")
	}
	if _, err := os.Stat(tlsKeyFile()); err != nil {
		t.Fatal("server.key must exist after install")
	}
	m := tlsMetaLoad()
	if m == nil || m.Domain != "my-cert" {
		t.Errorf("meta label = %+v, want my-cert", m)
	}
	if out["tls_status"] != "valid" {
		t.Errorf("status = %+v, want valid", out)
	}
	cleanupTLSFiles(t)
}

func TestCustomCertInstallServerPath(t *testing.T) {
	cert, key := testCertPEM(t, "panel.example.com")
	dir := t.TempDir()
	cf, kf := dir+"/c.pem", dir+"/k.pem"
	if err := os.WriteFile(cf, []byte(cert), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kf, []byte(key), 0600); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"cert_path": cf, "key_path": kf})
	code, out := postCustomCert(t, string(body), "application/json")
	if code != 200 {
		t.Fatalf("install from path = %d %+v, want 200", code, out)
	}
	if _, err := os.Stat(tlsCertFile()); err != nil {
		t.Fatal("server.crt must exist after install")
	}
	cleanupTLSFiles(t)
}

func TestCustomCertMultipartUpload(t *testing.T) {
	cert, key := testCertPEM(t, "upload.example.com")
	w := newMultipartWriter()
	addMultipartFile(t, w, "cert", "server.crt", cert)
	addMultipartFile(t, w, "key", "server.key", key)
	w.close()
	code, out := postCustomCert(t, w.buf.String(), w.contentType())
	if code != 200 {
		t.Fatalf("multipart upload = %d %+v, want 200", code, out)
	}
	if _, err := os.Stat(tlsCertFile()); err != nil {
		t.Fatal("server.crt must exist after upload")
	}
	cleanupTLSFiles(t)
}

func TestCustomCertKeepsPreviousOnBadKeypair(t *testing.T) {
	// install a good cert first, then attempt a bad one: old files must survive
	cert, key := testCertPEM(t, "good.example.com")
	body, _ := json.Marshal(map[string]string{"cert": cert, "key": key})
	if code, _ := postCustomCert(t, string(body), "application/json"); code != 200 {
		t.Fatal("setup install failed")
	}
	before, _ := os.ReadFile(tlsCertFile())
	_, otherKey := testCertPEM(t, "other.example.com")
	bad, _ := json.Marshal(map[string]string{"cert": cert, "key": otherKey})
	if code, _ := postCustomCert(t, string(bad), "application/json"); code != 400 {
		t.Fatalf("mismatched keypair must be 400")
	}
	after, _ := os.ReadFile(tlsCertFile())
	if string(before) != string(after) {
		t.Error("previous certificate must survive a failed install (rollback)")
	}
	cleanupTLSFiles(t)
}

func jsonStr(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func cleanupTLSFiles(t *testing.T) {
	t.Helper()
	_ = os.Remove(tlsCertFile())
	_ = os.Remove(tlsKeyFile())
	_ = os.Remove(tlsMetaFile())
	clearTLSBackups()
}
