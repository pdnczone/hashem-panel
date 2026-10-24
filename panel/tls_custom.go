package main

// Custom certificate install: the admin's own cert/key instead of certbot.
// Three inputs (exactly one per request):
//  1. paste PEM: {"cert":"-----BEGIN...","key":"-----BEGIN..."}
//  2. multipart upload: fields "cert" + "key" (files, ≤1MB each)
//  3. server path: {"cert_path":"/etc/ssl/x.crt","key_path":"/etc/ssl/x.key"}
//
// Validation (tls.X509KeyPair) happens BEFORE anything is touched; on success
// the previous files are backed up atomically and the HTTPS listener reloads
// in-process. Tunnels never touched. Global 1MB body cap (security_headers.go)
// already bounds paste/multipart size.

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// tlsCustomSource carries one validated cert+key pair plus a display label.
type tlsCustomSource struct {
	cert  []byte
	key   []byte
	label string
}

// tlsReadCustomBody extracts cert+key from JSON-paste or multipart upload.
func tlsReadCustomBody(r *http.Request) (*tlsCustomSource, string) {
	ct := r.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "multipart/form-data") {
		mr, err := r.MultipartReader()
		if err != nil {
			return nil, "cannot parse upload (multipart/form-data with cert + key files required)"
		}
		var cert, key []byte
		for {
			part, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, "cannot read upload: " + err.Error()
			}
			data, err := io.ReadAll(io.LimitReader(part, 1<<20+4096))
			_ = part.Close()
			if err != nil {
				return nil, "cannot read upload: " + err.Error()
			}
			switch part.FormName() {
			case "cert":
				cert = data
			case "key":
				key = data
			}
		}
		if len(cert) == 0 || len(key) == 0 {
			return nil, "upload must contain both cert and key files"
		}
		label := "uploaded cert"
		return &tlsCustomSource{cert: cert, key: key, label: label}, ""
	}

	var body struct {
		Cert     string `json:"cert"`
		Key      string `json:"key"`
		Label    string `json:"label"`
		CertPath string `json:"cert_path"`
		KeyPath  string `json:"key_path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		return nil, "invalid JSON (paste cert/key, or send cert_path/key_path)"
	}
	hasPaste := body.Cert != "" || body.Key != ""
	hasPath := body.CertPath != "" || body.KeyPath != ""
	switch {
	case hasPaste && hasPath:
		return nil, "send either pasted PEM or server paths, not both"
	case hasPaste:
		if body.Cert == "" || body.Key == "" {
			return nil, "both cert and key PEM text are required"
		}
		label := strings.TrimSpace(body.Label)
		if label == "" {
			label = "custom cert"
		}
		return &tlsCustomSource{cert: []byte(body.Cert), key: []byte(body.Key), label: label}, ""
	case hasPath:
		if body.CertPath == "" || body.KeyPath == "" {
			return nil, "both cert_path and key_path are required"
		}
		cert, err := os.ReadFile(filepath.Clean(body.CertPath))
		if err != nil {
			return nil, "cannot read cert file: " + err.Error()
		}
		key, err := os.ReadFile(filepath.Clean(body.KeyPath))
		if err != nil {
			return nil, "cannot read key file: " + err.Error()
		}
		return &tlsCustomSource{cert: cert, key: key, label: filepath.Base(body.CertPath)}, ""
	default:
		return nil, "nothing to install (paste cert/key, upload files, or send cert_path/key_path)"
	}
}

// tlsInstallCustom validates the pair, backs up the old files, installs, and
// reloads HTTPS. Validation first: a bad pair never touches disk.
func tlsInstallCustom(src *tlsCustomSource) (map[string]any, string) {
	pair, err := tls.X509KeyPair(src.cert, src.key)
	if err != nil {
		return nil, "certificate and key do not match: " + err.Error()
	}
	expiry := ""
	issuer := ""
	if len(pair.Certificate) > 0 {
		if c, err := parseCertLeaf(pair.Certificate[0]); err == nil {
			expiry = c.NotAfter.Format("2006-01-02 15:04:05")
			issuer = c.Issuer.CommonName
		}
	}
	backupTLSCerts()
	_ = os.MkdirAll(tlsDir(), 0700)
	if err := os.WriteFile(tlsCertFile(), src.cert, 0600); err != nil {
		rollbackTLSCerts()
		return nil, "cannot write certificate: " + err.Error()
	}
	if err := os.WriteFile(tlsKeyFile(), src.key, 0600); err != nil {
		rollbackTLSCerts()
		return nil, "cannot write key: " + err.Error()
	}
	meta := tlsMeta{
		Domain:   src.label,
		IssuedAt: time.Now().Format("2006-01-02 15:04:05"),
		Expiry:   expiry,
		Issuer:   issuer,
		Source:   tlsSourceCustom,
	}
	_ = os.WriteFile(tlsMetaFile(), mustJSON(meta), 0600)
	clearTLSBackups()
	startHTTPSListener()
	return map[string]any{
		"status":     "ok",
		"tls_status": "valid",
		"label":      src.label,
		"expiry":     expiry,
		"issuer":     issuer,
		"https_url":  tlsHTTPSURL(),
	}, ""
}

// POST /api/tls/custom — install the admin's own certificate.
func handleTLSCustomPost(w http.ResponseWriter, r *http.Request) {
	src, errMsg := tlsReadCustomBody(r)
	if errMsg != "" {
		writeAPIError(w, r, "E-TLS-12", errMsg)
		return
	}
	out, fail := tlsInstallCustom(src)
	if fail != "" {
		writeAPIError(w, r, "E-TLS-12", fail)
		return
	}
	LogSecurityAudit("TLS_CUSTOM_INSTALLED", cfg.Username, ClientIP(r), "custom certificate installed ("+src.label+")")
	recordError("E-TLS-00", r.Method+" "+r.URL.Path, "custom certificate installed ("+src.label+"), expires "+fmt.Sprint(out["expiry"]))
	writeJSON(w, out)
}

func parseCertLeaf(der []byte) (*x509.Certificate, error) { return x509.ParseCertificate(der) }
