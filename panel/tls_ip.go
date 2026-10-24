package main

// Self-signed TLS for IP access: a persistent local CA plus a server cert
// carrying the IP as SAN. The CA lives for 10 years (browsers trust it once
// after the admin installs hashem-ca.crt); server certs live 825 days (the
// browser maximum) and rotate with Regenerate while the CA stays the same.
// In-process HTTPS reload; tunnels never touched.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	ipCertValidityDays = 825
	caValidityDays     = 3650 // 10 years: install once, trust for a decade
)

func tlsCAFile() string    { return filepath.Join(tlsDir(), "hashem-ca.crt") }
func tlsCAKeyFile() string { return filepath.Join(tlsDir(), "hashem-ca.key") }

func pemEncode(blockType string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
}

// tlsEnsureCA creates the local CA on first use, loads it afterwards.
func tlsEnsureCA() (ca *x509.Certificate, caKey *ecdsa.PrivateKey, errMsg string) {
	if data, err := os.ReadFile(tlsCAFile()); err == nil {
		if kdata, kerr := os.ReadFile(tlsCAKeyFile()); kerr == nil {
			if blk, _ := pem.Decode(data); blk != nil {
				if c, perr := x509.ParseCertificate(blk.Bytes); perr == nil && c.IsCA {
					if kblk, _ := pem.Decode(kdata); kblk != nil {
						if k, kperr := x509.ParseECPrivateKey(kblk.Bytes); kperr == nil {
							return c, k, ""
						}
					}
				}
			}
		}
		// unreadable CA = corrupt install; start over (old server certs are
		// replaced by the new chain below, nothing else depends on the CA).
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, "cannot generate CA key: " + err.Error()
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, "cannot randomize CA serial: " + err.Error()
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{Organization: []string{"Hashem Panel Local CA"}, CommonName: "Hashem Panel Local CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(caValidityDays * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, "cannot sign CA: " + err.Error()
	}
	ca, err = x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, "cannot parse CA: " + err.Error()
	}
	_ = os.MkdirAll(tlsDir(), 0700)
	if err := os.WriteFile(tlsCAFile(), pemEncode("CERTIFICATE", der), 0600); err != nil {
		return nil, nil, "cannot write CA: " + err.Error()
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, "cannot encode CA key: " + err.Error()
	}
	if err := os.WriteFile(tlsCAKeyFile(), pemEncode("EC PRIVATE KEY", kb), 0600); err != nil {
		return nil, nil, "cannot write CA key: " + err.Error()
	}
	return ca, key, ""
}

// tlsIssueIPCert signs a server cert for ip from the local CA and installs it.
func tlsIssueIPCert(ip net.IP) (map[string]any, string) {
	ca, caKey, errMsg := tlsEnsureCA()
	if errMsg != "" {
		return nil, errMsg
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "cannot generate server key: " + err.Error()
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, "cannot randomize serial: " + err.Error()
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{Organization: []string{"Hashem Panel"}, CommonName: ip.String()},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(ipCertValidityDays * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{ip},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return nil, "cannot sign server cert: " + err.Error()
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, "cannot encode server key: " + err.Error()
	}
	backupTLSCerts()
	_ = os.MkdirAll(tlsDir(), 0700)
	if err := os.WriteFile(tlsCertFile(), pemEncode("CERTIFICATE", der), 0600); err != nil {
		rollbackTLSCerts()
		return nil, "cannot write certificate: " + err.Error()
	}
	if err := os.WriteFile(tlsKeyFile(), pemEncode("EC PRIVATE KEY", kb), 0600); err != nil {
		rollbackTLSCerts()
		return nil, "cannot write key: " + err.Error()
	}
	leaf, _ := x509.ParseCertificate(der)
	expiry := leaf.NotAfter.Format("2006-01-02 15:04:05")
	meta := tlsMeta{
		Domain:   ip.String(),
		IssuedAt: now.Format("2006-01-02 15:04:05"),
		Expiry:   expiry,
		Issuer:   "Hashem Panel Local CA (self-signed)",
		Source:   tlsSourceIP,
	}
	_ = os.WriteFile(tlsMetaFile(), mustJSON(meta), 0600)
	clearTLSBackups()
	startHTTPSListener()
	return map[string]any{
		"status":     "ok",
		"tls_status": "valid",
		"ip":         ip.String(),
		"expiry":     expiry,
		"issuer":     meta.Issuer,
		"https_url":  tlsHTTPSURL(),
	}, ""
}

// POST /api/tls/ip {"ip":"1.2.3.4","regenerate":true?} — empty ip = this server.
func handleTLSIPPost(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IP         string `json:"ip"`
		Regenerate bool   `json:"regenerate"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeAPIError(w, r, "E-TLS-13", "invalid JSON (send {\"ip\":\"1.2.3.4\"})")
		return
	}
	ipStr := strings.TrimSpace(body.IP)
	if ipStr == "" {
		if !body.Regenerate {
			writeAPIError(w, r, "E-TLS-13", "no IP given and the server IP cannot be detected here")
			return
		}
		if m := tlsMetaLoad(); m != nil && net.ParseIP(m.Domain) != nil {
			ipStr = m.Domain
		} else if cip := detectPublicIP(); net.ParseIP(cip) != nil {
			ipStr = cip
		} else {
			writeAPIError(w, r, "E-TLS-13", "no IP given and the server IP cannot be detected here")
			return
		}
	}
	ip := net.ParseIP(CleanHost(ipStr))
	if ip == nil {
		writeAPIError(w, r, "E-TLS-13", "not a valid IP address: "+ipStr)
		return
	}
	out, fail := tlsIssueIPCert(ip)
	if fail != "" {
		writeAPIError(w, r, "E-TLS-13", fail)
		return
	}
	LogSecurityAudit("TLS_IP_ISSUED", cfg.Username, ClientIP(r), "self-signed IP certificate for "+ip.String())
	recordError("E-TLS-00", r.Method+" "+r.URL.Path, "self-signed IP certificate for "+ip.String())
	writeJSON(w, out)
}

// GET /api/tls/ip/ca — download the CA cert (install in browser/OS once).
func handleTLSIPCAGet(w http.ResponseWriter, r *http.Request) {
	data, err := os.ReadFile(tlsCAFile())
	if err != nil {
		writeAPIError(w, r, "E-TLS-07", "no local CA yet — issue an IP certificate first")
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="hashem-ca.crt"`)
	_, _ = w.Write(data)
}
