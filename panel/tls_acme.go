package main

// Let's Encrypt for the panel, shared by the Settings tab (/api/tls) and the
// terminal (gre-panel tls ..., which hashem.sh calls). What used to go wrong:
// certbot missing (the panel only said "install it"), a firewall dropping port
// 80 or the HTTPS port, the certbot error buried in its full log, and "Renew"
// or the hourly auto-renew calling certbot for an IP or custom certificate.

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Where a certificate came from (tlsMeta.Source).
const (
	tlsSourceLE     = "letsencrypt"
	tlsSourceCustom = "custom"
	tlsSourceIP     = "ip"
)

// tlsSource tells what installed the current certificate. Metas written before
// Source existed: the local CA means an IP certificate, a certbot lineage for
// the name means Let's Encrypt, anything else was the admin's own.
func tlsSource(m *tlsMeta) string {
	if m == nil {
		return ""
	}
	if m.Source != "" {
		return m.Source
	}
	if strings.Contains(m.Issuer, "Hashem Panel Local CA") || net.ParseIP(m.Domain) != nil {
		return tlsSourceIP
	}
	if m.Domain != "" {
		if _, err := os.Stat(filepath.Join(letsencryptLiveDir, m.Domain, "fullchain.pem")); err == nil {
			return tlsSourceLE
		}
	}
	return tlsSourceCustom
}

// certbotLookPath and pkgLookPath are exec.LookPath; tests replace them.
var (
	certbotLookPath = func() error { _, err := exec.LookPath("certbot"); return err }
	pkgLookPath     = exec.LookPath
)

// ensureCertbot installs certbot when it is missing: apt, dnf, yum, then snap.
func ensureCertbot() error {
	if certbotLookPath() == nil {
		return nil
	}
	tries := [][]string{
		{"apt-get", "install", "-y", "-q", "certbot"},
		{"dnf", "install", "-y", "certbot"},
		{"yum", "install", "-y", "certbot"},
		{"snap", "install", "--classic", "certbot"},
	}
	var last string
	for _, t := range tries {
		if _, err := pkgLookPath(t[0]); err != nil {
			continue
		}
		if t[0] == "apt-get" { // a stale package list fails the install
			_, _ = runCmdTimeout(3*time.Minute, "apt-get", "update", "-q")
		}
		out, err := runCmdTimeout(5*time.Minute, t[0], t[1:]...)
		if t[0] == "snap" && err == nil {
			_, _ = runCmdTimeout(10*time.Second, "ln", "-sf", "/snap/bin/certbot", "/usr/bin/certbot")
		}
		if certbotLookPath() == nil {
			return nil
		}
		last = strings.TrimSpace(string(out))
	}
	if last == "" {
		last = "no package manager found (apt, dnf, yum or snap)"
	}
	return fmt.Errorf("certbot is not installed and could not be installed: %s", lastLines(last, 3))
}

// firewallOpenTCP allows a TCP port in ufw or firewalld when one of them is
// active. Without it the ACME challenge on :80 and the panel's HTTPS port time
// out while everything else looks right.
func firewallOpenTCP(port int) {
	p := strconv.Itoa(port)
	if out, err := runCmdTimeout(5*time.Second, "ufw", "status"); err == nil && strings.Contains(string(out), "Status: active") {
		_, _ = runCmdTimeout(10*time.Second, "ufw", "allow", p+"/tcp")
	}
	if out, err := runCmdTimeout(5*time.Second, "firewall-cmd", "--state"); err == nil && strings.TrimSpace(string(out)) == "running" {
		_, _ = runCmdTimeout(10*time.Second, "firewall-cmd", "--add-port="+p+"/tcp")
		_, _ = runCmdTimeout(10*time.Second, "firewall-cmd", "--permanent", "--add-port="+p+"/tcp")
	}
}

// port80Owner names what listens on TCP :80 ("nginx" etc.), "" when unknown.
func port80Owner() string {
	out, err := runCmdTimeout(5*time.Second, "ss", "-Htlnp", "sport = :80")
	if err != nil {
		return ""
	}
	s := string(out)
	if i := strings.Index(s, `(("`); i >= 0 {
		s = s[i+3:]
		if j := strings.Index(s, `"`); j > 0 {
			return s[:j]
		}
	}
	return ""
}

func port80Busy() string {
	if who := port80Owner(); who != "" {
		return "port 80 is in use by " + who
	}
	return "port 80 is in use by another program"
}

// certbotReason keeps the lines of a certbot log that say why it failed.
func certbotReason(out []byte) string {
	var keep []string
	for _, l := range strings.Split(string(out), "\n") {
		t := strings.TrimSpace(l)
		low := strings.ToLower(t)
		if strings.HasPrefix(low, "detail:") || strings.HasPrefix(low, "type:") || strings.HasPrefix(low, "domain:") ||
			strings.Contains(low, "error") || strings.Contains(low, "too many") || strings.Contains(low, "timeout") ||
			strings.Contains(low, "problem binding") || strings.Contains(low, "could not") {
			if !strings.HasPrefix(low, "ask for help") && !strings.Contains(low, "see the logfile") {
				keep = append(keep, t)
			}
		}
	}
	if len(keep) == 0 {
		return lastLines(strings.TrimSpace(string(out)), 4)
	}
	if len(keep) > 6 {
		keep = keep[:6]
	}
	return strings.Join(keep, "\n")
}

func lastLines(s string, n int) string {
	ls := strings.Split(s, "\n")
	if len(ls) > n {
		ls = ls[len(ls)-n:]
	}
	return strings.Join(ls, "\n")
}

// tlsFail is an error with the catalog code the API answers with.
type tlsFail struct {
	code, msg string
}

func (e *tlsFail) Error() string { return e.msg }

// tlsIssueLetsEncrypt gets a Let's Encrypt certificate for domain and serves
// it on the HTTPS port. Tunnels are never touched; on failure the previous
// certificate stays.
func tlsIssueLetsEncrypt(domain, email string, port int, skipDNS bool) error {
	domain = strings.ToLower(CleanHost(domain))
	email = strings.TrimSpace(email)
	if !tlsDomainRe.MatchString(domain) {
		return &tlsFail{"E-TLS-02", "invalid domain name: " + domain}
	}
	target := effectiveTLSPort()
	if port != 0 {
		if port < 1 || port > 65535 {
			return &tlsFail{"E-TLS-03", ""}
		}
		target = port
	}
	if err := checkPortConflict(target); err != nil {
		return &tlsFail{"E-TLS-10", err.Error()}
	}
	if !isPort80Available() {
		return &tlsFail{"E-TLS-10", port80Busy() + ". Let's Encrypt checks the domain on port 80: stop that program for a minute, or put the panel behind it as a reverse proxy."}
	}
	if !skipDNS {
		if _, err := checkDomainDNS(domain); err != nil {
			return &tlsFail{"E-TLS-09", err.Error()}
		}
	}
	if err := ensureCertbot(); err != nil {
		return &tlsFail{"E-TLS-04", err.Error()}
	}
	if port != 0 && port != cfg.TLSPort {
		cfg.TLSPort = port
		saveCfg()
	}
	firewallOpenTCP(80)
	firewallOpenTCP(target)

	backupTLSCerts()
	args := []string{"certonly", "--standalone", "--non-interactive", "--agree-tos",
		"--preferred-challenges", "http", "--http-01-port", "80",
		"--cert-name", domain, "-d", domain}
	if email != "" {
		args = append(args, "-m", email)
	} else {
		args = append(args, "--register-unsafely-without-email")
	}
	out, err := runCmdTimeout(4*time.Minute, "certbot", args...)
	if err != nil {
		rollbackTLSCerts()
		recordError("E-TLS-05", "certbot certonly "+domain, strings.TrimSpace(string(out)))
		return &tlsFail{"E-TLS-05", certbotReason(out)}
	}
	if err := tlsInstallFrom(filepath.Join(letsencryptLiveDir, domain), domain, email); err != nil {
		rollbackTLSCerts()
		return &tlsFail{"E-TLS-06", err.Error()}
	}
	clearTLSBackups()
	startHTTPSListener()
	return nil
}

// tlsRenewCurrent renews the certificate the panel serves, the way it was made:
// certbot for Let's Encrypt, a new server certificate for the IP one. A custom
// certificate can only be replaced by the admin. renewed=false: certbot found
// it not due yet.
func tlsRenewCurrent() (renewed bool, err error) {
	m := tlsMetaLoad()
	if m == nil || m.Domain == "" || !tlsHasCert() {
		return false, &tlsFail{"E-TLS-07", ""}
	}
	switch tlsSource(m) {
	case tlsSourceIP:
		ip := net.ParseIP(m.Domain)
		if ip == nil {
			return false, &tlsFail{"E-TLS-13", "the IP certificate has no IP in its record; issue it again"}
		}
		if _, fail := tlsIssueIPCert(ip); fail != "" {
			return false, &tlsFail{"E-TLS-13", fail}
		}
		return true, nil
	case tlsSourceCustom:
		return false, &tlsFail{"E-TLS-14", ""}
	}
	if err := ensureCertbot(); err != nil {
		return false, &tlsFail{"E-TLS-04", err.Error()}
	}
	if !isPort80Available() {
		return false, &tlsFail{"E-TLS-10", port80Busy() + "; certbot needs it for a minute to renew."}
	}
	firewallOpenTCP(80)
	before, _ := os.ReadFile(filepath.Join(letsencryptLiveDir, m.Domain, "fullchain.pem"))
	backupTLSCerts()
	out, err := runCmdTimeout(4*time.Minute, "certbot", "renew", "--cert-name", m.Domain, "--non-interactive")
	if err != nil {
		rollbackTLSCerts()
		recordError("E-TLS-05", "certbot renew "+m.Domain, strings.TrimSpace(string(out)))
		return false, &tlsFail{"E-TLS-05", certbotReason(out)}
	}
	if err := tlsInstallFrom(filepath.Join(letsencryptLiveDir, m.Domain), m.Domain, m.Email); err != nil {
		rollbackTLSCerts()
		return false, &tlsFail{"E-TLS-06", err.Error()}
	}
	clearTLSBackups()
	startHTTPSListener()
	after, _ := os.ReadFile(filepath.Join(letsencryptLiveDir, m.Domain, "fullchain.pem"))
	return string(before) != string(after), nil
}

// tlsRemoveAll stops HTTPS and deletes the panel's copy of the certificate.
// certbot's own lineage in /etc/letsencrypt stays (a later issue reuses it).
func tlsRemoveAll() {
	stopHTTPSListener()
	_ = os.Remove(tlsCertFile())
	_ = os.Remove(tlsKeyFile())
	_ = os.Remove(tlsMetaFile())
	clearTLSBackups()
}
