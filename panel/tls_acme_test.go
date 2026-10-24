package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func writeMeta(t *testing.T, m tlsMeta) {
	t.Helper()
	b, _ := json.Marshal(m)
	if err := os.WriteFile(tlsMetaFile(), b, 0600); err != nil {
		t.Fatal(err)
	}
}

func writeLive(t *testing.T, domain, cn string) string {
	t.Helper()
	live := filepath.Join(letsencryptLiveDir, domain)
	_ = os.MkdirAll(live, 0700)
	c, k := testCertPEM(t, cn)
	_ = os.WriteFile(filepath.Join(live, "fullchain.pem"), []byte(c), 0600)
	_ = os.WriteFile(filepath.Join(live, "privkey.pem"), []byte(k), 0600)
	return c
}

func freeTLSPort(t *testing.T) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg.TLSPort = l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
}

// Metas written before Source existed still say where the certificate came from.
func TestTLSSourceOfOldMetas(t *testing.T) {
	withTLSDir(t)
	writeLive(t, "le.example", "le.example")
	for _, c := range []struct {
		m    tlsMeta
		want string
	}{
		{tlsMeta{Domain: "203.0.113.7", Issuer: "Hashem Panel Local CA (self-signed)"}, tlsSourceIP},
		{tlsMeta{Domain: "le.example", Issuer: "R11"}, tlsSourceLE},
		{tlsMeta{Domain: "own.example", Issuer: "Sectigo"}, tlsSourceCustom},
		{tlsMeta{Domain: "le.example", Source: tlsSourceCustom}, tlsSourceCustom},
	} {
		if got := tlsSource(&c.m); got != c.want {
			t.Errorf("%+v: %s, want %s", c.m, got, c.want)
		}
	}
}

// The hourly auto-renew used to copy certbot's lineage over a custom
// certificate for the same name, and ran certbot for IP certificates.
func TestTLSRenewTickLeavesOwnCertificates(t *testing.T) {
	withTLSDir(t)
	freeTLSPort(t)
	writeServedCert(t, "mine.example")
	before, _ := os.ReadFile(tlsCertFile())
	writeMeta(t, tlsMeta{Domain: "panel.example", Source: tlsSourceCustom})
	writeLive(t, "panel.example", "certbot.example")

	var last time.Time
	tlsRenewTick(time.Now(), &last)
	if got, _ := os.ReadFile(tlsCertFile()); string(got) != string(before) {
		t.Fatal("auto-renew replaced a custom certificate")
	}
}

func TestTLSRenewCustomIsRefused(t *testing.T) {
	withTLSDir(t)
	writeServedCert(t, "mine.example")
	writeMeta(t, tlsMeta{Domain: "mine.example", Source: tlsSourceCustom})
	_, err := tlsRenewCurrent()
	var f *tlsFail
	if !errors.As(err, &f) || f.code != "E-TLS-14" {
		t.Fatalf("got %v, want E-TLS-14", err)
	}
}

func TestTLSRenewIPCertRegenerates(t *testing.T) {
	withTLSDir(t)
	freeTLSPort(t)
	if _, fail := tlsIssueIPCert(net.ParseIP("203.0.113.7")); fail != "" {
		t.Fatal(fail)
	}
	before, _ := os.ReadFile(tlsCertFile())
	renewed, err := tlsRenewCurrent()
	if err != nil || !renewed {
		t.Fatalf("renew IP certificate: %v %v", renewed, err)
	}
	if after, _ := os.ReadFile(tlsCertFile()); string(after) == string(before) {
		t.Fatal("IP certificate not regenerated")
	}
}

func TestCertbotReason(t *testing.T) {
	out := []byte(`Saving debug log to /var/log/letsencrypt/letsencrypt.log
Requesting a certificate for panel.example.com

Certbot failed to authenticate some domains (authenticator: standalone). The Certificate Authority reported these problems:
  Domain: panel.example.com
  Type:   connection
  Detail: 1.2.3.4: Fetching http://panel.example.com/.well-known/acme-challenge/x: Timeout during connect (likely firewall problem)

Hint: The Certificate Authority failed to download the challenge files from the temporary standalone webserver started by Certbot on port 80.

Some challenges have failed.
Ask for help or search for solutions at https://community.letsencrypt.org. See the logfile /var/log/letsencrypt/letsencrypt.log or re-run Certbot with -v for more details.`)
	got := certbotReason(out)
	if !strings.Contains(got, "Detail: 1.2.3.4") || !strings.Contains(got, "Type:   connection") {
		t.Errorf("reason lost the detail: %q", got)
	}
	if strings.Contains(got, "Saving debug log") || strings.Contains(got, "Ask for help") {
		t.Errorf("reason kept noise: %q", got)
	}
}

// Issue installs certbot when it is missing, opens the firewall, names the
// lineage after the domain and serves the result.
func TestTLSIssueInstallsCertbot(t *testing.T) {
	withTLSDir(t)
	freeTLSPort(t)
	oldRunner, oldLook, oldPkg, old80 := runner, certbotLookPath, pkgLookPath, isPort80Available
	t.Cleanup(func() { runner, certbotLookPath, pkgLookPath, isPort80Available = oldRunner, oldLook, oldPkg, old80 })
	isPort80Available = func() bool { return true }
	pkgLookPath = func(name string) (string, error) {
		if name == "apt-get" {
			return "/usr/bin/apt-get", nil
		}
		return "", errors.New("not found")
	}
	var mu sync.Mutex
	installed := false
	var calls []string
	certbotLookPath = func() error {
		mu.Lock()
		defer mu.Unlock()
		if installed {
			return nil
		}
		return errors.New("not found")
	}
	runner = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, name+" "+strings.Join(args, " "))
		switch {
		case name == "apt-get" && len(args) > 0 && args[0] == "install":
			installed = true
		case name == "ufw" && len(args) == 1:
			return []byte("Status: active\n"), nil
		case name == "certbot":
			writeLive(t, "panel.example.com", "panel.example.com")
		}
		return nil, nil
	}
	if err := tlsIssueLetsEncrypt("https://Panel.Example.com/", "", 0, true); err != nil {
		t.Fatal(err)
	}
	all := strings.Join(calls, "\n")
	for _, want := range []string{"apt-get install -y -q certbot", "ufw allow 80/tcp", "--cert-name panel.example.com -d panel.example.com", "--register-unsafely-without-email"} {
		if !strings.Contains(all, want) {
			t.Errorf("no %q in:\n%s", want, all)
		}
	}
	m := tlsMetaLoad()
	if m == nil || m.Domain != "panel.example.com" || m.Source != tlsSourceLE {
		t.Fatalf("meta: %+v", m)
	}
}

func TestTLSIssueNamesPort80Owner(t *testing.T) {
	withTLSDir(t)
	oldRunner, old80 := runner, isPort80Available
	t.Cleanup(func() { runner, isPort80Available = oldRunner, old80 })
	isPort80Available = func() bool { return false }
	runner = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "ss" {
			return []byte(`LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:(("nginx",pid=812,fd=6))`), nil
		}
		return nil, errors.New("no host commands")
	}
	err := tlsIssueLetsEncrypt("panel.example.com", "", 0, true)
	var f *tlsFail
	if !errors.As(err, &f) || f.code != "E-TLS-10" || !strings.Contains(f.msg, "nginx") {
		t.Fatalf("got %v", err)
	}
}
