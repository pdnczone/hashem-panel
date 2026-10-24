package main

import (
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func withTLSDir(t *testing.T) {
	t.Helper()
	oldDir, oldPort, oldLE := configDir, cfg.TLSPort, letsencryptLiveDir
	configDir = t.TempDir()
	letsencryptLiveDir = filepath.Join(configDir, "le")
	t.Cleanup(func() {
		stopHTTPSListener()
		configDir, cfg.TLSPort, letsencryptLiveDir = oldDir, oldPort, oldLE
	})
	if err := os.MkdirAll(tlsDir(), 0700); err != nil {
		t.Fatal(err)
	}
}

func writeServedCert(t *testing.T, cn string) {
	t.Helper()
	c, k := testCertPEM(t, cn)
	if err := os.WriteFile(tlsCertFile(), []byte(c), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tlsKeyFile(), []byte(k), 0600); err != nil {
		t.Fatal(err)
	}
}

func servedCN(t *testing.T, port int) string {
	t.Helper()
	var cn string
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := tls.Dial("tcp", "127.0.0.1:"+strconv.Itoa(port), &tls.Config{InsecureSkipVerify: true})
		if err == nil {
			cn = conn.ConnectionState().PeerCertificates[0].Subject.CommonName
			_ = conn.Close()
			return cn
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("HTTPS listener on %d not reachable", port)
	return ""
}

// M7: a certificate change is picked up without restarting the listener, so
// the request that triggered it (renew/upload over HTTPS) is not cut.
func TestHTTPSCertReloadKeepsListener(t *testing.T) {
	withTLSDir(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg.TLSPort = l.Addr().(*net.TCPAddr).Port
	_ = l.Close()

	writeServedCert(t, "first.example")
	startHTTPSListener()
	httpsSrvMu.Lock()
	srv := httpsSrv
	httpsSrvMu.Unlock()
	if got := servedCN(t, cfg.TLSPort); got != "first.example" {
		t.Fatalf("served %q", got)
	}

	writeServedCert(t, "second.example")
	startHTTPSListener()
	httpsSrvMu.Lock()
	same := httpsSrv == srv
	httpsSrvMu.Unlock()
	if !same {
		t.Fatal("listener was replaced instead of reloading the certificate")
	}
	if got := servedCN(t, cfg.TLSPort); got != "second.example" {
		t.Fatalf("new certificate not served, got %q", got)
	}
}

// M7: a certificate renewed by certbot's own timer is copied in and served.
func TestTLSRenewTickInstallsRenewedCert(t *testing.T) {
	withTLSDir(t)
	// A free port: a privileged one fails to bind on Linux, and the listener
	// goroutine then records the error while cleanup resets configDir (a race).
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg.TLSPort = l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	writeServedCert(t, "old.example")
	meta, _ := json.Marshal(tlsMeta{Domain: "panel.example"})
	_ = os.WriteFile(tlsMetaFile(), meta, 0600)

	live := filepath.Join(letsencryptLiveDir, "panel.example")
	_ = os.MkdirAll(live, 0700)
	c, k := testCertPEM(t, "renewed.example")
	_ = os.WriteFile(filepath.Join(live, "fullchain.pem"), []byte(c), 0600)
	_ = os.WriteFile(filepath.Join(live, "privkey.pem"), []byte(k), 0600)

	var last time.Time
	tlsRenewTick(time.Now(), &last)
	got, _ := os.ReadFile(tlsCertFile())
	if string(got) != c {
		t.Fatal("renewed certificate not installed")
	}
}

// M11: no GRE interface is only a problem where GRE is used.
func TestGreExpected(t *testing.T) {
	old := engineUnitDir
	engineUnitDir = t.TempDir()
	t.Cleanup(func() { engineUnitDir = old })
	if greExpected(tunnelStatus{Engine: "backhaul"}) {
		t.Error("standalone Backhaul does not use GRE")
	}
	if greExpected(tunnelStatus{}) {
		t.Error("no GRE unit installed: GRE not expected")
	}
	_ = os.WriteFile(filepath.Join(engineUnitDir, "gre-tunnel.service"), []byte("[Service]\n"), 0644)
	if !greExpected(tunnelStatus{Engine: "frp"}) {
		t.Error("FRP over GRE with a gre-tunnel unit expects GRE")
	}
}

// L16: an empty snapshot must not wipe the latency history.
func TestFleetRecordIgnoresEmptySnapshot(t *testing.T) {
	old := configDir
	configDir = t.TempDir()
	t.Cleanup(func() { configDir = old })
	fleetRecord([]peerLive{mkLive(1, true, true, true, "9ms")}, time.Now())
	fleetRecord(nil, time.Now())
	fleetMu.Lock()
	n := len(fleetHist[1])
	fleetMu.Unlock()
	if n != 1 {
		t.Fatalf("history after empty snapshot: %d samples, want 1", n)
	}
}

// L9: after a reset the tracker only primes, it does not alert on old state.
func TestAlertTrackerResetPrimesAgain(t *testing.T) {
	tr := newAlertTracker()
	now := time.Now()
	c := alertConfig{MinGapSec: 0}
	tr.observe(now, []linkSnap{{Name: "p1", State: stateHealthy}}, c)
	tr.reset()
	if ev := tr.observe(now, []linkSnap{{Name: "p1", State: stateDown}}, c); len(ev) != 0 {
		t.Fatalf("alert fired on the first observation after reset: %+v", ev)
	}
	if ev := tr.observe(now.Add(time.Minute), []linkSnap{{Name: "p1", State: stateHealthy}}, c); len(ev) != 1 {
		t.Fatalf("real change after reset not reported: %+v", ev)
	}
}

// L3: license errors carry an error_code the UI can show.
func TestLicensePostErrorCodes(t *testing.T) {
	if licenseErrCode(errString("license expired on 2026-01-01")) != "E-LIC-04" ||
		licenseErrCode(errString("license locked to machine a, this server is b")) != "E-LIC-05" ||
		licenseErrCode(errString("license signature verification failed")) != "E-LIC-03" ||
		licenseErrCode(errString("invalid license format (must be payload.signature)")) != "E-LIC-02" {
		t.Fatal("wrong license error mapping")
	}
	rr := httptest.NewRecorder()
	handleLicensePost(rr, httptest.NewRequest("POST", "/api/license", strings.NewReader(`{"key":"garbage"}`)))
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Header().Get("Content-Type"), "application/json") ||
		!strings.Contains(rr.Body.String(), `"error_code":"E-LIC-02"`) {
		t.Fatalf("got %d %q %s", rr.Code, rr.Header().Get("Content-Type"), rr.Body.String())
	}
}

type errString string

func (e errString) Error() string { return string(e) }

func postWatchdog(t *testing.T, body string) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/watchdog", strings.NewReader(body))
	req.RemoteAddr = "198.51.100.20:1234"
	handleWatchdogPost(rr, req)
	return rr
}

// L7: updating one Telegram field keeps the others.
func TestWatchdogTelegramPartialUpdate(t *testing.T) {
	withPro(t)
	old := configDir
	configDir = t.TempDir()
	t.Cleanup(func() { configDir = old })
	if rr := postWatchdog(t, `{"action":"set-telegram","bot_token":"123:abc","chat_id":"-100","route":"direct","tunnel_port":8443}`); rr.Code != http.StatusOK {
		t.Fatalf("setup: %d %s", rr.Code, rr.Body.String())
	}
	if rr := postWatchdog(t, `{"action":"set-telegram","route":"tunnel"}`); rr.Code != http.StatusOK {
		t.Fatalf("update: %d %s", rr.Code, rr.Body.String())
	}
	c := loadWatchdogConfig()
	if c.TGChatID != "-100" || c.TGTunnelPort != 8443 || c.TGRoute != "tunnel" {
		t.Fatalf("partial update wiped fields: %+v", c)
	}
}

// M6: the backup key is only released with the panel password.
func TestBackupKeyExportNeedsPassword(t *testing.T) {
	withPro(t)
	setupAuthCfg(t, hashPassword("Secret-Pass-1"))
	_ = os.WriteFile(filepath.Join(configDir, "backup.key"), []byte("k3y-material\n"), 0600)
	if rr := postWatchdog(t, `{"action":"backup-key","password":"wrong"}`); rr.Code == http.StatusOK || strings.Contains(rr.Body.String(), "k3y") {
		t.Fatalf("key released with a wrong password: %d %s", rr.Code, rr.Body.String())
	}
	rr := postWatchdog(t, `{"action":"backup-key","password":"Secret-Pass-1"}`)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"key":"k3y-material"`) {
		t.Fatalf("got %d %s", rr.Code, rr.Body.String())
	}
}

// M9: without Bagher, the snapshot status runs nothing and creates no key.
func TestBagherSnapshotStatusWithoutConfig(t *testing.T) {
	old := configDir
	configDir = t.TempDir()
	t.Cleanup(func() { configDir = old })
	st := getSSHFwdSnapshotStatus()
	if st["has_config"] != false || st["is_active"] != false {
		t.Fatalf("got %+v", st)
	}
	if _, err := os.Stat(defaultSSHFwdKeyPath()); err == nil && strings.HasPrefix(defaultSSHFwdKeyPath(), configDir) {
		t.Fatal("snapshot status generated an SSH key")
	}
}
