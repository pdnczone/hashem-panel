package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A certificate issued in the panel reaches Sentinel: the cert is copied, a
// systemd drop-in turns on HTTPS with it, Sentinel restarts once, and the
// status URL becomes https on the certificate's name. Removing the
// certificate takes it all back.
func TestSentinelTLS_SyncFollowsPanelCert(t *testing.T) {
	var calls []string
	oldHook := sentinelSystemctlHook
	sentinelSystemctlHook = func(args ...string) { calls = append(calls, strings.Join(args, " ")) }
	t.Cleanup(func() {
		sentinelSystemctlHook = oldHook
		_ = os.Remove(sentinelUnitPath)
		_ = os.Remove(sentinelTLSDropIn)
		_ = os.RemoveAll(tlsDir())
	})

	crt, key := testCertPEM(t, "panel.example.com")
	_ = os.MkdirAll(tlsDir(), 0700)
	if err := os.WriteFile(tlsCertFile(), []byte(crt), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tlsKeyFile(), []byte(key), 0600); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(tlsMetaFile(), mustJSON(tlsMeta{Domain: "panel.example.com", Source: tlsSourceCustom}), 0600)

	// Not installed: nothing happens.
	if syncSentinelTLS() {
		t.Fatal("synced without Sentinel installed")
	}

	_ = os.MkdirAll(filepath.Dir(sentinelUnitPath), 0755)
	_ = os.WriteFile(sentinelUnitPath, []byte("[Service]\n"), 0644)
	if !syncSentinelTLS() {
		t.Fatal("first sync changed nothing")
	}
	got, _ := os.ReadFile(sentinelTLSCertPath())
	if string(got) != crt {
		t.Fatal("certificate not copied for Sentinel")
	}
	di, _ := os.ReadFile(sentinelTLSDropIn)
	for _, want := range []string{"SENTINEL_USE_HTTPS=1", "SENTINEL_SSL_CERT=" + sentinelTLSCertPath(), "SENTINEL_SSL_KEY=" + sentinelTLSKeyPath()} {
		if !strings.Contains(string(di), want) {
			t.Fatalf("drop-in lacks %q:\n%s", want, di)
		}
	}
	if strings.Join(calls, ",") != "daemon-reload,try-restart sentinel.service" {
		t.Fatalf("systemctl calls = %v", calls)
	}

	// Same certificate again: no restart.
	calls = nil
	if syncSentinelTLS() || len(calls) != 0 {
		t.Fatalf("unchanged certificate restarted Sentinel: %v", calls)
	}

	// Status shows https on the certificate's name.
	_ = os.WriteFile(sentinelCredentialsPath(), []byte("port=34567\npath=abc\npassword=x\n"), 0600)
	st := GetSentinelStatus()
	if !st.HTTPS || st.Host != "panel.example.com" || !strings.HasPrefix(st.URL, "https://panel.example.com:34567/") {
		t.Fatalf("status = %+v", st)
	}

	// A renewed certificate is copied and Sentinel restarts.
	crt2, key2 := testCertPEM(t, "panel.example.com")
	_ = os.WriteFile(tlsCertFile(), []byte(crt2), 0600)
	_ = os.WriteFile(tlsKeyFile(), []byte(key2), 0600)
	calls = nil
	if !syncSentinelTLS() || len(calls) != 2 {
		t.Fatalf("renewal not synced: %v", calls)
	}

	// Certificate removed: Sentinel goes back to its own setting.
	_ = os.Remove(tlsCertFile())
	if !syncSentinelTLS() {
		t.Fatal("removal not synced")
	}
	if sentinelTLSActive() {
		t.Fatal("drop-in left after the certificate was removed")
	}
	if _, err := os.Stat(sentinelTLSKeyPath()); err == nil {
		t.Fatal("key copy left after the certificate was removed")
	}
	if st := GetSentinelStatus(); st.HTTPS || !strings.HasPrefix(st.URL, "http://") {
		t.Fatalf("status after removal = %+v", st)
	}
}
