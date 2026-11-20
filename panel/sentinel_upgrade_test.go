package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A panel update brings an installed Sentinel up to the embedded bundle once:
// the bundle is unpacked, install.sh runs, and the stamp stops it running
// again. Without Sentinel, without a license, or once up to date, nothing runs.
func TestSentinelUpgradeIfStale(t *testing.T) {
	oldDelay, oldRun, oldActive, oldHook := sentinelUpgradeDelay, sentinelRunInstaller, sentinelSystemctlActive, sentinelSystemctlHook
	var runs []string
	sentinelUpgradeDelay = 0
	sentinelRunInstaller = func(script string) ([]byte, error) { runs = append(runs, script); return nil, nil }
	sentinelSystemctlActive = func() bool { return true }
	sentinelSystemctlHook = func(args ...string) {}
	activeLicenseMu.Lock()
	oldLic, oldAt := activeLicense, licenseCheckedAt
	activeLicenseMu.Unlock()
	t.Cleanup(func() {
		sentinelUpgradeDelay, sentinelRunInstaller, sentinelSystemctlActive, sentinelSystemctlHook = oldDelay, oldRun, oldActive, oldHook
		activeLicenseMu.Lock()
		activeLicense, licenseCheckedAt = oldLic, oldAt
		activeLicenseMu.Unlock()
		_ = os.Remove(sentinelUnitPath)
		_ = os.RemoveAll(sentinelDir)
	})
	setLic := func(features ...string) {
		activeLicenseMu.Lock()
		activeLicense = nil
		if features != nil {
			activeLicense = &LicensePayload{Customer: "t", Features: features, ExpiresAt: time.Now().Add(time.Hour).Unix()}
		}
		licenseCheckedAt = time.Now()
		activeLicenseMu.Unlock()
	}

	setLic("sentinel")
	if upgradeSentinelIfStale() || len(runs) != 0 {
		t.Fatal("upgraded without Sentinel installed")
	}

	_ = os.MkdirAll(filepath.Dir(sentinelUnitPath), 0755)
	_ = os.WriteFile(sentinelUnitPath, []byte("[Service]\n"), 0644)
	setLic()
	if upgradeSentinelIfStale() || len(runs) != 0 {
		t.Fatal("upgraded without a Sentinel license")
	}

	setLic("sentinel")
	if !upgradeSentinelIfStale() || len(runs) != 1 {
		t.Fatalf("stale Sentinel not upgraded (runs %v)", runs)
	}
	if runs[0] != filepath.Join(sentinelDir, "install.sh") {
		t.Fatalf("ran %q", runs[0])
	}
	app, err := os.ReadFile(filepath.Join(sentinelDir, "app.py"))
	if err != nil || !strings.Contains(string(app), "hysteria2") {
		t.Fatal("bundle not unpacked, or it lacks Hysteria2 support")
	}
	if b, _ := os.ReadFile(sentinelBundleStamp()); strings.TrimSpace(string(b)) != sentinelBundleHash() {
		t.Fatalf("stamp = %q", b)
	}

	if upgradeSentinelIfStale() || len(runs) != 1 {
		t.Fatal("upgraded again with the same bundle")
	}
}
