package main

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"
)

// The Go pin and hashem.sh's DEFAULT_FRP_VERSION must be the same version, or
// the panel would ask the script for an upgrade it never does (or skip one).
func TestFrpPinnedVersionMatchesScript(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "hashem.sh"))
	if err != nil {
		t.Skip("hashem.sh not found:", err)
	}
	m := regexp.MustCompile(`(?m)^DEFAULT_FRP_VERSION="([^"]+)"`).FindSubmatch(b)
	if m == nil {
		t.Fatal("DEFAULT_FRP_VERSION not found in hashem.sh")
	}
	if string(m[1]) != frpPinnedVersion {
		t.Fatalf("hashem.sh pins FRP %s, the panel %s", m[1], frpPinnedVersion)
	}
}

func TestFrpVersionLess(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"0.61.1", "0.71.0", true},
		{"0.9.0", "0.71.0", true},
		{"0.71.0", "0.71.0", false},
		{"0.72.0", "0.71.0", false},
		{"1.0.0", "0.71.0", false},
		{"0.71.0", "0.71.1", true},
	} {
		if got := frpVersionLess(c.a, c.b); got != c.want {
			t.Errorf("%s < %s = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestUpgradeOldFrp(t *testing.T) {
	oldDir, oldDelay, oldRun := configDir, frpUpgradeDelay, frpUpgradeRun
	defer func() {
		configDir, frpUpgradeDelay, frpUpgradeRun = oldDir, oldDelay, oldRun
		frpVerMu.Lock()
		frpVerOnce = false
		frpVerMu.Unlock()
	}()
	frpUpgradeDelay = 0
	setLocal := func(v string) {
		frpVerMu.Lock()
		frpVerVal, frpVerAt, frpVerOnce = v, time.Now(), true
		frpVerMu.Unlock()
	}
	var runs int
	var runErr error
	frpUpgradeRun = func() ([]byte, error) { runs++; return []byte("[OK] FRP upgraded\n"), runErr }

	for _, c := range []struct {
		name, local string
		want        int
	}{
		{"no FRP here", "", 0},
		{"already pinned", frpPinnedVersion, 0},
		{"newer than pinned", "0.99.0", 0},
		{"older", "0.61.1", 1},
	} {
		configDir = t.TempDir()
		runs = 0
		setLocal(c.local)
		upgradeOldFrp()
		if runs != c.want {
			t.Errorf("%s: ran %d times, want %d", c.name, runs, c.want)
		}
	}

	// One try per pinned version: a restart after a failed try does not
	// download again (hashem update and hashem cores-upgrade still do).
	configDir = t.TempDir()
	runs = 0
	setLocal("0.61.1")
	upgradeOldFrp()
	setLocal("0.61.1")
	upgradeOldFrp()
	if runs != 1 {
		t.Errorf("second start ran the upgrade again (%d runs)", runs)
	}
	// The next panel version (an update from the web page) tries again.
	oldVer := panelVersion
	panelVersion = "v9.9.9-test"
	setLocal("0.61.1")
	upgradeOldFrp()
	panelVersion = oldVer
	if runs != 2 {
		t.Errorf("a new panel version did not try again (%d runs)", runs)
	}

	// An old hashem.sh without the command is no try: the next start runs it.
	configDir = t.TempDir()
	runs = 0
	runErr = errNoCoresUpgrade
	setLocal("0.61.1")
	upgradeOldFrp()
	runErr = nil
	setLocal("0.61.1")
	upgradeOldFrp()
	if runs != 2 {
		t.Errorf("after an old script the upgrade ran %d times, want 2", runs)
	}
}
