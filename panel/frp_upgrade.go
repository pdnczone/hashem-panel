package main

// An update replaces hashem.sh and this binary, but install_frp_binaries keeps
// any FRP it finds, so a server set up by an older release kept that release's
// FRP through every update. A release before this one updates with its own
// (old) code, and the only new code that runs then is this binary starting:
// so on start it runs `hashem.sh cores-upgrade` when the local FRP is older
// than the pinned one. The script checks the configs, swaps the binaries and
// restarts the FRP services (and goes back when one does not come up).

import (
	"bytes"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// frpPinnedVersion is DEFAULT_FRP_VERSION in hashem.sh (a test keeps them equal).
const frpPinnedVersion = "0.71.0"

var errNoCoresUpgrade = errors.New("hashem.sh has no cores-upgrade command yet")

var (
	// frpUpgradeDelay lets a terminal update (hashem update) finish copying
	// the new hashem.sh: it restarts the panel before it does.
	frpUpgradeDelay = 90 * time.Second

	// frpUpgradeRun runs the script's cores-upgrade; a var for tests.
	frpUpgradeRun = func() ([]byte, error) {
		script, err := greScriptPath()
		if err != nil {
			return nil, err
		}
		if b, err := os.ReadFile(script); err != nil || !bytes.Contains(b, []byte("cores-upgrade)")) {
			return nil, errNoCoresUpgrade
		}
		return runCmdTimeout(10*time.Minute, "bash", script, "cores-upgrade")
	}
)

// frpVersionLess is a < b for "x.y.z" versions.
func frpVersionLess(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < 3; i++ {
		var x, y int
		if i < len(pa) {
			x, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(pb[i])
		}
		if x != y {
			return x < y
		}
	}
	return false
}

// frpUpgradeMarker holds the panel version and FRP pin of the last try.
func frpUpgradeMarker() string { return filepath.Join(configDir, "frp_upgrade_tried") }

func frpUpgradeKey() string { return panelVersion + " " + frpPinnedVersion }

// upgradeOldFrp tries once per panel version. When the try leaves FRP older
// (download blocked, a config the new FRP refuses), the next update tries
// again, as do `hashem update` and `hashem cores-upgrade`; panel restarts
// do not, so a blocked download is not repeated on each one.
func upgradeOldFrp() {
	time.Sleep(frpUpgradeDelay)
	v := localFrpVersion() // "" where there is no FRP (and on a dev machine)
	if v == "" || !frpVersionLess(v, frpPinnedVersion) {
		return
	}
	if b, _ := os.ReadFile(frpUpgradeMarker()); strings.TrimSpace(string(b)) == frpUpgradeKey() {
		return
	}
	out, err := frpUpgradeRun()
	if errors.Is(err, errNoCoresUpgrade) {
		return // the next start, with the new script in place, tries
	}
	last := ""
	for _, line := range strings.Split(strings.TrimSpace(stripANSI(string(out))), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			log.Printf("[frp-upgrade] %s", line)
			last = line
		}
	}
	if err != nil {
		log.Printf("[frp-upgrade] failed: %v", err)
		if last == "" {
			last = err.Error()
		}
		recordError("E-UPDATE-10", "frp-upgrade", "FRP "+v+" kept: "+last)
	}
	_ = os.WriteFile(frpUpgradeMarker(), []byte(frpUpgradeKey()+"\n"), 0600)
	frpVerMu.Lock()
	frpVerOnce = false // Diagnostics reads the new version
	frpVerMu.Unlock()
}
