package main

// Settings → Danger Zone: remove every tunnel of this server at once.
//
// What goes: the FRP / Backhaul / GRE tunnels (the first one and every
// foreign server added after it), the extra Iran hubs a foreign server
// serves (join-hub), the Xray tunnel's links, Bagher and the Spoof tunnel,
// each through the same removal its own tab uses. What stays: the panel, its
// login and settings, the license, the customers' records, the Watchdog's
// backups, and the cluster's links to other hubs.
//
// It asks for the login password and a typed phrase, it is never relayed
// from a central or run from the Telegram bot (its path is in no relay
// group), and it makes a backup first when it can.

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// dangerResetPhrase is what the operator types to confirm.
const dangerResetPhrase = "DELETE ALL TUNNELS"

// dangerRemoveTimeout: removing many tunnels with ufw can take minutes.
var dangerRemoveTimeout = 5 * time.Minute

var dangerMu sync.Mutex

// dangerStep is one part of the reset, as the page shows it.
type dangerStep struct {
	Part   string `json:"part"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// The parts of the reset (vars for tests: they touch systemd and the script).
var (
	dangerBackup = func() (string, error) { return runWatchdogCmd("backup", "now") }

	dangerRemoveHubs = func() (int, error) {
		var errs []string
		n := 0
		for _, h := range readJoinedHubs() {
			if out, err := runHashemCluster(time.Minute, "leave-hub", "--id", fmt.Sprint(h.ID)); err != nil {
				errs = append(errs, fmt.Sprintf("%s: %s", h.Name, lastLines(out, 2)))
				continue
			}
			n++
		}
		joinedMu.Lock()
		joinedAt = time.Time{}
		joinedMu.Unlock()
		if len(errs) > 0 {
			return n, errors.New(strings.Join(errs, "; "))
		}
		return n, nil
	}

	dangerRemoveXray = func() (int, error) {
		xrayMu.Lock()
		defer xrayMu.Unlock()
		st := loadXrayState()
		for _, l := range st.Links {
			stopXrayLink(l.ID, true)
		}
		n := len(st.Links)
		st.Links = nil
		return n, saveXrayState(st)
	}

	dangerRemoveBagher = func() (int, error) {
		sshFwdMu.Lock()
		defer sshFwdMu.Unlock()
		cfg := loadSSHFwdConfigLocked()
		n := len(cfg.Links)
		if cfg.Enabled && n == 0 {
			n = 1
		}
		if err := cleanSSHFwd(); err != nil {
			return n, err
		}
		dropLinkNames("bagher-")
		return n, nil
	}

	dangerRemoveSpoof = func() (int, error) {
		s := loadSpoofState()
		if !s.Enabled {
			return 0, nil
		}
		err := stopSpoof()
		s.Enabled, s.LastError = false, ""
		if serr := saveSpoofState(s); err == nil {
			err = serr
		}
		return 1, err
	}

	// dangerRemoveTunnels is hashem.sh remove-tunnel --force: every FRP,
	// Backhaul and GRE tunnel, their units, interfaces, rules and configs.
	dangerRemoveTunnels = func() (string, error) {
		out, err := removeViaInstallerTO("--force", dangerRemoveTimeout)
		firstTunnelForget()
		pruneTunnelLinks()
		forgetPeerLink()
		invalidatePeerIfsCache()
		return out, err
	}
)

// resetAllTunnels removes every tunnel; each part runs even when one before
// it failed, and says how it went.
func resetAllTunnels(backup bool) ([]dangerStep, error) {
	var steps []dangerStep
	add := func(part string, err error, detail string) {
		s := dangerStep{Part: part, OK: err == nil, Detail: detail}
		if err != nil {
			s.Detail = strings.TrimSpace(strings.TrimPrefix(detail+"; "+err.Error(), "; "))
		}
		steps = append(steps, s)
	}
	count := func(n int) string {
		if n == 0 {
			return "none"
		}
		return fmt.Sprintf("%d removed", n)
	}
	if backup {
		out, err := dangerBackup()
		add("Backup", err, lastLines(out, 2))
		if err != nil {
			return steps, errors.New("the backup failed, so nothing was removed. Untick \"Make a backup first\" to go on without one")
		}
	}
	n, err := dangerRemoveHubs()
	add("Extra Iran hubs (join-hub)", err, count(n))
	n, err = dangerRemoveXray()
	add("Xray tunnel", err, count(n))
	n, err = dangerRemoveBagher()
	add("Bagher", err, count(n))
	n, err = dangerRemoveSpoof()
	add("Spoof tunnel", err, count(n))
	out, err := dangerRemoveTunnels()
	add("FRP, Backhaul and GRE tunnels", err, lastLines(out, 3))
	return steps, nil
}

// POST /api/danger/reset-tunnels {password, confirm, backup}
func handleDangerResetTunnels(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password string `json:"password"`
		Confirm  string `json:"confirm"`
		Backup   *bool  `json:"backup"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req) != nil {
		writeAPIError(w, r, "E-DANGER-01", "")
		return
	}
	if strings.TrimSpace(req.Confirm) != dangerResetPhrase {
		writeAPIError(w, r, "E-DANGER-01", "type "+dangerResetPhrase+" to confirm")
		return
	}
	mu.Lock()
	hash, user := cfg.PassHash, cfg.Username
	mu.Unlock()
	if ok, _ := verifyPassword(hash, req.Password); !ok {
		recordLoginFailure(clientIP(r))
		LogSecurityAudit("reset_tunnels_rejected", user, clientIP(r), "incorrect password")
		writeAPIError(w, r, "E-DANGER-02", "")
		return
	}
	if !dangerMu.TryLock() {
		writeAPIError(w, r, "E-DANGER-03", "")
		return
	}
	defer dangerMu.Unlock()
	LogSecurityAudit("reset_tunnels", user, clientIP(r), "removing every tunnel")
	steps, err := resetAllTunnels(req.Backup == nil || *req.Backup)
	if err != nil {
		writeJSON(w, map[string]any{"status": "error", "error": err.Error(), "steps": steps, "failed": len(steps)})
		return
	}
	failed := 0
	for _, s := range steps {
		if !s.OK && s.Part != "Backup" {
			failed++
		}
	}
	log.Printf("[danger] every tunnel removed by %s: %d part(s) failed", user, failed)
	LogSecurityAudit("reset_tunnels_done", user, clientIP(r), fmt.Sprintf("failed=%d", failed))
	writeJSON(w, map[string]any{"status": "ok", "steps": steps, "failed": failed})
}
