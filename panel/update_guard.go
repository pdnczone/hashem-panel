package main

// Update guard: after a binary swap the old binary is kept as <exe>.bak. If
// the new binary does not come up, nothing used to put the old one back and
// the panel stayed down. Now a transient systemd unit (outside gre-panel's
// cgroup, so the restart does not kill it) waits, and if the new binary has
// not cleared the pending marker by then, restores the .bak and restarts.

import (
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"
)

// updateGuardDelay is how long the new binary has to start listening.
const updateGuardDelay = 60 * time.Second

// updateGuardScript: $1 delay, $2 binary, $3 pending marker, $4 rollback
// record. Paths go in as arguments, never into the script text.
const updateGuardScript = `sleep "$1"
[ -f "$3" ] || exit 0
if [ -f "$2.bak" ]; then cp -f "$2.bak" "$2.rollback" && chmod 755 "$2.rollback" && mv -f "$2.rollback" "$2"; fi
mv -f "$3" "$4"
systemctl restart gre-panel`

type updateMarker struct {
	From string `json:"from"`
	To   string `json:"to"`
	At   int64  `json:"at"`
}

func updatePendingPath() string  { return filepath.Join(configDir, "update_pending.json") }
func updateRollbackPath() string { return filepath.Join(configDir, "update_rollback.json") }

// guardUpdate records the pending update and starts the rollback guard.
// false when no guard could be started (no systemd-run): the update still
// goes ahead, as before.
func guardUpdate(exe, from, to string) bool {
	m := updateMarker{From: from, To: to, At: time.Now().Unix()}
	if err := os.WriteFile(updatePendingPath(), mustJSON(m), 0600); err != nil {
		return false
	}
	_ = os.Remove(updateRollbackPath())
	_ = os.Remove(updateRollbackPath() + ".seen")
	run, err := exec.LookPath("systemd-run")
	if err != nil {
		return false
	}
	unit := "hashem-update-guard-" + strconv.FormatInt(m.At, 10)
	cmd := exec.Command(run, "--unit", unit, "--collect", "--quiet", "/bin/sh", "-c", updateGuardScript, "guard",
		strconv.Itoa(int(updateGuardDelay/time.Second)), exe, updatePendingPath(), updateRollbackPath())
	return cmd.Run() == nil
}

// clearUpdatePending runs once the server is listening: the update this
// binary came from succeeded, so the guard must not roll it back.
func clearUpdatePending() {
	data, err := os.ReadFile(updatePendingPath())
	if err != nil {
		return
	}
	var m updateMarker
	// Compared with the version updated from, not to: a build whose version
	// string differs from its tag must not be rolled back once it runs.
	if json.Unmarshal(data, &m) == nil && m.From == panelVersion {
		return // still the old binary: the swap did not take effect
	}
	_ = os.Remove(updatePendingPath())
	LogSecurityAudit("update_started_ok", "system", "local", "version="+panelVersion)
}

// lastRollback returns the update the guard undid in the last day, if any.
func lastRollback() *updateMarker {
	data, err := os.ReadFile(updateRollbackPath())
	if err != nil {
		return nil
	}
	var m updateMarker
	if json.Unmarshal(data, &m) != nil || time.Since(time.Unix(m.At, 0)) > 24*time.Hour {
		return nil
	}
	return &m
}

// reportRollback records a guard rollback once, on the restored binary's start.
func reportRollback() {
	if m := lastRollback(); m != nil {
		flag := updateRollbackPath() + ".seen"
		if _, err := os.Stat(flag); err == nil {
			return
		}
		_ = os.WriteFile(flag, []byte(m.To), 0600)
		recordError("E-UPDATE-09", "update", "version "+m.To+" did not start; restored "+displayVersion(panelVersion))
	}
}

// GET /api/update/peer: the linked server's panel version, so the Update tab
// can say when the two servers run different versions. Older peers do not
// report a version ("" with reachable=true).
func handleUpdatePeer(w http.ResponseWriter, r *http.Request) {
	c := loadPeerConfig()
	// The defaults always hold a secret and an address: only a link that was
	// made (join or handshake) counts.
	resp := map[string]any{"configured": c.PeerURL != "" || c.LastSync != "" || c.IsConnected}
	if resp["configured"] == true {
		if out, err := sendToPeer("/api/peer/ping", "POST", nil); err == nil {
			var p struct {
				Version string `json:"version"`
			}
			_ = json.Unmarshal(out, &p)
			resp["reachable"] = true
			resp["version"] = displayVersion(p.Version)
			resp["same"] = p.Version == panelVersion
		} else {
			resp["reachable"] = false
		}
	}
	writeJSON(w, resp)
}
