package main

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func setPanelVersion(t *testing.T, v string) {
	t.Helper()
	old := panelVersion
	panelVersion = v
	t.Cleanup(func() { panelVersion = old })
}

// The new binary clears the pending marker once it listens; the old binary
// (swap not in effect) leaves it for the guard.
func TestClearUpdatePending(t *testing.T) {
	withTmpConfig(t)
	setPanelVersion(t, "v1.0.0")
	write := func(to string) {
		_ = os.WriteFile(updatePendingPath(), mustJSON(updateMarker{From: "v1.0.0", To: to, At: time.Now().Unix()}), 0600)
	}
	write("v1.1.0")
	clearUpdatePending()
	if !fileExists(updatePendingPath()) {
		t.Fatal("old binary must not clear a marker for another version")
	}
	setPanelVersion(t, "v1.1.0")
	clearUpdatePending()
	if fileExists(updatePendingPath()) {
		t.Fatal("new binary must clear its marker")
	}
}

// A rollback by the guard shows in /api/version for a day.
func TestVersionReportsRollbackAndChanges(t *testing.T) {
	withTmpConfig(t)
	setPanelVersion(t, "v1.0.0")
	swapFetchers(t, canned([]ghRelease{
		{Tag: "v1.2.0", Body: "## v1.2.0\n- two"},
		{Tag: "v1.1.0", Body: "- one"},
		{Tag: "v1.0.0", Body: "- installed"},
		{Tag: "v1.3.0-rc1", Prerelease: true},
	}, nil), func() (string, error) { return "v1.2.0", nil })
	_ = os.WriteFile(updateRollbackPath(), mustJSON(updateMarker{From: "v1.0.0", To: "v1.2.0", At: time.Now().Unix()}), 0600)

	rr := httptest.NewRecorder()
	handleVersion(rr, httptest.NewRequest("GET", "/api/version?refresh=1", nil))
	var v struct {
		Latest     string `json:"latest"`
		Avail      bool   `json:"update_available"`
		RolledBack string `json:"rolled_back"`
		Changes    []struct {
			Tag, Notes string
		} `json:"changes"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	if v.Latest != "v1.2.0" || !v.Avail || v.RolledBack != "v1.2.0" {
		t.Fatalf("unexpected version reply: %s", rr.Body.String())
	}
	if len(v.Changes) != 2 || v.Changes[0].Tag != "v1.2.0" || v.Changes[1].Tag != "v1.1.0" {
		t.Fatalf("changes must be the releases after the installed one, newest first: %+v", v.Changes)
	}

	// older than a day: no longer reported
	_ = os.WriteFile(updateRollbackPath(), mustJSON(updateMarker{To: "v1.2.0", At: time.Now().Add(-25 * time.Hour).Unix()}), 0600)
	if lastRollback() != nil {
		t.Fatal("a rollback older than a day must not be reported")
	}
}

func TestUpdatePeerNotConfigured(t *testing.T) {
	withTmpConfig(t)
	rr := httptest.NewRecorder()
	handleUpdatePeer(rr, httptest.NewRequest("GET", "/api/update/peer", nil))
	if rr.Body.String() != "{\"configured\":false}\n" {
		t.Fatalf("unexpected: %q", rr.Body.String())
	}
}

// The guard restores the .bak and restarts when the marker is still there,
// and does nothing once the new binary cleared it.
func TestUpdateGuardScript(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs /bin/sh")
	}
	dir := t.TempDir()
	exe, marker, rb := filepath.Join(dir, "gre-panel"), filepath.Join(dir, "pending"), filepath.Join(dir, "rollback")
	bin := filepath.Join(dir, "bin")
	_ = os.Mkdir(bin, 0755)
	called := filepath.Join(dir, "restarted")
	_ = os.WriteFile(filepath.Join(bin, "systemctl"), []byte("#!/bin/sh\necho \"$@\" > "+called+"\n"), 0755)
	run := func() {
		cmd := exec.Command("/bin/sh", "-c", updateGuardScript, "guard", "0", exe, marker, rb)
		cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"))
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("guard: %v %s", err, out)
		}
	}
	_ = os.WriteFile(exe, []byte("new"), 0755)
	_ = os.WriteFile(exe+".bak", []byte("old"), 0755)

	run() // no marker: the new binary started
	if b, _ := os.ReadFile(exe); string(b) != "new" || fileExists(called) {
		t.Fatal("guard must do nothing when the marker is gone")
	}

	_ = os.WriteFile(marker, []byte(`{"to":"v2"}`), 0600)
	run()
	if b, _ := os.ReadFile(exe); string(b) != "old" {
		t.Fatalf("binary not restored: %q", b)
	}
	if fileExists(marker) || !fileExists(rb) {
		t.Fatal("marker must move to the rollback record")
	}
	if b, _ := os.ReadFile(called); string(b) != "restart gre-panel\n" {
		t.Fatalf("systemctl not called right: %q", b)
	}
}
