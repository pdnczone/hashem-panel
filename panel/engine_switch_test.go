package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// engineLab fakes installed engine binaries and (optionally) the Backhaul
// systemd units in throwaway dirs, restoring everything on cleanup.
func engineLab(t *testing.T, bins []string, units []string) {
	t.Helper()
	binDir, unitDir := t.TempDir(), t.TempDir()
	for _, b := range bins {
		if err := os.WriteFile(filepath.Join(binDir, b), []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, u := range units {
		if err := os.WriteFile(filepath.Join(unitDir, u+".service"), []byte("[Service]\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	oldDirs, oldExtra, oldUnit := engineBinDirs, backhaulExtraBins, engineUnitDir
	engineBinDirs, backhaulExtraBins, engineUnitDir = []string{binDir}, nil, unitDir
	t.Cleanup(func() { engineBinDirs, backhaulExtraBins, engineUnitDir = oldDirs, oldExtra, oldUnit })
}

func recordSystemctl(t *testing.T, failOn string) *[]string {
	t.Helper()
	var calls []string
	old := runSystemctl
	runSystemctl = func(args ...string) error {
		calls = append(calls, strings.Join(args, " "))
		if failOn != "" && strings.HasPrefix(strings.Join(args, " "), failOn) {
			return errors.New("boom")
		}
		return nil
	}
	t.Cleanup(func() { runSystemctl = old })
	return &calls
}

func TestSwitchEngineMissingBinaryChangesNothing(t *testing.T) {
	engineLab(t, nil, nil)
	calls := recordSystemctl(t, "")
	out, err := switchTunnelEngine("backhaul", "tcpmux")
	if err == nil {
		t.Fatalf("expected error for missing backhaul binary, got success: %q", out)
	}
	if !strings.Contains(err.Error(), "nothing was changed") {
		t.Errorf("error should state nothing changed: %v", err)
	}
	if len(*calls) != 0 {
		t.Errorf("running services must not be touched on preflight failure, got %v", *calls)
	}
}

func TestSwitchEngineMissingUnitChangesNothing(t *testing.T) {
	engineLab(t, []string{"backhaul"}, nil) // binary but no unit
	calls := recordSystemctl(t, "")
	_, err := switchTunnelEngine("backhaul", "tcpmux")
	if err == nil || !strings.Contains(err.Error(), ".service is missing") {
		t.Fatalf("expected missing-unit error, got %v", err)
	}
	if len(*calls) != 0 {
		t.Errorf("services touched despite preflight failure: %v", *calls)
	}
}

func TestSwitchEngineRestartFailureIsReported(t *testing.T) {
	engineLab(t, []string{"backhaul", "frpc", "frps"}, []string{"backhaul-server", "backhaul-client"})
	recordSystemctl(t, "restart backhaul-")
	_, err := switchTunnelEngine("backhaul", "tcpmux")
	if err == nil || !strings.Contains(err.Error(), "restart") {
		t.Fatalf("restart failure must surface as an error, got %v", err)
	}
}

func TestSwitchEngineSuccessWithEverythingInstalled(t *testing.T) {
	engineLab(t, []string{"backhaul", "frpc", "frps"}, []string{"backhaul-server", "backhaul-client"})
	recordSystemctl(t, "")
	if out, err := switchTunnelEngine("backhaul", "tcpmux"); err != nil {
		t.Fatalf("unexpected error: %v (%s)", err, out)
	}
}

func TestEngineConfigIsOwnerOnly(t *testing.T) {
	dir := t.TempDir()
	if err := writeEngineFile(dir, "frps.toml", "auth.token = \"x\"\n"); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(dir, "frps.toml"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("config must be 0600, got %v %v", fi, err)
	}
	if err := writeEngineFile(filepath.Join(dir, "frps.toml", "sub"), "a", "b"); err == nil {
		t.Error("expected error when directory cannot be created")
	}
}
