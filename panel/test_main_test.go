package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestMain points configDir, frpDir and backhaulDir at throwaway directories
// for the whole run so no test can read or write the real /etc/gre-panel
// (error journal, audit log, peers, sessions, ...), /etc/frp or /etc/backhaul,
// and stubs runSystemctl.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "gre-panel-test-*")
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot create test configDir:", err)
		os.Exit(1)
	}
	configDir = dir
	frpDir = filepath.Join(dir, "frp")
	backhaulDir = filepath.Join(dir, "backhaul")
	runSystemctl = func(args ...string) error { return nil }
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}
