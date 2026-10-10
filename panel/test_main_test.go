package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
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
	// Host commands that go through the runner fail by default; tests that
	// need output install their own stub. Nothing here ever reaches the host.
	runner = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return nil, errors.New("test runner: no host commands")
	}
	dialFn = func(network, addr string, timeout time.Duration) (net.Conn, error) {
		return nil, errors.New("test dialer: no network")
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}
