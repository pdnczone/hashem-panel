package main

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A datagram sent to a temp unixgram socket must arrive intact.
func TestSdNotifyBeat(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "notify.sock")
	pc, err := net.ListenPacket("unixgram", sock)
	if err != nil {
		t.Skipf("unixgram unavailable: %v", err)
	}
	defer pc.Close()
	if err := sdNotifyOnce(sock, "WATCHDOG=1"); err != nil {
		t.Fatalf("beat failed: %v", err)
	}
	buf := make([]byte, 64)
	_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := pc.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "WATCHDOG=1" {
		t.Fatalf("beat = %q, err = %v", buf[:n], err)
	}
}

// Empty socket path and HASHEM_NO_SDNOTIFY=1 are silent no-ops.
func TestSdNotifyNoop(t *testing.T) {
	if err := sdNotifyOnce("", "WATCHDOG=1"); err != nil {
		t.Fatalf("empty path must be a no-op: %v", err)
	}
	t.Setenv("HASHEM_NO_SDNOTIFY", "1")
	prev := sdNotifySocket
	sdNotifySocket = func() string { return "/nonexistent/notify.sock" }
	defer func() { sdNotifySocket = prev }()
	if err := sdNotify("WATCHDOG=1"); err != nil {
		t.Fatalf("HASHEM_NO_SDNOTIFY=1 must be a no-op: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startSdWatchdog(ctx) // must return without spawning network use
}

// Without NOTIFY_SOCKET the loop never starts (dev/tests/non-systemd).
func TestSdWatchdogNoSocket(t *testing.T) {
	prev := sdNotifySocket
	sdNotifySocket = func() string { return "" }
	defer func() { sdNotifySocket = prev }()
	os.Unsetenv("NOTIFY_SOCKET")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startSdWatchdog(ctx) // must return immediately, no goroutine, no error
}
