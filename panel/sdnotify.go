package main

// systemd watchdog heartbeat (C2.6). The gre-panel unit sets
// WatchdogSec=30 + NotifyAccess=main; this loop sends WATCHDOG=1 every 10 s
// so a hung (not crashed) panel is restarted automatically, and READY=1 once
// at start. No new dependencies: the datagram goes straight to $NOTIFY_SOCKET.
// Silent no-op when NOTIFY_SOCKET is unset (dev, tests, non-systemd) or when
// HASHEM_NO_SDNOTIFY=1 (tests, load lab).

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

const sdWatchdogInterval = 10 * time.Second

// notifySockAtStart is NOTIFY_SOCKET captured once at process start and then
// removed from the environment (see init): every exec.Command in the panel
// copies os.Environ(), and a child that inherits the socket and talks to
// systemd makes it log "Got notification message from PID n, but reception
// only permitted for main PID" for each command (thousands of lines an hour).
var notifySockAtStart = os.Getenv("NOTIFY_SOCKET")

func init() { _ = os.Unsetenv("NOTIFY_SOCKET") }

var sdNotifySocket = func() string { return notifySockAtStart }

// sdNotify sends one datagram to the systemd notify socket.
func sdNotify(state string) error {
	addr := sdNotifySocket()
	if addr == "" || os.Getenv("HASHEM_NO_SDNOTIFY") == "1" {
		return nil
	}
	c, err := net.Dial("unixgram", addr)
	if err != nil {
		return err
	}
	defer c.Close()
	_, err = c.Write([]byte(state))
	return err
}

// startSdWatchdog sends READY=1 once, then WATCHDOG=1 every interval until
// ctx ends. Errors are swallowed: notification must never break the panel.
func startSdWatchdog(ctx context.Context) {
	if sdNotifySocket() == "" || os.Getenv("HASHEM_NO_SDNOTIFY") == "1" {
		return
	}
	_ = sdNotify(fmt.Sprintf("MAINPID=%d\nREADY=1", os.Getpid()))
	tk := time.NewTicker(sdWatchdogInterval)
	go func() {
		defer tk.Stop()
		for {
			select {
			case <-tk.C:
				if panelAlive() {
					_ = sdNotify(fmt.Sprintf("MAINPID=%d\nWATCHDOG=1", os.Getpid()))
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}

// panelAlive is checked before each heartbeat (L6). A free-running ticker
// goroutine kept beating while the rest of the panel was deadlocked, so
// systemd's WatchdogSec never fired. Two cheap probes: the config lock most
// handlers take must be obtainable, and the snapshot collector must still be
// producing snapshots (nil = not built yet, i.e. still starting).
var panelAlive = func() bool {
	if !tryLockWithin(&mu, 5*time.Second) {
		return false
	}
	mu.Unlock()
	if s := snapPtr.Load(); s != nil && !s.At.IsZero() && time.Since(s.At) > 2*time.Minute {
		return false
	}
	return true
}

func tryLockWithin(m *sync.Mutex, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for {
		if m.TryLock() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// sdNotifyOnce is the seam for tests: send state to an explicit socket path.
func sdNotifyOnce(sockPath, state string) error {
	if sockPath == "" {
		return nil
	}
	c, err := net.Dial("unixgram", sockPath)
	if err != nil {
		return err
	}
	defer c.Close()
	_, err = c.Write([]byte(state))
	return err
}
