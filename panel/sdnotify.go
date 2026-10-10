package main

// systemd watchdog heartbeat (C2.6). The gre-panel unit sets
// WatchdogSec=30 + NotifyAccess=main; this loop sends WATCHDOG=1 every 10 s
// so a hung (not crashed) panel is restarted automatically, and READY=1 once
// at start. No new dependencies: the datagram goes straight to $NOTIFY_SOCKET.
// Silent no-op when NOTIFY_SOCKET is unset (dev, tests, non-systemd) or when
// HASHEM_NO_SDNOTIFY=1 (tests, load lab).

import (
	"context"
	"net"
	"os"
	"time"
)

const sdWatchdogInterval = 10 * time.Second

var sdNotifySocket = func() string { return os.Getenv("NOTIFY_SOCKET") }

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
	_ = sdNotify("READY=1")
	tk := time.NewTicker(sdWatchdogInterval)
	go func() {
		defer tk.Stop()
		for {
			select {
			case <-tk.C:
				_ = sdNotify("WATCHDOG=1")
			case <-ctx.Done():
				return
			}
		}
	}()
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
