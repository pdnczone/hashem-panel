package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestPickDisplayZone(t *testing.T) {
	if n, l := pickDisplayZone(""); n != "Asia/Tehran" || l == nil {
		t.Fatalf("default: %q %v", n, l)
	}
	if n, l := pickDisplayZone("Europe/Berlin"); n != "Europe/Berlin" || l == nil {
		t.Fatalf("other zone: %q %v", n, l)
	}
	for _, keep := range []string{"server", "Mars/Olympus", "../../etc/passwd", "Asia/Tehran;rm"} {
		if n, l := pickDisplayZone(keep); n != "" || l != nil {
			t.Fatalf("%q should keep the server's zone, got %q", keep, n)
		}
	}
}

func TestChildTZ(t *testing.T) {
	_, teh := pickDisplayZone("Asia/Tehran")
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	// no tzdata on the server: the POSIX form, which needs no file
	if got := childTZ("Asia/Tehran", teh, dir, now); got != "<+0330>-03:30" {
		t.Fatalf("tehran posix: %q", got)
	}
	ny, _ := time.LoadLocation("America/New_York")
	if got := childTZ("America/New_York", ny, dir, now); got != "<-0500>05:00" {
		t.Fatalf("west posix: %q", got)
	}
	// tzdata there: the name
	_ = os.MkdirAll(dir+"/Asia", 0o755)
	_ = os.WriteFile(dir+"/Asia/Tehran", nil, 0o644)
	if got := childTZ("Asia/Tehran", teh, dir, now); got != "Asia/Tehran" {
		t.Fatalf("with tzdata: %q", got)
	}
	// the POSIX form really reads 3:30 ahead in a child process (as journalctl would)
	if _, err := exec.LookPath("date"); err == nil {
		cmd := exec.Command("date", "-u", "-d", "@0", "+%H:%M")
		cmd.Env = append(os.Environ(), "TZ=<+0330>-03:30")
		utc, err := cmd.Output()
		if err != nil {
			t.Skip("this date has no -d (not GNU date); the POSIX form is checked on Linux")
		}
		cmd = exec.Command("date", "-d", "@0", "+%H:%M")
		cmd.Env = append(os.Environ(), "TZ=<+0330>-03:30")
		local, _ := cmd.Output()
		if strings.TrimSpace(string(utc)) != "00:00" || strings.TrimSpace(string(local)) != "03:30" {
			t.Fatalf("child process: utc %q local %q", utc, local)
		}
	}
}
