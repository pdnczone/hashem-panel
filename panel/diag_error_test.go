package main

import (
	"os"
	"testing"
	"time"
)

// The dashboard's Diagnostics cell shows only recent tunnel errors: a failed
// login (E-AUTH-01) or a day-old FRP error must not mark the tunnel red.
func TestLastTunnelErrorSkipsUnrelatedAndStale(t *testing.T) {
	oldDir := configDir
	configDir = t.TempDir()
	errMu.Lock()
	oldEvents := errEvents
	errMu.Unlock()
	t.Cleanup(func() {
		configDir = oldDir
		errMu.Lock()
		errEvents = oldEvents
		errMu.Unlock()
	})
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.Local)
	at := func(ago time.Duration) string { return now.Add(-ago).Format("2006-01-02 15:04:05") }
	set := func(evs ...errEvent) {
		errMu.Lock()
		errEvents = evs
		errMu.Unlock()
	}

	set(errEvent{Time: at(time.Minute), Code: "E-AUTH-01"})
	if e := lastTunnelErrorAt(now); e != nil {
		t.Fatalf("login error shown as tunnel diagnostics: %+v", e)
	}

	set(errEvent{Time: at(2 * time.Hour), Code: "E-FRP-03"}, errEvent{Time: at(time.Minute), Code: "E-AUTH-01"})
	if e := lastTunnelErrorAt(now); e == nil || e.Code != "E-FRP-03" {
		t.Fatalf("want E-FRP-03 behind the login error, got %+v", e)
	}

	set(errEvent{Time: at(25 * time.Hour), Code: "E-GRE-01"})
	if e := lastTunnelErrorAt(now); e != nil {
		t.Fatalf("day-old error still shown: %+v", e)
	}

	// After a restart the ring is empty and the log file is read.
	set()
	log := `{"time":"` + at(time.Hour) + `","code":"E-BH-02"}` + "\n" + `{"time":"` + at(time.Minute) + `","code":"E-TERM-12"}` + "\n"
	if err := os.WriteFile(errorLogPath(), []byte(log), 0600); err != nil {
		t.Fatal(err)
	}
	if e := lastTunnelErrorAt(now); e == nil || e.Code != "E-BH-02" {
		t.Fatalf("want E-BH-02 from the log file, got %+v", e)
	}
}
