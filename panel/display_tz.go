package main

import (
	"fmt"
	"os"
	"regexp"
	"time"
	_ "time/tzdata" // the zone works even on a server without tzdata
)

// Hashem shows its times in Tehran's zone, whatever zone the server runs.
// The server's own zone is never changed: a server set to Asia/Tehran is
// easier to tell apart from other hosts, so it stays as its owner set it
// (most run UTC). Only this process reads Tehran: the times it writes (events,
// last switch, errors), the journalctl lines the Logs page and the doctor
// show, and the hashem.sh it runs. The web page gets the zone in display_tz.
//
// HASHEM_DISPLAY_TZ=<zone> picks another zone, HASHEM_DISPLAY_TZ=server keeps
// the server's.
const defaultDisplayTZ = "Asia/Tehran"

// displayTZ is the zone the panel shows times in ("" = the server's own).
var displayTZ string

var zoneNameRe = regexp.MustCompile(`^[A-Za-z0-9_+-]+(/[A-Za-z0-9_+-]+)*$`)

// pickDisplayZone reads the setting: the zone's name and location, or ""
// and nil to keep the server's zone (asked for, or an unknown name).
func pickDisplayZone(env string) (string, *time.Location) {
	want := env
	if want == "" {
		want = defaultDisplayTZ
	}
	if want == "server" || !zoneNameRe.MatchString(want) {
		return "", nil
	}
	loc, err := time.LoadLocation(want)
	if err != nil {
		return "", nil
	}
	return want, loc
}

// childTZ is the TZ value for the programs the panel runs. With the zone in
// the server's tzdata it is the name; without it, the POSIX form of its
// current offset (Tehran: "<+0330>-03:30"), which needs no file.
func childTZ(name string, loc *time.Location, zoneinfo string, now time.Time) string {
	if _, err := os.Stat(zoneinfo + "/" + name); err == nil {
		return name
	}
	_, off := now.In(loc).Zone()
	sign, abs := "+", off
	if off < 0 {
		sign, abs = "-", -off
	}
	h, m := abs/3600, abs%3600/60
	// POSIX counts west of UTC as positive, so the sign flips
	posix := "-"
	if sign == "-" {
		posix = ""
	}
	return fmt.Sprintf("<%s%02d%02d>%s%02d:%02d", sign, h, m, posix, h, m)
}

// applyDisplayZone sets the panel's zone; main calls it first.
func applyDisplayZone() {
	name, loc := pickDisplayZone(os.Getenv("HASHEM_DISPLAY_TZ"))
	if loc == nil {
		return
	}
	time.Local = loc
	displayTZ = name
	_ = os.Setenv("TZ", childTZ(name, loc, "/usr/share/zoneinfo", time.Now()))
}
