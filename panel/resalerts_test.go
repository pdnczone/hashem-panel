package main

import (
	"strings"
	"testing"
	"time"
)

func TestResourceStateThresholds(t *testing.T) {
	th := resThreshold{85, 92}
	for pct, want := range map[float64]string{10: stateHealthy, 84.9: stateHealthy, 85: stateDegraded, 91.9: stateDegraded, 92: stateDown, 100: stateDown} {
		if got := resourceState("", pct, th); got != want {
			t.Errorf("%.1f%% -> %s want %s", pct, got, want)
		}
	}
}

func TestResourceStateHysteresis(t *testing.T) {
	th := resThreshold{85, 92}
	// critical does not clear until it falls 3 points under the threshold
	if resourceState(stateDown, 90, th) != stateDown {
		t.Error("89.x..91 must stay down once critical")
	}
	if resourceState(stateDown, 88.9, th) != stateDegraded {
		t.Error("below crit-3 drops to degraded")
	}
	if resourceState(stateDegraded, 83, th) != stateDegraded {
		t.Error("83% must stay degraded (warn-3 = 82)")
	}
	if resourceState(stateDegraded, 81.9, th) != stateHealthy {
		t.Error("81.9% clears")
	}
	if resourceState(stateHealthy, 84, th) != stateHealthy {
		t.Error("healthy only crosses at the real threshold")
	}
}

func TestCertState(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	day := 24 * time.Hour
	for _, c := range []struct {
		in   time.Duration
		want string
		msg  string
	}{
		{90 * day, stateHealthy, ""}, {22 * day, stateHealthy, ""},
		{20 * day, stateDegraded, "20 days"}, {7*day + time.Hour, stateDegraded, "7 days"},
		{6 * day, stateDown, "6 day"}, {time.Hour, stateDown, "0 day"},
		{-time.Hour, stateDown, "EXPIRED"},
	} {
		st, why := certState(now, now.Add(c.in))
		if st != c.want || (c.msg != "" && !strings.Contains(why, c.msg)) {
			t.Errorf("in %v -> %s %q want %s %q", c.in, st, why, c.want, c.msg)
		}
	}
}

func TestHostResourceLinksSkipUnavailable(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	got := hostResourceLinks(now, hostReaders{
		diskPct: func() (float64, bool) { return 50, true },
		ramPct:  func() (float64, bool) { return 0, false }, // unreadable
		cert:    nil,
	}, func(string) string { return "" })
	if len(got) != 1 || got[0].Name != "host:disk" || got[0].State != stateHealthy {
		t.Fatalf("%+v", got)
	}
}

func TestResourceAlertsFlowThroughTracker(t *testing.T) {
	tr := newAlertTracker()
	cfg := alertConfig{MinGapSec: 10}
	now := time.Unix(1_700_000_000, 0)
	disk := 50.0
	exp := now.Add(60 * 24 * time.Hour)
	tick := func(at time.Time) []alertEvent {
		links := hostResourceLinks(at, hostReaders{
			diskPct: func() (float64, bool) { return disk, true },
			cert:    func() (time.Time, bool) { return exp, true },
		}, tr.lastState)
		return tr.observe(at, links, cfg)
	}
	if ev := tick(now); len(ev) != 0 {
		t.Fatalf("baseline must be silent: %v", ev)
	}
	disk = 95
	ev := tick(now.Add(time.Minute))
	if len(ev) != 1 || ev[0].Link != "host:disk" || ev[0].To != stateDown || !strings.Contains(ev[0].Why, "95%") {
		t.Fatalf("critical disk must alert once: %+v", ev)
	}
	if ev := tick(now.Add(2 * time.Minute)); len(ev) != 0 {
		t.Fatalf("staying critical must not repeat: %v", ev)
	}
	disk = 90 // inside hysteresis band: no flap, no alert
	if ev := tick(now.Add(3 * time.Minute)); len(ev) != 0 {
		t.Fatalf("hysteresis band must be silent: %v", ev)
	}
	disk = 40
	ev = tick(now.Add(5 * time.Minute))
	if len(ev) != 1 || ev[0].To != stateHealthy {
		t.Fatalf("recovery must alert: %+v", ev)
	}
	exp = now.Add(5 * 24 * time.Hour) // certificate about to expire
	ev = tick(now.Add(10 * time.Minute))
	if len(ev) != 1 || ev[0].Link != "host:tls-cert" || ev[0].To != stateDown {
		t.Fatalf("cert expiry must alert: %+v", ev)
	}
}

func TestLiveHostReadersDoNotPanic(t *testing.T) {
	r := liveHostReaders()
	links := hostResourceLinks(time.Now(), r, func(string) string { return "" })
	for _, l := range links {
		if l.State == "" || l.Name == "" {
			t.Errorf("bad link entry %+v", l)
		}
	}
}
