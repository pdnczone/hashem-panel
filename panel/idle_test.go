package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func idleLab(t *testing.T, minutes int) (now *time.Time) {
	t.Helper()
	oldCfg, oldNow := cfg, timeNow
	t.Cleanup(func() {
		cfg, timeNow = oldCfg, oldNow
		idleMu.Lock()
		lastActive = map[string]time.Time{}
		idleMu.Unlock()
	})
	cfg.IdleTimeoutMin = minutes
	n := time.Unix(1_700_000_000, 0)
	timeNow = func() time.Time { return n }
	idleMu.Lock()
	lastActive = map[string]time.Time{}
	idleMu.Unlock()
	return &n
}

func TestIdleOffNeverExpires(t *testing.T) {
	now := idleLab(t, 0)
	touchSession("a")
	*now = now.Add(48 * time.Hour)
	if sessionIdleExpired("a", false) {
		t.Fatal("timeout 0 must never expire")
	}
}

func TestIdleExpiresWithoutActivityButPollingDoesNotKeepAlive(t *testing.T) {
	now := idleLab(t, 10)
	touchSession("a")
	for i := 0; i < 8; i++ { // background polling for 8 minutes, no user activity
		*now = now.Add(time.Minute)
		if sessionIdleExpired("a", false) {
			t.Fatalf("expired too early at minute %d", i+1)
		}
	}
	*now = now.Add(3 * time.Minute) // 11 min since last real activity
	if !sessionIdleExpired("a", false) {
		t.Fatal("polling alone must not keep a session alive")
	}
}

func TestIdleUserActivityRefreshes(t *testing.T) {
	now := idleLab(t, 10)
	touchSession("a")
	*now = now.Add(9 * time.Minute)
	if sessionIdleExpired("a", true) {
		t.Fatal("still within timeout")
	}
	*now = now.Add(9 * time.Minute) // 18 min after login, 9 after activity
	if sessionIdleExpired("a", false) {
		t.Fatal("activity should have reset the clock")
	}
}

func TestIdleUnknownTokenGetsFreshClock(t *testing.T) {
	idleLab(t, 10)
	if sessionIdleExpired("after-restart", false) {
		t.Fatal("a token unseen since restart must not be kicked")
	}
}

func TestIdleSettingsValidation(t *testing.T) {
	idleLab(t, 0)
	post := func(body string) int {
		rr := httptest.NewRecorder()
		handleSessionSettingsPost(rr, httptest.NewRequest("POST", "/x", strings.NewReader(body)))
		return rr.Code
	}
	if c := post(`{"idle_minutes":2}`); c == http.StatusOK {
		t.Error("2 minutes is below the minimum")
	}
	if c := post(`{"idle_minutes":99999}`); c == http.StatusOK {
		t.Error("above max must fail")
	}
	if c := post(`{"idle_minutes":30}`); c != http.StatusOK || cfg.IdleTimeoutMin != 30 {
		t.Errorf("30 should be accepted, code %d cfg %d", c, cfg.IdleTimeoutMin)
	}
	if c := post(`{"idle_minutes":0}`); c != http.StatusOK || cfg.IdleTimeoutMin != 0 {
		t.Error("0 must switch it off")
	}
}
