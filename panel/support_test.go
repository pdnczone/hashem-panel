package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func resetSupport(t *testing.T) {
	t.Helper()
	_ = os.Remove(supportPath())
}

func TestSupportClaimThrottle(t *testing.T) {
	resetSupport(t)
	now := time.Unix(1_800_000_000, 0)
	if !supportClaim(now) {
		t.Fatal("first claim must show")
	}
	if supportClaim(now.Add(time.Second)) {
		t.Fatal("second claim right after must not show (anti-spam)")
	}
	if supportClaim(now.Add(supportAfterShown - time.Minute)) {
		t.Fatal("claim just before window end must not show")
	}
	if !supportClaim(now.Add(supportAfterShown + time.Minute)) {
		t.Fatal("claim after the window must show again")
	}
}

func TestSupportClaimConcurrentSingleWinner(t *testing.T) {
	resetSupport(t)
	now := time.Unix(1_800_000_000, 0)
	var wins int32
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if supportClaim(now) {
				atomic.AddInt32(&wins, 1)
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("exactly one concurrent claim may win, got %d", wins)
	}
}

func TestSupportActionsSetWindows(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	cases := map[string]time.Duration{
		"close": supportAfterShown, "snooze": supportAfterSnooze, "donate": supportAfterDonate,
	}
	for action, d := range cases {
		resetSupport(t)
		if !supportRecord(action, now) {
			t.Fatalf("%s rejected", action)
		}
		supportMu.Lock()
		st := loadSupportLocked()
		supportMu.Unlock()
		if st.NextShowAt != now.Add(d).Unix() {
			t.Fatalf("%s: next=%d want %d", action, st.NextShowAt, now.Add(d).Unix())
		}
		if supportClaim(now.Add(d - time.Hour)) {
			t.Fatalf("%s: must stay quiet inside window", action)
		}
		if !supportClaim(now.Add(d + time.Hour)) {
			t.Fatalf("%s: must show after window", action)
		}
	}
	if supportRecord("bogus", now) {
		t.Fatal("unknown action must be rejected")
	}
}

func TestSupportCorruptFileIsFresh(t *testing.T) {
	resetSupport(t)
	_ = os.WriteFile(supportPath(), []byte("{not json"), 0600)
	if !supportClaim(time.Now()) {
		t.Fatal("corrupt state should behave as fresh")
	}
}

func TestSupportHandler(t *testing.T) {
	resetSupport(t)
	post := func(body string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		handleSupport(rr, httptest.NewRequest(http.MethodPost, "/api/support", strings.NewReader(body)))
		return rr
	}
	if rr := post(`{"action":"claim"}`); !strings.Contains(rr.Body.String(), `"show":true`) {
		t.Fatalf("first claim: %s", rr.Body.String())
	}
	if rr := post(`{"action":"claim"}`); !strings.Contains(rr.Body.String(), `"show":false`) {
		t.Fatalf("second claim: %s", rr.Body.String())
	}
	if rr := post(`{"action":"nope"}`); rr.Code == http.StatusOK {
		t.Fatal("bad action must fail")
	}
	if rr := post(`{"action":"donate"}`); rr.Code != http.StatusOK {
		t.Fatalf("donate: %d", rr.Code)
	}
	rr := httptest.NewRecorder()
	handleSupport(rr, httptest.NewRequest(http.MethodGet, "/api/support", nil))
	if !strings.Contains(rr.Body.String(), supportURL) {
		t.Fatalf("GET lacks url: %s", rr.Body.String())
	}
}

// A fresh install reports fresh=true so the UI shows the first popup without
// waiting for a healthy tunnel; once shown it is no longer fresh.
func TestSupportFreshUntilFirstShow(t *testing.T) {
	resetSupport(t)
	get := func() string {
		rr := httptest.NewRecorder()
		handleSupport(rr, httptest.NewRequest(http.MethodGet, "/api/support", nil))
		return rr.Body.String()
	}
	if b := get(); !strings.Contains(b, `"fresh":true`) || !strings.Contains(b, "https://pdnczone.com") {
		t.Fatalf("fresh install: %s", b)
	}
	if !supportClaim(time.Now()) {
		t.Fatal("first claim must show")
	}
	if b := get(); !strings.Contains(b, `"fresh":false`) {
		t.Fatalf("after first show: %s", b)
	}
}
