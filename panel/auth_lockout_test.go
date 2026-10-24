package main

import (
	"testing"
	"time"
)

func resetLockoutState() {
	attemptMu.Lock()
	attempts = map[string]*ipAttempts{}
	lockStrikes = map[string]*lockStrike{}
	usernameAttemptsMap = map[string]*usernameAttempts{}
	attemptMu.Unlock()
}

func TestLockoutDurationEscalates(t *testing.T) {
	want := []time.Duration{15 * time.Minute, 30 * time.Minute, time.Hour, 2 * time.Hour}
	for i, w := range want {
		if got := lockoutFor(i + 1); got != w {
			t.Errorf("strike %d: got %v want %v", i+1, got, w)
		}
	}
	if got := lockoutFor(50); got != maxLockoutDur {
		t.Errorf("cap: got %v want %v", got, maxLockoutDur)
	}
	if got := lockoutFor(0); got != loginLockoutDur {
		t.Errorf("zero strikes: got %v", got)
	}
}

func TestRepeatOffenderLockedLonger(t *testing.T) {
	resetLockoutState()
	ip := "203.0.113.9"
	for i := 0; i < loginMaxFails; i++ {
		recordLoginFailure(ip)
	}
	first := lockRemaining(ip)
	if first <= 0 || first > loginLockoutDur {
		t.Fatalf("first lockout should be <= %v, got %v", loginLockoutDur, first)
	}
	// lockout expires, offender tries again and fails again
	attemptMu.Lock()
	attempts[ip].lockedUntil = time.Now().Add(-time.Second)
	attempts[ip].fails = nil
	attemptMu.Unlock()
	for i := 0; i < loginMaxFails; i++ {
		recordLoginFailure(ip)
	}
	second := lockRemaining(ip)
	if second <= loginLockoutDur {
		t.Errorf("second lockout must exceed first (%v), got %v", loginLockoutDur, second)
	}
}

func TestSuccessfulLoginClearsStrikes(t *testing.T) {
	resetLockoutState()
	ip := "203.0.113.10"
	for i := 0; i < loginMaxFails; i++ {
		recordLoginFailure(ip)
	}
	recordLoginSuccess(ip)
	if checkLocked(ip) || lockRemaining(ip) != 0 {
		t.Error("success must clear lock")
	}
	attemptMu.Lock()
	_, has := lockStrikes[ip]
	attemptMu.Unlock()
	if has {
		t.Error("success must clear strikes")
	}
}

func TestOldStrikesDecay(t *testing.T) {
	resetLockoutState()
	ip := "203.0.113.11"
	attemptMu.Lock()
	lockStrikes[ip] = &lockStrike{n: 4, last: time.Now().Add(-strikeDecay - time.Minute)}
	attemptMu.Unlock()
	for i := 0; i < loginMaxFails; i++ {
		recordLoginFailure(ip)
	}
	if got := lockRemaining(ip); got > loginLockoutDur {
		t.Errorf("stale strikes must decay, lock is %v", got)
	}
}

func TestUsernameLockout(t *testing.T) {
	resetLockoutState()
	user := "admin"

	for i := 0; i < loginUserMaxFails-1; i++ {
		recordUsernameFailure(user)
	}
	if locked, _ := checkUsernameLocked(user); locked {
		t.Fatalf("user should not be locked after %d attempts", loginUserMaxFails-1)
	}

	recordUsernameFailure(user)
	if locked, rem := checkUsernameLocked(user); !locked || rem <= 0 {
		t.Fatalf("user must be locked after %d attempts", loginUserMaxFails)
	}

	recordUsernameSuccess(user)
	if locked, _ := checkUsernameLocked(user); locked {
		t.Fatalf("user lock should be cleared after successful login")
	}

	// Lock again and verify ResetAllLockouts
	for i := 0; i < loginUserMaxFails; i++ {
		recordUsernameFailure(user)
	}
	if locked, _ := checkUsernameLocked(user); !locked {
		t.Fatalf("user must be locked after %d attempts", loginUserMaxFails)
	}
	ResetAllLockouts()
	if locked, _ := checkUsernameLocked(user); locked {
		t.Fatalf("ResetAllLockouts must clear user locks")
	}
}
