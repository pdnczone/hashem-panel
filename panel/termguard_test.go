package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestIPAllowed(t *testing.T) {
	cases := []struct {
		ip   string
		list []string
		want bool
	}{
		{"1.2.3.4", nil, true},
		{"1.2.3.4", []string{"1.2.3.4"}, true},
		{"1.2.3.5", []string{"1.2.3.4"}, false},
		{"10.1.2.3", []string{"10.0.0.0/8"}, true},
		{"11.1.2.3", []string{"10.0.0.0/8"}, false},
		{"2001:db8::5", []string{"2001:db8::/32"}, true},
		{"garbage", []string{"1.2.3.4"}, false},
		{"1.2.3.4", []string{"bad", "1.2.3.4"}, true},
	}
	for _, c := range cases {
		if got := ipAllowed(c.ip, c.list); got != c.want {
			t.Errorf("ipAllowed(%q,%v)=%v want %v", c.ip, c.list, got, c.want)
		}
	}
	if validateAllowList([]string{"1.2.3.4", "x"}) || validateAllowList([]string{"10.0.0.0/99"}) || !validateAllowList([]string{"10.0.0.0/8", "::1"}) {
		t.Error("validateAllowList wrong")
	}
}

func TestTicketSingleUseBoundAndExpiring(t *testing.T) {
	oldNow := timeNow
	defer func() { timeNow = oldNow }()
	now := time.Unix(1_700_000_000, 0)
	timeNow = func() time.Time { return now }

	tk := newTermTicket("sess", "1.1.1.1")
	if !redeemTermTicket(tk, "sess", "1.1.1.1") {
		t.Fatal("valid ticket must redeem")
	}
	if redeemTermTicket(tk, "sess", "1.1.1.1") {
		t.Fatal("ticket must be single use")
	}
	tk = newTermTicket("sess", "1.1.1.1")
	if redeemTermTicket(tk, "other-session", "1.1.1.1") {
		t.Fatal("ticket bound to session")
	}
	if redeemTermTicket(tk, "sess", "1.1.1.1") {
		t.Fatal("a failed redemption must burn the ticket")
	}
	tk = newTermTicket("sess", "1.1.1.1")
	if redeemTermTicket(tk, "sess", "9.9.9.9") {
		t.Fatal("ticket bound to IP")
	}
	tk = newTermTicket("sess", "1.1.1.1")
	now = now.Add(termTicketTTL + time.Second)
	if redeemTermTicket(tk, "sess", "1.1.1.1") {
		t.Fatal("expired ticket must fail")
	}
	if redeemTermTicket("", "sess", "1.1.1.1") {
		t.Fatal("empty ticket must fail")
	}
}

func ticketReq(pass, code string) *httptest.ResponseRecorder {
	b, _ := json.Marshal(map[string]string{"password": pass, "code": code})
	req := httptest.NewRequest("POST", "/api/term/ticket", bytes.NewReader(b))
	req.RemoteAddr = "203.0.113.5:1234"
	req.AddCookie(&http.Cookie{Name: "gre_session", Value: "s1"})
	rr := httptest.NewRecorder()
	handleTermTicket(rr, req)
	return rr
}

func termLab(t *testing.T) {
	t.Helper()
	oldCfg, oldNow := cfg, timeNow
	t.Cleanup(func() { cfg, timeNow = oldCfg, oldNow })
	resetLockoutState()
	totpLastStep = 0
	cfg.Username, cfg.PassHash = "admin", hashPassword("Correct-Horse-Battery-9!")
	cfg.TOTPEnabled, cfg.TerminalAllowIPs = false, nil
}

func TestTicketNeedsPassword(t *testing.T) {
	termLab(t)
	if rr := ticketReq("wrong", ""); rr.Code == 200 {
		t.Fatal("wrong password must not yield a ticket")
	}
	rr := ticketReq("Correct-Horse-Battery-9!", "")
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"ticket"`) {
		t.Fatalf("right password must yield a ticket: %d %s", rr.Code, rr.Body.String())
	}
}

func TestTicketNeeds2FAWhenEnabled(t *testing.T) {
	termLab(t)
	secret := newTOTPSecret()
	cfg.TOTPEnabled, cfg.TOTPSecret = true, secret
	timeNow = func() time.Time { return time.Unix(1_700_000_000, 0) }
	if rr := ticketReq("Correct-Horse-Battery-9!", ""); rr.Code == 200 {
		t.Fatal("2FA on: password alone must not be enough")
	}
	code, _ := totpAt(secret, 1_700_000_000)
	if rr := ticketReq("Correct-Horse-Battery-9!", code); rr.Code != 200 {
		t.Fatalf("password+code must work: %s", rr.Body.String())
	}
}

func TestTicketDeniedForIPOutsideAllowlist(t *testing.T) {
	termLab(t)
	cfg.TerminalAllowIPs = []string{"198.51.100.0/24"}
	rr := ticketReq("Correct-Horse-Battery-9!", "")
	if rr.Code == 200 || !strings.Contains(rr.Body.String(), "E-TERM-12") {
		t.Fatalf("IP outside allowlist must be denied: %d %s", rr.Code, rr.Body.String())
	}
}

func TestTicketBruteForceLocksOut(t *testing.T) {
	termLab(t)
	for i := 0; i < loginMaxFails; i++ {
		ticketReq("nope", "")
	}
	if rr := ticketReq("Correct-Horse-Battery-9!", ""); rr.Code == 200 {
		t.Fatal("repeated bad re-auth must lock the IP out")
	}
}

func TestWSRejectsMissingTicket(t *testing.T) {
	termLab(t)
	cfg.TerminalEnabled = true
	tok := newSessionToken()
	addSession(tok)
	defer dropSession(tok)
	req := httptest.NewRequest("GET", "/api/term/ws", nil)
	req.AddCookie(&http.Cookie{Name: "gre_session", Value: tok})
	rr := httptest.NewRecorder()
	handleTermWS(rr, req)
	if rr.Code != http.StatusUnauthorized || !strings.Contains(rr.Body.String(), "E-TERM-16") {
		t.Fatalf("ws without ticket must be refused: %d %s", rr.Code, rr.Body.String())
	}
}

func TestAllowlistCannotLockOutCaller(t *testing.T) {
	termLab(t)
	post := func(ips []string) int {
		b, _ := json.Marshal(map[string][]string{"ips": ips})
		req := httptest.NewRequest("POST", "/x", bytes.NewReader(b))
		req.RemoteAddr = "203.0.113.5:1"
		rr := httptest.NewRecorder()
		handleTermAllowPost(rr, req)
		return rr.Code
	}
	if post([]string{"198.51.100.1"}) == 200 {
		t.Error("list excluding the caller must be refused")
	}
	if post([]string{"bad"}) == 200 {
		t.Error("invalid entry must be refused")
	}
	if post([]string{"203.0.113.0/24"}) != 200 || len(cfg.TerminalAllowIPs) != 1 {
		t.Error("list including the caller must be accepted")
	}
	if post(nil) != 200 || len(cfg.TerminalAllowIPs) != 0 {
		t.Error("empty list must clear the allowlist")
	}
}
