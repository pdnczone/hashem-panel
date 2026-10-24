package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseDialStatus(t *testing.T) {
	m := parseDialStatus("available=1\nmode=auto\nactive=gre\naddr=10.10.10.2\nevil=x\nnoequals\nport=55354\n")
	if m["available"] != true || m["mode"] != "auto" || m["active"] != "gre" || m["addr"] != "10.10.10.2" || m["port"] != "55354" {
		t.Errorf("parsed wrong: %v", m)
	}
	if _, ok := m["evil"]; ok {
		t.Error("unknown keys must be dropped")
	}
	if parseDialStatus("")["available"] != false {
		t.Error("empty output = unavailable")
	}
	if parseDialStatus("available=0")["available"] != false {
		t.Error("available=0 must be false")
	}
}

func TestValidDialMode(t *testing.T) {
	for m, want := range map[string]bool{"auto": true, "gre": true, "public": true, "": false, "AUTO": false, "gre; reboot": false} {
		if validDialMode(m) != want {
			t.Errorf("validDialMode(%q) != %v", m, want)
		}
	}
}

func TestDialPostRejectsBadInput(t *testing.T) {
	for _, body := range []string{`not json`, `{"mode":""}`, `{"mode":"gre; rm -rf /"}`, `{"mode":"direct"}`} {
		rr := httptest.NewRecorder()
		handleDialPost(rr, httptest.NewRequest("POST", "/x", strings.NewReader(body)))
		if rr.Code == http.StatusOK {
			t.Errorf("body %q must be rejected, got 200", body)
		}
	}
}

func TestSplitLogLines(t *testing.T) {
	got := splitLogLines("\n  a  \n\n b\n   \n")
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("got %q", got)
	}
	if len(splitLogLines("")) != 0 || len(splitLogLines("  \n \n")) != 0 {
		t.Error("blank input must give no lines")
	}
}

func TestStripANSI(t *testing.T) {
	if got := stripANSI("\x1b[0;32m[ok]\x1b[0m done \x1b[1;31mfail\x1b[0m"); got != "[ok] done fail" {
		t.Errorf("got %q", got)
	}
	if got := stripANSI("plain"); got != "plain" {
		t.Error("plain text must be unchanged")
	}
	if got := stripANSI("trunc\x1b[0;3"); !strings.HasPrefix(got, "trunc") {
		t.Errorf("truncated escape must not panic: %q", got)
	}
}

func TestIsMissingRemovePeer(t *testing.T) {
	for out, want := range map[string]bool{"Unknown command: remove-peer": true, "unknown flag --x": true, "removed ok": false, "": false} {
		if isMissingRemovePeer(out) != want {
			t.Errorf("isMissingRemovePeer(%q) != %v", out, want)
		}
	}
}

func TestGrePeerInner(t *testing.T) {
	for in, want := range map[string]string{
		"10.10.10.1/30": "10.10.10.2", "10.10.10.2/30": "10.10.10.1",
		"10.10.20.5": "10.10.20.6", "10.10.20.6": "10.10.20.5",
		"bad": "", "1.2.3/30": "",
	} {
		if got := grePeerInner(in); got != want {
			t.Errorf("grePeerInner(%q)=%q want %q", in, got, want)
		}
	}
}

func TestBundleKindDetection(t *testing.T) {
	for s, want := range map[string]bool{
		"hsh1_1.2.3.4_5000_a_b_tok": true, "  bh1_x": true, "gh1_x": true,
		"0123456789abcdef0123456789abcdef": false, "": false, "xhsh1_": false,
	} {
		if isBundle(s) != want {
			t.Errorf("isBundle(%q) != %v", s, want)
		}
	}
	if !isBackhaulBundle(" bh1_x") || isBackhaulBundle("gh1_x") || !isGreBackhaulBundle(" gh1_x") || isGreBackhaulBundle("bh1_x") {
		t.Error("bundle kinds must not overlap")
	}
}

func TestRandomFrpPortInRange(t *testing.T) {
	seen := map[int]bool{}
	for i := 0; i < 200; i++ {
		p := randomFrpPort()
		if p < defaultFrpPortMin || p > defaultFrpPortMax {
			t.Fatalf("port %d out of range", p)
		}
		seen[p] = true
	}
	if len(seen) < 100 {
		t.Errorf("ports look non-random: %d distinct of 200", len(seen))
	}
}

func TestPeerUnitNamesFallBackToDefaults(t *testing.T) {
	if peerFrpsSvc(0) != "frps" || peerGreSvc(0) != "gre-tunnel.service" {
		t.Error("peer 0 = legacy default units")
	}
	if peerFrpsSvc(7) != "frps-7" || peerGreSvc(7) != "gre-t7.service" {
		t.Errorf("unregistered peer 7 falls back to numbered names: %s %s", peerFrpsSvc(7), peerGreSvc(7))
	}
}

func TestHandleActionRejectsUnknownAndBadJSON(t *testing.T) {
	for _, body := range []string{`nope`, `{"action":"rm-rf"}`, `{"action":""}`} {
		rr := httptest.NewRecorder()
		handleAction(rr, httptest.NewRequest("POST", "/x", strings.NewReader(body)))
		if rr.Code == http.StatusOK {
			t.Errorf("body %q must be rejected", body)
		}
	}
}
