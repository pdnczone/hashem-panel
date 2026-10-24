package main

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAdviceNeedsEnoughSamples(t *testing.T) {
	a := adviseCarrier("direct", []string{"direct", "wss:8443"}, map[string]carrierStat{"direct": {Down: 5}})
	if len(a) != 1 || a[0].Level != "info" || a[0].Suggest != "" {
		t.Fatalf("too few samples must not advise a switch: %+v", a)
	}
}

func TestAdviceStableCarrierIsOK(t *testing.T) {
	a := adviseCarrier("direct", []string{"direct", "wss:8443"}, map[string]carrierStat{"direct": {Up: 95, Down: 5}})
	if a[0].Level != "ok" || a[0].Suggest != "" {
		t.Fatalf("%+v", a)
	}
}

func TestAdviceSuggestsProvenBetterCarrier(t *testing.T) {
	st := map[string]carrierStat{"direct": {Up: 30, Down: 70}, "wss:8443": {Up: 98, Down: 2}}
	a := adviseCarrier("direct", []string{"direct", "wss:8443"}, st)
	if a[0].Level != "warn" || a[0].Suggest != "wss:8443" || !strings.Contains(a[0].Message, "did better") {
		t.Fatalf("%+v", a)
	}
}

func TestAdviceSuggestsUntriedWhenNoProvenAlternative(t *testing.T) {
	st := map[string]carrierStat{"direct": {Up: 30, Down: 70}}
	a := adviseCarrier("direct", []string{"direct", "wss:8443"}, st)
	if a[0].Suggest != "wss:8443" || !strings.Contains(a[0].Message, "not been tried") {
		t.Fatalf("%+v", a)
	}
}

func TestAdviceWorseAlternativeIsNotSuggested(t *testing.T) {
	st := map[string]carrierStat{"direct": {Up: 50, Down: 50}, "wss:8443": {Up: 10, Down: 90}}
	a := adviseCarrier("direct", []string{"direct", "wss:8443"}, st)
	if a[0].Suggest != "" || !strings.Contains(a[0].Message, "No better carrier") {
		t.Fatalf("a worse carrier must not be recommended: %+v", a)
	}
}

func TestAdvisorRecordRateLimitAndDecay(t *testing.T) {
	a := &carrierAdvisor{stats: map[string]*carrierStat{}}
	t0 := time.Unix(1_700_000_000, 0)
	a.record(t0, "direct", stateHealthy)
	a.record(t0.Add(5*time.Second), "direct", stateDown) // within 30 s: ignored
	if s := a.snapshot()["direct"]; s.Up != 1 || s.Down != 0 {
		t.Fatalf("%+v", s)
	}
	a.record(t0.Add(time.Minute), "", stateDown)
	a.record(t0.Add(2*time.Minute), "direct", "")
	if len(a.snapshot()) != 1 {
		t.Fatal("empty carrier/state must be ignored")
	}
	a = &carrierAdvisor{stats: map[string]*carrierStat{"direct": {Up: advMaxSamples}}}
	a.record(t0, "direct", stateDown)
	if s := a.snapshot()["direct"]; s.total() > advMaxSamples {
		t.Fatalf("counters must decay: %+v", s)
	}
}

func TestAdviceEndpointNeverAutoSwitches(t *testing.T) {
	rr := httptest.NewRecorder()
	handleCarrierAdvice(rr, httptest.NewRequest("GET", "/x", nil))
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"auto_switch":false`) {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
}

func TestSuggestPorts(t *testing.T) {
	free := func(p int) bool { return p != 8443 }
	got := suggestPorts(map[int]bool{443: true}, free, 3)
	want := []int{2053, 2083, 2087}
	if len(got) != 3 || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Fatalf("got %v want %v (443 reserved, 8443 busy)", got, want)
	}
	seen := map[int]bool{}
	for _, p := range suggestPorts(nil, nil, 50) {
		if seen[p] {
			t.Fatalf("duplicate port %d", p)
		}
		seen[p] = true
	}
	if len(suggestPorts(nil, func(int) bool { return false }, 3)) != 0 {
		t.Fatal("nothing free -> no suggestion")
	}
}

func TestSuggestSNIAndValidation(t *testing.T) {
	got := suggestSNI("www.microsoft.com", 3)
	if len(got) != 3 || got[0] == "www.microsoft.com" {
		t.Fatalf("must skip the current SNI: %v", got)
	}
	for _, s := range preferredSNI {
		if !validSNI(s) {
			t.Errorf("preferred SNI %q invalid", s)
		}
	}
	for _, bad := range []string{"", "nodot", ".x.com", "x.com.", "a b.com", "-a.com", "a..com", strings.Repeat("a", 64) + ".com"} {
		if validSNI(bad) {
			t.Errorf("validSNI(%q) should be false", bad)
		}
	}
}

func TestSuggestEndpoint(t *testing.T) {
	for kind, key := range map[string]string{"port": "ports", "sni": "sni"} {
		rr := httptest.NewRecorder()
		handleSuggest(rr, httptest.NewRequest("GET", "/x?kind="+kind, nil))
		if rr.Code != 200 || !strings.Contains(rr.Body.String(), key) {
			t.Errorf("%s: %d %s", kind, rr.Code, rr.Body.String())
		}
	}
	rr := httptest.NewRecorder()
	handleSuggest(rr, httptest.NewRequest("GET", "/x?kind=bad", nil))
	if rr.Code == 200 {
		t.Error("bad kind must fail")
	}
}

// With direct down and nothing else tried, 6to4 is suggested first: it needs
// only the IPv4 addresses. 4in6 is offered only on a server with IPv6.
func TestAdvisorCandidatesIPv6(t *testing.T) {
	if got := strings.Join(advisorCandidates([]string{"direct", "wss:8443"}, false), ","); got != "direct,6to4,wss:8443" {
		t.Fatalf("no IPv6: %s", got)
	}
	if got := strings.Join(advisorCandidates([]string{"direct", "wss:8443"}, true), ","); got != "direct,6to4,wss:8443,4in6" {
		t.Fatalf("with IPv6: %s", got)
	}
	if got := strings.Join(advisorCandidates([]string{"wss:8443", "6to4"}, false), ","); got != "wss:8443,6to4" {
		t.Fatalf("6to4 already there: %s", got)
	}
	a := adviseCarrier("direct", advisorCandidates([]string{"direct", "wss:8443"}, false), map[string]carrierStat{"direct": {Down: 30}})
	if len(a) != 1 || a[0].Suggest != "6to4" {
		t.Fatalf("direct down: %+v", a)
	}
}
