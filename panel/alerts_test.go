package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

var alT0 = time.Unix(1_700_000_000, 0)

func lsUp(n string) linkSnap   { return linkSnap{Name: n, State: stateHealthy} }
func lsDown(n string) linkSnap { return linkSnap{Name: n, State: stateDown, Why: "no session"} }

func TestBaselineTickNeverAlerts(t *testing.T) {
	tr := newAlertTracker()
	if ev := tr.observe(alT0, []linkSnap{lsDown("a"), lsUp("b")}, alertConfig{MinGapSec: 120}); len(ev) != 0 {
		t.Fatalf("first snapshot must only record a baseline, got %v", ev)
	}
}

func TestOnlyStateChangesAlert(t *testing.T) {
	tr := newAlertTracker()
	c := alertConfig{MinGapSec: 120}
	tr.observe(alT0, []linkSnap{lsUp("a")}, c)
	for i := 1; i <= 5; i++ { // steady state: no alerts
		if ev := tr.observe(alT0.Add(time.Duration(i)*5*time.Second), []linkSnap{lsUp("a")}, c); len(ev) != 0 {
			t.Fatalf("steady state must not alert: %v", ev)
		}
	}
	ev := tr.observe(alT0.Add(time.Minute), []linkSnap{lsDown("a")}, c)
	if len(ev) != 1 || ev[0].From != stateHealthy || ev[0].To != stateDown || ev[0].Why != "no session" {
		t.Fatalf("down transition: %+v", ev)
	}
	if ev := tr.observe(alT0.Add(70*time.Second), []linkSnap{lsDown("a")}, c); len(ev) != 0 {
		t.Fatal("staying down must not repeat the alert")
	}
	ev = tr.observe(alT0.Add(5*time.Minute), []linkSnap{lsUp("a")}, c)
	if len(ev) != 1 || ev[0].To != stateHealthy {
		t.Fatalf("recovery must alert: %+v", ev)
	}
}

func TestDegradedOnlyWhenOptedIn(t *testing.T) {
	deg := linkSnap{Name: "a", State: stateDegraded}
	tr := newAlertTracker()
	tr.observe(alT0, []linkSnap{lsUp("a")}, alertConfig{MinGapSec: 120})
	if ev := tr.observe(alT0.Add(time.Hour), []linkSnap{deg}, alertConfig{MinGapSec: 120}); len(ev) != 0 {
		t.Fatalf("degraded is silent by default: %v", ev)
	}
	tr = newAlertTracker()
	tr.observe(alT0, []linkSnap{lsUp("a")}, alertConfig{MinGapSec: 120, NotifyDegrad: true})
	if ev := tr.observe(alT0.Add(time.Hour), []linkSnap{deg}, alertConfig{MinGapSec: 120, NotifyDegrad: true}); len(ev) != 1 {
		t.Fatalf("degraded alerts when opted in: %v", ev)
	}
}

func TestFlappingIsRateLimitedPerLink(t *testing.T) {
	tr := newAlertTracker()
	c := alertConfig{MinGapSec: 120}
	tr.observe(alT0, []linkSnap{lsUp("a"), lsUp("b")}, c)
	if ev := tr.observe(alT0.Add(10*time.Second), []linkSnap{lsDown("a"), lsUp("b")}, c); len(ev) != 1 {
		t.Fatal("first flap alerts")
	}
	if ev := tr.observe(alT0.Add(20*time.Second), []linkSnap{lsUp("a"), lsUp("b")}, c); len(ev) != 0 {
		t.Fatalf("recovery within the gap is suppressed: %v", ev)
	}
	if ev := tr.observe(alT0.Add(30*time.Second), []linkSnap{lsUp("a"), lsDown("b")}, c); len(ev) != 1 || ev[0].Link != "b" {
		t.Fatalf("another link is not affected by a's gap: %v", ev)
	}
}

func TestRemovedLinkForgotten(t *testing.T) {
	tr := newAlertTracker()
	c := alertConfig{MinGapSec: 10}
	tr.observe(alT0, []linkSnap{lsUp("a")}, c)
	tr.observe(alT0.Add(time.Minute), nil, c)
	if len(tr.last) != 0 {
		t.Fatal("removed link must be dropped from memory")
	}
	if ev := tr.observe(alT0.Add(2*time.Minute), []linkSnap{lsDown("a")}, c); len(ev) != 0 {
		t.Fatal("a re-added link starts from a fresh baseline")
	}
}

func TestWebhookDeliveryAndSecretMasking(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &got)
	}))
	defer srv.Close()
	e := alertEvent{Link: "tun1", From: stateHealthy, To: stateDown, Why: "x", Host: "h1"}
	if err := sendWebhook(srv.URL+"/hook/SECRETPATH", e); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got["text"].(string), "tun1") || !strings.Contains(got["text"].(string), "🔴") {
		t.Errorf("payload text: %v", got)
	}
	srv.Close()
	err := sendWebhook(srv.URL+"/hook/SECRETPATH", e)
	if err == nil || strings.Contains(err.Error(), "SECRETPATH") {
		t.Errorf("error must fail and not leak the secret path: %v", err)
	}
	if m := maskURL("https://hooks.example.com/services/AAA/BBB"); strings.Contains(m, "AAA") {
		t.Errorf("masked url leaks: %s", m)
	}
}

func TestWebhookURLValidation(t *testing.T) {
	for u, want := range map[string]bool{"": true, "https://x.io/a": true, "http://1.2.3.4:80/h": true, "ftp://x/y": false, "javascript:alert(1)": false, "https://": false, "/relative": false} {
		if validWebhookURL(u) != want {
			t.Errorf("validWebhookURL(%q) != %v", u, want)
		}
	}
}

func TestAlertsAPIKeepsMaskedWebhookAndRejectsBad(t *testing.T) {
	_ = saveAlertConfig(alertConfig{WebhookURL: "https://hooks.example.com/secret/xyz"})
	post := func(body string) int {
		rr := httptest.NewRecorder()
		handleAlertsPost(rr, httptest.NewRequest("POST", "/x", strings.NewReader(body)))
		return rr.Code
	}
	if post(`{"webhook_url":"https://hooks.example.com/…","enabled":true}`) != 200 || loadAlertConfig().WebhookURL != "https://hooks.example.com/secret/xyz" {
		t.Error("echoing the masked URL must leave the stored secret unchanged")
	}
	if post(`{"webhook_url":"ftp://bad"}`) == 200 {
		t.Error("bad scheme must be rejected")
	}
	rr := httptest.NewRecorder()
	handleAlertsGet(rr, httptest.NewRequest("GET", "/x", nil))
	if strings.Contains(rr.Body.String(), "xyz") {
		t.Errorf("GET must never return the webhook secret: %s", rr.Body.String())
	}
}

func TestSnapshotHookSendsOnlyWhenEnabledAndChanged(t *testing.T) {
	old, oldTrk := alertSend, alertTrk
	defer func() { alertSend, alertTrk = old, oldTrk }()
	alertTrk = newAlertTracker()
	sent := make(chan []alertEvent, 4)
	alertSend = func(c alertConfig, ev []alertEvent) { sent <- ev }
	snap := func(state string) *HubSnapshot {
		return &HubSnapshot{Peers: []peerLive{{peerRecord: peerRecord{ID: 2, Name: "p"}, HealthState: state}}}
	}
	_ = saveAlertConfig(alertConfig{Enabled: false})
	alertsOnSnapshot(snap(stateHealthy))
	alertsOnSnapshot(snap(stateDown))
	select {
	case <-sent:
		t.Fatal("disabled alerts must not send")
	case <-time.After(50 * time.Millisecond):
	}
	_ = saveAlertConfig(alertConfig{Enabled: true, MinGapSec: 10})
	alertsOnSnapshot(snap(stateDown)) // primes tracker (baseline)
	alertsOnSnapshot(snap(stateHealthy))
	select {
	case ev := <-sent:
		if len(ev) != 1 || ev[0].To != stateHealthy {
			t.Fatalf("unexpected: %+v", ev)
		}
	case <-time.After(time.Second):
		t.Fatal("expected one alert on recovery")
	}
}
