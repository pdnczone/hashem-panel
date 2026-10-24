package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeWorker is the other server over the Peer Link: it records the carriers
// it was told to apply and answers carrier-info with its IPv6.
func fakeWorker(t *testing.T, ip6 string) (*[]PeerApplyCarrierRequest, *sync.Mutex) {
	t.Helper()
	var mu sync.Mutex
	got := []PeerApplyCarrierRequest{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/api/peer/apply-carrier"):
			var req PeerApplyCarrierRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			mu.Lock()
			got = append(got, req)
			mu.Unlock()
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		case strings.HasSuffix(r.URL.Path, "/api/peer/carrier-info"):
			_, _ = w.Write([]byte(`{"public_ip6":"` + ip6 + `"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	withPeerLink(t, PeerConfig{Role: "master", PeerSecret: "s3cret", PeerURL: srv.URL, IsConnected: true, AutoPilotExplicit: true})
	return &got, &mu
}

func withCarrierVerify(t *testing.T, up func() bool) {
	t.Helper()
	oldUp, oldWait, oldTick := carrierLinkUp, carrierVerifyWait, carrierVerifyTick
	carrierLinkUp, carrierVerifyWait, carrierVerifyTick = up, 50*time.Millisecond, 10*time.Millisecond
	t.Cleanup(func() { carrierLinkUp, carrierVerifyWait, carrierVerifyTick = oldUp, oldWait, oldTick })
}

func TestCarrier6Applicable(t *testing.T) {
	for _, c := range []string{"6to4", "4in6", "direct", "wss:8443"} {
		if err := carrierApplicable(c); err != nil {
			t.Errorf("%s: %v", c, err)
		}
	}
	if err := carrierApplicable("6in4x"); err == nil {
		t.Error("unknown carrier accepted")
	}
	if got := (carrier6Opts{Local6: "2001:db8::1", Remote6: "2001:db8::2"}).args(); strings.Join(got, " ") != "--local6 2001:db8::1 --remote6 2001:db8::2" {
		t.Errorf("args: %v", got)
	}
}

func TestSwitchCarrierBothServers(t *testing.T) {
	got, mu := fakeWorker(t, "2001:db8::2")
	withCarrierVerify(t, func() bool { return true })
	detail, err := switchCarrier("6to4", carrier6Opts{})
	if err != nil || !strings.Contains(detail, "Both servers") {
		t.Fatalf("6to4: %q %v", detail, err)
	}
	if loadCarrierConfig().ActiveCarrier != "6to4" {
		t.Errorf("this server is on %q", loadCarrierConfig().ActiveCarrier)
	}
	// 4in6: this server's IPv6 given, the worker's asked over the Peer Link;
	// the worker gets them the other way round
	if _, err := switchCarrier("4in6", carrier6Opts{Local6: "2001:db8::1"}); err != nil {
		t.Fatalf("4in6: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(*got) != 2 || (*got)[0].Carrier != "6to4" || (*got)[1] != (PeerApplyCarrierRequest{Carrier: "4in6", Local6: "2001:db8::2", Remote6: "2001:db8::1"}) {
		t.Fatalf("worker was told %+v", *got)
	}
}

func TestSwitchCarrierUndoneWhenTunnelSilent(t *testing.T) {
	got, mu := fakeWorker(t, "")
	withCarrierVerify(t, func() bool { return false })
	if _, err := applyCarrierMode("direct"); err != nil && !strings.Contains(err.Error(), "script not found") {
		t.Fatal(err)
	}
	_, err := switchCarrier("6to4", carrier6Opts{})
	if err == nil || !strings.Contains(err.Error(), "back on direct") {
		t.Fatalf("silent tunnel: %v", err)
	}
	if a := loadCarrierConfig().ActiveCarrier; a != "direct" {
		t.Errorf("this server stayed on %q", a)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(*got) != 2 || (*got)[0].Carrier != "6to4" || (*got)[1].Carrier != "direct" {
		t.Fatalf("worker was told %+v, want 6to4 then direct", *got)
	}
}

func TestSwitchCarrier4in6NeedsAddresses(t *testing.T) {
	_, _ = fakeWorker(t, "") // the worker has no IPv6
	withCarrierVerify(t, func() bool { return true })
	if _, err := switchCarrier("4in6", carrier6Opts{Local6: "2001:db8::1"}); err == nil || !strings.Contains(err.Error(), "other server") {
		t.Errorf("worker without IPv6: %v", err)
	}
	if _, err := switchCarrier("4in6", carrier6Opts{Local6: "fd00::1", Remote6: "2001:db8::2"}); err == nil || !strings.Contains(err.Error(), "not a public IPv6") {
		t.Errorf("private IPv6 accepted: %v", err)
	}
	if a := loadCarrierConfig().ActiveCarrier; a == "4in6" {
		t.Error("switched although refused")
	}
}

func TestPeerApplyCarrier4in6(t *testing.T) {
	withPeerLink(t, PeerConfig{Role: "worker", PeerSecret: "s3cret"})
	rr := httptest.NewRecorder()
	handlePeerApplyCarrier(rr, httptest.NewRequest("POST", "/api/peer/apply-carrier", strings.NewReader(`{"carrier":"4in6","local6":"2001:db8::2","remote6":"10.0.0.1"}`)))
	if rr.Code != 400 {
		t.Errorf("IPv4 as remote6: %d %s", rr.Code, rr.Body.String())
	}
	rr = httptest.NewRecorder()
	handlePeerApplyCarrier(rr, httptest.NewRequest("POST", "/api/peer/apply-carrier", strings.NewReader(`{"carrier":"4in6","local6":"2001:db8::2","remote6":"2001:db8::1"}`)))
	// valid addresses get through to hashem.sh (not installed here)
	if rr.Code == 400 || loadCarrierConfig().ActiveCarrier != "4in6" {
		t.Errorf("4in6 from the master: %d %s", rr.Code, rr.Body.String())
	}
}
