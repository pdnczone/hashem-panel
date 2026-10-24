package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// withPeerRole sets this server's Peer Link role and secret for one test.
func withPeerRole(t *testing.T, role, secret string) {
	t.Helper()
	old, readErr := os.ReadFile(peerConfigFile())
	c := loadPeerConfig()
	c.Role, c.PeerSecret = role, secret
	if err := savePeerConfig(c); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if readErr == nil {
			_ = os.WriteFile(peerConfigFile(), old, 0o600)
		} else {
			_ = os.Remove(peerConfigFile())
		}
	})
}

// iranMux is the Iran server's peer API, reached in-process by peerCallJSON.
func iranMux(t *testing.T, secret string) {
	t.Helper()
	mux := http.NewServeMux()
	mountPeerRoutes(mux, "/base")
	old := peerCallJSON
	peerCallJSON = func(method, path string, payload any, timeout time.Duration) (int, []byte, error) {
		var body []byte
		if payload != nil {
			body, _ = json.Marshal(payload)
		}
		req := httptest.NewRequest(method, peerRoutePrefix+path, strings.NewReader(string(body)))
		req.Header.Set("X-Peer-Secret", secret)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if !json.Valid(w.Body.Bytes()) {
			return w.Code, nil, nil
		}
		return w.Code, w.Body.Bytes(), nil
	}
	t.Cleanup(func() { peerCallJSON = old })
}

// The foreign server of peer 2 asks the hub, with its own token, to swap its
// tunnel: the hub runs the swap of tunnel 2, foreign server told first.
func TestPeerSwapRequestSwapsTheCallersTunnel(t *testing.T) {
	swapLab(t)
	rec := swapStubs(t)
	rec.linked["frp:kcp"] = true
	iranMux(t, "tok-2")

	status, data, err := peerCallJSON("GET", "/api/peer/swap-request", nil, time.Second)
	if err != nil || status != 200 || !strings.Contains(string(data), `"current":"frp:tcp"`) || !strings.Contains(string(data), `"id":2`) {
		t.Fatalf("view: %d %s %v", status, data, err)
	}
	status, data, err = peerCallJSON("POST", "/api/peer/swap-request", map[string]string{"carrier": "frp:kcp"}, time.Second)
	if err != nil || status != 200 || !strings.Contains(string(data), "started") {
		t.Fatalf("start: %d %s %v", status, data, err)
	}
	if j := waitSwap(t, 2); j.State != "ok" {
		t.Fatalf("state %s (%s)", j.State, j.Error)
	}
	if strings.Join(rec.foreign, ",") != "frp:kcp" || strings.Join(rec.local, ",") != "frp:kcp" {
		t.Errorf("foreign %v local %v", rec.foreign, rec.local)
	}
	// a wrong secret sees nothing
	iranMux(t, "wrong")
	if status, data, _ := peerCallJSON("POST", "/api/peer/swap-request", map[string]string{"carrier": "frp:tcp"}, time.Second); status != 404 || data != nil {
		t.Errorf("wrong secret: %d %s", status, data)
	}
}

// On the foreign server the swap dialog shows the Iran server's view and the
// swap is started there.
func TestForeignSwapGoesThroughTheIranServer(t *testing.T) {
	engineLab(t, []string{"frpc"}, nil)
	_ = os.Remove(peersFile())
	var sent []string
	old := peerCallJSON
	peerCallJSON = func(method, path string, payload any, timeout time.Duration) (int, []byte, error) {
		if method == "POST" {
			b, _ := json.Marshal(payload)
			sent = append(sent, path+" "+string(b))
			return 200, []byte(`{"status":"started","job":{"id":2,"state":"running","from":"frp:tcp","to":"frp:kcp"}}`), nil
		}
		sent = append(sent, path)
		return 200, []byte(`{"id":2,"tunnel":{"id":2,"main":false,"name":"nl"},"current":"frp:tcp","backhaul_pro":true,"bins":{"frps":true,"backhaul":true},"follow":true}`), nil
	}
	t.Cleanup(func() { peerCallJSON = old })

	w := httptest.NewRecorder()
	handleSwapGet(w, httptest.NewRequest("GET", "/api/tunnel/swap?id=0&probe=1", nil))
	var v map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &v)
	if v["via_iran"] != true || v["current"] != "frp:tcp" || v["follow"] != true || v["id"] != float64(0) {
		t.Fatalf("view: %s", w.Body.String())
	}
	bins := v["bins"].(map[string]any)
	if bins["frps"] != true || bins["backhaul"] != false {
		t.Errorf("an engine missing here must show as missing: %v", bins)
	}
	if v["backhaul_pro"] != false {
		t.Error("moving this server onto Backhaul needs Pro here too")
	}

	w = httptest.NewRecorder()
	handleSwapPost(w, httptest.NewRequest("POST", "/api/tunnel/swap", strings.NewReader(`{"id":0,"carrier":"frp:kcp"}`)))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"state":"running"`) {
		t.Fatalf("start: %d %s", w.Code, w.Body.String())
	}
	if got := strings.Join(sent, " | "); !strings.Contains(got, `/api/peer/swap-request {"carrier":"frp:kcp"}`) || !strings.Contains(got, "/api/peer/swap-request?probe=1") {
		t.Errorf("sent: %s", got)
	}

	// an older Iran panel
	peerCallJSON = func(string, string, any, time.Duration) (int, []byte, error) { return 404, nil, nil }
	w = httptest.NewRecorder()
	handleSwapGet(w, httptest.NewRequest("GET", "/api/tunnel/swap?id=0", nil))
	if !strings.Contains(w.Body.String(), "older panel") || !strings.Contains(w.Body.String(), `"foreign_side":true`) {
		t.Errorf("older Iran panel: %s", w.Body.String())
	}
}

// The GRE wrap from the foreign server: the Iran server switches both and
// reports the end; the IPv6 ends arrive seen from the Iran side.
func TestWrapSwitchFromTheForeignServer(t *testing.T) {
	withPeerRole(t, "master", "link-secret")
	iranMux(t, "link-secret")
	oldFn, oldPoll := wrapSwitchFn, wrapPollEvery
	wrapPollEvery = time.Millisecond
	var got []string
	wrapSwitchFn = func(target string, o carrier6Opts) (string, error) {
		got = append(got, target+" "+o.Local6+" "+o.Remote6)
		time.Sleep(5 * time.Millisecond)
		return "Both servers now use " + target, nil
	}
	t.Cleanup(func() { wrapSwitchFn, wrapPollEvery = oldFn, oldPoll })

	detail, asked, err := switchCarrierViaIran(carrier4in6, carrier6Opts{Local6: "2001:db8::2", Remote6: "2001:db8::1"})
	if err != nil || !asked || detail != "Both servers now use 4in6" {
		t.Fatalf("detail %q asked %v err %v", detail, asked, err)
	}
	if len(got) != 1 || got[0] != "4in6 2001:db8::1 2001:db8::2" {
		t.Errorf("the Iran side must get its own IPv6 as local6: %v", got)
	}

	wrapSwitchFn = func(target string, o carrier6Opts) (string, error) {
		return "", os.ErrDeadlineExceeded
	}
	if _, asked, err := switchCarrierViaIran(carrier6to4, carrier6Opts{}); !asked || err == nil {
		t.Errorf("a failed switch must come back as an error: asked %v err %v", asked, err)
	}
	if _, _, err := switchCarrierViaIran("frp:kcp", carrier6Opts{}); err == nil || !strings.Contains(err.Error(), "not a GRE wrap") {
		t.Errorf("an engine is not a wrap: %v", err)
	}

	// a peer's own token may not switch the main tunnel's wrap
	swapLab(t)
	iranMux(t, "tok-2")
	if _, asked, err := switchCarrierViaIran(carrier6to4, carrier6Opts{}); !asked || err == nil || !strings.Contains(err.Error(), "Edit peer") {
		t.Errorf("peer token: asked %v err %v", asked, err)
	}

	// an older Iran panel: nothing was asked, the caller switches alone
	peerCallJSON = func(string, string, any, time.Duration) (int, []byte, error) { return 404, nil, nil }
	if _, asked, err := switchCarrierViaIran(carrier6to4, carrier6Opts{}); asked || err != errOldIranPanel {
		t.Errorf("older panel: asked %v err %v", asked, err)
	}
}
