package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestParseCarrierChoice(t *testing.T) {
	good := map[string]string{
		"frp":                 "frp:tcp",
		"FRP:KCP":             "frp:kcp",
		"frp:ws":              "frp:websocket",
		"backhaul":            "backhaul:tcpmux",
		"backhaul:wssmux":     "backhaul:wssmux",
		"gre-backhaul:udp":    "gre-backhaul:udp",
		" gre-backhaul:tcp  ": "gre-backhaul:tcp",
	}
	for in, want := range good {
		c, err := parseCarrierChoice(in)
		if err != nil || c.ID() != want {
			t.Errorf("parseCarrierChoice(%q) = %q, %v; want %q", in, c.ID(), err, want)
		}
	}
	for _, in := range []string{"", "frp:wss", "frp:tcpmux", "backhaul:kcp", "bagher", "direct", "wss:8443"} {
		if _, err := parseCarrierChoice(in); err == nil {
			t.Errorf("parseCarrierChoice(%q) should fail", in)
		}
	}
	if !(carrierChoice{Engine: "frp"}).needsGRE() || !(carrierChoice{Engine: "gre-backhaul"}).needsGRE() || (carrierChoice{Engine: "backhaul"}).needsGRE() {
		t.Error("needsGRE: frp and gre-backhaul need GRE, backhaul does not")
	}
}

func TestPeerCarrierFromRecord(t *testing.T) {
	cases := []struct {
		p    peerRecord
		want string
	}{
		{peerRecord{FrpsSvc: "frps-2"}, "frp:tcp"},
		{peerRecord{FrpsSvc: "frps-2", FRPTransport: "quic"}, "frp:quic"},
		{peerRecord{FrpsSvc: "backhaul-server-3", NoGre: true, Transport: "wssmux"}, "backhaul:wssmux"},
		{peerRecord{FrpsSvc: "backhaul-server-3"}, "gre-backhaul:tcpmux"},
		{peerRecord{Engine: "backhaul", Transport: "bogus"}, "backhaul:tcpmux"},
	}
	for _, c := range cases {
		if got := peerCarrier(c.p).ID(); got != c.want {
			t.Errorf("peerCarrier(%+v) = %s, want %s", c.p, got, c.want)
		}
	}
}

// swapLab: a hub with one FRP peer (id 2) and its files on disk.
func swapLab(t *testing.T) peerRecord {
	t.Helper()
	engineLab(t, []string{"frps", "frpc", "backhaul"}, []string{"gre-t2"})
	oldV := backhaulCoreVersion
	backhaulCoreVersion = func() string { return "v0.7.2" }
	t.Cleanup(func() { backhaulCoreVersion = oldV })
	for _, d := range []string{frpDir, backhaulDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	p := peerRecord{ID: 2, Name: "nl", LocalPub: "5.5.5.5", RemotePub: "92.2.2.2", FrpPort: 7001,
		LocalGre: "10.80.2.1", PeerGre: "10.80.2.2", Ports: []int{2083, 8443}, Token: "tok-2",
		GreIf: "gre-t2", FrpsSvc: "frps-2"}
	writePeersJSON(t, p)
	mustWrite(t, filepath.Join(frpDir, "frps-2.toml"), "bindPort = 7001\n")
	mustWrite(t, filepath.Join(engineUnitDir, "frps-2.service"), "[Service]\nExecStart=/usr/local/bin/frps -c frps-2.toml\n")
	t.Cleanup(func() {
		for _, f := range []string{peersFile(), filepath.Join(frpDir, "frps-2.toml"), filepath.Join(backhaulDir, "server-2.toml"), swapStatePath(), tunnelLinksPath()} {
			_ = os.Remove(f)
		}
	})
	return p
}

func writePeersJSON(t *testing.T, peers ...peerRecord) {
	t.Helper()
	data, _ := json.MarshalIndent(map[string]any{"peers": peers}, "", "  ")
	mustWrite(t, peersFile(), string(data))
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

func TestSwitchPeerCarrierFRPToBackhaul(t *testing.T) {
	p := swapLab(t)
	calls := recordSystemctl(t, "")
	if out, err := switchPeerCarrier(p, carrierChoice{Engine: "backhaul", Transport: "wssmux"}); err != nil {
		t.Fatalf("switch: %v (%s)", err, out)
	}
	conf := readFile(t, filepath.Join(backhaulDir, "server-2.toml"))
	for _, want := range []string{`bind_addr = "0.0.0.0:7001"`, `transport = "wssmux"`, `token = "tok-2"`, `"2083"`, `"8443"`} {
		if !strings.Contains(conf, want) {
			t.Errorf("server-2.toml lacks %s:\n%s", want, conf)
		}
	}
	unit := readFile(t, filepath.Join(engineUnitDir, "backhaul-server-2.service"))
	if !strings.Contains(unit, "server-2.toml") || strings.Contains(unit, "gre-t2.service") {
		t.Errorf("standalone Backhaul unit should run server-2.toml and not wait for GRE:\n%s", unit)
	}
	for _, gone := range []string{filepath.Join(frpDir, "frps-2.toml"), filepath.Join(engineUnitDir, "frps-2.service")} {
		if _, err := os.Stat(gone); err == nil {
			t.Errorf("%s should be removed after the swap", gone)
		}
	}
	got := findPeer(2)
	if got == nil || got.Engine != "backhaul" || got.Transport != "wssmux" || got.FrpsSvc != "backhaul-server-2" || !got.NoGre || got.Token != "tok-2" || got.GreIf != "gre-t2" {
		t.Errorf("peers.json not updated: %+v", got)
	}
	joined := strings.Join(*calls, "\n")
	for _, want := range []string{"stop frps-2", "restart backhaul-server-2", "disable frps-2"} {
		if !strings.Contains(joined, want) {
			t.Errorf("systemctl calls lack %q:\n%s", want, joined)
		}
	}
}

func TestSwitchPeerCarrierBackToFRPOverGRE(t *testing.T) {
	p := swapLab(t)
	recordSystemctl(t, "")
	if _, err := switchPeerCarrier(p, carrierChoice{Engine: "gre-backhaul", Transport: "tcpmux"}); err != nil {
		t.Fatal(err)
	}
	if u := readFile(t, filepath.Join(engineUnitDir, "backhaul-server-2.service")); !strings.Contains(u, "gre-t2.service") {
		t.Errorf("Backhaul over GRE must start after gre-t2:\n%s", u)
	}
	p2 := *findPeer(2)
	if _, err := switchPeerCarrier(p2, carrierChoice{Engine: "frp", Transport: "kcp"}); err != nil {
		t.Fatal(err)
	}
	conf := readFile(t, filepath.Join(frpDir, "frps-2.toml"))
	for _, want := range []string{"bindPort = 7001", "kcpBindPort = 7001", "quicBindPort = 7002", `auth.token = "tok-2"`} {
		if !strings.Contains(conf, want) {
			t.Errorf("frps-2.toml lacks %s:\n%s", want, conf)
		}
	}
	if _, err := os.Stat(filepath.Join(backhaulDir, "server-2.toml")); err == nil {
		t.Error("the Backhaul config should be gone after moving back to FRP")
	}
	got := findPeer(2)
	if got.Engine != "frp" || got.FRPTransport != "kcp" || got.FrpsSvc != "frps-2" || got.NoGre {
		t.Errorf("peers.json not updated: %+v", got)
	}
}

func TestSwitchPeerCarrierRollsBack(t *testing.T) {
	p := swapLab(t)
	recordSystemctl(t, "restart backhaul-server-2")
	before := readFile(t, peersFile())
	if _, err := switchPeerCarrier(p, carrierChoice{Engine: "backhaul", Transport: "tcpmux"}); err == nil {
		t.Fatal("a unit that does not start must fail the switch")
	}
	if readFile(t, filepath.Join(frpDir, "frps-2.toml")) != "bindPort = 7001\n" {
		t.Error("the old frps config must be put back")
	}
	if _, err := os.Stat(filepath.Join(engineUnitDir, "frps-2.service")); err != nil {
		t.Error("the old frps unit must be kept")
	}
	if _, err := os.Stat(filepath.Join(backhaulDir, "server-2.toml")); err == nil {
		t.Error("the new Backhaul config must be removed again")
	}
	if readFile(t, peersFile()) != before {
		t.Error("peers.json must not change on a failed switch")
	}
}

func TestSwitchPeerCarrierRefusesMissingBinary(t *testing.T) {
	p := swapLab(t)
	engineLab(t, []string{"frps"}, []string{"gre-t2"})
	calls := recordSystemctl(t, "")
	if _, err := switchPeerCarrier(p, carrierChoice{Engine: "backhaul", Transport: "tcpmux"}); err == nil || !strings.Contains(err.Error(), "nothing was changed") {
		t.Fatalf("want a missing-binary error, got %v", err)
	}
	if len(*calls) != 0 {
		t.Errorf("no unit may be touched: %v", *calls)
	}
}

// swapStubs replaces the network and the local switch with recorders.
type swapRec struct {
	mu      sync.Mutex
	foreign []string // carriers the foreign server was told
	local   []string // carriers this server switched to
	linked  map[string]bool
	callErr error
}

func (s *swapRec) log(which *[]string, v string) {
	s.mu.Lock()
	*which = append(*which, v)
	s.mu.Unlock()
}

func swapStubs(t *testing.T) *swapRec {
	t.Helper()
	rec := &swapRec{linked: map[string]bool{}}
	oldCall, oldLocal, oldLinked := swapCall, swapLocalFn, swapLinkedFn
	oldW, oldR, oldP := swapVerifyWait, swapRevertWait, swapPollEvery
	swapVerifyWait, swapRevertWait, swapPollEvery = 30*time.Millisecond, 30*time.Millisecond, time.Millisecond
	swapCall = func(tun swapTunnel, method, path string, payload any, timeout time.Duration) ([]byte, error) {
		if rec.callErr != nil {
			return nil, rec.callErr
		}
		if req, ok := payload.(peerSwapRequest); ok {
			rec.log(&rec.foreign, req.Engine+":"+req.Transport)
		}
		return []byte(`{"status":"ok"}`), nil
	}
	swapLocalFn = func(tun swapTunnel, to carrierChoice) (string, error) {
		rec.log(&rec.local, to.ID())
		return "", nil
	}
	swapLinkedFn = func(tun swapTunnel, to carrierChoice) bool {
		rec.mu.Lock()
		defer rec.mu.Unlock()
		return rec.linked[to.ID()]
	}
	t.Cleanup(func() {
		swapCall, swapLocalFn, swapLinkedFn = oldCall, oldLocal, oldLinked
		swapVerifyWait, swapRevertWait, swapPollEvery = oldW, oldR, oldP
		swapJobsMu.Lock()
		swapJobs = map[int]*swapJob{}
		swapJobsMu.Unlock()
		_ = os.Remove(swapStatePath())
	})
	return rec
}

func waitSwap(t *testing.T, id int) *swapJob {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if j := swapJobView(id); j != nil && j.State != "running" {
			return j
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("swap did not finish")
	return nil
}

func testTunnel() swapTunnel {
	p := peerRecord{ID: 2, Name: "nl", FrpPort: 7001, Token: "tok", LocalPub: "5.5.5.5", LocalGre: "10.80.2.1", PeerGre: "10.80.2.2", Ports: []int{2083}}
	return swapTunnel{ID: 2, Name: "nl", Current: carrierChoice{Engine: "frp", Transport: "tcp"}, GreOK: true, Port: 7001,
		Ports: []int{2083}, Raw: []string{"2083"}, LocalPub: "5.5.5.5", LocalGre: "10.80.2.1", PeerGre: "10.80.2.2", Token: "tok", rec: &p}
}

func TestSwapSucceedsWhenTheTunnelComesBack(t *testing.T) {
	rec := swapStubs(t)
	rec.linked["backhaul:wssmux"] = true
	if _, err := startSwap(testTunnel(), carrierChoice{Engine: "backhaul", Transport: "wssmux"}, false); err != nil {
		t.Fatal(err)
	}
	j := waitSwap(t, 2)
	if j.State != "ok" {
		t.Fatalf("state %s (%s), steps %+v", j.State, j.Error, j.Steps)
	}
	if strings.Join(rec.foreign, ",") != "backhaul:wssmux" || strings.Join(rec.local, ",") != "backhaul:wssmux" {
		t.Errorf("foreign %v local %v", rec.foreign, rec.local)
	}
	if loadSwapState()[2] != "backhaul:wssmux" {
		t.Error("the new carrier should be remembered")
	}
}

func TestSwapRevertsBothSidesWhenTheTunnelStaysDown(t *testing.T) {
	rec := swapStubs(t)
	rec.linked["frp:tcp"] = true // only the old carrier connects
	if _, err := startSwap(testTunnel(), carrierChoice{Engine: "frp", Transport: "quic"}, false); err != nil {
		t.Fatal(err)
	}
	j := waitSwap(t, 2)
	if j.State != "reverted" {
		t.Fatalf("state %s (%s), steps %+v", j.State, j.Error, j.Steps)
	}
	if strings.Join(rec.foreign, ",") != "frp:quic,frp:tcp" || strings.Join(rec.local, ",") != "frp:quic,frp:tcp" {
		t.Errorf("both sides must go to quic and back: foreign %v local %v", rec.foreign, rec.local)
	}
	if loadSwapState()[2] != "frp:tcp" {
		t.Error("the remembered carrier must be the old one again")
	}
}

func TestSwapChangesNothingWhenTheForeignServerCannotBeTold(t *testing.T) {
	rec := swapStubs(t)
	rec.callErr = errors.New("dial tcp 10.80.2.2:7777: i/o timeout")
	if _, err := startSwap(testTunnel(), carrierChoice{Engine: "backhaul", Transport: "tcpmux"}, false); err != nil {
		t.Fatal(err)
	}
	j := waitSwap(t, 2)
	if j.State != "failed" || len(rec.local) != 0 {
		t.Fatalf("state %s, local switches %v: this server must not switch alone", j.State, rec.local)
	}
}

func TestSwapManualSwitchesHereAndHandsOutTheBundle(t *testing.T) {
	rec := swapStubs(t)
	rec.callErr = errors.New("unreachable")
	if _, err := startSwap(testTunnel(), carrierChoice{Engine: "backhaul", Transport: "tcpmux"}, true); err != nil {
		t.Fatal(err)
	}
	j := waitSwap(t, 2)
	if j.State != "manual" || strings.Join(rec.local, ",") != "backhaul:tcpmux" {
		t.Fatalf("state %s local %v", j.State, rec.local)
	}
	if !strings.Contains(j.Bundle, "tok") || !strings.Contains(j.Bundle, "5.5.5.5") {
		t.Errorf("manual swap must carry the foreign bundle, got %q", j.Bundle)
	}
}

func TestSwapOneAtATime(t *testing.T) {
	rec := swapStubs(t)
	swapVerifyWait = 200 * time.Millisecond
	_ = rec
	if _, err := startSwap(testTunnel(), carrierChoice{Engine: "backhaul", Transport: "tcpmux"}, false); err != nil {
		t.Fatal(err)
	}
	if _, err := startSwap(testTunnel(), carrierChoice{Engine: "backhaul", Transport: "ws"}, false); err == nil {
		t.Error("a second swap must wait for the first")
	}
	waitSwap(t, 2)
}

func TestForeignSwapAcceptsThenSwitches(t *testing.T) {
	engineLab(t, []string{"frpc"}, nil)
	var mu sync.Mutex
	var gotOpts engineOpts
	var gotEng, gotTr string
	old := foreignSwitchFn
	foreignSwitchFn = func(e, tr string, o engineOpts) (string, error) {
		mu.Lock()
		gotEng, gotTr, gotOpts = e, tr, o
		mu.Unlock()
		return "ok", nil
	}
	t.Cleanup(func() { foreignSwitchFn = old })

	body := `{"engine":"frp","transport":"kcp","port":7001,"ports":[2083,8443],"remote":"5.5.5.5","peer_gre":"10.80.2.1","delay_ms":1}`
	w := httptest.NewRecorder()
	handlePeerSwapCarrier(w, httptest.NewRequest("POST", "/api/peer/swap-carrier", strings.NewReader(body)))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "accepted") {
		t.Fatalf("got %d %s", w.Code, w.Body.String())
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		foreignSwapMu.Lock()
		st := foreignSwapNow.State
		foreignSwapMu.Unlock()
		if st == "ok" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("foreign swap stuck in %q", st)
		}
		time.Sleep(2 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if gotEng != "frp" || gotTr != "kcp" || gotOpts.Port != 7001 || len(gotOpts.Ports) != 2 || gotOpts.Remote != "5.5.5.5" || gotOpts.PeerGre != "10.80.2.1" {
		t.Errorf("switch got %s %s %+v", gotEng, gotTr, gotOpts)
	}

	w = httptest.NewRecorder()
	handlePeerSwapCarrier(w, httptest.NewRequest("POST", "/api/peer/swap-carrier", strings.NewReader(`{"engine":"frp","transport":"wss"}`)))
	if w.Code == 200 {
		t.Error("an unknown transport must be refused")
	}
}

func TestForeignFRPSwitchUsesTheGivenPortsAndProtocol(t *testing.T) {
	engineLab(t, []string{"frpc", "frps", "backhaul"}, []string{"backhaul-server", "backhaul-client"})
	recordSystemctl(t, "")
	_ = os.MkdirAll(frpDir, 0o755)
	t.Cleanup(func() { _ = os.Remove(filepath.Join(frpDir, "frpc.toml")) })
	_, err := switchTunnelEngineWith("frp", "quic", engineOpts{Port: 7001, Ports: []int{2083, 8443}, PeerGre: "10.80.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	conf := readFile(t, filepath.Join(frpDir, "frpc.toml"))
	for _, want := range []string{`serverAddr = "10.80.2.1"`, "serverPort = 7002", `transport.protocol = "quic"`, "remotePort = 2083", "remotePort = 8443"} {
		if !strings.Contains(conf, want) {
			t.Errorf("frpc.toml lacks %s:\n%s", want, conf)
		}
	}
	if strings.Contains(conf, "remotePort = 443\n") {
		t.Error("the default ports must not replace the given ones")
	}
}

func TestTunnelTokenHandshakeRecordsTheForeignPanel(t *testing.T) {
	swapLab(t)
	mux := http.NewServeMux()
	mountPeerRoutes(mux, "/base")
	before := loadPeerConfig()

	req := httptest.NewRequest("POST", peerRoutePrefix+"/api/peer/handshake",
		strings.NewReader(`{"role":"worker","public_ip":"92.2.2.2","panel_port":9443,"internal_ip":"10.80.2.2"}`))
	req.Header.Set("X-Peer-Secret", "tok-2")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("handshake with the peer token: %d %s", w.Code, w.Body.String())
	}
	l := loadTunnelLinks()[2]
	if l.PanelPort != 9443 || l.InternalIP != "10.80.2.2" || l.PublicIP != "92.2.2.2" {
		t.Errorf("link not recorded: %+v", l)
	}
	if after := loadPeerConfig(); after.InternalIP != before.InternalIP || after.PeerURL != before.PeerURL || after.InternalPort != before.InternalPort {
		t.Error("a peer's handshake must not touch the main Peer Link")
	}

	for _, path := range []string{"/api/peer/handshake", "/api/peer/swap-carrier", "/api/peer/apply-engine"} {
		req = httptest.NewRequest("POST", peerRoutePrefix+path, strings.NewReader(`{}`))
		req.Header.Set("X-Peer-Secret", "wrong")
		w = httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != 404 {
			t.Errorf("%s with a wrong secret: %d, want 404", path, w.Code)
		}
	}
	// The peer token opens handshake and ping only.
	req = httptest.NewRequest("POST", peerRoutePrefix+"/api/peer/apply-engine", strings.NewReader(`{}`))
	req.Header.Set("X-Peer-Secret", "tok-2")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != 404 {
		t.Errorf("apply-engine with a peer token: %d, want 404", w.Code)
	}
}

func TestTunnelPeerCallUsesTheTokenAndRemembersTheURL(t *testing.T) {
	swapLab(t)
	var gotSecret, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSecret, gotPath = r.Header.Get("X-Peer-Secret"), r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"pong"}`))
	}))
	defer srv.Close()
	updateTunnelLink(2, func(l *tunnelLink) { l.LastURL = srv.URL })
	tun := peerSwapTunnel(*findPeer(2))
	tun.PeerGre, tun.RemotePub = "", "" // only the remembered URL can answer
	if _, err := tunnelPeerCall(tun, "POST", "/api/peer/ping", map[string]string{}, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	if gotSecret != "tok-2" || gotPath != peerRoutePrefix+"/api/peer/ping" {
		t.Errorf("secret %q path %q", gotSecret, gotPath)
	}
}

func TestSwapHandlerRefusesBadRequests(t *testing.T) {
	swapLab(t)
	swapStubs(t)
	for body, want := range map[string]string{
		`{"id":2,"carrier":"frp:tcp"}`:      "already runs",
		`{"id":2,"carrier":"frp:nope"}`:     "unknown FRP transport",
		`{"id":9,"carrier":"backhaul:tcp"}`: "not found",
	} {
		w := httptest.NewRecorder()
		handleSwapPost(w, httptest.NewRequest("POST", "/api/tunnel/swap", strings.NewReader(body)))
		if w.Code == 200 || !strings.Contains(w.Body.String(), want) {
			t.Errorf("%s: %d %s (want %q)", body, w.Code, w.Body.String(), want)
		}
	}
}
