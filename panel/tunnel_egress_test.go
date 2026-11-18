package main

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

// egressLab: an Iran hub with tunnel 2, a fake foreign panel serving the REAL
// relay route behind the panel's whole middleware chain, and a fake
// Telegram/Cloudflare. It returns the tunnel id and what the destination saw.
func egressLab(t *testing.T) (id int, seen *[]string) {
	t.Helper()
	swapLab(t)
	if err := updatePeerConfig(func(c *PeerConfig) { c.PeerSecret = "tok-2" }); err != nil {
		t.Fatal(err)
	}
	var hits []string
	dest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits = append(hits, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true,"success":true,"result":[]}`)
	}))
	t.Cleanup(dest.Close)

	mux := http.NewServeMux()
	mountPeerRoutes(mux, "/base")
	foreign := httptest.NewServer(panelChain(mux))
	t.Cleanup(foreign.Close)
	updateTunnelLink(2, func(l *tunnelLink) { l.LastURL = foreign.URL })

	oAllow, oDial, oTun := egressAllow, egressDialTarget, egressTunnelFor
	egressDialTarget = func(addr string, _ time.Duration) (net.Conn, error) {
		return net.Dial("tcp", strings.TrimPrefix(dest.URL, "http://")) // "api.telegram.org:443" is the local fake
	}
	egressTunnelFor = func(id int) (swapTunnel, error) {
		tun := peerSwapTunnel(*findPeer(id))
		tun.PeerGre, tun.RemotePub = "", "" // only the remembered URL answers
		return tun, nil
	}
	t.Cleanup(func() {
		egressAllow, egressDialTarget, egressTunnelFor = oAllow, oDial, oTun
		bridgeMu.Lock()
		for k, b := range bridges {
			_ = b.ln.Close()
			delete(bridges, k)
		}
		bridgeMu.Unlock()
	})
	return 2, &hits
}

// Telegram and Cloudflare reach their API through the chosen tunnel: Iran bridge
// -> foreign panel relay -> destination. No port is typed; the panel derives it.
func TestEgressThroughAChosenTunnel(t *testing.T) {
	id, seen := egressLab(t)

	old := tgAPIBase
	tgAPIBase = "http://api.telegram.org:443" // plain HTTP so the fake needs no certificate
	defer func() { tgAPIBase = old }()
	wd := watchdogConfig{TGBotToken: "123:secret", TGChatID: "42", TGRoute: "tunnel", TGTunnelID: &id}
	if err := sendTelegram(wd, "hello"); err != nil {
		t.Fatalf("Telegram through tunnel %d: %v", id, err)
	}
	if len(*seen) != 1 || (*seen)[0] != "POST /bot123:secret/sendMessage" {
		t.Fatalf("the destination saw %v", *seen)
	}

	oldAPI := cfAPI
	cfAPI = "http://api.cloudflare.com:443/client/v4"
	defer func() { cfAPI = oldAPI }()
	if _, err := cfCall(DNSConfig{Token: "tok", Route: "tunnel", TunnelID: &id}, "GET", "/zones", nil); err != nil {
		t.Fatalf("Cloudflare through tunnel %d: %v", id, err)
	}
	if len(*seen) != 2 || (*seen)[1] != "GET /client/v4/zones" {
		t.Fatalf("the destination saw %v", *seen)
	}

	// the same port serves hashem.sh's watchdog (curl --socks5-hostname)
	if port, err := routePort(&id, 0); err != nil || port != bridgePort(id) {
		t.Fatalf("port %d err %v", port, err)
	}
	ok, via, why := probeRoute(&id, 0, "api.telegram.org")
	if !ok || via == "" || why != "" {
		t.Fatalf("probe: ok=%v via=%q why=%q", ok, via, why)
	}
	if curl, err := exec.LookPath("curl"); err == nil { // what watchdog_send runs
		out, err := exec.Command(curl, "-s", "--max-time", "10", "--socks5-hostname", "127.0.0.1:"+strconv.Itoa(bridgePort(id)),
			"http://api.telegram.org:443/botX/sendMessage", "-d", "a=b").CombinedOutput()
		if err != nil || !strings.Contains(string(out), `"ok":true`) {
			t.Fatalf("curl through the bridge: %v %s", err, out)
		}
	}
}

// The relay is not an open proxy: the bridge and the foreign panel both refuse
// any other destination.
func TestEgressRefusesOtherDestinations(t *testing.T) {
	id, seen := egressLab(t)
	port, err := bridgeEnsure(id)
	if err != nil {
		t.Fatal(err)
	}
	// SOCKS5 CONNECT example.com:443 on the bridge
	c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = c.Write([]byte{5, 1, 0})
	b := make([]byte, 2)
	_, _ = io.ReadFull(c, b)
	host := "example.com"
	req := append([]byte{5, 1, 0, 3, byte(len(host))}, host...)
	_, _ = c.Write(append(req, 0x01, 0xBB))
	rep := make([]byte, 10)
	_, _ = io.ReadFull(c, rep)
	if rep[1] != 2 {
		t.Fatalf("the bridge answered %d for example.com, want 2 (not allowed)", rep[1])
	}

	// straight at the foreign panel, as a hub that was tampered with would
	req2, _ := http.NewRequest("POST", findLastURL(t, 2)+peerRoutePrefix+"/api/peer/egress?to=example.com:443", nil)
	req2.Header.Set("X-Peer-Secret", "tok-2")
	resp, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("the foreign panel relayed example.com: HTTP %d", resp.StatusCode)
	}
	req3, _ := http.NewRequest("POST", findLastURL(t, 2)+peerRoutePrefix+"/api/peer/egress?to=api.telegram.org:443", nil)
	req3.Header.Set("X-Peer-Secret", "wrong")
	resp, err = http.DefaultClient.Do(req3)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("a wrong secret got HTTP %d, want a bare 404", resp.StatusCode)
	}
	if len(*seen) != 0 {
		t.Fatalf("nothing may reach the destination: %v", *seen)
	}
}

// An older foreign panel has no relay route: say so, do not say "unreachable".
func TestEgressOldForeignPanel(t *testing.T) {
	id, _ := egressLab(t)
	old := httptest.NewServer(http.NotFoundHandler())
	defer old.Close()
	updateTunnelLink(id, func(l *tunnelLink) { l.LastURL = old.URL })
	ok, _, why := probeRoute(&id, 0, "api.telegram.org")
	if ok || !strings.Contains(why, "update its panel") {
		t.Fatalf("ok=%v why=%q", ok, why)
	}
}

// A foreign server that cannot reach the destination says that, with a reason.
func TestEgressForeignCannotReach(t *testing.T) {
	id, _ := egressLab(t)
	egressDialTarget = func(string, time.Duration) (net.Conn, error) { return nil, io.ErrClosedPipe }
	ok, _, why := probeRoute(&id, 0, "api.telegram.org")
	if ok || !strings.Contains(why, "could not reach api.telegram.org") {
		t.Fatalf("ok=%v why=%q", ok, why)
	}
}

// A foreign panel nobody answers on is reported as unreachable, with the tunnel's name.
func TestEgressForeignPanelDown(t *testing.T) {
	id, _ := egressLab(t)
	dead := httptest.NewServer(http.NotFoundHandler())
	url := dead.URL
	dead.Close()
	updateTunnelLink(id, func(l *tunnelLink) { l.LastURL = url })
	ok, _, why := probeRoute(&id, 0, "api.telegram.org")
	if ok || !strings.Contains(why, "cannot reach the foreign panel") {
		t.Fatalf("ok=%v why=%q", ok, why)
	}
}

func findLastURL(t *testing.T, id int) string {
	t.Helper()
	return loadTunnelLinks()[id].LastURL
}

// A DNS route saved with a manual port by an older version still shows as that
// port (the card must not fall back to Direct and drop it on the next save).
func TestDNSViewKeepsAnOldManualPort(t *testing.T) {
	b, err := json.Marshal(dnsView(ClusterConfig{DNS: DNSConfig{Route: "tunnel", TunnelPort: 1080}}))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"route":"tunnel"`) || !strings.Contains(string(b), `"tunnel_port":1080`) || !strings.Contains(string(b), `"tunnel_id":null`) {
		t.Fatalf("view: %s", b)
	}
}

// The main tunnel's foreign panel is the Peer Link's: found through its saved
// address and port, which tunnel_links does not know.
func TestEgressMainTunnelUsesThePeerLinkAddress(t *testing.T) {
	_, seen := egressLab(t)
	foreign := httptest.NewServer(panelChain(func() http.Handler {
		mux := http.NewServeMux()
		mountPeerRoutes(mux, "/base")
		return mux
	}()))
	defer foreign.Close()
	if err := updatePeerConfig(func(c *PeerConfig) { c.PeerSecret = "main-secret"; c.PeerURL = foreign.URL; c.InternalIP = "" }); err != nil {
		t.Fatal(err)
	}
	egressTunnelFor = func(id int) (swapTunnel, error) {
		return swapTunnel{ID: 0, Name: "Main tunnel", Main: true, Token: "main-secret"}, nil // no link info, no GRE address
	}
	zero := 0
	ok, via, why := probeRoute(&zero, 0, "api.telegram.org")
	if !ok {
		t.Fatalf("the main tunnel could not be reached through the Peer Link address: via=%q why=%q", via, why)
	}
	if len(*seen) != 0 {
		t.Fatalf("a probe only connects: %v", *seen)
	}
}

// A failed send names the reason the bridge recorded (here: the foreign panel
// is down) instead of the client's bare "host unreachable".
func TestTelegramViaTunnelNamesTheReason(t *testing.T) {
	id, _ := egressLab(t)
	dead := httptest.NewServer(http.NotFoundHandler())
	url := dead.URL
	dead.Close()
	updateTunnelLink(id, func(l *tunnelLink) { l.LastURL = url })
	old := tgAPIBase
	tgAPIBase = "http://api.telegram.org:443"
	defer func() { tgAPIBase = old }()
	wd := watchdogConfig{TGBotToken: "123:secret", TGChatID: "42", TGRoute: "tunnel", TGTunnelID: &id}
	err := sendTelegram(wd, "hello")
	if err == nil || !strings.Contains(err.Error(), "cannot reach the foreign panel") || strings.Contains(err.Error(), "secret") {
		t.Fatalf("error: %v", err)
	}
}
