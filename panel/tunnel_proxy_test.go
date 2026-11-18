package main

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// serveOnce runs handle for every connection on a loopback port and returns the port.
func serveOnce(t *testing.T, handle func(c net.Conn)) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); handle(c) }()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// A cluster hub binds its tunnel ports to a private address: the proxy must be
// dialed there, not on 127.0.0.1.
func TestTunnelProxyHost(t *testing.T) {
	old := procNetRoot
	procNetRoot = t.TempDir()
	defer func() { procNetRoot = old }()
	tcp := "  sl  local_address rem_address   st\n" +
		"   0: 024DFEA9:0438 00000000:0000 0A 0:0 0:0 0 0 0 1 1\n" + // 169.254.77.2:1080
		"   1: 00000000:07D0 00000000:0000 0A 0:0 0:0 0 0 0 1 1\n" + // 0.0.0.0:2000
		"   2: 0100007F:0BB8 00000000:0000 0A 0:0 0:0 0 0 0 1 1\n" + // 127.0.0.1:3000
		"   3: 024DFEA9:1388 0100007F:C000 01 0:0 0:0 0 0 0 1 1\n" // an established one on 5000 is not a listener
	if err := os.WriteFile(filepath.Join(procNetRoot, "tcp"), []byte(tcp), 0o644); err != nil {
		t.Fatal(err)
	}
	for port, want := range map[int]string{1080: "169.254.77.2", 2000: "127.0.0.1", 3000: "127.0.0.1", 5000: "127.0.0.1", 9999: "127.0.0.1"} {
		if got := tunnelProxyHost(port); got != want {
			t.Errorf("port %d: %s, want %s", port, got, want)
		}
	}
	if got := tunnelProxyAddr(1080); got != "169.254.77.2:1080" {
		t.Fatalf("addr %s", got)
	}
}

// The probe tells apart the ways a "tunnel port" fails, instead of a bare timeout.
func TestSocksProbeSaysWhy(t *testing.T) {
	good, _, stop := miniSocks5(t)
	defer stop()
	silent := serveOnce(t, func(c net.Conn) { _, _ = io.Copy(io.Discard, c) })
	closing := serveOnce(t, func(c net.Conn) {})
	web := serveOnce(t, func(c net.Conn) { _, _ = c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n")) })
	login := serveOnce(t, func(c net.Conn) { _, _ = c.Write([]byte{5, 0xFF}) })
	dead := func() int {
		ln, _ := net.Listen("tcp", "127.0.0.1:0")
		p := ln.Addr().(*net.TCPAddr).Port
		ln.Close()
		return p
	}()
	cases := []struct {
		port int
		ok   bool
		want string
	}{
		{good, true, ""},
		{silent, false, "not a SOCKS5 proxy"},
		{closing, false, "closes it at once"},
		{web, false, "another protocol"},
		{login, false, "asks for a login"},
		{dead, false, "nothing answers"},
	}
	for _, c := range cases {
		_, ok, why := probeTunnelProxy(c.port)
		if ok != c.ok || !strings.Contains(why, c.want) {
			t.Errorf("port %d: ok=%v why=%q, want ok=%v %q", c.port, ok, why, c.ok, c.want)
		}
	}
}

// Telegram goes out through the tunnel's proxy, and a port that is no proxy
// is refused at once with the reason (no 20 s wait, no token in the message).
func TestTelegramViaTunnel(t *testing.T) {
	var path string
	tg := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer tg.Close()
	old := tgAPIBase
	tgAPIBase = tg.URL
	defer func() { tgAPIBase = old }()

	port, _, stop := miniSocks5(t)
	wd := watchdogConfig{TGBotToken: "123:secret", TGChatID: "42", TGRoute: "tunnel", TGTunnelPort: port}
	if err := sendTelegram(wd, "hello"); err != nil {
		t.Fatal(err)
	}
	stop()
	if path != "/bot123:secret/sendMessage" {
		t.Fatalf("Telegram got %q", path)
	}
	wd.TGTunnelPort = serveOnce(t, func(c net.Conn) { _, _ = io.Copy(io.Discard, c) })
	err := sendTelegram(wd, "hello")
	if err == nil || !strings.Contains(err.Error(), "not a SOCKS5 proxy") || strings.Contains(err.Error(), "secret") {
		t.Fatalf("a port that is no proxy: %v", err)
	}
}

func TestProxyProbeEndpoint(t *testing.T) {
	port, _, stop := miniSocks5(t)
	defer stop()
	rr := httptest.NewRecorder()
	handleProxyProbe(rr, httptest.NewRequest("POST", "/", strings.NewReader(`{"port":`+strconv.Itoa(port)+`}`)))
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"ok":true`) {
		t.Fatalf("%d %s", rr.Code, rr.Body)
	}
	rr = httptest.NewRecorder()
	handleProxyProbe(rr, httptest.NewRequest("POST", "/", strings.NewReader(`{"port":0}`)))
	if rr.Code != 400 {
		t.Fatalf("port 0 must be refused, got %d", rr.Code)
	}
}
