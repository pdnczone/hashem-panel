package main

import (
	"context"
	"encoding/json"
	"math"
	"net"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestPathTestCodeRoundTrip(t *testing.T) {
	in := ptCode{Host: "203.0.113.7", Base: 41000, Token: "0123456789abcdef0123456789abcdef", Minutes: 10}
	code := ptEncodeCode(in)
	if !strings.HasPrefix(code, ptCodePrefix) {
		t.Fatalf("code %q has no prefix", code)
	}
	// pasted with a line break in the middle, as chat apps do
	out, err := ptDecodeCode("  " + code[:12] + "\n" + code[12:] + " ")
	if err != nil || out != in {
		t.Fatalf("round trip: %+v %v", out, err)
	}
	for _, bad := range []string{"", "hsh1_abc", ptCodePrefix + "!!!",
		ptEncodeCode(ptCode{Host: "not-an-ip", Base: 41000, Token: in.Token}),
		ptEncodeCode(ptCode{Host: "203.0.113.7", Base: 65530, Token: in.Token}),
		ptEncodeCode(ptCode{Host: "203.0.113.7", Base: 41000, Token: "short"})} {
		if _, err := ptDecodeCode(bad); err == nil {
			t.Errorf("accepted bad code %q", bad)
		}
	}
}

// Every transport has its own data port, all inside the documented span, and
// the public ports match what the cores are told to listen on.
func TestPathTestLayout(t *testing.T) {
	base := 41000
	cs := ptChecks(base, 2222)
	if len(cs) != 4+len(ptFRPTransports)+len(ptBHTransports) {
		t.Fatalf("got %d checks", len(cs))
	}
	fwd := map[int]string{}
	for _, c := range cs {
		if c.Status != "waiting" {
			t.Errorf("%s starts as %s", c.ID, c.Status)
		}
		if c.Fwd == 0 {
			continue
		}
		if c.Fwd < base+ptOffFwd || c.Fwd > base+ptSpan {
			t.Errorf("%s data port %d outside the span", c.ID, c.Fwd)
		}
		if other, dup := fwd[c.Fwd]; dup {
			t.Errorf("%s and %s share data port %d", c.ID, other, c.Fwd)
		}
		fwd[c.Fwd] = c.ID
	}
	if len(fwd) != len(ptFRPTransports)+len(ptBHTransports) {
		t.Errorf("%d data ports", len(fwd))
	}
	frps := ptFrpsConf(base, "tok")
	for _, want := range []string{"bindPort = 41001", "kcpBindPort = 41001", "quicBindPort = 41002", `proxyBindAddr = "127.0.0.1"`} {
		if !strings.Contains(frps, want) {
			t.Errorf("frps.toml lacks %q", want)
		}
	}
	for _, c := range cs {
		switch c.Engine {
		case "FRP":
			conf := ptFrpcConf("203.0.113.7", base, c.Name, "tok")
			for _, want := range []string{"serverPort = " + strconv.Itoa(c.Port), `transport.protocol = "` + c.Name + `"`,
				"remotePort = " + strconv.Itoa(c.Fwd), "localPort = 41019"} {
				if !strings.Contains(conf, want) {
					t.Errorf("frpc %s lacks %q", c.Name, want)
				}
			}
		case "Backhaul":
			i := c.Port - base - ptOffBH
			srv := ptBHServerConf(base, i, "tok", "/x")
			cli := ptBHClientConf("203.0.113.7", base, i, "tok")
			for _, want := range []string{`bind_addr = "0.0.0.0:` + strconv.Itoa(c.Port), `transport = "` + c.Name + `"`,
				`"127.0.0.1:` + strconv.Itoa(c.Fwd) + `=41019"`} {
				if !strings.Contains(srv, want) {
					t.Errorf("backhaul server %s lacks %q", c.Name, want)
				}
			}
			if strings.Contains(c.Name, "wss") != strings.Contains(srv, "tls_cert") {
				t.Errorf("backhaul %s: tls_cert presence wrong", c.Name)
			}
			if !strings.Contains(cli, `remote_addr = "203.0.113.7:`+strconv.Itoa(c.Port)+`"`) {
				t.Errorf("backhaul client %s dials the wrong port: %s", c.Name, cli)
			}
		}
	}
	if p, proto := ptFRPPort(base, "quic"); p != 41002 || proto != "udp" {
		t.Errorf("quic on %d/%s", p, proto)
	}
	// data through FRP kcp/quic is TCP even though they dial over UDP
	for _, c := range cs {
		want := "tcp"
		if c.ID == "bh-udp" {
			want = "udp"
		}
		if got := ptDataProto(*c); got != want {
			t.Errorf("%s data over %s, want %s", c.ID, got, want)
		}
	}
}

func TestPathTestMbps(t *testing.T) {
	// a run faster than the clock tick reads 0 elapsed (common on Windows)
	for _, d := range []time.Duration{0, -time.Second, time.Nanosecond} {
		if got := ptMbps(256<<10, d); got <= 0 || math.IsInf(got, 0) || math.IsNaN(got) {
			t.Errorf("ptMbps(256KiB, %v) = %v, want finite and > 0", d, got)
		}
	}
	if got := ptMbps(1<<20, time.Second); got != 8.4 {
		t.Errorf("1 MiB in 1s = %v Mbit/s, want 8.4", got)
	}
}

func TestPathTestProbes(t *testing.T) {
	tl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	defer tl.Close()
	go ptEchoTCP(tl)
	ul, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	defer ul.Close()
	go ptEchoUDP(ul)

	if rtt, err := ptProbe("tcp", tl.Addr().String(), 2*time.Second); err != nil || rtt < 0 {
		t.Errorf("tcp echo: %v %v", rtt, err)
	}
	if _, err := ptProbe("udp", ul.LocalAddr().String(), 2*time.Second); err != nil {
		t.Errorf("udp echo: %v", err)
	}
	if mbps, err := ptSpeed(tl.Addr().String(), 256<<10, 10*time.Second); err != nil || mbps <= 0 {
		t.Errorf("speed: %v %v", mbps, err)
	}
	// a port that accepts but never answers is not a working transport
	mute, _ := net.Listen("tcp", "127.0.0.1:0")
	defer mute.Close()
	go func() {
		for {
			c, err := mute.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	if _, err := ptProbe("tcp", mute.Addr().String(), 500*time.Millisecond); err == nil {
		t.Error("a silent port counted as working")
	}
	// SSH banner
	ssh, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ssh.Close()
	go func() {
		for {
			c, err := ssh.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("SSH-2.0-test\r\n"))
			c.Close()
		}
	}()
	port := ssh.Addr().(*net.TCPAddr).Port
	if _, err := ptSSH("127.0.0.1", port); err != nil {
		t.Errorf("ssh banner: %v", err)
	}
	if _, err := ptSSH("127.0.0.1", tl.Addr().(*net.TCPAddr).Port); err == nil {
		t.Error("an echo port counted as SSH")
	}
}

// The hub's control port: the token gates it, hello marks plain TCP working
// and learns the foreign IP, results never carry the code or token.
func TestPathTestHubControl(t *testing.T) {
	s := &ptSession{role: "iran", token: "0123456789abcdef0123456789abcdef", code: "HPT1-secret",
		checks: ptChecks(41000, 22), phase: "running", expires: time.Now().Add(time.Minute)}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	defer s.cancel()
	h := s.hubMux()

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/hpt/hello?t=wrong", nil))
	if rr.Code != 403 || s.statusOf("tcp") != "waiting" {
		t.Fatalf("wrong token: %d %s", rr.Code, s.statusOf("tcp"))
	}
	req := httptest.NewRequest("GET", "/hpt/hello?t="+s.token+"&rtt=41.26", nil)
	req.RemoteAddr = "198.51.100.9:50000"
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 200 || s.statusOf("tcp") != "ok" || s.foreignIP != "198.51.100.9" || s.joined.IsZero() {
		t.Fatalf("hello: %d %s %q", rr.Code, s.statusOf("tcp"), s.foreignIP)
	}
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/hpt/results?t="+s.token, nil))
	body := rr.Body.String()
	if strings.Contains(body, s.token) || strings.Contains(body, "HPT1-") {
		t.Fatalf("results leak the token or code: %s", body)
	}
	var r ptResults
	if err := json.Unmarshal(rr.Body.Bytes(), &r); err != nil || !r.Joined || r.Settled || len(r.Checks) != len(s.checks) {
		t.Fatalf("results: %+v %v", r, err)
	}
	if r.Checks[0].RTTMs != 41.3 {
		t.Errorf("tcp rtt %v", r.Checks[0].RTTMs)
	}
}

// A running tunnel holding the default ports: the test moves to the next free
// block by itself, and a port the admin chose that is taken is refused.
func TestPathTestPicksFreePorts(t *testing.T) {
	busy, err := net.Listen("tcp", ":"+strconv.Itoa(ptDefBase))
	if err != nil {
		t.Skip("port 41000 not available here")
	}
	defer busy.Close()
	b, err := ptPickBase(0)
	if err != nil || b == ptDefBase || (b-ptDefBase)%(ptSpan+9) != 0 {
		t.Fatalf("auto base %d %v", b, err)
	}
	if ptHubPortsFree(b) != nil {
		t.Fatalf("picked block %d is not free", b)
	}
	if _, err := ptPickBase(ptDefBase); err == nil || !strings.Contains(err.Error(), "leave the first port empty") {
		t.Fatalf("taken explicit port: %v", err)
	}
}
