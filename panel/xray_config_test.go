package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// xrayTestLink is a ready link of one preset, mode and side; both sides of
// one call share keys, as the bundle makes them.
func xrayTestLink(t *testing.T, preset, mode, side string) XrayLink {
	t.Helper()
	p := xrayPresets[preset]
	l := XrayLink{ID: 2, Mode: mode, Side: side, Remote: "198.51.100.7", TunnelPort: 8443, Ports: []int{2053, 443}, UDP: true, Profile: p}
	if mode == xrayModeReverse {
		l.Remote = "203.0.113.9"
	}
	if preset == "cdn" {
		l.Profile.SNI, l.Profile.Address = "tun.example.com", "104.16.0.1"
	}
	l.Keys = XrayKeys{UUID: "0f8d5c7e-1a2b-4c3d-8e9f-0123456789ab", ShortID: "a1b2c3d4"}
	if p.Security == "reality" {
		l.Keys.PrivateKey = "cGVwcGVycGVwcGVycGVwcGVycGVwcGVycGVwcGVyMDA" // 32 bytes, base64url
		l.Keys.PublicKey, _ = xrayRealityPub(l.Keys.PrivateKey)
	}
	l, err := newXrayLink(l)
	if err != nil {
		t.Fatal(err)
	}
	if p.Transport == "kcp" {
		l.Profile.KCP.Password = "kcppassword1"
	}
	l.Profile.Path = map[string]string{"grpc": "svc1", "kcp": ""}[p.Transport]
	if l.Profile.Path == "" && p.Transport != "raw" && p.Transport != "kcp" {
		l.Profile.Path = "/p1"
	}
	// The dialing end never has the Reality private key.
	if !l.serverEnd() {
		l.Keys.PrivateKey, l.Keys.TLSKey = "", ""
	}
	return l
}

func xrayJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestXrayKeys(t *testing.T) {
	priv, pub, err := newXrayRealityKeys()
	if err != nil {
		t.Fatal(err)
	}
	if got, err := xrayRealityPub(priv); err != nil || got != pub {
		t.Fatalf("pub from priv: %q %v, want %q", got, err, pub)
	}
	if len(priv) != 43 || len(pub) != 43 {
		t.Errorf("keys are not 32 bytes base64url: %q %q", priv, pub)
	}
	id, err := newXrayUUID()
	if err != nil || !xrayUUIDRe.MatchString(id) || id[14] != '4' {
		t.Errorf("uuid %q %v", id, err)
	}
	if _, err := xrayRealityPub("short"); err == nil {
		t.Error("a bad private key was accepted")
	}
}

func TestNewXrayLinkFillsSecrets(t *testing.T) {
	for name := range xrayPresets {
		l, err := newXrayLink(XrayLink{Mode: xrayModeDirect, Profile: xrayPresets[name]})
		if err != nil {
			t.Fatal(err)
		}
		if !xrayUUIDRe.MatchString(l.Keys.UUID) {
			t.Errorf("%s: no uuid", name)
		}
		if l.Profile.Security == "reality" && (l.Keys.PrivateKey == "" || l.Keys.ShortID == "" || l.Profile.SNI == "") {
			t.Errorf("%s: Reality keys or SNI missing: %+v", name, l)
		}
		if l.Profile.Transport == "kcp" && (l.Profile.KCP == nil || l.Profile.KCP.Password == "") {
			t.Errorf("%s: no mKCP password", name)
		}
		if xrayOneOf(l.Profile.Transport, []string{"xhttp", "grpc"}) && l.Profile.Path == "" {
			t.Errorf("%s: no path", name)
		}
	}
	// Reverse mode borrows a site the Iran server reaches.
	l, _ := newXrayLink(XrayLink{Mode: xrayModeReverse, Profile: xrayPresets["reality"]})
	if l.Profile.SNI != xraySNIReverse[0] {
		t.Errorf("reverse SNI %q", l.Profile.SNI)
	}
	// The presets are not changed by filling a link.
	if xrayPresets["kcp"].KCP.Password != "" {
		t.Error("newXrayLink wrote into the shared preset")
	}
}

func TestXrayConfigDirect(t *testing.T) {
	iran, err := buildXrayConfig(xrayTestLink(t, "reality", xrayModeDirect, xraySideIran))
	if err != nil {
		t.Fatal(err)
	}
	s := xrayJSON(t, iran)
	for _, want := range []string{
		`"port":"443,2053","protocol":"dokodemo-door"`,
		`"settings":{"address":"127.0.0.1","network":"tcp,udp"}`,
		`"address":"198.51.100.7"`, `"port":8443`, `"flow":"xtls-rprx-vision"`, `"encryption":"none"`,
		`"password":"`, `"serverName":"www.speedtest.net"`, `"fingerprint":"chrome"`,
		`{"inboundTag":["users"],"outboundTag":"tunnel"}`,
		`"access":"none"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("Iran config lacks %s\n%s", want, s)
		}
	}
	if strings.Contains(s, "privateKey") || strings.Contains(s, "freedom") {
		t.Errorf("Iran (client) has a private key or a freedom outbound:\n%s", s)
	}

	foreign, err := buildXrayConfig(xrayTestLink(t, "reality", xrayModeDirect, xraySideForeign))
	if err != nil {
		t.Fatal(err)
	}
	s = xrayJSON(t, foreign)
	for _, want := range []string{
		`"listen":"0.0.0.0","port":8443,"protocol":"vless"`, `"decryption":"none"`,
		`"privateKey":"cGVwcGVy`, `"serverNames":["www.speedtest.net"]`, `"target":"www.speedtest.net:443"`,
		`"shortIds":["a1b2c3d4"]`,
		// only its own services: 127.0.0.1 on the forwarded ports, the rest dropped
		`{"inboundTag":["tunnel"],"ip":["127.0.0.1"],"network":"tcp,udp","outboundTag":"direct","port":"443,2053"}`,
		`{"inboundTag":["tunnel"],"outboundTag":"block"}`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("foreign config lacks %s\n%s", want, s)
		}
	}
	if strings.Contains(s, "dokodemo") {
		t.Errorf("the foreign server listens on the users' ports:\n%s", s)
	}
	// blackhole is the default outbound
	if ob := foreign["outbounds"].([]any)[0].(map[string]any); ob["protocol"] != "blackhole" {
		t.Errorf("first outbound %v", ob)
	}
}

func TestXrayConfigReverse(t *testing.T) {
	iran, err := buildXrayConfig(xrayTestLink(t, "reality", xrayModeReverse, xraySideIran))
	if err != nil {
		t.Fatal(err)
	}
	s := xrayJSON(t, iran)
	for _, want := range []string{
		`"protocol":"dokodemo-door"`, `"port":8443,"protocol":"vless"`,
		`"reverse":{"tag":"reverse"}`, `"privateKey":`, `"serverNames":["www.digikala.com"]`,
		`{"inboundTag":["users"],"outboundTag":"reverse"}`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("Iran (portal) config lacks %s\n%s", want, s)
		}
	}
	if strings.Contains(s, `"address":"203.0.113.9"`) {
		t.Errorf("Iran dials out in reverse mode:\n%s", s)
	}

	foreign, err := buildXrayConfig(xrayTestLink(t, "reality", xrayModeReverse, xraySideForeign))
	if err != nil {
		t.Fatal(err)
	}
	s = xrayJSON(t, foreign)
	for _, want := range []string{
		`"address":"203.0.113.9"`, `"reverse":{"tag":"from-iran"}`, `"flow":"xtls-rprx-vision"`,
		`{"inboundTag":["from-iran"],"ip":["127.0.0.1"],"network":"tcp,udp","outboundTag":"direct","port":"443,2053"}`,
		`{"inboundTag":["from-iran"],"outboundTag":"block"}`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("foreign (bridge) config lacks %s\n%s", want, s)
		}
	}
	if strings.Contains(s, `"inbounds":[{`) {
		t.Errorf("the foreign server listens in reverse mode:\n%s", s)
	}
}

func TestXrayConfigTransports(t *testing.T) {
	cases := []struct {
		preset string
		want   []string
	}{
		{"xhttp", []string{`"network":"xhttp"`, `"xhttpSettings":{"mode":"auto","path":"/p1"}`, `"security":"reality"`}},
		{"grpc", []string{`"grpcSettings":{"serviceName":"svc1"}`}},
		{"cdn", []string{`"security":"tls"`, `"address":"104.16.0.1"`, `"host":"tun.example.com"`, `"mode":"packet-up"`}},
		{"kcp", []string{`"network":"kcp"`, `"kcpSettings":{"congestion":true,"downlinkCapacity":100,"mtu":1350,"tti":20,"uplinkCapacity":20}`,
			`"finalmask":{"udp":[{"settings":{"password":"kcppassword1"},"type":"mkcp-aes128gcm"}]}`, `"security":"none"`}},
	}
	for _, c := range cases {
		cfg, err := buildXrayConfig(xrayTestLink(t, c.preset, xrayModeDirect, xraySideIran))
		if err != nil {
			t.Fatalf("%s: %v", c.preset, err)
		}
		s := xrayJSON(t, cfg)
		for _, w := range c.want {
			if !strings.Contains(s, w) {
				t.Errorf("%s lacks %s\n%s", c.preset, w, s)
			}
		}
		if strings.Contains(s, "xtls-rprx-vision") {
			t.Errorf("%s uses Vision", c.preset)
		}
	}
	// mKCP's tunnel port is UDP
	l := xrayTestLink(t, "kcp", xrayModeDirect, xraySideForeign)
	if tcp, udp := l.listens(); xrayHasPort(tcp, 8443) || !xrayHasPort(udp, 8443) {
		t.Errorf("kcp listens tcp %v udp %v", tcp, udp)
	}
}

func TestXrayConfigTuning(t *testing.T) {
	l := xrayTestLink(t, "xhttp", xrayModeDirect, xraySideIran)
	l.Profile.Fragment = &XrayFragment{Packets: "tlshello", Length: "100-200", Delay: "10-20"}
	l.Profile.Mux, l.Profile.XUDP = 8, 16
	l.Profile.TFO, l.Profile.Congestion, l.Profile.MPTCP, l.Profile.Mark = true, "bbr", true, 255
	l.Profile.SpiderX = "/search?q=1"
	cfg, err := buildXrayConfig(l)
	if err != nil {
		t.Fatal(err)
	}
	s := xrayJSON(t, cfg)
	for _, w := range []string{
		`"finalmask":{"tcp":[{"settings":{"delay":"10-20","length":"100-200","packets":"tlshello"},"type":"fragment"}]}`,
		`"mux":{"concurrency":8,"enabled":true,"xudpConcurrency":16}`,
		`"mark":255,"tcpCongestion":"bbr","tcpFastOpen":true,"tcpMptcp":true}`,
		`"spiderX":"/search?q=1"`,
	} {
		if !strings.Contains(s, w) {
			t.Errorf("lacks %s\n%s", w, s)
		}
	}
	// The listening end: no fragment, no mark, no mux.
	l.Side = xraySideForeign
	l.Keys.PrivateKey = "cGVwcGVycGVwcGVycGVwcGVycGVwcGVycGVwcGVyMDA"
	cfg, err = buildXrayConfig(l)
	if err != nil {
		t.Fatal(err)
	}
	s = xrayJSON(t, cfg)
	if strings.Contains(s, "fragment") || strings.Contains(s, `"mark"`) || strings.Contains(s, `"mux"`) {
		t.Errorf("server end has dialing-only settings:\n%s", s)
	}
}

func TestXrayValidate(t *testing.T) {
	ok := xrayTestLink(t, "reality", xrayModeDirect, xraySideIran)
	if err := ok.validate(); err != nil {
		t.Fatalf("valid link refused: %v", err)
	}
	cases := map[string]func(l *XrayLink){
		"mode":            func(l *XrayLink) { l.Mode = "sideways" },
		"side":            func(l *XrayLink) { l.Side = "moon" },
		"remote":          func(l *XrayLink) { l.Remote = "a b;rm" },
		"no remote":       func(l *XrayLink) { l.Remote = "" },
		"tunnel port":     func(l *XrayLink) { l.TunnelPort = 70000 },
		"no ports":        func(l *XrayLink) { l.Ports = nil },
		"dup port":        func(l *XrayLink) { l.Ports = []int{443, 443} },
		"bad port":        func(l *XrayLink) { l.Ports = []int{0} },
		"listen":          func(l *XrayLink) { l.Listen = "eth0" },
		"uuid":            func(l *XrayLink) { l.Keys.UUID = "x" },
		"transport":       func(l *XrayLink) { l.Profile.Transport = "quic" },
		"security":        func(l *XrayLink) { l.Profile.Security = "xtls" },
		"reality ws":      func(l *XrayLink) { l.Profile.Transport = "ws"; l.Profile.Vision = false; l.Profile.Path = "/a" },
		"vision xhttp":    func(l *XrayLink) { l.Profile.Transport = "xhttp"; l.Profile.Path = "/a" },
		"vision mux":      func(l *XrayLink) { l.Profile.Mux = 4 },
		"sni":             func(l *XrayLink) { l.Profile.SNI = "" },
		"sni junk":        func(l *XrayLink) { l.Profile.SNI = "a\"b" },
		"target":          func(l *XrayLink) { l.Profile.Target = "nohost" },
		"fingerprint":     func(l *XrayLink) { l.Profile.Fingerprint = "hellogolang" },
		"spiderx":         func(l *XrayLink) { l.Profile.SpiderX = "noslash" },
		"xver":            func(l *XrayLink) { l.Profile.Xver = 3 },
		"short id":        func(l *XrayLink) { l.Keys.ShortID = "xyz" },
		"public key":      func(l *XrayLink) { l.Keys.PublicKey = "AAAA" },
		"congestion":      func(l *XrayLink) { l.Profile.Congestion = "vegas" },
		"fragment":        func(l *XrayLink) { l.Profile.Fragment = &XrayFragment{Packets: "tlshello", Length: "0-10"} },
		"fragment pkts":   func(l *XrayLink) { l.Profile.Fragment = &XrayFragment{Packets: "all", Length: "10-20"} },
		"expert not obj":  func(l *XrayLink) { l.Expert = json.RawMessage(`[1]`) },
		"expert not json": func(l *XrayLink) { l.Expert = json.RawMessage(`{`) },
	}
	for name, mut := range cases {
		l := ok
		l.Ports = append([]int(nil), ok.Ports...)
		mut(&l)
		if err := l.validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Reverse: the tunnel port cannot also be a user port on Iran; mux is refused.
	r := xrayTestLink(t, "xhttp", xrayModeReverse, xraySideIran)
	r.Ports = []int{8443}
	if err := r.validate(); err == nil {
		t.Error("reverse: tunnel port reused as a user port")
	}
	r = xrayTestLink(t, "xhttp", xrayModeReverse, xraySideForeign)
	r.Profile.Mux = 4
	if err := r.validate(); err == nil {
		t.Error("reverse: mux accepted")
	}
	// The server end checks its key pair; TLS needs files.
	s := xrayTestLink(t, "reality", xrayModeDirect, xraySideForeign)
	s.Keys.PrivateKey = "bad"
	if err := s.validate(); err == nil {
		t.Error("server end with a bad private key")
	}
	c := xrayTestLink(t, "cdn", xrayModeDirect, xraySideForeign)
	c.Profile.CertFile = "cert.pem"
	if err := c.validate(); err == nil {
		t.Error("TLS server end with a relative cert path")
	}
	k := xrayTestLink(t, "kcp", xrayModeDirect, xraySideIran)
	k.Profile.Security = "reality"
	if err := k.validate(); err == nil {
		t.Error("mKCP with Reality")
	}
	k = xrayTestLink(t, "kcp", xrayModeDirect, xraySideIran)
	k.Profile.KCP.Password = "short"
	if err := k.validate(); err == nil {
		t.Error("mKCP short password")
	}
	// The listening end needs no address of the other server.
	s = xrayTestLink(t, "reality", xrayModeReverse, xraySideIran)
	s.Remote = ""
	if err := s.validate(); err != nil {
		t.Errorf("reverse Iran without the foreign address: %v", err)
	}
}

func TestXrayExpertMerge(t *testing.T) {
	l := xrayTestLink(t, "reality", xrayModeDirect, xraySideIran)
	l.Expert = json.RawMessage(`{
		"log": {"loglevel": "debug"},
		"outbounds": [{"tag": "tunnel", "streamSettings": {"sockopt": {"tcpKeepAliveIdle": 30}}},
		              {"tag": "extra", "protocol": "freedom"}],
		"policy": {"levels": {"0": {"handshake": 4}}}
	}`)
	cfg, err := buildXrayConfig(l)
	if err != nil {
		t.Fatal(err)
	}
	s := xrayJSON(t, cfg)
	for _, w := range []string{`"loglevel":"debug"`, `"access":"none"`, `"tcpKeepAliveIdle":30`,
		`"realitySettings":`, `"tag":"extra"`, `"handshake":4`, `"tag":"block"`} {
		if !strings.Contains(s, w) {
			t.Errorf("merged config lacks %s\n%s", w, s)
		}
	}
	// A plain list replaces.
	if got := xrayMerge(map[string]any{"a": []any{1, 2}}, map[string]any{"a": []any{3}}); xrayJSON(t, got) != `{"a":[3]}` {
		t.Errorf("list merge %v", got)
	}
}

// xrayTestMatrix is every preset in both modes on both ends.
func xrayTestMatrix(t *testing.T) map[string]XrayLink {
	m := map[string]XrayLink{}
	for preset := range xrayPresets {
		for _, mode := range []string{xrayModeDirect, xrayModeReverse} {
			for _, side := range []string{xraySideIran, xraySideForeign} {
				m[preset+"-"+mode+"-"+side] = xrayTestLink(t, preset, mode, side)
			}
		}
	}
	// TLS without a CDN (the panel's certificate, pinned) on every transport it carries,
	// and the user's own certificate files
	for _, tr := range []string{"xhttp", "ws", "httpupgrade", "grpc"} {
		for _, mode := range []string{xrayModeDirect, xrayModeReverse} {
			for _, side := range []string{xraySideIran, xraySideForeign} {
				m["tls-"+tr+"-"+mode+"-"+side] = xrayTLSLink(t, tr, mode, side)
			}
		}
	}
	m["tls-xhttp-direct-foreign-owncert"] = xrayTLSLink(t, "xhttp", xrayModeDirect, xraySideForeign)
	// mKCP with noise (every packet type) on the dialing end
	for _, n := range []XrayNoise{{Type: "rand", Length: "10-60", Delay: "5-10", Count: 3}, {Type: "str", Packet: "hello"},
		{Type: "hex", Packet: "deadbeef"}, {Type: "base64", Packet: "aGVsbG8="}} {
		n := n
		dial := map[string]string{xrayModeDirect: xraySideIran, xrayModeReverse: xraySideForeign}
		for mode, side := range dial {
			l := xrayTestLink(t, "kcp", mode, side)
			l.Profile.Noise = &n
			m["kcp-noise-"+n.Type+"-"+mode] = l
		}
	}
	return m
}

// TestXrayConfigsLoad runs `xray run -test` on every generated config with a
// real Xray (CI sets XRAY_BIN to the pinned release).
func TestXrayConfigsLoad(t *testing.T) {
	bin := os.Getenv("XRAY_BIN")
	if bin == "" {
		t.Skip("set XRAY_BIN to check the configs with a real Xray")
	}
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	writeTestCert(t, cert, key)
	for name, l := range xrayTestMatrix(t) {
		if strings.HasSuffix(name, "-owncert") {
			l.Profile.CertFile, l.Profile.KeyFile = cert, key
		}
		cfg, err := buildXrayConfig(l)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		p := filepath.Join(dir, name+".json")
		raw, _ := json.MarshalIndent(cfg, "", "  ")
		if err := os.WriteFile(p, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command(bin, "run", "-test", "-c", p).CombinedOutput()
		if err != nil || !strings.Contains(string(out), "Configuration OK") {
			t.Errorf("%s: xray refused the config: %v\n%s\n%s", name, err, out, raw)
		}
	}
}

func writeTestCert(t *testing.T, certPath, keyPath string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "tun.example.com"},
		DNSNames: []string{"tun.example.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(k)
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		t.Fatal(err)
	}
}

// xrayTLSLink is a TLS link without a CDN on transport tr, as the Iran server
// makes it and each end keeps it.
func xrayTLSLink(t *testing.T, tr, mode, side string) XrayLink {
	t.Helper()
	l := XrayLink{ID: 3, Mode: mode, Side: xraySideIran, Remote: "198.51.100.7", TunnelPort: 2083, Ports: []int{2053}, UDP: true,
		Profile: XrayProfile{Transport: tr, Security: "tls", SNI: "tun.example.com", Fingerprint: "chrome"}}
	l.Keys.UUID = "0f8d5c7e-1a2b-4c3d-8e9f-0123456789ab"
	l, err := newXrayLink(l)
	if err != nil {
		t.Fatal(err)
	}
	l.Side = side
	if side == xraySideForeign && !l.serverEnd() {
		l.Keys.TLSKey = "" // the bundle keeps it from the dialing foreign server
	}
	return l
}

func TestXrayTLSAndCDN(t *testing.T) {
	// The panel's certificate: made for the SNI, kept, made again for a new SNI.
	l := xrayTLSLink(t, "xhttp", xrayModeDirect, xraySideIran)
	name, pin := xrayCertName(l.Keys.TLSCert)
	if name != "tun.example.com" || len(pin) != 64 || !xrayKeyOK(l.Keys.TLSKey) {
		t.Fatalf("certificate %q pin %q", name, pin)
	}
	same, _ := newXrayLink(l)
	if same.Keys.TLSCert != l.Keys.TLSCert {
		t.Error("the certificate changed although the SNI did not")
	}
	other := l
	other.Profile.SNI = "cdn.example.org"
	other, _ = newXrayLink(other)
	if n, _ := xrayCertName(other.Keys.TLSCert); n != "cdn.example.org" {
		t.Errorf("a new SNI kept the old certificate (%s)", n)
	}

	// Without a CDN the dialing end trusts exactly that certificate...
	cfg, err := buildXrayConfig(l)
	if err != nil {
		t.Fatal(err)
	}
	s := xrayJSON(t, cfg)
	if !strings.Contains(s, `"pinnedPeerCertSha256":"`+pin+`"`) || !strings.Contains(s, `"address":"198.51.100.7"`) {
		t.Errorf("Iran (client) does not pin the certificate or dials the wrong address:\n%s", s)
	}
	// ...and the server end serves it inline, no file needed.
	f := xrayTLSLink(t, "xhttp", xrayModeDirect, xraySideForeign)
	cfg, err = buildXrayConfig(f)
	if err != nil {
		t.Fatal(err)
	}
	s = xrayJSON(t, cfg)
	if !strings.Contains(s, `"certificate":["-----BEGIN CERTIFICATE-----"`) || !strings.Contains(s, `"key":["-----BEGIN EC PRIVATE KEY-----"`) {
		t.Errorf("server end lacks the inline certificate:\n%s", s)
	}

	// Through a CDN: the CDN's own certificate is checked, the domain or clean IP dialed.
	c := xrayTestLink(t, "cdn", xrayModeDirect, xraySideIran)
	c.Profile.Address = ""
	cfg, err = buildXrayConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	s = xrayJSON(t, cfg)
	if strings.Contains(s, "pinnedPeerCertSha256") || !strings.Contains(s, `"address":"tun.example.com"`) {
		t.Errorf("CDN client pins or does not dial the domain:\n%s", s)
	}
	c.TunnelPort = 9443
	if err := c.validate(); err == nil || !strings.Contains(err.Error(), "Cloudflare") {
		t.Errorf("CDN on a port Cloudflare does not pass: %v", err)
	}
	c.TunnelPort, c.Profile.SNI = 443, "203.0.113.4"
	if err := c.validate(); err == nil {
		t.Error("CDN with an IP for its domain")
	}
	c.Profile.SNI, c.Profile.Transport = "tun.example.com", "kcp"
	if err := c.validate(); err == nil {
		t.Error("CDN over mKCP")
	}

	// The bundle carries the key only to the end that serves TLS.
	l.Keys.PrivateKey = ""
	bd, err := makeXrayBundle(l, "203.0.113.9")
	if err != nil {
		t.Fatal(err)
	}
	fb, _ := parseXrayBundle(bd)
	if !xrayKeyOK(fb.Keys.TLSKey) {
		t.Error("direct: the foreign server (TLS server) did not get the key")
	}
	r := xrayTLSLink(t, "ws", xrayModeReverse, xraySideIran)
	bd, err = makeXrayBundle(r, "203.0.113.9")
	if err != nil {
		t.Fatal(err)
	}
	rb, _ := parseXrayBundle(bd)
	if rb.Keys.TLSKey != "" || rb.Keys.TLSCert == "" {
		t.Error("reverse: the foreign server (dialing) got the TLS key, or no certificate to pin")
	}
	// Reality links carry no certificate.
	if g := xrayTestLink(t, "reality", xrayModeDirect, xraySideIran); g.Keys.TLSCert != "" {
		t.Error("a Reality link has a TLS certificate")
	}
}

func TestXrayNoise(t *testing.T) {
	l := xrayTestLink(t, "kcp", xrayModeDirect, xraySideIran)
	l.Profile.Noise = &XrayNoise{Type: "rand", Length: "10-60", Delay: "10-20", Count: 2}
	cfg, err := buildXrayConfig(l)
	if err != nil {
		t.Fatal(err)
	}
	s := xrayJSON(t, cfg)
	// noise first (next to the wire), then the mKCP encryption
	want := `"finalmask":{"udp":[{"settings":{"noise":[{"delay":"10-20","rand":"10-60"},{"delay":"10-20","rand":"10-60"}]},"type":"noise"},{"settings":{"password":"kcppassword1"},"type":"mkcp-aes128gcm"}]}`
	if !strings.Contains(s, want) {
		t.Errorf("dialing end lacks %s\n%s", want, s)
	}
	f := xrayTestLink(t, "kcp", xrayModeDirect, xraySideForeign)
	f.Profile.Noise = l.Profile.Noise
	cfg, _ = buildXrayConfig(f)
	if s := xrayJSON(t, cfg); strings.Contains(s, `"noise"`) {
		t.Errorf("the listening end sends noise:\n%s", s)
	}
	l.Profile.Noise = &XrayNoise{Type: "hex", Packet: "deadbeef"}
	cfg, _ = buildXrayConfig(l)
	if s := xrayJSON(t, cfg); !strings.Contains(s, `"noise":[{"packet":"deadbeef","type":"hex"}]`) {
		t.Errorf("hex noise:\n%s", s)
	}
	for name, n := range map[string]XrayNoise{
		"type":       {Type: "zero", Packet: "x"},
		"no length":  {Type: "rand"},
		"zero":       {Type: "rand", Length: "0-10"},
		"too big":    {Type: "rand", Length: "10-2000"},
		"bad hex":    {Type: "hex", Packet: "zz"},
		"bad base64": {Type: "base64", Packet: "!!"},
		"empty str":  {Type: "str"},
		"delay":      {Type: "str", Packet: "x", Delay: "soon"},
		"count":      {Type: "str", Packet: "x", Count: 11},
	} {
		k := l
		k.Profile.Noise = &n
		if err := k.validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	r := xrayTestLink(t, "reality", xrayModeDirect, xraySideIran)
	r.Profile.Noise = &XrayNoise{Type: "str", Packet: "x"}
	if err := r.validate(); err == nil || !strings.Contains(err.Error(), "UDP") {
		t.Errorf("noise on a TCP link: %v", err)
	}
}

// Pre-connect: the dialing end in direct mode keeps connections ready
// (testpre) on the transports that open one per user connection, and the
// server end waits long enough for them.
func TestXrayPreConnect(t *testing.T) {
	testpre := func(l XrayLink) any {
		cfg, err := buildXrayConfig(l)
		if err != nil {
			t.Fatal(err)
		}
		for _, o := range cfg["outbounds"].([]any) {
			if m := o.(map[string]any); m["tag"] == xrayTagTunnel {
				return m["settings"].(map[string]any)["testpre"]
			}
		}
		return nil
	}
	iran := xrayTestLink(t, "reality", xrayModeDirect, xraySideIran)
	if got := testpre(iran); got != xrayPreConnectDefault {
		t.Fatalf("direct Reality: testpre = %v, want %d", got, xrayPreConnectDefault)
	}
	iran.Profile.PreConnect = 9
	if got := testpre(iran); got != 9 {
		t.Fatalf("chosen count: testpre = %v", got)
	}
	iran.Profile.PreConnect = -1
	if got := testpre(iran); got != nil {
		t.Fatalf("-1 should turn it off, got %v", got)
	}
	for _, preset := range []string{"xhttp", "grpc", "cdn"} {
		if got := testpre(xrayTestLink(t, preset, xrayModeDirect, xraySideIran)); got != nil {
			t.Fatalf("%s reuses its connections: testpre = %v", preset, got)
		}
	}
	if got := testpre(xrayTestLink(t, "reality", xrayModeReverse, xraySideForeign)); got != nil {
		t.Fatalf("the reverse link is already open: testpre = %v", got)
	}

	// The server end of a direct link waits 150 s for the first request.
	cfg, err := buildXrayConfig(xrayTestLink(t, "reality", xrayModeDirect, xraySideForeign))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(xrayJSON(t, cfg["policy"]), `"handshake":150`) {
		t.Fatalf("server end policy missing: %s", xrayJSON(t, cfg["policy"]))
	}
	cfg, _ = buildXrayConfig(xrayTestLink(t, "reality", xrayModeDirect, xraySideIran))
	if cfg["policy"] != nil {
		t.Fatal("the dialing end needs no policy")
	}

	bad := xrayTestLink(t, "reality", xrayModeDirect, xraySideIran)
	bad.Profile.PreConnect = 99
	if err := bad.validate(); err == nil {
		t.Fatal("pre-connect above the maximum must be refused")
	}
}

// The reverse link: several connections from the foreign server, a capped send
// queue on every link that multiplexes, and a dead connection noticed in
// seconds instead of minutes.
func TestXrayReverseLink(t *testing.T) {
	build := func(l XrayLink) map[string]any {
		cfg, err := buildXrayConfig(l)
		if err != nil {
			t.Fatal(err)
		}
		return cfg
	}
	tunnels := func(cfg map[string]any) (tags []string) {
		for _, o := range cfg["outbounds"].([]any) {
			if m := o.(map[string]any); m["protocol"] == "vless" {
				tags = append(tags, m["tag"].(string))
				if m["settings"].(map[string]any)["reverse"] == nil {
					t.Fatalf("%s is no reverse outbound", m["tag"])
				}
			}
		}
		return tags
	}
	fo := xrayTestLink(t, "reality", xrayModeReverse, xraySideForeign)
	if got := tunnels(build(fo)); strings.Join(got, " ") != "tunnel tunnel-2 tunnel-3 tunnel-4" {
		t.Fatalf("default reverse outbounds: %v", got)
	}
	fo.Profile.RevConns = 1
	if got := tunnels(build(fo)); len(got) != 1 {
		t.Fatalf("one reverse connection: %v", got)
	}
	fo.Profile.RevConns = xrayRevConnsMax + 1
	if _, err := buildXrayConfig(fo); err == nil {
		t.Fatal("more reverse connections than the maximum was accepted")
	}

	lowat := `"opt":"25","system":"linux","type":"int","value":"16384"`
	for _, c := range []struct {
		preset, mode, side string
		lowat, keep        bool
	}{
		{"reality", xrayModeReverse, xraySideForeign, true, true},
		{"reality", xrayModeReverse, xraySideIran, true, true},
		{"xhttp", xrayModeDirect, xraySideIran, true, false},
		{"grpc", xrayModeDirect, xraySideForeign, true, false},
		{"reality", xrayModeDirect, xraySideIran, false, false},
		{"kcp", xrayModeReverse, xraySideForeign, false, false},
	} {
		js := xrayJSON(t, build(xrayTestLink(t, c.preset, c.mode, c.side)))
		if got := strings.Contains(js, lowat); got != c.lowat {
			t.Errorf("%s %s %s: TCP_NOTSENT_LOWAT %v, want %v", c.preset, c.mode, c.side, got, c.lowat)
		}
		if got := strings.Contains(js, `"tcpKeepAliveIdle":10,"tcpKeepAliveInterval":5,"tcpUserTimeout":25000`); got != c.keep {
			t.Errorf("%s %s %s: keepalive and user timeout %v, want %v", c.preset, c.mode, c.side, got, c.keep)
		}
	}
	// a direct link keeps one outbound
	n := 0
	for _, o := range build(xrayTestLink(t, "reality", xrayModeDirect, xraySideIran))["outbounds"].([]any) {
		if o.(map[string]any)["protocol"] == "vless" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("direct link: %d VLESS outbounds", n)
	}
}
