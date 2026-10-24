package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A Backhaul bundle marks UDP after the transport, with the UDP companion's
// own control port; the foreign side reads both back. Bundles without the
// mark parse as before.
func TestBackhaulBundleUDPMark(t *testing.T) {
	for _, c := range []struct {
		in   string
		port int
		want string
	}{
		{"tcpmux", 3081, "tcpmux+udp3081"},
		{"wssmux", 3081, "wssmux+udp3081"},
		{"udp", 3081, "udp"}, // carries UDP only already
		{"tcpmux", 0, "tcpmux"},
		{"", 3081, "tcpmux+udp3081"},
		{"tcpmux+udp3081", 3081, "tcpmux+udp3081"},
	} {
		if got := backhaulBundleTransport(c.in, c.port); got != c.want {
			t.Errorf("backhaulBundleTransport(%q, %d) = %q, want %q", c.in, c.port, got, c.want)
		}
	}
	for in, want := range map[string]struct {
		tr   string
		udp  bool
		port int
	}{
		"tcpmux+udp3081": {"tcpmux", true, 3081},
		"wss+udp":        {"wss", true, 0},
		"tcpmux":         {"tcpmux", false, 0},
		"tcpmux+udpX":    {"tcpmux", true, 0},
	} {
		tr, udp, port := splitBundleTransport(in)
		if tr != want.tr || udp != want.udp || port != want.port {
			t.Errorf("splitBundleTransport(%q) = %q %v %d, want %+v", in, tr, udp, port, want)
		}
	}

	s := MakeBackhaulBundle("203.0.113.5", 3080, backhaulBundleTransport("tcpmux", 3082), "tok", []string{"443", "2083=8443"})
	b, err := ParseBackhaulBundle(s)
	if err != nil {
		t.Fatal(err)
	}
	if b.Transport != "tcpmux" || !b.UDP || b.UDPPort != 3082 {
		t.Fatalf("bh1 parse: %+v (%s)", b, s)
	}
	g := MakeGreBackhaulBundle("203.0.113.5", 3080, "10.80.0.1", "10.80.0.2", backhaulBundleTransport("wss", 3082), "tok", []string{"443"})
	gb, err := ParseGreBackhaulBundle(g)
	if err != nil {
		t.Fatal(err)
	}
	if gb.Transport != "wss" || !gb.UDP || gb.UDPPort != 3082 {
		t.Fatalf("gh1 parse: %+v", gb)
	}
	old, err := ParseBackhaulBundle("bh1_203.0.113.5_3080_tcpmux_tok_443")
	if err != nil || old.UDP || old.Transport != "tcpmux" {
		t.Fatalf("bundle without the mark: %+v %v", old, err)
	}

	var body setupRequest
	body.Role = "foreign"
	applyBundle(&body, b)
	if !body.AcceptUDP || body.UDPPort != 3082 || body.Transport != "tcpmux" {
		t.Fatalf("applyBundle: accept_udp %v port %d transport %q", body.AcceptUDP, body.UDPPort, body.Transport)
	}
	if !backhaulTransportOK(body.Transport) {
		t.Fatalf("transport %q after the mark is not a core transport", body.Transport)
	}
	args, _ := installerArgs(&body, []int{443}, []string{"443"})
	if got := strings.Join(args, " "); !strings.Contains(got, "--udp --udp-port 3082") {
		t.Fatalf("foreign setup from a +udp bundle lacks --udp --udp-port 3082: %v", args)
	}
}

// The Iran setup's bundle takes the companion port hashem.sh reports.
func TestSetupBundleCarriesUDP(t *testing.T) {
	steps := []string{"[OK] backhaul-server started", "[*] UDP: backhaul-udp-server-3 carries the UDP of the same ports on control port 7002."}
	if p := udpPortFromSteps(steps); p != 7002 {
		t.Fatalf("udpPortFromSteps = %d, want 7002", p)
	}
	if p := udpPortFromSteps([]string{"no udp here"}); p != 0 {
		t.Fatalf("udpPortFromSteps without a companion = %d", p)
	}
	s := MakeBackhaulBundle("203.0.113.5", 7001, backhaulBundleTransport("tcpmux", udpPortFromSteps(steps)), "tok", nil)
	if !strings.Contains(s, "_tcpmux+udp7002_") {
		t.Fatalf("bundle %q lacks the UDP mark", s)
	}
}

// backhaulUDPPort reads the companion unit hashem.sh writes.
func TestBackhaulUDPPort(t *testing.T) {
	dir := t.TempDir()
	old := backhaulUnitDir
	backhaulUnitDir = dir
	defer func() { backhaulUnitDir = old }()

	for unit, want := range map[string]string{
		"backhaul-server":    "backhaul-udp-server",
		"backhaul-server-3":  "backhaul-udp-server-3",
		"backhaul-client":    "backhaul-udp-client",
		"backhaul-client-h2": "backhaul-udp-client-h2",
	} {
		if got := backhaulUDPUnit(unit); got != want {
			t.Errorf("backhaulUDPUnit(%q) = %q, want %q", unit, got, want)
		}
	}
	if backhaulUDPPort("backhaul-server") != 0 || backhaulUDPPort("") != 0 {
		t.Fatal("UDP port reported without a companion unit")
	}
	unit := "[Unit]\nPartOf=backhaul-server-3.service\n\n[Service]\nExecCondition=/usr/local/bin/hashem backhaul-udp-conf /etc/backhaul/server-3.toml /etc/backhaul/udp/backhaul-server-3.toml 7002\nExecStart=/usr/local/bin/backhaul -c /etc/backhaul/udp/backhaul-server-3.toml\n"
	if err := os.WriteFile(filepath.Join(dir, "backhaul-udp-server-3.service"), []byte(unit), 0644); err != nil {
		t.Fatal(err)
	}
	if p := backhaulUDPPort("backhaul-server-3"); p != 7002 {
		t.Fatalf("backhaulUDPPort = %d, want 7002", p)
	}
	if backhaulUDPPort("backhaul-server") != 0 {
		t.Fatal("companion of backhaul-server-3 matched to another unit")
	}
}

// Bagher: UDP adds a udp proxy per port next to the tcp one, and the bundle
// carries the choice to the foreign side.
func TestBagherUDP(t *testing.T) {
	without := buildFRPCConfig(55400, 5, []int{443, 8443}, false)
	if strings.Contains(without, `type = "udp"`) {
		t.Fatalf("udp proxy without UDP:\n%s", without)
	}
	with := buildFRPCConfig(55400, 5, []int{443, 8443}, true)
	for _, want := range []string{`name = "p443"`, `name = "u443"`, `name = "u8443"`, `type = "udp"`} {
		if !strings.Contains(with, want) {
			t.Fatalf("frpc config lacks %s:\n%s", want, with)
		}
	}
	if n := strings.Count(with, "[[proxies]]"); n != 4 {
		t.Fatalf("want 4 proxies (2 tcp + 2 udp), got %d", n)
	}

	raw, _ := json.Marshal(BagherBundle{Version: 1, Role: "foreign", IranPub: "203.0.113.5", FRPPort: 55400,
		Ports: []int{443}, PoolCount: 5, SSHPublicKey: "ssh-ed25519 AAAA", UDP: true})
	b, err := ParseBagherBundle("BAGHER:" + base64.StdEncoding.EncodeToString(raw))
	if err != nil {
		t.Fatal(err)
	}
	if !b.UDP {
		t.Fatal("Bagher bundle lost the UDP choice")
	}
	cfg := defaultSSHFwdConfig()
	cfg.Ports = []int{443}
	cfg.UDP = true
	if cmd := buildForeignSetupCommand(cfg); !strings.Contains(cmd, `type = "udp"`) {
		t.Fatalf("foreign setup command lacks the udp proxy:\n%s", cmd)
	}
}
