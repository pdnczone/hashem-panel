package main

import (
	"strings"
	"testing"
)

// Every engine/role the Setup tab offers maps to the matching hashem.sh verb, and
// the route choice reaches the foreign setups that dial over GRE.
func TestInstallerArgsEngineMatrix(t *testing.T) {
	base := setupRequest{LocalPub: "203.0.113.1", RemotePub: "203.0.113.2", LocalGre: "10.10.10.2",
		PeerGre: "10.10.10.1", FrpPort: 3080, Token: "tok"}
	cases := []struct {
		engine, role, dial string
		verb               string
		want, not          []string
	}{
		{"frp", "iran", "", "setup-iran", nil, []string{"--dial"}},
		{"frp", "foreign", "", "setup-foreign", nil, []string{"--dial"}},
		{"frp", "foreign", "auto", "setup-foreign", nil, []string{"--dial"}},
		{"frp", "foreign", "public", "setup-foreign", []string{"--dial public"}, nil},
		{"", "foreign", "gre", "setup-foreign", []string{"--dial gre"}, nil},
		{"gre-backhaul", "iran", "", "setup-gre-backhaul-iran", []string{"--transport tcpmux", "--local-gre 10.10.10.2"}, []string{"--dial"}},
		{"gre-backhaul", "foreign", "gre", "setup-gre-backhaul-foreign", []string{"--dial gre", "--peer-gre 10.10.10.1"}, nil},
		{"gre-backhaul", "foreign", "public", "setup-gre-backhaul-foreign", []string{"--dial public"}, nil},
		{"gre-backhaul", "foreign", "nonsense", "setup-gre-backhaul-foreign", nil, []string{"--dial"}},
		{"backhaul", "iran", "", "setup-backhaul-iran", []string{"--transport tcpmux"}, []string{"--local-gre", "--dial"}},
		{"backhaul", "foreign", "gre", "setup-backhaul-foreign", nil, []string{"--dial", "--peer-gre"}},
		{"backhaul", "add-peer", "", "add-backhaul-peer", []string{"--no-gre"}, nil},
		{"gre-backhaul", "add-peer", "", "add-backhaul-peer", []string{"--local-gre 10.10.10.2"}, []string{"--no-gre"}},
	}
	for _, c := range cases {
		b := base
		b.Engine, b.Role, b.Dial = c.engine, c.role, c.dial
		args, _ := installerArgs(&b, []int{443}, []string{"443"})
		line := strings.Join(args, " ")
		name := c.engine + "/" + c.role + "/" + c.dial
		if len(args) == 0 || args[0] != c.verb {
			t.Errorf("%s: verb %q, want %q (%s)", name, args, c.verb, line)
			continue
		}
		for _, w := range c.want {
			if !strings.Contains(line, w) {
				t.Errorf("%s: missing %q in %s", name, w, line)
			}
		}
		for _, n := range c.not {
			if strings.Contains(line, n) {
				t.Errorf("%s: unexpected %q in %s", name, n, line)
			}
		}
	}
}

// UDP forwarding is a Backhaul option on both sides (the foreign client of a
// TCP-only transport runs a UDP companion too); FRP always forwards UDP.
func TestInstallerArgsUDP(t *testing.T) {
	for _, c := range []struct {
		engine, role string
		want         bool
	}{
		{"backhaul", "iran", true}, {"gre-backhaul", "iran", true}, {"gre-backhaul", "add-peer", true},
		{"gre-backhaul", "foreign", true}, {"backhaul", "foreign", true}, {"frp", "iran", false},
	} {
		b := setupRequest{Engine: c.engine, Role: c.role, AcceptUDP: true, Transport: "tcp", FrpPort: 3080}
		args, _ := installerArgs(&b, []int{443}, []string{"443"})
		if got := strings.Contains(strings.Join(args, " "), "--udp"); got != c.want {
			t.Errorf("%s/%s: --udp=%v, want %v", c.engine, c.role, got, c.want)
		}
	}
}
