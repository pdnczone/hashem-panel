package main

import (
	"reflect"
	"testing"
)

func TestParseBackhaulConfFlatServer(t *testing.T) {
	c := parseBackhaulConf(`[server]
bind_addr = "0.0.0.0:18080"
transport = "tcpmux"
token = "a=b#c"   # trailing comment
ports = [
  "443=8443",
  "2083", # inline
  "1000-1010"
]
`)
	want := backhaulConf{Transport: "tcpmux", BindAddr: "0.0.0.0:18080", Token: "a=b#c", Ports: []string{"443=8443", "2083", "1000-1010"}}
	if !reflect.DeepEqual(c, want) {
		t.Errorf("got %+v want %+v", c, want)
	}
}

func TestParseBackhaulConfIPv6AndComments(t *testing.T) {
	c := parseBackhaulConf("# transport = \"ws\"\n[client]\nremote_addr = \"[2001:db8::1]:443\"\ntransport = \"wss\" # real one\n")
	if c.RemoteAddr != "[2001:db8::1]:443" || c.Transport != "wss" {
		t.Errorf("got %+v", c)
	}
}

func TestParseBackhaulConfSectionedDialect(t *testing.T) {
	c := parseBackhaulConf(`[listener]
bind_addr = "[::]:8080"
[transport]
type = "wsmux"
[ports]
mapping = ["80=8080", "443"]
`)
	if c.BindAddr != "[::]:8080" || c.Transport != "wsmux" || len(c.Ports) != 2 || c.Ports[1] != "443" {
		t.Errorf("got %+v", c)
	}
}

func TestParseBackhaulConfGarbageIsSafe(t *testing.T) {
	for _, in := range []string{"", "=", "[", "ports = [", "ports = [\"a\"", "x = \"unterminated", "\x00\x01"} {
		_ = parseBackhaulConf(in) // must not panic
	}
}
