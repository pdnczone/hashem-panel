package main

import (
	"slices"
	"testing"
)

func TestPublicIPs(t *testing.T) {
	addr := `1: lo    inet 127.0.0.1/8 scope host lo\       valid_lft forever preferred_lft forever
1: lo    inet6 ::1/128 scope host noprefixroute \       valid_lft forever preferred_lft forever
2: eth0    inet 203.0.113.10/27 brd 203.0.113.31 scope global eth0\       valid_lft forever preferred_lft forever
2: eth0    inet 198.51.100.20/26 scope global secondary eth0\       valid_lft forever preferred_lft forever
2: eth0    inet6 2001:db8:c012:3a5e::1/64 scope global \       valid_lft forever preferred_lft forever
2: eth0    inet6 2001:db8:c012:3a5e:9c1:22ff:fe3a:1b2c/64 scope global temporary dynamic \       valid_lft 86000sec preferred_lft 14000sec
2: eth0    inet6 2001:db8:c012:3a5e::99/64 scope global deprecated \       valid_lft forever preferred_lft 0sec
2: eth0    inet6 fe80::9c1:22ff:fe3a:1b2c/64 scope link \       valid_lft forever preferred_lft forever
3: eth1    inet 192.168.10.4/24 scope global eth1\       valid_lft forever preferred_lft forever
14: gre-tunnel    inet 10.10.10.2/30 scope global gre-tunnel\       valid_lft forever preferred_lft forever
15: sit-gre-tunnel    inet6 fd68:6173:a0a:a00::2/64 scope global nodad \       valid_lft forever preferred_lft forever
`
	v4, v6 := publicIPs(addr, "203.0.113.10")
	if !slices.Equal(v4, []string{"203.0.113.10", "198.51.100.20"}) {
		t.Fatalf("v4 %v", v4)
	}
	if !slices.Equal(v6, []string{"2001:db8:c012:3a5e::1"}) {
		t.Fatalf("v6 %v", v6)
	}
	// the main address first even when the interface lists it second
	if v4, _ := publicIPs(addr, "198.51.100.20"); !slices.Equal(v4, []string{"198.51.100.20", "203.0.113.10"}) {
		t.Fatalf("main first: %v", v4)
	}
	if v4, v6 := publicIPs("", ""); v4 != nil || v6 != nil {
		t.Fatalf("nothing: %v %v", v4, v6)
	}
}

// The tunnel table still reads only IPv4 inner addresses from the same output.
func TestParseAddrShowSkipsIPv6(t *testing.T) {
	m := parseAddrShow(`14: gre-tunnel    inet6 fe80::5efe:d972:2ef2/64 scope link \       valid_lft forever preferred_lft forever
14: gre-tunnel    inet 10.10.10.2/30 scope global gre-tunnel\       valid_lft forever preferred_lft forever
`)
	if m["gre-tunnel"] != "10.10.10.2/30" {
		t.Fatalf("got %v", m)
	}
}
