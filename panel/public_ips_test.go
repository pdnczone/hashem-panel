package main

import (
	"slices"
	"testing"
)

func TestPublicIPv4s(t *testing.T) {
	addr := `1: lo    inet 127.0.0.1/8 scope host lo\       valid_lft forever preferred_lft forever
2: eth0    inet 217.114.46.242/27 brd 217.114.46.255 scope global eth0\       valid_lft forever preferred_lft forever
2: eth0    inet 88.218.18.121/26 scope global secondary eth0\       valid_lft forever preferred_lft forever
3: eth1    inet 192.168.10.4/24 scope global eth1\       valid_lft forever preferred_lft forever
14: gre-tunnel    inet 10.10.10.2/30 scope global gre-tunnel\       valid_lft forever preferred_lft forever
`
	if got := publicIPv4s(addr, "217.114.46.242"); !slices.Equal(got, []string{"217.114.46.242", "88.218.18.121"}) {
		t.Fatalf("got %v", got)
	}
	// the main address first even when the interface lists it second
	if got := publicIPv4s(addr, "88.218.18.121"); !slices.Equal(got, []string{"88.218.18.121", "217.114.46.242"}) {
		t.Fatalf("main first: %v", got)
	}
	if got := publicIPv4s("", ""); got != nil {
		t.Fatalf("nothing: %v", got)
	}
}
