package main

import (
	"net"
	"slices"
	"strings"
)

// publicIPs reads this server's public addresses from `ip -o addr show`.
//
// v4 is every public IPv4, main first, without repeats: the addresses Edit
// Tunnel accepts as a tunnel's Iran IP. GRE, loopback and LAN addresses are
// private, so they drop out.
//
// v6 is every global IPv6 the server keeps (the 6to4 and 4in6 carriers run
// over them). Temporary (privacy) and deprecated addresses change on their
// own, and private ones (fd68: on hashem's 6to4 devices, link-local) are not
// reachable from outside, so they drop out.
func publicIPs(addrShow, main string) (v4, v6 []string) {
	seen := map[string]bool{}
	add := func(list *[]string, ip string, fam int) {
		if ip != "" && !seen[ip] && validPublicIP(ip, fam) {
			seen[ip] = true
			*list = append(*list, ip)
		}
	}
	add(&v4, main, 4)
	for _, ln := range strings.Split(addrShow, "\n") {
		f := strings.Fields(ln)
		for i := 0; i+1 < len(f); i++ {
			switch f[i] {
			case "inet":
				if ip, _, err := net.ParseCIDR(f[i+1]); err == nil {
					add(&v4, ip.String(), 4)
				}
			case "inet6":
				if !slices.Contains(f, "global") || slices.Contains(f, "temporary") || slices.Contains(f, "deprecated") ||
					slices.Contains(f, "tentative") || slices.Contains(f, "dadfailed") {
					continue
				}
				if ip, _, err := net.ParseCIDR(f[i+1]); err == nil {
					add(&v6, ip.String(), 6)
				}
			}
		}
	}
	return v4, v6
}
