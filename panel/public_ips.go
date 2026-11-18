package main

import (
	"net"
	"strings"
)

// publicIPv4s lists every public IPv4 address in `ip -o -4 addr show`
// output, main first, without repeats. GRE and loopback addresses are
// private or the server's own public one again, so they drop out.
func publicIPv4s(addrShow, main string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(ip string) {
		if ip != "" && !seen[ip] && validPublicIP(ip, 4) {
			seen[ip] = true
			out = append(out, ip)
		}
	}
	add(main)
	for _, ln := range strings.Split(addrShow, "\n") {
		f := strings.Fields(ln)
		for i := 0; i+1 < len(f); i++ {
			if f[i] == "inet" {
				if ip, _, err := net.ParseCIDR(f[i+1]); err == nil {
					add(ip.String())
				}
			}
		}
	}
	return out
}
