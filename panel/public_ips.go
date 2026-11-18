package main

import (
	"net"
	"slices"
	"strings"
)

// publicIPs lists this server's public addresses in `ip -o addr show`
// output: main first, then the other IPv4 ones, then the global IPv6 ones
// (for 6to4 and 4in6), without repeats. GRE, loopback, link-local and the
// fd68: addresses of hashem's 6to4 devices are private, so they drop out, as
// do temporary (privacy) and deprecated IPv6 addresses, which change.
func publicIPs(addrShow, main string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(ip string, fam int) {
		if ip != "" && !seen[ip] && validPublicIP(ip, fam) {
			seen[ip] = true
			out = append(out, ip)
		}
	}
	add(main, 0)
	for _, fam := range []int{4, 6} {
		key := map[int]string{4: "inet", 6: "inet6"}[fam]
		for _, ln := range strings.Split(addrShow, "\n") {
			f := strings.Fields(ln)
			if fam == 6 && (!slices.Contains(f, "global") || slices.Contains(f, "temporary") ||
				slices.Contains(f, "deprecated") || slices.Contains(f, "tentative") || slices.Contains(f, "dadfailed")) {
				continue
			}
			for i := 0; i+1 < len(f); i++ {
				if f[i] == key {
					if ip, _, err := net.ParseCIDR(f[i+1]); err == nil {
						add(ip.String(), fam)
					}
				}
			}
		}
	}
	return out
}
