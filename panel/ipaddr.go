package main

import (
	"net"
	"strconv"
	"strings"
)

// ipFamily is 4 or 6 for an IP literal and 0 for anything else (a name, a
// CIDR, garbage). An IPv4-mapped IPv6 address ("::ffff:1.2.3.4") counts as 4.
func ipFamily(s string) int {
	ip := net.ParseIP(strings.TrimSpace(s))
	switch {
	case ip == nil:
		return 0
	case ip.To4() != nil:
		return 4
	default:
		return 6
	}
}

func isV6(s string) bool { return ipFamily(s) == 6 }

// hostPort is net.JoinHostPort with an int port: an IPv6 literal gets its
// brackets ("[2001:db8::1]:443"), an IPv4 address or a name does not.
func hostPort(host string, port int) string {
	return net.JoinHostPort(strings.Trim(strings.TrimSpace(host), "[]"), strconv.Itoa(port))
}

// urlHost is host as it goes into a URL without a port: IPv6 in brackets.
func urlHost(host string) string {
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if strings.Contains(host, ":") {
		return "[" + host + "]"
	}
	return host
}

// validPublicIP reports whether s is a public address of family fam (4, 6, or
// 0 for either).
func validPublicIP(s string, fam int) bool {
	f := ipFamily(s)
	return f != 0 && (fam == 0 || f == fam) && !isPrivateIP(s)
}
