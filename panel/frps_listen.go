package main

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var ssUserPidRe = regexp.MustCompile(`"([^"]+)",pid=(\d+)`)

// pidUnit reports whether a process belongs to a systemd unit, from its
// cgroup ("0::/system.slice/frps.service"). frps-2, frps-3 and the main frps
// are the same binary, so the process name alone cannot tell them apart.
var pidUnit = func(pid int, unit string) bool {
	b, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "cgroup"))
	if err != nil {
		return false
	}
	for _, ln := range strings.Split(string(b), "\n") {
		if strings.HasSuffix(strings.TrimSpace(ln), "/"+unit) {
			return true
		}
	}
	return false
}

// frpsUnitPorts reads `ss -Htlnp` and returns the TCP ports a process of the
// given unit listens on, sorted.
func frpsUnitPorts(ssOut, unit string) []int {
	seen := map[int]bool{}
	var out []int
	for _, ln := range strings.Split(ssOut, "\n") {
		f := strings.Fields(ln)
		if len(f) < 6 {
			continue
		}
		mine := false
		for _, m := range ssUserPidRe.FindAllStringSubmatch(ln, -1) {
			if pid, err := strconv.Atoi(m[2]); err == nil && pidUnit(pid, unit) {
				mine = true
				break
			}
		}
		if !mine {
			continue
		}
		local := f[3]
		i := strings.LastIndexByte(local, ':')
		if i < 0 {
			continue
		}
		p, err := strconv.Atoi(local[i+1:])
		if err != nil || p <= 0 || p > 65535 || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

// frpsProxyPorts are the listening ports of frps that carry users: all of
// them less its own (bindPort, the KCP/QUIC/vhost ports and the dashboard).
func frpsProxyPorts(listen []int, frpsToml string, bindPort int) []int {
	own := map[int]bool{bindPort: true}
	if b, err := os.ReadFile(frpsToml); err == nil {
		s := string(b)
		for _, k := range []string{"bindPort", "kcpBindPort", "quicBindPort", "vhostHTTPPort", "vhostHTTPSPort", "tcpmuxHTTPConnectPort", "webServer.port"} {
			if p := tomlInt(s, k); p > 0 {
				own[p] = true
			}
		}
	}
	var out []int
	for _, p := range listen {
		if !own[p] {
			out = append(out, p)
		}
	}
	return out
}
