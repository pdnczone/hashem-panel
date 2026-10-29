package main

import (
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
)

// allowUFWPorts opens both tcp and udp ports in UFW firewall if UFW is active.
func allowUFWPorts(ports []int) {
	if out, err := exec.Command("ufw", "status").CombinedOutput(); err == nil && strings.Contains(string(out), "Status: active") {
		for _, p := range ports {
			exec.Command("ufw", "allow", fmt.Sprintf("%d/tcp", p)).CombinedOutput()
			exec.Command("ufw", "allow", fmt.Sprintf("%d/udp", p)).CombinedOutput()
		}
	}
}

// rewriteTomlPorts rebuilds the [[proxies]] sections of an frpc TOML file
// with the new port list. Non-proxy lines (header, serverAddr, etc.) are kept
// verbatim. Per-proxy options (localIP, transport.proxyProtocolVersion,
// transport.useEncryption, ...) are carried over: from the old block for the
// same type and port when there is one, otherwise from the first old block of
// that type, so a backend that needs PROXY protocol keeps working.
func rewriteTomlPorts(src string, ports []int) string {
	type proxyOpts struct {
		localIP string
		extras  []string
	}
	byPort := map[string]proxyOpts{} // "tcp:443"
	byType := map[string]proxyOpts{} // first block per type

	var header strings.Builder
	inProxy := false
	var typ string
	var port int
	var cur proxyOpts
	flush := func() {
		if !inProxy || typ == "" {
			return
		}
		if port > 0 {
			byPort[fmt.Sprintf("%s:%d", typ, port)] = cur
		}
		if _, ok := byType[typ]; !ok {
			byType[typ] = cur
		}
	}
	for _, line := range strings.Split(src, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[[proxies]]") {
			flush()
			inProxy, typ, port, cur = true, "", 0, proxyOpts{}
			continue
		}
		if strings.HasPrefix(trimmed, "[") {
			flush()
			inProxy = false
		}
		if !inProxy {
			header.WriteString(line)
			header.WriteByte('\n')
			continue
		}
		key, val, ok := strings.Cut(trimmed, "=")
		if !ok || strings.HasPrefix(trimmed, "#") {
			continue
		}
		key, val = strings.TrimSpace(key), strings.TrimSpace(val)
		switch key {
		case "name":
		case "type":
			typ = strings.Trim(val, `"'`)
		case "localPort":
			if port == 0 {
				port, _ = strconv.Atoi(val)
			}
		case "remotePort":
			port, _ = strconv.Atoi(val)
		case "localIP":
			cur.localIP = strings.Trim(val, `"'`)
		default:
			cur.extras = append(cur.extras, trimmed)
		}
	}
	flush()

	block := func(typ string, p int) string {
		o, ok := byPort[fmt.Sprintf("%s:%d", typ, p)]
		if !ok {
			o = byType[typ]
		}
		if o.localIP == "" {
			o.localIP = "127.0.0.1"
		}
		s := fmt.Sprintf("\n[[proxies]]\nname = \"%s_%d\"\ntype = \"%s\"\nlocalIP = %q\nlocalPort = %d\nremotePort = %d\n", typ, p, typ, o.localIP, p, p)
		for _, e := range o.extras {
			s += e + "\n"
		}
		return s
	}
	result := strings.TrimRight(header.String(), "\n") + "\n"
	for _, p := range ports {
		result += block("tcp", p) + block("udp", p)
	}
	return result
}

func isV4(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() != nil
}

// peerPortClash reports "PORT (OWNER)" for the first requested port that
// something else on this server already takes (ports_registry.go): another
// tunnel, a relay's control port, the panel, Bagher, Xray or a sold customer
// tunnel. excludeID skips one peer's own ports (<0 = none). A port a cluster
// pool covers may be served by several tunnels: that is what the pool is for.
func peerPortClash(want []int, excludeID int) string {
	pooled := map[int]bool{}
	for _, p := range loadClusterConfig().Pools {
		pooled[p.Port] = true
	}
	claims := hashemPortClaims()
	skip := func(c portClaim) bool {
		return c.Kind == claimPool || (c.Kind == claimPeer && c.Ref == excludeID)
	}
	for _, port := range want {
		if pooled[port] {
			continue
		}
		for _, proto := range []string{"tcp", "udp"} {
			if owner := claimOwner(claims, proto, port, skip); owner != "" {
				return fmt.Sprintf("%d (%s)", port, owner)
			}
		}
	}
	return ""
}

// peerDuplicateIPClash reports the name of an existing peer that already
// uses the given remote IP, skipping excludeID.
func peerDuplicateIPClash(remoteIP string, excludeID int) string {
	for _, p := range loadPeers() {
		if p.ID == excludeID {
			continue
		}
		if p.RemotePub == remoteIP {
			return p.Name
		}
	}
	return ""
}

func parsePorts(s string) []int {
	var out []int
	seen := map[int]bool{}
	for _, p := range strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n'
	}) {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil || n < 1 || n > 65535 || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	return out
}

// isValidPortOrRangeOrMapping accepts the port entries the Backhaul core
// takes: PORT, A-B, P=Q and A-B=Q, with an optional IPv4: before either side
// (checked against the real v0.7.2 core).
func isValidPortOrRangeOrMapping(s string) bool {
	left, right, mapped := strings.Cut(strings.TrimSpace(s), "=")
	if mapped {
		target, ok := stripIPv4Prefix(right)
		if !ok {
			return false
		}
		if _, ok := portNum(target); !ok {
			return false
		}
	}
	left, ok := stripIPv4Prefix(left)
	if !ok {
		return false
	}
	lo, hi, isRange := strings.Cut(left, "-")
	p1, ok := portNum(lo)
	if !ok {
		return false
	}
	if !isRange {
		return true
	}
	p2, ok := portNum(hi)
	return ok && p1 < p2
}

func portNum(s string) (int, bool) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	return n, err == nil && n >= 1 && n <= 65535
}

// stripIPv4Prefix drops a leading "IPv4:" from a port entry side.
func stripIPv4Prefix(s string) (string, bool) {
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return s, true
	}
	if !isV4(strings.TrimSpace(s[:i])) {
		return "", false
	}
	return s[i+1:], true
}

// normalizeBackhaulPort turns "A-B:Q" (in Backhaul's README, rejected by the
// core with "invalid end port in range") into the accepted "A-B=Q".
func normalizeBackhaulPort(s string) string {
	if strings.Contains(s, "=") {
		return s
	}
	rng, target, ok := strings.Cut(s, ":")
	if !ok || !strings.Contains(rng, "-") || strings.Contains(target, ":") {
		return s
	}
	return rng + "=" + target
}

func parseRawPorts(s string) []string {
	var out []string
	seen := map[string]bool{}
	for _, p := range strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n'
	}) {
		p = normalizeBackhaulPort(strings.TrimSpace(p))
		if p == "" || seen[p] {
			continue
		}
		if isValidPortOrRangeOrMapping(p) {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// extractNumericPorts returns the first listening port of each entry.
func extractNumericPorts(rawPorts []string) []int {
	var out []int
	seen := map[int]bool{}
	for _, rp := range rawPorts {
		left, _, _ := strings.Cut(rp, "=")
		left, ok := stripIPv4Prefix(left)
		if !ok {
			continue
		}
		lo, _, _ := strings.Cut(left, "-")
		if p, ok := portNum(lo); ok && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

func rewriteBackhaulTomlPorts(src string, ports []string) string {
	lines := strings.Split(src, "\n")
	var out []string
	inPorts := false
	portsAdded := false
	var portsBlock []string
	portsBlock = append(portsBlock, "ports = [")
	for i, p := range ports {
		comma := ","
		if i == len(ports)-1 {
			comma = ""
		}
		portsBlock = append(portsBlock, fmt.Sprintf("  %q%s", strings.TrimSpace(p), comma))
	}
	portsBlock = append(portsBlock, "]")

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "ports =") || strings.HasPrefix(trimmed, "ports=") {
			inPorts = true
			if !portsAdded {
				out = append(out, portsBlock...)
				portsAdded = true
			}
			if strings.HasSuffix(trimmed, "]") && strings.Contains(trimmed, "[") {
				inPorts = false
			}
			continue
		}
		if inPorts {
			if strings.HasPrefix(trimmed, "]") || strings.Contains(trimmed, "]") {
				inPorts = false
			}
			continue
		}
		out = append(out, line)
	}
	if !portsAdded {
		out = append(out, "")
		out = append(out, portsBlock...)
	}
	return strings.Join(out, "\n")
}
