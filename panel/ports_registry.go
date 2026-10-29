package main

// One list of the ports Hashem's own configs take on this server, so every
// "is this port free" check asks the same question: peers (peerPortClash),
// Bagher (checkBagherLinkPorts), Xray (xrayClaimedPorts), cluster pools
// (validatePool) and sold customer tunnels (customers.go). A port is claimed
// by its config even while the unit that binds it is down.

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Claim kinds.
const (
	claimPanel    = "panel"  // the panel's HTTP / HTTPS port
	claimRelay    = "relay"  // an FRP / Backhaul relay's control port (the foreign server dials it)
	claimPeer     = "peer"   // a tunnel's user port (Ref: peer ID)
	claimBagher   = "bagher" // a Bagher user port (Ref: link ID)
	claimBagherFR = "bagher-frp"
	claimXray     = "xray"     // an Xray link's port on this end (Ref: link ID)
	claimPool     = "pool"     // a cluster pool's public port
	claimCustomer = "customer" // a sold tunnel's user or control port (Ref: customer ID)
)

type portClaim struct {
	Proto string // "tcp" | "udp"
	Port  int
	Kind  string
	Ref   int
	Sub   int    // a customer's link ID
	Owner string // for messages: "peer de-1", "Xray tunnel link 2", ...
}

// hashemPortClaims is every claim. It takes sshFwdMu: callers that hold it
// use portClaimsWith.
func hashemPortClaims() []portClaim {
	sshFwdMu.Lock()
	b := loadSSHFwdConfigLocked()
	sshFwdMu.Unlock()
	return portClaimsWith(b)
}

// portClaimsWith is every claim, with Bagher's config passed in.
func portClaimsWith(bagher SSHFwdConfig) []portClaim {
	var out []portClaim
	both := func(port int, kind string, ref int, owner string) {
		out = append(out, portClaim{"tcp", port, kind, ref, 0, owner}, portClaim{"udp", port, kind, ref, 0, owner})
	}
	if cfg.Port > 0 {
		out = append(out, portClaim{"tcp", cfg.Port, claimPanel, 0, 0, "the panel"})
	}
	if cfg.TLSPort > 0 {
		out = append(out, portClaim{"tcp", cfg.TLSPort, claimPanel, 0, 0, "the panel (HTTPS)"})
	}

	peers := loadPeers()
	for _, p := range peers {
		owner := "peer " + p.Name
		if p.Name == "" {
			owner = "peer " + strconv.Itoa(p.ID)
		}
		for _, port := range peerUserPorts(p) {
			both(port, claimPeer, p.ID, owner)
		}
		if p.FrpPort > 0 {
			both(p.FrpPort, claimRelay, p.ID, "the control port of "+owner)
		}
	}
	out = append(out, relayConfClaims()...)
	out = append(out, customerPortClaims()...)

	if bagher.Enabled && bagher.Role != "foreign" && bagher.Role != "server" {
		add := func(id int, ports []int) {
			owner := fmt.Sprintf("Bagher (foreign server %d)", id)
			for _, p := range ports {
				out = append(out, portClaim{"tcp", p, claimBagher, id, 0, owner})
				if bagher.UDP {
					out = append(out, portClaim{"udp", p, claimBagher, id, 0, owner})
				}
			}
		}
		add(1, bagher.Ports)
		for _, l := range bagher.Links {
			add(l.ID, l.Ports)
		}
		if bagher.FRPBindPort > 0 && bagher.FRPBindPort <= 65533 {
			owner := fmt.Sprintf("Bagher's internal FRP port (%d-%d)", bagher.FRPBindPort, bagher.FRPBindPort+2)
			for i := 0; i < 3; i++ {
				out = append(out, portClaim{"tcp", bagher.FRPBindPort + i, claimBagherFR, 0, 0, owner})
			}
		}
	}

	for _, l := range loadXrayState().Links {
		if l.Disabled {
			continue // stopped by the user: xrayPortConflicts skips it too
		}
		owner := fmt.Sprintf("Xray tunnel link %d", l.ID)
		tcp, udp := l.listens()
		for _, p := range tcp {
			if p == l.ProbePort {
				continue // loopback only: the panel's probe, never public
			}
			out = append(out, portClaim{"tcp", p, claimXray, l.ID, 0, owner})
		}
		for _, p := range udp {
			out = append(out, portClaim{"udp", p, claimXray, l.ID, 0, owner})
		}
	}

	for _, p := range loadClusterConfig().Pools {
		owner := "cluster pool " + strconv.Itoa(p.Port)
		if p.Name != "" {
			owner = "cluster pool " + p.Name
		}
		for _, proto := range lbProtos(p.Proto) {
			out = append(out, portClaim{proto, p.Port, claimPool, 0, 0, owner})
		}
	}

	return out
}

// peerUserPorts are the ports a peer's users connect to: its port list, with
// Backhaul ranges ("A-B" and "A-B=Q") expanded.
func peerUserPorts(p peerRecord) []int {
	seen := map[int]bool{}
	var out []int
	add := func(n int) {
		if n >= 1 && n <= 65535 && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	for _, n := range p.Ports {
		add(n)
	}
	for _, rp := range p.RawPorts {
		left, _, _ := strings.Cut(normalizeBackhaulPort(strings.TrimSpace(rp)), "=")
		left, ok := stripIPv4Prefix(left)
		if !ok {
			continue
		}
		lo, hi, isRange := strings.Cut(left, "-")
		a, ok := portNum(lo)
		if !ok {
			continue
		}
		b := a
		if isRange {
			if b, ok = portNum(hi); !ok || b < a {
				continue
			}
		}
		for n := a; n <= b; n++ {
			add(n)
		}
	}
	return out
}

// relayConfClaims are the control ports in the relay configs on disk:
// frps*.toml (bindPort, kcpBindPort, quicBindPort) and the Backhaul server
// configs (bind_addr). They cover a single-tunnel install without peers.json.
func relayConfClaims() []portClaim {
	var out []portClaim
	frps, _ := filepath.Glob(filepath.Join(frpDir, "frps*.toml"))
	for _, f := range frps {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		owner := "the control port of " + strings.TrimSuffix(filepath.Base(f), ".toml")
		s := string(data)
		if p := tomlInt(s, "bindPort"); p > 0 {
			out = append(out, portClaim{"tcp", p, claimRelay, 0, 0, owner})
		}
		for _, k := range []string{"kcpBindPort", "quicBindPort"} {
			if p := tomlInt(s, k); p > 0 {
				out = append(out, portClaim{"udp", p, claimRelay, 0, 0, owner})
			}
		}
	}
	bh, _ := filepath.Glob(filepath.Join(backhaulDir, "*.toml"))
	for _, f := range bh {
		base := filepath.Base(f)
		if base != "config.toml" && !strings.HasPrefix(base, "server") {
			continue
		}
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		c := parseBackhaulConf(string(data))
		if c.BindAddr == "" {
			continue
		}
		if _, p, err := net.SplitHostPort(c.BindAddr); err == nil {
			if n, ok := portNum(p); ok {
				owner := "the control port of Backhaul (" + strings.TrimSuffix(base, ".toml") + ")"
				out = append(out, portClaim{"tcp", n, claimRelay, 0, 0, owner}, portClaim{"udp", n, claimRelay, 0, 0, owner})
			}
		}
	}
	return out
}

// claimIndex is a list of claims by "proto:port" (a peer with a range of
// 65535 ports makes a long list: each lookup stays one map access).
type claimIndex map[string][]portClaim

func indexClaims(claims []portClaim) claimIndex {
	m := claimIndex{}
	for _, c := range claims {
		k := c.Proto + ":" + strconv.Itoa(c.Port)
		m[k] = append(m[k], c)
	}
	return m
}

// owner is the owner of the first claim on proto/port that skip does not
// exempt, "" when the port is free of Hashem's configs.
func (x claimIndex) owner(proto string, port int, skip func(portClaim) bool) string {
	for _, c := range x[proto+":"+strconv.Itoa(port)] {
		if skip == nil || !skip(c) {
			return c.Owner
		}
	}
	return ""
}

// claimOwner is claimIndex.owner for a one-off lookup.
func claimOwner(claims []portClaim, proto string, port int, skip func(portClaim) bool) string {
	for _, c := range claims {
		if c.Port == port && c.Proto == proto && (skip == nil || !skip(c)) {
			return c.Owner
		}
	}
	return ""
}

// claimedPortsByKey maps "tcp:443" to its owner, for the claims skip does
// not exempt (the first claim wins).
func claimedPortsByKey(claims []portClaim, skip func(portClaim) bool) map[string]string {
	m := map[string]string{}
	for _, c := range claims {
		if skip != nil && skip(c) {
			continue
		}
		k := c.Proto + ":" + strconv.Itoa(c.Port)
		if _, ok := m[k]; !ok {
			m[k] = c.Owner
		}
	}
	return m
}
