package main

// Traffic of tunnels that have no interface of their own.
//
// GRE tunnels are counted from /proc/net/dev. Backhaul and Bagher run over the
// public interface, where their bytes are mixed with everything else the
// server does, so the dashboard chart showed nothing (or the whole NIC) for
// them. They are counted with iptables instead: two filter chains,
// HASHEM_ACCT_IN (jumped to from INPUT) and HASHEM_ACCT_OUT (from OUTPUT),
// hold one rule without a target per carrier port. Such a rule only counts;
// every packet goes on through the firewall unchanged.
//
// Rules match on the default-route interface only, so a Backhaul that runs
// inside GRE (gre-backhaul) is not counted twice: its packets use the GRE
// interface, which /proc/net/dev already counts. IPv4 only.

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	acctIn  = "HASHEM_ACCT_IN"
	acctOut = "HASHEM_ACCT_OUT"
	// carrierKey is the pseudo interface the counters are filed under in the
	// traffic ledger (no real interface name contains '@').
	carrierKey = "@carrier"
)

// carrierEnd is one tunnel connection end this server takes part in.
type carrierEnd struct {
	Port   int
	Remote string // the IPv4 this server dials; "" when it listens on Port
	From   string // listening: count only this peer's IPv4 (sshd also serves logins)
	UDP    bool   // also count UDP on the port (Backhaul udp transport, UDP companion)
	// Tag is the tunnel the end belongs to: its Backhaul unit
	// ("backhaul-server-3", the UDP companion files under it too) or
	// "bagher-N" for Bagher link N. Per-link speeds and usage read it.
	Tag string
}

// acctKey identifies an end in iptables-save output, which has no tags.
type acctKey struct {
	Listen bool
	Port   int
	Peer   string // the -s/-d address, "" for any
}

func (e carrierEnd) key() acctKey {
	if e.Remote != "" {
		return acctKey{Port: e.Port, Peer: e.Remote}
	}
	return acctKey{Listen: true, Port: e.Port, Peer: e.From}
}

// backhaulTag is the unit a Backhaul config belongs to: config.toml and
// server.toml are backhaul-server, client.toml backhaul-client, server-3.toml
// backhaul-server-3; a UDP companion's config is udp/<unit>.toml.
func backhaulTag(path string) string {
	base := strings.TrimSuffix(filepath.Base(path), ".toml")
	if filepath.Base(filepath.Dir(path)) == "udp" {
		if rest, ok := strings.CutPrefix(base, "backhaul-udp-"); ok { // named after the companion unit
			return "backhaul-" + rest
		}
		return base
	}
	switch base {
	case "config", "server":
		return "backhaul-server"
	case "client":
		return "backhaul-client"
	}
	return "backhaul-" + base
}

// carrierConfigs lists the Backhaul configs on this server: the main ones, the
// peer and hub ones next to them, and the UDP companions.
func carrierConfigs() []string {
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		if !seen[p] && fileExists(p) {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, c := range staleConfigCandidates() {
		if strings.HasPrefix(c.svc, "backhaul") {
			add(c.path)
		}
	}
	for _, pat := range []string{filepath.Join(backhaulDir, "*.toml"), filepath.Join(backhaulDir, "udp", "*.toml")} {
		m, _ := filepath.Glob(pat)
		for _, p := range m {
			add(p)
		}
	}
	sort.Strings(out)
	return out
}

// carrierLookup resolves a dialled host name; swappable for tests.
var carrierLookup = func(host string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
	if err != nil || len(ips) == 0 {
		return ""
	}
	return ips[0].String()
}

var carrierDNS = struct {
	sync.Mutex
	m map[string]carrierDNSEntry
}{m: map[string]carrierDNSEntry{}}

type carrierDNSEntry struct {
	ip string
	at time.Time
}

// carrierIP is host as an IP address: an IPv6 literal stays IPv6, a name is
// resolved like carrierIPv4.
func carrierIP(host string) string {
	if h := normHost(host); isV6(h) {
		return net.ParseIP(h).String()
	}
	return carrierIPv4(host)
}

// carrierIPv4 is host as an IPv4 address ("" for IPv6 or a name that does not
// resolve). Names are looked up at most every 10 minutes.
func carrierIPv4(host string) string {
	host = normHost(host)
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return v4.String()
		}
		return ""
	}
	if host == "" {
		return ""
	}
	carrierDNS.Lock()
	e, ok := carrierDNS.m[host]
	carrierDNS.Unlock()
	if ok && time.Since(e.at) < 10*time.Minute {
		return e.ip
	}
	ip := carrierLookup(host)
	carrierDNS.Lock()
	carrierDNS.m[host] = carrierDNSEntry{ip, time.Now()}
	carrierDNS.Unlock()
	return ip
}

// carrierEnds reads every Backhaul config, the Bagher config and the Xray links.
func carrierEnds() []carrierEnd {
	var ends []carrierEnd
	for _, p := range carrierConfigs() {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		tag := backhaulTag(p)
		for _, e := range backhaulCarrierEnd(parseBackhaulConf(string(data))) {
			e.Tag = tag
			ends = append(ends, e)
		}
	}
	sshFwdMu.Lock()
	cfg := loadSSHFwdConfigLocked()
	sshFwdMu.Unlock()
	ends = append(ends, bagherCarrierEnds(cfg)...)
	ends = append(ends, xrayCarrierEnds()...)
	return dedupeEnds(ends)
}

// bagherCarrierEnds are Bagher's SSH connections: on Iran one per foreign
// server it dials, on the foreign server its sshd port for the Iran server
// only (the same sshd also serves admin logins). The check used to want
// role "client", which Bagher never has, so its traffic was never counted.
func bagherCarrierEnds(cfg SSHFwdConfig) []carrierEnd {
	if !cfg.Enabled || strings.TrimSpace(cfg.RemoteHost) == "" {
		return nil
	}
	port := func(p int) int {
		if p > 0 {
			return p
		}
		return 22
	}
	if cfg.Role == "foreign" || cfg.Role == "server" {
		if ip := carrierIP(cfg.RemoteHost); ip != "" {
			return []carrierEnd{{Port: port(cfg.RemoteSSHPort), From: ip, Tag: "bagher-1"}}
		}
		return nil
	}
	var ends []carrierEnd
	if ip := carrierIP(cfg.RemoteHost); ip != "" {
		ends = append(ends, carrierEnd{Port: port(cfg.RemoteSSHPort), Remote: ip, Tag: "bagher-1"})
	}
	for _, l := range cfg.Links {
		p := l.RemoteSSHPort
		if p <= 0 {
			p = cfg.RemoteSSHPort
		}
		if ip := carrierIP(l.RemoteHost); ip != "" {
			ends = append(ends, carrierEnd{Port: port(p), Remote: ip, Tag: fmt.Sprintf("bagher-%d", l.ID)})
		}
	}
	return ends
}

// backhaulCarrierEnd is the end a Backhaul config makes: it listens on the
// port of bind_addr (server) or dials remote_addr (client).
func backhaulCarrierEnd(c backhaulConf) []carrierEnd {
	if c.BindAddr != "" {
		if _, p, err := net.SplitHostPort(c.BindAddr); err == nil {
			if n, err := strconv.Atoi(p); err == nil && n > 0 && n <= 65535 {
				return []carrierEnd{{Port: n, UDP: true}}
			}
		}
	}
	if c.RemoteAddr != "" {
		if h, p, err := net.SplitHostPort(c.RemoteAddr); err == nil {
			n, err := strconv.Atoi(p)
			if ip := carrierIP(h); err == nil && n > 0 && n <= 65535 && ip != "" {
				return []carrierEnd{{Port: n, Remote: ip, UDP: true}}
			}
		}
	}
	return nil
}

// dedupeEnds keeps one end per counted connection (the first tag wins: two
// rules for the same packets would count them twice).
func dedupeEnds(ends []carrierEnd) []carrierEnd {
	seen := map[acctKey]int{}
	var out []carrierEnd
	for _, e := range ends {
		if i, ok := seen[e.key()]; ok {
			out[i].UDP = out[i].UDP || e.UDP
			continue
		}
		seen[e.key()] = len(out)
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		if out[i].Remote != out[j].Remote {
			return out[i].Remote < out[j].Remote
		}
		return out[i].From < out[j].From
	})
	return out
}

// carrierRules renders the two chains as iptables-restore input. ifname is the
// default-route interface ("" matches any).
func carrierRules(ends []carrierEnd, ifname string) string { return carrierRulesFam(ends, ifname, 4) }

// carrierRules6 is the IPv6 table for ip6tables-restore: the ends with an
// IPv6 peer, and the ports this server listens on for anyone (they are
// reached over IPv6 too) when it has an IPv6 address. "" when there is
// nothing to count over IPv6.
func carrierRules6(ends []carrierEnd, ifname string) string {
	return carrierRulesFam(ends, ifname, 6)
}

// acctIPv6 reports whether this server has a global IPv6 address; swappable
// for tests.
var acctIPv6 = func() bool {
	data, err := os.ReadFile("/proc/net/if_inet6")
	if err != nil {
		return false
	}
	for _, l := range strings.Split(string(data), "\n") {
		if f := strings.Fields(l); len(f) >= 4 && f[3] == "00" { // scope global
			return true
		}
	}
	return false
}

func carrierRulesFam(ends []carrierEnd, ifname string, fam int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "*filter\n:%s - [0:0]\n:%s - [0:0]\n-F %s\n-F %s\n", acctIn, acctOut, acctIn, acctOut)
	in, out := "", ""
	if ifname != "" {
		in, out = " -i "+ifname, " -o "+ifname
	}
	mask, v6host, n := "/32", fam == 6 && acctIPv6(), 0
	if fam == 6 {
		mask = "/128"
	}
	for _, e := range ends {
		peer := e.Remote
		if peer == "" {
			peer = e.From
		}
		if peer != "" && ipFamily(peer) != fam || peer == "" && fam == 6 && !v6host {
			continue
		}
		n++
		protos := []string{"tcp"}
		if e.UDP {
			protos = append(protos, "udp")
		}
		for _, pr := range protos {
			switch {
			case e.Remote == "" && e.From != "": // listens, for one peer only
				fmt.Fprintf(&b, "-A %s%s -s %s%s -p %s --dport %d\n", acctIn, in, e.From, mask, pr, e.Port)
				fmt.Fprintf(&b, "-A %s%s -d %s%s -p %s --sport %d\n", acctOut, out, e.From, mask, pr, e.Port)
			case e.Remote == "": // this server listens on the port
				fmt.Fprintf(&b, "-A %s%s -p %s --dport %d\n", acctIn, in, pr, e.Port)
				fmt.Fprintf(&b, "-A %s%s -p %s --sport %d\n", acctOut, out, pr, e.Port)
			default: // this server dials Remote:Port
				fmt.Fprintf(&b, "-A %s%s -s %s%s -p %s --sport %d\n", acctIn, in, e.Remote, mask, pr, e.Port)
				fmt.Fprintf(&b, "-A %s%s -d %s%s -p %s --dport %d\n", acctOut, out, e.Remote, mask, pr, e.Port)
			}
		}
	}
	b.WriteString("COMMIT\n")
	if fam == 6 && n == 0 {
		return ""
	}
	return b.String()
}

// parseAcctSave sums the byte counters of our chains in `iptables-save -c`
// output and reports whether both chains and both jumps to them exist.
func parseAcctSave(out string) (rx, tx uint64, ready bool) {
	rx, tx, _, ready = parseAcctSaveEnds(out)
	return rx, tx, ready
}

// acctRuleKey reads which end a counting rule belongs to from its text, as
// iptables-save prints it ("-A HASHEM_ACCT_IN -i eth0 -s 1.2.3.4/32 -p tcp
// -m tcp --sport 22"). In the IN chain --dport is a port this server listens
// on and -s the peer; in the OUT chain --sport and -d.
func acctRuleKey(rule string, in bool) (acctKey, bool) {
	f := strings.Fields(rule)
	var k acctKey
	var lport, dport int
	var peer string
	for i := 0; i+1 < len(f); i++ {
		switch f[i] {
		case "--dport":
			dport, _ = strconv.Atoi(f[i+1])
		case "--sport":
			lport, _ = strconv.Atoi(f[i+1])
		case "-s", "-d":
			if (f[i] == "-s") == in {
				peer = strings.TrimSuffix(strings.TrimSuffix(f[i+1], "/32"), "/128")
			}
		}
	}
	if !in { // OUT: the local port is the source port
		lport, dport = dport, lport
	}
	// now dport is the local listening port (if any), lport the remote's port
	switch {
	case dport > 0:
		k = acctKey{Listen: true, Port: dport, Peer: peer}
	case lport > 0:
		k = acctKey{Port: lport, Peer: peer}
	default:
		return k, false
	}
	return k, true
}

// parseAcctSaveEnds is parseAcctSave with the bytes of each end as well
// ([0] received, [1] sent).
func parseAcctSaveEnds(out string) (rx, tx uint64, ends map[acctKey][2]uint64, ready bool) {
	ends = map[acctKey][2]uint64{}
	var chains, hooks int
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, ":"+acctIn+" ") || strings.HasPrefix(line, ":"+acctOut+" ") {
			chains++
			continue
		}
		if !strings.HasPrefix(line, "[") {
			continue
		}
		end := strings.Index(line, "]")
		if end < 0 {
			continue
		}
		rule := strings.TrimSpace(line[end+1:])
		switch rule {
		case "-A INPUT -j " + acctIn, "-A OUTPUT -j " + acctOut:
			hooks++
			continue
		}
		_, bytesStr, ok := strings.Cut(line[1:end], ":")
		if !ok {
			continue
		}
		n, err := strconv.ParseUint(bytesStr, 10, 64)
		if err != nil {
			continue
		}
		in := strings.HasPrefix(rule, "-A "+acctIn+" ")
		if !in && !strings.HasPrefix(rule, "-A "+acctOut+" ") {
			continue
		}
		if in {
			rx += n
		} else {
			tx += n
		}
		if k, ok := acctRuleKey(rule, in); ok {
			c := ends[k]
			if in {
				c[0] += n
			} else {
				c[1] += n
			}
			ends[k] = c
		}
	}
	return rx, tx, ends, chains == 2 && hooks == 2
}

var carrierState = struct {
	sync.Mutex
	sig        string // the rules last loaded by this process
	sig6       string // the IPv6 ones
	at         time.Time
	rx, tx     uint64
	tags       map[string][2]uint64 // per tunnel: [0] received, [1] sent
	ok         bool
	lastFailed time.Time
	// The raw chain counters of each family at the last reading ("v4",
	// "v6"; tags under "v4/"+tag): the totals above add each family's own
	// change, so a family that is rebuilt or fails once does not make the
	// sum drop and the other family's whole count is not taken again.
	raw map[string][2]uint64
}{}

// carrierAddFam adds one family's reading (totals and per-tunnel tags) to
// the running totals; prev readings are in carrierState.raw. Caller holds
// carrierState.
func carrierAddFam(fam string, rx, tx uint64, tags map[string][2]uint64) {
	if carrierState.raw == nil {
		carrierState.raw = map[string][2]uint64{}
	}
	if carrierState.tags == nil {
		carrierState.tags = map[string][2]uint64{}
	}
	add := func(key string, cur [2]uint64) [2]uint64 {
		prev := carrierState.raw[key]
		carrierState.raw[key] = cur
		return [2]uint64{counterDelta(prev[0], cur[0]), counterDelta(prev[1], cur[1])}
	}
	d := add(fam, [2]uint64{rx, tx})
	carrierState.rx += d[0]
	carrierState.tx += d[1]
	for tag, c := range tags {
		d := add(fam+"/"+tag, c)
		t := carrierState.tags[tag]
		carrierState.tags[tag] = [2]uint64{t[0] + d[0], t[1] + d[1]}
	}
}

// carrierForgetFam drops a family's last readings (its chains are gone: a
// new chain counts from 0).
func carrierForgetFam(fam string) {
	for k := range carrierState.raw {
		if k == fam || strings.HasPrefix(k, fam+"/") {
			delete(carrierState.raw, k)
		}
	}
}

// carrierTagsOf sums byEnd per tunnel tag.
func carrierTagsOf(ends []carrierEnd, byEnd map[acctKey][2]uint64) map[string][2]uint64 {
	tags := map[string][2]uint64{}
	for _, e := range ends {
		c, t := byEnd[e.key()], tags[e.Tag]
		tags[e.Tag] = [2]uint64{t[0] + c[0], t[1] + c[1]}
	}
	return tags
}

// carrierTagCounters is the last reading per tunnel (see carrierEnd.Tag);
// call carrierCounters first for a fresh one.
func carrierTagCounters() map[string][2]uint64 {
	carrierState.Lock()
	defer carrierState.Unlock()
	if !carrierState.ok {
		return nil
	}
	out := make(map[string][2]uint64, len(carrierState.tags))
	for k, v := range carrierState.tags {
		out[k] = v
	}
	return out
}

// carrierCounters returns the bytes received (rx) and sent (tx) by this
// server's Backhaul and Bagher carriers since the chains were last built. ok
// is false when there is nothing to count or iptables is unavailable. The
// reading is cached for two seconds (the snapshot and the history recorder
// both ask).
var carrierCounters = readCarrierCounters

func readCarrierCounters() (rx, tx uint64, ok bool) {
	carrierState.Lock()
	defer carrierState.Unlock()
	if time.Since(carrierState.at) < 2*time.Second {
		return carrierState.rx, carrierState.tx, carrierState.ok
	}
	carrierState.at = time.Now()
	carrierState.ok = false

	ends := carrierEnds()
	if len(ends) == 0 {
		if carrierState.sig != "" || carrierState.sig6 != "" { // the tunnels are gone: remove the chains once
			carrierDrop()
			carrierState.sig, carrierState.sig6 = "", ""
		}
		return 0, 0, false
	}
	// A failing iptables is retried once a minute, not on every tick.
	if !carrierState.lastFailed.IsZero() && time.Since(carrierState.lastFailed) < time.Minute {
		return 0, 0, false
	}
	rules := carrierRules(ends, primaryInterface())
	out, err := runCmdTimeoutOut(5*time.Second, "iptables-save", "-c", "-t", "filter")
	if err != nil {
		carrierState.lastFailed = time.Now()
		return 0, 0, false
	}
	rx, tx, byEnd, ready := parseAcctSaveEnds(string(out))
	if !ready || rules != carrierState.sig {
		// New or changed tunnels, a reboot or a firewall reload: build the
		// chains again (their counters start over from 0).
		if err := carrierLoad(rules); err != nil {
			carrierState.lastFailed = time.Now()
			return 0, 0, false
		}
		carrierState.sig = rules
		rx, tx, byEnd = 0, 0, nil
	}
	carrierAddFam("v4", rx, tx, carrierTagsOf(ends, byEnd))
	// IPv6: a failing ip6tables leaves the IPv4 counts alone
	if rules6 := carrierRules6(ends, primaryInterface()); rules6 == "" && carrierState.sig6 != "" {
		carrierDropFam("ip6tables")
		carrierState.sig6 = ""
		carrierForgetFam("v6")
	} else if rules6 != "" {
		if out6, err := runCmdTimeoutOut(5*time.Second, "ip6tables-save", "-c", "-t", "filter"); err == nil {
			rx6, tx6, byEnd6, ready6 := parseAcctSaveEnds(string(out6))
			if !ready6 || rules6 != carrierState.sig6 {
				if carrierLoadFam("ip6tables", rules6) == nil {
					carrierState.sig6 = rules6
				}
				rx6, tx6, byEnd6 = 0, 0, nil
			}
			carrierAddFam("v6", rx6, tx6, carrierTagsOf(ends, byEnd6))
		}
	}
	carrierState.lastFailed = time.Time{}
	carrierState.ok = true
	return carrierState.rx, carrierState.tx, true
}

// carrierLoad replaces both chains and makes sure INPUT and OUTPUT jump to them.
func carrierLoad(rules string) error { return carrierLoadFam("iptables", rules) }

// carrierLoadFam is carrierLoad with bin ("iptables" or "ip6tables").
func carrierLoadFam(bin, rules string) error {
	_ = os.MkdirAll(configDir, 0o700)
	f := filepath.Join(configDir, "carrier-acct.v4")
	if bin == "ip6tables" {
		f = filepath.Join(configDir, "carrier-acct.v6")
	}
	if err := os.WriteFile(f, []byte(rules), 0o600); err != nil {
		return err
	}
	if out, err := runCmdTimeout(10*time.Second, bin+"-restore", "-w", "5", "-n", f); err != nil {
		return fmt.Errorf("%s-restore: %s", bin, strings.TrimSpace(string(out)))
	}
	for _, h := range [][2]string{{"INPUT", acctIn}, {"OUTPUT", acctOut}} {
		if _, err := runCmdTimeout(5*time.Second, bin, "-w", "5", "-C", h[0], "-j", h[1]); err != nil {
			if out, err := runCmdTimeout(5*time.Second, bin, "-w", "5", "-I", h[0], "1", "-j", h[1]); err != nil {
				return fmt.Errorf("%s -I %s: %s", bin, h[0], strings.TrimSpace(string(out)))
			}
		}
	}
	return nil
}

// carrierDrop removes both chains and the jumps to them, IPv4 and IPv6
// (hashem.sh acct_chains_drop does the same on uninstall).
func carrierDrop() {
	carrierDropFam("iptables")
	carrierDropFam("ip6tables")
}

func carrierDropFam(bin string) {
	// a host that never counted IPv6 has no chains to drop: skip the failing calls
	if out, err := runCmdTimeoutOut(5*time.Second, bin+"-save", "-t", "filter"); err == nil &&
		strings.Contains(string(out), "*filter") && !strings.Contains(string(out), ":"+acctIn+" ") {
		return
	}
	for _, h := range [][2]string{{"INPUT", acctIn}, {"OUTPUT", acctOut}} {
		_, _ = runCmdTimeout(5*time.Second, bin, "-w", "5", "-D", h[0], "-j", h[1])
		_, _ = runCmdTimeout(5*time.Second, bin, "-w", "5", "-F", h[1])
		_, _ = runCmdTimeout(5*time.Second, bin, "-w", "5", "-X", h[1])
	}
}
