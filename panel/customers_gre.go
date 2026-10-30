package main

// GRE wraps for sold links (P4). An FRP or Backhaul link can run inside a
// plain GRE tunnel between this server and the customer's foreign server:
// the panel makes the interface (hcg<cust>x<link>, a /30 from
// custGRENet), the customer's installer makes the other end, and the
// foreign end dials this end's inner address. The control port still
// listens on every address.
//
// Over GRE this server takes only the link's control port (and ping and
// the unreachable messages path MTU needs): no panel, SSH or another
// customer's port, no IPv6 (off on the interface, and dropped), and nothing
// is forwarded from or to a GRE interface.

import (
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	custGREChain = "HASHEM_CUST_GRE"  // raw PREROUTING: the control ports, then DROP
	custGREFwd   = "HASHEM_CUST_GREF" // FORWARD: nothing from or to hcg*
	custGREWild  = "hcg+"
	custGREMTU   = 1380
)

// custGREPortsBad are never sold: the cap's u32 filters read a GRE packet's
// protocol type (IPv4 0x0800, IPv6 0x86dd) as its destination port.
var custGREPortsBad = []int{2048, 34525}

// custGRENet is the pool the /30s come from.
var custGRENet = netip4("10.231.0.0", 16)

type ip4net struct {
	base uint32
	bits int
}

func netip4(s string, bits int) ip4net {
	return ip4net{ip4u(net.ParseIP(s)), bits}
}

func ip4u(ip net.IP) uint32 {
	v := ip.To4()
	if v == nil {
		return 0
	}
	return uint32(v[0])<<24 | uint32(v[1])<<16 | uint32(v[2])<<8 | uint32(v[3])
}

func u4ip(u uint32) string {
	return net.IPv4(byte(u>>24), byte(u>>16), byte(u>>8), byte(u)).String()
}

var custGRENameRe = regexp.MustCompile(`^hcg[0-9]{1,6}x[0-9]{1,4}$`)

// custGREName is a link's GRE interface (at most 14 characters).
func custGREName(cid, lid int) string { return fmt.Sprintf("hcg%dx%d", cid, lid) }

// greAddrs are the link's inner addresses: this end (.1) and the foreign
// end (.2) of its /30.
func (l customerLink) greAddrs() (iran, foreign string) {
	b := ip4u(net.ParseIP(l.GREInner))
	if !l.GRE || !custGREValidInner(l.GREInner) {
		return "", ""
	}
	return u4ip(b + 1), u4ip(b + 2)
}

// custGREValidInner: a /30's network address inside the pool.
func custGREValidInner(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil || ip.To4() == nil || ip.To4().String() != s {
		return false
	}
	u := ip4u(ip)
	mask := ^uint32(0) << (32 - custGRENet.bits)
	return u&3 == 0 && u&mask == custGRENet.base
}

// custLocalNets are this server's IPv4 networks other than its own GRE
// links' (a /30 must not overlap any of them). Swappable for tests.
var custLocalNets = func() []ip4net {
	var out []ip4net
	ifs, _ := net.Interfaces()
	for _, it := range ifs {
		if custGRENameRe.MatchString(it.Name) {
			continue
		}
		addrs, _ := it.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
				ones, _ := ipn.Mask.Size()
				out = append(out, ip4net{ip4u(ipn.IP), ones})
			}
		}
	}
	return out
}

func (n ip4net) overlaps(base uint32, bits int) bool {
	b := min(n.bits, bits)
	mask := ^uint32(0)
	if b < 32 {
		mask = ^uint32(0) << (32 - b)
	}
	if b == 0 {
		mask = 0
	}
	return n.base&mask == base&mask
}

// custGREAlloc gives every GRE link of links without a /30 one that no
// other link and no local network uses. links belong to customer cid (they
// replace its links of the same IDs in all). One GRE link per foreign
// server: a second plain GRE between the same two addresses (no key) is one
// the kernel refuses, on both ends.
func custGREAlloc(all []customer, cid int, links []customerLink) error {
	used := map[uint32]bool{}
	remote := map[string]string{}
	mine := map[int]bool{}
	for _, l := range links {
		mine[l.ID] = true
	}
	var others []customerLink
	for _, c := range all {
		for _, l := range c.Links {
			if c.ID == cid && mine[l.ID] {
				continue
			}
			if l.GRE {
				others = append(others, l)
				remote[l.RemoteIP] = fmt.Sprintf("%s (customer %d, foreign server %d)", c.Name, c.ID, l.ID)
			}
		}
	}
	for _, l := range append(others, links...) {
		if l.GRE && l.GREInner != "" {
			used[ip4u(net.ParseIP(l.GREInner))] = true
		}
	}
	for _, r := range custOwnGRERemotes() {
		if _, ok := remote[r]; !ok {
			remote[r] = "this server's own GRE tunnel"
		}
	}
	for i, l := range links {
		if !l.GRE {
			continue
		}
		if who, ok := remote[l.RemoteIP]; ok {
			return fmt.Errorf("%s already has a GRE link: %s (one GRE per foreign server)", l.RemoteIP, who)
		}
		remote[l.RemoteIP] = fmt.Sprintf("foreign server %d", links[i].ID)
	}
	local := custLocalNets()
	size := uint32(1) << (32 - custGRENet.bits) / 4
	for i := range links {
		l := &links[i]
		if !l.GRE || l.GREInner != "" {
			continue
		}
		start := uint32(rand.IntN(int(size)))
		for k := uint32(0); k < size; k++ {
			b := custGRENet.base + ((start+k)%size)*4
			if used[b] {
				continue
			}
			clash := false
			for _, n := range local {
				if n.overlaps(b, 30) {
					clash = true
					break
				}
			}
			if clash {
				continue
			}
			used[b], l.GREInner = true, u4ip(b)
			break
		}
		if l.GREInner == "" {
			return fmt.Errorf("no free GRE subnet in %s/%d", u4ip(custGRENet.base), custGRENet.bits)
		}
	}
	return nil
}

// custGREIf is what a link's interface must be.
type custGREIf struct{ remote, local, inner string }

// custOwnGRERemotes are the remotes of this server's other GRE interfaces
// (Hashem's own tunnels): a link's GRE to the same address would never get
// a packet (theirs has a local address: the kernel prefers it). Swappable.
var custOwnGRERemotes = func() []string {
	out, err := custRun("ip", "-d", "-o", "link", "show", "type", "gre")
	if err != nil {
		return nil
	}
	var rs []string
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || custGRENameRe.MatchString(strings.TrimSuffix(strings.SplitN(f[1], "@", 2)[0], ":")) {
			continue
		}
		for i := 0; i+1 < len(f); i++ {
			if f[i] == "remote" && net.ParseIP(f[i+1]) != nil {
				rs = append(rs, f[i+1])
			}
		}
	}
	return rs
}

// custGREWant are the GRE interfaces list needs.
func custGREWant(list []customer) map[string]custGREIf {
	want := map[string]custGREIf{}
	for _, c := range list {
		local := custGRELocal(c)
		for _, l := range c.Links {
			if iran, _ := l.greAddrs(); iran != "" && l.RemoteIP != "" {
				want[custGREName(c.ID, l.ID)] = custGREIf{l.RemoteIP, local, iran}
			}
		}
	}
	return want
}

// custGRELocal is the GRE's local address for c: the IPv4 address its kit
// gives the customer (gpub) when it is one of this server's, so the outer
// packets leave from the address the customer's end expects (the kernel
// would pick by route on a server with several). "" otherwise: behind 1:1
// NAT the public address is not a local one.
func custGRELocal(c customer) string {
	a := c.Address
	if a == "" {
		a = custDefaultAddress()
	}
	if ip := net.ParseIP(a); ip != nil && ip.To4() != nil && custIsLocalAddr(ip.To4().String()) {
		return ip.To4().String()
	}
	return ""
}

// custIsLocalAddr: addr is on one of this server's interfaces. Swappable.
var custIsLocalAddr = func(addr string) bool {
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && ipn.IP.String() == addr {
			return true
		}
	}
	return false
}

// custGRERules is the GRE fence as iptables-restore input ("" when no link
// is wrapped): in raw PREROUTING (before any filter rule can accept), each
// link's interface takes only its foreign end's inner address to this
// end's on the control port, and ICMP between the two; the rest of hcg+
// is dropped. In filter FORWARD nothing goes from or to hcg+.
func custGRERules(list []customer) string {
	var accept []string
	for _, c := range list {
		for _, l := range c.Links {
			iran, foreign := l.greAddrs()
			if iran == "" {
				continue
			}
			m := fmt.Sprintf("-A %s -s %s/32 -d %s/32 -i %s", custGREChain, foreign, iran, custGREName(c.ID, l.ID))
			accept = append(accept, fmt.Sprintf("%s -p tcp -m tcp --dport %d -j RETURN", m, l.CtrlPort))
			if l.ctrlUDP() {
				accept = append(accept, fmt.Sprintf("%s -p udp -m udp --dport %d -j RETURN", m, l.CtrlPort))
			}
			accept = append(accept, m+" -p icmp -j RETURN")
		}
	}
	if len(accept) == 0 {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "*raw\n:%s - [0:0]\n-F %s\n", custGREChain, custGREChain)
	for _, a := range accept {
		b.WriteString(a + "\n")
	}
	fmt.Fprintf(&b, "-A %s -i %s -j DROP\nCOMMIT\n", custGREChain, custGREWild)
	fmt.Fprintf(&b, "*filter\n:%s - [0:0]\n-F %s\n", custGREFwd, custGREFwd)
	fmt.Fprintf(&b, "-A %s -i %s -j DROP\n-A %s -o %s -j DROP\nCOMMIT\n", custGREFwd, custGREWild, custGREFwd, custGREWild)
	return b.String()
}

// custGRERuleLines are the -A lines of rules, as `iptables -S` prints them.
func custGRERuleLines(rules string) []string {
	var out []string
	for _, l := range strings.Split(rules, "\n") {
		if strings.HasPrefix(l, "-A ") {
			out = append(out, l)
		}
	}
	return out
}

// custGREHooks: table, built-in chain, the fence chain hung first in it.
var custGREHooks = [][3]string{{"raw", "PREROUTING", custGREChain}, {"filter", "FORWARD", custGREFwd}}

// custGRE6Rules: no IPv6 from or through a GRE interface (it is off there
// too; this holds if something turns it on).
var custGRE6Rules = [][]string{{"INPUT", "-i", custGREWild, "-j", "DROP"}, {"FORWARD", "-i", custGREWild, "-j", "DROP"}, {"FORWARD", "-o", custGREWild, "-j", "DROP"}}

// custGREHooksFirst: each fence chain is the first rule of its built-in
// chain (a later "-I ... 1 -j ACCEPT" would otherwise open the GRE) and the
// IPv6 drops are in place.
func custGREHooksFirst() bool {
	for _, h := range custGREHooks {
		out, err := custRun("iptables", "-w", "5", "-t", h[0], "-S", h[1])
		if err != nil {
			return false
		}
		first := ""
		for _, l := range strings.Split(string(out), "\n") {
			if l = strings.TrimSpace(l); strings.HasPrefix(l, "-A ") {
				first = l
				break
			}
		}
		if first != "-A "+h[1]+" -j "+h[2] {
			return false
		}
	}
	if _, err := custRun("ip6tables", "-w", "5", "-S", "INPUT"); err == nil {
		for _, r := range custGRE6Rules {
			if _, err := custRun("ip6tables", append([]string{"-w", "5", "-C"}, r...)...); err != nil {
				return false
			}
		}
	}
	return true
}

// custGREChainOK: the kernel's fence is rules, rule for rule, hooked first.
func custGREChainOK(rules string) bool {
	var got []string
	for _, h := range custGREHooks {
		out, err := custRun("iptables", "-w", "5", "-t", h[0], "-S", h[2])
		if err != nil {
			return false
		}
		for _, l := range strings.Split(string(out), "\n") {
			if l = strings.TrimSpace(l); strings.HasPrefix(l, "-A ") {
				got = append(got, l)
			}
		}
	}
	return strings.Join(got, "\n") == strings.Join(custGRERuleLines(rules), "\n") && custGREHooksFirst()
}

func custGRELoadChain(rules string) error {
	_ = os.MkdirAll(configDir, 0o700)
	f := filepath.Join(configDir, "customers-gre.v4")
	if err := os.WriteFile(f, []byte(rules), 0o600); err != nil {
		return err
	}
	if out, err := custRun("iptables-restore", "-w", "5", "-n", f); err != nil {
		return fmt.Errorf("iptables-restore (GRE): %s", strings.TrimSpace(string(out)))
	}
	return custGREHook()
}

// custGREHook puts each hook first (removing it wherever else it is).
func custGREHook() error {
	for _, h := range custGREHooks {
		for i := 0; i < 4; i++ {
			if _, err := custRun("iptables", "-w", "5", "-t", h[0], "-D", h[1], "-j", h[2]); err != nil {
				break
			}
		}
		if out, err := custRun("iptables", "-w", "5", "-t", h[0], "-I", h[1], "1", "-j", h[2]); err != nil {
			return fmt.Errorf("iptables -t %s -I %s: %s", h[0], h[1], strings.TrimSpace(string(out)))
		}
	}
	if _, err := custRun("ip6tables", "-w", "5", "-S", "INPUT"); err == nil {
		for _, r := range custGRE6Rules {
			if _, err := custRun("ip6tables", append([]string{"-w", "5", "-C"}, r...)...); err != nil {
				if out, err := custRun("ip6tables", append([]string{"-w", "5", "-I", r[0], "1"}, r[1:]...)...); err != nil {
					return fmt.Errorf("ip6tables -I %s: %s", r[0], strings.TrimSpace(string(out)))
				}
			}
		}
	}
	return nil
}

func custGREDropChain() {
	for _, h := range custGREHooks {
		for i := 0; i < 4; i++ {
			if _, err := custRun("iptables", "-w", "5", "-t", h[0], "-D", h[1], "-j", h[2]); err != nil {
				break
			}
		}
		_, _ = custRun("iptables", "-w", "5", "-t", h[0], "-F", h[2])
		_, _ = custRun("iptables", "-w", "5", "-t", h[0], "-X", h[2])
	}
	// a fence from before it moved to raw
	_, _ = custRun("iptables", "-w", "5", "-D", "INPUT", "-j", custGREChain)
	_, _ = custRun("iptables", "-w", "5", "-F", custGREChain)
	_, _ = custRun("iptables", "-w", "5", "-X", custGREChain)
	for _, r := range custGRE6Rules {
		_, _ = custRun("ip6tables", append([]string{"-w", "5", "-D"}, r...)...)
	}
}

// custGREIfacesNow are the hcg* interfaces in the kernel. Swappable.
var custGREIfacesNow = func() []string {
	ents, _ := os.ReadDir("/sys/class/net")
	var out []string
	for _, e := range ents {
		if custGRENameRe.MatchString(e.Name()) {
			out = append(out, e.Name())
		}
	}
	return out
}

// custGREIfaceOK: the interface is a plain GRE (no FOU/GUE encapsulation,
// which Hashem's carrier switch could put on it) from local to remote, up,
// with inner/30 on it.
func custGREIfaceOK(name string, w custGREIf) bool {
	out, err := custRun("ip", "-d", "-o", "link", "show", "dev", name)
	if err != nil {
		return false
	}
	s := string(out)
	f := strings.Fields(s)
	remote, local := false, w.local == ""
	for i := 0; i+1 < len(f); i++ {
		switch {
		case f[i] == "remote" && f[i+1] == w.remote:
			remote = true
		case f[i] == "local" && f[i+1] == w.local:
			local = true
		}
	}
	if !remote || !local || !strings.Contains(s, " link/gre ") || !strings.Contains(s, ",UP") || strings.Contains(s, "encap fou") || strings.Contains(s, "encap gue") {
		return false
	}
	out, err = custRun("ip", "-o", "-4", "addr", "show", "dev", name)
	return err == nil && strings.Contains(string(out), " "+w.inner+"/30 ")
}

// custGREMake (re)makes a link's interface: plain GRE (the installer's end
// has no key either), hardened before it comes up.
func custGREMake(name string, w custGREIf) error {
	_, _ = custRun("ip", "link", "del", "dev", name)
	args := []string{"link", "add", name, "type", "gre", "remote", w.remote}
	if w.local != "" {
		args = append(args, "local", w.local)
	}
	if out, err := custRun("ip", append(args, "ttl", "255")...); err != nil {
		return fmt.Errorf("GRE %s to %s: %s", name, w.remote, strings.TrimSpace(string(out)))
	}
	custGREHarden(name)
	steps := [][]string{
		{"ip", "addr", "add", w.inner + "/30", "dev", name},
		{"ip", "link", "set", "dev", name, "mtu", strconv.Itoa(custGREMTU), "up"},
	}
	for _, s := range steps {
		if out, err := custRun(s[0], s[1:]...); err != nil {
			_, _ = custRun("ip", "link", "del", "dev", name)
			return fmt.Errorf("GRE %s: %s", name, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// custGREHarden: IPv6 off on the interface (no link-local address) and
// strict reverse-path filtering (only the /30's peer comes in on it).
var custGREHarden = func(name string) {
	_ = os.WriteFile(filepath.Join("/proc/sys/net/ipv6/conf", name, "disable_ipv6"), []byte("1\n"), 0o644)
	_ = os.WriteFile(filepath.Join("/proc/sys/net/ipv4/conf", name, "rp_filter"), []byte("1\n"), 0o644)
}

// custGREDown takes the interfaces down (the fence could not be put in
// place: no GRE without it).
func custGREDown(names []string) {
	for _, n := range names {
		_, _ = custRun("ip", "link", "set", "dev", n, "down")
	}
}

// custGRESync makes the interfaces and the fence list needs and removes the
// rest. The fence's hooks are checked every tick (they must stay first);
// the rest against the kernel when the wanted set changes and once a
// minute. made: an interface was (re)made (its caps must be loaded again).
func custGRESync(list []customer, now time.Time) (made bool, err error) {
	want := custGREWant(list)
	rules := custGRERules(list)
	sig := fmt.Sprint(want) + rules
	check := now.Sub(custApplied.greCheck) > time.Minute
	names := make([]string, 0, len(want))
	for n := range want {
		names = append(names, n)
	}
	sort.Strings(names)
	if sig == custApplied.gre && (!check || rules == "") {
		if rules == "" || custGREHooksFirst() {
			return false, nil
		}
		check = true // a hook moved or went: the full check below
	}
	custApplied.greCheck = now
	// the fence first: an interface never runs without it
	if rules == "" {
		custGREDropChain()
	} else if !custGREChainOK(rules) {
		if err := custGRELoadChain(rules); err != nil {
			custGREDown(names)
			custApplied.gre = ""
			return false, err
		}
	}
	for _, name := range custGREIfacesNow() {
		if _, ok := want[name]; !ok {
			_, _ = custRun("ip", "link", "del", "dev", name)
		}
	}
	var errs []string
	for _, name := range names {
		if custGREIfaceOK(name, want[name]) {
			custGREHarden(name)
			continue
		}
		made = true
		if err := custGREMake(name, want[name]); err != nil {
			errs = append(errs, err.Error()) // only this link: the others go on
		}
	}
	if len(errs) > 0 {
		custApplied.gre = ""
		return made, fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	custApplied.gre = sig
	return made, nil
}
