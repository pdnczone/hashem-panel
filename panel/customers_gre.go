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
	custGREChain   = "HASHEM_CUST_GRE"  // INPUT: the control ports, then DROP
	custGREFwd     = "HASHEM_CUST_GREF" // FORWARD: nothing from or to hcg*
	custGREWild    = "hcg+"
	custGREMTU     = 1380
	custGREPortBad = 2048 // u32 reads GRE's protocol type (0x0800) as a port
)

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
	if !l.GRE || b == 0 {
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

// custGREWant are the GRE interfaces list needs: name -> "remote inner".
func custGREWant(list []customer) map[string]string {
	want := map[string]string{}
	for _, c := range list {
		for _, l := range c.Links {
			if iran, _ := l.greAddrs(); iran != "" && l.RemoteIP != "" {
				want[custGREName(c.ID, l.ID)] = l.RemoteIP + " " + iran
			}
		}
	}
	return want
}

// custGRERules is the GRE chains as iptables-restore input ("" when no
// link is wrapped).
func custGRERules(list []customer) string {
	var accept []string
	for _, c := range list {
		for _, l := range c.Links {
			if iran, _ := l.greAddrs(); iran == "" {
				continue
			}
			ifn := custGREName(c.ID, l.ID)
			accept = append(accept, fmt.Sprintf("-A %s -i %s -p tcp -m tcp --dport %d -j RETURN", custGREChain, ifn, l.CtrlPort))
			if l.ctrlUDP() {
				accept = append(accept, fmt.Sprintf("-A %s -i %s -p udp -m udp --dport %d -j RETURN", custGREChain, ifn, l.CtrlPort))
			}
		}
	}
	if len(accept) == 0 {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "*filter\n:%s - [0:0]\n:%s - [0:0]\n-F %s\n-F %s\n", custGREChain, custGREFwd, custGREChain, custGREFwd)
	for _, a := range accept {
		b.WriteString(a + "\n")
	}
	fmt.Fprintf(&b, "-A %s -i %s -p icmp -m icmp --icmp-type 8 -j RETURN\n", custGREChain, custGREWild)
	fmt.Fprintf(&b, "-A %s -i %s -p icmp -m icmp --icmp-type 3 -j RETURN\n", custGREChain, custGREWild)
	fmt.Fprintf(&b, "-A %s -i %s -j DROP\n", custGREChain, custGREWild)
	fmt.Fprintf(&b, "-A %s -i %s -j DROP\n-A %s -o %s -j DROP\n", custGREFwd, custGREWild, custGREFwd, custGREWild)
	b.WriteString("COMMIT\n")
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

// custGREHooks: chain -> the built-in chain it hangs off.
var custGREHooks = [][2]string{{"INPUT", custGREChain}, {"FORWARD", custGREFwd}}

// custGRE6Rules: no IPv6 from or through a GRE interface (it is off there
// too; this holds if something turns it on).
var custGRE6Rules = [][]string{{"INPUT", "-i", custGREWild, "-j", "DROP"}, {"FORWARD", "-i", custGREWild, "-j", "DROP"}, {"FORWARD", "-o", custGREWild, "-j", "DROP"}}

// custGREChainOK: the kernel's chains are rules, rule for rule, and hooked.
func custGREChainOK(rules string) bool {
	var got []string
	for _, ch := range []string{custGREChain, custGREFwd} {
		out, err := custRun("iptables", "-w", "5", "-S", ch)
		if err != nil {
			return false
		}
		for _, l := range strings.Split(string(out), "\n") {
			if l = strings.TrimSpace(l); strings.HasPrefix(l, "-A ") {
				got = append(got, l)
			}
		}
	}
	if strings.Join(got, "\n") != strings.Join(custGRERuleLines(rules), "\n") {
		return false
	}
	for _, h := range custGREHooks {
		if _, err := custRun("iptables", "-w", "5", "-C", h[0], "-j", h[1]); err != nil {
			return false
		}
	}
	return true
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
	for _, h := range custGREHooks {
		if _, err := custRun("iptables", "-w", "5", "-C", h[0], "-j", h[1]); err != nil {
			if out, err := custRun("iptables", "-w", "5", "-I", h[0], "1", "-j", h[1]); err != nil {
				return fmt.Errorf("iptables -I %s: %s", h[0], strings.TrimSpace(string(out)))
			}
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
		_, _ = custRun("iptables", "-w", "5", "-D", h[0], "-j", h[1])
	}
	for _, ch := range []string{custGREChain, custGREFwd} {
		_, _ = custRun("iptables", "-w", "5", "-F", ch)
		_, _ = custRun("iptables", "-w", "5", "-X", ch)
	}
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

// custGREIfaceOK: the interface is a GRE to remote, up, with inner/30 on it.
func custGREIfaceOK(name, remote, inner string) bool {
	out, err := custRun("ip", "-d", "-o", "link", "show", "dev", name)
	if err != nil {
		return false
	}
	f := strings.Fields(string(out))
	ok := false
	for i := 0; i+1 < len(f); i++ {
		if f[i] == "remote" && f[i+1] == remote {
			ok = true
		}
	}
	if !ok || !strings.Contains(string(out), ",UP") {
		return false
	}
	out, err = custRun("ip", "-o", "-4", "addr", "show", "dev", name)
	return err == nil && strings.Contains(string(out), " "+inner+"/30 ")
}

// custGREMake (re)makes a link's interface: plain GRE (the installer's end
// has no key either), IPv6 off before it comes up.
func custGREMake(name, remote, inner string) error {
	_, _ = custRun("ip", "link", "del", "dev", name)
	if out, err := custRun("ip", "link", "add", name, "type", "gre", "remote", remote, "ttl", "255"); err != nil {
		return fmt.Errorf("GRE %s to %s: %s", name, remote, strings.TrimSpace(string(out)))
	}
	custGRENoIPv6(name)
	steps := [][]string{
		{"ip", "addr", "add", inner + "/30", "dev", name},
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

// custGRENoIPv6 turns IPv6 off on an interface (no link-local address).
var custGRENoIPv6 = func(name string) {
	_ = os.WriteFile(filepath.Join("/proc/sys/net/ipv6/conf", name, "disable_ipv6"), []byte("1\n"), 0o644)
}

// custGRESync makes the interfaces and the chains list needs and removes
// the rest. The interfaces are checked against the kernel when the wanted
// set changes and once a minute.
func custGRESync(list []customer, now time.Time) error {
	want := custGREWant(list)
	rules := custGRERules(list)
	sig := fmt.Sprint(want) + rules
	check := now.Sub(custApplied.greCheck) > time.Minute
	if sig == custApplied.gre && (!check || rules == "") {
		return nil
	}
	custApplied.greCheck = now
	var errs []string
	// the chain first: an interface never exists without its fence
	if rules == "" {
		custGREDropChain()
	} else if !custGREChainOK(rules) {
		if err := custGRELoadChain(rules); err != nil {
			errs = append(errs, err.Error())
		}
	}
	for _, name := range custGREIfacesNow() {
		if _, ok := want[name]; !ok {
			_, _ = custRun("ip", "link", "del", "dev", name)
		}
	}
	names := make([]string, 0, len(want))
	for n := range want {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		if len(errs) > 0 {
			break // no interface without its fence
		}
		remote, inner, _ := strings.Cut(want[name], " ")
		if custGREIfaceOK(name, remote, inner) {
			continue
		}
		if err := custGREMake(name, remote, inner); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		custApplied.gre = ""
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	custApplied.gre = sig
	return nil
}
