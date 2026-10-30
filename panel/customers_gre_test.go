package main

import (
	"fmt"
	"net"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// GRE-wrapped links (P4).
func TestCustomersGRE(t *testing.T) {
	lab := newCustLab(t)
	withPro(t)
	oldRes := custResolveRemote
	custResolveRemote = func(h string) (string, error) {
		switch h {
		case "fo.example.org":
			return "198.51.100.30", nil
		case "iran.example.com":
			return "203.0.113.1", nil
		case "lan.example.org":
			return "10.0.0.5", nil
		}
		return oldRes(h)
	}
	t.Cleanup(func() { custResolveRemote = oldRes })
	// no hook yet: -C finds none
	lab.failRun = func(cmd string) bool {
		return strings.Contains(cmd, " -C ") && (strings.Contains(cmd, "HASHEM_CUST_GRE") || strings.Contains(cmd, "hcg+"))
	}

	// refused: Xray in GRE, GRE to a private address or without one, port 2048
	for _, bad := range []string{
		`{"name":"x","engine":"xray","transport":"reality","ports":"9443","gre":true,"remote":"198.51.100.30"}`,
		`{"name":"x","engine":"frp","transport":"tcp","ports":"9443","gre":true,"remote":"lan.example.org"}`,
		`{"name":"x","engine":"frp","transport":"tcp","ports":"9443","gre":true}`,
		`{"name":"x","engine":"frp","transport":"tcp","ports":"9443, 2048"}`,
		`{"name":"x","engine":"frp","transport":"tcp","ports":"9443","ctrl_port":2048}`,
		`{"name":"x","engine":"frp","transport":"tcp","ports":"34525"}`,
		// Hashem's own GRE tunnel goes to that address
		`{"name":"x","engine":"frp","transport":"tcp","ports":"9443","gre":true,"remote":"198.51.100.99"}`,
	} {
		if code, m := custPost(t, `{"action":"create","name":"bad","days":30,"address":"iran.example.com","links":[`+bad+`]}`); code == 200 {
			t.Errorf("accepted %s: %v", bad, m)
		}
	}

	code, m := custPost(t, `{"action":"create","name":"gre","days":30,"rate_mbit":10,"address":"203.0.113.1","links":[
		{"name":"f","engine":"frp","transport":"kcp","ports":"9443","gre":true,"remote":"fo.example.org","ctrl_port":31700},
		{"name":"b","engine":"backhaul","transport":"tcp","ports":"9444","gre":true,"remote":"198.51.100.31","ctrl_port":31701},
		{"name":"p","engine":"frp","transport":"tcp","ports":"9445","ctrl_port":31702}]}`)
	if code != 200 {
		t.Fatalf("create: %d %v", code, m)
	}
	lab.mu.Lock()
	lab.failRun = nil
	lab.mu.Unlock()
	c := custGet(t, 1)
	f, b, p := c.Links[0], c.Links[1], c.Links[2]
	if !f.GRE || f.RemoteIP != "198.51.100.30" || !custGREValidInner(f.GREInner) || !custGREValidInner(b.GREInner) || f.GREInner == b.GREInner {
		t.Fatalf("GRE links: %+v %+v", f, b)
	}
	if p.GRE || p.GREInner != "" {
		t.Errorf("a plain link got a GRE: %+v", p)
	}
	for _, l := range []customerLink{f, b} {
		if strings.HasPrefix(l.GREInner, "10.231.0.") {
			t.Errorf("the /30 %s overlaps a local network (10.231.0.0/24)", l.GREInner)
		}
	}
	fi, fo := f.greAddrs()
	if ip4u(net.ParseIP(fi)) != ip4u(net.ParseIP(f.GREInner))+1 || ip4u(net.ParseIP(fo)) != ip4u(net.ParseIP(f.GREInner))+2 {
		t.Errorf("inner addresses %s %s of %s", fi, fo, f.GREInner)
	}

	// the fence: each link's control port (kcp: udp too) on its interface, then DROP; nothing forwarded
	log := lab.log()
	rules, _ := os.ReadFile(filepath.Join(configDir, "customers-gre.v4"))
	bi, bo := b.greAddrs()
	m1 := "-A HASHEM_CUST_GRE -s " + fo + "/32 -d " + fi + "/32 -i hcg1x1"
	for _, want := range []string{
		"*raw", m1 + " -p tcp -m tcp --dport 31700 -j RETURN",
		m1 + " -p udp -m udp --dport 31700 -j RETURN", m1 + " -p icmp -j RETURN",
		"-A HASHEM_CUST_GRE -s " + bo + "/32 -d " + bi + "/32 -i hcg1x2 -p tcp -m tcp --dport 31701 -j RETURN",
		"-A HASHEM_CUST_GRE -i hcg+ -j DROP",
		"-A HASHEM_CUST_GREF -i hcg+ -j DROP", "-A HASHEM_CUST_GREF -o hcg+ -j DROP",
	} {
		if !strings.Contains(string(rules), want+"\n") {
			t.Errorf("GRE fence lacks %q:\n%s", want, rules)
		}
	}
	if strings.Contains(string(rules), "-i hcg1x2 -p udp") || strings.Contains(string(rules), "9443") || strings.Contains(string(rules), "31702") {
		t.Errorf("GRE fence opens more than the control ports:\n%s", rules)
	}
	for _, want := range []string{
		"ip link add hcg1x1 type gre remote 198.51.100.30 local 203.0.113.1 ttl 255",
		"ip addr add " + fi + "/30 dev hcg1x1",
		fmt.Sprintf("ip link set dev hcg1x1 mtu %d up", custGREMTU),
		"ip link add hcg1x2 type gre remote 198.51.100.31 local 203.0.113.1 ttl 255",
		"iptables -w 5 -t raw -I PREROUTING 1 -j HASHEM_CUST_GRE",
		"iptables -w 5 -t filter -I FORWARD 1 -j HASHEM_CUST_GREF",
		"ip6tables -w 5 -I INPUT 1 -i hcg+ -j DROP",
	} {
		if !strings.Contains(log, want) {
			t.Errorf("missing %q in:\n%s", want, log)
		}
	}
	if strings.Index(log, "customers-gre.v4") > strings.Index(log, "ip link add hcg1x1") {
		t.Error("the GRE came up before its fence")
	}
	if strings.Contains(log, "hcg1x3") {
		t.Error("a plain link got a GRE interface")
	}

	// steady state: the hooks are checked every tick, nothing is reloaded
	// or remade; a rule put above a hook moves it back first
	lab.mu.Lock()
	lab.cmds = nil
	lab.mu.Unlock()
	customersTick(time.Now())
	if l := lab.log(); strings.Contains(l, "customers-gre.v4") || strings.Contains(l, "ip link add") || !strings.Contains(l, "-t raw -S PREROUTING") {
		t.Errorf("steady state:\n%s", l)
	}
	lab.mu.Lock()
	lab.cmds, lab.greMoved = nil, true
	lab.mu.Unlock()
	customersTick(time.Now())
	lab.mu.Lock()
	lab.greMoved = false
	lab.mu.Unlock()
	if l := lab.log(); !strings.Contains(l, "iptables -w 5 -t raw -D PREROUTING -j HASHEM_CUST_GRE") || !strings.Contains(l, "iptables -w 5 -t raw -I PREROUTING 1 -j HASHEM_CUST_GRE") {
		t.Errorf("a hook under another rule was not put back first:\n%s", l)
	}
	// the fence does not load: the interfaces go down
	lab.mu.Lock()
	lab.cmds, lab.greMoved = nil, true
	lab.failRun = func(cmd string) bool {
		return strings.Contains(cmd, "customers-gre.v4") || strings.Contains(cmd, "-I PREROUTING")
	}
	lab.mu.Unlock()
	custApplied.gre = ""
	customersTick(time.Now())
	lab.mu.Lock()
	lab.greMoved, lab.failRun = false, nil
	lab.mu.Unlock()
	if l := lab.log(); !strings.Contains(l, "ip link set dev hcg1x1 down") || !strings.Contains(l, "ip link set dev hcg1x2 down") {
		t.Errorf("no fence, yet the GRE stayed up:\n%s", l)
	}
	customersTick(time.Now())

	// the kit: version 3, this server's IPv4, both inner addresses; the
	// manual config dials the inner address
	km, body := custKitOf(t, 1, 1)
	for _, want := range []string{"v=3\n", "gpub=203.0.113.1\n", "gin=" + fi + "\n", "gout=" + fo + "\n", "server=203.0.113.1\n"} {
		if !strings.Contains(body, want) {
			t.Errorf("GRE kit lacks %q:\n%s", want, body)
		}
	}
	if man := fmt.Sprint(km["manual"]); !strings.Contains(man, `serverAddr = "`+fi+`"`) || !strings.Contains(man, "type gre remote 203.0.113.1") {
		t.Errorf("manual GRE setup:\n%s", man)
	}
	if _, body := custKitOf(t, 1, 3); strings.Contains(body, "gpub=") || !strings.HasPrefix(body, "v=1\n") {
		t.Errorf("a plain link's kit:\n%s", body)
	}

	// a domain for this server's own address: the GRE could leave from another
	if code, m := custPost(t, `{"action":"update","id":1,"name":"gre","days":30,"rate_mbit":10,"address":"iran.example.com"}`); code != 200 {
		t.Fatalf("update: %d %v", code, m)
	}
	rr := httptest.NewRecorder()
	handleCustomersKit(rr, httptest.NewRequest("GET", "/api/customers/kit?id=1&link=1", nil))
	if rr.Code == 200 || !strings.Contains(rr.Body.String(), "203.0.113.1") {
		t.Errorf("a GRE kit for a domain naming a local address: %d %s", rr.Code, rr.Body.String())
	}
	custPost(t, `{"action":"update","id":1,"name":"gre","days":30,"rate_mbit":10,"address":"203.0.113.1"}`)

	// the installer reads the panel's GRE kit
	installer, _ := filepath.Abs("../tools/hashem-customer.sh")
	out, err := runBash(installer, "config", fmt.Sprint(km["kit"]))
	if err != nil || !strings.Contains(out, `serverAddr = "`+fi+`"`) {
		t.Errorf("installer on the GRE kit: %v\n%s", err, out)
	}

	// saving again keeps the /30; out of GRE, the interface goes; no GRE
	// link left: the fence goes too
	lab.mu.Lock()
	lab.cmds, lab.greIfs = nil, []string{"hcg1x1", "hcg1x2", "hcg9x9"}
	lab.mu.Unlock()
	custApplied.greCheck = time.Time{} // the once-a-minute look at the kernel
	if code, m := custPost(t, `{"action":"link-update","id":1,"link_id":1,"link":{"name":"f","engine":"frp","transport":"kcp","ports":"9443, 9446","gre":true,"remote":"fo.example.org","ctrl_port":31700}}`); code != 200 {
		t.Fatalf("update: %d %v", code, m)
	}
	if got := custGet(t, 1).Links[0].GREInner; got != f.GREInner {
		t.Errorf("the /30 moved on a save: %s -> %s", f.GREInner, got)
	}
	if !strings.Contains(lab.log(), "ip link del dev hcg9x9") {
		t.Errorf("a stray GRE interface stayed:\n%s", lab.log())
	}
	for _, id := range []int{1, 2} {
		if code, m := custPost(t, fmt.Sprintf(`{"action":"link-update","id":1,"link_id":%d,"link":{"name":"x","engine":"frp","transport":"tcp","ports":"%d","ctrl_port":%d}}`, id, 9442+id, 31699+id)); code != 200 {
			t.Fatalf("out of GRE: %d %v", code, m)
		}
	}
	log = lab.log()
	for _, want := range []string{"ip link del dev hcg1x1", "ip link del dev hcg1x2", "iptables -w 5 -t filter -D FORWARD -j HASHEM_CUST_GREF", "iptables -w 5 -t raw -X HASHEM_CUST_GRE", "ip6tables -w 5 -D INPUT -i hcg+ -j DROP"} {
		if !strings.Contains(log, want) {
			t.Errorf("out of GRE: missing %q in:\n%s", want, log)
		}
	}
	if l := custGet(t, 1).Links[0]; l.GRE || l.GREInner != "" || l.Remote != "" {
		t.Errorf("a link out of GRE keeps it: %+v", l)
	}
}

func runBash(args ...string) (string, error) {
	out, err := exec.Command("bash", args...).CombinedOutput()
	return string(out), err
}

func TestCustGREAlloc(t *testing.T) {
	old := custLocalNets
	t.Cleanup(func() { custLocalNets = old })
	// only 10.231.224.0/19 is not local: the /30 comes from it, never the used one
	custLocalNets = func() []ip4net {
		return []ip4net{netip4("10.231.0.0", 17), netip4("10.231.128.0", 18), netip4("10.231.192.0", 19)}
	}
	all := []customer{{ID: 1, Links: []customerLink{{ID: 1, GRE: true, GREInner: "10.231.224.0", RemoteIP: "198.51.100.1"}}}}
	links := []customerLink{{ID: 2, GRE: true, RemoteIP: "198.51.100.2"}}
	if err := custGREAlloc(all, 2, links); err != nil || !custGREValidInner(links[0].GREInner) || links[0].GREInner == "10.231.224.0" || !strings.HasPrefix(links[0].GREInner, "10.231.2") {
		t.Fatalf("alloc: %v %+v", err, links)
	}
	// one GRE per foreign server: another customer's, or two of one customer's
	if err := custGREAlloc(all, 2, []customerLink{{ID: 1, GRE: true, RemoteIP: "198.51.100.1"}}); err == nil {
		t.Error("a second GRE link to the same foreign server was given a /30")
	}
	if err := custGREAlloc(nil, 2, []customerLink{{ID: 1, GRE: true, RemoteIP: "198.51.100.3"}, {ID: 2, GRE: true, RemoteIP: "198.51.100.3"}}); err == nil {
		t.Error("two GRE links of one customer to one foreign server")
	}
	// the link itself, saved again, keeps its GRE
	if err := custGREAlloc(all, 1, []customerLink{{ID: 1, GRE: true, GREInner: "10.231.224.0", RemoteIP: "198.51.100.1"}}); err != nil {
		t.Errorf("a link saved again: %v", err)
	}
	custLocalNets = func() []ip4net { return []ip4net{netip4("10.0.0.0", 8)} }
	if err := custGREAlloc(nil, 1, []customerLink{{ID: 3, GRE: true}}); err == nil {
		t.Error("a /30 inside a local network was given")
	}
	for s, ok := range map[string]bool{"10.231.4.8": true, "10.231.4.9": false, "10.232.4.8": false, "010.231.4.8": false, "::1": false, "": false} {
		if custGREValidInner(s) != ok {
			t.Errorf("custGREValidInner(%q) != %v", s, ok)
		}
	}
	if n := custGREName(999999, 9999); len(n) > 15 {
		t.Errorf("interface name %s is too long", n)
	}
}
