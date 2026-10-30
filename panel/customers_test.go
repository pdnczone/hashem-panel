package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// custLabCurrent is the last newCustLab (for helpers).
var custLabCurrent *custLab

// custLab is a customers environment with every host command stubbed.
type custLab struct {
	mu      sync.Mutex
	cmds    []string // custRun commands
	sysctl  []string // systemctl calls
	save    string   // what iptables-save prints
	failRun func(cmd string) bool
	alerts  []custEvent
	greIfs  []string // the hcg* interfaces "in the kernel"
}

func (l *custLab) log() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.cmds, "\n")
}

func (l *custLab) systemctl() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.sysctl, "\n")
}

func (l *custLab) reset() {
	l.mu.Lock()
	l.cmds, l.sysctl = nil, nil
	l.mu.Unlock()
}

func resetCustState() {
	custs.Lock()
	custs.loaded, custs.loadErr, custs.f, custs.speed, custs.at, custs.dirty, custs.err = false, "", customersFile{}, nil, time.Time{}, false, ""
	custs.Unlock()
	custApplied.ipt, custApplied.tc, custApplied.tcIfs, custApplied.tcCheck = "", "", nil, time.Time{}
	custApplied.police, custApplied.cleaned, custApplied.running, custApplied.swept, custApplied.reserved = nil, false, nil, false, ""
	custApplied.gre, custApplied.greCheck = "", time.Time{}
}

func newCustLab(t *testing.T) *custLab {
	t.Helper()
	dir := registryEnv(t)
	l := &custLab{}
	custLabCurrent = l
	oldUnit, oldBin, oldSrc, oldBH, oldXray := engineUnitDir, custBinDir, custFrpsSrc, custBackhaulSrc, custXraySrc
	oldRun, oldSave, oldIf, oldAlert, oldBusy, oldSys := custRun, custSaveOut, custIfaces, custAlert, custPortBusy, runSystemctl
	oldActive, oldLinked, oldLimRun, oldSysctl := custUnitsActive, custLinked, limitsRun, custReserveSysctl
	oldGREIfs, oldGRE6, oldLocal := custGREIfacesNow, custGRENoIPv6, custLocalNets
	custGREIfacesNow = func() []string {
		l.mu.Lock()
		defer l.mu.Unlock()
		return append([]string(nil), l.greIfs...)
	}
	custGRENoIPv6 = func(string) {}
	custLocalNets = func() []ip4net { return []ip4net{netip4("10.231.0.0", 24), netip4("192.0.2.0", 24)} }
	custReserveSysctl = filepath.Join(dir, "reserved")
	_ = os.WriteFile(custReserveSysctl, []byte("7000-7002\n"), 0o644)
	limitsRun = func(name string, args ...string) ([]byte, error) { return nil, nil } // tc filter show
	engineUnitDir = filepath.Join(dir, "systemd")
	custBinDir = filepath.Join(dir, "hashem-sell")
	custFrpsSrc = filepath.Join(dir, "frps-src")
	custBackhaulSrc = filepath.Join(dir, "backhaul-src")
	custXraySrc = filepath.Join(dir, "xray-src")
	_ = os.MkdirAll(engineUnitDir, 0o755)
	for _, f := range []string{custFrpsSrc, custBackhaulSrc, custXraySrc} {
		if err := os.WriteFile(f, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	custRun = func(name string, args ...string) ([]byte, error) {
		cmd := name + " " + strings.Join(args, " ")
		l.mu.Lock()
		l.cmds = append(l.cmds, cmd)
		fail := l.failRun
		l.mu.Unlock()
		if fail != nil && fail(cmd) {
			return []byte("boom"), fmt.Errorf("exit 1")
		}
		if name == "iptables-restore" && strings.HasSuffix(args[len(args)-1], "customers.v4") {
			// a rebuilt chain counts from zero (args[len-1] is the rules file)
			data, _ := os.ReadFile(args[len(args)-1])
			_ = os.WriteFile(filepath.Join(configDir, "customers.v4"), data, 0o600)
			l.mu.Lock()
			l.save = chainSave(nil)
			l.mu.Unlock()
		}
		if name == "tc" && len(args) > 1 && args[0] == "qdisc" && args[1] == "show" {
			return []byte("qdisc clsact ffff: parent ffff:fff1"), nil
		}
		return nil, nil
	}
	custSaveOut = func() ([]byte, error) {
		l.mu.Lock()
		defer l.mu.Unlock()
		return []byte(l.save), nil
	}
	custIfaces = func() []custIfc { return []custIfc{{"eth0", []string{"192.0.2.10"}}} }
	custAlert = func(e custEvent) {
		l.mu.Lock()
		l.alerts = append(l.alerts, e)
		l.mu.Unlock()
	}
	custPortBusy = func(string, int) bool { return false }
	runSystemctl = func(args ...string) error {
		l.mu.Lock()
		l.sysctl = append(l.sysctl, strings.Join(args, " "))
		l.mu.Unlock()
		return nil
	}
	custUnitsActive = func(units []string) map[string]bool { return map[string]bool{} }
	custLinked = func(ports []int) map[int]bool { return map[int]bool{} }
	resetCustState()
	t.Cleanup(func() {
		engineUnitDir, custBinDir, custFrpsSrc, custBackhaulSrc, custXraySrc = oldUnit, oldBin, oldSrc, oldBH, oldXray
		custRun, custSaveOut, custIfaces, custAlert, custPortBusy, runSystemctl = oldRun, oldSave, oldIf, oldAlert, oldBusy, oldSys
		custUnitsActive, custLinked, limitsRun, custReserveSysctl = oldActive, oldLinked, oldLimRun, oldSysctl
		custGREIfacesNow, custGRENoIPv6, custLocalNets = oldGREIfs, oldGRE6, oldLocal
		resetCustState()
	})
	return l
}

// chainSave is iptables-save -c output with the chain as the panel last
// loaded it (customers.v4), hooked in, and these byte counters by comment
// (on the first rule of each comment).
func chainSave(counters map[string]uint64) string {
	var b strings.Builder
	b.WriteString("*filter\n:INPUT ACCEPT [0:0]\n:" + custChain + " - [0:0]\n[1:1] -A INPUT -j " + custChain + "\n[1:1] -A OUTPUT -j " + custChain + "\n")
	rules, _ := os.ReadFile(filepath.Join(configDir, "customers.v4"))
	done := map[string]bool{}
	for _, l := range strings.Split(string(rules), "\n") {
		if !strings.HasPrefix(l, "-A "+custChain+" ") {
			continue
		}
		var n uint64
		f := strings.Fields(l)
		for i := 0; i+1 < len(f); i++ {
			if f[i] == "--comment" && !done[f[i+1]] {
				n, done[f[i+1]] = counters[f[i+1]], true
			}
		}
		fmt.Fprintf(&b, "[10:%d] %s\n", n, l)
	}
	b.WriteString("COMMIT\n")
	return b.String()
}

func custPost(t *testing.T, body string) (int, map[string]any) {
	t.Helper()
	rr := httptest.NewRecorder()
	handleCustomersPost(rr, httptest.NewRequest("POST", "/api/customers", strings.NewReader(body)))
	var m map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &m)
	return rr.Code, m
}

func custGet(t *testing.T, id int) customer {
	t.Helper()
	custs.Lock()
	defer custs.Unlock()
	c := custFindLocked(id)
	if c == nil {
		t.Fatalf("no customer %d", id)
	}
	return *c
}

const custCreateBody = `{"action":"create","name":"Ali","days":30,"quota_gb":10,"rate_mbit":20,
 "links":[{"name":"de-1","ports":"443, 2083","udp":true},{"name":"nl-1","transport":"kcp","ctrl_port":30001,"ports":"8443"}]}`

func TestCustomersCreateNeedsPro(t *testing.T) {
	newCustLab(t)
	setTestLicense(t, nil)
	if code, m := custPost(t, custCreateBody); code != 403 || m["error_code"] != "E-LIC-01" {
		t.Fatalf("create without a license: %d %v", code, m)
	}
}

func TestCustomersLifecycle(t *testing.T) {
	l := newCustLab(t)
	withPro(t)
	code, m := custPost(t, custCreateBody)
	if code != 200 {
		t.Fatalf("create: %d %v", code, m)
	}
	c := custGet(t, 1)
	if len(c.Links) != 2 || c.Links[0].CtrlPort < 20000 || c.Links[1].CtrlPort != 30001 || !custTokenRe.MatchString(c.Token) || len(c.Links[0].Token) != 32 {
		t.Fatalf("customer: %+v", c)
	}
	if c.ExpiresAt-time.Now().Unix() < 29*86400 {
		t.Errorf("30 days: expires %d", c.ExpiresAt)
	}
	// the API never hands out the frp tokens in the list
	raw, _ := json.Marshal(m)
	if strings.Contains(string(raw), c.Links[0].Token) || strings.Contains(string(raw), c.Links[1].Token) {
		t.Errorf("a link token is in the list: %s", raw)
	}

	// configs and units
	conf, _ := os.ReadFile(custConfPath(1, 1, custEngineFRP))
	for _, want := range []string{"bindPort = " + fmt.Sprint(c.Links[0].CtrlPort), "{ single = 443 }", "{ single = 2083 }", `auth.token = "` + c.Links[0].Token + `"`, `proxyBindAddr = "0.0.0.0"`} {
		if !strings.Contains(string(conf), want) {
			t.Errorf("1-1.toml lacks %q:\n%s", want, conf)
		}
	}
	conf2, _ := os.ReadFile(custConfPath(1, 2, custEngineFRP))
	if !strings.Contains(string(conf2), "kcpBindPort = 30001") {
		t.Errorf("kcp link:\n%s", conf2)
	}
	unit, _ := os.ReadFile(custUnitPath(1, 1))
	if !strings.Contains(string(unit), "ExecStart="+custBin()+" -c "+custConfPath(1, 1, custEngineFRP)) {
		t.Errorf("unit:\n%s", unit)
	}
	if _, err := os.Stat(custBin()); err != nil {
		t.Errorf("frps copy: %v", err)
	}
	// the chain is loaded before the units start
	log := l.log()
	sys := l.systemctl()
	if !strings.Contains(log, "iptables-restore") || !strings.Contains(sys, "start hsell-1-1.service") || !strings.Contains(sys, "start hsell-1-2.service") {
		t.Fatalf("apply:\n%s\n--\n%s", log, sys)
	}
	rules, _ := os.ReadFile(filepath.Join(configDir, "customers.v4"))
	for _, want := range []string{
		"-A HASHEM_CUST -p tcp -m tcp --dport 443 -m comment --comment hsell-1-in\n",
		"-A HASHEM_CUST -p udp -m udp --sport 2083 -m comment --comment hsell-1-out\n",
		"-A HASHEM_CUST -p tcp -m tcp --sport 8443 -m comment --comment hsell-1-out\n",
	} {
		if !strings.Contains(string(rules), want) {
			t.Errorf("rules lack %q:\n%s", want, rules)
		}
	}
	if strings.Contains(string(rules), "-p udp -m udp --dport 8443") {
		t.Errorf("udp rule for a tcp-only link:\n%s", rules)
	}
	// one speed cap for the customer: both directions, every port of every link
	idxOut, idxIn := fmt.Sprint(custPoliceIndex(1, true)), fmt.Sprint(custPoliceIndex(1, false))
	for _, want := range []string{
		"tc actions replace action police rate 20000kbit burst 1250000 mtu 65535 conform-exceed drop/pass index " + idxOut,
		// to the users: policed as it enters from the customer's frpc (the control port)
		"tc filter add dev eth0 ingress pref 4919 protocol ip u32 match ip dst 192.0.2.10/32 match ip dport 30001 0xffff action police index " + idxOut,
		"tc filter add dev eth0 ingress pref 4919 protocol ip u32 match ip dst 192.0.2.10/32 match ip dport 443 0xffff action police index " + idxIn,
	} {
		if !strings.Contains(log, want) {
			t.Errorf("tc lacks %q:\n%s", want, log)
		}
	}

	// the port registry knows the sold ports
	if clash := peerPortClash([]int{2083}, -1); !strings.Contains(clash, "customer Ali") {
		t.Errorf("peer on a sold port: %q", clash)
	}
	if clash := peerPortClash([]int{c.Links[0].CtrlPort}, -1); !strings.Contains(clash, "control port of customer Ali") {
		t.Errorf("peer on a sold control port: %q", clash)
	}

	// usage: counted per customer, both directions, not while cut
	// the chain was loaded empty when the customer was made: every byte counts
	l.save = chainSave(map[string]uint64{"hsell-1-in": 1000, "hsell-1-out": 5000})
	t0 := time.Now()
	customersTick(t0)
	l.save = chainSave(map[string]uint64{"hsell-1-in": 3000, "hsell-1-out": 9000})
	customersTick(t0.Add(10 * time.Second))
	if c := custGet(t, 1); c.UsedRx != 3000 || c.UsedTx != 9000 {
		t.Fatalf("usage: rx %d tx %d", c.UsedRx, c.UsedTx)
	}

	// cut by hand (works without a license): DROP, units stopped
	setTestLicense(t, nil)
	l.reset()
	if code, m := custPost(t, `{"action":"cut","id":1}`); code != 200 {
		t.Fatalf("cut: %d %v", code, m)
	}
	rules, _ = os.ReadFile(filepath.Join(configDir, "customers.v4"))
	if !strings.Contains(string(rules), "--comment hsell-1-in -j DROP") || !strings.Contains(l.systemctl(), "stop hsell-1-1.service") {
		t.Fatalf("cut:\n%s\n--\n%s", rules, l.systemctl())
	}
	if strings.Contains(l.log(), "tc filter add") {
		t.Errorf("a cut customer keeps a speed cap:\n%s", l.log())
	}
	// resume needs Pro
	if code, _ := custPost(t, `{"action":"resume","id":1}`); code != 403 {
		t.Errorf("resume without a license: %d", code)
	}
	withPro(t)
	l.reset()
	if code, m := custPost(t, `{"action":"resume","id":1}`); code != 200 {
		t.Fatalf("resume: %d %v", code, m)
	}
	if !strings.Contains(l.systemctl(), "start hsell-1-1.service") {
		t.Errorf("resume did not start the units:\n%s", l.systemctl())
	}

	// a link: add, edit, remove
	if code, m := custPost(t, `{"action":"link-add","id":1,"link":{"name":"fi-1","ports":"2083"}}`); code != 409 || m["error_code"] != "E-CUST-03" {
		t.Errorf("link on the customer's own port: %d %v", code, m)
	}
	if code, m := custPost(t, `{"action":"link-add","id":1,"link":{"name":"fi-1","ports":"2087"}}`); code != 200 {
		t.Fatalf("link-add: %d %v", code, m)
	}
	c1 := custGet(t, 1)
	ctrl3, tok3 := c1.link(3).CtrlPort, c1.link(3).Token
	if code, m := custPost(t, `{"action":"link-update","id":1,"link_id":3,"link":{"name":"fi-1","ports":"2087, 2097"}}`); code != 200 {
		t.Fatalf("link-update: %d %v", code, m)
	}
	c1 = custGet(t, 1)
	if l3 := c1.link(3); l3.CtrlPort != ctrl3 || l3.Token != tok3 || len(l3.Ports) != 2 {
		t.Errorf("an edit keeps the control port and token: %+v", l3)
	}
	l.reset()
	if code, m := custPost(t, `{"action":"link-remove","id":1,"link_id":3}`); code != 200 {
		t.Fatalf("link-remove: %d %v", code, m)
	}
	if _, err := os.Stat(custUnitPath(1, 3)); !os.IsNotExist(err) || !strings.Contains(l.systemctl(), "disable --now hsell-1-3.service") {
		t.Errorf("link-remove left the unit: %v\n%s", err, l.systemctl())
	}

	// remove: everything goes, the chain and caps are dropped
	l.reset()
	if code, m := custPost(t, `{"action":"remove","id":1}`); code != 200 {
		t.Fatalf("remove: %d %v", code, m)
	}
	for _, p := range []string{custUnitPath(1, 1), custConfPath(1, 1, custEngineFRP), custUnitPath(1, 2)} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s survived remove", p)
		}
	}
	for _, want := range []string{"iptables -w 5 -X HASHEM_CUST", "tc filter del dev eth0 egress pref 4919", "tc actions del action police index " + idxOut} {
		if !strings.Contains(l.log(), want) {
			t.Errorf("remove lacks %q:\n%s", want, l.log())
		}
	}
}

func TestCustomersValidation(t *testing.T) {
	newCustLab(t)
	withPro(t)
	writeJSONFile(t, filepath.Join(configDir, "peers.json"), map[string]any{"peers": []peerRecord{{ID: 1, Name: "de-1", FrpPort: 7000, Ports: []int{443}}}})
	for _, c := range []struct {
		body, code, want string
	}{
		{`{"action":"create","name":"","links":[{"ports":"80"}]}`, "E-CUST-02", "name"},
		{`{"action":"create","name":"A","links":[]}`, "E-CUST-02", "at least one foreign server"},
		{`{"action":"create","name":"A","rate_mbit":-1,"links":[{"ports":"80"}]}`, "E-CUST-02", "speed"},
		{`{"action":"create","name":"A","days":5000,"links":[{"ports":"80"}]}`, "E-CUST-02", "days"},
		{`{"action":"create","name":"A","address":"a b","links":[{"ports":"80"}]}`, "E-CUST-02", "address"},
		{`{"action":"create","name":"A","links":[{"ports":""}]}`, "E-CUST-03", "at least one user port"},
		{`{"action":"create","name":"A","links":[{"ports":"80, 70000"}]}`, "E-CUST-03", "not a port"},
		{`{"action":"create","name":"A","links":[{"ports":"80","transport":"wss"}]}`, "E-CUST-03", "transport"},
		{`{"action":"create","name":"A","links":[{"ports":"443"}]}`, "E-CUST-03", "peer de-1"},
		{`{"action":"create","name":"A","links":[{"ports":"2096"}]}`, "E-CUST-03", "the panel"},
		{`{"action":"create","name":"A","links":[{"ports":"80","ctrl_port":7000}]}`, "E-CUST-03", "control port 7000"},
		{`{"action":"create","name":"A","links":[{"ports":"80","ctrl_port":80}]}`, "E-CUST-03", "also a user port"},
		{`{"action":"create","name":"A","links":[{"ports":"80"},{"ports":"80"}]}`, "E-CUST-03", "customer A"},
		{`{"action":"create","name":"A\u0007","links":[{"ports":"80"}]}`, "E-CUST-02", "name"},
		{`{"action":"bogus"}`, "E-CUST-04", ""},
		{`{"action":"renew","id":9,"days":30}`, "E-CUST-04", "no customer 9"},
	} {
		code, m := custPost(t, c.body)
		if m["error_code"] != c.code || !strings.Contains(fmt.Sprint(m["error"]), c.want) {
			t.Errorf("%s: %d %v, want %s %q", c.body, code, m, c.code, c.want)
		}
	}
	custs.Lock()
	n := len(custs.f.Customers)
	custs.Unlock()
	if n != 0 {
		t.Errorf("a refused create left %d customers", n)
	}
	// something outside Hashem holds the port
	custPortBusy = func(proto string, p int) bool { return p == 8080 }
	if code, m := custPost(t, `{"action":"create","name":"A","links":[{"ports":"8080"}]}`); code != 409 || !strings.Contains(fmt.Sprint(m["error"]), "another program") {
		t.Errorf("busy port: %d %v", code, m)
	}
}

func TestCustomersQuotaAndExpiry(t *testing.T) {
	l := newCustLab(t)
	withPro(t)
	if code, m := custPost(t, `{"action":"create","name":"Q","quota_gb":0.01,"days":1,"links":[{"ports":"443"}]}`); code != 200 {
		t.Fatalf("create: %d %v", code, m)
	}
	t0 := time.Now()
	l.save = chainSave(map[string]uint64{"hsell-1-in": 0, "hsell-1-out": 0})
	customersTick(t0)
	l.save = chainSave(map[string]uint64{"hsell-1-in": 1e6, "hsell-1-out": 8.2e6}) // 92% of 10 MB
	customersTick(t0.Add(10 * time.Second))
	if c := custGet(t, 1); c.Cut != "" || !c.Warned {
		t.Fatalf("90%%: %+v", c)
	}
	l.save = chainSave(map[string]uint64{"hsell-1-in": 2e6, "hsell-1-out": 9e6})
	l.reset()
	customersTick(t0.Add(20 * time.Second))
	if c := custGet(t, 1); c.Cut != "quota" {
		t.Fatalf("over quota: %+v", c)
	}
	if !strings.Contains(l.systemctl(), "stop hsell-1-1.service") {
		t.Errorf("quota cut left the unit running:\n%s", l.systemctl())
	}
	// cut: usage stops counting
	l.save = chainSave(map[string]uint64{"hsell-1-in": 9e6, "hsell-1-out": 99e6})
	customersTick(t0.Add(30 * time.Second))
	if c := custGet(t, 1); c.used() != 11e6 {
		t.Errorf("counted while cut: %d", c.used())
	}
	if code, m := custPost(t, `{"action":"resume","id":1}`); code != 409 || !strings.Contains(fmt.Sprint(m["error"]), "volume is used up") {
		t.Errorf("resume over quota: %d %v", code, m)
	}
	// a bigger volume reconnects
	if code, m := custPost(t, `{"action":"update","id":1,"name":"Q","quota_gb":1}`); code != 200 {
		t.Fatalf("update: %d %v", code, m)
	}
	if c := custGet(t, 1); c.Cut != "" || c.Warned {
		t.Errorf("a bigger volume: %+v", c)
	}
	// the plan ends
	l.reset()
	custs.Lock()
	custFindLocked(1).ExpiresAt = time.Now().Unix() - 1
	custs.Unlock()
	customersTick(time.Now())
	if c := custGet(t, 1); c.Cut != "expired" {
		t.Fatalf("expiry: %+v", c)
	}
	if len(l.alerts) < 2 {
		t.Errorf("alerts: %+v", l.alerts)
	}
	if code, m := custPost(t, `{"action":"resume","id":1}`); code != 409 || !strings.Contains(fmt.Sprint(m["error"]), "renew") {
		t.Errorf("resume an ended plan: %d %v", code, m)
	}
	// renew: from now (the plan ended), usage reset by default
	if code, m := custPost(t, `{"action":"renew","id":1,"days":30}`); code != 200 {
		t.Fatalf("renew: %d %v", code, m)
	}
	c := custGet(t, 1)
	if c.Cut != "" || c.used() != 0 || c.ExpiresAt < time.Now().Add(29*24*time.Hour).Unix() {
		t.Errorf("renewed: %+v", c)
	}
	// renewing a running plan extends it from its end
	before := c.ExpiresAt
	if code, _ := custPost(t, `{"action":"renew","id":1,"reset_usage":false}`); code != 200 {
		t.Fatal("second renew")
	}
	if c := custGet(t, 1); c.ExpiresAt != before+30*86400 {
		t.Errorf("renew from the end: %d, want %d", c.ExpiresAt, before+30*86400)
	}
}

func TestCustomersChainFirst(t *testing.T) {
	l := newCustLab(t)
	withPro(t)
	l.failRun = func(cmd string) bool { return strings.HasPrefix(cmd, "iptables-restore") }
	if code, m := custPost(t, `{"action":"create","name":"C","links":[{"ports":"443"}]}`); code != 200 {
		t.Fatalf("create: %d %v", code, m)
	}
	if strings.Contains(l.systemctl(), "start hsell") {
		t.Fatalf("a unit started without its counting chain:\n%s", l.systemctl())
	}
	if v := customersView(); !strings.Contains(fmt.Sprint(v["error"]), "iptables-restore") {
		t.Errorf("the error is not shown: %v", v["error"])
	}
	l.failRun = nil
	customersTick(time.Now())
	if !strings.Contains(l.systemctl(), "start hsell-1-1.service") {
		t.Fatalf("not started once the chain loads:\n%s", l.systemctl())
	}
	// a later reload failure does not stop a running customer
	l.failRun = func(cmd string) bool { return strings.HasPrefix(cmd, "iptables-restore") }
	custApplied.ipt = "" // force a reload
	l.reset()
	customersTick(time.Now())
	if strings.Contains(l.systemctl(), "disable") {
		t.Errorf("a failed reload stopped a running customer:\n%s", l.systemctl())
	}
}

func TestCustomersNoFrps(t *testing.T) {
	l := newCustLab(t)
	withPro(t)
	_ = os.Remove(custFrpsSrc)
	if code, m := custPost(t, `{"action":"create","name":"N","links":[{"ports":"443"}]}`); code != 200 {
		t.Fatalf("create: %d %v", code, m)
	}
	if strings.Contains(l.systemctl(), "start hsell") {
		t.Errorf("started without frps:\n%s", l.systemctl())
	}
	if v := customersView(); !strings.Contains(fmt.Sprint(v["error"]), "frps is not installed") || v["frps_ok"] != false {
		t.Errorf("view: %v %v", v["error"], v["frps_ok"])
	}
}

func TestCustomersKit(t *testing.T) {
	newCustLab(t)
	withPro(t)
	if code, m := custPost(t, `{"action":"create","name":"K","address":"iran.example.com","links":[{"ports":"443, 2083","udp":true,"transport":"websocket","ctrl_port":31000}]}`); code != 200 {
		t.Fatalf("create: %d %v", code, m)
	}
	rr := httptest.NewRecorder()
	handleCustomersKit(rr, httptest.NewRequest("GET", "/api/customers/kit?id=1&link=1", nil))
	var m map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &m)
	kit, _ := m["kit"].(string)
	if rr.Code != 200 || !strings.HasPrefix(kit, "hsk1.") {
		t.Fatalf("kit: %d %v", rr.Code, m)
	}
	body, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(kit, "hsk1."))
	if err != nil {
		t.Fatal(err)
	}
	c := custGet(t, 1)
	for _, want := range []string{"v=1\n", "name=hsell-1-1\n", "server=iran.example.com\n", "port=31000\n", "transport=websocket\n", "token=" + c.Links[0].Token + "\n", "udp=1\n", "ports=443,2083\n"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("kit lacks %q:\n%s", want, body)
		}
	}
	if !strings.Contains(fmt.Sprint(m["oneliner"]), "/releases/download/"+panelVersion+"/hashem-customer.sh") || !strings.Contains(fmt.Sprint(m["oneliner"]), kit) {
		t.Errorf("oneliner: %v", m["oneliner"])
	}
	toml := fmt.Sprint(m["manual"])
	for _, want := range []string{`serverAddr = "iran.example.com"`, "serverPort = 31000", `transport.protocol = "websocket"`, `name = "udp-2083"`, "remotePort = 443"} {
		if !strings.Contains(toml, want) {
			t.Errorf("frpc.toml lacks %q:\n%s", want, toml)
		}
	}
	rr = httptest.NewRecorder()
	handleCustomersKit(rr, httptest.NewRequest("GET", "/api/customers/kit?id=1&link=9", nil))
	if rr.Code != 404 {
		t.Errorf("unknown link: %d", rr.Code)
	}
}

func TestCustomerStatusPage(t *testing.T) {
	newCustLab(t)
	withPro(t)
	if code, m := custPost(t, `{"action":"create","name":"<b>Sara</b>","days":10,"quota_gb":50,"links":[{"ports":"443"}]}`); code != 200 {
		t.Fatalf("create: %d %v", code, m)
	}
	c := custGet(t, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /_hs/{token}", handleCustomerStatus)
	get := func(path string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest("GET", path, nil)
		req.RemoteAddr = "203.0.113.9:5555"
		mux.ServeHTTP(rr, req)
		return rr
	}
	rr := get("/_hs/" + c.Token)
	page := rr.Body.String()
	if rr.Code != 200 || !strings.Contains(page, `\u003cb\u003eSara\u003c/b\u003e`) || strings.Contains(page, "<b>Sara") {
		t.Fatalf("page: %d\n%.400s", rr.Code, page)
	}
	if strings.Contains(page, c.Links[0].Token) || strings.Contains(page, "ctrl_port") || strings.Contains(page, "/*HS_DATA*/null") {
		t.Errorf("the page leaks the link or was not filled")
	}
	if csp := rr.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") || rr.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("headers: %v", rr.Header())
	}
	rr = get("/_hs/" + c.Token + ".json")
	var p custPublic
	if err := json.Unmarshal(rr.Body.Bytes(), &p); err != nil || p.QuotaGB != 50 || p.DaysLeft == nil || *p.DaysLeft != 10 || len(p.Links) != 1 {
		t.Errorf("json: %v %+v", err, p)
	}
	for _, bad := range []string{"/_hs/" + strings.ToUpper(c.Token[:1]) + c.Token[1:] + "x", "/_hs/short", "/_hs/" + strings.Repeat("A", 32)} {
		if rr := get(bad); rr.Code != 404 {
			t.Errorf("%s: %d", bad, rr.Code)
		}
	}
	// guessing is rate limited per address
	for i := 0; i < 70; i++ {
		rr = get("/_hs/" + strings.Repeat("B", 32))
	}
	if rr.Code != 429 {
		t.Errorf("no rate limit: %d", rr.Code)
	}
}

func TestCustomersRules(t *testing.T) {
	list := []customer{
		{ID: 1, Links: []customerLink{{ID: 1, Ports: []int{443}, UDP: true}}},
		{ID: 2, Cut: "quota", Links: []customerLink{{ID: 1, Ports: []int{8443}}}},
	}
	text := custRules(list)
	if !strings.Contains(text, "--dport 8443 -m comment --comment hsell-2-in -j DROP") || strings.Contains(text, "hsell-1-in -j DROP") {
		t.Errorf("rules:\n%s", text)
	}
	m, ready := parseCustSave(`*filter
:HASHEM_CUST - [0:0]
[5:100] -A INPUT -j HASHEM_CUST
[5:100] -A OUTPUT -j HASHEM_CUST
[3:300] -A HASHEM_CUST -p tcp -m tcp --dport 443 -m comment --comment hsell-1-in
[3:200] -A HASHEM_CUST -p udp -m udp --dport 443 -m comment --comment "hsell-1-in"
[3:50] -A HASHEM_CUST -p tcp -m tcp --sport 443 -m comment --comment hsell-1-out
COMMIT
`)
	if !ready || m["hsell-1-in"] != 500 || m["hsell-1-out"] != 50 {
		t.Errorf("parse: %v %v", ready, m)
	}
	if _, ready := parseCustSave("*filter\n:HASHEM_CUST - [0:0]\n[1:1] -A INPUT -j HASHEM_CUST\nCOMMIT\n"); ready {
		t.Error("ready without the OUTPUT hook")
	}
	// no cap: no tc commands; two customers: separate actions
	list[0].RateMbit = 10
	list = append(list, customer{ID: 3, RateMbit: 5, Links: []customerLink{{ID: 1, Ports: []int{80}}, {ID: 2, Ports: []int{81}}}})
	cmds := custTCArgs([]custIfc{{"eth0", []string{"192.0.2.10"}}}, list)
	if got := custTCPolice(cmds); len(got) != 4 || custTCFilters(cmds) != 6 {
		t.Errorf("tc: police %v, %d filters\n%v", got, custTCFilters(cmds), cmds)
	}
	if custPoliceIndex(3, true) == custPoliceIndex(1, false) || custPoliceIndex(1, true) < custPoliceBase {
		t.Error("police indexes overlap")
	}
}

// TestCustomersFrpConfigsLoad checks the generated frps and frpc configs with
// the pinned FRP itself (FRP_BIN_DIR holds frps and frpc v0.71.0).
func TestCustomersFrpConfigsLoad(t *testing.T) {
	bin := os.Getenv("FRP_BIN_DIR")
	if bin == "" {
		t.Skip("set FRP_BIN_DIR to check the configs with the real FRP")
	}
	old := runner
	runner = execRunner
	t.Cleanup(func() { runner = old })
	dir := t.TempDir()
	c := customer{ID: 7, Name: "v", Token: strings.Repeat("a", 32)}
	for i, tr := range []string{"tcp", "kcp", "quic", "websocket"} {
		l := customerLink{ID: i + 1, Engine: "frp", Transport: tr, CtrlPort: 31000 + i, Ports: []int{443, 2083}, UDP: true, Token: strings.Repeat("b", 32)}
		for name, conf := range map[string]string{"frps": custFrpsConf(l), "frpc": custFrpcConf(c, l, "203.0.113.7")} {
			p := filepath.Join(dir, fmt.Sprintf("%s-%s.toml", name, tr))
			if err := os.WriteFile(p, []byte(conf), 0o600); err != nil {
				t.Fatal(err)
			}
			out, err := runCmdTimeoutOut(20*time.Second, filepath.Join(bin, name), "verify", "-c", p)
			if err != nil || !strings.Contains(string(out), "syntax is ok") {
				t.Errorf("%s %s: %v\n%s\n%s", name, tr, err, out, conf)
			}
		}
	}
}

func TestCustomersReviewFixes(t *testing.T) {
	l := newCustLab(t)
	withPro(t)
	if code, m := custPost(t, `{"action":"create","name":"A","links":[{"ports":"443","ctrl_port":31000}]}`); code != 200 {
		t.Fatalf("create: %d %v", code, m)
	}
	// a request's id/link_id cannot let a second customer take a sold port
	if code, m := custPost(t, `{"action":"create","id":1,"link_id":1,"name":"B","links":[{"ports":"443"}]}`); code != 409 {
		t.Errorf("create with id/link_id on a sold port: %d %v", code, m)
	}
	if code, m := custPost(t, `{"action":"link-add","id":1,"link_id":1,"link":{"ports":"443"}}`); code != 409 {
		t.Errorf("link-add repeating a port: %d %v", code, m)
	}
	if code, m := custPost(t, `{"action":"update","id":1,"name":"A","address":"2001:db8::1"}`); code != 400 || !strings.Contains(fmt.Sprint(m["error"]), "IPv4") {
		t.Errorf("an IPv6 address: %d %v", code, m)
	}

	// the frps plugin: tcp on sold ports only, udp only when sold, from loopback
	c := custGet(t, 1)
	conf, _ := os.ReadFile(custConfPath(1, 1, custEngineFRP))
	key := custPluginKey(c.Links[0].Token)
	if !strings.Contains(string(conf), `path = "/_hsplugin/`+key+`"`) || !strings.Contains(string(conf), fmt.Sprintf(`addr = "127.0.0.1:%d"`, cfg.Port)) {
		t.Fatalf("frps config lacks the plugin:\n%s", conf)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /_hsplugin/{key}", handleCustomerPlugin)
	plug := func(remote, k, typ string, port int) (int, map[string]any) {
		body := fmt.Sprintf(`{"version":"0.1.0","op":"NewProxy","content":{"proxy_name":"x","proxy_type":%q,"remote_port":%d}}`, typ, port)
		rr := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/_hsplugin/"+k+"?op=NewProxy", strings.NewReader(body))
		req.RemoteAddr = remote
		mux.ServeHTTP(rr, req)
		var m map[string]any
		_ = json.Unmarshal(rr.Body.Bytes(), &m)
		return rr.Code, m
	}
	for _, x := range []struct {
		typ    string
		port   int
		reject bool
	}{{"tcp", 443, false}, {"tcp", 80, true}, {"udp", 443, true}, {"stcp", 0, true}, {"sudp", 0, true}, {"xtcp", 0, true}, {"http", 0, true}} {
		if code, m := plug("127.0.0.1:5000", key, x.typ, x.port); code != 200 || m["reject"] != x.reject {
			t.Errorf("%s/%d: %d %v, want reject=%v", x.typ, x.port, code, m, x.reject)
		}
	}
	if code, _ := plug("203.0.113.5:5000", key, "tcp", 443); code != 404 {
		t.Errorf("a plugin call from outside: %d", code)
	}
	if code, _ := plug("127.0.0.1:5000", strings.Repeat("0", 32), "tcp", 443); code != 404 {
		t.Errorf("a wrong key: %d", code)
	}

	// a panel restart bills what passed while it was down, nothing twice
	l.save = chainSave(map[string]uint64{"hsell-1-in": 1000, "hsell-1-out": 2000})
	customersTick(time.Now())
	l.save = chainSave(map[string]uint64{"hsell-1-in": 5000, "hsell-1-out": 9000})
	custs.Lock()
	custs.loaded = false // the panel starts again: everything from disk
	custs.Unlock()
	custApplied.ipt, custApplied.running, custApplied.swept = "", nil, false
	l.reset()
	customersTick(time.Now())
	if c := custGet(t, 1); c.UsedRx != 5000 || c.UsedTx != 9000 {
		t.Errorf("after a restart: rx %d tx %d, want 5000 9000", c.UsedRx, c.UsedTx)
	}
	if strings.Contains(l.log(), "iptables-restore") {
		t.Errorf("a restart reloaded an intact chain (its counters would be lost):\n%s", l.log())
	}
	// a flushed chain is noticed and rebuilt
	l.save = strings.Replace(chainSave(nil), "-A HASHEM_CUST -p tcp -m tcp --dport 443", "-A HASHEM_CUST -p tcp -m tcp --dport 444", 1)
	l.reset()
	customersTick(time.Now())
	if !strings.Contains(l.log(), "iptables-restore") {
		t.Errorf("a changed chain was not rebuilt")
	}

	// sold ports are kept out of the ephemeral range, the kernel's list kept
	if r, _ := os.ReadFile(custReserveSysctl); !strings.HasPrefix(string(r), "7000-7002,") || !strings.Contains(string(r), "31000") {
		t.Errorf("reserved ports: %q", r)
	}
	if r, _ := os.ReadFile(custReservedPath()); !strings.Contains(string(r), "\n31000\n") && !strings.HasPrefix(string(r), "31000\n") {
		t.Errorf("ports.reserved: %q", r)
	}

	// a unit no customer has is removed once at start
	stray := filepath.Join(engineUnitDir, "hsell-9-1.service")
	_ = os.WriteFile(stray, []byte("x"), 0o644)
	custApplied.swept = false
	l.reset()
	customersTick(time.Now())
	if _, err := os.Stat(stray); !os.IsNotExist(err) || !strings.Contains(l.systemctl(), "disable --now hsell-9-1.service") {
		t.Errorf("stray unit: %v\n%s", err, l.systemctl())
	}
	if _, err := os.Stat(custUnitPath(1, 1)); err != nil {
		t.Errorf("the sweep removed a real unit: %v", err)
	}
	if u, _ := os.ReadFile(custUnitPath(1, 1)); strings.Contains(string(u), "[Install]") {
		t.Errorf("units must not start at boot before the panel:\n%s", u)
	}

	// a corrupt customers.json changes nothing
	_ = os.WriteFile(customersPath(), []byte("{broken"), 0o600)
	custs.Lock()
	custs.loaded = false
	custs.Unlock()
	l.reset()
	customersTick(time.Now())
	if log := l.log() + l.systemctl(); strings.Contains(log, "-X HASHEM_CUST") || strings.Contains(log, "stop") || strings.Contains(log, "disable") {
		t.Errorf("a corrupt file dropped rules or units:\n%s", log)
	}
	if code, m := custPost(t, `{"action":"cut","id":1}`); code != 500 || m["error_code"] != "E-CUST-06" {
		t.Errorf("a change on a corrupt file: %d %v", code, m)
	}
	if b, _ := os.ReadFile(customersPath()); string(b) != "{broken" {
		t.Errorf("the corrupt file was overwritten: %q", b)
	}
}
