package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// TestCustomersLab runs inside tests/test_customers_lab.sh's hub namespace
// with the real iptables, tc, frps and frpc 0.71.0: the panel sells a tunnel
// to a customer whose foreign server (CUST_LAB_FO_NS) runs the frpc config
// tools/hashem-customer.sh makes from the kit; users (CUST_LAB_US_NS) reach
// the customer's service through the hub. It checks the shared speed cap,
// the billed volume against exact bytes (control traffic not billed), the
// cut on volume and on expiry, resume, and that remove leaves nothing.
// custLabRig is the lab's panel side: the real iptables and tc of the hub
// namespace, a systemd stand-in that runs each unit's ExecStart, the frps
// plugin endpoint on a loopback port, and helpers for the users.
type custLabRig struct {
	t                 *testing.T
	dir               string
	foNS, usNS        string
	hubFo, hubUs      string
	installer, client string
	noTC              bool
	mu                sync.Mutex
	procs             map[string]*exec.Cmd
	payload           int64
	foreign           []*exec.Cmd
}

func newCustLabRig(t *testing.T) *custLabRig {
	r := &custLabRig{t: t, dir: t.TempDir(), procs: map[string]*exec.Cmd{},
		foNS: os.Getenv("CUST_LAB_FO_NS"), usNS: os.Getenv("CUST_LAB_US_NS"),
		hubFo: os.Getenv("CUST_LAB_HUB_FO_IP"), hubUs: os.Getenv("CUST_LAB_HUB_US_IP"),
		installer: os.Getenv("CUST_LAB_INSTALLER"), client: os.Getenv("CUST_LAB_CLIENT"),
		// CUST_LAB_NO_TC=1: a kernel without tc police (a dev box): no speed parts
		noTC: os.Getenv("CUST_LAB_NO_TC") == "1"}
	withPro(t)
	dir := r.dir
	oldDir, oldUnit, oldBin, oldRunner, oldSys, oldPort := configDir, engineUnitDir, custBinDir, runner, runSystemctl, cfg.Port
	oldFrps, oldBH, oldXray := custFrpsSrc, custBackhaulSrc, custXraySrc
	configDir, engineUnitDir, custBinDir = dir, filepath.Join(dir, "systemd"), filepath.Join(dir, "sell")
	custFrpsSrc = filepath.Join(os.Getenv("CUST_LAB_FRP_DIR"), "frps")
	custBackhaulSrc, custXraySrc = os.Getenv("CUST_LAB_BACKHAUL"), os.Getenv("CUST_LAB_XRAY")
	// the panel's own port: frps asks it about every proxy (/_hsplugin)
	plugMux := http.NewServeMux()
	plugMux.HandleFunc("POST /_hsplugin/{key}", handleCustomerPlugin)
	plugLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	plugSrv := &http.Server{Handler: plugMux}
	go func() { _ = plugSrv.Serve(plugLn) }()
	cfg.Port = plugLn.Addr().(*net.TCPAddr).Port
	runner = execRunner // the real iptables and tc of this namespace
	_ = os.MkdirAll(engineUnitDir, 0o755)
	runSystemctl = func(args ...string) error {
		r.mu.Lock()
		defer r.mu.Unlock()
		switch {
		case len(args) == 2 && args[0] == "start":
			if r.procs[args[1]] == nil {
				return r.start(args[1])
			}
		case len(args) == 2 && args[0] == "stop":
			r.stop(args[1])
		case len(args) == 3 && args[0] == "disable" && args[1] == "--now":
			r.stop(args[2])
		case len(args) == 2 && args[0] == "restart":
			r.stop(args[1])
			return r.start(args[1])
		}
		return nil
	}
	resetCustState()
	t.Cleanup(func() {
		for _, c := range r.foreign {
			_ = c.Process.Kill()
			_ = c.Wait()
		}
		r.mu.Lock()
		for u := range r.procs {
			r.stop(u)
		}
		r.mu.Unlock()
		_ = plugSrv.Close()
		custDropChain()
		custTCClear(custIfcNames(custIfaces()), custApplied.police)
		configDir, engineUnitDir, custBinDir, runner, runSystemctl, cfg.Port = oldDir, oldUnit, oldBin, oldRunner, oldSys, oldPort
		custFrpsSrc, custBackhaulSrc, custXraySrc = oldFrps, oldBH, oldXray
		resetCustState()
	})
	return r
}

var custLabUnitRe = regexp.MustCompile(`^hsell-(\d+)-(\d+)\.service$`)

// start runs a unit's ExecStart with its Environment (r.mu held).
func (r *custLabRig) start(u string) error {
	if custLabUnitRe.FindStringSubmatch(u) == nil {
		return fmt.Errorf("unit %s", u)
	}
	unit, err := os.ReadFile(filepath.Join(engineUnitDir, u))
	if err != nil {
		return err
	}
	var argv, env []string
	for _, line := range strings.Split(string(unit), "\n") {
		if v, ok := strings.CutPrefix(line, "ExecStart="); ok {
			argv = strings.Fields(v)
		}
		if v, ok := strings.CutPrefix(line, "Environment="); ok {
			env = append(env, v)
		}
	}
	if len(argv) == 0 {
		return fmt.Errorf("unit %s has no ExecStart", u)
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = append(os.Environ(), env...)
	logf, _ := os.Create(filepath.Join(r.dir, u+".log"))
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := cmd.Start(); err != nil {
		return err
	}
	r.procs[u] = cmd
	return nil
}

func (r *custLabRig) stop(u string) {
	if p := r.procs[u]; p != nil {
		_ = p.Process.Kill()
		_ = p.Wait()
		delete(r.procs, u)
	}
}

func (r *custLabRig) running(u string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.procs[u] != nil
}

func (r *custLabRig) post(body string) map[string]any {
	r.t.Helper()
	rr := httptest.NewRecorder()
	handleCustomersPost(rr, httptest.NewRequest("POST", "/api/customers", strings.NewReader(body)))
	var m map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &m)
	if rr.Code != 200 {
		r.t.Fatalf("%s: %d %v", body, rr.Code, m)
	}
	return m
}

func (r *custLabRig) get(id int) customer {
	custs.Lock()
	defer custs.Unlock()
	return *custFindLocked(id)
}

// kit is a link's kit and what the customer's installer makes of it.
func (r *custLabRig) kit(cid, lid int) (kit, conf string) {
	r.t.Helper()
	rr := httptest.NewRecorder()
	handleCustomersKit(rr, httptest.NewRequest("GET", fmt.Sprintf("/api/customers/kit?id=%d&link=%d", cid, lid), nil))
	var k struct {
		Kit string `json:"kit"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &k)
	// the lab has no DNS: the SNI "resolves" to a public-looking address,
	// which the Xray direct test swaps for the lab's site
	stub := filepath.Join(r.dir, "stub")
	_ = os.MkdirAll(stub, 0o755)
	_ = os.WriteFile(filepath.Join(stub, "getent"), []byte("#!/bin/sh\necho \"198.51.100.77     STREAM x\"\n"), 0o755)
	cmd := exec.Command("bash", r.installer, "config", k.Kit)
	cmd.Env = append(os.Environ(), "PATH="+stub+":"+os.Getenv("PATH"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		r.t.Fatalf("installer config %d/%d: %v\n%s", cid, lid, err, out)
	}
	return k.Kit, string(out)
}

// runForeign starts a process in the foreign server's namespace (log: name.log).
func (r *custLabRig) runForeign(name string, argv ...string) *exec.Cmd {
	r.t.Helper()
	cmd := exec.Command("ip", append([]string{"netns", "exec", r.foNS}, argv...)...)
	f, _ := os.Create(filepath.Join(r.dir, name+".log"))
	cmd.Stdout, cmd.Stderr = f, f
	if err := cmd.Start(); err != nil {
		r.t.Fatal(err)
	}
	r.foreign = append(r.foreign, cmd)
	return cmd
}

func (r *custLabRig) logs(names ...string) string {
	var b strings.Builder
	for _, n := range names {
		data, _ := os.ReadFile(filepath.Join(r.dir, n+".log"))
		fmt.Fprintf(&b, "--- %s:\n%s\n", n, data)
	}
	return b.String()
}

// user runs client.py in the users' namespace against the hub's port.
func (r *custLabRig) user(port int, args ...string) (map[string]float64, error) {
	a := append([]string{"netns", "exec", r.usNS, "python3", r.client, r.hubUs, strconv.Itoa(port)}, args...)
	out, err := exec.Command("ip", a...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%v: %s", err, out)
	}
	var m map[string]float64
	if err := json.Unmarshal(out, &m); err != nil {
		return nil, fmt.Errorf("%v: %s", err, out)
	}
	return m, nil
}

// xfer moves up and down bytes through port and counts them as payload.
func (r *custLabRig) xfer(port int, up, down int64) map[string]float64 {
	r.t.Helper()
	m, err := r.user(port, "tcp", strconv.FormatInt(up, 10), strconv.FormatInt(down, 10))
	if err != nil {
		r.t.Fatalf("port %d: transfer up %d down %d: %v", port, up, down, err)
	}
	atomicAdd(&r.mu, &r.payload, up+down)
	return m
}

func atomicAdd(mu *sync.Mutex, p *int64, n int64) {
	mu.Lock()
	*p += n
	mu.Unlock()
}

// waitUp waits until users reach the service on port.
func (r *custLabRig) waitUp(port int, what string, d time.Duration, logs ...string) {
	r.t.Helper()
	var err error
	for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(time.Second) {
		if _, err = r.user(port, "tcp", "0", "1"); err == nil {
			atomicAdd(&r.mu, &r.payload, 1)
			return
		}
	}
	r.t.Fatalf("%s: users cannot reach the service on port %d: %v\n%s", what, port, err, r.logs(logs...))
}

// udpOK sends one UDP datagram through port and back (2 x 1200 bytes billed).
func (r *custLabRig) udpOK(port int) error {
	_, err := r.user(port, "udp")
	if err == nil {
		atomicAdd(&r.mu, &r.payload, 2*1200)
	}
	return err
}

// checkBilled: the customer's volume is the users' bytes plus their packet
// headers, never the control traffic.
func (r *custLabRig) checkBilled(id int, slack int64) {
	r.t.Helper()
	customersTick(time.Now())
	c := r.get(id)
	r.mu.Lock()
	payload := r.payload
	r.mu.Unlock()
	r.t.Logf("billed %d bytes for %d bytes of payload (%.1f%% overhead)", c.used(), payload, float64(int64(c.used())-payload)/float64(payload)*100)
	if c.used() < uint64(payload) || c.used() > uint64(float64(payload)*1.08)+uint64(slack) {
		r.t.Errorf("billed %d bytes for %d bytes of payload: want payload + headers (and no control traffic)", c.used(), payload)
	}
}

// checkClean: remove left nothing in the kernel and no unit running.
func (r *custLabRig) checkClean(police []int, units ...string) {
	r.t.Helper()
	if out, err := runCmdTimeoutOut(5*time.Second, "iptables", "-w", "5", "-S", custChain); err == nil {
		r.t.Errorf("the chain survived remove:\n%s", out)
	}
	if n := labTCFilters(); n != 0 {
		r.t.Errorf("tc filters survived remove: %d", n)
	}
	for _, idx := range police {
		if out, err := runCmdTimeoutOut(5*time.Second, "tc", "actions", "get", "action", "police", "index", strconv.Itoa(idx)); err == nil {
			r.t.Errorf("police action %d survived remove:\n%s", idx, out)
		}
	}
	for _, u := range units {
		if r.running(u) {
			r.t.Errorf("%s survived remove", u)
		}
	}
}

func TestCustomersLab(t *testing.T) {
	frpDirEnv := os.Getenv("CUST_LAB_FRP_DIR")
	if frpDirEnv == "" {
		t.Skip("set CUST_LAB_FRP_DIR (and run tests/test_customers_lab.sh) for the customers lab")
	}
	r := newCustLabRig(t)
	dir, hubFo, noTC := r.dir, r.hubFo, r.noTC
	rate := 20
	if noTC {
		rate = 0
	}
	post, running := r.post, r.running
	get := func() customer { return r.get(1) }

	// 1. a customer: one foreign server, users' port 9000 (TCP and UDP), 20 Mbit/s, 60 MB
	post(fmt.Sprintf(`{"action":"create","name":"lab","days":30,"quota_gb":0.06,"rate_mbit":%d,"address":%q,
		"links":[{"name":"fo","ports":"9000","udp":true,"ctrl_port":7700}]}`, rate, hubFo))
	if !running("hsell-1-1.service") {
		t.Fatalf("the unit did not start: %v", customersView()["error"])
	}
	// two interfaces (users', foreign server's), each: the user port and the control port
	if n := labTCFilters(); !noTC && n != 4 {
		t.Fatalf("tc filters: %d, want 4", n)
	}

	// 2. the kit, turned into a frpc config by the customer's installer
	_, conf := r.kit(1, 1)
	frpcConf := filepath.Join(dir, "frpc.toml")
	_ = os.WriteFile(frpcConf, []byte(conf), 0o600)
	r.runForeign("frpc", filepath.Join(frpDirEnv, "frpc"), "-c", frpcConf)
	logs := []string{"frpc", "hsell-1-1.service"}
	r.waitUp(9000, "first connection", 40*time.Second, logs...)

	// the customer's token cannot open proxies that bypass billing: stcp
	// (traffic over the control port) and a port that was not sold
	tok := get().Links[0].Token
	rogue := fmt.Sprintf("serverAddr = %q\nserverPort = 7700\nauth.token = %q\nloginFailExit = false\n"+
		"\n[[proxies]]\nname = \"bypass\"\ntype = \"stcp\"\nsecretKey = \"x\"\nlocalIP = \"127.0.0.1\"\nlocalPort = 9000\n"+
		"\n[[proxies]]\nname = \"extra\"\ntype = \"tcp\"\nlocalIP = \"127.0.0.1\"\nlocalPort = 9000\nremotePort = 9001\n", hubFo, tok)
	rogueConf := filepath.Join(dir, "rogue.toml")
	_ = os.WriteFile(rogueConf, []byte(rogue), 0o600)
	rc := r.runForeign("rogue", filepath.Join(frpDirEnv, "frpc"), "-c", rogueConf)
	time.Sleep(6 * time.Second)
	_ = rc.Process.Kill()
	_ = rc.Wait()
	rl, _ := os.ReadFile(filepath.Join(dir, "rogue.log"))
	if !strings.Contains(string(rl), "only tcp and udp proxies are allowed") {
		t.Errorf("an stcp proxy was not refused:\n%s", rl)
	}
	if !strings.Contains(string(rl), "port 9001 is not part of this tunnel") && !strings.Contains(string(rl), "port not allowed") {
		t.Errorf("a proxy on an unsold port was not refused:\n%s", rl)
	}
	if err := r.udpOK(9000); err != nil {
		t.Errorf("UDP through the sold tunnel: %v", err)
	}

	// 3. the speed cap, both ways
	m := r.xfer(9000, 0, 12e6)
	t.Logf("capped download: %.1f Mbit/s (cap 20)", m["down_mbit"])
	if !noTC && (m["down_mbit"] > 23 || m["down_mbit"] < 8) {
		t.Errorf("download %.1f Mbit/s under a 20 Mbit/s cap", m["down_mbit"])
	}
	m = r.xfer(9000, 8e6, 0)
	t.Logf("capped upload: %.1f Mbit/s (cap 20)", m["up_mbit"])
	if !noTC && (m["up_mbit"] > 23 || m["up_mbit"] < 8) {
		t.Errorf("upload %.1f Mbit/s under a 20 Mbit/s cap", m["up_mbit"])
	}

	// 4. the volume: users' bytes plus their packet headers, the control port not billed
	r.checkBilled(1, 200000)
	if c := get(); c.UsedTx < 12e6 || c.UsedRx < 8e6 {
		t.Errorf("directions: rx %d (from users) tx %d (to users)", c.UsedRx, c.UsedTx)
	}

	// 5. no cap: faster; then the volume runs out: cut
	post(`{"action":"update","id":1,"name":"lab","quota_gb":0.06,"rate_mbit":0}`)
	if n := labTCFilters(); n != 0 {
		t.Errorf("tc filters after the cap was removed: %d", n)
	}
	m = r.xfer(9000, 0, 45e6)
	t.Logf("uncapped download: %.1f Mbit/s", m["down_mbit"])
	customersTick(time.Now())
	if c := get(); c.Cut != "quota" {
		t.Fatalf("over the volume (%d of 60 MB): not cut: %+v", c.used(), c)
	}
	if running("hsell-1-1.service") {
		t.Error("the unit kept running after the cut")
	}
	if _, err := r.user(9000, "tcp", "0", "1"); err == nil {
		t.Error("users still reach a cut customer")
	}

	// 6. reset: back on
	post(`{"action":"reset","id":1}`)
	r.waitUp(9000, "after reset", 60*time.Second, logs...)

	// 7. the plan ends
	custs.Lock()
	custFindLocked(1).ExpiresAt = time.Now().Unix() - 1
	custs.Unlock()
	customersTick(time.Now())
	if c := get(); c.Cut != "expired" || running("hsell-1-1.service") {
		t.Fatalf("expiry: %+v running=%v", c, running("hsell-1-1.service"))
	}
	if _, err := r.user(9000, "tcp", "0", "1"); err == nil {
		t.Error("users still reach an expired customer")
	}
	post(`{"action":"renew","id":1,"days":30}`)
	r.waitUp(9000, "after renew", 60*time.Second, logs...)

	// 8. remove: nothing left in the kernel
	post(`{"action":"renew","id":1,"days":1}`) // a cap again, so its actions exist before remove
	post(`{"action":"update","id":1,"name":"lab","rate_mbit":5}`)
	police := append([]int(nil), custApplied.police...)
	if !noTC && len(police) != 2 {
		t.Fatalf("police actions: %v", police)
	}
	post(`{"action":"remove","id":1}`)
	r.checkClean(police, "hsell-1-1.service")
}

func labTCFilters() int {
	n := 0
	for _, ifn := range custIfcNames(custIfaces()) {
		if c := tcFiltersPresent(ifn, custTCPref, custTCPref6); c > 0 {
			n += c
		}
	}
	return n
}

// TestCustomersLabEngines sells one customer four foreign-server links on
// the real Backhaul v0.7.2 and Xray-core v26.3.27 (CUST_LAB_BACKHAUL,
// CUST_LAB_XRAY): Backhaul tcp (with UDP) and wssmux, Xray reverse Reality
// (with UDP) and mKCP. The customer's ends run the configs the installer
// makes from the kits. It checks that users reach every link, that one
// speed cap is shared by them all, the billed volume against exact bytes,
// that the Xray user is no proxy into the seller's server, cut and resume,
// and that remove leaves nothing.
func TestCustomersLabEngines(t *testing.T) {
	bh, xr, target := os.Getenv("CUST_LAB_BACKHAUL"), os.Getenv("CUST_LAB_XRAY"), os.Getenv("CUST_LAB_XRAY_TARGET")
	if bh == "" || xr == "" || target == "" {
		t.Skip("set CUST_LAB_BACKHAUL, CUST_LAB_XRAY and CUST_LAB_XRAY_TARGET (tests/test_customers_lab.sh)")
	}
	r := newCustLabRig(t)
	rate := 20
	if r.noTC {
		rate = 0
	}
	r.post(fmt.Sprintf(`{"action":"create","name":"engines","days":30,"rate_mbit":%d,"address":%q,"links":[
		{"name":"bh","engine":"backhaul","transport":"tcp","ports":"9000","udp":true,"ctrl_port":7701},
		{"name":"bhs","engine":"backhaul","transport":"wssmux","ports":"9002","ctrl_port":7702},
		{"name":"xr","engine":"xray","transport":"reality","ports":"9003","udp":true,"ctrl_port":7703,"sni":"lab.hashem.dev"},
		{"name":"xk","engine":"xray","transport":"kcp","ports":"9004","ctrl_port":7704}]}`, rate, r.hubFo))
	// Reality borrows the lab's own TLS site (no internet here)
	custs.Lock()
	custFindLocked(1).Links[2].Xray.Profile.Target = target
	custs.Unlock()
	customersTick(time.Now())
	units := []string{"hsell-1-1.service", "hsell-1-2.service", "hsell-1-3.service", "hsell-1-4.service"}
	for _, u := range units {
		if !r.running(u) {
			t.Fatalf("%s did not start: %v", u, customersView()["error"])
		}
	}
	// two interfaces, each: four user ports and four control ports
	if n := labTCFilters(); !r.noTC && n != 16 {
		t.Fatalf("tc filters: %d, want 16", n)
	}

	// the customer's ends, from the kits. Link 1's Backhaul client runs
	// behind the installer's fence, in a cgroup of its own as under systemd.
	// ip netns exec mounts its own /sys without the cgroup tree: the
	// client's shell mounts cgroup2 itself (one hierarchy for the host)
	fenceCG := ""
	if fs, _ := os.ReadFile("/proc/filesystems"); strings.Contains(string(fs), "cgroup2") {
		fenceCG = filepath.Join(r.dir, "cg")
		_ = os.MkdirAll(fenceCG, 0o755)
		t.Cleanup(func() {
			_ = exec.Command("ip", "netns", "exec", r.foNS, "sh", "-c", "mount -t cgroup2 none "+fenceCG+" && rmdir "+fenceCG+"/hcust-lab; umount "+fenceCG).Run()
		})
	} else {
		t.Log("no cgroup v2 here: the Backhaul fence part is skipped")
	}
	cconf := filepath.Join(r.dir, "cconf")
	_ = os.MkdirAll(cconf, 0o700)
	const fenceUnit = "hcust-lab-1-1"
	// its fence hook stays in the foreign namespace otherwise (another
	// test's processes in the same cgroup path would meet it)
	t.Cleanup(func() {
		_ = exec.Command("ip", "netns", "exec", r.foNS, "env", "HASHEM_CUSTOMER_CONF_DIR="+cconf, "bash", r.installer, "unguard", fenceUnit).Run()
	})
	for lid := 1; lid <= 4; lid++ {
		kit, conf := r.kit(1, lid)
		name := fmt.Sprintf("client-%d", lid)
		if lid == 1 && fenceCG != "" {
			p := filepath.Join(r.dir, name+".toml")
			_ = os.WriteFile(p, []byte(conf), 0o600)
			id, err := exec.Command("bash", r.installer, "idfile", kit).Output()
			if err != nil {
				t.Fatal(err)
			}
			_ = os.WriteFile(filepath.Join(cconf, fenceUnit+".id"), id, 0o600)
			r.runForeign(name, "env", "HASHEM_CUSTOMER_CONF_DIR="+cconf, "bash", "-c",
				`mount -t cgroup2 none `+fenceCG+` && mkdir -p `+fenceCG+`/hcust-lab && echo $$ > `+fenceCG+`/hcust-lab/cgroup.procs && `+
					`bash "$1" guard `+fenceUnit+` && exec "$2" -c "$3"`, "fence", r.installer, bh, p)
			continue
		}
		if lid <= 2 {
			p := filepath.Join(r.dir, name+".toml")
			_ = os.WriteFile(p, []byte(conf), 0o600)
			r.runForeign(name, bh, "-c", p)
		} else {
			p := filepath.Join(r.dir, name+".json")
			_ = os.WriteFile(p, []byte(conf), 0o600)
			r.runForeign(name, "env", "GODEBUG=multipathtcp=0", xr, "run", "-c", p)
		}
	}
	for i, port := range []int{9000, 9002, 9003, 9004} {
		r.waitUp(port, "first connection", 60*time.Second, fmt.Sprintf("client-%d", i+1), units[i])
	}
	for _, port := range []int{9000, 9003} {
		if err := r.udpOK(port); err != nil {
			t.Errorf("UDP through port %d: %v", port, err)
		}
	}

	// one cap for the customer: two links at once share it
	var wg sync.WaitGroup
	t0 := time.Now()
	for _, port := range []int{9000, 9003} {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			r.xfer(port, 0, 8e6)
		}(port)
	}
	wg.Wait()
	both := 16e6 * 8 / 1e6 / time.Since(t0).Seconds()
	t.Logf("Backhaul + Xray downloads at once: %.1f Mbit/s together (cap 20)", both)
	if !r.noTC && (both > 23 || both < 8) {
		t.Errorf("two links together downloaded at %.1f Mbit/s under one 20 Mbit/s cap", both)
	}
	m := r.xfer(9002, 12e6, 0) // large enough that the 500 ms burst does not show
	t.Logf("capped upload over Backhaul wssmux: %.1f Mbit/s (cap 20)", m["up_mbit"])
	if !r.noTC && (m["up_mbit"] > 23 || m["up_mbit"] < 8) {
		t.Errorf("upload %.1f Mbit/s under a 20 Mbit/s cap", m["up_mbit"])
	}
	m = r.xfer(9004, 1e6, 3e6)
	t.Logf("Xray mKCP: down %.1f Mbit/s, up %.1f Mbit/s", m["down_mbit"], m["up_mbit"])
	r.checkBilled(1, 400000)

	// a seller who adds targets to a Backhaul server: the customer's fence
	// lets 127.0.0.1 on the link's own port through and rejects the rest
	if fenceCG != "" {
		bhConf := custConfPath(1, 1, custEngineBackhaul)
		data, _ := os.ReadFile(bhConf)
		evil := strings.Replace(string(data), `"0.0.0.0:9000=127.0.0.1:9000"`,
			`"0.0.0.0:9000=127.0.0.1:9000", "0.0.0.0:9011=127.0.0.1:9000", "0.0.0.0:9010=127.0.0.1:9004"`, 1)
		if evil == string(data) {
			t.Fatalf("cannot find the port line in:\n%s", data)
		}
		_ = os.WriteFile(bhConf, []byte(evil), 0o600)
		_ = runSystemctl("restart", "hsell-1-1.service")
		r.waitUp(9011, "the allowed extra target (control)", 60*time.Second, "client-1", "hsell-1-1.service")
		if _, err := r.user(9010, "tcp", "0", "1"); err == nil {
			t.Errorf("the seller reached 127.0.0.1:9004 on the customer's server past the fence\n%s", r.logs("client-1"))
		}
		customersTick(time.Now()) // the panel writes its own config back
		r.waitUp(9000, "after the panel restored the config", 60*time.Second, "client-1", "hsell-1-1.service")
	}

	// the Xray link's user cannot reach the seller's own services: a VLESS
	// client with its UUID asks for the panel's port on the hub's loopback
	_, conf := r.kit(1, 3)
	var rogue map[string]any
	if err := json.Unmarshal([]byte(conf), &rogue); err != nil {
		t.Fatal(err)
	}
	var tunnel map[string]any
	for _, ob := range rogue["outbounds"].([]any) {
		if o := ob.(map[string]any); o["tag"] == "tunnel" {
			tunnel = o
			// a plain VLESS client: the same user, Vision and all, minus reverse
			delete(o["settings"].(map[string]any), "reverse")
		}
	}
	rogue["outbounds"] = []any{tunnel}
	rogue["inbounds"] = []any{map[string]any{"tag": "in", "listen": "127.0.0.1", "port": 19999, "protocol": "dokodemo-door",
		"settings": map[string]any{"address": "127.0.0.1", "port": cfg.Port, "network": "tcp"}}}
	rogue["routing"] = map[string]any{"rules": []any{map[string]any{"inboundTag": []string{"in"}, "outboundTag": "tunnel"}}}
	rp := filepath.Join(r.dir, "rogue.json")
	data, _ := json.Marshal(rogue)
	_ = os.WriteFile(rp, data, 0o600)
	rc := r.runForeign("rogue", "env", "GODEBUG=multipathtcp=0", xr, "run", "-c", rp)
	time.Sleep(2 * time.Second)
	probe := `import socket,sys
s=socket.create_connection(("127.0.0.1",19999),timeout=5); s.settimeout(5)
s.sendall(b"POST /_hsplugin/x HTTP/1.0\r\nContent-Length: 0\r\n\r\n")
try: d=s.recv(100)
except Exception: d=b""
sys.stdout.write(repr(d))`
	out, _ := exec.Command("ip", "netns", "exec", r.foNS, "python3", "-c", probe).CombinedOutput()
	if strings.Contains(string(out), "HTTP/") {
		t.Errorf("the Xray user reached the seller's panel port through the link: %s", out)
	}
	_ = rc.Process.Kill()
	_ = rc.Wait()
	t.Logf("the Xray user as a forward proxy: %s", out)

	// cut: every link stops; resume: every link comes back
	r.post(`{"action":"cut","id":1}`)
	for _, u := range units {
		if r.running(u) {
			t.Errorf("%s kept running after the cut", u)
		}
	}
	for _, port := range []int{9000, 9003} {
		if _, err := r.user(port, "tcp", "0", "1"); err == nil {
			t.Errorf("users still reach port %d of a cut customer", port)
		}
	}
	r.post(`{"action":"resume","id":1}`)
	for i, port := range []int{9000, 9002, 9003, 9004} {
		r.waitUp(port, "after resume", 90*time.Second, fmt.Sprintf("client-%d", i+1), units[i])
	}

	// remove: nothing left
	police := append([]int(nil), custApplied.police...)
	if !r.noTC && len(police) != 2 {
		t.Fatalf("police actions: %v", police)
	}
	r.post(`{"action":"remove","id":1}`)
	r.checkClean(police, units...)
}

// TestCustomersLabDial sells two links this server dials, on the real
// Xray-core v26.3.27 (direct, Reality) and Bagher (the panel's own SSH
// carrier to a real sshd, frps/frpc 0.71.0): reach, one cap shared by both,
// the billed volume, the host key pinned by the reply code (a wrong code
// does not connect), the customer's sshd lets the link's key do nothing
// but its tunnel port, cut/resume and a clean remove.
func TestCustomersLabDial(t *testing.T) {
	xr, target, foIP := os.Getenv("CUST_LAB_XRAY"), os.Getenv("CUST_LAB_XRAY_TARGET"), os.Getenv("CUST_LAB_FO_IP")
	sshd, panelBin := os.Getenv("CUST_LAB_SSHD"), os.Getenv("CUST_LAB_PANEL_BIN")
	if xr == "" || sshd == "" || panelBin == "" || os.Getenv("CUST_LAB_FRP_DIR") == "" {
		t.Skip("set CUST_LAB_XRAY, CUST_LAB_SSHD, CUST_LAB_PANEL_BIN and CUST_LAB_FRP_DIR (tests/test_customers_lab.sh)")
	}
	r := newCustLabRig(t)
	oldExe := custPanelExe
	custPanelExe = panelBin
	t.Cleanup(func() { custPanelExe = oldExe })
	rate := 20
	if r.noTC {
		rate = 0
	}
	r.post(fmt.Sprintf(`{"action":"create","name":"dial","days":30,"rate_mbit":%d,"address":%q,"links":[
		{"name":"xd","engine":"xray-direct","transport":"reality","ports":"9005","udp":true,"remote":%q,"ctrl_port":7805,"sni":"lab.hashem.dev"},
		{"name":"bg","engine":"bagher","transport":"ssh","ports":"9006","udp":true,"remote":%q,"ctrl_port":7806}]}`, rate, r.hubFo, foIP, foIP))
	units := []string{"hsell-1-1.service", "hsell-1-2.service"}
	if !r.running(units[0]) {
		t.Fatalf("the Xray direct unit did not start: %v", customersView()["error"])
	}
	if r.running(units[1]) {
		t.Fatal("the Bagher unit started before the reply code")
	}

	// Xray direct: the customer's server serves the kit's config (Reality
	// borrowing the lab's own site)
	_, conf := r.kit(1, 1)
	if !strings.Contains(conf, `"target": "198.51.100.77:443"`) {
		t.Fatalf("the installer did not pin the SNI's address:\n%s", conf)
	}
	conf = strings.ReplaceAll(conf, `"198.51.100.77:443"`, strconv.Quote(target))
	xp := filepath.Join(r.dir, "xd.json")
	_ = os.WriteFile(xp, []byte(conf), 0o600)
	r.runForeign("client-1", "env", "GODEBUG=multipathtcp=0", xr, "run", "-c", xp)

	// Bagher: the customer's sshd with the kit's key line and host key
	kit, conf := r.kit(1, 2)
	hk := filepath.Join(r.dir, "hostkeys")
	_ = os.MkdirAll(hk, 0o700)
	keygen := func(dir string) {
		if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", filepath.Join(dir, "ssh_host_ed25519_key")).CombinedOutput(); err != nil {
			t.Fatalf("ssh-keygen: %v %s", err, out)
		}
	}
	keygen(hk)
	auth, err := exec.Command("bash", r.installer, "authline", kit).Output()
	if err != nil {
		t.Fatal(err)
	}
	ak := filepath.Join(r.dir, "authorized_keys")
	_ = os.WriteFile(ak, auth, 0o600)
	// and the installer's Match block for the user (here root)
	rulesCmd := exec.Command("bash", r.installer, "sshdrules")
	rulesCmd.Env = append(os.Environ(), "HASHEM_CUSTOMER_SSH_USER=root", "HASHEM_CUSTOMER_AUTH_KEYS="+ak)
	rules, err := rulesCmd.Output()
	if err != nil || !bytes.Contains(rules, []byte("Match User root")) {
		t.Fatalf("sshd rules: %v %s", err, rules)
	}
	sshdConf := filepath.Join(r.dir, "sshd_config")
	_ = os.WriteFile(sshdConf, []byte(fmt.Sprintf("Port 2222\nListenAddress %s\nHostKey %s\nPidFile none\nUsePAM no\nStrictModes no\nPermitRootLogin prohibit-password\nPasswordAuthentication no\n%s",
		foIP, filepath.Join(hk, "ssh_host_ed25519_key"), rules)), 0o600)
	r.runForeign("sshd", sshd, "-D", "-e", "-f", sshdConf)
	fp := filepath.Join(r.dir, "bg.toml")
	_ = os.WriteFile(fp, []byte(conf), 0o600)
	r.runForeign("client-2", filepath.Join(os.Getenv("CUST_LAB_FRP_DIR"), "frpc"), "-c", fp)
	reply := func(dir string) string {
		cmd := exec.Command("bash", r.installer, "reply", kit)
		cmd.Env = append(os.Environ(), "HASHEM_SSH_DIR="+dir, "HASHEM_SSH_PORT=2222", "HASHEM_CUSTOMER_SSH_USER=root")
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("reply code: %v", err)
		}
		return strings.TrimSpace(string(out))
	}
	good := reply(hk)

	// a reply code with another host key: the carrier refuses the server
	other := filepath.Join(r.dir, "otherkeys")
	_ = os.MkdirAll(other, 0o700)
	keygen(other)
	r.post(fmt.Sprintf(`{"action":"link-reply","id":1,"link_id":2,"reply":%q}`, reply(other)))
	time.Sleep(8 * time.Second)
	if _, err := r.user(9006, "tcp", "0", "1"); err == nil {
		t.Errorf("Bagher connected to a server whose host key is not the reply code's\n%s", r.logs(units[1]))
	}
	if l, _ := os.ReadFile(filepath.Join(r.dir, units[1]+".log")); !strings.Contains(string(l), "knownhosts: key mismatch") {
		t.Errorf("the relay did not refuse the wrong host key (no knownhosts: key mismatch):\n%s", l)
	}
	r.post(fmt.Sprintf(`{"action":"link-reply","id":1,"link_id":2,"reply":%q}`, good))
	r.waitUp(9005, "Xray direct", 60*time.Second, "client-1", units[0])
	r.waitUp(9006, "Bagher", 60*time.Second, "client-2", "sshd", units[1])
	for _, port := range []int{9005, 9006} {
		if err := r.udpOK(port); err != nil {
			t.Errorf("UDP through port %d: %v", port, err)
		}
	}
	// two interfaces, each: two user ports and two foreign endpoints
	if n := labTCFilters(); !r.noTC && n != 8 {
		t.Errorf("tc filters: %d, want 8", n)
	}

	// one cap for both links
	var wg sync.WaitGroup
	t0 := time.Now()
	for _, port := range []int{9005, 9006} {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			r.xfer(port, 0, 8e6)
		}(port)
	}
	wg.Wait()
	both := 16e6 * 8 / 1e6 / time.Since(t0).Seconds()
	t.Logf("Xray direct + Bagher downloads at once: %.1f Mbit/s together (cap 20)", both)
	if !r.noTC && (both > 23 || both < 8) {
		t.Errorf("two dialing links together downloaded at %.1f Mbit/s under one 20 Mbit/s cap", both)
	}
	m := r.xfer(9006, 12e6, 0)
	t.Logf("capped upload over Bagher: %.1f Mbit/s (cap 20)", m["up_mbit"])
	if !r.noTC && (m["up_mbit"] > 23 || m["up_mbit"] < 8) {
		t.Errorf("upload %.1f Mbit/s under a 20 Mbit/s cap", m["up_mbit"])
	}
	r.checkBilled(1, 300000)

	// the customer's side: the link's key opens nothing but its own port
	signer, err := ssh.ParsePrivateKey([]byte(r.get(1).Links[1].SSHKey))
	if err != nil {
		t.Fatal(err)
	}
	cl, err := ssh.Dial("tcp", net.JoinHostPort(foIP, "2222"), &ssh.ClientConfig{User: "root", Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("ssh to the customer's server with the link's key: %v", err)
	}
	if c, err := cl.Dial("tcp", "127.0.0.1:9000"); err == nil {
		_ = c.Close()
		t.Error("the link's key reached another service on the customer's server (permitopen)")
	}
	if c, err := cl.Dial("tcp", "127.0.0.1:7806"); err == nil {
		_ = c.Close()
		t.Error("the link's key forwarded to its own port (sshd allows remote forwarding only)")
	}
	sock := filepath.Join(r.dir, "svc.sock")
	if sl, err := net.Listen("unix", sock); err == nil {
		defer sl.Close()
		if c, err := cl.Dial("unix", sock); err == nil {
			_ = c.Close()
			t.Error("the link's key reached a Unix socket on the customer's server")
		}
	}
	if ln, err := cl.ListenUnix(filepath.Join(r.dir, "seller.sock")); err == nil {
		_ = ln.Close()
		t.Error("the link's key made a Unix socket on the customer's server")
	}
	if ln, err := cl.Listen("tcp", "127.0.0.1:9999"); err == nil {
		_ = ln.Close()
		t.Error("the link's key listened on another port of the customer's server (permitlisten)")
	}
	if s, err := cl.NewSession(); err == nil {
		out, _ := s.CombinedOutput("id")
		if strings.Contains(string(out), "uid=") {
			t.Errorf("the link's key ran a command on the customer's server: %s", out)
		}
		_ = s.Close()
	}
	_ = cl.Close()

	// cut and resume
	r.post(`{"action":"cut","id":1}`)
	for _, u := range units {
		if r.running(u) {
			t.Errorf("%s kept running after the cut", u)
		}
	}
	for _, port := range []int{9005, 9006} {
		if _, err := r.user(port, "tcp", "0", "1"); err == nil {
			t.Errorf("users still reach port %d of a cut customer", port)
		}
	}
	r.post(`{"action":"resume","id":1}`)
	r.waitUp(9005, "Xray direct after resume", 60*time.Second, "client-1", units[0])
	r.waitUp(9006, "Bagher after resume", 90*time.Second, "client-2", "sshd", units[1])

	police := append([]int(nil), custApplied.police...)
	r.post(`{"action":"remove","id":1}`)
	r.checkClean(police, units...)
}

// TestCustomersLabGRE sells an FRP link inside GRE (P4) between the hub's
// and the foreign server's public addresses (CUST_LAB_HUB_GRE_IP,
// CUST_LAB_FO_GRE_IP): the panel makes the hub's end, the installer's
// gre-up the foreign end, and frpc dials the inner address. It checks that
// users reach the service, the link runs inside GRE, the cap and the billed
// volume, that over GRE each end takes nothing but the tunnel (no other
// port, no IPv6, nothing forwarded), a second GRE to the same server is
// refused, and that remove leaves no interface or rule on either end.
func TestCustomersLabGRE(t *testing.T) {
	frpDir, hubPub, foPub := os.Getenv("CUST_LAB_FRP_DIR"), os.Getenv("CUST_LAB_HUB_GRE_IP"), os.Getenv("CUST_LAB_FO_GRE_IP")
	if frpDir == "" || hubPub == "" || foPub == "" {
		t.Skip("run tests/test_customers_lab.sh for the GRE lab")
	}
	if out, err := exec.Command("ip", "link", "add", "hcgprobe", "type", "gre", "remote", "192.0.2.99").CombinedOutput(); err != nil {
		t.Skipf("this kernel makes no GRE interface: %v %s", err, out)
	}
	_ = exec.Command("ip", "link", "del", "hcgprobe").Run()
	// public-looking addresses on the hub-foreign wire (a GRE link needs public ends)
	hubIf, foIf0, foNS := os.Getenv("CUST_LAB_HUB_FO_IF"), os.Getenv("CUST_LAB_FO_IF"), os.Getenv("CUST_LAB_FO_NS")
	for _, c := range [][]string{{"addr", "add", hubPub + "/24", "dev", hubIf}, {"-n", foNS, "addr", "add", foPub + "/24", "dev", foIf0}} {
		if out, err := exec.Command("ip", c...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v %s", c, err, out)
		}
	}
	t.Cleanup(func() {
		_ = exec.Command("ip", "addr", "del", hubPub+"/24", "dev", hubIf).Run()
		_ = exec.Command("ip", "-n", foNS, "addr", "del", foPub+"/24", "dev", foIf0).Run()
	})
	r := newCustLabRig(t)
	rate := 20
	if r.noTC {
		rate = 0
	}
	r.post(fmt.Sprintf(`{"action":"create","name":"gre","days":30,"rate_mbit":%d,"address":%q,
		"links":[{"name":"fo","ports":"9005","ctrl_port":7710,"gre":true,"remote":%q}]}`, rate, hubPub, foPub))
	l := r.get(1).Links[0]
	hubIn, foIn := l.greAddrs()
	if hubIn == "" || !r.running("hsell-1-1.service") {
		t.Fatalf("GRE link: %+v %v", l, customersView()["error"])
	}
	if out, err := runCmdTimeoutOut(5*time.Second, "ip", "-d", "-o", "addr", "show", "dev", "hcg1x1"); err != nil || !strings.Contains(string(out), hubIn+"/30") {
		t.Fatalf("the hub's GRE: %v %s", err, out)
	}
	if v, _ := os.ReadFile("/proc/sys/net/ipv6/conf/hcg1x1/disable_ipv6"); strings.TrimSpace(string(v)) != "1" {
		t.Errorf("IPv6 is on on the hub's GRE: %q", v)
	}
	// a second GRE link to the same foreign server is refused
	rr := httptest.NewRecorder()
	handleCustomersPost(rr, httptest.NewRequest("POST", "/api/customers",
		strings.NewReader(fmt.Sprintf(`{"action":"link-add","id":1,"link":{"name":"x","ports":"9006","gre":true,"remote":%q}}`, foPub))))
	if rr.Code == 200 || len(r.get(1).Links) != 1 {
		t.Errorf("a second GRE to %s: %d %s", foPub, rr.Code, rr.Body.String())
	}

	// the foreign end: the installer's id file and gre-up, then frpc on the kit's config
	kit, conf := r.kit(1, 1)
	if !strings.Contains(conf, `serverAddr = "`+hubIn+`"`) {
		t.Fatalf("the kit's frpc does not dial the inner address:\n%s", conf)
	}
	cconf := filepath.Join(r.dir, "gconf")
	_ = os.MkdirAll(cconf, 0o700)
	const unit = "hcust-lab-g-1"
	id, err := exec.Command("bash", r.installer, "idfile", kit).Output()
	if err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(cconf, unit+".id"), id, 0o600)
	foIf := fmt.Sprintf("hcc%x", sha256.Sum256([]byte(unit)))[:11]
	inFo := func(args ...string) ([]byte, error) {
		return exec.Command("ip", append([]string{"netns", "exec", r.foNS, "env", "HASHEM_CUSTOMER_CONF_DIR=" + cconf}, args...)...).CombinedOutput()
	}
	if out, err := inFo("bash", r.installer, "gre-up", unit); err != nil {
		t.Fatalf("gre-up: %v\n%s", err, out)
	}
	t.Cleanup(func() { _, _ = inFo("bash", r.installer, "gre-down", unit) })
	// the minute check reads the real kernel's rules as gre-up made them
	if out, err := inFo("bash", r.installer, "gre-check", unit); err != nil {
		t.Errorf("gre-check right after gre-up: %v\n%s", err, out)
	}
	if out, err := inFo("cat", "/proc/sys/net/ipv6/conf/"+foIf+"/disable_ipv6"); err != nil || strings.TrimSpace(string(out)) != "1" {
		t.Errorf("IPv6 on the foreign GRE: %v %s", err, out)
	}
	p := filepath.Join(r.dir, "gfrpc.toml")
	_ = os.WriteFile(p, []byte(conf), 0o600)
	r.runForeign("gfrpc", filepath.Join(frpDir, "frpc"), "-c", p)
	r.waitUp(9005, "over GRE", 40*time.Second, "gfrpc", "hsell-1-1.service")
	if out, _ := runCmdTimeoutOut(5*time.Second, "ss", "-Htn", "state", "established", "( sport = :7710 )"); !strings.Contains(string(out), " "+foIn+":") && !strings.Contains(string(out), "[::ffff:"+foIn+"]:") {
		t.Errorf("the link does not run inside GRE (no session from %s):\n%s", foIn, out)
	}

	// the cap and the volume, as on the public path
	m := r.xfer(9005, 0, 12e6)
	t.Logf("capped download over GRE: %.1f Mbit/s (cap 20)", m["down_mbit"])
	if !r.noTC && (m["down_mbit"] > 23 || m["down_mbit"] < 8) {
		t.Errorf("download %.1f Mbit/s under a 20 Mbit/s cap", m["down_mbit"])
	}
	m = r.xfer(9005, 8e6, 0)
	t.Logf("capped upload over GRE: %.1f Mbit/s (cap 20)", m["up_mbit"])
	if !r.noTC && (m["up_mbit"] > 23 || m["up_mbit"] < 8) {
		t.Errorf("upload %.1f Mbit/s under a 20 Mbit/s cap", m["up_mbit"])
	}
	r.checkBilled(1, 200000)

	// over GRE the hub takes the control port only: a service on every
	// address answers on the public address, not the inner one
	ln, err := net.Listen("tcp", "0.0.0.0:7807")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	reach := func(host string, port int) bool {
		_, err := inFo("timeout", "3", "bash", "-c", fmt.Sprintf("exec 3<>/dev/tcp/%s/%d", host, port))
		return err == nil
	}
	if !reach(hubPub, 7807) {
		t.Error("control: the hub's service is not reachable on its public address")
	}
	if reach(hubIn, 7807) {
		t.Error("the foreign server reaches another port of the hub over GRE")
	}
	// the foreign end takes nothing new over GRE either
	r.runForeign("glisten", "python3", "-c", "import socket,time\ns=socket.socket();s.setsockopt(1,2,1);s.bind(('0.0.0.0',7808));s.listen(8);time.sleep(900)")
	time.Sleep(time.Second)
	dial := func(addr string) bool {
		c, err := net.DialTimeout("tcp", addr, 3*time.Second)
		if err == nil {
			_ = c.Close()
		}
		return err == nil
	}
	if !dial(net.JoinHostPort(foPub, "7808")) {
		t.Error("control: the foreign service is not reachable on its public address")
	}
	if dial(net.JoinHostPort(foIn, "7808")) {
		t.Error("the hub reaches a port of the foreign server over GRE")
	}
	// nor from the tunnel's own port: a SYN from hubIn:7710 (made by hand:
	// frps holds the port) passes the stateless raw fence but is no reply,
	// so the stateful stage drops it
	mangled := func() int64 {
		out, _ := inFo("iptables", "-w", "5", "-t", "mangle", "-L", "PREROUTING", "-v", "-n", "-x")
		for _, l := range strings.Split(string(out), "\n") {
			if f := strings.Fields(l); len(f) > 6 && f[2] == "DROP" && f[5] == foIf {
				n, _ := strconv.ParseInt(f[0], 10, 64)
				return n
			}
		}
		t.Fatalf("no stateful GRE drop on the foreign end:\n%s", out)
		return 0
	}
	syn := `import socket,struct,sys
s,d,sp,dp=sys.argv[1],sys.argv[2],int(sys.argv[3]),int(sys.argv[4])
def ck(b):
    if len(b)%2: b+=b"\\0"
    t=sum(struct.unpack("!%dH"%(len(b)//2),b)); t=(t>>16)+(t&0xffff); t+=t>>16
    return (~t)&0xffff
tcp=struct.pack("!HHIIBBHHH",sp,dp,1,0,5<<4,2,65535,0,0)
ph=socket.inet_aton(s)+socket.inet_aton(d)+struct.pack("!BBH",0,6,len(tcp))
tcp=tcp[:16]+struct.pack("!H",ck(ph+tcp))+tcp[18:]
r=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_TCP)
for _ in range(3): r.sendto(tcp,(d,0))
`
	m0 := mangled()
	if out, err := exec.Command("python3", "-c", syn, hubIn, foIn, "7710", "7808").CombinedOutput(); err != nil {
		t.Fatalf("raw SYN: %v %s", err, out)
	}
	time.Sleep(500 * time.Millisecond)
	if m1 := mangled(); m1 < m0+3 {
		t.Errorf("a SYN from the control port to a foreign service was not dropped by the stateful stage: %d -> %d", m0, m1)
	}
	// nothing is forwarded from GRE: the foreign server routes the users'
	// network into the tunnel, with forwarding on in the hub
	fwd, _ := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	_ = os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0o644)
	defer func() { _ = os.WriteFile("/proc/sys/net/ipv4/ip_forward", fwd, 0o644) }()
	if out, err := inFo("ip", "route", "add", "10.24.0.2/32", "dev", foIf); err != nil {
		t.Fatalf("route: %v %s", err, out)
	}
	// the fence's last rule (DROP) counts what came in over GRE and was
	// not the tunnel
	dropped := func() int64 {
		out, _ := runCmdTimeoutOut(5*time.Second, "iptables", "-w", "5", "-t", "raw", "-L", custGREChain, "-v", "-n", "-x")
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		f := strings.Fields(lines[len(lines)-1])
		if len(f) < 3 || f[2] != "DROP" {
			t.Fatalf("the fence does not end in DROP:\n%s", out)
		}
		n, _ := strconv.ParseInt(f[0], 10, 64)
		return n
	}
	before := dropped()
	if _, err := inFo("ping", "-c", "3", "-W", "1", "10.24.0.2"); err == nil {
		t.Error("the foreign server reached the users' network through the hub over GRE")
	}
	if after := dropped(); after < before+3 {
		t.Errorf("the pings to the users' network were not dropped at the fence: %d -> %d", before, after)
	}
	if _, err := runCmdTimeoutOut(5*time.Second, "iptables", "-w", "5", "-C", custGREFwd, "-o", custGREWild, "-j", "DROP"); err != nil {
		t.Error("nothing keeps the hub from forwarding into GRE")
	}
	_, _ = inFo("ip", "route", "del", "10.24.0.2/32", "dev", foIf)

	// steady state against the real kernel: the minute check finds the
	// fence and the interface as made (iptables -S prints the rules as the
	// panel wrote them): nothing is loaded or made again
	oldRun := custRun
	var ran []string
	var ranMu sync.Mutex
	custRun = func(name string, args ...string) ([]byte, error) {
		ranMu.Lock()
		ran = append(ran, name+" "+strings.Join(args, " "))
		ranMu.Unlock()
		return oldRun(name, args...)
	}
	custApplied.greCheck = time.Time{}
	customersTick(time.Now())
	custRun = oldRun
	if j := strings.Join(ran, "\n"); strings.Contains(j, "customers-gre.v4") || strings.Contains(j, "ip link add") || !strings.Contains(j, "-S "+custGREChain) {
		t.Errorf("the minute check changed a GRE that was as made:\n%s", j)
	}

	// Backhaul inside GRE, under the installer's fence (the tunnel's own GRE
	// packets pass it; nothing else does)
	if bh := os.Getenv("CUST_LAB_BACKHAUL"); bh != "" {
		if fs, _ := os.ReadFile("/proc/filesystems"); strings.Contains(string(fs), "cgroup2") {
			r.post(fmt.Sprintf(`{"action":"link-update","id":1,"link_id":1,"link":{"name":"fo","engine":"backhaul","transport":"tcp","ports":"9005","ctrl_port":7711,"gre":true,"remote":%q}}`, foPub))
			kit, conf := r.kit(1, 1)
			if !strings.Contains(conf, `remote_addr = "`+hubIn+`:7711"`) {
				t.Fatalf("the Backhaul kit does not dial the inner address:\n%s", conf)
			}
			id, err := exec.Command("bash", r.installer, "idfile", kit).Output()
			if err != nil {
				t.Fatal(err)
			}
			_ = os.WriteFile(filepath.Join(cconf, unit+".id"), id, 0o600)
			if out, err := inFo("bash", r.installer, "gre-up", unit); err != nil {
				t.Fatalf("gre-up (Backhaul): %v\n%s", err, out)
			}
			if out, err := inFo("bash", r.installer, "gre-check", unit); err != nil {
				t.Errorf("gre-check (Backhaul): %v\n%s", err, out)
			}
			cg := filepath.Join(r.dir, "gcg")
			_ = os.MkdirAll(cg, 0o755)
			t.Cleanup(func() {
				_ = exec.Command("ip", "netns", "exec", r.foNS, "sh", "-c", "mount -t cgroup2 none "+cg+" && rmdir "+cg+"/hcust-lab-gre; umount "+cg).Run()
			})
			bp := filepath.Join(r.dir, "gbh.toml")
			_ = os.WriteFile(bp, []byte(conf), 0o600)
			r.runForeign("gbh", "env", "HASHEM_CUSTOMER_CONF_DIR="+cconf, "bash", "-c",
				`mount -t cgroup2 none `+cg+` && mkdir -p `+cg+`/hcust-lab-gre && echo $$ > `+cg+`/hcust-lab-gre/cgroup.procs && `+
					`bash "$1" guard `+unit+` && exec "$2" -c "$3"`, "fence", r.installer, bh, bp)
			t.Cleanup(func() { _, _ = inFo("bash", r.installer, "unguard", unit) })
			var upErr error
			for end := time.Now().Add(60 * time.Second); time.Now().Before(end); time.Sleep(time.Second) {
				if _, upErr = r.user(9005, "tcp", "0", "1"); upErr == nil {
					atomicAdd(&r.mu, &r.payload, 1)
					break
				}
			}
			if upErr != nil {
				ss, _ := exec.Command("ss", "-Htlnp").CombinedOutput()
				unitF, _ := os.ReadFile(filepath.Join(engineUnitDir, "hsell-1-1.service"))
				fwAll, _ := inFo("iptables-save", "-c")
				var fwl []string
				for _, l := range strings.Split(string(fwAll), "\n") {
					if strings.Contains(l, " HC") || strings.Contains(l, "OUTPUT") {
						fwl = append(fwl, l)
					}
				}
				fw := strings.Join(fwl, "\n")
				idf, _ := os.ReadFile(filepath.Join(cconf, unit+".id"))
				t.Logf("Backhaul over GRE id file:\n%s", strings.ReplaceAll(string(idf), "token=", "token-len="))
				t.Fatalf("Backhaul over GRE, fenced: users cannot reach port 9005: %v\nforeign fence:\n%s\npanel: %v\nhub listens:\n%s\nunit:\n%s",
					upErr, fw, customersView()["error"], ss, unitF)
			}
			r.xfer(9005, 2e6, 2e6)
			r.checkBilled(1, 300000)
		} else {
			t.Log("no cgroup v2 here: the Backhaul over GRE part is skipped")
		}
	}

	// remove: no interface or rule left on either end
	r.post(`{"action":"remove","id":1}`)
	r.checkClean(nil, "hsell-1-1.service")
	if _, err := runCmdTimeoutOut(5*time.Second, "ip", "link", "show", "hcg1x1"); err == nil {
		t.Error("the hub's GRE survived remove")
	}
	for _, ch := range []string{custGREChain, custGREFwd} {
		if out, err := runCmdTimeoutOut(5*time.Second, "iptables", "-w", "5", "-S", ch); err == nil {
			t.Errorf("%s survived remove:\n%s", ch, out)
		}
	}
	if out, err := inFo("bash", r.installer, "gre-down", unit); err != nil {
		t.Errorf("gre-down: %v %s", err, out)
	}
	if _, err := inFo("ip", "link", "show", foIf); err == nil {
		t.Error("the foreign GRE survived gre-down")
	}
	if out, _ := inFo("iptables", "-w", "5", "-S"); strings.Contains(string(out), foIf) {
		t.Errorf("foreign GRE rules survived gre-down:\n%s", out)
	}
}
