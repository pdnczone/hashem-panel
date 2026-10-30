package main

import (
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
	out, err := exec.Command("bash", r.installer, "config", k.Kit).CombinedOutput()
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
