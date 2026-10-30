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
func TestCustomersLab(t *testing.T) {
	frpDirEnv := os.Getenv("CUST_LAB_FRP_DIR")
	if frpDirEnv == "" {
		t.Skip("set CUST_LAB_FRP_DIR (and run tests/test_customers_lab.sh) for the customers lab")
	}
	foNS, usNS := os.Getenv("CUST_LAB_FO_NS"), os.Getenv("CUST_LAB_US_NS")
	hubFo, hubUs := os.Getenv("CUST_LAB_HUB_FO_IP"), os.Getenv("CUST_LAB_HUB_US_IP")
	installer, client := os.Getenv("CUST_LAB_INSTALLER"), os.Getenv("CUST_LAB_CLIENT")
	// CUST_LAB_NO_TC=1: a kernel without tc police (a dev box): no speed parts
	noTC := os.Getenv("CUST_LAB_NO_TC") == "1"
	rate := 20
	if noTC {
		rate = 0
	}
	withPro(t)

	dir := t.TempDir()
	oldDir, oldUnit, oldBin, oldSrc, oldRunner, oldSys, oldPort := configDir, engineUnitDir, custBinDir, custFrpsSrc, runner, runSystemctl, cfg.Port
	configDir, engineUnitDir, custBinDir, custFrpsSrc = dir, filepath.Join(dir, "systemd"), filepath.Join(dir, "sell"), filepath.Join(frpDirEnv, "frps")
	// the panel's own port: frps asks it about every proxy (/_hsplugin)
	plugMux := http.NewServeMux()
	plugMux.HandleFunc("POST /_hsplugin/{key}", handleCustomerPlugin)
	plugLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	plugSrv := &http.Server{Handler: plugMux}
	go func() { _ = plugSrv.Serve(plugLn) }()
	t.Cleanup(func() { _ = plugSrv.Close() })
	cfg.Port = plugLn.Addr().(*net.TCPAddr).Port
	runner = execRunner // the real iptables and tc of this namespace
	_ = os.MkdirAll(engineUnitDir, 0o755)

	// systemd stand-in: a unit is its frps process
	var pmMu sync.Mutex
	procs := map[string]*exec.Cmd{}
	unitRe := regexp.MustCompile(`^hsell-(\d+)-(\d+)\.service$`)
	stop := func(u string) {
		if p := procs[u]; p != nil {
			_ = p.Process.Kill()
			_ = p.Wait()
			delete(procs, u)
		}
	}
	start := func(u string) error {
		m := unitRe.FindStringSubmatch(u)
		if m == nil {
			return fmt.Errorf("unit %s", u)
		}
		cid, _ := strconv.Atoi(m[1])
		lid, _ := strconv.Atoi(m[2])
		cmd := exec.Command(custBin(), "-c", custConfPath(cid, lid))
		logf, _ := os.Create(filepath.Join(dir, u+".log"))
		cmd.Stdout, cmd.Stderr = logf, logf
		if err := cmd.Start(); err != nil {
			return err
		}
		procs[u] = cmd
		return nil
	}
	running := func(u string) bool {
		pmMu.Lock()
		defer pmMu.Unlock()
		return procs[u] != nil
	}
	runSystemctl = func(args ...string) error {
		pmMu.Lock()
		defer pmMu.Unlock()
		switch {
		case len(args) == 2 && args[0] == "start":
			if procs[args[1]] == nil {
				return start(args[1])
			}
		case len(args) == 2 && args[0] == "stop":
			stop(args[1])
		case len(args) == 3 && args[0] == "disable" && args[1] == "--now":
			stop(args[2])
		case len(args) == 2 && args[0] == "restart":
			stop(args[1])
			return start(args[1])
		}
		return nil
	}
	resetCustState()
	var frpc *exec.Cmd
	t.Cleanup(func() {
		if frpc != nil {
			_ = frpc.Process.Kill()
			_ = frpc.Wait()
		}
		pmMu.Lock()
		for u := range procs {
			stop(u)
		}
		pmMu.Unlock()
		custDropChain()
		custTCClear(custIface(), custApplied.police)
		configDir, engineUnitDir, custBinDir, custFrpsSrc, runner, runSystemctl, cfg.Port = oldDir, oldUnit, oldBin, oldSrc, oldRunner, oldSys, oldPort
		resetCustState()
	})

	post := func(body string) map[string]any {
		t.Helper()
		rr := httptest.NewRecorder()
		handleCustomersPost(rr, httptest.NewRequest("POST", "/api/customers", strings.NewReader(body)))
		var m map[string]any
		_ = json.Unmarshal(rr.Body.Bytes(), &m)
		if rr.Code != 200 {
			t.Fatalf("%s: %d %v", body, rr.Code, m)
		}
		return m
	}
	get := func() customer {
		custs.Lock()
		defer custs.Unlock()
		return *custFindLocked(1)
	}

	// 1. a customer: one foreign server, users' port 9000 (TCP and UDP), 20 Mbit/s, 60 MB
	post(fmt.Sprintf(`{"action":"create","name":"lab","days":30,"quota_gb":0.06,"rate_mbit":%d,"address":%q,
		"links":[{"name":"fo","ports":"9000","udp":true,"ctrl_port":7700}]}`, rate, hubFo))
	if !running("hsell-1-1.service") {
		t.Fatalf("the unit did not start: %v", customersView()["error"])
	}
	if n := tcFiltersPresent(custIface(), custTCPref, custTCPref6); !noTC && n != 2 {
		t.Fatalf("tc filters: %d, want 2 (one per direction)", n)
	}

	// 2. the kit, turned into a frpc config by the customer's installer
	rr := httptest.NewRecorder()
	handleCustomersKit(rr, httptest.NewRequest("GET", "/api/customers/kit?id=1&link=1", nil))
	var kit struct {
		Kit string `json:"kit"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &kit)
	conf, err := exec.Command("bash", installer, "config", kit.Kit).CombinedOutput()
	if err != nil {
		t.Fatalf("installer config: %v\n%s", err, conf)
	}
	frpcConf := filepath.Join(dir, "frpc.toml")
	_ = os.WriteFile(frpcConf, conf, 0o600)
	frpc = exec.Command("ip", "netns", "exec", foNS, filepath.Join(frpDirEnv, "frpc"), "-c", frpcConf)
	flog, _ := os.Create(filepath.Join(dir, "frpc.log"))
	frpc.Stdout, frpc.Stderr = flog, flog
	if err := frpc.Start(); err != nil {
		t.Fatal(err)
	}

	// users: client.py in the users' namespace
	var payload int64
	user := func(args ...string) (map[string]float64, error) {
		a := append([]string{"netns", "exec", usNS, "python3", client, hubUs, "9000"}, args...)
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
	xfer := func(up, down int64) map[string]float64 {
		t.Helper()
		m, err := user("tcp", strconv.FormatInt(up, 10), strconv.FormatInt(down, 10))
		if err != nil {
			t.Fatalf("transfer up %d down %d: %v", up, down, err)
		}
		payload += up + down
		return m
	}
	waitUp := func(what string, d time.Duration) {
		t.Helper()
		var err error
		for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(time.Second) {
			if _, err = user("tcp", "0", "1"); err == nil {
				payload++
				return
			}
		}
		fl, _ := os.ReadFile(filepath.Join(dir, "frpc.log"))
		sl, _ := os.ReadFile(filepath.Join(dir, "hsell-1-1.service.log"))
		t.Fatalf("%s: users cannot reach the service: %v\nfrpc:\n%s\nfrps:\n%s", what, err, fl, sl)
	}
	waitUp("first connection", 40*time.Second)

	// the customer's token cannot open proxies that bypass billing: stcp
	// (traffic over the control port) and a port that was not sold
	tok := get().Links[0].Token
	rogue := fmt.Sprintf("serverAddr = %q\nserverPort = 7700\nauth.token = %q\nloginFailExit = false\n"+
		"\n[[proxies]]\nname = \"bypass\"\ntype = \"stcp\"\nsecretKey = \"x\"\nlocalIP = \"127.0.0.1\"\nlocalPort = 9000\n"+
		"\n[[proxies]]\nname = \"extra\"\ntype = \"tcp\"\nlocalIP = \"127.0.0.1\"\nlocalPort = 9000\nremotePort = 9001\n", hubFo, tok)
	rogueConf := filepath.Join(dir, "rogue.toml")
	_ = os.WriteFile(rogueConf, []byte(rogue), 0o600)
	rc := exec.Command("ip", "netns", "exec", foNS, filepath.Join(frpDirEnv, "frpc"), "-c", rogueConf)
	rlog := filepath.Join(dir, "rogue.log")
	rf, _ := os.Create(rlog)
	rc.Stdout, rc.Stderr = rf, rf
	if err := rc.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(6 * time.Second)
	_ = rc.Process.Kill()
	_ = rc.Wait()
	rl, _ := os.ReadFile(rlog)
	if !strings.Contains(string(rl), "only tcp and udp proxies are allowed") {
		t.Errorf("an stcp proxy was not refused:\n%s", rl)
	}
	if !strings.Contains(string(rl), "port 9001 is not part of this tunnel") && !strings.Contains(string(rl), "port not allowed") {
		t.Errorf("a proxy on an unsold port was not refused:\n%s", rl)
	}
	if _, err := user("udp"); err != nil {
		t.Errorf("UDP through the sold tunnel: %v", err)
	}
	payload += 2 * 1200 // the UDP probe: 1200 bytes each way

	// 3. the speed cap, both ways
	m := xfer(0, 12e6)
	t.Logf("capped download: %.1f Mbit/s (cap 20)", m["down_mbit"])
	if !noTC && (m["down_mbit"] > 23 || m["down_mbit"] < 8) {
		t.Errorf("download %.1f Mbit/s under a 20 Mbit/s cap", m["down_mbit"])
	}
	m = xfer(8e6, 0)
	t.Logf("capped upload: %.1f Mbit/s (cap 20)", m["up_mbit"])
	if !noTC && (m["up_mbit"] > 23 || m["up_mbit"] < 8) {
		t.Errorf("upload %.1f Mbit/s under a 20 Mbit/s cap", m["up_mbit"])
	}

	// 4. the volume: users' bytes plus their packet headers, the control port not billed
	customersTick(time.Now())
	c := get()
	t.Logf("billed %d bytes for %d bytes of payload (%.1f%% overhead)", c.used(), payload, float64(c.used()-uint64(payload))/float64(payload)*100)
	if c.used() < uint64(payload) || c.used() > uint64(float64(payload)*1.08)+200000 {
		t.Errorf("billed %d bytes for %d bytes of payload: want payload + headers (and no control traffic)", c.used(), payload)
	}
	if c.UsedTx < 12e6 || c.UsedRx < 8e6 {
		t.Errorf("directions: rx %d (from users) tx %d (to users)", c.UsedRx, c.UsedTx)
	}

	// 5. no cap: faster; then the volume runs out: cut
	post(`{"action":"update","id":1,"name":"lab","quota_gb":0.06,"rate_mbit":0}`)
	if n := tcFiltersPresent(custIface(), custTCPref, custTCPref6); n != 0 {
		t.Errorf("tc filters after the cap was removed: %d", n)
	}
	m = xfer(0, 45e6)
	t.Logf("uncapped download: %.1f Mbit/s", m["down_mbit"])
	customersTick(time.Now())
	if c := get(); c.Cut != "quota" {
		t.Fatalf("over the volume (%d of 60 MB): not cut: %+v", c.used(), c)
	}
	if running("hsell-1-1.service") {
		t.Error("the unit kept running after the cut")
	}
	if _, err := user("tcp", "0", "1"); err == nil {
		t.Error("users still reach a cut customer")
	}

	// 6. reset: back on
	post(`{"action":"reset","id":1}`)
	waitUp("after reset", 60*time.Second)

	// 7. the plan ends
	custs.Lock()
	custFindLocked(1).ExpiresAt = time.Now().Unix() - 1
	custs.Unlock()
	customersTick(time.Now())
	if c := get(); c.Cut != "expired" || running("hsell-1-1.service") {
		t.Fatalf("expiry: %+v running=%v", c, running("hsell-1-1.service"))
	}
	if _, err := user("tcp", "0", "1"); err == nil {
		t.Error("users still reach an expired customer")
	}
	post(`{"action":"renew","id":1,"days":30}`)
	waitUp("after renew", 60*time.Second)

	// 8. remove: nothing left in the kernel
	post(`{"action":"renew","id":1,"days":1}`) // a cap again, so its actions exist before remove
	post(`{"action":"update","id":1,"name":"lab","rate_mbit":5}`)
	police := append([]int(nil), custApplied.police...)
	if !noTC && len(police) != 2 {
		t.Fatalf("police actions: %v", police)
	}
	post(`{"action":"remove","id":1}`)
	if out, err := runCmdTimeoutOut(5*time.Second, "iptables", "-w", "5", "-S", custChain); err == nil {
		t.Errorf("the chain survived remove:\n%s", out)
	}
	if n := tcFiltersPresent(custIface(), custTCPref, custTCPref6); n != 0 {
		t.Errorf("tc filters survived remove: %d", n)
	}
	for _, idx := range police {
		if out, err := runCmdTimeoutOut(5*time.Second, "tc", "actions", "get", "action", "police", "index", strconv.Itoa(idx)); err == nil {
			t.Errorf("police action %d survived remove:\n%s", idx, out)
		}
	}
	if running("hsell-1-1.service") {
		t.Error("the unit survived remove")
	}
}
