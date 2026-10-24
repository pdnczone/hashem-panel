package main

// Lab tests of the cluster on a real kernel. They need root, iptables and a
// network namespace of their own; tests/test_cluster_lab.sh runs them (CI's
// lab job does, with the pinned FRP and Backhaul releases):
//   - TestLBLab: the kernel rules alone. Backends listen on private addresses
//     of the hashem-lb dummy interface; connections to this host's own
//     address must reach them the way the pools, the stickiness and the
//     pass-through ports say (HASHEM_LB_LAB=1).
//   - TestLBLabForward: a pool forwarded to another Iran hub (HASHEM_LB_LAB=1).
//   - TestLBLabE2E: everything at once on real relays (HASHEM_LB_E2E=1).

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func labServe(t *testing.T, addr string) {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("listen %s: %v", addr, err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			fmt.Fprintf(c, "%s\n", addr)
			c.Close()
		}
	}()
}

func labAsk(t *testing.T, addr string) string {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return "refused"
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	line, _ := bufio.NewReader(c).ReadString('\n')
	return strings.TrimSpace(line)
}

func labHostIP(t *testing.T) string {
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if ip, ok := a.(*net.IPNet); ok && ip.IP.To4() != nil && !ip.IP.IsLoopback() && !strings.HasPrefix(ip.IP.String(), "169.254.") {
			return ip.IP.String()
		}
	}
	t.Skip("no IPv4 address")
	return ""
}

func TestLBLab(t *testing.T) {
	if os.Getenv("HASHEM_LB_LAB") != "1" {
		t.Skip("lab test: set HASHEM_LB_LAB=1 (root, iptables, own network namespace)")
	}
	configDir, lbUnitDir = t.TempDir(), t.TempDir()
	old := runner
	runner = execRunner // TestMain stubs host commands; this test is about them
	defer func() { runner = old }()
	a2, a3 := "169.254.77.2", "169.254.77.3"
	if err := lbEnsureAddrs([]string{a2, a3}); err != nil {
		t.Fatal(err)
	}
	defer lbEnsureAddrs(nil)
	labServe(t, a2+":18080")
	labServe(t, a3+":18080")
	labServe(t, a3+":18443")
	labServe(t, a2+":19000")
	labServe(t, a2+":19001")
	host := labHostIP(t)

	two := []lbTarget{{Link: 1, Addr: a2, Port: 18080, Weight: 1}, {Link: 2, Addr: a3, Port: 18080, Weight: 1}}
	plan := lbPlan{
		Pools: []lbPoolPlan{
			{Port: 18080, Proto: "both", Mode: lbBalance, Targets: two},
			{Port: 18081, Proto: "tcp", Mode: lbSticky, Targets: two},
			{Port: 18082, Proto: "tcp", Mode: lbFailover, Targets: []lbTarget{{Link: 2, Addr: a3, Port: 18443, Weight: 1}}},
		},
		Pass: []lbPortRange{{Proto: "tcp", From: 19000, To: 19001, Addr: a2, Link: 1}},
	}
	text := lbRulesText(plan)
	if err := lbApplyRules(text, nil); err != nil {
		t.Fatalf("apply: %v\n%s", err, text)
	}
	defer lbClearRules(lbChainsIn(text))

	// balance: both members get connections
	hits := map[string]int{}
	for i := 0; i < 200; i++ {
		hits[labAsk(t, host+":18080")]++
	}
	if hits[a2+":18080"] < 50 || hits[a3+":18080"] < 50 {
		t.Fatalf("balance spread: %v", hits)
	}
	// sticky: one source address always lands on the same member
	sticky := map[string]int{}
	for i := 0; i < 50; i++ {
		sticky[labAsk(t, host+":18081")]++
	}
	if len(sticky) != 1 || sticky["refused"] > 0 {
		t.Fatalf("sticky moved a user: %v", sticky)
	}
	// failover target with its own port, and pass-through ports of a bound relay
	if got := labAsk(t, host+":18082"); got != a3+":18443" {
		t.Fatalf("failover: %s", got)
	}
	if got := labAsk(t, host+":19001"); got != a2+":19001" {
		t.Fatalf("pass-through: %s", got)
	}
	// the relays' private addresses still answer locally
	if got := labAsk(t, a2+":18080"); got != a2+":18080" {
		t.Fatalf("local to private address: %s", got)
	}
	// re-applying a changed plan swaps atomically; a removed pool's chain goes
	plan.Pools = plan.Pools[:1]
	plan.Pools[0].Targets = two[1:]
	text2 := lbRulesText(plan)
	if err := lbApplyRules(text2, lbChainsIn(text)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		if got := labAsk(t, host+":18080"); got != a3+":18080" {
			t.Fatalf("after the swap: %s", got)
		}
	}
	if out, _ := runCmdTimeout(5*time.Second, "iptables", "-t", "nat", "-S"); strings.Contains(string(out), "HLB-T18081") {
		t.Fatal("the removed pool's chain is still there")
	}
	// clearing removes every hook: the port is closed again
	lbClearRules(lbChainsIn(text2))
	if got := labAsk(t, host+":18080"); got != "refused" {
		t.Fatalf("after clear: %s", got)
	}
	if out, _ := runCmdTimeout(5*time.Second, "iptables", "-t", "nat", "-S"); strings.Contains(string(out), "HASHEM-LB") {
		t.Fatalf("leftovers:\n%s", out)
	}
}

// TestLBLabServe is not a test: TestLBLabForward runs the test binary inside
// a network namespace with HASHEM_LB_LAB_SERVE=addr to stand in for the
// other Iran hub.
func TestLBLabServe(t *testing.T) {
	addr := os.Getenv("HASHEM_LB_LAB_SERVE")
	if addr == "" {
		t.Skip("helper")
	}
	label := os.Getenv("HASHEM_LB_LAB_NAME")
	if label == "" {
		label = "far"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		fmt.Fprintf(c, "%s %s\n", label, c.RemoteAddr().(*net.TCPAddr).IP)
		c.Close()
	}
}

// A pool with no working member is forwarded to another hub: a client in its
// own namespace connects to this host, the hub "far" (another namespace)
// answers, with FORWARD dropped by default as ufw sets it.
func TestLBLabForward(t *testing.T) {
	if os.Getenv("HASHEM_LB_LAB") != "1" {
		t.Skip("lab test: set HASHEM_LB_LAB=1")
	}
	configDir, lbUnitDir = t.TempDir(), t.TempDir()
	old := runner
	runner = execRunner
	defer func() { runner = old }()
	sh := func(a ...string) {
		if out, err := runCmdTimeout(10*time.Second, a[0], a[1:]...); err != nil {
			t.Fatalf("%v: %s", a, out)
		}
	}
	for _, ns := range []string{"far", "client"} {
		_, _ = runCmdTimeout(5*time.Second, "ip", "netns", "del", ns)
		sh("ip", "netns", "add", ns)
		defer runCmdTimeout(5*time.Second, "ip", "netns", "del", ns)
	}
	sh("ip", "link", "add", "vfar", "type", "veth", "peer", "name", "vfar0", "netns", "far")
	sh("ip", "addr", "add", "10.99.0.1/24", "dev", "vfar")
	sh("ip", "link", "set", "vfar", "up")
	sh("ip", "netns", "exec", "far", "ip", "addr", "add", "10.99.0.2/24", "dev", "vfar0")
	sh("ip", "netns", "exec", "far", "ip", "link", "set", "vfar0", "up")
	sh("ip", "link", "add", "vcli", "type", "veth", "peer", "name", "vcli0", "netns", "client")
	sh("ip", "addr", "add", "10.98.0.1/24", "dev", "vcli")
	sh("ip", "link", "set", "vcli", "up")
	sh("ip", "netns", "exec", "client", "ip", "addr", "add", "10.98.0.2/24", "dev", "vcli0")
	sh("ip", "netns", "exec", "client", "ip", "link", "set", "vcli0", "up")
	sh("ip", "netns", "exec", "client", "ip", "route", "add", "default", "via", "10.98.0.1")
	sh("iptables", "-P", "FORWARD", "DROP")
	defer runCmdTimeout(5*time.Second, "iptables", "-P", "FORWARD", "ACCEPT")

	exe, _ := os.Executable()
	srv := exec.Command("ip", "netns", "exec", "far", exe, "-test.run", "^TestLBLabServe$")
	srv.Env = append(os.Environ(), "HASHEM_LB_LAB_SERVE=10.99.0.2:18090")
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Process.Kill()
	time.Sleep(500 * time.Millisecond)

	ask := func() string {
		out, _ := runCmdTimeout(5*time.Second, "ip", "netns", "exec", "client", "bash", "-c",
			"exec 3<>/dev/tcp/10.98.0.1/18090 && head -1 <&3")
		return strings.TrimSpace(string(out))
	}
	if got := ask(); strings.HasPrefix(got, "far") {
		t.Fatalf("answered before forwarding: %s", got)
	}
	text := lbRulesText(lbPlan{Forward: []lbForward{{Port: 18090, Proto: "tcp", To: "10.99.0.2"}}})
	if err := lbApplyRules(text, nil); err != nil {
		t.Fatalf("%v\n%s", err, text)
	}
	defer lbClearRules(nil)
	// the far hub sees this hub (MASQUERADE), so its answer comes back here
	if got := ask(); got != "far 10.99.0.1" {
		t.Fatalf("forward: %q", got)
	}
	lbClearRules(nil)
	if got := ask(); strings.HasPrefix(got, "far") {
		t.Fatalf("still forwarded after clear: %s", got)
	}
}

// labForeign is one foreign server of the end-to-end lab: a namespace with a
// small service on 127.0.0.1:8080 and the tunnel client in front of it.
type labForeign struct {
	ns, net, name string
	link, ctrl    int
	svc, addr     string
	backhaul      bool
	service       *exec.Cmd
	client        *exec.Cmd
}

// TestLBLabE2E is the cluster on real relays. tests/test_cluster_lab.sh runs
// it inside a network namespace of its own (the Iran hub): real frps (two
// foreign servers) and a real Backhaul server (a third one), whose clients run
// in namespaces of their own in front of a small service, and a user in one
// more namespace. clusterTick runs with every host seam real (sockets, ping,
// service check, private addresses, iptables) except the link list and the
// relay binding: the relays here start already bound to their addresses.
func TestLBLabE2E(t *testing.T) {
	if os.Getenv("HASHEM_LB_E2E") != "1" {
		t.Skip("lab test: run tests/test_cluster_lab.sh")
	}
	frpDir, bhBin := os.Getenv("FRP_DIR"), os.Getenv("BACKHAUL_BIN")
	configDir, lbUnitDir = t.TempDir(), t.TempDir()
	tmp := t.TempDir()
	oldRunner, oldProc := runner, procNetRoot
	runner, procNetRoot = execRunner, "/proc/net"
	saved := []any{lbSnapshot, lbBind, lbIsBound, lbHubForward}
	defer func() {
		runner, procNetRoot = oldRunner, oldProc
		lbSnapshot = saved[0].(func() *HubSnapshot)
		lbBind = saved[1].(func(string, string) (bool, error))
		lbIsBound = saved[2].(func(string, string) bool)
		lbHubForward = saved[3].(func(ClusterConfig, LBPool) string)
		resetClusterState()
	}()
	resetClusterState()
	sh := func(a ...string) {
		t.Helper()
		if out, err := runCmdTimeout(10*time.Second, a[0], a[1:]...); err != nil {
			t.Fatalf("%v: %s", a, out)
		}
	}
	exe, _ := os.Executable()
	start := func(name string, env []string, args ...string) *exec.Cmd {
		t.Helper()
		log, _ := os.Create(filepath.Join(tmp, name+".log"))
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Env = append(os.Environ(), env...)
		cmd.Stdout, cmd.Stderr = log, log
		if err := cmd.Start(); err != nil {
			t.Fatalf("start %s: %v", name, err)
		}
		t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
		return cmd
	}
	stop := func(c *exec.Cmd) { _ = c.Process.Kill(); _ = c.Wait() }
	write := func(name, text string) string {
		p := filepath.Join(tmp, name)
		if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	fs := []*labForeign{
		{ns: "hlb-de", net: "10.91.0", name: "de", link: 1, ctrl: 17001, svc: "frps-1", addr: "169.254.77.2"},
		{ns: "hlb-nl", net: "10.92.0", name: "nl", link: 2, ctrl: 17011, svc: "frps-2", addr: "169.254.77.3"},
	}
	if bhBin != "" {
		fs = append(fs, &labForeign{ns: "hlb-bh", net: "10.93.0", name: "bh", link: 3, ctrl: 17021, svc: "backhaul-server-3", addr: "169.254.77.4", backhaul: true})
	}
	type nsNet struct{ ns, net string }
	nets := []nsNet{{"hlb-user", "10.98.0"}}
	for _, f := range fs {
		nets = append(nets, nsNet{f.ns, f.net})
	}
	for i, n := range nets {
		_, _ = runCmdTimeout(5*time.Second, "ip", "netns", "del", n.ns)
		sh("ip", "netns", "add", n.ns)
		ns := n.ns
		t.Cleanup(func() { _, _ = runCmdTimeout(5*time.Second, "ip", "netns", "del", ns) })
		v := fmt.Sprintf("vhlb%d", i)
		sh("ip", "link", "add", v, "type", "veth", "peer", "name", v+"p", "netns", n.ns)
		sh("ip", "addr", "add", n.net+".1/24", "dev", v)
		sh("ip", "link", "set", v, "up")
		sh("ip", "netns", "exec", n.ns, "ip", "addr", "add", n.net+".2/24", "dev", v+"p")
		sh("ip", "netns", "exec", n.ns, "ip", "link", "set", v+"p", "up")
		sh("ip", "netns", "exec", n.ns, "ip", "link", "set", "lo", "up")
		sh("ip", "netns", "exec", n.ns, "ip", "route", "add", "default", "via", n.net+".1")
	}
	var addrs []string
	for _, f := range fs {
		addrs = append(addrs, f.addr)
	}
	if err := lbEnsureAddrs(addrs); err != nil {
		t.Fatal(err)
	}
	defer lbEnsureAddrs(nil)

	startService := func(f *labForeign) {
		f.service = start(f.name+"-svc", []string{"HASHEM_LB_LAB_SERVE=127.0.0.1:8080", "HASHEM_LB_LAB_NAME=" + f.name},
			"ip", "netns", "exec", f.ns, exe, "-test.run", "^TestLBLabServe$")
	}
	startClient := func(f *labForeign) {
		if f.backhaul {
			conf := write(f.name+"-client.toml", fmt.Sprintf("[client]\nremote_addr = \"%s.1:%d\"\ntransport = \"tcpmux\"\ntoken = \"lab\"\nretry_interval = 1\ndial_timeout = 5\n", f.net, f.ctrl))
			f.client = start(f.name+"-client", nil, "ip", "netns", "exec", f.ns, bhBin, "-c", conf)
			return
		}
		conf := write(f.name+"-frpc.toml", fmt.Sprintf("serverAddr = \"%s.1\"\nserverPort = %d\nauth.token = \"lab\"\nloginFailExit = false\n\n"+
			"[[proxies]]\nname = \"svc443\"\ntype = \"tcp\"\nlocalIP = \"127.0.0.1\"\nlocalPort = 8080\nremotePort = 443\n", f.net, f.ctrl))
		f.client = start(f.name+"-frpc", nil, "ip", "netns", "exec", f.ns, filepath.Join(frpDir, "frpc"), "-c", conf)
	}
	for _, f := range fs {
		if f.backhaul {
			conf := write(f.name+"-server.toml", fmt.Sprintf("[server]\nbind_addr = \"0.0.0.0:%d\"\ntransport = \"tcpmux\"\ntoken = \"lab\"\nheartbeat = 5\nports = [\"%s:443=127.0.0.1:8080\"]\n", f.ctrl, f.addr))
			start(f.name+"-server", nil, bhBin, "-c", conf)
		} else {
			conf := write(f.svc+".toml", fmt.Sprintf("bindAddr = \"0.0.0.0\"\nbindPort = %d\nproxyBindAddr = \"%s\"\nauth.token = \"lab\"\n", f.ctrl, f.addr))
			start(f.svc, nil, filepath.Join(frpDir, "frps"), "-c", conf)
		}
		startService(f)
	}
	time.Sleep(time.Second)
	for _, f := range fs {
		startClient(f)
	}

	lbSnapshot = func() *HubSnapshot {
		s := &HubSnapshot{At: time.Now()}
		for _, f := range fs {
			s.Peers = append(s.Peers, peerLive{peerRecord: peerRecord{ID: f.link, Name: f.name, RemotePub: f.net + ".2",
				FrpPort: f.ctrl, FrpsSvc: f.svc, Ports: []int{443}}, HealthState: stateHealthy})
		}
		return s
	}
	lbBind = func(string, string) (bool, error) { return false, nil }
	lbIsBound = func(string, string) bool { return true }
	lbHubForward = func(ClusterConfig, LBPool) string { return "" }

	logs := func() string {
		var b strings.Builder
		ents, _ := os.ReadDir(tmp)
		for _, e := range ents {
			if strings.HasSuffix(e.Name(), ".log") {
				data, _ := os.ReadFile(filepath.Join(tmp, e.Name()))
				if len(data) > 1500 {
					data = data[len(data)-1500:]
				}
				fmt.Fprintf(&b, "--- %s\n%s\n", e.Name(), data)
			}
		}
		b.WriteString("--- rules\n" + clusterRT.rules)
		fmt.Fprintf(&b, "--- events\n%v\n", clusterEvents(30))
		return b.String()
	}
	// until ticks the cluster every 250 ms until ok() holds.
	until := func(what string, limit time.Duration, ok func() bool) time.Duration {
		t.Helper()
		t0 := time.Now()
		for time.Since(t0) < limit {
			clusterTick(time.Now())
			if ok() {
				return time.Since(t0)
			}
			time.Sleep(250 * time.Millisecond)
		}
		t.Fatalf("%s: not within %s\n%s", what, limit, logs())
		return 0
	}
	targets := func() map[int]bool {
		clusterRT.mu.Lock()
		defer clusterRT.mu.Unlock()
		out := map[int]bool{}
		for _, x := range clusterRT.plans["tcp/443"].Targets {
			out[x.Link] = true
		}
		return out
	}
	hits := func(n int) map[string]int {
		out := map[string]int{}
		for i := 0; i < n; i++ {
			got, _ := runCmdTimeout(5*time.Second, "ip", "netns", "exec", "hlb-user", "bash", "-c",
				"exec 3<>/dev/tcp/10.98.0.1/443 && timeout 3 head -1 <&3")
			f := strings.Fields(string(got))
			if len(f) == 0 {
				out["refused"]++
				continue
			}
			out[f[0]]++
		}
		return out
	}

	var members []LBMember
	for _, f := range fs {
		members = append(members, LBMember{Link: f.link, Weight: 1, Priority: f.link})
	}
	if err := saveClusterConfig(ClusterConfig{Version: 2, NodeID: "lab", Health: LBHealth{IntervalMs: 1000, Fall: 2, Rise: 2},
		Pools: []LBPool{{Port: 443, Proto: "tcp", Mode: lbBalance, Check: "tcp", CheckEvery: 1, Members: members}}}); err != nil {
		t.Fatal(err)
	}

	// 1. every relay listens and passes, traffic is spread over all of them
	until("every foreign server serves the pool", 40*time.Second, func() bool { return len(targets()) == len(fs) })
	h := hits(12 * len(fs))
	for _, f := range fs {
		if h[f.name] < 3 {
			t.Fatalf("balance: %v\n%s", h, logs())
		}
	}
	t.Logf("balance over %d foreign servers: %v", len(fs), h)

	// 2. the service on each foreign server stops while its tunnel stays up:
	// only the service check sees it
	for _, f := range fs {
		stop(f.service)
		d := until(f.name+"'s dead service taken out", 20*time.Second, func() bool { return !targets()[f.link] })
		t.Logf("%s (%s): service stopped, out of the pool after %s", f.name, map[bool]string{true: "Backhaul", false: "FRP"}[f.backhaul], d.Round(100*time.Millisecond))
		if h := hits(10); h[f.name] > 0 || h["refused"] > 0 {
			t.Fatalf("traffic after %s's service died: %v\n%s", f.name, h, logs())
		}
		startService(f)
		d = until(f.name+"'s service back", 20*time.Second, func() bool { return targets()[f.link] })
		t.Logf("%s: service back, in the pool again after %s", f.name, d.Round(100*time.Millisecond))
	}

	// 3. a tunnel dies (the foreign client is killed): its relay stops
	// listening on the port and its control session goes
	nl := fs[1]
	stop(nl.client)
	d := until("dead tunnel taken out", 20*time.Second, func() bool { return !targets()[nl.link] })
	t.Logf("nl: tunnel killed, out of the pool after %s", d.Round(100*time.Millisecond))
	if h := hits(10); h["nl"] > 0 || h["refused"] > 0 {
		t.Fatalf("traffic after nl's tunnel died: %v\n%s", h, logs())
	}
	startClient(nl)
	d = until("tunnel back", 40*time.Second, func() bool { return targets()[nl.link] })
	t.Logf("nl: tunnel back, in the pool again after %s", d.Round(100*time.Millisecond))

	// 4. failover with a standby member and sticky users
	c := loadClusterConfig()
	c.Pools[0].Mode = lbFailover
	c.Pools[0].Members[0].Backup = true // de is standby: nl (priority 2) is first
	_ = saveClusterConfig(c)
	until("failover to the first primary", 10*time.Second, func() bool { tg := targets(); return len(tg) == 1 && tg[2] })
	if h := hits(8); h["nl"] != 8 {
		t.Fatalf("failover: %v", h)
	}
	c.Pools[0].Mode = lbSticky
	_ = saveClusterConfig(c)
	until("sticky", 10*time.Second, func() bool { return len(targets()) == len(fs)-1 })
	if h := hits(15); len(h) != 1 || h["refused"] > 0 {
		t.Fatalf("sticky moved a user: %v", h)
	}

	// 5. no pool left: the rules go
	c.Pools = nil
	_ = saveClusterConfig(c)
	clusterTick(time.Now())
	clusterTick(time.Now())
	if out, _ := runCmdTimeout(5*time.Second, "iptables", "-t", "nat", "-S"); strings.Contains(string(out), "HLB-T443") {
		t.Fatalf("pool rules left:\n%s", out)
	}
	lbClearRules(lbChainsIn(clusterRT.rules))
}
