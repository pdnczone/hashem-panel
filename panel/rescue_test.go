package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestParsePortList(t *testing.T) {
	ok := map[string][]int{
		"1020, 1030 1040": {1020, 1030, 1040},
		"2000-2003":       {2000, 2001, 2002, 2003},
		"443,443,80":      {80, 443},
		"1;2\n3":          {1, 2, 3},
	}
	for in, want := range ok {
		got, err := parsePortList(in)
		if err != nil || len(got) != len(want) {
			t.Fatalf("%q => %v, %v want %v", in, got, err, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("%q => %v want %v", in, got, want)
			}
		}
	}
	for _, bad := range []string{"", "  ", "0", "65536", "abc", "10-5", "1-100", "1,2,x", "-5", "80-"} {
		if _, err := parsePortList(bad); err == nil {
			t.Fatalf("%q must be rejected", bad)
		}
	}
	var big []string
	for i := 1; i <= 70; i++ {
		big = append(big, strconv.Itoa(2000+i))
	}
	if _, err := parsePortList(strings.Join(big, ",")); err == nil {
		t.Fatal("more than 64 ports must be rejected")
	}
}

func TestValidRemoteIP(t *testing.T) {
	for _, in := range []string{"203.0.113.102", " 198.51.100.22 "} {
		if _, err := validRemoteIP(in); err != nil {
			t.Fatalf("%q should pass: %v", in, err)
		}
	}
	for _, in := range []string{"", "127.0.0.1", "0.0.0.0", "224.0.0.1", "169.254.1.1", "::1", "2001:db8::1", "example.com", "1.2.3", "1.2.3.4; rm -rf /", "1.2.3.4\nfoo"} {
		if _, err := validRemoteIP(in); err == nil {
			t.Fatalf("%q must be rejected", in)
		}
	}
}

func TestRescueVerdict(t *testing.T) {
	cases := []struct {
		ping  bool
		ports map[int]string
		want  string
	}{
		{true, map[int]string{7777: "open"}, "ok"},
		{false, map[int]string{7777: "timeout", 22: "open"}, "ok"},
		{true, map[int]string{7777: "timeout", 22: "timeout"}, "one_way_block"},
		{false, map[int]string{7777: "timeout"}, "host_unreachable"},
		{true, map[int]string{7777: "refused"}, "service_down"},
		{false, map[int]string{7777: "refused", 22: "timeout"}, "service_down"},
		{true, map[int]string{}, "unknown"},
	}
	for i, c := range cases {
		if got := rescueVerdict(c.ping, c.ports); got != c.want {
			t.Fatalf("case %d: got %s want %s", i, got, c.want)
		}
	}
}

func TestClassifyDial(t *testing.T) {
	if classifyDial(nil) != "open" {
		t.Fatal("nil => open")
	}
	if classifyDial(&net.OpError{Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}) != "refused" {
		t.Fatal("ECONNREFUSED => refused")
	}
	if classifyDial(errors.New("i/o timeout")) != "timeout" {
		t.Fatal("other => timeout")
	}
}

func goodCode(t *testing.T) (rescueState, string) {
	t.Helper()
	st := rescueState{CtrlPort: 31000, Token: randHex(24), Secret: randHex(16), Ports: []int{1020, 1030, 1040}}
	return st, rescueEncode(st, "198.51.100.22")
}

func TestRescueCodeRoundTripAndHostile(t *testing.T) {
	st, code := goodCode(t)
	c, err := rescueDecode(code)
	if err != nil || c.IP != "198.51.100.22" || c.CPort != 31000 || c.Token != st.Token || len(c.Ports) != 3 {
		t.Fatalf("round trip failed: %+v %v", c, err)
	}
	bad := []string{
		"", "hrc1_", "hrc1_!!!", "nope", strings.Repeat("A", 5000),
		rescueEncode(rescueState{CtrlPort: 0, Token: st.Token, Secret: st.Secret, Ports: []int{1}}, "198.51.100.22"),
		rescueEncode(rescueState{CtrlPort: 99999, Token: st.Token, Secret: st.Secret, Ports: []int{1}}, "198.51.100.22"),
		rescueEncode(rescueState{CtrlPort: 5, Token: "short", Secret: st.Secret, Ports: []int{1}}, "198.51.100.22"),
		rescueEncode(rescueState{CtrlPort: 5, Token: st.Token, Secret: st.Secret, Ports: []int{1}}, "127.0.0.1"),
		rescueEncode(rescueState{CtrlPort: 5, Token: st.Token, Secret: st.Secret, Ports: []int{70000}}, "198.51.100.22"),
		rescueEncode(rescueState{CtrlPort: 5, Token: st.Token, Secret: st.Secret, Ports: nil}, "198.51.100.22"),
		// config injection through the token must never reach a TOML file
		rescueEncode(rescueState{CtrlPort: 5, Token: "aa\"\nbindPort = 22\n#xx", Secret: st.Secret, Ports: []int{1}}, "198.51.100.22"),
	}
	for i, b := range bad {
		if _, err := rescueDecode(b); err == nil {
			t.Fatalf("hostile code %d must be rejected", i)
		}
	}
}

func TestRenderedFilesAreWellFormed(t *testing.T) {
	frps := rescueFrpsToml(31000, "tok")
	for _, w := range []string{"bindPort = 31000", `auth.token = "tok"`} {
		if !strings.Contains(frps, w) {
			t.Fatalf("frps missing %q:\n%s", w, frps)
		}
	}
	o := rescueOriginFrpcToml(31000, "tok", "sec", []int{1020, 1030})
	if strings.Count(o, "[[proxies]]") != 4 || !strings.Contains(o, `type = "sudp"`) || !strings.Contains(o, `localIP = "127.0.0.1"`) {
		t.Fatalf("origin frpc wrong:\n%s", o)
	}
	e := rescueEntryFrpcToml("198.51.100.22", 31000, "tok", "sec", []int{1020})
	if strings.Count(e, "[[visitors]]") != 2 || !strings.Contains(e, `serverAddr = "198.51.100.22"`) || !strings.Contains(e, "bindPort = 1020") {
		t.Fatalf("entry frpc wrong:\n%s", e)
	}
	fw := rescueFwNft(31000, "203.0.113.102")
	if !strings.Contains(fw, "tcp dport 31000 ip saddr != 203.0.113.102") || !strings.Contains(fw, `iifname "lo" accept`) {
		t.Fatalf("firewall wrong:\n%s", fw)
	}
	dn := rescueDnatNft("198.51.100.22", []int{1020, 1030})
	if !strings.Contains(dn, "fib daddr type local meta l4proto { tcp, udp } th dport { 1020, 1030 } dnat ip to 198.51.100.22") || !strings.Contains(dn, "ip daddr 198.51.100.22 meta l4proto { tcp, udp } th dport { 1020, 1030 } masquerade") {
		t.Fatalf("dnat wrong:\n%s", dn)
	}
}

// fakeSystem swaps runCmd/ dirs so enable/disable runs for real on disk
// without touching systemd.
func fakeSystem(t *testing.T) (*[]string, string) {
	t.Helper()
	dir := t.TempDir()
	oldDir, oldUnit, oldBin, oldRun, oldCfg := configDir, rescueUnitDir, rescueBinDir, runCmd, cfg
	configDir = filepath.Join(dir, "cfg")
	rescueUnitDir = filepath.Join(dir, "units")
	rescueBinDir = filepath.Join(dir, "bin")
	_ = os.MkdirAll(rescueUnitDir, 0755)
	_ = os.MkdirAll(rescueBinDir, 0755)
	for _, b := range []string{"frps", "frpc"} {
		_ = os.WriteFile(filepath.Join(rescueBinDir, b), []byte("#!/bin/sh\n"), 0755)
	}
	cfg = panelConfig{Port: 7777, TLSPort: 7443}
	var mu sync.Mutex
	var calls []string
	runCmd = func(name string, args ...string) (string, error) {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, name+" "+strings.Join(args, " "))
		return "", nil
	}
	// Default: the origin is unreachable from here, so every port is relayed.
	oldFrp := rescueFrpConfigs
	rescueFrpConfigs = []string{filepath.Join(dir, "frpc.toml")}
	// High, free port: CI runs unprivileged and cannot bind below 1024.
	fp := pickFreePort(43000)
	_ = os.WriteFile(rescueFrpConfigs[0], []byte(fmt.Sprintf("[[proxies]]\nlocalPort = %d\nremotePort = %d\n", fp, fp)), 0600)
	t.Cleanup(func() { rescueFrpConfigs = oldFrp })
	oldDial := rescueDial
	rescueDial = func(string, time.Duration) (net.Conn, error) { return nil, os.ErrDeadlineExceeded }
	t.Cleanup(func() {
		configDir, rescueUnitDir, rescueBinDir, runCmd, cfg, rescueDial = oldDir, oldUnit, oldBin, oldRun, oldCfg, oldDial
	})
	return &calls, dir
}

func TestEnableOriginThenDisableLeavesNothing(t *testing.T) {
	calls, dir := fakeSystem(t)
	st, err := rescueEnableOrigin("203.0.113.102", []int{1020, 1030, 1040})
	if err != nil {
		t.Fatal(err)
	}
	if st.Role != "origin" || st.CtrlPort < 20000 || len(st.Token) != 48 {
		t.Fatalf("bad state %+v", st)
	}
	for _, f := range []string{"frps.toml", "frpc.toml", "fw.nft"} {
		fi, err := os.Stat(filepath.Join(configDir, "rescue", f))
		if err != nil {
			t.Fatalf("%s missing: %v", f, err)
		}
		if fi.Mode().Perm() != 0600 {
			t.Fatalf("%s has mode %v, want 0600 (contains secrets)", f, fi.Mode().Perm())
		}
	}
	for _, u := range []string{"hashem-rescue-fw", "hashem-rescue-frps", "hashem-rescue-frpc"} {
		if _, err := os.Stat(filepath.Join(rescueUnitDir, u+".service")); err != nil {
			t.Fatalf("unit %s missing", u)
		}
	}
	joined := strings.Join(*calls, "\n")
	for _, w := range []string{"daemon-reload", "enable --now hashem-rescue-fw.service", "enable --now hashem-rescue-frps.service", "enable --now hashem-rescue-frpc.service"} {
		if !strings.Contains(joined, w) {
			t.Fatalf("expected systemctl call %q in:\n%s", w, joined)
		}
	}
	if _, err := rescueEnableOrigin("203.0.113.102", []int{1020}); err == nil {
		t.Fatal("enabling twice must fail")
	}
	rescueDisable()
	if _, err := os.Stat(filepath.Join(configDir, "rescue")); !os.IsNotExist(err) {
		t.Fatal("rescue dir must be removed")
	}
	if _, err := os.Stat(rescueStatePath()); !os.IsNotExist(err) {
		t.Fatal("rescue.json must be removed")
	}
	left, _ := filepath.Glob(filepath.Join(rescueUnitDir, "hashem-rescue-*"))
	if len(left) != 0 {
		t.Fatalf("units left behind: %v", left)
	}
	if !strings.Contains(strings.Join(*calls, "\n"), "nft delete table inet hashem_rescue") {
		t.Fatal("firewall table must be deleted on disable")
	}
	_ = dir
}

func TestEnableRejectsReservedAndBadInput(t *testing.T) {
	fakeSystem(t)
	for _, p := range [][]int{{22}, {7777}, {7443}, {1020, 22}} {
		if _, err := rescueEnableOrigin("203.0.113.102", p); err == nil {
			t.Fatalf("ports %v must be rejected (reserved)", p)
		}
	}
	if _, err := rescueEnableOrigin("not-an-ip", []int{1020}); err == nil {
		t.Fatal("bad ip must be rejected")
	}
	if _, err := rescueEnableOrigin("203.0.113.102", nil); err == nil {
		t.Fatal("no ports must be rejected")
	}
	if _, err := os.Stat(filepath.Join(configDir, "rescue")); !os.IsNotExist(err) {
		t.Fatal("a rejected enable must leave nothing behind")
	}
}

func TestEnableRollsBackOnSystemctlFailure(t *testing.T) {
	calls, _ := fakeSystem(t)
	runCmd = func(name string, args ...string) (string, error) {
		*calls = append(*calls, name+" "+strings.Join(args, " "))
		if name == "systemctl" && len(args) > 1 && args[0] == "enable" && strings.Contains(args[2], "frps") {
			return "boom", errors.New("exit 1")
		}
		return "", nil
	}
	if _, err := rescueEnableOrigin("203.0.113.102", []int{1020}); err == nil {
		t.Fatal("must fail when a service cannot start")
	}
	if _, err := os.Stat(rescueStatePath()); !os.IsNotExist(err) {
		t.Fatal("failed enable must roll back state")
	}
	left, _ := filepath.Glob(filepath.Join(rescueUnitDir, "hashem-rescue-*"))
	if len(left) != 0 {
		t.Fatalf("failed enable must remove units, left: %v", left)
	}
}

func TestApplyCodeSkipsBusyPortsAndWritesEntry(t *testing.T) {
	calls, _ := fakeSystem(t)
	busy, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Skip("cannot listen")
	}
	defer busy.Close()
	busyPort := busy.Addr().(*net.TCPAddr).Port
	free := pickFreePort(41000)
	st := rescueState{CtrlPort: 31000, Token: randHex(24), Secret: randHex(16), Ports: []int{free, busyPort, 22}}
	got, err := rescueApplyCode(rescueEncode(st, "198.51.100.22"))
	if err != nil {
		t.Fatal(err)
	}
	if got.Role != "entry" || len(got.Ports) != 1 || got.Ports[0] != free || len(got.Skipped) != 2 {
		t.Fatalf("unexpected: %+v", got)
	}
	b, _ := os.ReadFile(filepath.Join(configDir, "rescue", "frpc.toml"))
	if !strings.Contains(string(b), `serverAddr = "198.51.100.22"`) || strings.Contains(string(b), "bindPort = 22\n") {
		t.Fatalf("entry config wrong:\n%s", b)
	}
	if !strings.Contains(strings.Join(*calls, "\n"), "enable --now hashem-rescue-frpc.service") {
		t.Fatal("frpc must be started")
	}
	if _, err := rescueApplyCode(rescueEncode(st, "198.51.100.22")); err == nil {
		t.Fatal("second apply while active must fail")
	}
}

func TestObserveNeedsConsecutiveStrikes(t *testing.T) {
	fakeSystem(t)
	now := time.Unix(1_800_000_000, 0)
	blocked := rescueProbeResult{Host: "1.2.3.4", Verdict: "one_way_block"}
	okr := rescueProbeResult{Host: "1.2.3.4", Verdict: "ok"}
	for i := 0; i < rescueStrikes-1; i++ {
		if st := rescueObserve(blocked, now); st.SuspectedSince != 0 {
			t.Fatalf("banner raised after only %d strikes", i+1)
		}
	}
	if st := rescueObserve(okr, now); st.Strikes != 0 || st.SuspectedSince != 0 {
		t.Fatal("a healthy probe must reset strikes")
	}
	var st rescueState
	for i := 0; i < rescueStrikes; i++ {
		st = rescueObserve(blocked, now)
	}
	if st.SuspectedSince == 0 {
		t.Fatal("banner must appear after consecutive strikes")
	}
	// one transient healthy probe clears the suspicion again
	if st = rescueObserve(okr, now); st.SuspectedSince != 0 {
		t.Fatal("recovery must clear the banner")
	}
	// service_down / host_unreachable never count as a one-way block
	for i := 0; i < 5; i++ {
		rescueObserve(rescueProbeResult{Verdict: "host_unreachable"}, now)
	}
	if st = loadRescueLocked(); st.SuspectedSince != 0 {
		t.Fatal("plain outage must not trigger the rescue banner")
	}
}

func TestObserveDetectsLiftedBlockWhileRescued(t *testing.T) {
	fakeSystem(t)
	if _, err := rescueEnableOrigin("203.0.113.102", []int{1020}); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	if st := rescueObserve(rescueProbeResult{Verdict: "ok"}, now); st.LiftedSince == 0 {
		t.Fatal("a working direct route must flag block_lifted")
	}
	if st := rescueObserve(rescueProbeResult{Verdict: "one_way_block"}, now); st.LiftedSince != 0 {
		t.Fatal("block back => lifted flag cleared")
	}
}

func TestRescueAutoEnableAndAutoJoin(t *testing.T) {
	fakeSystem(t)
	now := time.Unix(1_800_000_000, 0)
	blocked := rescueProbeResult{Host: "203.0.113.102", Verdict: "one_way_block"}

	// 0. H6: by default a detected block only raises the banner.
	var st rescueState
	for i := 0; i < rescueStrikes+1; i++ {
		st = rescueObserve(blocked, now)
	}
	if st.Role != "" || st.SuspectedSince == 0 {
		t.Fatalf("without auto mode expected banner only, got role=%q suspected=%d", st.Role, st.SuspectedSince)
	}

	// 1. With auto mode on, consecutive strikes activate the origin.
	rescueMu.Lock()
	stAuto := loadRescueLocked()
	stAuto.AutoMode, stAuto.Strikes = true, 0
	_ = saveRescueLocked(stAuto)
	rescueMu.Unlock()
	for i := 0; i < rescueStrikes; i++ {
		st = rescueObserve(blocked, now)
	}

	if st.Role != "origin" {
		t.Fatalf("expected origin role after %d strikes, got %q", rescueStrikes, st.Role)
	}
	if !st.AutoTriggered {
		t.Fatal("expected AutoTriggered to be true")
	}
	if st.RemoteIP != "203.0.113.102" {
		t.Fatalf("expected remote IP 203.0.113.102, got %q", st.RemoteIP)
	}

	// 2. Test auto-offer generation
	pub := rescuePublicIP()
	if pub == "" {
		pub = "198.51.100.22"
	}
	code := rescueEncode(st, pub)
	if !strings.HasPrefix(code, rescueCodePrefix) {
		t.Fatalf("bad rescue code: %q", code)
	}

	// 3. Clear origin (simulating distinct entry server) and test applying the code
	rescueDisable()
	stEntry, err := rescueApplyCode(code)
	if err != nil {
		t.Fatalf("auto-join apply error: %v", err)
	}
	if stEntry.Role != "entry" {
		t.Fatalf("expected entry role, got %q", stEntry.Role)
	}
}

func TestApplyCodeUsesKernelDNATForDirectlyReachablePorts(t *testing.T) {
	calls, _ := fakeSystem(t)
	p1, p2 := pickFreePort(42000), pickFreePort(42100)
	// p1 answers directly (fast path), p2 is filtered (frp fallback).
	rescueDial = func(addr string, _ time.Duration) (net.Conn, error) {
		if strings.HasSuffix(addr, ":"+strconv.Itoa(p1)) {
			a, b := net.Pipe()
			_ = b.Close()
			return a, nil
		}
		return nil, os.ErrDeadlineExceeded
	}
	st := rescueState{CtrlPort: 31000, Token: randHex(24), Secret: randHex(16), Ports: []int{p1, p2}}
	got, err := rescueApplyCode(rescueEncode(st, "198.51.100.22"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Direct) != 1 || got.Direct[0] != p1 || len(got.Relay) != 1 || got.Relay[0] != p2 {
		t.Fatalf("split wrong: direct=%v relay=%v", got.Direct, got.Relay)
	}
	dn, err := os.ReadFile(filepath.Join(configDir, "rescue", "dnat.nft"))
	if err != nil || !strings.Contains(string(dn), fmt.Sprintf("th dport { %d } dnat ip to 198.51.100.22", p1)) {
		t.Fatalf("dnat rules wrong: %v\n%s", err, dn)
	}
	fc, _ := os.ReadFile(filepath.Join(configDir, "rescue", "frpc.toml"))
	if strings.Contains(string(fc), fmt.Sprintf("bindPort = %d\n", p1)) || !strings.Contains(string(fc), fmt.Sprintf("bindPort = %d\n", p2)) {
		t.Fatalf("frpc must only carry the filtered port:\n%s", fc)
	}
	j := strings.Join(*calls, "\n")
	if !strings.Contains(j, "enable --now hashem-rescue-dnat.service") || !strings.Contains(j, "enable --now hashem-rescue-frpc.service") {
		t.Fatalf("services not started:\n%s", j)
	}
	rescueDisable()
	if left, _ := filepath.Glob(filepath.Join(rescueUnitDir, "hashem-rescue-*")); len(left) != 0 {
		t.Fatalf("disable left units: %v", left)
	}
	if !strings.Contains(strings.Join(*calls, "\n"), "nft delete table inet hashem_dnat") {
		t.Fatal("disable must drop the dnat table")
	}
}
