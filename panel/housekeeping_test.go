package main

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// ---- frp log level ----

func TestFRPLogLevelDefaultsToWarn(t *testing.T) {
	defer withTempConfigDir(t)()
	if got := frpLogLevel(); got != "warn" {
		t.Fatalf("default level = %q, want warn", got)
	}
	if !strings.Contains(frpLogTomlLines(), `log.level = "warn"`) {
		t.Fatalf("lines: %q", frpLogTomlLines())
	}
	_ = os.WriteFile(perfConfigPath(), []byte(`{"frp_log_level":"info"}`), 0600)
	if got := frpLogLevel(); got != "info" {
		t.Fatalf("explicit level = %q, want info", got)
	}
	_ = os.WriteFile(perfConfigPath(), []byte(`{"frp_log_level":"loud"}`), 0600)
	if got := frpLogLevel(); got != "warn" {
		t.Fatalf("unknown level must fall back to warn, got %q", got)
	}
	// the key survives a save by the Performance tab
	_ = os.WriteFile(perfConfigPath(), []byte(`{"frp_log_level":"debug"}`), 0600)
	if err := savePerfConfig(loadPerfConfig()); err != nil {
		t.Fatal(err)
	}
	if got := frpLogLevel(); got != "debug" {
		t.Fatalf("level lost on save: %q", got)
	}
}

func TestTomlWithLogLevel(t *testing.T) {
	conf := "bindPort = 7000\nauth.token = \"x\"\n\n[[proxies]]\nname = \"a\"\n"
	out, changed := tomlWithLogLevel(conf, "warn")
	if !changed {
		t.Fatal("a config without log.level must change")
	}
	head := strings.SplitN(out, "[[proxies]]", 2)[0]
	if !strings.Contains(head, "log.level = \"warn\"\n") {
		t.Fatalf("log.level must be in the top-level part, got:\n%s", out)
	}
	if !strings.Contains(out, "[[proxies]]\nname = \"a\"\n") {
		t.Fatalf("proxy block damaged:\n%s", out)
	}
	if again, changed := tomlWithLogLevel(out, "warn"); changed || again != out {
		t.Fatal("second run must change nothing")
	}
	// the operator's own level stays
	own := "bindPort = 7000\nlog.level = \"info\"\n"
	if got, changed := tomlWithLogLevel(own, "warn"); changed || got != own {
		t.Fatalf("an explicit level was overwritten: %q", got)
	}
	if got, _ := tomlWithLogLevel("bindPort = 7000", "warn"); got != "bindPort = 7000\nlog.level = \"warn\"\n" {
		t.Fatalf("no-proxy config: %q", got)
	}
}

func TestEnsureFRPLogLevelFiles(t *testing.T) {
	defer withTempConfigDir(t)()
	old := frpDir
	frpDir = t.TempDir()
	defer func() { frpDir = old }()
	_ = os.WriteFile(filepath.Join(frpDir, "frps.toml"), []byte("bindPort = 7000\n"), 0600)
	_ = os.WriteFile(filepath.Join(frpDir, "frps-2.toml"), []byte("bindPort = 7001\nlog.level = \"debug\"\n"), 0600)
	_ = os.WriteFile(filepath.Join(frpDir, "frpc.toml"), []byte("serverPort = 7000\n\n[[proxies]]\nname = \"p\"\n"), 0600)
	done := ensureFRPLogLevel()
	if len(done) != 2 {
		t.Fatalf("changed %v, want frps.toml and frpc.toml", done)
	}
	b, _ := os.ReadFile(filepath.Join(frpDir, "frps-2.toml"))
	if !strings.Contains(string(b), `"debug"`) || strings.Contains(string(b), `"warn"`) {
		t.Fatalf("explicit level touched: %s", b)
	}
	if fi, _ := os.Stat(filepath.Join(frpDir, "frpc.toml")); fi.Mode().Perm() != 0600 {
		t.Fatalf("token file mode = %v", fi.Mode().Perm())
	}
	if again := ensureFRPLogLevel(); len(again) != 0 {
		t.Fatalf("second run changed %v", again)
	}
}

// ---- units ----

const oldFrpsUnit = `[Unit]
Description=FRP Server Service
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
Restart=always
RestartSec=10s
StartLimitIntervalSec=60s
StartLimitBurst=5
LimitNOFILE=1048576
ExecStart=/usr/local/bin/frps -c /etc/frp/frps.toml

[Install]
WantedBy=multi-user.target
`

func unitSection(unit, name string) string {
	i := strings.Index(unit, "["+name+"]")
	if i < 0 {
		return ""
	}
	rest := unit[i+len(name)+2:]
	if j := strings.Index(rest, "\n["); j >= 0 {
		rest = rest[:j]
	}
	return rest
}

func TestFRPUnitFixed(t *testing.T) {
	out := frpUnitFixed(oldFrpsUnit, 4096)
	if svc := unitSection(out, "Service"); strings.Contains(svc, "StartLimit") {
		t.Fatalf("StartLimit left in [Service]:\n%s", out)
	}
	if u := unitSection(out, "Unit"); !strings.Contains(u, "StartLimitIntervalSec=0\n") {
		t.Fatalf("StartLimitIntervalSec=0 missing from [Unit]:\n%s", out)
	}
	if strings.Count(out, "StartLimit") != 1 {
		t.Fatalf("want exactly one StartLimit line:\n%s", out)
	}
	svc := unitSection(out, "Service")
	if !strings.Contains(svc, "Environment=GOMEMLIMIT=900MiB\n") || !strings.Contains(svc, "Environment=GOGC=40\n") {
		t.Fatalf("Go memory env missing for a 4GB server:\n%s", out)
	}
	if again := frpUnitFixed(out, 4096); again != out {
		t.Fatalf("not idempotent:\n%s", again)
	}
	// a limit the operator wrote stays, also when RAM says otherwise
	own := strings.Replace(out, "GOMEMLIMIT=900MiB", "GOMEMLIMIT=3GiB", 1)
	if got := frpUnitFixed(own, 16384); !strings.Contains(got, "GOMEMLIMIT=3GiB") || strings.Contains(got, "2500MiB") {
		t.Fatalf("operator's GOMEMLIMIT replaced:\n%s", got)
	}
}

func TestFRPGoMemForRAM(t *testing.T) {
	for _, c := range []struct {
		mem   int
		limit string
		gogc  int
	}{
		{0, "300MiB", 40}, {1024, "300MiB", 40}, {2048, "500MiB", 40}, {3900, "900MiB", 40},
		{5900, "1400MiB", 45}, {7900, "1800MiB", 50}, {15900, "2500MiB", 50}, {32000, "4000MiB", 50},
	} {
		l, g := frpGoMemForRAM(c.mem)
		if l != c.limit || g != c.gogc {
			t.Errorf("RAM %dMB: got %s/%d, want %s/%d", c.mem, l, g, c.limit, c.gogc)
		}
		if g < 40 || g > 50 {
			t.Errorf("RAM %dMB: GOGC %d outside 40..50", c.mem, g)
		}
	}
}

func TestEnsureFRPUnitFiles(t *testing.T) {
	oldDir, oldMem := systemdUnitDir, hostMemMB
	systemdUnitDir = t.TempDir()
	hostMemMB = func() int { return 6000 }
	defer func() { systemdUnitDir, hostMemMB = oldDir, oldMem }()
	for _, n := range []string{"frps.service", "frps-3.service", "frpc.service", "gre-panel.service"} {
		_ = os.WriteFile(filepath.Join(systemdUnitDir, n), []byte(oldFrpsUnit), 0644)
	}
	done := ensureFRPUnitFiles()
	if len(done) != 3 {
		t.Fatalf("changed %v, want the three frp units", done)
	}
	b, _ := os.ReadFile(filepath.Join(systemdUnitDir, "frps-3.service"))
	if !strings.Contains(string(b), "GOMEMLIMIT=1400MiB") {
		t.Fatalf("6GB server: %s", b)
	}
	if b, _ := os.ReadFile(filepath.Join(systemdUnitDir, "gre-panel.service")); string(b) != oldFrpsUnit {
		t.Fatal("a unit that is not frps/frpc was touched")
	}
	if again := ensureFRPUnitFiles(); len(again) != 0 {
		t.Fatalf("second run changed %v", again)
	}
}

func TestNewUnitsKeepStartLimitInUnit(t *testing.T) {
	units := map[string]string{
		"engineUnit": engineUnit("x", "", "/bin/true"),
		"rescueUnit": rescueUnit("x", "/bin/true", "", ""),
	}
	for name, u := range units {
		if strings.Contains(unitSection(u, "Service"), "StartLimit") {
			t.Errorf("%s: StartLimit in [Service]:\n%s", name, u)
		}
		if !strings.Contains(unitSection(u, "Unit"), "StartLimitIntervalSec=0") {
			t.Errorf("%s: StartLimitIntervalSec=0 missing from [Unit]:\n%s", name, u)
		}
	}
	src, _ := os.ReadFile("sshfwd.go")
	for _, block := range strings.Split(string(src), "[Service]")[1:] {
		if i := strings.Index(block, "[Install]"); i >= 0 && strings.Contains(block[:i], "StartLimit") {
			t.Errorf("sshfwd.go writes StartLimit under [Service]: %q", block[:i])
		}
	}
}

func TestEnsureJournaldCap(t *testing.T) {
	old := journaldDropDir
	journaldDropDir = filepath.Join(t.TempDir(), "journald.conf.d")
	defer func() { journaldDropDir = old }()
	if !ensureJournaldCap() {
		t.Fatal("first run must write the drop-in")
	}
	b, _ := os.ReadFile(filepath.Join(journaldDropDir, "99-hashem.conf"))
	for _, want := range []string{"[Journal]", "SystemMaxUse=500M", "RuntimeMaxUse=200M"} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("drop-in lacks %s:\n%s", want, b)
		}
	}
	if ensureJournaldCap() {
		t.Fatal("second run must change nothing")
	}
	// the smaller cap of `hashem free-ram` stays
	small := "# hashem free-ram: journal size cap (rewritten automatically)\n[Journal]\nSystemMaxUse=32M\nRuntimeMaxUse=16M\n"
	_ = os.WriteFile(filepath.Join(journaldDropDir, "99-hashem.conf"), []byte(small), 0644)
	if ensureJournaldCap() {
		t.Fatal("the free-ram cap was replaced")
	}
}

// ---- panel-errors.log ----

func TestErrorLogRotates(t *testing.T) {
	defer withTempConfigDir(t)()
	path := errorLogPath()
	big := make([]byte, errLogMaxBytes+10)
	for i := range big {
		big[i] = 'x'
	}
	if err := os.WriteFile(path, big, 0600); err != nil {
		t.Fatal(err)
	}
	recordError("E-AUTH-01", "POST /api/peer/ping", "peer authentication failed")
	fi, err := os.Stat(path)
	if err != nil || fi.Size() > 4096 {
		t.Fatalf("log not rotated: %v size=%d", err, fi.Size())
	}
	if fi1, err := os.Stat(path + ".1"); err != nil || fi1.Size() != int64(len(big)) {
		t.Fatalf("old log not kept as .1: %v", err)
	}
	// a second full log replaces .1: the two files never pass ~2x the cap
	_ = os.WriteFile(path, big[:errLogMaxBytes], 0600)
	recordError("E-AUTH-01", "x", "y")
	if fi1, _ := os.Stat(path + ".1"); fi1.Size() != errLogMaxBytes {
		t.Fatalf(".1 size = %d", fi1.Size())
	}
	if _, err := os.Stat(path + ".2"); err == nil {
		t.Fatal("more than one old log kept")
	}
	b, _ := os.ReadFile(path)
	var ev errEvent
	if json.Unmarshal([]byte(strings.TrimSpace(string(b))), &ev) != nil || ev.Code != "E-AUTH-01" {
		t.Fatalf("new log content: %q", b)
	}
}

// ---- [CMD-ERROR] for a cleanup of something that is not there ----

func TestAbsentIsAnswer(t *testing.T) {
	yes := [][]string{
		{"iptables", "1", "-w", "5", "-F", "HASHEM_LIMIT"},
		{"iptables", "1", "-w", "5", "-X", "HASHEM_CUST"},
		{"iptables", "1", "-w", "5", "-D", "INPUT", "-j", "HASHEM_CUST_GRE"},
		{"ip6tables", "1", "-w", "5", "-F", "HASHEM_LIMIT"},
		{"iptables", "1", "-t", "nat", "-X", "HASHEM-CLUSTER-PREROUTING"},
		{"iptables", "1", "-t", "mangle", "-C", "POSTROUTING", "-j", "TCPMSS"},
		{"tc", "2", "qdisc", "del", "dev", "eth0", "root"},
	}
	no := [][]string{
		{"iptables", "1", "-w", "5", "-A", "INPUT", "-j", "HASHEM_LIMIT"},
		{"iptables", "1", "-N", "HASHEM_LIMIT"},
		{"iptables", "4", "-F", "HASHEM_LIMIT"}, // the xtables lock: a real failure
		{"iptables", "2", "-X", "HASHEM_CUST"},
		{"tc", "2", "qdisc", "add", "dev", "eth0", "root", "htb"},
		{"tc", "1", "qdisc", "del", "dev", "eth0", "root"},
		{"ip", "1", "link", "del", "gre-t2"},
	}
	code := func(s string) int { return int(s[0] - '0') }
	for _, c := range yes {
		if !exitIsAnswer(c[0], c[2:], code(c[1])) {
			t.Errorf("must not be logged as an error: %v", c)
		}
	}
	for _, c := range no {
		if exitIsAnswer(c[0], c[2:], code(c[1])) {
			t.Errorf("must still be logged: %v", c)
		}
	}
}

// ---- TCPMSS copies ----

func TestMssRewriteDropsCopies(t *testing.T) {
	rule := "-A POSTROUTING -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1340"
	fwd := "-A FORWARD -o gre-t2 -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1340"
	rules := strings.Join([]string{"-P POSTROUTING ACCEPT", rule, rule, rule, fwd, fwd}, "\n")
	del, add := mssRewrite(rules, 1340)
	if len(add) != 0 {
		t.Fatalf("nothing to add, got %v", add)
	}
	if len(del) != 3 {
		t.Fatalf("want 2 POSTROUTING copies and 1 FORWARD copy deleted, got %v", del)
	}
	for _, d := range del {
		if d[0] != "-t" || d[1] != "mangle" || d[2] != "-D" {
			t.Fatalf("bad delete %v", d)
		}
	}
	if del, add := mssRewrite("-P POSTROUTING ACCEPT\n"+rule+"\n"+fwd, 1340); len(del)+len(add) != 0 {
		t.Fatalf("single rules must stay: del=%v add=%v", del, add)
	}
	// copies of a clamp that is too large: every copy goes, one smaller rule comes
	big := strings.ReplaceAll(rule, "1340", "1400")
	del, add = mssRewrite(big+"\n"+big, 1340)
	if len(del) != 2 || len(add) != 1 {
		t.Fatalf("large copies: del=%v add=%v", del, add)
	}
}

// ---- Peer Link: an address that does not connect goes last ----

func resetPeerDown() {
	peerDownMu.Lock()
	peerDown = map[string]*peerDownEntry{}
	peerDownMu.Unlock()
}

func TestPeerOrderURLs(t *testing.T) {
	resetPeerDown()
	defer resetPeerDown()
	oldDial, oldNow := peerProbeDial, peerNow
	defer func() { peerProbeDial, peerNow = oldDial, oldNow }()
	now := time.Unix(1_700_000_000, 0)
	peerNow = func() time.Time { return now }
	probed := make(chan string, 4)
	var probeErr error = errors.New("no answer")
	peerProbeDial = func(hp string, _ time.Duration) error { probed <- hp; return probeErr }

	urls := []string{"http://10.10.10.2:7777/_hp/api/peer/ping", "http://10.10.10.2:7777/x/api/peer/ping", "http://5.6.7.8:7777/_hp/api/peer/ping"}
	if got := peerOrderURLs(urls); strings.Join(got, " ") != strings.Join(urls, " ") {
		t.Fatalf("nothing marked: order must not change, got %v", got)
	}
	peerMarkDown("10.10.10.2:7777")
	got := peerOrderURLs(urls)
	if got[0] != urls[2] || got[1] != urls[0] || got[2] != urls[1] {
		t.Fatalf("the public address must come first, the marked one stays as last resort: %v", got)
	}
	select {
	case hp := <-probed:
		t.Fatalf("probed %s before a minute passed", hp)
	case <-time.After(50 * time.Millisecond):
	}
	// a minute later one light probe goes out; a failed one keeps the mark
	now = now.Add(peerProbeEvery + time.Second)
	peerOrderURLs(urls)
	select {
	case hp := <-probed:
		if hp != "10.10.10.2:7777" {
			t.Fatalf("probed %s", hp)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no probe after the interval")
	}
	waitFor(t, func() bool {
		peerDownMu.Lock()
		defer peerDownMu.Unlock()
		e := peerDown["10.10.10.2:7777"]
		return e != nil && !e.probing
	})
	if !peerIsDown("10.10.10.2:7777") {
		t.Fatal("a failed probe must keep the mark")
	}
	// GRE is back: the probe unmarks it and the inner address leads again
	probeErr = nil
	now = now.Add(peerProbeEvery + time.Second)
	peerOrderURLs(urls)
	<-probed
	waitFor(t, func() bool { return !peerIsDown("10.10.10.2:7777") })
	if got := peerOrderURLs(urls); got[0] != urls[0] {
		t.Fatalf("after recovery the inner address must be first again: %v", got)
	}
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if ok() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not reached")
}

func TestPeerHostKeyAndConnectFailed(t *testing.T) {
	for in, want := range map[string]string{
		"http://10.10.10.2:7777/_hp/api": "10.10.10.2:7777",
		"https://example.com/x":          "example.com:443",
		"http://example.com":             "example.com:80",
		"http://[2001:db8::1]:7777/a":    "[2001:db8::1]:7777",
		"not a url":                      "",
	} {
		if got := peerHostKey(in); got != want {
			t.Errorf("peerHostKey(%q) = %q, want %q", in, got, want)
		}
	}
	if !peerConnectFailed(&net.OpError{Op: "dial", Err: errors.New("connect: connection refused")}) {
		t.Error("a refused dial is a connect failure")
	}
	if peerConnectFailed(errors.New("peer returned HTTP 500")) || peerConnectFailed(nil) {
		t.Error("an HTTP error is an answer, not a connect failure")
	}
}

// The inner address refuses, the public one answers: the first call falls
// back, and the next one goes to the public address at once.
func TestSendToPeerRemembersDeadInnerAddress(t *testing.T) {
	defer withTempConfigDir(t)()
	resetPeerDown()
	defer resetPeerDown()
	oldDial := peerProbeDial
	peerProbeDial = func(string, time.Duration) error { return errors.New("still down") }
	defer func() { peerProbeDial = oldDial }()

	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"pong"}`))
	}))
	defer srv.Close()
	// a port nothing listens on: the "blocked GRE" address
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadPort := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()

	if err := savePeerConfig(PeerConfig{Role: "worker", PeerSecret: "s3cret", InternalIP: "127.0.0.1", InternalPort: deadPort, PeerURL: srv.URL}); err != nil {
		t.Fatal(err)
	}
	if _, err := sendToPeer("/api/peer/ping", "POST", map[string]string{"action": "ping"}); err != nil {
		t.Fatalf("fallback to the public address failed: %v", err)
	}
	dead := net.JoinHostPort("127.0.0.1", strconv.Itoa(deadPort))
	if !peerIsDown(dead) {
		t.Fatalf("%s must be remembered as not connecting", dead)
	}
	order := peerOrderURLs(peerTargetURLs(loadPeerConfig(), "/api/peer/ping"))
	if !strings.HasPrefix(order[0], srv.URL) {
		t.Fatalf("the next call must start with the public address, got %v", order)
	}
	if peerIsDown(peerHostKey(srv.URL)) {
		t.Fatal("the address that answered was marked down")
	}
	if _, err := sendToPeer("/api/peer/ping", "POST", nil); err != nil || hits != 2 {
		t.Fatalf("second call: err=%v hits=%d", err, hits)
	}
}

// ---- tunnel_links.json and the Peer Link after a removal ----

func TestPruneTunnelLinks(t *testing.T) {
	defer withTempConfigDir(t)()
	updateTunnelLink(2, func(l *tunnelLink) { l.PublicIP, l.TLSPin = "5.6.7.8", "aa" })
	updateTunnelLink(3, func(l *tunnelLink) { l.PublicIP, l.TLSPin = "9.9.9.9", "bb" })
	updateTunnelLink(7, func(l *tunnelLink) { l.LastURL = "http://1.2.3.4:7777" })

	// peers.json that cannot be read is not "no peers": nothing goes
	_ = os.WriteFile(peersFile(), []byte("{broken"), 0600)
	pruneTunnelLinks()
	if n := len(loadTunnelLinks()); n != 3 {
		t.Fatalf("unreadable peers.json pruned records: %d left", n)
	}

	_ = os.WriteFile(peersFile(), []byte(`{"peers":[{"id":3,"name":"de"}]}`), 0600)
	pruneTunnelLinks()
	m := loadTunnelLinks()
	if len(m) != 1 || m[3].TLSPin != "bb" {
		t.Fatalf("want only peer 3 left, got %v", m)
	}
	if fi, _ := os.Stat(tunnelLinksPath()); fi.Mode().Perm() != 0600 {
		t.Fatalf("mode = %v", fi.Mode().Perm())
	}

	// the last peer is removed: the file goes
	_ = os.Remove(peersFile())
	pruneTunnelLinks()
	if _, err := os.Stat(tunnelLinksPath()); !os.IsNotExist(err) {
		t.Fatalf("tunnel_links.json must be removed, stat err = %v", err)
	}
}

func TestForgetPeerLink(t *testing.T) {
	defer withTempConfigDir(t)()
	_ = savePeerConfig(PeerConfig{Role: "worker", PeerSecret: "old-secret", PeerURL: "http://5.6.7.8:7777",
		PeerBasePath: "abc", TLSFingerprint: "ff", IsConnected: true, LatencyMs: 12, PeerFrpVersion: "0.61.1"})
	forgetPeerLink()
	c := loadPeerConfig()
	if c.PeerSecret == "old-secret" || c.PeerSecret == "" {
		t.Fatalf("the old secret must be replaced, got %q", c.PeerSecret)
	}
	if c.PeerURL != "" || c.TLSFingerprint != "" || c.PeerBasePath != "" || c.IsConnected || c.PeerFrpVersion != "" {
		t.Fatalf("link fields left: %+v", c)
	}
}

// ---- Auto Pool ceiling and frp versions ----

func TestEffectivePoolFollowsFRPMaxPool(t *testing.T) {
	defer withTempConfigDir(t)()
	_ = os.WriteFile(autoPoolStatePath(), []byte(`{"pool":40,"max_pool":500}`), 0600)
	_ = os.WriteFile(perfConfigPath(), []byte(`{"auto_pool":true,"frp_max_pool":1200}`), 0600)
	if pool, max := effectivePoolValues(); pool != 40 || max != 1200 {
		t.Fatalf("auto pool with frp_max_pool 1200: got %d/%d, want 40/1200", pool, max)
	}
	// the default (60) never lowers what Auto Pool picked
	_ = os.WriteFile(perfConfigPath(), []byte(`{"auto_pool":true}`), 0600)
	if _, max := effectivePoolValues(); max != 500 {
		t.Fatalf("default frp_max_pool lowered the ceiling to %d", max)
	}
}

func TestFrpVersionDrift(t *testing.T) {
	for in, want := range map[string]string{"0.61.1": "0.61.1", "v0.71.0\n": "0.71.0", "frps 0.61": "", "<b>1.2.3</b>": "", "": ""} {
		if got := cleanFrpVersion(in); got != want {
			t.Errorf("cleanFrpVersion(%q) = %q, want %q", in, got, want)
		}
	}
	links := map[int]tunnelLink{2: {FrpVersion: "0.61.1"}, 3: {FrpVersion: "0.71.0"}, 9: {FrpVersion: "0.50.0"}}
	peers := []peerRecord{{ID: 2, Name: "de-1"}, {ID: 3, Name: "nl-1"}, {ID: 4, Name: "fi-1"}}
	got := frpVersionDrift("0.71.0", "0.61.1", links, peers)
	if strings.Join(got, "|") != "main tunnel 0.61.1|de-1 0.61.1" {
		t.Fatalf("drift = %v", got)
	}
	if d := frpVersionDrift("0.71.0", "0.71.0", map[int]tunnelLink{3: {FrpVersion: "0.71.0"}}, peers); len(d) != 0 {
		t.Fatalf("same versions reported: %v", d)
	}
	if d := frpVersionDrift("", "0.61.1", links, peers); len(d) != 0 {
		t.Fatalf("unknown local version must report nothing: %v", d)
	}
}
