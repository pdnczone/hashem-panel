package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func withBackhaulVersion(t *testing.T, v string) {
	t.Helper()
	old := backhaulCoreVersion
	backhaulCoreVersion = func() string { return v }
	t.Cleanup(func() { backhaulCoreVersion = old })
}

// H4: a v2 core needs the sectioned schema; v0.x keeps the flat one.
func TestBackhaulConfigSchemaFollowsCoreVersion(t *testing.T) {
	dir := t.TempDir()
	srv, cli := filepath.Join(dir, "config.toml"), filepath.Join(dir, "client.toml")

	withBackhaulVersion(t, "v2.1.3")
	if err := writeBackhaulServerConfig(srv, "0.0.0.0:3080", "tcpmux", "tok", []string{"443", "2083=8443"}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(srv)
	for _, want := range []string{"[listener]", `bind_addr = "0.0.0.0:3080"`, "[security]", `token = "tok"`, "[mux]", "[ports]", `"2083=8443",`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("v2 server config lacks %q:\n%s", want, b)
		}
	}
	if strings.Contains(string(b), "[server]") {
		t.Errorf("v2 server config still uses the v0 [server] table")
	}
	if err := writeBackhaulClientConfig(cli, "10.10.10.1:3080", "wss", "tok"); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(cli)
	if !strings.Contains(string(b), "[dialer]") || !strings.Contains(string(b), `sni = "10.10.10.1"`) {
		t.Errorf("v2 client config wrong:\n%s", b)
	}

	withBackhaulVersion(t, "v0.6.5")
	if err := writeBackhaulServerConfig(srv, "0.0.0.0:3080", "tcpmux", "tok", []string{"443"}); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(srv)
	if !strings.Contains(string(b), "[server]") || strings.Contains(string(b), "[listener]") {
		t.Errorf("v0 server config wrong:\n%s", b)
	}
}

// H4: a failed switch restores the old configs and restarts what ran before.
func TestEngineSwitchRollbackRestoresPreviousEngine(t *testing.T) {
	dir := t.TempDir()
	frps := filepath.Join(dir, "frps.toml")
	newFile := filepath.Join(dir, "config.toml")
	_ = os.WriteFile(frps, []byte("bindPort = 7000\n"), 0600)

	oldActive := engineServiceActive
	engineServiceActive = func(s string) bool { return s == "frps" || s == "gre-tunnel" }
	t.Cleanup(func() { engineServiceActive = oldActive })
	calls := recordSystemctl(t, "")

	tx := newEngineSwitchTx()
	tx.backup(frps)
	tx.backup(newFile)
	_ = os.WriteFile(frps, []byte("broken\n"), 0600)
	_ = os.WriteFile(newFile, []byte("new engine\n"), 0600)

	err := tx.rollback(os.ErrDeadlineExceeded)
	if err == nil || !strings.Contains(err.Error(), "previous engine restored (gre-tunnel, frps)") {
		t.Fatalf("unexpected rollback error: %v", err)
	}
	if b, _ := os.ReadFile(frps); string(b) != "bindPort = 7000\n" {
		t.Errorf("frps.toml not restored: %q", b)
	}
	if _, err := os.Stat(newFile); !os.IsNotExist(err) {
		t.Errorf("config created by the failed switch was not removed")
	}
	joined := strings.Join(*calls, "|")
	if !strings.Contains(joined, "restart frps") || !strings.Contains(joined, "restart gre-tunnel") || strings.Contains(joined, "restart backhaul") {
		t.Errorf("wrong services restarted: %v", *calls)
	}
}

// H4: a unit that exits right after its restart counts as a failed start.
func TestEngineSwitchStartDetectsCrashedUnit(t *testing.T) {
	oldActive := engineServiceActive
	engineServiceActive = func(string) bool { return false }
	t.Cleanup(func() { engineServiceActive = oldActive })
	recordSystemctl(t, "")
	tx := &engineSwitchTx{wasActive: map[string]bool{}, files: map[string][]byte{}}
	if err := tx.start("backhaul-server"); err == nil || !strings.Contains(err.Error(), "exited right after restart") {
		t.Fatalf("crashed unit not detected: %v", err)
	}
}

// H9: Backhaul and Bagher are engines; applying them as a carrier is refused.
func TestCarrierApplicable(t *testing.T) {
	for _, ok := range []string{"direct", "fou:443", "wss", "wss:8443", "frp:tcp", "frp:kcp", "frp:quic", "frp:ws"} {
		if err := carrierApplicable(ok); err != nil {
			t.Errorf("%s rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"backhaul:3080", "bagher:22", "frp:bogus", "nonsense", ""} {
		if err := carrierApplicable(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if _, err := applyCarrierMode("backhaul:3080"); err == nil {
		t.Error("applyCarrierMode must refuse backhaul:*")
	}
}

// L13: the port in "wss:PORT" is applied to the WSS carrier.
func TestWSSConfigForCarrierAppliesPort(t *testing.T) {
	old := configDir
	configDir = t.TempDir()
	t.Cleanup(func() { configDir = old })
	c := loadWSSConfig()
	c.RemoteAddr = "203.0.113.5:8443"
	_ = saveWSSConfig(c)
	got := wssConfigForCarrier("wss:2096")
	if got.ListenPort != 2096 || got.RemoteAddr != "203.0.113.5:2096" || !got.Enabled {
		t.Fatalf("got %+v", got)
	}
}

// H9: frpc moves to the frps QUIC port (bindPort+1) and back.
func TestUpdateFrpcTransportMovesQuicPort(t *testing.T) {
	oldFrp := frpDir
	frpDir = t.TempDir()
	t.Cleanup(func() { frpDir = oldFrp })
	p := filepath.Join(frpDir, "frpc.toml")
	_ = os.WriteFile(p, []byte("serverAddr = \"10.10.10.1\"\nserverPort = 7000\ntransport.protocol = \"tcp\"\n"), 0600)

	if err := updateFrpcTransport("quic"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	if !strings.Contains(string(b), "serverPort = 7001") || !strings.Contains(string(b), `transport.protocol = "quic"`) {
		t.Fatalf("quic switch:\n%s", b)
	}
	if err := updateFrpcTransport("kcp"); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(p)
	if !strings.Contains(string(b), "serverPort = 7000") {
		t.Fatalf("back from quic:\n%s", b)
	}
}

// H4/H9: older frps configs get the kcp/quic listeners added.
func TestEnsureFrpsUDPListeners(t *testing.T) {
	oldFrp := frpDir
	frpDir = t.TempDir()
	t.Cleanup(func() { frpDir = oldFrp })
	calls := recordSystemctl(t, "")
	_ = os.WriteFile(filepath.Join(frpDir, "frps-2.toml"), []byte("bindAddr = \"0.0.0.0\"\nbindPort = 7002\nauth.token = \"x\"\n"), 0600)
	_ = os.WriteFile(filepath.Join(frpDir, "frps.toml"), []byte("bindPort = 7000\nkcpBindPort = 7000\nquicBindPort = 7001\n"), 0600)
	if err := ensureFrpsUDPListeners(); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(frpDir, "frps-2.toml"))
	if !strings.Contains(string(b), "bindPort = 7002\nkcpBindPort = 7002\nquicBindPort = 7003\n") {
		t.Fatalf("listeners not added:\n%s", b)
	}
	if strings.Join(*calls, "|") != "restart frps-2" {
		t.Fatalf("only the changed frps must restart, got %v", *calls)
	}
}

// H9: KCP/QUIC are reported as unmeasured and never recommended.
func TestBenchmarkUDPCarriersUnmeasured(t *testing.T) {
	old := configDir
	configDir = t.TempDir()
	t.Cleanup(func() { configDir = old })
	rep := runCarrierBenchmark(BenchmarkRunRequest{TargetHost: "127.0.0.1"})
	if rep == nil {
		t.Fatal("no report")
	}
	for _, m := range rep.Metrics {
		if m.Type == "frp_kcp" || m.Type == "frp_quic" {
			if m.Status != benchUnmeasured || m.Score != 0 || m.IsRecommended {
				t.Errorf("%s: status=%q score=%d recommended=%v", m.ID, m.Status, m.Score, m.IsRecommended)
			}
		}
	}
	if strings.HasPrefix(rep.BestCarrier, "frp:kcp") || strings.HasPrefix(rep.BestCarrier, "frp:quic") {
		t.Errorf("unmeasured carrier recommended: %s", rep.BestCarrier)
	}
}
