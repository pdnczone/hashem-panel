package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// spoofLab points every spoof path at temp dirs and gives the test a Pro
// license, so saving, config writing and the handlers never touch the host.
func spoofLab(t *testing.T) {
	t.Helper()
	withPro(t) // sets configDir to a temp dir and a Bagher license
	od, owg, ou := spoofDir, wgConfDir, engineUnitDir
	spoofDir = t.TempDir()
	wgConfDir = t.TempDir()
	engineUnitDir = t.TempDir()
	t.Cleanup(func() { spoofDir, wgConfDir, engineUnitDir = od, owg, ou })
}

func TestSpoofKeypairRoundTrip(t *testing.T) {
	priv, pub, err := spoofGenKeypair()
	if err != nil {
		t.Fatal(err)
	}
	got, err := spoofPubFromPriv(priv)
	if err != nil {
		t.Fatal(err)
	}
	if got != pub {
		t.Fatalf("derived pub %q != %q", got, pub)
	}
	if _, err := spoofPubFromPriv("not-base64!!"); err == nil {
		t.Fatal("expected error for a bad private key")
	}
}

func TestSpoofCoreConfigLocal(t *testing.T) {
	s := spoofState{Role: "local", PeerPublicIP: "198.51.100.10", ListenPort: 8090, RecvPort: 5001,
		CorePort: 5000, SpoofPort: 443, SpoofIPs: []string{"1.2.3.4"}, SendTransport: "tcp", RecvTransport: "udp"}
	m := s.coreConfig()
	if m["mode"] != "local" || m["remote"] != "198.51.100.10" || m["listen"] != "127.0.0.1:5000" {
		t.Fatalf("local core config wrong: %#v", m)
	}
	if m["spoof_ip"] != "1.2.3.4" {
		t.Fatalf("single spoof IP should arm spoof_ip, got %#v", m)
	}
	if _, ok := m["spoof_ip_file"]; ok {
		t.Fatal("single IP must not set spoof_ip_file")
	}
}

func TestSpoofCoreConfigRemoteUsesList(t *testing.T) {
	s := spoofState{Role: "remote", PeerPublicIP: "203.0.113.5", ListenPort: 8090, RecvPort: 5001,
		WGListen: 51820, SpoofPort: 8090, SpoofIPs: []string{"1.1.1.1", "2.2.2.2"}, SendTransport: "udp", RecvTransport: "tcp"}
	m := s.coreConfig()
	if m["mode"] != "remote" || m["forward"] != "127.0.0.1:51820" || m["client_ip"] != "203.0.113.5" {
		t.Fatalf("remote core config wrong: %#v", m)
	}
	if _, ok := m["spoof_ip"]; ok {
		t.Fatal("a list must not set a single spoof_ip (peer filter would drop packets)")
	}
	if m["spoof_ip_file"] != spoofIPFilePath() {
		t.Fatalf("list should set spoof_ip_file, got %#v", m)
	}
}

func TestSpoofBundleRoundTrip(t *testing.T) {
	spoofLab(t)
	iran := spoofState{Role: "local", LocalPublic: "198.51.100.10", ListenPort: 8090, RecvPort: 5001,
		SpoofPort: 443, SendTransport: "tcp", RecvTransport: "udp", CorePort: 5000, WGListen: 51820}
	iran.applyRoleDefaults()
	bundle, iran2, err := makeSpoofBundle(iran)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(bundle, "spf1_") {
		t.Fatalf("bundle prefix wrong: %q", bundle)
	}
	if iran2.WGPubKey == "" || iran2.WGPeerPub == "" {
		t.Fatal("making a bundle should fill both our key and the peer key")
	}

	foreign, err := importSpoofBundle(bundle, spoofState{SpoofIPs: []string{"9.9.9.9"}})
	if err != nil {
		t.Fatal(err)
	}
	if foreign.Role != "remote" {
		t.Fatalf("imported role = %q, want remote", foreign.Role)
	}
	// Transports mirror the Iran side.
	if foreign.SendTransport != "udp" || foreign.RecvTransport != "tcp" {
		t.Fatalf("transports not mirrored: send=%s recv=%s", foreign.SendTransport, foreign.RecvTransport)
	}
	// Each side must hold the other's public key.
	if foreign.WGPeerPub != iran2.WGPubKey {
		t.Fatal("foreign's peer key must equal the Iran public key")
	}
	if foreign.WGPubKey != iran2.WGPeerPub {
		t.Fatal("foreign's own key must equal the key the Iran side pinned as peer")
	}
	// WG addresses cross over.
	if foreign.WGLocalIP != iran2.WGPeerIP || foreign.WGPeerIP != iran2.WGLocalIP {
		t.Fatalf("WG addresses not crossed: %s/%s vs %s/%s", foreign.WGLocalIP, foreign.WGPeerIP, iran2.WGLocalIP, iran2.WGPeerIP)
	}
	if foreign.PeerPublicIP != "198.51.100.10" {
		t.Fatalf("foreign should dial the Iran public IP, got %q", foreign.PeerPublicIP)
	}
	// The foreign side keeps its own tester-found spoof IPs.
	if len(foreign.SpoofIPs) != 1 || foreign.SpoofIPs[0] != "9.9.9.9" {
		t.Fatalf("import must keep this server's spoof IPs, got %#v", foreign.SpoofIPs)
	}
	if foreign.WGPeerPriv != "" {
		t.Fatal("the foreign side must not keep a peer private key")
	}
	if spoofView(iran2)["wg_peer_priv"] != nil {
		t.Fatal("GET must never expose the foreign private key")
	}

	// Showing the bundle again keeps the keys, so a running tunnel survives.
	again, iran3, err := makeSpoofBundle(iran2)
	if err != nil {
		t.Fatal(err)
	}
	if again != bundle || iran3.WGPeerPub != iran2.WGPeerPub {
		t.Fatal("a re-shown bundle must carry the same keys")
	}
}

func TestSpoofBundleNeedsPublicIP(t *testing.T) {
	spoofLab(t)
	s := spoofState{Role: "local", ListenPort: 8090, RecvPort: 5001, SendTransport: "tcp", RecvTransport: "udp",
		CorePort: 5000, WGListen: 51820, LocalPublic: "not-an-ip"}
	s.applyRoleDefaults()
	if _, _, err := makeSpoofBundle(s); err == nil {
		t.Fatal("a bundle without this server's public IP must be refused")
	}
}

// A crafted bundle must not be able to put anything but keys, addresses and
// ports into wg-spoof.conf (wg-quick runs PostUp lines as root).
func TestSpoofImportRejectsInjection(t *testing.T) {
	_, pub, _ := spoofGenKeypair()
	priv, _, _ := spoofGenKeypair()
	good := spoofBundle{V: 1, IranPublicIP: "198.51.100.10", ListenPort: 8090, RecvPort: 5001, SpoofPort: 443,
		SendTransport: "tcp", RecvTransport: "udp", IranWGPub: pub, ForeignWGPriv: priv,
		WGIranIP: "10.20.0.1", WGForeignIP: "10.20.0.2", WGListen: 51820, CorePort: 5000}
	enc := func(b spoofBundle) string {
		raw, _ := json.Marshal(b)
		return "spf1_" + base64.RawURLEncoding.EncodeToString(raw)
	}
	if _, err := importSpoofBundle(enc(good), spoofState{}); err != nil {
		t.Fatalf("good bundle refused: %v", err)
	}
	bad := []func(*spoofBundle){
		func(b *spoofBundle) { b.IranWGPub = pub + "\nPostUp = touch /tmp/x" },
		func(b *spoofBundle) { b.WGIranIP = "10.20.0.1/24\nPostUp = id" },
		func(b *spoofBundle) { b.IranPublicIP = "" },
		func(b *spoofBundle) { b.SendTransport = "gre" },
		func(b *spoofBundle) { b.WGListen = 70000 },
		func(b *spoofBundle) { b.WGForeignIP = b.WGIranIP },
	}
	for i, mut := range bad {
		b := good
		mut(&b)
		if _, err := importSpoofBundle(enc(b), spoofState{}); err == nil {
			t.Fatalf("case %d: crafted bundle accepted", i)
		}
	}
}

func TestSpoofImportRejectsGarbage(t *testing.T) {
	for _, b := range []string{"", "hello", "spf1_@@@", "spf1_" + "Zm9v"} {
		if _, err := importSpoofBundle(b, spoofState{}); err == nil {
			t.Fatalf("expected error for bundle %q", b)
		}
	}
}

func TestSpoofReadyReportsMissing(t *testing.T) {
	s := spoofState{Role: "local", SendTransport: "tcp", RecvTransport: "udp"}
	s.applyRoleDefaults()
	if err := s.ready(); err == nil {
		t.Fatal("expected not-ready without a peer IP")
	}
	s.PeerPublicIP = "198.51.100.10"
	s.SpoofIPs = []string{"1.2.3.4"}
	s.WGPeerPub = "abc"
	if err := s.ready(); err != nil {
		t.Fatalf("should be ready now: %v", err)
	}
}

func TestApplySpoofFormValidatesAndReDerives(t *testing.T) {
	s := spoofState{Role: "remote"}
	s.applyRoleDefaults()
	if s.WGLocalIP != "10.20.0.2" {
		t.Fatalf("remote default WG IP wrong: %q", s.WGLocalIP)
	}
	applySpoofForm(&s, spoofPostRequest{Role: "local", ListenPort: 70000, SpoofPort: 443,
		SendTransport: "bogus", RecvTransport: "icmp", SpoofIPs: []string{"1.2.3.4", "bad", "1.2.3.4"}})
	if s.Role != "local" || s.WGLocalIP != "10.20.0.1" {
		t.Fatalf("role switch should re-derive WG IP, got role=%s ip=%s", s.Role, s.WGLocalIP)
	}
	if s.ListenPort == 70000 {
		t.Fatal("out-of-range port must be rejected")
	}
	if s.SendTransport == "bogus" {
		t.Fatal("invalid transport must be rejected")
	}
	if s.RecvTransport != "icmp" {
		t.Fatalf("valid transport should apply, got %q", s.RecvTransport)
	}
	if len(s.SpoofIPs) != 1 || s.SpoofIPs[0] != "1.2.3.4" {
		t.Fatalf("spoof IPs should be cleaned/deduped, got %#v", s.SpoofIPs)
	}
}

func TestSpoofWriteConfigsAndUnit(t *testing.T) {
	spoofLab(t)
	s := spoofState{Role: "local", PeerPublicIP: "198.51.100.10", ListenPort: 8090, RecvPort: 5001,
		CorePort: 5000, SpoofPort: 443, SpoofIPs: []string{"1.2.3.4"}, SendTransport: "tcp", RecvTransport: "udp",
		WGPrivKey: "cHJpdg==", WGPubKey: "cHVi", WGPeerPub: "cGVlcg==", WGLocalIP: "10.20.0.1", WGPeerIP: "10.20.0.2"}
	if err := s.writeCoreConfig(); err != nil {
		t.Fatal(err)
	}
	var cc map[string]any
	data, _ := os.ReadFile(spoofCoreConfigPath())
	if err := json.Unmarshal(data, &cc); err != nil || cc["mode"] != "local" {
		t.Fatalf("core config not written right: %v %s", err, data)
	}
	if err := s.writeWGConfig(); err != nil {
		t.Fatal(err)
	}
	wg, _ := os.ReadFile(spoofWGConfPath())
	if !strings.Contains(string(wg), "Endpoint = 127.0.0.1:5000") || !strings.Contains(string(wg), "PersistentKeepalive") {
		t.Fatalf("local WG config missing endpoint/keepalive:\n%s", wg)
	}
	if err := s.writeCoreUnit(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(engineUnitDir, spoofCoreSvc+".service")); err != nil {
		t.Fatalf("core unit not written: %v", err)
	}
}

func TestSpoofWGConfigRemoteListens(t *testing.T) {
	s := spoofState{Role: "remote", WGPrivKey: "cHJpdg==", WGPeerPub: "cGVlcg==",
		WGLocalIP: "10.20.0.2", WGPeerIP: "10.20.0.1", WGListen: 51820}
	cfg := s.wgConfig()
	if !strings.Contains(cfg, "ListenPort = 51820") {
		t.Fatalf("remote WG must listen: %s", cfg)
	}
	if strings.Contains(cfg, "Endpoint") {
		t.Fatalf("remote WG must not set an endpoint: %s", cfg)
	}
}

func TestSpoofGetRequiresNothingButPostIsPro(t *testing.T) {
	spoofLab(t)
	// GET works and reports pro=true under the lab license.
	rr := httptest.NewRecorder()
	handleSpoofGet(rr, httptest.NewRequest("GET", "/api/spoof", nil))
	var g map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &g); err != nil {
		t.Fatalf("bad GET json: %v", err)
	}
	if g["pro"] != true {
		t.Fatalf("expected pro=true under lab license, got %#v", g["pro"])
	}

	// genkeys persists a keypair.
	rr = httptest.NewRecorder()
	handleSpoofPost(rr, httptest.NewRequest("POST", "/api/spoof", strings.NewReader(`{"action":"genkeys"}`)))
	if apiCode(t, rr) != "" {
		t.Fatalf("genkeys failed: %s", rr.Body.String())
	}
	if loadSpoofState().WGPrivKey == "" {
		t.Fatal("genkeys should persist a private key")
	}
}

func TestSpoofPostGatedWithoutPro(t *testing.T) {
	// No license at all: POST actions must be refused with E-LIC-01.
	setTestLicense(t, nil)
	od, owg, ou := spoofDir, wgConfDir, engineUnitDir
	spoofDir, wgConfDir, engineUnitDir = t.TempDir(), t.TempDir(), t.TempDir()
	t.Cleanup(func() { spoofDir, wgConfDir, engineUnitDir = od, owg, ou })
	rr := httptest.NewRecorder()
	handleSpoofPost(rr, httptest.NewRequest("POST", "/api/spoof", strings.NewReader(`{"action":"genkeys"}`)))
	if apiCode(t, rr) != "E-LIC-01" {
		t.Fatalf("want E-LIC-01, got %q (%s)", apiCode(t, rr), rr.Body.String())
	}
}

func TestSpoofTesterParse(t *testing.T) {
	out := `[tester] loaded 3 source IPs
198.51.100.1 10/10 0.0%
198.51.100.2 8/10 20.0%
garbage line
[tester] 2/3 IPs passed`
	res := parseSpoofTesterOutput(out)
	if len(res) != 2 {
		t.Fatalf("want 2 results, got %d: %#v", len(res), res)
	}
	if res[0].IP != "198.51.100.1" || res[0].Received != 10 || res[1].LossPct != 20.0 {
		t.Fatalf("parsed wrong: %#v", res)
	}
}

func TestSpoofTesterStartStop(t *testing.T) {
	spoofLab(t)
	// A fake binary so engineBinaryPresent passes; skip where the exec bit
	// cannot be set (Windows), matching the repo's other exec-bit tests.
	bin := filepath.Join(t.TempDir(), spoofBinName)
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	ob := engineBinDirs
	engineBinDirs = []string{filepath.Dir(bin)}
	t.Cleanup(func() { engineBinDirs = ob })
	if !engineBinaryPresent(spoofBinName) {
		t.Skip("exec bit not settable here (verified in CI)")
	}

	srcFile := filepath.Join(spoofDir, "tester-sources.txt")
	spoofTesterRun = func(ctx context.Context, args []string) (string, error) {
		// The sources file must have been written before we run.
		if _, err := os.Stat(srcFile); err != nil {
			t.Errorf("sources file missing: %v", err)
		}
		<-ctx.Done() // wait for stop
		return "198.51.100.7 10/10 0.0%\n", nil
	}
	t.Cleanup(func() { spoofTesterRun = spoofTesterRunReal })

	if err := startSpoofTester(spoofTesterRequest{Action: "start", Mode: "receiver", Protocol: "icmp",
		Sources: []string{"198.51.100.0/24"}, Timeout: 30, PacketCount: 10, MaxLoss: 20}); err != nil {
		t.Fatal(err)
	}
	if spoofTesterView().Status != "running" {
		t.Fatal("tester should be running")
	}
	stopSpoofTester()
	spoofTesterWG.Wait() // the run goroutine must finish before cleanup
	if v := spoofTesterView(); v.Status != "stopped" {
		t.Fatalf("tester status %q (%s), want stopped", v.Status, v.Error)
	}

	// A run that reaches its timeout reports the binary's passing IPs.
	spoofTesterRun = func(ctx context.Context, args []string) (string, error) {
		return "[tester] loaded 256 source IPs\n198.51.100.7 10/10 0.0%\n", nil
	}
	if err := startSpoofTester(spoofTesterRequest{Action: "start", Mode: "receiver", Protocol: "icmp",
		Sources: []string{"198.51.100.0/24"}, Timeout: 30, PacketCount: 10, MaxLoss: 20}); err != nil {
		t.Fatal(err)
	}
	spoofTesterWG.Wait()
	v := spoofTesterView()
	if v.Status != "done" || len(v.Passed) != 1 || v.Passed[0].IP != "198.51.100.7" {
		t.Fatalf("finished run = %+v", v)
	}

	// A failing binary reports its own last log line, not "exit status 1".
	spoofTesterRun = func(ctx context.Context, args []string) (string, error) {
		return "2026/10/22 tester receiver: raw socket: operation not permitted\n", errors.New("exit status 1")
	}
	if err := startSpoofTester(spoofTesterRequest{Action: "start", Mode: "receiver", Protocol: "icmp",
		Sources: []string{"198.51.100.0/24"}, Timeout: 30, PacketCount: 10, MaxLoss: 20}); err != nil {
		t.Fatal(err)
	}
	spoofTesterWG.Wait()
	if v := spoofTesterView(); v.Status != "error" || !strings.Contains(v.Error, "operation not permitted") {
		t.Fatalf("failed run = %+v", v)
	}
}

// The Iran server makes the peer keypair itself, so "up" never stops on a
// missing peer key; making it twice keeps the same key.
func TestSpoofEnsurePeerKeypairKeepsKey(t *testing.T) {
	var s spoofState
	if err := s.ensurePeerKeypair(); err != nil {
		t.Fatal(err)
	}
	if s.WGPeerPub == "" || s.WGPeerPriv == "" {
		t.Fatal("the peer keypair was not made")
	}
	pub := s.WGPeerPub
	if err := s.ensurePeerKeypair(); err != nil {
		t.Fatal(err)
	}
	if s.WGPeerPub != pub {
		t.Fatal("a second call must keep the same peer key")
	}
}
