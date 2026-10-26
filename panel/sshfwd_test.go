package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestSSHFwdFormatAuthorizedKeyLine(t *testing.T) {
	pub := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... test"

	// Bagher mode
	lineBagher := formatAuthorizedKeyLine(pub, "bagher", 55400, []int{443, 80})
	if !strings.Contains(lineBagher, "permitlisten=\"127.0.0.1:55400\"") {
		t.Fatalf("expected permitlisten for frp_bind_port, got: %s", lineBagher)
	}
	if !strings.Contains(lineBagher, "restrict,port-forwarding") {
		t.Fatalf("expected restrict,port-forwarding, got: %s", lineBagher)
	}
	// restrict alone still runs commands, and port-forwarding alone allows -L
	// anywhere (both proven in tests/test_bagher_lab.sh).
	if !strings.HasPrefix(lineBagher, `command="/bin/false",`) || !strings.Contains(lineBagher, `permitopen="127.0.0.1:55400"`) {
		t.Fatalf("bagher key must be locked to its tunnel port, got: %s", lineBagher)
	}

	// Direct mode
	lineDirect := formatAuthorizedKeyLine(pub, "direct", 55400, []int{443, 8443})
	if !strings.Contains(lineDirect, "permitopen=\"127.0.0.1:443\"") || !strings.Contains(lineDirect, "permitopen=\"127.0.0.1:8443\"") {
		t.Fatalf("expected permitopen list, got: %s", lineDirect)
	}
	if !strings.HasPrefix(lineDirect, `command="/bin/false",`) {
		t.Fatalf("direct key must not run commands, got: %s", lineDirect)
	}
}

// frpc 0.71 rejects unknown fields; transport.tcpKeepalive is frps-only and
// kept the Foreign frpc from starting, so Bagher carried no data at all.
func TestBagherFRPCConfigHasOnlyClientFields(t *testing.T) {
	c := buildFRPCConfig(55400, 5, []int{443}, true)
	if strings.Contains(c, "tcpKeepalive") {
		t.Fatalf("frpc config uses the frps-only field tcpKeepalive:\n%s", c)
	}
}

func TestSSHFwdBuildService(t *testing.T) {
	cfg := SSHFwdConfig{
		Mode:                "bagher",
		RemoteHost:          "1.2.3.4",
		RemoteUser:          "root",
		RemoteSSHPort:       22,
		KeyPath:             "/root/.ssh/hashem-fwd",
		Ports:               []int{443, 80},
		BindAddr:            "0.0.0.0",
		FRPBindPort:         55400,
		ServerAliveInterval: 10,
		ServerAliveCountMax: 3,
	}

	svc := buildSSHFwdService(cfg)
	if !strings.Contains(svc, "ExecStart=/usr/local/bin/gre-panel bagher-carrier -link 1\n") {
		t.Fatalf("bagher service must run the panel's carrier for link 1: %s", svc)
	}
	if !strings.Contains(svc, "Hashem Bagher Engine") {
		t.Fatalf("service description missing Bagher Engine: %s", svc)
	}
	cfg.Links = []BagherLink{{ID: 3, RemoteHost: "5.6.7.8", Ports: []int{9443}}}
	if svc3 := buildBagherCarrierUnit(cfg, 3); !strings.Contains(svc3, "bagher-carrier -link 3\n") || !strings.Contains(svc3, "to 5.6.7.8") {
		t.Fatalf("link 3 unit: %s", svc3)
	}

	// Direct mode test
	cfg.Mode = "direct"
	svcDirect := buildSSHFwdService(cfg)
	if !strings.Contains(svcDirect, "-L *:443:127.0.0.1:443") {
		t.Fatalf("direct service missing -L forward on every address: %s", svcDirect)
	}
	cfg.BindAddr = "2001:db8::7"
	if svc := buildSSHFwdService(cfg); !strings.Contains(svc, "-L [2001:db8::7]:443:127.0.0.1:443") {
		t.Fatalf("direct service on one IPv6 address: %s", svc)
	}
}

func TestSSHFwdBuildForeignSetupCommand(t *testing.T) {
	cfg := SSHFwdConfig{
		Mode:        "bagher",
		FRPBindPort: 55400,
		PoolCount:   25,
		Ports:       []int{443, 8443},
	}
	cmd := buildForeignSetupCommand(cfg)
	if !strings.Contains(cmd, "hashem-bagher-frpc.service") {
		t.Fatalf("foreign setup missing hashem-bagher-frpc.service: %s", cmd)
	}
	if !strings.Contains(cmd, "transport.poolCount = 25") {
		t.Fatalf("foreign setup missing poolCount: %s", cmd)
	}
	if !strings.Contains(cmd, "localPort = 443") || !strings.Contains(cmd, "localPort = 8443") {
		t.Fatalf("foreign setup missing proxy ports: %s", cmd)
	}
}

func TestSSHFwdDefaultConfig(t *testing.T) {
	cfg := defaultSSHFwdConfig()
	if cfg.Mode != "bagher" {
		t.Fatalf("expected default mode 'bagher', got: %s", cfg.Mode)
	}
	if cfg.FRPBindPort != 55400 {
		t.Fatalf("expected FRPBindPort 55400, got: %d", cfg.FRPBindPort)
	}
	if cfg.PoolCount != 5 {
		t.Fatalf("expected PoolCount 5, got: %d", cfg.PoolCount)
	}
	if len(cfg.Ports) != 0 {
		t.Fatalf("expected default Ports to be empty for clean installation, got: %v", cfg.Ports)
	}
}

func TestSSHFwdLicenseGating(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "hashem-lic-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	oldConfigDir := configDir
	configDir = tmpDir
	defer func() { configDir = oldConfigDir }()

	// Ensure no active license in memory or disk
	_ = os.Remove(filepath.Join(configDir, "license.key"))
	activeLicenseMu.Lock()
	oldLic := activeLicense
	activeLicense = nil
	activeLicenseMu.Unlock()
	defer func() {
		activeLicenseMu.Lock()
		activeLicense = oldLic
		activeLicenseMu.Unlock()
	}()

	// Test get_bundle gating via API
	bodyBundle := `{"action":"get_bundle"}`
	reqBundle := httptest.NewRequest("POST", "/api/ssh-fwd", strings.NewReader(bodyBundle))
	recBundle := httptest.NewRecorder()
	handleSSHFwdPost(recBundle, reqBundle)
	if recBundle.Code != http.StatusForbidden {
		t.Fatalf("expected status 403 Forbidden for un-licensed get_bundle, got %d", recBundle.Code)
	}

	// Test apply_bundle gating via API
	bodyApply := `{"action":"apply_bundle","bundle":"BAGHER:123"}`
	reqApply := httptest.NewRequest("POST", "/api/ssh-fwd", strings.NewReader(bodyApply))
	recApply := httptest.NewRecorder()
	handleSSHFwdPost(recApply, reqApply)
	if recApply.Code != http.StatusForbidden {
		t.Fatalf("expected status 403 Forbidden for un-licensed apply_bundle, got %d", recApply.Code)
	}

	// Test Bagher mode gating via API
	body := `{"action":"enable","mode":"bagher","remote_host":"1.2.3.4"}`
	req := httptest.NewRequest("POST", "/api/ssh-fwd", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handleSSHFwdPost(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected status 403 Forbidden for un-licensed Bagher Engine, got %d (body: %s)", rec.Code, rec.Body.String())
	}

	var res map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("invalid json returned: %v", err)
	}
	if res["error_code"] != "E-LIC-01" {
		t.Fatalf("expected error_code E-LIC-01, got %v", res["error_code"])
	}
	if !strings.Contains(res["error"].(string), "Bagher Engine requires a valid Premium license") {
		t.Fatalf("unexpected error message: %v", res["error"])
	}
}

func TestBagherBundleRoundtrip(t *testing.T) {
	cfg := SSHFwdConfig{
		Mode:          "bagher",
		RemoteHost:    "1.2.3.4",
		RemoteSSHPort: 22,
		FRPBindPort:   55400,
		PoolCount:     25,
		Ports:         []int{443, 8443, 1020},
		BindAddr:      "127.0.0.1",
	}
	pub := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGo345test hashem-bagher-carrier"

	bundleStr, err := MakeBagherBundle(cfg, pub)
	if err != nil {
		t.Fatalf("MakeBagherBundle failed: %v", err)
	}
	if !strings.HasPrefix(bundleStr, "BAGHER:") {
		t.Fatalf("expected bundle prefix 'BAGHER:', got: %s", bundleStr)
	}

	parsed, err := ParseBagherBundle(bundleStr)
	if err != nil {
		t.Fatalf("ParseBagherBundle failed: %v", err)
	}
	if parsed.FRPPort != 55400 {
		t.Errorf("expected FRPPort 55400, got: %d", parsed.FRPPort)
	}
	if parsed.PoolCount != 25 {
		t.Errorf("expected PoolCount 25, got: %d", parsed.PoolCount)
	}
	if len(parsed.Ports) != 3 || parsed.Ports[0] != 443 {
		t.Errorf("unexpected ports: %v", parsed.Ports)
	}
	if parsed.SSHPublicKey != pub {
		t.Errorf("expected pub key %q, got: %q", pub, parsed.SSHPublicKey)
	}

	// Corrupted bundle test
	if _, err := ParseBagherBundle("BAGHER:invalid-b64-here"); err == nil {
		t.Error("expected error parsing corrupted bundle, got nil")
	}
	if _, err := ParseBagherBundle("WRONGPREFIX:xxx"); err == nil {
		t.Error("expected error for wrong prefix, got nil")
	}
}

func TestBagherFormatByteSize(t *testing.T) {
	if formatByteSize(0) != "0 B" {
		t.Errorf("expected 0 B, got %s", formatByteSize(0))
	}
	if formatByteSize(500) != "500 B" {
		t.Errorf("expected 500 B, got %s", formatByteSize(500))
	}
	if formatByteSize(1024) != "1.0 KB" {
		t.Errorf("expected 1.0 KB, got %s", formatByteSize(1024))
	}
	if formatByteSize(1048576) != "1.0 MB" {
		t.Errorf("expected 1.0 MB, got %s", formatByteSize(1048576))
	}
	if formatByteSize(1073741824*2) != "2.0 GB" {
		t.Errorf("expected 2.0 GB, got %s", formatByteSize(1073741824*2))
	}
}

func TestBagherAPIEndpoints(t *testing.T) {
	activeLicenseMu.Lock()
	oldLic := activeLicense
	activeLicense = &LicensePayload{
		Customer:    "test",
		MachineHash: getMachineHash(),
		Features:    []string{"bagher", "frp_ssh"},
		ExpiresAt:   time.Now().Add(24 * time.Hour).Unix(),
	}
	activeLicenseMu.Unlock()
	defer func() {
		activeLicenseMu.Lock()
		activeLicense = oldLic
		activeLicenseMu.Unlock()
	}()

	// Test get_bundle without remote_host (should fail with 400)
	bodyNoHost := `{"action":"get_bundle"}`
	reqNoHost := httptest.NewRequest("POST", "/api/sshfwd", strings.NewReader(bodyNoHost))
	recNoHost := httptest.NewRecorder()
	handleSSHFwdPost(recNoHost, reqNoHost)
	if recNoHost.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for get_bundle without remote host, got %d", recNoHost.Code)
	}

	// Test get_bundle with valid remote_host and ports
	body := `{"action":"get_bundle","remote_host":"198.51.100.73","ports":"443,8443"}`
	req := httptest.NewRequest("POST", "/api/sshfwd", strings.NewReader(body))
	rec := httptest.NewRecorder()
	handleSSHFwdPost(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for get_bundle, got %d (body: %s)", rec.Code, rec.Body.String())
	}
	var res map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("invalid json from get_bundle: %v", err)
	}
	bundleStr, ok := res["bundle"].(string)
	if !ok || !strings.HasPrefix(bundleStr, "BAGHER:") {
		t.Fatalf("expected bundle starting with BAGHER:, got: %v", res["bundle"])
	}

	// Test apply_bundle with empty bundle
	bodyEmpty := `{"action":"apply_bundle","bundle":""}`
	reqEmpty := httptest.NewRequest("POST", "/api/sshfwd", strings.NewReader(bodyEmpty))
	recEmpty := httptest.NewRecorder()
	handleSSHFwdPost(recEmpty, reqEmpty)
	if recEmpty.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty bundle, got %d", recEmpty.Code)
	}

	// Test apply_bundle with invalid bundle
	bodyInvalid := `{"action":"apply_bundle","bundle":"NOT_BAGHER_FORMAT"}`
	reqInvalid := httptest.NewRequest("POST", "/api/sshfwd", strings.NewReader(bodyInvalid))
	recInvalid := httptest.NewRecorder()
	handleSSHFwdPost(recInvalid, reqInvalid)
	if recInvalid.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid bundle prefix, got %d", recInvalid.Code)
	}
}

func TestSSHFwdServiceBackoff(t *testing.T) {
	cfg := SSHFwdConfig{
		Mode:          "bagher",
		RemoteHost:    "1.2.3.4",
		RemoteUser:    "root",
		RemoteSSHPort: 22,
		KeyPath:       "/etc/gre-panel/sshfwd_id_ed25519",
		Ports:         []int{443, 8443},
		BindAddr:      "127.0.0.1",
		FRPBindPort:   55400,
	}

	svc := buildSSHFwdService(cfg)
	if !strings.Contains(svc, "RestartSec=15") {
		t.Fatalf("expected RestartSec=15 for fail2ban protection, got:\n%s", svc)
	}
	if !strings.Contains(svc, "StartLimitIntervalSec=120") {
		t.Fatalf("expected StartLimitIntervalSec=120 in service unit, got:\n%s", svc)
	}
	if !strings.Contains(svc, "After=network-online.target hashem-bagher-frps.service") {
		t.Fatalf("the carrier must start after frps, got:\n%s", svc)
	}
}

func TestIsPrivateIP(t *testing.T) {
	if !isPrivateIP("127.0.0.1") {
		t.Fatalf("expected 127.0.0.1 to be private")
	}
	if !isPrivateIP("10.0.0.5") {
		t.Fatalf("expected 10.0.0.5 to be private")
	}
	if !isPrivateIP("172.16.5.1") {
		t.Fatalf("expected 172.16.5.1 to be private")
	}
	if !isPrivateIP("172.26.32.7") {
		t.Fatalf("expected 172.26.32.7 to be private")
	}
	if !isPrivateIP("192.168.1.100") {
		t.Fatalf("expected 192.168.1.100 to be private")
	}
	if isPrivateIP("1.1.1.1") {
		t.Fatalf("expected 1.1.1.1 to be public")
	}
	if isPrivateIP("8.8.8.8") {
		t.Fatalf("expected 8.8.8.8 to be public")
	}
}

func TestBagherBundleGeneration(t *testing.T) {
	cfg := SSHFwdConfig{
		Role:        "iran",
		RemoteHost:  "198.51.100.1",
		Ports:       []int{443, 8443},
		FRPBindPort: 55400,
		PoolCount:   25,
	}
	pubKey := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKey hashem-fwd"
	bundleStr, err := MakeBagherBundle(cfg, pubKey)
	if err != nil {
		t.Fatalf("failed to make bundle: %v", err)
	}
	if !strings.HasPrefix(bundleStr, "BAGHER:") {
		t.Fatalf("expected bundle prefix BAGHER:, got: %s", bundleStr)
	}

	bundle, err := ParseBagherBundle(bundleStr)
	if err != nil {
		t.Fatalf("failed to parse bundle: %v", err)
	}
	if bundle.Role != "foreign" {
		t.Fatalf("expected foreign role in bundle, got: %s", bundle.Role)
	}
	if bundle.RemoteHost != "198.51.100.1" {
		t.Fatalf("expected remote host 198.51.100.1, got: %s", bundle.RemoteHost)
	}
	if len(bundle.Ports) != 2 || bundle.Ports[0] != 443 || bundle.Ports[1] != 8443 {
		t.Fatalf("unexpected ports in bundle: %v", bundle.Ports)
	}
}

func testPubKey(t *testing.T, comment string) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sp, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sp))) + " " + comment
}

// C4: a peer-supplied key must not inject extra lines or wipe other keys.
func TestInstallRestrictedKeyValidation(t *testing.T) {
	old := authorizedKeysPath
	authorizedKeysPath = filepath.Join(t.TempDir(), "authorized_keys")
	t.Cleanup(func() { authorizedKeysPath = old })

	admin := testPubKey(t, "admin@laptop")
	if err := os.WriteFile(authorizedKeysPath, []byte(admin+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	peer := testPubKey(t, "bagher")
	attacker := testPubKey(t, "attacker")

	for _, bad := range []string{
		"ssh",
		"ssh-ed25519",
		peer + "\n" + attacker,
		`command="/bin/sh" ` + peer,
		"not-a-key AAAA",
	} {
		if err := installRestrictedKey(bad, "bagher", 55400, nil); err == nil {
			t.Fatalf("accepted bad key %q", bad)
		}
	}
	data, _ := os.ReadFile(authorizedKeysPath)
	if string(data) != admin+"\n" {
		t.Fatalf("rejected keys modified authorized_keys: %q", data)
	}

	if err := installRestrictedKey(peer, "bagher", 55400, nil); err != nil {
		t.Fatal(err)
	}
	// Re-installing the same key (different comment) replaces its line.
	if err := installRestrictedKey(strings.TrimSuffix(peer, " bagher")+" renamed", "bagher", 55401, nil); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(authorizedKeysPath)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 || lines[0] != admin {
		t.Fatalf("unexpected authorized_keys:\n%s", data)
	}
	if !strings.HasPrefix(lines[1], `command="/bin/false",restrict,port-forwarding,permitlisten="127.0.0.1:55401",permitopen="127.0.0.1:55401" ssh-ed25519 `) {
		t.Fatalf("peer key not restricted: %s", lines[1])
	}
}

// Keys written by older panels are upgraded in place; other keys stay as they are.
func TestUpgradeBagherKeyLocks(t *testing.T) {
	old := authorizedKeysPath
	authorizedKeysPath = filepath.Join(t.TempDir(), "authorized_keys")
	t.Cleanup(func() { authorizedKeysPath = old })
	bagher := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOKlYNIwJmKAWfCv6ik2l9WhPl3ESB5oTPSJ41vr1bFN"
	admin := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBfz1IUl3T0hKUFvTGxbuF+R2pbdlVxSNMhhD7m0NZ8i admin@laptop"
	custom := `restrict,port-forwarding,permitlisten="127.0.0.1:9000",permitopen="10.0.0.1:22" ` + admin
	in := `restrict,port-forwarding,permitlisten="127.0.0.1:55401" ` + bagher + "\n" + admin + "\n" + custom + "\n"
	if err := os.WriteFile(authorizedKeysPath, []byte(in), 0600); err != nil {
		t.Fatal(err)
	}
	n, err := upgradeBagherKeyLocks()
	if err != nil || n != 1 {
		t.Fatalf("upgraded %d keys (err %v), want 1", n, err)
	}
	got, _ := os.ReadFile(authorizedKeysPath)
	lines := strings.Split(strings.TrimSpace(string(got)), "\n")
	want := `command="/bin/false",restrict,port-forwarding,permitlisten="127.0.0.1:55401",permitopen="127.0.0.1:55401" ` + bagher
	if len(lines) != 3 || lines[0] != want || lines[1] != admin || lines[2] != custom {
		t.Fatalf("unexpected authorized_keys:\n%s", got)
	}
	if n, _ := upgradeBagherKeyLocks(); n != 0 {
		t.Fatalf("second run upgraded %d keys, want 0", n)
	}
}

// frpc reaches frps through the SSH tunnel: frp's own TLS (default on since
// 0.50) would encrypt everything twice and cost a handshake per work conn.
func TestBagherFRPCConfigTurnsOffFRPTLS(t *testing.T) {
	c := buildFRPCConfig(55400, 5, []int{443}, false)
	if !strings.Contains(c, "\ntransport.tls.enable = false\n") || strings.Index(c, "tls.enable") > strings.Index(c, "[[proxies]]") {
		t.Fatalf("frpc config must turn off frp TLS as a top-level key:\n%s", c)
	}
}

func TestMigrateBagherFRPCTLS(t *testing.T) {
	var ran []string
	old := runCmd
	runCmd = func(name string, args ...string) (string, error) {
		ran = append(ran, name+" "+strings.Join(args, " "))
		return "", nil
	}
	defer func() { runCmd = old }()

	dir := t.TempDir()
	p := filepath.Join(dir, "frpc.toml")
	if ok, err := migrateBagherFRPCTLS(p); ok || err != nil {
		t.Fatalf("no file must be a no-op, got %v %v", ok, err)
	}
	legacy := "serverAddr = \"127.0.0.1\"\nserverPort = 55400\ntransport.tcpMux = false\n\n[[proxies]]\nname = \"p443\"\n"
	_ = os.WriteFile(p, []byte(legacy), 0o600)
	if ok, err := migrateBagherFRPCTLS(p); !ok || err != nil {
		t.Fatalf("an old frpc.toml must be migrated, got %v %v", ok, err)
	}
	got, _ := os.ReadFile(p)
	if string(got) != "transport.tls.enable = false\n"+legacy {
		t.Fatalf("the key must come first, before any table:\n%s", got)
	}
	if len(ran) != 1 || ran[0] != "systemctl try-restart hashem-bagher-frpc.service" {
		t.Fatalf("a running frpc must be restarted once, ran %q", ran)
	}
	if ok, _ := migrateBagherFRPCTLS(p); ok {
		t.Fatal("a second start must not touch the file again")
	}
	_ = os.WriteFile(p, []byte("transport.tls.enable = true\n"+legacy), 0o600)
	if ok, _ := migrateBagherFRPCTLS(p); ok {
		t.Fatal("a file that sets TLS itself must be left alone")
	}
	_ = os.WriteFile(p, []byte("serverPort = 55400\n\n[transport]\ntcpMux = false\n"), 0o600)
	if ok, _ := migrateBagherFRPCTLS(p); ok {
		t.Fatal("a file with a [transport] table must be left alone (the dotted key would be invalid TOML)")
	}
}
