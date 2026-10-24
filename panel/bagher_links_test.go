package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
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

func bagherTestCfg() SSHFwdConfig {
	cfg := defaultSSHFwdConfig()
	cfg.RemoteHost = "198.51.100.1"
	cfg.Ports = []int{443, 8443}
	return cfg
}

func TestAddBagherLink(t *testing.T) {
	cfg := bagherTestCfg()
	l, err := addBagherLink(&cfg, BagherLink{RemoteHost: " 198.51.100.2 ", Ports: []int{2053, 2083}, UDP: true})
	if err != nil || l.ID != 2 || l.RemoteHost != "198.51.100.2" {
		t.Fatalf("first extra link: %+v %v", l, err)
	}
	l3, err := addBagherLink(&cfg, BagherLink{RemoteHost: "fo3.example.com", Ports: []int{2096}, RemoteSSHPort: 2222, RemoteUser: "tunnel"})
	if err != nil || l3.ID != 3 || len(cfg.Links) != 2 {
		t.Fatalf("second extra link: %+v %v", l3, err)
	}
	for _, c := range []struct {
		name string
		l    BagherLink
		want string
	}{
		{"port of link 1", BagherLink{RemoteHost: "198.51.100.9", Ports: []int{8443}}, "foreign server 1"},
		{"port of link 2", BagherLink{RemoteHost: "198.51.100.9", Ports: []int{2083}}, "foreign server 2"},
		{"internal FRP port", BagherLink{RemoteHost: "198.51.100.9", Ports: []int{55401}}, "internal FRP"},
		{"same host as link 1", BagherLink{RemoteHost: "198.51.100.1", Ports: []int{9000}}, "already"},
		{"same host as link 3", BagherLink{RemoteHost: "fo3.example.com", Ports: []int{9000}}, "already"},
		{"no ports", BagherLink{RemoteHost: "198.51.100.9"}, "port"},
		{"unit injection", BagherLink{RemoteHost: "1.2.3.4\nExecStartPre=/bin/sh", Ports: []int{9000}}, "invalid"},
		{"bad user", BagherLink{RemoteHost: "198.51.100.9", RemoteUser: "root;id", Ports: []int{9000}}, "invalid SSH user"},
	} {
		if _, err := addBagherLink(&cfg, c.l); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err %v, want %q", c.name, err, c.want)
		}
	}
	if len(cfg.Links) != 2 {
		t.Fatalf("refused links must not be added: %+v", cfg.Links)
	}
	// ids are never reused while a higher one exists
	if !removeBagherLink(&cfg, 2) || removeBagherLink(&cfg, 2) {
		t.Fatal("remove link 2 once")
	}
	l4, _ := addBagherLink(&cfg, BagherLink{RemoteHost: "198.51.100.4", Ports: []int{2053}})
	if l4.ID != 4 {
		t.Fatalf("new id after removal: %d", l4.ID)
	}
}

func TestAddBagherLinkNeedsFirstServer(t *testing.T) {
	cfg := defaultSSHFwdConfig()
	if _, err := addBagherLink(&cfg, BagherLink{RemoteHost: "198.51.100.2", Ports: []int{443}}); err == nil {
		t.Fatal("a second foreign server needs the first one set up")
	}
}

// Each link's bundle carries that foreign server's own ports and SSH port,
// and the config survives a save and load with its links.
func TestBagherLinkBundleAndPersistence(t *testing.T) {
	dir := t.TempDir()
	old := configDir
	configDir = dir
	t.Cleanup(func() { configDir = old })

	cfg := bagherTestCfg()
	l, err := addBagherLink(&cfg, BagherLink{RemoteHost: "198.51.100.2", RemoteSSHPort: 2222, Ports: []int{2053}, UDP: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := saveSSHFwdConfigLocked(cfg); err != nil {
		t.Fatal(err)
	}
	got := loadSSHFwdConfigLocked()
	if len(got.Links) != 1 || got.Links[0].RemoteHost != "198.51.100.2" || got.Links[0].Ports[0] != 2053 {
		t.Fatalf("links after reload: %+v", got.Links)
	}
	bundle, err := MakeBagherBundle(bagherLinkCfg(got, l), "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOnTRjS0jM0VjLzF8N0O3Cz6k0d9xq5Kkqk6a2o3x0k9 test")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(bundle, "BAGHER:"))
	var b BagherBundle
	_ = json.Unmarshal(raw, &b)
	if b.RemoteHost != "198.51.100.2" || len(b.Ports) != 1 || b.Ports[0] != 2053 || !b.UDP || b.SSHPort != 2222 || b.FRPPort != 55400 {
		t.Fatalf("link bundle: %+v", b)
	}
	if lc := bagherLinkCfg(got, l); len(lc.Links) != 0 || lc.RemoteHost != "198.51.100.2" {
		t.Fatalf("link view: %+v", lc)
	}
}

func TestBagherLinkUp(t *testing.T) {
	online := map[string]bool{"p443": true, "p2053": false, "u2053": true}
	if !bagherLinkUp(online, []int{80, 443}) || bagherLinkUp(online, []int{2053}) {
		t.Fatal("a link is up when one of its TCP proxies is online")
	}
}

func TestBagherLinkAPI(t *testing.T) {
	dir := t.TempDir()
	old := configDir
	configDir = dir
	t.Cleanup(func() { configDir = old })
	activeLicenseMu.Lock()
	oldLic := activeLicense
	activeLicense = &LicensePayload{Customer: "test", MachineHash: getMachineHash(), Features: []string{"bagher"}, ExpiresAt: time.Now().Add(time.Hour).Unix()}
	activeLicenseMu.Unlock()
	t.Cleanup(func() { activeLicenseMu.Lock(); activeLicense = oldLic; activeLicenseMu.Unlock() })

	oldRun := runCmd
	runCmd = func(name string, args ...string) (string, error) { return "", nil } // no systemctl on the test host
	t.Cleanup(func() { runCmd = oldRun })

	// a key on disk, so no ssh-keygen runs
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	sp, _ := ssh.NewPublicKey(pub)
	keyPath := filepath.Join(dir, "hashem-fwd")
	_ = os.WriteFile(keyPath, []byte("unused"), 0600)
	_ = os.WriteFile(keyPath+".pub", ssh.MarshalAuthorizedKey(sp), 0600)
	cfg := bagherTestCfg()
	cfg.KeyPath = keyPath
	if err := saveSSHFwdConfigLocked(cfg); err != nil {
		t.Fatal(err)
	}

	post := func(body string) (int, map[string]any) {
		rec := httptest.NewRecorder()
		handleSSHFwdPost(rec, httptest.NewRequest("POST", "/api/sshfwd", strings.NewReader(body)))
		var m map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &m)
		return rec.Code, m
	}
	code, m := post(`{"action":"add_link","remote_host":"198.51.100.2","ports":"2053, 2083","udp":true,"ssh_port":2222}`)
	if code != http.StatusOK || m["id"].(float64) != 2 || !strings.HasPrefix(m["bundle"].(string), "BAGHER:") {
		t.Fatalf("add_link: %d %v", code, m)
	}
	st := m["status_data"].(map[string]any)
	links := st["links"].([]any)
	if len(links) != 1 || links[0].(map[string]any)["remote_host"] != "198.51.100.2" || links[0].(map[string]any)["bundle"] == nil {
		t.Fatalf("status links: %v", st["links"])
	}
	if code, m = post(`{"action":"add_link","remote_host":"198.51.100.3","ports":"443"}`); code != http.StatusBadRequest {
		t.Fatalf("a port of link 1 must be refused: %d %v", code, m)
	}
	// the first server cannot take a port of link 2 either
	if code, m = post(`{"action":"enable","remote_host":"198.51.100.1","ports":"443, 2053"}`); code != http.StatusBadRequest {
		t.Fatalf("enable with link 2's port must be refused: %d %v", code, m)
	}
	if code, m = post(`{"action":"remove_link","id":2}`); code != http.StatusOK {
		t.Fatalf("remove_link: %d %v", code, m)
	}
	if code, _ = post(`{"action":"remove_link","id":2}`); code != http.StatusBadRequest {
		t.Fatalf("removing twice: %d", code)
	}
	if got := loadSSHFwdConfigLocked(); len(got.Links) != 0 {
		t.Fatalf("links after removal: %+v", got.Links)
	}
}

func TestMigrateBagherCarrierUnit(t *testing.T) {
	dir := t.TempDir()
	old := configDir
	configDir = dir
	t.Cleanup(func() { configDir = old })
	var calls []string
	oldRun := runCmd
	runCmd = func(name string, args ...string) (string, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return "", nil
	}
	t.Cleanup(func() { runCmd = oldRun })

	cfg := bagherTestCfg()
	cfg.KeyPath = filepath.Join(dir, "hashem-fwd")
	_ = os.WriteFile(cfg.KeyPath, []byte("k"), 0600)
	if err := saveSSHFwdConfigLocked(cfg); err != nil {
		t.Fatal(err)
	}
	// the unit v2.6.0 wrote
	legacy := "[Unit]\nDescription=Hashem Bagher Engine (Stealth Hybrid Tunnel)\n\n[Service]\n" +
		"ExecStart=/usr/bin/ssh -N -i " + cfg.KeyPath + " -o BatchMode=yes -o IdentitiesOnly=yes -o ExitOnForwardFailure=yes -o ConnectTimeout=8 " +
		"-o ServerAliveInterval=15 -o ServerAliveCountMax=3 -o StrictHostKeyChecking=accept-new -R 127.0.0.1:55400:127.0.0.1:55400 " +
		"-o Ciphers=aes128-gcm@openssh.com,chacha20-poly1305@openssh.com -o TCPKeepAlive=yes root@198.51.100.1\nRestart=always\n"
	unit := filepath.Join(dir, "hashem-bagher.service")
	_ = os.WriteFile(unit, []byte(legacy), 0644)
	if ok, err := migrateBagherCarrierUnit(unit); !ok || err != nil {
		t.Fatalf("legacy unit not migrated: %v %v", ok, err)
	}
	got, _ := os.ReadFile(unit)
	if !strings.Contains(string(got), "bagher-carrier -link 1") || strings.Contains(string(got), "/usr/bin/ssh") {
		t.Fatalf("migrated unit: %s", got)
	}
	if strings.Join(calls, "; ") != "systemctl daemon-reload; systemctl try-restart hashem-bagher.service" {
		t.Fatalf("systemctl calls: %v", calls)
	}
	// already the carrier: nothing to do
	if ok, _ := migrateBagherCarrierUnit(unit); ok {
		t.Fatal("a carrier unit must not be migrated again")
	}
	// a unit for another host (written by the CLI, say) is left alone
	_ = os.WriteFile(unit, []byte(strings.Replace(legacy, "root@198.51.100.1", "root@198.51.100.99", 1)), 0644)
	if ok, _ := migrateBagherCarrierUnit(unit); ok {
		t.Fatal("a unit for another foreign server must be left alone")
	}
}
