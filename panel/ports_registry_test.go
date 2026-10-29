package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// registryEnv points every config the registry reads at a fresh dir.
func registryEnv(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	oldC, oldF, oldB, oldPort, oldTLS := configDir, frpDir, backhaulDir, cfg.Port, cfg.TLSPort
	configDir, frpDir, backhaulDir = dir, filepath.Join(dir, "frp"), filepath.Join(dir, "backhaul")
	cfg.Port, cfg.TLSPort = 2096, 0
	_ = os.MkdirAll(frpDir, 0o700)
	_ = os.MkdirAll(backhaulDir, 0o700)
	clusterCache = nil
	t.Cleanup(func() {
		configDir, frpDir, backhaulDir, cfg.Port, cfg.TLSPort = oldC, oldF, oldB, oldPort, oldTLS
		clusterCache = nil
	})
	return dir
}

func writeJSONFile(t *testing.T, path string, v any) {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func registryFixture(t *testing.T) {
	dir := registryEnv(t)
	writeJSONFile(t, filepath.Join(dir, "peers.json"), map[string]any{"peers": []peerRecord{
		{ID: 1, Name: "de-1", FrpPort: 7000, Ports: []int{443, 8443}},
		{ID: 2, Name: "nl-2", FrpPort: 7001, Ports: []int{2053}, RawPorts: portList{"3000-3002=4000"}},
	}})
	b := bagherTestCfg() // 443, 8443 on link 1: overlap on purpose, the check is per caller
	b.Enabled, b.Ports, b.UDP = true, []int{9443}, true
	if err := saveSSHFwdConfigLocked(b); err != nil {
		t.Fatal(err)
	}
	writeJSONFile(t, xrayStatePath(), xrayState{Links: []XrayLink{
		{ID: 1, Mode: "reverse", Side: xraySideIran, TunnelPort: 10443, Ports: []int{2087}, UDP: true, Profile: XrayProfile{Transport: "tcp"}},
	}})
	if err := os.WriteFile(filepath.Join(frpDir, "frps-9.toml"), []byte("bindPort = 7009\nquicBindPort = 7010\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(backhaulDir, "server-3.toml"), []byte("[server]\nbind_addr = \"0.0.0.0:3080\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := defaultClusterConfig()
	c.Pools = []LBPool{{Port: 2083, Proto: "tcp", Mode: "failover"}}
	if err := saveClusterConfig(c); err != nil {
		t.Fatal(err)
	}
}

func TestPortRegistryClaims(t *testing.T) {
	registryFixture(t)
	claims := hashemPortClaims()
	for _, c := range []struct {
		proto string
		port  int
		want  string
	}{
		{"tcp", 2096, "the panel"},
		{"tcp", 443, "peer de-1"},
		{"udp", 443, "peer de-1"},
		{"tcp", 3001, "peer nl-2"}, // a Backhaul range, expanded
		{"tcp", 7001, "control port of peer nl-2"},
		{"tcp", 7009, "frps-9"},
		{"udp", 7010, "frps-9"},
		{"tcp", 3080, "Backhaul (server-3)"},
		{"udp", 9443, "Bagher (foreign server 1)"},
		{"tcp", 55401, "Bagher's internal FRP port"},
		{"tcp", 2087, "Xray tunnel link 1"},
		{"udp", 2087, "Xray tunnel link 1"},
		{"tcp", 10443, "Xray tunnel link 1"},
		{"tcp", 2083, "cluster pool"},
	} {
		if got := claimOwner(claims, c.proto, c.port, nil); !strings.Contains(got, c.want) {
			t.Errorf("%s/%d: owner %q, want %q", c.proto, c.port, got, c.want)
		}
	}
	if got := claimOwner(claims, "udp", 2083, nil); got != "" {
		t.Errorf("a tcp pool claims udp: %q", got)
	}
	if got := claimOwner(claims, "tcp", 3003, nil); got != "" {
		t.Errorf("past the range: %q", got)
	}
}

func TestPeerPortClashUsesRegistry(t *testing.T) {
	registryFixture(t)
	for _, c := range []struct {
		ports   []int
		exclude int
		want    string
	}{
		{[]int{443}, -1, "443 (peer de-1)"},
		{[]int{443, 8443}, 1, ""},        // editing peer 1 keeps its own ports
		{[]int{2053}, 1, "peer nl-2"},    // but not another peer's
		{[]int{2083}, -1, ""},            // a pool port may be served by several tunnels
		{[]int{2087}, -1, "Xray"},        // Xray's user port
		{[]int{9443}, -1, "Bagher"},      // Bagher's
		{[]int{2096}, -1, "the panel"},   // the panel's own port
		{[]int{7009}, -1, "frps-9"},      // a relay's control port
		{[]int{7001}, 2, "control port"}, // even the peer's own control port
		{[]int{5555}, -1, ""},
	} {
		got := peerPortClash(c.ports, c.exclude)
		if (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
			t.Errorf("peerPortClash(%v, %d) = %q, want %q", c.ports, c.exclude, got, c.want)
		}
	}
}

func TestBagherPortsUseRegistry(t *testing.T) {
	registryFixture(t)
	b := loadSSHFwdConfigLocked()
	if err := checkBagherLinkPorts(b, []int{9443}, 1); err != nil {
		t.Errorf("Bagher's own port on its own link: %v", err)
	}
	if err := checkBagherLinkPorts(b, []int{9443}, 2); err == nil || !strings.Contains(err.Error(), "foreign server 1") {
		t.Errorf("another Bagher link's port: %v", err)
	}
	for port, want := range map[int]string{443: "peer de-1", 2087: "Xray", 2096: "the panel", 7000: "control port"} {
		if err := checkBagherLinkPorts(b, []int{port}, 1); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("port %d: %v, want %q", port, err, want)
		}
	}
	if err := checkBagherLinkPorts(b, []int{2083, 6000}, 1); err != nil {
		t.Errorf("pool and free ports: %v", err)
	}
}

func TestXrayClaimedPortsUseRegistry(t *testing.T) {
	registryFixture(t)
	m := xrayClaimedPorts(XrayLink{ID: 1, Side: xraySideIran})
	for k, want := range map[string]string{"tcp:443": "peer de-1", "udp:9443": "Bagher", "tcp:2096": "the panel", "tcp:2083": "cluster pool"} {
		if !strings.Contains(m[k], want) {
			t.Errorf("%s: %q, want %q", k, m[k], want)
		}
	}
	if m["tcp:2087"] != "" {
		t.Errorf("Xray's own claims belong to xrayPortConflicts: %q", m["tcp:2087"])
	}
}

func TestValidatePoolUsesRegistry(t *testing.T) {
	registryFixture(t)
	c := loadClusterConfig()
	pool := func(port int) LBPool { return LBPool{Port: port, Proto: "both", Mode: "failover"} }
	if code, msg := validatePool(c, pool(443), -1); code != "" {
		t.Errorf("a pool over peers' user port: %s %s", code, msg)
	}
	for port, want := range map[int]string{2087: "Xray", 9443: "Bagher"} {
		if code, msg := validatePool(c, pool(port), -1); code != "E-CLUSTER-03" || !strings.Contains(msg, want) {
			t.Errorf("port %d: %s %q, want %q", port, code, msg, want)
		}
	}
}
