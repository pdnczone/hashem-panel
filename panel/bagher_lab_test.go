package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestBagherLabConfigs writes the files the panel generates for a Bagher
// tunnel, so tests/test_bagher_lab.sh runs the real thing (sshd, the panel's
// SSH carrier, frps, frpc) with exactly the panel's output. Runs only when the
// lab asks for it:
//
//	BAGHER_LAB_DIR=/tmp/x BAGHER_LAB_KEY=/tmp/x/id BAGHER_LAB_HOST=10.0.0.2 \
//	BAGHER_LAB_PORTS=18080,18081 [BAGHER_LAB_HOST2=10.0.1.2 BAGHER_LAB_PORTS2=18082] \
//	go test -run TestBagherLabConfigs
//
// With HOST2 a second foreign server is added as link 2 (frpc2.toml,
// authorized_keys2).
func TestBagherLabConfigs(t *testing.T) {
	dir := os.Getenv("BAGHER_LAB_DIR")
	if dir == "" {
		t.Skip("set BAGHER_LAB_DIR to generate the Bagher lab configs")
	}
	ports := labPorts(t, "BAGHER_LAB_PORTS")
	cfg := defaultSSHFwdConfig()
	cfg.RemoteHost = os.Getenv("BAGHER_LAB_HOST")
	cfg.KeyPath = os.Getenv("BAGHER_LAB_KEY")
	cfg.Ports = ports
	cfg.PoolCount = 5
	cfg.UDP = os.Getenv("BAGHER_LAB_UDP") == "1"
	if v := os.Getenv("BAGHER_LAB_FRP_PORT"); v != "" {
		cfg.FRPBindPort, _ = strconv.Atoi(v)
	}

	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	var link2 BagherLink
	if h := os.Getenv("BAGHER_LAB_HOST2"); h != "" {
		var err error
		if link2, err = addBagherLink(&cfg, BagherLink{RemoteHost: h, Ports: labPorts(t, "BAGHER_LAB_PORTS2")}); err != nil {
			t.Fatal(err)
		}
	}
	write("frps.toml", buildFRPSConfig(cfg))
	write("frpc.toml", buildFRPCConfig(cfg.FRPBindPort, cfg.PoolCount, cfg.Ports, cfg.UDP))
	if link2.ID != 0 {
		l := bagherLinkCfg(cfg, link2)
		write("frpc2.toml", buildFRPCConfig(l.FRPBindPort, l.PoolCount, l.Ports, l.UDP))
	}
	// The carrier reads the panel's own config file.
	old := configDir
	configDir = dir
	defer func() { configDir = old }()
	if err := saveSSHFwdConfigLocked(cfg); err != nil {
		t.Fatal(err)
	}
	write("unit.service", buildSSHFwdService(cfg))

	// authorized_keys on the Foreign side, written by the same code a peer
	// key install or a bundle apply uses.
	pub, err := os.ReadFile(cfg.KeyPath + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	oldAK := authorizedKeysPath
	defer func() { authorizedKeysPath = oldAK }()
	authorizedKeysPath = filepath.Join(dir, "authorized_keys")
	if err := installRestrictedKey(string(pub), "bagher", cfg.FRPBindPort, cfg.Ports); err != nil {
		t.Fatal(err)
	}
	if link2.ID != 0 {
		authorizedKeysPath = filepath.Join(dir, "authorized_keys2")
		if err := installRestrictedKey(string(pub), "bagher", cfg.FRPBindPort, link2.Ports); err != nil {
			t.Fatal(err)
		}
	}
}

func labPorts(t *testing.T, env string) []int {
	var ports []int
	for _, p := range strings.Split(os.Getenv(env), ",") {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil {
			t.Fatalf("%s: %v", env, err)
		}
		ports = append(ports, n)
	}
	return ports
}

// TestBagherLabCarrier runs the panel's carrier (gre-panel bagher-carrier)
// from the test binary, so the lab needs no separate build. It runs until
// killed:
//
//	GRE_PANEL_DIR=/tmp/x BAGHER_LAB_CARRIER_LINK=1 BAGHER_LAB_KNOWN=/tmp/x/kh \
//	bagherlab.test -test.run '^TestBagherLabCarrier$'
func TestBagherLabCarrier(t *testing.T) {
	link := os.Getenv("BAGHER_LAB_CARRIER_LINK")
	if link == "" {
		t.Skip("set BAGHER_LAB_CARRIER_LINK to run the Bagher carrier")
	}
	os.Exit(bagherCarrierCmd([]string{"-link", link, "-known-hosts", os.Getenv("BAGHER_LAB_KNOWN")}))
}
