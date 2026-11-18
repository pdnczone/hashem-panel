package main

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// The main frps and a peer's frps-2 are the same binary: only the unit
// (its cgroup) says whose a listening port is.
func TestFrpsUnitPorts(t *testing.T) {
	old := pidUnit
	t.Cleanup(func() { pidUnit = old })
	pidUnit = func(pid int, unit string) bool {
		return unit == "frps.service" && pid == 100
	}
	ss := `LISTEN 0      4096               *:7001             *:*    users:(("frps",pid=100,fd=7))
LISTEN 0      4096               *:55973            *:*    users:(("frps",pid=100,fd=10))
LISTEN 0      4096       0.0.0.0:7003       0.0.0.0:*    users:(("frps",pid=200,fd=7))
LISTEN 0      4096       0.0.0.0:23521      0.0.0.0:*    users:(("frps",pid=200,fd=9))
LISTEN 0      4096         [::]:55973          [::]:*    users:(("frps",pid=100,fd=11))
LISTEN 0      128        0.0.0.0:22         0.0.0.0:*    users:(("sshd",pid=1,fd=3))
`
	if got := frpsUnitPorts(ss, "frps.service"); !slices.Equal(got, []int{7001, 55973}) {
		t.Fatalf("got %v", got)
	}
	if got := frpsUnitPorts("", "frps.service"); got != nil {
		t.Fatalf("empty: %v", got)
	}
}

func TestFrpsProxyPorts(t *testing.T) {
	toml := filepath.Join(t.TempDir(), "frps.toml")
	_ = os.WriteFile(toml, []byte("bindPort = 7001\nkcpBindPort = 7001\nquicBindPort = 7002\nwebServer.port = 7500\n"), 0o600)
	got := frpsProxyPorts([]int{7001, 7002, 7500, 2096, 55973}, toml, 7001)
	if !slices.Equal(got, []int{2096, 55973}) {
		t.Fatalf("got %v", got)
	}
	// no config: only the bind port is its own
	if got := frpsProxyPorts([]int{7001, 443}, filepath.Join(t.TempDir(), "none.toml"), 7001); !slices.Equal(got, []int{443}) {
		t.Fatalf("no config: %v", got)
	}
}
