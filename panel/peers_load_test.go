package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// One record with values of the wrong type used to hide every tunnel.
func TestLoadPeersKeepsTheOthersWhenOneRecordIsOdd(t *testing.T) {
	defer withTempConfigDir(t)()
	doc := `{"peers": [
  {"id": 1, "name": "de", "frp_port": 7000, "ports": [443], "gre_if": "gre-tunnel", "frps_svc": "frps", "legacy": true},
  {"id": "2", "name": 42, "frp_port": "7002", "ports": "2083, 8080", "gre_if": "gre-t2", "frps_svc": "frps-2", "no_gre": "0", "legacy": "false"},
  {"id": 3, "name": "fi", "frp_port": 7003, "ports": ["8443", 9443], "gre_if": "gre-t3", "frps_svc": "frps-3"},
  {"id": "x", "name": "an id that is no number"}
]}`
	if err := os.WriteFile(peersFile(), []byte(doc), 0600); err != nil {
		t.Fatal(err)
	}
	peers := loadPeers()
	if len(peers) != 3 {
		t.Fatalf("loadPeers() = %d peers (%+v), want the 3 readable ones", len(peers), peers)
	}
	p2 := findPeer(2)
	if p2 == nil || p2.FrpPort != 7002 || p2.Name != "42" || len(p2.Ports) != 2 || p2.Ports[1] != 8080 || p2.Legacy {
		t.Fatalf("lenient record = %+v", p2)
	}
	if p3 := findPeer(3); p3 == nil || len(p3.Ports) != 2 || p3.Ports[0] != 8443 {
		t.Fatalf("mixed port list = %+v", p3)
	}
}

// A peers.json cut short falls back to the last copy that was read in full.
func TestLoadPeersFallsBackToTheLastGoodCopy(t *testing.T) {
	defer withTempConfigDir(t)()
	good := `{"peers": [{"id": 2, "name": "de", "frp_port": 7002, "ports": [443], "gre_if": "gre-t2", "frps_svc": "frps-2"}]}`
	if err := os.WriteFile(peersFile(), []byte(good), 0600); err != nil {
		t.Fatal(err)
	}
	if n := len(loadPeers()); n != 1 {
		t.Fatalf("good file: %d peers", n)
	}
	if _, err := os.Stat(peersBackupFile()); err != nil {
		t.Fatalf("no last good copy kept: %v", err)
	}
	if err := os.WriteFile(peersFile(), []byte(`{"peers": [{"id": 2, "na`), 0600); err != nil {
		t.Fatal(err)
	}
	if p := findPeer(2); p == nil || p.Name != "de" {
		t.Fatalf("a cut-short file must show the last good copy, got %+v", p)
	}
	// no peers.json at all is "no tunnels", whatever the old copy says
	os.Remove(peersFile())
	if n := len(loadPeers()); n != 0 {
		t.Fatalf("removed peers.json: %d peers", n)
	}
}

// Rewriting peers.json from loadPeers must not delete a record it could not read.
func TestWritePeersKeepsUnreadableRecords(t *testing.T) {
	defer withTempConfigDir(t)()
	doc := `{"peers": [{"id": 2, "name": "de", "frp_port": 7002}, {"id": "x", "name": "odd"}]}`
	if err := os.WriteFile(peersFile(), []byte(doc), 0600); err != nil {
		t.Fatal(err)
	}
	recs := loadPeers()
	if len(recs) != 1 {
		t.Fatalf("readable = %d", len(recs))
	}
	recs[0].Name = "de2"
	if err := writePeers(recs); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(peersFile())
	if !strings.Contains(string(data), `"de2"`) || !strings.Contains(string(data), `"odd"`) {
		t.Fatalf("rewrite = %s", data)
	}
	if _, err := os.Stat(peersFile() + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("temporary file left behind: %v", err)
	}
}

// A first tunnel whose GRE is gone and whose service is stopped is still shown
// (as down), so it can be seen, alerted on and removed.
func TestMainTunnelStaysWhenFullyDown(t *testing.T) {
	old := systemdUnitDir
	systemdUnitDir = t.TempDir()
	defer func() { systemdUnitDir = old }()
	v := &hostView{}
	st := tunnelStatus{Role: "iran (server)", FrpSvc: "frps", RemotePub: "198.51.100.7"}
	m := mainTunnelFrom(st, v)
	if m == nil || m.HealthState != stateDown || m.RemotePub != "198.51.100.7" {
		t.Fatalf("a configured first tunnel that is down: %+v", m)
	}
	// only a peer's unit: that is the peer, not a first tunnel
	if m := mainTunnelFrom(tunnelStatus{Role: "iran (backhaul)", FrpSvc: "backhaul-server-2"}, v); m != nil {
		t.Fatalf("a per-peer unit must not make a first tunnel: %+v", m)
	}
	// nothing configured: no first tunnel
	if m := mainTunnelFrom(tunnelStatus{Role: "iran (server)"}, v); m != nil {
		t.Fatalf("nothing configured: %+v", m)
	}
	// its GRE unit alone is enough
	if err := os.WriteFile(filepath.Join(systemdUnitDir, "gre-tunnel.service"), []byte("[Unit]\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if m := mainTunnelFrom(tunnelStatus{Role: "iran (server)"}, v); m == nil {
		t.Fatal("gre-tunnel.service on disk: the first tunnel must be shown")
	}
}
