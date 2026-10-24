package main

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

// A Backhaul peer written by an older hashem.sh has raw_ports as one string.
// It used to fail the whole decode, so every peer tunnel vanished from the panel.
func TestLoadPeersReadsStringRawPorts(t *testing.T) {
	old := configDir
	configDir = t.TempDir()
	defer func() { configDir = old }()

	doc := `{"peers": [
  {"id": 1, "name": "de", "frp_port": 7000, "ports": [443], "gre_if": "gre-tunnel", "frps_svc": "frps"},
  {"id": 2, "name": "nl", "frp_port": 3080, "ports": [2083, 8080], "gre_if": "none", "frps_svc": "backhaul-server-2",
   "engine": "backhaul", "no_gre": true, "raw_ports": "2083, 8080=9090"},
  {"id": 3, "name": "fi", "frp_port": 7003, "ports": [8443], "gre_if": "gre-t3", "frps_svc": "frps-3", "raw_ports": ["8443"]}
]}`
	if err := os.WriteFile(peersFile(), []byte(doc), 0600); err != nil {
		t.Fatal(err)
	}
	peers := loadPeers()
	if len(peers) != 3 {
		t.Fatalf("loadPeers() = %d peers, want 3", len(peers))
	}
	if want := (portList{"2083", "8080=9090"}); !reflect.DeepEqual(peers[1].RawPorts, want) {
		t.Errorf("string raw_ports = %q, want %q", peers[1].RawPorts, want)
	}
	if want := (portList{"8443"}); !reflect.DeepEqual(peers[2].RawPorts, want) {
		t.Errorf("list raw_ports = %q, want %q", peers[2].RawPorts, want)
	}
	// written back as a list
	out, _ := json.Marshal(peers[1])
	var back struct {
		RawPorts []string `json:"raw_ports"`
	}
	if err := json.Unmarshal(out, &back); err != nil || len(back.RawPorts) != 2 {
		t.Errorf("re-encoded raw_ports = %s (%v)", out, err)
	}
}
