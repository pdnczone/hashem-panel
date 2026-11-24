package main

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// An Iran server's Backhaul config with a range: the status keeps the entry
// as written (for display and editing) and lists every port it listens on
// (it used to list 1051 alone, so the card read "1 port").
func TestBackhaulStatusExpandsRanges(t *testing.T) {
	oldBh, oldCfg := backhaulDir, configDir
	backhaulDir, configDir = t.TempDir(), t.TempDir()
	t.Cleanup(func() { backhaulDir, configDir = oldBh, oldCfg })
	conf := "[server]\nbind_addr = \"0.0.0.0:7001\"\ntransport = \"tcpmux\"\nports = [\n  \"1051-1060\",\n  \"2083=8443\",\n  \"203.0.113.5:9000-9001=443\",\n  \"3000-3002:5201\",\n]\n"
	if err := os.WriteFile(filepath.Join(backhaulDir, "config.toml"), []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	st := localStatusFrom(&hostView{active: map[string]bool{"backhaul-server": true}})
	if !slices.Equal(st.Proxies, []string{"1051-1060", "2083=8443", "203.0.113.5:9000-9001=443", "3000-3002:5201"}) {
		t.Fatalf("entries as written: %v", st.Proxies)
	}
	want := []int{1051, 1052, 1053, 1054, 1055, 1056, 1057, 1058, 1059, 1060, 2083, 9000, 9001, 3000, 3001, 3002}
	got := slices.Clone(st.ProxyPorts)
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("every listening port: %v", st.ProxyPorts)
	}
}

// A Backhaul peer stores the first port of each entry; whatever asks which
// ports are taken reads every port of its ranges.
func TestPeerUserPortsCoversRanges(t *testing.T) {
	p := peerRecord{ID: 2, Ports: []int{1051}, RawPorts: []string{"1051-1060"}}
	got := peerUserPorts(p)
	if len(got) != 10 || !slices.Contains(got, 1055) || !slices.Contains(got, 1060) {
		t.Fatalf("got %v", got)
	}
}

// An engine switch writes a Backhaul list as it was entered: an entry is not
// repeated port by port (Backhaul cannot listen twice on one port).
func TestCurrentForwardPorts(t *testing.T) {
	st := tunnelStatus{Proxies: []string{"1051-1053", "2083=8443", "3000-3001:5201"}, ProxyPorts: []int{1051, 1052, 1053, 2083, 3000, 3001}}
	ports, raw := currentForwardPorts(st)
	if len(ports) != 6 || !slices.Equal(raw, []string{"1051-1053", "2083=8443", "3000-3001=5201"}) {
		t.Fatalf("Backhaul: %v %v", ports, raw)
	}
	// FRP: proxies are names, so the ports themselves
	ports, raw = currentForwardPorts(tunnelStatus{Proxies: []string{"tcp_443", "udp_443"}, ProxyPorts: []int{443, 2083}})
	if !slices.Equal(ports, []int{443, 2083}) || !slices.Equal(raw, []string{"443", "2083"}) {
		t.Fatalf("FRP: %v %v", ports, raw)
	}
}

// Rescue takes at most rescueMaxPorts: a wide range must not make the
// suggestion (and with it automatic rescue) unusable.
func TestRescueSuggestionFitsTheLimit(t *testing.T) {
	oldBh, oldCfg := backhaulDir, configDir
	backhaulDir, configDir = t.TempDir(), t.TempDir()
	t.Cleanup(func() { backhaulDir, configDir = oldBh, oldCfg })
	if err := writePeers([]peerRecord{{ID: 2, Ports: []int{10000}, RawPorts: []string{"10000-10200=443"}}}); err != nil {
		t.Fatal(err)
	}
	if got := suggestRescuePorts(); len(got) != rescueMaxPorts {
		t.Fatalf("%d ports", len(got))
	}
}
