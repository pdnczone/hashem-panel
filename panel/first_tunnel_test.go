package main

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// firstTunnelLab: empty config, FRP, Backhaul and systemd folders, and an
// installer that echoes its arguments.
func firstTunnelLab(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	oc, of, ob, ou := configDir, frpDir, backhaulDir, systemdUnitDir
	configDir, frpDir, backhaulDir, systemdUnitDir = dir, t.TempDir(), t.TempDir(), t.TempDir()
	t.Cleanup(func() { configDir, frpDir, backhaulDir, systemdUnitDir = oc, of, ob, ou })
	script := filepath.Join(dir, "hashem.sh")
	if err := os.WriteFile(script, []byte("echo \"$@\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HASHEM_SCRIPT", script)
	return dir
}

func put(t *testing.T, path, s string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}

const (
	labPeers = `{"peers":[{"id":1,"name":"f2","gre_if":"gre-t1","frps_svc":"frps-1","frp_port":7021,"peer_gre":"10.12.0.1","local_gre":"10.12.0.2","remote_pub":"203.0.113.12","ports":[4432]},` +
		`{"id":2,"name":"f3","gre_if":"gre-t2","frps_svc":"frps-2","frp_port":7031,"peer_gre":"10.13.0.1","local_gre":"10.13.0.2","remote_pub":"203.0.113.13","ports":[4433]}]}`
	labHubs = `{"hubs":[{"id":2,"name":"tehran-2","iran_pub":"203.0.113.20","engine":"frp","svc":"frpc-h2","gre_if":"gre-h2","port":7100,"iran_gre":"10.9.0.1","ports":[443]},` +
		`{"id":3,"name":"tehran-3","iran_pub":"203.0.113.30","engine":"backhaul","svc":"backhaul-client-h3","gre_if":"none","port":7200}]}`
)

// A hub whose first tunnel was removed is still an Iran hub, and none of its
// other tunnels takes the removed one's place.
func TestHubWithoutFirstTunnel(t *testing.T) {
	firstTunnelLab(t)
	put(t, peersFile(), labPeers)
	v := &hostView{active: map[string]bool{"frps-1": true, "frps-2": true}, inner: map[string]string{"gre-t1": "10.12.0.2/30", "gre-t2": "10.13.0.2/30"}}
	st := localStatusFrom(v)
	if st.Role != "iran (server)" || st.FrpSvc != "" || st.FrpUp || hasFirstTunnel(st) {
		t.Fatalf("%+v", st)
	}
	if m := mainTunnelFrom(st, v); m != nil {
		t.Fatalf("a first tunnel that is gone: %+v", m)
	}
	relays, gres := otherTunnelUnits()
	if strings.Join(relays, " ") != "frps-1 frps-2" || strings.Join(gres, " ") != "gre-t1.service gre-t2.service" {
		t.Errorf("units: %v %v", relays, gres)
	}
	// a left-over client config does not turn the hub into a foreign server
	staleLab(t)
	if st := localStatusFrom(v); !strings.HasPrefix(st.Role, "iran") {
		t.Errorf("role with a stale client config: %q", st.Role)
	}
}

// A foreign server without its first Iran hub still serves the others.
func TestForeignWithoutFirstHub(t *testing.T) {
	firstTunnelLab(t)
	put(t, hubsFile(), labHubs)
	v := &hostView{active: map[string]bool{"frpc-h2": true}, inner: map[string]string{"gre-h2": "10.9.0.2/30"},
		sessions: []ssSession{{LPort: 40000, RHost: "10.9.0.1", RPort: 7100, RTTms: 31}}}
	st := localStatusFrom(v)
	if st.Role != "foreign (client)" || hasFirstTunnel(st) {
		t.Fatalf("%+v", st)
	}
	h := liveHubsFrom(v, readJoinedHubs())
	if len(h) != 2 || h[0].HealthState != stateHealthy || h[0].LatencyMs != 31 || !h[0].GreUp || h[1].HealthState != stateDown {
		t.Fatalf("%+v", h)
	}
	// removing a first tunnel that is not there touches nothing
	if out, err := runAction("remove-tunnel", 0); err == nil {
		t.Fatalf("ran %q", out)
	}
	// with a first one, it alone goes: --force would drop every hub
	put(t, filepath.Join(frpDir, "frpc.toml"), "serverAddr = \"203.0.113.10\"\n")
	if out, err := runAction("remove-tunnel", 0); err != nil || out != "remove-tunnel --base" {
		t.Fatalf("ran %q (%v)", out, err)
	}
}

// Peer 1 next to a first tunnel from Setup is the second tunnel, not the first.
func TestBasePeerIsNotPeerOne(t *testing.T) {
	firstTunnelLab(t)
	put(t, peersFile(), labPeers)
	if p := basePeer(loadPeers()); p != nil {
		t.Fatalf("peer %d taken for the first tunnel", p.ID)
	}
	if peerFrpsSvc(1) != "frps-1" || peerGreSvc(1) != "gre-t1.service" {
		t.Errorf("peer 1's units: %s %s", peerFrpsSvc(1), peerGreSvc(1))
	}
	// editing a first tunnel that is not there must not edit peer 1
	rr := httptest.NewRecorder()
	handlePeersPatch(rr, httptest.NewRequest("PATCH", "/api/peers", strings.NewReader(`{"id":0,"ports":"9999"}`)))
	if rr.Code == 200 || !strings.Contains(rr.Body.String(), "E-PEER-05") {
		t.Errorf("edit without a first tunnel: %d %s", rr.Code, rr.Body.String())
	}
	if b, _ := os.ReadFile(peersFile()); string(b) != labPeers {
		t.Errorf("peers.json changed: %s", b)
	}
}

// Removing the first tunnel forgets its name and what Setup recorded about it,
// and nothing about the others.
func TestRemovedFirstTunnelIsForgotten(t *testing.T) {
	dir := firstTunnelLab(t)
	put(t, peersFile(), labPeers)
	put(t, filepath.Join(frpDir, "frps.toml"), "bindPort = 7001\n")
	put(t, filepath.Join(dir, "setup.json"), `{"local_public":"203.0.113.1","remote_public":"203.0.113.11","token":"old"}`)
	if err := setLinkName("main", "Frankfurt"); err != nil {
		t.Fatal(err)
	}
	if err := setLinkName("bagher-1", "Paris"); err != nil {
		t.Fatal(err)
	}
	if out, err := runAction("remove-tunnel", 0); err != nil || out != "remove-tunnel --base" {
		t.Fatalf("ran %q (%v)", out, err)
	}
	if linkLabel("main") != "" || linkLabel("bagher-1") != "Paris" {
		t.Errorf("names: %q %q", linkLabel("main"), linkLabel("bagher-1"))
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "setup.json")); string(b) != `{"local_public":"203.0.113.1"}` {
		t.Errorf("setup.json: %s", b)
	}
	if b, _ := os.ReadFile(peersFile()); string(b) != labPeers {
		t.Errorf("peers.json changed: %s", b)
	}
	// another tunnel's removal does not touch the first one's record
	if err := setLinkName("main", "Berlin"); err != nil {
		t.Fatal(err)
	}
	if out, err := runAction("remove-tunnel", 2); err != nil || out != "remove-peer --id 2 --force" || linkLabel("main") != "Berlin" {
		t.Errorf("removing tunnel 2: %q %v, the first is named %q", out, err, linkLabel("main"))
	}
}

// Setup next to other tunnels makes one more tunnel: it may not take theirs.
func TestSetupNextToOtherTunnels(t *testing.T) {
	firstTunnelLab(t)
	put(t, peersFile(), labPeers)
	for _, c := range []struct{ body, want string }{
		{`"remote_public":"203.0.113.12","frp_port":7001,"ports":"4431"`, "E-PEER-08"},
		{`"remote_public":"203.0.113.11","frp_port":7001,"ports":"4433"`, "E-PEER-02"},
		{`"remote_public":"203.0.113.11","frp_port":7021,"ports":"4431"`, "E-SETUP-07"},
		{`"remote_public":"203.0.113.11","frp_port":7001,"ports":"4431","local_gre":"10.13.0.2","peer_gre":"10.13.0.1"`, "E-SETUP-05"},
	} {
		if !strings.Contains(c.body, "local_gre") {
			c.body += `,"local_gre":"10.10.10.2","peer_gre":"10.10.10.1"`
		}
		rr := httptest.NewRecorder()
		handleSetupPost(rr, httptest.NewRequest("POST", "/api/setup", strings.NewReader(`{"role":"iran","engine":"frp","local_public":"203.0.113.1",`+c.body+`}`)))
		if !strings.Contains(rr.Body.String(), c.want) {
			t.Errorf("%s: %d %s", c.want, rr.Code, rr.Body.String())
		}
	}
}
