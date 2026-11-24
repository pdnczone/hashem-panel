package main

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGreFreePair(t *testing.T) {
	for _, tc := range []struct{ used, want string }{
		{"", "10.10.10.2"},
		{"10.10.10.1", "10.11.0.2"},
		{"10.10.10.3", "10.11.0.2"},             // another host of that /30
		{"10.10.10.5", "10.10.10.2"},            // the next /30
		{"10.10.0.0/16 10.11.0.2", "10.12.0.2"}, // the provider's private network
		{"10.0.0.0/8", "172.30.1.2"},            // all of it
		{"10.0.0.0/8 172.16.0.0/12", "192.168.191.2"},
		{"10.0.0.0/8 172.16.0.0/12 192.168.0.0/16", ""},
		{"10.10.10.9/32 junk 0.0.0.0/0 ::1", "10.10.10.2"},
	} {
		if a, _ := greFreePair(strings.Fields(tc.used)); a != tc.want {
			t.Errorf("used %q: %q, want %q", tc.used, a, tc.want)
		}
	}
	for _, tc := range []struct {
		a, b string
		ok   bool
	}{{"10.11.0.2", "10.11.0.1", true}, {"10.11.0.5", "10.11.0.6", true}, {"10.11.0.2", "10.11.0.2", false},
		{"10.11.0.2", "10.11.0.3", false}, {"10.11.0.4", "10.11.0.5", false}, {"10.11.0.2", "10.12.0.1", false}} {
		if grePairOK(tc.a, tc.b) != tc.ok {
			t.Errorf("%s %s: %v", tc.a, tc.b, !tc.ok)
		}
	}
}

func TestGreConnectedRoutes(t *testing.T) {
	old := procNetRoot
	procNetRoot = t.TempDir()
	defer func() { procNetRoot = old }()
	_ = os.WriteFile(filepath.Join(procNetRoot, "route"), []byte("Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\n"+
		"eth0\t00000000\t0100000A\t0003\t0\t0\t0\t00000000\n"+
		"eth1\t00000B0A\t00000000\t0001\t0\t0\t0\t0000FFFF\n"+ // 10.11.0.0/16
		"eth0\t00FEA8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\n"), 0o644) // 192.168.254.0/24
	got := strings.Join(greConnected(), " ")
	if !strings.Contains(got, "10.11.0.0/16") || !strings.Contains(got, "192.168.254.0/24") || strings.Contains(got, "0.0.0.0/0") {
		t.Fatal(got)
	}
}

// The panel refuses a pair that another tunnel's /30 holds, on every path.
func TestSetupGreClash(t *testing.T) {
	newClusterFixture(t, true)
	oldFT := firstTunnelInfo
	ft := firstTunnel{}
	firstTunnelInfo = func() firstTunnel { return ft }
	defer func() { firstTunnelInfo = oldFT }()
	_ = os.WriteFile(filepath.Join(configDir, "peers.json"), []byte(`{"peers":[{"id":2,"name":"de","local_pub":"5.5.5.5","remote_pub":"9.9.9.9","frp_port":7002,"local_gre":"10.12.0.2","peer_gre":"10.12.0.1","gre_if":"gre-t2","frps_svc":"frps-2","ports":[443]}]}`), 0o600)
	r := func(role, a, b string) string { return greClash(setupRequest{Role: role, LocalGre: a, PeerGre: b}) }
	if w := r("add-peer", "10.12.0.1", "10.12.0.2"); !strings.Contains(w, "de") {
		t.Fatal("the same /30 the other way round", w)
	}
	if w := r("add-peer", "10.13.0.2", "10.13.0.1"); w != "" {
		t.Fatal(w)
	}
	if w := r("iran", "10.12.0.2", "10.12.0.1"); w == "" {
		t.Fatal("setup next to another tunnel")
	}
	if w := r("add-peer", "10.13.0.2", "10.14.0.1"); !strings.Contains(w, "/30") {
		t.Fatal(w)
	}
	ft = firstTunnel{Exists: true, Side: "iran", LocalGre: "10.10.10.2", PeerGre: "10.10.10.1"}
	if w := r("add-peer", "10.10.10.2", "10.10.10.1"); !strings.Contains(w, "first tunnel") {
		t.Fatal(w)
	}
	if w := r("iran", "10.10.10.2", "10.10.10.1"); w != "" {
		t.Fatal("Setup replaces the first tunnel:", w)
	}
	_ = os.WriteFile(hubsFile(), []byte(`{"hubs":[{"id":2,"name":"hub-2","iran_pub":"6.6.6.6","svc":"frpc-h2","port":7100,"gre_if":"gre-h2","iran_gre":"10.15.0.2"}]}`), 0o600)
	if w := r("foreign", "10.15.0.1", "10.15.0.2"); !strings.Contains(w, "hub-2") {
		t.Fatal(w)
	}
	// over the API
	rr := httptest.NewRecorder()
	handleSetupPost(rr, httptest.NewRequest("POST", "/", strings.NewReader(`{"role":"add-peer","local_public":"5.5.5.5","remote_public":"8.8.4.4","local_gre":"10.12.0.2","peer_gre":"10.12.0.1","frp_port":7005,"ports":"8443","token":"0123456789abcdef0123456789abcdef"}`)))
	if rr.Code != 400 || !strings.Contains(rr.Body.String(), "10.12.0.2") {
		t.Fatal(rr.Code, rr.Body)
	}
}

// A linked hub's pairs count as used: two hubs never give one foreign server
// the same pair.
func TestClusterGre(t *testing.T) {
	newClusterFixture(t, true)
	if clusterGre() != nil {
		t.Fatal("no hubs")
	}
	oldGo := greHubsGo
	greHubsGo = func(f func()) { f() }
	defer func() { greHubsGo = oldGo }()
	b := fakeHub(t, syncTestSecret, func(path string, _ []byte) any {
		return syncList{Tunnels: []syncTunnel{{Remote: "9.9.9.9", LocalGre: "10.10.10.2", PeerGre: "10.10.10.1"}}}
	})
	c := defaultClusterConfig()
	c.Secret, c.Hubs = syncTestSecret, []HubPeer{{ID: "hub-b", URL: b.URL}}
	_ = saveClusterConfig(c)
	greHubs.Lock()
	greHubs.at, greHubs.m = time.Time{}, nil
	greHubs.Unlock()
	if a, _ := greFreePair(clusterGre()); a != "10.11.0.2" {
		t.Fatal(a)
	}
	greHubs.Lock()
	greHubs.at, greHubs.m = time.Time{}, nil
	greHubs.Unlock()
}
