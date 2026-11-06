package main

import (
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
)

// The Spoof tunnel came up but carried nothing: no user port was forwarded
// over it. The Iran side now forwards its listed ports to the foreign
// WireGuard address, loaded and dropped with the WireGuard link.
func TestSpoofForwardPortsInWGConfig(t *testing.T) {
	spoofLab(t)
	s := spoofState{Role: "local", WGPrivKey: "cHJpdg==", WGPeerPub: "cGVlcg==", CorePort: 5000,
		RecvPort: 5001, WGLocalIP: "10.20.0.1", WGPeerIP: "10.20.0.2"}
	if err := s.setForwardPorts("8080-8082, 443"); err != nil {
		t.Fatal(err)
	}
	if got := s.ForwardPorts; len(got) != 4 || got[0] != 443 || got[3] != 8082 {
		t.Fatalf("ports = %v", got)
	}
	if err := s.writeWGConfig(); err != nil {
		t.Fatal(err)
	}
	wg, _ := os.ReadFile(spoofWGConfPath())
	ifc, _, _ := strings.Cut(string(wg), "[Peer]")
	if !strings.Contains(ifc, "PostUp = sysctl -q -w net.ipv4.ip_forward=1; nft -f "+spoofForwardNftPath()) ||
		!strings.Contains(ifc, "PostDown = nft delete table inet hashem_spoof") {
		t.Fatalf("hooks missing from [Interface]:\n%s", wg)
	}
	nft, err := os.ReadFile(spoofForwardNftPath())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`th dport { 443, 8080, 8081, 8082 } dnat ip to 10.20.0.2`,
		`iifname != "wg-spoof"`,
		`oifname "wg-spoof" ip daddr 10.20.0.2 masquerade`,
		`tcp option maxseg size set rt mtu`,
		"delete table inet hashem_spoof",
	} {
		if !strings.Contains(string(nft), want) {
			t.Fatalf("nft lacks %q:\n%s", want, nft)
		}
	}

	// No ports: no hooks and no rules file left behind.
	_ = s.setForwardPorts("")
	if err := s.writeWGConfig(); err != nil {
		t.Fatal(err)
	}
	wg, _ = os.ReadFile(spoofWGConfPath())
	if strings.Contains(string(wg), "PostUp") {
		t.Fatalf("hooks left with no ports:\n%s", wg)
	}
	if _, err := os.Stat(spoofForwardNftPath()); err == nil {
		t.Fatal("rules file left with no ports")
	}

	// The foreign server never forwards, whatever its state holds.
	r := spoofState{Role: "remote", ForwardPorts: []int{443}, WGLocalIP: "10.20.0.2", WGPeerIP: "10.20.0.1"}
	if strings.Contains(r.wgConfig(), "PostUp") {
		t.Fatal("the foreign side must not forward")
	}
}

func TestSpoofForwardPortsRejectsReserved(t *testing.T) {
	spoofLab(t)
	s := spoofState{Role: "local", RecvPort: 5001}
	for _, bad := range []string{"22", "5001", "80,abc", "0", "70000"} {
		if err := s.setForwardPorts(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
	if s.ForwardPorts != nil {
		t.Fatalf("a refused list changed the ports: %v", s.ForwardPorts)
	}
	if cfg.Port > 0 {
		if err := s.setForwardPorts(strconv.Itoa(cfg.Port)); err == nil {
			t.Fatal("the panel port was accepted")
		}
	}
}

func TestSpoofForwardPortsAPI(t *testing.T) {
	spoofLab(t)
	post := func(body string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		handleSpoofPost(rr, httptest.NewRequest("POST", "/api/spoof", strings.NewReader(body)))
		return rr
	}
	if rr := post(`{"action":"save","role":"local","forward_ports":"443, 2053"}`); apiCode(t, rr) != "" {
		t.Fatalf("save failed: %s", rr.Body.String())
	}
	if got := loadSpoofState().ForwardPorts; len(got) != 2 || got[1] != 2053 {
		t.Fatalf("saved ports = %v", got)
	}
	// A save without the field keeps them.
	if rr := post(`{"action":"save","peer_public_ip":"198.51.100.10"}`); apiCode(t, rr) != "" {
		t.Fatalf("save failed: %s", rr.Body.String())
	}
	if got := loadSpoofState().ForwardPorts; len(got) != 2 {
		t.Fatalf("ports lost on a save without them: %v", got)
	}
	// A bad list is refused and nothing changes.
	if rr := post(`{"action":"save","forward_ports":"22"}`); apiCode(t, rr) != "E-ENGINE-02" {
		t.Fatalf("SSH port accepted: %s", rr.Body.String())
	}
	if got := loadSpoofState().ForwardPorts; len(got) != 2 {
		t.Fatalf("a refused save changed the ports: %v", got)
	}
	// An empty string clears them.
	if rr := post(`{"action":"save","forward_ports":""}`); apiCode(t, rr) != "" {
		t.Fatalf("clear failed: %s", rr.Body.String())
	}
	if got := loadSpoofState().ForwardPorts; len(got) != 0 {
		t.Fatalf("ports not cleared: %v", got)
	}
}
