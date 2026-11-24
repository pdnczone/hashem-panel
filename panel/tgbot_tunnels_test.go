package main

import (
	"strings"
	"testing"
	"time"
)

// tgTexts is the menu, the status and the tunnel list as one text.
func tgTexts(c tgBotConfig, usr *tgBotUser) string {
	var b strings.Builder
	for _, d := range []string{"m", "st", "tl"} {
		s := tgOnButton(c, usr, 42, d)
		b.WriteString(s.Text + "\n")
		for _, row := range s.Keys {
			for _, k := range row {
				b.WriteString(k.Text + " [" + k.Data + "]\n")
			}
		}
	}
	return b.String()
}

// A foreign server has no hub link in the snapshot: the bot said "No tunnels
// yet" there while the panel showed its tunnel.
func TestTGBotForeignServerShowsItsTunnels(t *testing.T) {
	f := newTGHarness(t, true)
	c := loadTGBotConfig()
	usr := c.user(42)
	snapPtr.Store(&HubSnapshot{At: time.Now(), LocalSession: true, LocalRTT: 41,
		Local: tunnelStatus{Role: "foreign (client)", FrpSvc: "frpc", FrpUp: true, Engine: "frp", BindPort: 7001,
			RemotePub: "203.0.113.9", Gre: greState{Exists: true, Inner: "10.10.10.1/30"}, ProxyPorts: []int{443}}})
	if err := atomicWriteFile(hubsFile(), []byte(`{"hubs":[{"id":2,"name":"tehran-2","iran_pub":"203.0.113.20","engine":"frp","svc":"frpc-h2","port":7005,"ports":[443]}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	joinedMu.Lock()
	joinedAt = time.Time{}
	joinedMu.Unlock()
	t.Cleanup(func() { joinedMu.Lock(); joinedAt, joinedCache = time.Time{}, nil; joinedMu.Unlock() })
	out := tgTexts(c, usr)
	if strings.Contains(out, "No tunnels") {
		t.Fatalf("the foreign server's tunnels are missing:\n%s", out)
	}
	for _, want := range []string{"203.0.113.9", "tehran-2", "[t:0]", "[hb:2]", "Tunnels: 2", "🟢"} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in:\n%s", want, out)
		}
	}
	// its own tunnel can be acted on; a joined hub is read only
	d := tgOnButton(c, usr, 42, "t:0")
	if !strings.Contains(d.Text, "203.0.113.9") {
		t.Fatalf("details: %s", d.Text)
	}
	for _, row := range d.Keys {
		for _, k := range row {
			if strings.HasPrefix(k.Data, "tx:") {
				t.Fatal("removing the first tunnel here removes the other hubs too: not from the bot")
			}
		}
	}
	tgOnButton(c, usr, 42, "tr:0")
	if strings.Join(f.actions, ",") != "restart-engine" {
		t.Fatalf("restart: %v", f.actions)
	}
	if h := tgOnButton(c, usr, 42, "hb:2"); !strings.Contains(h.Text, "203.0.113.20") || !strings.Contains(h.Text, "frpc-h2") {
		t.Fatalf("hub: %s", h.Text)
	}
}

// Xray, Bagher and Spoof tunnels are not in the snapshot's links either.
func TestTGBotShowsXrayAndBagher(t *testing.T) {
	newTGHarness(t, true)
	c := loadTGBotConfig()
	usr := c.user(42)
	if err := saveXrayState(xrayState{Links: []XrayLink{{ID: 1, Name: "reality-de", Mode: xrayModeReverse, Side: xraySideIran,
		Remote: "198.51.100.7", TunnelPort: 8443, Ports: []int{2053}, Profile: XrayProfile{Transport: "raw", Security: "reality"}}}}); err != nil {
		t.Fatal(err)
	}
	xrayHealthCache.Lock()
	xrayHealthCache.m[1] = xrayHealth{Active: true, Link: "down", Error: "the foreign server has not connected yet", At: time.Now().UnixMilli()}
	xrayHealthCache.Unlock()
	t.Cleanup(func() { xrayHealthDrop(1) })
	snapPtr.Store(&HubSnapshot{At: time.Now(), Bagher: map[string]any{"has_config": true, "is_active": true, "connected": true,
		"remote_host": "198.51.100.8", "ports": []int{80}, "latency_ms": 55.0, "name": "",
		"links": []map[string]any{{"id": 2, "remote_host": "198.51.100.18", "ports": []int{81}, "is_active": true, "connected": false, "name": "bg2"}}}})
	out := tgTexts(c, usr)
	for _, want := range []string{"reality-de", "[xl:1]", "198.51.100.8", "bg2", "[bl:1]", "[bl:2]", "Tunnels: 3  ·  🟢 1  🟡 1  🔴 1"} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in:\n%s", want, out)
		}
	}
	if x := tgOnButton(c, usr, 42, "xl:1"); !strings.Contains(x.Text, "has not connected") {
		t.Fatalf("xray details: %s", x.Text)
	}
	if b := tgOnButton(c, usr, 42, "bl:2"); !strings.Contains(b.Text, "198.51.100.18") {
		t.Fatalf("bagher details: %s", b.Text)
	}
}

// Before the first reading the bot says so; it does not claim there are none.
func TestTGBotBeforeTheFirstReading(t *testing.T) {
	newTGHarness(t, true)
	c := loadTGBotConfig()
	snapPtr.Store(&HubSnapshot{})
	if out := tgTexts(c, c.user(42)); strings.Contains(out, "No tunnels") || !strings.Contains(out, "not been read yet") {
		t.Fatalf("%s", out)
	}
}

// A button for a tunnel that is gone never breaks.
func TestTGBotGoneTunnels(t *testing.T) {
	newTGHarness(t, true)
	c := loadTGBotConfig()
	for _, d := range []string{"hb:9", "xl:9", "bl:9", "sp:1", "nd", "xs:9", "xp:9"} {
		if s := tgOnButton(c, c.user(42), 42, d); strings.TrimSpace(s.Text) == "" {
			t.Errorf("%s: empty", d)
		}
	}
}
