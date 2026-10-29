package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestXrayLabGen writes the configs tests/test_xray_lab.sh runs with a real
// Xray: for every preset in both modes, the Iran end as the panel makes it and
// the foreign end from its bundle (makeXrayBundle -> parseXrayBundle), so the
// lab tests the code the panel runs. Reality borrows the lab's own TLS 1.3
// site (XRAY_LAB_TARGET, SNI lab.example) since the namespaces have no internet.
//
//	XRAY_LAB_DIR=<dir> XRAY_LAB_IRAN=<ip> XRAY_LAB_FOREIGN=<ip> XRAY_LAB_TARGET=<host:port>
//	XRAY_LAB_PORT=<service port> XRAY_LAB_TUNNEL=<tunnel port> XRAY_LAB_PROBE=<probe port>
func TestXrayLabGen(t *testing.T) {
	dir := os.Getenv("XRAY_LAB_DIR")
	if dir == "" {
		t.Skip("set XRAY_LAB_DIR to generate the Xray lab configs")
	}
	env := func(k string) string { return os.Getenv("XRAY_LAB_" + k) }
	num := func(k string) int { n, _ := strconv.Atoi(env(k)); return n }
	write := func(name string, v any) {
		raw, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var combos []string
	// the presets, and TLS with the panel's own certificate (pinned) on each
	// transport a CDN carries: the path a CDN takes to the server end
	presets := []string{"reality", "xhttp", "grpc", "kcp", "tls-xhttp", "tls-ws", "tls-httpupgrade", "tls-grpc", "kcp-noise"}
	if v := env("PRESETS"); v != "" {
		presets = strings.Fields(v)
	}
	for _, preset := range presets {
		for _, mode := range []string{xrayModeDirect, xrayModeReverse} {
			p := xrayPresets[preset]
			if tr, ok := strings.CutPrefix(preset, "tls-"); ok {
				p = XrayProfile{Transport: tr, Security: "tls", SNI: "tls.lab", Fingerprint: "chrome"}
			}
			if preset == "kcp-noise" {
				p = xrayPresets["kcp"]
				p.Noise = &XrayNoise{Type: "rand", Length: "20-80", Delay: "5-10", Count: 3}
			}
			if p.Security == "reality" {
				p.SNI, p.Target = "lab.example", env("TARGET")
			}
			l := XrayLink{ID: 1, Mode: mode, Side: xraySideIran, Remote: env("FOREIGN"), TunnelPort: num("TUNNEL"),
				Ports: []int{num("PORT")}, UDP: true, ProbePort: num("PROBE"), Profile: p}
			l, err := newXrayLink(l)
			if err != nil {
				t.Fatal(err)
			}
			bundle, err := makeXrayBundle(l, env("IRAN"))
			if err != nil {
				t.Fatalf("%s %s: bundle: %v", preset, mode, err)
			}
			f, err := parseXrayBundle(bundle)
			if err != nil {
				t.Fatalf("%s %s: import: %v", preset, mode, err)
			}
			ic, err := buildXrayConfig(l)
			if err != nil {
				t.Fatalf("%s %s: Iran config: %v", preset, mode, err)
			}
			fc, err := buildXrayConfig(f)
			if err != nil {
				t.Fatalf("%s %s: foreign config: %v", preset, mode, err)
			}
			name := preset + "-" + mode
			write("iran-"+name+".json", ic)
			write("fo-"+name+".json", fc)
			combos = append(combos, name)
			if preset == "reality" && mode == xrayModeReverse {
				// The reverse link as v2.8.4 made it, for the lab to compare:
				// one connection, no send queue cap, no fast dead-link check.
				write("iran-"+name+"-base.json", xrayLabBase(ic))
				write("fo-"+name+"-base.json", xrayLabBase(fc))
			}
			if preset == "reality" && mode == xrayModeDirect {
				// The same Iran end with one more door, to ask the foreign end
				// for a port that is not forwarded: it must refuse.
				ic = xrayNormalize(ic)
				ic["inbounds"] = append(ic["inbounds"].([]any), map[string]any{
					"tag": "evil", "listen": "127.0.0.1", "port": num("PROBE") + 1, "protocol": "dokodemo-door",
					"settings": map[string]any{"address": "127.0.0.1", "port": num("EVIL"), "network": "tcp"},
				})
				routing := ic["routing"].(map[string]any)
				routing["rules"] = append(routing["rules"].([]any), map[string]any{"inboundTag": []string{"evil"}, "outboundTag": xrayTagTunnel})
				write("iran-evil.json", ic)
			}
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "combos"), []byte(strings.Join(combos, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// xrayLabBase is cfg without what this version adds to a reverse link: the
// extra reverse outbounds and the link's socket options.
func xrayLabBase(cfg map[string]any) map[string]any {
	cfg = xrayNormalize(cfg)
	strip := func(o map[string]any) {
		if ss, ok := o["streamSettings"].(map[string]any); ok {
			if so, ok := ss["sockopt"].(map[string]any); ok {
				for _, k := range []string{"customSockopt", "tcpKeepAliveIdle", "tcpKeepAliveInterval", "tcpUserTimeout"} {
					delete(so, k)
				}
			}
		}
	}
	var outs []any
	for _, o := range cfg["outbounds"].([]any) {
		m := o.(map[string]any)
		if tag, _ := m["tag"].(string); strings.HasPrefix(tag, xrayTagTunnel+"-") {
			continue
		}
		strip(m)
		outs = append(outs, m)
	}
	cfg["outbounds"] = outs
	ins, _ := cfg["inbounds"].([]any)
	for _, i := range ins {
		strip(i.(map[string]any))
	}
	return cfg
}

// TestXrayLabPorts runs in the lab's foreign namespace next to a fake x-ui:
// the panel must see who holds the port, refuse it and suggest another.
//
//	XRAY_LAB_TAKEN=<port the fake x-ui holds>
func TestXrayLabPorts(t *testing.T) {
	taken, _ := strconv.Atoi(os.Getenv("XRAY_LAB_TAKEN"))
	if taken == 0 {
		t.Skip("set XRAY_LAB_TAKEN to check the ports in the Xray lab")
	}
	oldRunner := runner
	runner = execRunner // the real `ss` of this namespace
	t.Cleanup(func() { runner = oldRunner })
	ls := xrayListeners()
	l := XrayLink{ID: 1, Mode: xrayModeDirect, Side: xraySideForeign, TunnelPort: taken, Ports: []int{2053}, Profile: XrayProfile{Transport: "raw"}}
	cs := xrayPortConflicts(l, nil, ls, nil)
	if len(cs) != 1 || cs[0].Owner != "3x-ui (x-ui)" {
		t.Fatalf("the fake x-ui on %d: conflicts %v (listeners %+v)", taken, cs, ls)
	}
	msg := xrayPortsError(l, cs, ls)
	t.Logf("refused: %s", msg)
	if !strings.Contains(msg, "Use tunnel port") {
		t.Errorf("no free port suggested: %s", msg)
	}
}
