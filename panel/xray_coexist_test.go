package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const xraySSSample = `tcp   LISTEN 0      4096         0.0.0.0:443        0.0.0.0:*    users:(("xray-linux-amd6",pid=812,fd=9))
tcp   LISTEN 0      4096       127.0.0.1:62789      0.0.0.0:*    users:(("xray-linux-amd6",pid=812,fd=3))
tcp   LISTEN 0      4096               *:2053             *:*    users:(("x-ui",pid=700,fd=8))
tcp   LISTEN 0      511             [::]:80            [::]:*    users:(("nginx",pid=1,fd=6),("nginx",pid=2,fd=6))
udp   UNCONN 0      0      127.0.0.53%lo:53         0.0.0.0:*    users:(("systemd-resolve",pid=500,fd=13))
udp   UNCONN 0      0            0.0.0.0:2083       0.0.0.0:*    users:(("xray",pid=900,fd=3))
tcp   LISTEN 0      4096         0.0.0.0:9443       0.0.0.0:*
garbage line
`

func TestParseSSListeners(t *testing.T) {
	ls := parseSSListeners(xraySSSample)
	if len(ls) != 7 {
		t.Fatalf("got %d listeners: %+v", len(ls), ls)
	}
	want := []xrayListener{
		{"tcp", 443, "xray-linux-amd6", 812, ""}, {"tcp", 62789, "xray-linux-amd6", 812, ""},
		{"tcp", 2053, "x-ui", 700, ""}, {"tcp", 80, "nginx", 1, ""}, {"udp", 53, "systemd-resolve", 500, ""},
		{"udp", 2083, "xray", 900, ""}, {"tcp", 9443, "", 0, ""},
	}
	for i, w := range want {
		if ls[i] != w {
			t.Errorf("%d: %+v, want %+v", i, ls[i], w)
		}
	}
}

func TestXrayOwnerLabel(t *testing.T) {
	cases := map[string]xrayListener{
		"3x-ui (x-ui)":           {Proc: "xray-linux-amd6", Exe: "/usr/local/x-ui/bin/xray-linux-amd64"},
		"Marzban":                {Proc: "xray", Exe: "/var/lib/marzban/xray-core/xray"},
		"a Docker container":     {Proc: "docker-proxy"},
		"the Hashem Xray tunnel": {Proc: "xray", Exe: xrayBinPath},
		"xray":                   {Proc: "xray", Exe: "/usr/local/bin/xray"},
		"another program":        {},
	}
	for want, l := range cases {
		if got := xrayOwnerLabel(l); got != want {
			t.Errorf("%+v: %q, want %q", l, got, want)
		}
	}
}

func TestDetectXrayPanels(t *testing.T) {
	root := t.TempDir()
	old := xrayRoot
	xrayRoot = root
	t.Cleanup(func() { xrayRoot = old })
	if got := detectXrayPanels(); len(got) != 0 {
		t.Fatalf("empty root: %+v", got)
	}
	for _, p := range []string{"usr/local/x-ui/bin", "var/lib/marzban", "etc/systemd/system"} {
		if err := os.MkdirAll(filepath.Join(root, p), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "etc/systemd/system/xray.service"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	got := detectXrayPanels()
	names := []string{}
	for _, p := range got {
		names = append(names, p.Name+"@"+p.Evidence)
	}
	want := "3x-ui (x-ui)@/usr/local/x-ui,Marzban@/var/lib/marzban,Xray (official install)@/etc/systemd/system/xray.service"
	if strings.Join(names, ",") != want {
		t.Errorf("got %v\nwant %s", names, want)
	}
}

func TestXrayPortConflicts(t *testing.T) {
	ls := parseSSListeners(xraySSSample)
	ls[0].Exe = "/usr/local/x-ui/bin/xray-linux-amd64"

	// Direct, foreign end: only the tunnel port. 443 is 3x-ui's.
	l := XrayLink{ID: 1, Mode: xrayModeDirect, Side: xraySideForeign, TunnelPort: 443, Ports: []int{2053, 2083}, UDP: true,
		Profile: XrayProfile{Transport: "raw"}}
	got := xrayPortConflicts(l, nil, ls, nil)
	if len(got) != 1 || got[0].String() != "TCP port 443 is used by 3x-ui (x-ui)" {
		t.Fatalf("foreign end: %v", got)
	}
	// The foreign end does not bind the service ports (they are 3x-ui's).
	l.TunnelPort = 8443
	if got := xrayPortConflicts(l, nil, ls, nil); len(got) != 0 {
		t.Errorf("foreign end with a free tunnel port: %v", got)
	}

	// Iran end, direct: the users' ports, TCP and UDP.
	l.Side = xraySideIran
	got = xrayPortConflicts(l, nil, ls, nil)
	if len(got) != 2 || got[0].Port != 2053 || got[0].Owner != "3x-ui (x-ui)" || got[1].Port != 2083 || got[1].Proto != "udp" {
		t.Errorf("Iran end: %v", got)
	}
	// TCP only: UDP 2083 is fine.
	l.UDP = false
	if got := xrayPortConflicts(l, nil, ls, nil); len(got) != 1 {
		t.Errorf("Iran end, TCP only: %v", got)
	}

	// The tunnel's own Xray holding a port is this link restarting, not a conflict.
	own := []xrayListener{{Proto: "tcp", Port: 2053, Proc: "xray", Exe: xrayBinPath}}
	if got := xrayPortConflicts(l, nil, own, nil); len(got) != 0 {
		t.Errorf("own process: %v", got)
	}
	// ...unless another link claims the port.
	other := XrayLink{ID: 3, Mode: xrayModeDirect, Side: xraySideIran, Ports: []int{2053}, Profile: XrayProfile{Transport: "raw"}}
	got = xrayPortConflicts(l, []XrayLink{l, other}, own, nil)
	if len(got) != 1 || got[0].Owner != "Xray tunnel link 3" {
		t.Errorf("another link: %v", got)
	}
	// Reverse mode: Iran also listens on the tunnel port.
	r := XrayLink{ID: 1, Mode: xrayModeReverse, Side: xraySideIran, TunnelPort: 443, Ports: []int{8080}, Profile: XrayProfile{Transport: "raw"}}
	got = xrayPortConflicts(r, nil, ls, map[string]string{"tcp:8080": "Bagher (foreign server 2)"})
	if len(got) != 2 || got[0].Port != 443 || got[1].Owner != "Bagher (foreign server 2)" {
		t.Errorf("reverse Iran: %v", got)
	}
	// Reverse, foreign end: dials out, binds nothing.
	r.Side = xraySideForeign
	if got := xrayPortConflicts(r, nil, ls, nil); len(got) != 0 {
		t.Errorf("reverse foreign: %v", got)
	}
}

func TestXraySuggestPort(t *testing.T) {
	ls := parseSSListeners(xraySSSample) // 443 taken
	if got := xraySuggestPort("tcp", ls, nil); got != 8443 {
		t.Errorf("got %d, want 8443", got)
	}
	if got := xraySuggestPort("tcp", ls, []int{8443, 2053}); got != 2083 {
		t.Errorf("got %d, want 2083 (2053 is taken, 8443 avoided)", got)
	}
	if got := xraySuggestPort("udp", ls, nil); got != 443 {
		t.Errorf("udp: got %d, want 443", got)
	}
}
