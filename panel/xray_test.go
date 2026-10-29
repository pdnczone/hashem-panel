package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// xrayEnv is one server's Xray tunnel with every host call stubbed: units
// and configs in temp dirs, a fake core, systemctl recorded.
type xrayEnv struct {
	t         *testing.T
	dir       string
	mu        sync.Mutex
	systemctl []string
	testOut   string // what `xray run -test` prints
	listeners []xrayListener
	active    bool
}

func newXrayEnv(t *testing.T) *xrayEnv {
	t.Helper()
	withPro(t) // first: it points configDir at a temp dir of its own
	e := &xrayEnv{t: t, dir: t.TempDir(), testOut: "Configuration OK.", active: true}
	oldCfg, oldUnit, oldBin, oldDir := configDir, engineUnitDir, xrayBinPath, xrayDir
	oldRunner, oldSys, oldActive := runner, runSystemctl, engineServiceActive
	oldVerify, oldWait, oldLs, oldProbe, oldPing, oldConns := xrayVerifyDelay, xrayLinkWait, xrayListeners, xrayProbe, xrayTCPPing, xrayConns
	t.Cleanup(func() {
		configDir, engineUnitDir, xrayBinPath, xrayDir = oldCfg, oldUnit, oldBin, oldDir
		runner, runSystemctl, engineServiceActive = oldRunner, oldSys, oldActive
		xrayVerifyDelay, xrayLinkWait, xrayListeners, xrayProbe, xrayTCPPing, xrayConns = oldVerify, oldWait, oldLs, oldProbe, oldPing, oldConns
		xrayEnvActive = nil
	})
	e.use()
	if err := os.MkdirAll(xrayDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(xrayBinPath, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return e
}

// xrayEnvActive is the server the globals point at now.
var xrayEnvActive *xrayEnv

// use makes this server the one the panel code sees (a test may have two).
// It writes the globals only when the server changes: a goroutine of this
// server's (the install, a health check) may be reading them.
func (e *xrayEnv) use() {
	if xrayEnvActive == e {
		return
	}
	xrayEnvActive = e
	configDir, engineUnitDir = filepath.Join(e.dir, "cfg"), filepath.Join(e.dir, "units")
	xrayDir = filepath.Join(e.dir, "core")
	xrayBinPath = filepath.Join(xrayDir, "xray")
	bin := xrayBinPath
	runner = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		switch {
		case name == bin && len(args) > 1 && args[1] == "-test":
			// like Xray: the config format comes from the file extension
			if c := args[len(args)-1]; !strings.HasSuffix(c, ".json") {
				return []byte("Failed to start: main: failed to load config files: [" + c + "] > core: Failed to get format of " + c), fmt.Errorf("exit status 23")
			}
			if !strings.Contains(e.testOut, "OK") {
				return []byte(e.testOut), fmt.Errorf("exit status 23")
			}
			return []byte(e.testOut), nil
		case name == bin && args[0] == "version":
			return []byte("Xray 26.3.27 (Xray, Penetrates Everything.) Custom\nA unified platform"), nil
		}
		return nil, fmt.Errorf("no host commands in this test: %s", name)
	}
	runSystemctl = func(args ...string) error {
		e.mu.Lock()
		e.systemctl = append(e.systemctl, strings.Join(args, " "))
		e.mu.Unlock()
		return nil
	}
	engineServiceActive = func(string) bool { return e.active }
	xrayVerifyDelay, xrayLinkWait = 0, 0
	xrayListeners = func() []xrayListener { return e.listeners }
	xrayProbe = func(int) (float64, error) { return 41.5, nil }
	xrayTCPPing = func(string, int) (float64, error) { return 20.25, nil }
	xrayConns = func(XrayLink) int { return 1 }
	xrayHealthCache.Lock()
	xrayHealthCache.m, xrayHealthCache.busy = map[int]xrayHealth{}, map[int]bool{}
	xrayHealthCache.Unlock()
}

// post sends one action to /api/xray on this server.
func (e *xrayEnv) post(body string) (int, map[string]any) {
	e.t.Helper()
	e.use()
	rr := httptest.NewRecorder()
	handleXrayPost(rr, httptest.NewRequest("POST", "/api/xray", strings.NewReader(body)))
	var m map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &m)
	return rr.Code, m
}

func (e *xrayEnv) get() map[string]any {
	e.t.Helper()
	e.use()
	rr := httptest.NewRecorder()
	handleXrayGet(rr, httptest.NewRequest("GET", "/api/xray", nil))
	var m map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &m); err != nil {
		e.t.Fatalf("GET /api/xray: %v %s", err, rr.Body.String())
	}
	return m
}

func (e *xrayEnv) read(path string) string {
	e.t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		e.t.Fatal(err)
	}
	return string(b)
}

func stepsOK(m map[string]any) string {
	var out []string
	steps, _ := m["steps"].([]any)
	for _, s := range steps {
		st := s.(map[string]any)
		mark := "x"
		if st["ok"] == true {
			mark = "ok"
		} else if st["wait"] == true {
			mark = "wait"
		}
		out = append(out, fmt.Sprint(st["key"], ":", mark))
	}
	return strings.Join(out, " ")
}

func TestXrayCreateDirectAndImport(t *testing.T) {
	iran := newXrayEnv(t)
	code, m := iran.post(`{"action":"create","mode":"direct","preset":"reality","remote":"198.51.100.7","tunnel_port":443,"ports":[2053,8080],"udp":true,"public_ip":"203.0.113.9","name":"Frankfurt"}`)
	if code != 200 || m["status"] != "ok" {
		t.Fatalf("create: %d %v", code, m)
	}
	if got := stepsOK(m); got != "core:ok ports:ok config:ok service:ok link:ok" {
		t.Errorf("steps %s", got)
	}
	bundle, _ := m["bundle"].(string)
	if !strings.HasPrefix(bundle, "xr1_") {
		t.Fatalf("bundle %q", bundle)
	}
	link := m["link"].(map[string]any)
	if link["id"] != float64(1) || link["unit"] != "hashem-xray-1" || link["name"] != "Frankfurt" {
		t.Errorf("link %v", link)
	}
	if keys := link["keys"].(map[string]any); keys["private_key"] != nil || keys["public_key"] == "" {
		t.Errorf("the API shows the private key or no public key: %v", keys)
	}
	cfg := iran.read(xrayLinkConfPath(1))
	for _, w := range []string{`"protocol": "dokodemo-door"`, `"port": "2053,8080"`, `"address": "198.51.100.7"`, `"tag": "probe"`} {
		if !strings.Contains(cfg, w) {
			t.Errorf("Iran config lacks %s", w)
		}
	}
	unit := iran.read(xrayUnitPath(1))
	if !strings.Contains(unit, "ExecStart="+xrayBinPath+" run -c "+xrayLinkConfPath(1)) || !strings.Contains(unit, "XRAY_LOCATION_ASSET="+xrayDir) || !strings.Contains(unit, "Environment=GODEBUG=multipathtcp=0") {
		t.Errorf("unit:\n%s", unit)
	}
	if got := strings.Join(iran.systemctl, ","); got != "daemon-reload,enable hashem-xray-1,restart hashem-xray-1" {
		t.Errorf("systemctl %s", got)
	}
	st := loadXrayState()
	if l := st.Links[0]; l.ProbePort == 0 || l.Keys.PrivateKey == "" || st.PublicIP != "203.0.113.9" {
		t.Errorf("Iran keeps the probe port, the key pair and its IP: %+v %q", l, st.PublicIP)
	}

	// GET: health from the probe, the public IP, no private key anywhere
	g := iran.get()
	h := g["links"].([]any)[0].(map[string]any)["health"].(map[string]any)
	if h["link"] != "up" || h["ping_ms"] != 20.25 || h["probe_ms"] != 41.5 {
		t.Errorf("health %v", h)
	}
	if raw, _ := json.Marshal(g); strings.Contains(string(raw), st.Links[0].Keys.PrivateKey) {
		t.Error("GET leaks the Reality private key")
	}
	if g["public_ip"] != "203.0.113.9" || g["installed"] != true || g["version"] != "Xray 26.3.27" {
		t.Errorf("GET %v %v %v", g["public_ip"], g["installed"], g["version"])
	}

	// The foreign server imports the bundle: it serves Reality on 443 and
	// reaches only its own ports.
	foreign := newXrayEnv(t)
	code, m = foreign.post(`{"action":"import","bundle":"` + bundle + `"}`)
	if code != 200 || m["status"] != "ok" || m["updated"] != false {
		t.Fatalf("import: %d %v", code, m)
	}
	if got := stepsOK(m); got != "core:ok ports:ok config:ok service:ok link:wait" {
		t.Errorf("foreign steps %s", got)
	}
	fl := loadXrayState().Links[0]
	if fl.Side != xraySideForeign || fl.Remote != "203.0.113.9" || fl.Keys.PrivateKey == "" || fl.ProbePort != 0 {
		t.Errorf("foreign link %+v", fl)
	}
	fcfg := foreign.read(xrayLinkConfPath(1))
	for _, w := range []string{`"protocol": "vless"`, `"privateKey"`, `"ip": [`, `"127.0.0.1"`, `"full:probe.hashem"`, `"type": "http"`} {
		if !strings.Contains(fcfg, w) {
			t.Errorf("foreign config lacks %s", w)
		}
	}
	if strings.Contains(fcfg, "dokodemo") {
		t.Error("the foreign server listens on the users' ports")
	}
	// The same bundle again updates the link in place.
	_, m = foreign.post(`{"action":"import","bundle":"` + bundle + `"}`)
	if m["updated"] != true || len(loadXrayState().Links) != 1 {
		t.Errorf("re-import: %v", m)
	}
}

func TestXrayReverseBundle(t *testing.T) {
	iran := newXrayEnv(t)
	// No public IP known: the foreign server would have nothing to dial.
	code, m := iran.post(`{"action":"create","mode":"reverse","preset":"xhttp","tunnel_port":8443,"ports":[2053]}`)
	if code != 400 || !strings.Contains(fmt.Sprint(m["error"]), "public IP") {
		t.Fatalf("reverse without a public IP: %d %v", code, m)
	}
	if len(loadXrayState().Links) != 0 {
		t.Fatal("a refused link was saved")
	}
	_, m = iran.post(`{"action":"create","mode":"reverse","preset":"xhttp","tunnel_port":8443,"ports":[2053],"public_ip":"203.0.113.9"}`)
	if m["status"] != "ok" {
		t.Fatalf("create reverse: %v", m)
	}
	cfg := iran.read(xrayLinkConfPath(1))
	if !strings.Contains(cfg, `"reverse": {`) || !strings.Contains(cfg, `"privateKey"`) {
		t.Errorf("Iran is not the Reality server in reverse mode:\n%s", cfg)
	}
	b, err := parseXrayBundle(m["bundle"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if b.Keys.PrivateKey != "" || b.Remote != "203.0.113.9" || b.Mode != xrayModeReverse {
		t.Errorf("reverse bundle gives the foreign server %+v", b)
	}
	foreign := newXrayEnv(t)
	_, m = foreign.post(`{"action":"import","bundle":"` + m["bundle"].(string) + `"}`)
	if got := stepsOK(m); got != "core:ok ports:ok config:ok service:ok link:ok" {
		t.Errorf("foreign reverse steps %s (%v)", got, m)
	}
	if cfg := foreign.read(xrayLinkConfPath(1)); !strings.Contains(cfg, `"address": "203.0.113.9"`) || strings.Contains(cfg, "privateKey") {
		t.Errorf("foreign (bridge) config:\n%s", cfg)
	}
}

func TestXrayPortsTaken(t *testing.T) {
	e := newXrayEnv(t)
	e.listeners = []xrayListener{{Proto: "tcp", Port: 2053, Proc: "xray-linux-amd6", Exe: "/usr/local/x-ui/bin/xray-linux-amd64"}}
	code, m := e.post(`{"action":"create","mode":"direct","remote":"198.51.100.7","tunnel_port":443,"ports":[2053]}`)
	if code != 409 || m["error_code"] != "E-XRAY-03" || !strings.Contains(fmt.Sprint(m["error"]), "3x-ui") {
		t.Fatalf("taken user port: %d %v", code, m)
	}
	if len(loadXrayState().Links) != 0 {
		t.Error("a link with a taken port was saved")
	}
	// The wizard's check names the owner and suggests a tunnel port.
	e.listeners = append(e.listeners, xrayListener{Proto: "tcp", Port: 443, Proc: "nginx"})
	_, m = e.post(`{"action":"check","mode":"reverse","remote":"","tunnel_port":443,"ports":[2053]}`)
	cs, _ := m["conflicts"].([]any)
	if len(cs) != 2 || m["suggest_tunnel_port"] != float64(8443) {
		t.Errorf("check: %v", m)
	}
	// Foreign end, direct: its tunnel port is taken by 3x-ui.
	foreign := newXrayEnv(t)
	foreign.listeners = []xrayListener{{Proto: "tcp", Port: 443, Proc: "x-ui"}}
	iran := newXrayEnv(t)
	_, m = iran.post(`{"action":"create","mode":"direct","remote":"198.51.100.7","tunnel_port":443,"ports":[2053],"public_ip":"203.0.113.9"}`)
	code, m = foreign.post(`{"action":"import","bundle":"` + m["bundle"].(string) + `"}`)
	if code != 409 || !strings.Contains(fmt.Sprint(m["error"]), "TCP port 443 is used by 3x-ui (x-ui). Use tunnel port 8443 instead") {
		t.Errorf("foreign import onto a taken port: %d %v", code, m)
	}
}

func TestXrayApplyFailures(t *testing.T) {
	e := newXrayEnv(t)
	e.testOut = "Failed to start: main: failed to load config files > infra/conf: bad realitySettings"
	_, m := e.post(`{"action":"create","mode":"direct","remote":"198.51.100.7","tunnel_port":443,"ports":[2053]}`)
	if m["status"] != "error" || m["error_code"] != "E-XRAY-04" || stepsOK(m) != "core:ok ports:ok config:x" ||
		!strings.Contains(fmt.Sprint(m["error"]), "bad realitySettings") {
		t.Errorf("rejected config: %v", m)
	}
	if _, err := os.Stat(xrayLinkConfPath(1)); err == nil {
		t.Error("a config Xray refused was put in place")
	}
	// Fixed config, but the unit dies right after it starts.
	e.testOut, e.active = "Configuration OK.", false
	_, m = e.post(`{"action":"apply","id":1}`)
	if m["error_code"] != "E-XRAY-05" || stepsOK(m) != "core:ok ports:ok config:ok service:x" {
		t.Errorf("dead unit: %v", m)
	}
	// No core: the link is kept, the UI offers the install.
	e.active = true
	os.Remove(xrayBinPath)
	_, m = e.post(`{"action":"apply","id":1}`)
	if m["error_code"] != "E-XRAY-02" || stepsOK(m) != "core:x" {
		t.Errorf("no core: %v", m)
	}
	if code, m := e.post(`{"action":"apply","id":9}`); code != 404 || m["error_code"] != "E-XRAY-06" {
		t.Errorf("unknown link: %d %v", code, m)
	}
}

func TestXrayUpdateStopRemove(t *testing.T) {
	e := newXrayEnv(t)
	_, m := e.post(`{"action":"create","mode":"direct","preset":"reality","remote":"198.51.100.7","tunnel_port":443,"ports":[2053],"public_ip":"203.0.113.9"}`)
	first := m["bundle"]
	uuid := loadXrayState().Links[0].Keys.UUID
	// Only the name: the foreign server needs nothing new.
	_, m = e.post(`{"action":"update","id":1,"mode":"direct","remote":"198.51.100.7","tunnel_port":443,"ports":[2053],"name":"Paris"}`)
	if m["bundle_changed"] != false || m["bundle"] != first {
		t.Errorf("rename changed the bundle: %v", m["bundle_changed"])
	}
	// Another transport: a new bundle, the same link (UUID, unit).
	_, m = e.post(`{"action":"update","id":1,"mode":"direct","preset":"xhttp","remote":"198.51.100.7","tunnel_port":443,"ports":[2053],"name":"Paris"}`)
	l := loadXrayState().Links[0]
	if m["bundle_changed"] != true || l.Keys.UUID != uuid || l.Profile.Transport != "xhttp" || l.Profile.Path == "" || l.Name != "Paris" {
		t.Errorf("transport change: %v %+v", m["bundle_changed"], l)
	}
	// Expert JSON, then cleared.
	_, m = e.post(`{"action":"update","id":1,"mode":"direct","remote":"198.51.100.7","tunnel_port":443,"ports":[2053],"expert":{"log":{"loglevel":"info"}}}`)
	if !strings.Contains(e.read(xrayLinkConfPath(1)), `"loglevel": "info"`) {
		t.Error("expert JSON not applied")
	}
	_, _ = e.post(`{"action":"update","id":1,"mode":"direct","remote":"198.51.100.7","tunnel_port":443,"ports":[2053],"expert":{}}`)
	if strings.Contains(e.read(xrayLinkConfPath(1)), `"loglevel": "info"`) {
		t.Error("expert JSON not cleared")
	}
	e.systemctl = nil
	if _, m = e.post(`{"action":"stop","id":1}`); m["status"] != "ok" || !loadXrayState().Links[0].Disabled {
		t.Errorf("stop: %v", m)
	}
	if g := e.get(); g["links"].([]any)[0].(map[string]any)["health"].(map[string]any)["link"] != "off" {
		t.Error("a stopped link is not shown off")
	}
	if _, m = e.post(`{"action":"remove","id":1}`); m["status"] != "ok" {
		t.Fatalf("remove: %v", m)
	}
	if _, err := os.Stat(xrayUnitPath(1)); err == nil {
		t.Error("unit left behind")
	}
	if got := strings.Join(e.systemctl, ","); got != "disable --now hashem-xray-1,disable --now hashem-xray-1,daemon-reload" {
		t.Errorf("systemctl %s", got)
	}
	// IDs are never reused.
	_, m = e.post(`{"action":"create","mode":"direct","remote":"198.51.100.7","tunnel_port":443,"ports":[2053]}`)
	if m["link"].(map[string]any)["id"] != float64(2) {
		t.Errorf("new link id %v", m["link"].(map[string]any)["id"])
	}
	// A foreign link is changed on the Iran server only.
	if _, m = e.post(`{"action":"update","id":2,"mode":"direct","remote":"198.51.100.7","tunnel_port":443,"ports":[2053]}`); m["status"] != "ok" {
		t.Errorf("update Iran link: %v", m)
	}
}

func TestXrayBundleIsValidated(t *testing.T) {
	good := xrayTestLink(t, "reality", xrayModeDirect, xraySideIran)
	good.Keys.PrivateKey = "cGVwcGVycGVwcGVycGVwcGVycGVwcGVycGVwcGVyMDA" // Iran keeps the pair it made
	b, err := makeXrayBundle(good, "203.0.113.9")
	if err != nil {
		t.Fatal(err)
	}
	if l, err := parseXrayBundle(" " + b[:20] + "\n" + b[20:] + " "); err != nil || l.Side != xraySideForeign {
		t.Errorf("bundle with spaces and a line break: %v", err)
	}
	for name, s := range map[string]string{
		"prefix":  "spf1_abc",
		"damaged": "xr1_%%%",
		"version": "xr1_" + b64(`{"v":2,"link":{}}`),
		"iran":    "xr1_" + b64(`{"v":1,"link":{"side":"iran"}}`),
		"inject": "xr1_" + b64(`{"v":1,"link":{"side":"foreign","mode":"direct","tunnel_port":443,"ports":[2053],`+
			`"remote":"1.2.3.4\nExecStartPre=/bin/sh","keys":{"uuid":"`+good.Keys.UUID+`"},"profile":{"transport":"raw","security":"none"}}}`),
	} {
		if _, err := parseXrayBundle(s); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func b64(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

func TestXrayCarrierEnds(t *testing.T) {
	e := newXrayEnv(t)
	_ = e
	st := xrayState{NextID: 4, Links: []XrayLink{
		{ID: 1, Mode: xrayModeDirect, Side: xraySideIran, Remote: "198.51.100.7", TunnelPort: 443, Profile: XrayProfile{Transport: "raw"}},
		{ID: 2, Mode: xrayModeReverse, Side: xraySideIran, Remote: "", TunnelPort: 8443, Profile: XrayProfile{Transport: "xhttp"}},
		{ID: 3, Mode: xrayModeDirect, Side: xraySideForeign, Remote: "203.0.113.9", TunnelPort: 2083, Profile: XrayProfile{Transport: "kcp"}},
		{ID: 5, Mode: xrayModeDirect, Side: xraySideIran, Remote: "198.51.100.8", TunnelPort: 443, Disabled: true},
	}}
	if err := saveXrayState(st); err != nil {
		t.Fatal(err)
	}
	got := xrayCarrierEnds()
	want := []carrierEnd{
		{Port: 443, Remote: "198.51.100.7", Tag: "xray-1"},
		{Port: 8443, Tag: "xray-2"},
		{Port: 2083, From: "203.0.113.9", UDP: true, Tag: "xray-3"},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("ends\n got %+v\nwant %+v", got, want)
	}
}

func TestXrayInstallAndSNI(t *testing.T) {
	e := newXrayEnv(t)
	old := xrayInstallCmd
	t.Cleanup(func() { xrayInstallCmd = old })
	release := make(chan struct{})
	xrayInstallCmd = func() (string, error) { <-release; return "[OK] Xray-core v26.3.27 installed", nil }
	if _, m := e.post(`{"action":"install"}`); m["status"] != "ok" {
		t.Fatalf("install: %v", m)
	}
	if code, m := e.post(`{"action":"install"}`); code != 409 || m["error_code"] != "E-XRAY-07" {
		t.Errorf("second install while running: %d %v", code, m)
	}
	close(release)
	deadline := time.Now().Add(5 * time.Second)
	for {
		in := e.get()["install"].(map[string]any)
		if in["done"] == true {
			if in["ok"] != true || !strings.Contains(fmt.Sprint(in["log"]), "installed") {
				t.Errorf("install view %v", in)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("install never finished")
		}
		time.Sleep(10 * time.Millisecond)
	}

	oldDial := xraySNIDial
	t.Cleanup(func() { xraySNIDial = oldDial })
	xraySNIDial = func(s string) xraySNIResult {
		switch s {
		case "fast.example":
			return xraySNIResult{SNI: s, OK: true, TLS13: true, H2: true, MS: 30}
		case "slow.example":
			return xraySNIResult{SNI: s, OK: true, TLS13: true, H2: true, MS: 90}
		}
		return xraySNIResult{SNI: s, TLS13: true, Error: "needs TLS 1.3 and h2"}
	}
	_, m := e.post(`{"action":"snitest","sni":["noh2.example","slow.example","1.2.3.4","fast.example"]}`)
	var order []string
	for _, r := range m["results"].([]any) {
		order = append(order, r.(map[string]any)["sni"].(string))
	}
	if strings.Join(order, ",") != "fast.example,slow.example,noh2.example,1.2.3.4" {
		t.Errorf("SNI order %v", order)
	}
}

// Review fixes: a forwarded port that is also the tunnel port, a probe port
// another program took, mKCP in reverse on the foreign end, and the dialing
// end counting only its own tunnel connections.
func TestXrayReviewFixes(t *testing.T) {
	// direct: the foreign server would feed that port back into its own tunnel
	l := xrayTestLink(t, "reality", xrayModeDirect, xraySideIran)
	l.Ports = []int{8443}
	if err := l.validate(); err == nil || !strings.Contains(err.Error(), "tunnel port") {
		t.Errorf("direct link with a port equal to the tunnel port: %v", err)
	}

	e := newXrayEnv(t)
	_, m := e.post(`{"action":"create","mode":"direct","remote":"198.51.100.7","tunnel_port":443,"ports":[2053],"public_ip":"203.0.113.9"}`)
	probe := loadXrayState().Links[0].ProbePort
	if m["status"] != "ok" || probe == 0 {
		t.Fatalf("create: %v", m)
	}
	// another program takes the probe port: the link moves its probe, it is not refused
	e.listeners = []xrayListener{{Proto: "tcp", Port: probe, Proc: "nginx"}}
	if _, m = e.post(`{"action":"apply","id":1}`); m["status"] != "ok" {
		t.Errorf("apply with the probe port taken: %v", m)
	}
	if now := loadXrayState().Links[0].ProbePort; now == probe || now == 0 {
		t.Errorf("probe port %d -> %d", probe, now)
	}
	if _, m = e.post(`{"action":"update","id":1,"mode":"direct","remote":"198.51.100.7","tunnel_port":443,"ports":[2053],"name":"x"}`); m["status"] != "ok" {
		t.Errorf("update with the old probe port taken: %v", m)
	}

	// mKCP in reverse, foreign end: nothing to count over UDP, Iran checks it
	k := xrayTestLink(t, "kcp", xrayModeReverse, xraySideForeign)
	if h := xrayCheckHealth(k, 0); h.Link != "listening" {
		t.Errorf("reverse mKCP foreign end: %+v", h)
	}
}

func TestXrayConnsCountsOnlyTheLink(t *testing.T) {
	old := runner
	t.Cleanup(func() { runner = old })
	var got []string
	runner = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		got = append(got, name+" "+strings.Join(args, " "))
		return []byte("0 0 10.0.0.2:51000 198.51.100.7:443\n0 0 10.0.0.2:51002 198.51.100.7:443\n"), nil
	}
	l := xrayTestLink(t, "reality", xrayModeDirect, xraySideIran)
	l.TunnelPort = 443
	if n := xrayConns(l); n != 2 {
		t.Errorf("count %d", n)
	}
	if len(got) != 1 || !strings.Contains(got[0], "( dport = :443 and dst 198.51.100.7 )") {
		t.Errorf("ss filter: %v", got)
	}
}

// A link made by an older version gets this version's config and a restart
// at start; an unchanged one is left alone.
func TestXrayMigrateConfigs(t *testing.T) {
	e := newXrayEnv(t)
	l := xrayTestLink(t, "reality", xrayModeDirect, xraySideIran)
	st := xrayState{}
	l = st.add(l)
	if err := saveXrayState(st); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(xrayConfDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	old := `{"outbounds": []}`
	if err := os.WriteFile(xrayLinkConfPath(l.ID), []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	if n := migrateXrayConfigs(); n != 1 {
		t.Fatalf("want 1 link rebuilt, got %d", n)
	}
	if got := e.read(xrayLinkConfPath(l.ID)); !strings.Contains(got, `"testpre"`) {
		t.Fatalf("config not rebuilt:\n%s", got)
	}
	if !strings.Contains(e.read(xrayUnitPath(l.ID)), "LogRateLimitBurst") {
		t.Fatal("unit not rewritten")
	}
	if !strings.Contains(strings.Join(e.systemctl, "\n"), "try-restart "+xrayUnitName(l.ID)) {
		t.Fatalf("link not restarted: %v", e.systemctl)
	}
	if n := migrateXrayConfigs(); n != 0 {
		t.Fatalf("an up-to-date link must not restart, got %d", n)
	}
}
