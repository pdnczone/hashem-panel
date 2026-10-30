package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Backhaul and Xray reverse links for customers (P2).

func custKitOf(t *testing.T, cid, lid int) (map[string]any, string) {
	t.Helper()
	rr := httptest.NewRecorder()
	handleCustomersKit(rr, httptest.NewRequest("GET", fmt.Sprintf("/api/customers/kit?id=%d&link=%d", cid, lid), nil))
	var m map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &m)
	if rr.Code != 200 {
		t.Fatalf("kit %d/%d: %d %v", cid, lid, rr.Code, m)
	}
	body, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(fmt.Sprint(m["kit"]), "hsk1."))
	if err != nil {
		t.Fatal(err)
	}
	return m, string(body)
}

func TestCustomersEngines(t *testing.T) {
	newCustLab(t)
	withPro(t)
	code, m := custPost(t, `{"action":"create","name":"multi","days":30,"address":"iran.example.com","links":[
		{"name":"bh","engine":"backhaul","transport":"tcp","ports":"8443","udp":true,"ctrl_port":31000},
		{"name":"bhs","engine":"backhaul","transport":"wssmux","ports":"8444","ctrl_port":31001},
		{"name":"xr","engine":"xray","transport":"reality","ports":"9443, 9444","udp":true,"ctrl_port":31002,"sni":"www.example.ir"},
		{"name":"xk","engine":"xray","transport":"kcp","ports":"9445","ctrl_port":31003}]}`)
	if code != 200 {
		t.Fatalf("create: %d %v", code, m)
	}
	c := custGet(t, 1)

	// Backhaul: the server lists the ports, to the foreign 127.0.0.1
	bh, _ := os.ReadFile(custConfPath(1, 1, custEngineBackhaul))
	for _, want := range []string{`bind_addr = "0.0.0.0:31000"`, `transport = "tcp"`, `token = "` + c.Links[0].Token + `"`,
		"accept_udp = true", `"8443=127.0.0.1:8443"`, "web_port = 0", "sniffer = false"} {
		if !strings.Contains(string(bh), want) {
			t.Errorf("backhaul server lacks %q:\n%s", want, bh)
		}
	}
	unit, _ := os.ReadFile(custUnitPath(1, 1))
	if !strings.Contains(string(unit), "ExecStart="+custEngineBin("backhaul")+" -c "+custConfPath(1, 1, "backhaul")) {
		t.Errorf("backhaul unit:\n%s", unit)
	}
	// wss: the certificate next to the config, the key private
	bhs, _ := os.ReadFile(custConfPath(1, 2, custEngineBackhaul))
	if !strings.Contains(string(bhs), `tls_cert = "`+custCertPath(1, 2, ".crt")+`"`) || strings.Contains(string(bhs), "accept_udp") {
		t.Errorf("backhaul wssmux server:\n%s", bhs)
	}
	if st, err := os.Stat(custCertPath(1, 2, ".key")); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("wss key: %v %v", st, err)
	}
	for _, e := range []string{"backhaul", "xray", "frps"} {
		if _, err := os.Stat(filepath.Join(custBinDir, e)); err != nil && e != "frps" {
			t.Errorf("no %s copy: %v", e, err)
		}
	}
	if _, err := os.Stat(filepath.Join(custBinDir, "frps")); err == nil {
		t.Error("an frps copy was made for a customer without FRP links")
	}

	// Xray: a reverse portal whose user may only open reverse links, and the
	// blackhole for everything else
	data, _ := os.ReadFile(custConfPath(1, 3, custEngineXray))
	var xc map[string]any
	if err := json.Unmarshal(data, &xc); err != nil {
		t.Fatalf("xray config: %v\n%s", err, data)
	}
	s := string(data)
	for _, want := range []string{`"reverse": {`, `"tag": "reverse"`, `"port": "9443,9444"`, `"network": "tcp,udp"`, `"port": 31002`, `"www.example.ir"`} {
		if !strings.Contains(s, want) {
			t.Errorf("xray Iran config lacks %s:\n%s", want, s)
		}
	}
	if ob := xc["outbounds"].([]any); len(ob) != 1 || ob[0].(map[string]any)["protocol"] != "blackhole" {
		t.Errorf("xray Iran outbounds: only the blackhole, got %v", ob)
	}
	unit, _ = os.ReadFile(custUnitPath(1, 3))
	if !strings.Contains(string(unit), "ExecStart="+custEngineBin("xray")+" run -c "+custConfPath(1, 3, "xray")) ||
		!strings.Contains(string(unit), "GODEBUG=multipathtcp=0") {
		t.Errorf("xray unit:\n%s", unit)
	}

	// claims: an mKCP control port is UDP too
	idx := indexClaims(customerPortClaims())
	if idx.owner("udp", 31003, nil) == "" || idx.owner("udp", 31002, nil) != "" || idx.owner("udp", 31001, nil) != "" {
		t.Error("control port claims: xray kcp is udp, reality and backhaul are tcp only")
	}

	// the browser never gets a secret
	raw, _ := json.Marshal(customersView())
	for _, l := range c.Links {
		if strings.Contains(string(raw), l.Token) {
			t.Error("the view carries a link token")
		}
		if l.Xray != nil && ((l.Xray.Keys.PrivateKey != "" && strings.Contains(string(raw), l.Xray.Keys.PrivateKey)) || strings.Contains(string(raw), l.Xray.Keys.UUID)) {
			t.Error("the view carries Xray keys")
		}
		if l.TLSKey != "" && strings.Contains(string(raw), "PRIVATE KEY") {
			t.Error("the view carries the wss key")
		}
	}
	if !strings.Contains(string(raw), `"sni":"www.example.ir"`) {
		t.Error("the view lacks the SNI")
	}

	// kits: version 2 with the engine; Xray's carries the public half only
	km, body := custKitOf(t, 1, 3)
	x := c.Links[2].Xray
	for _, want := range []string{"v=2\n", "engine=xray\n", "transport=reality\n", "uuid=" + x.Keys.UUID + "\n", "pbk=" + x.Keys.PublicKey + "\n",
		"sid=" + x.Keys.ShortID + "\n", "sni=www.example.ir\n", "ports=9443,9444\n", "udp=1\n"} {
		if !strings.Contains(body, want) {
			t.Errorf("xray kit lacks %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, x.Keys.PrivateKey) || strings.Contains(fmt.Sprint(km["manual"]), x.Keys.PrivateKey) {
		t.Error("the kit carries the Reality private key")
	}
	if km["manual_name"] != "config.json" || km["engine"] != "xray" {
		t.Errorf("xray kit: %v %v", km["manual_name"], km["engine"])
	}
	km, body = custKitOf(t, 1, 1)
	if !strings.Contains(body, "engine=backhaul\n") || km["manual_name"] != "client.toml" ||
		!strings.Contains(fmt.Sprint(km["manual"]), `remote_addr = "iran.example.com:31000"`) {
		t.Errorf("backhaul kit:\n%s\n%v", body, km["manual"])
	}

	// an edit that keeps engine and transport keeps the keys (the
	// customer's installed kit stays valid); another transport makes new ones
	code, m = custPost(t, `{"action":"link-update","id":1,"link_id":3,"link":{"name":"xr","engine":"xray","transport":"reality","ports":"9443,9444,9446","udp":true}}`)
	if code != 200 {
		t.Fatalf("link-update: %d %v", code, m)
	}
	if y := custGet(t, 1).Links[2].Xray; y.Keys != x.Keys || y.Profile.SNI != "www.example.ir" {
		t.Errorf("the keys changed on a port edit: %+v", y.Keys)
	}
	cert := c.Links[1].TLSCert
	custPost(t, `{"action":"link-update","id":1,"link_id":2,"link":{"engine":"backhaul","transport":"wssmux","ports":"8444,8445"}}`)
	if custGet(t, 1).Links[1].TLSCert != cert {
		t.Error("the wss certificate changed on a port edit")
	}
	custPost(t, `{"action":"link-update","id":1,"link_id":3,"link":{"engine":"xray","transport":"xhttp","ports":"9443"}}`)
	if y := custGet(t, 1).Links[2].Xray; y.Keys.UUID == x.Keys.UUID || y.Profile.Transport != "xhttp" {
		t.Errorf("a new transport kept the old keys: %+v", y)
	}
	// an engine change leaves no file of the old engine
	custPost(t, `{"action":"link-update","id":1,"link_id":2,"link":{"engine":"xray","transport":"grpc","ports":"8444"}}`)
	for _, f := range []string{custConfPath(1, 2, "backhaul"), custCertPath(1, 2, ".crt"), custCertPath(1, 2, ".key")} {
		if _, err := os.Stat(f); err == nil {
			t.Errorf("%s survived the engine change", f)
		}
	}
	if _, err := os.Stat(custConfPath(1, 2, "xray")); err != nil {
		t.Errorf("no xray config after the engine change: %v", err)
	}
	// remove: every file of every link
	custPost(t, `{"action":"remove","id":1}`)
	left, _ := filepath.Glob(filepath.Join(custConfDir(), "1-*"))
	if len(left) > 0 {
		t.Errorf("remove left %v", left)
	}
}

func TestCustomersEngineValidation(t *testing.T) {
	newCustLab(t)
	withPro(t)
	for _, tc := range []struct{ link, want string }{
		{`{"engine":"spoof","ports":"443"}`, "engine: frp, backhaul, xray"},
		{`{"engine":"backhaul","transport":"kcp","ports":"443"}`, "backhaul transport"},
		{`{"engine":"backhaul","transport":"tcpmux","ports":"443","udp":true}`, "UDP on the tcp transport only"},
		{`{"engine":"xray","transport":"websocket","ports":"443"}`, "xray transport"},
		{`{"engine":"xray","transport":"reality","ports":"443","sni":"1.2.3.4"}`, "SNI"},
		{`{"engine":"xray","transport":"reality","ports":"443","sni":"a\"b"}`, "SNI"},
		{`{"engine":"xray","transport":"reality","ports":"443","ctrl_port":443}`, "also a user port"},
	} {
		code, m := custPost(t, `{"action":"create","name":"v","links":[`+tc.link+`]}`)
		if code == 200 || !strings.Contains(fmt.Sprint(m["error"]), tc.want) {
			t.Errorf("%s: %d %v (want %q)", tc.link, code, m["error"], tc.want)
		}
	}
	// the seller has no Backhaul: the link is kept but its unit cannot start
	_ = os.Remove(custBackhaulSrc)
	code, m := custPost(t, `{"action":"create","name":"v","links":[{"engine":"backhaul","ports":"443"}]}`)
	if code != 200 || !strings.Contains(fmt.Sprint(m["error"]), "install the Backhaul engine first") {
		t.Errorf("no backhaul: %d %v", code, m["error"])
	}
	if eng, _ := m["engines"].(map[string]any); eng["backhaul"] != false || eng["xray"] != true {
		t.Errorf("engines: %v", m["engines"])
	}
}

// TestCustomersXrayKitMatches: the installer writes, from the kit alone, the
// exact config the panel builds for the customer's end, for every preset.
func TestCustomersXrayKitMatches(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("no bash")
	}
	installer, _ := filepath.Abs("../tools/hashem-customer.sh")
	c := customer{ID: 4, Name: "x", Token: strings.Repeat("a", 32)}
	for i, preset := range custTransports[custEngineXray] {
		for _, udp := range []bool{false, true} {
			l := customerLink{ID: i + 1, Engine: custEngineXray, Transport: preset, CtrlPort: 31000 + i, Ports: []int{443, 2083}, UDP: udp, Token: strings.Repeat("b", 32)}
			if err := custLinkSecrets(&l, nil, ""); err != nil {
				t.Fatal(err)
			}
			kit := custKit(c, l, "203.0.113.7")
			out, err := exec.Command("bash", installer, "config", kit).CombinedOutput()
			if err != nil {
				t.Fatalf("%s: installer: %v\n%s", preset, err, out)
			}
			var got any
			if err := json.Unmarshal(out, &got); err != nil {
				t.Fatalf("%s: installer output is not JSON: %v\n%s", preset, err, out)
			}
			_, manual, err := custClientConf(c, l, "203.0.113.7")
			if err != nil {
				t.Fatal(err)
			}
			var want any
			_ = json.Unmarshal([]byte(manual), &want)
			if !reflect.DeepEqual(got, want) {
				g, _ := json.MarshalIndent(got, "", " ")
				t.Errorf("%s udp=%v: the installer's config differs from the panel's:\ninstaller:\n%s\npanel:\n%s", preset, udp, g, manual)
			}
		}
	}
}

// TestCustomersEngineConfigsLoad checks the Backhaul and Xray configs with
// the pinned binaries (BACKHAUL_BIN, XRAY_BIN): Xray's -test, and Backhaul
// started for a moment (it has no config check).
func TestCustomersEngineConfigsLoad(t *testing.T) {
	xrayBin, bhBin := os.Getenv("XRAY_BIN"), os.Getenv("BACKHAUL_BIN")
	if xrayBin == "" && bhBin == "" {
		t.Skip("set XRAY_BIN and/or BACKHAUL_BIN to check the configs with the real engines")
	}
	old := runner
	runner = execRunner
	t.Cleanup(func() { runner = old })
	dir := t.TempDir()
	oldDir := configDir
	configDir = dir
	t.Cleanup(func() { configDir = oldDir })
	c := customer{ID: 7, Name: "v", Token: strings.Repeat("a", 32)}
	if xrayBin != "" {
		for i, preset := range custTransports[custEngineXray] {
			l := customerLink{ID: i + 1, Engine: custEngineXray, Transport: preset, CtrlPort: 31000 + i, Ports: []int{443, 2083}, UDP: true, Token: strings.Repeat("b", 32)}
			if err := custLinkSecrets(&l, nil, ""); err != nil {
				t.Fatal(err)
			}
			server, err := custServerConf(c.ID, l)
			if err != nil {
				t.Fatal(err)
			}
			_, client, err := custClientConf(c, l, "203.0.113.7")
			if err != nil {
				t.Fatal(err)
			}
			for name, conf := range map[string]string{"iran": server, "foreign": client} {
				p := filepath.Join(dir, fmt.Sprintf("%s-%s.json", name, preset))
				_ = os.WriteFile(p, []byte(conf), 0o600)
				out, err := runCmdTimeoutOut(20*time.Second, xrayBin, "run", "-test", "-c", p)
				if err != nil || !strings.Contains(string(out), "Configuration OK") {
					t.Errorf("xray %s %s: %v\n%s\n%s", name, preset, err, out, conf)
				}
			}
		}
	}
	if bhBin != "" {
		for i, tr := range custTransports[custEngineBackhaul] {
			l := customerLink{ID: i + 1, Engine: custEngineBackhaul, Transport: tr, CtrlPort: 38000 + i, Ports: []int{38100 + i}, UDP: tr == "tcp", Token: strings.Repeat("b", 32)}
			if err := custLinkSecrets(&l, nil, ""); err != nil {
				t.Fatal(err)
			}
			if _, err := custWriteLinkFiles(c.ID, l); err != nil {
				t.Fatal(err)
			}
			_, client, _ := custClientConf(c, l, "127.0.0.1")
			cp := filepath.Join(dir, fmt.Sprintf("client-%s.toml", tr))
			_ = os.WriteFile(cp, []byte(client), 0o600)
			for name, p := range map[string]string{"server": custConfPath(c.ID, l.ID, custEngineBackhaul), "client": cp} {
				cmd := exec.Command(bhBin, "-c", p)
				var buf strings.Builder
				cmd.Stdout, cmd.Stderr = &buf, &buf
				if err := cmd.Start(); err != nil {
					t.Fatal(err)
				}
				time.Sleep(700 * time.Millisecond)
				exited := cmd.ProcessState != nil
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
				if exited || strings.Contains(strings.ToLower(buf.String()), "fatal") || strings.Contains(buf.String(), "not properly set") {
					t.Errorf("backhaul %s %s:\n%s", name, tr, buf.String())
				}
			}
		}
	}
}
