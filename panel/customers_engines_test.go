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
		"accept_udp = true", `"0.0.0.0:8443=127.0.0.1:8443"`, "skip_optz = true", "web_port = 0", "sniffer = false"} {
		if !strings.Contains(string(bh), want) {
			t.Errorf("backhaul server lacks %q:\n%s", want, bh)
		}
	}
	unit, _ := os.ReadFile(custUnitPath(1, 1))
	if !strings.Contains(string(unit), "ExecStart="+custEngineBin("backhaul")+" -c "+custConfPath(1, 1, "backhaul")) ||
		!strings.Contains(string(unit), "TemporaryFileSystem="+configDir+":ro\nBindReadOnlyPaths="+custConfPath(1, 1, "backhaul")+"\n") ||
		strings.Contains(string(unit), "AF_NETLINK") {
		t.Errorf("backhaul unit: its own config only, no netlink:\n%s", unit)
	}
	if unit2, _ := os.ReadFile(custUnitPath(1, 2)); !strings.Contains(string(unit2), "BindReadOnlyPaths="+custConfPath(1, 2, "backhaul")+" "+custCertPath(1, 2, ".crt")+" "+custCertPath(1, 2, ".key")+"\n") {
		t.Errorf("wss unit: its certificate and key readable:\n%s", unit2)
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
		{`{"engine":"xray","transport":"reality","ports":"443","sni":"localhost"}`, "SNI"},
		{`{"engine":"xray","transport":"reality","ports":"443","sni":"nas.lan"}`, "SNI"},
		{`{"engine":"xray","transport":"reality","ports":"443","sni":"router"}`, "SNI"},
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
		for _, eng := range []string{custEngineXray, custEngineXrayDirect} {
			for _, udp := range []bool{false, true} {
				l := customerLink{ID: i + 1, Engine: eng, Transport: preset, CtrlPort: 31000 + i, Ports: []int{443, 2083}, UDP: udp, Token: strings.Repeat("b", 32), Remote: "198.51.100.9"}
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
					t.Errorf("%s %s udp=%v: the installer's config differs from the panel's:\ninstaller:\n%s\npanel:\n%s", eng, preset, udp, g, manual)
				}
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
				done := make(chan struct{})
				go func() { _ = cmd.Wait(); close(done) }()
				exited := false
				select {
				case <-done:
					exited = true // Backhaul refused the config
				case <-time.After(1500 * time.Millisecond):
					_ = cmd.Process.Kill()
					<-done
				}
				if exited || strings.Contains(strings.ToLower(buf.String()), "fatal") || strings.Contains(buf.String(), "not properly set") {
					t.Errorf("backhaul %s %s:\n%s", name, tr, buf.String())
				}
			}
		}
	}
}

// TestCustomersDialEngines: Xray direct and Bagher, the links this server
// dials (P3).
func TestCustomersDialEngines(t *testing.T) {
	newCustLab(t)
	withPro(t)
	oldPeer := custPeerIPs
	custPeerIPs = func(h string) []string {
		if h == "fo.example.org" {
			return []string{"198.51.100.20"}
		}
		return oldPeer(h)
	}
	t.Cleanup(func() { custPeerIPs = oldPeer })
	code, m := custPost(t, `{"action":"create","name":"dial","days":30,"rate_mbit":10,"address":"iran.example.com","links":[
		{"name":"xd","engine":"xray-direct","transport":"reality","ports":"9443","remote":"198.51.100.9","ctrl_port":8443},
		{"name":"bg","engine":"bagher","transport":"ssh","ports":"9444","udp":true,"remote":"fo.example.org","ctrl_port":31500}]}`)
	if code != 200 {
		t.Fatalf("create: %d %v", code, m)
	}
	c := custGet(t, 1)
	xd, bg := c.Links[0], c.Links[1]

	// claims: xray-direct's port is the foreign server's, Bagher's frps is local
	idx := indexClaims(customerPortClaims())
	if idx.owner("tcp", 8443, nil) != "" || idx.owner("tcp", 31500, nil) == "" {
		t.Error("claims: xray-direct's tunnel port is not this server's; Bagher's frps port is")
	}
	// xray-direct: Iran dials the foreign server; the kit carries the private key
	data, _ := os.ReadFile(custConfPath(1, 1, custEngineXrayDirect))
	if !strings.Contains(string(data), `"address": "198.51.100.9"`) || strings.Contains(string(data), xd.Xray.Keys.PrivateKey) {
		t.Errorf("xray-direct Iran config:\n%s", data)
	}
	_, body := custKitOf(t, 1, 1)
	if !strings.Contains(body, "engine=xray-direct\n") || !strings.Contains(body, "pk="+xd.Xray.Keys.PrivateKey+"\n") {
		t.Errorf("xray-direct kit:\n%s", body)
	}

	// Bagher: frps on 127.0.0.1 only; no unit before the reply code
	frps, _ := os.ReadFile(custConfPath(1, 2, custEngineBagher))
	if !strings.Contains(string(frps), `bindAddr = "127.0.0.1"`) || !strings.Contains(string(frps), "bindPort = 31500") {
		t.Errorf("bagher frps:\n%s", frps)
	}
	if v := customersView()["customers"].([]custView)[0].Links[1]; !v.AwaitReply {
		t.Error("a Bagher link without a reply code does not say it waits")
	}
	if strings.Contains(custLabSys(t), "start hsell-1-2.service") {
		t.Error("the Bagher unit started before the reply code")
	}
	km, body := custKitOf(t, 1, 2)
	if !strings.Contains(body, "engine=bagher\n") || !strings.Contains(body, "sshpub="+bg.SSHPub+"\n") || strings.Contains(body, "PRIVATE") {
		t.Errorf("bagher kit:\n%s", body)
	}
	if !strings.Contains(fmt.Sprint(km["manual"]), `permitlisten="127.0.0.1:31500",permitopen="127.0.0.1:31500"`) {
		t.Errorf("bagher manual setup lacks the locked-down key line:\n%v", km["manual"])
	}
	raw, _ := json.Marshal(customersView())
	if strings.Contains(string(raw), "OPENSSH PRIVATE KEY") || strings.Contains(string(raw), bg.SSHPub) {
		t.Error("the view carries the Bagher key")
	}

	// the installer's reply code, pasted back: the unit starts with the host key pinned
	installer, _ := filepath.Abs("../tools/hashem-customer.sh")
	hk := t.TempDir()
	hostPub := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl root@fo"
	_ = os.WriteFile(filepath.Join(hk, "ssh_host_ed25519_key.pub"), []byte(hostPub+"\n"), 0o644)
	cmd := exec.Command("bash", installer, "reply", fmt.Sprint(km["kit"]))
	cmd.Env = append(os.Environ(), "HASHEM_SSH_DIR="+hk, "HASHEM_SSH_PORT=2222")
	reply, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("reply: %v %s", err, reply)
	}
	// another link's code is refused
	code, m = custPost(t, fmt.Sprintf(`{"action":"link-reply","id":1,"link_id":1,"reply":%q}`, strings.TrimSpace(string(reply))))
	if code == 200 {
		t.Error("a reply code was taken by an Xray link")
	}
	code, m = custPost(t, fmt.Sprintf(`{"action":"link-reply","id":1,"link_id":2,"reply":%q}`, strings.TrimSpace(string(reply))))
	if code != 200 {
		t.Fatalf("link-reply: %d %v", code, m)
	}
	bg = custGet(t, 1).Links[1]
	if bg.SSHPort != 2222 || bg.SSHUser != "hcust" || len(bg.HostKeys) != 1 || !strings.HasPrefix(hostPub, bg.HostKeys[0]) {
		t.Errorf("reply: port %d user %q keys %v", bg.SSHPort, bg.SSHUser, bg.HostKeys)
	}
	known, _ := os.ReadFile(custCertPath(1, 2, ".known"))
	if string(known) != "[fo.example.org]:2222 "+bg.HostKeys[0]+"\n" {
		t.Errorf("known_hosts: %q", known)
	}
	unit, _ := os.ReadFile(custUnitPath(1, 2))
	for _, want := range []string{custEngineBin("bagher") + " sell-bagher -frps " + custEngineBin("frp"), "-host fo.example.org -port 2222 -user hcust -frp-port 31500",
		"-key " + custCertPath(1, 2, ".ssh"), "BindReadOnlyPaths=" + custConfPath(1, 2, "bagher") + " " + custCertPath(1, 2, ".ssh") + " " + custCertPath(1, 2, ".known")} {
		if !strings.Contains(string(unit), want) {
			t.Errorf("bagher unit lacks %q:\n%s", want, unit)
		}
	}
	if !strings.Contains(custLabSys(t), "start hsell-1-2.service") {
		t.Error("the Bagher unit did not start after the reply code")
	}
	if _, err := os.Stat(filepath.Join(custBinDir, "frps")); err != nil {
		t.Error("no frps copy for the Bagher relay")
	}
	// Bagher's frps asks the plugin like FRP's does
	plug := func(port int, typ string) string {
		req := httptest.NewRequest("POST", "/_hsplugin/"+custPluginKey(bg.Token), strings.NewReader(fmt.Sprintf(`{"op":"NewProxy","content":{"proxy_type":%q,"remote_port":%d}}`, typ, port)))
		req.RemoteAddr = "127.0.0.1:5000"
		req.SetPathValue("key", custPluginKey(bg.Token))
		rr := httptest.NewRecorder()
		handleCustomerPlugin(rr, req)
		return fmt.Sprint(rr.Code, " ", rr.Body.String())
	}
	if got := plug(9444, "tcp"); !strings.Contains(got, `"reject":false`) {
		t.Errorf("the plugin refused a Bagher link's sold port: %s", got)
	}
	if got := plug(9445, "tcp"); !strings.Contains(got, `"reject":true`) {
		t.Errorf("the plugin let a Bagher link open an unsold port: %s", got)
	}
	if got := plug(9443, "stcp"); !strings.Contains(got, `"reject":true`) {
		t.Errorf("the plugin let a Bagher link open stcp: %s", got)
	}

	// a new address forgets the pinned keys
	custPost(t, `{"action":"link-update","id":1,"link_id":2,"link":{"engine":"bagher","transport":"ssh","ports":"9444","remote":"198.51.100.30"}}`)
	if l := custGet(t, 1).Links[1]; len(l.HostKeys) != 0 || l.SSHKey != bg.SSHKey {
		t.Errorf("a new address: host keys %v, key kept %v", l.HostKeys, l.SSHKey == bg.SSHKey)
	}

	// the cap on data from the foreign servers: from their address and port
	cmds := custTCArgs([]custIfc{{"eth0", []string{"192.0.2.10"}}}, []customer{custGet(t, 1)})
	text := fmt.Sprint(cmds)
	if !strings.Contains(text, "src 198.51.100.9/32 match ip sport 8443") || !strings.Contains(text, "src 198.51.100.30/32 match ip sport 22") {
		t.Errorf("tc for dialing links:\n%s", text)
	}
	if strings.Contains(text, "dport 8443") {
		t.Error("tc polices xray-direct's foreign port as a local one")
	}

	// a reply code that is not one
	for _, bad := range []string{"hsr1.%%%", "hsk1.AAAA", "hsr1." + base64.RawURLEncoding.EncodeToString([]byte("v=1\nname=hsell-1-2\nport=22\nuser=root;x\nkey="+hostPub+"\n")),
		"hsr1." + base64.RawURLEncoding.EncodeToString([]byte("v=1\nname=hsell-1-2\nport=22\nuser=hcust\nkey=ssh-ed25519 AAAA\n"))} {
		if code, _ := custPost(t, fmt.Sprintf(`{"action":"link-reply","id":1,"link_id":2,"reply":%q}`, bad)); code == 200 {
			t.Errorf("reply code %q was taken", bad)
		}
	}
}

func custLabSys(t *testing.T) string {
	t.Helper()
	l := custLabCurrent
	if l == nil {
		t.Fatal("no custLab")
	}
	return l.systemctl()
}
