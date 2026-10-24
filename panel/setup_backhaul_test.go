package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBackhaulBundleMakeAndParse(t *testing.T) {
	iranPub := "1.2.3.4"
	bhPort := 3080
	transport := "tcpmux"
	token := "bh-secret-token-12345"
	rawPorts := []string{"443", "10000-10050", "2083=8443"}

	// 1. Make bundle
	bStr := MakeBackhaulBundle(iranPub, bhPort, transport, token, rawPorts)
	if !strings.HasPrefix(bStr, "bh1_") {
		t.Fatalf("expected bundle to start with bh1_, got %s", bStr)
	}

	// 2. ParseBackhaulBundle directly
	b, err := ParseBackhaulBundle(bStr)
	if err != nil {
		t.Fatalf("ParseBackhaulBundle failed: %v", err)
	}
	if b.Engine != "backhaul" {
		t.Fatalf("expected engine=backhaul, got %s", b.Engine)
	}
	if b.IranPub != iranPub {
		t.Fatalf("expected iranPub=%s, got %s", iranPub, b.IranPub)
	}
	if b.FrpPort != bhPort {
		t.Fatalf("expected frpPort=%d, got %d", bhPort, b.FrpPort)
	}
	if b.Transport != transport {
		t.Fatalf("expected transport=%s, got %s", transport, b.Transport)
	}
	if b.Token != token {
		t.Fatalf("expected token=%s, got %s", token, b.Token)
	}
	if len(b.RawPorts) != 3 || b.RawPorts[0] != "443" || b.RawPorts[1] != "10000-10050" || b.RawPorts[2] != "2083=8443" {
		t.Fatalf("unexpected raw ports: %+v", b.RawPorts)
	}
	if len(b.Ports) != 3 || b.Ports[0] != 443 || b.Ports[1] != 10000 || b.Ports[2] != 2083 {
		t.Fatalf("unexpected extracted numeric ports: %+v", b.Ports)
	}

	// 3. Unified ParseBundle auto-detects bh1_
	unified, err := ParseBundle(bStr)
	if err != nil {
		t.Fatalf("unified ParseBundle failed: %v", err)
	}
	if unified.Engine != "backhaul" || unified.IranPub != iranPub || unified.Transport != transport {
		t.Fatalf("unified bundle mismatch: %+v", unified)
	}

	// 4. Test applyBundle on setupRequest
	req := setupRequest{Role: "foreign", Token: bStr}
	applyBundle(&req, unified)
	if req.Engine != "backhaul" {
		t.Fatalf("expected req.Engine=backhaul, got %s", req.Engine)
	}
	if req.Transport != "tcpmux" {
		t.Fatalf("expected req.Transport=tcpmux, got %s", req.Transport)
	}
	if req.RemotePub != iranPub {
		t.Fatalf("expected req.RemotePub=%s, got %s", iranPub, req.RemotePub)
	}
	if req.FrpPort != bhPort {
		t.Fatalf("expected req.FrpPort=%d, got %d", bhPort, req.FrpPort)
	}
	if req.LocalGre != "" || req.PeerGre != "" {
		t.Fatalf("expected empty GRE IPs for standalone Backhaul, got local=%s, peer=%s", req.LocalGre, req.PeerGre)
	}
	if !strings.Contains(req.Ports, "10000-10050") || !strings.Contains(req.Ports, "2083=8443") {
		t.Fatalf("expected raw ports in req.Ports, got %s", req.Ports)
	}
}

func TestGreBackhaulBundleMakeAndParse(t *testing.T) {
	iranPub := "5.6.7.8"
	bhPort := 4080
	iranGre := "10.10.10.2"
	foreignGre := "10.10.10.1"
	transport := "wssmux"
	token := "gh-secret-token-67890"
	rawPorts := []string{"80", "443", "8080=80"}

	// 1. Make GRE+Backhaul bundle
	bStr := MakeGreBackhaulBundle(iranPub, bhPort, iranGre, foreignGre, transport, token, rawPorts)
	if !strings.HasPrefix(bStr, "gh1_") {
		t.Fatalf("expected bundle to start with gh1_, got %s", bStr)
	}

	// 2. ParseGreBackhaulBundle directly
	b, err := ParseGreBackhaulBundle(bStr)
	if err != nil {
		t.Fatalf("ParseGreBackhaulBundle failed: %v", err)
	}
	if b.Engine != "gre-backhaul" {
		t.Fatalf("expected engine=gre-backhaul, got %s", b.Engine)
	}
	if b.IranPub != iranPub || b.FrpPort != bhPort || b.IranGre != iranGre || b.ForeignGre != foreignGre {
		t.Fatalf("unexpected fields in GRE bundle: %+v", b)
	}
	if b.Transport != transport || b.Token != token {
		t.Fatalf("unexpected transport/token: %+v", b)
	}
	if len(b.RawPorts) != 3 || b.RawPorts[2] != "8080=80" {
		t.Fatalf("unexpected raw ports: %+v", b.RawPorts)
	}

	// 3. Unified ParseBundle auto-detects gh1_
	unified, err := ParseBundle(bStr)
	if err != nil {
		t.Fatalf("unified ParseBundle failed: %v", err)
	}
	if unified.Engine != "gre-backhaul" {
		t.Fatalf("expected engine=gre-backhaul, got %s", unified.Engine)
	}

	// 4. Test applyBundle on setupRequest
	req := setupRequest{Role: "foreign", Token: bStr}
	applyBundle(&req, unified)
	if req.Engine != "gre-backhaul" {
		t.Fatalf("expected req.Engine=gre-backhaul, got %s", req.Engine)
	}
	if req.LocalGre != foreignGre || req.PeerGre != iranGre {
		t.Fatalf("expected foreignGre=%s and iranGre=%s, got local=%s, peer=%s", foreignGre, iranGre, req.LocalGre, req.PeerGre)
	}
}

func TestBackhaulPortParsingAndValidation(t *testing.T) {
	// Valid single ports, ranges, mappings
	validCases := []string{
		"443",
		"80",
		"10000-10050",
		"2083=8443",
		"8080=80",
		"1-65535",
		"10000-10050=443",
		"443=1.1.1.1:5201",
		"127.0.0.2:443=1.1.1.1:5201",
	}
	for _, c := range validCases {
		if !isValidPortOrRangeOrMapping(c) {
			t.Errorf("expected %q to be valid", c)
		}
	}

	// Invalid cases
	invalidCases := []string{
		"",
		"0",
		"70000",
		"abc",
		"10050-10000", // p1 > p2
		"100-",
		"-100",
		"=80",
		"80=",
		"80=90000",
		"1.2.3:443",
		"443=1.1.1:80",
		"10000-10050:443", // the core rejects it; parseRawPorts rewrites it first
	}
	for _, c := range invalidCases {
		if isValidPortOrRangeOrMapping(c) {
			t.Errorf("expected %q to be invalid", c)
		}
	}

	raw := "443, 10000-10050, 2083=8443, invalid, 443"
	parsed := parseRawPorts(raw)
	if len(parsed) != 3 || parsed[0] != "443" || parsed[1] != "10000-10050" || parsed[2] != "2083=8443" {
		t.Fatalf("unexpected parseRawPorts result: %+v", parsed)
	}

	nums := extractNumericPorts(parsed)
	if len(nums) != 3 || nums[0] != 443 || nums[1] != 10000 || nums[2] != 2083 {
		t.Fatalf("unexpected extractNumericPorts result: %+v", nums)
	}
}

func TestBackhaulTomlGenerators(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "backhaul-toml-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// 1. Write server config
	serverPath := filepath.Join(tmpDir, "server.toml")
	err = writeBackhaulServerConfig(serverPath, "0.0.0.0:3080", "tcpmux", "secretToken", []string{"443", "10000-10050"})
	if err != nil {
		t.Fatalf("writeBackhaulServerConfig failed: %v", err)
	}
	sData, err := os.ReadFile(serverPath)
	if err != nil {
		t.Fatal(err)
	}
	sContent := string(sData)
	if !strings.Contains(sContent, `bind_addr = "0.0.0.0:3080"`) ||
		!strings.Contains(sContent, `transport = "tcpmux"`) ||
		!strings.Contains(sContent, `token = "secretToken"`) ||
		!strings.Contains(sContent, `"10000-10050"`) {
		t.Fatalf("server.toml missing expected fields:\n%s", sContent)
	}

	// 2. Rewrite server TOML ports
	updated := rewriteBackhaulTomlPorts(sContent, []string{"8443", "2083=8443"})
	if !strings.Contains(updated, `"8443"`) || !strings.Contains(updated, `"2083=8443"`) || strings.Contains(updated, `"10000-10050"`) {
		t.Fatalf("rewritten TOML did not properly replace ports:\n%s", updated)
	}

	// 3. Write client config
	clientPath := filepath.Join(tmpDir, "client.toml")
	err = writeBackhaulClientConfig(clientPath, "1.2.3.4:3080", "tcpmux", "secretToken")
	if err != nil {
		t.Fatalf("writeBackhaulClientConfig failed: %v", err)
	}
	cData, err := os.ReadFile(clientPath)
	if err != nil {
		t.Fatal(err)
	}
	cContent := string(cData)
	if !strings.Contains(cContent, `remote_addr = "1.2.3.4:3080"`) ||
		!strings.Contains(cContent, `transport = "tcpmux"`) ||
		!strings.Contains(cContent, `token = "secretToken"`) {
		t.Fatalf("client.toml missing expected fields:\n%s", cContent)
	}
}

func TestBackhaulPeersPatchWithRangesAndMappings(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "backhaul-patch-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	oldConfigDir := configDir
	configDir = tmpDir
	defer func() { configDir = oldConfigDir }()

	// Seed peers.json with a Backhaul peer
	mockPeer := peerRecord{
		ID:        2,
		Name:      "De-Frankfurt-BH",
		LocalPub:  "1.2.3.4",
		RemotePub: "5.6.7.8",
		FrpPort:   3080,
		Engine:    "backhaul",
		Transport: "tcpmux",
		NoGre:     true,
		Token:     "bh-token-xyz",
		Ports:     []int{443},
		RawPorts:  []string{"443"},
		FrpsSvc:   "backhaul-server-2",
	}
	peersJSON, _ := json.MarshalIndent(map[string]any{"peers": []peerRecord{mockPeer}}, "", "  ")
	if err := os.WriteFile(peersFile(), peersJSON, 0600); err != nil {
		t.Fatal(err)
	}

	// Test PATCH /api/peers with raw_ports range and mapping
	trueVal := true
	patchReq := peerPatchRequest{
		ID:             2,
		Name:           "De-Frankfurt-Renamed",
		Transport:      "wssmux",
		RawPorts:       &[]string{"443", "10000-10050", "2083=8443"},
		ProxyProtocol:  "v2",
		FRPTransport:   "quic",
		UseEncryption:  &trueVal,
		UseCompression: &trueVal,
	}
	bodyBytes, _ := json.Marshal(patchReq)
	req := httptest.NewRequest("PATCH", "/api/peers", bytes.NewReader(bodyBytes))
	w := httptest.NewRecorder()

	handlePeersPatch(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["status"] != "ok" {
		t.Fatalf("expected status=ok, got %+v", resp)
	}

	// Verify updated peers.json
	updatedPeers := loadPeers()
	if len(updatedPeers) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(updatedPeers))
	}
	p := updatedPeers[0]
	if p.Name != "De-Frankfurt-Renamed" {
		t.Errorf("expected updated name, got %s", p.Name)
	}
	if p.Transport != "wssmux" {
		t.Errorf("expected updated transport wssmux, got %s", p.Transport)
	}
	if p.ProxyProtocol != "v2" {
		t.Errorf("expected updated proxy_protocol v2, got %s", p.ProxyProtocol)
	}
	if p.FRPTransport != "quic" {
		t.Errorf("expected updated frp_transport quic, got %s", p.FRPTransport)
	}
	if !p.UseEncryption {
		t.Errorf("expected updated use_encryption true")
	}
	if !p.UseCompression {
		t.Errorf("expected updated use_compression true")
	}
	if len(p.RawPorts) != 3 || p.RawPorts[1] != "10000-10050" || p.RawPorts[2] != "2083=8443" {
		t.Errorf("unexpected raw ports in registry: %+v", p.RawPorts)
	}
	if len(p.Ports) != 3 || p.Ports[1] != 10000 || p.Ports[2] != 2083 {
		t.Errorf("unexpected numeric ports in registry: %+v", p.Ports)
	}

	// Verify returned bundle is a valid bh1_ bundle with updated transport and ports
	bundleStr, ok := resp["bundle"].(string)
	if !ok || !strings.HasPrefix(bundleStr, "bh1_") {
		t.Fatalf("expected returned bundle to start with bh1_, got %v", resp["bundle"])
	}
	parsedBundle, err := ParseBackhaulBundle(bundleStr)
	if err != nil {
		t.Fatalf("failed to parse returned bundle: %v", err)
	}
	if parsedBundle.Transport != "wssmux" {
		t.Errorf("expected bundle transport wssmux, got %s", parsedBundle.Transport)
	}
	if len(parsedBundle.RawPorts) != 3 {
		t.Errorf("expected 3 raw ports in bundle, got %d", len(parsedBundle.RawPorts))
	}
}

func TestParseRawPortsBackhaulForms(t *testing.T) {
	got := parseRawPorts("10000-10050:443 127.0.0.2:443=1.1.1.1:5201,8080")
	want := []string{"10000-10050=443", "127.0.0.2:443=1.1.1.1:5201", "8080"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("parseRawPorts = %v, want %v", got, want)
	}
	if nums := extractNumericPorts(got); len(nums) != 3 || nums[0] != 10000 || nums[1] != 443 || nums[2] != 8080 {
		t.Fatalf("extractNumericPorts = %v", nums)
	}
}

func TestBackhaulTransportOK(t *testing.T) {
	for _, ok := range []string{"tcp", "tcpmux", "ws", "wss", "wsmux", "wssmux", "udp"} {
		if !backhaulTransportOK(ok) {
			t.Errorf("%q refused", ok)
		}
	}
	for _, bad := range []string{"", "anytls", "xtcpmux", "tun", "kcp"} {
		if backhaulTransportOK(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
	if _, err := switchTunnelEngine("backhaul", "anytls"); err == nil || !strings.Contains(err.Error(), "invalid Backhaul transport") {
		t.Fatalf("switchTunnelEngine(anytls) err = %v", err)
	}
}
