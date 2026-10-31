package main

// Setup API: validate the web form, then run the SAME hashem.sh install
// functions the CLI/menu use (single source of truth). The request fields
// map 1:1 to the setup-iran / setup-foreign CLI flags at the bottom of
// hashem.sh, and the installer script path is resolved next to the binary so it
// works both in dev (./hashem.sh) and on servers (/usr/local/bin/).
//
// Iran side: GRE + frps (token auto-generated, shown for copy to Foreign).
// Foreign side: GRE + frpc (token entered manually, ports like "443, 2083").
//
// Setup bundle: the Iran side also returns a single readable string holding
// everything the foreign side needs:
//   hsh1_<IRAN_PUB>_<FRP_PORT>_<IRAN_GRE>_<FOREIGN_GRE>_<TOKEN>[_<PORTS>]
// Pasting it into the foreign token field auto-fills the rest (explicit
// fields always win). Legacy 32-char tokens (no hsh1_ prefix) keep working.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultIranGRE    = "10.10.10.2"
	defaultForeignGRE = "10.10.10.1"
	defaultFrpPortMin = 20000
	defaultFrpPortMax = 60000

	// bundlePrefix marks a single-string foreign-setup bundle:
	// hsh1_<IRAN_PUB>_<FRP_PORT>_<IRAN_GRE>_<FOREIGN_GRE>_<TOKEN>[_<PORTS>]
	bundlePrefix            = "hsh1_"
	bundlePrefixBackhaul    = "bh1_"
	bundlePrefixGreBackhaul = "gh1_"
)

// ---- hashem.sh location ----

// scriptPath finds the installer: HASHEM_SCRIPT env wins, legacy
// GRE_SCRIPT still accepted, else <bindir>/hashem.sh (servers: alongside
// /usr/local/bin/gre-panel), else legacy <bindir>/gre.sh or
// /usr/local/bin/gre.sh, else ./hashem.sh (repo dev).
// update_all() migrates servers to the new name; old paths are read-only
// fallbacks so already-installed servers never break.
func greScriptPath() (string, error) {
	if p := os.Getenv("HASHEM_SCRIPT"); p != "" {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
		return "", fmt.Errorf("HASHEM_SCRIPT=%s not found", p)
	}
	if p := os.Getenv("GRE_SCRIPT"); p != "" {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
		return "", fmt.Errorf("GRE_SCRIPT=%s not found", p)
	}
	if exe, err := os.Executable(); err == nil {
		if p := filepath.Join(filepath.Dir(exe), "hashem.sh"); fileExists(p) {
			return p, nil
		}
		if p := filepath.Join(filepath.Dir(exe), "gre.sh"); fileExists(p) {
			return p, nil
		}
	}
	if fileExists("/usr/local/bin/hashem.sh") {
		return "/usr/local/bin/hashem.sh", nil
	}
	if fileExists("/usr/local/bin/gre.sh") {
		return "/usr/local/bin/gre.sh", nil
	}
	if fileExists("/usr/local/bin/hashem") {
		if abs, err := filepath.Abs("/usr/local/bin/hashem"); err == nil {
			return abs, nil
		}
		return "/usr/local/bin/hashem", nil
	}
	if fileExists("hashem.sh") {
		if abs, err := filepath.Abs("hashem.sh"); err == nil {
			return abs, nil
		}
		return "hashem.sh", nil
	}
	if fileExists("gre.sh") {
		if abs, err := filepath.Abs("gre.sh"); err == nil {
			return abs, nil
		}
		return "gre.sh", nil
	}
	return "", fmt.Errorf("hashem.sh not found (set HASHEM_SCRIPT=/path/to/hashem.sh)")
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// greScriptTarget is where syncPanelScript writes the fresh script:
// same place greScriptPath() reads from (HASHEM_SCRIPT wins, else next to
// the running binary, else ./hashem.sh for panel/ dev).
func greScriptTarget() string {
	if p := os.Getenv("HASHEM_SCRIPT"); p != "" {
		return p
	}
	if p := os.Getenv("GRE_SCRIPT"); p != "" {
		return p
	}
	if exe, err := os.Executable(); err == nil {
		return filepath.Join(filepath.Dir(exe), panelScriptName)
	}
	return panelScriptName
}

// ensureFreshScript checks the script on disk supports recent features
// (add-peer CLI verb and --bundle flag in setup-foreign); if not (stale copy),
// it pulls the latest hashem.sh from main (bash -n verified) and replaces it — so
// setup requests self-heal instead of failing with E-INSTALL-02.
func ensureFreshScript(script string) {
	data, err := os.ReadFile(script)
	if err != nil {
		return
	}
	content := string(data)
	if strings.Contains(content, "add-peer") && strings.Contains(content, "--bundle") {
		return
	}
	syncPanelScript()
}

// ---- GET /api/setup: defaults + whether a tunnel already exists ----

func currentIranBundle() (string, string) {
	st := currentLocal()

	var setupMeta struct {
		Role       string `json:"role"`
		LocalPub   string `json:"local_public"`
		RemotePub  string `json:"remote_public"`
		Token      string `json:"token"`
		IranGre    string `json:"iran_gre"`
		ForeignGre string `json:"foreign_gre"`
		FrpPort    int    `json:"frp_port"`
		Ports      string `json:"ports"`
		Engine     string `json:"engine"`
		Transport  string `json:"transport"`
	}
	if sData, err := os.ReadFile(filepath.Join(configDir, "setup.json")); err == nil {
		_ = json.Unmarshal(sData, &setupMeta)
	}

	iranPub := setupMeta.LocalPub
	if iranPub == "" {
		iranPub = detectPublicIP()
	}
	if iranPub == "" {
		iranPub = st.LocalPub
	}
	if iranPub == "" {
		iranPub = "127.0.0.1"
	}

	// GRE inner addresses actually in use: the setup record, else the live
	// tunnel, else the defaults. A bundle with the defaults breaks the
	// tunnel when the admin chose other addresses.
	iranGre, foreignGre := setupMeta.IranGre, setupMeta.ForeignGre
	if iranGre == "" {
		iranGre = strings.SplitN(st.Gre.Inner, "/", 2)[0]
	}
	if foreignGre == "" && st.Gre.Inner != "" {
		foreignGre = grePeerInner(st.Gre.Inner) // st.GrePeer is the outer (public) address
	}
	if iranGre == "" || foreignGre == "" {
		iranGre, foreignGre = defaultIranGRE, defaultForeignGRE
	}

	// Backhaul server
	if st.FrpSvc == "backhaul-server" || st.Engine == "backhaul" || st.Engine == "gre-backhaul" || setupMeta.Engine == "backhaul" || setupMeta.Engine == "gre-backhaul" {
		data, err := os.ReadFile(filepath.Join(backhaulDir, "config.toml"))
		if err != nil {
			data, err = os.ReadFile(filepath.Join(backhaulDir, "server.toml"))
		}
		if err == nil {
			var token, transport string
			var rawPorts []string
			for _, line := range strings.Split(string(data), "\n") {
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "token") {
					parts := strings.Split(trimmed, "=")
					if len(parts) >= 2 {
						token = strings.Trim(strings.TrimSpace(parts[1]), `"' `)
					}
				}
				if strings.HasPrefix(trimmed, "transport") {
					parts := strings.Split(trimmed, "=")
					if len(parts) >= 2 {
						transport = strings.Trim(strings.TrimSpace(parts[1]), `"' `)
					}
				}
				if strings.HasPrefix(trimmed, `"`) {
					pStr := strings.Trim(trimmed, `", `)
					if pStr != "" {
						rawPorts = append(rawPorts, pStr)
					}
				}
			}
			bindPort := st.BindPort
			if bindPort <= 0 {
				bindPort = st.FrpPort
			}
			if bindPort <= 0 {
				bindPort = setupMeta.FrpPort
			}
			if bindPort <= 0 {
				bindPort = 3080
			}
			if token != "" {
				if st.Engine == "gre-backhaul" || setupMeta.Engine == "gre-backhaul" || st.Gre.Exists {
					return MakeGreBackhaulBundle(iranPub, bindPort, iranGre, foreignGre, backhaulBundleTransport(transport, backhaulUDPPort("backhaul-server")), token, rawPorts), token
				}
				return MakeBackhaulBundle(iranPub, bindPort, backhaulBundleTransport(transport, backhaulUDPPort("backhaul-server")), token, rawPorts), token
			}
		}
	}

	// FRP server
	data, err := os.ReadFile(filepath.Join(frpDir, "frps.toml"))
	if err == nil {
		var token string
		for _, line := range strings.Split(string(data), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "auth.token") {
				parts := strings.Split(trimmed, "=")
				if len(parts) >= 2 {
					token = strings.Trim(strings.TrimSpace(parts[1]), `"' `)
				}
			}
		}
		if token != "" && st.FrpPort > 0 {
			return MakeBundle(iranPub, st.FrpPort, iranGre, foreignGre, token, st.ProxyPorts), token
		}
	}

	// Fallback to setup.json metadata if server is configured but TOML not accessible
	if setupMeta.Token != "" {
		p := setupMeta.FrpPort
		if p <= 0 {
			p = st.FrpPort
		}
		if p <= 0 {
			p = 7000
		}
		iGre := setupMeta.IranGre
		if iGre == "" {
			iGre = defaultIranGRE
		}
		fGre := setupMeta.ForeignGre
		if fGre == "" {
			fGre = defaultForeignGRE
		}
		ports := st.ProxyPorts
		if len(ports) == 0 && setupMeta.Ports != "" {
			for _, part := range strings.Split(setupMeta.Ports, ",") {
				if v, err := strconv.Atoi(strings.TrimSpace(part)); err == nil {
					ports = append(ports, v)
				}
			}
		}
		if setupMeta.Engine == "backhaul" {
			return MakeBackhaulBundle(iranPub, p, backhaulBundleTransport(setupMeta.Transport, backhaulUDPPort("backhaul-server")), setupMeta.Token, []string{setupMeta.Ports}), setupMeta.Token
		}
		if setupMeta.Engine == "gre-backhaul" {
			return MakeGreBackhaulBundle(iranPub, p, iGre, fGre, backhaulBundleTransport(setupMeta.Transport, backhaulUDPPort("backhaul-server")), setupMeta.Token, []string{setupMeta.Ports}), setupMeta.Token
		}
		return MakeBundle(iranPub, p, iGre, fGre, setupMeta.Token, ports), setupMeta.Token
	}

	return "", ""
}

func handleSetupGet(w http.ResponseWriter, r *http.Request) {
	st := currentLocal()
	resp := map[string]any{
		"local_public":  detectPublicIP(),
		"local_public6": detectPublicIP6(),
		"iran_gre":      defaultIranGRE,
		"foreign_gre":   defaultForeignGRE,
		"frp_port":      randomFrpPort(),
		"role_guess":    st.Role,
		"exists":        tunnelExists(),
	}
	if bStr, tok := currentIranBundle(); bStr != "" {
		resp["bundle"] = bStr
		resp["token"] = tok
	}
	writeJSON(w, resp)
}

func tunnelExists() bool {
	if out, err := exec.Command("ip", "tunnel", "show").CombinedOutput(); err == nil {
		if strings.Contains(string(out), "gre-tunnel") {
			return true
		}
	}
	if out, err := exec.Command("ip", "link", "show", "gre-tunnel").CombinedOutput(); err == nil {
		if strings.Contains(string(out), "gre-tunnel") {
			return true
		}
	}
	// FRP, and Backhaul without GRE (its first tunnel has no gre-tunnel)
	for _, f := range []string{filepath.Join(frpDir, "frps.toml"), filepath.Join(frpDir, "frpc.toml"),
		filepath.Join(backhaulDir, "config.toml"), filepath.Join(backhaulDir, "server.toml"), filepath.Join(backhaulDir, "client.toml")} {
		if _, err := os.Stat(f); err == nil {
			return true
		}
	}
	return false
}

// detectPublicIP returns this server's public IPv4. The route source address
// is only used when it is public: behind NAT (many clouds) it is a private
// address, which broke bundles, DNS checks and URLs. Then the address the
// admin entered at setup, then an external lookup (cached), and only as a last
// resort the private source address.
func detectPublicIP() string {
	src := routeSourceIP()
	if src != "" && !isPrivateIP(src) {
		return src
	}
	if v := savedPublicIP(); v != "" {
		return v
	}
	if v := externalPublicIPCached(); v != "" {
		return v
	}
	return src
}

func routeSourceIP() string {
	out, err := runCmdTimeout(5*time.Second, "ip", "route", "get", "1.1.1.1")
	if err == nil {
		f := strings.Fields(string(out))
		for i, p := range f {
			if p == "src" && i+1 < len(f) {
				if net.ParseIP(f[i+1]) != nil {
					return f[i+1]
				}
			}
		}
	}
	return ""
}

// savedPublicIP is the public address recorded in setup.json, if valid.
func savedPublicIP() string {
	var meta struct {
		LocalPub string `json:"local_public"`
	}
	if data, err := os.ReadFile(filepath.Join(configDir, "setup.json")); err == nil {
		_ = json.Unmarshal(data, &meta)
	}
	if ip := strings.TrimSpace(meta.LocalPub); net.ParseIP(ip) != nil && !isPrivateIP(ip) {
		return ip
	}
	return ""
}

var (
	extIPMu   sync.Mutex
	extIPVal  string
	extIPTime time.Time
	// externalIPLookup asks public "what is my IP" services; swappable for tests.
	externalIPLookup = lookupExternalPublicIP
)

// externalPublicIPCached caches the external lookup (30 min, failures 2 min),
// since detectPublicIP runs from request handlers and lookups can be slow or
// filtered from Iran.
func externalPublicIPCached() string {
	extIPMu.Lock()
	defer extIPMu.Unlock()
	if extIPVal != "" && time.Since(extIPTime) < 30*time.Minute {
		return extIPVal
	}
	if extIPVal == "" && !extIPTime.IsZero() && time.Since(extIPTime) < 2*time.Minute {
		return ""
	}
	extIPTime = time.Now()
	if v := externalIPLookup(); v != "" {
		extIPVal = v
	}
	return extIPVal
}

// The tunnel and the bundles are IPv4 only, so the lookup dials over IPv4:
// on a dual-stack host these services otherwise answer with the IPv6 address.
func lookupExternalPublicIP() string {
	dialer := &net.Dialer{Timeout: 1200 * time.Millisecond}
	client := &http.Client{Timeout: 1200 * time.Millisecond, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp4", addr)
		},
	}}
	for _, u := range []string{"https://api.ipify.org", "https://ipv4.icanhazip.com", "https://ifconfig.me/ip"} {
		resp, err := client.Get(u)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
		_ = resp.Body.Close()
		candidate := strings.TrimSpace(string(body))
		if resp.StatusCode == 200 && isV4(candidate) && !isPrivateIP(candidate) {
			return candidate
		}
	}
	return ""
}

// detectPublicIP6 is this server's public IPv6, or "": the route source when it
// is a global address, else an external lookup over IPv6 (cached like the
// IPv4 one).
func detectPublicIP6() string {
	if src := routeSourceIP6(); validPublicIP(src, 6) {
		return src
	}
	return externalPublicIP6Cached()
}

func routeSourceIP6() string { return routeSourceTo6("2001:4860:4860::8888") }

// routeSourceTo6 is the source address this server uses towards IPv6 dst.
func routeSourceTo6(dst string) string {
	out, err := runCmdTimeout(5*time.Second, "ip", "-6", "route", "get", dst)
	if err != nil {
		return ""
	}
	f := strings.Fields(string(out))
	for i, p := range f {
		if p == "src" && i+1 < len(f) && isV6(f[i+1]) {
			return f[i+1]
		}
	}
	return ""
}

var (
	extIP6Mu   sync.Mutex
	extIP6Val  string
	extIP6Time time.Time
	// externalIP6Lookup is externalIPLookup over IPv6; swappable for tests.
	externalIP6Lookup = lookupExternalPublicIP6
)

func externalPublicIP6Cached() string {
	extIP6Mu.Lock()
	defer extIP6Mu.Unlock()
	if extIP6Val != "" && time.Since(extIP6Time) < 30*time.Minute {
		return extIP6Val
	}
	if extIP6Val == "" && !extIP6Time.IsZero() && time.Since(extIP6Time) < 2*time.Minute {
		return ""
	}
	extIP6Time = time.Now()
	if v := externalIP6Lookup(); v != "" {
		extIP6Val = v
	}
	return extIP6Val
}

func lookupExternalPublicIP6() string {
	dialer := &net.Dialer{Timeout: 1200 * time.Millisecond}
	client := &http.Client{Timeout: 1200 * time.Millisecond, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp6", addr)
		},
	}}
	for _, u := range []string{"https://api6.ipify.org", "https://ipv6.icanhazip.com"} {
		resp, err := client.Get(u)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
		_ = resp.Body.Close()
		candidate := strings.TrimSpace(string(body))
		if resp.StatusCode == 200 && validPublicIP(candidate, 6) {
			return candidate
		}
	}
	return ""
}

// ---- POST /api/setup ----

type setupRequest struct {
	Role           string `json:"role"`                 // "iran" | "foreign" | "add-peer"
	Engine         string `json:"engine,omitempty"`     // "" | "frp" | "backhaul" | "gre-backhaul"
	Transport      string `json:"transport,omitempty"`  // "tcpmux" (default), "tcp", "ws", "wss", "wsmux", "wssmux", "udp"
	AcceptUDP      bool   `json:"accept_udp,omitempty"` // Backhaul: also forward UDP (tcp: inside the tunnel; tcpmux/ws/wss: a udp companion)
	UDPPort        int    `json:"udp_port,omitempty"`   // foreign: the Iran companion's control port (from the bundle)
	Name           string `json:"name"`                 // add-peer label
	LocalPub       string `json:"local_public"`
	RemotePub      string `json:"remote_public"`
	LocalGre       string `json:"local_gre"`
	PeerGre        string `json:"peer_gre"`
	FrpPort        int    `json:"frp_port"`
	Token          string `json:"token"` // foreign/add-peer (manual or auto)
	Ports          string `json:"ports"` // foreign/add-peer, e.g. "443, 2083, 8080"
	Force          bool   `json:"force"`
	Autogen        bool   `json:"autogen"`                   // add-peer: generate token server-side
	ProxyProtocol  string `json:"proxy_protocol,omitempty"`  // "off" | "v2" | "v1"
	FRPTransport   string `json:"frp_transport,omitempty"`   // "tcp" | "kcp" | "quic" | "websocket" | "wss"
	UseEncryption  bool   `json:"use_encryption,omitempty"`  // transport.useEncryption
	UseCompression bool   `json:"use_compression,omitempty"` // transport.useCompression
	Dial           string `json:"dial,omitempty"`            // foreign over GRE: "auto" (default) | "gre" | "public"
	// OrigBundle holds the raw hsh1_... string when setup-foreign is invoked
	// via a bundle paste. applyBundle() fills every explicit field AND stores
	// the bundle here so runInstaller can pass --bundle to hashem.sh (which
	// handles carrier/FOU setup that the explicit flags do not cover).
	OrigBundle string `json:"-"` // internal; not sent by client
}

func handleSetupPost(w http.ResponseWriter, r *http.Request) {
	var body setupRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeAPIError(w, r, "E-SETUP-01", "")
		return
	}
	body.LocalPub = strings.TrimSpace(body.LocalPub)
	body.RemotePub = strings.TrimSpace(body.RemotePub)
	body.LocalGre = strings.TrimSpace(body.LocalGre)
	body.PeerGre = strings.TrimSpace(body.PeerGre)
	body.Token = strings.TrimSpace(body.Token)
	body.Name = strings.TrimSpace(body.Name)
	if err := validLinkName(body.Name); err != nil {
		writeAPIError(w, r, "E-SETUP-01", err.Error())
		return
	}

	// add-peer mode: each new foreign server gets its own token + tunnel.
	// Port conflicts (same remotePort on two peers) are rejected with 409
	// so the user picks another port instead of silently breaking a peer.
	if body.Role == "add-peer" {
		if body.Autogen || body.Token == "" {
			body.Token = randomToken(32)
		}
		if len(loadPeers()) >= maxPeers() {
			writeAPIError(w, r, "E-PEER-01", "")
			return
		}
	}

	// bundle paste: a foreign-setup string in the token field auto-fills
	// whatever the user left empty (explicit fields always win).
	// Malformed bundles fail fast with E-SETUP-08, before field checks.
	if body.Role == "foreign" && isBundle(body.Token) {
		b, err := ParseBundle(body.Token)
		if err != nil {
			writeAPIError(w, r, "E-SETUP-08", "bad setup bundle: "+err.Error())
			return
		}
		// Preserve the original bundle string for runInstaller before
		// applyBundle() replaces body.Token with the inner token.
		body.OrigBundle = body.Token
		applyBundle(&body, b)
	}
	if (body.Engine == "backhaul" || body.Engine == "gre-backhaul") && proRequired(w, r, proBackhaul, "Backhaul") {
		return
	}

	// validation (mirrors hashem.sh prompt_* / validate_setup_common rules)
	if body.Role != "iran" && body.Role != "foreign" && body.Role != "add-peer" {
		writeAPIError(w, r, "E-SETUP-02", "")
		return
	}
	if net.ParseIP(body.LocalPub) == nil {
		writeAPIError(w, r, "E-SETUP-03", "")
		return
	}
	if net.ParseIP(body.RemotePub) == nil {
		writeAPIError(w, r, "E-SETUP-04", "")
		return
	}
	if body.Engine != "backhaul" {
		// GRE runs between the two IPv4 addresses
		if !isV4(body.LocalPub) || !isV4(body.RemotePub) {
			writeAPIError(w, r, "E-SETUP-04", "a tunnel over GRE needs the IPv4 addresses of both servers; for IPv6 use Backhaul without GRE")
			return
		}
		if net.ParseIP(body.LocalGre) == nil || !isV4(body.LocalGre) {
			writeAPIError(w, r, "E-SETUP-05", "")
			return
		}
		if net.ParseIP(body.PeerGre) == nil || !isV4(body.PeerGre) {
			writeAPIError(w, r, "E-SETUP-06", "")
			return
		}
	}
	if body.FrpPort < 1 || body.FrpPort > 65535 {
		writeAPIError(w, r, "E-SETUP-07", "")
		return
	}

	var ports []int
	var rawPorts []string
	if body.Ports != "" {
		if body.Engine == "backhaul" || body.Engine == "gre-backhaul" {
			rawPorts = parseRawPorts(body.Ports)
			ports = extractNumericPorts(rawPorts)
		} else {
			ports = parsePorts(body.Ports)
			for _, p := range ports {
				rawPorts = append(rawPorts, strconv.Itoa(p))
			}
		}
	}
	if body.Role == "foreign" || body.Role == "add-peer" {
		if body.Token == "" {
			writeAPIError(w, r, "E-SETUP-08", "")
			return
		}
		if !isBundle(body.Token) && len(body.Token) > 128 {
			writeAPIError(w, r, "E-SETUP-09", "")
			return
		}
		if isBundle(body.Token) && len(body.Token) > 256 {
			writeAPIError(w, r, "E-SETUP-09", "")
			return
		}
		if len(rawPorts) == 0 && len(ports) == 0 {
			writeAPIError(w, r, "E-SETUP-10", "")
			return
		}
	}

	// add-peer pre-check: reject ports another tunnel already serves (409 + peer name)
	if body.Role == "add-peer" {
		if clash := peerDuplicateIPClash(body.RemotePub, -1); clash != "" {
			writeAPIError(w, r, "E-PEER-08", "Foreign IP is already used by tunnel '"+clash+"' — you cannot add multiple tunnels to the exact same server")
			return
		}
		if clash := peerPortClash(ports, -1); clash != "" {
			writeAPIError(w, r, "E-PEER-02", "port "+clash+" is already served by another tunnel — pick a different port")
			return
		}
	}

	// overwrite guard: warn first, proceed only with force
	// add-peer never overwrites: it appends a new tunnel instead.
	if body.Role != "add-peer" && tunnelExists() && !body.Force {
		writeAPIError(w, r, "E-PEER-03", "tunnel already exists — resubmit with force:true to overwrite")
		return
	}

	// run the shared installer: GRE_SKIP_PANEL=1 because the panel is already
	// running here — reinstalling/downloading it mid-request would be slow and
	// could restart this very process.
	token, bundle, steps, err := runInstaller(body, ports, rawPorts)
	if err != nil {
		steps = append(steps, "FAILED: "+err.Error())
		code := "E-INSTALL-02"
		if strings.Contains(err.Error(), "not found") {
			code = "E-INSTALL-01"
		}
		info := errCatalog[code]
		recordError(code, r.Method+" "+r.URL.Path, err.Error())
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(info.Status)
		resp := map[string]any{"error_code": code, "error": err.Error(), "hint": info.Hint, "steps": steps}
		if token != "" {
			resp["token"] = token
		}
		if bundle != "" {
			resp["bundle"] = bundle
		}
		_ = json.NewEncoder(w).Encode(resp)
		return
	}
	out := map[string]any{"status": "ok", "steps": steps}
	if token != "" {
		out["token"] = token
	}
	if bundle != "" {
		out["bundle"] = bundle
	}

	// Auto-configure peer synchronization link
	if body.Role == "iran" && token != "" {
		pcfg := loadPeerConfig()
		pcfg.Role = "master"
		pcfg.PeerSecret = token
		if body.PeerGre != "" {
			pcfg.InternalIP = body.PeerGre
		}
		_ = savePeerConfig(pcfg)
	} else if body.Role == "foreign" {
		// perf.json is what perf apply (also run on every update) writes back
		// into frpc.toml; without this the setup choice was removed again.
		if body.Engine == "" || body.Engine == "frp" {
			pc := loadPerfConfig()
			pc.ProxyEncryption, pc.ProxyCompression = body.UseEncryption, body.UseCompression
			if validProxyProtocol(body.ProxyProtocol) {
				pc.ProxyProtocol = body.ProxyProtocol
			} else {
				pc.ProxyProtocol = "off"
			}
			_ = savePerfConfig(pc)
		}
		pcfg := loadPeerConfig()
		pcfg.Role = "worker"
		if body.Token != "" {
			pcfg.PeerSecret = body.Token
		}
		if body.PeerGre != "" {
			pcfg.InternalIP = body.PeerGre
		}
		if body.RemotePub != "" {
			// The master's panel port is unknown here (each panel picks its
			// own); without a port sendToPeer tries the usual ones, and the
			// handshake reply then records the real port.
			pcfg.PeerURL = "http://" + urlHost(body.RemotePub)
		}
		_ = savePeerConfig(pcfg)

		go func() {
			for attempt := 1; attempt <= 6; attempt++ {
				time.Sleep(time.Duration(attempt*2) * time.Second)
				if err := peerHandshake("worker", body.LocalGre); err == nil {
					log.Printf("[PeerSync] Auto-connected handshake with master on attempt %d", attempt)
					break
				}
			}
		}()
	}

	// what the first tunnel is, for the central's plan (setup_plan.go)
	if body.Role == "iran" || body.Role == "foreign" {
		firstTunnelSave(firstTunnelRec{Side: body.Role, LocalPub: body.LocalPub, RemotePub: body.RemotePub,
			LocalGre: body.LocalGre, PeerGre: body.PeerGre, Engine: body.Engine})
	}
	// the first tunnel's other server: named in the setup form
	if (body.Role == "iran" || body.Role == "foreign") && body.Name != "" {
		_ = setLinkName("main", body.Name)
	}
	writeJSON(w, out)
}

// runInstaller shells out to hashem.sh setup-iran|setup-foreign with the same
// flags the CLI uses, so menu / CLI / panel execute identical steps.
// Returns the Iran-side token + foreign-setup bundle (bundle holds the
// token plus all addresses/ports, so one paste configures foreign).
// ("", "", steps, nil) for foreign (nothing generated there).
// installerTimeout bounds one hashem.sh setup/add-peer run.
const installerTimeout = 15 * time.Minute

func runInstaller(b setupRequest, ports []int, rawPorts []string) (string, string, []string, error) {
	script, err := greScriptPath()
	if err != nil {
		return "", "", nil, err
	}
	// Self-healing: if setup or add-peer is invoked on a host whose hashem.sh is
	// an old version (lacking the "add-peer" CLI verb or "--bundle"), auto-sync the
	// script before shelling out so the user does not hit E-INSTALL-02.
	ensureFreshScript(script)
	args, token := installerArgs(&b, ports, rawPorts)
	// token is used verbatim as an argv element (no shell), safe from injection.
	// The installer downloads FRP/Backhaul (45s per mirror, several mirrors and
	// a fallback version) and waits for services; on slow links 60s killed it
	// half-way and left a half-installed server. POST requests carry no server
	// write deadline (see isLongRunning), so the reply still arrives.
	ctx, cancel := context.WithTimeout(context.Background(), installerTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", append([]string{script}, args...)...)
	cmd.Env = append(os.Environ(), "GRE_SKIP_PANEL=1", "TERM=dumb", "GRE_PANEL_DIR="+configDir)
	out, runErr := cmd.CombinedOutput()
	steps := []string{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			steps = append(steps, line)
		}
	}
	if b.Role == "iran" || b.Role == "add-peer" {
		steps = append([]string{"token generated (copy to Foreign side)"}, steps...)
	}

	var bundleStr string
	if b.Role == "iran" || b.Role == "add-peer" {
		switch b.Engine {
		case "backhaul":
			bundleStr = MakeBackhaulBundle(b.LocalPub, b.FrpPort, backhaulBundleTransport(b.Transport, udpPortFromSteps(steps)), token, rawPorts)
		case "gre-backhaul":
			bundleStr = MakeGreBackhaulBundle(b.LocalPub, b.FrpPort, b.LocalGre, b.PeerGre, backhaulBundleTransport(b.Transport, udpPortFromSteps(steps)), token, rawPorts)
		default:
			trans := b.FRPTransport
			if trans == "" && b.Transport != "" && b.Transport != "tcpmux" {
				trans = b.Transport
			}
			bundleStr = MakeBundle(b.LocalPub, b.FrpPort, b.LocalGre, b.PeerGre, token, ports, trans)
		}
	}

	if runErr != nil {
		errText := runErr.Error()
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			errText = fmt.Sprintf("timed out after %s (slow download?); the server may be half-installed, re-run setup", installerTimeout)
		}
		if len(steps) > 0 {
			var failDetails []string
			for _, s := range steps {
				if strings.Contains(s, "[FAILED]") || (strings.Contains(s, "FAILED") && !strings.Contains(s, "Overall Installation Status")) {
					failDetails = append(failDetails, s)
				}
			}
			if len(failDetails) > 0 {
				errText += " — " + strings.Join(failDetails, " | ")
			} else if tail := strings.Join(steps[max(0, len(steps)-3):], " | "); tail != "" {
				errText += " — " + tail
			}
		}
		if b.Role == "add-peer" && strings.Contains(strings.Join(steps, "\n"), "Unknown command") {
			errText += " — panel hashem.sh is an old version: run Update to latest, or re-run install.sh on this host"
		}
		return token, bundleStr, steps, fmt.Errorf("hashem.sh %s failed: %s", args[0], errText)
	}

	return token, bundleStr, steps, nil
}

// installerArgs builds the hashem.sh command line for a setup request. It fills
// b.Transport with the engine default, which the bundle uses afterwards.
func installerArgs(b *setupRequest, ports []int, rawPorts []string) ([]string, string) {
	token := ""
	var args []string

	switch b.Engine {
	case "backhaul":
		if b.Transport == "" {
			b.Transport = "tcpmux"
		}
		switch b.Role {
		case "add-peer":
			name := b.Name
			if name == "" {
				name = "peer"
			}
			token = b.Token
			args = []string{"add-backhaul-peer",
				"--name", name,
				"--no-gre",
				"--local-pub", b.LocalPub, "--remote-pub", b.RemotePub,
				"--port", strconv.Itoa(b.FrpPort),
				"--transport", b.Transport,
				"--token", token,
				"--ports", strings.Join(rawPorts, ","),
			}
		case "iran":
			token = randomToken(32)
			args = []string{"setup-backhaul-iran",
				"--local-pub", b.LocalPub, "--remote-pub", b.RemotePub,
				"--port", strconv.Itoa(b.FrpPort),
				"--transport", b.Transport,
				"--token", token,
			}
			if len(rawPorts) > 0 {
				args = append(args, "--ports", strings.Join(rawPorts, ","))
			}
		default: // foreign
			args = []string{"setup-backhaul-foreign",
				"--local-pub", b.LocalPub, "--remote-pub", b.RemotePub,
				"--port", strconv.Itoa(b.FrpPort),
				"--transport", b.Transport,
				"--token", b.Token,
			}
			if b.OrigBundle != "" {
				args = append(args, "--bundle", b.OrigBundle)
			}
		}
	case "gre-backhaul":
		if b.Transport == "" {
			b.Transport = "tcpmux"
		}
		switch b.Role {
		case "add-peer":
			name := b.Name
			if name == "" {
				name = "peer"
			}
			token = b.Token
			args = []string{"add-backhaul-peer",
				"--name", name,
				"--local-pub", b.LocalPub, "--remote-pub", b.RemotePub,
				"--port", strconv.Itoa(b.FrpPort),
				"--local-gre", b.LocalGre, "--peer-gre", b.PeerGre,
				"--transport", b.Transport,
				"--token", token,
				"--ports", strings.Join(rawPorts, ","),
			}
		case "iran":
			token = randomToken(32)
			args = []string{"setup-gre-backhaul-iran",
				"--local-pub", b.LocalPub, "--remote-pub", b.RemotePub,
				"--port", strconv.Itoa(b.FrpPort),
				"--local-gre", b.LocalGre, "--peer-gre", b.PeerGre,
				"--transport", b.Transport,
				"--token", token,
			}
			if len(rawPorts) > 0 {
				args = append(args, "--ports", strings.Join(rawPorts, ","))
			}
		default: // foreign
			args = []string{"setup-gre-backhaul-foreign",
				"--local-pub", b.LocalPub, "--remote-pub", b.RemotePub,
				"--port", strconv.Itoa(b.FrpPort),
				"--local-gre", b.LocalGre, "--peer-gre", b.PeerGre,
				"--transport", b.Transport,
				"--token", b.Token,
			}
			if b.OrigBundle != "" {
				args = append(args, "--bundle", b.OrigBundle)
			}
		}
	default:
		switch b.Role {
		case "add-peer":
			name := b.Name
			if name == "" {
				name = "peer"
			}
			strs := make([]string, len(ports))
			for i, q := range ports {
				strs[i] = strconv.Itoa(q)
			}
			token = b.Token
			args = []string{"add-peer",
				"--name", name,
				"--local-pub", b.LocalPub, "--remote-pub", b.RemotePub,
				"--frp-port", strconv.Itoa(b.FrpPort),
				"--local-gre", b.LocalGre, "--peer-gre", b.PeerGre,
				"--token", token,
				"--ports", strings.Join(strs, ","),
			}
			if b.FRPTransport != "" && b.FRPTransport != "tcp" {
				args = append(args, "--frp-transport", b.FRPTransport)
			}
		case "iran":
			token = randomToken(32)
			args = []string{"setup-iran",
				"--local-pub", b.LocalPub, "--remote-pub", b.RemotePub,
				"--frp-port", strconv.Itoa(b.FrpPort),
				"--local-gre", b.LocalGre, "--peer-gre", b.PeerGre,
				"--token", token,
			}
			if len(rawPorts) > 0 {
				args = append(args, "--ports", strings.Join(rawPorts, ","))
			}
			frpTrans := b.FRPTransport
			if frpTrans == "" && b.Transport != "" && b.Transport != "tcpmux" {
				frpTrans = b.Transport
			}
			if frpTrans != "" && frpTrans != "tcp" {
				args = append(args, "--frp-transport", frpTrans)
			}
		default:
			strs := make([]string, len(ports))
			for i, p := range ports {
				strs[i] = strconv.Itoa(p)
			}
			args = []string{"setup-foreign",
				"--local-pub", b.LocalPub, "--remote-pub", b.RemotePub,
				"--frp-port", strconv.Itoa(b.FrpPort),
				"--local-gre", b.LocalGre, "--peer-gre", b.PeerGre,
				"--token", b.Token,
				"--ports", strings.Join(strs, ","),
			}
			if b.ProxyProtocol != "" && b.ProxyProtocol != "off" {
				args = append(args, "--proxy-protocol", b.ProxyProtocol)
			}
			if b.FRPTransport != "" && b.FRPTransport != "tcp" {
				args = append(args, "--frp-transport", b.FRPTransport)
			}
			if b.UseEncryption {
				args = append(args, "--encrypt")
			}
			if b.UseCompression {
				args = append(args, "--compress")
			}
			// Pass --bundle when available so hashem.sh can configure carrier/FOU
			// ports (carrier_set_fou_ports) that are not covered by explicit flags.
			if b.OrigBundle != "" {
				args = append(args, "--bundle", b.OrigBundle)
			} else if isBundle(b.Token) {
				// Fallback: if applyBundle was not called (old client path)
				args = append(args, "--bundle", b.Token)
			}
		}
	}
	// UDP on both sides: the Iran server and the foreign client of a TCP-only
	// transport each run a UDP companion on its own control port (hashem.sh
	// backhaul_udp_apply); the foreign side takes the port from the bundle.
	if b.AcceptUDP && (b.Engine == "backhaul" || b.Engine == "gre-backhaul") {
		args = append(args, "--udp")
		if b.UDPPort > 0 && b.UDPPort <= 65535 {
			args = append(args, "--udp-port", strconv.Itoa(b.UDPPort))
		}
	}
	// Route to Iran for a foreign side with GRE (FRP, Backhaul with GRE).
	if b.Role == "foreign" && b.Engine != "backhaul" && validDialMode(b.Dial) && b.Dial != "auto" {
		args = append(args, "--dial", b.Dial)
	}
	if b.Force {
		args = append(args, "--force")
	}
	return args, token
}

// ---- peers API: list tunnels + token lookup ----

// ---- setup bundle: one readable string with everything foreign needs ----
