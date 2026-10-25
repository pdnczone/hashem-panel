package main

// Spoof Tunnel: ParsaKSH/spoof-tunnel is a bidirectional IP-spoofing UDP pipe
// that crosses whitelist-based Layer-3 firewalls. The pipe alone carries raw
// UDP, so the panel wraps it with WireGuard to give a real, encrypted tunnel
// (10.20.0.1 <-> 10.20.0.2). The Iran server is "local", the foreign server is
// "remote". The panel only orchestrates the external `spoof` binary, WireGuard
// and systemd; all raw-socket work lives in the binary (needs root/CAP_NET_RAW).
//
// Pro feature ("spoof"), gated like Backhaul and Cluster. The license checks
// themselves are never touched here.

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"
)

// Paths and the WireGuard interface name (vars so tests point them at temp dirs).
var (
	spoofDir   = "/etc/spoof"
	wgConfDir  = "/etc/wireguard"
	spoofIface = "wg-spoof"
)

const (
	spoofBinName     = "spoof"
	spoofCoreSvc     = "spoof-core"
	spoofWGUnitTmpl  = "wg-quick@" // wg-quick@wg-spoof
	defaultSpoofPort = 8090        // public UDP port the remote receives on
	defaultRecvPort  = 5001        // local recv port / remote client_port
	defaultCorePort  = 5000        // local core UDP listen (WireGuard dials this)
	defaultWGListen  = 51820       // foreign WireGuard listen port
	defaultWGMTU     = 1280
)

// spoofTransports are the per-direction carriers the core supports.
var spoofTransports = []string{"tcp", "udp", "icmp", "icmpv6"}

func spoofTransportOK(t string) bool {
	for _, v := range spoofTransports {
		if t == v {
			return true
		}
	}
	return false
}

// spoofState is the whole configuration of this server's spoof tunnel,
// persisted to configDir/spoof.json. One spoof tunnel per server.
type spoofState struct {
	Role         string `json:"role"`            // "local" (Iran) | "remote" (foreign)
	Enabled      bool   `json:"enabled"`         // whether apply has brought it up
	PeerPublicIP string `json:"peer_public_ip"`  // the OTHER server's real public IP
	LocalPublic  string `json:"local_public_ip"` // this server's real public IP (for the bundle)
	ListenPort   int    `json:"listen_port"`     // public UDP port the remote receives on
	RecvPort     int    `json:"recv_port"`       // local recv port / remote client_port
	SpoofPort    int    `json:"spoof_port"`      // source port stamped on outgoing packets

	// SpoofIPs are the addresses this server forges as its source (round-robin
	// when more than one). A single IP also sets the peer's receive filter.
	SpoofIPs      []string `json:"spoof_ips"`
	SendTransport string   `json:"send_transport"` // how this server sends
	RecvTransport string   `json:"recv_transport"` // how the peer sends to this server

	// WireGuard overlay.
	WGPrivKey string `json:"wg_priv_key"`
	WGPubKey  string `json:"wg_pub_key"`
	WGPeerPub string `json:"wg_peer_pub"`
	// WGPeerPriv is the foreign private key, kept on the Iran side only so the
	// bundle stays the same when it is shown again (never sent by GET).
	WGPeerPriv string `json:"wg_peer_priv,omitempty"`
	WGLocalIP  string `json:"wg_local_ip"` // 10.20.0.1 (local) / 10.20.0.2 (remote)
	WGPeerIP   string `json:"wg_peer_ip"`
	WGListen   int    `json:"wg_listen"` // foreign WireGuard listen port
	CorePort   int    `json:"core_port"` // local core UDP listen

	LastError string `json:"last_error,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

func spoofStatePath() string { return filepath.Join(configDir, "spoof.json") }

// defaultSpoofState fills a fresh config, guessing the role from the base
// tunnel and taking the public IP the panel already knows.
func defaultSpoofState() spoofState {
	role := "remote"
	st := localStatus()
	if strings.Contains(strings.ToLower(st.Role), "iran") || st.Role == "master" {
		role = "local"
	}
	s := spoofState{
		Role:          role,
		ListenPort:    defaultSpoofPort,
		RecvPort:      defaultRecvPort,
		SpoofPort:     443,
		SendTransport: "tcp",
		RecvTransport: "udp",
		WGListen:      defaultWGListen,
		CorePort:      defaultCorePort,
		LocalPublic:   savedPublicIP(),
	}
	s.applyRoleDefaults()
	return s
}

// applyRoleDefaults sets the direction-dependent defaults (WG addresses and the
// recommended transports) for the current role, without clobbering explicit values.
func (s *spoofState) applyRoleDefaults() {
	if s.Role == "local" {
		if s.WGLocalIP == "" {
			s.WGLocalIP = "10.20.0.1"
		}
		if s.WGPeerIP == "" {
			s.WGPeerIP = "10.20.0.2"
		}
	} else {
		if s.WGLocalIP == "" {
			s.WGLocalIP = "10.20.0.2"
		}
		if s.WGPeerIP == "" {
			s.WGPeerIP = "10.20.0.1"
		}
		// The foreign server's SpoofPort defaults to the listen port.
		if s.SpoofPort == 443 {
			s.SpoofPort = s.ListenPort
		}
	}
}

func loadSpoofState() spoofState {
	s := defaultSpoofState()
	if data, err := os.ReadFile(spoofStatePath()); err == nil {
		_ = json.Unmarshal(data, &s)
	}
	if s.CorePort <= 0 {
		s.CorePort = defaultCorePort
	}
	if s.WGListen <= 0 {
		s.WGListen = defaultWGListen
	}
	s.applyRoleDefaults()
	return s
}

func saveSpoofState(s spoofState) error {
	s.UpdatedAt = time.Now().Format(time.RFC3339)
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return err
	}
	tmp := spoofStatePath() + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, spoofStatePath())
}

// ---- WireGuard keys (curve25519, no shelling out) ----

// spoofGenKeypair returns a base64 (private, public) WireGuard keypair.
func spoofGenKeypair() (priv, pub string, err error) {
	var p [32]byte
	if _, err = rand.Read(p[:]); err != nil {
		return "", "", err
	}
	// Clamp like WireGuard does.
	p[0] &= 248
	p[31] &= 127
	p[31] |= 64
	pubB, err := curve25519.X25519(p[:], curve25519.Basepoint)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(p[:]), base64.StdEncoding.EncodeToString(pubB), nil
}

// spoofPubFromPriv derives the public key for a base64 private key.
func spoofPubFromPriv(priv string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(priv))
	if err != nil || len(raw) != 32 {
		return "", fmt.Errorf("invalid WireGuard private key")
	}
	pubB, err := curve25519.X25519(raw, curve25519.Basepoint)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(pubB), nil
}

// ensureSpoofKeys fills this server's keypair if it has none.
func (s *spoofState) ensureSpoofKeys() error {
	if s.WGPrivKey != "" && s.WGPubKey != "" {
		return nil
	}
	priv, pub, err := spoofGenKeypair()
	if err != nil {
		return err
	}
	s.WGPrivKey, s.WGPubKey = priv, pub
	return nil
}

// ---- config file generation ----

func spoofCoreConfigPath() string { return filepath.Join(spoofDir, "config.json") }
func spoofIPFilePath() string     { return filepath.Join(spoofDir, "spoof-ips.txt") }
func spoofWGConfPath() string     { return filepath.Join(wgConfDir, spoofIface+".conf") }

// coreConfig builds the JSON the spoof binary reads (`spoof run -c`).
func (s spoofState) coreConfig() map[string]any {
	m := map[string]any{
		"spoof_port":     s.SpoofPort,
		"send_transport": s.SendTransport,
		"recv_transport": s.RecvTransport,
	}
	// One spoof IP goes inline, a list goes to a file (round-robin). The
	// receive filter (peer_spoof_ip) stays off: the peer may spoof several
	// IPs, and WireGuard on top authenticates every packet anyway.
	if len(s.SpoofIPs) == 1 {
		m["spoof_ip"] = s.SpoofIPs[0]
	} else if len(s.SpoofIPs) > 1 {
		m["spoof_ip_file"] = spoofIPFilePath()
	}
	if s.Role == "local" {
		m["mode"] = "local"
		m["listen"] = fmt.Sprintf("127.0.0.1:%d", s.CorePort)
		m["remote"] = s.PeerPublicIP
		m["remote_port"] = s.ListenPort
		m["recv_port"] = s.RecvPort
	} else {
		m["mode"] = "remote"
		m["listen_port"] = s.ListenPort
		m["forward"] = fmt.Sprintf("127.0.0.1:%d", s.WGListen)
		m["client_ip"] = s.PeerPublicIP
		m["client_port"] = s.RecvPort
	}
	return m
}

func (s spoofState) writeCoreConfig() error {
	if err := os.MkdirAll(spoofDir, 0700); err != nil {
		return err
	}
	if len(s.SpoofIPs) > 1 {
		if err := os.WriteFile(spoofIPFilePath(), []byte(strings.Join(s.SpoofIPs, "\n")+"\n"), 0600); err != nil {
			return err
		}
	}
	data, err := json.MarshalIndent(s.coreConfig(), "", "  ")
	if err != nil {
		return err
	}
	tmp := spoofCoreConfigPath() + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, spoofCoreConfigPath())
}

// wgConfig renders the WireGuard config. The Iran side dials the core on
// loopback; the foreign side listens and learns the endpoint from the pipe.
func (s spoofState) wgConfig() string {
	var b strings.Builder
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "Address = %s/24\n", s.WGLocalIP)
	fmt.Fprintf(&b, "PrivateKey = %s\n", s.WGPrivKey)
	fmt.Fprintf(&b, "MTU = %d\n", defaultWGMTU)
	if s.Role == "remote" {
		fmt.Fprintf(&b, "ListenPort = %d\n", s.WGListen)
	}
	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", s.WGPeerPub)
	fmt.Fprintf(&b, "AllowedIPs = %s/32\n", s.WGPeerIP)
	if s.Role == "local" {
		fmt.Fprintf(&b, "Endpoint = 127.0.0.1:%d\n", s.CorePort)
		b.WriteString("PersistentKeepalive = 25\n")
	}
	return b.String()
}

func (s spoofState) writeWGConfig() error {
	if err := os.MkdirAll(wgConfDir, 0700); err != nil {
		return err
	}
	tmp := spoofWGConfPath() + ".tmp"
	if err := os.WriteFile(tmp, []byte(s.wgConfig()), 0600); err != nil {
		return err
	}
	return os.Rename(tmp, spoofWGConfPath())
}

// ---- systemd units ----

func spoofCoreUnitPath() string {
	return filepath.Join(engineUnitDir, spoofCoreSvc+".service")
}

func (s spoofState) writeCoreUnit() error {
	cmd := engineBinaryPath(spoofBinName) + " run -c " + spoofCoreConfigPath()
	unit := engineUnit("Spoof Tunnel core ("+s.Role+")", "", cmd)
	return writeUnitFile(spoofCoreUnitPath(), unit)
}

// ---- apply / stop / status ----

// spoofReady reports what is missing before the tunnel can come up.
func (s spoofState) ready() error {
	if s.PeerPublicIP == "" {
		return fmt.Errorf("the other server's public IP is not set")
	}
	if net.ParseIP(CleanHost(s.PeerPublicIP)) == nil {
		return fmt.Errorf("the other server's public IP is not a valid address")
	}
	if len(s.SpoofIPs) == 0 {
		return fmt.Errorf("no spoof IP set: run the tester and pick at least one usable IP")
	}
	if s.WGPeerPub == "" {
		return fmt.Errorf("the peer WireGuard key is missing: import the bundle from the Iran server (Spoof tab → Bundle) on this foreign server first")
	}
	if !spoofTransportOK(s.SendTransport) || !spoofTransportOK(s.RecvTransport) {
		return fmt.Errorf("transports must be one of %s", strings.Join(spoofTransports, ", "))
	}
	return nil
}

// applySpoof writes every config and unit and brings the tunnel up. It is
// idempotent: callers may run it after any settings change.
func applySpoof(s spoofState) (string, error) {
	if err := s.ready(); err != nil {
		return "", err
	}
	if !engineBinaryPresent(spoofBinName) {
		return "", fmt.Errorf("the spoof binary is not installed (install it with `hashem spoof` first); nothing was changed")
	}
	if err := s.writeCoreConfig(); err != nil {
		return "", fmt.Errorf("write core config: %w", err)
	}
	if err := s.writeWGConfig(); err != nil {
		return "", fmt.Errorf("write WireGuard config: %w", err)
	}
	if err := s.writeCoreUnit(); err != nil {
		return "", fmt.Errorf("write core service: %w", err)
	}
	openSpoofFirewall(s)
	_ = runSystemctl("daemon-reload")
	// The core carries the pipe; WireGuard rides on top, so start the core first.
	if err := runSystemctl("restart", spoofCoreSvc); err != nil {
		return "", fmt.Errorf("start %s: %w", spoofCoreSvc, err)
	}
	_ = runSystemctl("enable", spoofCoreSvc)
	wgUnit := spoofWGUnitTmpl + spoofIface
	if err := runSystemctl("restart", wgUnit); err != nil {
		// WireGuard failing leaves the pipe up but unusable; report it.
		return "", fmt.Errorf("start WireGuard (%s): %w", wgUnit, err)
	}
	_ = runSystemctl("enable", wgUnit)
	return "Spoof tunnel is up on " + s.Role + " (" + s.SendTransport + "/" + s.RecvTransport + ").", nil
}

func stopSpoof() error {
	wgUnit := spoofWGUnitTmpl + spoofIface
	_ = runSystemctl("disable", "--now", wgUnit)
	_ = runSystemctl("disable", "--now", spoofCoreSvc)
	return nil
}

// openSpoofFirewall opens the public listen port (both TCP and UDP, since the
// carrier can be either) on the server that receives packets.
func openSpoofFirewall(s spoofState) {
	if s.Role == "remote" && s.ListenPort > 0 {
		allowUFWPorts([]int{s.ListenPort})
	}
	if s.Role == "local" && s.RecvPort > 0 {
		allowUFWPorts([]int{s.RecvPort})
	}
}

// spoofHealth is a best-effort runtime view (Linux only; empty elsewhere).
type spoofHealth struct {
	CoreActive bool   `json:"core_active"`
	WGActive   bool   `json:"wg_active"`
	PeerPing   bool   `json:"peer_ping"`
	Handshake  string `json:"handshake,omitempty"` // last WireGuard handshake, human text
}

func spoofRuntimeHealth(s spoofState) spoofHealth {
	h := spoofHealth{}
	h.CoreActive = engineServiceActive(spoofCoreSvc)
	h.WGActive = engineServiceActive(spoofWGUnitTmpl + spoofIface)
	if runtime.GOOS != "linux" {
		return h
	}
	if s.Enabled && s.WGPeerIP != "" {
		if err := exec.Command("ping", "-c", "1", "-W", "2", s.WGPeerIP).Run(); err == nil {
			h.PeerPing = true
		}
	}
	if out, err := exec.Command("wg", "show", spoofIface, "latest-handshakes").Output(); err == nil {
		fields := strings.Fields(strings.TrimSpace(string(out)))
		if len(fields) >= 2 {
			if ts, err := strconv.ParseInt(fields[len(fields)-1], 10, 64); err == nil && ts > 0 {
				h.Handshake = time.Since(time.Unix(ts, 0)).Truncate(time.Second).String() + " ago"
			}
		}
	}
	return h
}

// ---- bundle: one string the Iran side hands the foreign side ----

// spoofBundle is the payload encoded in the bundle. The Iran side generates
// both keypairs, so the foreign side imports a private key it never had to
// create and both ends know each other's public key from one transfer.
type spoofBundle struct {
	V             int    `json:"v"`
	IranPublicIP  string `json:"iran_ip"`
	ListenPort    int    `json:"listen_port"`
	RecvPort      int    `json:"recv_port"`
	SpoofPort     int    `json:"spoof_port"`
	SendTransport string `json:"send"` // the Iran side's send transport
	RecvTransport string `json:"recv"` // the Iran side's recv transport
	IranWGPub     string `json:"iran_wg_pub"`
	ForeignWGPriv string `json:"foreign_wg_priv"`
	WGIranIP      string `json:"wg_iran_ip"`
	WGForeignIP   string `json:"wg_foreign_ip"`
	WGListen      int    `json:"wg_listen"`
	CorePort      int    `json:"core_port"`
}

// ensurePeerKeypair makes the foreign server's keypair on the Iran side. It is
// made once and kept, so showing the bundle again gives the same keys and a
// running tunnel keeps working.
func (s *spoofState) ensurePeerKeypair() error {
	if pub, err := spoofPubFromPriv(s.WGPeerPriv); err == nil && pub == s.WGPeerPub {
		return nil
	}
	priv, pub, err := spoofGenKeypair()
	if err != nil {
		return err
	}
	s.WGPeerPriv, s.WGPeerPub = priv, pub
	return nil
}

// makeSpoofBundle is called on the Iran side. It ensures both keypairs exist,
// persists the foreign public key into our own state, and returns the bundle
// plus the (possibly updated) state to save.
func makeSpoofBundle(s spoofState) (string, spoofState, error) {
	if s.Role != "local" {
		return "", s, fmt.Errorf("the bundle is generated on the Iran server")
	}
	if err := s.ensureSpoofKeys(); err != nil {
		return "", s, err
	}
	if err := s.ensurePeerKeypair(); err != nil {
		return "", s, err
	}
	if s.LocalPublic == "" {
		s.LocalPublic = savedPublicIP()
	}
	if net.ParseIP(CleanHost(s.LocalPublic)) == nil {
		return "", s, fmt.Errorf("this server's public IP is unknown, so the foreign server could not reach it")
	}
	b := spoofBundle{
		V: 1, IranPublicIP: CleanHost(s.LocalPublic), ListenPort: s.ListenPort, RecvPort: s.RecvPort,
		SpoofPort: s.SpoofPort, SendTransport: s.SendTransport, RecvTransport: s.RecvTransport,
		IranWGPub: s.WGPubKey, ForeignWGPriv: s.WGPeerPriv, WGIranIP: s.WGLocalIP,
		WGForeignIP: s.WGPeerIP, WGListen: s.WGListen, CorePort: s.CorePort,
	}
	raw, err := json.Marshal(b)
	if err != nil {
		return "", s, err
	}
	return "spf1_" + base64.RawURLEncoding.EncodeToString(raw), s, nil
}

// validate checks every field that ends up in a config file, so a damaged
// or crafted bundle cannot write anything but addresses, ports and keys.
func (b spoofBundle) validate() error {
	ip4 := func(v string) bool { ip := net.ParseIP(v); return ip != nil && ip.To4() != nil }
	port := func(p int) bool { return p > 0 && p <= 65535 }
	key := func(v string) bool {
		raw, err := base64.StdEncoding.DecodeString(v)
		return err == nil && len(raw) == 32
	}
	switch {
	case !ip4(b.IranPublicIP):
		return fmt.Errorf("the bundle has no valid Iran server IP")
	case !port(b.ListenPort) || !port(b.RecvPort) || !port(b.WGListen) || !port(b.CorePort):
		return fmt.Errorf("the bundle has an invalid port")
	case !spoofTransportOK(b.SendTransport) || !spoofTransportOK(b.RecvTransport):
		return fmt.Errorf("the bundle has an unknown transport")
	case !key(b.IranWGPub) || !key(b.ForeignWGPriv):
		return fmt.Errorf("the bundle has an invalid WireGuard key")
	case !ip4(b.WGIranIP) || !ip4(b.WGForeignIP) || b.WGIranIP == b.WGForeignIP:
		return fmt.Errorf("the bundle has invalid WireGuard addresses")
	}
	return nil
}

// importSpoofBundle is called on the foreign server with the pasted bundle. It
// returns a ready-to-save remote-role state (keeping this server's own spoof
// IPs, which come from its own tester run).
func importSpoofBundle(bundle string, prev spoofState) (spoofState, error) {
	bundle = strings.TrimSpace(bundle)
	enc, ok := strings.CutPrefix(bundle, "spf1_")
	if !ok {
		return prev, fmt.Errorf("not a spoof bundle (want a string starting with spf1_)")
	}
	raw, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		return prev, fmt.Errorf("the bundle is corrupted")
	}
	var b spoofBundle
	if err := json.Unmarshal(raw, &b); err != nil || b.V != 1 {
		return prev, fmt.Errorf("the bundle is not valid")
	}
	if err := b.validate(); err != nil {
		return prev, err
	}
	foreignPub, err := spoofPubFromPriv(b.ForeignWGPriv)
	if err != nil {
		return prev, err
	}
	s := prev
	s.Role = "remote"
	s.PeerPublicIP = b.IranPublicIP
	s.ListenPort = b.ListenPort
	s.RecvPort = b.RecvPort
	// Our source port defaults to our listen port (the core's remote default);
	// the Iran side's spoof port is its own.
	s.SpoofPort = b.ListenPort
	s.WGPeerPriv = ""
	// Transports mirror the Iran side: our send is how the Iran side receives.
	s.SendTransport = b.RecvTransport
	s.RecvTransport = b.SendTransport
	s.WGPrivKey = b.ForeignWGPriv
	s.WGPubKey = foreignPub
	s.WGPeerPub = b.IranWGPub
	s.WGLocalIP = b.WGForeignIP
	s.WGPeerIP = b.WGIranIP
	s.WGListen = b.WGListen
	s.CorePort = b.CorePort
	s.applyRoleDefaults()
	return s, nil
}

// ---- HTTP ----

// spoofView is the GET /api/spoof response (private key never leaves the server).
func spoofView(s spoofState) map[string]any {
	return map[string]any{
		"role":           s.Role,
		"enabled":        s.Enabled,
		"peer_public_ip": s.PeerPublicIP,
		"local_public":   s.LocalPublic,
		"listen_port":    s.ListenPort,
		"recv_port":      s.RecvPort,
		"spoof_port":     s.SpoofPort,
		"spoof_ips":      s.SpoofIPs,
		"send_transport": s.SendTransport,
		"recv_transport": s.RecvTransport,
		"wg_pub":         s.WGPubKey,
		"wg_peer_pub":    s.WGPeerPub,
		"wg_local_ip":    s.WGLocalIP,
		"wg_peer_ip":     s.WGPeerIP,
		"has_keys":       s.WGPrivKey != "" && s.WGPubKey != "",
		"last_error":     s.LastError,
	}
}

func handleSpoofGet(w http.ResponseWriter, r *http.Request) {
	s := loadSpoofState()
	resp := spoofView(s)
	resp["installed"] = engineBinaryPresent(spoofBinName)
	resp["pro"] = hasPro(proSpoof)
	resp["transports"] = spoofTransports
	resp["health"] = spoofRuntimeHealth(s)
	resp["tester"] = spoofTesterView()
	writeJSON(w, resp)
}

// spoofPostRequest carries one action and the fields it needs.
type spoofPostRequest struct {
	Action        string   `json:"action"` // save | genkeys | bundle | import | up | down
	Role          string   `json:"role,omitempty"`
	PeerPublicIP  string   `json:"peer_public_ip,omitempty"`
	ListenPort    int      `json:"listen_port,omitempty"`
	RecvPort      int      `json:"recv_port,omitempty"`
	SpoofPort     int      `json:"spoof_port,omitempty"`
	SpoofIPs      []string `json:"spoof_ips,omitempty"`
	SendTransport string   `json:"send_transport,omitempty"`
	RecvTransport string   `json:"recv_transport,omitempty"`
	Bundle        string   `json:"bundle,omitempty"`
}

func handleSpoofPost(w http.ResponseWriter, r *http.Request) {
	var req spoofPostRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req); err != nil {
		writeAPIError(w, r, "E-ACTION-01", "invalid json")
		return
	}
	// Every spoof action beyond reading is Pro.
	if proRequired(w, r, proSpoof, "Spoof Tunnel") {
		return
	}
	s := loadSpoofState()
	switch strings.ToLower(strings.TrimSpace(req.Action)) {
	case "save":
		applySpoofForm(&s, req)
		if err := saveSpoofState(s); err != nil {
			writeAPIError(w, r, "E-ACTION-01", err.Error())
			return
		}
		writeJSON(w, map[string]any{"status": "ok", "spoof": spoofView(s)})

	case "genkeys":
		priv, pub, err := spoofGenKeypair()
		if err != nil {
			writeAPIError(w, r, "E-ACTION-01", err.Error())
			return
		}
		s.WGPrivKey, s.WGPubKey = priv, pub
		if err := saveSpoofState(s); err != nil {
			writeAPIError(w, r, "E-ACTION-01", err.Error())
			return
		}
		writeJSON(w, map[string]any{"status": "ok", "wg_pub": pub})

	case "bundle":
		applySpoofForm(&s, req)
		bundle, s2, err := makeSpoofBundle(s)
		if err != nil {
			writeAPIError(w, r, "E-ACTION-01", err.Error())
			return
		}
		if err := saveSpoofState(s2); err != nil {
			writeAPIError(w, r, "E-ACTION-01", err.Error())
			return
		}
		writeJSON(w, map[string]any{"status": "ok", "bundle": bundle, "spoof": spoofView(s2)})

	case "import":
		s2, err := importSpoofBundle(req.Bundle, s)
		if err != nil {
			writeAPIError(w, r, "E-ACTION-01", err.Error())
			return
		}
		// The pasted spoof IPs (if any) replace the list; otherwise keep ours.
		if len(req.SpoofIPs) > 0 {
			s2.SpoofIPs = cleanSpoofIPs(req.SpoofIPs)
		}
		if err := saveSpoofState(s2); err != nil {
			writeAPIError(w, r, "E-ACTION-01", err.Error())
			return
		}
		writeJSON(w, map[string]any{"status": "ok", "spoof": spoofView(s2)})

	case "up", "apply":
		applySpoofForm(&s, req)
		// The Iran server owns both keypairs, so it makes any that are missing
		// instead of refusing to start; the foreign server only gets the peer
		// key from the bundle, so it cannot.
		if s.Role == "local" {
			err := s.ensureSpoofKeys()
			if err == nil {
				err = s.ensurePeerKeypair()
			}
			if err != nil {
				writeAPIError(w, r, "E-ENGINE-01", err.Error())
				return
			}
		}
		if err := s.ready(); err != nil {
			s.LastError = err.Error()
			_ = saveSpoofState(s)
			writeAPIError(w, r, "E-ENGINE-02", err.Error())
			return
		}
		out, err := applySpoof(s)
		if err != nil {
			s.LastError = err.Error()
			_ = saveSpoofState(s)
			writeAPIError(w, r, "E-ENGINE-01", err.Error())
			return
		}
		s.Enabled, s.LastError = true, ""
		_ = saveSpoofState(s)
		writeJSON(w, map[string]any{"status": "ok", "detail": out, "health": spoofRuntimeHealth(s)})

	case "down", "stop":
		_ = stopSpoof()
		s.Enabled = false
		_ = saveSpoofState(s)
		writeJSON(w, map[string]any{"status": "ok", "detail": "Spoof tunnel stopped."})

	default:
		writeAPIError(w, r, "E-ACTION-01", "unknown action: want save, genkeys, bundle, import, up or down")
	}
}

// applySpoofForm copies the editable fields from a request onto the state,
// leaving anything the request omits untouched.
func applySpoofForm(s *spoofState, req spoofPostRequest) {
	if req.Role == "local" || req.Role == "remote" {
		s.Role = req.Role
		s.WGLocalIP, s.WGPeerIP = "", "" // re-derive for the new role
	}
	if req.PeerPublicIP != "" {
		s.PeerPublicIP = CleanHost(req.PeerPublicIP)
	}
	if req.ListenPort > 0 && req.ListenPort <= 65535 {
		s.ListenPort = req.ListenPort
	}
	if req.RecvPort > 0 && req.RecvPort <= 65535 {
		s.RecvPort = req.RecvPort
	}
	if req.SpoofPort > 0 && req.SpoofPort <= 65535 {
		s.SpoofPort = req.SpoofPort
	}
	if req.SpoofIPs != nil {
		s.SpoofIPs = cleanSpoofIPs(req.SpoofIPs)
	}
	if spoofTransportOK(req.SendTransport) {
		s.SendTransport = req.SendTransport
	}
	if spoofTransportOK(req.RecvTransport) {
		s.RecvTransport = req.RecvTransport
	}
	s.applyRoleDefaults()
}

// cleanSpoofIPs keeps only valid, unique IPv4 addresses.
func cleanSpoofIPs(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range in {
		v = strings.TrimSpace(v)
		ip := net.ParseIP(v)
		if ip == nil || ip.To4() == nil || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}
