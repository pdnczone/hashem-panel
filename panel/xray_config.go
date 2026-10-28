package main

// Xray Tunnel (Hashem Pro, "xray"): a port forward over Xray-core between the
// Iran server and a foreign server, like Bagher and Backhaul. Users connect to
// the Iran server's ports; Xray carries each connection to 127.0.0.1:<the same
// port> on the foreign server, where the service (often a 3x-ui inbound)
// listens.
//
//	direct:  Iran dials the foreign server (Iran is the VLESS client).
//	reverse: the foreign server dials Iran (VLESS reverse proxy: Iran's
//	         inbound hands the users' connections back down the link the
//	         foreign server opened), for when Iran cannot reach it.
//
// The panel runs its own Xray binary under its own units (hashem-xray-N) and
// never touches an Xray panel's binary, units or ports (xray_coexist.go).
// This file only builds configs: pure functions, no I/O.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"
)

const (
	xrayModeDirect  = "direct"
	xrayModeReverse = "reverse"
	xraySideIran    = "iran"
	xraySideForeign = "foreign"

	xrayFlowVision = "xtls-rprx-vision"
	// Inbound and outbound tags; the routing rules refer to them.
	xrayTagUsers   = "users"     // Iran: the users' ports
	xrayTagTunnel  = "tunnel"    // the VLESS link (outbound on the dialing side, inbound on the other)
	xrayTagReverse = "reverse"   // Iran in reverse mode: the users' way down the foreign server's link
	xrayTagFromIR  = "from-iran" // foreign in reverse mode: connections that arrive from Iran
	xrayTagDirect  = "direct"
	xrayTagBlock   = "block"
	xrayTagProbe   = "probe"

	// xrayProbeHost is the name the probe asks for; it never leaves Xray.
	xrayProbeHost = "probe.hashem"
)

// XrayLink is one tunnel between this server and one other server. Both ends
// keep the same link (the bundle carries it); Side says which end this is.
type XrayLink struct {
	ID   int    `json:"id"`
	Name string `json:"name,omitempty"`
	Mode string `json:"mode"` // direct | reverse
	Side string `json:"side"` // iran | foreign: this server
	// Remote is the other server's address: the foreign server on Iran, the
	// Iran server on the foreign server.
	Remote string `json:"remote"`
	// TunnelPort is where the VLESS server end listens: the foreign server in
	// direct mode, the Iran server in reverse mode.
	TunnelPort int   `json:"tunnel_port"`
	Ports      []int `json:"ports"` // service ports, the same on both ends
	UDP        bool  `json:"udp"`
	// Listen is the address the users' ports bind on Iran ("" = every address).
	Listen  string          `json:"listen,omitempty"`
	Profile XrayProfile     `json:"profile"`
	Keys    XrayKeys        `json:"keys"`
	Expert  json.RawMessage `json:"expert,omitempty"` // merged over the generated config

	// Iran only: the loopback port the panel probes the link through.
	ProbePort int  `json:"probe_port,omitempty"`
	Disabled  bool `json:"disabled,omitempty"` // stopped by the user
}

// XrayKeys are the link's secrets. The Reality private key lives only on the
// end that serves Reality.
type XrayKeys struct {
	UUID       string `json:"uuid"`
	PrivateKey string `json:"private_key,omitempty"`
	PublicKey  string `json:"public_key,omitempty"`
	ShortID    string `json:"short_id,omitempty"`
	// TLS without a certificate of the user's own: one the panel makes for the
	// SNI (PEM). The key lives only on the TLS server end; the dialing end
	// pins the certificate, or, through a CDN, checks the CDN's real one.
	TLSCert string `json:"tls_cert,omitempty"`
	TLSKey  string `json:"tls_key,omitempty"`
}

// XrayProfile is how the link looks on the wire. A beginner picks a preset
// (xrayPresets); every field stays editable.
type XrayProfile struct {
	Preset    string `json:"preset,omitempty"`
	Transport string `json:"transport"` // raw | xhttp | grpc | ws | httpupgrade | kcp
	Security  string `json:"security"`  // reality | tls | none
	Vision    bool   `json:"vision,omitempty"`

	SNI         string `json:"sni,omitempty"`
	Target      string `json:"target,omitempty"` // Reality: whose handshake it borrows (default SNI:443)
	Fingerprint string `json:"fingerprint,omitempty"`
	SpiderX     string `json:"spider_x,omitempty"`
	Xver        int    `json:"xver,omitempty"` // PROXY protocol to the Reality target

	Path      string `json:"path,omitempty"` // xhttp / ws / httpupgrade path, gRPC service name
	Host      string `json:"host,omitempty"` // HTTP Host header
	XHTTPMode string `json:"xhttp_mode,omitempty"`
	// CDN: the dialing end goes through a CDN (Cloudflare) to the SNI domain,
	// whose DNS record points at the TLS server end.
	CDN bool `json:"cdn,omitempty"`
	// Address is dialed instead of the other server (a CDN's clean IP).
	Address  string `json:"address,omitempty"`
	CertFile string `json:"cert_file,omitempty"` // TLS server end: the user's own certificate
	KeyFile  string `json:"key_file,omitempty"`

	Mux        int    `json:"mux,omitempty"` // mux concurrency, 0 = off
	XUDP       int    `json:"xudp,omitempty"`
	TFO        bool   `json:"tfo,omitempty"`
	Congestion string `json:"congestion,omitempty"` // tcpCongestion: bbr, cubic, …
	MPTCP      bool   `json:"mptcp,omitempty"`
	Mark       int    `json:"mark,omitempty"`
	// PreConnect is how many connections the dialing end keeps open ahead of
	// time (Xray's VLESS "testpre"): 0 = the default, -1 = off.
	PreConnect int `json:"preconnect,omitempty"`

	Fragment *XrayFragment `json:"fragment,omitempty"` // dialing end only
	Noise    *XrayNoise    `json:"noise,omitempty"`    // dialing end, UDP (mKCP) only
	KCP      *XrayKCP      `json:"kcp,omitempty"`
}

// XrayFragment splits the dialing end's first packets (finalmask "fragment").
type XrayFragment struct {
	Packets string `json:"packets"` // "tlshello" or a range such as "1-3"
	Length  string `json:"length"`  // "100-200"
	Delay   string `json:"delay"`   // "10-20" ms
}

// XrayNoise is what the dialing end sends before its first real UDP packet
// (finalmask "noise"): Count packets of random bytes (Length) or of a fixed
// Packet (str, hex or base64), Delay ms apart.
type XrayNoise struct {
	Type   string `json:"type"`             // rand | str | hex | base64
	Packet string `json:"packet,omitempty"` // str / hex / base64
	Length string `json:"length,omitempty"` // rand: bytes, "10-60"
	Delay  string `json:"delay,omitempty"`  // ms, "10-20"
	Count  int    `json:"count,omitempty"`  // 1-10, default 1
}

func (n XrayNoise) validate() error {
	if n.Delay != "" && !xrayRangeRe.MatchString(n.Delay) {
		return fmt.Errorf("noise: the delay is a range in ms, like 10-20")
	}
	if n.Count < 0 || n.Count > 10 {
		return fmt.Errorf("noise: 1-10 packets")
	}
	var size int
	switch n.Type {
	case "rand":
		if !xrayRangeRe.MatchString(n.Length) || strings.HasPrefix(n.Length, "0") {
			return fmt.Errorf("noise: random packets need a length range, like 10-60")
		}
		hi := n.Length
		if i := strings.IndexByte(hi, '-'); i >= 0 {
			hi = hi[i+1:]
		}
		size, _ = strconv.Atoi(hi)
	case "str":
		size = len(n.Packet)
	case "hex":
		b, err := hex.DecodeString(n.Packet)
		if err != nil {
			return fmt.Errorf("noise: the packet is not hex")
		}
		size = len(b)
	case "base64":
		b, err := base64.StdEncoding.DecodeString(n.Packet)
		if err != nil {
			return fmt.Errorf("noise: the packet is not base64")
		}
		size = len(b)
	default:
		return fmt.Errorf("noise: the type is rand, str, hex or base64")
	}
	if size < 1 || size > 1200 {
		return fmt.Errorf("noise: a packet is 1-1200 bytes")
	}
	return nil
}

// xrayNoiseMask is a noise setting as Xray's finalmask.
func xrayNoiseMask(n XrayNoise) map[string]any {
	item := map[string]any{}
	if n.Type == "rand" {
		item["rand"] = n.Length
	} else {
		item["type"], item["packet"] = n.Type, n.Packet
	}
	if n.Delay != "" {
		item["delay"] = n.Delay
	}
	count := n.Count
	if count < 1 {
		count = 1
	}
	items := make([]any, count)
	for i := range items {
		items[i] = item
	}
	return map[string]any{"type": "noise", "settings": map[string]any{"noise": items}}
}

// XrayKCP is mKCP's tuning. Password keys the mkcp-aes128gcm mask (what the
// old "seed" did), which both ends need.
type XrayKCP struct {
	MTU        int    `json:"mtu,omitempty"`
	TTI        int    `json:"tti,omitempty"`
	Up         int    `json:"up,omitempty"`   // uplinkCapacity, MB/s
	Down       int    `json:"down,omitempty"` // downlinkCapacity, MB/s
	Congestion bool   `json:"congestion,omitempty"`
	Password   string `json:"password,omitempty"`
}

var (
	xrayTransports   = []string{"raw", "xhttp", "grpc", "ws", "httpupgrade", "kcp"}
	xraySecurities   = []string{"reality", "tls", "none"}
	xrayXHTTPModes   = []string{"auto", "packet-up", "stream-up", "stream-one"}
	xrayFingerprints = []string{"chrome", "firefox", "safari", "edge", "ios", "android", "random", "randomized"}
	xrayCongestions  = []string{"bbr", "cubic", "reno"}
)

func xrayOneOf(v string, list []string) bool {
	for _, x := range list {
		if v == x {
			return true
		}
	}
	return false
}

// xrayPresets are what a beginner chooses from. Keys and random paths are
// filled per link by newXrayLink.
var xrayPresets = map[string]XrayProfile{
	// The fastest: plain TCP wrapped in Reality, Vision for TLS-in-TLS.
	"reality": {Preset: "reality", Transport: "raw", Security: "reality", Vision: true, Fingerprint: "chrome"},
	// HTTP requests instead of one long stream: for when raw Reality is cut.
	"xhttp": {Preset: "xhttp", Transport: "xhttp", Security: "reality", XHTTPMode: "auto", Fingerprint: "chrome"},
	// Through a CDN (Cloudflare): a real domain and certificate.
	"cdn":  {Preset: "cdn", Transport: "xhttp", Security: "tls", CDN: true, XHTTPMode: "packet-up", Fingerprint: "chrome"},
	"grpc": {Preset: "grpc", Transport: "grpc", Security: "reality", Fingerprint: "chrome"},
	// UDP: for when TCP is throttled.
	"kcp": {Preset: "kcp", Transport: "kcp", Security: "none", KCP: &XrayKCP{MTU: 1350, TTI: 20, Up: 20, Down: 100, Congestion: true}},
}

// xraySNIDirect and xraySNIReverse are the sites Reality borrows a handshake
// from by default, tried in order by the SNI tester: in direct mode the
// foreign server serves Reality, in reverse mode the Iran server does (and
// must reach the site). No apple/icloud: Xray warns those get IPs blocked.
var (
	xraySNIDirect  = []string{"www.speedtest.net", "www.microsoft.com", "www.cloudflare.com", "dl.google.com", "www.yahoo.com"}
	xraySNIReverse = []string{"www.digikala.com", "www.aparat.com", "divar.ir", "snapp.ir", "www.speedtest.net"}
)

// serverEnd reports whether this end runs the VLESS inbound: the foreign
// server in direct mode, the Iran server in reverse mode.
func (l XrayLink) serverEnd() bool { return (l.Mode == xrayModeDirect) == (l.Side == xraySideForeign) }

// listens are the ports this end binds: the users' ports on Iran and the
// tunnel port on the VLESS server end.
func (l XrayLink) listens() (tcp, udp []int) {
	if l.Side == xraySideIran {
		tcp = append(tcp, l.Ports...)
		if l.ProbePort > 0 {
			tcp = append(tcp, l.ProbePort)
		}
		if l.UDP {
			udp = append(udp, l.Ports...)
		}
	}
	if l.serverEnd() {
		if l.Profile.Transport == "kcp" {
			udp = append(udp, l.TunnelPort)
		} else {
			tcp = append(tcp, l.TunnelPort)
		}
	}
	return tcp, udp
}

// ---- keys ----

// newXrayUUID is a random (version 4) UUID.
func newXrayUUID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], nil
}

// newXrayRealityKeys is an x25519 pair in Xray's encoding (base64url, no
// padding), the same as `xray x25519`.
func newXrayRealityKeys() (priv, pub string, err error) {
	k := make([]byte, 32)
	if _, err = rand.Read(k); err != nil {
		return "", "", err
	}
	k[0] &= 248
	k[31] &= 127
	k[31] |= 64
	p, err := curve25519.X25519(k, curve25519.Basepoint)
	if err != nil {
		return "", "", err
	}
	return base64.RawURLEncoding.EncodeToString(k), base64.RawURLEncoding.EncodeToString(p), nil
}

// xrayRealityPub derives the public key from a private one.
func xrayRealityPub(priv string) (string, error) {
	k, err := base64.RawURLEncoding.DecodeString(priv)
	if err != nil || len(k) != 32 {
		return "", fmt.Errorf("invalid Reality private key")
	}
	p, err := curve25519.X25519(k, curve25519.Basepoint)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(p), nil
}

// newXrayLink fills a link's secrets and the random parts of its profile.
func newXrayLink(l XrayLink) (XrayLink, error) {
	var err error
	if l.Keys.UUID == "" {
		if l.Keys.UUID, err = newXrayUUID(); err != nil {
			return l, err
		}
	}
	if l.Profile.Security == "reality" && l.Keys.PrivateKey == "" {
		if l.Keys.PrivateKey, l.Keys.PublicKey, err = newXrayRealityKeys(); err != nil {
			return l, err
		}
	}
	if l.Profile.Security == "reality" && l.Keys.ShortID == "" {
		l.Keys.ShortID = randHex(4)
	}
	if l.Profile.Path == "" && xrayOneOf(l.Profile.Transport, []string{"xhttp", "ws", "httpupgrade", "grpc"}) {
		l.Profile.Path = "/" + randHex(6)
		if l.Profile.Transport == "grpc" {
			l.Profile.Path = randHex(6) // a gRPC service name has no slash
		}
	}
	if l.Profile.Transport == "kcp" {
		k := XrayKCP{} // a copy: the presets share their pointer
		if l.Profile.KCP != nil {
			k = *l.Profile.KCP
		}
		l.Profile.KCP = &k
		if l.Profile.KCP.Password == "" {
			l.Profile.KCP.Password = randHex(12)
		}
	}
	if l.Profile.Security == "reality" && l.Profile.SNI == "" {
		l.Profile.SNI = xraySNIDirect[0]
		if l.Mode == xrayModeReverse {
			l.Profile.SNI = xraySNIReverse[0]
		}
	}
	// TLS with no certificate of the user's own: the panel makes one for the
	// SNI, and a new one when the SNI changes.
	if l.Profile.Security == "tls" && l.Profile.CertFile == "" && l.Profile.SNI != "" {
		if cn, _ := xrayCertName(l.Keys.TLSCert); cn != l.Profile.SNI {
			if l.Keys.TLSCert, l.Keys.TLSKey, err = newXrayCert(l.Profile.SNI); err != nil {
				return l, err
			}
		}
	}
	if l.Profile.Security != "tls" {
		l.Keys.TLSCert, l.Keys.TLSKey = "", ""
	}
	return l, nil
}

// newXrayCert is a self-signed ECDSA certificate for name, valid ten years
// (PEM). A CDN in "Full" mode accepts it; without a CDN the dialing end pins it.
func newXrayCert(name string) (certPEM, keyPEM string, err error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return "", "", err
	}
	tpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-24 * time.Hour), NotAfter: time.Now().AddDate(10, 0, 0),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(name); ip != nil {
		tpl.DNSNames, tpl.IPAddresses = nil, []net.IP{ip}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		return "", "", err
	}
	kb, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return "", "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})), nil
}

// xrayCertName is a PEM certificate's name and its SHA-256 (hex), the pin
// the dialing end checks.
func xrayCertName(certPEM string) (name, sha string) {
	b, _ := pem.Decode([]byte(certPEM))
	if b == nil || b.Type != "CERTIFICATE" {
		return "", ""
	}
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return "", ""
	}
	sum := sha256.Sum256(c.Raw)
	return c.Subject.CommonName, hex.EncodeToString(sum[:])
}

// xrayKeyOK reports whether a PEM private key parses.
func xrayKeyOK(keyPEM string) bool {
	b, _ := pem.Decode([]byte(keyPEM))
	if b == nil {
		return false
	}
	if _, err := x509.ParseECPrivateKey(b.Bytes); err == nil {
		return true
	}
	_, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	return err == nil
}

// xrayPEMLines is a PEM block as Xray's inline certificate lines.
func xrayPEMLines(s string) []string { return strings.Split(strings.TrimSpace(s), "\n") }

// xrayCDNPorts are the HTTPS ports Cloudflare proxies.
var xrayCDNPorts = []int{443, 2053, 2083, 2087, 2096, 8443}

// ---- validation ----

var (
	xrayPathRe    = regexp.MustCompile(`^/[A-Za-z0-9._~/-]{0,127}$`)
	xrayGRPCRe    = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
	xrayRangeRe   = regexp.MustCompile(`^\d{1,5}(-\d{1,5})?$`)
	xrayHexRe     = regexp.MustCompile(`^([0-9a-f]{2}){0,8}$`)
	xrayUUIDRe    = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	xrayFileRe    = regexp.MustCompile(`^/[A-Za-z0-9._/-]{1,255}$`)
	xrayKCPPassRe = regexp.MustCompile(`^[A-Za-z0-9]{8,64}$`)
)

func xrayPortOK(p int) bool { return p > 0 && p <= 65535 }

// validate checks every field that ends up in a config, so a damaged or
// crafted bundle cannot write anything but addresses, ports, names and keys.
func (l XrayLink) validate() error {
	p := l.Profile
	if l.Mode != xrayModeDirect && l.Mode != xrayModeReverse {
		return fmt.Errorf("mode must be direct or reverse")
	}
	if l.Side != xraySideIran && l.Side != xraySideForeign {
		return fmt.Errorf("side must be iran or foreign")
	}
	// The end that dials needs the other's address; the listening end can
	// do without (its routing never uses it).
	if !l.serverEnd() || l.Remote != "" {
		if !validBagherHost(l.Remote) {
			return fmt.Errorf("the other server's address is not a valid IP or domain")
		}
	}
	if !xrayPortOK(l.TunnelPort) {
		return fmt.Errorf("the tunnel port must be 1-65535")
	}
	if len(l.Ports) == 0 {
		return fmt.Errorf("add at least one port to forward")
	}
	seen := map[int]bool{}
	for _, q := range l.Ports {
		if !xrayPortOK(q) {
			return fmt.Errorf("port %d is not 1-65535", q)
		}
		if seen[q] {
			return fmt.Errorf("port %d is listed twice", q)
		}
		seen[q] = true
		// Reverse: Iran would listen on both. Direct: the foreign server would
		// hand that port's traffic back to its own tunnel inbound, a loop.
		if q == l.TunnelPort {
			return fmt.Errorf("port %d is also the tunnel port: pick another tunnel port", q)
		}
	}
	if l.ProbePort != 0 && (!xrayPortOK(l.ProbePort) || seen[l.ProbePort] || l.ProbePort == l.TunnelPort) {
		return fmt.Errorf("the probe port must be a free port of its own")
	}
	if l.Listen != "" && net.ParseIP(l.Listen) == nil {
		return fmt.Errorf("the listen address must be an IP")
	}
	if !xrayUUIDRe.MatchString(l.Keys.UUID) {
		return fmt.Errorf("the link has no valid UUID")
	}
	if !xrayOneOf(p.Transport, xrayTransports) {
		return fmt.Errorf("transport must be one of %s", strings.Join(xrayTransports, ", "))
	}
	if !xrayOneOf(p.Security, xraySecurities) {
		return fmt.Errorf("security must be one of %s", strings.Join(xraySecurities, ", "))
	}
	if p.Transport == "kcp" && p.Security != "none" {
		return fmt.Errorf("mKCP runs over UDP: Reality and TLS need TCP, use security none (mKCP has its own encryption)")
	}
	if p.Security == "reality" && !xrayOneOf(p.Transport, []string{"raw", "xhttp", "grpc"}) {
		return fmt.Errorf("Reality works with raw, xhttp or gRPC")
	}
	if p.Vision {
		if p.Transport != "raw" || p.Security == "none" {
			return fmt.Errorf("Vision needs the raw transport with Reality or TLS")
		}
		if p.Mux > 0 {
			return fmt.Errorf("Vision and mux cannot be used together")
		}
	}
	if p.Mux > 0 && l.Mode == xrayModeReverse {
		return fmt.Errorf("the reverse link multiplexes by itself: turn mux off")
	}
	if p.Mux < 0 || p.Mux > 1024 || p.XUDP < 0 || p.XUDP > 1024 {
		return fmt.Errorf("mux concurrency must be 0-1024")
	}
	if p.PreConnect < -1 || p.PreConnect > xrayPreConnectMax {
		return fmt.Errorf("pre-connect must be 0-%d connections (-1 = off)", xrayPreConnectMax)
	}
	if !validXrayName(p.SNI, true) || !validXrayName(p.Host, true) || !validXrayName(p.Address, true) {
		return fmt.Errorf("SNI, host and address must be domain names or IPs")
	}
	if p.Security != "none" && p.SNI == "" {
		return fmt.Errorf("set the SNI (server name) for %s", p.Security)
	}
	if p.Target != "" {
		h, port, err := net.SplitHostPort(p.Target)
		n, _ := strconv.Atoi(port)
		if err != nil || !validXrayName(h, false) || !xrayPortOK(n) {
			return fmt.Errorf("the Reality target must be host:port")
		}
	}
	if p.Fingerprint != "" && !xrayOneOf(p.Fingerprint, xrayFingerprints) {
		return fmt.Errorf("fingerprint must be one of %s", strings.Join(xrayFingerprints, ", "))
	}
	if p.SpiderX != "" && !xrayPathRe.MatchString(strings.SplitN(p.SpiderX, "?", 2)[0]) {
		return fmt.Errorf("spiderX must be a path starting with /")
	}
	if p.Xver < 0 || p.Xver > 2 {
		return fmt.Errorf("xver must be 0, 1 or 2")
	}
	switch p.Transport {
	case "grpc":
		if !xrayGRPCRe.MatchString(p.Path) {
			return fmt.Errorf("the gRPC service name may only hold letters, digits, dot, dash and underscore")
		}
	case "xhttp", "ws", "httpupgrade":
		if !xrayPathRe.MatchString(p.Path) {
			return fmt.Errorf("the path must start with / and hold only URL-safe characters")
		}
	}
	if p.XHTTPMode != "" && !xrayOneOf(p.XHTTPMode, xrayXHTTPModes) {
		return fmt.Errorf("XHTTP mode must be one of %s", strings.Join(xrayXHTTPModes, ", "))
	}
	if p.Congestion != "" && !xrayOneOf(p.Congestion, xrayCongestions) {
		return fmt.Errorf("congestion must be one of %s", strings.Join(xrayCongestions, ", "))
	}
	if p.Mark < 0 {
		return fmt.Errorf("mark must be 0 or more")
	}
	if p.Security == "reality" {
		if !xrayHexRe.MatchString(l.Keys.ShortID) {
			return fmt.Errorf("the Reality short ID must be up to 16 hex digits")
		}
		if l.serverEnd() {
			if pub, err := xrayRealityPub(l.Keys.PrivateKey); err != nil || (l.Keys.PublicKey != "" && pub != l.Keys.PublicKey) {
				return fmt.Errorf("the Reality key pair is invalid")
			}
		} else if k, err := base64.RawURLEncoding.DecodeString(l.Keys.PublicKey); err != nil || len(k) != 32 {
			return fmt.Errorf("the Reality public key is invalid")
		}
	}
	if p.Security == "tls" {
		ownCert := p.CertFile != "" || p.KeyFile != ""
		switch {
		case ownCert && (!xrayFileRe.MatchString(p.CertFile) || !xrayFileRe.MatchString(p.KeyFile)):
			return fmt.Errorf("your own certificate needs both files, as absolute paths")
		case !ownCert && l.serverEnd() && !xrayKeyOK(l.Keys.TLSKey):
			return fmt.Errorf("the link's TLS certificate is missing: save the link again on the Iran server")
		case !ownCert && !p.CDN:
			// the dialing end pins the panel's certificate
			if _, sha := xrayCertName(l.Keys.TLSCert); sha == "" {
				return fmt.Errorf("the link's TLS certificate is missing: save the link again on the Iran server")
			}
		}
	}
	if p.CDN {
		if p.Security != "tls" {
			return fmt.Errorf("a CDN needs TLS")
		}
		if net.ParseIP(p.SNI) != nil {
			return fmt.Errorf("a CDN needs a domain name, not an IP")
		}
		if !xrayHasPort(xrayCDNPorts, l.TunnelPort) {
			return fmt.Errorf("Cloudflare passes HTTPS only on ports 443, 2053, 2083, 2087, 2096 and 8443: pick one as the tunnel port")
		}
		if p.Transport != "xhttp" && p.Transport != "ws" && p.Transport != "httpupgrade" && p.Transport != "grpc" {
			return fmt.Errorf("a CDN carries XHTTP, WebSocket, HTTPUpgrade or gRPC")
		}
	}
	if f := p.Fragment; f != nil {
		if (f.Packets != "tlshello" && !xrayRangeRe.MatchString(f.Packets)) || !xrayRangeRe.MatchString(f.Length) ||
			(f.Delay != "" && !xrayRangeRe.MatchString(f.Delay)) || strings.HasPrefix(f.Length, "0") {
			return fmt.Errorf("fragment: packets is tlshello or a range like 1-3, length a range like 100-200 (not 0), delay a range in ms")
		}
	}
	if n := p.Noise; n != nil {
		if p.Transport != "kcp" {
			return fmt.Errorf("noise is for links over UDP (mKCP); use fragment for TCP")
		}
		if err := n.validate(); err != nil {
			return err
		}
	}
	if p.Transport == "kcp" {
		k := p.KCP
		if k == nil || !xrayKCPPassRe.MatchString(k.Password) {
			return fmt.Errorf("mKCP needs a password of 8-64 letters and digits")
		}
		if (k.MTU != 0 && (k.MTU < 576 || k.MTU > 1460)) || (k.TTI != 0 && (k.TTI < 10 || k.TTI > 5000)) || k.Up < 0 || k.Down < 0 {
			return fmt.Errorf("mKCP: MTU 576-1460, TTI 10-5000 ms")
		}
	}
	if len(l.Expert) > 0 {
		var m map[string]any
		if err := json.Unmarshal(l.Expert, &m); err != nil {
			return fmt.Errorf("the expert JSON must be an object: %v", err)
		}
	}
	return nil
}

// validXrayName accepts a DNS name or an IP ("" when empty is allowed).
func validXrayName(v string, emptyOK bool) bool {
	if v == "" {
		return emptyOK
	}
	return validBagherHost(v)
}

// ---- config ----

// xrayPortList is the ports as Xray's port list ("443,2053").
func xrayPortList(ports []int) string {
	s := append([]int(nil), ports...)
	sort.Ints(s)
	out := make([]string, len(s))
	for i, p := range s {
		out[i] = strconv.Itoa(p)
	}
	return strings.Join(out, ",")
}

func (l XrayLink) network() string {
	if l.UDP {
		return "tcp,udp"
	}
	return "tcp"
}

func (l XrayLink) flow() string {
	if l.Profile.Vision {
		return xrayFlowVision
	}
	return ""
}

// Pre-connect: in direct mode every user connection is a new TCP connection
// plus a new Reality/TLS handshake to the foreign server, about 4 round trips
// before the first byte (the reverse link and HTTP/2 transports reuse one
// that is already open: 1). The dialing end keeps a few ready instead.
const (
	xrayPreConnectDefault = 4
	xrayPreConnectMax     = 32
	// xrayPreConnectIdle is how long the server end waits for the first
	// request on a connection (Xray's "handshake" policy, 4 s by default).
	// Xray keeps a pre-connected connection for 2 minutes, so the server must
	// wait longer; only clients that passed Reality/TLS get this far.
	xrayPreConnectIdle = 150
)

// preConnect is the testpre count for this link's dialing end (0 = none):
// direct mode only (the reverse link is already open), on the transports
// that open a connection per user connection, not through a CDN (it closes
// idle connections sooner than Xray's 2 minutes) and not with mux.
func (l XrayLink) preConnect() int {
	p := l.Profile
	if l.Mode != xrayModeDirect || p.CDN || p.Mux > 0 || p.PreConnect < 0 ||
		!xrayOneOf(p.Transport, []string{"raw", "ws", "httpupgrade"}) {
		return 0
	}
	if p.PreConnect == 0 {
		return xrayPreConnectDefault
	}
	return p.PreConnect
}

// buildXrayConfig is this end's whole Xray config.
func buildXrayConfig(l XrayLink) (map[string]any, error) {
	if err := l.validate(); err != nil {
		return nil, err
	}
	var inbounds, outbounds []any
	var rules []any
	if l.Side == xraySideIran {
		listen := l.Listen
		if listen == "" {
			listen = "0.0.0.0"
		}
		// Port 0: each connection goes to 127.0.0.1 on the port it came in on.
		inbounds = append(inbounds, map[string]any{
			"tag": xrayTagUsers, "listen": listen, "port": xrayPortList(l.Ports), "protocol": "dokodemo-door",
			"settings": map[string]any{"address": "127.0.0.1", "network": l.network()},
		})
		via := xrayTagTunnel
		if l.Mode == xrayModeReverse {
			via = xrayTagReverse
		}
		rules = append(rules, map[string]any{"inboundTag": []string{xrayTagUsers}, "outboundTag": via})
		// The panel's probe: a loopback port whose connections ask the other
		// end for probe.hashem, which its Xray answers itself (xrayTagProbe).
		if l.ProbePort > 0 {
			inbounds = append(inbounds, map[string]any{
				"tag": xrayTagProbe, "listen": "127.0.0.1", "port": l.ProbePort, "protocol": "dokodemo-door",
				"settings": map[string]any{"address": xrayProbeHost, "port": 80, "network": "tcp"},
			})
			rules = append(rules, map[string]any{"inboundTag": []string{xrayTagProbe}, "outboundTag": via})
		}
	}

	// The VLESS link.
	if l.serverEnd() {
		client := map[string]any{"id": l.Keys.UUID, "email": "hashem@link"}
		if f := l.flow(); f != "" {
			client["flow"] = f
		}
		if l.Mode == xrayModeReverse {
			// Iran: this user may only open reverse links (Xray refuses it a
			// forward proxy), and its links become the "reverse" outbound.
			client["reverse"] = map[string]any{"tag": xrayTagReverse}
		}
		inbounds = append(inbounds, map[string]any{
			"tag": xrayTagTunnel, "listen": "0.0.0.0", "port": l.TunnelPort, "protocol": "vless",
			"settings":       map[string]any{"clients": []any{client}, "decryption": "none"},
			"streamSettings": xrayStream(l, true),
		})
	} else {
		ob := map[string]any{
			"address": xrayDialAddress(l), "port": l.TunnelPort, "id": l.Keys.UUID, "encryption": "none",
		}
		if f := l.flow(); f != "" {
			ob["flow"] = f
		}
		if n := l.preConnect(); n > 0 {
			ob["testpre"] = n
		}
		if l.Mode == xrayModeReverse {
			// The foreign server: the link it opens to Iran is an inbound for
			// the users' connections Iran sends down it.
			ob["reverse"] = map[string]any{"tag": xrayTagFromIR}
		}
		out := map[string]any{"tag": xrayTagTunnel, "protocol": "vless", "settings": ob, "streamSettings": xrayStream(l, false)}
		if l.Profile.Mux > 0 {
			mux := map[string]any{"enabled": true, "concurrency": l.Profile.Mux}
			if l.Profile.XUDP > 0 {
				mux["xudpConcurrency"] = l.Profile.XUDP
			}
			out["mux"] = mux
		}
		outbounds = append(outbounds, out)
	}

	// The foreign end hands connections only to its own services: if the
	// UUID leaks, the link is still no open proxy.
	if l.Side == xraySideForeign {
		from := xrayTagTunnel
		if l.Mode == xrayModeReverse {
			from = xrayTagFromIR
		}
		rules = append(rules,
			// the probe gets an HTTP 403 from Xray itself: one round trip
			map[string]any{"inboundTag": []string{from}, "domain": []string{"full:" + xrayProbeHost}, "outboundTag": xrayTagProbe},
			map[string]any{"inboundTag": []string{from}, "ip": []string{"127.0.0.1"}, "port": xrayPortList(l.Ports),
				"network": l.network(), "outboundTag": xrayTagDirect},
			map[string]any{"inboundTag": []string{from}, "outboundTag": xrayTagBlock})
		outbounds = append(outbounds, map[string]any{"tag": xrayTagDirect, "protocol": "freedom"})
		outbounds = append(outbounds, map[string]any{"tag": xrayTagProbe, "protocol": "blackhole",
			"settings": map[string]any{"response": map[string]any{"type": "http"}}})
	}
	// blackhole first: the default for anything no rule matched.
	outbounds = append([]any{map[string]any{"tag": xrayTagBlock, "protocol": "blackhole"}}, outbounds...)

	cfg := map[string]any{
		"log":       map[string]any{"loglevel": "warning", "access": "none"},
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"routing":   map[string]any{"domainStrategy": "AsIs", "rules": rules},
	}
	// The server end waits for the dialing end's pre-connected connections.
	// Always set in direct mode, so a dialing end that turns pre-connect on
	// later needs nothing new here.
	if l.serverEnd() && l.Mode == xrayModeDirect && l.Profile.Transport != "kcp" {
		cfg["policy"] = map[string]any{"levels": map[string]any{"0": map[string]any{"handshake": xrayPreConnectIdle}}}
	}
	if len(l.Expert) > 0 {
		var ex map[string]any
		if err := json.Unmarshal(l.Expert, &ex); err != nil {
			return nil, fmt.Errorf("expert JSON: %w", err)
		}
		cfg = xrayMerge(xrayNormalize(cfg), ex).(map[string]any)
	}
	return cfg, nil
}

// xrayDialAddress is what the dialing end connects to: the CDN address when
// one is set, else the other server.
func xrayDialAddress(l XrayLink) string {
	if l.Profile.Address != "" {
		return l.Profile.Address
	}
	if l.Profile.CDN {
		return l.Profile.SNI // the domain, which the CDN answers for
	}
	return l.Remote
}

// xrayStream is the streamSettings of the link on one end.
func xrayStream(l XrayLink, server bool) map[string]any {
	p := l.Profile
	network := p.Transport
	s := map[string]any{"network": network, "security": p.Security}
	switch p.Security {
	case "reality":
		if server {
			target := p.Target
			if target == "" {
				target = net.JoinHostPort(p.SNI, "443")
			}
			s["realitySettings"] = map[string]any{
				"target": target, "xver": p.Xver, "serverNames": []string{p.SNI},
				"privateKey": l.Keys.PrivateKey, "shortIds": []string{l.Keys.ShortID},
			}
		} else {
			rs := map[string]any{
				"serverName": p.SNI, "fingerprint": xrayFP(p), "password": l.Keys.PublicKey, "shortId": l.Keys.ShortID,
			}
			if p.SpiderX != "" {
				rs["spiderX"] = p.SpiderX
			}
			s["realitySettings"] = rs
		}
	case "tls":
		if server {
			// the user's own certificate files, or the panel's, inline
			cert := map[string]any{"certificateFile": p.CertFile, "keyFile": p.KeyFile}
			if p.CertFile == "" {
				cert = map[string]any{"certificate": xrayPEMLines(l.Keys.TLSCert), "key": xrayPEMLines(l.Keys.TLSKey)}
			}
			s["tlsSettings"] = map[string]any{"serverName": p.SNI, "certificates": []any{cert}}
		} else {
			ts := map[string]any{"serverName": p.SNI, "fingerprint": xrayFP(p)}
			// No CDN and the panel's certificate: trust exactly that one. Through
			// a CDN the CDN's real certificate is checked as usual.
			if !p.CDN && p.CertFile == "" {
				if _, sha := xrayCertName(l.Keys.TLSCert); sha != "" {
					ts["pinnedPeerCertSha256"] = sha
				}
			}
			s["tlsSettings"] = ts
		}
	}
	host := p.Host
	if host == "" && p.Security == "tls" {
		host = p.SNI
	}
	switch network {
	case "xhttp":
		x := map[string]any{"path": p.Path, "mode": xrayOr(p.XHTTPMode, "auto")}
		if host != "" {
			x["host"] = host
		}
		s["xhttpSettings"] = x
	case "ws":
		s["wsSettings"] = map[string]any{"path": p.Path, "host": host}
	case "httpupgrade":
		s["httpupgradeSettings"] = map[string]any{"path": p.Path, "host": host}
	case "grpc":
		s["grpcSettings"] = map[string]any{"serviceName": p.Path}
	case "kcp":
		k := XrayKCP{}
		if p.KCP != nil {
			k = *p.KCP
		}
		ks := map[string]any{"congestion": k.Congestion}
		if k.MTU > 0 {
			ks["mtu"] = k.MTU
		}
		if k.TTI > 0 {
			ks["tti"] = k.TTI
		}
		if k.Up > 0 {
			ks["uplinkCapacity"] = k.Up
		}
		if k.Down > 0 {
			ks["downlinkCapacity"] = k.Down
		}
		s["kcpSettings"] = ks
		masks := []any{map[string]any{"type": "mkcp-aes128gcm", "settings": map[string]any{"password": k.Password}}}
		// Noise on the dialing end: junk packets before the first real one to
		// each address. The first mask sits next to the wire, so the junk goes
		// out raw and the other end's aes128gcm drops it.
		if !server && p.Noise != nil {
			masks = append([]any{xrayNoiseMask(*p.Noise)}, masks...)
		}
		s["finalmask"] = map[string]any{"udp": masks}
	}
	if !server && p.Fragment != nil && network != "kcp" {
		fs := map[string]any{"packets": p.Fragment.Packets, "length": p.Fragment.Length}
		if p.Fragment.Delay != "" {
			fs["delay"] = p.Fragment.Delay
		}
		s["finalmask"] = map[string]any{"tcp": []any{map[string]any{"type": "fragment", "settings": fs}}}
	}
	so := map[string]any{}
	if p.TFO {
		so["tcpFastOpen"] = true
	}
	if p.Congestion != "" {
		so["tcpCongestion"] = p.Congestion
	}
	if p.MPTCP {
		so["tcpMptcp"] = true
	}
	if p.Mark > 0 && !server {
		so["mark"] = p.Mark
	}
	if len(so) > 0 {
		s["sockopt"] = so
	}
	return s
}

func xrayFP(p XrayProfile) string { return xrayOr(p.Fingerprint, "chrome") }

func xrayOr(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// ---- expert JSON ----

// xrayNormalize turns a generated config into plain JSON values ([]any,
// map[string]any), the shapes xrayMerge works on.
func xrayNormalize(v map[string]any) map[string]any {
	raw, _ := json.Marshal(v)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return out
}

// xrayMerge lays over on base: objects merge key by key, lists of tagged
// objects (inbounds, outbounds) merge by "tag" (a new tag is appended), any
// other value replaces. So an expert edits one field of the "tunnel"
// outbound without restating the rest.
func xrayMerge(base, over any) any {
	switch o := over.(type) {
	case map[string]any:
		b, ok := base.(map[string]any)
		if !ok {
			return o
		}
		for k, v := range o {
			b[k] = xrayMerge(b[k], v)
		}
		return b
	case []any:
		b, ok := base.([]any)
		if !ok || !xrayTagged(o) || !xrayTagged(b) {
			return o
		}
		for _, item := range o {
			tag := item.(map[string]any)["tag"]
			merged := false
			for i, have := range b {
				if have.(map[string]any)["tag"] == tag {
					b[i] = xrayMerge(have, item)
					merged = true
					break
				}
			}
			if !merged {
				b = append(b, item)
			}
		}
		return b
	}
	return over
}

func xrayTagged(list []any) bool {
	for _, v := range list {
		m, ok := v.(map[string]any)
		if !ok {
			return false
		}
		if _, ok := m["tag"].(string); !ok {
			return false
		}
	}
	return len(list) > 0
}
