package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSHFwdConfig stores configuration for the Bagher Engine / SSH carrier.
type SSHFwdConfig struct {
	Role          string `json:"role"` // "client" (Iran entry) or "server" (Foreign origin)
	Mode          string `json:"mode"` // "bagher" (default stealth hybrid) or "direct" (pure ssh)
	RemoteHost    string `json:"remote_host"`
	RemoteUser    string `json:"remote_user"`
	RemoteSSHPort int    `json:"remote_ssh_port"`
	KeyPath       string `json:"key_path"`
	Ports         []int  `json:"ports"`
	BindAddr      string `json:"bind_addr"`
	FRPBindPort   int    `json:"frp_bind_port"`
	PoolCount     int    `json:"pool_count"`
	UDP           bool   `json:"udp,omitempty"` // Bagher mode: also forward UDP (frp udp proxies); direct SSH cannot
	// Links are the foreign servers after the first (link 1, the fields
	// above). They share the Iran server's frps and SSH key; each has its own
	// carrier unit and its own ports.
	Links               []BagherLink `json:"links,omitempty"`
	Enabled             bool         `json:"enabled"`
	ServerAliveInterval int          `json:"server_alive_interval"`
	ServerAliveCountMax int          `json:"server_alive_count_max"`
	LastStatus          string       `json:"last_status"`
	LastError           string       `json:"last_error"`
	UpdatedAt           string       `json:"updated_at"`
}

var (
	sshFwdMu sync.Mutex
)

func defaultSSHFwdKeyPath() string {
	if os.Geteuid() != 0 || strings.Contains(configDir, "gre-panel-test-") {
		return filepath.Join(configDir, "hashem-fwd")
	}
	return "/root/.ssh/hashem-fwd"
}

func defaultSSHFwdConfig() SSHFwdConfig {
	return SSHFwdConfig{
		Role:                "iran",
		Mode:                "bagher",
		RemoteHost:          "",
		RemoteUser:          "root",
		RemoteSSHPort:       22,
		KeyPath:             defaultSSHFwdKeyPath(),
		Ports:               []int{},
		BindAddr:            "0.0.0.0",
		FRPBindPort:         55400,
		PoolCount:           5,
		Enabled:             false,
		ServerAliveInterval: 15,
		ServerAliveCountMax: 3,
		LastStatus:          "inactive",
		LastError:           "",
		UpdatedAt:           "",
	}
}

func sshFwdConfigFile() string {
	return filepath.Join(configDir, "sshfwd.json")
}

func loadSSHFwdConfigLocked() SSHFwdConfig {
	cfg := defaultSSHFwdConfig()
	b, err := os.ReadFile(sshFwdConfigFile())
	if err == nil {
		_ = json.Unmarshal(b, &cfg)
	}
	cfg.Mode = "bagher"
	if cfg.RemoteUser == "" {
		cfg.RemoteUser = "root"
	}
	if cfg.RemoteSSHPort <= 0 {
		cfg.RemoteSSHPort = 22
	}
	if cfg.KeyPath == "" || (os.Geteuid() != 0 && strings.HasPrefix(cfg.KeyPath, "/root")) {
		cfg.KeyPath = defaultSSHFwdKeyPath()
	}
	if cfg.Ports == nil {
		cfg.Ports = []int{}
	}
	if cfg.BindAddr == "" {
		cfg.BindAddr = "0.0.0.0"
	}
	if cfg.FRPBindPort <= 0 {
		cfg.FRPBindPort = 55400
	}
	if cfg.PoolCount <= 0 {
		cfg.PoolCount = 25
	}
	if cfg.ServerAliveInterval <= 0 {
		cfg.ServerAliveInterval = 10
	}
	if cfg.ServerAliveCountMax <= 0 {
		cfg.ServerAliveCountMax = 3
	}
	return cfg
}

func saveSSHFwdConfigLocked(cfg SSHFwdConfig) error {
	cfg.UpdatedAt = time.Now().Format("2006-01-02 15:04:05")
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(sshFwdConfigFile(), b, 0600)
}

// ensureSSHFwdKey generates an ed25519 keypair if not present.
func ensureSSHFwdKey(keyPath string) (pubKey string, err error) {
	if keyPath == "" || (os.Geteuid() != 0 && strings.HasPrefix(keyPath, "/root")) {
		keyPath = defaultSSHFwdKeyPath()
	}
	pubPath := keyPath + ".pub"
	if _, statErr := os.Stat(keyPath); os.IsNotExist(statErr) {
		if err := os.MkdirAll(filepath.Dir(keyPath), 0700); err != nil {
			keyPath = filepath.Join(configDir, "hashem-fwd")
			pubPath = keyPath + ".pub"
			_ = os.MkdirAll(filepath.Dir(keyPath), 0700)
		}
		if _, statErr2 := os.Stat(keyPath); os.IsNotExist(statErr2) {
			out, err := runCmd("ssh-keygen", "-t", "ed25519", "-N", "", "-f", keyPath, "-C", "hashem-bagher-carrier")
			if err != nil {
				return "", fmt.Errorf("ssh-keygen failed: %v (%s)", err, strings.TrimSpace(out))
			}
		}
	}
	b, err := os.ReadFile(pubPath)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// bagherKeyLock confines the Iran server's key on the Foreign server. restrict
// alone still lets a key run commands (as root here), and port-forwarding
// without permitopen allows -L to any service. command="/bin/false" stops
// command execution (Bagher's ssh -N opens no session, so it is unaffected);
// "none" is not valid for permitopen in authorized_keys, so -L is limited to
// the tunnel port itself, which only leads back to Iran's own frps.
const bagherKeyLock = `command="/bin/false",restrict,port-forwarding`

// formatAuthorizedKeyLine constructs an authorized_keys entry with restrict & permitopen/permitlisten.
func formatAuthorizedKeyLine(pubKey string, mode string, frpPort int, ports []int) string {
	if mode == "bagher" || mode == "frp_ssh" {
		if frpPort <= 0 {
			frpPort = 55400
		}
		return fmt.Sprintf("%s,permitlisten=\"127.0.0.1:%d\",permitopen=\"127.0.0.1:%d\" %s", bagherKeyLock, frpPort, frpPort, strings.TrimSpace(pubKey))
	}
	permitOpenOpts := make([]string, 0, len(ports))
	for _, p := range ports {
		permitOpenOpts = append(permitOpenOpts, fmt.Sprintf("permitopen=\"127.0.0.1:%d\"", p))
	}
	permitStr := strings.Join(permitOpenOpts, ",")
	return fmt.Sprintf("%s,%s %s", bagherKeyLock, permitStr, strings.TrimSpace(pubKey))
}

// authorizedKeysPath is root's authorized_keys; tests point it elsewhere.
var authorizedKeysPath = "/root/.ssh/authorized_keys"

// installRestrictedKey adds pubKey to authorized_keys behind the restrict
// options from formatAuthorizedKeyLine, replacing any earlier entry for the
// same key. The key comes from a peer, so it must be exactly one valid public
// key: a newline could smuggle in a second, unrestricted key, and a loose
// substring match on removal could delete every other root key.
func installRestrictedKey(pubKey, mode string, frpPort int, ports []int) error {
	pubKey = strings.TrimSpace(pubKey)
	if strings.ContainsAny(pubKey, "\r\n") {
		return fmt.Errorf("public key must be a single line")
	}
	pk, _, opts, rest, err := ssh.ParseAuthorizedKey([]byte(pubKey))
	if err != nil {
		return fmt.Errorf("invalid public key: %v", err)
	}
	if len(opts) > 0 || len(bytes.TrimSpace(rest)) > 0 {
		return fmt.Errorf("public key must not carry options or extra data")
	}
	canonical := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk)))
	authLine := formatAuthorizedKeyLine(canonical, mode, frpPort, ports)

	_ = os.MkdirAll(filepath.Dir(authorizedKeysPath), 0700)
	existing, _ := os.ReadFile(authorizedKeysPath)
	var newLines []string
	for _, line := range strings.Split(string(existing), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if old, _, _, _, err := ssh.ParseAuthorizedKey([]byte(trimmed)); err == nil && bytes.Equal(old.Marshal(), pk.Marshal()) {
			continue
		}
		newLines = append(newLines, trimmed)
	}
	newLines = append(newLines, authLine)
	tmp := authorizedKeysPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(strings.Join(newLines, "\n")+"\n"), 0600); err != nil {
		return fmt.Errorf("failed writing authorized_keys: %w", err)
	}
	if err := os.Rename(tmp, authorizedKeysPath); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("failed writing authorized_keys: %w", err)
	}
	return nil
}

// upgradeBagherKeyLocks rewrites Bagher key entries written by older panels
// (restrict,port-forwarding,permitlisten="127.0.0.1:N" only), which let the
// Iran server's key run commands as root and open -L forwards on this server.
// Only lines in exactly that old form change; every other key is untouched.
func upgradeBagherKeyLocks() (int, error) {
	data, err := os.ReadFile(authorizedKeysPath)
	if err != nil {
		return 0, nil // no authorized_keys: nothing to upgrade
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	changed := 0
	for i, line := range lines {
		pk, _, opts, _, perr := ssh.ParseAuthorizedKey([]byte(strings.TrimSpace(line)))
		if perr != nil || len(opts) != 3 || opts[0] != "restrict" || opts[1] != "port-forwarding" ||
			!strings.HasPrefix(opts[2], `permitlisten="127.0.0.1:`) {
			continue
		}
		port, cerr := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(opts[2], `permitlisten="127.0.0.1:`), `"`))
		if cerr != nil || port <= 0 || port > 65535 {
			continue
		}
		lines[i] = formatAuthorizedKeyLine(strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk))), "bagher", port, nil)
		changed++
	}
	if changed == 0 {
		return 0, nil
	}
	tmp := authorizedKeysPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(strings.Join(lines, "\n")+"\n"), 0600); err != nil {
		return 0, err
	}
	if err := os.Rename(tmp, authorizedKeysPath); err != nil {
		_ = os.Remove(tmp)
		return 0, err
	}
	return changed, nil
}

// bagherCarrierBin is the panel binary, which runs the Bagher carrier.
func bagherCarrierBin() string {
	if exe, err := os.Executable(); err == nil {
		if p, err := filepath.EvalSymlinks(exe); err == nil {
			exe = p
		}
		if b := filepath.Base(exe); strings.HasSuffix(b, ".test") || strings.HasSuffix(b, ".test.exe") { // unit tests
			return "/usr/local/bin/gre-panel"
		}
		return exe
	}
	return "/usr/local/bin/gre-panel"
}

// buildSSHFwdService generates the systemd unit of link 1's carrier.
func buildSSHFwdService(cfg SSHFwdConfig) string {
	return buildBagherCarrierUnit(cfg, 1)
}

// buildBagherCarrierUnit is the unit of one link's carrier. In Bagher mode
// that is the panel's own SSH client (bagher_carrier.go); direct mode, which
// the panel no longer offers, keeps plain ssh -L.
func buildBagherCarrierUnit(cfg SSHFwdConfig, id int) string {
	var execCmd, desc string
	if cfg.Mode == "bagher" || cfg.Mode == "frp_ssh" {
		execCmd = fmt.Sprintf("%s bagher-carrier -link %d", bagherCarrierBin(), id)
		desc = "Hashem Bagher Engine (Stealth Hybrid Tunnel)"
		if id > 1 {
			if l, ok := findBagherLink(cfg, id); ok {
				desc += " to " + l.RemoteHost
			}
		}
	} else {
		portArg := ""
		if cfg.RemoteSSHPort > 0 && cfg.RemoteSSHPort != 22 {
			portArg = fmt.Sprintf("-p %d ", cfg.RemoteSSHPort)
		}
		// "*" is every address of both families: users reach the port over
		// IPv4 and IPv6, and a host without IPv6 still binds IPv4 alone.
		bind := cfg.BindAddr
		if bind == "0.0.0.0" || bind == "::" {
			bind = "*"
		}
		forwards := make([]string, 0, len(cfg.Ports))
		for _, p := range cfg.Ports {
			forwards = append(forwards, fmt.Sprintf("-L %s:127.0.0.1:%d", hostPort(bind, p), p))
		}
		execCmd = fmt.Sprintf("/usr/bin/ssh -N -i %s -o BatchMode=yes -o IdentitiesOnly=yes -o ExitOnForwardFailure=yes -o ConnectTimeout=8 -o ServerAliveInterval=%d -o ServerAliveCountMax=%d -o StrictHostKeyChecking=accept-new %s%s %s@%s",
			cfg.KeyPath, cfg.ServerAliveInterval, cfg.ServerAliveCountMax, portArg, strings.Join(forwards, " "), cfg.RemoteUser, cfg.RemoteHost)
		desc = "Hashem Direct SSH Forward Carrier"
	}

	return fmt.Sprintf(`[Unit]
Description=%s
After=network-online.target hashem-bagher-frps.service
Wants=network-online.target

[Service]
ExecStart=%s
Restart=always
RestartSec=15
StartLimitIntervalSec=120
StartLimitBurst=5
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
`, desc, execCmd)
}

// buildFRPSConfig generates the frps TOML configuration for Iran host in Bagher mode.
func buildFRPSConfig(cfg SSHFwdConfig) string {
	dashPort := cfg.FRPBindPort + 1
	return fmt.Sprintf(`bindAddr = "127.0.0.1"
bindPort = %d
proxyBindAddr = "0.0.0.0"
auth.token = "hashem-bagher-sec"
transport.tcpMux = false

webServer.addr = "127.0.0.1"
webServer.port = %d
webServer.user = "admin"
webServer.password = "bagher-dash-local"
`, cfg.FRPBindPort, dashPort)
}

// buildFRPSService generates the systemd unit for frps on Iran host.
func buildFRPSService() string {
	return `[Unit]
Description=Hashem Bagher Engine server (Iran)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/frps -c /etc/gre-panel/bagher/frps.toml
Restart=always
RestartSec=10
StartLimitIntervalSec=60
StartLimitBurst=5
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
`
}

// bagherFRPCNoTLS turns off frp's own TLS (on by default since frp 0.50): frpc
// reaches frps through the SSH tunnel, which already encrypts, so TLS only
// added an RSA-2048 handshake to every work connection on both servers.
const bagherFRPCNoTLS = "transport.tls.enable = false"

// buildFRPCConfig generates the frpc TOML configuration for Foreign host in Bagher mode.
// With udp, each port also gets a udp proxy: frp carries it over the same
// work connections, so it rides the SSH tunnel like TCP.
func buildFRPCConfig(frpBindPort int, poolCount int, ports []int, udp bool) string {
	var proxyBlocks strings.Builder
	for _, p := range ports {
		proxyBlocks.WriteString(fmt.Sprintf(`
[[proxies]]
name = "p%d"
type = "tcp"
localIP = "127.0.0.1"
localPort = %d
remotePort = %d
`, p, p, p))
		if udp {
			proxyBlocks.WriteString(fmt.Sprintf(`
[[proxies]]
name = "u%d"
type = "udp"
localIP = "127.0.0.1"
localPort = %d
remotePort = %d
`, p, p, p))
		}
	}
	dashPort := frpBindPort + 2
	return fmt.Sprintf(`serverAddr = "127.0.0.1"
serverPort = %d
auth.token = "hashem-bagher-sec"
transport.tcpMux = false
%s
transport.poolCount = %d
transport.heartbeatInterval = 15
transport.heartbeatTimeout = 45
transport.dialServerKeepalive = 15
loginFailExit = false

webServer.addr = "127.0.0.1"
webServer.port = %d
webServer.user = "admin"
webServer.password = "bagher-dash-local"
%s`, frpBindPort, bagherFRPCNoTLS, poolCount, dashPort, proxyBlocks.String())
}

// buildForeignSetupCommand creates a standalone shell command to be executed on Foreign host.
func buildForeignSetupCommand(cfg SSHFwdConfig) string {
	if len(cfg.Ports) == 0 {
		return ""
	}
	frpcToml := buildFRPCConfig(cfg.FRPBindPort, cfg.PoolCount, cfg.Ports, cfg.UDP)
	return fmt.Sprintf(`mkdir -p /etc/gre-panel/bagher
cat > /etc/gre-panel/bagher/frpc.toml <<'EOF'
%sEOF
cat > /etc/systemd/system/hashem-bagher-frpc.service <<'EOF'
[Unit]
Description=Hashem Bagher Engine client (Foreign)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/frpc -c /etc/gre-panel/bagher/frpc.toml
Restart=always
RestartSec=10
StartLimitIntervalSec=60
StartLimitBurst=5
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload && systemctl enable --now hashem-bagher-frpc.service`, strings.TrimSpace(frpcToml))
}

// BagherBundle encapsulates all connection, authentication, and port parameters
// for zero-terminal Foreign server auto-configuration.
type BagherBundle struct {
	Version      int    `json:"v"`
	Role         string `json:"role"`
	IranPub      string `json:"iran_pub"`
	RemoteHost   string `json:"remote_host,omitempty"`
	FRPPort      int    `json:"frp_port"`
	Ports        []int  `json:"ports"`
	Token        string `json:"token"`
	PoolCount    int    `json:"pool_count"`
	UDP          bool   `json:"udp,omitempty"`
	SSHPublicKey string `json:"ssh_pub_key"`
	SSHPort      int    `json:"ssh_port"`
	Timestamp    int64  `json:"ts"`
}

func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return true
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return ip.IsPrivate() || ip.IsMulticast() // fc00::/7 unique local
	}
	if ip4[0] == 10 {
		return true
	}
	if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
		return true
	}
	if ip4[0] == 192 && ip4[1] == 168 {
		return true
	}
	if ip4[0] == 100 && ip4[1]&0xC0 == 64 { // 100.64.0.0/10 carrier-grade NAT
		return true
	}
	return false
}

// resolvePublicIP is detectPublicIP, which now skips private addresses and
// caches its external lookup itself.
func resolvePublicIP() string {
	return detectPublicIP()
}

// MakeBagherBundle builds a portable encrypted/base64 string for zero-terminal Foreign setup.
// It requires both remote host IP and forwarded ports to be set before generating a bundle.
func MakeBagherBundle(cfg SSHFwdConfig, pubKey string) (string, error) {
	if len(cfg.Ports) == 0 {
		return "", fmt.Errorf("forwarded ports are required before generating bundle")
	}
	if strings.TrimSpace(cfg.RemoteHost) == "" {
		return "", fmt.Errorf("remote host IP is required before generating bundle")
	}
	iranIP := resolvePublicIP()
	if isV6(cfg.RemoteHost) { // the link runs over IPv6: the foreign server sees this one's IPv6
		if v6 := detectPublicIP6(); v6 != "" {
			iranIP = v6
		}
	}
	if iranIP == "" || iranIP == "0.0.0.0" {
		iranIP = cfg.BindAddr
	}
	b := BagherBundle{
		Version:      1,
		Role:         "foreign",
		IranPub:      iranIP,
		RemoteHost:   strings.TrimSpace(cfg.RemoteHost),
		FRPPort:      cfg.FRPBindPort,
		Ports:        cfg.Ports,
		Token:        "hashem-bagher-sec",
		PoolCount:    cfg.PoolCount,
		UDP:          cfg.UDP,
		SSHPublicKey: strings.TrimSpace(pubKey),
		SSHPort:      cfg.RemoteSSHPort,
		Timestamp:    time.Now().Unix(),
	}
	data, err := json.Marshal(b)
	if err != nil {
		return "", err
	}
	return "BAGHER:" + base64.StdEncoding.EncodeToString(data), nil
}

// ParseBagherBundle parses and validates a BAGHER:... bundle string.
func ParseBagherBundle(bundleStr string) (*BagherBundle, error) {
	bundleStr = strings.TrimSpace(bundleStr)
	if !strings.HasPrefix(bundleStr, "BAGHER:") {
		return nil, fmt.Errorf("invalid bundle prefix, expected BAGHER: prefix")
	}
	rawB64 := strings.TrimPrefix(bundleStr, "BAGHER:")
	data, err := base64.StdEncoding.DecodeString(rawB64)
	if err != nil {
		return nil, fmt.Errorf("failed decoding base64 bundle: %w", err)
	}
	var b BagherBundle
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("invalid bundle json: %w", err)
	}
	if strings.TrimSpace(b.SSHPublicKey) == "" {
		return nil, fmt.Errorf("bundle missing ssh_pub_key")
	}
	if len(b.Ports) == 0 {
		return nil, fmt.Errorf("bundle contains no forwarded ports")
	}
	if strings.TrimSpace(b.IranPub) == "" && strings.TrimSpace(b.RemoteHost) == "" {
		return nil, fmt.Errorf("bundle missing server IP")
	}
	if b.FRPPort <= 0 {
		b.FRPPort = 55400
	}
	if b.PoolCount <= 0 {
		b.PoolCount = 25
	}
	if b.Token == "" {
		b.Token = "hashem-bagher-sec"
	}
	return &b, nil
}

// applyBagherBundle configures Foreign host automatically from a parsed BagherBundle.
func applyBagherBundle(b *BagherBundle) error {
	if err := installRestrictedKey(b.SSHPublicKey, "bagher", b.FRPPort, b.Ports); err != nil {
		return err
	}

	_ = os.MkdirAll("/etc/gre-panel/bagher", 0755)
	frpcToml := buildFRPCConfig(b.FRPPort, b.PoolCount, b.Ports, b.UDP)
	if err := writeTokenFile("/etc/gre-panel/bagher/frpc.toml", []byte(frpcToml)); err != nil {
		return fmt.Errorf("failed writing frpc.toml: %w", err)
	}

	frpcUnit := `[Unit]
Description=Hashem Bagher Engine client (Foreign)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/frpc -c /etc/gre-panel/bagher/frpc.toml
Restart=always
RestartSec=10
StartLimitIntervalSec=60
StartLimitBurst=5
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
`
	if err := os.WriteFile("/etc/systemd/system/hashem-bagher-frpc.service", []byte(frpcUnit), 0644); err != nil {
		return fmt.Errorf("failed writing frpc service: %w", err)
	}

	if _, err := runCmd("systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("daemon-reload failed: %w", err)
	}
	if _, err := runCmd("systemctl", "enable", "--now", "hashem-bagher-frpc.service"); err != nil {
		return fmt.Errorf("failed starting hashem-bagher-frpc: %w", err)
	}

	cfg := loadSSHFwdConfigLocked()
	cfg.Role = "foreign"
	cfg.Mode = "bagher"
	cfg.FRPBindPort = b.FRPPort
	cfg.PoolCount = b.PoolCount
	if b.SSHPort > 0 { // this server's sshd port, which the Iran server dials (its traffic is counted there)
		cfg.RemoteSSHPort = b.SSHPort
	}
	cfg.UDP = b.UDP
	cfg.Ports = b.Ports
	if b.IranPub != "" {
		cfg.RemoteHost = b.IranPub
	} else if b.RemoteHost != "" {
		cfg.RemoteHost = b.RemoteHost
	}
	cfg.Enabled = true
	cfg.LastStatus = "active"
	cfg.LastError = ""
	return saveSSHFwdConfigLocked(cfg)
}

func formatByteSize(b int64) string {
	if b <= 0 {
		return "0 B"
	}
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

type BagherLiveMetrics struct {
	Connected      bool    `json:"connected"`
	StatusText     string  `json:"status_text"`
	LatencyMs      float64 `json:"latency_ms"`
	RxBytes        int64   `json:"rx_bytes"`
	TxBytes        int64   `json:"tx_bytes"`
	TotalBytes     int64   `json:"total_bytes"`
	RxFormatted    string  `json:"rx_formatted"`
	TxFormatted    string  `json:"tx_formatted"`
	TotalFormatted string  `json:"total_formatted"`
	CurConns       int     `json:"cur_conns"`
	ClientCounts   int     `json:"client_counts"`
}

func getBagherLiveMetrics(cfg SSHFwdConfig) BagherLiveMetrics {
	isForeign := cfg.Role == "foreign" || cfg.Role == "server"
	if !isForeign {
		outFrpc, _ := runCmd("systemctl", "is-active", "hashem-bagher-frpc.service")
		if strings.TrimSpace(outFrpc) == "active" {
			isForeign = true
		}
	}

	if isForeign {
		outFrpc, _ := runCmd("systemctl", "is-active", "hashem-bagher-frpc.service")
		if strings.TrimSpace(outFrpc) != "active" {
			return BagherLiveMetrics{Connected: false, StatusText: "inactive", RxFormatted: "0 B", TxFormatted: "0 B", TotalFormatted: "0 B"}
		}

		// Dial 127.0.0.1:FRPBindPort (SSH reverse forward to Iran)
		t0 := time.Now()
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", cfg.FRPBindPort), 600*time.Millisecond)
		var lat float64
		connected := false
		statusText := "waiting_for_iran"
		if err == nil {
			lat = float64(time.Since(t0).Microseconds()) / 1000.0
			_ = conn.Close()
			connected = true
			statusText = "connected"
		}

		return BagherLiveMetrics{
			Connected:      connected,
			StatusText:     statusText,
			LatencyMs:      lat,
			RxFormatted:    "0 B",
			TxFormatted:    "0 B",
			TotalFormatted: "0 B",
			ClientCounts:   1,
		}
	}

	// Iran side
	outBagher, _ := runCmd("systemctl", "is-active", "hashem-bagher.service")
	outFrps, _ := runCmd("systemctl", "is-active", "hashem-bagher-frps.service")
	bagherActive := strings.TrimSpace(outBagher) == "active"
	frpsActive := strings.TrimSpace(outFrps) == "active"

	if !bagherActive && !frpsActive {
		return BagherLiveMetrics{Connected: false, StatusText: "inactive", RxFormatted: "0 B", TxFormatted: "0 B", TotalFormatted: "0 B"}
	}

	// The carrier's keepalive round trip is the tunnel's own ping; a TCP
	// connect to the SSH port is only the path's, used until it reports.
	lat, _ := bagherCarrierRTT(cfg, 1)
	if lat <= 0 && cfg.RemoteHost != "" {
		remoteSSHPort := cfg.RemoteSSHPort
		if remoteSSHPort <= 0 {
			remoteSSHPort = 22
		}
		tRemote := time.Now()
		rConn, rErr := net.DialTimeout("tcp", hostPort(cfg.RemoteHost, remoteSSHPort), 600*time.Millisecond)
		if rErr == nil {
			lat = float64(time.Since(tRemote).Microseconds()) / 1000.0
			_ = rConn.Close()
		}
	}
	if lat <= 0 {
		t0 := time.Now()
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", cfg.FRPBindPort), 400*time.Millisecond)
		if err == nil {
			lat = float64(time.Since(t0).Microseconds()) / 1000.0
			_ = conn.Close()
		}
	}

	dashPort := cfg.FRPBindPort + 1
	dashURL := fmt.Sprintf("http://127.0.0.1:%d/api/serverinfo", dashPort)
	client := &http.Client{Timeout: 400 * time.Millisecond}
	req, err := http.NewRequest("GET", dashURL, nil)
	var rx, tx int64
	var clientCount, curConns int
	gotDashboard := false
	if err == nil {
		req.SetBasicAuth("admin", "bagher-dash-local")
		resp, rErr := client.Do(req)
		if rErr == nil && resp.StatusCode == 200 {
			var info struct {
				TotalTrafficIn  int64 `json:"totalTrafficIn"`
				TotalTrafficOut int64 `json:"totalTrafficOut"`
				CurConns        int   `json:"curConns"`
				ClientCounts    int   `json:"clientCounts"`
			}
			if json.NewDecoder(resp.Body).Decode(&info) == nil {
				rx = info.TotalTrafficIn
				tx = info.TotalTrafficOut
				curConns = info.CurConns
				clientCount = info.ClientCounts
				gotDashboard = true
			}
			_ = resp.Body.Close()
		}
	}

	connected := false
	statusText := "waiting_for_peer"
	if online, ok := bagherProxiesOnline(cfg); ok && len(cfg.Links) > 0 {
		// several foreign servers share this frps: link 1 is up when its own
		// ports are registered, not when any frpc is connected
		if bagherLinkUp(online, cfg.Ports) {
			connected = true
			statusText = "connected"
		}
	} else if gotDashboard {
		if clientCount > 0 {
			connected = true
			statusText = "connected"
		}
	} else {
		outSS, _ := runCmd("ss", "-tn", "state", "established", fmt.Sprintf("sport = :%d or dport = :%d", cfg.FRPBindPort, cfg.FRPBindPort))
		lines := strings.Split(strings.TrimSpace(outSS), "\n")
		if len(lines) > 1 {
			connected = true
			statusText = "connected"
			clientCount = 1
		}
	}

	tot := rx + tx
	return BagherLiveMetrics{
		Connected:      connected,
		StatusText:     statusText,
		LatencyMs:      lat,
		RxBytes:        rx,
		TxBytes:        tx,
		TotalBytes:     tot,
		RxFormatted:    formatByteSize(rx),
		TxFormatted:    formatByteSize(tx),
		TotalFormatted: formatByteSize(tot),
		CurConns:       curConns,
		ClientCounts:   clientCount,
	}
}

// cleanDnatConflict removes conflicting nftables table or rescues that capture these ports.
func cleanDnatConflict(ports []int) error {
	_, _ = runCmd("systemctl", "disable", "--now", "hashem-rescue-dnat.service")
	_, _ = runCmd("nft", "delete", "table", "inet", "hashem_dnat")
	return nil
}

// enableSSHFwd applies configuration, clears DNAT conflicts, installs service and starts it.
func enableSSHFwd(cfg SSHFwdConfig) error {
	if cfg.RemoteHost == "" {
		return fmt.Errorf("remote host is required")
	}
	if len(cfg.Ports) == 0 {
		return fmt.Errorf("at least one port is required")
	}
	if _, err := ensureSSHFwdKey(cfg.KeyPath); err != nil {
		return fmt.Errorf("failed ensuring key: %w", err)
	}

	_ = cleanDnatConflict(cfg.Ports)

	_, _ = runCmd("systemctl", "disable", "--now", "hashem-ssh-fwd.service")
	_, _ = runCmd("systemctl", "disable", "--now", "hashem-ssh-frps.service")
	_ = os.Remove("/etc/systemd/system/hashem-ssh-fwd.service")
	_ = os.Remove("/etc/systemd/system/hashem-ssh-frps.service")

	isBagher := cfg.Mode == "bagher" || cfg.Mode == "frp_ssh"
	if isBagher {
		_ = os.MkdirAll("/etc/gre-panel/bagher", 0755)
		frpsToml := buildFRPSConfig(cfg)
		if err := writeTokenFile("/etc/gre-panel/bagher/frps.toml", []byte(frpsToml)); err != nil {
			return fmt.Errorf("failed writing frps.toml: %w", err)
		}
		if err := os.WriteFile("/etc/systemd/system/hashem-bagher-frps.service", []byte(buildFRPSService()), 0644); err != nil {
			return fmt.Errorf("failed writing frps service: %w", err)
		}
	} else {
		_, _ = runCmd("systemctl", "disable", "--now", "hashem-bagher-frps.service")
	}

	svcContent := buildSSHFwdService(cfg)
	unitPath := "/etc/systemd/system/hashem-bagher.service"
	if err := os.WriteFile(unitPath, []byte(svcContent), 0644); err != nil {
		return fmt.Errorf("failed writing unit: %w", err)
	}

	if _, err := runCmd("systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("daemon-reload failed: %w", err)
	}
	if isBagher {
		if _, err := runCmd("systemctl", "enable", "--now", "hashem-bagher-frps.service"); err != nil {
			return fmt.Errorf("failed starting hashem-bagher-frps: %w", err)
		}
	}
	// restart, not enable --now: a running carrier read the old settings
	go func() {
		_, _ = runCmd("systemctl", "enable", "hashem-bagher.service")
		_, _ = runCmd("systemctl", "restart", "hashem-bagher.service")
	}()
	if isBagher && len(cfg.Links) > 0 {
		if err := installBagherLinkUnits(cfg, true); err != nil {
			return err
		}
	}

	cfg.Enabled = true
	cfg.LastStatus = "active"
	cfg.LastError = ""
	return saveSSHFwdConfigLocked(cfg)
}

// disableSSHFwd stops and disables the systemd services.
func disableSSHFwd() error {
	cfg := loadSSHFwdConfigLocked()
	stopBagherLinkUnits(cfg, false)
	_, _ = runCmd("systemctl", "disable", "--now", "hashem-bagher.service")
	_, _ = runCmd("systemctl", "disable", "--now", "hashem-bagher-frps.service")
	_, _ = runCmd("systemctl", "disable", "--now", "hashem-bagher-frpc.service")
	_, _ = runCmd("systemctl", "disable", "--now", "hashem-ssh-fwd.service")
	_, _ = runCmd("systemctl", "disable", "--now", "hashem-ssh-frps.service")
	cfg.Enabled = false
	cfg.LastStatus = "inactive"
	return saveSSHFwdConfigLocked(cfg)
}

// cleanSSHFwd completely purges Bagher services, units, configs, and firewall rules while preserving SSH keys.
func cleanSSHFwd() error {
	_ = disableSSHFwd()
	stopBagherLinkUnits(loadSSHFwdConfigLocked(), true)
	_ = os.Remove(bagherCarrierStatusPath(1))
	units := []string{
		"/etc/systemd/system/hashem-bagher.service",
		"/etc/systemd/system/hashem-bagher-frps.service",
		"/etc/systemd/system/hashem-bagher-frpc.service",
		"/etc/systemd/system/hashem-ssh-fwd.service",
		"/etc/systemd/system/hashem-ssh-frps.service",
	}
	for _, u := range units {
		_ = os.Remove(u)
	}
	_, _ = runCmd("systemctl", "daemon-reload")
	_, _ = runCmd("systemctl", "reset-failed")

	_ = os.Remove("/etc/gre-panel/bagher/frps.toml")
	_ = os.Remove("/etc/gre-panel/bagher/frpc.toml")
	_, _ = runCmd("nft", "delete", "table", "inet", "hashem_dnat")

	cfg := loadSSHFwdConfigLocked()
	cfg.Enabled = false
	cfg.RemoteHost = ""
	cfg.Ports = nil
	cfg.Links = nil
	cfg.Mode = "bagher"
	cfg.LastStatus = "inactive"
	cfg.LastError = ""
	cfg.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	cfg.Role = ""
	return saveSSHFwdConfigLocked(cfg)
}

// checkPortListening returns true if a TCP listener exists on bind:port.
func checkPortListening(bind string, port int) bool {
	target := net.JoinHostPort(bind, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", target, 500*time.Millisecond)
	if err == nil {
		_ = conn.Close()
		return true
	}
	return false
}

// bagherUnitNames are every unit name Bagher (or its predecessors) used.
var bagherUnitNames = []string{"hashem-bagher", "hashem-bagher-frpc", "hashem-bagher-frps", "hashem-ssh-fwd", "hashem-frp-ssh-tunnel"}

// bagherUnitInstalled reports whether any Bagher unit file exists (no fork).
func bagherUnitInstalled() bool {
	for _, n := range bagherUnitNames {
		if _, err := os.Stat(filepath.Join("/etc/systemd/system", n+".service")); err == nil {
			return true
		}
	}
	return len(staleBagherLinkUnits(nil)) > 0
}

// getSSHFwdSnapshotStatus is the cheap status the 5s snapshot collects (M9).
// The full getSSHFwdStatus also creates the SSH key (ssh-keygen on every
// server, Bagher or not) and builds the bundle, which looks up the public IP
// over HTTP; neither belongs in a 5-second loop. Without any Bagher config or
// unit nothing is run at all.
func getSSHFwdSnapshotStatus() map[string]any {
	sshFwdMu.Lock()
	defer sshFwdMu.Unlock()
	cfg := loadSSHFwdConfigLocked()
	configured := cfg.Enabled || (strings.TrimSpace(cfg.RemoteHost) != "" && len(cfg.Ports) > 0) || bagherUnitInstalled()
	if !configured {
		return map[string]any{"has_config": false, "enabled": false, "is_active": false, "connected": false}
	}
	isActive := false
	for _, n := range bagherUnitNames {
		if out, _ := runCmd("systemctl", "is-active", n+".service"); strings.TrimSpace(out) == "active" {
			isActive = true
			break
		}
	}
	metrics := getBagherLiveMetrics(cfg)
	return map[string]any{
		"links":           bagherLinksStatus(cfg, "", false),
		"name":            linkLabel("bagher-1"),
		"has_config":      true,
		"enabled":         cfg.Enabled || isActive,
		"is_active":       isActive,
		"mode":            cfg.Mode,
		"role":            cfg.Role,
		"remote_host":     cfg.RemoteHost,
		"ports":           cfg.Ports,
		"udp":             cfg.UDP,
		"frp_bind_port":   cfg.FRPBindPort,
		"last_error":      cfg.LastError,
		"connected":       metrics.Connected,
		"status_text":     metrics.StatusText,
		"latency_ms":      metrics.LatencyMs,
		"rx_bytes":        metrics.RxBytes,
		"tx_bytes":        metrics.TxBytes,
		"total_bytes":     metrics.TotalBytes,
		"rx_formatted":    metrics.RxFormatted,
		"tx_formatted":    metrics.TxFormatted,
		"total_formatted": metrics.TotalFormatted,
		"cur_conns":       metrics.CurConns,
		"client_counts":   metrics.ClientCounts,
	}
}

// getSSHFwdStatus returns runtime status of the forwarder.
func getSSHFwdStatus() map[string]any {
	sshFwdMu.Lock()
	defer sshFwdMu.Unlock()
	return getSSHFwdStatusLocked()
}

// getSSHFwdStatusLocked returns runtime status when sshFwdMu is already held.
func getSSHFwdStatusLocked() map[string]any {
	cfg := loadSSHFwdConfigLocked()
	pubKey, _ := ensureSSHFwdKey(cfg.KeyPath)

	out, _ := runCmd("systemctl", "is-active", "hashem-bagher.service")
	isActive := strings.TrimSpace(out) == "active"
	if !isActive {
		outFrpc, _ := runCmd("systemctl", "is-active", "hashem-bagher-frpc.service")
		if strings.TrimSpace(outFrpc) == "active" {
			isActive = true
		}
	}
	if !isActive {
		outFrps, _ := runCmd("systemctl", "is-active", "hashem-bagher-frps.service")
		if strings.TrimSpace(outFrps) == "active" {
			isActive = true
		}
	}
	// Fallback check for legacy services
	if !isActive {
		outLegacy, _ := runCmd("systemctl", "is-active", "hashem-ssh-fwd.service")
		if strings.TrimSpace(outLegacy) == "active" {
			isActive = true
		} else {
			outTun, _ := runCmd("systemctl", "is-active", "hashem-frp-ssh-tunnel.service")
			if strings.TrimSpace(outTun) == "active" {
				isActive = true
			}
		}
	}

	portStatus := make(map[string]bool)
	for _, p := range cfg.Ports {
		portStatus[strconv.Itoa(p)] = checkPortListening("127.0.0.1", p)
	}

	dnatOut, _ := runCmd("nft", "list", "table", "inet", "hashem_dnat")
	dnatActive := strings.Contains(dnatOut, "table inet hashem_dnat")

	authLine := ""
	if pubKey != "" {
		authLine = formatAuthorizedKeyLine(pubKey, cfg.Mode, cfg.FRPBindPort, cfg.Ports)
	}

	foreignCmd := ""
	bundleStr := ""
	if len(cfg.Ports) > 0 && strings.TrimSpace(cfg.RemoteHost) != "" {
		foreignCmd = buildForeignSetupCommand(cfg)
		bundleStr, _ = MakeBagherBundle(cfg, pubKey)
	}
	metrics := getBagherLiveMetrics(cfg)

	hasBagher := HasFeature("bagher") || HasFeature("frp_ssh")
	hasConfig := (len(strings.TrimSpace(cfg.RemoteHost)) > 0 && len(cfg.Ports) > 0) || cfg.Enabled || isActive

	return map[string]any{
		"links":             bagherLinksStatus(cfg, pubKey, true),
		"name":              linkLabel("bagher-1"),
		"has_config":        hasConfig,
		"enabled":           cfg.Enabled || isActive,
		"is_active":         isActive,
		"mode":              cfg.Mode,
		"role":              cfg.Role,
		"remote_host":       cfg.RemoteHost,
		"remote_user":       cfg.RemoteUser,
		"remote_ssh_port":   cfg.RemoteSSHPort,
		"key_path":          cfg.KeyPath,
		"pub_key":           pubKey,
		"auth_line":         authLine,
		"foreign_setup_cmd": foreignCmd,
		"bundle":            bundleStr,
		"ports":             cfg.Ports,
		"bind_addr":         cfg.BindAddr,
		"frp_bind_port":     cfg.FRPBindPort,
		"pool_count":        cfg.PoolCount,
		"udp":               cfg.UDP,
		"licensed_bagher":   hasBagher,
		"licensed_frp_ssh":  hasBagher,
		"machine_hash":      getMachineHash(),
		"port_status":       portStatus,
		"dnat_conflict":     dnatActive,
		"last_error":        cfg.LastError,
		"updated_at":        cfg.UpdatedAt,
		"connected":         metrics.Connected,
		"status_text":       metrics.StatusText,
		"latency_ms":        metrics.LatencyMs,
		"rx_bytes":          metrics.RxBytes,
		"tx_bytes":          metrics.TxBytes,
		"total_bytes":       metrics.TotalBytes,
		"rx_formatted":      metrics.RxFormatted,
		"tx_formatted":      metrics.TxFormatted,
		"total_formatted":   metrics.TotalFormatted,
		"cur_conns":         metrics.CurConns,
		"client_counts":     metrics.ClientCounts,
	}
}

// handleSSHFwdGet returns current SSH Forwarding / Bagher configuration and status.
func handleSSHFwdGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, getSSHFwdStatus())
}

// handleSSHFwdPost handles commands like enable, disable, update-ports, gen-key, sync-peer, apply-bundle.
func handleSSHFwdPost(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Action      string `json:"action"`
		Mode        string `json:"mode"`
		Role        string `json:"role"`
		RemoteHost  string `json:"remote_host"`
		RemoteUser  string `json:"remote_user"`
		SSHPort     int    `json:"ssh_port"`
		Ports       string `json:"ports"`
		BindAddr    string `json:"bind_addr"`
		FRPBindPort int    `json:"frp_bind_port"`
		PoolCount   int    `json:"pool_count"`
		Bundle      string `json:"bundle"`
		UDP         *bool  `json:"udp"`
		ID          int    `json:"id"`
		// Name labels the foreign server (link 1 on enable, the new one on
		// add_link); a pointer, so an enable that does not send it keeps it
		Name *string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeAPIError(w, r, "E-SSHFWD-01", "invalid json payload")
		return
	}

	act := strings.ToLower(strings.TrimSpace(body.Action))
	sshFwdMu.Lock()
	defer sshFwdMu.Unlock()
	cfg := loadSSHFwdConfigLocked()

	switch act {
	case "apply_bundle", "apply-bundle":
		if !(HasFeature("bagher") || HasFeature("frp_ssh")) {
			writeAPIError(w, r, "E-LIC-01", "Bagher Engine requires a valid Premium license (Machine: "+getMachineHash()+")")
			return
		}
		bundleStr := strings.TrimSpace(body.Bundle)
		if bundleStr == "" {
			writeAPIError(w, r, "E-SSHFWD-07", "bundle string is required")
			return
		}
		b, err := ParseBagherBundle(bundleStr)
		if err != nil {
			writeAPIError(w, r, "E-SSHFWD-07", fmt.Sprintf("invalid bagher bundle: %v", err))
			return
		}
		if body.Name != nil {
			if err := validLinkName(strings.TrimSpace(*body.Name)); err != nil {
				writeAPIError(w, r, "E-SSHFWD-07", err.Error())
				return
			}
		}
		if err := applyBagherBundle(b); err != nil {
			writeAPIError(w, r, "E-SSHFWD-08", fmt.Sprintf("failed applying bagher bundle: %v", err))
			return
		}
		if body.Name != nil && strings.TrimSpace(*body.Name) != "" {
			_ = setLinkName("bagher-1", *body.Name)
		}
		writeJSON(w, map[string]any{
			"status":      "ok",
			"message":     "Bagher bundle applied successfully. Foreign client active.",
			"status_data": getSSHFwdStatusLocked(),
		})

	case "get_bundle", "get-bundle":
		if !(HasFeature("bagher") || HasFeature("frp_ssh")) {
			writeAPIError(w, r, "E-LIC-01", "Bagher Engine requires a valid Premium license (Machine: "+getMachineHash()+")")
			return
		}
		if body.RemoteHost != "" {
			cfg.RemoteHost = strings.TrimSpace(body.RemoteHost)
		}
		if body.UDP != nil {
			cfg.UDP = *body.UDP
		}
		if body.Ports != "" {
			parsed := parsePorts(body.Ports)
			if len(parsed) > 0 {
				cfg.Ports = parsed
			}
		}
		if len(cfg.Ports) == 0 {
			writeAPIError(w, r, "E-SSHFWD-02", "Forwarded ports must be specified before generating bundle")
			return
		}
		if strings.TrimSpace(cfg.RemoteHost) == "" {
			writeAPIError(w, r, "E-SSHFWD-01", "Remote host IP must be specified before generating bundle")
			return
		}
		_ = saveSSHFwdConfigLocked(cfg)

		pub, err := ensureSSHFwdKey(cfg.KeyPath)
		if err != nil {
			writeAPIError(w, r, "E-SSHFWD-03", err.Error())
			return
		}
		bundleStr, err := MakeBagherBundle(cfg, pub)
		if err != nil {
			writeAPIError(w, r, "E-SSHFWD-07", fmt.Sprintf("failed generating bundle: %v", err))
			return
		}
		writeJSON(w, map[string]any{"status": "ok", "bundle": bundleStr})

	case "gen_key", "gen-key":
		if !(HasFeature("bagher") || HasFeature("frp_ssh")) {
			writeAPIError(w, r, "E-LIC-01", "Bagher Engine requires a valid Premium license (Machine: "+getMachineHash()+")")
			return
		}
		pub, err := ensureSSHFwdKey(cfg.KeyPath)
		if err != nil {
			writeAPIError(w, r, "E-SSHFWD-03", err.Error())
			return
		}
		writeJSON(w, map[string]any{"status": "ok", "pub_key": pub, "auth_line": formatAuthorizedKeyLine(pub, cfg.Mode, cfg.FRPBindPort, cfg.Ports)})

	case "enable", "apply":
		if !(HasFeature("bagher") || HasFeature("frp_ssh")) {
			writeAPIError(w, r, "E-LIC-01", "Bagher Engine requires a valid Premium license (Machine: "+getMachineHash()+")")
			return
		}
		if body.Name != nil {
			if err := setLinkName("bagher-1", *body.Name); err != nil {
				writeAPIError(w, r, "E-SSHFWD-02", err.Error())
				return
			}
		}
		cfg.Mode = "bagher"
		if body.Role != "" {
			cfg.Role = strings.TrimSpace(body.Role)
		} else if cfg.Role == "" || cfg.Role == "foreign" {
			cfg.Role = "iran"
		}
		if body.RemoteHost != "" {
			cfg.RemoteHost = strings.TrimSpace(body.RemoteHost)
		}
		if body.RemoteUser != "" {
			cfg.RemoteUser = strings.TrimSpace(body.RemoteUser)
		}
		if body.SSHPort > 0 {
			cfg.RemoteSSHPort = body.SSHPort
		}
		if body.BindAddr != "" {
			cfg.BindAddr = strings.TrimSpace(body.BindAddr)
		}
		if body.FRPBindPort > 0 {
			cfg.FRPBindPort = body.FRPBindPort
		}
		if body.PoolCount > 0 {
			cfg.PoolCount = body.PoolCount
		}
		if body.UDP != nil {
			cfg.UDP = *body.UDP
		}
		if body.Ports != "" {
			parsed := parsePorts(body.Ports)
			if len(parsed) > 0 {
				cfg.Ports = parsed
			}
		}

		if cfg.RemoteHost == "" {
			writeAPIError(w, r, "E-SSHFWD-01", "remote_host is required")
			return
		}
		if len(cfg.Ports) == 0 {
			writeAPIError(w, r, "E-SSHFWD-02", "At least one port must be specified in Forwarded Ports")
			return
		}
		if err := checkBagherLinkPorts(cfg, cfg.Ports, 1); err != nil {
			writeAPIError(w, r, "E-SSHFWD-02", err.Error())
			return
		}
		for _, l := range cfg.Links {
			if l.RemoteHost == cfg.RemoteHost {
				writeAPIError(w, r, "E-SSHFWD-01", cfg.RemoteHost+" is already Bagher foreign server "+strconv.Itoa(l.ID))
				return
			}
		}

		if err := enableSSHFwd(cfg); err != nil {
			writeAPIError(w, r, "E-SSHFWD-04", err.Error())
			return
		}
		pubKey, _ := ensureSSHFwdKey(cfg.KeyPath)
		bundleStr, _ := MakeBagherBundle(cfg, pubKey)
		writeJSON(w, map[string]any{
			"status":      "ok",
			"message":     "Bagher Engine enabled successfully",
			"bundle":      bundleStr,
			"status_data": getSSHFwdStatusLocked(),
		})

	case "disable", "stop":
		if err := disableSSHFwd(); err != nil {
			writeAPIError(w, r, "E-SSHFWD-04", err.Error())
			return
		}
		writeJSON(w, map[string]any{"status": "ok", "message": "Bagher Engine disabled", "status_data": getSSHFwdStatusLocked()})

	case "clean", "purge", "reset":
		if err := cleanSSHFwd(); err != nil {
			writeAPIError(w, r, "E-SSHFWD-07", err.Error())
			return
		}
		dropLinkNames("bagher-")
		writeJSON(w, map[string]any{
			"status":      "ok",
			"message":     "Bagher tunnel cleaned and reset",
			"status_data": getSSHFwdStatusLocked(),
		})

	case "sync_peer", "sync-peer":
		pubKey, err := ensureSSHFwdKey(cfg.KeyPath)
		if err != nil {
			writeAPIError(w, r, "E-SSHFWD-03", err.Error())
			return
		}
		pcfg := loadPeerConfig()
		if pcfg.PeerSecret == "" {
			writeAPIError(w, r, "E-SSHFWD-05", "peer secret not configured")
			return
		}
		reqPayload := map[string]any{
			"pub_key":       pubKey,
			"mode":          cfg.Mode,
			"frp_bind_port": cfg.FRPBindPort,
			"ports":         cfg.Ports,
		}
		respBytes, err := sendToPeer("/api/peer/sshfwd-install-key", "POST", reqPayload)
		if err != nil {
			writeAPIError(w, r, "E-SSHFWD-06", fmt.Sprintf("failed pushing key to peer: %v", err))
			return
		}
		writeJSON(w, map[string]any{"status": "ok", "peer_response": string(respBytes)})

	case "add_link", "add-link":
		if !(HasFeature("bagher") || HasFeature("frp_ssh")) {
			writeAPIError(w, r, "E-LIC-01", "Bagher Engine requires a valid Premium license (Machine: "+getMachineHash()+")")
			return
		}
		name := ""
		if body.Name != nil {
			name = strings.TrimSpace(*body.Name)
		}
		if err := validLinkName(name); err != nil {
			writeAPIError(w, r, "E-SSHFWD-02", err.Error())
			return
		}
		l, err := addBagherLink(&cfg, BagherLink{
			RemoteHost: body.RemoteHost, RemoteUser: strings.TrimSpace(body.RemoteUser),
			RemoteSSHPort: body.SSHPort, Ports: parsePorts(body.Ports), UDP: body.UDP != nil && *body.UDP,
		})
		if err != nil {
			writeAPIError(w, r, "E-SSHFWD-02", err.Error())
			return
		}
		pub, err := ensureSSHFwdKey(cfg.KeyPath)
		if err != nil {
			writeAPIError(w, r, "E-SSHFWD-03", err.Error())
			return
		}
		if err := saveSSHFwdConfigLocked(cfg); err != nil {
			writeAPIError(w, r, "E-SSHFWD-04", err.Error())
			return
		}
		if name != "" {
			_ = setLinkName(fmt.Sprintf("bagher-%d", l.ID), name)
		}
		if cfg.Enabled {
			if err := installBagherLinkUnits(cfg, false); err != nil {
				writeAPIError(w, r, "E-SSHFWD-04", err.Error())
				return
			}
		}
		bundleStr, err := MakeBagherBundle(bagherLinkCfg(cfg, l), pub)
		if err != nil {
			writeAPIError(w, r, "E-SSHFWD-07", fmt.Sprintf("failed generating bundle: %v", err))
			return
		}
		writeJSON(w, map[string]any{"status": "ok", "id": l.ID, "bundle": bundleStr, "status_data": getSSHFwdStatusLocked()})

	case "remove_link", "remove-link":
		if !removeBagherLink(&cfg, body.ID) {
			writeAPIError(w, r, "E-SSHFWD-01", fmt.Sprintf("no Bagher foreign server %d", body.ID))
			return
		}
		_, _ = runCmd("systemctl", "disable", "--now", bagherLinkUnit(body.ID)+".service")
		_ = os.Remove(bagherLinkUnitPath(body.ID))
		_ = os.Remove(bagherCarrierStatusPath(body.ID))
		_ = setLinkName(fmt.Sprintf("bagher-%d", body.ID), "")
		_, _ = runCmd("systemctl", "daemon-reload")
		if err := saveSSHFwdConfigLocked(cfg); err != nil {
			writeAPIError(w, r, "E-SSHFWD-04", err.Error())
			return
		}
		writeJSON(w, map[string]any{"status": "ok", "status_data": getSSHFwdStatusLocked()})

	case "clear_dnat", "clear-dnat":
		_ = cleanDnatConflict(cfg.Ports)
		writeJSON(w, map[string]any{"status": "ok", "message": "dnat table cleared"})

	default:
		writeAPIError(w, r, "E-SSHFWD-01", "unknown action: want enable, disable, gen_key, sync_peer, clear_dnat, apply_bundle, get_bundle, add_link, remove_link, or clean")
	}
}

// handlePeerSSHFwdInstallKey is called on Kharej by Iran panel to register the restrict SSH key.
func handlePeerSSHFwdInstallKey(w http.ResponseWriter, r *http.Request) {
	var body struct {
		PubKey      string `json:"pub_key"`
		Mode        string `json:"mode"`
		FRPBindPort int    `json:"frp_bind_port"`
		Ports       []int  `json:"ports"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeAPIError(w, r, "E-SSHFWD-01", "invalid json")
		return
	}
	if strings.TrimSpace(body.PubKey) == "" {
		writeAPIError(w, r, "E-SSHFWD-01", "pub_key is required")
		return
	}
	if len(body.Ports) == 0 {
		body.Ports = []int{443, 8443, 1020, 1030, 1040}
	}
	if body.FRPBindPort <= 0 {
		body.FRPBindPort = 55400
	}
	if body.Mode == "" {
		body.Mode = "bagher"
	}

	if err := installRestrictedKey(body.PubKey, body.Mode, body.FRPBindPort, body.Ports); err != nil {
		code := "E-SSHFWD-06"
		if !strings.HasPrefix(err.Error(), "failed writing") {
			code = "E-SSHFWD-01"
		}
		writeAPIError(w, r, code, err.Error())
		return
	}

	LogSecurityAudit("bagher_key_installed", "peer", ClientIP(r), fmt.Sprintf("mode=%s ports=%v frp_port=%d", body.Mode, body.Ports, body.FRPBindPort))
	writeJSON(w, map[string]any{"status": "ok", "message": "bagher key authorized with restrictions", "ports": body.Ports})
}
