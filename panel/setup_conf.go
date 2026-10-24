package main

import (
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// backhaulCoreVersion returns the first line of `backhaul -v` for the
// installed core ("" when unknown); swappable for tests.
var backhaulCoreVersion = func() string {
	cands := []string{}
	for _, d := range engineBinDirs {
		cands = append(cands, filepath.Join(d, "backhaul"))
	}
	cands = append(cands, backhaulExtraBins...)
	for _, bin := range cands {
		if !executableFile(bin) {
			continue
		}
		out, err := runCmdTimeoutOut(5*time.Second, bin, "-v")
		if err != nil {
			continue
		}
		line, _, _ := strings.Cut(strings.TrimSpace(string(out)), "\n")
		return strings.TrimSpace(line)
	}
	return ""
}

// backhaulTransports mirrors BACKHAUL_TRANSPORTS in hashem.sh: what the
// installed core accepts. All carry TCP except udp, which carries UDP only.
var backhaulTransports = []string{"tcp", "tcpmux", "ws", "wss", "wsmux", "wssmux", "udp"}

// backhaulUnitDir is where hashem.sh writes the Backhaul units; tests point it elsewhere.
var backhaulUnitDir = "/etc/systemd/system"

// backhaulUDPUnit names the UDP companion of a Backhaul unit (hashem.sh
// backhaul_udp_unit): a udp-transport Backhaul on the same port number that
// carries the UDP of a TCP-only transport (tcpmux, ws, wss and the mux kinds).
func backhaulUDPUnit(unit string) string {
	return "backhaul-udp-" + strings.TrimPrefix(unit, "backhaul-")
}

// backhaulUDPPort is the control port of a Backhaul unit's UDP companion: the
// last field of its ExecCondition line (hashem backhaul-udp-conf MAIN OUT
// PORT). 0 when the unit has no companion.
func backhaulUDPPort(unit string) int {
	if unit == "" {
		return 0
	}
	data, err := os.ReadFile(filepath.Join(backhaulUnitDir, backhaulUDPUnit(unit)+".service"))
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if f := strings.Fields(strings.TrimPrefix(line, "ExecCondition=")); strings.HasPrefix(line, "ExecCondition=") && len(f) > 0 {
			if p, err := strconv.Atoi(f[len(f)-1]); err == nil && p > 0 && p <= 65535 {
				return p
			}
		}
	}
	return 0
}

// udpPortRe finds the companion's port in hashem.sh's setup output.
var udpPortRe = regexp.MustCompile(`UDP: backhaul-udp-\S+ .*control port (\d+)`)

// udpPortFromSteps is the UDP companion port a setup just made (0: none).
func udpPortFromSteps(steps []string) int {
	for _, s := range steps {
		if m := udpPortRe.FindStringSubmatch(s); m != nil {
			p, _ := strconv.Atoi(m[1])
			return p
		}
	}
	return 0
}

func backhaulTransportOK(t string) bool {
	for _, v := range backhaulTransports {
		if t == v {
			return true
		}
	}
	return false
}

// backhaulIsV2 mirrors backhaul_is_v2 in hashem.sh. hashem installs upstream
// v0.7.2 (flat [server]/[client]); a v2.x core an operator put in its place
// uses a sectioned TOML schema ([listener]/[dialer]/...) and rejects the flat one.
func backhaulIsV2() bool {
	v := strings.TrimPrefix(backhaulCoreVersion(), "v")
	return strings.HasPrefix(v, "2.")
}

// ensureBackhaulTLS creates the self-signed cert the wss transports need,
// like backhaul_ensure_tls in hashem.sh.
func ensureBackhaulTLS() {
	crt, key := filepath.Join(backhaulDir, "server.crt"), filepath.Join(backhaulDir, "server.key")
	if _, err := os.Stat(crt); err == nil {
		if _, err := os.Stat(key); err == nil {
			return
		}
	}
	_ = os.MkdirAll(backhaulDir, 0755)
	_, _ = runCmdTimeout(30*time.Second, "openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048", "-days", "3650",
		"-keyout", key, "-out", crt, "-subj", "/CN=backhaul")
	_ = os.Chmod(key, 0600)
}

func writeBackhaulServerConfig(path string, bindAddr string, transport string, token string, ports []string) error {
	if transport == "" {
		transport = "tcpmux"
	}
	if transport == "wss" || transport == "wssmux" {
		ensureBackhaulTLS()
	}
	if backhaulIsV2() {
		return writeBackhaulFile(path, backhaulServerConfigV2(bindAddr, transport, token, ports))
	}
	var sb strings.Builder
	sb.WriteString("[server]\n")
	sb.WriteString(fmt.Sprintf("bind_addr = %q\n", bindAddr))
	sb.WriteString(fmt.Sprintf("transport = %q\n", transport))
	if token != "" {
		sb.WriteString(fmt.Sprintf("token = %q\n", token))
	}
	sb.WriteString("keepalive_period = 75\n")
	sb.WriteString("nodelay = true\n")
	sb.WriteString("heartbeat = 40\n")
	sb.WriteString("channel_size = 2048\n")
	sb.WriteString("sniffer = false\n")
	sb.WriteString("web_port = 0\n")
	sb.WriteString("sniffer_log = \"\"\n")
	sb.WriteString("log_level = \"info\"\n")
	if transport == "wss" || transport == "wssmux" {
		sb.WriteString(fmt.Sprintf("tls_cert = %q\n", filepath.Join(backhaulDir, "server.crt")))
		sb.WriteString(fmt.Sprintf("tls_key = %q\n", filepath.Join(backhaulDir, "server.key")))
	}
	sb.WriteString("ports = [\n")
	for i, p := range ports {
		comma := ","
		if i == len(ports)-1 {
			comma = ""
		}
		sb.WriteString(fmt.Sprintf("  %q%s\n", strings.TrimSpace(p), comma))
	}
	sb.WriteString("]\n")
	return writeBackhaulFile(path, sb.String())
}

// backhaulServerConfigV2 is backhaul_write_server_conf_v2 from hashem.sh.
func backhaulServerConfigV2(bindAddr, transport, token string, ports []string) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "[listener]\nbind_addr = %q\n\n", bindAddr)
	fmt.Fprintf(&sb, "[transport]\ntype = %q\nnodelay = true\nkeepalive_period = 75\n\n", transport)
	fmt.Fprintf(&sb, "[security]\ntoken = %q\n\n", token)
	if strings.HasSuffix(transport, "mux") {
		sb.WriteString("[mux]\nmux_version = 1\n\n")
	}
	if transport == "wss" || transport == "wssmux" {
		fmt.Fprintf(&sb, "[tls]\ntls_cert = %q\ntls_key = %q\n\n", filepath.Join(backhaulDir, "server.crt"), filepath.Join(backhaulDir, "server.key"))
	}
	sb.WriteString("[logging]\nlog_level = \"info\"\n\n[ports]\nmapping = [\n")
	for _, p := range ports {
		if p = strings.TrimSpace(p); p != "" {
			fmt.Fprintf(&sb, "    %q,\n", p)
		}
	}
	sb.WriteString("]\n")
	return sb.String()
}

// backhaulClientConfigV2 is backhaul_write_client_conf_v2 from hashem.sh.
func backhaulClientConfigV2(remoteAddr, transport, token string) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "[dialer]\nremote_addr = %q\ndial_timeout = 10\nretry_interval = 3\n\n", remoteAddr)
	fmt.Fprintf(&sb, "[transport]\ntype = %q\nconnection_pool = %d\nnodelay = true\nkeepalive_period = 75\n\n", transport, backhaulPoolSize())
	fmt.Fprintf(&sb, "[security]\ntoken = %q\n\n", token)
	if strings.HasSuffix(transport, "mux") {
		sb.WriteString("[mux]\nmux_version = 1\n\n")
	}
	if transport == "wss" || transport == "wssmux" {
		host, _, err := net.SplitHostPort(remoteAddr)
		if err != nil {
			host, _, _ = strings.Cut(remoteAddr, ":")
		}
		fmt.Fprintf(&sb, "[tls]\nsni = %q\n\n", host)
	}
	sb.WriteString("[logging]\nlog_level = \"info\"\n")
	return sb.String()
}

func writeBackhaulFile(path, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return writeTokenFile(path, []byte(content))
}

func writeBackhaulClientConfig(path string, remoteAddr string, transport string, token string) error {
	if transport == "" {
		transport = "tcpmux"
	}
	if backhaulIsV2() {
		return writeBackhaulFile(path, backhaulClientConfigV2(remoteAddr, transport, token))
	}
	var sb strings.Builder
	sb.WriteString("[client]\n")
	sb.WriteString(fmt.Sprintf("remote_addr = %q\n", remoteAddr))
	sb.WriteString(fmt.Sprintf("transport = %q\n", transport))
	if token != "" {
		sb.WriteString(fmt.Sprintf("token = %q\n", token))
	}
	fmt.Fprintf(&sb, "connection_pool = %d\n", backhaulPoolSize())
	sb.WriteString("nodelay = true\n")
	sb.WriteString("retry_interval = 3\n")
	sb.WriteString("keepalive_period = 75\n")
	sb.WriteString("sniffer = false\n")
	sb.WriteString("web_port = 0\n")
	sb.WriteString("sniffer_log = \"\"\n")
	sb.WriteString("log_level = \"info\"\n")
	return writeBackhaulFile(path, sb.String())
}

func randomToken(n int) string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("token-%d", n)
	}
	for i := range b {
		b[i] = chars[int(b[i])%len(chars)]
	}
	return string(b)
}

func randomFrpPort() int {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return defaultFrpPortMin + (os.Getpid() % (defaultFrpPortMax - defaultFrpPortMin + 1))
	}
	val := int(b[0])<<8 | int(b[1])
	return defaultFrpPortMin + (val % (defaultFrpPortMax - defaultFrpPortMin + 1))
}
