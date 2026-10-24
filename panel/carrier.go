package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type carrierConfig struct {
	Mode          string   `json:"mode"`           // "auto", "direct", "fou:PORT", "wss:PORT"
	ActiveCarrier string   `json:"active_carrier"` // "direct", "fou:443", "fou:55555", "wss:8443"
	FOUPort1      int      `json:"fou_port1"`
	FOUPort2      int      `json:"fou_port2"`
	WSSPort       int      `json:"wss_port"`
	Candidates    []string `json:"candidates"`
	LastSwitch    string   `json:"last_switch"`
	SwitchCount   int      `json:"switch_count"`
}

type carrierStatusResponse struct {
	Mode          string           `json:"mode"`
	Active        string           `json:"active"`
	ActiveCarrier string           `json:"active_carrier"`
	FOUPort1      int              `json:"fou_port1"`
	FOUPort2      int              `json:"fou_port2"`
	WSSPort       int              `json:"wss_port"`
	FouPorts      []int            `json:"fou_ports"`
	Candidates    []string         `json:"candidates"`
	LastSwitch    string           `json:"last_switch"`
	SwitchCount   int              `json:"switch_count"`
	PingStatus    string           `json:"ping_status"`
	PingRTT       string           `json:"ping_rtt"`
	StatusText    string           `json:"status_text"`
	GREExists     bool             `json:"gre_exists"`
	WSSSNI        string           `json:"wss_sni"`
	WSSRemote     string           `json:"wss_remote"` // the other server's WSS host: IPv4, IPv6 or a name
	WSS           wssCarrierStatus `json:"wss"`
}

type carrierPostRequest struct {
	Action    string `json:"action"` // "set_mode", "set-mode", "set_active", "apply", "cycle_next", "cycle", "set-ports", "set_wss"
	Mode      string `json:"mode,omitempty"`
	Target    string `json:"target,omitempty"`
	FouPorts  []int  `json:"fou_ports,omitempty"`
	FOUPort1  int    `json:"fou_port1,omitempty"`
	FOUPort2  int    `json:"fou_port2,omitempty"`
	WSSPort   int    `json:"wss_port,omitempty"`
	WSSRemote string `json:"wss_remote,omitempty"`
	Local6    string `json:"local6,omitempty"`  // switch to 4in6: this server's IPv6 (default: detected)
	Remote6   string `json:"remote6,omitempty"` // switch to 4in6: the other server's IPv6 (default: asked over the Peer Link)
	// WSSSNI: nil leaves the SNI as it is, "" clears it.
	WSSSNI *string `json:"wss_sni,omitempty"`
}

// wssRemoteHost is the host of a WSS remote address ("host:port", "[v6]:port"
// or a bare host).
func wssRemoteHost(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return strings.Trim(addr, "[]")
}

func carrierConfigPath() string {
	return filepath.Join(configDir, "carrier.json")
}

func defaultCarrierConfig() carrierConfig {
	return carrierConfig{
		Mode:          "direct",
		ActiveCarrier: "direct",
		FOUPort1:      443,
		FOUPort2:      55555,
		WSSPort:       8443,
		Candidates:    []string{"direct", "wss:8443"},
		LastSwitch:    "",
		SwitchCount:   0,
	}
}

func loadCarrierConfig() carrierConfig {
	def := defaultCarrierConfig()
	data, err := os.ReadFile(carrierConfigPath())
	if err != nil {
		return def
	}
	var c carrierConfig
	if err := json.Unmarshal(data, &c); err != nil {
		return def
	}
	// Migration: "auto" (failover) mode is no longer supported.
	// Existing servers that had mode=auto are silently migrated to "direct"
	// so they don't lose connectivity on update.
	needsSave := false
	if c.Mode == "" || c.Mode == "auto" {
		c.Mode = "direct"
		needsSave = true
	}
	if c.ActiveCarrier == "" || c.ActiveCarrier == "auto" {
		c.ActiveCarrier = "direct"
		needsSave = true
	}
	if c.FOUPort1 <= 0 {
		c.FOUPort1 = 443
	}
	if c.FOUPort2 <= 0 {
		c.FOUPort2 = 55555
	}
	if c.WSSPort <= 0 {
		c.WSSPort = 8443
	}
	// Remove any FOU candidates left from old configs.
	clean := []string{}
	hadFOU := false
	for _, cand := range c.Candidates {
		if strings.HasPrefix(cand, "fou:") {
			hadFOU = true
			continue
		}
		clean = append(clean, cand)
	}
	if hadFOU {
		needsSave = true
	}
	if len(clean) == 0 {
		clean = []string{"direct", "wss:" + strconv.Itoa(c.WSSPort)}
	}
	c.Candidates = clean
	// Persist migration exactly once (only when we actually changed something).
	if needsSave {
		_ = saveCarrierConfig(c)
	}
	return c
}

func saveCarrierConfig(cfg carrierConfig) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return err
	}
	tmp := carrierConfigPath() + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, carrierConfigPath())
}

func getPeerGRE() string {
	if p := findPeer(1); p != nil && p.PeerGre != "" {
		return p.PeerGre
	}
	data, err := os.ReadFile(filepath.Join(configDir, "setup.json"))
	if err == nil {
		var s struct {
			PeerGre string `json:"peer_gre"`
		}
		if json.Unmarshal(data, &s) == nil && s.PeerGre != "" {
			return s.PeerGre
		}
	}
	return "10.10.10.1"
}

func getCarrierPingStatus() (string, string) {
	peer := getPeerGRE()
	if peer == "" {
		return "no_peer", ""
	}
	out, err := exec.Command("ping", "-c", "1", "-W", "2", peer).CombinedOutput()
	if err != nil {
		return "fail", ""
	}
	str := string(out)
	if strings.Contains(str, "1 received") || strings.Contains(str, "1 packets received") {
		if idx := strings.Index(str, "time="); idx != -1 {
			sub := str[idx+5:]
			if end := strings.Index(sub, " "); end != -1 {
				return "ok", sub[:end] + " ms"
			}
		}
		return "ok", "< 1 ms"
	}
	return "fail", ""
}

func handleCarrierGet(w http.ResponseWriter, r *http.Request) {
	cfg := loadCarrierConfig()
	// Without a GRE interface there is nothing to ping: say so instead of
	// reporting packet loss to the 10.10.10.1 fallback.
	greExists := fileExists(filepath.Join(sysClassNet, "gre-tunnel"))
	st, rtt, statusText := "no_tunnel", "", "No tunnel"
	if greExists {
		st, rtt = getCarrierPingStatus()
		statusText = "Peer replies"
		if st == "fail" {
			statusText = "Peer not replying"
		}
	}
	wc := loadWSSConfig()
	resp := carrierStatusResponse{
		Mode:          cfg.Mode,
		Active:        cfg.ActiveCarrier,
		ActiveCarrier: cfg.ActiveCarrier,
		FOUPort1:      cfg.FOUPort1,
		FOUPort2:      cfg.FOUPort2,
		WSSPort:       cfg.WSSPort,
		FouPorts:      []int{cfg.FOUPort1, cfg.FOUPort2},
		Candidates:    cfg.Candidates,
		LastSwitch:    cfg.LastSwitch,
		SwitchCount:   cfg.SwitchCount,
		PingStatus:    st,
		PingRTT:       rtt,
		StatusText:    statusText,
		GREExists:     greExists,
		WSSSNI:        wc.SNI,
		WSSRemote:     wssRemoteHost(wc.RemoteAddr),
		WSS:           getWSSStatus(),
	}
	writeJSON(w, resp)
}

func handleCarrierPost(w http.ResponseWriter, r *http.Request) {
	var req carrierPostRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeAPIError(w, r, "E-ACTION-01", "invalid json")
		return
	}

	cfg := loadCarrierConfig()
	act := strings.ToLower(strings.TrimSpace(req.Action))

	switch act {
	case "set_mode", "set-mode":
		m := strings.TrimSpace(req.Mode)
		if m != "direct" && !strings.HasPrefix(m, "wss") {
			writeAPIError(w, r, "E-ACTION-01", "invalid mode: want direct or wss:PORT")
			return
		}
		cfg.Mode = m
		cfg.ActiveCarrier = m
		cfg.LastSwitch = time.Now().Format("2006-01-02 15:04:05")
		cfg.SwitchCount++
		if strings.HasPrefix(m, "wss") {
			wssCfg := wssConfigForCarrier(m)
			_ = saveWSSConfig(wssCfg)
			_ = startWSSCarrier(wssCfg)
		} else {
			_ = stopWSSCarrier()
		}
		_, _ = runHashemCarrierCmd("set", m)
		_ = saveCarrierConfig(cfg)
		writeJSON(w, map[string]any{"status": "ok", "mode": cfg.Mode, "active": cfg.ActiveCarrier, "active_carrier": cfg.ActiveCarrier})

	case "switch":
		// both servers over the Peer Link, checked, undone when the tunnel
		// does not answer
		t := strings.TrimSpace(req.Target)
		detail, err := switchCarrier(t, carrier6Opts{Local6: strings.TrimSpace(req.Local6), Remote6: strings.TrimSpace(req.Remote6)})
		if err != nil {
			writeAPIError(w, r, "E-CARRIER-01", err.Error())
			return
		}
		cfg = loadCarrierConfig()
		writeJSON(w, map[string]any{"status": "ok", "detail": detail, "active": cfg.ActiveCarrier, "active_carrier": cfg.ActiveCarrier})

	case "set_active", "set-active", "apply", "set":
		t := strings.TrimSpace(req.Target)
		if t == "" && req.Mode != "" {
			t = strings.TrimSpace(req.Mode)
		}
		if out, err := applyCarrierMode(t); err != nil && !strings.Contains(err.Error(), "script not found") {
			writeAPIError(w, r, "E-CARRIER-01", fmt.Sprintf("%v %s", err, strings.TrimSpace(out)))
			return
		}
		cfg = loadCarrierConfig()
		writeJSON(w, map[string]any{"status": "ok", "active": cfg.ActiveCarrier, "active_carrier": cfg.ActiveCarrier, "detail": "Applied carrier " + cfg.ActiveCarrier})

	case "cycle_next", "cycle", "next":
		out, err := runHashemCarrierCmd("cycle")
		if err == nil && len(out) > 0 {
			cfg = loadCarrierConfig()
		} else {
			cands := cfg.Candidates
			if len(cands) == 0 {
				cands = []string{"direct", "wss:8443"}
			}
			idx := 0
			for i, c := range cands {
				if c == cfg.ActiveCarrier {
					idx = (i + 1) % len(cands)
					break
				}
			}
			cfg.ActiveCarrier = cands[idx]
			cfg.LastSwitch = time.Now().Format("2006-01-02 15:04:05")
			cfg.SwitchCount++
			if strings.HasPrefix(cfg.ActiveCarrier, "wss") {
				wssCfg := loadWSSConfig()
				wssCfg.Enabled = true
				_ = saveWSSConfig(wssCfg)
				_ = startWSSCarrier(wssCfg)
			} else {
				_ = stopWSSCarrier()
			}
			_ = saveCarrierConfig(cfg)
			_, _ = runHashemCarrierCmd("set", cfg.ActiveCarrier)
		}
		writeJSON(w, map[string]any{"status": "ok", "active": cfg.ActiveCarrier, "active_carrier": cfg.ActiveCarrier})

	case "set_ports", "set-ports":
		p1, p2 := req.FOUPort1, req.FOUPort2
		if len(req.FouPorts) >= 2 {
			p1, p2 = req.FouPorts[0], req.FouPorts[1]
		} else if len(req.FouPorts) == 1 {
			p1 = req.FouPorts[0]
			p2 = 55555
		}
		if p1 <= 0 || p1 > 65535 || p2 <= 0 || p2 > 65535 {
			writeAPIError(w, r, "E-ACTION-01", "invalid ports: must be between 1 and 65535")
			return
		}
		cfg.FOUPort1 = p1
		cfg.FOUPort2 = p2
		cfg.Candidates = []string{"direct", "wss:" + strconv.Itoa(cfg.WSSPort)}
		_ = saveCarrierConfig(cfg)
		_, _ = runHashemCarrierCmd("set-ports", strconv.Itoa(p1), strconv.Itoa(p2))
		writeJSON(w, map[string]any{"status": "ok", "fou_port1": p1, "fou_port2": p2, "fou_ports": []int{p1, p2}})

	case "set_wss", "set-wss":
		if req.WSSPort < 0 || req.WSSPort > 65535 {
			writeAPIError(w, r, "E-ACTION-01", "invalid port: must be between 1 and 65535")
			return
		}
		wssCfg := loadWSSConfig()
		if req.WSSPort > 0 {
			ps := strconv.Itoa(req.WSSPort)
			wssCfg.ListenPort = req.WSSPort
			if host, _, err := net.SplitHostPort(wssCfg.RemoteAddr); err == nil && host != "" {
				wssCfg.RemoteAddr = net.JoinHostPort(host, ps)
			}
			cfg.WSSPort = req.WSSPort
			// Keep the carrier names on the new port, or Cycle and the
			// active carrier still point at the old one.
			cfg.Candidates = []string{"direct", "wss:" + ps}
			if strings.HasPrefix(cfg.ActiveCarrier, "wss") {
				cfg.ActiveCarrier = "wss:" + ps
			}
			if strings.HasPrefix(cfg.Mode, "wss") {
				cfg.Mode = "wss:" + ps
			}
			_ = saveCarrierConfig(cfg)
		}
		if req.WSSRemote != "" {
			h := wssRemoteHost(strings.TrimSpace(req.WSSRemote))
			if !validBagherHost(h) {
				writeAPIError(w, r, "E-ACTION-01", "invalid address of the other server: an IPv4, an IPv6 or a host name")
				return
			}
			wssCfg.RemoteAddr = net.JoinHostPort(h, strconv.Itoa(wssCfg.ListenPort))
		}
		if req.WSSSNI != nil {
			wssCfg.SNI = strings.TrimSpace(*req.WSSSNI)
		}
		_ = saveWSSConfig(wssCfg)
		if strings.HasPrefix(cfg.ActiveCarrier, "wss") {
			_ = startWSSCarrier(wssCfg)
		}
		writeJSON(w, map[string]any{"status": "ok", "wss_port": cfg.WSSPort, "wss_sni": wssCfg.SNI, "active": cfg.ActiveCarrier})

	default:
		writeAPIError(w, r, "E-ACTION-01", "unknown action: want set_mode, set_active, cycle_next, set_ports, or set_wss")
	}
}

func runHashemCarrierCmd(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	script, err := greScriptPath()
	if err == nil {
		cmdArgs := append([]string{script, "carrier"}, args...)
		cmd := exec.CommandContext(ctx, "bash", cmdArgs...)
		cmd.Env = append(os.Environ(), "GRE_SKIP_PANEL=1", "TERM=dumb", "GRE_PANEL_DIR="+configDir)
		return cmd.CombinedOutput()
	}
	if fileExists("/usr/local/bin/hashem") {
		cmdArgs := append([]string{"carrier"}, args...)
		cmd := exec.CommandContext(ctx, "/usr/local/bin/hashem", cmdArgs...)
		cmd.Env = append(os.Environ(), "GRE_SKIP_PANEL=1", "TERM=dumb", "GRE_PANEL_DIR="+configDir)
		return cmd.CombinedOutput()
	}
	return nil, fmt.Errorf("hashem script not found")
}

func updateFrpcTransport(proto string) error {
	frpcPath := filepath.Join(frpDir, "frpc.toml")
	data, err := os.ReadFile(frpcPath)
	if err != nil {
		return err
	}
	lines := strings.Split(string(data), "\n")
	// frps listens for QUIC on bindPort+1 (bindPort-1 at 65535), so the
	// client's serverPort moves with the protocol.
	curProto, portLine, curPort := "tcp", -1, 0
	for i, line := range lines {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			switch strings.TrimSpace(k) {
			case "transport.protocol":
				curProto = strings.Trim(strings.TrimSpace(v), `"'`)
			case "serverPort":
				if portLine < 0 {
					portLine = i
					curPort, _ = strconv.Atoi(strings.TrimSpace(v))
				}
			}
		}
	}
	if portLine >= 0 && curPort > 0 {
		bind := curPort
		if curProto == "quic" {
			bind = curPort - 1
		}
		want := bind
		if proto == "quic" {
			want = bind + 1
			if want > 65535 {
				want = bind - 1
			}
		}
		lines[portLine] = fmt.Sprintf("serverPort = %d", want)
	}
	found := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "transport.protocol") {
			lines[i] = fmt.Sprintf("transport.protocol = %q", proto)
			found = true
			break
		}
	}
	if !found {
		var newLines []string
		inserted := false
		for _, l := range lines {
			if strings.HasPrefix(strings.TrimSpace(l), "[[proxies]]") && !inserted {
				newLines = append(newLines, fmt.Sprintf("transport.protocol = %q", proto), "")
				inserted = true
			}
			newLines = append(newLines, l)
		}
		if !inserted {
			newLines = append(newLines, fmt.Sprintf("transport.protocol = %q", proto))
		}
		lines = newLines
	}
	if err := writeTokenFile(frpcPath, []byte(strings.Join(lines, "\n"))); err != nil {
		return err
	}
	if _, err := exec.LookPath("systemctl"); err == nil {
		_ = exec.Command("systemctl", "restart", "frpc").Run()
	}
	return nil
}

// wssConfigForCarrier enables the WSS carrier and applies the port from a
// "wss:PORT" carrier, which used to be ignored (the old port stayed in use).
func wssConfigForCarrier(t string) wssConfig {
	c := loadWSSConfig()
	c.Enabled = true
	if ps, ok := strings.CutPrefix(strings.TrimSpace(t), "wss:"); ok {
		if p, err := strconv.Atoi(ps); err == nil && p >= 1 && p <= 65535 {
			c.ListenPort = p
			if host, _, err := net.SplitHostPort(c.RemoteAddr); err == nil && host != "" {
				c.RemoteAddr = net.JoinHostPort(host, ps)
			}
		}
	}
	return c
}

// ensureFrpsUDPListeners adds kcpBindPort/quicBindPort to frps configs that
// lack them (written by older versions) and restarts those frps units, so a
// switch to frp:kcp or frp:quic has something to connect to.
func ensureFrpsUDPListeners() error {
	files, _ := filepath.Glob(filepath.Join(frpDir, "frps*.toml"))
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		content := string(data)
		if strings.Contains(content, "kcpBindPort") && strings.Contains(content, "quicBindPort") {
			continue
		}
		bind := 0
		lines := strings.Split(content, "\n")
		at := -1
		for i, l := range lines {
			if k, v, ok := strings.Cut(strings.TrimSpace(l), "="); ok && strings.TrimSpace(k) == "bindPort" {
				bind, _ = strconv.Atoi(strings.TrimSpace(v))
				at = i
				break
			}
		}
		if bind <= 0 || at < 0 {
			continue
		}
		quic := bind + 1
		if quic > 65535 {
			quic = bind - 1
		}
		var add []string
		if !strings.Contains(content, "kcpBindPort") {
			add = append(add, fmt.Sprintf("kcpBindPort = %d", bind))
		}
		if !strings.Contains(content, "quicBindPort") {
			add = append(add, fmt.Sprintf("quicBindPort = %d", quic))
		}
		lines = append(lines[:at+1], append(add, lines[at+1:]...)...)
		if err := writeTokenFile(f, []byte(strings.Join(lines, "\n"))); err != nil {
			return fmt.Errorf("update %s: %w", filepath.Base(f), err)
		}
		svc := strings.TrimSuffix(filepath.Base(f), ".toml") // frps or frps-N
		if err := runSystemctl("restart", svc); err != nil {
			return fmt.Errorf("restart %s: %w", svc, err)
		}
	}
	return nil
}

// carrierApplicable reports whether t is a carrier applyCarrierMode can switch
// to live. Backhaul and Bagher are engines, not GRE carriers: hashem.sh
// carrier_apply has no branch for them and used to rebuild the GRE interface
// and record a meaningless carrier.
func carrierApplicable(t string) error {
	t = strings.TrimSpace(t)
	switch {
	case t == "direct", strings.HasPrefix(t, "fou:"), t == "wss", strings.HasPrefix(t, "wss:"), isCarrier6(t):
		return nil
	case strings.HasPrefix(t, "frp:"):
		switch strings.TrimPrefix(t, "frp:") {
		case "tcp", "kcp", "quic", "ws", "websocket", "wss":
			return nil
		}
		return fmt.Errorf("unknown FRP transport in %q", t)
	case strings.HasPrefix(t, "backhaul:"), strings.HasPrefix(t, "bagher:"):
		return fmt.Errorf("%s is a tunnel engine, not a carrier: use Switch Engine (Backhaul) or the Bagher page", t)
	}
	return fmt.Errorf("unknown carrier %q", t)
}

func applyCarrierMode(t string) (string, error) { return applyCarrierModeOpts(t, carrier6Opts{}) }

func applyCarrierModeOpts(t string, o carrier6Opts) (string, error) {
	cfg := loadCarrierConfig()
	t = strings.TrimSpace(t)
	if strings.HasPrefix(t, "backhaul:") || strings.HasPrefix(t, "bagher:") {
		return "", carrierApplicable(t)
	}
	if t != "direct" && !strings.HasPrefix(t, "fou:") && !strings.HasPrefix(t, "wss") && !strings.HasPrefix(t, "frp:") && !isCarrier6(t) {
		t = cfg.ActiveCarrier
	}
	cfg.ActiveCarrier = t
	cfg.LastSwitch = time.Now().Format("2006-01-02 15:04:05")
	cfg.SwitchCount++
	if strings.HasPrefix(t, "wss") {
		wssCfg := wssConfigForCarrier(t)
		_ = saveWSSConfig(wssCfg)
		_ = startWSSCarrier(wssCfg)
	} else {
		_ = stopWSSCarrier()
	}
	_ = saveCarrierConfig(cfg)
	if strings.HasPrefix(t, "frp:") {
		proto := strings.TrimPrefix(t, "frp:")
		if proto == "ws" {
			proto = "websocket"
		}
		// Iran (frps): make sure the UDP listeners exist. Foreign (frpc):
		// switch the client protocol. A server has one or the other.
		if proto == "kcp" || proto == "quic" {
			if err := ensureFrpsUDPListeners(); err != nil {
				return "", err
			}
		}
		if err := updateFrpcTransport(proto); err != nil && !os.IsNotExist(err) {
			return "", fmt.Errorf("update frpc transport: %w", err)
		}
		return "switched to " + t, nil
	}
	out, err := runHashemCarrierCmd(append([]string{"set", t}, o.args()...)...)
	return string(out), err
}
