package main

// Tunnel inspection + actions: read GRE/FRP state via ip/systemd (never
// writes), restart/ping/remove via systemctl/ping or the shared hashem.sh
// installer (single source of truth, same as the CLI/menu path).

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// status of GRE + FRP on this machine.
func handleStatus(w http.ResponseWriter, r *http.Request) {
	st := localStatus()
	peers := livePeers()
	resp := map[string]any{"local": st, "peers": peers, "peer_count": len(peers)}
	if c, err := r.Cookie("gre_session"); err == nil && c.Value != "" {
		resp["csrf_token"] = GenerateCSRFToken(c.Value)
	}
	writeJSON(w, resp)
}

func splitLogLines(text string) []string {
	var res []string
	for _, l := range strings.Split(strings.TrimSpace(text), "\n") {
		trimmed := strings.TrimSpace(l)
		if trimmed != "" {
			res = append(res, trimmed)
		}
	}
	return res
}

func handleLogs(w http.ResponseWriter, r *http.Request) {
	svc := r.URL.Query().Get("svc")
	n := r.URL.Query().Get("n")
	lines := 100
	if v, err := strconv.Atoi(n); err == nil && v >= 5 && v <= 1000 {
		lines = v
	}

	// Stream / All activity mode for right sidebar
	if svc == "" || svc == "stream" || svc == "all" {
		units := []string{"frps", "frpc", "gre-panel", "hashem-watchdog"}
		var args []string
		for _, u := range units {
			args = append(args, "-u", u)
		}
		args = append(args, "-n", strconv.Itoa(lines), "--no-pager")
		if _, err := exec.LookPath("journalctl"); err == nil {
			out, err := exec.Command("journalctl", args...).CombinedOutput()
			if err == nil && len(bytes.TrimSpace(out)) > 0 {
				raw := string(out)
				writeJSON(w, map[string]any{"logs": raw, "lines": splitLogLines(raw), "svc": "stream", "findings": summarizeLogs(raw)})
				return
			}
		}
		// Fallback to whichever default service exists
		svc = "frps"
		if _, err := os.Stat(filepath.Join(frpDir, "frpc.toml")); err == nil {
			svc = "frpc"
		}
	}

	// allowed units: legacy frps/frpc, per-peer frps-N, GRE units, panel itself
	allowed := map[string]bool{"frps": true, "frpc": true, "gre-panel": true,
		"gre-tunnel": true, "gre-tunnel.service": true, "hashem-watchdog": true,
		"backhaul": true, "backhaul-server": true, "backhaul-client": true}
	if !allowed[svc] {
		if strings.HasPrefix(svc, "frps-") || strings.HasPrefix(svc, "gre-t") || strings.HasPrefix(svc, "backhaul-") {
			allowed[svc] = true
		}
	}
	if !allowed[svc] {
		// unknown? fall back to whichever FRP side exists
		svc = "frps"
		if _, err := os.Stat(filepath.Join(frpDir, "frpc.toml")); err == nil {
			svc = "frpc"
		}
	}
	unit := svc
	if _, err := exec.LookPath("journalctl"); err == nil {
		out, err := exec.Command("journalctl", "-u", unit, "-n", strconv.Itoa(lines), "--no-pager").CombinedOutput()
		if err == nil {
			raw := string(out)
			writeJSON(w, map[string]any{"logs": raw, "lines": splitLogLines(raw), "svc": svc, "findings": summarizeLogs(raw)})
			return
		}
	}
	// fallback: log files
	for _, q := range []string{"/var/log/" + svc + ".log", "/root/" + svc + ".log"} {
		if data, err := os.ReadFile(q); err == nil {
			raw := string(data)
			writeJSON(w, map[string]any{"logs": raw, "lines": splitLogLines(raw), "svc": svc, "findings": summarizeLogs(raw)})
			return
		}
	}
	noLog := "(no logs available — is " + svc + " installed?)"
	writeJSON(w, map[string]any{"logs": noLog, "lines": []string{noLog}, "svc": svc, "findings": []logFinding{}})
}

// actions: restart frps/frpc/gre, ping peer, optimize/restore network tuning, switch engine.
func handleAction(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Action    string `json:"action"`
		PeerID    int    `json:"peer_id"`
		Engine    string `json:"engine"`
		Transport string `json:"transport"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeAPIError(w, r, "E-ACTION-02", "")
		return
	}
	switch body.Action {
	case "restart-frps", "restart-frpc", "restart-gre", "ping", "remove-tunnel":
		out, err := runAction(body.Action, body.PeerID)
		if err != nil {
			writeAPIError(w, r, "E-ACTION-03", err.Error())
			return
		}
		writeJSON(w, map[string]string{"status": "ok", "output": out})
	case "optimize", "restore", "tune-status":
		// network tuning via the installer (single source of truth).
		out, err := tuneViaInstaller(body.Action)
		if err != nil {
			writeAPIError(w, r, "E-ACTION-03", out+": "+err.Error())
			return
		}
		writeJSON(w, map[string]string{"status": "ok", "output": out})
	case "switch-engine", "switch_engine":
		out, err := switchTunnelEngine(body.Engine, body.Transport)
		if err != nil {
			writeAPIError(w, r, "E-ACTION-03", err.Error())
			return
		}
		writeJSON(w, map[string]string{"status": "ok", "output": out})
	default:
		writeAPIError(w, r, "E-ACTION-01", "")
	}
}

func runAction(action string, peerID int) (string, error) {
	switch action {
	case "restart-frps":
		if localStatus().FrpSvc == "frpc" {
			out, err := exec.Command("systemctl", "restart", "frpc").CombinedOutput()
			return string(out), err
		}
		svc := peerFrpsSvc(peerID)
		out, err := exec.Command("systemctl", "restart", svc).CombinedOutput()
		return string(out), err
	case "restart-frpc":
		out, err := exec.Command("systemctl", "restart", "frpc").CombinedOutput()
		return string(out), err
	case "restart-gre":
		svc := peerGreSvc(peerID)
		out, err := exec.Command("systemctl", "restart", svc).CombinedOutput()
		return string(out), err
	case "ping":
		target := peerPingTarget(peerID)
		if target == "" {
			return "", fmt.Errorf("no GRE peer known")
		}
		out, err := exec.Command("ping", "-c", "3", "-W", "2", target).CombinedOutput()
		return string(out), err
	case "remove-tunnel":
		if peerID > 0 {
			return removePeerViaInstaller(peerID)
		}
		// mirror of hashem.sh remove_tunnel_force(): GRE + FRP gone, panel untouched.
		// Implemented via the installer itself (single source of truth) so the
		// shell-out path and the menu path can never drift apart.
		out, err := removeViaInstaller()
		if err != nil {
			return "", err
		}
		return out, nil
	}
	return "", fmt.Errorf("unknown action")
}

// tuneViaInstaller runs `hashem.sh optimize|restore|tune-status` and returns its
// output as the action result (single source of truth, same as menu/CLI).
func tuneViaInstaller(action string) (string, error) {
	script, err := greScriptPath()
	if err != nil {
		return "", err
	}
	arg := map[string]string{
		"optimize": "optimize", "restore": "restore", "tune-status": "tune-status",
	}[action]
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", script, arg)
	cmd.Env = append(os.Environ(), "GRE_SKIP_PANEL=1", "TERM=dumb", "GRE_PANEL_DIR="+configDir)
	out, runErr := cmd.CombinedOutput()
	o := strings.TrimSpace(string(out))
	if o == "" {
		o = action + " done"
	}
	if runErr != nil {
		return o, fmt.Errorf("tune command failed: %w", runErr)
	}
	return o, nil
}

// removeViaInstaller runs `hashem.sh remove-tunnel --force` and returns its
// output as the action result. GRE_SKIP_PANEL is irrelevant here (removal
// never touches the panel), but kept for symmetry with runInstaller.
func removeViaInstaller() (string, error) {
	script, err := greScriptPath()
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", script, "remove-tunnel", "--force")
	cmd.Env = append(os.Environ(), "GRE_SKIP_PANEL=1", "TERM=dumb", "GRE_PANEL_DIR="+configDir)
	out, runErr := cmd.CombinedOutput()
	o := strings.TrimSpace(string(out))
	if o == "" {
		o = "tunnel removed — panel still running"
	}
	if runErr != nil {
		return o, fmt.Errorf("remove-tunnel failed: %w", runErr)
	}
	return o, nil
}

// ---- multi-peer: registry + per-tunnel inspection ----
// peers.json (written by hashem.sh add-peer) is the source of truth for how
// many foreign servers hang off this Iran. Legacy single installs without
// a registry fall back to the old single-tunnel view.

type peerRecord struct {
	ID             int      `json:"id"`
	Name           string   `json:"name"`
	LocalPub       string   `json:"local_pub"`
	RemotePub      string   `json:"remote_pub"`
	FrpPort        int      `json:"frp_port"`
	LocalGre       string   `json:"local_gre"`
	PeerGre        string   `json:"peer_gre"`
	Ports          []int    `json:"ports"`
	RawPorts       []string `json:"raw_ports,omitempty"`
	Token          string   `json:"token,omitempty"`
	GreIf          string   `json:"gre_if"`
	FrpsSvc        string   `json:"frps_svc"`
	Carrier        string   `json:"carrier,omitempty"`
	Engine         string   `json:"engine,omitempty"`    // "frp" | "backhaul" | "gre-backhaul"
	Transport      string   `json:"transport,omitempty"` // "tcpmux" | "wssmux" | "tcp" | etc.
	NoGre          bool     `json:"no_gre,omitempty"`
	Legacy         bool     `json:"legacy,omitempty"`
	ProxyProtocol  string   `json:"proxy_protocol,omitempty"`  // "off" | "v2" | "v1"
	FRPTransport   string   `json:"frp_transport,omitempty"`   // "tcp" | "kcp" | "quic" | "websocket" | "wss"
	UseEncryption  bool     `json:"use_encryption,omitempty"`  // transport.useEncryption
	UseCompression bool     `json:"use_compression,omitempty"` // transport.useCompression
}

type peerLive struct {
	peerRecord
	GreUp    bool   `json:"gre_up"`
	GreInner string `json:"gre_inner"`
	FrpUp    bool   `json:"frp_up"`
	Linked   bool   `json:"linked"`   // an FRP/Backhaul client holds an established session to this peer's control port
	FrpOnly  bool   `json:"frp_only"` // linked while the GRE inner address does not answer ping
	PingOK   bool   `json:"ping_ok"`
	PingMs   string `json:"ping_ms"`
	// LatencyMs/LatencyKind: ICMP to the GRE inner address when it answers,
	// else the kernel TCP RTT of the live control session ("icmp" | "tcp" | "").
	LatencyMs   float64 `json:"latency_ms"`
	LatencyKind string  `json:"latency_kind"`
	Rx          *uint64 `json:"rx"`
	Tx          *uint64 `json:"tx"`
}

func peersFile() string { return configDir + "/peers.json" }

func loadPeers() []peerRecord {
	data, err := os.ReadFile(peersFile())
	if err != nil {
		return nil
	}
	var v struct {
		Peers []peerRecord `json:"peers"`
	}
	if json.Unmarshal(data, &v) != nil {
		return nil
	}
	return v.Peers
}

func findPeer(id int) *peerRecord {
	for _, p := range loadPeers() {
		if p.ID == id {
			c := p
			return &c
		}
	}
	return nil
}

// unit names for actions; peerID 0 = legacy default.
func peerFrpsSvc(peerID int) string {
	if peerID > 0 {
		if p := findPeer(peerID); p != nil && p.FrpsSvc != "" {
			return p.FrpsSvc
		}
		if peerID > 1 {
			return fmt.Sprintf("frps-%d", peerID)
		}
	}
	return "frps"
}

func peerGreSvc(peerID int) string {
	if peerID > 0 {
		if p := findPeer(peerID); p != nil && p.GreIf != "" {
			return p.GreIf + ".service"
		}
		if peerID > 1 {
			return fmt.Sprintf("gre-t%d.service", peerID)
		}
	}
	return "gre-tunnel.service"
}

func peerPingTarget(peerID int) string {
	if peerID > 0 {
		if p := findPeer(peerID); p != nil && p.PeerGre != "" {
			return p.PeerGre
		}
	}
	return localStatus().GrePeer
}

func ifaceTraffic(ifname string) (rx, tx *uint64) {
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return nil, nil
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, ifname+":") {
			continue
		}
		f := strings.Fields(strings.TrimPrefix(line, ifname+":"))
		if len(f) < 9 {
			return nil, nil
		}
		var r, t uint64
		if _, err := fmt.Sscanf(f[0], "%d", &r); err != nil {
			return nil, nil
		}
		if _, err := fmt.Sscanf(f[8], "%d", &t); err != nil {
			return nil, nil
		}
		return &r, &t
	}
	return nil, nil
}

func ifaceInner(ifname string) string {
	out, err := exec.Command("ip", "-4", "addr", "show", "dev", ifname).CombinedOutput()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "inet ") {
			return strings.Fields(line)[1]
		}
	}
	return ""
}

func svcActive(svc string) bool {
	out, err := exec.Command("systemctl", "is-active", svc).CombinedOutput()
	return err == nil && strings.TrimSpace(string(out)) == "active"
}

// livePeers inspects every registered peer: GRE up, frps up, ping, counters.
func livePeers() []peerLive {
	recs := loadPeers()
	if len(recs) == 0 {
		return nil
	}
	out := make([]peerLive, 0, len(recs))
	for _, p := range recs {
		l := peerLive{peerRecord: p}
		if p.NoGre {
			l.GreInner = "standalone"
			l.GreUp = true
		} else if _, err := exec.Command("ip", "tunnel", "show").CombinedOutput(); err == nil {
			// presence check via interface address (works without parsing tun show)
			l.GreInner = ifaceInner(p.GreIf)
			l.GreUp = l.GreInner != ""
		}
		l.FrpUp = svcActive(p.FrpsSvc)
		var tcpRTT float64 = -1
		if l.FrpUp {
			l.Linked, tcpRTT = controlSession(p.FrpPort, p.RemotePub, p.PeerGre)
		}
		pingTarget := p.PeerGre
		if pingTarget == "" && p.NoGre {
			pingTarget = p.RemotePub
		}
		if pingTarget != "" {
			start := time.Now()
			if err := exec.Command("ping", "-c", "1", "-W", "2", pingTarget).Run(); err == nil {
				l.PingOK = true
				l.PingMs = fmt.Sprintf("%.0fms", float64(time.Since(start).Microseconds())/1000)
			}
		}
		if !p.NoGre {
			l.Rx, l.Tx = ifaceTraffic(p.GreIf)
		}
		l.FrpOnly = l.Linked && !l.PingOK
		l.LatencyMs, l.LatencyKind = pickLatency(l.PingOK, l.PingMs, tcpRTT)
		out = append(out, l)
	}
	return out
}

func removePeerViaInstaller(id int) (string, error) {
	script, err := greScriptPath()
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", script, "remove-peer", "--id", fmt.Sprint(id), "--force")
	cmd.Env = append(os.Environ(), "GRE_SKIP_PANEL=1", "TERM=dumb", "GRE_PANEL_DIR="+configDir)
	out, runErr := cmd.CombinedOutput()
	o := strings.TrimSpace(stripANSI(string(out)))
	if o == "" {
		o = fmt.Sprintf("peer %d removed", id)
	}
	if runErr != nil {
		// Stale installer without remove-peer: fall back to direct removal
		// from the registry record (same units the installer would stop).
		if p := findPeer(id); p != nil && isMissingRemovePeer(o) {
			if fo, ferr := removePeerDirect(p); ferr == nil {
				return fo, nil
			} else {
				return o, fmt.Errorf("remove-peer failed (%v) and fallback failed: %v", runErr, ferr)
			}
		}
		return o, fmt.Errorf("remove-peer failed: %w", runErr)
	}
	invalidatePeerIfsCache()
	return o, nil
}

// isMissingRemovePeer reports whether installer output means the script has
// no remove-peer subcommand (stale gre.sh on a server that was never updated).
func isMissingRemovePeer(out string) bool {
	l := strings.ToLower(out)
	return strings.Contains(l, "unknown command") || strings.Contains(l, "unknown flag")
}

// stripANSI drops shell color codes so output matching works on any installer.
func stripANSI(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '[' {
			i += 2
			for i < len(s) && s[i] != 'm' {
				i++
			}
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// removePeerDirect deletes one peer using its registry record: stop + disable
// its units, delete unit files + frps toml + GRE iface, drop the record.
// Legacy peer 1 also drops the old single tunnel (same as remove_tunnel_force).
func removePeerDirect(p *peerRecord) (string, error) {
	if p.Legacy {
		return removeViaInstaller()
	}
	greSvc := p.GreIf
	if greSvc == "" {
		greSvc = fmt.Sprintf("gre-t%d", p.ID)
	}
	frpsSvc := p.FrpsSvc
	if frpsSvc == "" {
		frpsSvc = fmt.Sprintf("frps-%d", p.ID)
	}
	exec.Command("systemctl", "stop", frpsSvc, greSvc+".service").CombinedOutput()
	exec.Command("systemctl", "disable", frpsSvc, greSvc+".service").CombinedOutput()
	os.Remove("/etc/systemd/system/" + frpsSvc + ".service")
	os.Remove("/etc/systemd/system/" + greSvc + ".service")
	os.Remove(filepath.Join(frpDir, fmt.Sprintf("frps-%d.toml", p.ID)))
	exec.Command("systemctl", "daemon-reload").CombinedOutput()
	exec.Command("systemctl", "reset-failed").CombinedOutput()
	exec.Command("ip", "tunnel", "del", greSvc).CombinedOutput()
	peers := loadPeers()
	keep := peers[:0]
	for _, q := range peers {
		if q.ID != p.ID {
			keep = append(keep, q)
		}
	}
	data, _ := json.MarshalIndent(map[string]any{"peers": keep}, "", "  ")
	if err := os.WriteFile(peersFile(), append(data, '\n'), 0600); err != nil {
		return "", err
	}
	return fmt.Sprintf("peer '%s' (id %d) removed", p.Name, p.ID), nil
}

// ---- local inspection (reads systemd + ip, never writes except via actions) ----

type greState struct {
	Exists bool   `json:"exists"`
	Name   string `json:"name"`
	Local  string `json:"local"`
	PeerIP string `json:"peer_ip"`
	Inner  string `json:"inner"`
}

type tunnelStatus struct {
	Role         string   `json:"role"`
	Engine       string   `json:"engine,omitempty"`
	TunnelEngine string   `json:"tunnel_engine,omitempty"`
	TunnelType   string   `json:"tunnel_type,omitempty"`
	Transport    string   `json:"transport,omitempty"`
	Gre          greState `json:"gre"`
	GrePeer      string   `json:"gre_peer"`
	LocalPub     string   `json:"local_pub,omitempty"`
	RemotePub    string   `json:"remote_pub,omitempty"`
	PingOK       bool     `json:"ping_ok"`
	PingMs       string   `json:"ping_ms"`
	FrpUp        bool     `json:"frp_up"`
	FrpSvc       string   `json:"frp_svc"`
	FrpPort      int      `json:"frp_port"`
	Proxies      []string `json:"proxies"`
	ProxyPorts   []int    `json:"proxy_ports"`
	Ports        []int    `json:"ports,omitempty"`
	BindPort     int      `json:"bind_port"`
}

func localStatus() tunnelStatus {
	var st tunnelStatus
	// GRE interface
	if out, err := exec.Command("ip", "tunnel", "show").CombinedOutput(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, "gre-tunnel") {
				st.Gre.Exists = true
				st.Gre.Name = "gre-tunnel"
				parts := strings.Fields(line)
				for i, p := range parts {
					if p == "local" && i+1 < len(parts) {
						st.Gre.Local = parts[i+1]
					}
					if p == "remote" && i+1 < len(parts) {
						st.Gre.PeerIP = parts[i+1]
						st.GrePeer = parts[i+1]
					}
				}
			}
		}
	}
	if out, err := exec.Command("ip", "-4", "addr", "show", "dev", "gre-tunnel").CombinedOutput(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "inet ") {
				st.Gre.Inner = strings.Fields(line)[1]
				st.Gre.Exists = true
				if st.Gre.Name == "" {
					st.Gre.Name = "gre-tunnel"
				}
			}
		}
	}
	// FRP / Backhaul role: which unit file exists / is active
	for _, svc := range []string{"frps", "frpc", "backhaul-server", "backhaul-client"} {
		if out, err := exec.Command("systemctl", "is-active", svc).CombinedOutput(); err == nil &&
			strings.TrimSpace(string(out)) == "active" {
			st.FrpUp = true
			st.FrpSvc = svc
			switch svc {
			case "frps":
				st.Role = "iran (server)"
			case "frpc":
				st.Role = "foreign (client)"
			case "backhaul-server":
				st.Role = "iran (backhaul)"
			case "backhaul-client":
				st.Role = "foreign (backhaul)"
			}
			break
		}
	}
	if st.Role == "" {
		// fall back to config presence
		if _, err := os.Stat(filepath.Join(frpDir, "frps.toml")); err == nil {
			st.Role = "iran (server)"
			st.FrpSvc = "frps"
		} else if _, err := os.Stat(filepath.Join(frpDir, "frpc.toml")); err == nil {
			st.Role = "foreign (client)"
			st.FrpSvc = "frpc"
		} else if _, err := os.Stat(filepath.Join(backhaulDir, "config.toml")); err == nil {
			st.Role = "iran (backhaul)"
			st.FrpSvc = "backhaul-server"
		} else if _, err := os.Stat(filepath.Join(backhaulDir, "server.toml")); err == nil {
			st.Role = "iran (backhaul)"
			st.FrpSvc = "backhaul-server"
		} else if _, err := os.Stat(filepath.Join(configDir, "server.toml")); err == nil {
			st.Role = "iran (backhaul)"
			st.FrpSvc = "backhaul-server"
		} else if _, err := os.Stat(filepath.Join(backhaulDir, "client.toml")); err == nil {
			st.Role = "foreign (backhaul)"
			st.FrpSvc = "backhaul-client"
		} else if _, err := os.Stat(filepath.Join(configDir, "client.toml")); err == nil {
			st.Role = "foreign (backhaul)"
			st.FrpSvc = "backhaul-client"
		}
	}
	// ports & proxies from Backhaul or FRP
	if strings.HasPrefix(st.FrpSvc, "backhaul") {
		if st.Gre.Exists {
			st.Engine = "gre-backhaul"
		} else {
			st.Engine = "backhaul"
		}
		st.TunnelEngine = st.Engine
		st.TunnelType = st.Engine
		bhPath := filepath.Join(backhaulDir, "config.toml")
		if _, err := os.Stat(bhPath); err != nil {
			if _, err := os.Stat(filepath.Join(backhaulDir, "server.toml")); err == nil {
				bhPath = filepath.Join(backhaulDir, "server.toml")
			} else if _, err := os.Stat(filepath.Join(configDir, "server.toml")); err == nil {
				bhPath = filepath.Join(configDir, "server.toml")
			}
		}
		if st.FrpSvc == "backhaul-client" {
			if _, err := os.Stat(filepath.Join(backhaulDir, "client.toml")); err == nil {
				bhPath = filepath.Join(backhaulDir, "client.toml")
			} else if _, err := os.Stat(filepath.Join(configDir, "client.toml")); err == nil {
				bhPath = filepath.Join(configDir, "client.toml")
			}
		}
		if data, err := os.ReadFile(bhPath); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "transport") {
					parts := strings.Split(trimmed, "=")
					if len(parts) >= 2 {
						st.Transport = strings.Trim(strings.TrimSpace(parts[1]), `"' `)
					}
				}
				if strings.HasPrefix(trimmed, "remote_addr") {
					parts := strings.SplitN(trimmed, "=", 2)
					if len(parts) == 2 {
						val := strings.Trim(strings.TrimSpace(parts[1]), `"' `)
						host, portStr, err := net.SplitHostPort(val)
						if err == nil {
							st.RemotePub = host
							st.Gre.PeerIP = host
							if v, err := strconv.Atoi(portStr); err == nil {
								st.BindPort = v
								st.FrpPort = v
							}
						}
					}
				} else if strings.HasPrefix(trimmed, "bind_addr") {
					parts := strings.Split(trimmed, ":")
					if len(parts) >= 2 {
						pStr := strings.Trim(parts[len(parts)-1], `" ')`)
						if v, err := strconv.Atoi(pStr); err == nil {
							st.BindPort = v
							st.FrpPort = v
						}
					}
				}
				if strings.HasPrefix(trimmed, `"`) {
					pStr := strings.Trim(trimmed, `", `)
					st.Proxies = append(st.Proxies, pStr)
					basePart := strings.Split(strings.Split(pStr, "-")[0], "=")[0]
					if v, err := strconv.Atoi(basePart); err == nil {
						st.ProxyPorts = append(st.ProxyPorts, v)
					}
				}
			}
		}
	} else {
		if st.FrpSvc != "" {
			st.Engine = "frp"
		}
		tomlPath := filepath.Join(frpDir, "frps.toml")
		if st.FrpSvc == "frpc" {
			tomlPath = filepath.Join(frpDir, "frpc.toml")
		}
		if data, err := os.ReadFile(tomlPath); err == nil {
			inProxy := false
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "serverAddr = ") {
					addr := strings.Trim(strings.TrimPrefix(line, "serverAddr = "), `"' `)
					st.RemotePub = addr
					if st.Gre.PeerIP == "" {
						st.Gre.PeerIP = addr
					}
				}
				if strings.HasPrefix(line, "bindPort") || strings.HasPrefix(line, "serverPort") {
					// "bindPort = 7000" / "serverPort = 7000" — split on '='
					// (fmt.Sscanf with %*s is not supported by Go and left this 0).
					if parts := strings.SplitN(line, "=", 2); len(parts) == 2 {
						if v, err := strconv.Atoi(strings.TrimSpace(parts[1])); err == nil && v > 0 {
							st.BindPort = v
							st.FrpPort = v
						}
					}
					continue
				}
				// TOML table headers: [[proxies]] opens a proxy block, and any
				// other [section] closes it. remotePort/localPort lines are only
				// meaningful inside a proxies block.
				if strings.HasPrefix(line, "[[proxies]]") {
					// open a new proxy block (name filled by the next name = line)
					inProxy = true
					continue
				}
				if strings.HasPrefix(line, "[") {
					inProxy = false // any other section closes the proxy block
					continue
				}
				if strings.HasPrefix(line, "name = ") {
					name := strings.Trim(strings.TrimPrefix(line, "name = "), `"`)
					if inProxy {
						st.Proxies = append(st.Proxies, name)
					}
					continue
				}
				// per-proxy ports: shown in the FRP card next to the bind port.
				if inProxy && (strings.HasPrefix(line, "remotePort") || strings.HasPrefix(line, "localPort")) {
					if parts := strings.SplitN(line, "=", 2); len(parts) == 2 {
						if v, err := strconv.Atoi(strings.TrimSpace(parts[1])); err == nil && v > 0 {
							st.ProxyPorts = append(st.ProxyPorts, v)
						}
					}
				}
			}
		}
	}
	// de-duplicate proxy ports (each proxy has local+remote for the same port)
	st.ProxyPorts = uniqInts(st.ProxyPorts)
	// quick ping to GRE peer inner ip
	if st.Gre.Inner != "" {
		target := grePeerInner(st.Gre.Inner)
		if target != "" {
			start := time.Now()
			if err := exec.Command("ping", "-c", "1", "-W", "2", target).Run(); err == nil {
				st.PingOK = true
				st.PingMs = fmt.Sprintf("%.0fms", float64(time.Since(start).Microseconds())/1000)
			}
		}
	}
	st.TunnelEngine = st.Engine
	st.TunnelType = st.Engine
	st.LocalPub = st.Gre.Local
	if st.RemotePub == "" {
		st.RemotePub = st.Gre.PeerIP
	}
	st.Ports = st.ProxyPorts
	return st
}

// uniqInts keeps first occurrence order.
func uniqInts(in []int) []int {
	seen := map[int]bool{}
	out := []int{}
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

// grePeerInner flips the last bit of a /30 inner address.
func grePeerInner(cidr string) string {
	ip := strings.Split(cidr, "/")[0]
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return ""
	}
	last := 0
	fmt.Sscanf(parts[3], "%d", &last)
	if last%2 == 0 {
		last--
	} else {
		last++
	}
	return fmt.Sprintf("%s.%s.%s.%d", parts[0], parts[1], parts[2], last)
}

// switchTunnelEngine changes the active tunnel engine live without reinstalling from scratch.
func switchTunnelEngine(targetEngine, targetTransport string) (string, error) {
	targetEngine = strings.ToLower(strings.TrimSpace(targetEngine))
	if targetEngine != "frp" && targetEngine != "backhaul" && targetEngine != "gre-backhaul" {
		return "", fmt.Errorf("invalid engine %q: must be frp, backhaul, or gre-backhaul", targetEngine)
	}
	if targetTransport == "" {
		targetTransport = "tcpmux"
	}

	st := localStatus()
	isIran := strings.Contains(strings.ToLower(st.Role), "iran") || st.Role == "master"

	// Gather common params
	token := ""
	var proxyPorts []int
	var rawPorts []string
	port := st.BindPort
	if port <= 0 {
		port = st.FrpPort
	}
	if port <= 0 {
		port = 7000
	}

	// 1. Read token & ports from current config
	if data, err := os.ReadFile(filepath.Join(frpDir, "frps.toml")); err == nil {
		for _, l := range strings.Split(string(data), "\n") {
			l = strings.TrimSpace(l)
			if strings.HasPrefix(l, "auth.token = ") {
				token = strings.Trim(strings.TrimPrefix(l, "auth.token = "), `"' `)
			}
		}
	}
	if token == "" {
		if data, err := os.ReadFile(filepath.Join(frpDir, "frpc.toml")); err == nil {
			for _, l := range strings.Split(string(data), "\n") {
				l = strings.TrimSpace(l)
				if strings.HasPrefix(l, "auth.token = ") {
					token = strings.Trim(strings.TrimPrefix(l, "auth.token = "), `"' `)
				}
			}
		}
	}
	if token == "" {
		if data, err := os.ReadFile(filepath.Join(backhaulDir, "config.toml")); err == nil {
			for _, l := range strings.Split(string(data), "\n") {
				l = strings.TrimSpace(l)
				if strings.HasPrefix(l, "token = ") {
					token = strings.Trim(strings.TrimPrefix(l, "token = "), `"' `)
				}
			}
		}
	}
	if token == "" {
		if data, err := os.ReadFile(filepath.Join(backhaulDir, "client.toml")); err == nil {
			for _, l := range strings.Split(string(data), "\n") {
				l = strings.TrimSpace(l)
				if strings.HasPrefix(l, "token = ") {
					token = strings.Trim(strings.TrimPrefix(l, "token = "), `"' `)
				}
			}
		}
	}
	if token == "" {
		pcfg := loadPeerConfig()
		token = pcfg.PeerSecret
	}
	if token == "" {
		token = randomToken(32)
	}

	for _, p := range st.ProxyPorts {
		proxyPorts = append(proxyPorts, p)
		rawPorts = append(rawPorts, strconv.Itoa(p))
	}
	for _, p := range st.Proxies {
		found := false
		for _, rp := range rawPorts {
			if rp == p {
				found = true
				break
			}
		}
		if !found {
			rawPorts = append(rawPorts, p)
		}
	}
	if len(rawPorts) == 0 {
		rawPorts = []string{"443", "2083"}
		proxyPorts = []int{443, 2083}
	}

	remotePub := CleanHost(st.RemotePub)
	if remotePub == "" {
		remotePub = CleanHost(st.Gre.PeerIP)
	}
	if remotePub == "" {
		pcfg := loadPeerConfig()
		remotePub = CleanHost(pcfg.PeerURL)
	}

	peerGre := st.Gre.PeerIP
	if isIran {
		if peerGre == "" {
			peerGre = defaultForeignGRE
		}
	} else {
		if peerGre == "" {
			peerGre = defaultIranGRE
		}
	}

	var outMsg strings.Builder
	outMsg.WriteString(fmt.Sprintf("Switching engine to %s (%s)...\n", targetEngine, targetTransport))

	// Stop previous services
	_ = runSystemctl("stop", "frps")
	_ = runSystemctl("stop", "frpc")
	_ = runSystemctl("stop", "backhaul-server")
	_ = runSystemctl("stop", "backhaul-client")

	switch targetEngine {
	case "frp":
		// Ensure GRE is active
		_ = runSystemctl("restart", "gre-tunnel")
		if isIran {
			// Write frps.toml
			_, maxPool := effectivePoolValues()
			frpsToml := fmt.Sprintf(`bindAddr = "0.0.0.0"
bindPort = %d
auth.method = "token"
auth.token = %q
%stransport.tcpKeepalive = 30
transport.heartbeatTimeout = 90
transport.maxPoolCount = %d
`, port, token, tcpMuxTomlLines(), maxPool)
			_ = os.MkdirAll(frpDir, 0755)
			_ = os.WriteFile(filepath.Join(frpDir, "frps.toml"), []byte(frpsToml), 0644)
			ensureFRPServiceUnits("frps")
			_ = runSystemctl("restart", "frps")
			_ = runSystemctl("enable", "frps")
			outMsg.WriteString("frps service configured and started with high-concurrency limits.\n")
		} else {
			// Foreign FRP client
			var frpcBuf strings.Builder
			frpProto := "tcp"
			useEnc := false
			useComp := false
			ppVersion := ""
			for _, p := range loadPeers() {
				if p.ProxyProtocol == "v2" || p.ProxyProtocol == "v1" {
					ppVersion = p.ProxyProtocol
				}
				if p.FRPTransport != "" {
					frpProto = p.FRPTransport
				}
				if p.UseEncryption {
					useEnc = true
				}
				if p.UseCompression {
					useComp = true
				}
			}
			if ppVersion == "" {
				if data, err := os.ReadFile(filepath.Join(frpDir, "frpc.toml")); err == nil && strings.Contains(string(data), `proxyProtocolVersion = "v2"`) {
					ppVersion = "v2"
				}
			}
			ppLine := ""
			if ppVersion != "" {
				ppLine = fmt.Sprintf("transport.proxyProtocolVersion = %q\n", ppVersion)
			}
			encLine := ""
			if useEnc {
				encLine = "transport.useEncryption = true\n"
			}
			compLine := ""
			if useComp {
				compLine = "transport.useCompression = true\n"
			}

			effPort := port
			if frpProto == "quic" {
				effPort = port + 1
				if effPort > 65535 {
					effPort = port - 1
				}
			}

			pool, _ := effectivePoolValues()
			frpcBuf.WriteString(fmt.Sprintf(`serverAddr = %q
serverPort = %d
auth.method = "token"
auth.token = %q
loginFailExit = false
transport.protocol = %q
%stransport.heartbeatInterval = 30
transport.heartbeatTimeout = 90
transport.dialServerTimeout = 15
transport.dialServerKeepalive = 30
transport.poolCount = %d
`, peerGre, effPort, token, frpProto, tcpMuxTomlLines(), pool))

			for _, p := range proxyPorts {
				frpcBuf.WriteString(fmt.Sprintf(`
[[proxies]]
name = "tcp-%d"
type = "tcp"
localIP = "127.0.0.1"
localPort = %d
remotePort = %d
%s%s%s
[[proxies]]
name = "udp-%d"
type = "udp"
localIP = "127.0.0.1"
localPort = %d
remotePort = %d
`, p, p, p, ppLine, encLine, compLine, p, p, p))
			}
			_ = os.MkdirAll(frpDir, 0755)
			_ = os.WriteFile(filepath.Join(frpDir, "frpc.toml"), []byte(frpcBuf.String()), 0644)
			ensureFRPServiceUnits("frpc")
			_ = runSystemctl("restart", "frpc")
			_ = runSystemctl("enable", "frpc")
			outMsg.WriteString("frpc service configured and started with high-concurrency limits.\n")
		}

	case "backhaul":
		// Standalone Backhaul (no GRE)
		_ = runSystemctl("stop", "gre-tunnel")
		if isIran {
			_ = writeBackhaulServerConfig(filepath.Join(backhaulDir, "config.toml"), fmt.Sprintf("0.0.0.0:%d", port), targetTransport, token, rawPorts)
			_ = runSystemctl("restart", "backhaul-server")
			_ = runSystemctl("enable", "backhaul-server")
			outMsg.WriteString("backhaul-server configured and started.\n")
		} else {
			remoteAddr := fmt.Sprintf("%s:%d", remotePub, port)
			_ = writeBackhaulClientConfig(filepath.Join(backhaulDir, "client.toml"), remoteAddr, targetTransport, token)
			_ = runSystemctl("restart", "backhaul-client")
			_ = runSystemctl("enable", "backhaul-client")
			outMsg.WriteString("backhaul-client configured and started.\n")
		}

	case "gre-backhaul":
		// GRE + Backhaul
		_ = runSystemctl("restart", "gre-tunnel")
		if isIran {
			_ = writeBackhaulServerConfig(filepath.Join(backhaulDir, "config.toml"), fmt.Sprintf("0.0.0.0:%d", port), targetTransport, token, rawPorts)
			_ = runSystemctl("restart", "backhaul-server")
			_ = runSystemctl("enable", "backhaul-server")
			outMsg.WriteString("backhaul-server (over GRE) configured and started.\n")
		} else {
			remoteAddr := fmt.Sprintf("%s:%d", peerGre, port)
			_ = writeBackhaulClientConfig(filepath.Join(backhaulDir, "client.toml"), remoteAddr, targetTransport, token)
			_ = runSystemctl("restart", "backhaul-client")
			_ = runSystemctl("enable", "backhaul-client")
			outMsg.WriteString("backhaul-client (over GRE) configured and started.\n")
		}
	}

	// If master with active Peer Link, propagate to worker
	if isIran {
		go func() {
			time.Sleep(1 * time.Second)
			_ = syncEngineToPeer(targetEngine, targetTransport)
		}()
	}

	return outMsg.String(), nil
}

// ensureFRPServiceUnits enforces high-concurrency systemd limits (LimitNOFILE, TasksMax, Restart=always)
// to prevent connection drops under heavy concurrent load.
func ensureFRPServiceUnits(svcName string) {
	if runtime.GOOS == "windows" {
		return
	}
	unitPath := "/etc/systemd/system/" + svcName + ".service"
	data, err := os.ReadFile(unitPath)
	if err != nil {
		return
	}
	content := string(data)
	changed := false
	if !strings.Contains(content, "LimitNOFILE") {
		content = strings.Replace(content, "[Service]", "[Service]\nLimitNOFILE=1048576\nLimitNPROC=512000\nTasksMax=infinity\nStartLimitIntervalSec=0", 1)
		changed = true
	}
	if strings.Contains(content, "Restart=on-failure") {
		content = strings.Replace(content, "Restart=on-failure", "Restart=always", 1)
		changed = true
	}
	if strings.Contains(content, "StartLimitIntervalSec=60") {
		content = strings.Replace(content, "StartLimitIntervalSec=60\nStartLimitBurst=5\n", "", 1)
		changed = true
	}
	if changed {
		_ = os.WriteFile(unitPath, []byte(content), 0644)
		_ = runSystemctl("daemon-reload")
	}
}

// pickLatency chooses the per-link latency: ICMP when the GRE inner address
// answers, else the TCP RTT of the live control session, else none (-1).
func pickLatency(pingOK bool, pingMs string, tcpRTT float64) (float64, string) {
	if pingOK {
		if v := parsePingMs(pingMs); v >= 0 {
			return v, "icmp"
		}
	}
	if tcpRTT >= 0 {
		return round1(tcpRTT), "tcp"
	}
	return -1, ""
}
