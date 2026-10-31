package main

// Tunnel inspection + actions: read GRE/FRP state via ip/systemd (never
// writes), restart/ping/remove via systemctl/ping or the shared hashem.sh
// installer (single source of truth, same as the CLI/menu path).

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// status of GRE + FRP on this machine.
func handleStatus(w http.ResponseWriter, r *http.Request) {
	snap := currentSnapshot()
	setSnapshotAgeHeader(w, snap)
	peers := snap.PeersAged()
	lv := localView{tunnelStatus: snap.Local, LatencyMs: -1}
	if m := snap.Main; m != nil {
		lv.HealthState, lv.ICMPFiltered, lv.LatencyMs, lv.LatencyKind, lv.Reasons = m.HealthState, m.ICMPFiltered, m.LatencyMs, m.LatencyKind, m.Reasons
		lv.Rx, lv.Tx = m.Rx, m.Tx
	}
	lv.CarrierID = mainCarrierID(snap.Local)
	lv.Name = linkLabel("main")
	if lv.Rx == nil {
		lv.Rx, lv.Tx = snap.LocalRx, snap.LocalTx
	}
	resp := map[string]any{"local": lv, "peers": peers, "peer_count": len(peers), "peer_max": maxPeers(), "snapshot_age_ms": snap.AgeMs(),
		"counters_at": countersAtMs(snap)}
	if c, err := r.Cookie("gre_session"); err == nil && c.Value != "" {
		resp["csrf_token"] = GenerateCSRFToken(c.Value)
	}
	writeJSON(w, resp)
}

// localView is the base tunnel status plus its multi-signal health (additive
// fields; the embedded status keeps every existing key).
type localView struct {
	tunnelStatus
	HealthState  string   `json:"health_state,omitempty"`
	ICMPFiltered bool     `json:"icmp_filtered"`
	LatencyMs    float64  `json:"latency_ms"`
	LatencyKind  string   `json:"latency_kind,omitempty"`
	Reasons      []string `json:"reasons,omitempty"`
	// Rx/Tx: bytes received/sent by the base tunnel (its GRE interface, or the
	// Backhaul/Bagher port counters when this server has no other tunnel);
	// null when unknown. The Tunnel tab turns them into live speeds.
	Rx *uint64 `json:"rx"`
	Tx *uint64 `json:"tx"`
	// CarrierID: the carrier the base tunnel runs on ("frp:kcp", "backhaul:tcpmux"),
	// for the Carriers card and Swap carrier.
	CarrierID string `json:"carrier_id,omitempty"`
	// Name: what the user calls the base tunnel's other server ("" = none).
	Name string `json:"name,omitempty"`
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
		// Every engine the panel runs; journalctl skips units that do not exist.
		units := []string{"frps", "frpc", "gre-panel", "hashem-watchdog", "gre-tunnel",
			"backhaul", "backhaul-server", "backhaul-client"}
		var args []string
		for _, u := range units {
			args = append(args, "-u", u)
		}
		args = append(args, "-n", strconv.Itoa(lines), "--no-pager")
		if _, err := exec.LookPath("journalctl"); err == nil {
			out, err := exec.Command("journalctl", args...).CombinedOutput()
			if err == nil && len(bytes.TrimSpace(out)) > 0 {
				raw := redactLogSecrets(string(out))
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
			raw := redactLogSecrets(string(out))
			writeJSON(w, map[string]any{"logs": raw, "lines": splitLogLines(raw), "svc": svc, "findings": summarizeLogs(raw)})
			return
		}
	}
	// fallback: log files
	for _, q := range []string{"/var/log/" + svc + ".log", "/root/" + svc + ".log"} {
		if data, err := os.ReadFile(q); err == nil {
			raw := redactLogSecrets(string(data))
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
		// The Tunnel tab sent these names, which this handler never read:
		// every live engine switch failed with `invalid engine ""`.
		TargetEngine    string `json:"target_engine"`
		TargetTransport string `json:"target_transport"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeAPIError(w, r, "E-ACTION-02", "")
		return
	}
	switch body.Action {
	case "restart-frps", "restart-frpc", "restart-engine", "restart-gre", "ping", "remove-tunnel":
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
		if body.Action != "tune-status" { // an older hashem.sh puts MTU 1380 back
			if fixed := enforcePathMTU(); len(fixed) > 0 {
				out += "\n" + strings.Join(fixed, "\n")
			}
		}
		writeJSON(w, map[string]string{"status": "ok", "output": out})
	case "switch-engine", "switch_engine":
		eng, trans := body.Engine, body.Transport
		if eng == "" {
			eng, trans = body.TargetEngine, body.TargetTransport
		}
		if backhaulLocked(eng) && proRequired(w, r, proBackhaul, "Backhaul") {
			return
		}
		out, err := switchTunnelEngine(eng, trans)
		if err != nil {
			writeAPIError(w, r, "E-ACTION-03", err.Error())
			return
		}
		// The other server must run the same engine, or the tunnel stays
		// down: tell the linked worker and say whether it followed.
		peer := "none"
		if engineSyncNeeded() {
			switch told, perr := engineSyncFn(strings.ToLower(strings.TrimSpace(eng)), trans); {
			case !told:
			case perr != nil:
				peer = "failed"
				out += "\nForeign server did not switch: " + perr.Error()
			default:
				peer = "switched"
				out += "\nForeign server switched too.\n"
			}
		}
		writeJSON(w, map[string]string{"status": "ok", "output": out, "peer": peer})
	default:
		writeAPIError(w, r, "E-ACTION-01", "")
	}
}

func runAction(action string, peerID int) (string, error) {
	switch action {
	case "restart-frps", "restart-engine":
		// The main tunnel restarts whatever engine runs it (frps, frpc or a
		// Backhaul unit); "frps" on a Backhaul server failed.
		if peerID <= 0 {
			if svc := localStatus().FrpSvc; svc != "" {
				out, err := exec.Command("systemctl", "restart", svc).CombinedOutput()
				return string(out), err
			}
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
		// The first tunnel next to other tunnels: remove it alone. The full
		// removal stops every frps*, backhaul* and gre-t* and drops peers.json.
		if peers := loadPeers(); len(peers) > 0 {
			if p := basePeer(peers); p != nil {
				out, err := removePeerViaInstaller(p.ID)
				if err == nil {
					firstTunnelForget()
				}
				return out, err
			}
			out, err := removeViaInstaller("--base")
			invalidatePeerIfsCache()
			if err == nil {
				firstTunnelForget()
			}
			return out, err
		}
		// mirror of hashem.sh remove_tunnel_force(): GRE + FRP gone, panel untouched.
		// Implemented via the installer itself (single source of truth) so the
		// shell-out path and the menu path can never drift apart.
		out, err := removeViaInstaller("--force")
		if err != nil {
			return "", err
		}
		firstTunnelForget()
		return out, nil
	}
	return "", fmt.Errorf("unknown action")
}

// basePeer is the peer record that is the first tunnel itself (peer 1 on the
// legacy names, or a peer that took gre-tunnel), or nil.
func basePeer(peers []peerRecord) *peerRecord {
	for i, p := range peers {
		if p.Legacy || p.GreIf == "gre-tunnel" || slices.Contains(baseUnits, p.FrpsSvc) {
			return &peers[i]
		}
	}
	return nil
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

// removeViaInstaller runs `hashem.sh remove-tunnel --force` (every tunnel) or
// `--base` (the first tunnel only) and returns its output as the action
// result. GRE_SKIP_PANEL is irrelevant here (removal never touches the
// panel), but kept for symmetry with runInstaller.
func removeViaInstaller(mode string) (string, error) {
	script, err := greScriptPath()
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", script, "remove-tunnel", mode)
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
	RawPorts       portList `json:"raw_ports,omitempty"`
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

// portList is raw_ports. Older hashem.sh wrote it for Backhaul peers as one
// string ("443, 2083"); that failed the whole peers.json decode and hid every
// peer tunnel from the panel. Both forms are read; it is written as a list.
type portList []string

func (l *portList) UnmarshalJSON(b []byte) error {
	var list []string
	if err := json.Unmarshal(b, &list); err == nil {
		*l = list
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	*l = strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' })
	return nil
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
	// Multi-signal health (health.go). HealthState is the published (debounced)
	// verdict; the legacy fields above keep their meaning.
	HealthState   string   `json:"health_state"`
	ICMPFiltered  bool     `json:"icmp_filtered"`
	ICMPOK        bool     `json:"icmp_ok"`
	ICMPMs        float64  `json:"icmp_ms"` // -1 when ICMP has not answered
	Reasons       []string `json:"reasons"`
	SnapshotAgeMs int64    `json:"snapshot_age_ms"`
	ICMPKnown     bool     `json:"-"` // an ICMP measurement exists for this link
	icmpTarget    string
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
	if err := json.Unmarshal(data, &v); err != nil {
		logPeersDecodeErr(err)
		return nil
	}
	return v.Peers
}

var peersDecodeErr sync.Once

// logPeersDecodeErr says once why peers.json was not read: every peer tunnel
// disappears from the panel then, while its services keep running.
func logPeersDecodeErr(err error) {
	peersDecodeErr.Do(func() { log.Printf("peers.json: cannot read it, peer tunnels are hidden: %v", err) })
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

// livePeersFrom derives every peer's live state from an already collected host
// view; it runs no commands itself.
func livePeersFrom(v *hostView, recs []peerRecord) []peerLive {
	if len(recs) == 0 {
		return nil
	}
	out := make([]peerLive, 0, len(recs))
	for _, p := range recs {
		l := peerLive{peerRecord: p}
		if p.NoGre {
			l.GreInner = "standalone"
			l.GreUp = true
		} else if v.tunnelOK {
			// presence check via interface address (works without parsing tun show)
			l.GreInner = v.inner[p.GreIf]
			l.GreUp = l.GreInner != ""
		}
		l.FrpUp = v.active[p.FrpsSvc]
		sig := LinkSignals{ServiceActive: l.FrpUp, GreIfUp: l.GreUp}
		q := ctrlQuery{ID: p.ID, Port: p.FrpPort, RemotePub: p.RemotePub, PeerGre: p.PeerGre}
		if l.FrpUp {
			r := controlSessionIn(v.sessions, q, v.owners)
			l.Linked, sig.Session, sig.TCPRTTms = r.Linked, r.Linked, r.RTTms
			if !r.Linked && v.connect != nil {
				if c := v.connect(p.ID); c.OK {
					sig.ConnectRTTms = c.RTTms
				}
			}
		}
		l.icmpTarget = p.PeerGre
		if l.icmpTarget == "" && p.NoGre {
			l.icmpTarget = p.RemotePub
		}
		ic := v.icmpFor(l.icmpTarget)
		if !p.NoGre {
			l.Rx, l.Tx = v.traffic(p.GreIf)
			sig.TrafficFlowing = v.flowing[p.GreIf]
		} else {
			// Backhaul without GRE has no interface: its unit's port counters
			l.Rx, l.Tx = v.carrierTraffic(p.FrpsSvc)
		}
		sig.Rx, sig.Tx = l.Rx, l.Tx
		l.applyHealth(sig, ic)
		out = append(out, l)
	}
	return out
}

// applyHealth fills the PingOK/latency/health fields from one signal set so every
// consumer sees the same verdict (health.go is the single definition).
func (l *peerLive) applyHealth(sig LinkSignals, ic icmpResult) {
	sig.ICMPOK, sig.ICMPms, sig.ICMPFresh = ic.OK, ic.Ms, ic.Known
	l.PingOK, l.ICMPOK, l.ICMPKnown, l.ICMPMs = ic.OK, ic.OK, ic.Known, -1
	if ic.OK {
		l.PingMs = fmt.Sprintf("%.0fms", ic.Ms)
		l.ICMPMs = ic.Ms
	}
	h := ComputeHealth(sig)
	l.HealthState, l.ICMPFiltered, l.Reasons = h.State, h.ICMPFiltered, h.Reasons
	l.LatencyMs, l.LatencyKind = h.LatencyMs, h.LatencyKind
	l.FrpOnly = l.Linked && !l.PingOK
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
// Legacy peer 1 is the first tunnel; an installer this old can only remove
// every tunnel with it, so it is refused until hashem.sh is updated.
func removePeerDirect(p *peerRecord) (string, error) {
	if p.Legacy {
		return "", fmt.Errorf("this hashem.sh cannot remove the first tunnel alone; run `hashem update` first")
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
	// TuneBackup: hashem.sh optimize saved the previous settings, so Restore works.
	TuneBackup bool `json:"tune_backup"`
}

// engineBinDirs / backhaulExtraBins are where hashem.sh installs engine
// binaries (INSTALL_DIR, plus the backhaul-core copy); vars so tests can
// point them at temp dirs.
var (
	engineBinDirs     = []string{"/usr/local/bin"}
	backhaulExtraBins = []string{"/root/backhaul-core/backhaul_premium"}
)

func executableFile(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0o111 != 0
}

// engineBinaryPresent reports whether the engine ("frps", "frpc" or
// "backhaul") has an executable binary in any known install location.
func engineBinaryPresent(engine string) bool {
	for _, d := range engineBinDirs {
		if executableFile(filepath.Join(d, engine)) {
			return true
		}
	}
	if engine == "backhaul" {
		for _, p := range backhaulExtraBins {
			if executableFile(p) {
				return true
			}
		}
	}
	return false
}

type staleConfigCandidate struct {
	path, engine, role, svc string
}

// staleConfigCandidates lists every config file that can imply a role, in
// fallback preference order.
func staleConfigCandidates() []staleConfigCandidate {
	return []staleConfigCandidate{
		{filepath.Join(frpDir, "frps.toml"), "frps", "iran (server)", "frps"},
		{filepath.Join(frpDir, "frpc.toml"), "frpc", "foreign (client)", "frpc"},
		{filepath.Join(backhaulDir, "config.toml"), "backhaul", "iran (backhaul)", "backhaul-server"},
		{filepath.Join(backhaulDir, "server.toml"), "backhaul", "iran (backhaul)", "backhaul-server"},
		{filepath.Join(configDir, "server.toml"), "backhaul", "iran (backhaul)", "backhaul-server"},
		{filepath.Join(backhaulDir, "client.toml"), "backhaul", "foreign (backhaul)", "backhaul-client"},
		{filepath.Join(configDir, "client.toml"), "backhaul", "foreign (backhaul)", "backhaul-client"},
	}
}

// localStatus reads the base tunnel with a fresh synchronous read (batched host
// commands, ICMP inline). Polling handlers use the shared snapshot instead.
func localStatus() tunnelStatus {
	return localStatusFrom(directView(nil))
}

// localStatusFrom derives the base tunnel state from a collected host view plus
// the config files; it runs no commands itself.
func localStatusFrom(v *hostView) tunnelStatus {
	var st tunnelStatus
	st.TuneBackup = fileExists(filepath.Join(configDir, "tune.bak"))
	// GRE interface
	if v.tunnelOK {
		for _, line := range strings.Split(v.tunnelShow, "\n") {
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
	if inner := v.inner["gre-tunnel"]; inner != "" {
		st.Gre.Inner = inner
		st.Gre.Exists = true
		if st.Gre.Name == "" {
			st.Gre.Name = "gre-tunnel"
		}
		// 6to4 / 4in6: an ip6gre device is not in `ip tunnel show`
		if st.Gre.PeerIP == "" {
			if r, l := gre6Ends("gre-tunnel"); r != "" {
				st.Gre.PeerIP, st.GrePeer, st.Gre.Local = r, r, l
			}
		}
	}
	// FRP / Backhaul role: which unit file exists / is active
	for _, svc := range baseUnits {
		if v.active[svc] {
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
		// per-peer Backhaul units (backhaul-server-N) created for extra peers
		var per []string
		for u, on := range v.active {
			if on && strings.HasPrefix(u, "backhaul-server-") {
				per = append(per, u)
			}
		}
		if len(per) > 0 {
			sort.Strings(per) // deterministic: lowest unit name wins
			st.FrpUp = true
			st.FrpSvc = per[0]
			st.Role = "iran (backhaul)"
		}
	}
	if st.Role == "" {
		// fall back to config presence, but only for an engine that is
		// actually installed; a stale config alone must not claim a role
		for _, c := range staleConfigCandidates() {
			if fileExists(c.path) && engineBinaryPresent(c.engine) {
				st.Role = c.role
				st.FrpSvc = c.svc
				break
			}
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
			bc := parseBackhaulConf(string(data))
			if bc.Transport != "" {
				st.Transport = bc.Transport
			}
			if bc.RemoteAddr != "" {
				if host, portStr, err := net.SplitHostPort(bc.RemoteAddr); err == nil {
					st.RemotePub = host
					st.Gre.PeerIP = host
					if v, err := strconv.Atoi(portStr); err == nil {
						st.BindPort = v
						st.FrpPort = v
					}
				}
			}
			if bc.BindAddr != "" {
				if _, portStr, err := net.SplitHostPort(bc.BindAddr); err == nil {
					if v, err := strconv.Atoi(portStr); err == nil {
						st.BindPort = v
						st.FrpPort = v
					}
				}
			}
			for _, pStr := range bc.Ports {
				st.Proxies = append(st.Proxies, pStr)
				basePart := strings.Split(strings.Split(pStr, "-")[0], "=")[0]
				if v, err := strconv.Atoi(basePart); err == nil {
					st.ProxyPorts = append(st.ProxyPorts, v)
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
	// ICMP to the GRE peer inner ip (metadata only; see health.go)
	if st.Gre.Inner != "" {
		if target := grePeerInner(st.Gre.Inner); target != "" {
			ic := v.icmpFor(target)
			st.PingOK = ic.OK
			if ic.OK {
				st.PingMs = fmt.Sprintf("%.0fms", ic.Ms)
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

// engineUnitDir is where systemd unit files for tunnel engines live (tests
// point it at a throwaway dir).
var engineUnitDir = "/etc/systemd/system"

// preflightEngineSwitch verifies the target engine can actually run on this
// host BEFORE any running service is stopped: binary installed and, for
// Backhaul, the systemd unit written by hashem.sh present. A failed switch
// must never take down the working tunnel.
func preflightEngineSwitch(engine string, isIran bool) error {
	switch engine {
	case "frp":
		bin := "frpc"
		if isIran {
			bin = "frps"
		}
		if !engineBinaryPresent(bin) {
			return fmt.Errorf("%s binary not found (install it with `hashem` first); nothing was changed", bin)
		}
	case "backhaul", "gre-backhaul":
		if !engineBinaryPresent("backhaul") {
			return fmt.Errorf("backhaul binary not found (install it with `hashem` first); nothing was changed")
		}
		unit := "backhaul-client"
		if isIran {
			unit = "backhaul-server"
		}
		if _, err := os.Stat(filepath.Join(engineUnitDir, unit+".service")); err != nil {
			return fmt.Errorf("systemd unit %s.service is missing (run the Backhaul setup in `hashem` first); nothing was changed", unit)
		}
	}
	return nil
}

// switchTunnelEngine changes the active tunnel engine live without reinstalling from scratch.
// backhaulLocked: moving this server onto Backhaul needs Pro. A tunnel that
// already runs Backhaul keeps working (and may switch between its GRE modes)
// without a license, so an update never takes a running tunnel away.
func backhaulLocked(target string) bool {
	t := strings.ToLower(strings.TrimSpace(target))
	if (t != "backhaul" && t != "gre-backhaul") || hasPro(proBackhaul) {
		return false
	}
	return !strings.HasPrefix(localStatus().FrpSvc, "backhaul")
}

// engineOpts carries what the other server knows better than this one's
// configs: a foreign server that runs Backhaul has no port list, so a carrier
// swap to FRP must be told which ports to forward. Zero values keep the old
// behaviour (everything read from the running configs).
type engineOpts struct {
	Port    int      // control port
	Ports   []int    // forwarded ports (FRP proxies)
	Raw     []string // forwarded ports as entered (Backhaul: ranges, mappings)
	Remote  string   // the other server's public address
	PeerGre string   // the other server's GRE inner address
}

// frpProtocols are the FRP client transports a carrier swap can pick. wss
// needs a TLS front on the Iran side that only the installer sets up.
var frpProtocols = []string{"tcp", "kcp", "quic", "websocket"}

func frpProtocolOK(t string) bool {
	for _, v := range frpProtocols {
		if t == v {
			return true
		}
	}
	return false
}

func switchTunnelEngine(targetEngine, targetTransport string) (string, error) {
	return switchTunnelEngineWith(targetEngine, targetTransport, engineOpts{})
}

func switchTunnelEngineWith(targetEngine, targetTransport string, o engineOpts) (string, error) {
	targetEngine = strings.ToLower(strings.TrimSpace(targetEngine))
	if targetEngine != "frp" && targetEngine != "backhaul" && targetEngine != "gre-backhaul" {
		return "", fmt.Errorf("invalid engine %q: must be frp, backhaul, or gre-backhaul", targetEngine)
	}
	// For FRP the transport names the client protocol (tcp, kcp, ...); the
	// Tunnel tab sends tcpmux there, which keeps the recorded protocol.
	frpWant := ""
	if targetEngine == "frp" && frpProtocolOK(targetTransport) {
		frpWant = targetTransport
	}
	if targetTransport == "" || frpWant != "" {
		targetTransport = "tcpmux"
	}
	if targetEngine != "frp" && !backhaulTransportOK(targetTransport) {
		return "", fmt.Errorf("invalid Backhaul transport %q: must be one of %s", targetTransport, strings.Join(backhaulTransports, ", "))
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
	if o.Port > 0 {
		port = o.Port
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
		// st.Proxies holds FRP proxy *names* (tcp_443, udp_443, ...); only
		// real ports, ranges or mappings belong in Backhaul's port list.
		if !isValidPortOrRangeOrMapping(p) {
			continue
		}
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
	if len(o.Ports) > 0 || len(o.Raw) > 0 {
		proxyPorts, rawPorts = append([]int(nil), o.Ports...), append([]string(nil), o.Raw...)
		if len(rawPorts) == 0 {
			for _, p := range proxyPorts {
				rawPorts = append(rawPorts, strconv.Itoa(p))
			}
		}
		if len(proxyPorts) == 0 {
			proxyPorts = extractNumericPorts(rawPorts)
		}
	}
	if len(rawPorts) == 0 {
		rawPorts = []string{"443", "2083"}
		proxyPorts = []int{443, 2083}
	}

	remotePub := CleanHost(st.RemotePub)
	if o.Remote != "" {
		remotePub = CleanHost(o.Remote)
	}
	if remotePub == "" {
		remotePub = CleanHost(st.Gre.PeerIP)
	}
	if remotePub == "" {
		pcfg := loadPeerConfig()
		remotePub = CleanHost(pcfg.PeerURL)
	}

	// The peer's GRE *inner* address: st.Gre.PeerIP is the outer (public)
	// one, which made "GRE + Backhaul" bypass the GRE tunnel entirely.
	peerGre := ""
	if st.Gre.Inner != "" {
		peerGre = grePeerInner(st.Gre.Inner)
	}
	if o.PeerGre != "" {
		peerGre = o.PeerGre
	}
	if peerGre == "" {
		if isIran {
			peerGre = defaultForeignGRE
		} else {
			peerGre = defaultIranGRE
		}
	}

	if err := preflightEngineSwitch(targetEngine, isIran); err != nil {
		return "", err
	}

	var outMsg strings.Builder
	outMsg.WriteString(fmt.Sprintf("Switching engine to %s (%s)...\n", targetEngine, targetTransport))

	// Remember what runs now and every config about to be overwritten, so a
	// failed switch puts the previous tunnel back instead of leaving the
	// server with no tunnel at all.
	tx := newEngineSwitchTx()

	// The engines share the control port, so the old ones must stop first.
	_ = runSystemctl("stop", "frps")
	_ = runSystemctl("stop", "frpc")
	_ = runSystemctl("stop", "backhaul-server")
	_ = runSystemctl("stop", "backhaul-client")

	switch targetEngine {
	case "frp":
		// Ensure GRE is active
		if err := runSystemctl("restart", "gre-tunnel"); err != nil {
			return outMsg.String(), tx.rollback(fmt.Errorf("systemctl restart %s failed: %w", "gre-tunnel", err))
		}
		if isIran {
			// Write frps.toml. kcp/quic bind ports match hashem.sh so peers
			// using those FRP transports can still connect.
			_, maxPool := effectivePoolValues()
			quicPort := port + 1
			if quicPort > 65535 {
				quicPort = port - 1
			}
			frpsToml := fmt.Sprintf(`bindAddr = "0.0.0.0"
bindPort = %d
kcpBindPort = %d
quicBindPort = %d
auth.method = "token"
auth.token = %q
%stransport.tcpKeepalive = 15
transport.heartbeatTimeout = 45
transport.maxPoolCount = %d
`, port, port, quicPort, token, tcpMuxTomlLines(), maxPool)
			tx.backup(filepath.Join(frpDir, "frps.toml"))
			if err := writeEngineFile(frpDir, "frps.toml", frpsToml); err != nil {
				return outMsg.String(), tx.rollback(err)
			}
			ensureFRPServiceUnits("frps")
			if err := tx.start("frps"); err != nil {
				return outMsg.String(), tx.rollback(err)
			}
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
			if frpWant != "" {
				frpProto = frpWant
			}
			if ppVersion == "" {
				if data, err := os.ReadFile(filepath.Join(frpDir, "frpc.toml")); err == nil && strings.Contains(string(data), `proxyProtocolVersion = "v2"`) {
					ppVersion = "v2"
				}
			}
			pc := loadPerfConfig()
			if pc.ProxyProtocol != "" { // set in the Performance tab: it wins
				ppVersion = ""
				if pc.ProxyProtocol != "off" {
					ppVersion = pc.ProxyProtocol
				}
			}
			pc.ProxyProtocol = "" // written below as ppLine
			ppLine := ""
			if ppVersion != "" {
				ppLine = fmt.Sprintf("transport.proxyProtocolVersion = %q\n", ppVersion)
			}
			tcpExtra, udpExtra := frpcProxyExtras(pc, true), frpcProxyExtras(pc, false)
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
%stransport.heartbeatInterval = 15
transport.heartbeatTimeout = 45
transport.dialServerTimeout = 10
transport.dialServerKeepalive = 15
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
%s%s%s%s
[[proxies]]
name = "udp-%d"
type = "udp"
localIP = "127.0.0.1"
localPort = %d
remotePort = %d
%s`, p, p, p, ppLine, encLine, compLine, tcpExtra, p, p, p, udpExtra))
			}
			tx.backup(filepath.Join(frpDir, "frpc.toml"))
			if err := writeEngineFile(frpDir, "frpc.toml", frpcBuf.String()); err != nil {
				return outMsg.String(), tx.rollback(err)
			}
			ensureFRPServiceUnits("frpc")
			if err := tx.start("frpc"); err != nil {
				return outMsg.String(), tx.rollback(err)
			}
			outMsg.WriteString("frpc service configured and started with high-concurrency limits.\n")
		}

	case "backhaul", "gre-backhaul":
		overGre := targetEngine == "gre-backhaul"
		if overGre {
			if err := runSystemctl("restart", "gre-tunnel"); err != nil {
				return outMsg.String(), tx.rollback(fmt.Errorf("systemctl restart %s failed: %w", "gre-tunnel", err))
			}
		} else {
			// Standalone Backhaul (no GRE)
			_ = runSystemctl("stop", "gre-tunnel")
		}
		suffix := ""
		if overGre {
			suffix = " (over GRE)"
		}
		if isIran {
			conf := filepath.Join(backhaulDir, "config.toml")
			tx.backup(conf)
			if err := writeBackhaulServerConfig(conf, fmt.Sprintf("0.0.0.0:%d", port), targetTransport, token, rawPorts); err != nil {
				return outMsg.String(), tx.rollback(fmt.Errorf("write backhaul config: %w", err))
			}
			if err := tx.start("backhaul-server"); err != nil {
				return outMsg.String(), tx.rollback(err)
			}
			outMsg.WriteString("backhaul-server" + suffix + " configured and started.\n")
		} else {
			dial := remotePub
			if overGre {
				dial = peerGre
			}
			conf := filepath.Join(backhaulDir, "client.toml")
			tx.backup(conf)
			if err := writeBackhaulClientConfig(conf, hostPort(dial, port), targetTransport, token); err != nil {
				return outMsg.String(), tx.rollback(fmt.Errorf("write backhaul config: %w", err))
			}
			if err := tx.start("backhaul-client"); err != nil {
				return outMsg.String(), tx.rollback(err)
			}
			outMsg.WriteString("backhaul-client" + suffix + " configured and started.\n")
		}
	}

	// Fire-and-forget health test of the new engine; never delays the response.
	go runTunnelHealthOnce()

	return outMsg.String(), nil
}

// engineSyncFn is swappable so tests never call a real peer.
var engineSyncFn = syncEngineToPeer

// engineSyncNeeded: only the Iran side directs the foreign worker.
func engineSyncNeeded() bool {
	st := localStatus()
	return strings.Contains(strings.ToLower(st.Role), "iran") || st.Role == "master"
}

// engineSwitchServices are the units an engine switch may stop or start.
var engineSwitchServices = []string{"gre-tunnel", "frps", "frpc", "backhaul-server", "backhaul-client"}

var (
	// engineServiceActive reports whether a unit is running; swappable for tests.
	engineServiceActive = func(svc string) bool {
		out, err := runCmdTimeoutOut(5*time.Second, "systemctl", "is-active", svc+".service")
		return err == nil && strings.TrimSpace(string(out)) == "active"
	}
	// engineVerifyDelay is how long a new engine must stay up after its
	// restart: Type=simple units "start" fine and then exit on a bad config.
	engineVerifyDelay = 3 * time.Second
)

// engineSwitchTx records the state before an engine switch so it can be undone.
type engineSwitchTx struct {
	wasActive map[string]bool
	files     map[string][]byte // nil = file did not exist
	svcs      []string          // units the switch may touch; the first (GRE) is left running on rollback
}

func newEngineSwitchTx() *engineSwitchTx {
	return newUnitSwitchTx(engineSwitchServices)
}

// backup saves path's current content (once) before it is overwritten.
func (tx *engineSwitchTx) backup(path string) {
	if _, seen := tx.files[path]; seen {
		return
	}
	b, err := os.ReadFile(path)
	if err != nil {
		b = nil
	}
	tx.files[path] = b
}

// start restarts and enables svc, then checks it is still running.
func (tx *engineSwitchTx) start(svc string) error {
	if err := runSystemctl("restart", svc); err != nil {
		return fmt.Errorf("systemctl restart %s failed: %w", svc, err)
	}
	_ = runSystemctl("enable", svc)
	if engineVerifyDelay > 0 {
		time.Sleep(engineVerifyDelay)
	}
	if !engineServiceActive(svc) {
		return fmt.Errorf("%s exited right after restart (check its config with journalctl -u %s)", svc, svc)
	}
	return nil
}

// rollback restores the saved configs and restarts whatever ran before.
func (tx *engineSwitchTx) rollback(cause error) error {
	for _, s := range tx.svcs[1:] {
		_ = runSystemctl("stop", s)
	}
	for p, b := range tx.files {
		if b == nil {
			_ = os.Remove(p)
		} else {
			_ = writeTokenFile(p, b)
		}
	}
	restored := []string{}
	for _, s := range tx.svcs {
		if tx.wasActive[s] {
			_ = runSystemctl("restart", s)
			restored = append(restored, s)
		}
	}
	if len(restored) == 0 {
		return fmt.Errorf("%w; previous configs restored", cause)
	}
	return fmt.Errorf("%w; previous engine restored (%s)", cause, strings.Join(restored, ", "))
}

// writeEngineFile writes an engine config (mode 0600: it contains the token)
// and reports any failure instead of claiming success.
func writeEngineFile(dir, name, content string) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	if err := writeTokenFile(filepath.Join(dir, name), []byte(content)); err != nil {
		return fmt.Errorf("write %s: %w", filepath.Join(dir, name), err)
	}
	return nil
}

// writeTokenFile writes a file that holds a token (FRP/Backhaul configs) as
// 0600. os.WriteFile keeps the mode of an existing file, so older installs'
// 0644 configs are tightened with an explicit chmod.
func writeTokenFile(path string, data []byte) error {
	if err := os.WriteFile(path, data, 0600); err != nil {
		return err
	}
	return os.Chmod(path, 0600)
}

// ensureFRPServiceUnits enforces high-concurrency systemd limits (LimitNOFILE, TasksMax, Restart=always)
// to prevent connection drops under heavy concurrent load. FRP units keep
// CPUWeight=100 (below the panel's 200) so the UI stays responsive when the
// box is saturated (C2.6).
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
	if !strings.Contains(content, "CPUWeight=") {
		content = strings.Replace(content, "[Service]", "[Service]\nCPUWeight=100", 1)
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
