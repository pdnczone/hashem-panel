package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

type doctorReport struct {
	Timestamp       string          `json:"timestamp"`
	Role            string          `json:"role"`
	PeerGREIP       string          `json:"peer_gre_ip"`
	TunnelName      string          `json:"tunnel_name"`
	InterfaceUp     bool            `json:"interface_up"`
	FRPUp           bool            `json:"frp_up"`
	PingResult      pingSummary     `json:"ping_result"`
	MTUResult       mtuSummary      `json:"mtu_result"`
	KernelAudit     kernelAudit     `json:"kernel_audit"`
	SpeedResult     speedSummary    `json:"speed_result"`
	Score           int             `json:"score"`
	Rating          string          `json:"rating"` // "excellent", "good", "warning", "critical"
	Issues          []string        `json:"issues"`
	Recommendations []string        `json:"recommendations"`
	FixAvailable    bool            `json:"fix_available"`
	// RevPath is the cached read-only reverse-path diagnosis (never probes here).
	RevPath []revPathEntry `json:"revpath,omitempty"`
}

type pingSummary struct {
	Sent       int     `json:"sent"`
	Received   int     `json:"received"`
	PacketLoss float64 `json:"packet_loss"`
	MinRTT     float64 `json:"min_rtt"`
	AvgRTT     float64 `json:"avg_rtt"`
	MaxRTT     float64 `json:"max_rtt"`
	Jitter     float64 `json:"jitter"`
	Success    bool    `json:"success"`
}

type mtuSummary struct {
	MTU1420 bool `json:"mtu_1420"`
	MTU1400 bool `json:"mtu_1400"`
	MTU1360 bool `json:"mtu_1360"`
	Optimal int  `json:"optimal"`
}

type kernelAudit struct {
	BBREnabled    bool   `json:"bbr_enabled"`
	CongestionAlg string `json:"congestion_alg"`
	IPForwarding  bool   `json:"ip_forwarding"`
	MSSClamping   bool   `json:"mss_clamping"`
	LimitNOFILE   int    `json:"limit_nofile"`
	Somaxconn     int    `json:"somaxconn"`
	ConntrackMax  int    `json:"conntrack_max"`
	TCPTwReuse    bool   `json:"tcp_tw_reuse"`
}

type speedSummary struct {
	Tested         bool    `json:"tested"`
	ThroughputMbps float64 `json:"throughput_mbps"`
	Mode           string  `json:"mode"` // "iperf3", "http", "estimated"
	ServerActive   bool    `json:"server_active"`
	Detail         string  `json:"detail"`
}

type doctorPostRequest struct {
	Action string `json:"action"` // "run", "fix", "iperf-start", "iperf-stop"
}

var (
	lastDoctorMu     sync.RWMutex
	lastDoctorReport *doctorReport
)

func handleDoctorGet(w http.ResponseWriter, r *http.Request) {
	lastDoctorMu.RLock()
	rep := lastDoctorReport
	lastDoctorMu.RUnlock()

	if rep == nil {
		rep = runFullDiagnostics()
		lastDoctorMu.Lock()
		lastDoctorReport = rep
		lastDoctorMu.Unlock()
	}
	writeJSON(w, rep)
}

func handleDoctorPost(w http.ResponseWriter, r *http.Request) {
	var req doctorPostRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		req.Action = "run"
	}

	switch req.Action {
	case "run", "refresh":
		rep := runFullDiagnostics()
		lastDoctorMu.Lock()
		lastDoctorReport = rep
		lastDoctorMu.Unlock()
		writeJSON(w, rep)
	case "fix":
		res := applyFixesFn()
		// Re-run diagnostics after fix
		rep := runFullDiagnostics()
		lastDoctorMu.Lock()
		lastDoctorReport = rep
		lastDoctorMu.Unlock()
		writeJSON(w, map[string]any{
			"status": "ok",
			"fix":    res,
			"report": rep,
		})
	case "iperf-start":
		msg, err := startIperfServer()
		if err != nil {
			writeAPIError(w, r, "E-SYS-01", err.Error())
			return
		}
		writeJSON(w, map[string]string{"status": "ok", "message": msg})
	case "iperf-stop":
		msg, err := stopIperfServer()
		if err != nil {
			writeAPIError(w, r, "E-SYS-01", err.Error())
			return
		}
		writeJSON(w, map[string]string{"status": "ok", "message": msg})
	default:
		writeAPIError(w, r, "E-ACTION-01", "unknown doctor action: "+req.Action)
	}
}

func runFullDiagnostics() *doctorReport {
	st := localStatus()
	peerIP := peerOr(st)
	if peerIP == "" && st.Gre.Inner != "" {
		peerIP = grePeerInner(st.Gre.Inner)
	}

	rep := &doctorReport{
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		Role:        st.Role,
		PeerGREIP:   peerIP,
		TunnelName:  "gre-tunnel",
		InterfaceUp: st.Gre.Exists,
		FRPUp:       st.FrpUp,
		Score:       100,
		Rating:      "excellent",
		Issues:      []string{},
		Recommendations: []string{},
	}

	// 1. Check Interface & Service status
	if !rep.InterfaceUp {
		rep.Score = 0
		rep.Rating = "critical"
		rep.Issues = append(rep.Issues, "GRE tunnel interface is DOWN")
		rep.Recommendations = append(rep.Recommendations, "Restart GRE service via Tunnel tab or run 'hashem restart'")
		rep.FixAvailable = true
	} else if !rep.FRPUp {
		rep.Score -= 30
		rep.Issues = append(rep.Issues, "FRP reverse service is NOT active")
		rep.Recommendations = append(rep.Recommendations, "Restart FRP service via Tunnel tab")
		rep.FixAvailable = true
	}

	// 1b. frpc EOF on login = hub/spoke tcpMux mismatch (hint only, never auto-changed)
	if st.FrpSvc == "frpc" && frpcLoginEOF() {
		rep.Issues = append(rep.Issues, "frpc login fails with 'connect to server error: EOF'")
		rep.Recommendations = append(rep.Recommendations, errCatalog["E-FRP-10"].Hint)
	}

	// 2. Kernel sysctl & MSS Clamping Audit (always audited)
	rep.KernelAudit = executeKernelAudit()
	if !rep.KernelAudit.BBREnabled {
		rep.Score -= 15
		rep.Issues = append(rep.Issues, "TCP BBR congestion control is NOT active (running "+rep.KernelAudit.CongestionAlg+")")
		rep.Recommendations = append(rep.Recommendations, "Enable BBR congestion control for higher throughput on lossy networks")
		rep.FixAvailable = true
	}
	if !rep.KernelAudit.IPForwarding {
		rep.Score -= 15
		rep.Issues = append(rep.Issues, "IP Forwarding is disabled in kernel")
		rep.Recommendations = append(rep.Recommendations, "Enable net.ipv4.ip_forward in sysctl")
		rep.FixAvailable = true
	}
	if !rep.KernelAudit.MSSClamping {
		rep.Score -= 10
		rep.Issues = append(rep.Issues, "TCP MSS PMTU clamping rule missing in iptables")
		rep.Recommendations = append(rep.Recommendations, "Insert TCPMSS clamp rule to prevent TLS handshake freeze")
		rep.FixAvailable = true
	}
	if rep.KernelAudit.Somaxconn > 0 && rep.KernelAudit.Somaxconn < 8192 {
		rep.Score -= 10
		rep.Issues = append(rep.Issues, fmt.Sprintf("TCP listen backlog somaxconn is low (%d)", rep.KernelAudit.Somaxconn))
		rep.Recommendations = append(rep.Recommendations, "Apply network optimization to increase somaxconn to 65535 to prevent connection drops under load")
		rep.FixAvailable = true
	}
	if rep.KernelAudit.LimitNOFILE > 0 && rep.KernelAudit.LimitNOFILE < 65535 {
		rep.Score -= 10
		rep.Issues = append(rep.Issues, fmt.Sprintf("File descriptor limit (LimitNOFILE) is low (%d)", rep.KernelAudit.LimitNOFILE))
		rep.Recommendations = append(rep.Recommendations, "Increase LimitNOFILE to 1048576 to prevent EMFILE socket drop under high concurrency")
		rep.FixAvailable = true
	}

	// 3. Ping & Jitter
	if rep.PeerGREIP != "" && rep.InterfaceUp {
		rep.PingResult = executePing(rep.PeerGREIP, 10)
		if !rep.PingResult.Success || rep.PingResult.PacketLoss >= 100 {
			rep.Score -= 50
			rep.Issues = append(rep.Issues, "Peer internal IP is unreachable (100% packet loss)")
			rep.Recommendations = append(rep.Recommendations, "Verify that the other server's GRE tunnel is running and public IPs match")
		} else {
			if rep.PingResult.PacketLoss > 15 {
				rep.Score -= 25
				rep.Issues = append(rep.Issues, fmt.Sprintf("High packet loss: %.1f%%", rep.PingResult.PacketLoss))
				rep.Recommendations = append(rep.Recommendations, "Check carrier jitter or test with FOU UDP mode (Carrier tab)")
				rep.FixAvailable = true
			} else if rep.PingResult.PacketLoss > 2 {
				rep.Score -= 10
				rep.Issues = append(rep.Issues, fmt.Sprintf("Minor packet loss: %.1f%%", rep.PingResult.PacketLoss))
			}
			if rep.PingResult.Jitter > 25 {
				rep.Score -= 10
				rep.Issues = append(rep.Issues, fmt.Sprintf("High network jitter: %.1f ms", rep.PingResult.Jitter))
			}
		}
	} else if rep.PeerGREIP == "" {
		rep.Score = 20
		rep.Rating = "warning"
		rep.Issues = append(rep.Issues, "No GRE tunnel configured on this server")
		rep.Recommendations = append(rep.Recommendations, "Configure tunnel in Setup tab")
		return rep
	}

	// 4. Path MTU Discovery
	if rep.PeerGREIP != "" && rep.InterfaceUp && rep.PingResult.Success {
		rep.MTUResult = executeMTUTest(rep.PeerGREIP)
		if !rep.MTUResult.MTU1420 && !rep.MTUResult.MTU1400 {
			rep.Score -= 15
			rep.Issues = append(rep.Issues, "Strict MTU clamping required — 1400B packets are fragmented or dropped")
			rep.Recommendations = append(rep.Recommendations, "Apply TCP MSS clamping (1360B) to stop packet drops on mobile networks")
			rep.FixAvailable = true
		}
	}

	// 5. Throughput / Speed
	rep.SpeedResult = executeThroughputTest(rep.PeerGREIP, rep.InterfaceUp)

	rep.RevPath = revPathCached()

	// Final Score normalization
	if rep.Score < 0 {
		rep.Score = 0
	} else if rep.Score > 100 {
		rep.Score = 100
	}

	if rep.Score >= 90 {
		rep.Rating = "excellent"
	} else if rep.Score >= 75 {
		rep.Rating = "good"
	} else if rep.Score >= 50 {
		rep.Rating = "warning"
	} else {
		rep.Rating = "critical"
	}

	return rep
}

func executePing(ip string, count int) pingSummary {
	res := pingSummary{Sent: count}
	if ip == "" {
		return res
	}

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "ping", "-n", strconv.Itoa(count), ip)
	} else {
		cmd = exec.CommandContext(ctx, "ping", "-c", strconv.Itoa(count), "-i", "0.2", "-q", ip)
	}

	out, err := cmd.CombinedOutput()
	output := string(out)

	if runtime.GOOS != "windows" {
		// Linux ping parser
		// Example: 10 packets transmitted, 10 received, 0% packet loss, time 1812ms
		lossRe := regexp.MustCompile(`(\d+)% packet loss`)
		if m := lossRe.FindStringSubmatch(output); len(m) > 1 {
			loss, _ := strconv.ParseFloat(m[1], 64)
			res.PacketLoss = loss
		}
		rxRe := regexp.MustCompile(`(\d+) received`)
		if m := rxRe.FindStringSubmatch(output); len(m) > 1 {
			rx, _ := strconv.Atoi(m[1])
			res.Received = rx
		}
		// rtt min/avg/max/mdev = 32.140/35.210/41.800/2.840 ms
		rttRe := regexp.MustCompile(`rtt min/avg/max/mdev = ([0-9.]+)/([0-9.]+)/([0-9.]+)/([0-9.]+)`)
		if m := rttRe.FindStringSubmatch(output); len(m) > 4 {
			res.MinRTT, _ = strconv.ParseFloat(m[1], 64)
			res.AvgRTT, _ = strconv.ParseFloat(m[2], 64)
			res.MaxRTT, _ = strconv.ParseFloat(m[3], 64)
			res.Jitter, _ = strconv.ParseFloat(m[4], 64)
			res.Success = true
		} else if res.Received > 0 {
			res.Success = true
		}
	} else {
		// Mock/Windows ping parser
		if err == nil {
			res.Received = count
			res.PacketLoss = 0
			res.MinRTT = 30.0
			res.AvgRTT = 34.5
			res.MaxRTT = 40.0
			res.Jitter = 2.1
			res.Success = true
		}
	}

	return res
}

func executeMTUTest(ip string) mtuSummary {
	res := mtuSummary{Optimal: 1420}
	if runtime.GOOS == "windows" {
		res.MTU1420 = true
		res.MTU1400 = true
		res.MTU1360 = true
		res.Optimal = 1420
		return res
	}

	// 1420 MTU = 1392 payload + 28 header
	res.MTU1420 = pingWithDF(ip, 1392)
	// 1400 MTU = 1372 payload + 28 header
	res.MTU1400 = pingWithDF(ip, 1372)
	// 1360 MTU = 1332 payload + 28 header
	res.MTU1360 = pingWithDF(ip, 1332)

	if res.MTU1420 {
		res.Optimal = 1420
	} else if res.MTU1400 {
		res.Optimal = 1400
	} else {
		res.Optimal = 1360
	}
	return res
}

func pingWithDF(ip string, size int) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ping", "-c", "2", "-M", "do", "-s", strconv.Itoa(size), "-W", "1", ip)
	return cmd.Run() == nil
}

func executeKernelAudit() kernelAudit {
	res := kernelAudit{
		CongestionAlg: "unknown",
	}

	if runtime.GOOS == "windows" {
		res.BBREnabled = true
		res.CongestionAlg = "bbr"
		res.IPForwarding = true
		res.MSSClamping = true
		res.LimitNOFILE = 1048576
		res.Somaxconn = 65535
		res.ConntrackMax = 1048576
		res.TCPTwReuse = true
		return res
	}

	// 1. Congestion Alg
	if data, err := os.ReadFile("/proc/sys/net/ipv4/tcp_congestion_control"); err == nil {
		alg := strings.TrimSpace(string(data))
		res.CongestionAlg = alg
		if alg == "bbr" {
			res.BBREnabled = true
		}
	}

	// 2. IP Forwarding
	if data, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward"); err == nil {
		if strings.TrimSpace(string(data)) == "1" {
			res.IPForwarding = true
		}
	}

	// 3. MSS Clamping in iptables (clamp-to-pmtu or explicit set-mss 1340)
	cmd := exec.Command("iptables", "-t", "mangle", "-C", "FORWARD", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu")
	if cmd.Run() == nil {
		res.MSSClamping = true
	} else {
		// check iptables-save as fallback
		if out, err := exec.Command("iptables-save").CombinedOutput(); err == nil {
			if strings.Contains(string(out), "TCPMSS") {
				res.MSSClamping = true
			}
		}
	}

	// 4. Somaxconn (TCP listen backlog)
	if data, err := os.ReadFile("/proc/sys/net/core/somaxconn"); err == nil {
		if v, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil {
			res.Somaxconn = v
		}
	}

	// 5. Conntrack max
	if data, err := os.ReadFile("/proc/sys/net/netfilter/nf_conntrack_max"); err == nil {
		if v, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil {
			res.ConntrackMax = v
		}
	} else if data, err := os.ReadFile("/proc/sys/net/nf_conntrack_max"); err == nil {
		if v, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil {
			res.ConntrackMax = v
		}
	}

	// 6. TCP TIME_WAIT reuse
	if data, err := os.ReadFile("/proc/sys/net/ipv4/tcp_tw_reuse"); err == nil {
		if strings.TrimSpace(string(data)) == "1" {
			res.TCPTwReuse = true
		}
	}

	// 7. LimitNOFILE from process limits
	if data, err := os.ReadFile("/proc/self/limits"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "Max open files") {
				fields := strings.Fields(line)
				if len(fields) >= 5 {
					if v, err := strconv.Atoi(fields[3]); err == nil {
						res.LimitNOFILE = v
					}
				}
				break
			}
		}
	}

	return res
}

func executeThroughputTest(peerIP string, ifUp bool) speedSummary {
	res := speedSummary{
		Mode:   "iperf3",
		Detail: "Ready for benchmark",
	}

	// Check if local iperf3 server daemon is listening
	if isIperfServerRunning() {
		res.ServerActive = true
	}

	if !ifUp || peerIP == "" {
		res.Detail = "GRE tunnel offline — throughput test skipped"
		return res
	}

	if _, err := exec.LookPath("iperf3"); err != nil {
		res.Mode = "http"
		res.Detail = "iperf3 binary not installed on this host"
		return res
	}

	// Try iperf3 client test to peer IP on port 5201
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "iperf3", "-c", peerIP, "-t", "3", "-J")
	out, err := cmd.CombinedOutput()
	if err == nil {
		var iperfJSON struct {
			End struct {
				SumReceived struct {
					BitsPerSecond float64 `json:"bits_per_second"`
				} `json:"sum_received"`
			} `json:"end"`
		}
		if json.Unmarshal(out, &iperfJSON) == nil && iperfJSON.End.SumReceived.BitsPerSecond > 0 {
			res.Tested = true
			res.ThroughputMbps = float64(int((iperfJSON.End.SumReceived.BitsPerSecond/(1000*1000))*10)) / 10.0
			res.Detail = fmt.Sprintf("%.1f Mbps active speed via iperf3", res.ThroughputMbps)
			return res
		}
	}

	res.Detail = "iperf3 peer server not active. Start iperf server on peer or click 'Start iperf Server'."
	return res
}

func isIperfServerRunning() bool {
	if runtime.GOOS == "windows" {
		return false
	}
	// 1. Direct TCP probe on port 5201 (fastest & most accurate)
	conn, err := net.DialTimeout("tcp", "127.0.0.1:5201", 200*time.Millisecond)
	if err == nil {
		conn.Close()
		return true
	}
	// 2. Check pgrep if available
	if out, err := exec.Command("pgrep", "-x", "iperf3").CombinedOutput(); err == nil && len(strings.TrimSpace(string(out))) > 0 {
		return true
	}
	// 3. Check pidof if available
	if out, err := exec.Command("pidof", "iperf3").CombinedOutput(); err == nil && len(strings.TrimSpace(string(out))) > 0 {
		return true
	}
	return false
}

func startIperfServer() (string, error) {
	if runtime.GOOS == "windows" {
		return "Mock: iperf3 server started on :5201", nil
	}
	if isIperfServerRunning() {
		return "iperf3 server already running on port 5201", nil
	}

	// Ensure iperf3 is installed
	if _, err := exec.LookPath("iperf3"); err != nil {
		// Attempt automatic installation on Debian/Ubuntu
		_ = exec.Command("apt-get", "update", "-qq").Run()
		_ = exec.Command("apt-get", "install", "-y", "-qq", "iperf3").Run()
		if _, err := exec.LookPath("iperf3"); err != nil {
			return "", fmt.Errorf("iperf3 is not installed on this server. Run 'apt update && apt install -y iperf3'")
		}
	}

	// Launch iperf3 as daemon
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "iperf3", "-s", "-D")
	out, err := cmd.CombinedOutput()
	if err != nil {
		time.Sleep(250 * time.Millisecond)
		if isIperfServerRunning() {
			return "iperf3 server active on port 5201", nil
		}
		errMsg := strings.TrimSpace(string(out))
		if errMsg != "" {
			return "", fmt.Errorf("%s", errMsg)
		}
		return "", fmt.Errorf("failed to start iperf3: %w", err)
	}

	time.Sleep(250 * time.Millisecond)
	return "iperf3 daemon started on port 5201", nil
}

func stopIperfServer() (string, error) {
	if runtime.GOOS == "windows" {
		return "Mock: iperf3 server stopped", nil
	}
	_ = exec.Command("pkill", "-x", "iperf3").Run()
	_ = exec.Command("killall", "-9", "iperf3").Run()
	_ = exec.Command("fuser", "-k", "5201/tcp").Run()
	time.Sleep(200 * time.Millisecond)
	return "iperf3 daemon stopped", nil
}

// applyFixesFn is swappable so tests never run the real fixer (sysctl, iptables,
// installer optimize, gre-tunnel restart) on the machine running them.
var applyFixesFn = applyDoctorFixes

func applyDoctorFixes() map[string]any {
	fixes := []string{}

	if runtime.GOOS == "windows" {
		return map[string]any{
			"applied": []string{"Mock: BBR enabled", "Mock: TCPMSS clamp added"},
		}
	}

	// 1. Enable BBR & optimization via tuneViaInstaller
	if out, err := tuneViaInstaller("optimize"); err == nil {
		fixes = append(fixes, "Applied TCP BBR & sysctl optimization: "+out)
	}

	// 2. Ensure MSS Clamping rule
	cmd := exec.Command("iptables", "-t", "mangle", "-C", "FORWARD", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu")
	if cmd.Run() != nil {
		addCmd := exec.Command("iptables", "-t", "mangle", "-A", "FORWARD", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu")
		if err := addCmd.Run(); err == nil {
			fixes = append(fixes, "Inserted TCPMSS clamp-to-pmtu rule into iptables")
		}
	} else {
		fixes = append(fixes, "TCPMSS clamp-to-pmtu rule verified active")
	}

	// 3. Ensure IP Forwarding & socket sysctls
	_ = exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run()
	_ = exec.Command("sysctl", "-w", "net.core.somaxconn=65535").Run()
	_ = exec.Command("sysctl", "-w", "net.ipv4.tcp_tw_reuse=1").Run()
	fixes = append(fixes, "Enabled IPv4 packet forwarding & tuned socket limits (somaxconn=65535, tw_reuse=1)")

	// 4. Ensure FRP services have high-concurrency limits (LimitNOFILE 1M)
	ensureFRPServiceUnits("frps")
	ensureFRPServiceUnits("frpc")
	fixes = append(fixes, "Configured FRP systemd service limits (LimitNOFILE=1048576, LimitNPROC=512000, Restart=always)")

	// 5. Interface & routing health check
	st := localStatus()
	if !st.Gre.Exists {
		if err := exec.Command("systemctl", "restart", "gre-tunnel").Run(); err == nil {
			fixes = append(fixes, "Restarted gre-tunnel service to bring interface UP")
		}
	} else if !st.PingOK && st.Gre.PeerIP != "" {
		if err := exec.Command("systemctl", "restart", "gre-tunnel").Run(); err == nil {
			fixes = append(fixes, "Refreshed gre-tunnel routing and interface link")
		}
	}

	return map[string]any{
		"applied": fixes,
	}
}

// frpcLoginEOF reports whether the recent frpc journal shows the login EOF
// pattern that a hub/spoke tcpMux mismatch produces. Read-only.
func frpcLoginEOF() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "journalctl", "-u", "frpc", "-n", "50", "--no-pager").Output()
	if err != nil {
		return false
	}
	// only the newest login outcome counts: an old EOF followed by a successful login is a recovered tunnel
	lines := strings.Split(strings.ToLower(string(out)), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		switch {
		case strings.Contains(lines[i], "login to server success"):
			return false
		case strings.Contains(lines[i], "connect to server error: eof"):
			return true
		}
	}
	return false
}
