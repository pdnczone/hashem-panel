package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type CarrierMetric struct {
	ID            string  `json:"id"`             // e.g. "direct", "fou:443", "fou:55555", "wss:8443", "backhaul:tcp"
	Name          string  `json:"name"`           // Friendly display name
	Type          string  `json:"type"`           // "gre", "fou", "wss", "backhaul", "frp"
	Port          int     `json:"port"`           // Port number (or 0 for raw)
	AvgRTTMs      float64 `json:"avg_rtt_ms"`     // Average RTT in milliseconds
	MinRTTMs      float64 `json:"min_rtt_ms"`     // Minimum RTT
	MaxRTTMs      float64 `json:"max_rtt_ms"`     // Maximum RTT
	PacketLoss    float64 `json:"packet_loss"`    // Percentage 0.0 - 100.0%
	JitterMs      float64 `json:"jitter_ms"`      // Jitter in milliseconds
	Score         int     `json:"score"`          // Health / performance score 0 - 100
	Status        string  `json:"status"`         // "healthy", "good", "warning", "critical", "down"
	IsActive      bool    `json:"is_active"`      // Currently active carrier
	IsRecommended bool    `json:"is_recommended"` // Recommended winner by benchmark
	ErrorDetail   string  `json:"error_detail,omitempty"`
}

type BenchmarkReport struct {
	Timestamp       string          `json:"timestamp"`
	DurationSec     float64         `json:"duration_sec"`
	TargetHost      string          `json:"target_host,omitempty"`
	TargetRole      string          `json:"target_role,omitempty"`
	PeerURL         string          `json:"peer_url"`
	PeerInternalIP  string          `json:"peer_internal_ip"`
	ActiveCarrier   string          `json:"active_carrier"`
	BestCarrier     string          `json:"best_carrier"`
	BestCarrierName string          `json:"best_carrier_name,omitempty"`
	AutoPilot       AutoPilotStatus `json:"auto_pilot"`
	Metrics         []CarrierMetric `json:"metrics"`
}

type AutoPilotStatus struct {
	Enabled       bool    `json:"enabled"`
	ThresholdLoss float64 `json:"threshold_loss"`
	LastTriggered string  `json:"last_triggered"`
	TriggerCount  int     `json:"trigger_count"`
}

type BenchmarkRunRequest struct {
	TargetHost   string `json:"target_host,omitempty"`
	TargetRole   string `json:"target_role,omitempty"`
	FrpPort      int    `json:"frp_port,omitempty"`
	WssPort      int    `json:"wss_port,omitempty"`
	SshPort      int    `json:"ssh_port,omitempty"`
	BackhaulPort int    `json:"backhaul_port,omitempty"`
}

type BenchmarkApplyRequest struct {
	Carrier string `json:"carrier"` // e.g. "fou:443"
}

type BenchmarkAutoPilotRequest struct {
	Enabled   *bool    `json:"enabled,omitempty"`
	Threshold *float64 `json:"threshold,omitempty"`
}

var (
	benchmarkMu           sync.RWMutex
	benchmarkRunning      atomic.Bool
	lastBenchmarkReport   *BenchmarkReport
	autoPilotTriggerCount int
	lastAutoPilotSwitch   string
)

func benchmarkReportFile() string {
	return filepath.Join(configDir, "benchmark_report.json")
}

func loadSavedBenchmarkReport() *BenchmarkReport {
	benchmarkMu.RLock()
	if lastBenchmarkReport != nil {
		defer benchmarkMu.RUnlock()
		return lastBenchmarkReport
	}
	benchmarkMu.RUnlock()

	data, err := os.ReadFile(benchmarkReportFile())
	if err == nil {
		var r BenchmarkReport
		if json.Unmarshal(data, &r) == nil {
			benchmarkMu.Lock()
			lastBenchmarkReport = &r
			benchmarkMu.Unlock()
			return &r
		}
	}
	return nil
}

func saveBenchmarkReport(r *BenchmarkReport) {
	benchmarkMu.Lock()
	lastBenchmarkReport = r
	benchmarkMu.Unlock()

	_ = os.MkdirAll(configDir, 0700)
	data, err := json.Marshal(r)
	if err == nil {
		tmpPath := benchmarkReportFile() + ".tmp"
		if err := os.WriteFile(tmpPath, data, 0600); err == nil {
			_ = os.Rename(tmpPath, benchmarkReportFile())
		}
	}
}

// calculateScore derives a 0..100 quality score based on loss, RTT, and jitter.
func calculateScore(loss, rtt, jitter float64) int {
	if loss >= 100.0 {
		return 0
	}
	// Base score 100
	// Loss has highest penalty (-1.5 per 1% loss)
	// RTT penalty (-0.15 per ms, capped at 300ms)
	// Jitter penalty (-0.2 per ms, capped at 100ms)
	effectiveRTT := rtt
	if effectiveRTT > 300 {
		effectiveRTT = 300
	}
	effectiveJitter := jitter
	if effectiveJitter > 100 {
		effectiveJitter = 100
	}

	raw := 100.0 - (loss * 1.5) - (effectiveRTT * 0.15) - (effectiveJitter * 0.2)
	if raw < 1 {
		raw = 1
	}
	if raw > 100 {
		raw = 100
	}
	return int(math.Round(raw))
}

// benchUnmeasured marks a carrier the benchmark cannot probe for real.
const benchUnmeasured = "unmeasured"

func determineStatus(score int, loss float64) string {
	if loss >= 100.0 || score == 0 {
		return "down"
	}
	if score >= 80 {
		return "healthy"
	}
	if score >= 60 {
		return "good"
	}
	if score >= 35 {
		return "warning"
	}
	return "critical"
}

// probeTCP attempts multiple TCP connections to measure latency and packet loss.
func probeTCP(ctx context.Context, addr string, count int, timeout time.Duration) (avgRTT, minRTT, maxRTT, loss, jitter float64, err error) {
	if count <= 0 {
		count = 3
	}
	var rtts []float64
	var failed int

	dialer := &net.Dialer{Timeout: timeout}

	for i := 0; i < count; i++ {
		if ctx.Err() != nil {
			failed += (count - i)
			break
		}
		start := time.Now()
		conn, dialErr := dialer.DialContext(ctx, "tcp", addr)
		if dialErr != nil {
			failed++
			continue
		}
		rtt := float64(time.Since(start).Microseconds()) / 1000.0
		_ = conn.Close()
		rtts = append(rtts, rtt)
	}

	loss = (float64(failed) / float64(count)) * 100.0
	if len(rtts) == 0 {
		return 0, 0, 0, 100.0, 0, fmt.Errorf("all %d probes failed to %s", count, addr)
	}

	minRTT = rtts[0]
	maxRTT = rtts[0]
	total := 0.0
	for _, r := range rtts {
		if r < minRTT {
			minRTT = r
		}
		if r > maxRTT {
			maxRTT = r
		}
		total += r
	}
	avgRTT = total / float64(len(rtts))

	if len(rtts) > 1 {
		var diffSum float64
		for i := 1; i < len(rtts); i++ {
			diffSum += math.Abs(rtts[i] - rtts[i-1])
		}
		jitter = diffSum / float64(len(rtts)-1)
	}

	return avgRTT, minRTT, maxRTT, loss, jitter, nil
}

// probeTLS attempts TLS handshakes to verify obfuscated WSS transport and measure RTT.
func probeTLS(ctx context.Context, addr string, count int, timeout time.Duration) (avgRTT, minRTT, maxRTT, loss, jitter float64, err error) {
	if count <= 0 {
		count = 3
	}
	var rtts []float64
	var failed int

	dialer := &net.Dialer{Timeout: timeout}
	// InsecureSkipVerify is intentional: this dial only measures handshake
	// latency to the carrier port and never sends or trusts any data.
	conf := &tls.Config{InsecureSkipVerify: true}

	for i := 0; i < count; i++ {
		if ctx.Err() != nil {
			failed += (count - i)
			break
		}
		start := time.Now()
		rawConn, dialErr := dialer.DialContext(ctx, "tcp", addr)
		if dialErr != nil {
			failed++
			continue
		}
		tlsConn := tls.Client(rawConn, conf)
		_ = tlsConn.SetDeadline(time.Now().Add(timeout))
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = rawConn.Close()
			failed++
			continue
		}
		rtt := float64(time.Since(start).Microseconds()) / 1000.0
		_ = tlsConn.Close()
		rtts = append(rtts, rtt)
	}

	loss = (float64(failed) / float64(count)) * 100.0
	if len(rtts) == 0 {
		return 0, 0, 0, 100.0, 0, fmt.Errorf("all %d TLS probes failed to %s", count, addr)
	}

	minRTT = rtts[0]
	maxRTT = rtts[0]
	total := 0.0
	for _, r := range rtts {
		if r < minRTT {
			minRTT = r
		}
		if r > maxRTT {
			maxRTT = r
		}
		total += r
	}
	avgRTT = total / float64(len(rtts))

	if len(rtts) > 1 {
		var diffSum float64
		for i := 1; i < len(rtts); i++ {
			diffSum += math.Abs(rtts[i] - rtts[i-1])
		}
		jitter = diffSum / float64(len(rtts)-1)
	}

	return avgRTT, minRTT, maxRTT, loss, jitter, nil
}

func probePing(ctx context.Context, host string, count int) (avgRTT, minRTT, maxRTT, loss, jitter float64, err error) {
	if host == "" {
		return 0, 0, 0, 100.0, 0, fmt.Errorf("empty host")
	}

	cmd := exec.CommandContext(ctx, "ping", "-c", strconv.Itoa(count), "-W", "2", host)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return 0, 0, 0, 100.0, 0, fmt.Errorf("ping failed: %v", err)
	}

	str := string(out)
	// Parse packet loss
	if idx := strings.Index(str, "% packet loss"); idx != -1 {
		part := str[:idx]
		if lastSpace := strings.LastIndex(part, " "); lastSpace != -1 {
			lossVal, _ := strconv.ParseFloat(strings.TrimSpace(part[lastSpace:]), 64)
			loss = lossVal
		}
	}

	// Parse rtt min/avg/max/mdev
	if idx := strings.Index(str, "rtt min/avg/max/mdev = "); idx != -1 {
		sub := str[idx+23:]
		if end := strings.Index(sub, " "); end != -1 {
			parts := strings.Split(sub[:end], "/")
			if len(parts) >= 4 {
				minRTT, _ = strconv.ParseFloat(parts[0], 64)
				avgRTT, _ = strconv.ParseFloat(parts[1], 64)
				maxRTT, _ = strconv.ParseFloat(parts[2], 64)
				jitter, _ = strconv.ParseFloat(parts[3], 64)
			}
		}
	} else {
		// No summary line: report nothing rather than an invented time.
		return 0, 0, 0, 100.0, 0, fmt.Errorf("ping gave no round-trip summary")
	}

	return avgRTT, minRTT, maxRTT, loss, jitter, nil
}

// runCarrierBenchmark probes all candidate carrier models and evaluates performance.
func runCarrierBenchmark(customReq ...BenchmarkRunRequest) *BenchmarkReport {
	if !benchmarkRunning.CompareAndSwap(false, true) {
		if rep := loadSavedBenchmarkReport(); rep != nil {
			return rep
		}
		return &BenchmarkReport{Timestamp: time.Now().Format("2006-01-02 15:04:05"), Metrics: []CarrierMetric{}}
	}
	defer benchmarkRunning.Store(false)

	startTime := time.Now()
	peerCfg := loadPeerConfig()
	carrierCfg := loadCarrierConfig()
	localSt := localStatus()

	activeCarrier := carrierCfg.ActiveCarrier
	if activeCarrier == "" {
		activeCarrier = "direct"
	}

	remotePub := localSt.Gre.PeerIP
	if remotePub == "" {
		for _, p := range loadPeers() {
			if p.RemotePub != "" {
				remotePub = p.RemotePub
				break
			}
		}
	}
	if remotePub == "" && peerCfg.PeerURL != "" {
		// Extract hostname/IP from PeerURL
		clean := strings.TrimPrefix(peerCfg.PeerURL, "http://")
		clean = strings.TrimPrefix(clean, "https://")
		if host, _, err := net.SplitHostPort(clean); err == nil {
			remotePub = host
		} else {
			remotePub = clean
		}
	}

	targetRole := localSt.Role
	if targetRole == "" {
		targetRole = "iran"
	}

	controlPort := localSt.FrpPort
	if controlPort <= 0 {
		controlPort = localSt.BindPort
	}
	if controlPort <= 0 {
		controlPort = 7000
	}

	wssPort := carrierCfg.WSSPort
	if wssPort <= 0 {
		wssPort = 8443
	}

	sshPort := 22
	backhaulPort := 3080

	if len(customReq) > 0 {
		req := customReq[0]
		if req.TargetRole != "" {
			targetRole = req.TargetRole
		}
		if req.TargetHost != "" {
			clean := strings.TrimSpace(req.TargetHost)
			clean = strings.TrimPrefix(clean, "http://")
			clean = strings.TrimPrefix(clean, "https://")
			if host, _, err := net.SplitHostPort(clean); err == nil {
				clean = host
			}
			if idx := strings.Index(clean, "/"); idx != -1 {
				clean = clean[:idx]
			}
			if clean != "" {
				remotePub = clean
			}
		}
		if req.FrpPort > 0 {
			controlPort = req.FrpPort
		}
		if req.WssPort > 0 {
			wssPort = req.WssPort
		}
		if req.SshPort > 0 {
			sshPort = req.SshPort
		}
		if req.BackhaulPort > 0 {
			backhaulPort = req.BackhaulPort
		}
	}

	if remotePub == "" {
		remotePub = "127.0.0.1"
	}

	// The peer's GRE inner address (localSt.GrePeer is its public one).
	grePeer := ""
	if localSt.Gre.Inner != "" {
		grePeer = grePeerInner(localSt.Gre.Inner)
	}
	if grePeer == "" {
		grePeer = peerCfg.InternalIP
	}
	if grePeer == "" {
		grePeer = "10.10.10.1"
	}

	quicPort := controlPort + 1
	if quicPort > 65535 {
		quicPort = controlPort - 1
	}

	candidates := []CarrierMetric{
		{
			ID:       "direct",
			Name:     "GRE Direct (Protocol 47)",
			Type:     "gre",
			Port:     0,
			IsActive: activeCarrier == "direct",
		},
		{
			ID:       "frp:tcp",
			Name:     fmt.Sprintf("FRP TCP Multiplexed (Port %d)", controlPort),
			Type:     "frp_tcp",
			Port:     controlPort,
			IsActive: strings.Contains(activeCarrier, "tcp") || activeCarrier == "frp",
		},
		{
			ID:       "frp:kcp",
			Name:     fmt.Sprintf("FRP KCP (UDP ARQ Anti-Loss %d)", controlPort),
			Type:     "frp_kcp",
			Port:     controlPort,
			IsActive: strings.Contains(activeCarrier, "kcp"),
		},
		{
			ID:       "frp:quic",
			Name:     fmt.Sprintf("FRP QUIC (UDP Stream %d)", quicPort),
			Type:     "frp_quic",
			Port:     quicPort,
			IsActive: strings.Contains(activeCarrier, "quic"),
		},
		{
			ID:       fmt.Sprintf("wss:%d", wssPort),
			Name:     fmt.Sprintf("FRP / Obfuscated WSS (TLS %d)", wssPort),
			Type:     "wss",
			Port:     wssPort,
			IsActive: strings.HasPrefix(activeCarrier, "wss"),
		},
		{
			ID:       fmt.Sprintf("backhaul:%d", backhaulPort),
			Name:     fmt.Sprintf("Backhaul Transport (Port %d)", backhaulPort),
			Type:     "backhaul",
			Port:     backhaulPort,
			IsActive: strings.Contains(activeCarrier, "backhaul"),
		},
		{
			ID:       fmt.Sprintf("bagher:%d", sshPort),
			Name:     fmt.Sprintf("Bagher Pro (SSH Tunnel %d)", sshPort),
			Type:     "bagher",
			Port:     sshPort,
			IsActive: strings.Contains(activeCarrier, "bagher") || strings.Contains(activeCarrier, "ssh"),
		},
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)

	for i := range candidates {
		wg.Add(1)
		sem <- struct{}{}
		go func(c *CarrierMetric) {
			defer wg.Done()
			defer func() { <-sem }()

			cctx, ccancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer ccancel()

			probeCount := 3
			timeout := 1500 * time.Millisecond

			switch c.Type {
			case "gre":
				// Measured results only: the old code invented numbers for a
				// loopback target, which ranked carriers that were never tested.
				avg, min, max, loss, jit, err := probePing(cctx, grePeer, probeCount)
				if err != nil {
					// Fallback probe to remote public IP if GRE link down
					avg, min, max, loss, jit, err = probePing(cctx, remotePub, probeCount)
				}
				c.AvgRTTMs = math.Round(avg*10) / 10
				c.MinRTTMs = math.Round(min*10) / 10
				c.MaxRTTMs = math.Round(max*10) / 10
				c.PacketLoss = math.Round(loss*10) / 10
				c.JitterMs = math.Round(jit*10) / 10
				if err != nil {
					c.ErrorDetail = err.Error()
				}

			case "wss":
				targetHost := remotePub
				addr := net.JoinHostPort(targetHost, strconv.Itoa(c.Port))
				avg, min, max, loss, jit, err := probeTLS(cctx, addr, probeCount, timeout)
				c.AvgRTTMs = math.Round(avg*10) / 10
				c.MinRTTMs = math.Round(min*10) / 10
				c.MaxRTTMs = math.Round(max*10) / 10
				c.PacketLoss = math.Round(loss*10) / 10
				c.JitterMs = math.Round(jit*10) / 10
				if err != nil {
					c.ErrorDetail = err.Error()
				}

			case "frp_kcp", "frp_quic":
				// A UDP "probe" without a protocol handshake always succeeds
				// (UDP is connectionless), so it measured nothing and always
				// won. Report these as unmeasured instead of inventing a score.
				c.Status = benchUnmeasured
				c.ErrorDetail = "not measurable without a KCP/QUIC handshake; switch to it only if TCP carriers are blocked"
				return

			case "frp_tcp", "frp_ws", "backhaul", "frp", "bagher":
				targetHost := remotePub
				addr := net.JoinHostPort(targetHost, strconv.Itoa(c.Port))
				avg, min, max, loss, jit, err := probeTCP(cctx, addr, probeCount, timeout)
				c.AvgRTTMs = math.Round(avg*10) / 10
				c.MinRTTMs = math.Round(min*10) / 10
				c.MaxRTTMs = math.Round(max*10) / 10
				c.PacketLoss = math.Round(loss*10) / 10
				c.JitterMs = math.Round(jit*10) / 10
				if err != nil {
					c.ErrorDetail = err.Error()
				}
			}

			c.Score = calculateScore(c.PacketLoss, c.AvgRTTMs, c.JitterMs)
			c.Status = determineStatus(c.Score, c.PacketLoss)
		}(&candidates[i])
	}
	wg.Wait()

	// Sort candidates by score descending
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].Score > candidates[j].Score
	})

	// Determine best recommended carrier
	// Only measured carriers can be recommended.
	bestCarrier := ""
	bestCarrierName := ""
	for i := range candidates {
		if candidates[i].Status == benchUnmeasured {
			continue
		}
		id := candidates[i].ID
		if id == "direct" || strings.HasPrefix(id, "wss:") || strings.HasPrefix(id, "frp:") || strings.HasPrefix(id, "backhaul:") || strings.HasPrefix(id, "bagher:") {
			if bestCarrier == "" && candidates[i].Score >= 10 {
				bestCarrier = id
				bestCarrierName = candidates[i].Name
				candidates[i].IsRecommended = true
				break
			}
		}
	}
	if bestCarrier == "" {
		for i := range candidates {
			if candidates[i].Status != benchUnmeasured {
				bestCarrier = candidates[i].ID
				bestCarrierName = candidates[i].Name
				candidates[i].IsRecommended = true
				break
			}
		}
	}

	duration := float64(time.Since(startTime).Milliseconds()) / 1000.0

	report := &BenchmarkReport{
		Timestamp:       time.Now().Format("2006-01-02 15:04:05"),
		DurationSec:     duration,
		TargetHost:      remotePub,
		TargetRole:      targetRole,
		PeerURL:         peerCfg.PeerURL,
		PeerInternalIP:  grePeer,
		ActiveCarrier:   activeCarrier,
		BestCarrier:     bestCarrier,
		BestCarrierName: bestCarrierName,
		AutoPilot: AutoPilotStatus{
			Enabled:       peerCfg.AutoPilotEnabled,
			ThresholdLoss: peerCfg.AutoPilotThreshold,
			LastTriggered: lastAutoPilotSwitch,
			TriggerCount:  autoPilotTriggerCount,
		},
		Metrics: candidates,
	}

	saveBenchmarkReport(report)

	// Check AutoPilot triggering
	// Automatic carrier switching is strictly disabled: carrier changes require manual user action.
	if peerCfg.AutoPilotEnabled && peerCfg.Role == "master" && bestCarrier != "" && bestCarrier != activeCarrier {
		// Find active carrier metric
		var activeLoss float64 = 100.0
		for _, m := range candidates {
			if m.IsActive {
				activeLoss = m.PacketLoss
				break
			}
		}

		if activeLoss >= peerCfg.AutoPilotThreshold {
			log.Printf("[AutoPilot] Active carrier %s has %.1f%% loss (threshold: %.1f%%). Best candidate: %s (automatic switching is disabled — carrier remains manual)",
				activeCarrier, activeLoss, peerCfg.AutoPilotThreshold, bestCarrier)
		}
	}

	return report
}

// applyBenchmarkCarrier applies the selected carrier locally and then on the
// Peer Link worker. It returns a short description of what was done.
func applyBenchmarkCarrier(target string) (string, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", fmt.Errorf("empty carrier target")
	}

	if err := carrierApplicable(target); err != nil {
		return "", err
	}
	prev := loadCarrierConfig().ActiveCarrier

	// 1. Apply locally first: if that fails nothing has changed anywhere. The
	// old order switched the peer first and then could fail here, leaving the
	// two ends on different carriers.
	out, err := applyCarrierMode(target)
	if err != nil && !strings.Contains(err.Error(), "script not found") {
		return "", fmt.Errorf("failed applying carrier %s locally: %v (%s)", target, err, out)
	}

	// 2. Then the peer. Both ends must match, so undo the local change when the
	// peer cannot follow. Without a Peer Link that ever connected there is
	// no peer to command: the admin applies the same carrier there.
	detail := "Synchronized and applied carrier: " + target
	if pc := loadPeerConfig(); pc.Role == "master" && pc.PeerSecret != "" && (pc.IsConnected || pc.LastSync != "") {
		if err := syncCarrierToPeer(target); err != nil {
			if prev != "" && prev != target {
				_, _ = applyCarrierMode(prev)
			}
			return "", fmt.Errorf("peer could not apply %s (%v); this server was switched back to %s", target, err, prev)
		}
	} else {
		detail = "Applied carrier " + target + " on this server only (no Peer Link): apply the same carrier on the other server"
	}

	// 3. Update report if loaded
	benchmarkMu.Lock()
	if lastBenchmarkReport != nil {
		lastBenchmarkReport.ActiveCarrier = target
		for i := range lastBenchmarkReport.Metrics {
			lastBenchmarkReport.Metrics[i].IsActive = lastBenchmarkReport.Metrics[i].ID == target
		}
	}
	benchmarkMu.Unlock()

	LogSecurityAudit("carrier_switched", "admin", "127.0.0.1", "target="+target)
	return detail, nil
}

// GET /api/benchmark
func handleBenchmarkGet(w http.ResponseWriter, r *http.Request) {
	if proRequired(w, r, proBenchmark, "The benchmark") {
		return
	}
	rep := loadSavedBenchmarkReport()
	if rep == nil {
		rep = runCarrierBenchmark()
	}
	writeJSON(w, rep)
}

// POST /api/benchmark/run
func handleBenchmarkRun(w http.ResponseWriter, r *http.Request) {
	if proRequired(w, r, proBenchmark, "The benchmark") {
		return
	}
	var req BenchmarkRunRequest
	if r.Body != nil && r.ContentLength > 0 {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}
	rep := runCarrierBenchmark(req)
	writeJSON(w, rep)
}

// POST /api/benchmark/apply
func handleBenchmarkApply(w http.ResponseWriter, r *http.Request) {
	if proRequired(w, r, proBenchmark, "The benchmark") {
		return
	}
	var req BenchmarkApplyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeAPIError(w, r, "E-ACTION-01", "invalid json")
		return
	}

	carrier := strings.TrimSpace(req.Carrier)
	if carrier == "" {
		writeAPIError(w, r, "E-ACTION-01", "carrier required")
		return
	}

	detail, err := applyBenchmarkCarrier(carrier)
	if err != nil {
		writeAPIError(w, r, "E-CARRIER-01", err.Error())
		return
	}

	writeJSON(w, map[string]any{
		"status":         "ok",
		"active_carrier": carrier,
		"detail":         detail,
	})
}

// POST /api/benchmark/autopilot
func handleBenchmarkAutoPilot(w http.ResponseWriter, r *http.Request) {
	if proRequired(w, r, proBenchmark, "The benchmark") {
		return
	}
	var req BenchmarkAutoPilotRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeAPIError(w, r, "E-ACTION-01", "invalid json")
		return
	}

	c := loadPeerConfig()
	if req.Enabled != nil {
		c.AutoPilotEnabled = *req.Enabled
		c.AutoPilotExplicit = true
	}
	if req.Threshold != nil && *req.Threshold > 0 {
		c.AutoPilotThreshold = *req.Threshold
	}

	if err := savePeerConfig(c); err != nil {
		writeAPIError(w, r, "E-ACTION-02", "failed to save autopilot settings")
		return
	}

	writeJSON(w, map[string]any{
		"status":              "ok",
		"autopilot_enabled":   c.AutoPilotEnabled,
		"autopilot_threshold": c.AutoPilotThreshold,
	})
}

// startAutoPilotMonitor runs a periodic check every 60s when AutoPilot is enabled.
func startAutoPilotMonitor() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		pcfg := loadPeerConfig()
		if pcfg.AutoPilotEnabled && pcfg.Role == "master" {
			if !benchmarkRunning.Load() {
				_ = runCarrierBenchmark()
			}
		}
	}
}
