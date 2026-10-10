package main

// Dashboard API: one JSON snapshot for the Dashboard tab.
// Every value is read live from the system; anything unavailable is null
// and the frontend renders it as N/A (never crashes).

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

var panelStartedAt = time.Now()

// last CPU sample for delta-based usage %. First request returns N/A.
var (
	cpuMu   sync.Mutex
	cpuPrev cpuSample
	cpuHave bool
)

type cpuSample struct {
	idle  uint64
	total uint64
	when  time.Time
}

func handleDashboard(w http.ResponseWriter, r *http.Request) {
	st := localStatus()
	traffic := greTraffic()
	recordTrafficSample(traffic)
	peers := livePeers()
	// Rollup uses the same per-tunnel verdict as the fleet graph (fleetHealth):
	// a live FRP session is healthy even when the GRE inner address has no ping.
	// The main tunnel counts as one more spoke of the hub.
	anyUp := st.Gre.Exists || st.FrpUp
	health := "DOWN"
	all := peers
	if m := mainTunnelLive(); m != nil {
		all = append([]peerLive{*m}, peers...)
	}
	if len(all) > 0 {
		healthy, up := 0, 0
		anyUp = false
		for _, p := range all {
			if p.GreUp || p.FrpUp {
				anyUp = true
			}
			switch fleetHealth(p) {
			case fleetOK:
				healthy++
				up++
			case fleetDeg:
				up++
			}
		}
		switch {
		case healthy == len(all):
			health = "HEALTHY"
		case up > 0:
			health = "DEGRADED"
		}
	} else {
		if st.Gre.Exists && st.FrpUp && st.PingOK {
			health = "HEALTHY"
		} else if st.Gre.Exists || st.FrpUp {
			health = "DEGRADED"
		}
	}
	peerCfg := loadPeerConfig()
	carrierCfg := loadCarrierConfig()
	lastErr := lastErrorEvent()

	engine := st.Engine
	if engine == "" {
		if strings.HasPrefix(st.FrpSvc, "backhaul") {
			engine = "backhaul"
		} else if st.FrpSvc != "" {
			engine = "frp"
		} else {
			engine = "unknown"
		}
	}

	d := map[string]any{
		"online":         anyUp,
		"health":         health,
		"peer_count":     len(peers),
		"peers":          peers,
		"ping_ok":        st.PingOK,
		"ping":           nilIfEmpty(st.PingMs),
		"role":           nilIfEmpty(st.Role),
		"local_pub":      nilIfEmpty(detectPublicIP()),
		"active_engine":  engine,
		"active_carrier": carrierCfg.ActiveCarrier,
		"auto_failover":  peerCfg.AutoPilotEnabled,
		"last_error":     lastErr,
		"gre": map[string]any{
			"exists": st.Gre.Exists,
			"inner":  nilIfEmpty(st.Gre.Inner),
			"local":  nilIfEmpty(st.Gre.Local),
			"peer":   nilIfEmpty(peerOr(st)),
		},
		"frp": map[string]any{
			"up":          st.FrpUp,
			"svc":         nilIfEmpty(st.FrpSvc),
			"port":        nilIfZero(st.FrpPort),
			"proxies":     st.Proxies,
			"proxy_ports": st.ProxyPorts,
		},
		"traffic": traffic,
		"history": trafficHistory(r.URL.Query().Get("range")),
		"uptime":  uptimeInfo(st),
		"system":  systemInfo(),
		"conns":   activeConns(),
		"checked": time.Now().UTC().Format(time.RFC3339),
	}
	writeJSON(w, d)
}

func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nilIfZero(n int) any {
	if n == 0 {
		return nil
	}
	return n
}

func peerOr(st tunnelStatus) string {
	if st.Gre.PeerIP != "" {
		return st.Gre.PeerIP
	}
	return st.GrePeer
}

var trafficStateMu sync.Mutex
var lastRawUp, lastRawDown uint64
var lifetimeUp, lifetimeDown uint64
var trafficStateInit bool

var (
	peerIfsMu       sync.RWMutex
	peerIfsCache    map[string]bool
	peerIfsCacheExp time.Time
)

func getKnownPeerIfs() map[string]bool {
	peerIfsMu.RLock()
	if peerIfsCache != nil && time.Now().Before(peerIfsCacheExp) {
		res := peerIfsCache
		peerIfsMu.RUnlock()
		return res
	}
	peerIfsMu.RUnlock()

	peerIfsMu.Lock()
	defer peerIfsMu.Unlock()
	if peerIfsCache != nil && time.Now().Before(peerIfsCacheExp) {
		return peerIfsCache
	}
	m := make(map[string]bool)
	for _, q := range loadPeers() {
		if q.GreIf != "" {
			m[q.GreIf] = true
		}
	}
	peerIfsCache = m
	peerIfsCacheExp = time.Now().Add(10 * time.Second)
	return m
}

func invalidatePeerIfsCache() {
	peerIfsMu.Lock()
	peerIfsCache = nil
	peerIfsMu.Unlock()
}

// isTunnelInterface determines if an interface is a GRE or Backhaul tunnel.
func isTunnelInterface(ifname string) bool {
	if ifname == "lo" || ifname == "gre0" || ifname == "gretap0" || ifname == "erspan0" {
		return false
	}
	if strings.HasPrefix(ifname, "docker") || strings.HasPrefix(ifname, "veth") ||
		strings.HasPrefix(ifname, "br-") || strings.HasPrefix(ifname, "dummy") ||
		strings.HasPrefix(ifname, "eth") || strings.HasPrefix(ifname, "ens") ||
		strings.HasPrefix(ifname, "enp") || strings.HasPrefix(ifname, "wl") {
		return false
	}
	if strings.HasPrefix(ifname, "gre-") || strings.HasPrefix(ifname, "tun") {
		return true
	}
	known := getKnownPeerIfs()
	if known[ifname] {
		return true
	}
	if data, err := os.ReadFile(filepath.Join("/sys/class/net", ifname, "type")); err == nil {
		t := strings.TrimSpace(string(data))
		if t == "778" || t == "823" {
			return true
		}
	}
	return false
}

// ---- traffic: rx/tx bytes summed across tunnel interfaces ----
// Multi-peer: sum counters of every registered GRE and Backhaul interface.
func greTraffic() map[string]any {
	var rawUp, rawDown uint64
	var have bool

	data, err := os.ReadFile("/proc/net/dev")
	if err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if !strings.Contains(line, ":") {
				continue
			}
			ifname := strings.TrimSpace(strings.Split(line, ":")[0])
			if !isTunnelInterface(ifname) {
				continue
			}
			f := strings.Fields(strings.TrimPrefix(line, ifname+":"))
			if len(f) < 9 {
				continue
			}
			var r, t uint64
			if _, err := fmt.Sscanf(f[0], "%d", &r); err == nil {
				rawDown += r
			}
			if _, err := fmt.Sscanf(f[8], "%d", &t); err == nil {
				rawUp += t
			}
			have = true
		}
	}

	if !have {
		return map[string]any{"up": nil, "down": nil, "total": nil}
	}

	trafficStateMu.Lock()
	defer trafficStateMu.Unlock()

	if !trafficStateInit {
		hist := loadHistory()
		if len(hist) > 0 {
			last := hist[len(hist)-1]
			if last.Up != nil {
				lifetimeUp = *last.Up
			}
			if last.Down != nil {
				lifetimeDown = *last.Down
			}
		}
		lastRawUp = rawUp
		lastRawDown = rawDown
		trafficStateInit = true
	}

	dU := rawUp
	if rawUp >= lastRawUp {
		dU = rawUp - lastRawUp
	}
	dD := rawDown
	if rawDown >= lastRawDown {
		dD = rawDown - lastRawDown
	}

	lifetimeUp += dU
	lifetimeDown += dD
	lastRawUp = rawUp
	lastRawDown = rawDown

	return map[string]any{"up": lifetimeUp, "down": lifetimeDown, "total": lifetimeUp + lifetimeDown}
}

// ---- uptime: system + panel + frp service ----

func uptimeInfo(st tunnelStatus) map[string]any {
	out := map[string]any{"system": nil, "panel": nil, "frp_since": nil}
	if data, err := os.ReadFile("/proc/uptime"); err == nil {
		if secs, err := strconv.ParseFloat(strings.Fields(string(data))[0], 64); err == nil {
			out["system"] = int64(secs)
		}
	}
	out["panel"] = int64(time.Since(panelStartedAt).Seconds())
	if st.FrpSvc != "" {
		if ts, err := exec.Command("systemctl", "show", st.FrpSvc,
			"-p", "ActiveEnterTimestamp", "--value").CombinedOutput(); err == nil {
			if s := strings.TrimSpace(string(ts)); s != "" && s != "n/a" {
				out["frp_since"] = s
			}
		}
	}
	return out
}

// ---- system: cpu %, mem, disk, load ----

func systemInfo() map[string]any {
	return map[string]any{
		"cpu_pct":  cpuPct(),
		"load":     loadAvg(),
		"cores":    runtime.NumCPU(),
		"mem":      memInfo(),
		"disk_pct": diskPct("/"),
	}
}

func loadAvg() any {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return nil
	}
	f := strings.Fields(string(data))
	if len(f) < 3 {
		return nil
	}
	return strings.Join(f[:3], " ")
}

// memInfo reports RAM usage the way operators expect: real process memory
// plus reclaimable page cache (file cache the kernel frees on demand) is
// excluded — "used" stays honest while "cache" is shown separately so the
// dashboard never looks alarming on a healthy machine.
func memInfo() map[string]any {
	out := map[string]any{"used": nil, "total": nil, "pct": nil, "cache": nil}
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return out
	}
	var total, avail, cached, buffers, sreclaim uint64
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		v, err := strconv.ParseUint(f[1], 10, 64)
		if err != nil {
			continue
		}
		switch f[0] {
		case "MemTotal:":
			total = v * 1024
		case "MemAvailable:":
			avail = v * 1024
		case "Cached:":
			cached = v * 1024
		case "Buffers:":
			buffers = v * 1024
		case "SReclaimable:":
			sreclaim = v * 1024
		}
	}
	if total == 0 {
		return out
	}
	cache := cached + buffers + sreclaim
	used := total - avail
	out["used"] = used
	out["total"] = total
	out["pct"] = fmt.Sprintf("%.1f", float64(used)*100/float64(total))
	out["cache"] = cache
	return out
}

func diskPct(path string) any {
	total, free, err := getDiskUsage(path)
	if err != nil || total == 0 {
		return nil
	}
	used := total - free
	return fmt.Sprintf("%.1f", float64(used)*100/float64(total))
}

// cpuPct reads /proc/stat and compares with the previous sample.
func cpuPct() any {
	cur, ok := readCPU()
	if !ok {
		return nil
	}
	cpuMu.Lock()
	defer cpuMu.Unlock()
	if !cpuHave {
		cpuPrev, cpuHave = cur, true
		return nil
	}
	dTotal := cur.total - cpuPrev.total
	dIdle := cur.idle - cpuPrev.idle
	cpuPrev = cur
	if dTotal == 0 {
		return nil
	}
	return fmt.Sprintf("%.1f", float64(dTotal-dIdle)*100/float64(dTotal))
}

func readCPU() (cpuSample, bool) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return cpuSample{}, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		f := strings.Fields(line)[1:]
		if len(f) < 5 {
			return cpuSample{}, false
		}
		nums := make([]uint64, len(f))
		for i, s := range f {
			v, err := strconv.ParseUint(s, 10, 64)
			if err != nil {
				return cpuSample{}, false
			}
			nums[i] = v
		}
		var total uint64
		for _, v := range nums {
			total += v
		}
		idle := nums[3]
		if len(nums) > 4 {
			idle += nums[4] // iowait counts as idle
		}
		return cpuSample{idle: idle, total: total, when: time.Now()}, true
	}
	return cpuSample{}, false
}

// ---- connections: established TCP/UDP via ss ----

func activeConns() any {
	out, err := runCmdTimeout(5*time.Second, "ss", "-tun", "state", "established")
	if err != nil {
		return nil
	}
	n := 0
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Netid") {
			continue
		}
		n++
	}
	// ss always prints a header; n counts real connections.
	return n
}

// ---- traffic history: cumulative rx/tx sampled into a ring on disk ----

type trafficPoint struct {
	T     int64   `json:"t"`
	Up    *uint64 `json:"up"`
	Down  *uint64 `json:"down"`
	Total *uint64 `json:"total"`
	Conns *int    `json:"conns"`
}

var (
	histMu        sync.Mutex
	histCached    []trafficPoint
	histLoaded    bool
	histDirty     bool
	lastFlushTime time.Time
	recorderOnce  sync.Once
)

func historyFile() string { return filepath.Join(configDir, "traffic.json") }

func loadHistory() []trafficPoint {
	if histLoaded {
		return histCached
	}
	histLoaded = true
	data, err := os.ReadFile(historyFile())
	if err == nil {
		_ = json.Unmarshal(data, &histCached)
	}
	return histCached
}

// compactHistoryLocked applies tiered downsampling to keep traffic.json lightweight:
// - Samples <= 24 hours: preserved at full 5-second fidelity.
// - Samples 24h .. 7 days: compact to 1-minute intervals.
// - Samples 7d .. 90 days: compact to 5-minute intervals.
// - Samples > 90 days: discarded.
func compactHistoryLocked(now int64) {
	if len(histCached) == 0 {
		return
	}
	cutoff90d := now - 90*86400
	cutoff7d := now - 7*86400
	cutoff24h := now - 86400

	var compacted []trafficPoint
	var lastBucket5m int64 = -1
	var lastBucket1m int64 = -1

	for _, p := range histCached {
		if p.T < cutoff90d {
			continue
		}
		if p.T < cutoff7d {
			bucket := p.T / 300 // 5m buckets
			if bucket == lastBucket5m {
				continue
			}
			lastBucket5m = bucket
			compacted = append(compacted, p)
		} else if p.T < cutoff24h {
			bucket := p.T / 60 // 1m buckets
			if bucket == lastBucket1m {
				continue
			}
			lastBucket1m = bucket
			compacted = append(compacted, p)
		} else {
			compacted = append(compacted, p)
		}
	}
	histCached = compacted
}

func saveHistoryLocked() {
	if histCached == nil {
		return
	}
	compactHistoryLocked(time.Now().Unix())
	_ = os.WriteFile(historyFile(), mustJSON(histCached), 0600)
	histDirty = false
	lastFlushTime = time.Now()
}

func flushHistoryIfDirty() {
	histMu.Lock()
	defer histMu.Unlock()
	if histDirty {
		saveHistoryLocked()
	}
}

// startTrafficRecorder runs 24/7 in the background, sampling every 5s
// and flushing to disk every 30s.
func startTrafficRecorder() {
	recorderOnce.Do(func() {
		go func() {
			histMu.Lock()
			loadHistory()
			histMu.Unlock()

			// Initial sample
			recordTrafficSample(greTraffic())

			sampleTicker := time.NewTicker(5 * time.Second)
			defer sampleTicker.Stop()

			flushTicker := time.NewTicker(30 * time.Second)
			defer flushTicker.Stop()

			compactTicker := time.NewTicker(10 * time.Minute)
			defer compactTicker.Stop()

			for {
				select {
				case <-sampleTicker.C:
					t0 := time.Now()
					traffic := greTraffic()
					recordTrafficSample(traffic)
					recordSampler("trafficRecorder", time.Since(t0))
				case <-flushTicker.C:
					flushHistoryIfDirty()
				case <-compactTicker.C:
					histMu.Lock()
					compactHistoryLocked(time.Now().Unix())
					histDirty = true
					saveHistoryLocked()
					histMu.Unlock()
				}
			}
		}()
	})
}

// recordTrafficSample appends one point per sample (5s). Points are
// cumulative counters, so rate = delta between neighbours. Cap 90 days.
func recordTrafficSample(traffic map[string]any) {
	histMu.Lock()
	defer histMu.Unlock()
	hist := loadHistory()
	now := time.Now().Unix()
	if n := len(hist); n > 0 && now-hist[n-1].T < 4 {
		return // same poll, don't double-record
	}
	pt := trafficPoint{T: now}
	if v, ok := traffic["up"].(uint64); ok {
		c := v
		pt.Up = &c
	}
	if v, ok := traffic["down"].(uint64); ok {
		c := v
		pt.Down = &c
	}
	if v, ok := traffic["total"].(uint64); ok {
		c := v
		pt.Total = &c
	}
	if v, ok := activeConns().(int); ok {
		c := v
		pt.Conns = &c
	}
	hist = append(hist, pt)
	cutoff := now - 90*86400
	i := 0
	for i < len(hist) && hist[i].T < cutoff {
		i++
	}
	if i > 0 {
		hist = append([]trafficPoint(nil), hist[i:]...)
	}
	histCached = hist
	histDirty = true

	// If history is small (initial start), save immediately so it's not lost
	if len(histCached) <= 5 || time.Since(lastFlushTime) >= 30*time.Second {
		saveHistoryLocked()
	}
}

// trafficHistory returns downsampled points for range=1h|24h|7d|30d|90d.
// Default 24h. Missing interface (tunnel down) yields gaps: null values.
func trafficHistory(rng string) []trafficPoint {
	histMu.Lock()
	defer histMu.Unlock()
	hist := loadHistory()
	now := time.Now().Unix()
	span := int64(24 * 3600)
	switch rng {
	case "1h":
		span = 3600
	case "7d":
		span = 7 * 86400
	case "30d":
		span = 30 * 86400
	case "90d":
		span = 90 * 86400
	}
	cutoff := now - span
	var in []trafficPoint
	for _, p := range hist {
		if p.T >= cutoff {
			in = append(in, p)
		}
	}
	maxPts := 240
	if len(in) <= maxPts {
		if in == nil {
			return []trafficPoint{}
		}
		return in
	}
	step := float64(len(in)-1) / float64(maxPts-1)
	out := make([]trafficPoint, 0, maxPts)
	for i := 0; i < maxPts-1; i++ {
		idx := int(float64(i) * step)
		if idx >= len(in) {
			idx = len(in) - 1
		}
		out = append(out, in[idx])
	}
	out = append(out, in[len(in)-1])
	return out
}

