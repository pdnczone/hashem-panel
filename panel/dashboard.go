package main

// Dashboard API: one JSON snapshot for the Dashboard tab.
// Every value is read live from the system; anything unavailable is null
// and the frontend renders it as N/A (never crashes).

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
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
	// Everything host-derived comes from the shared snapshot: this handler never forks.
	snap := currentSnapshot()
	setSnapshotAgeHeader(w, snap)
	st := snap.Local
	traffic := snap.Traffic
	if traffic == nil {
		traffic = greTraffic()
	}
	peers := snap.PeersAged()
	var bagherStatus map[string]any
	if snap != nil && snap.Bagher != nil {
		bagherStatus = snap.Bagher
	} else if flag.Lookup("test.v") == nil {
		bagherStatus = getSSHFwdStatus()
	}
	if bagherStatus == nil {
		bagherStatus = map[string]any{}
	}
	bagherActive := false
	if bAct, ok := bagherStatus["is_active"].(bool); ok && bAct {
		bagherActive = true
	} else if bConn, ok := bagherStatus["connected"].(bool); ok && bConn {
		bagherActive = true
	}

	// Rollup uses the same per-tunnel verdict as the fleet graph (fleetHealth):
	// a live FRP session is healthy even when the GRE inner address has no ping.
	// The main tunnel counts as one more spoke of the hub.
	anyUp := st.Gre.Exists || st.FrpUp || bagherActive
	health := "DOWN"
	var reasons []string
	icmpFiltered := false
	latMs, latKind := -1.0, ""
	all := snap.All()
	if len(all) > 0 {
		healthy, up := 0, 0
		anyUp = false
		total := len(all)
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
			if p.HealthState != stateHealthy {
				for _, rs := range p.Reasons {
					reasons = append(reasons, p.Name+": "+rs)
				}
			}
			icmpFiltered = icmpFiltered || p.ICMPFiltered
			if p.LatencyKind != "" && (latKind == "" || p.ID == mainTunnelID) {
				latMs, latKind = p.LatencyMs, p.LatencyKind
			}
		}
		if bagherActive {
			anyUp = true
			healthy++
			up++
			total++
		}
		switch {
		case healthy == total:
			health = "HEALTHY"
		case up > 0:
			health = "DEGRADED"
		}
	} else {
		pingMs := parsePingMs(st.PingMs)
		greConfigured := st.Gre.Exists || st.FrpUp
		if greConfigured {
			h := ComputeHealth(LinkSignals{
				ServiceActive: st.FrpUp, GreIfUp: st.Gre.Exists, Session: snap.LocalSession, TCPRTTms: snap.LocalRTT,
				ICMPOK: st.PingOK, ICMPms: pingMs, ICMPFresh: st.PingOK || snap.LocalSession,
			})
			health = map[string]string{stateHealthy: "HEALTHY", stateDegraded: "DEGRADED", stateDown: "DOWN"}[h.State]
			reasons, icmpFiltered, latMs, latKind = h.Reasons, h.ICMPFiltered, h.LatencyMs, h.LatencyKind
		} else if bagherActive {
			health = "HEALTHY"
			if bLat, ok := bagherStatus["latency_ms"].(float64); ok && bLat > 0 {
				latMs = bLat
				latKind = "bagher"
			}
		} else {
			health = "DOWN"
		}
	}
	if reasons == nil {
		reasons = []string{}
	}
	snapAt := ""
	if !snap.At.IsZero() {
		snapAt = snap.At.UTC().Format(time.RFC3339)
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
		"online":          anyUp,
		"health":          health,
		"peer_count":      len(peers),
		"peers":           peers,
		"ping_ok":         st.PingOK,
		"ping":            nilIfEmpty(st.PingMs),
		"health_state":    strings.ToLower(health),
		"icmp_filtered":   icmpFiltered,
		"reasons":         reasons,
		"latency_ms":      latMs,
		"latency_kind":    latKind,
		"snapshot_age_ms": snap.AgeMs(),
		"snapshot_at":     nilIfEmpty(snapAt),
		"role":            nilIfEmpty(st.Role),
		"local_pub":       nilIfEmpty(snap.PublicIP),
		"remote_pub":      nilIfEmpty(st.RemotePub),
		"active_engine":   engine,
		"active_carrier":  carrierCfg.ActiveCarrier,
		"auto_failover":   peerCfg.AutoPilotEnabled,
		"last_error":      lastErr,
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
		// when the counters (traffic, peers' rx/tx) were read: speeds in the
		// browser are bytes over the difference of two of these
		"counters_at": countersAtMs(snap),
		"main_name":   linkLabel("main"),
		"uptime":      uptimeInfo(snap.FrpSince),
		"system":      systemInfo(),
		"conns":       snap.ActiveConns,
		"bagher":      bagherStatus,
		"xray":        xrayDashLinks(snap),
		"checked":     time.Now().UTC().Format(time.RFC3339),
	}
	writeJSON(w, d)
}

// countersAtMs is the snapshot's counter reading time in unix ms (nil before
// the first snapshot).
func countersAtMs(s *HubSnapshot) any {
	if s == nil || s.CountersAt.IsZero() {
		return nil
	}
	return s.CountersAt.UnixMilli()
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

var (
	trafficStateMu   sync.Mutex
	lastRawUp        uint64
	lastRawDown      uint64
	lastRawIf        map[string][2]uint64 // per interface: received, transmitted
	lifetimeUp       uint64
	lifetimeDown     uint64
	trafficStateInit bool
	lastSampleAt     time.Time // when the counters of the last speed window were read
	lastStateSave    time.Time
	speedDeltaUp     uint64
	speedDeltaDown   uint64
	currentSpeedUp   float64
	currentSpeedDown float64
)

type persistentTrafficState struct {
	LifetimeUp    uint64 `json:"lifetime_up"`
	LifetimeDown  uint64 `json:"lifetime_down"`
	LifetimeTotal uint64 `json:"lifetime_total"`
	LastRawUp     uint64 `json:"last_raw_up"`
	LastRawDown   uint64 `json:"last_raw_down"`
	// LastIf: each interface's last raw counters, so the traffic it moved
	// while the panel was stopped (an update, a restart) is counted too.
	LastIf  map[string][2]uint64 `json:"last_if,omitempty"`
	SavedAt int64                `json:"saved_at"`
}

func trafficStateFile() string { return filepath.Join(configDir, "traffic_state.json") }

func loadTrafficStateLocked() {
	if trafficStateInit {
		return
	}
	trafficStateInit = true

	// 1. Try dedicated disk database state file
	if data, err := os.ReadFile(trafficStateFile()); err == nil {
		var st persistentTrafficState
		if json.Unmarshal(data, &st) == nil && (st.LifetimeUp > 0 || st.LifetimeDown > 0) {
			lifetimeUp = st.LifetimeUp
			lifetimeDown = st.LifetimeDown
			lastRawUp = st.LastRawUp
			lastRawDown = st.LastRawDown
			// The carrier chains are rebuilt (from 0) when the panel starts:
			// their old reading is no baseline.
			delete(st.LastIf, carrierKey)
			lastRawIf = st.LastIf
			return
		}
	}

	// 2. Fallback to latest sample in traffic.json history
	hist := loadHistory()
	for i := len(hist) - 1; i >= 0; i-- {
		if hist[i].Up != nil && hist[i].Down != nil {
			lifetimeUp = *hist[i].Up
			lifetimeDown = *hist[i].Down
			break
		}
	}
}

func saveTrafficStateLocked() {
	_ = os.MkdirAll(configDir, 0700)
	st := persistentTrafficState{
		LifetimeUp:    lifetimeUp,
		LifetimeDown:  lifetimeDown,
		LifetimeTotal: lifetimeUp + lifetimeDown,
		LastRawUp:     lastRawUp,
		LastRawDown:   lastRawDown,
		LastIf:        lastRawIf,
		SavedAt:       time.Now().Unix(),
	}
	b := mustJSON(st)
	tmp := trafficStateFile() + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err == nil {
		_ = os.Rename(tmp, trafficStateFile())
	}
	lastStateSave = time.Now()
}

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
	if strings.HasPrefix(ifname, "gre-") || strings.HasPrefix(ifname, "tun") || ifname == spoofIface {
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

// primaryInterface returns the default network interface from /proc/net/route.
func primaryInterface() string {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] == "00000000" && fields[0] != "lo" {
			return fields[0]
		}
	}
	return ""
}

// ---- traffic: rx/tx bytes summed across tunnel interfaces ----
// Every GRE (and WireGuard Spoof) interface, plus the port counters of the
// tunnels that have no interface (Backhaul without GRE, Bagher).

// greTraffic samples the counters now. The snapshot is the one regular
// sampler; this is for a dashboard request before the first snapshot.
func greTraffic() map[string]any {
	at := time.Now()
	data, _ := os.ReadFile("/proc/net/dev")
	rx, tx, ok := carrierCounters()
	return trafficSample(string(data), rx, tx, ok, at)
}

// greTrafficFrom is trafficSample with the carrier counters read now.
func greTrafficFrom(devData string) map[string]any {
	rx, tx, ok := carrierCounters()
	return trafficSample(devData, rx, tx, ok, time.Now())
}

// trafficTunnelIfs reads every tunnel interface's raw counters from a
// /proc/net/dev dump: [0] received (down), [1] transmitted (up).
func trafficTunnelIfs(devData string) map[string][2]uint64 {
	cur := map[string][2]uint64{}
	for _, line := range strings.Split(devData, "\n") {
		i := strings.Index(line, ":")
		if i < 0 {
			continue
		}
		ifname := strings.TrimSpace(line[:i])
		if !isTunnelInterface(ifname) {
			continue
		}
		f := strings.Fields(line[i+1:])
		if len(f) < 9 {
			continue
		}
		r, e1 := strconv.ParseUint(f[0], 10, 64)
		t, e2 := strconv.ParseUint(f[8], 10, 64)
		if e1 == nil && e2 == nil {
			cur[ifname] = [2]uint64{r, t}
		}
	}
	return cur
}

// trafficSample folds one reading of the counters, taken at at, into the
// lifetime totals and the live speed.
//
// Readings must arrive in time order. Two samplers used to share this state
// (the snapshot, with a /proc/net/dev read seconds earlier, and the history
// recorder, reading fresh): a stale reading looked like every counter had
// gone down, was taken for a reset, and each interface's whole counter was
// added to the total again. A reading older than the last one is now ignored.
//
// There is no fallback to the main network interface any more: with no
// tunnel it counted the whole server's traffic as tunnel traffic, and while a
// GRE interface was being recreated it counted the server's traffic for it.
func trafficSample(devData string, carrierRx, carrierTx uint64, carrierOK bool, at time.Time) map[string]any {
	cur := trafficTunnelIfs(devData)
	// Backhaul and Bagher have no interface: their port counters (carrier_traffic.go).
	if carrierOK {
		cur[carrierKey] = [2]uint64{carrierRx, carrierTx}
	}

	trafficStateMu.Lock()
	defer trafficStateMu.Unlock()

	first := !trafficStateInit
	if first {
		loadTrafficStateLocked()
	}
	if !lastSampleAt.IsZero() && at.Before(lastSampleAt) {
		return trafficResultLocked() // out of order: already counted past it
	}

	// Deltas are taken per interface. Comparing one summed counter made the
	// chart spike: when one of several tunnels dropped, the smaller sum was
	// taken for a counter reset and counted again. An interface seen for the
	// first time is only a baseline; one seen before this process started
	// (traffic_state.json) counts what it moved while the panel was down.
	var dU, dD, rawUp, rawDown uint64
	for name, c := range cur {
		rawDown += c[0]
		rawUp += c[1]
		prev, seen := lastRawIf[name]
		if !seen {
			continue
		}
		dD += counterDelta(prev[0], c[0])
		dU += counterDelta(prev[1], c[1])
	}
	lastRawIf = cur

	lifetimeUp += dU
	lifetimeDown += dD
	lastRawUp = rawUp
	lastRawDown = rawDown

	if (dU > 0 || dD > 0 || first) && time.Since(lastStateSave) >= 5*time.Second {
		saveTrafficStateLocked()
	}

	speedDeltaUp += dU
	speedDeltaDown += dD
	if lastSampleAt.IsZero() {
		speedDeltaUp, speedDeltaDown = 0, 0
		lastSampleAt = at
	} else if dt := at.Sub(lastSampleAt).Seconds(); dt >= 1.0 {
		currentSpeedUp = float64(speedDeltaUp) / dt
		currentSpeedDown = float64(speedDeltaDown) / dt
		speedDeltaUp, speedDeltaDown = 0, 0
		lastSampleAt = at
	}
	return trafficResultLocked()
}

// counterDelta is the bytes a counter moved from prev to cur. A counter
// below its last value was recreated (interface re-added, reboot, chains
// rebuilt): it counts from 0, so the new value is the traffic since then.
func counterDelta(prev, cur uint64) uint64 {
	if cur >= prev {
		return cur - prev
	}
	return cur
}

func trafficResultLocked() map[string]any {
	return map[string]any{
		"up":         lifetimeUp,
		"down":       lifetimeDown,
		"total":      lifetimeUp + lifetimeDown,
		"speed_up":   currentSpeedUp,
		"speed_down": currentSpeedDown,
	}
}

// ---- uptime: system + panel + frp service ----

func uptimeInfo(frpSince string) map[string]any {
	out := map[string]any{"system": nil, "panel": nil, "frp_since": nil}
	if data, err := os.ReadFile("/proc/uptime"); err == nil {
		if secs, err := strconv.ParseFloat(strings.Fields(string(data))[0], 64); err == nil {
			out["system"] = int64(secs)
		}
	}
	out["panel"] = int64(time.Since(panelStartedAt).Seconds())
	if frpSince != "" {
		out["frp_since"] = frpSince
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

// activeConnsCache: the four /proc/net tables are the kernel's slow path on a
// host with many sockets, and the snapshot and the history recorder both ask
// every 5s, so one reading serves for 30s.
var activeConnsCache struct {
	sync.Mutex
	root string
	at   time.Time
	v    any
}

func activeConns() any {
	c := &activeConnsCache
	c.Lock()
	defer c.Unlock()
	if c.root == procRoot && time.Since(c.at) < 30*time.Second {
		return c.v
	}
	c.root, c.at, c.v = procRoot, time.Now(), countActiveConns()
	return c.v
}

func countActiveConns() any {
	n := 0
	have := false
	for _, f := range []string{"net/tcp", "net/tcp6", "net/udp", "net/udp6"} {
		c, ok := countEstablished(filepath.Join(procRoot, f))
		if ok {
			have = true
			n += c
		}
	}
	if !have {
		return nil
	}
	return n
}

// countEstablished streams a /proc/net/{tcp,udp}[6] table and counts rows in
// state 01 (ESTABLISHED / connected UDP) without holding the file in memory.
func countEstablished(path string) (int, bool) {
	f, err := os.Open(path)
	if err != nil {
		return 0, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 4096), 64*1024)
	n := 0
	for first := true; sc.Scan(); {
		if first { // header row
			first = false
			continue
		}
		fields := strings.Fields(sc.Text())
		if len(fields) > 3 && fields[3] == "01" {
			n++
		}
	}
	return n, true
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
		var raw []trafficPoint
		if json.Unmarshal(data, &raw) == nil {
			var lastUp, lastDown uint64
			cleaned := make([]trafficPoint, 0, len(raw))
			for _, p := range raw {
				if p.Up == nil {
					u := lastUp
					p.Up = &u
				} else {
					lastUp = *p.Up
				}
				if p.Down == nil {
					d := lastDown
					p.Down = &d
				} else {
					lastDown = *p.Down
				}
				if p.Total == nil {
					tot := lastUp + lastDown
					p.Total = &tot
				}
				cleaned = append(cleaned, p)
			}
			histCached = cleaned
		}
	}
	if histCached == nil {
		histCached = []trafficPoint{}
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
	_ = os.MkdirAll(configDir, 0700)
	b := mustJSON(histCached)
	tmp := historyFile() + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err == nil {
		_ = os.Rename(tmp, historyFile())
	}
	histDirty = false
	lastFlushTime = time.Now()
}

func flushHistoryIfDirty() {
	histMu.Lock()
	defer histMu.Unlock()
	if histDirty {
		saveHistoryLocked()
	}
	trafficStateMu.Lock()
	saveTrafficStateLocked()
	trafficStateMu.Unlock()
}

// startTrafficRecorder runs 24/7 in the background, sampling every 5s
// and flushing to disk every 30s.
func startTrafficRecorder() {
	recorderOnce.Do(func() {
		go func() {
			histMu.Lock()
			loadHistory()
			histMu.Unlock()

			sampleTicker := time.NewTicker(5 * time.Second)
			defer sampleTicker.Stop()

			flushTicker := time.NewTicker(30 * time.Second)
			defer flushTicker.Stop()

			compactTicker := time.NewTicker(10 * time.Minute)
			defer compactTicker.Stop()

			for {
				select {
				case <-sampleTicker.C:
					// The snapshot's reading: a second sampler of the same
					// counters raced it (see trafficSample).
					t0 := time.Now()
					if snap := currentSnapshot(); snap != nil && snap.Traffic != nil && !snap.CountersAt.IsZero() {
						recordTrafficSampleAt(snap.Traffic, snap.CountersAt)
					}
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
	recordTrafficSampleAt(traffic, time.Now())
}

// recordTrafficSampleAt records a reading taken at at; the point carries
// that time, so a rate between two points is over the time the counters
// actually moved in.
func recordTrafficSampleAt(traffic map[string]any, at time.Time) {
	histMu.Lock()
	defer histMu.Unlock()
	hist := loadHistory()
	now := at.Unix()
	if n := len(hist); n > 0 && now-hist[n-1].T < 4 {
		return // the same snapshot, or one too close to the last point
	}
	pt := trafficPoint{T: now}
	if v, ok := traffic["up"].(uint64); ok {
		c := v
		pt.Up = &c
	} else {
		var z uint64 = 0
		pt.Up = &z
	}
	if v, ok := traffic["down"].(uint64); ok {
		c := v
		pt.Down = &c
	} else {
		var z uint64 = 0
		pt.Down = &z
	}
	if v, ok := traffic["total"].(uint64); ok {
		c := v
		pt.Total = &c
	} else {
		var z uint64 = 0
		pt.Total = &z
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
