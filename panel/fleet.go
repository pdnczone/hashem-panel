package main

// Fleet view: per-server health + a persisted ping history so the Tunnel tab
// can draw sparklines that survive page refreshes and are identical on every
// device. A single background sampler appends one point per peer every
// fleetSampleEvery; /api/fleet only reads that history (it never pings), so
// polling it is cheap and cannot slow the tunnels down.

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	fleetSampleEvery = 15 * time.Second
	fleetKeepSamples = 720 // 3h at 15s
	fleetFlushEvery  = 60 * time.Second
	fleetStatsWindow = 240 // last 1h drives sparkline + stats
)

// Sample health levels.
const (
	fleetDown = 0
	fleetDeg  = 1
	fleetOK   = 2
)

type fleetSample struct {
	T  int64   `json:"t"`  // unix seconds
	Ms float64 `json:"ms"` // round-trip ms, -1 = no answer
	S  int     `json:"s"`  // fleetDown | fleetDeg | fleetOK
}

type fleetStats struct {
	Samples int     `json:"samples"`
	AvgMs   float64 `json:"avg_ms"`
	MinMs   float64 `json:"min_ms"`
	MaxMs   float64 `json:"max_ms"`
	LossPct float64 `json:"loss_pct"`
	UpPct   float64 `json:"up_pct"`
}

type fleetNode struct {
	ID          int           `json:"id"`
	Name        string        `json:"name"`
	RemotePub   string        `json:"remote_pub"`
	Engine      string        `json:"engine"`
	Transport   string        `json:"transport"`
	Carrier     string        `json:"carrier"`
	GreUp       bool          `json:"gre_up"`
	FrpUp       bool          `json:"frp_up"`
	PingOK      bool          `json:"ping_ok"`
	PingMs      float64       `json:"ping_ms"`
	FrpOnly     bool          `json:"frp_only"`
	Linked      bool          `json:"linked"`
	LatencyMs   float64       `json:"latency_ms"`
	LatKind     string        `json:"latency_kind"`
	GreInner    string        `json:"gre_inner"`
	ControlPort int           `json:"control_port"`
	Main        bool          `json:"main"`
	Health      string        `json:"health"` // healthy | degraded | down
	HealthState string        `json:"health_state"`
	ICMPFilt    bool          `json:"icmp_filtered"`
	ICMPOK      bool          `json:"icmp_ok"`
	ICMPMs      float64       `json:"icmp_ms"`
	Reasons     []string      `json:"reasons"`
	SnapAgeMs   int64         `json:"snapshot_age_ms"`
	Rx          *uint64       `json:"rx"`
	Tx          *uint64       `json:"tx"`
	Ports       []int         `json:"ports"`
	History     []fleetSample `json:"history"`
	Stats       fleetStats    `json:"stats"`
}

var (
	fleetMu    sync.Mutex
	fleetHist  = map[int][]fleetSample{}
	fleetDirty bool
	fleetOnce  sync.Once
	fleetLoad  sync.Once
)

func fleetPath() string { return filepath.Join(configDir, "ping_history.json") }

func fleetLoadLocked() {
	fleetLoad.Do(func() {
		b, err := os.ReadFile(fleetPath())
		if err != nil {
			return
		}
		raw := map[string][]fleetSample{}
		if json.Unmarshal(b, &raw) != nil {
			return
		}
		for k, v := range raw {
			if id, err := strconv.Atoi(k); err == nil {
				if len(v) > fleetKeepSamples {
					v = v[len(v)-fleetKeepSamples:]
				}
				fleetHist[id] = v
			}
		}
	})
}

func fleetSaveLocked() {
	raw := make(map[string][]fleetSample, len(fleetHist))
	for id, v := range fleetHist {
		raw[strconv.Itoa(id)] = v
	}
	_ = os.MkdirAll(configDir, 0700)
	tmp := fleetPath() + ".tmp"
	if err := os.WriteFile(tmp, mustJSON(raw), 0600); err == nil {
		_ = os.Rename(tmp, fleetPath())
		fleetDirty = false
	}
}

// fleetFlushIfDirty persists the history only when a sample was added since the
// last write (the write itself is temp file + atomic rename).
func fleetFlushIfDirty() bool {
	fleetMu.Lock()
	defer fleetMu.Unlock()
	if !fleetDirty {
		return false
	}
	fleetSaveLocked()
	return true
}

func parsePingMs(s string) float64 {
	s = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(s), "ms"))
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || v < 0 {
		return -1
	}
	return v
}

// fleetHealth is the sample level of a live record. Snapshot-built records carry
// the published (debounced) state; others are computed by ComputeHealth, so
// there is one definition of health.
func fleetHealth(l peerLive) int {
	if l.HealthState != "" {
		return healthLevel(l.HealthState)
	}
	return healthLevel(ComputeHealth(signalsOf(l)).State)
}

func healthName(s int) string {
	switch s {
	case fleetOK:
		return "healthy"
	case fleetDeg:
		return "degraded"
	}
	return "down"
}

// fleetRecord appends one sample per live peer and drops history of peers
// that no longer exist.
func fleetRecord(peers []peerLive, now time.Time) {
	fleetMu.Lock()
	defer fleetMu.Unlock()
	fleetLoadLocked()
	alive := map[int]bool{}
	for _, p := range peers {
		alive[p.ID] = true
		ms := p.LatencyMs
		if p.LatencyKind == "" {
			ms = -1
			if p.PingOK {
				ms = parsePingMs(p.PingMs)
			}
		}
		h := append(fleetHist[p.ID], fleetSample{T: now.Unix(), Ms: ms, S: fleetHealth(p)})
		if len(h) > fleetKeepSamples {
			h = h[len(h)-fleetKeepSamples:]
		}
		fleetHist[p.ID] = h
	}
	for id := range fleetHist {
		if !alive[id] {
			delete(fleetHist, id)
		}
	}
	fleetDirty = true
}

func fleetCompute(h []fleetSample) fleetStats {
	var st fleetStats
	if len(h) == 0 {
		return st
	}
	st.Samples = len(h)
	var sum float64
	var n, loss, up int
	for _, s := range h {
		if s.S >= fleetDeg {
			up++
		}
		if s.Ms < 0 {
			// no latency is loss only when the link was not healthy: a healthy
			// link without a measurable RTT (ICMP filtered) is not loss.
			if s.S < fleetOK {
				loss++
			}
			continue
		}
		if n == 0 || s.Ms < st.MinMs {
			st.MinMs = s.Ms
		}
		if s.Ms > st.MaxMs {
			st.MaxMs = s.Ms
		}
		sum += s.Ms
		n++
	}
	if n > 0 {
		st.AvgMs = round1(sum / float64(n))
	}
	st.LossPct = round1(float64(loss) * 100 / float64(len(h)))
	st.UpPct = round1(float64(up) * 100 / float64(len(h)))
	return st
}

func round1(v float64) float64 { return float64(int(v*10+0.5)) / 10 }

// fleetSnapshot builds the API payload from the latest sample of each peer.
// Static fields come from the peer records; nothing here can leak tokens.
func fleetSnapshot(recs []peerRecord, live map[int]peerLive) []fleetNode {
	fleetMu.Lock()
	defer fleetMu.Unlock()
	fleetLoadLocked()
	out := make([]fleetNode, 0, len(recs))
	for _, r := range recs {
		h := fleetHist[r.ID]
		win := h
		if len(win) > fleetStatsWindow {
			win = win[len(win)-fleetStatsWindow:]
		}
		n := fleetNode{
			ID: r.ID, Name: r.Name, RemotePub: r.RemotePub, Engine: r.Engine,
			Transport: r.Transport, Carrier: r.Carrier, Ports: r.Ports, PingMs: -1,
			LatencyMs: -1, ControlPort: r.FrpPort,
			Health: "down", HealthState: "down", ICMPMs: -1, Reasons: []string{}, SnapAgeMs: -1, History: append([]fleetSample{}, win...), Stats: fleetCompute(win),
		}
		if n.Name == "" {
			n.Name = "peer-" + strconv.Itoa(r.ID)
		}
		n.Main = r.ID == mainTunnelID
		if n.Ports == nil {
			n.Ports = []int{}
		}
		if l, ok := live[r.ID]; ok {
			n.GreUp, n.FrpUp, n.PingOK, n.Rx, n.Tx = l.GreUp, l.FrpUp, l.PingOK, l.Rx, l.Tx
			n.FrpOnly, n.Linked, n.GreInner = l.FrpOnly, l.Linked, l.GreInner
			n.LatencyMs, n.LatKind = l.LatencyMs, l.LatencyKind
			if n.LatKind == "" {
				n.LatencyMs = -1
			}
			if l.PingOK {
				n.PingMs = parsePingMs(l.PingMs)
			}
			n.Health = healthName(fleetHealth(l))
			n.HealthState, n.ICMPFilt, n.ICMPOK, n.ICMPMs = n.Health, l.ICMPFiltered, l.ICMPOK, l.ICMPMs
			n.SnapAgeMs = l.SnapshotAgeMs
			if n.ICMPMs == 0 && !l.ICMPOK {
				n.ICMPMs = -1
			}
			n.Reasons = append([]string{}, l.Reasons...)
		} else if len(win) > 0 {
			last := win[len(win)-1]
			n.Health, n.PingOK, n.PingMs = healthName(last.S), last.Ms >= 0, last.Ms
			n.HealthState = n.Health
			n.LatencyMs = last.Ms
		}
		out = append(out, n)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func handleFleet(w http.ResponseWriter, r *http.Request) {
	snap := currentSnapshot()
	setSnapshotAgeHeader(w, snap)
	recs := loadPeers()
	all := snap.All()
	live := make(map[int]peerLive, len(all))
	for _, l := range all {
		live[l.ID] = l
	}
	// The main tunnel is just another spoke of the Iran hub.
	if m, ok := live[mainTunnelID]; ok {
		recs = append([]peerRecord{m.peerRecord}, recs...)
	}
	nodes := fleetSnapshot(recs, live)
	healthy, degraded, down := 0, 0, 0
	for _, n := range nodes {
		switch n.Health {
		case "healthy":
			healthy++
		case "degraded":
			degraded++
		default:
			down++
		}
	}
	snapAt := ""
	if !snap.At.IsZero() {
		snapAt = snap.At.UTC().Format(time.RFC3339)
	}
	writeJSON(w, map[string]any{
		"nodes": nodes, "count": len(nodes), "latency": hubLatency(nodes),
		"healthy": healthy, "degraded": degraded, "down": down,
		"interval_s":      int(fleetSampleEvery / time.Second),
		"hub":             nilIfEmpty(snap.PublicIP),
		"checked":         time.Now().UTC().Format(time.RFC3339),
		"snapshot_age_ms": snap.AgeMs(),
		"snapshot_at":     nilIfEmpty(snapAt),
	})
}

// detectPublicIPCached avoids a network lookup on every poll.
var (
	pubIPMu   sync.Mutex
	pubIPVal  string
	pubIPTime time.Time
)

func detectPublicIPCached() string {
	pubIPMu.Lock()
	defer pubIPMu.Unlock()
	if pubIPVal != "" && time.Since(pubIPTime) < 10*time.Minute {
		return pubIPVal
	}
	if pubIPVal == "" && time.Since(pubIPTime) < time.Minute {
		return "" // recent failed lookup: do not retry on every snapshot tick
	}
	pubIPTime = time.Now()
	if v := detectPublicIP(); v != "" {
		pubIPVal = v
	}
	return pubIPVal
}

func startFleetSampler() {
	fleetOnce.Do(func() {
		go func() {
			// The sampler only records the latest shared snapshot; it never
			// collects on its own.
			tick := func() {
				defer func(t time.Time) { recordSampler("fleetSampler", time.Since(t)) }(time.Now())
				fleetRecord(currentSnapshot().All(), time.Now())
			}
			tick()
			sample := time.NewTicker(fleetSampleEvery)
			flush := time.NewTicker(fleetFlushEvery)
			defer sample.Stop()
			defer flush.Stop()
			for {
				select {
				case <-sample.C:
					tick()
				case <-flush.C:
					fleetFlushIfDirty()
				}
			}
		}()
	})
}

// syncOnceReset returns a fresh sync.Once (tests reload history from disk).
func syncOnceReset() sync.Once { return sync.Once{} }

// mainTunnelID is the synthetic fleet id of the base (non-peer) tunnel. Peer
// ids start at 1, so 0 never collides.
const mainTunnelID = 0

type hubLat struct {
	Avg   float64 `json:"avg_ms"`
	Min   float64 `json:"min_ms"`
	Max   float64 `json:"max_ms"`
	Count int     `json:"count"` // links with a latency value
	ICMP  int     `json:"icmp"`
	TCP   int     `json:"tcp"`
}

// hubLatency summarises the hub -> servers latency over links that have a
// current value. Links with no value (down / no answer) are not counted.
func hubLatency(nodes []fleetNode) hubLat {
	var h hubLat
	sum := 0.0
	for _, n := range nodes {
		if n.LatencyMs < 0 || n.LatKind == "" {
			continue
		}
		if h.Count == 0 || n.LatencyMs < h.Min {
			h.Min = n.LatencyMs
		}
		if n.LatencyMs > h.Max {
			h.Max = n.LatencyMs
		}
		sum += n.LatencyMs
		h.Count++
		if n.LatKind == "icmp" {
			h.ICMP++
		} else {
			h.TCP++
		}
	}
	if h.Count > 0 {
		h.Avg = round1(sum / float64(h.Count))
		h.Min, h.Max = round1(h.Min), round1(h.Max)
	}
	return h
}
