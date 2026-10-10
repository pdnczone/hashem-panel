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

func parsePingMs(s string) float64 {
	s = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(s), "ms"))
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || v < 0 {
		return -1
	}
	return v
}

func fleetHealth(l peerLive) int {
	switch {
	case l.GreUp && l.FrpUp && l.PingOK:
		return fleetOK
	case l.FrpUp && l.Linked:
		// A live FRP session is the real service path: healthy even when the
		// GRE inner address does not answer ping (reported as "FRP only").
		return fleetOK
	case l.GreUp || l.FrpUp:
		return fleetDeg
	}
	return fleetDown
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
			loss++
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
			Health: "down", History: append([]fleetSample{}, win...), Stats: fleetCompute(win),
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
		} else if len(win) > 0 {
			last := win[len(win)-1]
			n.Health, n.PingOK, n.PingMs = healthName(last.S), last.Ms >= 0, last.Ms
			n.LatencyMs = last.Ms
		}
		out = append(out, n)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// lastLive caches the most recent sampler result so the API never pings.
var (
	lastLiveMu sync.Mutex
	lastLive   = map[int]peerLive{}
)

func fleetRemember(peers []peerLive) {
	m := make(map[int]peerLive, len(peers))
	for _, p := range peers {
		m[p.ID] = p
	}
	lastLiveMu.Lock()
	lastLive = m
	lastLiveMu.Unlock()
}

func handleFleet(w http.ResponseWriter, r *http.Request) {
	recs := loadPeers()
	lastLiveMu.Lock()
	live := make(map[int]peerLive, len(lastLive))
	for k, v := range lastLive {
		live[k] = v
	}
	lastLiveMu.Unlock()
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
	writeJSON(w, map[string]any{
		"nodes": nodes, "count": len(nodes), "latency": hubLatency(nodes),
		"healthy": healthy, "degraded": degraded, "down": down,
		"interval_s": int(fleetSampleEvery / time.Second),
		"hub":        nilIfEmpty(detectPublicIPCached()),
		"checked":    time.Now().UTC().Format(time.RFC3339),
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
	if v := detectPublicIP(); v != "" {
		pubIPVal, pubIPTime = v, time.Now()
	}
	return pubIPVal
}

func startFleetSampler() {
	fleetOnce.Do(func() {
		go func() {
			tick := func() {
				defer func(t time.Time) { recordSampler("fleetSampler", time.Since(t)) }(time.Now())
				peers := livePeers()
				if m := mainTunnelLive(); m != nil {
					peers = append([]peerLive{*m}, peers...)
				}
				fleetRemember(peers)
				fleetRecord(peers, time.Now())
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
					fleetMu.Lock()
					if fleetDirty {
						fleetSaveLocked()
					}
					fleetMu.Unlock()
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

// mainTunnelLive describes the base tunnel as a hub spoke, or nil when this
// machine is not an Iran hub or has no base tunnel configured.
func mainTunnelLive() *peerLive {
	st := localStatus()
	if !strings.HasPrefix(st.Role, "iran") || !(st.Gre.Exists || st.FrpUp || len(st.Proxies) > 0) {
		return nil
	}
	name := "Tunnel"
	if st.RemotePub != "" {
		name = "Tunnel · " + st.RemotePub
	}
	rec := peerRecord{ID: mainTunnelID, Name: name, RemotePub: st.RemotePub, Engine: st.Engine,
		Transport: st.Transport, FrpPort: st.BindPort, Ports: st.ProxyPorts}
	l := &peerLive{peerRecord: rec, GreUp: st.Gre.Exists, FrpUp: st.FrpUp, PingOK: st.PingOK, PingMs: st.PingMs,
		GreInner: st.Gre.Inner}
	var tcpRTT float64 = -1
	if st.FrpUp {
		l.Linked, tcpRTT = controlSession(st.BindPort)
	}
	l.FrpOnly = l.Linked && !l.PingOK
	l.LatencyMs, l.LatencyKind = pickLatency(l.PingOK, l.PingMs, tcpRTT)
	return l
}

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
