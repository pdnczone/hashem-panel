package main

// One definition of link health. The FRP/Backhaul control session (and the TCP
// round-trip time of that session) decides whether a link works; ICMP over the
// GRE inner address is metadata only. ComputeHealth is pure; the debouncer
// below is fed by the snapshot builder so the published state does not flap.

import (
	"fmt"
	"strings"
	"sync"
)

// LinkSignals are the raw observations about one hub -> spoke link. RTT values
// <= 0 mean "unknown". ICMPFresh says an ICMP measurement exists (ICMP is only
// refreshed in the background and is skipped while a session is live, so the
// cached result is reused); without one, ICMPOK=false means "not measured".
type LinkSignals struct {
	ServiceActive  bool
	Session        bool
	TCPRTTms       float64 // kernel RTT of the live control session
	ConnectRTTms   float64 // active TCP connect RTT (fallback)
	ICMPOK         bool
	ICMPms         float64
	ICMPFresh      bool
	GreIfUp        bool
	Rx, Tx         *uint64
	TrafficFlowing bool
	ReverseICMP    *bool // from the reverse-path doctor; nil = unknown
}

// LinkHealth is the verdict. State is "healthy" | "degraded" | "down".
type LinkHealth struct {
	State        string
	ICMPFiltered bool
	LatencyMs    float64 // -1 when unknown
	LatencyKind  string  // "tcp" | "icmp" | ""
	Reasons      []string
}

const (
	stateHealthy  = "healthy"
	stateDegraded = "degraded"
	stateDown     = "down"
)

func ComputeHealth(s LinkSignals) LinkHealth {
	h := LinkHealth{LatencyMs: -1}
	switch {
	case s.Session && s.TCPRTTms > 0:
		h.LatencyMs, h.LatencyKind = round1(s.TCPRTTms), "tcp"
	case s.ConnectRTTms > 0:
		h.LatencyMs, h.LatencyKind = round1(s.ConnectRTTms), "tcp"
	case s.ICMPOK:
		h.LatencyMs, h.LatencyKind = round1(s.ICMPms), "icmp"
	}
	switch {
	case s.Session:
		h.State = stateHealthy
		h.Reasons = append(h.Reasons, "control session is established")
		if s.ICMPFresh && !s.ICMPOK {
			h.ICMPFiltered = true
			h.Reasons = append(h.Reasons, "ICMP does not answer on this link (filtered); the TCP session is the health signal")
		}
	case s.ServiceActive && s.GreIfUp && s.ICMPOK:
		h.State = stateHealthy
		h.Reasons = append(h.Reasons, "service is active and the GRE peer answers ping (no control session seen)")
	case s.ServiceActive || s.GreIfUp:
		h.State = stateDegraded
		switch {
		case s.ServiceActive && !s.GreIfUp:
			h.Reasons = append(h.Reasons, "service is active but the GRE interface is not up")
		case s.GreIfUp && !s.ServiceActive:
			h.Reasons = append(h.Reasons, "GRE interface is up but the tunnel service is not active")
		default:
			h.Reasons = append(h.Reasons, "service and GRE interface are up but no client holds a control session")
		}
		if s.ConnectRTTms > 0 {
			h.Reasons = append(h.Reasons, fmt.Sprintf("peer host answers TCP (%.0f ms) but the client has not connected", s.ConnectRTTms))
		}
		if s.ICMPFresh && !s.ICMPOK {
			h.Reasons = append(h.Reasons, "ICMP does not answer")
		}
		if s.TrafficFlowing {
			h.Reasons = append(h.Reasons, "traffic is still flowing on the GRE interface")
		}
	default:
		h.State = stateDown
		h.Reasons = append(h.Reasons, "service is not active and the GRE interface is down")
	}
	if s.ReverseICMP != nil && !*s.ReverseICMP {
		h.Reasons = append(h.Reasons, "reverse-path ICMP fails (see Reverse Path diagnosis)")
	}
	return h
}

// signalsOf rebuilds LinkSignals from a live record, for callers (fleetHealth)
// that only hold a peerLive. ICMPFresh is inferred from the record itself.
func signalsOf(l peerLive) LinkSignals {
	return LinkSignals{
		ServiceActive: l.FrpUp, Session: l.FrpUp && l.Linked, ICMPOK: l.PingOK,
		ICMPFresh: l.ICMPKnown, GreIfUp: l.GreUp, Rx: l.Rx, Tx: l.Tx,
	}
}

// healthLevel maps a state name onto the fleet sample levels.
func healthLevel(state string) int {
	switch state {
	case stateHealthy:
		return fleetOK
	case stateDegraded:
		return fleetDeg
	}
	return fleetDown
}

// ---- debounce ----

// healthDebounceN is how many consecutive snapshots must agree on a new state
// before it is published (5 s snapshots => ~10 s).
const healthDebounceN = 2

type debState struct {
	published string
	reasons   []string
	cand      string
	n         int
}

type healthDebouncer struct {
	mu sync.Mutex
	m  map[int]*debState
}

func newHealthDebouncer() *healthDebouncer { return &healthDebouncer{m: map[int]*debState{}} }

// observe feeds one snapshot's raw verdict for a peer and returns the state and
// reasons to publish. The first observation publishes immediately; afterwards a
// different state is published only once healthDebounceN snapshots in a row
// agree on it. While a change is pending the previous reasons are kept so state
// and explanation never disagree.
func (d *healthDebouncer) observe(id int, raw LinkHealth) (string, []string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	st := d.m[id]
	if st == nil {
		d.m[id] = &debState{published: raw.State, reasons: raw.Reasons}
		return raw.State, raw.Reasons
	}
	switch {
	case raw.State == st.published:
		st.cand, st.n = "", 0
		st.reasons = raw.Reasons
	case raw.State == st.cand:
		st.n++
		if st.n >= healthDebounceN {
			st.published, st.reasons, st.cand, st.n = raw.State, raw.Reasons, "", 0
		}
	default:
		st.cand, st.n = raw.State, 1
		if st.n >= healthDebounceN {
			st.published, st.reasons, st.cand, st.n = raw.State, raw.Reasons, "", 0
		}
	}
	return st.published, st.reasons
}

// prune forgets peers that no longer exist.
func (d *healthDebouncer) prune(alive map[int]bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for id := range d.m {
		if !alive[id] {
			delete(d.m, id)
		}
	}
}

func reasonsText(r []string) string { return strings.Join(r, "; ") }
