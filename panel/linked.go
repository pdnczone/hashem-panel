package main

import (
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ssSession is one ESTABLISHED TCP session from `ss -Htin`.
type ssSession struct {
	LPort int
	RHost string
	RPort int
	RTTms float64 // kernel smoothed RTT; -1 when ss did not report one
}

// parseSS parses `ss -Htin state established` output. Each session is a
// header line (Recv-Q Send-Q Local Peer) optionally followed by an indented
// info line carrying "rtt:<srtt>/<var>".
func parseSS(out string) []ssSession {
	var res []ssSession
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			if len(res) == 0 {
				continue
			}
			if i := strings.Index(line, " rtt:"); i >= 0 {
				v := line[i+5:]
				if j := strings.IndexAny(v, "/ "); j >= 0 {
					v = v[:j]
				}
				if f, err := strconv.ParseFloat(v, 64); err == nil && f >= 0 && res[len(res)-1].RTTms < 0 {
					res[len(res)-1].RTTms = f
				}
			}
			continue
		}
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		_, lp, e1 := net.SplitHostPort(f[2])
		rh, rp, e2 := net.SplitHostPort(f[3])
		if e1 != nil || e2 != nil {
			continue
		}
		p, err := strconv.Atoi(lp)
		if err != nil {
			continue
		}
		rport, _ := strconv.Atoi(rp)
		res = append(res, ssSession{LPort: p, RHost: normHost(rh), RPort: rport, RTTms: -1})
	}
	return res
}

// sessionsOn picks sessions on any of the local ports, optionally restricted to
// the given remote addresses (empty list = any remote).
func sessionsOn(all []ssSession, ports []int, remotes ...string) []ssSession {
	want := map[string]bool{}
	for _, r := range remotes {
		if r = strings.TrimSpace(r); r != "" {
			want[r] = true
		}
	}
	var res []ssSession
	for _, s := range all {
		hit := false
		for _, p := range ports {
			if p > 0 && s.LPort == p {
				hit = true
				break
			}
		}
		if hit && (len(want) == 0 || want[s.RHost]) {
			res = append(res, s)
		}
	}
	return res
}

func ssEstablished() string {
	out, err := runCmdTimeoutOut(5*time.Second, "ss", "-Htin", "state", "established")
	if err != nil {
		return ""
	}
	return string(out)
}

// minRTT returns the lowest reported RTT among sessions, or -1.
func minRTT(ss []ssSession) float64 {
	best := -1.0
	for _, s := range ss {
		if s.RTTms >= 0 && (best < 0 || s.RTTms < best) {
			best = s.RTTms
		}
	}
	return best
}

// normHost canonicalises an address for comparison: brackets and zone ids are
// dropped and IPv4-mapped IPv6 ("[::ffff:1.2.3.4]") becomes plain IPv4.
func normHost(h string) string {
	h = strings.TrimSpace(strings.Trim(h, "[]"))
	if i := strings.IndexByte(h, '%'); i >= 0 {
		h = h[:i]
	}
	if ip := net.ParseIP(h); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return v4.String()
		}
		return ip.String()
	}
	return h
}

// controlPorts is the local port set a peer's clients may use: the control
// port, its WSS TLS front (port+2) and the port-2 sibling.
func controlPorts(port int) []int {
	if port <= 0 {
		return nil
	}
	return []int{port, port + 2, port - 2}
}

// portOwners counts, per local port, how many control ports claim it. A session
// on a port with a single owner can be attributed to that peer whatever its
// remote address (NAT / CGNAT / roaming).
func portOwners(ports []int) map[int]int {
	m := map[int]int{}
	for _, p := range ports {
		for _, q := range controlPorts(p) {
			m[q]++
		}
	}
	return m
}

// ctrlQuery identifies one link when matching hub-side control sessions.
type ctrlQuery struct {
	ID        int
	Port      int
	RemotePub string
	PeerGre   string
	Extra     []string // additional accepted remotes (legacy variadic callers)
}

type ctrlResult struct {
	Linked bool
	RTTms  float64
	Remote string
}

// lastRemote caches the remote address last seen on each peer's control
// sessions, so a NAT'd client keeps matching after its address is learned.
var lastRemote = struct {
	sync.Mutex
	m map[int]string
}{m: map[int]string{}}

func cachedRemote(id int) string {
	lastRemote.Lock()
	defer lastRemote.Unlock()
	return lastRemote.m[id]
}

func rememberRemote(id int, host string) {
	lastRemote.Lock()
	lastRemote.m[id] = host
	lastRemote.Unlock()
}

// controlSessionIn decides from already-parsed sessions whether a client holds
// an ESTABLISHED session to this link's control port set. Order: remote in
// {RemotePub, PeerGre, last seen}; else, when the session's local port belongs
// to exactly one link (owners; nil = unknown, assumed unique), any remote.
func controlSessionIn(all []ssSession, q ctrlQuery, owners map[int]int) ctrlResult {
	none := ctrlResult{RTTms: -1}
	cands := sessionsOn(all, controlPorts(q.Port))
	if len(cands) == 0 {
		return none
	}
	known := map[string]bool{}
	for _, r := range append([]string{q.RemotePub, q.PeerGre, cachedRemote(q.ID)}, q.Extra...) {
		if r = normHost(r); r != "" {
			known[r] = true
		}
	}
	var hit []ssSession
	for _, s := range cands {
		if known[s.RHost] {
			hit = append(hit, s)
		}
	}
	if len(hit) == 0 {
		for _, s := range cands {
			if owners == nil || owners[s.LPort] <= 1 {
				hit = append(hit, s)
			}
		}
	}
	if len(hit) == 0 {
		return none
	}
	best := hit[0]
	for _, s := range hit[1:] {
		if s.RTTms >= 0 && (best.RTTms < 0 || s.RTTms < best.RTTms) {
			best = s
		}
	}
	if q.ID >= 0 {
		rememberRemote(q.ID, best.RHost)
	}
	return ctrlResult{Linked: true, RTTms: minRTT(hit), Remote: best.RHost}
}

// controlSession reports whether a foreign client holds an ESTABLISHED TCP
// session to this hub's control port (or its WSS TLS front, port+2), and the
// kernel RTT of that session. Thin wrapper for callers that need a fresh read;
// the snapshot collector uses controlSessionIn on one shared ss parse.
func controlSession(port int, remotes ...string) (linked bool, rttMs float64) {
	if port <= 0 {
		return false, -1
	}
	r := controlSessionIn(parseSS(ssEstablished()), ctrlQuery{ID: -1, Port: port, Extra: remotes}, nil)
	return r.Linked, r.RTTms
}

// linkedFromSS is the pure helper used by tests.
func linkedFromSS(out string, ports []int, remotes ...string) bool {
	return len(sessionsOn(parseSS(out), ports, remotes...)) > 0
}

// dialFn is the TCP connect used by the active probe; tests swap it.
var dialFn = func(network, addr string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout(network, addr, timeout)
}

const connectProbeTimeout = 1500 * time.Millisecond

type connectResult struct {
	OK    bool
	RTTms float64
	Addr  string
}

// connectProbe is the fallback when ss shows no session: one TCP connect to
// the control port on the peer's GRE inner address, then on its public address.
// A completed handshake or an immediate refusal both prove the path answers and
// give a round-trip time (the spoke runs a client, not a listener, so refusal is
// the normal case). It never sets Session. Collector-only: never call from a
// request handler.
func connectProbe(q ctrlQuery) connectResult {
	for _, host := range []string{q.PeerGre, q.RemotePub} {
		if host == "" || q.Port <= 0 {
			continue
		}
		addr := net.JoinHostPort(host, strconv.Itoa(q.Port))
		start := time.Now()
		c, err := dialFn("tcp", addr, connectProbeTimeout)
		rtt := max(float64(time.Since(start).Nanoseconds())/1e6, 0.001) // > 0: zero means "unknown" downstream
		if err == nil {
			_ = c.Close()
		} else if !errors.Is(err, syscall.ECONNREFUSED) {
			continue
		}
		return connectResult{OK: true, RTTms: rtt, Addr: addr}
	}
	return connectResult{RTTms: -1}
}
