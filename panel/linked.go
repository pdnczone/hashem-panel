package main

import (
	"net"
	"strconv"
	"strings"
	"time"
)

// ssSession is one ESTABLISHED TCP session from `ss -Htin`.
type ssSession struct {
	LPort int
	RHost string
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
		rh, _, e2 := net.SplitHostPort(f[3])
		if e1 != nil || e2 != nil {
			continue
		}
		p, err := strconv.Atoi(lp)
		if err != nil {
			continue
		}
		res = append(res, ssSession{LPort: p, RHost: strings.Trim(rh, "[]"), RTTms: -1})
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

// controlSession reports whether a foreign client holds an ESTABLISHED TCP
// session to this hub's control port (or its WSS TLS front, port+2), and the
// kernel RTT of that session. The client may arrive over the GRE inner address
// or the hub's public IP (dial route), so a match on either remote counts.
func controlSession(port int, remotes ...string) (linked bool, rttMs float64) {
	if port <= 0 {
		return false, -1
	}
	ss := sessionsOn(parseSS(ssEstablished()), []int{port, port + 2, port - 2}, remotes...)
	return len(ss) > 0, minRTT(ss)
}

// linkedFromSS is the pure helper used by tests.
func linkedFromSS(out string, ports []int, remotes ...string) bool {
	return len(sessionsOn(parseSS(out), ports, remotes...)) > 0
}
