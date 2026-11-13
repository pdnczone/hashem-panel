package main

// Peer Link: which address of the other server to try first.
//
// A peer has up to two addresses: the GRE inner one and the public one. When
// GRE is blocked (the tunnel runs on FRP alone, or ICMP and TCP inside GRE
// are dropped), every call used to wait out the timeout on the inner address
// before the public one answered: a 4 second "latency" on a healthy link.
//
// An address that did not connect is remembered here. Calls then start with
// the addresses that are not marked; the marked one is still the last resort.
// At most once a minute a short TCP connect in the background looks whether
// it is back, and one that answers is unmarked.

import (
	"errors"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	peerDialTimeout  = 2 * time.Second         // TCP connect to a peer panel
	peerProbeEvery   = 60 * time.Second        // between background probes of a marked address
	peerProbeTimeout = 1500 * time.Millisecond // one background probe
)

type peerDownEntry struct {
	probed  time.Time
	probing bool
}

var (
	peerDownMu sync.Mutex
	peerDown   = map[string]*peerDownEntry{} // "host:port" that did not connect

	// peerProbeDial is the background probe; a var so tests need no network.
	peerProbeDial = func(hostport string, timeout time.Duration) error {
		c, err := net.DialTimeout("tcp", hostport, timeout)
		if err == nil {
			_ = c.Close()
		}
		return err
	}
	peerNow = time.Now
)

// peerHostKey is the "host:port" of a peer URL ("" when it has none).
func peerHostKey(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	if u.Port() != "" {
		return u.Host
	}
	if u.Scheme == "https" {
		return net.JoinHostPort(u.Hostname(), "443")
	}
	return net.JoinHostPort(u.Hostname(), "80")
}

func peerMarkDown(hostport string) {
	if hostport == "" {
		return
	}
	peerDownMu.Lock()
	if peerDown[hostport] == nil {
		peerDown[hostport] = &peerDownEntry{probed: peerNow()}
	}
	peerDownMu.Unlock()
}

func peerMarkUp(hostport string) {
	peerDownMu.Lock()
	delete(peerDown, hostport)
	peerDownMu.Unlock()
}

func peerIsDown(hostport string) bool {
	peerDownMu.Lock()
	defer peerDownMu.Unlock()
	return peerDown[hostport] != nil
}

// peerProbe looks once whether a marked address connects again.
func peerProbe(hostport string) {
	err := peerProbeDial(hostport, peerProbeTimeout)
	peerDownMu.Lock()
	defer peerDownMu.Unlock()
	e := peerDown[hostport]
	if e == nil {
		return
	}
	if err == nil {
		delete(peerDown, hostport)
		return
	}
	e.probed, e.probing = peerNow(), false
}

// peerOrderURLs keeps the order of urls but moves the ones whose address is
// marked down to the end, and starts the probe of a marked address that is due.
func peerOrderURLs(urls []string) []string {
	var up, down []string
	var due []string
	peerDownMu.Lock()
	for _, u := range urls {
		k := peerHostKey(u)
		e := peerDown[k]
		if e == nil {
			up = append(up, u)
			continue
		}
		down = append(down, u)
		if !e.probing && peerNow().Sub(e.probed) >= peerProbeEvery {
			e.probing = true
			due = append(due, k)
		}
	}
	peerDownMu.Unlock()
	for _, k := range due {
		go peerProbe(k)
	}
	return append(up, down...)
}

// peerConnectFailed: the request never reached a panel (no answer to the
// connect, refused, no route), as opposed to a panel that answered an error.
func peerConnectFailed(err error) bool {
	if err == nil {
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	var oe *net.OpError
	if errors.As(err, &oe) && oe.Op == "dial" {
		return true
	}
	s := err.Error()
	return strings.Contains(s, "connection refused") || strings.Contains(s, "no route to host") || strings.Contains(s, "network is unreachable")
}
