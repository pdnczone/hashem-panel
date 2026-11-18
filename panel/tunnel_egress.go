package main

// Reaching Telegram and Cloudflare through a tunnel you pick from a list.
//
// The panel used to ask for a tunnel PORT whose far end happened to be a SOCKS5
// proxy, which almost no tunnel port is. Now a tunnel is chosen by name and the
// panel does the rest:
//
//	Iran panel  --SOCKS5-->  127.0.0.1:bridge port   (this file, bridge)
//	            --HTTP upgrade over the tunnel's panel link-->  foreign panel (relay)
//	            --TCP-->  api.telegram.org:443 / api.cloudflare.com:443
//
// The foreign panel only relays to the two hosts below, over the same
// authenticated link the panels already use to talk to each other, so no port
// is opened to the internet and nothing is set up on the foreign server.
// The bridge is a plain SOCKS5 server on loopback, so the Go sender and
// hashem.sh's watchdog (curl --socks5-hostname) use the same thing.

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// egressAllow says whether the relay may open host:port. Only what the panel
// itself calls through a tunnel: a var so tests can point it at a local server.
var egressAllow = func(host string, port int) bool {
	if port != 443 {
		return false
	}
	switch strings.ToLower(strings.TrimSuffix(host, ".")) {
	case "api.telegram.org", "api.cloudflare.com":
		return true
	}
	return false
}

// egressDialTarget opens the relay's outgoing connection (a var for tests).
var egressDialTarget = func(addr string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout("tcp", addr, timeout)
}

const egressMaxSession = 3 * time.Minute

// ---- the foreign panel: the relay ----

// handlePeerEgress is POST /_hp/api/peer/egress?to=host:port. It answers
// "200" and then carries raw bytes both ways, like an HTTP CONNECT.
func handlePeerEgress(w http.ResponseWriter, r *http.Request) {
	host, portStr, err := net.SplitHostPort(r.URL.Query().Get("to"))
	port, perr := strconv.Atoi(portStr)
	if err != nil || perr != nil || host == "" {
		writeAPIError(w, r, "E-ACTION-03", "to=host:port is needed")
		return
	}
	if !egressAllow(host, port) {
		http.Error(w, "the relay only reaches Telegram and Cloudflare", http.StatusForbidden)
		return
	}
	out, err := egressDialTarget(net.JoinHostPort(host, portStr), 10*time.Second)
	if err != nil {
		http.Error(w, "this server could not reach "+host+": "+err.Error(), http.StatusBadGateway)
		return
	}
	defer out.Close()
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "this connection cannot be relayed (HTTP/2)", http.StatusInternalServerError)
		return
	}
	in, rw, err := hj.Hijack()
	if err != nil {
		return
	}
	defer in.Close()
	_ = in.SetDeadline(time.Now().Add(egressMaxSession)) // replaces the server's own timeouts
	_ = out.SetDeadline(time.Now().Add(egressMaxSession))
	if _, err := rw.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"); err != nil || rw.Flush() != nil {
		return
	}
	pipeConns(in, rw.Reader, out)
}

// pipeConns copies both ways until one side ends. aIn is a's buffered reader.
func pipeConns(a net.Conn, aIn io.Reader, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst net.Conn, src io.Reader) {
		_, _ = io.Copy(dst, src)
		if tc, ok := dst.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		} else {
			_ = dst.SetReadDeadline(time.Now())
		}
		done <- struct{}{}
	}
	go cp(b, aIn)
	go cp(a, b)
	<-done
	<-done
}

// ---- the Iran panel: dialing through a tunnel ----

var (
	errEgressOld  = errors.New("the foreign panel did not recognise the request: update its panel to this version (or its Peer Link secret differs)")
	egressTunMu   sync.Mutex
	egressTunMemo = map[int]struct {
		t  swapTunnel
		at time.Time
	}{}
)

// egressTunnelFor replaces egressTunnel in tests. It has no initializer, so it
// adds no package-initialisation dependency.
var egressTunnelFor func(id int) (swapTunnel, error)

// egressTunnel is tunnel id as the swap code sees it. Resolving reads the host,
// so it is remembered for 30 seconds: a bridge calls it for every connection.
func egressTunnel(id int) (swapTunnel, error) {
	if egressTunnelFor != nil {
		return egressTunnelFor(id)
	}
	egressTunMu.Lock()
	m, ok := egressTunMemo[id]
	egressTunMu.Unlock()
	if ok && time.Since(m.at) < 30*time.Second {
		return m.t, nil
	}
	t, err := resolveSwapTunnel(id)
	if err != nil {
		return swapTunnel{}, err
	}
	egressTunMu.Lock()
	egressTunMemo[id] = struct {
		t  swapTunnel
		at time.Time
	}{t, time.Now()}
	egressTunMu.Unlock()
	return t, nil
}

// egressLast remembers why a tunnel's last relayed connection failed, so the
// sender can name the reason after a failed call without dialing again.
var (
	egressLastMu  sync.Mutex
	egressLastErr = map[int]struct {
		msg string
		at  time.Time
	}{}
)

func egressNote(id int, name string, err error) {
	egressLastMu.Lock()
	defer egressLastMu.Unlock()
	if err == nil {
		delete(egressLastErr, id)
		return
	}
	egressLastErr[id] = struct {
		msg string
		at  time.Time
	}{name + ": " + err.Error(), time.Now()}
}

// egressWhy is the reason tunnel id's last connection failed (within 5 minutes), or "".
func egressWhy(id int) string {
	egressLastMu.Lock()
	defer egressLastMu.Unlock()
	if e, ok := egressLastErr[id]; ok && time.Since(e.at) < 5*time.Minute {
		return e.msg
	}
	return ""
}

// bufConn is a connection whose first bytes may already sit in a bufio.Reader.
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// egressDial opens target (host:port) from the foreign server of tunnel t and
// returns the byte stream, with the panel address that carried it.
func egressDial(t swapTunnel, target string, timeout time.Duration) (net.Conn, string, error) {
	secrets := []string{}
	if t.Token != "" {
		secrets = append(secrets, t.Token)
	}
	if c := loadPeerConfig(); c.PeerSecret != "" && c.PeerSecret != t.Token {
		secrets = append(secrets, c.PeerSecret)
	}
	if len(secrets) == 0 {
		return nil, "", errNoPeerLink
	}
	l := loadTunnelLinks()[t.ID]
	bases := tunnelPeerBases(t, l)
	if t.Main {
		// the main tunnel's foreign panel is the Peer Link's: its address and port
		// are saved there, and may differ from the usual ones
		seen := map[string]bool{}
		for _, b := range bases {
			seen[b] = true
		}
		for _, b := range peerBases(loadPeerConfig()) {
			if !seen[b] {
				bases = append(bases, b)
			}
		}
	}
	var lastErr error
	old := false
	dead := map[string]bool{}
	for _, base := range peerOrderURLs(bases) {
		u, err := url.Parse(base)
		if err != nil || dead[u.Host] {
			continue
		}
		for _, sec := range secrets {
			conn, status, msg, derr := egressOpen(u, sec, target, t.ID, l.TLSPin, timeout)
			if derr != nil {
				lastErr = fmt.Errorf("%s: %v", u.Host, derr)
				dead[u.Host] = true
				if peerConnectFailed(derr) {
					peerMarkDown(peerHostKey(base))
				}
				break
			}
			peerMarkUp(peerHostKey(base))
			switch {
			case status == http.StatusOK:
				if l.LastURL != base {
					updateTunnelLink(t.ID, func(x *tunnelLink) { x.LastURL = base })
				}
				return conn, u.Host, nil
			case status == http.StatusNotFound:
				old = true // a wrong secret answers the same bare 404
				lastErr = errEgressOld
				continue
			default:
				return nil, u.Host, fmt.Errorf("the foreign server answered %d: %s", status, msg)
			}
		}
	}
	if old {
		return nil, "", errEgressOld
	}
	if lastErr == nil {
		lastErr = errors.New("no address of the foreign panel is known")
	}
	return nil, "", fmt.Errorf("cannot reach the foreign panel (%v)", lastErr)
}

// egressOpen makes one attempt on one panel address. On a connect/IO failure err
// is set; otherwise status is the relay's answer and conn is live only for 200.
func egressOpen(u *url.URL, secret, target string, id int, pin string, timeout time.Duration) (conn net.Conn, status int, msg string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	c, err := (&net.Dialer{Timeout: peerDialTimeout}).DialContext(ctx, "tcp", u.Host)
	if err != nil {
		return nil, 0, "", err
	}
	if u.Scheme == "https" {
		cfg := tunnelPinnedTLS(id, pin)
		cfg.NextProtos = []string{"http/1.1"} // a hijacked stream needs HTTP/1.1
		cfg.ServerName = u.Hostname()
		tc := tls.Client(c, cfg)
		_ = tc.SetDeadline(time.Now().Add(timeout))
		if err := tc.Handshake(); err != nil {
			c.Close()
			return nil, 0, "", err
		}
		c = tc
	}
	_ = c.SetDeadline(time.Now().Add(timeout))
	req, _ := http.NewRequest("POST", u.Scheme+"://"+u.Host+peerRoutePrefix+"/api/peer/egress?to="+url.QueryEscape(target), nil)
	req.Header.Set("X-Peer-Secret", secret)
	if werr := req.Write(c); werr != nil {
		c.Close()
		return nil, 0, "", werr
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		c.Close()
		return nil, 0, "", err
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		c.Close()
		return nil, resp.StatusCode, strings.TrimSpace(string(b)), nil
	}
	_ = c.SetDeadline(time.Time{})
	return &bufConn{Conn: c, r: br}, http.StatusOK, "", nil
}

// ---- the Iran panel: the loopback SOCKS5 bridge ----

// bridgeBase is the first bridge port; tunnel N uses bridgeBase+N, so the port
// is the same after every restart and hashem.sh can read it from the config.
const bridgeBase = 17080

func bridgePort(id int) int { return bridgeBase + id }

type tunnelBridge struct {
	id int
	ln net.Listener
}

var (
	bridgeMu sync.Mutex
	bridges  = map[int]*tunnelBridge{}
)

// bridgeEnsure starts the loopback SOCKS5 bridge for tunnel id (once) and
// returns its port.
func bridgeEnsure(id int) (int, error) {
	if id < 0 || id > 200 {
		return 0, fmt.Errorf("tunnel %d is not a tunnel number", id)
	}
	bridgeMu.Lock()
	defer bridgeMu.Unlock()
	if b := bridges[id]; b != nil {
		return bridgePort(id), nil
	}
	ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(bridgePort(id)))
	if err != nil {
		return 0, fmt.Errorf("port %d on this server is taken by another program, so the tunnel route cannot start: %v", bridgePort(id), err)
	}
	b := &tunnelBridge{id: id, ln: ln}
	bridges[id] = b
	go bridgeServe(b)
	return bridgePort(id), nil
}

// bridgeServe is set in init: a direct reference from bridgeEnsure would make
// the alert sender (alertSend) depend on the snapshot that triggers it, which
// Go reports as an initialisation cycle.
var bridgeServe func(b *tunnelBridge)

func init() { bridgeServe = (*tunnelBridge).serve }

func (b *tunnelBridge) serve() {
	for {
		c, err := b.ln.Accept()
		if err != nil {
			return
		}
		go b.handle(c)
	}
}

// socks5Reply writes a reply with code rep (0 = succeeded).
func socks5Reply(c net.Conn, rep byte) {
	_, _ = c.Write([]byte{5, rep, 0, 1, 0, 0, 0, 0, 0, 0})
}

// socksTarget reads the greeting and the CONNECT request: host and port.
func socksTarget(c net.Conn) (string, int, error) {
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	defer c.SetDeadline(time.Time{})
	h := make([]byte, 2)
	if _, err := io.ReadFull(c, h); err != nil || h[0] != 5 {
		return "", 0, errors.New("not SOCKS5")
	}
	methods := make([]byte, int(h[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return "", 0, err
	}
	noAuth := false
	for _, m := range methods {
		if m == 0 {
			noAuth = true
		}
	}
	if !noAuth {
		_, _ = c.Write([]byte{5, 0xFF})
		return "", 0, errors.New("no usable method")
	}
	if _, err := c.Write([]byte{5, 0}); err != nil {
		return "", 0, err
	}
	q := make([]byte, 4)
	if _, err := io.ReadFull(c, q); err != nil || q[0] != 5 {
		return "", 0, errors.New("bad request")
	}
	if q[1] != 1 {
		socks5Reply(c, 7) // command not supported
		return "", 0, errors.New("only CONNECT")
	}
	var host string
	switch q[3] {
	case 1:
		b := make([]byte, 4)
		if _, err := io.ReadFull(c, b); err != nil {
			return "", 0, err
		}
		host = net.IP(b).String()
	case 4:
		b := make([]byte, 16)
		if _, err := io.ReadFull(c, b); err != nil {
			return "", 0, err
		}
		host = net.IP(b).String()
	case 3:
		n := make([]byte, 1)
		if _, err := io.ReadFull(c, n); err != nil {
			return "", 0, err
		}
		b := make([]byte, int(n[0]))
		if _, err := io.ReadFull(c, b); err != nil {
			return "", 0, err
		}
		host = string(b)
	default:
		socks5Reply(c, 8)
		return "", 0, errors.New("address type")
	}
	p := make([]byte, 2)
	if _, err := io.ReadFull(c, p); err != nil {
		return "", 0, err
	}
	return host, int(binary.BigEndian.Uint16(p)), nil
}

func (b *tunnelBridge) handle(c net.Conn) {
	defer c.Close()
	host, port, err := socksTarget(c)
	if err != nil {
		return
	}
	if !egressAllow(host, port) {
		socks5Reply(c, 2) // not allowed by ruleset
		return
	}
	t, err := egressTunnel(b.id)
	if err != nil {
		socks5Reply(c, 1)
		return
	}
	out, _, err := egressDial(t, net.JoinHostPort(host, strconv.Itoa(port)), 15*time.Second)
	egressNote(b.id, t.Name, err)
	if err != nil {
		socks5Reply(c, 4) // host unreachable
		return
	}
	defer out.Close()
	socks5Reply(c, 0)
	_ = c.SetDeadline(time.Now().Add(egressMaxSession))
	_ = out.SetDeadline(time.Now().Add(egressMaxSession))
	pipeConns(c, c, out)
}
