package main

// A SOCKS5 proxy reached through a tunnel: the Telegram alerts and the DNS
// failover's Cloudflare calls use it when this server cannot reach them
// directly. The port has to be a tunnel port whose far end (on the foreign
// server) is a SOCKS5 proxy. Two things made it fail without saying why: on a
// cluster hub the tunnel's ports listen on a private address (169.254.77.N),
// not on 127.0.0.1, and most tunnel ports are services (VLESS, HTTPS), not
// proxies, so the handshake hung until the timeout. Now the address is looked
// up, the port is probed with a SOCKS5 greeting, and an error says which case
// it is.

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// tunnelProxyHost is the address the tunnel port listens on: 127.0.0.1 when it
// listens on loopback or every address, else the address it is bound to.
func tunnelProxyHost(port int) string {
	best := ""
	for _, s := range readSockets() {
		if s.Proto != "tcp" || s.State != sockListen || int(s.Local.Port()) != port {
			continue
		}
		a := s.Local.Addr()
		switch {
		case a.IsUnspecified() || (a.Is4() && a.IsLoopback()):
			return "127.0.0.1"
		case a.Is6() && a.IsLoopback():
			if best == "" {
				best = "::1"
			}
		case a.Is4():
			best = a.String()
		case best == "":
			best = a.String()
		}
	}
	if best != "" {
		return best
	}
	return "127.0.0.1"
}

func tunnelProxyAddr(port int) string {
	return net.JoinHostPort(tunnelProxyHost(port), strconv.Itoa(port))
}

// socksProbe sends a SOCKS5 greeting (no authentication) and says whether a
// SOCKS5 proxy answers, or what is wrong.
func socksProbe(addr string) (bool, string) {
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return false, fmt.Sprintf("nothing answers on %s: the tunnel is down or the port is wrong", addr)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2500 * time.Millisecond))
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		return false, fmt.Sprintf("%s closed the connection: the far end of the tunnel is not answering", addr)
	}
	b := make([]byte, 2)
	n, err := io.ReadFull(c, b)
	var ne net.Error
	switch {
	case err != nil && n == 0 && errors.As(err, &ne) && ne.Timeout():
		return false, fmt.Sprintf("%s does not answer a SOCKS5 greeting: it is a service (TLS, HTTP, VLESS...), not a SOCKS5 proxy", addr)
	case err != nil && n == 0:
		return false, fmt.Sprintf("%s accepts the connection but closes it at once: the tunnel is up, but nothing at the foreign end listens (or it is not SOCKS5)", addr)
	case err != nil:
		return false, fmt.Sprintf("%s sent an incomplete answer: it is not a SOCKS5 proxy", addr)
	case b[0] != 5:
		return false, fmt.Sprintf("%s speaks another protocol, not SOCKS5", addr)
	case b[1] == 0xFF:
		return false, fmt.Sprintf("%s is a SOCKS5 proxy that asks for a login; the panel connects without one", addr)
	case b[1] != 0:
		return false, fmt.Sprintf("%s is a SOCKS5 proxy that wants authentication method %d; the panel connects without one", addr, b[1])
	}
	return true, ""
}

// probeTunnelProxy checks tunnel port port.
func probeTunnelProxy(port int) (addr string, ok bool, why string) {
	addr = tunnelProxyAddr(port)
	ok, why = socksProbe(addr)
	return
}

// tunnelProxyClient is an HTTP client that goes out through the tunnel's SOCKS5
// proxy ("socks5h": the name is looked up on the foreign side too).
func tunnelProxyClient(port int, timeout time.Duration) *http.Client {
	pu := &url.URL{Scheme: "socks5h", Host: tunnelProxyAddr(port)}
	return &http.Client{Timeout: timeout, Transport: &http.Transport{Proxy: http.ProxyURL(pu), DisableKeepAlives: true}}
}

// tunnelProxyReady is nil when the tunnel port is a SOCKS5 proxy that answers.
// Called before a request so a wrong port fails at once with the reason, not
// after the request's long timeout.
func tunnelProxyReady(port int) error {
	if _, ok, why := probeTunnelProxy(port); !ok {
		return errors.New(why)
	}
	return nil
}
