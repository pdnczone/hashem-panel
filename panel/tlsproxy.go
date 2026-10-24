package main

// tls-proxy: tiny TLS terminator used in front of frps when the FRP transport
// is "wss". frps cannot terminate WSS itself (frpc sends a WebSocket over TLS,
// frps only speaks WebSocket in cleartext on its mux port), so without this
// front the "wss" transport never connects (B-01).
//
//	gre-panel tls-proxy -listen 0.0.0.0:7002 -target 127.0.0.1:7000 [-sni host]

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"
)

func tlsProxyCmd(args []string) int {
	fs := flag.NewFlagSet("tls-proxy", flag.ContinueOnError)
	listen := fs.String("listen", "", "address to listen on (TLS), e.g. 0.0.0.0:7002")
	target := fs.String("target", "", "plain TCP address to forward to, e.g. 127.0.0.1:7000")
	sni := fs.String("sni", "", "subject name for the self-signed certificate")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *listen == "" || *target == "" {
		fmt.Fprintln(os.Stderr, "usage: gre-panel tls-proxy -listen ADDR -target ADDR [-sni NAME]")
		return 2
	}
	cert, err := generateSelfSignedCert(*sni)
	if err != nil {
		log.Printf("tls-proxy: cert: %v", err)
		return 1
	}
	ln, err := tls.Listen("tcp", *listen, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if err != nil {
		log.Printf("tls-proxy: listen: %v", err)
		return 1
	}
	log.Printf("tls-proxy: %s -> %s", *listen, *target)
	serveTLSProxy(ln, *target)
	return 0
}

// serveTLSProxy accepts on ln and pipes each connection to target.
func serveTLSProxy(ln net.Listener, target string) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}
		go pipeTo(c, target)
	}
}

func pipeTo(c net.Conn, target string) {
	defer c.Close()
	// Bound the TLS handshake so stalled/scanner connections don't pile up.
	if tc, ok := c.(*tls.Conn); ok {
		_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
		if err := tc.Handshake(); err != nil {
			return
		}
		_ = tc.SetDeadline(time.Time{})
	}
	up, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		return
	}
	defer up.Close()
	for _, x := range []net.Conn{c, up} {
		if t, ok := x.(*net.TCPConn); ok {
			_ = t.SetKeepAlive(true)
			_ = t.SetKeepAlivePeriod(30 * time.Second)
		}
	}
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		// half-close so the peer sees EOF but the other direction can drain
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = dst.Close()
		}
	}
	go cp(up, c)
	go cp(c, up)
	wg.Wait()
}
