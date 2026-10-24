package main

import (
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"
)

// B-01: the TLS front used for the FRP "wss" transport must terminate TLS and
// relay bytes both ways to the plain backend.
func TestTLSProxyRelaysBothWays(t *testing.T) {
	// plain echo backend
	be, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer be.Close()
	go func() {
		for {
			c, err := be.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	cert, err := generateSelfSignedCert("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go serveTLSProxy(ln, be.Addr().String())

	c, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("tls dial: %v", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	msg := []byte("GET /~!frp HTTP/1.1\r\n")
	if _, err := c.Write(msg); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != string(msg) {
		t.Fatalf("echo mismatch: %q err=%v", buf, err)
	}
}

func TestTLSProxyUsage(t *testing.T) {
	if rc := tlsProxyCmd([]string{}); rc != 2 {
		t.Fatalf("missing flags must return 2, got %d", rc)
	}
}
