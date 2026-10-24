package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// Regression: sendToPeer used to build a fresh http.Transport per call and
// leave its keep-alive connection open forever (no IdleConnTimeout, never
// closed). The peer sync loop calls it every 10s, so sockets, goroutines and
// RAM grew without bound (tens of thousands of ESTABLISHED sockets).
func TestSendToPeerDoesNotLeakConnections(t *testing.T) {
	oldDir := configDir
	configDir = t.TempDir()
	t.Cleanup(func() { configDir = oldDir })

	var open int64
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		switch s {
		case http.StateNew:
			atomic.AddInt64(&open, 1)
		case http.StateClosed, http.StateHijacked:
			atomic.AddInt64(&open, -1)
		}
	}
	srv.Start()
	defer srv.Close()

	c := loadPeerConfig()
	c.InternalIP = "" // skip default unreachable GRE IP (would add 4s timeouts)
	c.PeerURL = srv.URL
	c.PeerSecret = "s3cret"
	if err := savePeerConfig(c); err != nil {
		t.Fatal(err)
	}

	const calls = 40
	for i := 0; i < calls; i++ {
		if _, err := sendToPeer("/api/peer/ping", "POST", map[string]string{"action": "ping"}); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && atomic.LoadInt64(&open) > 0 {
		time.Sleep(20 * time.Millisecond)
	}
	if n := atomic.LoadInt64(&open); n != 0 {
		t.Fatalf("leaked %d open connections after %d sendToPeer calls", n, calls)
	}
}
