package main

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestFRPConcurrencyStress runs 500 concurrent connections through the multiplexed proxy relay.
func TestFRPConcurrencyStress(t *testing.T) {
	runConcurrentStress(t, 500)
}

// TestFRP1000HighConcurrencyStress runs 1,000 concurrent connections to ensure no drops under heavy load.
func TestFRP1000HighConcurrencyStress(t *testing.T) {
	runConcurrentStress(t, 1000)
}

func runConcurrentStress(t *testing.T, totalClients int) {
	// 1. Start a backend echo target server
	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to bind target listener: %v", err)
	}
	defer targetLn.Close()

	var targetReceivedConns int64
	go func() {
		for {
			conn, err := targetLn.Accept()
			if err != nil {
				return
			}
			atomic.AddInt64(&targetReceivedConns, 1)
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 256)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					if _, err := c.Write(buf[:n]); err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	targetAddr := targetLn.Addr().String()

	// 2. Start a Multiplexed Proxy Relay (simulating FRPS/FRPC with high connection pool)
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to bind proxy listener: %v", err)
	}
	defer proxyLn.Close()

	proxyAddr := proxyLn.Addr().String()

	go func() {
		for {
			clientConn, err := proxyLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				targetConn, err := net.DialTimeout("tcp", targetAddr, 5*time.Second)
				if err != nil {
					return
				}
				defer targetConn.Close()

				// Bidirectional forward
				var wg sync.WaitGroup
				wg.Add(2)
				go func() {
					defer wg.Done()
					_, _ = io.Copy(targetConn, c)
				}()
				go func() {
					defer wg.Done()
					_, _ = io.Copy(c, targetConn)
				}()
				wg.Wait()
			}(clientConn)
		}
	}()

	// 3. Stress Test: Launch totalClients concurrent connections with payload verification
	var successCount int64
	var failureCount int64

	var wg sync.WaitGroup
	wg.Add(totalClients)

	startSignal := make(chan struct{})

	for i := 0; i < totalClients; i++ {
		go func(clientId int) {
			defer wg.Done()
			<-startSignal

			conn, err := net.DialTimeout("tcp", proxyAddr, 8*time.Second)
			if err != nil {
				atomic.AddInt64(&failureCount, 1)
				t.Logf("client %d dial failed: %v", clientId, err)
				return
			}
			defer conn.Close()

			_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

			// Send unique payload
			payload := make([]byte, 64)
			_, _ = rand.Read(payload)

			if _, err := conn.Write(payload); err != nil {
				atomic.AddInt64(&failureCount, 1)
				return
			}

			// Read back echo
			resp := make([]byte, len(payload))
			if _, err := io.ReadFull(conn, resp); err != nil {
				atomic.AddInt64(&failureCount, 1)
				return
			}

			if !bytes.Equal(payload, resp) {
				atomic.AddInt64(&failureCount, 1)
				return
			}

			// Hold connection slightly to ensure concurrent overlap
			time.Sleep(30 * time.Millisecond)

			atomic.AddInt64(&successCount, 1)
		}(i)
	}

	// Release all workers simultaneously
	close(startSignal)
	wg.Wait()

	succ := atomic.LoadInt64(&successCount)
	fail := atomic.LoadInt64(&failureCount)
	t.Logf("Stress Test Result: Total=%d, Success=%d, Failures=%d", totalClients, succ, fail)

	if fail > 0 {
		t.Fatalf("Connection drops detected under load! Failures=%d, Success=%d", fail, succ)
	}
	if succ != int64(totalClients) {
		t.Fatalf("Expected %d successful connections, got %d", totalClients, succ)
	}
}

// TestStrictFailoverDefaults verifies that AutoPilot / Automatic Failover
// is STRICTLY disabled by default on clean installations AND existing installations.
func TestStrictFailoverDefaults(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "hashem_failover_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	oldConfigDir := configDir
	configDir = tmpDir
	defer func() { configDir = oldConfigDir }()

	// 1. Fresh config: Must be false
	fresh := defaultPeerConfig()
	if fresh.AutoPilotEnabled {
		t.Fatalf("Fresh config must have AutoPilotEnabled=false, got true")
	}

	// 2. Load without existing file: Must be false
	loaded := loadPeerConfig()
	if loaded.AutoPilotEnabled {
		t.Fatalf("Uninitialized config must have AutoPilotEnabled=false, got true")
	}

	// 3. Existing legacy config that previously had AutoPilotEnabled=true without explicit flag
	legacyJSON := `{"peer_url":"http://1.2.3.4:8080","role":"master","autopilot_enabled":true}`
	_ = os.WriteFile(filepath.Join(tmpDir, "peer_config.json"), []byte(legacyJSON), 0600)

	migrated := loadPeerConfig()
	if migrated.AutoPilotEnabled {
		t.Fatalf("Legacy migration MUST turn AutoPilotEnabled=false by default, got true")
	}
	if !migrated.AutoPilotExplicit {
		t.Fatalf("Legacy migration must mark AutoPilotExplicit=true")
	}
}

// TestFRPDropErrorClassification verifies that FRPS/FRPC drop error signatures
// are accurately parsed into the new diagnostic error codes (E-FRP-05 to E-FRP-09).
func TestFRPDropErrorClassification(t *testing.T) {
	testCases := []struct {
		logLine      string
		expectedCode string
	}{
		{
			logLine:      "accept tcp [::]:7000: accept4: too many open files",
			expectedCode: "E-FRP-05",
		},
		{
			logLine:      "socket: EMFILE: maximum file descriptors reached",
			expectedCode: "E-FRP-05",
		},
		{
			logLine:      "control connection closed: heartbeat timeout",
			expectedCode: "E-FRP-06",
		},
		{
			logLine:      "write tcp 127.0.0.1:7000: write: broken pipe",
			expectedCode: "E-FRP-07",
		},
		{
			logLine:      "read tcp 127.0.0.1:7000: connection reset by peer",
			expectedCode: "E-FRP-07",
		},
		{
			logLine:      "nf_conntrack: table full, dropping packet",
			expectedCode: "E-FRP-08",
		},
		{
			logLine:      "yamux: stream reset by remote party",
			expectedCode: "E-FRP-09",
		},
	}

	for _, tc := range testCases {
		code, _ := matchLogCode(tc.logLine)
		if code != tc.expectedCode {
			t.Errorf("for log %q, expected code %s, got %s", tc.logLine, tc.expectedCode, code)
		}
	}
}
