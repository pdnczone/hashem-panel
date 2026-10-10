package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

const (
	LocalBridgeFOUPort     = 19998
	LocalBridgeCapturePort = 19999
)

type wssConfig struct {
	Enabled        bool   `json:"enabled"`
	Role           string `json:"role"`             // "server", "client", "auto"
	ListenPort     int    `json:"listen_port"`      // e.g. 8443
	RemoteAddr     string `json:"remote_addr"`      // e.g. "remote_ip:8443" or "domain.com:8443"
	LocalBridgeUDP int    `json:"local_bridge_udp"` // default 19998
	AuthToken      string `json:"auth_token"`       // secret key
	UseTLS         bool   `json:"use_tls"`          // default true
	SNI            string `json:"sni"`              // custom SNI (e.g. "speedtest.net")
	InsecureTLS    bool   `json:"insecure_tls"`     // allow self-signed
}

type wssCarrierStatus struct {
	Running        bool    `json:"running"`
	Connected      bool    `json:"connected"`
	Role           string  `json:"role"`
	ListenAddr     string  `json:"listen_addr"`
	RemoteAddr     string  `json:"remote_addr"`
	BytesSent      int64   `json:"bytes_sent"`
	BytesRecv      int64   `json:"bytes_recv"`
	PacketsSent    int64   `json:"packets_sent"`
	PacketsRecv    int64   `json:"packets_recv"`
	LatencyMs      float64 `json:"latency_ms"`
	LastConnected  string  `json:"last_connected"`
	ReconnectCount int     `json:"reconnect_count"`
	LastError      string  `json:"last_error,omitempty"`
}

var (
	wssMu          sync.RWMutex
	wssActiveState *wssCarrierManager
)

type wssCarrierManager struct {
	cfg            wssConfig
	tlsCertPath    string // panel cert paths, resolved at start so the server goroutine never reads configDir
	tlsKeyPath     string
	ctx            context.Context
	cancel         context.CancelFunc
	running        bool
	connected      int32 // 1 if connected, 0 otherwise
	bytesSent      int64
	bytesRecv      int64
	packetsSent    int64
	packetsRecv    int64
	latencyMs      int64 // stored in microseconds for atomic ops
	lastConnected  string
	reconnectCount int32
	lastError      string
	errMu          sync.Mutex
	httpServer     *http.Server
	activeConn     *websocket.Conn
	connMu         sync.Mutex
	udpConn        *net.UDPConn
}

func wssConfigPath() string {
	return filepath.Join(configDir, "wss_carrier.json")
}

func defaultWSSConfig() wssConfig {
	token := ""
	data, err := os.ReadFile(filepath.Join(configDir, "setup.json"))
	if err == nil {
		var s struct {
			Token string `json:"token"`
		}
		if json.Unmarshal(data, &s) == nil && s.Token != "" {
			token = s.Token
		}
	}

	role := "server"
	if strings.HasPrefix(localStatus().Role, "foreign") {
		role = "client"
	}

	remoteAddr := ""
	st := localStatus()
	peerIP := peerOr(st)
	if peerIP == "" {
		peerIP = st.RemotePub
	}
	if peerIP == "" && st.Gre.PeerIP != "" {
		peerIP = st.Gre.PeerIP
	}
	if peerIP != "" {
		remoteAddr = net.JoinHostPort(peerIP, "8443")
	}

	return wssConfig{
		Enabled:        false,
		Role:           role,
		ListenPort:     8443,
		RemoteAddr:     remoteAddr,
		LocalBridgeUDP: LocalBridgeFOUPort,
		AuthToken:      token,
		UseTLS:         true,
		SNI:            "",
		InsecureTLS:    true,
	}
}

func loadWSSConfig() wssConfig {
	def := defaultWSSConfig()
	data, err := os.ReadFile(wssConfigPath())
	if err != nil {
		return def
	}
	var c wssConfig
	if err := json.Unmarshal(data, &c); err != nil {
		return def
	}
	if c.ListenPort <= 0 {
		c.ListenPort = 8443
	}
	if c.LocalBridgeUDP <= 0 {
		c.LocalBridgeUDP = 19998
	}
	if c.Role == "" {
		c.Role = def.Role
	}
	if c.RemoteAddr == "" {
		c.RemoteAddr = def.RemoteAddr
	}
	if c.AuthToken == "" {
		c.AuthToken = def.AuthToken
	}
	return c
}

func saveWSSConfig(cfg wssConfig) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return err
	}
	tmp := wssConfigPath() + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, wssConfigPath())
}

// generateSelfSignedCert creates an in-memory ECDSA TLS cert for zero-config WSS
func generateSelfSignedCert(domain string) (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	if domain == "" {
		domain = "localhost"
	}

	notBefore := time.Now().Add(-1 * time.Hour)
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Hashem Tunnel Obfuscated Carrier"},
			CommonName:   domain,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	if ip := net.ParseIP(domain); ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
	} else {
		template.DNSNames = append(template.DNSNames, domain)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}, nil
}

func getWSSStatus() wssCarrierStatus {
	wssMu.RLock()
	mgr := wssActiveState
	wssMu.RUnlock()

	if mgr == nil || !mgr.running {
		cfg := loadWSSConfig()
		return wssCarrierStatus{
			Running:    false,
			Connected:  false,
			Role:       cfg.Role,
			ListenAddr: ":" + strconv.Itoa(cfg.ListenPort),
			RemoteAddr: cfg.RemoteAddr,
		}
	}

	mgr.errMu.Lock()
	lastErr := mgr.lastError
	mgr.errMu.Unlock()

	latency := float64(atomic.LoadInt64(&mgr.latencyMs)) / 1000.0

	return wssCarrierStatus{
		Running:        true,
		Connected:      atomic.LoadInt32(&mgr.connected) == 1,
		Role:           mgr.cfg.Role,
		ListenAddr:     ":" + strconv.Itoa(mgr.cfg.ListenPort),
		RemoteAddr:     mgr.cfg.RemoteAddr,
		BytesSent:      atomic.LoadInt64(&mgr.bytesSent),
		BytesRecv:      atomic.LoadInt64(&mgr.bytesRecv),
		PacketsSent:    atomic.LoadInt64(&mgr.packetsSent),
		PacketsRecv:    atomic.LoadInt64(&mgr.packetsRecv),
		LatencyMs:      latency,
		LastConnected:  mgr.lastConnected,
		ReconnectCount: int(atomic.LoadInt32(&mgr.reconnectCount)),
		LastError:      lastErr,
	}
}

func startWSSCarrier(cfg wssConfig) error {
	wssMu.Lock()
	defer wssMu.Unlock()

	if wssActiveState != nil && wssActiveState.running {
		_ = wssActiveState.stop()
	}

	ctx, cancel := context.WithCancel(context.Background())
	mgr := &wssCarrierManager{
		cfg:         cfg,
		ctx:         ctx,
		cancel:      cancel,
		running:     true,
		tlsCertPath: tlsCertFile(),
		tlsKeyPath:  tlsKeyFile(),
	}
	wssActiveState = mgr

	if runtime.GOOS == "windows" {
		atomic.StoreInt32(&mgr.connected, 1)
		mgr.lastConnected = time.Now().Format("2006-01-02 15:04:05")
		return nil
	}

	// Determine effective role
	role := strings.ToLower(cfg.Role)
	if role == "auto" {
		if strings.HasPrefix(localStatus().Role, "iran") {
			role = "server"
		} else {
			role = "client"
		}
	}

	if role == "server" {
		go mgr.runServer()
	} else {
		go mgr.runClient()
	}

	return nil
}

func stopWSSCarrier() error {
	wssMu.Lock()
	defer wssMu.Unlock()

	if wssActiveState == nil || !wssActiveState.running {
		return nil
	}
	err := wssActiveState.stop()
	wssActiveState = nil
	return err
}

func (m *wssCarrierManager) stop() error {
	m.running = false
	if m.cancel != nil {
		m.cancel()
	}
	m.connMu.Lock()
	if m.activeConn != nil {
		_ = m.activeConn.Close()
		m.activeConn = nil
	}
	srv := m.httpServer
	m.httpServer = nil
	udp := m.udpConn
	m.udpConn = nil
	m.connMu.Unlock()

	if srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}
	if udp != nil {
		_ = udp.Close()
	}
	atomic.StoreInt32(&m.connected, 0)
	return nil
}

func (m *wssCarrierManager) setErr(err error) {
	if err == nil {
		return
	}
	m.errMu.Lock()
	m.lastError = err.Error()
	m.errMu.Unlock()
}

// runServer starts the WebSocket receiver and bridges to local UDP FOU
func (m *wssCarrierManager) runServer() {
	var upgrader = websocket.Upgrader{
		// Carrier peers are not browsers and never send Origin. Rejecting any
		// browser-originated upgrade blocks cross-site WebSocket hijacking (M-02).
		CheckOrigin: wssOriginAllowed,
	}

	// Prepare local UDP socket to send/recv to/from FOU
	fouPort := m.cfg.LocalBridgeUDP
	if fouPort <= 0 {
		fouPort = LocalBridgeFOUPort
	}
	udpAddr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("127.0.0.1:%d", fouPort))
	if err != nil {
		m.setErr(fmt.Errorf("resolve local udp: %w", err))
		return
	}

	// Bind local UDP receiver on LocalBridgeCapturePort (19999) with fallback to ephemeral
	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: LocalBridgeCapturePort})
	if err != nil {
		udpConn, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
		if err != nil {
			m.setErr(fmt.Errorf("listen local udp: %w", err))
			return
		}
	}
	m.connMu.Lock()
	m.udpConn = udpConn
	m.connMu.Unlock()
	defer func() {
		m.connMu.Lock()
		if m.udpConn == udpConn {
			m.udpConn = nil
		}
		m.connMu.Unlock()
		_ = udpConn.Close()
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/tunnel-stream", func(w http.ResponseWriter, r *http.Request) {
		// Authenticate token
		token := r.Header.Get("X-Hashem-Token")
		if token == "" {
			token = r.URL.Query().Get("token")
		}
		if m.cfg.AuthToken != "" && !wssTokenEqual(token, m.cfg.AuthToken) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			m.setErr(fmt.Errorf("ws upgrade: %w", err))
			return
		}

		m.connMu.Lock()
		if m.activeConn != nil {
			_ = m.activeConn.Close()
		}
		m.activeConn = ws
		m.connMu.Unlock()

		atomic.StoreInt32(&m.connected, 1)
		m.lastConnected = time.Now().Format("2006-01-02 15:04:05")

		m.bridgePump(ws, udpConn, udpAddr)
	})

	server := &http.Server{
		Addr:              fmt.Sprintf(":%d", m.cfg.ListenPort),
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	m.connMu.Lock()
	m.httpServer = server
	m.connMu.Unlock()
	defer func() {
		m.connMu.Lock()
		if m.httpServer == server {
			m.httpServer = nil
		}
		m.connMu.Unlock()
	}()

	// TLS Setup
	if m.cfg.UseTLS {
		var cert tls.Certificate
		var certErr error

		panelCert := m.tlsCertPath
		panelKey := m.tlsKeyPath
		if _, err := os.Stat(panelCert); err == nil {
			cert, certErr = tls.LoadX509KeyPair(panelCert, panelKey)
		} else {
			cert, certErr = generateSelfSignedCert(m.cfg.SNI)
		}

		if certErr == nil {
			server.TLSConfig = &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS12,
			}
			log.Printf("[WSS-Carrier] Server listening (WSS) on :%d", m.cfg.ListenPort)
			if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				m.setErr(err)
			}
			return
		}
	}

	log.Printf("[WSS-Carrier] Server listening (WS plain) on :%d", m.cfg.ListenPort)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		m.setErr(err)
	}
}

// runClient connects to remote WSS server with auto-reconnection
func (m *wssCarrierManager) runClient() {
	fouPort := m.cfg.LocalBridgeUDP
	if fouPort <= 0 {
		fouPort = LocalBridgeFOUPort
	}
	udpAddr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("127.0.0.1:%d", fouPort))
	if err != nil {
		m.setErr(fmt.Errorf("resolve local udp: %w", err))
		return
	}

	// Bind local UDP receiver on LocalBridgeCapturePort (19999) with fallback to ephemeral
	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: LocalBridgeCapturePort})
	if err != nil {
		udpConn, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
		if err != nil {
			m.setErr(fmt.Errorf("listen local udp: %w", err))
			return
		}
	}
	m.connMu.Lock()
	m.udpConn = udpConn
	m.connMu.Unlock()
	defer func() {
		m.connMu.Lock()
		if m.udpConn == udpConn {
			m.udpConn = nil
		}
		m.connMu.Unlock()
		_ = udpConn.Close()
	}()

	for m.running {
		select {
		case <-m.ctx.Done():
			return
		default:
		}

		scheme := "wss"
		if !m.cfg.UseTLS {
			scheme = "ws"
		}
		url := fmt.Sprintf("%s://%s/tunnel-stream", scheme, m.cfg.RemoteAddr)

		dialer := *websocket.DefaultDialer
		if m.cfg.UseTLS {
			sni := m.cfg.SNI
			if sni == "" {
				host, _, _ := net.SplitHostPort(m.cfg.RemoteAddr)
				sni = host
			}
			dialer.TLSClientConfig = &tls.Config{
				InsecureSkipVerify: m.cfg.InsecureTLS,
				ServerName:         sni,
			}
		}

		headers := http.Header{}
		if m.cfg.AuthToken != "" {
			headers.Set("X-Hashem-Token", m.cfg.AuthToken)
		}

		t0 := time.Now()
		ws, resp, err := dialer.DialContext(m.ctx, url, headers)
		if err != nil {
			atomic.StoreInt32(&m.connected, 0)
			atomic.AddInt32(&m.reconnectCount, 1)
			m.setErr(fmt.Errorf("dial wss: %w", err))
			if resp != nil && resp.StatusCode == http.StatusUnauthorized {
				m.setErr(fmt.Errorf("unauthorized token on %s", url))
			}
			time.Sleep(2 * time.Second)
			continue
		}

		rtt := time.Since(t0).Microseconds()
		atomic.StoreInt64(&m.latencyMs, rtt)
		atomic.StoreInt32(&m.connected, 1)
		m.lastConnected = time.Now().Format("2006-01-02 15:04:05")

		m.connMu.Lock()
		m.activeConn = ws
		m.connMu.Unlock()

		m.bridgePump(ws, udpConn, udpAddr)

		atomic.StoreInt32(&m.connected, 0)
		time.Sleep(1 * time.Second)
	}
}

// bridgePump forwards packets bi-directionally between WebSocket and local UDP FOU
func (m *wssCarrierManager) bridgePump(ws *websocket.Conn, udpConn *net.UDPConn, targetUDP *net.UDPAddr) {
	done := make(chan struct{})

	// UDP -> WS pump
	go func() {
		defer close(done)
		buf := make([]byte, 2048)
		for {
			_ = udpConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			n, _, err := udpConn.ReadFrom(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					select {
					case <-m.ctx.Done():
						return
					default:
						continue
					}
				}
				return
			}
			if n > 0 {
				m.connMu.Lock()
				err := ws.WriteMessage(websocket.BinaryMessage, buf[:n])
				m.connMu.Unlock()
				if err != nil {
					return
				}
				atomic.AddInt64(&m.bytesSent, int64(n))
				atomic.AddInt64(&m.packetsSent, 1)
			}
		}
	}()

	// WS -> UDP pump
	ws.SetReadLimit(65535)
	_ = ws.SetReadDeadline(time.Now().Add(30 * time.Second))
	ws.SetPongHandler(func(string) error {
		_ = ws.SetReadDeadline(time.Now().Add(30 * time.Second))
		return nil
	})

	// Heartbeat ticker
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	go func() {
		for {
			select {
			case <-ticker.C:
				m.connMu.Lock()
				err := ws.WriteControl(websocket.PingMessage, []byte{}, time.Now().Add(3*time.Second))
				m.connMu.Unlock()
				if err != nil {
					_ = ws.Close()
					return
				}
			case <-done:
				return
			case <-m.ctx.Done():
				return
			}
		}
	}()

	for {
		msgType, data, err := ws.ReadMessage()
		if err != nil {
			break
		}
		if msgType == websocket.BinaryMessage && len(data) > 0 {
			_, _ = udpConn.WriteTo(data, targetUDP)
			atomic.AddInt64(&m.bytesRecv, int64(len(data)))
			atomic.AddInt64(&m.packetsRecv, 1)
		}
	}

	_ = ws.Close()
	<-done
}

// wssOriginAllowed accepts only non-browser clients (no Origin header).
func wssOriginAllowed(r *http.Request) bool { return r.Header.Get("Origin") == "" }

// wssTokenEqual compares the carrier token in constant time.
func wssTokenEqual(got, want string) bool {
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}
