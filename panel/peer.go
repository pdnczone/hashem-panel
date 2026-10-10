package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type PeerConfig struct {
	Role               string  `json:"role"`                // "master" (Iran) or "worker" (Kharej)
	PeerSecret         string  `json:"peer_secret"`         // Shared secret token for inter-panel authentication
	PeerURL            string  `json:"peer_url"`            // Public URL of peer, e.g. "http://5.6.7.8:8080"
	InternalIP         string  `json:"internal_ip"`         // Tunnel internal IP, e.g. "10.10.10.1"
	InternalPort       int     `json:"internal_port"`       // Panel port on internal IP (default 8080)
	LastSync           string  `json:"last_sync"`           // Timestamp of last successful handshake/sync
	IsConnected        bool    `json:"is_connected"`
	LatencyMs          float64 `json:"latency_ms"`
	AutoPilotEnabled   bool    `json:"autopilot_enabled"`
	AutoPilotExplicit  bool    `json:"autopilot_explicit,omitempty"`
	AutoPilotThreshold float64 `json:"autopilot_threshold"` // Packet loss percentage threshold (e.g. 20.0)
	TLSFingerprint     string  `json:"tls_fingerprint,omitempty"` // Pinned SHA-256 (hex) of the peer's leaf TLS cert (TOFU)
}

type PeerHandshakeRequest struct {
	Role       string `json:"role"`
	PublicIP   string `json:"public_ip"`
	PanelPort  int    `json:"panel_port"`
	InternalIP string `json:"internal_ip"`
}

type PeerApplyCarrierRequest struct {
	Carrier string `json:"carrier"` // "direct", "fou:443", "wss:8443", etc.
}

type PeerApplyEngineRequest struct {
	Engine    string `json:"engine"`    // "frp", "backhaul", "gre-backhaul"
	Transport string `json:"transport"` // "tcpmux", "tcp", "ws", "wss"
}

type PeerConfigUpdateRequest struct {
	Action             string  `json:"action,omitempty"` // "save", "test"
	PeerURL            string  `json:"peer_url,omitempty"`
	PeerSecret         string  `json:"peer_secret,omitempty"`
	InternalIP         string  `json:"internal_ip,omitempty"`
	Role               string  `json:"role,omitempty"`
	AutoPilotEnabled   *bool   `json:"autopilot_enabled,omitempty"`
	AutoPilotThreshold float64 `json:"autopilot_threshold,omitempty"`
}

var (
	peerMu sync.RWMutex
)

func peerConfigFile() string {
	return filepath.Join(configDir, "peer_link.json")
}

func defaultPeerConfig() PeerConfig {
	st := localStatus()
	role := "master"
	if strings.ToLower(st.Role) == "kharej" || strings.ToLower(st.Role) == "foreign" {
		role = "worker"
	}

	secret := randomToken(32)

	internalIP := st.GrePeer
	if internalIP == "" {
		if role == "master" {
			internalIP = defaultForeignGRE
		} else {
			internalIP = defaultIranGRE
		}
	}

	return PeerConfig{
		Role:               role,
		PeerSecret:         secret,
		PeerURL:            "",
		InternalIP:         internalIP,
		InternalPort:       cfg.Port,
		LastSync:           "",
		IsConnected:        false,
		LatencyMs:          0,
		AutoPilotEnabled:   false,
		AutoPilotExplicit:  true,
		AutoPilotThreshold: 20.0,
	}
}

func loadPeerConfig() PeerConfig {
	peerMu.RLock()
	data, err := os.ReadFile(peerConfigFile())
	if err != nil {
		peerMu.RUnlock()
		return defaultPeerConfig()
	}
	var c PeerConfig
	if err := json.Unmarshal(data, &c); err != nil {
		peerMu.RUnlock()
		return defaultPeerConfig()
	}

	def := defaultPeerConfig()
	if c.Role == "" {
		c.Role = def.Role
	}
	if c.PeerSecret == "" {
		c.PeerSecret = def.PeerSecret
	}
	if c.InternalPort <= 0 {
		c.InternalPort = cfg.Port
	}
	if c.AutoPilotThreshold <= 0 {
		c.AutoPilotThreshold = 20.0
	}

	needsSave := false
	// Migration: disable AutoPilot on existing configs so tunnels do not switch automatically.
	// AutoPilot was previously true by default, causing unwanted tunnel flap/switching.
	if !c.AutoPilotExplicit {
		c.AutoPilotEnabled = false
		c.AutoPilotExplicit = true
		needsSave = true
	}
	peerMu.RUnlock()

	if needsSave {
		_ = savePeerConfig(c)
	}
	return c
}

func savePeerConfig(c PeerConfig) error {
	peerMu.Lock()
	defer peerMu.Unlock()

	_ = os.MkdirAll(configDir, 0700)
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := peerConfigFile() + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, peerConfigFile())
}

// requirePeerAuth validates requests either from authenticated web sessions
// or via shared X-Peer-Secret / Bearer token header.
func requirePeerAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 1. Check if authenticated via active admin session cookie
		if authed(r) {
			next(w, r)
			return
		}

		// 2. Check header-based peer token
		c := loadPeerConfig()
		if c.PeerSecret == "" {
			writeAPIError(w, r, "E-AUTH-01", "peer link secret unconfigured")
			return
		}

		clientSecret := strings.TrimSpace(r.Header.Get("X-Peer-Secret"))
		if clientSecret == "" {
			authHdr := r.Header.Get("Authorization")
			if strings.HasPrefix(strings.ToLower(authHdr), "bearer ") {
				clientSecret = strings.TrimSpace(authHdr[7:])
			}
		}

		if clientSecret == "" || !ConstantTimeCompare(c.PeerSecret, clientSecret) {
			LogSecurityAudit("peer_auth_rejected", "peer", ClientIP(r), "path="+r.URL.Path)
			writeAPIError(w, r, "E-AUTH-01", "invalid peer secret")
			return
		}

		next(w, r)
	}
}

// POST /api/peer/handshake
func handlePeerHandshake(w http.ResponseWriter, r *http.Request) {
	var req PeerHandshakeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeAPIError(w, r, "E-ACTION-01", "invalid handshake json")
		return
	}

	c := loadPeerConfig()
	c.IsConnected = true
	c.LastSync = time.Now().Format("2006-01-02 15:04:05")

	if req.PublicIP != "" && req.PanelPort > 0 {
		scheme := "http"
		if req.PanelPort == 443 {
			scheme = "https"
		}
		c.PeerURL = fmt.Sprintf("%s://%s:%d", scheme, req.PublicIP, req.PanelPort)
	}
	if req.InternalIP != "" {
		c.InternalIP = req.InternalIP
	}

	_ = savePeerConfig(c)

	carrierCfg := loadCarrierConfig()
	writeJSON(w, map[string]any{
		"status":         "ok",
		"role":           c.Role,
		"active_carrier": carrierCfg.ActiveCarrier,
		"version":        panelVersion,
		"timestamp":      time.Now().Unix(),
	})
}

// POST /api/peer/apply-carrier
func handlePeerApplyCarrier(w http.ResponseWriter, r *http.Request) {
	var req PeerApplyCarrierRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeAPIError(w, r, "E-ACTION-01", "invalid request json")
		return
	}

	target := strings.TrimSpace(req.Carrier)
	if target == "" {
		writeAPIError(w, r, "E-ACTION-01", "carrier parameter required")
		return
	}

	log.Printf("[PeerSync] Received remote carrier apply command: %s", target)
	out, err := applyCarrierMode(target)
	if err != nil {
		log.Printf("[PeerSync] Error applying carrier %s: %v (%s)", target, err, out)
		writeAPIError(w, r, "E-CARRIER-01", fmt.Sprintf("failed applying carrier: %v", err))
		return
	}

	c := loadPeerConfig()
	c.IsConnected = true
	c.LastSync = time.Now().Format("2006-01-02 15:04:05")
	_ = savePeerConfig(c)

	carrierCfg := loadCarrierConfig()
	writeJSON(w, map[string]any{
		"status":         "ok",
		"active_carrier": carrierCfg.ActiveCarrier,
		"detail":         out,
	})
}

// POST /api/peer/apply-engine
func handlePeerApplyEngine(w http.ResponseWriter, r *http.Request) {
	var req PeerApplyEngineRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeAPIError(w, r, "E-ACTION-01", "invalid request json")
		return
	}

	engine := strings.TrimSpace(req.Engine)
	if engine == "" {
		writeAPIError(w, r, "E-ACTION-01", "engine parameter required")
		return
	}

	log.Printf("[PeerSync] Received remote engine apply command: %s (%s)", engine, req.Transport)
	out, err := switchTunnelEngine(engine, req.Transport)
	if err != nil {
		log.Printf("[PeerSync] Error applying engine %s: %v (%s)", engine, err, out)
		writeAPIError(w, r, "E-ENGINE-01", fmt.Sprintf("failed applying engine: %v", err))
		return
	}

	c := loadPeerConfig()
	c.IsConnected = true
	c.LastSync = time.Now().Format("2006-01-02 15:04:05")
	_ = savePeerConfig(c)

	writeJSON(w, map[string]any{
		"status": "ok",
		"engine": engine,
		"detail": out,
	})
}

// POST /api/peer/ping
func handlePeerPing(w http.ResponseWriter, r *http.Request) {
	carrierCfg := loadCarrierConfig()
	writeJSON(w, map[string]any{
		"status":         "pong",
		"active_carrier": carrierCfg.ActiveCarrier,
		"time":           time.Now().UnixNano(),
	})
}

// GET /api/peer/status
func handlePeerStatus(w http.ResponseWriter, r *http.Request) {
	c := loadPeerConfig()
	carrierCfg := loadCarrierConfig()
	st := localStatus()

	writeJSON(w, map[string]any{
		"role":             c.Role,
		"peer_url":         c.PeerURL,
		"internal_ip":      c.InternalIP,
		"is_connected":     c.IsConnected,
		"latency_ms":       c.LatencyMs,
		"last_sync":        c.LastSync,
		"active_carrier":   carrierCfg.ActiveCarrier,
		"tunnel_name":      st.Gre.Name,
		"autopilot":        c.AutoPilotEnabled,
		"threshold":        c.AutoPilotThreshold,
	})
}

// GET /api/peer/config (Web admin only)
func handlePeerConfigGet(w http.ResponseWriter, r *http.Request) {
	c := loadPeerConfig()
	writeJSON(w, c)
}

// POST /api/peer/config (Web admin only)
func handlePeerConfigPost(w http.ResponseWriter, r *http.Request) {
	var req PeerConfigUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeAPIError(w, r, "E-ACTION-01", "invalid json")
		return
	}

	c := loadPeerConfig()

	if strings.ToLower(req.Action) == "test" {
		// Test connection to peer
		ok, lat, err := testPeerLink()
		if err != nil {
			writeAPIError(w, r, "E-PEER-02", fmt.Sprintf("peer unreachable: %v", err))
			return
		}
		c = loadPeerConfig()
		writeJSON(w, map[string]any{
			"status":       "ok",
			"reachable":    ok,
			"latency_ms":   lat,
			"is_connected": c.IsConnected,
		})
		return
	}

	if req.PeerURL != "" {
		u := strings.TrimRight(strings.TrimSpace(req.PeerURL), "/")
		if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
			u = "http://" + u
		}
		if u != c.PeerURL {
			c.TLSFingerprint = "" // new peer address: re-pin on first use
		}
		c.PeerURL = u
	}
	if req.PeerSecret != "" {
		c.PeerSecret = strings.TrimSpace(req.PeerSecret)
	}
	if req.InternalIP != "" {
		c.InternalIP = strings.TrimSpace(req.InternalIP)
	}
	if req.Role != "" {
		role := strings.ToLower(strings.TrimSpace(req.Role))
		if role == "master" || role == "worker" {
			c.Role = role
		}
	}
	if req.AutoPilotEnabled != nil {
		c.AutoPilotEnabled = *req.AutoPilotEnabled
		c.AutoPilotExplicit = true
	}
	if req.AutoPilotThreshold > 0 {
		c.AutoPilotThreshold = req.AutoPilotThreshold
	}

	if err := savePeerConfig(c); err != nil {
		writeAPIError(w, r, "E-ACTION-02", "failed to save peer config")
		return
	}

	writeJSON(w, map[string]any{
		"status": "ok",
		"config": c,
	})
}

var peerPinMu sync.Mutex

// peerTLSConfig returns a client TLS config that pins the peer's leaf
// certificate by SHA-256 fingerprint (trust-on-first-use). Chain validation is
// skipped on purpose because peers use self-signed certs; the pin replaces it.
// If c.TLSFingerprint is empty the first seen fingerprint is stored in c and
// persisted to peer_link.json; afterwards any mismatch is rejected.
func peerTLSConfig(c *PeerConfig) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true, // verification is done by VerifyPeerCertificate below
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("peer presented no TLS certificate")
			}
			sum := sha256.Sum256(rawCerts[0])
			got := hex.EncodeToString(sum[:])

			peerPinMu.Lock()
			defer peerPinMu.Unlock()
			pinned := strings.ToLower(strings.TrimSpace(c.TLSFingerprint))
			if pinned == "" {
				c.TLSFingerprint = got
				if err := savePeerConfig(*c); err != nil {
					log.Printf("peer TLS pin: cannot persist fingerprint: %v", err)
				}
				return nil
			}
			if subtle.ConstantTimeCompare([]byte(pinned), []byte(got)) != 1 {
				return fmt.Errorf("peer TLS certificate fingerprint mismatch: pinned %s, got %s (possible MITM or peer cert changed; clear tls_fingerprint to re-pin)", pinned, got)
			}
			return nil
		},
	}
}

// sendToPeer sends an HTTP request to the remote peer using dual-path fallback:
// Path 1: Internal tunnel IP (e.g. http://10.10.10.1:8080/api/peer/...)
// Path 2: Public URL (e.g. http://5.6.7.8:8080/api/peer/...)
func sendToPeer(path string, method string, payload any) ([]byte, error) {
	c := loadPeerConfig()
	var bodyBytes []byte
	var err error
	if payload != nil {
		bodyBytes, err = json.Marshal(payload)
		if err != nil {
			return nil, err
		}
	}

	cleanPath := path
	if !strings.HasPrefix(cleanPath, "/") {
		cleanPath = "/" + cleanPath
	}
	basePath := ""
	if cfg.BasePath != "" {
		basePath = "/" + strings.Trim(cfg.BasePath, "/")
	}
	fullPath := basePath + cleanPath

	var targetURLs []string

	// 1. Try Internal tunnel IP first if configured
	if c.InternalIP != "" {
		portList := []int{}
		if c.InternalPort > 0 {
			portList = append(portList, c.InternalPort)
		}
		if cfg.Port > 0 && cfg.Port != c.InternalPort {
			portList = append(portList, cfg.Port)
		}
		if len(portList) == 0 {
			portList = []int{8080, 80}
		}
		for _, p := range portList {
			targetURLs = append(targetURLs, fmt.Sprintf("http://%s:%d%s", c.InternalIP, p, fullPath))
		}
	}

	// 2. Try Public URL as fallback
	if c.PeerURL != "" {
		u := strings.TrimRight(c.PeerURL, "/")
		if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
			u = "http://" + u
		}
		targetURLs = append(targetURLs, u+fullPath)

		parsed, err := url.Parse(u)
		if err == nil {
			scheme := parsed.Scheme
			if scheme == "" {
				scheme = "http"
			}
			host := parsed.Hostname()
			if parsed.Port() == "" {
				if cfg.Port > 0 {
					targetURLs = append(targetURLs, fmt.Sprintf("%s://%s:%d%s", scheme, host, cfg.Port, fullPath))
				}
				for _, p := range []int{effectiveTLSPort(), 7443, 7777, 8080} {
					if p != cfg.Port && p > 0 {
						targetURLs = append(targetURLs, fmt.Sprintf("%s://%s:%d%s", scheme, host, p, fullPath))
					}
				}
			}
		}
	}

	if len(targetURLs) == 0 {
		return nil, fmt.Errorf("no peer address configured (both InternalIP and PeerURL are empty)")
	}

	tr := &http.Transport{
		TLSClientConfig: peerTLSConfig(&c),
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{
		Timeout:   4 * time.Second,
		Transport: tr,
	}

	var lastErr error
	for _, target := range targetURLs {
		req, err := http.NewRequest(method, target, bytes.NewReader(bodyBytes))
		if err != nil {
			lastErr = err
			continue
		}

		req.Header.Set("Content-Type", "application/json")
		if c.PeerSecret != "" {
			req.Header.Set("X-Peer-Secret", c.PeerSecret)
		}

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		respBytes, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			// Successful connection!
			c.IsConnected = true
			c.LastSync = time.Now().Format("2006-01-02 15:04:05")
			_ = savePeerConfig(c)
			return respBytes, nil
		}

		lastErr = fmt.Errorf("peer returned HTTP %d: %s", resp.StatusCode, string(respBytes))
	}

	c.IsConnected = false
	_ = savePeerConfig(c)
	return nil, lastErr
}

// testPeerLink measures HTTP ping round-trip time to peer and updates status.
func testPeerLink() (bool, float64, error) {
	start := time.Now()
	_, err := sendToPeer("/api/peer/ping", "POST", map[string]string{"action": "ping"})
	latency := float64(time.Since(start).Microseconds()) / 1000.0

	c := loadPeerConfig()
	if err != nil {
		c.IsConnected = false
		c.LatencyMs = 0
		_ = savePeerConfig(c)
		return false, 0, err
	}

	c.IsConnected = true
	c.LatencyMs = latency
	c.LastSync = time.Now().Format("2006-01-02 15:04:05")
	_ = savePeerConfig(c)
	return true, latency, nil
}

// syncCarrierToPeer tells the remote worker to apply the specified carrier.
func syncCarrierToPeer(carrier string) error {
	c := loadPeerConfig()
	if c.Role != "master" {
		return nil // Only master directs the worker
	}

	log.Printf("[PeerSync] Commanding peer worker to apply carrier: %s", carrier)
	_, err := sendToPeer("/api/peer/apply-carrier", "POST", PeerApplyCarrierRequest{Carrier: carrier})
	return err
}

// syncEngineToPeer tells the remote worker to apply the specified tunnel engine.
func syncEngineToPeer(engine, transport string) error {
	c := loadPeerConfig()
	if c.Role != "master" {
		return nil
	}

	log.Printf("[PeerSync] Commanding peer worker to apply engine: %s (%s)", engine, transport)
	_, err := sendToPeer("/api/peer/apply-engine", "POST", PeerApplyEngineRequest{Engine: engine, Transport: transport})
	return err
}

var peerSyncOnce sync.Once

// startPeerSyncWorker initializes the background Peer Link monitoring and auto-sync loop.
func startPeerSyncWorker() {
	peerSyncOnce.Do(func() {
		go peerSyncLoop()
	})
}

func peerSyncLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		t0 := time.Now()
		peerSyncTick()
		recordSampler("peerSync", time.Since(t0))
	}
}

func peerSyncTick() {
	c := loadPeerConfig()
	if c.PeerSecret == "" {
		return
	}

	if c.Role == "worker" {
		if !c.IsConnected {
			st := localStatus()
			localInner := st.Gre.Inner
			if localInner == "" {
				localInner = defaultForeignGRE
			}
			innerIP := strings.Split(localInner, "/")[0]
			_, err := sendToPeer("/api/peer/handshake", "POST", PeerHandshakeRequest{
				Role:       "worker",
				PublicIP:   detectPublicIP(),
				PanelPort:  cfg.Port,
				InternalIP: innerIP,
			})
			if err == nil {
				log.Printf("[PeerSync] Background handshake succeeded with master")
			}
		} else {
			// Periodically test link to update latency & maintain health
			_, _, _ = testPeerLink()
		}
	} else if c.Role == "master" && c.IsConnected {
		_, _, _ = testPeerLink()
	}
}
