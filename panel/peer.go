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
	Role               string  `json:"role"`          // "master" (Iran) or "worker" (Kharej)
	PeerSecret         string  `json:"peer_secret"`   // Shared secret token for inter-panel authentication
	PeerURL            string  `json:"peer_url"`      // Public URL of peer, e.g. "http://5.6.7.8:8080"
	InternalIP         string  `json:"internal_ip"`   // Tunnel internal IP, e.g. "10.10.10.1"
	InternalPort       int     `json:"internal_port"` // Panel port on internal IP (default 8080)
	LastSync           string  `json:"last_sync"`     // Timestamp of last successful handshake/sync
	IsConnected        bool    `json:"is_connected"`
	LatencyMs          float64 `json:"latency_ms"`
	AutoPilotEnabled   bool    `json:"autopilot_enabled"`
	AutoPilotExplicit  bool    `json:"autopilot_explicit,omitempty"`
	AutoPilotThreshold float64 `json:"autopilot_threshold"`       // Packet loss percentage threshold (e.g. 20.0)
	TLSFingerprint     string  `json:"tls_fingerprint,omitempty"` // Pinned SHA-256 (hex) of the peer's leaf TLS cert (TOFU)
	// PeerBasePath is the peer panel's own random base path (each panel has a
	// different one), learned from the handshake or from a pasted panel URL.
	// Only needed to reach peers that predate the fixed peerRoutePrefix.
	PeerBasePath string `json:"peer_base_path,omitempty"`
}

type PeerHandshakeRequest struct {
	Role       string `json:"role"`
	PublicIP   string `json:"public_ip"`
	PanelPort  int    `json:"panel_port"`
	InternalIP string `json:"internal_ip"`
	BasePath   string `json:"base_path,omitempty"`
}

// peerRoutePrefix serves the peer API at a fixed path, independent of each
// panel's random base path, which the other side cannot know. Requests there
// must carry the peer secret; anything else gets a plain 404 so the prefix
// does not reveal the panel.
const peerRoutePrefix = "/_hp"

type PeerApplyCarrierRequest struct {
	Carrier string `json:"carrier"` // "direct", "wss:8443", "6to4", "4in6", etc.
	// 4in6: the receiver's own IPv6 (Local6) and the sender's (Remote6)
	Local6  string `json:"local6,omitempty"`
	Remote6 string `json:"remote6,omitempty"`
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
	st := currentLocal() // reached from request handlers via loadPeerConfig: no fresh fork
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
	c, needsSave := readPeerConfig()
	peerMu.RUnlock()

	if needsSave {
		_ = savePeerConfig(c)
	}
	return c
}

// readPeerConfig reads peer_link.json and fills defaults. Caller holds peerMu.
func readPeerConfig() (PeerConfig, bool) {
	data, err := os.ReadFile(peerConfigFile())
	if err != nil {
		return defaultPeerConfig(), false
	}
	var c PeerConfig
	if err := json.Unmarshal(data, &c); err != nil {
		return defaultPeerConfig(), false
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
	return c, needsSave
}

func savePeerConfig(c PeerConfig) error {
	peerMu.Lock()
	defer peerMu.Unlock()
	return writePeerConfig(c)
}

// updatePeerConfig applies fn to the current peer_link.json under one lock.
// Background status updates use it so they only touch their own fields: a
// copy loaded before a multi-second peer call would otherwise overwrite a
// secret or URL the admin saved in the meantime.
func updatePeerConfig(fn func(c *PeerConfig)) error {
	peerMu.Lock()
	defer peerMu.Unlock()
	c, _ := readPeerConfig()
	fn(&c)
	return writePeerConfig(c)
}

// writePeerConfig persists c atomically. Caller holds peerMu.
func writePeerConfig(c PeerConfig) error {
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
		// 1. Check if authenticated via active admin session cookie, or
		// relayed from this node's central (only /api/peer/status is: node_relay.go)
		if nodeRelayed(r) || authed(r) {
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

// requirePeerSecretHidden guards the fixed peerRoutePrefix routes: only the
// peer secret is accepted, and every failure is a bare 404 so scanners
// cannot tell the prefix belongs to a panel.
func requirePeerSecretHidden(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c := loadPeerConfig()
		got := strings.TrimSpace(r.Header.Get("X-Peer-Secret"))
		if got == "" {
			if h := r.Header.Get("Authorization"); strings.HasPrefix(strings.ToLower(h), "bearer ") {
				got = strings.TrimSpace(h[7:])
			}
		}
		if c.PeerSecret == "" || got == "" || !ConstantTimeCompare(c.PeerSecret, got) {
			if got != "" {
				LogSecurityAudit("peer_auth_rejected", "peer", ClientIP(r), "path="+r.URL.Path)
			}
			http.NotFound(w, r)
			return
		}
		next(w, r)
	}
}

// mountPeerRoutes registers the peer API under base (the panel's base path)
// and under the fixed peerRoutePrefix.
func mountPeerRoutes(mux *http.ServeMux, base string) {
	routes := []struct {
		method, path string
		h            http.HandlerFunc
	}{
		{"POST", "/api/peer/handshake", handlePeerHandshake},
		{"POST", "/api/peer/apply-carrier", handlePeerApplyCarrier},
		{"POST", "/api/peer/carrier-info", handlePeerCarrierInfo},
		{"POST", "/api/peer/apply-engine", handlePeerApplyEngine},
		{"POST", "/api/peer/ping", handlePeerPing},
		{"POST", "/api/peer/revpath-probe", handlePeerRevPathProbe},
		{"POST", "/api/peer/sshfwd-install-key", handlePeerSSHFwdInstallKey},
		{"GET", "/api/peer/status", handlePeerStatus},
		{"GET", "/api/peer/node-offer", handlePeerNodeOffer}, // nodes N5 (node_migrate.go)
		{"POST", "/api/peer/swap-carrier", handlePeerSwapCarrier},
		{"GET", "/api/peer/swap-status", handlePeerSwapStatus},
		{"GET", "/api/peer/swap-request", handlePeerSwapRequestGet},
		{"POST", "/api/peer/swap-request", handlePeerSwapRequest},
		{"GET", "/api/peer/wrap-request", handlePeerWrapStatus},
		{"POST", "/api/peer/wrap-request", handlePeerWrapRequest},
	}
	for _, rt := range routes {
		mux.HandleFunc(rt.method+" "+base+rt.path, requirePeerAuth(rt.h))
		guard := requirePeerSecretHidden
		switch rt.path {
		case "/api/peer/handshake", "/api/peer/ping", "/api/peer/swap-request", "/api/peer/wrap-request", "/api/peer/node-offer":
			// A peer's foreign server knows its own tunnel token, not the
			// Peer Link secret: it may still say where its panel answers,
			// and ask for a swap of its own tunnel.
			guard = requireTunnelSecretHidden
		}
		mux.HandleFunc(rt.method+" "+peerRoutePrefix+rt.path, guard(rt.h))
	}
	mux.HandleFunc("GET "+peerRoutePrefix+"/api/peer/rescue-offer", requireRescuePeerHidden(handlePeerRescueOffer))
	mux.HandleFunc("POST "+peerRoutePrefix+"/api/peer/rescue-ack", requireRescuePeerHidden(handlePeerRescueAck))
	// Anything else under the prefix (other paths, wrong methods) is a plain
	// 404 rather than the catch-all redirect or a 405 that would reveal routes.
	mux.HandleFunc(peerRoutePrefix+"/", http.NotFound)
}

// POST /api/peer/handshake
func handlePeerHandshake(w http.ResponseWriter, r *http.Request) {
	var req PeerHandshakeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeAPIError(w, r, "E-ACTION-01", "invalid handshake json")
		return
	}
	if id, _ := r.Context().Value(tunnelCtxKey{}).(int); id > 0 {
		tunnelHandshake(w, id, req)
		return
	}

	var role string
	_ = updatePeerConfig(func(c *PeerConfig) {
		c.IsConnected = true
		c.LastSync = time.Now().Format("2006-01-02 15:04:05")
		if req.PublicIP != "" && req.PanelPort > 0 {
			scheme := "http"
			if req.PanelPort == 443 {
				scheme = "https"
			}
			c.PeerURL = scheme + "://" + hostPort(req.PublicIP, req.PanelPort)
		}
		if req.PanelPort > 0 && req.PanelPort <= 65535 {
			c.InternalPort = req.PanelPort
		}
		if req.InternalIP != "" {
			c.InternalIP = req.InternalIP
		}
		if bp := strings.Trim(req.BasePath, "/"); bp != "" {
			c.PeerBasePath = bp
		}
		role = c.Role
	})

	carrierCfg := loadCarrierConfig()
	writeJSON(w, map[string]any{
		"status":         "ok",
		"role":           role,
		"active_carrier": carrierCfg.ActiveCarrier,
		"version":        panelVersion,
		"timestamp":      time.Now().Unix(),
		// Lets the caller reach this panel directly next time.
		"base_path":  strings.Trim(cfg.BasePath, "/"),
		"panel_port": cfg.Port,
	})
}

// peerHandshake introduces this panel to the peer and stores the base path and
// panel port the peer reports back.
func peerHandshake(role, internalIP string) error {
	resp, err := sendToPeer("/api/peer/handshake", "POST", PeerHandshakeRequest{
		Role:       role,
		PublicIP:   detectPublicIP(),
		PanelPort:  cfg.Port,
		InternalIP: internalIP,
		BasePath:   strings.Trim(cfg.BasePath, "/"),
	})
	if err != nil {
		return err
	}
	var hs struct {
		BasePath  string `json:"base_path"`
		PanelPort int    `json:"panel_port"`
	}
	if json.Unmarshal(resp, &hs) == nil {
		_ = updatePeerConfig(func(c *PeerConfig) {
			if bp := strings.Trim(hs.BasePath, "/"); bp != "" {
				c.PeerBasePath = bp
			}
			if hs.PanelPort > 0 && hs.PanelPort <= 65535 {
				c.InternalPort = hs.PanelPort
			}
		})
	}
	return nil
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
	o := carrier6Opts{Local6: strings.TrimSpace(req.Local6), Remote6: strings.TrimSpace(req.Remote6)}
	if target == carrier4in6 && o.Local6 == "" {
		o.Local6 = detectPublicIP6()
	}
	if err := o.validate(); err != nil {
		writeAPIError(w, r, "E-ACTION-01", err.Error())
		return
	}
	out, err := applyCarrierModeOpts(target, o)
	if err != nil {
		log.Printf("[PeerSync] Error applying carrier %s: %v (%s)", target, err, out)
		writeAPIError(w, r, "E-CARRIER-01", fmt.Sprintf("failed applying carrier: %v", err))
		return
	}

	markPeerSeen()

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

	if backhaulLocked(engine) && proRequired(w, r, proBackhaul, "Backhaul") {
		return
	}
	log.Printf("[PeerSync] Received remote engine apply command: %s (%s)", engine, req.Transport)
	out, err := switchTunnelEngine(engine, req.Transport)
	if err != nil {
		log.Printf("[PeerSync] Error applying engine %s: %v (%s)", engine, err, out)
		writeAPIError(w, r, "E-ENGINE-01", fmt.Sprintf("failed applying engine: %v", err))
		return
	}

	markPeerSeen()

	writeJSON(w, map[string]any{
		"status": "ok",
		"engine": engine,
		"detail": out,
	})
}

// markPeerSeen records that the peer just reached us.
func markPeerSeen() {
	_ = updatePeerConfig(func(c *PeerConfig) {
		c.IsConnected = true
		c.LastSync = time.Now().Format("2006-01-02 15:04:05")
	})
}

// POST /api/peer/ping
func handlePeerPing(w http.ResponseWriter, r *http.Request) {
	carrierCfg := loadCarrierConfig()
	writeJSON(w, map[string]any{
		"status":         "pong",
		"active_carrier": carrierCfg.ActiveCarrier,
		"version":        panelVersion,
		"time":           time.Now().UnixNano(),
	})
}

// GET /api/peer/status
func handlePeerStatus(w http.ResponseWriter, r *http.Request) {
	c := loadPeerConfig()
	carrierCfg := loadCarrierConfig()
	st := currentLocal()

	writeJSON(w, map[string]any{
		"role":           c.Role,
		"peer_url":       c.PeerURL,
		"internal_ip":    c.InternalIP,
		"is_connected":   c.IsConnected,
		"latency_ms":     c.LatencyMs,
		"last_sync":      c.LastSync,
		"active_carrier": carrierCfg.ActiveCarrier,
		"tunnel_name":    st.Gre.Name,
		"autopilot":      c.AutoPilotEnabled,
		"threshold":      c.AutoPilotThreshold,
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
		// A pasted panel URL ("http://ip:port/<base>/") carries the peer's
		// base path: keep it separately and store only scheme://host:port.
		if pu, err := url.Parse(u); err == nil && pu.Host != "" {
			if bp := strings.Trim(pu.Path, "/"); bp != "" {
				c.PeerBasePath = bp
			}
			u = pu.Scheme + "://" + pu.Host
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
				if err := updatePeerConfig(func(p *PeerConfig) { p.TLSFingerprint = got }); err != nil {
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
	return sendToPeerTimeout(path, method, payload, 4*time.Second)
}

// sendToPeerTimeout is sendToPeer for calls the peer needs longer to answer
// (an engine switch restarts services before it replies).
func sendToPeerTimeout(path string, method string, payload any, timeout time.Duration) ([]byte, error) {
	c := loadPeerConfig()
	var bodyBytes []byte
	var err error
	if payload != nil {
		bodyBytes, err = json.Marshal(payload)
		if err != nil {
			return nil, err
		}
	}

	targetURLs := peerTargetURLs(c, path)
	if len(targetURLs) == 0 {
		return nil, fmt.Errorf("no peer address configured (both InternalIP and PeerURL are empty)")
	}

	tr := &http.Transport{
		TLSClientConfig: peerTLSConfig(&c),
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{
		Timeout:   timeout,
		Transport: tr,
		// A wrong path hits the catch-all redirect to the login page; following
		// it turned that into a 200 "success", so never follow redirects.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	var lastErr error
	deadHosts := map[string]bool{} // scheme://host:port that failed to connect
	for _, target := range targetURLs {
		pu, _ := url.Parse(target)
		hostKey := ""
		if pu != nil {
			hostKey = pu.Scheme + "://" + pu.Host
		}
		if deadHosts[hostKey] {
			continue // no point retrying an unreachable address with another path
		}
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
			deadHosts[hostKey] = true
			continue
		}

		respBytes, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}

		// Every peer endpoint answers JSON; an HTML page means we reached
		// something other than the peer API.
		if resp.StatusCode >= 200 && resp.StatusCode < 300 && json.Valid(respBytes) {
			markPeerSeen()
			return respBytes, nil
		}

		lastErr = fmt.Errorf("peer returned HTTP %d: %s", resp.StatusCode, truncateForError(respBytes))
	}

	_ = updatePeerConfig(func(p *PeerConfig) { p.IsConnected = false })
	return nil, lastErr
}

func truncateForError(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	return s
}

// peerTargetURLs lists the URLs to try for a peer API path, best first:
// the fixed peer prefix (works without knowing the peer's base path), then
// the peer's own base path when known, on the tunnel IP and then the public URL.
func peerTargetURLs(c PeerConfig, path string) []string {
	cleanPath := "/" + strings.TrimLeft(path, "/")
	prefixes := []string{peerRoutePrefix}
	if bp := strings.Trim(c.PeerBasePath, "/"); bp != "" {
		prefixes = append(prefixes, "/"+bp)
	} else if bp := strings.Trim(cfg.BasePath, "/"); bp != "" {
		// Legacy fallback for old peers installed with the same base path.
		prefixes = append(prefixes, "/"+bp)
	}

	var bases []string
	if c.InternalIP != "" {
		ports := []int{}
		if c.InternalPort > 0 {
			ports = append(ports, c.InternalPort)
		}
		if cfg.Port > 0 && cfg.Port != c.InternalPort {
			ports = append(ports, cfg.Port)
		}
		for _, p := range ports {
			bases = append(bases, "http://"+hostPort(c.InternalIP, p))
		}
	}
	if c.PeerURL != "" {
		u := strings.TrimRight(c.PeerURL, "/")
		if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
			u = "http://" + u
		}
		if parsed, err := url.Parse(u); err == nil && parsed.Host != "" {
			host := parsed.Hostname()
			if parsed.Port() != "" {
				bases = append(bases, parsed.Scheme+"://"+parsed.Host)
			} else {
				seen := map[int]bool{}
				for _, p := range []int{c.InternalPort, cfg.Port, effectiveTLSPort(), 7443, 7777, 8080} {
					if p > 0 && !seen[p] {
						seen[p] = true
						bases = append(bases, parsed.Scheme+"://"+hostPort(host, p))
					}
				}
			}
		}
	}

	var out []string
	for _, b := range bases {
		for _, pre := range prefixes {
			out = append(out, b+pre+cleanPath)
		}
	}
	return out
}

// testPeerLink measures HTTP ping round-trip time to peer and updates status.
func testPeerLink() (bool, float64, error) {
	start := time.Now()
	_, err := sendToPeer("/api/peer/ping", "POST", map[string]string{"action": "ping"})
	latency := float64(time.Since(start).Microseconds()) / 1000.0

	if err != nil {
		_ = updatePeerConfig(func(c *PeerConfig) {
			c.IsConnected = false
			c.LatencyMs = 0
		})
		return false, 0, err
	}

	_ = updatePeerConfig(func(c *PeerConfig) {
		c.IsConnected = true
		c.LatencyMs = latency
		c.LastSync = time.Now().Format("2006-01-02 15:04:05")
	})
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

// syncEngineToPeer tells the remote worker to apply the specified tunnel
// engine and waits for its answer. ok is false when there is no linked worker
// to tell (this server is not the master, or no peer secret).
func syncEngineToPeer(engine, transport string) (ok bool, err error) {
	c := loadPeerConfig()
	if c.Role != "master" || c.PeerSecret == "" {
		return false, nil
	}

	log.Printf("[PeerSync] Commanding peer worker to apply engine: %s (%s)", engine, transport)
	_, err = sendToPeerTimeout("/api/peer/apply-engine", "POST", PeerApplyEngineRequest{Engine: engine, Transport: transport}, 40*time.Second)
	return true, err
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
			st := currentLocal() // a full localStatus() scan every 10s only to read the GRE address
			localInner := st.Gre.Inner
			if localInner == "" {
				localInner = defaultForeignGRE
			}
			innerIP := strings.Split(localInner, "/")[0]
			if err := peerHandshake("worker", innerIP); err == nil {
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
