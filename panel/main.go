package main

// Entry point: config load, route table, static assets.
// Auth lives in auth.go, tunnel status/actions in tunnel.go,
// setup in setup.go, dashboard metrics in dashboard.go.

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"embed"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed index.html fonts.css tokens.css base.css enterprise.css favicon.png xterm.js xterm-fit.js xterm-search.js xterm.css fonts/vazirmatn.woff2
var panelFS embed.FS

var configDir = "/etc/gre-panel"

// frpDir / backhaulDir hold the FRP and Backhaul configs; tests point them at
// throwaway dirs. Overridable with GRE_FRP_DIR / GRE_BACKHAUL_DIR.
var (
	frpDir      = "/etc/frp"
	backhaulDir = "/etc/backhaul"
)

// runSystemctl is the one place the panel shells out to systemctl for tunnel
// engine switches and port rewrites (swappable for tests).
var runSystemctl = func(args ...string) error {
	return exec.Command("systemctl", args...).Run()
}

type panelConfig struct {
	Username string `json:"username"`
	PassHash string `json:"pass_hash"`
	Port     int    `json:"port"`
	BasePath string `json:"base_path"`
	// TerminalEnabled gates the Phase 3 interactive terminal tab
	// (feature flag, default off; user enables after testing).
	TerminalEnabled bool `json:"terminal_enabled,omitempty"`
	// TLSPort is the HTTPS listener port (default 7443). HTTP stays on Port.
	TLSPort int `json:"tls_port,omitempty"`
}

func termEnabled() bool { return cfg.TerminalEnabled }

// effectiveTLSPort returns the HTTPS port (7443 default when unset).
func effectiveTLSPort() int {
	if cfg.TLSPort < 1 || cfg.TLSPort > 65535 {
		return 7443
	}
	return cfg.TLSPort
}

var (
	cfg panelConfig
	// panelVersion is set at release build time:
	// go build -ldflags "-X main.panelVersion=panel-rN"
	panelVersion = "v0.1.3"
	// panelMux is shared between the HTTP listener and the HTTPS listener.
	panelMux *http.ServeMux
)

func cfgPath() string { return filepath.Join(configDir, "panel.json") }

func saveCfg() { _ = os.WriteFile(cfgPath(), mustJSON(cfg), 0600) }

// ---- auto port: never fail install when the HTTP/TLS port is taken ----

// portFree reports whether TCP :port can be bound right now.
func portFree(port int) bool {
	ln, err := net.Listen("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		return false
	}
	_ = ln.Close()
	return true
}

// pickFreePort scans upward from start for the first bindable TCP port
// (max 100 tries). Falls back to start so the caller errors naturally.
func pickFreePort(start int) int {
	for p := start; p < start+100 && p <= 65535; p++ {
		if p < 1 {
			continue
		}
		if portFree(p) {
			return p
		}
	}
	return start
}

// envPanelPort reads GRE_PANEL_PORT (set by hashem.sh or the admin).
// Returns 0 when unset/invalid.
func envPanelPort() int {
	v := strings.TrimSpace(os.Getenv("GRE_PANEL_PORT"))
	if v == "" {
		return 0
	}
	p, err := strconv.Atoi(v)
	if err != nil || p < 1 || p > 65535 {
		log.Printf("ignoring invalid GRE_PANEL_PORT=%q (must be 1-65535)", v)
		return 0
	}
	return p
}

// ensureFreeHTTPPort guarantees cfg.Port is bindable: env override wins,
// otherwise the saved port (or 7777 fresh) is kept; when busy we scan
// upward and persist the new port so show_panel_url/displays stay correct.
func ensureFreeHTTPPort() {
	desired := cfg.Port
	if p := envPanelPort(); p != 0 {
		desired = p
	} else if desired < 1 || desired > 65535 {
		desired = 7777
	}
	if portFree(desired) {
		if cfg.Port != desired {
			cfg.Port = desired
			saveCfg()
		}
		return
	}
	next := pickFreePort(desired + 1)
	log.Printf("panel port %d busy — auto-switched to %d (saved to panel.json)", desired, next)
	cfg.Port = next
	saveCfg()
}

func loadOrInit() {
	_ = os.MkdirAll(configDir, 0700)

	// CWE-256 Migration: Delete legacy plaintext panel.pass if it exists on disk
	legacyPassFile := filepath.Join(configDir, "panel.pass")
	if _, err := os.Stat(legacyPassFile); err == nil {
		_ = os.Remove(legacyPassFile)
		log.Printf("Security migration (CWE-256): deleted legacy plaintext password file %s", legacyPassFile)
	}

	data, err := os.ReadFile(cfgPath())
	if err == nil && json.Unmarshal(data, &cfg) == nil && cfg.PassHash != "" {
		// Test/dev override: fixed password via env (takes effect on restart).
		if pw := os.Getenv("GRE_PANEL_PASSWORD"); pw != "" {
			cfg.PassHash = hashPassword(pw)
			_ = os.WriteFile(cfgPath(), mustJSON(cfg), 0600)
			log.Printf("panel password updated from GRE_PANEL_PASSWORD environment variable")
		}
		return
	}
	pass := os.Getenv("GRE_PANEL_PASSWORD")
	if pass == "" {
		pass = SecureRandomPassword(16)
	}
	cfg = panelConfig{
		Username: "admin",
		PassHash: hashPassword(pass),
		Port:     7777,
		BasePath: randomBase(12),
	}
	_ = os.WriteFile(cfgPath(), mustJSON(cfg), 0600)
	// CWE-256: Plaintext passwords are NEVER stored on disk!
	log.Printf("==================================================================")
	log.Printf("INITIAL PANEL PASSWORD: %s (user: %s)", pass, cfg.Username)
	log.Printf("Please record this password now. Plaintext is not stored on disk.")
	log.Printf("==================================================================")
}

func mustJSON(v any) []byte {
	b, _ := json.MarshalIndent(v, "", "  ")
	return b
}

func randomBase(n int) string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = chars[int(b[i])%len(chars)]
	}
	return string(b)
}

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "--version" || os.Args[1] == "-v" || os.Args[1] == "version") {
		fmt.Println(panelVersion)
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "tls-proxy" {
		os.Exit(tlsProxyCmd(os.Args[2:]))
	}
	if v := os.Getenv("GRE_PANEL_DIR"); v != "" {
		configDir = v
	}
	if v := os.Getenv("GRE_FRP_DIR"); v != "" {
		frpDir = v
	}
	if v := os.Getenv("GRE_BACKHAUL_DIR"); v != "" {
		backhaulDir = v
	}
	loadOrInit()
	ensureFreeHTTPPort()
	if _, err := rand.Read(nonce[:]); err != nil {
		log.Fatal(err)
	}

	base := "/" + cfg.BasePath
	mux := http.NewServeMux()
	panelMux = mux
	mux.HandleFunc("GET "+base+"/", serveIndex)
	mux.HandleFunc("GET "+base+"/tokens.css", serveAsset("tokens.css", "text/css; charset=utf-8"))
	mux.HandleFunc("GET "+base+"/fonts.css", serveAsset("fonts.css", "text/css; charset=utf-8"))
	mux.HandleFunc("GET "+base+"/fonts/vazirmatn.woff2", serveAsset("fonts/vazirmatn.woff2", "font/woff2"))
	mux.HandleFunc("GET "+base+"/base.css", serveAsset("base.css", "text/css; charset=utf-8"))
	mux.HandleFunc("GET "+base+"/enterprise.css", serveAsset("enterprise.css", "text/css; charset=utf-8"))
	mux.HandleFunc("GET "+base+"/favicon.png", serveAsset("favicon.png", "image/png"))
	mux.HandleFunc("GET "+base+"/xterm.js", serveAsset("xterm.js", "text/javascript; charset=utf-8"))
	mux.HandleFunc("GET "+base+"/xterm-fit.js", serveAsset("xterm-fit.js", "text/javascript; charset=utf-8"))
	mux.HandleFunc("GET "+base+"/xterm-search.js", serveAsset("xterm-search.js", "text/javascript; charset=utf-8"))
	mux.HandleFunc("GET "+base+"/xterm.css", serveAsset("xterm.css", "text/css; charset=utf-8"))
	mux.HandleFunc("GET "+base+"/api/term/ws", requireAuth(handleTermWS))
	mux.HandleFunc("GET "+base+"/api/term/status", requireAuth(handleTermStatus))
	mux.HandleFunc("POST "+base+"/api/term/kill", requireAuth(requireCSRF(handleTermKill)))
	mux.HandleFunc("POST "+base+"/api/term/enable", requireAuth(requireCSRF(handleTermEnable)))
	mux.HandleFunc("GET "+base+"/api/health", handleHealth)
	mux.HandleFunc("GET "+base+"/api/status", requireAuth(handleStatus))
	mux.HandleFunc("GET "+base+"/api/dashboard", requireAuth(handleDashboard))
	mux.HandleFunc("POST "+base+"/api/login", handleLogin)
	mux.HandleFunc("POST "+base+"/api/logout", handleLogout)
	mux.HandleFunc("GET "+base+"/api/logs", requireAuth(handleLogs))
	mux.HandleFunc("GET "+base+"/api/errors", requireAuth(handleErrors))
	mux.HandleFunc("POST "+base+"/api/action", requireAuth(requireCSRF(handleAction)))
	mux.HandleFunc("POST "+base+"/api/password", requireAuth(requireCSRF(handlePassword)))
	mux.HandleFunc("GET "+base+"/api/setup", requireAuth(handleSetupGet))
	mux.HandleFunc("GET "+base+"/api/version", requireAuth(handleVersion))
	mux.HandleFunc("POST "+base+"/api/update", requireAuth(requireCSRF(handleUpdate)))
	mux.HandleFunc("POST "+base+"/api/setup", requireAuth(requireCSRF(handleSetupPost)))
	mux.HandleFunc("GET "+base+"/api/peers", requireAuth(handlePeersGet))
	mux.HandleFunc("POST "+base+"/api/peers", requireAuth(requireCSRF(handlePeersPost)))
	mux.HandleFunc("PATCH "+base+"/api/peers", requireAuth(requireCSRF(handlePeersPatch)))
	mux.HandleFunc("GET "+base+"/api/tls", requireAuth(handleTLSGet))
	mux.HandleFunc("POST "+base+"/api/tls", requireAuth(requireCSRF(handleTLSIssue)))
	mux.HandleFunc("DELETE "+base+"/api/tls", requireAuth(requireCSRF(handleTLSRemove)))
	mux.HandleFunc("POST "+base+"/api/tls/renew", requireAuth(requireCSRF(handleTLSRenew)))
	mux.HandleFunc("POST "+base+"/api/tls/check", requireAuth(requireCSRF(handleTLSCheck)))
	mux.HandleFunc("GET "+base+"/api/tls/proxy-config", requireAuth(handleReverseProxyConfig))
	mux.HandleFunc("GET "+base+"/api/watchdog", requireAuth(handleWatchdogGet))
	mux.HandleFunc("POST "+base+"/api/watchdog", requireAuth(requireCSRF(handleWatchdogPost)))
	mux.HandleFunc("GET "+base+"/api/watchdog/backup-download", requireAuth(handleBackupDownload))
	mux.HandleFunc("POST "+base+"/api/watchdog/backup-download", requireAuth(requireCSRF(handleBackupDownload)))
	mux.HandleFunc("GET "+base+"/api/perf", requireAuth(handlePerfGet))
	mux.HandleFunc("POST "+base+"/api/perf", requireAuth(requireCSRF(handlePerfPost)))
	mux.HandleFunc("GET "+base+"/api/carrier", requireAuth(handleCarrierGet))
	mux.HandleFunc("POST "+base+"/api/carrier", requireAuth(requireCSRF(handleCarrierPost)))
	mux.HandleFunc("GET "+base+"/api/fleet", requireAuth(handleFleet))
	mux.HandleFunc("GET "+base+"/api/dial", requireAuth(handleDialGet))
	mux.HandleFunc("POST "+base+"/api/dial", requireAuth(requireCSRF(handleDialPost)))
	mux.HandleFunc("GET "+base+"/api/support", requireAuth(handleSupport))
	mux.HandleFunc("POST "+base+"/api/support", requireAuth(requireCSRF(handleSupport)))
	mux.HandleFunc("GET "+base+"/api/doctor", requireAuth(handleDoctorGet))
	mux.HandleFunc("POST "+base+"/api/doctor", requireAuth(requireCSRF(handleDoctorPost)))

	// Peer-to-peer synchronization & commands
	mux.HandleFunc("POST "+base+"/api/peer/handshake", requirePeerAuth(handlePeerHandshake))
	mux.HandleFunc("POST "+base+"/api/peer/apply-carrier", requirePeerAuth(handlePeerApplyCarrier))
	mux.HandleFunc("POST "+base+"/api/peer/apply-engine", requirePeerAuth(handlePeerApplyEngine))
	mux.HandleFunc("POST "+base+"/api/peer/ping", requirePeerAuth(handlePeerPing))
	mux.HandleFunc("GET "+base+"/api/peer/rescue-offer", requireRescuePeerAuth(handlePeerRescueOffer))
	mux.HandleFunc("POST "+base+"/api/peer/rescue-ack", requireRescuePeerAuth(handlePeerRescueAck))
	mux.HandleFunc("GET "+base+"/api/rescue", requireAuth(handleRescueGet))
	mux.HandleFunc("POST "+base+"/api/rescue", requireAuth(requireCSRF(handleRescuePost)))
	mux.HandleFunc("GET "+base+"/api/peer/status", requirePeerAuth(handlePeerStatus))
	mux.HandleFunc("GET "+base+"/api/peer/config", requireAuth(handlePeerConfigGet))
	mux.HandleFunc("POST "+base+"/api/peer/config", requireAuth(requireCSRF(handlePeerConfigPost)))

	// Carrier benchmark & auto-pilot
	mux.HandleFunc("GET "+base+"/api/benchmark", requireAuth(handleBenchmarkGet))
	mux.HandleFunc("POST "+base+"/api/benchmark/run", requireAuth(requireCSRF(handleBenchmarkRun)))
	mux.HandleFunc("POST "+base+"/api/benchmark/apply", requireAuth(requireCSRF(handleBenchmarkApply)))
	mux.HandleFunc("POST "+base+"/api/benchmark/autopilot", requireAuth(requireCSRF(handleBenchmarkAutoPilot)))

	addr := fmt.Sprintf(":%d", cfg.Port)
	log.Printf("gre-panel listening on %s under /%s", addr, cfg.BasePath)
	go startHTTPSListener()
	go startAutoPilotMonitor()
	go startPeerSyncWorker()
	go startTrafficRecorder()
	go startFleetSampler()
	go startRescueMonitor()
	go func() {
		cc := loadCarrierConfig()
		if strings.HasPrefix(cc.ActiveCarrier, "wss") {
			_ = startWSSCarrier(loadWSSConfig())
		}
	}()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		next := pickFreePort(cfg.Port + 1)
		log.Printf("panel port %d busy — auto-switched to %d (saved to panel.json)", cfg.Port, next)
		cfg.Port = next
		saveCfg()
		addr = fmt.Sprintf(":%d", cfg.Port)
		log.Printf("gre-panel listening on %s under /%s", addr, cfg.BasePath)
		ln, err = net.Listen("tcp", addr)
		if err != nil {
			log.Fatal(err)
		}
	}
	srv := &http.Server{
		Handler:           securityMiddleware(mux),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	log.Fatal(srv.Serve(ln))
}

func serveAsset(name, ctype string) http.HandlerFunc {
	// Pre-compress text assets once at first request: on lossy Iran links,
	// xterm.js (283KB) stalled mid-transfer while small files passed through.
	// gzip shrinks it to ~70KB so the panel loads instantly.
	type blob struct {
		raw []byte
		gz  []byte
	}
	var mu sync.Mutex
	cache := map[string]*blob{}
	gzOK := func(ct string) bool {
		return strings.HasPrefix(ct, "text/") || strings.Contains(ct, "javascript") || strings.HasSuffix(ct, ".woff2") || ct == "font/woff2"
	}
	return func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		b, ok := cache[name]
		if !ok {
			data, err := panelFS.ReadFile(name)
			mu.Unlock()
			if err != nil {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			b = &blob{raw: data}
			if gzOK(ctype) {
				var buf bytes.Buffer
				gw := gzip.NewWriter(&buf)
				_, _ = gw.Write(data)
				_ = gw.Close()
				b.gz = buf.Bytes()
			}
			mu.Lock()
			cache[name] = b
			mu.Unlock()
		} else {
			mu.Unlock()
		}
		w.Header().Set("Content-Type", ctype)
		w.Header().Set("Cache-Control", "public, max-age=86400")
		if len(b.gz) > 0 && strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			w.Header().Set("Content-Encoding", "gzip")
			w.Header().Set("Vary", "Accept-Encoding")
			_, _ = w.Write(b.gz)
			return
		}
		_, _ = w.Write(b.raw)
	}
}

func serveIndex(w http.ResponseWriter, r *http.Request) {
	data, err := panelFS.ReadFile("index.html")
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	page := strings.ReplaceAll(string(data), "__BASE_PATH__", "/"+cfg.BasePath)
	// Cache-bust first-party CSS per build: assets are served with a 24h cache.
	for _, f := range []string{"tokens.css", "base.css", "enterprise.css"} {
		page = strings.ReplaceAll(page, `href="`+f+`"`, `href="`+f+`?v=`+panelVersion+`"`)
	}
	body := []byte(page)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") && len(body) > 1024 {
		var buf bytes.Buffer
		gw := gzip.NewWriter(&buf)
		_, _ = gw.Write(body)
		_ = gw.Close()
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Vary", "Accept-Encoding")
		_, _ = w.Write(buf.Bytes())
		return
	}
	_, _ = w.Write(body)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// handleHealth is unauthenticated: lets browsers/proxies verify the panel
// is reachable without exposing any data.
func handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]string{"status": "ok", "version": panelVersion})
}
