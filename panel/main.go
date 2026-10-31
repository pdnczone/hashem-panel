package main

// Entry point: config load, route table, static assets.
// Auth lives in auth.go, tunnel status/actions in tunnel.go,
// setup in setup.go, dashboard metrics in dashboard.go.

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

//go:embed index.html app.js i18n-fa.js fonts.css tokens.css base.css enterprise.css favicon.png favicon.svg apple-touch-icon.png xterm.js xterm-fit.js xterm-search.js xterm.css fonts/vazirmatn.woff2
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
	// TerminalAllowIPs limits who may open the shell (IPs/CIDRs; empty = any).
	TerminalAllowIPs []string `json:"terminal_allow_ips,omitempty"`
	// TLSPort is the HTTPS listener port (default 7443). HTTP stays on Port.
	TLSPort int `json:"tls_port,omitempty"`
	// DebugEnabled mounts /debug/pprof behind auth (also HASHEM_PPROF=1).
	DebugEnabled bool `json:"debug_enabled,omitempty"`
	// RevPathAuto enables automatic application of reverse-path fixes
	// (rate-limited; report-only when false, the default).
	RevPathAuto bool `json:"revpath_auto,omitempty"`
	// Optional TOTP 2FA (off by default). Secret and recovery hashes live in
	// panel.json (0600) like the password hash.
	// IdleTimeoutMin logs a session out after this many minutes without user
	// activity (0 = off, the default).
	IdleTimeoutMin int `json:"idle_timeout_min,omitempty"`
	// MetricsToken enables GET /metrics (Prometheus) for scrapers using a
	// bearer token; empty = endpoint disabled (404).
	MetricsToken   string   `json:"metrics_token,omitempty"`
	LicenseKey     string   `json:"license_key,omitempty"`
	TOTPEnabled    bool     `json:"totp_enabled,omitempty"`
	TOTPSecret     string   `json:"totp_secret,omitempty"`
	RecoveryHashes []string `json:"recovery_hashes,omitempty"`
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
	// go build -ldflags "-X main.panelVersion=v2.8.5"
	panelVersion = "v2.8.5"
	// panelMux is shared between the HTTP listener and the HTTPS listener.
	panelMux *http.ServeMux
)

func cfgPath() string { return filepath.Join(configDir, "panel.json") }

var (
	cfgFileModTime time.Time
	cfgFileMu      sync.RWMutex
	// cfgLoaded is set once loadOrInit has populated cfg; saving before that
	// would overwrite panel.json with zero values.
	cfgLoaded atomic.Bool
	// licenseKeyCleared lets an explicit deactivation save an empty
	// LicenseKey instead of saveConfigAtomic restoring the previous one.
	licenseKeyCleared atomic.Bool
)

func recordLoadedModTime() {
	if fi, err := os.Stat(cfgPath()); err == nil {
		cfgFileMu.Lock()
		cfgFileModTime = fi.ModTime()
		cfgFileMu.Unlock()
	}
}

func reloadConfigIfChanged() {
	p := cfgPath()
	fi, err := os.Stat(p)
	if err != nil {
		return
	}
	cfgFileMu.RLock()
	lastMod := cfgFileModTime
	cfgFileMu.RUnlock()

	if !fi.ModTime().After(lastMod) {
		return
	}

	cfgFileMu.Lock()
	defer cfgFileMu.Unlock()
	if !fi.ModTime().After(cfgFileModTime) {
		return
	}

	data, err := os.ReadFile(p)
	if err != nil || len(data) == 0 {
		return
	}
	var parsed panelConfig
	if err := json.Unmarshal(data, &parsed); err == nil && strings.TrimSpace(parsed.PassHash) != "" {
		mu.Lock()
		cfg.PassHash = parsed.PassHash
		if strings.TrimSpace(parsed.Username) != "" {
			cfg.Username = parsed.Username
		}
		if parsed.LicenseKey != "" {
			cfg.LicenseKey = parsed.LicenseKey
		}
		mu.Unlock()
		cfgFileModTime = fi.ModTime()
		log.Printf("panel credentials reloaded from disk: user=%s", cfg.Username)
	}
}

func saveCfg() {
	_ = saveConfigAtomic(cfg)
}

func saveConfigAtomic(c panelConfig) error {
	p := cfgPath()
	// Prevent accidental credential or config wipe if empty fields passed
	if existingData, err := os.ReadFile(p); err == nil && len(existingData) > 0 {
		var prev panelConfig
		if json.Unmarshal(existingData, &prev) == nil {
			if strings.TrimSpace(c.PassHash) == "" && strings.TrimSpace(prev.PassHash) != "" {
				c.PassHash = prev.PassHash
			}
			if strings.TrimSpace(c.BasePath) == "" && strings.TrimSpace(prev.BasePath) != "" {
				c.BasePath = prev.BasePath
			}
			if strings.TrimSpace(c.Username) == "" && strings.TrimSpace(prev.Username) != "" {
				c.Username = prev.Username
			}
			if c.Port <= 0 && prev.Port > 0 {
				c.Port = prev.Port
			}
			if strings.TrimSpace(c.LicenseKey) == "" && strings.TrimSpace(prev.LicenseKey) != "" && !licenseKeyCleared.Load() {
				c.LicenseKey = prev.LicenseKey
			}
		}
	}
	data := mustJSON(c)
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, p); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	bak := p + ".bak"
	_ = os.WriteFile(bak, data, 0600)
	recordLoadedModTime()
	return nil
}

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
	defer cfgLoaded.Store(true)
	_ = os.MkdirAll(configDir, 0700)

	// CWE-256 Migration: Delete legacy plaintext panel.pass if it exists on disk
	legacyPassFile := filepath.Join(configDir, "panel.pass")
	if _, err := os.Stat(legacyPassFile); err == nil {
		_ = os.Remove(legacyPassFile)
		log.Printf("Security migration (CWE-256): deleted legacy plaintext password file %s", legacyPassFile)
	}

	primaryPath := cfgPath()
	data, err := os.ReadFile(primaryPath)
	if err != nil || len(data) == 0 {
		bakPath := filepath.Join(configDir, "panel.json.bak")
		if bakData, bakErr := os.ReadFile(bakPath); bakErr == nil && len(bakData) > 0 {
			data = bakData
			err = nil
			log.Printf("recovered config from backup %s", bakPath)
		}
	}
	if err != nil || len(data) == 0 {
		// Fallback check for config.json if panel.json does not exist
		altPath := filepath.Join(configDir, "config.json")
		if altData, altErr := os.ReadFile(altPath); altErr == nil && len(altData) > 0 {
			data = altData
			err = nil
			log.Printf("migrating config from %s to %s", altPath, primaryPath)
		}
	}

	var existingBasePath string
	var existingPort int
	var existingUser string
	var existingLicense string

	extractDefaults := func(src []byte) {
		var raw map[string]any
		if json.Unmarshal(src, &raw) == nil {
			if v, ok := raw["base_path"].(string); ok && strings.TrimSpace(v) != "" && existingBasePath == "" {
				existingBasePath = strings.TrimSpace(v)
			}
			if v, ok := raw["port"].(float64); ok && v >= 1 && v <= 65535 && existingPort == 0 {
				existingPort = int(v)
			}
			if v, ok := raw["username"].(string); ok && strings.TrimSpace(v) != "" && existingUser == "" {
				existingUser = strings.TrimSpace(v)
			}
			if v, ok := raw["license_key"].(string); ok && strings.TrimSpace(v) != "" && existingLicense == "" {
				existingLicense = strings.TrimSpace(v)
			}
		}
	}

	if len(data) > 0 {
		extractDefaults(data)
	}
	if existingBasePath == "" {
		if bData, bErr := os.ReadFile(filepath.Join(configDir, "panel.json.bak")); bErr == nil {
			extractDefaults(bData)
		}
	}

	if err == nil && len(data) > 0 {
		var parsed panelConfig
		if json.Unmarshal(data, &parsed) == nil && strings.TrimSpace(parsed.PassHash) != "" {
			cfg = parsed
			if strings.TrimSpace(cfg.Username) == "" {
				cfg.Username = "admin"
			}
			if cfg.Port <= 0 || cfg.Port > 65535 {
				cfg.Port = 7777
			}
			if strings.TrimSpace(cfg.BasePath) == "" {
				if existingBasePath != "" {
					cfg.BasePath = existingBasePath
				} else {
					cfg.BasePath = "panel"
				}
			}
			// Test/dev override: fixed password via env (takes effect on restart).
			if pw := os.Getenv("GRE_PANEL_PASSWORD"); pw != "" {
				cfg.PassHash = hashPassword(pw)
				saveCfg()
				log.Printf("panel password updated from GRE_PANEL_PASSWORD environment variable")
			}
			recordLoadedModTime()
			return
		}

		// Resilient fallback: rescue credentials if fields differed or minor format issue
		var raw map[string]any
		if json.Unmarshal(data, &raw) == nil {
			passHash := ""
			for _, k := range []string{"pass_hash", "password", "hash", "admin_pass", "admin_password"} {
				if v, ok := raw[k].(string); ok && strings.TrimSpace(v) != "" {
					passHash = strings.TrimSpace(v)
					break
				}
			}
			if passHash != "" {
				username := "admin"
				if existingUser != "" {
					username = existingUser
				}
				port := 7777
				if existingPort != 0 {
					port = existingPort
				}
				basePath := "panel"
				if existingBasePath != "" {
					basePath = existingBasePath
				}

				if !strings.HasPrefix(passHash, "argon2id$") && !strings.HasPrefix(passHash, "$argon2id$") && len(passHash) != 64 {
					passHash = hashPassword(passHash)
				}

				cfg = panelConfig{
					Username:   username,
					PassHash:   passHash,
					Port:       port,
					BasePath:   basePath,
					LicenseKey: existingLicense,
				}
				saveCfg()
				recordLoadedModTime()
				log.Printf("rescued panel credentials from config (user: %s, port: %d, base: %s)", cfg.Username, cfg.Port, cfg.BasePath)
				return
			}
		}
	}

	pass := os.Getenv("GRE_PANEL_PASSWORD")
	if pass == "" {
		pass = SecureRandomPassword(16)
	}

	basePath := existingBasePath
	if basePath == "" {
		basePath = randomBase(12)
	}
	port := 7777
	if existingPort != 0 {
		port = existingPort
	}
	user := "admin"
	if existingUser != "" {
		user = existingUser
	}

	cfg = panelConfig{
		Username:   user,
		PassHash:   hashPassword(pass),
		Port:       port,
		BasePath:   basePath,
		LicenseKey: existingLicense,
	}
	saveCfg()
	recordLoadedModTime()
	log.Printf("==================================================")
	log.Printf("INITIAL PANEL PASSWORD: %s (user: %s, base: /%s)", pass, cfg.Username, cfg.BasePath)
	log.Printf("Please record this password now. Plaintext is not stored on disk.")
	log.Printf("==================================================")
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

func getOutboundIP() string {
	conn, err := net.Dial("udp", "1.1.1.1:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()
	localAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || localAddr.IP == nil {
		return "127.0.0.1"
	}
	return localAddr.IP.String()
}

func cliSetPassword(args []string) int {
	if v := os.Getenv("GRE_PANEL_DIR"); v != "" {
		configDir = v
	}
	loadOrInit()

	newPass := ""
	if len(args) > 0 && strings.TrimSpace(args[0]) != "" {
		newPass = strings.TrimSpace(args[0])
	} else {
		newPass = SecureRandomPassword(16)
	}

	if len(newPass) < 8 {
		fmt.Fprintf(os.Stderr, "Error: password must be at least 8 characters\n")
		return 1
	}

	mu.Lock()
	cfg.PassHash = hashPassword(newPass)
	saveCfg()
	mu.Unlock()

	ResetAllLockouts()

	ip := getOutboundIP()
	fmt.Println("==================================================")
	fmt.Println("[OK] Panel password updated.")
	fmt.Printf("Username:  %s\n", cfg.Username)
	fmt.Printf("Password:  %s\n", newPass)
	fmt.Printf("Base Path: /%s (UNCHANGED)\n", cfg.BasePath)
	fmt.Printf("Login URL: http://%s:%d/%s/\n", ip, cfg.Port, cfg.BasePath)
	fmt.Println("==================================================")
	return 0
}

func cliShowInfo() int {
	if v := os.Getenv("GRE_PANEL_DIR"); v != "" {
		configDir = v
	}
	loadOrInit()
	ip := getOutboundIP()
	fmt.Println("==================================================")
	fmt.Println("Hashem GRE-FRP Web Panel Info")
	fmt.Printf("Username:  %s\n", cfg.Username)
	fmt.Printf("Port:      %d\n", cfg.Port)
	fmt.Printf("Base Path: /%s\n", cfg.BasePath)
	fmt.Printf("Login URL: http://%s:%d/%s/\n", ip, cfg.Port, cfg.BasePath)
	fmt.Println("==================================================")
	return 0
}
func validateConfigDirs() {
	// Check and create directories if they don't exist, but only warn if we cannot create them.
	// We don't want to fail the panel if the directories are missing, but we should log.
	for _, dir := range []string{configDir, frpDir, backhaulDir} {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			if err := os.MkdirAll(dir, 0700); err != nil {
				log.Printf("WARNING: Failed to create directory %s: %v", dir, err)
			} else {
				log.Printf("INFO: Created missing directory %s", dir)
			}
		}
	}
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "--version", "-v", "version":
			fmt.Println(panelVersion)
			return
		case "--help", "-h", "help":
			fmt.Println("Usage: gre-panel [password <new-password> | info | version | tls [status|issue|renew|remove|ip|custom] | settings [show|2fa off|terminal on|off|idle N] | doctor [check|fix] | tls-proxy | pathtest | cluster [status|pool|member|join-code|add-hub|events|rules|reset] | license [status|activate|deactivate] | node [status|join CODE|-|leave]]")
			return
		case "tls-proxy":
			os.Exit(tlsProxyCmd(os.Args[2:]))
		case "bagher-carrier":
			os.Exit(bagherCarrierCmd(os.Args[2:]))
		case "sell-bagher":
			os.Exit(custBagherRelayCmd(os.Args[2:]))
		case "pathtest":
			os.Exit(cliPathTest(os.Args[2:]))
		case "cluster", "mesh":
			os.Exit(cliCluster(os.Args[2:]))
		case "password", "pass", "set-password":
			os.Exit(cliSetPassword(os.Args[2:]))
		case "info", "status", "url":
			os.Exit(cliShowInfo())
		case "license":
			os.Exit(cliLicense(os.Args[2:]))
		case "tls":
			os.Exit(cliTLS(os.Args[2:]))
		case "settings":
			os.Exit(cliSettings(os.Args[2:]))
		case "doctor":
			os.Exit(cliDoctor(os.Args[2:]))
		case "node":
			os.Exit(cliNode(os.Args[2:]))
		}
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
	if v := os.Getenv("GRE_SYSCTL_CONF"); v != "" {
		revpathSysctlConf = v
	}
	validateConfigDirs()
	loadOrInit()
	ensureFreeHTTPPort()
	if n, err := upgradeBagherKeyLocks(); err != nil {
		log.Printf("bagher: upgrading key restrictions in %s: %v", authorizedKeysPath, err)
	} else if n > 0 {
		log.Printf("bagher: locked down %d Bagher key(s) in %s (no commands, no -L forwards)", n, authorizedKeysPath)
	}
	if ok, err := migrateBagherFRPCTLS("/etc/gre-panel/bagher/frpc.toml"); err != nil {
		log.Printf("bagher: turning off frp TLS inside the SSH tunnel: %v", err)
	} else if ok {
		log.Printf("bagher: frp TLS turned off inside the SSH tunnel (it encrypted everything twice)")
	}
	if n := migrateXrayConfigs(); n > 0 {
		log.Printf("xray: %d link(s) rebuilt for this version (pre-connect: lower ping in direct mode)", n)
	}
	if ok, err := migrateBagherCarrierUnit(bagherLinkUnitPath(1)); err != nil {
		log.Printf("bagher: moving the carrier off ssh -N: %v", err)
	} else if ok {
		log.Printf("bagher: the carrier now runs in the panel (ssh -N held small packets back: high ping)")
	}
	if _, err := rand.Read(nonce[:]); err != nil {
		log.Fatal(err)
	}

	go func() {
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		nonceTicker := time.NewTicker(12 * time.Hour)
		defer nonceTicker.Stop()
		for {
			select {
			case <-ticker.C:
				reloadConfigIfChanged()
			case <-nonceTicker.C:
				rotateNonce()
			}
		}
	}()

	base := "/" + cfg.BasePath
	mux := http.NewServeMux()
	panelMux = mux
	mux.HandleFunc("GET "+base+"/", serveIndex)
	mux.HandleFunc("GET "+base+"/app.js", serveAsset("app.js", "text/javascript; charset=utf-8"))
	mux.HandleFunc("GET "+base+"/i18n-fa.js", serveAsset("i18n-fa.js", "text/javascript; charset=utf-8"))
	mux.HandleFunc("GET "+base+"/tokens.css", serveAsset("tokens.css", "text/css; charset=utf-8"))
	mux.HandleFunc("GET "+base+"/fonts.css", serveAsset("fonts.css", "text/css; charset=utf-8"))
	mux.HandleFunc("GET "+base+"/fonts/vazirmatn.woff2", serveAsset("fonts/vazirmatn.woff2", "font/woff2"))
	mux.HandleFunc("GET "+base+"/base.css", serveAsset("base.css", "text/css; charset=utf-8"))
	mux.HandleFunc("GET "+base+"/enterprise.css", serveAsset("enterprise.css", "text/css; charset=utf-8"))
	mux.HandleFunc("GET "+base+"/favicon.png", serveAsset("favicon.png", "image/png"))
	mux.HandleFunc("GET "+base+"/favicon.svg", serveAsset("favicon.svg", "image/svg+xml"))
	mux.HandleFunc("GET "+base+"/apple-touch-icon.png", serveAsset("apple-touch-icon.png", "image/png"))
	mux.HandleFunc("GET "+base+"/xterm.js", serveAsset("xterm.js", "text/javascript; charset=utf-8"))
	mux.HandleFunc("GET "+base+"/xterm-fit.js", serveAsset("xterm-fit.js", "text/javascript; charset=utf-8"))
	mux.HandleFunc("GET "+base+"/xterm-search.js", serveAsset("xterm-search.js", "text/javascript; charset=utf-8"))
	mux.HandleFunc("GET "+base+"/xterm.css", serveAsset("xterm.css", "text/css; charset=utf-8"))
	mux.HandleFunc("GET "+base+"/api/term/ws", requireAuth(handleTermWS))
	mux.HandleFunc("GET "+base+"/api/term/status", requireAuth(handleTermStatus))
	mux.HandleFunc("POST "+base+"/api/term/ticket", requireAuth(requireCSRF(handleTermTicket)))
	mux.HandleFunc("GET "+base+"/api/term/allowlist", requireAuth(handleTermAllowGet))
	mux.HandleFunc("POST "+base+"/api/term/allowlist", requireAuth(requireCSRF(handleTermAllowPost)))
	mux.HandleFunc("POST "+base+"/api/term/kill", requireAuth(requireCSRF(handleTermKill)))
	mux.HandleFunc("POST "+base+"/api/term/enable", requireAuth(requireCSRF(handleTermEnable)))
	mux.HandleFunc("GET "+base+"/api/health", handleHealth)
	mux.HandleFunc("GET "+base+"/api/status", requireAuth(handleStatus))
	mux.HandleFunc("GET "+base+"/api/dashboard", requireAuth(handleDashboard))
	mux.HandleFunc("POST "+base+"/api/login", handleLogin)
	mux.HandleFunc("POST "+base+"/api/logout", handleLogout)
	mux.HandleFunc("GET "+base+"/api/logs", requireAuth(handleLogs))
	mux.HandleFunc("GET "+base+"/api/errors", requireAuth(handleErrors))
	mux.HandleFunc("GET "+base+"/api/audit", requireAuth(handleAuditGet))
	mux.HandleFunc("GET "+base+"/api/access", requireAuth(handleAccessGet))
	mux.HandleFunc("POST "+base+"/api/access", requireAuth(requireCSRF(handleAccessPost)))
	mux.HandleFunc("GET "+base+"/api/session-settings", requireAuth(handleSessionSettingsGet))
	mux.HandleFunc("POST "+base+"/api/session-settings", requireAuth(requireCSRF(handleSessionSettingsPost)))
	mux.HandleFunc("GET "+base+"/api/alerts", requireAuth(handleAlertsGet))
	mux.HandleFunc("POST "+base+"/api/alerts", requireAuth(requireCSRF(handleAlertsPost)))
	mux.HandleFunc("GET "+base+"/api/history", requireAuth(handleHistoryGet))
	mux.HandleFunc("GET "+base+"/api/traffic/usage", requireAuth(handleUsageGet))
	mux.HandleFunc("GET "+base+"/metrics", handleMetrics)
	mux.HandleFunc("GET "+base+"/api/metrics-token", requireAuth(handleMetricsTokenGet))
	mux.HandleFunc("POST "+base+"/api/metrics-token", requireAuth(requireCSRF(handleMetricsTokenPost)))
	mux.HandleFunc("GET "+base+"/api/carrier/advice", requireAuth(handleCarrierAdvice))
	mux.HandleFunc("GET "+base+"/api/suggest", requireAuth(handleSuggest))
	mux.HandleFunc("GET "+base+"/api/2fa", requireAuth(handle2FAStatus))
	mux.HandleFunc("POST "+base+"/api/2fa/setup", requireAuth(requireCSRF(handle2FASetup)))
	mux.HandleFunc("POST "+base+"/api/2fa/enable", requireAuth(requireCSRF(handle2FAEnable)))
	mux.HandleFunc("POST "+base+"/api/2fa/disable", requireAuth(requireCSRF(handle2FADisable)))
	mux.HandleFunc("POST "+base+"/api/action", requireAuth(requireCSRF(handleAction)))
	mux.HandleFunc("POST "+base+"/api/password", requireAuth(requireCSRF(handlePassword)))
	mux.HandleFunc("GET "+base+"/api/setup", requireAuth(handleSetupGet))
	mux.HandleFunc("GET "+base+"/api/version", requireAuth(handleVersion))
	mux.HandleFunc("POST "+base+"/api/update", requireAuth(requireCSRF(handleUpdate)))
	mux.HandleFunc("GET "+base+"/api/update/channel", requireAuth(handleUpdateChannelGet))
	mux.HandleFunc("POST "+base+"/api/update/channel", requireAuth(requireCSRF(handleUpdateChannelPost)))
	mux.HandleFunc("GET "+base+"/api/releases", requireAuth(handleReleases))
	mux.HandleFunc("GET "+base+"/api/update/peer", requireAuth(handleUpdatePeer))
	mux.HandleFunc("POST "+base+"/api/setup", requireAuth(requireCSRF(handleSetupPost)))
	mux.HandleFunc("GET "+base+"/api/peers", requireAuth(handlePeersGet))
	mux.HandleFunc("POST "+base+"/api/peers", requireAuth(requireCSRF(handlePeersPost)))
	mux.HandleFunc("PATCH "+base+"/api/peers", requireAuth(requireCSRF(handlePeersPatch)))
	mux.HandleFunc("GET "+base+"/api/tls", requireAuth(handleTLSGet))
	mux.HandleFunc("POST "+base+"/api/tls", requireAuth(requireCSRF(handleTLSIssue)))
	mux.HandleFunc("DELETE "+base+"/api/tls", requireAuth(requireCSRF(handleTLSRemove)))
	mux.HandleFunc("POST "+base+"/api/tls/renew", requireAuth(requireCSRF(handleTLSRenew)))
	mux.HandleFunc("POST "+base+"/api/tls/check", requireAuth(requireCSRF(handleTLSCheck)))
	mux.HandleFunc("POST "+base+"/api/tls/custom", requireAuth(requireCSRF(handleTLSCustomPost)))
	mux.HandleFunc("POST "+base+"/api/tls/ip", requireAuth(requireCSRF(handleTLSIPPost)))
	mux.HandleFunc("GET "+base+"/api/tls/ip/ca", requireAuth(handleTLSIPCAGet))
	mux.HandleFunc("GET "+base+"/api/tls/proxy-config", requireAuth(handleReverseProxyConfig))
	mux.HandleFunc("GET "+base+"/api/watchdog", requireAuth(handleWatchdogGet))
	mux.HandleFunc("POST "+base+"/api/watchdog", requireAuth(requireCSRF(handleWatchdogPost)))
	mux.HandleFunc("GET "+base+"/api/watchdog/backup-download", requireAuth(handleBackupDownload))
	mux.HandleFunc("POST "+base+"/api/watchdog/backup-download", requireAuth(requireCSRF(handleBackupDownload)))
	mux.HandleFunc("GET "+base+"/api/perf", requireAuth(handlePerfGet))
	mux.HandleFunc("POST "+base+"/api/perf", requireAuth(requireCSRF(handlePerfPost)))
	mux.HandleFunc("GET "+base+"/api/carrier", requireAuth(handleCarrierGet))
	mux.HandleFunc("POST "+base+"/api/carrier", requireAuth(requireCSRF(handleCarrierPost)))
	mux.HandleFunc("GET "+base+"/api/tunnel/swap", requireAuth(handleSwapGet))
	mux.HandleFunc("POST "+base+"/api/tunnel/swap", requireAuth(requireCSRF(handleSwapPost)))
	mux.HandleFunc("GET "+base+"/api/spoof", requireAuth(handleSpoofGet))
	mux.HandleFunc("POST "+base+"/api/spoof", requireAuth(requireCSRF(handleSpoofPost)))
	mux.HandleFunc("GET "+base+"/api/spoof/tester", requireAuth(handleSpoofTester))
	mux.HandleFunc("POST "+base+"/api/spoof/tester", requireAuth(requireCSRF(handleSpoofTester)))
	mux.HandleFunc("GET "+base+"/api/xray", requireAuth(handleXrayGet))
	mux.HandleFunc("POST "+base+"/api/xray", requireAuth(requireCSRF(handleXrayPost)))
	mux.HandleFunc("GET "+base+"/api/limits", requireAuth(handleLimitsGet))
	mux.HandleFunc("POST "+base+"/api/limits", requireAuth(requireCSRF(handleLimitsPost)))
	mux.HandleFunc("GET "+base+"/api/customers", requireAuth(handleCustomersGet))
	mux.HandleFunc("POST "+base+"/api/customers", requireAuth(requireCSRF(handleCustomersPost)))
	mux.HandleFunc("GET "+base+"/api/customers/kit", requireAuth(handleCustomersKit))
	mux.HandleFunc("GET "+base+"/api/customers/export.csv", requireAuth(handleCustomersExport))
	mux.HandleFunc("GET "+base+"/api/customers/history", requireAuth(handleCustomersHistory))
	// a sold tunnel's status page: no login, the token in the path is the secret
	mux.HandleFunc("GET /_hs/{token}", handleCustomerStatus)
	// frps of a sold tunnel asks which proxies to allow (loopback only)
	mux.HandleFunc("POST /_hsplugin/{key}", handleCustomerPlugin)
	mux.HandleFunc("POST "+base+"/api/link-name", requireAuth(requireCSRF(handleLinkName)))
	mux.HandleFunc("GET "+base+"/api/fleet", requireAuth(handleFleet))
	mux.HandleFunc("GET "+base+"/api/selfstats", requireAuth(handleSelfStats))
	mux.HandleFunc("GET "+base+"/api/tunnel-health", requireAuth(handleTunnelHealthGet))
	mux.HandleFunc("POST "+base+"/api/tunnel-health/run", requireAuth(requireCSRF(handleTunnelHealthRun)))
	mux.HandleFunc("GET "+base+"/api/revpath", requireAuth(handleRevPathGet))
	mux.HandleFunc("POST "+base+"/api/revpath/run", requireAuth(requireCSRF(handleRevPathRun)))
	mux.HandleFunc("POST "+base+"/api/revpath/fix", requireAuth(requireCSRF(handleRevPathFix)))
	mux.HandleFunc("GET "+base+"/api/revpath/fixes", requireAuth(handleRevPathFixes))
	mountDebug(mux, base)
	mux.HandleFunc("GET "+base+"/api/dial", requireAuth(handleDialGet))
	mux.HandleFunc("POST "+base+"/api/dial", requireAuth(requireCSRF(handleDialPost)))
	mux.HandleFunc("GET "+base+"/api/support", requireAuth(handleSupport))
	mux.HandleFunc("POST "+base+"/api/support", requireAuth(requireCSRF(handleSupport)))
	mux.HandleFunc("GET "+base+"/api/doctor", requireAuth(handleDoctorGet))
	mux.HandleFunc("POST "+base+"/api/doctor", requireAuth(requireCSRF(handleDoctorPost)))

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		curBase := cfg.BasePath
		mu.Unlock()
		if curBase == "" {
			curBase = "panel"
		}
		target := "/" + curBase + "/"
		if r.URL.RawQuery != "" {
			target += "?" + r.URL.RawQuery
		}
		http.Redirect(w, r, target, http.StatusFound)
	})

	// Peer-to-peer synchronization & commands
	mountPeerRoutes(mux, base)
	mux.HandleFunc("GET "+base+"/api/peer/rescue-offer", requireRescuePeerAuth(handlePeerRescueOffer))
	mux.HandleFunc("POST "+base+"/api/peer/rescue-ack", requireRescuePeerAuth(handlePeerRescueAck))
	mux.HandleFunc("GET "+base+"/api/rescue", requireAuth(handleRescueGet))
	mux.HandleFunc("POST "+base+"/api/rescue", requireAuth(requireCSRF(handleRescuePost)))
	mux.HandleFunc("GET "+base+"/api/sshfwd", requireAuth(handleSSHFwdGet))
	mux.HandleFunc("POST "+base+"/api/sshfwd", requireAuth(requireCSRF(handleSSHFwdPost)))
	mux.HandleFunc("GET "+base+"/api/sentinel", requireAuth(handleSentinelGet))
	mux.HandleFunc("POST "+base+"/api/sentinel", requireAuth(requireCSRF(handleSentinelPost)))

	// Cluster: pools, linked Iran hubs, DNS failover, extra hubs of a foreign server
	mux.HandleFunc("GET "+base+"/api/cluster/status", requireAuth(handleClusterStatus))
	mux.HandleFunc("GET "+base+"/api/cluster/rules", requireAuth(handleClusterRules))
	mux.HandleFunc("POST "+base+"/api/cluster/pool", requireAuth(requireCSRF(handleClusterPool)))
	mux.HandleFunc("POST "+base+"/api/cluster/pool/delete", requireAuth(requireCSRF(handleClusterPoolDelete)))
	mux.HandleFunc("POST "+base+"/api/cluster/pool/failback", requireAuth(requireCSRF(handleClusterPoolFailback)))
	mux.HandleFunc("POST "+base+"/api/cluster/member", requireAuth(requireCSRF(handleClusterMember)))
	mux.HandleFunc("POST "+base+"/api/cluster/settings", requireAuth(requireCSRF(handleClusterSettings)))
	mux.HandleFunc("POST "+base+"/api/cluster/join-code", requireAuth(requireCSRF(handleClusterJoinCode)))
	mux.HandleFunc("POST "+base+"/api/cluster/hubs/add", requireAuth(requireCSRF(handleClusterHubAdd)))
	mux.HandleFunc("POST "+base+"/api/cluster/hubs/delete", requireAuth(requireCSRF(handleClusterHubDelete)))
	mux.HandleFunc("POST "+base+"/api/cluster/dns", requireAuth(requireCSRF(handleClusterDNS)))
	mux.HandleFunc("POST "+base+"/api/cluster/join-hub", requireAuth(requireCSRF(handleClusterJoinHub)))
	mux.HandleFunc("POST "+base+"/api/cluster/leave-hub", requireAuth(requireCSRF(handleClusterLeaveHub)))
	mountMeshRoutes(mux)
	// Nodes: the central's list and join codes; the channel nodes dial
	mux.HandleFunc("GET "+base+"/api/nodes", requireAuth(handleNodesGet))
	mux.HandleFunc("POST "+base+"/api/nodes", requireAuth(requireCSRF(handleNodesPost)))
	mux.HandleFunc("GET "+nodeLinkPath, handleNodeLink)
	mux.HandleFunc("GET "+base+"/api/bagher", requireAuth(handleSSHFwdGet))
	mux.HandleFunc("POST "+base+"/api/bagher", requireAuth(requireCSRF(handleSSHFwdPost)))
	mux.HandleFunc("GET "+base+"/api/license", requireAuth(handleLicenseGet))
	mux.HandleFunc("POST "+base+"/api/license", requireAuth(requireCSRF(handleLicensePost)))
	mux.HandleFunc("GET "+base+"/api/peer/config", requireAuth(handlePeerConfigGet))
	mux.HandleFunc("POST "+base+"/api/peer/config", requireAuth(requireCSRF(handlePeerConfigPost)))

	// Carrier benchmark & auto-pilot
	mux.HandleFunc("GET "+base+"/api/benchmark", requireAuth(handleBenchmarkGet))
	mux.HandleFunc("POST "+base+"/api/benchmark/run", requireAuth(requireCSRF(handleBenchmarkRun)))
	mux.HandleFunc("POST "+base+"/api/benchmark/apply", requireAuth(requireCSRF(handleBenchmarkApply)))
	mux.HandleFunc("POST "+base+"/api/benchmark/autopilot", requireAuth(requireCSRF(handleBenchmarkAutoPilot)))
	// Path test: which transports cross between the two servers, before any tunnel
	mux.HandleFunc("GET "+base+"/api/pathtest", requireAuth(handlePathTestGet))
	mux.HandleFunc("POST "+base+"/api/pathtest", requireAuth(requireCSRF(handlePathTestPost)))

	addr := fmt.Sprintf(":%d", cfg.Port)
	log.Printf("gre-panel listening on %s under /%s", addr, cfg.BasePath)
	histStop := make(chan struct{})
	loadLicenseFromDisk()
	startHistoryPersistence(histStop)
	startUsagePersistence(histStop)
	startSnapshotCollector(context.Background())
	startSdWatchdog(context.Background())
	go startHTTPSListener()
	startTLSRenewWatcher()
	go startAutoPilotMonitor()
	go startPeerSyncWorker()
	go startTrafficRecorder()
	go startFleetSampler()
	go startRescueMonitor()
	go startClusterMonitor()
	go startMeshLoop()
	go startNodeLoop()
	go startLimitsLoop()
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
	// after the busy-port switch: the sold relays' plugin calls go to cfg.Port
	go startCustomersLoop()
	srv := &http.Server{
		Handler:           panelChain(mux),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	applyServerLimits(srv)
	// Listening: an update that brought this binary in worked.
	clearUpdatePending()
	reportRollback()
	go pathMTUKeeper()
	go migrateLegacyBackhaul()
	// systemd stop sends SIGTERM: flush history, then stop serving.
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigc
		close(histStop)
		limitsFlush()
		customersFlush()
		time.Sleep(300 * time.Millisecond) // let the final history write finish
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
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

var (
	assetTagOnce sync.Once
	assetTagVal  string
)

// assetTag is the ?v= of the first-party assets: the version plus a hash of
// their content, so a new build is fetched even under the same version (a dev
// build, a rebuilt release). i18n-fa.js reuses app.js's query.
func assetTag() string {
	assetTagOnce.Do(func() {
		h := sha256.New()
		for _, f := range []string{"app.js", "i18n-fa.js", "tokens.css", "base.css", "enterprise.css"} {
			b, _ := panelFS.ReadFile(f)
			h.Write(b)
		}
		assetTagVal = panelVersion + "-" + hex.EncodeToString(h.Sum(nil)[:5])
	})
	return assetTagVal
}

func serveIndex(w http.ResponseWriter, r *http.Request) {
	if authed(r) {
		if c, err := r.Cookie("gre_session"); err == nil && c.Value != "" {
			csrfTok := GenerateCSRFToken(c.Value)
			http.SetCookie(w, csrfCookie(r, csrfTok, 86400))
		}
	}
	data, err := panelFS.ReadFile("index.html")
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	page := strings.ReplaceAll(string(data), "__BASE_PATH__", "/"+cfg.BasePath)
	// Cache-bust first-party assets per build: they are served with a 24h cache.
	for _, f := range []string{"tokens.css", "base.css", "enterprise.css"} {
		page = strings.ReplaceAll(page, `href="`+f+`"`, `href="`+f+`?v=`+assetTag()+`"`)
	}
	page = strings.ReplaceAll(page, `src="app.js"`, `src="app.js?v=`+assetTag()+`"`)
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
