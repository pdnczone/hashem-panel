package main

// Panel TLS & Domain Layer: Decoupled, Atomic, and Zero-Tunnel-Impact.
//
// Key Architectural Principles:
// 1. Strict Layer Separation: Domain/TLS/Proxy operations ONLY manage the Web layer.
//    Tunnel infrastructure (FRP, Backhaul, GRE, P2P) is NEVER touched, restarted,
//    or reconfigured during domain operations.
// 2. Pre-flight Checks: Validate domain syntax, verify DNS resolution, and check for
//    port conflicts with active tunnel proxies and existing listeners.
// 3. Atomic Updates & Rollback: Before any certificate issuance or renewal, existing
//    certificates are backed up. On any failure, previous state is immediately restored.
// 4. In-Process Reload: Changes to HTTPS are applied via in-process server reload
//    (startHTTPSListener), avoiding systemd restarts that would drop connections.
// 5. Clean Domain Removal: Revert back to plain HTTP IP access on demand without
//    affecting running tunnels.
// 6. Reverse Proxy Support: Seamless integration with Nginx / Caddy including WebSocket
//    upgrade and real client IP forwarding.

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func tlsDir() string      { return filepath.Join(configDir, "tls") }
func tlsCertFile() string { return filepath.Join(tlsDir(), "server.crt") }
func tlsKeyFile() string  { return filepath.Join(tlsDir(), "server.key") }
func tlsMetaFile() string { return filepath.Join(tlsDir(), "meta.json") }

type tlsMeta struct {
	Domain   string `json:"domain"`
	Email    string `json:"email,omitempty"`
	IssuedAt string `json:"issued_at"`
	Expiry   string `json:"expiry"`
	Issuer   string `json:"issuer,omitempty"`
	Source   string `json:"source,omitempty"` // letsencrypt | custom | ip (tls_acme.go)
}

var tlsDomainRe = regexp.MustCompile(`^(?i)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$`)

func tlsMetaLoad() *tlsMeta {
	data, err := os.ReadFile(tlsMetaFile())
	if err != nil {
		return nil
	}
	var m tlsMeta
	if err := json.Unmarshal(data, &m); err != nil {
		return nil
	}
	return &m
}

func tlsHasCert() bool {
	if _, err := os.Stat(tlsCertFile()); err != nil {
		return false
	}
	if _, err := os.Stat(tlsKeyFile()); err != nil {
		return false
	}
	return true
}

func tlsCertExpiry() (time.Time, string, error) {
	data, err := os.ReadFile(tlsCertFile())
	if err != nil {
		return time.Time{}, "", err
	}
	var blk *pem.Block
	for {
		blk, data = pem.Decode(data)
		if blk == nil {
			break
		}
		if blk.Type == "CERTIFICATE" {
			c, err := x509.ParseCertificate(blk.Bytes)
			if err != nil {
				continue
			}
			return c.NotAfter, c.Issuer.CommonName, nil
		}
	}
	return time.Time{}, "", fmt.Errorf("no certificate found")
}

// ---- Atomic Backup & Rollback Helpers ----

func backupTLSCerts() {
	_ = os.MkdirAll(tlsDir(), 0700)
	if _, err := os.Stat(tlsCertFile()); err == nil {
		_ = copyFile(tlsCertFile(), tlsCertFile()+".bak")
	}
	if _, err := os.Stat(tlsKeyFile()); err == nil {
		_ = copyFile(tlsKeyFile(), tlsKeyFile()+".bak")
	}
	if _, err := os.Stat(tlsMetaFile()); err == nil {
		_ = copyFile(tlsMetaFile(), tlsMetaFile()+".bak")
	}
}

func rollbackTLSCerts() {
	if _, err := os.Stat(tlsCertFile() + ".bak"); err == nil {
		_ = copyFile(tlsCertFile()+".bak", tlsCertFile())
		_ = os.Remove(tlsCertFile() + ".bak")
	}
	if _, err := os.Stat(tlsKeyFile() + ".bak"); err == nil {
		_ = copyFile(tlsKeyFile()+".bak", tlsKeyFile())
		_ = os.Remove(tlsKeyFile() + ".bak")
	}
	if _, err := os.Stat(tlsMetaFile() + ".bak"); err == nil {
		_ = copyFile(tlsMetaFile()+".bak", tlsMetaFile())
		_ = os.Remove(tlsMetaFile() + ".bak")
	}
}

func clearTLSBackups() {
	_ = os.Remove(tlsCertFile() + ".bak")
	_ = os.Remove(tlsKeyFile() + ".bak")
	_ = os.Remove(tlsMetaFile() + ".bak")
}

// ---- Pre-flight Checks: Port Conflict & DNS ----

// isPort80Available: certbot's standalone challenge needs :80. A var for tests.
var isPort80Available = func() bool {
	ln, err := net.Listen("tcp", ":80")
	if err != nil {
		return false
	}
	_ = ln.Close()
	return true
}

// checkPortConflict ensures the domain HTTPS configuration does not clash with
// active tunnel proxies, bind ports, or the existing panel HTTP port.
func checkPortConflict(requestedTLSPort int) error {
	st := localStatus()
	tunnelPorts := map[int]string{}

	if st.BindPort > 0 {
		tunnelPorts[st.BindPort] = "Tunnel Bind Port (" + st.TunnelEngine + ")"
	}
	if st.FrpPort > 0 {
		tunnelPorts[st.FrpPort] = "FRP Port"
	}
	for _, p := range st.ProxyPorts {
		if p > 0 {
			tunnelPorts[p] = fmt.Sprintf("Tunnel Proxy Port (%d)", p)
		}
	}
	for _, pStr := range st.Proxies {
		if p, err := strconv.Atoi(strings.TrimSpace(pStr)); err == nil && p > 0 {
			tunnelPorts[p] = fmt.Sprintf("Tunnel Proxy Port (%s)", pStr)
		}
	}

	for _, c := range hashemPortClaims() {
		if _, ok := tunnelPorts[c.Port]; !ok && c.Proto == "tcp" && c.Kind != claimPanel {
			tunnelPorts[c.Port] = c.Owner
		}
	}

	// 1. Check if ACME port 80 is used by a tunnel proxy
	if reason, ok := tunnelPorts[80]; ok {
		return fmt.Errorf("port 80 is forwarded by %s. Let's Encrypt HTTP challenge requires port 80. Free port 80 or use Reverse Proxy mode", reason)
	}

	// 2. Check if requested HTTPS port is used by a tunnel
	if reason, ok := tunnelPorts[requestedTLSPort]; ok {
		return fmt.Errorf("requested HTTPS port %d is forwarded by %s. Choose a dedicated panel port (e.g. 7443) or resolve conflict", requestedTLSPort, reason)
	}

	// 3. Check if requested HTTPS port collides with panel HTTP port
	if requestedTLSPort == cfg.Port {
		return fmt.Errorf("HTTPS port %d cannot be the same as HTTP port %d", requestedTLSPort, cfg.Port)
	}

	return nil
}

// checkDomainDNS resolves the domain and validates whether it points to this host.
func checkDomainDNS(domain string) ([]string, error) {
	domain = CleanHost(domain)
	if domain == "" {
		return nil, fmt.Errorf("domain is empty")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", domain)
	if err != nil || len(ips) == 0 {
		ips, err = net.DefaultResolver.LookupIP(ctx, "ip", domain)
	}
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("domain %q does not resolve to any IP address. Please verify your DNS records", domain)
	}

	var ipStrs []string
	for _, ip := range ips {
		ipStrs = append(ipStrs, ip.String())
	}

	serverIP := detectPublicIP()
	if serverIP != "" {
		matched := false
		for _, ip := range ipStrs {
			if ip == serverIP {
				matched = true
				break
			}
		}
		if !matched {
			return ipStrs, fmt.Errorf("domain %q resolves to %v, but this server's public IP is %s. DNS A record must point to this server", domain, ipStrs, serverIP)
		}
	}

	return ipStrs, nil
}

// tlsStatusJSON is shared by the API, CLI, and frontend.
func tlsStatusJSON() map[string]any {
	out := map[string]any{
		"http_port":         cfg.Port,
		"https_port":        effectiveTLSPort(),
		"http_url":          tlsHTTPURL(),
		"enabled":           tlsHasCert(),
		"panel_status":      "healthy",
		"port_80_available": isPort80Available(),
		"server_ip":         detectPublicIP(),
	}

	m := tlsMetaLoad()
	if m != nil && m.Domain != "" {
		out["domain"] = m.Domain
		out["issued_at"] = m.IssuedAt
		out["source"] = tlsSource(m)
		out["domain_status"] = "active"
	} else {
		out["domain_status"] = "not_configured"
	}

	if tlsHasCert() {
		exp, issuer, err := tlsCertExpiry()
		if err == nil {
			out["expiry"] = exp.Format("2006-01-02 15:04:05")
			out["issuer"] = issuer
			days := int(time.Until(exp).Hours() / 24)
			out["days_left"] = days
			out["expiring_soon"] = days < 15
			out["tls_status"] = "valid"
			if days < 0 {
				out["tls_status"] = "expired"
			} else if days < 15 {
				out["tls_status"] = "expiring_soon"
			}
			out["https_url"] = tlsHTTPSURL()
		} else {
			out["cert_error"] = err.Error()
			out["tls_status"] = "error"
		}
	} else {
		out["tls_status"] = "none"
	}

	// Port conflict check
	if err := checkPortConflict(effectiveTLSPort()); err != nil {
		out["port_conflict"] = true
		out["port_conflict_detail"] = err.Error()
	} else {
		out["port_conflict"] = false
	}

	return out
}

func tlsHTTPURL() string {
	ip := detectPublicIP()
	if ip == "" {
		ip = "<this-server-ip>"
	}
	return fmt.Sprintf("http://%s/%s", hostPort(ip, cfg.Port), cfg.BasePath)
}

func tlsHTTPSURL() string {
	m := tlsMetaLoad()
	host := ""
	if m != nil {
		host = m.Domain
	}
	if host == "" {
		host = detectPublicIP()
		if host == "" {
			host = "<this-server-ip>"
		}
	}
	return fmt.Sprintf("https://%s/%s", hostPort(host, effectiveTLSPort()), cfg.BasePath)
}

// GET /api/tls — status (enabled/domain/expiry/urls/ports).
func handleTLSGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, tlsStatusJSON())
}

// POST /api/tls/check — pre-flight verification before issuing
func handleTLSCheck(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Domain string `json:"domain"`
		Port   int    `json:"https_port"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	body.Domain = strings.ToLower(CleanHost(body.Domain))
	if body.Port == 0 {
		body.Port = effectiveTLSPort()
	}

	resp := map[string]any{
		"domain":            body.Domain,
		"https_port":        body.Port,
		"http_port":         cfg.Port,
		"server_ip":         detectPublicIP(),
		"port_80_available": isPort80Available(),
		"valid_domain":      tlsDomainRe.MatchString(body.Domain),
	}

	if err := checkPortConflict(body.Port); err != nil {
		resp["port_conflict"] = true
		resp["port_conflict_error"] = err.Error()
	} else {
		resp["port_conflict"] = false
	}

	if body.Domain != "" && tlsDomainRe.MatchString(body.Domain) {
		ips, err := checkDomainDNS(body.Domain)
		if err != nil {
			resp["dns_ok"] = false
			resp["dns_error"] = err.Error()
		} else {
			resp["dns_ok"] = true
		}
		resp["resolved_ips"] = ips
	}

	resp["certbot_installed"] = certbotLookPath() == nil // installed on demand by the issue

	writeJSON(w, resp)
}

// POST /api/tls {"domain":"panel.example.com","email":"...","https_port":7443,"skip_dns_check":false,"action":"issue|remove"}
func handleTLSIssue(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Action       string `json:"action"`
		Domain       string `json:"domain"`
		Email        string `json:"email"`
		Port         int    `json:"https_port"`
		SkipDNSCheck bool   `json:"skip_dns_check"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeAPIError(w, r, "E-TLS-01", "")
		return
	}

	if strings.EqualFold(body.Action, "remove") {
		handleTLSRemove(w, r)
		return
	}

	if err := tlsIssueLetsEncrypt(body.Domain, body.Email, body.Port, body.SkipDNSCheck); err != nil {
		writeTLSFail(w, r, err)
		return
	}
	domain := strings.ToLower(CleanHost(body.Domain))
	LogSecurityAudit("DOMAIN_CONFIGURED", cfg.Username, ClientIP(r), "Domain "+domain+" configured with HTTPS on port "+strconv.Itoa(effectiveTLSPort()))
	writeJSON(w, tlsStatusJSON())
}

// writeTLSFail answers with the code a tlsFail carries.
func writeTLSFail(w http.ResponseWriter, r *http.Request, err error) {
	if f, ok := err.(*tlsFail); ok {
		writeAPIError(w, r, f.code, f.msg)
		return
	}
	writeAPIError(w, r, "E-TLS-06", err.Error())
}

// POST /api/tls/renew — certbot renew --cert-name domain, re-install, reload.
func handleTLSRenew(w http.ResponseWriter, r *http.Request) {
	renewed, err := tlsRenewCurrent()
	if err != nil {
		writeTLSFail(w, r, err)
		return
	}
	m := tlsMetaLoad()
	LogSecurityAudit("DOMAIN_RENEWED", cfg.Username, ClientIP(r), "Certificate renewed for "+m.Domain)
	out := tlsStatusJSON()
	out["renewed"] = renewed
	writeJSON(w, out)
}

// DELETE /api/tls or POST /api/tls {"action":"remove"} — clean domain removal
func handleTLSRemove(w http.ResponseWriter, r *http.Request) {
	tlsRemoveAll()
	LogSecurityAudit("DOMAIN_REMOVED", cfg.Username, ClientIP(r), "Domain removed; reverted to HTTP IP access")
	recordError("E-TLS-11", r.Method+" "+r.URL.Path, "TLS domain removed, reverted to HTTP")

	writeJSON(w, map[string]any{
		"success": true,
		"status":  tlsStatusJSON(),
		"message": "Domain removed successfully. Panel remains accessible via HTTP on port " + strconv.Itoa(cfg.Port),
	})
}

// GET /api/tls/proxy-config — generate production-ready Nginx & Caddy reverse proxy configs
func handleReverseProxyConfig(w http.ResponseWriter, r *http.Request) {
	domain := strings.TrimSpace(r.URL.Query().Get("domain"))
	if domain == "" {
		if m := tlsMetaLoad(); m != nil && m.Domain != "" {
			domain = m.Domain
		}
	}
	if domain == "" {
		domain = "panel.example.com"
	}
	httpPort := cfg.Port
	if httpPort == 0 {
		httpPort = 7777
	}

	nginxConf := fmt.Sprintf(`# Nginx Reverse Proxy Configuration for Hashem Panel
# The panel only trusts X-Forwarded-* from listed proxies. Allow this local one:
#   systemctl edit gre-panel   ->  [Service]
#                                  Environment=TRUSTED_PROXY_IPS=127.0.0.1
#   systemctl restart gre-panel
server {
    listen 80;
    server_name %s;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name %s;

    # SSL Certificates
    ssl_certificate /etc/gre-panel/tls/server.crt; # or /etc/letsencrypt/live/%s/fullchain.pem
    ssl_certificate_key /etc/gre-panel/tls/server.key; # or /etc/letsencrypt/live/%s/privkey.pem

    # Proxy Performance & Timeouts
    client_max_body_size 50M;
    proxy_read_timeout 3600s;
    proxy_send_timeout 3600s;

    location / {
        proxy_pass http://127.0.0.1:%d;
        proxy_http_version 1.1;

        # Standard Proxy Headers (Trusted by Panel)
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;

        # WebSocket Upgrade for Terminal & Realtime Telemetry
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
`, domain, domain, domain, domain, httpPort)

	caddyConf := fmt.Sprintf(`# Caddyfile Configuration for Hashem Panel
# Also set Environment=TRUSTED_PROXY_IPS=127.0.0.1 on gre-panel (systemctl edit gre-panel).
%s {
    reverse_proxy 127.0.0.1:%d {
        header_up Host {host}
        header_up X-Real-IP {remote_host}
        header_up X-Forwarded-For {remote_host}
        header_up X-Forwarded-Proto {scheme}
        header_up X-Forwarded-Host {host}
    }
}
`, domain, httpPort)

	writeJSON(w, map[string]any{
		"domain":    domain,
		"http_port": httpPort,
		"base_path": cfg.BasePath,
		"nginx":     nginxConf,
		"caddy":     caddyConf,
		// Without it the panel sees every visitor as 127.0.0.1 behind the proxy.
		"trusted_proxy_env": "TRUSTED_PROXY_IPS=127.0.0.1",
		"trusted_proxy_set": IsTrustedProxy("127.0.0.1"),
	})
}

// In-process HTTPS listener management:
// Avoids restarting the gre-panel systemd service, thus never dropping tunnels.
var (
	httpsSrv     *http.Server
	httpsSrvPort int
	httpsSrvMu   sync.Mutex
	// httpsCert is served through GetCertificate, so a new certificate takes
	// effect on the next handshake without restarting the listener.
	httpsCert atomic.Pointer[tls.Certificate]
)

func stopHTTPSListener() {
	httpsSrvMu.Lock()
	defer httpsSrvMu.Unlock()
	if httpsSrv != nil {
		_ = httpsSrv.Close()
		httpsSrv = nil
		httpsSrvPort = 0
	}
}

// startHTTPSListener starts the HTTPS listener, or reloads its certificate
// when it already runs on the configured port. It used to Close() the running
// server first, which cut the very request (issue/renew/upload over HTTPS)
// that asked for the reload, so the UI showed a network error (M7).
func startHTTPSListener() {
	if cliMode { // gre-panel tls ...: the service restart serves the new files
		return
	}
	httpsSrvMu.Lock()
	defer httpsSrvMu.Unlock()

	if !tlsHasCert() {
		return
	}
	c, err := tls.LoadX509KeyPair(tlsCertFile(), tlsKeyFile())
	if err != nil {
		recordError("E-TLS-08", "HTTPS listener", "load certificate: "+err.Error())
		return
	}
	httpsCert.Store(&c)

	port := effectiveTLSPort()
	if httpsSrv != nil && httpsSrvPort == port {
		return // same port: the new certificate is already live
	}
	if httpsSrv != nil {
		// Port changed: let in-flight requests finish on the old listener.
		old := httpsSrv
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = old.Shutdown(ctx)
		}()
		httpsSrv = nil
	}
	if !portFree(port) {
		next := pickFreePort(port + 1)
		log.Printf("panel https port %d busy — auto-switched to %d (saved to panel.json)", port, next)
		cfg.TLSPort = next
		saveCfg()
		port = next
	}
	httpsSrv = &http.Server{
		Addr:              fmt.Sprintf(":%d", port),
		Handler:           panelHandler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
				return httpsCert.Load(), nil
			},
		},
	}
	httpsSrvPort = port
	applyServerLimits(httpsSrv)
	srvToStart := httpsSrv
	go func(srv *http.Server) {
		if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			recordError("E-TLS-08", "HTTPS listener", err.Error())
		}
	}(srvToStart)
}

// letsencryptLiveDir is where certbot keeps the current certificate; tests
// point it elsewhere.
var letsencryptLiveDir = "/etc/letsencrypt/live"

// tlsRenewTick keeps a Let's Encrypt certificate fresh (M7). The panel serves
// a copy in <configDir>/tls, which certbot's own timer never updated, so the
// panel's HTTPS expired after 90 days. Each tick installs certbot's copy when
// it differs, and runs "certbot renew" itself (at most once a day) when the
// certificate expires within 30 days, e.g. when certbot's timer is missing.
func tlsRenewTick(now time.Time, lastRenewTry *time.Time) {
	m := tlsMetaLoad()
	if m == nil || m.Domain == "" || tlsSource(m) != tlsSourceLE {
		return // an IP or custom certificate: certbot has nothing to do with it
	}
	live := filepath.Join(letsencryptLiveDir, m.Domain)
	if exp, _, err := tlsCertExpiry(); err == nil && exp.Sub(now) < 30*24*time.Hour && now.Sub(*lastRenewTry) > 24*time.Hour {
		*lastRenewTry = now
		if certbotLookPath() == nil {
			firewallOpenTCP(80)
			if out, rerr := runCmdTimeout(5*time.Minute, "certbot", "renew", "--cert-name", m.Domain, "--quiet"); rerr != nil {
				recordError("E-TLS-05", "auto-renew", strings.TrimSpace(string(out)))
			}
		}
	}
	fresh, err := os.ReadFile(filepath.Join(live, "fullchain.pem"))
	if err != nil {
		return
	}
	cur, _ := os.ReadFile(tlsCertFile())
	if bytes.Equal(fresh, cur) {
		return
	}
	if err := tlsInstallFrom(live, m.Domain, m.Email); err != nil {
		recordError("E-TLS-06", "auto-renew", err.Error())
		return
	}
	startHTTPSListener()
	LogSecurityAudit("DOMAIN_RENEWED", "system", "local", "certificate reloaded for "+m.Domain)
}

// startTLSRenewWatcher runs tlsRenewTick shortly after start and then hourly.
func startTLSRenewWatcher() {
	go func() {
		var lastTry time.Time
		time.Sleep(time.Minute)
		for {
			tlsRenewTick(time.Now(), &lastTry)
			time.Sleep(time.Hour)
		}
	}()
}

// tlsInstallFrom copies fullchain/privkey into <configDir>/tls + writes meta.
func tlsInstallFrom(liveDir, domain, email string) error {
	crt, err := os.ReadFile(filepath.Join(liveDir, "fullchain.pem"))
	if err != nil {
		return fmt.Errorf("read fullchain.pem: %w", err)
	}
	key, err := os.ReadFile(filepath.Join(liveDir, "privkey.pem"))
	if err != nil {
		return fmt.Errorf("read privkey.pem: %w", err)
	}
	if _, err := tls.X509KeyPair(crt, key); err != nil {
		return fmt.Errorf("keypair invalid: %w", err)
	}
	_ = os.MkdirAll(tlsDir(), 0700)
	if err := os.WriteFile(tlsCertFile(), crt, 0600); err != nil {
		return err
	}
	if err := os.WriteFile(tlsKeyFile(), key, 0600); err != nil {
		return err
	}
	exp, issuer, _ := tlsCertExpiry()
	meta := tlsMeta{
		Domain:   domain,
		Email:    email,
		IssuedAt: time.Now().Format("2006-01-02 15:04:05"),
		Expiry:   exp.Format("2006-01-02 15:04:05"),
		Issuer:   issuer,
		Source:   tlsSourceLE,
	}
	_ = os.WriteFile(tlsMetaFile(), mustJSON(meta), 0600)
	recordError("E-TLS-00", "TLS "+domain, "certificate installed, expires "+meta.Expiry)
	return nil
}
