package main

// Panel access settings: HTTP port, login username, and URL base path.
// Changed only through POST /api/access (auth + CSRF, current password
// required); applied by restarting ONLY the gre-panel service — tunnels
// (FRP/Backhaul/GRE) are never touched. The response carries the new URL so
// the UI can redirect after the restart.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	basePathRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{2,62}[A-Za-z0-9]$`)
	usernameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{3,64}$`)
)

// accessTunnelPorts lists ports the panel must not steal (tunnel bind/FRP/
// proxies). A var so tests inject a deterministic view; production reads the
// live local status.
var accessTunnelPorts = func() map[int]string {
	st := localStatus()
	out := map[int]string{}
	if st.BindPort > 0 {
		out[st.BindPort] = "Tunnel Bind Port (" + st.TunnelEngine + ")"
	}
	if st.FrpPort > 0 {
		out[st.FrpPort] = "FRP Port"
	}
	for _, p := range st.ProxyPorts {
		if p > 0 {
			out[p] = fmt.Sprintf("Tunnel Proxy Port (%d)", p)
		}
	}
	for _, pStr := range st.Proxies {
		if p, err := strconv.Atoi(pStr); err == nil && p > 0 {
			out[p] = fmt.Sprintf("Tunnel Proxy Port (%s)", pStr)
		}
	}
	return out
}

// accessRestarter restarts only the panel service (var for tests).
var accessRestarter = func() error { return runSystemctl("restart", "gre-panel") }

func validBasePath(s string) bool { return basePathRe.MatchString(s) }
func validUsername(s string) bool { return usernameRe.MatchString(s) }

// GET /api/access — current access settings (no secrets).
func handleAccessGet(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()
	writeJSON(w, map[string]any{
		"username":   cfg.Username,
		"http_port":  cfg.Port,
		"https_port": effectiveTLSPort(),
		"base_path":  cfg.BasePath,
		"http_url":   tlsHTTPURL(),
	})
}

// POST /api/access {current_password, port?, username?, base_path?}
func handleAccessPost(w http.ResponseWriter, r *http.Request) {
	var body struct {
		CurrentPassword string `json:"current_password"`
		Port            *int   `json:"port"`
		Username        string `json:"username"`
		BasePath        string `json:"base_path"`
		HasUsername     bool
		HasBasePath     bool
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	raw := map[string]any{}
	if err := dec.Decode(&raw); err != nil {
		writeAPIError(w, r, "E-ACCESS-01", "")
		return
	}
	if v, ok := raw["current_password"].(string); ok {
		body.CurrentPassword = v
	}
	if v, ok := raw["port"].(float64); ok {
		p := int(v)
		body.Port = &p
	} else if _, ok := raw["port"]; ok {
		writeAPIError(w, r, "E-ACCESS-01", "port must be a number 1-65535")
		return
	}
	if v, ok := raw["username"].(string); ok {
		body.Username, body.HasUsername = v, true
	} else if _, ok := raw["username"]; ok {
		writeAPIError(w, r, "E-ACCESS-01", "username must be a string")
		return
	}
	if v, ok := raw["base_path"].(string); ok {
		body.BasePath, body.HasBasePath = v, true
	} else if _, ok := raw["base_path"]; ok {
		writeAPIError(w, r, "E-ACCESS-01", "base_path must be a string")
		return
	}

	mu.Lock()
	storedHash, curUser := cfg.PassHash, cfg.Username
	mu.Unlock()
	okPass, _ := verifyPassword(storedHash, body.CurrentPassword)
	if !okPass {
		recordLoginFailure(clientIP(r))
		LogSecurityAudit("access_change_rejected", curUser, clientIP(r), "incorrect current password")
		writeAPIError(w, r, "E-ACCESS-02", "")
		return
	}

	mu.Lock()
	changed := []string{}
	if body.Port != nil && *body.Port != cfg.Port {
		p := *body.Port
		if p < 1 || p > 65535 {
			mu.Unlock()
			writeAPIError(w, r, "E-ACCESS-01", "port must be 1-65535")
			return
		}
		if p == 80 || p == 443 {
			mu.Unlock()
			writeAPIError(w, r, "E-ACCESS-03", fmt.Sprintf("port %d is reserved (use a reverse proxy in front of the panel, or the HTTPS listener)", p))
			return
		}
		if p == effectiveTLSPort() {
			mu.Unlock()
			writeAPIError(w, r, "E-ACCESS-03", fmt.Sprintf("port %d is already the panel HTTPS port", p))
			return
		}
		if reason, clash := accessTunnelPorts()[p]; clash {
			mu.Unlock()
			writeAPIError(w, r, "E-ACCESS-03", fmt.Sprintf("port %d is used by %s", p, reason))
			return
		}
		cfg.Port = p
		changed = append(changed, "port="+strconv.Itoa(p))
	}
	if body.HasUsername && body.Username != cfg.Username {
		if !validUsername(body.Username) {
			mu.Unlock()
			writeAPIError(w, r, "E-ACCESS-01", "username must be 3-64 chars: letters, digits, . _ -")
			return
		}
		changed = append(changed, "username="+cfg.Username+"->"+body.Username)
		cfg.Username = body.Username
	}
	if body.HasBasePath && body.BasePath != cfg.BasePath {
		if !validBasePath(body.BasePath) {
			mu.Unlock()
			writeAPIError(w, r, "E-ACCESS-01", "base_path must be 4-64 chars: letters, digits, _ -")
			return
		}
		changed = append(changed, "base_path="+cfg.BasePath+"->"+body.BasePath)
		cfg.BasePath = body.BasePath
	}
	if len(changed) == 0 {
		mu.Unlock()
		writeAPIError(w, r, "E-ACCESS-01", "nothing to change")
		return
	}
	saveCfg()
	newURL := tlsHTTPURL()
	respPort, respBase, respUser := cfg.Port, cfg.BasePath, cfg.Username
	changes := strings.Join(changed, ", ")
	mu.Unlock()

	LogSecurityAudit("access_changed", respUser, clientIP(r), "changed "+changes)
	recordError("E-ACCESS-00", r.Method+" "+r.URL.Path, "access settings changed: "+changes)

	// Respond first (the UI redirects to newURL), then restart only gre-panel.
	writeJSON(w, map[string]any{
		"status":     "ok",
		"http_url":   newURL,
		"http_port":  respPort,
		"base_path":  respBase,
		"username":   respUser,
		"restarting": true,
		"message":    "Access settings saved. The panel restarts now — reopen it at the new address. Tunnels are unaffected.",
	})
	go func() {
		time.Sleep(500 * time.Millisecond)
		_ = accessRestarter()
	}()
}
