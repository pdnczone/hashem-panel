package main

// Error codes: every backend failure returns a stable E-XXXX code so the
// exact cause is identifiable from the UI or API. Codes are also recorded
// into a small on-disk journal (panel-errors.log) and served via
// GET /api/errors. Journald/frps lines are annotated with the same codes
// by matchLogCode() so raw logs and API errors speak one language.
//
// Families:
//   E-AUTH-xx    login / session / password
//   E-SETUP-xx   setup form validation
//   E-PEER-xx    multi-peer registry (full / clash / unknown peer)
//   E-INSTALL-xx hashem.sh missing / installer failed
//   E-ACTION-xx  tunnel actions (restart/ping/remove/tune)
//   E-UPDATE-xx  version check / download / install
//   E-GRE-xx     GRE interface / ping diagnostics (log annotation)
//   E-FRP-xx     FRP diagnostics (log annotation)
//   E-BH-xx      Backhaul diagnostics (log annotation)
//   E-SYS-xx     host tooling (journalctl/systemctl missing)
//   E-WD-xx      watchdog / telegram alerts / backup

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type errInfo struct {
	Status int    `json:"-"`
	Msg    string `json:"msg"`
	Hint   string `json:"hint"`
}

var errCatalog = map[string]errInfo{
	// auth
	"E-AUTH-01": {401, "unauthorized (login required)", "Log in again from the login screen."},
	"E-AUTH-02": {401, "wrong username or password", "Check caps-lock; or use GRE_PANEL_PASSWORD to reset."},
	"E-AUTH-03": {400, "bad login request", "Reload the page and try again."},
	"E-AUTH-04": {400, "password does not meet complexity requirements", "Must be at least 12 characters and contain uppercase, lowercase, numbers, and special symbols."},
	"E-AUTH-05": {500, "cannot switch password", "Disk write failed — check /etc/gre-panel permissions."},
	"E-AUTH-06": {401, "session expired", "Log in again from the login screen."},
	"E-AUTH-07": {401, "current password is incorrect", "Verify your current password before setting a new one."},
	"E-AUTH-08": {403, "invalid or missing CSRF token", "Refresh the page and try again."},
	// setup validation
	"E-SETUP-01": {400, "bad setup request (invalid JSON)", "Reload the page and resubmit the form."},
	"E-SETUP-02": {400, "role must be iran, foreign or add-peer", "Pick the role from the Setup tab buttons."},
	"E-SETUP-03": {400, "invalid local public IP", "Use the server's real public IPv4 (Setup tab auto-detects it)."},
	"E-SETUP-04": {400, "invalid remote public IP", "Enter the other side's public IPv4 exactly."},
	"E-SETUP-05": {400, "invalid local GRE IP", "Use the suggested 10.x address or another private IPv4."},
	"E-SETUP-06": {400, "invalid peer GRE IP", "Use the suggested 10.x address or another private IPv4."},
	"E-SETUP-07": {400, "frp port must be 1-65535", "Use any free port 1-65535 (default is random 20000-60000)."},
	"E-SETUP-08": {400, "token from Iran side is required", "Copy the token shown on the Iran panel into this form — or paste the whole hsh1_... bundle (it fills every field)."},
	"E-SETUP-09": {400, "token too long (max 128, bundles longer than 256 rejected)", "Paste the token/bundle as-is; do not add extra text."},
	"E-SETUP-10": {400, "at least one reverse port is required (e.g. 443, 2083)", "Add the ports clients will connect to. If your bundle has no ports (e.g. ends with __fou...), enter ports manually in the Reverse Ports field."},
	// peers
	"E-PEER-01": {409, "peer table full (maximum foreign servers reached)", "Remove one peer card before adding another, or increase GRE_MAX_PEERS in environment variables."},
	"E-PEER-02": {409, "reverse port already served by another tunnel", "Pick a different port — the conflicting peer is named in the message."},
	"E-PEER-03": {409, "tunnel already exists on this server", "Resubmit with force:true to overwrite, or remove it first."},
	"E-PEER-04": {404, "unknown peer id", "Refresh the page; the peer may have been removed."},
	"E-PEER-05": {400, "bad peer id", "Refresh the page and try again."},
	"E-PEER-06": {400, "use POST /api/setup with role=add-peer", "This endpoint is read-only; create peers from the Tunnel tab."},
	"E-PEER-07": {400, "invalid peer edit request", "Check the peer ID and forwarded ports list."},
	// installer
	"E-INSTALL-01": {500, "hashem.sh installer not found", "Reinstall the panel or set HASHEM_SCRIPT=/path/to/hashem.sh (legacy GRE_SCRIPT still works)."},
	"E-INSTALL-02": {500, "installer (hashem.sh) failed", "Open the steps output — failing detail is appended. \"Unknown command\" = panel hashem.sh is an old version: run Update to latest."},
	// actions
	"E-ACTION-01": {400, "unknown action", "Reload the page; the button may be from an older version."},
	"E-ACTION-02": {400, "bad action request (invalid JSON)", "Reload the page and try again."},
	"E-ACTION-03": {400, "action command failed", "See the Logs tab for this service right after the failure."},
	// update
	"E-UPDATE-01": {502, "cannot check latest release", "Server has no GitHub access (filter/DNS) — retry later."},
	"E-UPDATE-02": {502, "panel download failed", "GitHub unreachable mid-download — retry; check Iran network filter."},
	"E-UPDATE-03": {502, "downloaded file failed verification", "Corrupted download or non-ELF binary — retry update."},
	"E-UPDATE-04": {500, "cannot install new binary (rolled back)", "Disk full or /usr/local/bin not writable — old binary kept."},
	"E-UPDATE-05": {400, "unsupported arch for update", "Only amd64/arm64 prebuilt binaries are published."},
	"E-UPDATE-06": {500, "cannot sync hashem.sh installer script", "Panel binary updated, but installer script download failed — check internet or DNS."},
	"E-UPDATE-07": {502, "checksum verification failed", "Downloaded binary or script failed SHA256 checksum check."},
	"E-UPDATE-08": {400, "invalid update channel", "Channel must be stable or dev."},
	// log diagnostics (annotation only, also reused by status hints)
	"E-GRE-01": {0, "GRE interface missing / down", "Tunnel setup did not create it, or it was deleted — reinstall that peer."},
	"E-GRE-02": {0, "GRE ping failed (100% loss / unreachable)", "Peers cannot reach each other: firewall, wrong public IP, or GRE blocked."},
	"E-FRP-01": {0, "frps service not active", "Start it from the peer card (Restart) or check its log."},
	"E-FRP-02": {0, "frp authentication failed (token mismatch)", "Re-copy the token from the Iran peer card to the Foreign side."},
	"E-FRP-03": {0, "frp bind conflict (address already in use)", "Another tunnel uses this port — change frp_port or the reverse port."},
	"E-FRP-04": {0, "frp cannot reach server (connection refused/timeout)", "Iran unreachable: wrong IP/port, firewall, or frps down."},
	"E-FRP-05": {0, "file descriptor limit reached (too many open files)", "Process hit LimitNOFILE. Ensure LimitNOFILE=1048576 in systemd and kernel fs.file-max."},
	"E-FRP-06": {0, "heartbeat timeout (FRP control link dropped)", "Network jitter or heavy bandwidth contention delayed heartbeat packets. Heartbeat timeout relaxed to 90s."},
	"E-FRP-07": {0, "connection reset by peer / broken pipe", "Remote peer or network carrier reset the TCP stream."},
	"E-FRP-08": {0, "connection tracking table full (packet dropped)", "Kernel nf_conntrack_max limit reached under high concurrent connections. Run Optimize in Tunnel tab."},
	"E-FRP-09": {0, "yamux stream capacity / buffer overflow", "High stream contention on single TCP mux. Increase poolCount in frpc."},
	"E-BH-01": {0, "backhaul authentication failed (token mismatch)", "The client token differs from the server token. Re-copy it from the Iran side; the token shown in logs is masked."},
	"E-BH-02": {0, "backhaul control channel failed (EOF)", "Usually a wrong token or a transport mismatch (e.g. tcp vs tcpmux/ws) between hub and spoke. Make both ends use the same transport and token."},
	"E-BH-03": {0, "backhaul rejected the config file", "The binary does not understand this config dialect (sectioned premium schema vs flat server/client). Re-run the Backhaul setup in `hashem`."},
	"E-FRP-10": {0, "frpc login failed with EOF (likely tcpMux mismatch)", "tcpMux mismatch: hub is likely tcpMux=true, run `hashem perf tcpmux on|off` so both ends match (default OFF)."},
	"E-SYS-01": {0, "host tool unavailable", "journalctl/systemctl/ip missing on this host."},
	"E-SYS-02": {503, "panel is busy (too many requests in flight)", "Retry in a couple of seconds; /api/selfstats still answers."},
	"E-SUPPORT-01": {400, "bad support request (invalid JSON)", "Reload the page and try again."},
	"E-SUPPORT-02": {400, "unknown support action", "Use claim, close, snooze or donate."},
	"E-RESCUE-01": {400, "bad rescue request", "Reload the page and try again."},
	"E-RESCUE-02": {409, "no peer address known to test against", "Pair this server with its peer first (Settings > Peer link) or create a tunnel."},
	"E-RESCUE-03": {400, "invalid port list", "Use ports like 1020, 1030 or a range 2000-2005 (max 64)."},
	"E-RESCUE-04": {400, "cannot enable rescue", "See the message for the cause; nothing was left behind."},
	"E-RESCUE-05": {400, "cannot apply rescue code", "Paste the full code generated on the blocked server."},
	"E-RESCUE-06": {409, "rescue is not active on this server", "Enable rescue on the blocked server first."},
	"E-RESCUE-07": {403, "rescue offer denied", "Only the server named when rescue was enabled may fetch the offer."},
	// terminal (Phase 3)
	"E-TERM-00": {0, "terminal command audit", "Informational: redacted command line from the terminal session."},
	"E-TERM-01": {500, "cannot start shell", "bash/sh missing or PTY unavailable on this host."},
	"E-TERM-06": {500, "terminal output overflow (session killed)", "A command produced >256KB unread output — avoid full dumps, use pipes/less."},
	"E-TERM-07": {409, "terminal busy (another shell is active)", "Kill the active session from the Terminal tab first."},
	"E-TERM-08": {440, "terminal session idle too long (killed)", "Reconnect from the Terminal tab; sessions die after 10 idle minutes."},
	"E-TERM-09": {440, "terminal session reached 30 minute cap (killed)", "Reconnect for a fresh shell."},
	"E-TERM-10": {400, "no active terminal session", "Nothing to kill — connect first."},
	"E-TERM-11": {400, "bad terminal flag request", "Send {\"enabled\":true|false}."},
	// panel TLS (Let's Encrypt)
	"E-TLS-00": {0, "TLS certificate installed", "Informational: HTTPS is now served alongside HTTP."},
	"E-TLS-01": {400, "bad TLS request (invalid JSON)", "Reload the page and resubmit the form."},
	"E-TLS-02": {400, "invalid domain name", "Enter the panel domain exactly (e.g. panel.example.com) — it must point to this server."},
	"E-TLS-03": {400, "https port must be 1-65535", "Use 7443 (default) or another free port."},
	"E-TLS-04": {500, "certbot not installed", "Install certbot on this server first (apt install certbot), then retry."},
	"E-TLS-05": {502, "certificate issue/renew failed", "Port 80 must be reachable and the domain must resolve to this server."},
	"E-TLS-06": {500, "cannot install certificate", "Disk write failed — check /etc/gre-panel permissions."},
	"E-TLS-07": {400, "no certificate to renew", "Issue a certificate first from the Settings tab."},
	"E-TLS-08": {500, "HTTPS listener failed", "Port in use or bad cert — HTTP still works; check the error detail."},
	"E-TLS-09": {400, "domain DNS resolution failed", "The domain does not resolve to this server's public IP. Please verify DNS A/AAAA records before setting domain."},
	"E-TLS-10": {409, "port conflict detected", "The requested port or ACME port 80 conflicts with an active tunnel or service. Resolve port conflict or use a reverse proxy."},
	"E-TLS-11": {200, "domain removed successfully", "TLS configuration removed. Panel reverted to HTTP IP access without interrupting tunnels."},
	// watchdog & backup
	"E-WD-01": {400, "bad watchdog request", "Check request parameters and try again."},
	"E-WD-02": {502, "telegram alert failed", "Verify bot token, chat ID, and selected route."},
	"E-WD-03": {500, "backup creation failed", "Check disk space and write permissions in /var/backups/hashem."},
	"E-WD-04": {500, "backup restore failed", "Decryption failed or backup archive is corrupted."},
	"E-WD-05": {502, "telegram route unreachable", "Ensure tunnel is up or switch route to direct."},
	// performance & obfuscation
	"E-PERF-00": {0, "Performance settings applied", "Informational: settings saved and tunnels updated."},
	"E-PERF-01": {400, "bad performance request", "Check request parameters and try again."},
	"E-PERF-02": {500, "cannot save performance settings", "Disk write failed — check /etc/gre-panel permissions."},
	"E-PERF-03": {500, "cannot apply performance settings", "Check FRP services and configuration."},
}

type errEvent struct {
	Time     string `json:"time"`
	Code     string `json:"code"`
	Endpoint string `json:"endpoint"`
	Detail   string `json:"detail"`
}

var (
	errMu     sync.Mutex
	errEvents []errEvent // in-memory ring, capped
)

func errorLogPath() string { return filepath.Join(configDir, "panel-errors.log") }

// writeAPIError is the single way backend handlers report failures:
// stable JSON {error_code, error, hint} + journal entry.
func writeAPIError(w http.ResponseWriter, r *http.Request, code, detail string) {
	info, ok := errCatalog[code]
	if !ok {
		info = errInfo{Status: http.StatusBadRequest, Msg: "request failed", Hint: ""}
		code = "E-SYS-01"
	}
	msg := info.Msg
	if detail != "" {
		msg = detail
	}
	ep := ""
	if r != nil {
		ep = r.Method + " " + r.URL.Path
	}
	recordError(code, ep, msg)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(info.Status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error_code": code, "error": msg, "hint": info.Hint,
	})
}

func recordError(code, endpoint, detail string) {
	ev := errEvent{
		Time:     time.Now().Format("2006-01-02 15:04:05"),
		Code:     code,
		Endpoint: endpoint,
		Detail:   detail,
	}
	errMu.Lock()
	errEvents = append(errEvents, ev)
	if len(errEvents) > 200 {
		errEvents = errEvents[len(errEvents)-200:]
	}
	errMu.Unlock()
	line, _ := json.Marshal(ev)
	f, err := os.OpenFile(errorLogPath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err == nil {
		_, _ = f.Write(append(line, '\n'))
		_ = f.Close()
	}
}

func lastErrorEvent() *errEvent {
	errMu.Lock()
	defer errMu.Unlock()
	if len(errEvents) > 0 {
		e := errEvents[len(errEvents)-1]
		return &e
	}
	// Try reading last line from error log file if in-memory buffer is fresh
	if data, err := os.ReadFile(errorLogPath()); err == nil {
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		if len(lines) > 0 && lines[len(lines)-1] != "" {
			var e errEvent
			if json.Unmarshal([]byte(lines[len(lines)-1]), &e) == nil {
				return &e
			}
		}
	}
	return nil
}

// GET /api/errors?n=100 — recent panel error events (newest last).
func handleErrors(w http.ResponseWriter, r *http.Request) {
	n := 100
	if v := r.URL.Query().Get("n"); v != "" {
		if q, err := strconv.Atoi(v); err == nil {
			if q < 10 {
				q = 10
			}
			if q > 200 {
				q = 200
			}
			n = q
		}
	}
	errMu.Lock()
	mem := append([]errEvent(nil), errEvents...)
	errMu.Unlock()
	// merge with on-disk journal (dedupe by full line, keep last 200)
	seen := map[string]bool{}
	for _, e := range mem {
		b, _ := json.Marshal(e)
		seen[string(b)] = true
	}
	if data, err := os.ReadFile(errorLogPath()); err == nil {
		for _, ln := range strings.Split(string(data), "\n") {
			ln = strings.TrimSpace(ln)
			if ln == "" || seen[ln] {
				continue
			}
			var e errEvent
			if json.Unmarshal([]byte(ln), &e) == nil {
				mem = append(mem, e)
				seen[ln] = true
			}
		}
	}
	if len(mem) > 200 {
		mem = mem[len(mem)-200:]
	}
	if len(mem) > n {
		mem = mem[len(mem)-n:]
	}
	writeJSON(w, map[string]any{"events": mem, "count": len(mem)})
}

// matchLogCode annotates one journald/frps log line with a stable code.
// Returns "" when the line carries no known failure signature.
func matchLogCode(line string) (code, hint string) {
	l := strings.ToLower(line)
	has := func(words ...string) bool {
		for _, wd := range words {
			if strings.Contains(l, wd) {
				return true
			}
		}
		return false
	}
	switch {
	case has("invalid security token"):
		return "E-BH-01", errCatalog["E-BH-01"].Hint
	case has("failed to receive control channel response"):
		return "E-BH-02", errCatalog["E-BH-02"].Hint
	case has("neither server nor client configuration is properly set"):
		return "E-BH-03", errCatalog["E-BH-03"].Hint
	case has("connect to server error: eof"):
		return "E-FRP-10", errCatalog["E-FRP-10"].Hint
	case has("too many open files") || has("emfile", "enfile") || has("socket: too many"):
		return "E-FRP-05", errCatalog["E-FRP-05"].Hint
	case has("heartbeat timeout") || has("heartbeat out of date") || has("heartbeat failed"):
		return "E-FRP-06", errCatalog["E-FRP-06"].Hint
	case has("broken pipe") || has("connection reset by peer") || has("connection reset"):
		return "E-FRP-07", errCatalog["E-FRP-07"].Hint
	case has("nf_conntrack: table full") || has("conntrack full") || has("table full, dropping"):
		return "E-FRP-08", errCatalog["E-FRP-08"].Hint
	case has("yamux: stream reset") || has("session is closed") || has("stream reset"):
		return "E-FRP-09", errCatalog["E-FRP-09"].Hint
	case has("address already in use", "bind:") && has("7000", "bind", "listen", "error", "fail"):
		return "E-FRP-03", errCatalog["E-FRP-03"].Hint
	case has("address already in use"):
		return "E-FRP-03", errCatalog["E-FRP-03"].Hint
	case has("token", "auth") && has("mismatch", "invalid", "incorrect", "unauthorized", "failed", "reject", "denied"):
		return "E-FRP-02", errCatalog["E-FRP-02"].Hint
	case has("authentication failed", "login failed", "authorization failed"):
		return "E-FRP-02", errCatalog["E-FRP-02"].Hint
	case has("connection refused"):
		return "E-FRP-04", errCatalog["E-FRP-04"].Hint
	case has("i/o timeout", "dial timeout", "connect timeout", "deadline exceeded") && has("frp", "proxy", "tunnel", "server", "dial"):
		return "E-FRP-04", errCatalog["E-FRP-04"].Hint
	case has("cannot find device", "no such device", "network is unreachable") && has("gre"):
		return "E-GRE-01", errCatalog["E-GRE-01"].Hint
	case has("destination host unreachable", "100% packet loss", "packet loss 100%"):
		return "E-GRE-02", errCatalog["E-GRE-02"].Hint
	case has("permission denied") && has("frp", "gre", "tunnel", "bind"):
		return "E-SYS-01", errCatalog["E-SYS-01"].Hint
	case has("unauthorized", "wrong username or password") && has("login", "session", "panel"):
		return "E-AUTH-02", errCatalog["E-AUTH-02"].Hint
	case has("port", "already") && has("served", "peer", "tunnel"):
		return "E-PEER-02", errCatalog["E-PEER-02"].Hint
	case has("peer table full"):
		return "E-PEER-01", errCatalog["E-PEER-01"].Hint
	}
	return "", ""
}

type logFinding struct {
	Code  string `json:"code"`
	Msg   string `json:"msg"`
	Hint  string `json:"hint"`
	Count int    `json:"count"`
	Line  string `json:"line"` // first matching line (trimmed)
}

// summarizeLogs folds raw log text into per-code findings for the UI header.
func summarizeLogs(raw string) []logFinding {
	by := map[string]*logFinding{}
	order := []string{}
	for _, ln := range strings.Split(raw, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		code, _ := matchLogCode(ln)
		if code == "" {
			continue
		}
		f, ok := by[code]
		if !ok {
			info := errCatalog[code]
			f = &logFinding{Code: code, Msg: info.Msg, Hint: info.Hint, Line: trimLen(ln, 220)}
			by[code] = f
			order = append(order, code)
		}
		f.Count++
	}
	out := []logFinding{}
	for _, c := range order {
		out = append(out, *by[c])
	}
	return out
}

func trimLen(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
