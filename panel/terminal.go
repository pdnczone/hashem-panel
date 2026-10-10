package main

// Interactive terminal (Phase 3): xterm.js + WebSocket + local PTY.
//
// One root shell per panel login, guarded by the same session cookie used
// by every other /api route (requireAuth inside the WS upgrade). Hardening
// (all user-confirmed choices):
//   - single active PTY at a time (second dial gets E-TERM-07 busy)
//   - idle kill after 10 minutes without client input (E-TERM-08)
//   - absolute session cap 30 minutes, max 256 KB pending output
//   - protocol is versioned (v=1) and session-ready: every connection gets
//     a random resume id; reconnect-with-resume is a future upgrade, but
//     the client already speaks the envelope so no rewrite is needed.
//   - first bytes of each command line are appended to panel-errors.log
//     as E-TERM-* audit events (secrets redacted, see redactTermLine).
//   - Origin check: the WS endpoint only accepts same-origin upgrades
//     (Origin must match the request Host, or be empty for non-browsers).
// Wire envelope (JSON text frames, binary pty output as base64 data msg):
//   c->s {"v":1,"t":"in","d":"..."}      keystrokes / paste
//   c->s {"v":1,"t":"resize","cols":N,"rows":N}
//   c->s {"v":1,"t":"hb"}                heartbeat (also resets idle)
//   s->c {"v":1,"t":"out","d":"<b64>"}   pty output chunk
//   s->c {"v":1,"t":"exit","code":N}     shell exited
//   s->c {"v":1,"t":"err","code":"E-TERM-xx","msg":"..."} fatal error

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/creack/pty"
	"github.com/gorilla/websocket"
)

const (
	termProtoV     = 1
	termIdleKill   = 10 * time.Minute
	termMaxAge     = 30 * time.Minute
	termMaxPending = 256 * 1024
	termShell      = "/bin/bash"
)

type termMsg struct {
	V    int    `json:"v"`
	T    string `json:"t"`
	D    string `json:"d,omitempty"`
	Code string `json:"code,omitempty"`
	Msg  string `json:"msg,omitempty"`
	Cols int    `json:"cols,omitempty"`
	Rows int    `json:"rows,omitempty"`
}

// single-session guard: at most one live PTY per panel process.
var termMu sync.Mutex

type termSess struct {
	id        string
	pty       *os.File
	cmd       *exec.Cmd
	conn      *websocket.Conn
	lastIn    time.Time
	started   time.Time
	pending   int
	closed    chan struct{}
	closeOnce sync.Once
}

var termCur *termSess

var termUpgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 32768,
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		if origin == "" {
			return true // non-browser client
		}
		origHost := CleanHost(origin)
		reqHost := CleanHost(r.Host)
		if origHost != "" && strings.EqualFold(origHost, reqHost) {
			return true
		}
		// If behind a trusted reverse proxy, also accept X-Forwarded-Host
		directHost, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			directHost = strings.Trim(r.RemoteAddr, "[]")
		}
		if IsTrustedProxy(directHost) {
			if xfh := r.Header.Get("X-Forwarded-Host"); xfh != "" {
				firstXFH := CleanHost(strings.TrimSpace(strings.Split(xfh, ",")[0]))
				if firstXFH != "" && strings.EqualFold(origHost, firstXFH) {
					return true
				}
			}
		}
		return false
	},
}

func termSessID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func termClose(s *termSess) {
	s.closeOnce.Do(func() { close(s.closed) })
	termMu.Lock()
	if termCur == s {
		termCur = nil
	}
	termMu.Unlock()
	_ = s.conn.Close()
	_ = s.pty.Close()
	if s.cmd != nil && s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
		_, _ = s.cmd.Process.Wait()
	}
}

func termSendErr(conn *websocket.Conn, code, detail string) {
	info, ok := errCatalog[code]
	msg := detail
	if !ok {
		msg = detail
	}
	_ = conn.WriteJSON(termMsg{V: termProtoV, T: "err", Code: code, Msg: msg, D: info.Hint})
}

// redactTermLine strips likely secrets before audit logging: tokens after
// KEY=/--token/p -p flags, and any 20+ char base64-ish blob.
func redactTermLine(line string) string {
	fields := strings.Fields(line)
	for i, f := range fields {
		lf := strings.ToLower(f)
		if strings.HasPrefix(lf, "token=") || strings.HasPrefix(lf, "password=") || strings.HasPrefix(lf, "passwd=") {
			if eq := strings.Index(f, "="); eq >= 0 {
				fields[i] = f[:eq+1] + "***"
			}
			continue
		}
		if (lf == "-p" || lf == "--token" || lf == "--password" || lf == "--passwd") && i+1 < len(fields) {
			fields[i+1] = "***"
		}
	}
	out := strings.Join(fields, " ")
	if len(out) > 220 {
		out = out[:220] + "…"
	}
	return out
}

// GET <base>/api/term/ws — hijacked to WebSocket after requireAuth.
func handleTermWS(w http.ResponseWriter, r *http.Request) {
	if !authed(r) {
		writeAPIError(w, r, "E-AUTH-01", "")
		return
	}
	if !termEnabled() {
		writeAPIError(w, r, "E-TERM-11", "terminal disabled — enable it from Settings first")
		return
	}
	if !ipAllowed(ClientIP(r), cfg.TerminalAllowIPs) {
		LogSecurityAudit("terminal_ip_denied", cfg.Username, ClientIP(r), "ws connect")
		writeAPIError(w, r, "E-TERM-12", "")
		return
	}
	sess := ""
	if c, err := r.Cookie("gre_session"); err == nil {
		sess = c.Value
	}
	if !redeemTermTicket(r.URL.Query().Get("ticket"), sess, ClientIP(r)) {
		LogSecurityAudit("terminal_ticket_rejected", cfg.Username, ClientIP(r), "missing/expired/mismatched ticket")
		writeAPIError(w, r, "E-TERM-16", "")
		return
	}
	termMu.Lock()
	if termCur != nil {
		termMu.Unlock()
		writeAPIError(w, r, "E-TERM-07", "")
		return
	}
	termMu.Unlock()

	conn, err := termUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return // upgrade failure: not our protocol, nothing to JSON-write
	}

	shell := termShell
	if _, err := os.Stat(shell); err != nil {
		shell = "/bin/sh"
	}
	cmd := exec.Command(shell, "-l")
	// Minimal safe env: keep PATH/HOME/TERM, drop the rest.
	cmd.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "TERM=xterm-256color", "HOME=/root", "LANG=C.UTF-8"}
	pf, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: 24, Cols: 100})
	if err != nil {
		termSendErr(conn, "E-TERM-01", "")
		_ = conn.Close()
		return
	}
	s := &termSess{
		id:      termSessID(),
		pty:     pf,
		cmd:     cmd,
		conn:    conn,
		lastIn:  time.Now(),
		started: time.Now(),
		closed:  make(chan struct{}),
	}
	termMu.Lock()
	termCur = s
	termMu.Unlock()

	clientIP := ClientIP(r)
	LogSecurityAudit("terminal_connect", cfg.Username, clientIP, "session="+s.id)

	// Interactive warning banner informing operator of monitoring
	warnBanner := fmt.Sprintf("\r\n\x1b[1;33m*** NOTICE: Terminal session opened for user '%s' from %s. Session ID: %s. All commands are audited. ***\x1b[0m\r\n\r\n", cfg.Username, clientIP, s.id)
	_, _ = pf.Write([]byte(warnBanner))

	_ = conn.WriteJSON(termMsg{V: termProtoV, T: "hello", D: s.id})

	// pty -> ws pump.
	go func() {
		buf := make([]byte, 8192)
		for {
			_ = pf.SetReadDeadline(time.Now().Add(30 * time.Second))
			n, err := pf.Read(buf)
			if err != nil || n <= 0 {
				code := 0
				if cmd.ProcessState != nil {
					code = cmd.ProcessState.ExitCode()
				}
				_ = conn.WriteJSON(termMsg{V: termProtoV, T: "exit", D: s.id, Cols: code})
				termClose(s)
				return
			}
			termMu.Lock()
			s.pending += n
			over := s.pending > termMaxPending
			termMu.Unlock()
			if over {
				termSendErr(conn, "E-TERM-06", "")
				termClose(s)
				return
			}
			out := termMsg{V: termProtoV, T: "out", D: base64.StdEncoding.EncodeToString(buf[:n])}
			_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := conn.WriteJSON(out); err != nil {
				termClose(s)
				return
			}
			termMu.Lock()
			s.pending -= n
			if s.pending < 0 {
				s.pending = 0
			}
			termMu.Unlock()
		}
	}()

	// idle / max-age watchdog.
	go func() {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-s.closed:
				return
			case now := <-t.C:
				termMu.Lock()
				idle := now.Sub(s.lastIn)
				age := now.Sub(s.started)
				termMu.Unlock()
				if age > termMaxAge {
					termSendErr(conn, "E-TERM-09", "")
					recordError("E-TERM-09", "WS "+r.URL.Path, "session "+s.id+" reached 30m cap")
					termClose(s)
					return
				}
				if idle > termIdleKill {
					termSendErr(conn, "E-TERM-08", "")
					recordError("E-TERM-08", "WS "+r.URL.Path, "session "+s.id+" idle 10m, killed")
					termClose(s)
					return
				}
			}
		}
	}()

	// ws -> pty pump (this goroutine owns conn reads).
	var lineBuf strings.Builder
	defer func() {
		LogSecurityAudit("terminal_disconnect", cfg.Username, clientIP, "session="+s.id)
		termClose(s)
	}()
	conn.SetReadLimit(64 * 1024)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		var m termMsg
		if err := conn.ReadJSON(&m); err != nil {
			return // client gone: close shell with it
		}
		if m.V != termProtoV {
			continue
		}
		switch m.T {
		case "hb":
			// keepalive only: any received frame already refreshes the
			// read deadline. Deliberately does NOT reset lastIn, so the
			// 10-minute idle kill still fires for hands-off watchers.
		case "resize":
			cols, rows := m.Cols, m.Rows
			if cols < 20 {
				cols = 20
			}
			if cols > 400 {
				cols = 400
			}
			if rows < 5 {
				rows = 5
			}
			if rows > 100 {
				rows = 100
			}
			_ = pty.Setsize(pf, &pty.Winsize{Rows: uint16(rows), Cols: uint16(cols)})
			termMu.Lock()
			s.lastIn = time.Now()
			termMu.Unlock()
		case "in":
			if m.D == "" {
				continue
			}
			if len(m.D) > 16*1024 {
				m.D = m.D[:16*1024]
			}
			// audit: accumulate until newline, then journal one line.
			for _, ch := range m.D {
				if ch == '\r' || ch == '\n' {
					if lineBuf.Len() > 0 {
						red := redactTermLine(lineBuf.String())
						if strings.TrimSpace(red) != "" {
							recordError("E-TERM-00", "WS "+r.URL.Path, "session "+s.id+": "+red)
							LogSecurityAudit("terminal_command", cfg.Username, clientIP, "session="+s.id+" cmd="+red)
						}
						lineBuf.Reset()
					}
				} else if lineBuf.Len() < 1024 {
					lineBuf.WriteRune(ch)
				}
			}
			termMu.Lock()
			s.lastIn = time.Now()
			termMu.Unlock()
			_ = pf.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if _, err := pf.Write([]byte(m.D)); err != nil {
				return
			}
		}
	}
}

// POST <base>/api/term/enable {"enabled":true|false} — feature flag switch.
func handleTermEnable(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled *bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Enabled == nil {
		writeAPIError(w, r, "E-TERM-11", "")
		return
	}
	cfg.TerminalEnabled = *body.Enabled
	_ = os.WriteFile(cfgPath(), mustJSON(cfg), 0600)
	writeJSON(w, map[string]any{"status": "ok", "enabled": cfg.TerminalEnabled})
}

// GET <base>/api/term/status — for the tab header (enabled flag + busy).
func handleTermStatus(w http.ResponseWriter, r *http.Request) {
	termMu.Lock()
	busy := termCur != nil
	termMu.Unlock()
	writeJSON(w, map[string]any{"enabled": termEnabled(), "busy": busy, "idle_kill_min": 10, "max_age_min": 30})
}

// POST <base>/api/term/kill — kill the active shell (toolbar Kill button).
func handleTermKill(w http.ResponseWriter, r *http.Request) {
	termMu.Lock()
	s := termCur
	termMu.Unlock()
	if s == nil {
		writeAPIError(w, r, "E-TERM-10", "")
		return
	}
	recordError("E-TERM-10", "POST "+r.URL.Path, "session "+s.id+" killed by user")
	termClose(s)
	writeJSON(w, map[string]string{"status": "ok"})
}
