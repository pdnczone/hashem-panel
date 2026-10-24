package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Terminal hardening: the root shell needs (1) the client IP to be on the
// optional allowlist and (2) a one-time ticket obtained by re-entering the
// password (plus the 2FA code when 2FA is on). Tickets are bound to the
// browser session and IP, single-use, and live 60 seconds.

const termTicketTTL = 60 * time.Second

type termTicket struct {
	session string
	ip      string
	expires time.Time
}

var (
	termTicketMu sync.Mutex
	termTickets  = map[string]termTicket{}
)

// ipAllowed reports whether ip matches any entry (plain IP or CIDR).
// An empty list allows everyone.
func ipAllowed(ip string, list []string) bool {
	if len(list) == 0 {
		return true
	}
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return false
	}
	for _, e := range list {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if strings.Contains(e, "/") {
			if _, n, err := net.ParseCIDR(e); err == nil && n.Contains(parsed) {
				return true
			}
			continue
		}
		if p := net.ParseIP(e); p != nil && p.Equal(parsed) {
			return true
		}
	}
	return false
}

// validateAllowList rejects entries that are neither an IP nor a CIDR.
func validateAllowList(list []string) bool {
	for _, e := range list {
		e = strings.TrimSpace(e)
		if strings.Contains(e, "/") {
			if _, _, err := net.ParseCIDR(e); err != nil {
				return false
			}
		} else if net.ParseIP(e) == nil {
			return false
		}
	}
	return true
}

func newTermTicket(session, ip string) string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	t := hex.EncodeToString(b)
	termTicketMu.Lock()
	now := timeNow()
	for k, v := range termTickets { // bound memory
		if now.After(v.expires) {
			delete(termTickets, k)
		}
	}
	termTickets[t] = termTicket{session: session, ip: ip, expires: now.Add(termTicketTTL)}
	termTicketMu.Unlock()
	return t
}

// redeemTermTicket consumes a ticket; it must match the session and IP.
func redeemTermTicket(t, session, ip string) bool {
	if t == "" {
		return false
	}
	termTicketMu.Lock()
	defer termTicketMu.Unlock()
	v, ok := termTickets[t]
	delete(termTickets, t) // single use, even on mismatch
	return ok && timeNow().Before(v.expires) && v.session == session && v.ip == ip
}

// POST /api/term/ticket {password, code?} -> {ticket}
func handleTermTicket(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if !ipAllowed(ip, cfg.TerminalAllowIPs) {
		LogSecurityAudit("terminal_ip_denied", cfg.Username, ip, "ticket request")
		writeAPIError(w, r, "E-TERM-12", "")
		return
	}
	if checkLocked(ip) {
		writeAPIError(w, r, "E-AUTH-02", "Too many failed attempts. Temporarily locked.")
		return
	}
	var body struct {
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeAPIError(w, r, "E-TERM-11", "")
		return
	}
	okPass, _ := verifyPassword(cfg.PassHash, body.Password)
	if !okPass || (cfg.TOTPEnabled && !checkSecondFactor(body.Code)) {
		recordLoginFailure(ip)
		LogSecurityAudit("terminal_reauth_failed", cfg.Username, ip, "bad password or code")
		writeAPIError(w, r, "E-TERM-13", "")
		return
	}
	c, _ := r.Cookie("gre_session")
	sess := ""
	if c != nil {
		sess = c.Value
	}
	writeJSON(w, map[string]any{"ticket": newTermTicket(sess, ip), "ttl_seconds": int(termTicketTTL.Seconds())})
}

// GET/POST /api/term/allowlist {ips:[...]}
func handleTermAllowGet(w http.ResponseWriter, r *http.Request) {
	list := cfg.TerminalAllowIPs
	if list == nil {
		list = []string{}
	}
	writeJSON(w, map[string]any{"ips": list, "your_ip": clientIP(r)})
}

func handleTermAllowPost(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IPs []string `json:"ips"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || !validateAllowList(body.IPs) || len(body.IPs) > 32 {
		writeAPIError(w, r, "E-TERM-14", "")
		return
	}
	if len(body.IPs) > 0 && !ipAllowed(clientIP(r), body.IPs) {
		writeAPIError(w, r, "E-TERM-15", "") // refuse a list that locks out the caller
		return
	}
	mu.Lock()
	cfg.TerminalAllowIPs = body.IPs
	saveCfg()
	mu.Unlock()
	LogSecurityAudit("terminal_allowlist_changed", cfg.Username, clientIP(r), "entries="+strings.Join(body.IPs, ","))
	writeJSON(w, map[string]any{"status": "ok", "ips": body.IPs})
}
