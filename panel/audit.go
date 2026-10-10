package main

import (
	"bufio"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Security audit log: size rotation and a read API. Writing is done by
// LogSecurityAudit (security.go); every state-changing API call is recorded
// by requireCSRF via auditMutation (method, path, status, never the body).

const (
	auditMaxBytes = 2 << 20 // rotate at 2 MiB
	auditKeep     = 3       // security-audit.log.1 .. .3
)

func auditLogPath() string { return filepath.Join(configDir, "security-audit.log") }

// rotateAuditLocked shifts .log -> .1 -> .2 -> .3 when the log is too big.
// Caller holds auditMu.
func rotateAuditLocked(path string) {
	fi, err := os.Stat(path)
	if err != nil || fi.Size() < auditMaxBytes {
		return
	}
	_ = os.Remove(path + "." + strconv.Itoa(auditKeep))
	for i := auditKeep - 1; i >= 1; i-- {
		_ = os.Rename(path+"."+strconv.Itoa(i), path+"."+strconv.Itoa(i+1))
	}
	_ = os.Rename(path, path+".1")
}

// statusRecorder captures the response status for the audit line.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *statusRecorder) Hijack() (c net.Conn, rw *bufio.ReadWriter, err error) {
	h, ok := s.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	return h.Hijack()
}

// auditMutation logs one state-changing API call after it finished.
func auditMutation(r *http.Request, status int) {
	if status == 0 {
		status = http.StatusOK
	}
	LogSecurityAudit("api_mutation", cfg.Username, ClientIP(r),
		"method="+r.Method+" path="+r.URL.Path+" status="+strconv.Itoa(status))
}

// tailLines returns the last n lines of path (oldest first).
func tailLines(path string, n int) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	ring := make([]string, 0, n)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		if len(ring) == n {
			copy(ring, ring[1:])
			ring = ring[:n-1]
		}
		ring = append(ring, sc.Text())
	}
	return ring
}

// GET /api/audit?n=200&q=text — newest entries of the security audit log.
func handleAuditGet(w http.ResponseWriter, r *http.Request) {
	n := 200
	if v, err := strconv.Atoi(r.URL.Query().Get("n")); err == nil && v >= 1 && v <= 1000 {
		n = v
	}
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	auditMu.Lock()
	lines := tailLines(auditLogPath(), 5000)
	auditMu.Unlock()
	out := make([]string, 0, n)
	for i := len(lines) - 1; i >= 0 && len(out) < n; i-- { // newest first
		if q == "" || strings.Contains(strings.ToLower(lines[i]), q) {
			out = append(out, redactLogSecrets(lines[i]))
		}
	}
	writeJSON(w, map[string]any{"entries": out, "count": len(out)})
}
