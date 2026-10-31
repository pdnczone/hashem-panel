package main

// Nodes N2: the central relays the panel's API to a node. The page calls
// /api/node/<id>/<path> on the central (after the central's own login, CSRF
// check and audit); the central sends it over the node's channel, and the
// node runs it through its own panel handlers as if its own page had asked,
// so its validation, Pro gates and audit apply. Only paths on
// nodeRelayGroups go through; the terminal, logins and the panel's own
// access settings never do.
//
// A relayed request carries nodeRelayKey in its context. Nothing outside
// this process can set a context value, so the only way in is the channel,
// which only the pinned central can open.
//
// Licenses: a key active on the central is offered to each node; the node
// activates it through its own /api/license (its own check decides). Only a
// key not locked to a machine, or locked to that node's machine, is sent; a
// node's own key is never replaced (nodeLicenseSync).

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	nodeRelayBodyMax = 10 << 20 // request or answer body (base64 in a 16 MiB frame)
	nodeRelayGetTO   = 2 * time.Minute
	nodeRelayPostTO  = 20 * time.Minute // installs, updates, benchmarks
)

// nodeRelayGroups: the first path element after /api/ that may be relayed.
var nodeRelayGroups = map[string]bool{
	"action": true, "alerts": true, "audit": true, "bagher": true, "benchmark": true, "carrier": true,
	"cluster": true, "customers": true, "dashboard": true, "dial": true, "doctor": true, "errors": true,
	"fleet": true, "health": true, "history": true, "license": true, "limits": true, "link-name": true,
	"logs": true, "pathtest": true, "peers": true, "perf": true, "releases": true, "rescue": true,
	"revpath": true, "selfstats": true, "sentinel": true, "setup": true, "spoof": true, "sshfwd": true,
	"status": true, "suggest": true, "support": true, "traffic": true, "tunnel": true, "tunnel-health": true,
	"update": true, "version": true, "watchdog": true, "xray": true,
}

// nodeRelayAllowed: path is /api/<group>[/...] with a relayed group, and no
// dot segments or other tricks.
func nodeRelayAllowed(path string) bool {
	if !strings.HasPrefix(path, "/api/") || strings.Contains(path, "..") || strings.Contains(path, "//") ||
		strings.ContainsAny(path, "?#\\%") {
		return false
	}
	group, _, _ := strings.Cut(strings.TrimPrefix(path, "/api/"), "/")
	return nodeRelayGroups[group] || nodeRelayPaths[path]
}

// nodeRelayPaths: single paths of groups that are not relayed (the rest of
// /api/peer is server-to-server).
var nodeRelayPaths = map[string]bool{"/api/peer/status": true, "/api/peer/config": true}

// nodeRelayMethod: the methods the page uses.
func nodeRelayMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodPost || m == http.MethodPatch || m == http.MethodDelete
}

type nodeRelayCtx struct{}

var nodeRelayKey nodeRelayCtx

// nodeRelayed reports whether r came through the central's channel.
func nodeRelayed(r *http.Request) bool {
	_, ok := r.Context().Value(nodeRelayKey).(string)
	return ok
}

// nodeHTTPReq / nodeHTTPRes are the "http" call's body and answer.
type nodeHTTPReq struct {
	Method string `json:"method"`
	Path   string `json:"path"` // /api/...
	Query  string `json:"query,omitempty"`
	Type   string `json:"type,omitempty"` // Content-Type
	Body   []byte `json:"body,omitempty"`
	User   string `json:"user,omitempty"` // the central's user, for the node's audit log
}

type nodeHTTPRes struct {
	Status int               `json:"status"`
	Header map[string]string `json:"header,omitempty"`
	Body   []byte            `json:"body,omitempty"`
}

// answers' headers kept through the relay
var nodeRelayHeaders = []string{"Content-Type", "Content-Disposition", "Cache-Control", "Retry-After", "X-Snapshot-Age-Ms"}

var nodeRelayMux = func() http.Handler { return panelMux } // tests

// nodeServeHTTP runs a relayed request on this node.
func nodeServeHTTP(raw json.RawMessage) (json.RawMessage, error) {
	var q nodeHTTPReq
	if err := json.Unmarshal(raw, &q); err != nil {
		return nil, errors.New("bad relayed request")
	}
	if !nodeRelayMethod(q.Method) {
		return nil, fmt.Errorf("method %s is not relayed", q.Method)
	}
	if !nodeRelayAllowed(q.Path) {
		return nil, fmt.Errorf("%s is not available through the central: open this node's own panel", q.Path)
	}
	if len(q.Body) > nodeRelayBodyMax {
		return nil, errors.New("request too big")
	}
	mux := nodeRelayMux()
	if mux == nil {
		return nil, errors.New("the panel is starting")
	}
	to := nodeRelayGetTO
	if q.Method != http.MethodGet {
		to = nodeRelayPostTO
	}
	user := q.User
	if user == "" {
		user = "central"
	}
	ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), nodeRelayKey, user), to)
	defer cancel()
	target := "/" + cfg.BasePath + q.Path
	if q.Query != "" {
		target += "?" + q.Query
	}
	req, err := http.NewRequestWithContext(ctx, q.Method, target, bytes.NewReader(q.Body))
	if err != nil {
		return nil, err
	}
	if q.Type != "" {
		req.Header.Set("Content-Type", q.Type)
	}
	req.RemoteAddr = "127.0.0.1:0" // the central, through the channel
	rec := &nodeRelayRecorder{ResponseRecorder: httptest.NewRecorder()}
	mux.ServeHTTP(rec, req)
	if rec.over {
		return nil, fmt.Errorf("the answer is bigger than %d MB: open this node's own panel for it", nodeRelayBodyMax>>20)
	}
	res := nodeHTTPRes{Status: rec.Code, Body: rec.Body.Bytes(), Header: map[string]string{}}
	for _, h := range nodeRelayHeaders {
		if v := rec.Header().Get(h); v != "" {
			res.Header[h] = v
		}
	}
	if q.Method != http.MethodGet {
		LogSecurityAudit("via_central", user, "central", fmt.Sprintf("%s %s -> %d", q.Method, q.Path, rec.Code))
	}
	return json.Marshal(res)
}

// nodeRelayRecorder caps the answer.
type nodeRelayRecorder struct {
	*httptest.ResponseRecorder
	over bool
}

func (r *nodeRelayRecorder) Write(b []byte) (int, error) {
	if r.Body.Len()+len(b) > nodeRelayBodyMax {
		r.over = true
		return 0, errors.New("answer too big")
	}
	return r.ResponseRecorder.Write(b)
}

// ---- the node view ----
//
// The page shows a node in a sandboxed frame (index.html?nv=<id>, served with
// CSP sandbox: an origin of its own, no cookies, no access to the central's
// page). The frame reaches only /api/nv/<token>/..., the relay of that one
// node, with a token bound to the central's login session. So whatever a
// node answers runs, at worst, inside its own frame: it cannot act as the
// central.

type nodeFrameView struct {
	node int
	sess string // the central's session it belongs to
	exp  time.Time
}

const (
	nodeViewTTL = 12 * time.Hour
	nodeViewMax = 64
)

var nodeViews = struct {
	sync.Mutex
	m map[string]nodeFrameView // by nodeViewKey(token)
}{m: map[string]nodeFrameView{}}

func nodeViewKey(tok string) string {
	h := sha256.Sum256([]byte("hashem-node-view:" + tok))
	return hex.EncodeToString(h[:])
}

// nodeViewNew makes a token for node id in session sess.
func nodeViewNew(sess string, id int) string {
	var b [32]byte
	_, _ = rand.Read(b[:]) // crypto/rand: never fails on Linux
	tok := hex.EncodeToString(b[:])
	now := time.Now()
	nodeViews.Lock()
	defer nodeViews.Unlock()
	for k, v := range nodeViews.m {
		if now.After(v.exp) || !validSession(v.sess) {
			delete(nodeViews.m, k)
		}
	}
	for len(nodeViews.m) >= nodeViewMax { // drop the oldest
		var ok string
		var ot time.Time
		for k, v := range nodeViews.m {
			if ok == "" || v.exp.Before(ot) {
				ok, ot = k, v.exp
			}
		}
		delete(nodeViews.m, ok)
	}
	nodeViews.m[nodeViewKey(tok)] = nodeFrameView{node: id, sess: sess, exp: now.Add(nodeViewTTL)}
	return tok
}

// nodeViewCheck is the view of tok while its session lasts.
func nodeViewCheck(tok string, active bool) (nodeFrameView, bool) {
	if len(tok) < 32 || len(tok) > 128 {
		return nodeFrameView{}, false
	}
	k := nodeViewKey(tok)
	nodeViews.Lock()
	v, ok := nodeViews.m[k]
	nodeViews.Unlock()
	if !ok || time.Now().After(v.exp) {
		return nodeFrameView{}, false
	}
	if !validSession(v.sess) {
		nodeViews.Lock()
		delete(nodeViews.m, k)
		nodeViews.Unlock()
		return nodeFrameView{}, false
	}
	if sessionIdleExpired(v.sess, active) { // the login itself ends, as in authed()
		dropSession(v.sess)
		LogSecurityAudit("session_idle_expired", "", "", "idle timeout (seen by a node view)")
		nodeViews.Lock()
		delete(nodeViews.m, k)
		nodeViews.Unlock()
		return nodeFrameView{}, false
	}
	return v, true
}

// nodeViewRedact hides a node view's token in a path (logs, route stats).
func nodeViewRedact(p string) string {
	i := strings.Index(p, "/api/nv/")
	if i < 0 {
		return p
	}
	rest := p[i+len("/api/nv/"):]
	if j := strings.IndexByte(rest, '/'); j >= 0 {
		rest = rest[j:]
	} else {
		rest = ""
	}
	return p[:i] + "/api/nv/*" + rest
}

// nodeViewCSP is the frame's policy: the panel's, in a sandbox, framed only
// by the central's own page.
func nodeViewCSP() string {
	csp := strings.Replace(panelCSP, "frame-ancestors 'none'", "frame-ancestors 'self'", 1)
	csp = strings.Replace(csp, "connect-src 'self' ws: wss:", "connect-src 'self'", 1) // no terminal in a node's view
	return csp +
		"; sandbox allow-scripts allow-forms allow-downloads allow-modals allow-popups"
}

// handleNodeView is the central's /api/nv/{tok}/{path...}.
func handleNodeView(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", "null")                                 // the sandboxed frame
	h.Set("Access-Control-Expose-Headers", "X-Hashem-Node, Content-Disposition") // set on the node's answers only: the frame tells them from the central's own
	h.Set("Vary", "Origin")
	h.Set("Referrer-Policy", "no-referrer")
	if r.Method == http.MethodOptions {
		h.Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE")
		h.Set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token, X-User-Active")
		h.Set("Access-Control-Max-Age", "600")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	// never counts as activity: only the central's own page keeps its login
	// from going idle
	v, ok := nodeViewCheck(r.PathValue("tok"), false)
	if !ok {
		writeAPIError(w, r, "E-AUTH-06", "the central's session ended: reload the page")
		return
	}
	path := "/api/" + r.PathValue("path")
	if r.Method != http.MethodGet {
		mu.Lock()
		user := cfg.Username
		mu.Unlock()
		LogSecurityAudit("node_relay", user, clientIP(r), fmt.Sprintf("node=%d %s %s", v.node, r.Method, path))
	}
	nodeRelayTo(w, r, v.node, path)
}

// nodeRelayTo relays r to node id and writes the answer.
func nodeRelayTo(w http.ResponseWriter, r *http.Request, id int, path string) {
	self, err := nodeSelfLoad()
	if err != nil || self.Role != nodeRoleCentral {
		writeAPIError(w, r, "E-NODE-02", "this panel is not a central")
		return
	}
	if !nodeRelayMethod(r.Method) || !nodeRelayAllowed(path) {
		writeAPIError(w, r, "E-NODE-06", path+" is not available through the central: open the node's own panel for it")
		return
	}
	s := nodeSessionFor(id)
	if s == nil {
		nodesMu.Lock()
		nodesLoadLocked()
		known := nodeFindLocked(id) != nil
		nodesMu.Unlock()
		if !known {
			writeAPIError(w, r, "E-NODE-03", fmt.Sprintf("no node %d", id))
			return
		}
		writeAPIError(w, r, "E-NODE-04", fmt.Sprintf("node %d is offline: its tunnels keep running; open its own panel, or wait for it to connect", id))
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, nodeRelayBodyMax+1))
	if err != nil || len(body) > nodeRelayBodyMax {
		writeAPIError(w, r, "E-NODE-01", "request too big")
		return
	}
	to := nodeRelayGetTO
	if r.Method != http.MethodGet {
		to = nodeRelayPostTO
	}
	ctx, cancel := context.WithTimeout(r.Context(), to+10*time.Second)
	defer cancel()
	// the node's audit says "central", not the central's login name
	raw, err := s.call(ctx, "http", nodeHTTPReq{Method: r.Method, Path: path, Query: r.URL.RawQuery,
		Type: r.Header.Get("Content-Type"), Body: body, User: "central"})
	if err != nil {
		writeAPIError(w, r, "E-NODE-04", err.Error())
		return
	}
	var res nodeHTTPRes
	if err := json.Unmarshal(raw, &res); err != nil || res.Status < 200 || res.Status > 599 {
		writeAPIError(w, r, "E-NODE-04", "the node gave a bad answer")
		return
	}
	nodeRelayHeadersOut(w.Header(), res.Header)
	w.Header().Set("X-Hashem-Node", strconv.Itoa(id))
	w.WriteHeader(res.Status)
	_, _ = w.Write(res.Body)
}

// nodeRelayHeadersOut sets the answer's headers from what the node sent, in
// forms that cannot make a browser run it: a node is not trusted to choose
// its type, and anything but JSON is a download in a sandbox.
func nodeRelayHeadersOut(h http.Header, from map[string]string) {
	mt, _, _ := mime.ParseMediaType(from["Content-Type"])
	isJSON := false
	switch mt {
	case "application/json":
		mt, isJSON = "application/json; charset=utf-8", true
	case "text/plain", "text/csv":
		mt += "; charset=utf-8"
	default:
		mt = "application/octet-stream"
	}
	h.Set("Content-Type", mt)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", "sandbox; default-src 'none'")
	if cd := from["Content-Disposition"]; cd != "" || !isJSON {
		h.Set("Content-Disposition", `attachment; filename="`+nodeRelayFileName(cd)+`"`)
	}
	if v := from["Cache-Control"]; nodeRelayPlain(v) {
		h.Set("Cache-Control", v)
	}
	for _, k := range []string{"Retry-After", "X-Snapshot-Age-Ms"} {
		if v := from[k]; v != "" && len(v) <= 12 && strings.Trim(v, "0123456789") == "" {
			h.Set(k, v)
		}
	}
}

// nodeRelayFileName is the file name in a node's Content-Disposition, cut
// to plain characters.
func nodeRelayFileName(cd string) string {
	name := ""
	if _, p, err := mime.ParseMediaType(cd); err == nil {
		name = p["filename"]
	}
	var b strings.Builder
	for _, c := range name {
		if b.Len() >= 100 {
			break
		}
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_' {
			b.WriteRune(c)
		}
	}
	if n := strings.Trim(b.String(), "."); n != "" {
		return n
	}
	return "download"
}

func nodeRelayPlain(v string) bool {
	if v == "" || len(v) > 64 {
		return false
	}
	for _, c := range v {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '=' || c == ',' || c == ' ') {
			return false
		}
	}
	return true
}

// ---- licenses ----

// nodeKeyHash is a short hash of a license key: the central and a node
// compare keys by it (the key itself is never in a report).
func nodeKeyHash(key string) string {
	key = strings.TrimSpace(key)
	if key == "" {
		return ""
	}
	h := sha256.Sum256([]byte("hashem-node-lic:" + key))
	return hex.EncodeToString(h[:8])
}

// nodeLicTried: the last try per node, so a node that refuses a key is not
// asked every 15 s.
var nodeLicTried = struct {
	sync.Mutex
	at map[int]time.Time
}{at: map[int]time.Time{}}

const nodeLicRetry = 10 * time.Minute

// nodeLicensePlan decides what the central does with a node's license:
// "push" its key, "remove" the key it pushed before, or "" nothing.
//
//	key, keyMachine: the central's active key and the machine it is locked to
//	("" or "*": none); pushed: the hash of the key the central last put on
//	this node.
func nodeLicensePlan(key, keyMachine string, info nodeInfo, pushed string) string {
	if key == "" {
		if pushed != "" && info.License.KeyHash == pushed {
			return "remove" // the central's key was removed: so is the copy
		}
		return ""
	}
	h := nodeKeyHash(key)
	if info.License.KeyHash == h {
		return ""
	}
	if keyMachine != "" && keyMachine != "*" && !strings.EqualFold(keyMachine, info.MachineHash) {
		return "" // locked to another machine: no use there
	}
	// never over a node's own key: only a node with none, or with the copy
	// the central gave it before (a renewal)
	if !info.License.Active || (pushed != "" && info.License.KeyHash == pushed) {
		return "push"
	}
	return ""
}

// nodeLicenseSync applies nodeLicensePlan to the node of s.
func nodeLicenseSync(s *nodeSession, info nodeInfo) {
	if info.Proto < 1 || !info.License.Reported {
		return // a node too old to report its key: nothing is changed on it
	}
	mu.Lock()
	key := strings.TrimSpace(cfg.LicenseKey)
	mu.Unlock()
	machine := ""
	activeLicenseMu.RLock()
	if activeLicense == nil {
		key = "" // a key the central's own check does not accept is not sent
	} else {
		machine = activeLicense.MachineHash
	}
	activeLicenseMu.RUnlock()
	nodesMu.Lock()
	pushed := ""
	if rec := nodeFindLocked(s.id); rec != nil {
		pushed = rec.LicensePushed
	}
	nodesMu.Unlock()
	plan := nodeLicensePlan(key, machine, info, pushed)
	if plan == "" {
		return
	}
	nodeLicTried.Lock()
	if t, ok := nodeLicTried.at[s.id]; ok && time.Since(t) < nodeLicRetry {
		nodeLicTried.Unlock()
		return
	}
	nodeLicTried.at[s.id] = time.Now()
	nodeLicTried.Unlock()
	send := key
	if plan == "remove" {
		send = ""
	}
	body, _ := json.Marshal(map[string]string{"key": send})
	ctx, cancel := context.WithTimeout(context.Background(), nodeCallTO)
	raw, err := s.call(ctx, "http", nodeHTTPReq{Method: http.MethodPost, Path: "/api/license", Type: "application/json", Body: body, User: "central"})
	cancel()
	var res nodeHTTPRes
	if err == nil {
		err = json.Unmarshal(raw, &res)
	}
	if err == nil && res.Status != http.StatusOK {
		err = fmt.Errorf("%d %s", res.Status, nodeLogText(res.Body))
	}
	if err != nil {
		log.Printf("nodes: license on node %d: %v", s.id, err)
		return
	}
	nodesMu.Lock()
	if rec := nodeFindLocked(s.id); rec != nil {
		rec.LicensePushed = ""
		if plan == "push" {
			rec.LicensePushed = nodeKeyHash(key)
		}
		_ = nodesSaveLocked()
	}
	nodesMu.Unlock()
	nodeLicTried.Lock()
	delete(nodeLicTried.at, s.id)
	nodeLicTried.Unlock()
	log.Printf("nodes: license %s on node %d", map[string]string{"push": "activated", "remove": "removed"}[plan], s.id)
}

// nodeLogText is a node's text cut for the central's log: one short line.
func nodeLogText(b []byte) string {
	if len(b) > 200 {
		b = b[:200]
	}
	return strings.Map(func(c rune) rune {
		if c < 0x20 || c == 0x7f {
			return ' '
		}
		return c
	}, strings.ToValidUTF8(string(b), "?"))
}
