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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
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
	return nodeRelayGroups[group]
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
	if q.Method != http.MethodGet && q.Method != http.MethodPost {
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
	if q.Method == http.MethodPost {
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
	if q.Method == http.MethodPost {
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

// handleNodeRelay is the central's /api/node/{id}/{path...}.
func handleNodeRelay(w http.ResponseWriter, r *http.Request) {
	self, err := nodeSelfLoad()
	if err != nil || self.Role != nodeRoleCentral {
		writeAPIError(w, r, "E-NODE-02", "this panel is not a central")
		return
	}
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		writeAPIError(w, r, "E-NODE-03", "bad node id")
		return
	}
	path := "/api/" + r.PathValue("path")
	if !nodeRelayAllowed(path) {
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
	if r.Method == http.MethodPost {
		to = nodeRelayPostTO
	}
	ctx, cancel := context.WithTimeout(r.Context(), to+10*time.Second)
	defer cancel()
	raw, err := s.call(ctx, "http", nodeHTTPReq{Method: r.Method, Path: path, Query: r.URL.RawQuery,
		Type: r.Header.Get("Content-Type"), Body: body, User: cfg.Username})
	if err != nil {
		writeAPIError(w, r, "E-NODE-04", err.Error())
		return
	}
	var res nodeHTTPRes
	if err := json.Unmarshal(raw, &res); err != nil || res.Status < 100 || res.Status > 599 {
		writeAPIError(w, r, "E-NODE-04", "the node gave a bad answer")
		return
	}
	for _, h := range nodeRelayHeaders {
		if v, ok := res.Header[h]; ok {
			w.Header().Set(h, v)
		}
	}
	w.Header().Set("X-Hashem-Node", strconv.Itoa(id))
	w.WriteHeader(res.Status)
	_, _ = w.Write(res.Body)
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
		err = fmt.Errorf("%d %s", res.Status, strings.TrimSpace(string(res.Body)))
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
