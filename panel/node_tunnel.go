package main

// Nodes N3: a tunnel between two of the central's servers, made from one
// page. The central has no tunnel database: it asks both servers for their
// plan (GET /api/setup/plan), then makes the tunnel with each server's own
// API, in order:
//
//  1. the server end (Iran side): POST /api/setup role "iran" (its first
//     tunnel) or "add-peer"; it answers with the bundle it makes today, and
//     the central checks that bundle against what was planned;
//  2. the client end (foreign side): POST /api/setup role "foreign" with
//     that bundle, or POST /api/cluster/join-hub when it already has a
//     tunnel to another Iran server.
//
// When step 2 fails, step 1 is removed again. When that fails too, or when
// step 1 failed half-way, the server end is kept in nodes.json as "left
// over". A left-over end is only ever removed by finding it again on its
// server (the peer whose remote is the client), never by a stored id alone.
// Removal goes the other way round: the client end first, then the server
// end. Server 0 is the central itself. A server's plan is its own claim:
// two plans claiming one address are not paired at all.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	nodeTunPlanTO   = time.Minute
	nodeTunSetupTO  = 20 * time.Minute
	nodeTunActionTO = 2 * time.Minute
	nodeTunJobsMax  = 20
	nodeTunLeftMax  = 50
	nodeTunPlanMax  = 256 // entries of each list a plan may carry
)

// nodeTunFindRetry: a new server end not in the plan yet is looked for once
// more after this (a server's status snapshot is refreshed every few seconds).
var nodeTunFindRetry = 6 * time.Second

// nodeTunLeft is a server end whose tunnel was not finished and that could
// not be removed: it is listed until it is removed.
type nodeTunLeft struct {
	ID         int    `json:"id"`
	Server     int    `json:"server"`
	Client     int    `json:"client"`
	ServerRole string `json:"server_role"` // iran (the server's first tunnel) | add-peer
	ClientIP   string `json:"client_ip"`   // how it is found again on the server
	Error      string `json:"error"`
	At         int64  `json:"at"`
}

type nodeTunJob struct {
	ID      int    `json:"id"`
	Kind    string `json:"kind"` // create | remove
	Server  int    `json:"server"`
	Client  int    `json:"client"`
	State   string `json:"state"` // running | done | failed
	Log     string `json:"log"`
	Started int64  `json:"started"`
	Ended   int64  `json:"ended,omitempty"`
}

var nodeTun struct {
	sync.Mutex
	jobs []*nodeTunJob
	next int
	busy map[int]bool // servers a job is changing now
}

func (j *nodeTunJob) logf(format string, a ...any) {
	nodeTun.Lock()
	j.Log += time.Now().Format("15:04:05") + " " + fmt.Sprintf(format, a...) + "\n"
	if len(j.Log) > nodeSSHLogMax {
		j.Log = j.Log[len(j.Log)-nodeSSHLogMax:]
	}
	nodeTun.Unlock()
}

func nodeTunJobsView() []nodeTunJob {
	nodeTun.Lock()
	defer nodeTun.Unlock()
	out := make([]nodeTunJob, 0, len(nodeTun.jobs))
	for i := len(nodeTun.jobs) - 1; i >= 0; i-- {
		out = append(out, *nodeTun.jobs[i])
	}
	return out
}

// nodeTunStart runs fn as a job on servers ids, one job per server at a time.
func nodeTunStart(kind string, server, client int, fn func(j *nodeTunJob) error) (int, error) {
	nodeTun.Lock()
	if nodeTun.busy == nil {
		nodeTun.busy = map[int]bool{}
	}
	if nodeTun.busy[server] || nodeTun.busy[client] {
		nodeTun.Unlock()
		return 0, nodeErr{"E-NODE-07", "a tunnel job on one of these servers is still running: wait for it"}
	}
	nodeTun.busy[server], nodeTun.busy[client] = true, true
	nodeTun.next++
	j := &nodeTunJob{ID: nodeTun.next, Kind: kind, Server: server, Client: client, State: "running", Started: time.Now().Unix()}
	nodeTun.jobs = append(nodeTun.jobs, j)
	if len(nodeTun.jobs) > nodeTunJobsMax {
		nodeTun.jobs = nodeTun.jobs[len(nodeTun.jobs)-nodeTunJobsMax:]
	}
	nodeTun.Unlock()
	go func() {
		err := fn(j)
		if err != nil {
			j.logf("FAILED: %v", err)
		} else {
			j.logf("done")
		}
		nodeTun.Lock()
		j.State, j.Ended = "done", time.Now().Unix()
		if err != nil {
			j.State = "failed"
		}
		delete(nodeTun.busy, server)
		delete(nodeTun.busy, client)
		nodeTun.Unlock()
	}()
	return j.ID, nil
}

// ---- calls to a server's API ----

// nodeAPIFn calls method path (with ?query) on server id (0: this panel)
// and answers the status and body (tests replace it).
var nodeAPIFn = nodeAPI

func nodeAPI(ctx context.Context, id int, method, path string, body any) (int, []byte, error) {
	q := nodeHTTPReq{Method: method, User: "central"}
	q.Path, q.Query, _ = strings.Cut(path, "?")
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		q.Body, q.Type = b, "application/json"
	}
	var raw json.RawMessage
	var err error
	if id == 0 {
		b, _ := json.Marshal(q)
		raw, err = nodeServeHTTP(b) // this panel's own handlers, as the relay runs them on a node
	} else {
		s := nodeSessionFor(id)
		if s == nil {
			return 0, nil, fmt.Errorf("server %s is offline", nodeTunName(id))
		}
		raw, err = s.call(ctx, "http", q)
	}
	if err != nil {
		return 0, nil, err
	}
	var res nodeHTTPRes
	if err := json.Unmarshal(raw, &res); err != nil {
		return 0, nil, errors.New("a bad answer")
	}
	return res.Status, res.Body, nil
}

// nodeAPIError is a server's own error answer (an HTTP status, not a
// failure to reach it).
type nodeAPIError struct {
	Status int
	Code   string
	Msg    string
}

func (e *nodeAPIError) Error() string { return e.Msg }

// installed: the server's installer ran (and may have left something).
func (e *nodeAPIError) installed() bool { return strings.HasPrefix(e.Code, "E-INSTALL") }

func apiErrOf(err error) *nodeAPIError {
	var e *nodeAPIError
	if errors.As(err, &e) {
		return e
	}
	return nil
}

// nodeAPIJSON calls and decodes a 2xx answer into out; any other answer is
// a *nodeAPIError with the server's own message.
func nodeAPIJSON(ctx context.Context, id int, method, path string, body, out any) error {
	st, b, err := nodeAPIFn(ctx, id, method, path, body)
	if err != nil {
		return fmt.Errorf("%s: %v", nodeTunName(id), err)
	}
	if st < 200 || st > 299 {
		var e struct {
			Code  string `json:"error_code"`
			Error string `json:"error"`
		}
		_ = json.Unmarshal(b, &e)
		msg := e.Error
		if msg == "" {
			msg = nodeLogText(b)
		}
		if e.Code != "" {
			msg = "[" + e.Code + "] " + msg
		}
		return &nodeAPIError{Status: st, Code: e.Code, Msg: nodeTunName(id) + ": " + nodeLogText([]byte(msg))}
	}
	if out != nil {
		if err := json.Unmarshal(b, out); err != nil {
			return &nodeAPIError{Status: st, Msg: nodeTunName(id) + ": a bad answer"}
		}
	}
	return nil
}

// nodeTunName is server id as the log names it.
func nodeTunName(id int) string {
	if id == 0 {
		return "this server (the central)"
	}
	nodesMu.Lock()
	defer nodesMu.Unlock()
	if rec := nodeFindLocked(id); rec != nil {
		return fmt.Sprintf("%q", rec.Name)
	}
	return fmt.Sprintf("node %d", id)
}

// nodeTunLabel is a node's name as a tunnel label on the other server:
// plain characters, at most max bytes (join-hub takes 32, Setup 40 runes).
func nodeTunLabel(id, max int) string {
	name := "central"
	if id != 0 {
		nodesMu.Lock()
		if rec := nodeFindLocked(id); rec != nil {
			name = rec.Name
		}
		nodesMu.Unlock()
	}
	name = strings.Map(func(r rune) rune {
		if strings.ContainsRune("<>\"'`$\\\n\r\t", r) {
			return -1
		}
		return r
	}, name)
	for len(name) > max {
		r := []rune(name)
		name = string(r[:len(r)-1])
	}
	return strings.TrimSpace(name)
}

func nodeTunPlan(ctx context.Context, id int, ports string, relay int) (setupPlan, error) {
	return nodeTunPlanProof(ctx, id, ports, relay, "")
}

// nodeTunPlanProof: with a nonce, each tunnel in the plan carries the proof
// of its token (setup_plan.go).
func nodeTunPlanProof(ctx context.Context, id int, ports string, relay int, nonce string) (setupPlan, error) {
	var p setupPlan
	v := url.Values{}
	if nonce != "" {
		v.Set("proof", nonce)
	}
	if ports != "" {
		v.Set("ports", ports)
	}
	if relay > 0 {
		v.Set("relay", strconv.Itoa(relay))
	}
	path := "/api/setup/plan"
	if len(v) > 0 {
		path += "?" + v.Encode()
	}
	if err := nodeAPIJSON(ctx, id, http.MethodGet, path, nil, &p); err != nil {
		// an older panel has no plan: the page (HTML), or not relayed
		if e := apiErrOf(err); e != nil && (e.Status == http.StatusOK || e.Status == http.StatusNotFound || e.Code == "E-NODE-06") {
			return p, fmt.Errorf("%s runs an older Hashem: update it first", nodeTunName(id))
		}
		return p, err
	}
	// a server's plan is its own claim: keep it small
	p.Peers, p.Uplinks, p.GreUsed = capList(p.Peers), capList(p.Uplinks), capList(p.GreUsed)
	if len(p.Clashes) > nodeTunPlanMax {
		p.Clashes = map[string]string{"…": fmt.Sprintf("%d ports", len(p.Clashes))}
	}
	return p, nil
}

func capList[T any](l []T) []T {
	if len(l) > nodeTunPlanMax {
		return l[:nodeTunPlanMax]
	}
	return l
}

// ---- create ----

type nodeTunReq struct {
	Server    int    `json:"server"`
	Client    int    `json:"client"`
	Engine    string `json:"engine"`    // frp | backhaul | gre-backhaul
	Transport string `json:"transport"` // the engine's transport ("" = its default)
	Ports     string `json:"ports"`     // "443, 2083" (Backhaul also "8080=80")
	FrpPort   int    `json:"frp_port"`  // 0: the server's free port
	AcceptUDP bool   `json:"accept_udp"`
}

var nodeTunPortsRe = regexp.MustCompile(`^[0-9 ,=:\-]{1,300}$`)

// nodeTunTransports: what each engine's Setup takes ("" = its default).
var nodeTunTransports = map[string][]string{
	"frp":          {"", "tcp", "kcp", "quic", "websocket", "wss"},
	"backhaul":     {"", "tcp", "tcpmux", "udp", "ws", "wss", "wsmux", "wssmux"},
	"gre-backhaul": {"", "tcp", "tcpmux", "udp", "ws", "wss", "wsmux", "wssmux"},
}

func (q *nodeTunReq) check() error {
	q.Engine, q.Transport, q.Ports = strings.TrimSpace(q.Engine), strings.TrimSpace(q.Transport), strings.TrimSpace(q.Ports)
	if q.Engine == "" {
		q.Engine = "frp"
	}
	switch {
	case q.Server == q.Client:
		return nodeErr{"E-NODE-01", "pick two different servers"}
	case q.Server < 0 || q.Client < 0:
		return nodeErr{"E-NODE-01", "bad server"}
	case nodeTunTransports[q.Engine] == nil:
		return nodeErr{"E-NODE-01", "engine: frp, backhaul or gre-backhaul"}
	case !slices.Contains(nodeTunTransports[q.Engine], q.Transport):
		return nodeErr{"E-NODE-01", fmt.Sprintf("transport for %s: one of %s", q.Engine, strings.Join(nodeTunTransports[q.Engine][1:], ", "))}
	case !nodeTunPortsRe.MatchString(q.Ports):
		return nodeErr{"E-NODE-01", "ports: numbers separated by commas, e.g. 443, 2083"}
	case q.FrpPort < 0 || q.FrpPort > 65535:
		return nodeErr{"E-NODE-01", "bad control port"}
	}
	if q.Engine == "frp" {
		q.AcceptUDP = false
		// FRP takes single ports only (ranges and 8080=80 are Backhaul's);
		// split as parsePorts does, so "443 2083" and a repeat are fine
		seen := map[string]bool{}
		for _, f := range strings.FieldsFunc(q.Ports, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' }) {
			seen[strings.TrimLeft(f, "0")] = true
		}
		if len(parsePorts(q.Ports)) != len(seen) {
			return nodeErr{"E-NODE-01", "ports: FRP takes single port numbers (ranges and mappings are for Backhaul)"}
		}
	}
	for _, id := range []int{q.Server, q.Client} {
		if id == 0 {
			continue
		}
		nodesMu.Lock()
		rec := nodeFindLocked(id)
		held := rec != nil && rec.Held
		nodesMu.Unlock()
		if rec == nil {
			return errNodeUnknown(id)
		}
		if held {
			return nodeErr{"E-NODE-01", fmt.Sprintf("%s joined by the move to nodes and is not approved yet: approve it on the Nodes page first", nodeTunName(id))}
		}
	}
	return nil
}

// nodeTunDraft is what the central will do, from both plans.
type nodeTunDraft struct {
	Server     setupPlan `json:"server"`
	Client     setupPlan `json:"client"`
	ServerRole string    `json:"server_role"` // iran | add-peer
	ClientMode string    `json:"client_mode"` // foreign | join-hub
	LocalGre   string    `json:"local_gre"`   // on the server ("" for Backhaul without GRE)
	PeerGre    string    `json:"peer_gre"`    // on the client
	FrpPort    int       `json:"frp_port"`
	Problems   []string  `json:"problems,omitempty"` // a create would fail: say why first
}

func nodeTunDraftFor(ctx context.Context, q nodeTunReq) (nodeTunDraft, error) {
	var d nodeTunDraft
	var err error
	if d.Server, err = nodeTunPlan(ctx, q.Server, q.Ports, q.FrpPort); err != nil {
		return d, err
	}
	if d.Client, err = nodeTunPlan(ctx, q.Client, "", 0); err != nil {
		return d, err
	}
	s, c := d.Server, d.Client
	problem := func(f string, a ...any) { d.Problems = append(d.Problems, fmt.Sprintf(f, a...)) }
	d.ServerRole = "add-peer"
	if !s.Exists && len(s.Peers) == 0 {
		d.ServerRole = "iran"
	}
	d.ClientMode = "foreign"
	if c.Exists || len(c.Uplinks) > 0 {
		d.ClientMode = "join-hub"
	}
	for _, x := range []struct {
		id int
		p  setupPlan
	}{{q.Server, s}, {q.Client, c}} {
		if x.p.Exists && x.p.Side == "" {
			problem("%s has a tunnel config but no running tunnel: remove it there first (Tunnel page)", nodeTunName(x.id))
		}
	}
	if s.Side == "foreign" || len(s.Uplinks) > 0 {
		problem("%s is a foreign server (it dials an Iran server): pick an Iran server as the server end", nodeTunName(q.Server))
	}
	if c.Side == "iran" || len(c.Peers) > 0 {
		problem("%s serves tunnels as an Iran server: pick a foreign server as the client end", nodeTunName(q.Client))
	}
	if net.ParseIP(s.Public) == nil || net.ParseIP(c.Public) == nil {
		problem("the public address of a server is not known yet")
	} else if q.Engine != "backhaul" && (net.ParseIP(s.Public).To4() == nil || net.ParseIP(c.Public).To4() == nil) {
		problem("a tunnel over GRE needs the IPv4 addresses of both servers; for IPv6 use Backhaul")
	}
	if s.Public != "" && s.Public == c.Public {
		problem("both servers have the same public address (%s): they look like the same server", s.Public)
	}
	for _, p := range s.Peers {
		if p.RemotePub == c.Public && c.Public != "" {
			problem("these two servers already have a tunnel")
		}
	}
	for _, u := range c.Uplinks {
		if u.IranPub == s.Public && s.Public != "" {
			problem("%s already dials %s", nodeTunName(q.Client), nodeTunName(q.Server))
		}
	}
	for port, who := range s.Clashes {
		problem("port %s is already used on %s by %s", port, nodeTunName(q.Server), who)
	}
	// what each server's own license allows (it decides again when asked)
	if q.Engine != "frp" {
		for _, x := range []struct {
			id int
			p  setupPlan
		}{{q.Server, s}, {q.Client, c}} {
			if !x.p.Pro["backhaul"] {
				problem("Backhaul is a Pro feature and %s has no license for it", nodeTunName(x.id))
			}
		}
	}
	if d.ClientMode == "join-hub" && !c.Pro["cluster"] {
		problem("%s already has a tunnel, so it would join as one more Iran hub: that is Cluster, a Pro feature it has no license for", nodeTunName(q.Client))
	}
	d.FrpPort = q.FrpPort
	if d.FrpPort == 0 {
		d.FrpPort = s.RelayPort
	} else if s.RelayTaken != "" {
		problem("control port %d is already used on %s by %s", q.FrpPort, nodeTunName(q.Server), s.RelayTaken)
	}
	if d.FrpPort == 0 {
		problem("no free control port on %s", nodeTunName(q.Server))
	}
	if q.Engine == "backhaul" {
		return d, nil // no GRE
	}
	used := map[string]bool{}
	for _, a := range append(append([]string{}, s.GreUsed...), c.GreUsed...) {
		used[a] = true
	}
	pairs := [][2]string{{defaultIranGRE, defaultForeignGRE}}
	for k := 1; k <= 89; k++ {
		pairs = append(pairs, [2]string{fmt.Sprintf("10.1%d.0.2", k), fmt.Sprintf("10.1%d.0.1", k)})
	}
	for _, p := range pairs {
		if !used[p[0]] && !used[p[1]] {
			d.LocalGre, d.PeerGre = p[0], p[1]
			break
		}
	}
	if d.LocalGre == "" {
		problem("no free GRE address pair")
	}
	return d, nil
}

// nodeTunBundleCheck: the server end's bundle is what was planned (the
// client trusts it as a pasted bundle; a server end that is not honest must
// not point the client elsewhere or publish other ports).
func nodeTunBundleCheck(bundle string, q nodeTunReq, d nodeTunDraft) error {
	b, err := ParseBundle(bundle)
	if err != nil {
		return fmt.Errorf("the server end's bundle cannot be read: %v", err)
	}
	engine := b.Engine
	if engine == "" {
		engine = "frp"
	}
	want := extractNumericPorts(parseRawPorts(q.Ports))
	got := append([]int{}, b.Ports...)
	slices.Sort(want)
	slices.Sort(got)
	switch {
	case b.IranPub != d.Server.Public:
		return fmt.Errorf("the server end's bundle names %s, not %s", b.IranPub, d.Server.Public)
	case b.FrpPort != d.FrpPort:
		return fmt.Errorf("the server end's bundle has control port %d, not %d", b.FrpPort, d.FrpPort)
	case engine != q.Engine:
		return fmt.Errorf("the server end's bundle is %s, not %s", engine, q.Engine)
	case q.Engine != "backhaul" && (b.IranGre != d.LocalGre || b.ForeignGre != d.PeerGre):
		return errors.New("the server end's bundle has other GRE addresses than planned")
	case !slices.Equal(slices.Compact(want), slices.Compact(got)):
		return errors.New("the server end's bundle has other ports than planned")
	case nodeTunTransport(q.Engine, b.Transport) != nodeTunTransport(q.Engine, q.Transport):
		return fmt.Errorf("the server end's bundle has transport %q, not %q", b.Transport, q.Transport)
	case q.Engine != "frp" && b.UDP != nodeTunUDPMark(q):
		return errors.New("the server end's bundle forwards UDP otherwise than planned")
	}
	return nil
}

// nodeTunUDPMark: whether the bundle carries Backhaul's UDP mark. Only a
// UDP companion is marked (tcpmux and the ws family); on tcp UDP goes inside
// the tunnel, and udp is UDP already.
func nodeTunUDPMark(q nodeTunReq) bool {
	t := nodeTunTransport(q.Engine, q.Transport)
	return q.AcceptUDP && t != "tcp" && t != "udp"
}

// nodeTunTransport is t with the engine's default filled in.
func nodeTunTransport(engine, t string) string {
	if t != "" {
		return t
	}
	if engine == "frp" {
		return "tcp"
	}
	return "tcpmux"
}

// nodeTunFindPeer finds the server end of a tunnel to clientIP on server id
// again: its peer id (0: the first tunnel), or -1.
func nodeTunFindPeer(ctx context.Context, id int, clientIP string) (int, error) {
	p, err := nodeTunPlan(ctx, id, "", 0)
	if err != nil {
		return -1, err
	}
	for _, x := range p.Peers {
		if clientIP != "" && x.RemotePub == clientIP {
			return x.ID, nil
		}
	}
	return -1, nil
}

func nodeTunCreate(ctx context.Context, j *nodeTunJob, q nodeTunReq) error {
	j.logf("reading the plan of both servers")
	pctx, cancel := context.WithTimeout(ctx, nodeTunPlanTO)
	d, err := nodeTunDraftFor(pctx, q)
	cancel()
	if err != nil {
		return err
	}
	if len(d.Problems) > 0 {
		return errors.New(strings.Join(d.Problems, "; "))
	}
	// 1. the server end
	before := map[int]bool{}
	for _, p := range d.Server.Peers {
		before[p.ID] = true
	}
	body := map[string]any{
		"role": d.ServerRole, "engine": q.Engine, "transport": q.Transport, "accept_udp": q.AcceptUDP,
		"name": nodeTunLabel(q.Client, 40), "local_public": d.Server.Public, "remote_public": d.Client.Public,
		"local_gre": d.LocalGre, "peer_gre": d.PeerGre, "frp_port": d.FrpPort, "ports": q.Ports, "autogen": true,
	}
	if q.Engine == "frp" {
		body["frp_transport"] = q.Transport
	}
	j.logf("making the server end on %s (%s, control port %d, GRE %s)", nodeTunName(q.Server), d.ServerRole, d.FrpPort, d.LocalGre)
	var res struct {
		Bundle string `json:"bundle"`
	}
	sctx, cancel := context.WithTimeout(ctx, nodeTunSetupTO)
	err = nodeAPIJSON(sctx, q.Server, http.MethodPost, "/api/setup", body, &res)
	cancel()
	findNew := func() int { // the new server end, by the client's address
		for try := 0; try < 2; try++ {
			if try > 0 {
				time.Sleep(nodeTunFindRetry) // the server's status snapshot may lag the install
			}
			fctx, cancel := context.WithTimeout(ctx, nodeTunPlanTO)
			id, ferr := nodeTunFindPeer(fctx, q.Server, d.Client.Public)
			cancel()
			if ferr == nil && id >= 0 && !(before[id] && d.ServerRole == "add-peer") {
				return id
			}
		}
		return -1
	}
	if err != nil {
		// the server answered "no" before installing anything: nothing to undo
		if e := apiErrOf(err); e != nil && !e.installed() {
			return err
		}
		// it may be half-made (the installer ran, or the answer was lost)
		if findNew() >= 0 {
			nodeTunKeep(q, d.ServerRole, d.Client.Public, err.Error())
			return fmt.Errorf("%v; the server end exists, so it is listed as left over", err)
		}
		return err
	}
	peerID := findNew()
	if peerID < 0 {
		j.logf("warning: the new tunnel on the server is not found in its plan")
	}
	undo := func(cause error) error { // remove the server end again
		j.logf("removing the server end again")
		if peerID < 0 {
			nodeTunKeep(q, d.ServerRole, d.Client.Public, "not found on the server after it was made")
			return fmt.Errorf("%v; the server end could not be found to remove it, so it is listed as left over", cause)
		}
		rctx, cancel := context.WithTimeout(ctx, nodeTunActionTO)
		rerr := nodeAPIJSON(rctx, q.Server, http.MethodPost, "/api/action", map[string]any{"action": "remove-tunnel", "peer_id": peerID}, nil)
		cancel()
		if rerr != nil {
			nodeTunKeep(q, d.ServerRole, d.Client.Public, rerr.Error())
			return fmt.Errorf("%v; removing the server end failed too (%v), so it is listed as left over", cause, rerr)
		}
		return fmt.Errorf("%v; the server end was removed again", cause)
	}
	if berr := nodeTunBundleCheck(res.Bundle, q, d); berr != nil {
		return undo(berr)
	}
	// 2. the client end
	j.logf("making the client end on %s (%s)", nodeTunName(q.Client), d.ClientMode)
	cctx, cancel := context.WithTimeout(ctx, nodeTunSetupTO)
	if d.ClientMode == "join-hub" {
		err = nodeAPIJSON(cctx, q.Client, http.MethodPost, "/api/cluster/join-hub", map[string]any{"bundle": res.Bundle, "name": nodeTunLabel(q.Server, 32)}, nil)
	} else {
		err = nodeAPIJSON(cctx, q.Client, http.MethodPost, "/api/setup", map[string]any{"role": "foreign", "token": res.Bundle,
			"local_public": d.Client.Public, "name": nodeTunLabel(q.Server, 40), "accept_udp": q.AcceptUDP}, nil)
	}
	cancel()
	if err == nil {
		nodeAuditf("node_tunnel_made", "server=%d client=%d peer=%d engine=%s", q.Server, q.Client, peerID, q.Engine)
		return nil
	}
	j.logf("the client end failed: %v", err)
	// the half-made client end, only when this job's install ran there (it
	// had no tunnel before: a "foreign" client)
	if e := apiErrOf(err); d.ClientMode == "foreign" && e != nil && e.installed() {
		rctx, cancel := context.WithTimeout(ctx, nodeTunActionTO)
		if rerr := nodeAPIJSON(rctx, q.Client, http.MethodPost, "/api/action", map[string]any{"action": "remove-tunnel", "peer_id": 0}, nil); rerr != nil {
			j.logf("cleaning the client end: %v", rerr)
		}
		cancel()
	}
	return undo(err)
}

// nodeTunKeep lists a server end that is left over.
func nodeTunKeep(q nodeTunReq, role, clientIP, why string) {
	nodesMu.Lock()
	defer nodesMu.Unlock()
	nodesLoadLocked()
	nodesF.LeftNext = max(nodesF.LeftNext, 1)
	for _, l := range nodesF.Left {
		nodesF.LeftNext = max(nodesF.LeftNext, l.ID+1)
	}
	nodesF.Left = append(nodesF.Left, nodeTunLeft{ID: nodesF.LeftNext, Server: q.Server, Client: q.Client, ServerRole: role,
		ClientIP: clientIP, Error: why, At: time.Now().Unix()})
	nodesF.LeftNext++
	if n := len(nodesF.Left) - nodeTunLeftMax; n > 0 {
		for _, l := range nodesF.Left[:n] {
			log.Printf("nodes: forgetting the oldest left-over tunnel end (server %d, to %s): remove it on that server if it is still there", l.Server, l.ClientIP)
		}
		nodesF.Left = nodesF.Left[n:]
	}
	if err := nodesSaveLocked(); err != nil {
		log.Printf("nodes: cannot save a left-over tunnel: %v", err)
	}
}

// ---- the tunnels between servers, and removing one ----

// nodeTunLink is a tunnel both of whose ends are servers of this central.
type nodeTunLink struct {
	Server   int    `json:"server"`
	Client   int    `json:"client"`
	PeerID   int    `json:"peer_id"` // on the server
	Hub      int    `json:"hub"`     // on the client: 1 its first tunnel, 2 and up a joined hub
	Name     string `json:"name,omitempty"`
	Engine   string `json:"engine,omitempty"`
	ServerIP string `json:"server_ip"`
	ClientIP string `json:"client_ip"`
}

// nodeTunLinks reads every online server's plan and pairs the ends: by
// address, and only when both ends prove they hold the same tunnel token
// (an HMAC of a fresh nonce). Servers that claim the same address are not
// paired at all (one of them is not honest).
func nodeTunLinks(ctx context.Context) ([]nodeTunLink, []string) {
	ids := []int{0}
	nodesMu.Lock()
	nodesLoadLocked()
	for _, rec := range nodesF.Nodes {
		if nodeSessions[rec.ID] != nil && !rec.Held { // not approved yet: not used for tunnels
			ids = append(ids, rec.ID)
		}
	}
	nodesMu.Unlock()
	plans := map[int]setupPlan{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	var errs []string
	var nb [16]byte
	_, _ = rand.Read(nb[:])
	nonce := hex.EncodeToString(nb[:])
	for _, id := range ids {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			p, err := nodeTunPlanProof(ctx, id, "", 0, nonce)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err.Error())
				return
			}
			plans[id] = p
		}(id)
	}
	wg.Wait()
	claims := map[string][]int{}
	for id, p := range plans {
		if p.Public != "" {
			claims[p.Public] = append(claims[p.Public], id)
		}
	}
	for ip, who := range claims {
		if len(who) > 1 {
			slices.Sort(who)
			names := make([]string, len(who))
			for i, id := range who {
				names[i] = nodeTunName(id)
				delete(plans, id)
			}
			errs = append(errs, fmt.Sprintf("%s all say they are %s: their tunnels are not listed", strings.Join(names, ", "), ip))
		}
	}
	links := []nodeTunLink{}
	for sid, s := range plans {
		for _, p := range s.Peers {
			for cid, c := range plans {
				if cid == sid || c.Public == "" || p.RemotePub != c.Public {
					continue
				}
				for _, u := range c.Uplinks {
					// both ends hold the same token: a claimed address alone is not enough
					if u.IranPub == s.Public && p.Proof != "" && p.Proof == u.Proof {
						links = append(links, nodeTunLink{Server: sid, Client: cid, PeerID: p.ID, Hub: u.Hub, Name: p.Name,
							Engine: p.Engine, ServerIP: s.Public, ClientIP: c.Public})
					}
				}
			}
		}
	}
	slices.SortFunc(links, func(a, b nodeTunLink) int {
		if a.Server != b.Server {
			return a.Server - b.Server
		}
		return a.PeerID - b.PeerID
	})
	slices.Sort(errs)
	return links, errs
}

type nodeTunRemoveReq struct {
	Server int `json:"server"`
	Client int `json:"client"`
	PeerID int `json:"peer_id"`
	Hub    int `json:"hub"`
	Left   int `json:"left"` // a left-over server end: its id
}

// nodeTunRemoveLeft removes a left-over server end: found again on its
// server by the client's address, never by a stored id.
func nodeTunRemoveLeft(ctx context.Context, j *nodeTunJob, left int) error {
	nodesMu.Lock()
	nodesLoadLocked()
	i := slices.IndexFunc(nodesF.Left, func(l nodeTunLeft) bool { return l.ID == left })
	var l nodeTunLeft
	if i >= 0 {
		l = nodesF.Left[i]
	}
	nodesMu.Unlock()
	if i < 0 {
		return errors.New("no such left-over tunnel")
	}
	j.logf("finding the left-over server end on %s (the tunnel to %s)", nodeTunName(l.Server), l.ClientIP)
	fctx, cancel := context.WithTimeout(ctx, nodeTunPlanTO)
	peer, err := nodeTunFindPeer(fctx, l.Server, l.ClientIP)
	cancel()
	switch {
	case err != nil:
		return err
	case peer < 0:
		return errors.New("it is not on the server any more: press \"Removed by hand\"")
	case peer == 0 && l.ServerRole != "iran":
		return errors.New("the tunnel to that address is the server's first tunnel, which this job did not make: remove it on that server if you mean to")
	}
	j.logf("removing it (peer %d)", peer)
	rctx, cancel := context.WithTimeout(ctx, nodeTunActionTO)
	err = nodeAPIJSON(rctx, l.Server, http.MethodPost, "/api/action", map[string]any{"action": "remove-tunnel", "peer_id": peer}, nil)
	cancel()
	if err != nil {
		return err
	}
	nodesMu.Lock()
	nodesLoadLocked()
	nodesF.Left = slices.DeleteFunc(nodesF.Left, func(x nodeTunLeft) bool { return x.ID == left })
	err = nodesSaveLocked()
	nodesMu.Unlock()
	return err
}

// nodeTunRemove removes the client end, then the server end. The pair must
// be listed exactly once from both servers' plans.
func nodeTunRemove(ctx context.Context, j *nodeTunJob, q nodeTunRemoveReq) error {
	if q.Left > 0 {
		return nodeTunRemoveLeft(ctx, j, q.Left)
	}
	pctx, cancel := context.WithTimeout(ctx, nodeTunPlanTO)
	links, _ := nodeTunLinks(pctx)
	cancel()
	var link *nodeTunLink
	n := 0
	for i, l := range links {
		if l.Server == q.Server && l.Client == q.Client && l.PeerID == q.PeerID && l.Hub == q.Hub {
			link = &links[i]
			n++
		}
	}
	if n != 1 {
		return errors.New("this tunnel is not listed between these servers (any more): refresh the list")
	}
	if q.Hub == 1 {
		// the client's first tunnel: removing it removes the whole client
		// set-up, so not while it also serves other Iran servers
		cctx, cancel := context.WithTimeout(ctx, nodeTunPlanTO)
		c, err := nodeTunPlan(cctx, q.Client, "", 0)
		cancel()
		if err != nil {
			return err
		}
		if len(c.Uplinks) > 1 {
			return fmt.Errorf("%s also dials other Iran servers through this first tunnel's set-up: remove those first, or remove this one on its own panel", nodeTunName(q.Client))
		}
	}
	j.logf("removing the client end on %s", nodeTunName(q.Client))
	cctx, cancel := context.WithTimeout(ctx, nodeTunActionTO)
	var err error
	if q.Hub >= 2 {
		err = nodeAPIJSON(cctx, q.Client, http.MethodPost, "/api/cluster/leave-hub", map[string]any{"id": q.Hub}, nil)
	} else {
		err = nodeAPIJSON(cctx, q.Client, http.MethodPost, "/api/action", map[string]any{"action": "remove-tunnel", "peer_id": 0}, nil)
	}
	cancel()
	if err != nil {
		return fmt.Errorf("%v; the server end was not touched", err)
	}
	j.logf("removing the server end on %s", nodeTunName(q.Server))
	sctx, cancel := context.WithTimeout(ctx, nodeTunActionTO)
	err = nodeAPIJSON(sctx, q.Server, http.MethodPost, "/api/action", map[string]any{"action": "remove-tunnel", "peer_id": q.PeerID}, nil)
	cancel()
	if err != nil {
		role := "add-peer"
		if q.PeerID == 0 {
			role = "iran"
		}
		nodeTunKeep(nodeTunReq{Server: q.Server, Client: q.Client}, role, link.ClientIP, err.Error())
		return fmt.Errorf("the client end is removed; the server end: %v (listed as left over)", err)
	}
	nodeAuditf("node_tunnel_removed", "server=%d client=%d peer=%d", q.Server, q.Client, q.PeerID)
	return nil
}

func nodeAuditf(event, format string, a ...any) {
	mu.Lock()
	user := cfg.Username
	mu.Unlock()
	LogSecurityAudit(event, user, "", fmt.Sprintf(format, a...))
}
