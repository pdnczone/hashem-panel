package main

// Nodes N3: a tunnel between two of the central's servers, made from one
// page. The central has no tunnel database: it asks both servers for their
// plan (GET /api/setup/plan), then makes the tunnel with each server's own
// API, in order:
//
//  1. the server end (Iran side): POST /api/setup role "iran" (its first
//     tunnel) or "add-peer"; it answers with the bundle it makes today;
//  2. the client end (foreign side): POST /api/setup role "foreign" with
//     that bundle, or POST /api/cluster/join-hub when it already has a
//     tunnel to another Iran server.
//
// When step 2 fails, step 1 is removed again. When that fails too, the
// tunnel is kept in nodes.json as "left over" with a remove button. Removal
// goes the other way round: the client end first, then the server end.
// Server 0 is the central itself.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	nodeTunPlanTO   = time.Minute
	nodeTunSetupTO  = 20 * time.Minute
	nodeTunActionTO = 2 * time.Minute
	nodeTunJobsMax  = 20
)

// nodeTunLeft is a server end whose client end failed and whose rollback
// failed too: it is listed until it is removed.
type nodeTunLeft struct {
	ID       int    `json:"id"`
	Server   int    `json:"server"`
	Client   int    `json:"client"`
	PeerID   int    `json:"peer_id"` // 0: the server's first tunnel
	ClientIP string `json:"client_ip"`
	Error    string `json:"error"`
	At       int64  `json:"at"`
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

// nodeAPIJSON calls and decodes a 2xx answer into out; any other answer is
// an error with the server's own message.
func nodeAPIJSON(ctx context.Context, id int, method, path string, body, out any) error {
	st, b, err := nodeAPIFn(ctx, id, method, path, body)
	if err != nil {
		return err
	}
	if st < 200 || st > 299 {
		var e struct {
			Code  string   `json:"error_code"`
			Error string   `json:"error"`
			Steps []string `json:"steps"`
		}
		_ = json.Unmarshal(b, &e)
		msg := e.Error
		if msg == "" {
			msg = nodeLogText(b)
		}
		if e.Code != "" {
			msg = "[" + e.Code + "] " + msg
		}
		return fmt.Errorf("%s: %s", nodeTunName(id), nodeLogText([]byte(msg)))
	}
	if out != nil {
		if err := json.Unmarshal(b, out); err != nil {
			return fmt.Errorf("%s: a bad answer", nodeTunName(id))
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

// nodeTunLabel is a node's name as a tunnel label on the other server.
func nodeTunLabel(id int) string {
	name := "central"
	if id != 0 {
		nodesMu.Lock()
		if rec := nodeFindLocked(id); rec != nil {
			name = rec.Name
		}
		nodesMu.Unlock()
	}
	name = strings.Map(func(r rune) rune {
		if strings.ContainsRune("<>\"'`\\\n\r\t", r) {
			return -1
		}
		return r
	}, name)
	if r := []rune(name); len(r) > 40 {
		name = string(r[:40])
	}
	return strings.TrimSpace(name)
}

func nodeTunPlan(ctx context.Context, id int, ports string) (setupPlan, error) {
	var p setupPlan
	path := "/api/setup/plan"
	if ports != "" {
		path += "?ports=" + url.QueryEscape(ports)
	}
	if err := nodeAPIJSON(ctx, id, http.MethodGet, path, nil, &p); err != nil {
		if strings.Contains(err.Error(), "404") || strings.Contains(err.Error(), "E-NODE-06") {
			return p, fmt.Errorf("%s runs an older Hashem: update it first", nodeTunName(id))
		}
		return p, err
	}
	return p, nil
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

var (
	nodeTunPortsRe = regexp.MustCompile(`^[0-9 ,=:\-]{1,300}$`)
	nodeTunTransRe = regexp.MustCompile(`^[a-z]{0,12}$`)
)

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
	case !slices.Contains([]string{"frp", "backhaul", "gre-backhaul"}, q.Engine):
		return nodeErr{"E-NODE-01", "engine: frp, backhaul or gre-backhaul"}
	case !nodeTunTransRe.MatchString(q.Transport):
		return nodeErr{"E-NODE-01", "bad transport"}
	case !nodeTunPortsRe.MatchString(q.Ports):
		return nodeErr{"E-NODE-01", "ports: numbers separated by commas, e.g. 443, 2083"}
	case q.FrpPort < 0 || q.FrpPort > 65535:
		return nodeErr{"E-NODE-01", "bad control port"}
	}
	for _, id := range []int{q.Server, q.Client} {
		if id == 0 {
			continue
		}
		nodesMu.Lock()
		known := nodeFindLocked(id) != nil
		nodesMu.Unlock()
		if !known {
			return errNodeUnknown(id)
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
	LocalGre   string    `json:"local_gre"`   // on the server
	PeerGre    string    `json:"peer_gre"`    // on the client
	FrpPort    int       `json:"frp_port"`
	Problems   []string  `json:"problems,omitempty"` // a create would fail: say why first
}

func nodeTunDraftFor(ctx context.Context, q nodeTunReq) (nodeTunDraft, error) {
	var d nodeTunDraft
	var err error
	if d.Server, err = nodeTunPlan(ctx, q.Server, q.Ports); err != nil {
		return d, err
	}
	if d.Client, err = nodeTunPlan(ctx, q.Client, ""); err != nil {
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
	for port, who := range s.Clashes {
		problem("port %s is already used on %s by %s", port, nodeTunName(q.Server), who)
	}
	if strings.TrimSpace(q.Ports) == "" {
		problem("give the ports users connect to")
	}
	d.FrpPort = q.FrpPort
	if d.FrpPort == 0 {
		d.FrpPort = s.RelayPort
	}
	if d.FrpPort == 0 {
		problem("no free control port on %s", nodeTunName(q.Server))
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
		"name": nodeTunLabel(q.Client), "local_public": d.Server.Public, "remote_public": d.Client.Public,
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
	if err != nil {
		return err // nothing to roll back: the server's own setup failed as a whole
	}
	if res.Bundle == "" {
		return errors.New("the server end gave no bundle")
	}
	peerID := 0 // the server's first tunnel
	if d.ServerRole == "add-peer" {
		actx, cancel := context.WithTimeout(ctx, nodeTunPlanTO)
		after, perr := nodeTunPlan(actx, q.Server, "")
		cancel()
		if perr == nil {
			for _, p := range after.Peers {
				if !before[p.ID] && p.RemotePub == d.Client.Public {
					peerID = p.ID
				}
			}
		}
		if peerID == 0 {
			j.logf("warning: the new tunnel's id on the server is not known")
		}
	}
	// 2. the client end
	j.logf("making the client end on %s (%s)", nodeTunName(q.Client), d.ClientMode)
	cctx, cancel := context.WithTimeout(ctx, nodeTunSetupTO)
	if d.ClientMode == "join-hub" {
		err = nodeAPIJSON(cctx, q.Client, http.MethodPost, "/api/cluster/join-hub", map[string]any{"bundle": res.Bundle, "name": nodeTunLabel(q.Server)}, nil)
	} else {
		err = nodeAPIJSON(cctx, q.Client, http.MethodPost, "/api/setup", map[string]any{"role": "foreign", "token": res.Bundle,
			"local_public": d.Client.Public, "name": nodeTunLabel(q.Server)}, nil)
	}
	cancel()
	if err == nil {
		nodeAuditf("node_tunnel_made", "server=%d client=%d peer=%d engine=%s", q.Server, q.Client, peerID, q.Engine)
		return nil
	}
	j.logf("the client end failed: %v", err)
	// roll back: the half-made client end (only when it had no tunnel
	// before), then the server end
	if d.ClientMode == "foreign" {
		rctx, cancel := context.WithTimeout(ctx, nodeTunActionTO)
		if rerr := nodeAPIJSON(rctx, q.Client, http.MethodPost, "/api/action", map[string]any{"action": "remove-tunnel", "peer_id": 0}, nil); rerr != nil {
			j.logf("cleaning the client end: %v", rerr)
		}
		cancel()
	}
	if d.ServerRole == "add-peer" && peerID == 0 {
		nodeTunKeep(q, 0, d.Client.Public, "the new tunnel's id on the server is not known: remove it there by hand")
		return fmt.Errorf("%v; the server end could not be found to remove it, so it is listed as left over", err)
	}
	j.logf("removing the server end again")
	rctx, cancel := context.WithTimeout(ctx, nodeTunActionTO)
	rerr := nodeAPIJSON(rctx, q.Server, http.MethodPost, "/api/action", map[string]any{"action": "remove-tunnel", "peer_id": peerID}, nil)
	cancel()
	if rerr != nil {
		nodeTunKeep(q, peerID, d.Client.Public, rerr.Error())
		return fmt.Errorf("%v; removing the server end failed too (%v), so it is listed as left over", err, rerr)
	}
	return fmt.Errorf("%v; the server end was removed again", err)
}

// nodeTunKeep lists a server end that is left over.
func nodeTunKeep(q nodeTunReq, peerID int, clientIP, why string) {
	nodesMu.Lock()
	defer nodesMu.Unlock()
	nodesLoadLocked()
	id := 1
	for _, l := range nodesF.Left {
		id = max(id, l.ID+1)
	}
	nodesF.Left = append(nodesF.Left, nodeTunLeft{ID: id, Server: q.Server, Client: q.Client, PeerID: peerID,
		ClientIP: clientIP, Error: why, At: time.Now().Unix()})
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

// nodeTunLinks reads every online server's plan and pairs the ends.
func nodeTunLinks(ctx context.Context) ([]nodeTunLink, []string) {
	ids := []int{0}
	nodesMu.Lock()
	nodesLoadLocked()
	for _, rec := range nodesF.Nodes {
		if nodeSessions[rec.ID] != nil {
			ids = append(ids, rec.ID)
		}
	}
	nodesMu.Unlock()
	plans := map[int]setupPlan{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	var errs []string
	for _, id := range ids {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			p, err := nodeTunPlan(ctx, id, "")
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
	links := []nodeTunLink{}
	for sid, s := range plans {
		for _, p := range s.Peers {
			for cid, c := range plans {
				if cid == sid || c.Public == "" || p.RemotePub != c.Public {
					continue
				}
				for _, u := range c.Uplinks {
					if u.IranPub == s.Public {
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
	return links, errs
}

type nodeTunRemoveReq struct {
	Server int `json:"server"`
	Client int `json:"client"`
	PeerID int `json:"peer_id"`
	Hub    int `json:"hub"`
	Left   int `json:"left"` // a left-over server end: its id
}

// nodeTunRemove removes the client end, then the server end. The pair is
// checked against both servers' plans first.
func nodeTunRemove(ctx context.Context, j *nodeTunJob, q nodeTunRemoveReq) error {
	if q.Left > 0 {
		j.logf("removing the left-over server end on %s", nodeTunName(q.Server))
		rctx, cancel := context.WithTimeout(ctx, nodeTunActionTO)
		err := nodeAPIJSON(rctx, q.Server, http.MethodPost, "/api/action", map[string]any{"action": "remove-tunnel", "peer_id": q.PeerID}, nil)
		cancel()
		if err != nil {
			return err
		}
		nodesMu.Lock()
		nodesLoadLocked()
		nodesF.Left = slices.DeleteFunc(nodesF.Left, func(l nodeTunLeft) bool { return l.ID == q.Left })
		err = nodesSaveLocked()
		nodesMu.Unlock()
		return err
	}
	pctx, cancel := context.WithTimeout(ctx, nodeTunPlanTO)
	links, _ := nodeTunLinks(pctx)
	cancel()
	found := false
	for _, l := range links {
		if l.Server == q.Server && l.Client == q.Client && l.PeerID == q.PeerID && l.Hub == q.Hub {
			found = true
		}
	}
	if !found {
		return errors.New("this tunnel is not between these servers any more: refresh the list")
	}
	if q.Hub == 1 {
		// the client's first tunnel: removing it removes the whole client
		// set-up, so not while it also serves other Iran servers
		cctx, cancel := context.WithTimeout(ctx, nodeTunPlanTO)
		c, err := nodeTunPlan(cctx, q.Client, "")
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
		return fmt.Errorf("the client end is removed; the server end: %v (remove it on that server)", err)
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
