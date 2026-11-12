package main

// The Peer Link over the node channel. A tunnel's two servers talk to each
// other on the Peer Link (carrier swap, path test, Autopilot, handshake).
// Until now that was always a direct HTTP call to the other server's panel
// port, which a filtered path or a closed port stops, and that is when it is
// needed most. When both servers belong to one central, the call now goes
// over the channels they already hold:
//
//	node A --"ask"--> central --"peer" req--> node B     (or the central itself)
//
// What it carries is one Peer Link request, as the direct call would send
// it: /api/peer/... with the same secret. The server that gets it runs it on
// its own Peer Link routes (peerRoutePrefix), whose guards check that secret
// as they do for a direct call. So the channel is a second road to the same
// door: it gives nobody a right the direct call does not give. The central
// only passes /api/peer/ paths, GET or POST, between servers it knows and
// has approved.
//
// A node may now ask its central for this one thing ("ask" frames); it still
// cannot command it. Old ends: a node asks only a central that said proto 2
// in its welcome, and a node that does not know "peer" answers so at once.
// Whenever the channel cannot carry a call, the caller goes on to the direct
// call as before.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"
)

const (
	nodePeerProto    = 2       // the channel protocol that has "ask" and "peer"
	nodePeerBodyMax  = 1 << 20 // a Peer Link request or answer
	nodePeerParallel = 8       // asks of one node in flight on the central
	nodePeerMissTTL  = time.Minute
)

// nodePeerReq is one Peer Link request on the channel.
type nodePeerReq struct {
	To     string `json:"to,omitempty"`   // ask: the other server's public IP
	From   string `json:"from,omitempty"` // peer: the asking server's IP, as the central saw it
	Method string `json:"method"`
	Path   string `json:"path"` // /api/peer/...[?query]
	Secret string `json:"secret,omitempty"`
	Body   []byte `json:"body,omitempty"`
}

// errNodePeerNoRoute: the channel cannot carry this call (no channel, an old
// end, or the other server is not one of this central's): use the direct call.
var errNodePeerNoRoute = errors.New("no node channel to that server")

// nodePeerPathOK: only the Peer Link, with no tricks in the path.
func nodePeerPathOK(p string) bool {
	path, _, _ := strings.Cut(p, "?")
	return strings.HasPrefix(path, "/api/peer/") && !strings.Contains(path, "..") && !strings.Contains(path, "//") &&
		!strings.ContainsAny(p, "#\\ \r\n")
}

func nodePeerCheck(q nodePeerReq) error {
	if q.Method != http.MethodGet && q.Method != http.MethodPost {
		return errors.New("only GET and POST go over the channel")
	}
	if !nodePeerPathOK(q.Path) {
		return errors.New("only the Peer Link goes over the channel")
	}
	if len(q.Body) > nodePeerBodyMax {
		return errors.New("request too big")
	}
	return nil
}

// nodePeerServe runs a Peer Link request that came over the channel on this
// server's own Peer Link routes. No relay mark is set: the route's guard
// checks the secret exactly as for a direct call.
func nodePeerServe(raw json.RawMessage) (json.RawMessage, error) {
	var q nodePeerReq
	if err := json.Unmarshal(raw, &q); err != nil {
		return nil, errors.New("bad peer request")
	}
	if err := nodePeerCheck(q); err != nil {
		return nil, err
	}
	mux := nodeRelayMux()
	if mux == nil {
		return nil, errors.New("the panel is starting")
	}
	from := net.ParseIP(strings.Trim(q.From, "[]"))
	if from == nil {
		return nil, errors.New("bad peer request: no sender")
	}
	to := nodeRelayGetTO
	if q.Method != http.MethodGet {
		to = nodeRelayPostTO
	}
	ctx, cancel := context.WithTimeout(context.Background(), to)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, q.Method, peerRoutePrefix+q.Path, bytes.NewReader(q.Body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if q.Secret != "" {
		req.Header.Set("X-Peer-Secret", q.Secret)
	}
	req.RemoteAddr = net.JoinHostPort(from.String(), "0")
	rec := &nodeRelayRecorder{ResponseRecorder: httptest.NewRecorder()}
	mux.ServeHTTP(rec, req)
	if rec.over || rec.Body.Len() > nodePeerBodyMax {
		return nil, errors.New("answer too big")
	}
	return json.Marshal(nodeHTTPRes{Status: rec.Code, Body: rec.Body.Bytes()})
}

// ---- the central: who an IP is, and passing a call on ----

// nodePeerTarget finds the server at ip among this central's: its node id,
// 0 for the central itself, -1 for none (or one not approved yet).
func nodePeerTarget(ip string, except int) int {
	want := net.ParseIP(strings.Trim(ip, "[]"))
	if want == nil {
		return -1
	}
	same := func(s string) bool {
		if h, _, err := net.SplitHostPort(s); err == nil {
			s = h
		}
		got := net.ParseIP(strings.Trim(s, "[]"))
		return got != nil && got.Equal(want)
	}
	nodesMu.Lock()
	nodesLoadLocked()
	for _, rec := range nodesF.Nodes {
		if rec.ID != except && !rec.Held && (same(rec.Info.PublicIP) || same(rec.Addr)) {
			nodesMu.Unlock()
			return rec.ID
		}
	}
	nodesMu.Unlock()
	if except != 0 && same(detectPublicIPCached()) {
		return 0
	}
	return -1
}

// nodePeerDeliver sends q to server id (0: this central itself).
func nodePeerDeliver(ctx context.Context, id int, q nodePeerReq) (nodeHTTPRes, error) {
	var res nodeHTTPRes
	q.To = ""
	body, err := json.Marshal(q)
	if err != nil {
		return res, err
	}
	var raw json.RawMessage
	if id == 0 {
		raw, err = nodePeerServe(body)
	} else {
		s := nodeSessionFor(id)
		if s == nil {
			return res, errNodePeerNoRoute
		}
		raw, err = s.call(ctx, "peer", json.RawMessage(body))
	}
	if err != nil {
		return res, err
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return res, errors.New("a bad answer")
	}
	return res, nil
}

// nodeServeAsk answers one "ask" of node s on the central.
func nodeServeAsk(s *nodeSession, fr nodeFrame) {
	answer := func(body json.RawMessage, err error) {
		f := nodeFrame{T: "ans", ID: fr.ID, Body: body}
		if err != nil {
			f.Body, f.Err = nil, err.Error()
		}
		_ = s.conn.send(f)
	}
	if fr.Method != "peer" {
		answer(nil, fmt.Errorf("this central (%s) does not know %q: update it", panelVersion, fr.Method))
		return
	}
	select {
	case s.asks <- struct{}{}:
		defer func() { <-s.asks }()
	default:
		answer(nil, errors.New("the central is busy with this node's requests: try again in a moment"))
		return
	}
	var q nodePeerReq
	if err := json.Unmarshal(fr.Body, &q); err != nil {
		answer(nil, errors.New("bad peer request"))
		return
	}
	if err := nodePeerCheck(q); err != nil {
		answer(nil, err)
		return
	}
	nodesMu.Lock()
	rec := nodeFindLocked(s.id)
	held := rec == nil || rec.Held
	nodesMu.Unlock()
	if held {
		answer(nil, errNodePeerNoRoute) // not approved yet: nothing is passed on for it
		return
	}
	id := nodePeerTarget(q.To, s.id)
	if id < 0 {
		answer(nil, errNodePeerNoRoute)
		return
	}
	// the sender's address is what the central saw, never what the node says
	q.From = s.addr
	if h, _, err := net.SplitHostPort(s.addr); err == nil {
		q.From = h
	}
	ctx, cancel := context.WithTimeout(context.Background(), nodeRelayPostTO)
	defer cancel()
	res, err := nodePeerDeliver(ctx, id, q)
	if err != nil {
		answer(nil, err)
		return
	}
	body, err := json.Marshal(res)
	answer(body, err)
}

// ---- a node: asking its central ----

// nodeUp is this node's live channel to its central, for its own asks.
var nodeUp struct {
	sync.Mutex
	nc      *nodeConn
	next    uint64
	pending map[uint64]chan nodeFrame
}

// nodeUpSet records the channel once the central welcomed this node, when
// that central passes peer calls on.
func nodeUpSet(nc *nodeConn, proto int) {
	if proto < nodePeerProto {
		return
	}
	nodeUp.Lock()
	nodeUp.nc, nodeUp.pending = nc, map[uint64]chan nodeFrame{}
	nodeUp.Unlock()
}

// nodeUpClear drops the channel (if it is still nc) and ends what waits on it.
func nodeUpClear(nc *nodeConn) {
	nodeUp.Lock()
	if nodeUp.nc == nc {
		for _, ch := range nodeUp.pending {
			close(ch)
		}
		nodeUp.nc, nodeUp.pending = nil, nil
	}
	nodeUp.Unlock()
}

// nodeUpAnswer hands an "ans" frame to the ask that waits for it.
func nodeUpAnswer(fr nodeFrame) {
	nodeUp.Lock()
	defer nodeUp.Unlock() // under the lock: nodeUpClear closes these channels
	if ch := nodeUp.pending[fr.ID]; ch != nil {
		delete(nodeUp.pending, fr.ID)
		ch <- fr // room for one, and one answer an ask
	}
}

// nodeAsk sends one ask to the central and waits for its answer.
func nodeAsk(ctx context.Context, method string, body any) (json.RawMessage, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	nodeUp.Lock()
	nc := nodeUp.nc
	if nc == nil {
		nodeUp.Unlock()
		return nil, errNodePeerNoRoute
	}
	nodeUp.next++
	id := nodeUp.next
	ch := make(chan nodeFrame, 1)
	nodeUp.pending[id] = ch
	nodeUp.Unlock()
	defer func() {
		nodeUp.Lock()
		delete(nodeUp.pending, id)
		nodeUp.Unlock()
	}()
	if err := nc.send(nodeFrame{T: "ask", ID: id, Method: method, Body: raw}); err != nil {
		return nil, errNodePeerNoRoute
	}
	select {
	case f, ok := <-ch:
		if !ok {
			return nil, errNodePeerNoRoute // the channel closed
		}
		if f.Err != "" {
			if f.Err == errNodePeerNoRoute.Error() {
				return nil, errNodePeerNoRoute
			}
			return nil, errors.New(nodeLogText([]byte(f.Err)))
		}
		return f.Body, nil
	case <-ctx.Done():
		return nil, errors.New("the central did not answer in time")
	}
}

// ---- the caller: sendToPeer and tunnelPeerCall try this first ----

// nodePeerMiss remembers for a minute that an IP is not reachable over the
// channel, so a peer outside this central costs one ask a minute, not one a
// call.
var nodePeerMiss = struct {
	sync.Mutex
	m map[string]time.Time
}{m: map[string]time.Time{}}

func nodePeerMissed(ip string) bool {
	nodePeerMiss.Lock()
	defer nodePeerMiss.Unlock()
	t, ok := nodePeerMiss.m[ip]
	if ok && time.Since(t) > nodePeerMissTTL {
		delete(nodePeerMiss.m, ip)
		return false
	}
	return ok
}

func nodePeerMissSet(ip string) {
	nodePeerMiss.Lock()
	if len(nodePeerMiss.m) > 256 {
		nodePeerMiss.m = map[string]time.Time{}
	}
	nodePeerMiss.m[ip] = time.Now()
	nodePeerMiss.Unlock()
}

// peerChannel is peerChannelCall; a var so tests need no channel.
var peerChannel = peerChannelCall

// peerChannelCall sends one Peer Link request to the server at one of ips
// over the node channel. ok is false when the channel cannot carry it (the
// caller then makes the direct call); otherwise status and data are the
// other server's answer.
func peerChannelCall(ips []string, method, path, secret string, body []byte, timeout time.Duration) (status int, data []byte, ok bool) {
	self, err := nodeSelfLoad()
	if err != nil || self.Role == "" {
		return 0, nil, false
	}
	q := nodePeerReq{Method: method, Path: path, Secret: secret, Body: body}
	if nodePeerCheck(q) != nil {
		return 0, nil, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	seen := map[string]bool{}
	for _, ip := range ips {
		ip = CleanHost(ip)
		if ip == "" || seen[ip] || net.ParseIP(ip) == nil || nodePeerMissed(ip) {
			continue
		}
		seen[ip] = true
		var res nodeHTTPRes
		var cerr error
		if self.Role == nodeRoleCentral {
			id := nodePeerTarget(ip, 0)
			if id <= 0 {
				nodePeerMissSet(ip)
				continue
			}
			q.From = detectPublicIPCached()
			res, cerr = nodePeerDeliver(ctx, id, q)
		} else {
			q.To = ip
			var raw json.RawMessage
			if raw, cerr = nodeAsk(ctx, "peer", q); cerr == nil && json.Unmarshal(raw, &res) != nil {
				cerr = errors.New("a bad answer")
			}
		}
		if cerr != nil {
			// not one of this central's servers, an old node, a busy channel,
			// a timeout: the direct call decides, and the channel is not
			// tried again for this server for a minute
			nodePeerMissSet(ip)
			continue
		}
		return res.Status, res.Body, true
	}
	return 0, nil, false
}
