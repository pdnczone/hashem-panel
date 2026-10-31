package main

// The node channel: the node dials the central's panel port (a websocket at
// nodeLinkPath), and inside it the two run TLS 1.3 with both keys pinned, so
// the channel is private and authenticated even over plain HTTP. Inside the
// TLS stream: length-prefixed JSON frames. The central asks, the node
// answers; a node cannot send the central commands.
//
// Frames: the node opens with "hello" (a joined node) or "enroll" (a join
// code); the central answers "welcome" or "refused". Then the central sends
// "req" frames and the node answers each with a "res" of the same id. "bye"
// (central) = this node was removed: it goes back to standalone.

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

const (
	nodeFrameMax    = 16 << 20 // one frame
	nodeFirstMax    = 4 << 10  // the first frame (enroll / hello), before anything is known
	nodePreAuthMax  = 32       // connections not past their first frame yet
	nodePreAuthIP   = 4        // ... from one address
	nodeSeenFlush   = 5 * time.Minute
	nodeReqParallel = 8
	nodePartMax     = 256 << 10 // an answer bigger than this goes in parts, so other frames get through between them
)

// Timers (variables: the lab runs them fast).
var (
	nodeHandshakeTO  = 15 * time.Second
	nodeInfoEvery    = 15 * time.Second // also the keepalive
	nodeCallTO       = 30 * time.Second
	nodeIdleTO       = 75 * time.Second // the node hears nothing this long: dial again
	nodeRefusedRetry = 10 * time.Minute
	nodeBackoffMax   = time.Minute
)

type nodeFrame struct {
	T       string          `json:"t"` // hello | enroll | welcome | refused | req | res | bye
	ID      uint64          `json:"id,omitempty"`
	Proto   int             `json:"proto,omitempty"`
	NodeID  int             `json:"node_id,omitempty"`
	Name    string          `json:"name,omitempty"`
	Secret  string          `json:"secret,omitempty"`
	Version string          `json:"version,omitempty"`
	Reason  string          `json:"reason,omitempty"`
	Method  string          `json:"method,omitempty"`
	Body    json.RawMessage `json:"body,omitempty"`
	Data    []byte          `json:"data,omitempty"` // part | res: a piece of an answer sent in parts
	Err     string          `json:"err,omitempty"`
}

// ---- websocket as a byte stream (TLS runs over it) ----

type wsStream struct {
	ws *websocket.Conn
	r  io.Reader
	wm sync.Mutex
}

func (s *wsStream) Read(p []byte) (int, error) {
	for {
		if s.r == nil {
			t, r, err := s.ws.NextReader()
			if err != nil {
				return 0, err
			}
			if t != websocket.BinaryMessage {
				continue
			}
			s.r = r
		}
		n, err := s.r.Read(p)
		if err == io.EOF {
			s.r = nil
			if n > 0 {
				return n, nil
			}
			continue
		}
		return n, err
	}
}

func (s *wsStream) Write(p []byte) (int, error) {
	s.wm.Lock()
	defer s.wm.Unlock()
	if err := s.ws.WriteMessage(websocket.BinaryMessage, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (s *wsStream) Close() error                       { return s.ws.Close() }
func (s *wsStream) LocalAddr() net.Addr                { return s.ws.LocalAddr() }
func (s *wsStream) RemoteAddr() net.Addr               { return s.ws.RemoteAddr() }
func (s *wsStream) SetReadDeadline(t time.Time) error  { return s.ws.SetReadDeadline(t) }
func (s *wsStream) SetWriteDeadline(t time.Time) error { return s.ws.SetWriteDeadline(t) }
func (s *wsStream) SetDeadline(t time.Time) error {
	if err := s.ws.SetReadDeadline(t); err != nil {
		return err
	}
	return s.ws.SetWriteDeadline(t)
}

// ---- frames ----

// nodeConn is one end of the channel: frames over the TLS stream.
type nodeConn struct {
	c  net.Conn
	wm sync.Mutex
}

func (n *nodeConn) send(f nodeFrame) error {
	b, err := json.Marshal(f)
	if err != nil {
		return err
	}
	if len(b) > nodeFrameMax {
		return fmt.Errorf("frame of %d bytes is too big", len(b))
	}
	buf := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(buf, uint32(len(b)))
	copy(buf[4:], b)
	n.wm.Lock()
	defer n.wm.Unlock()
	_ = n.c.SetWriteDeadline(time.Now().Add(nodeCallTO))
	_, err = n.c.Write(buf)
	return err
}

// recv reads one frame of at most max bytes. The buffer grows with what
// arrives, not with the size the header claims.
func (n *nodeConn) recv(timeout time.Duration, max int) (nodeFrame, error) {
	var f nodeFrame
	if timeout > 0 {
		_ = n.c.SetReadDeadline(time.Now().Add(timeout))
	} else {
		_ = n.c.SetReadDeadline(time.Time{})
	}
	var hdr [4]byte
	if _, err := io.ReadFull(n.c, hdr[:]); err != nil {
		return f, err
	}
	size := binary.BigEndian.Uint32(hdr[:])
	if size == 0 || size > uint32(max) {
		return f, fmt.Errorf("bad frame size %d", size)
	}
	var buf bytes.Buffer
	if _, err := io.CopyN(&buf, n.c, int64(size)); err != nil {
		return f, err
	}
	if err := json.Unmarshal(buf.Bytes(), &f); err != nil {
		return f, fmt.Errorf("bad frame: %v", err)
	}
	return f, nil
}

// ---- central side ----

// nodeSession is a connected node, on the central.
type nodeSession struct {
	id      int
	conn    *nodeConn
	addr    string
	version string
	since   time.Time
	next    atomic.Uint64
	pm      sync.Mutex
	pending map[uint64]chan nodeFrame
	parts   map[uint64]*bytes.Buffer // pm: answers arriving in parts
	lastRx  atomic.Int64             // unix nano of the last frame from the node
	slots   chan struct{}            // "http" calls in flight: they wait here, so the node never has to say busy
	done    chan struct{}
	once    sync.Once
}

var nodeSessions = map[int]*nodeSession{} // nodesMu

func (s *nodeSession) close() {
	s.once.Do(func() {
		close(s.done)
		_ = s.conn.c.Close()
	})
}

// call asks the node and waits for its answer.
func (s *nodeSession) call(ctx context.Context, method string, body any) (json.RawMessage, error) {
	var raw json.RawMessage
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		raw = b
	}
	if method == "http" && s.slots != nil {
		select {
		case s.slots <- struct{}{}:
			defer func() { <-s.slots }()
		case <-s.done:
			return nil, fmt.Errorf("node %d went offline", s.id)
		case <-ctx.Done():
			return nil, fmt.Errorf("node %d is busy with other requests: try again", s.id)
		}
	}
	id := s.next.Add(1)
	ch := make(chan nodeFrame, 1)
	s.pm.Lock()
	s.pending[id] = ch
	s.pm.Unlock()
	defer func() {
		s.pm.Lock()
		delete(s.pending, id)
		delete(s.parts, id)
		s.pm.Unlock()
	}()
	if err := s.conn.send(nodeFrame{T: "req", ID: id, Method: method, Body: raw}); err != nil {
		s.close()
		return nil, fmt.Errorf("node %d: %v", s.id, err)
	}
	select {
	case f := <-ch:
		if f.Err != "" {
			return nil, errors.New(f.Err)
		}
		return f.Body, nil
	case <-s.done:
		return nil, fmt.Errorf("node %d went offline", s.id)
	case <-ctx.Done():
		return nil, fmt.Errorf("node %d did not answer in time", s.id)
	}
}

// alive: a frame came from the node within nodeCallTO.
func (s *nodeSession) alive() bool {
	return time.Since(time.Unix(0, s.lastRx.Load())) < nodeCallTO
}

// addPartLocked adds a part to its answer; at the final "res" it returns the
// whole answer. An answer over nodeFrameMax in all is refused.
func (s *nodeSession) addPartLocked(fr nodeFrame) nodeFrame {
	b := s.parts[fr.ID]
	if b == nil {
		b = &bytes.Buffer{}
		s.parts[fr.ID] = b
	}
	if b.Len()+len(fr.Data) > nodeFrameMax {
		delete(s.parts, fr.ID)
		return nodeFrame{T: "res", ID: fr.ID, Err: "the node's answer is too big"}
	}
	b.Write(fr.Data)
	if fr.T != "res" {
		return fr
	}
	delete(s.parts, fr.ID)
	if fr.Err != "" {
		return fr
	}
	fr.Body, fr.Data = json.RawMessage(b.Bytes()), nil
	return fr
}

// nodeSessionFor is the live session of node id, or nil.
func nodeSessionFor(id int) *nodeSession {
	nodesMu.Lock()
	defer nodesMu.Unlock()
	return nodeSessions[id]
}

var nodeUpgrader = websocket.Upgrader{
	ReadBufferSize:  32 << 10,
	WriteBufferSize: 32 << 10,
	// No cookies are used here and the inner TLS needs the node's key, so a
	// browser page that opens this socket gets nowhere.
	CheckOrigin: func(*http.Request) bool { return true },
}

// Connections that have not sent their first frame yet: capped, in all and
// per address, so a flood of half-open links cannot use up the central.
var nodePreAuth = struct {
	sync.Mutex
	n    int
	byIP map[string]int
}{byIP: map[string]int{}}

// nodePreAuthKey: the address a link is counted under; IPv6 by /64 (one
// host gets a whole /64, so per address would be no limit).
func nodePreAuthKey(ip string) string {
	if a, err := netip.ParseAddr(ip); err == nil && a.Is6() && !a.Is4In6() {
		if p, err := a.Prefix(64); err == nil {
			return p.String()
		}
	}
	return ip
}

func nodePreAuthTake(ip string) bool {
	ip = nodePreAuthKey(ip)
	nodePreAuth.Lock()
	defer nodePreAuth.Unlock()
	if nodePreAuth.n >= nodePreAuthMax || nodePreAuth.byIP[ip] >= nodePreAuthIP {
		return false
	}
	nodePreAuth.n++
	nodePreAuth.byIP[ip]++
	return true
}

func nodePreAuthDone(ip string) {
	ip = nodePreAuthKey(ip)
	nodePreAuth.Lock()
	defer nodePreAuth.Unlock()
	nodePreAuth.n--
	if nodePreAuth.byIP[ip]--; nodePreAuth.byIP[ip] <= 0 {
		delete(nodePreAuth.byIP, ip)
	}
}

// nodeRawCerts is the other end's certificate chain as sent.
func nodeRawCerts(cs tls.ConnectionState) [][]byte {
	raw := make([][]byte, 0, len(cs.PeerCertificates))
	for _, c := range cs.PeerCertificates {
		raw = append(raw, c.Raw)
	}
	return raw
}

// nodeAuditEvery: one refused-enroll line per address a minute (a flood
// would rotate the real entries out of the audit log).
var nodeAuditSeen = struct {
	sync.Mutex
	at map[string]time.Time
}{at: map[string]time.Time{}}

func nodeAuditOnce(ip string) bool {
	nodeAuditSeen.Lock()
	defer nodeAuditSeen.Unlock()
	now := time.Now()
	if t, ok := nodeAuditSeen.at[ip]; ok && now.Sub(t) < time.Minute {
		return false
	}
	if len(nodeAuditSeen.at) > 1000 {
		nodeAuditSeen.at = map[string]time.Time{}
	}
	nodeAuditSeen.at[ip] = now
	return true
}

// handleNodeLink is the central's end of the channel. Anything that is not a
// node's websocket on a central gets a plain 404.
func handleNodeLink(w http.ResponseWriter, r *http.Request) {
	self, err := nodeSelfLoad()
	if err != nil || self.Role != nodeRoleCentral || !isWebSocketUpgrade(r) {
		http.NotFound(w, r)
		return
	}
	addr := ClientIP(r)
	if !nodePreAuthTake(addr) {
		http.Error(w, "busy", http.StatusServiceUnavailable)
		return
	}
	released := false
	release := func() {
		if !released {
			released = true
			nodePreAuthDone(addr)
		}
	}
	defer release()
	ws, err := nodeUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	// one deadline for the TLS handshake and the first frame (the server's
	// own deadlines do not apply to a hijacked conn)
	deadline := time.Now().Add(nodeHandshakeTO)
	_ = ws.UnderlyingConn().SetDeadline(deadline)
	ws.SetReadLimit(nodeFrameMax + 64<<10)
	tc, err := nodeTLSConfig(true, func(string) error { return nil }) // any key here: enroll or hello decides
	if err != nil {
		_ = ws.Close()
		log.Printf("nodes: %v", err)
		return
	}
	tlsc := tls.Server(&wsStream{ws: ws}, tc)
	_ = tlsc.SetDeadline(deadline)
	if err := tlsc.Handshake(); err != nil {
		_ = tlsc.Close()
		return
	}
	peerKey, err := nodePeerKey(nodeRawCerts(tlsc.ConnectionState()))
	if err != nil || peerKey == "" {
		_ = tlsc.Close()
		return
	}
	nc := &nodeConn{c: tlsc}
	first, err := nc.recv(time.Until(deadline), nodeFirstMax)
	if err != nil {
		_ = tlsc.Close()
		return
	}
	_ = tlsc.SetDeadline(time.Time{})
	_ = ws.UnderlyingConn().SetDeadline(time.Time{})
	release()
	switch first.T {
	case "enroll":
		nodeServeEnroll(nc, first, peerKey, addr)
	case "hello":
		nodeServeHello(nc, first, peerKey, addr)
	default:
		_ = tlsc.Close()
	}
}

func nodeServeEnroll(nc *nodeConn, f nodeFrame, key, addr string) {
	defer nc.c.Close()
	name, _ := nodeCleanName(f.Name)
	now := time.Now()
	nodesMu.Lock()
	nodesLoadLocked()
	id, err := nodeEnrollLocked(f.Secret, key, name, addr, now)
	if err == nil {
		err = nodesSaveLocked()
	}
	nodesMu.Unlock()
	if err != nil {
		if nodeAuditOnce(addr) {
			LogSecurityAudit("node_enroll_refused", "node", addr, err.Error())
		}
		_ = nc.send(nodeFrame{T: "refused", Reason: err.Error()})
		return
	}
	LogSecurityAudit("node_enrolled", "node", addr, "id="+strconv.Itoa(id)+" key="+nodeFingerprint(key))
	_ = nc.send(nodeFrame{T: "welcome", NodeID: id, Proto: nodeProto})
}

func nodeServeHello(nc *nodeConn, f nodeFrame, key, addr string) {
	nodesMu.Lock()
	nodesLoadLocked()
	if nodesEr != "" { // the list cannot be read: not a reason to tell nodes they are unknown
		nodesMu.Unlock()
		_ = nc.send(nodeFrame{T: "refused", Reason: "unavailable"})
		_ = nc.c.Close()
		return
	}
	rec := nodeFindKeyLocked(key)
	if rec == nil {
		nodesMu.Unlock()
		_ = nc.send(nodeFrame{T: "refused", Reason: "unknown"})
		_ = nc.c.Close()
		return
	}
	s := &nodeSession{id: rec.ID, conn: nc, addr: addr, version: f.Version, since: time.Now(),
		pending: map[uint64]chan nodeFrame{}, parts: map[uint64]*bytes.Buffer{}, done: make(chan struct{}),
		slots: make(chan struct{}, nodeReqParallel)}
	s.lastRx.Store(time.Now().UnixNano())
	if old := nodeSessions[rec.ID]; old != nil {
		old.close()
	}
	nodeSessions[rec.ID] = s
	rec.Addr, rec.LastSeen = addr, time.Now().Unix()
	_ = nodesSaveLocked()
	nodesMu.Unlock()
	if err := nc.send(nodeFrame{T: "welcome", NodeID: s.id, Proto: nodeProto}); err != nil {
		nodeSessionEnd(s)
		return
	}
	go nodeInfoLoop(s)
	for {
		fr, err := nc.recv(0, nodeFrameMax)
		if err != nil {
			break
		}
		s.lastRx.Store(time.Now().UnixNano())
		if fr.T == "bye" {
			nodeForget(s, fr.Reason)
			break
		}
		if fr.T != "res" && fr.T != "part" {
			continue
		}
		s.pm.Lock()
		ch := s.pending[fr.ID]
		if ch != nil && (fr.T == "part" || s.parts[fr.ID] != nil) {
			fr = s.addPartLocked(fr)
		}
		s.pm.Unlock()
		if ch != nil && fr.T == "res" {
			select {
			case ch <- fr:
			default:
			}
		}
	}
	nodeSessionEnd(s)
}

// nodeSessionEnd drops s (if it is still the node's session).
func nodeSessionEnd(s *nodeSession) {
	s.close()
	nodesMu.Lock()
	if nodeSessions[s.id] == s {
		delete(nodeSessions, s.id)
		if rec := nodeFindLocked(s.id); rec != nil {
			rec.LastSeen = time.Now().Unix()
			_ = nodesSaveLocked()
		}
	}
	nodesMu.Unlock()
}

// nodeInfoLoop asks the node for its info every nodeInfoEvery (which also
// keeps the channel alive) while the session lasts.
func nodeInfoLoop(s *nodeSession) {
	var saved time.Time
	t := time.NewTicker(nodeInfoEvery)
	defer t.Stop()
	for {
		ctx, cancel := context.WithTimeout(context.Background(), nodeCallTO)
		raw, err := s.call(ctx, "info", nil)
		cancel()
		if err != nil && s.alive() {
			// the node is still sending (a big answer ahead of this one on a
			// slow link): not a dead channel
			select {
			case <-s.done:
				return
			case <-t.C:
				continue
			}
		}
		if err != nil {
			// a channel that went silent (a firewall drops it, the node hangs)
			// may never error by itself: drop it, the node dials again
			log.Printf("nodes: node %d: %v; closing its channel", s.id, err)
			nodeSessionEnd(s)
			return
		}
		var info nodeInfo
		syncLic := false
		if json.Unmarshal(raw, &info) == nil {
			info = nodeInfoClean(info)
			now := time.Now()
			nodesMu.Lock()
			if nodeSessions[s.id] == s {
				if rec := nodeFindLocked(s.id); rec != nil {
					changed := rec.Info.Version != info.Version || rec.Info.License.Active != info.License.Active
					rec.Info, rec.LastSeen = info, now.Unix()
					syncLic = true
					if changed || now.Sub(saved) > nodeSeenFlush {
						if nodesSaveLocked() == nil {
							saved = now
						}
					}
				}
			}
			nodesMu.Unlock()
			if syncLic {
				nodeLicenseSync(s, info)
			}
		}
		select {
		case <-s.done:
			return
		case <-t.C:
		}
	}
}

// nodeForget drops a node that left its central by itself.
func nodeForget(s *nodeSession, why string) {
	nodesMu.Lock()
	for i, rec := range nodesF.Nodes {
		if rec.ID == s.id && nodeSessions[s.id] == s {
			nodesF.Nodes = append(nodesF.Nodes[:i], nodesF.Nodes[i+1:]...)
			_ = nodesSaveLocked()
			break
		}
	}
	nodesMu.Unlock()
	LogSecurityAudit("node_left", "node", s.addr, "id="+strconv.Itoa(s.id)+" "+why)
}

// nodeKick tells node id it was removed and closes its session.
func nodeKick(id int) {
	nodesMu.Lock()
	s := nodeSessions[id]
	delete(nodeSessions, id)
	nodesMu.Unlock()
	if s != nil {
		_ = s.conn.send(nodeFrame{T: "bye", Reason: "removed"})
		// closing at once can reset the connection and lose the bye (unread
		// answers in the socket): let the node close it, or give up in 3 s
		go func() {
			select {
			case <-s.done:
			case <-time.After(3 * time.Second):
				s.close()
			}
		}()
	}
}

// ---- node side ----

// nodeDial opens the channel to central and pins its key.
func nodeDial(ctx context.Context, central, centralKey string) (*nodeConn, error) {
	d := websocket.Dialer{
		HandshakeTimeout: nodeHandshakeTO,
		ReadBufferSize:   32 << 10,
		WriteBufferSize:  32 << 10,
		// the outer https (if any) is only a wrapper: the key inside is pinned
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
	}
	ws, resp, err := d.DialContext(ctx, nodeLinkURL(central), nil)
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			return nil, fmt.Errorf("%s is not a central (no node link there): is the address right, and is that panel the central?", central)
		}
		return nil, fmt.Errorf("cannot reach the central at %s: %v", central, err)
	}
	ws.SetReadLimit(nodeFrameMax + 64<<10)
	tc, err := nodeTLSConfig(false, func(k string) error {
		if !ConstantTimeCompare(k, centralKey) {
			return errors.New("the central's key does not match the join code (another server answered)")
		}
		return nil
	})
	if err != nil {
		_ = ws.Close()
		return nil, err
	}
	tlsc := tls.Client(&wsStream{ws: ws}, tc)
	_ = tlsc.SetDeadline(time.Now().Add(nodeHandshakeTO))
	if err := tlsc.HandshakeContext(ctx); err != nil {
		_ = tlsc.Close()
		return nil, fmt.Errorf("secure channel to %s: %v", central, err)
	}
	_ = tlsc.SetDeadline(time.Time{})
	return &nodeConn{c: tlsc}, nil
}

// nodeJoin enrolls this panel with a join code and writes node.json.
func nodeJoin(ctx context.Context, code, name string) (nodeSelf, error) {
	c, err := parseNodeCode(code)
	if err != nil {
		return nodeSelf{}, err
	}
	name, err = nodeCleanName(name)
	if err != nil {
		return nodeSelf{}, err
	}
	nodesMu.Lock()
	cur, err := nodeSelfLoad()
	nodesMu.Unlock()
	if err != nil {
		return nodeSelf{}, err
	}
	if cur.Role == nodeRoleCentral {
		return nodeSelf{}, errors.New("this panel is a central: it cannot be a node too (remove its nodes and leave first)")
	}
	if name == "" {
		name, _ = os.Hostname()
		name, _ = nodeCleanName(name)
	}
	nc, err := nodeDial(ctx, c.URL, c.Key)
	if err != nil {
		return nodeSelf{}, err
	}
	defer nc.c.Close()
	if err := nc.send(nodeFrame{T: "enroll", Proto: nodeProto, Secret: c.Secret, Name: name, Version: panelVersion}); err != nil {
		return nodeSelf{}, err
	}
	f, err := nc.recv(nodeHandshakeTO, nodeFirstMax)
	if err != nil {
		return nodeSelf{}, fmt.Errorf("the central did not answer: %v", err)
	}
	if f.T == "refused" {
		return nodeSelf{}, fmt.Errorf("the central refused: %s", f.Reason)
	}
	if f.T != "welcome" || f.NodeID < 1 {
		return nodeSelf{}, errors.New("the central gave an unexpected answer")
	}
	s := nodeSelf{Role: nodeRoleNode, ID: f.NodeID, Central: c.URL, CentralKey: c.Key, Name: name, JoinedAt: time.Now().Unix()}
	nodesMu.Lock()
	defer nodesMu.Unlock()
	// the role again: another join (or becoming a central) during the dial wins
	if now, err := nodeSelfLoad(); err != nil || now.Role != cur.Role || now.JoinedAt != cur.JoinedAt {
		return nodeSelf{}, errors.New("this panel's role changed while joining: try again")
	}
	return s, nodeSelfSave(s)
}

// nodeLinkState is the node's view of its channel, for the panel and CLI.
var nodeLinkState struct {
	sync.Mutex
	Connected bool
	Since     time.Time
	LastErr   string
}

func nodeLinkSet(connected bool, errText string) {
	nodeLinkState.Lock()
	if connected && !nodeLinkState.Connected {
		nodeLinkState.Since = time.Now()
	}
	nodeLinkState.Connected = connected
	if errText != "" || connected {
		nodeLinkState.LastErr = errText
	}
	nodeLinkState.Unlock()
}

// startNodeLoop keeps a node connected to its central (nothing to do on a
// standalone panel or a central). node.json is read again every few seconds,
// so a join or leave by the CLI takes effect without a restart.
func startNodeLoop() {
	backoff := 2 * time.Second
	for {
		s, err := nodeSelfLoad()
		if err != nil || s.Role != nodeRoleNode {
			nodeLinkSet(false, "")
			time.Sleep(5 * time.Second)
			continue
		}
		res := nodeRunOnce(s)
		switch {
		case res == "bye":
			nodeLinkSet(false, "removed by the central")
			continue
		case res == "refused":
			nodeLinkSet(false, "the central does not know this node")
			nodeSleepWhile(s, nodeRefusedRetry)
			continue
		case res == "ok":
			backoff = min(2*time.Second, nodeBackoffMax) // it was up: dial again soon
		}
		nodeSleepWhile(s, backoff+time.Duration(rand.Int64N(int64(backoff/2+1))))
		if backoff < nodeBackoffMax {
			backoff = min(backoff*2, nodeBackoffMax)
		}
	}
}

// nodeSleepWhile waits d, or less when node.json changes.
func nodeSleepWhile(s nodeSelf, d time.Duration) {
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		time.Sleep(min(2*time.Second, time.Until(end)+time.Millisecond))
		cur, err := nodeSelfLoad()
		if err != nil || cur.Role != s.Role || cur.ID != s.ID || cur.Central != s.Central || cur.CentralKey != s.CentralKey || cur.JoinedAt != s.JoinedAt {
			return
		}
	}
}

// nodeRunOnce dials the central and serves it until the channel drops.
// It returns "ok" (was connected), "fail", "refused" or "bye".
func nodeRunOnce(s nodeSelf) string {
	ctx, cancel := context.WithTimeout(context.Background(), nodeHandshakeTO*2)
	nc, err := nodeDial(ctx, s.Central, s.CentralKey)
	cancel()
	if err != nil {
		nodeLinkSet(false, err.Error())
		return "fail"
	}
	defer nc.c.Close()
	if err := nc.send(nodeFrame{T: "hello", Proto: nodeProto, NodeID: s.ID, Version: panelVersion}); err != nil {
		nodeLinkSet(false, err.Error())
		return "fail"
	}
	f, err := nc.recv(nodeHandshakeTO, nodeFirstMax)
	if err != nil {
		nodeLinkSet(false, "the central did not answer: "+err.Error())
		return "fail"
	}
	if f.T == "refused" && f.Reason != "unknown" {
		nodeLinkSet(false, "the central cannot take this node now: "+f.Reason)
		return "fail"
	}
	if f.T == "refused" {
		nodesMu.Lock()
		if cur, err := nodeSelfLoad(); err == nil && cur.Role == nodeRoleNode && cur.CentralKey == s.CentralKey && cur.JoinedAt == s.JoinedAt {
			cur.Refused = time.Now().UTC().Format(time.RFC3339)
			_ = nodeSelfSave(cur)
		}
		nodesMu.Unlock()
		return "refused"
	}
	if f.T != "welcome" {
		nodeLinkSet(false, "the central gave an unexpected answer")
		return "fail"
	}
	if s.Refused != "" {
		nodesMu.Lock()
		if cur, err := nodeSelfLoad(); err == nil && cur.Role == nodeRoleNode {
			cur.Refused = ""
			_ = nodeSelfSave(cur)
		}
		nodesMu.Unlock()
	}
	nodeLinkSet(true, "")
	defer nodeLinkSet(false, "")
	// leave: node.json gone or changed while connected
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		t := time.NewTicker(3 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				cur, err := nodeSelfLoad()
				if err == nil && cur.Role == "" {
					_ = nc.send(nodeFrame{T: "bye", Reason: "left"}) // left: the central drops it from its list
				}
				if err != nil || cur.Role != nodeRoleNode || cur.ID != s.ID || cur.CentralKey != s.CentralKey {
					_ = nc.c.Close()
					return
				}
			}
		}
	}()
	sem := make(chan struct{}, nodeReqParallel)
	for {
		fr, err := nc.recv(nodeIdleTO, nodeFrameMax)
		if err != nil {
			return "ok"
		}
		switch fr.T {
		case "bye":
			nodesMu.Lock()
			if cur, err := nodeSelfLoad(); err == nil && cur.Role == nodeRoleNode && cur.CentralKey == s.CentralKey {
				_ = nodeSelfClear()
			}
			nodesMu.Unlock()
			log.Printf("nodes: the central removed this node; it is standalone again (tunnels untouched)")
			return "bye"
		case "req":
			if fr.Method == "info" { // small and quick: never waits behind relayed calls
				body, err := nodeHandleReq(fr)
				nodeSendRes(nc, fr.ID, body, err)
				continue
			}
			select {
			case sem <- struct{}{}:
			default: // full: answer now, so this loop keeps reading
				nodeSendRes(nc, fr.ID, nil, fmt.Errorf("this node is busy with %d requests from the central: try again in a moment", nodeReqParallel))
				continue
			}
			go func(fr nodeFrame) {
				defer func() { <-sem }()
				body, err := nodeHandleReq(fr)
				nodeSendRes(nc, fr.ID, body, err)
			}(fr)
		}
	}
}

// nodeSendRes answers request id; a big answer goes in parts of nodePartMax
// ("part" frames, then a "res" with the last piece in Data).
func nodeSendRes(nc *nodeConn, id uint64, body json.RawMessage, err error) {
	if err != nil {
		_ = nc.send(nodeFrame{T: "res", ID: id, Err: err.Error()})
		return
	}
	if len(body) <= nodePartMax {
		_ = nc.send(nodeFrame{T: "res", ID: id, Body: body})
		return
	}
	for len(body) > nodePartMax {
		if nc.send(nodeFrame{T: "part", ID: id, Data: body[:nodePartMax]}) != nil {
			return
		}
		body = body[nodePartMax:]
	}
	_ = nc.send(nodeFrame{T: "res", ID: id, Data: body})
}

// nodeHandleReq answers one request from the central.
func nodeHandleReq(f nodeFrame) (json.RawMessage, error) {
	switch f.Method {
	case "info":
		return json.Marshal(nodeInfoFn())
	case "http":
		return nodeServeHTTP(f.Body)
	}
	return nil, fmt.Errorf("this node (%s) does not know %q: update it", panelVersion, f.Method)
}

// node CPU: its own sample, so it does not shorten the dashboard's.
var (
	nodeCPUMu   sync.Mutex
	nodeCPUPrev cpuSample
	nodeCPUHave bool
)

func nodeCPUPct() float64 {
	cur, ok := readCPU()
	if !ok {
		return -1
	}
	nodeCPUMu.Lock()
	defer nodeCPUMu.Unlock()
	prev, had := nodeCPUPrev, nodeCPUHave
	nodeCPUPrev, nodeCPUHave = cur, true
	if !had || cur.total <= prev.total {
		return -1
	}
	// signed: the idle counters (iowait) can go back a little
	dt, di := float64(cur.total-prev.total), float64(int64(cur.idle-prev.idle))
	return max(0, min(100, (dt-di)*100/dt))
}

func pctOf(v any) float64 {
	if s, ok := v.(string); ok {
		if f, err := strconv.ParseFloat(s, 64); err == nil {
			return f
		}
	}
	return -1
}

// nodeInfoClean caps what a node reports before the central keeps it.
func nodeInfoClean(i nodeInfo) nodeInfo {
	cut := func(s string, n int) string {
		if len(s) <= n {
			return s
		}
		r := []rune(s[:n])
		return string(r[:len(r)-1])
	}
	i.Version, i.Hostname, i.PublicIP, i.Side = cut(i.Version, 64), cut(i.Hostname, 128), cut(i.PublicIP, 64), cut(i.Side, 16)
	i.MachineHash, i.License.Customer, i.License.KeyHash = cut(i.MachineHash, 64), cut(i.License.Customer, 128), cut(i.License.KeyHash, 32)
	if len(i.License.Features) > 32 {
		i.License.Features = i.License.Features[:32]
	}
	for k, f := range i.License.Features {
		i.License.Features[k] = cut(f, 64)
	}
	return i
}

var nodeInfoFn = nodeLocalInfo // tests

// nodeLocalInfo is this panel's report to its central.
func nodeLocalInfo() nodeInfo {
	host, _ := os.Hostname()
	st := currentLocal()
	side := ""
	switch r := strings.ToLower(st.Role); {
	case strings.Contains(r, "iran") || r == "master":
		side = "iran"
	case strings.Contains(r, "foreign") || strings.Contains(r, "kharej"):
		side = "foreign"
	}
	mem := -1.0
	if m := memInfo(); m != nil {
		mem = pctOf(m["pct"])
	}
	info := nodeInfo{
		Proto: nodeProto, Version: panelVersion, Hostname: host, PublicIP: detectPublicIPCached(), Side: side,
		Tunnels: len(loadPeers()), CPUPct: nodeCPUPct(), MemPct: mem, DiskPct: pctOf(diskPct("/")),
		UptimeSec: int64(time.Since(panelStartedAt).Seconds()), MachineHash: getMachineHash(), At: time.Now().Unix(),
	}
	mu.Lock()
	key := cfg.LicenseKey
	mu.Unlock()
	activeLicenseMu.RLock()
	if l := activeLicense; l != nil {
		info.License = nodeLicense{Active: true, Customer: l.Customer, Expires: l.ExpiresAt,
			Locked: l.MachineHash != "" && l.MachineHash != "*", Features: append([]string(nil), l.Features...),
			KeyHash: nodeKeyHash(key)}
	}
	activeLicenseMu.RUnlock()
	info.License.Reported = true
	return info
}
