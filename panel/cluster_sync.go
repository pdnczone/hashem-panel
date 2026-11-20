package main

// Copying a linked hub's tunnels to this hub ("Sync tunnels").
//
// Two Iran hubs that serve the same foreign servers used to need three manual
// steps for every foreign server: add it on the second hub (Setup), copy the
// bundle, and paste it into "Join Another Iran Hub" on the foreign server.
// Now, when hub B is linked to hub A (or presses Sync Tunnels With This Hub),
// B does it, and the same button on either hub makes both hubs serve the same
// foreign servers: whatever the other hub has that this one lacks is copied
// here, and whatever this one has that the other lacks is copied there (this
// hub asks it to, POST /_hc/pull, and follows its progress). B does it:
//
//  1. B asks A, over the signed hub channel, which tunnels it has and which
//     pools (POST /_hc/tunnels). No token travels: only addresses, ports and
//     the engine.
//  2. For each foreign server B does not serve yet, B makes the tunnel the way
//     Setup does (add-peer, or its first tunnel), with the same ports.
//  3. B sends the bundle to A (POST /_hc/deliver). A passes it to the foreign
//     server over the tunnel's own Peer Link (POST /_hp/api/peer/join-hub),
//     which the foreign server only accepts with that tunnel's secret, and the
//     foreign server runs join-hub (cluster_join.go).
//  4. When step 3 fails, B removes the tunnel it made again.
//  5. Pools of A that B has no pool for are made on B, so the hubs can
//     forward a port to each other.
//
// Trust: the hubs already share the cluster secret that signs every
// heartbeat, and a join code is only given to your own servers. What changes
// is that a foreign server now accepts "also serve this Iran hub" from the
// hub it already has, and A only delivers a bundle that names the hub that
// asked.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	syncDeliverTO = 6 * time.Minute // join-hub downloads and starts a client on the foreign server
	syncListTO    = 15 * time.Second
	syncMaxTun    = 64
)

// syncTunnel is one tunnel of a hub as another hub needs it to make its own.
type syncTunnel struct {
	Name           string   `json:"name"`
	Remote         string   `json:"remote"` // the foreign server
	Engine         string   `json:"engine"` // frp | backhaul | gre-backhaul
	Transport      string   `json:"transport,omitempty"`
	FRPTransport   string   `json:"frp_transport,omitempty"`
	ProxyProtocol  string   `json:"proxy_protocol,omitempty"`
	UseEncryption  bool     `json:"use_encryption,omitempty"`
	UseCompression bool     `json:"use_compression,omitempty"`
	Ports          []int    `json:"ports"`
	RawPorts       []string `json:"raw_ports,omitempty"` // Backhaul: mappings and ranges as written
	LocalGre       string   `json:"local_gre,omitempty"`
	PeerGre        string   `json:"peer_gre,omitempty"`
}

type syncPool struct {
	Port       int    `json:"port"`
	Proto      string `json:"proto"`
	Mode       string `json:"mode"`
	Name       string `json:"name,omitempty"`
	Check      string `json:"check,omitempty"`
	CheckEvery int    `json:"check_every,omitempty"`
	NoFailback bool   `json:"no_failback,omitempty"`
}

type syncList struct {
	Tunnels []syncTunnel `json:"tunnels"`
	Pools   []syncPool   `json:"pools"`
	Version string       `json:"version"`
}

// syncLocalTunnels lists this hub's tunnels (a var so tests can set them).
var syncLocalTunnels = func() []syncTunnel {
	s := lbSnapshot()
	if s == nil {
		return nil
	}
	var out []syncTunnel
	for _, l := range s.All() {
		if l.RemotePub == "" {
			continue
		}
		engine := l.Engine
		if engine == "" {
			engine = "frp"
		}
		if len(l.Ports) == 0 && engine == "frp" {
			// The first FRP tunnel's ports are written on the foreign server
			// (its frpc.toml), not here: read what its frps serves.
			svc := l.FrpsSvc
			if l.ID == mainTunnelID && svc == "" {
				svc = s.Local.FrpSvc
			}
			l.Ports = syncFrpsServed(svc)
		}
		t := syncTunnel{Name: l.Name, Remote: l.RemotePub, Engine: engine, Transport: l.Transport,
			FRPTransport: l.FRPTransport, ProxyProtocol: l.ProxyProtocol, UseEncryption: l.UseEncryption,
			UseCompression: l.UseCompression, Ports: append([]int(nil), l.Ports...), RawPorts: []string(l.RawPorts),
			LocalGre: l.LocalGre, PeerGre: l.PeerGre}
		if t.PeerGre == "" && l.GreInner != "" { // the first tunnel has no peer record: its GRE address is in its status
			t.LocalGre, t.PeerGre = strings.SplitN(l.GreInner, "/", 2)[0], grePeerInner(l.GreInner)
		}
		out = append(out, t)
		if len(out) >= syncMaxTun {
			break
		}
	}
	return out
}

// syncFrpsServed is the user ports the FRP server unit svc listens on: every
// port its process holds but the ones its own config names (bindPort,
// kcpBindPort, quicBindPort, the dashboard). A port appears only while the
// foreign server is connected. A var for tests.
var syncFrpsServed = func(svc string) []int {
	path, engine := lbConfFor(svc)
	if engine != "frp" {
		return nil
	}
	out, err := runCmdTimeoutOut(5*time.Second, "systemctl", "show", "-p", "MainPID", "--value", svc)
	pid, _ := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil || pid <= 0 {
		return nil
	}
	own := map[int]bool{}
	if data, err := os.ReadFile(path); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			k, v, ok := strings.Cut(line, "=")
			if ok && strings.Contains(strings.ToLower(k), "port") {
				if p, err := strconv.Atoi(strings.Trim(strings.TrimSpace(v), `"'`)); err == nil {
					own[p] = true
				}
			}
		}
	}
	return frpsServedPorts(xrayListeners(), pid, own)
}

// frpsServedTTL is how long the snapshot reuses syncFrpsServed's answer.
// The ports change only when the foreign server's frpc.toml changes, and the
// listener scan (ss -p) walks every process, too much for each 5 s tick.
const frpsServedTTL = 30 * time.Second

var frpsServedCache struct {
	sync.Mutex
	svc   string
	at    time.Time
	ports []int
}

// frpsServedCached is syncFrpsServed for svc, read at most once per
// frpsServedTTL. The snapshot uses it for an Iran server's first FRP tunnel,
// whose ports are written in the foreign frpc.toml, not here.
func frpsServedCached(svc string, now time.Time) []int {
	c := &frpsServedCache
	c.Lock()
	defer c.Unlock()
	if c.svc != svc || c.at.IsZero() || now.Sub(c.at) >= frpsServedTTL || now.Before(c.at) {
		c.svc, c.at, c.ports = svc, now, syncFrpsServed(svc)
	}
	return slices.Clone(c.ports)
}

// frpsServedPorts picks the ports process pid listens on, without own.
func frpsServedPorts(ls []xrayListener, pid int, own map[int]bool) []int {
	var ports []int
	for _, l := range ls {
		if l.PID == pid && !own[l.Port] && !hasInt(ports, l.Port) {
			ports = append(ports, l.Port)
		}
	}
	sort.Ints(ports)
	return ports
}

func syncLocalList() syncList {
	l := syncList{Tunnels: syncLocalTunnels(), Version: panelVersion}
	for _, p := range loadClusterConfig().Pools {
		if p.Disabled {
			continue
		}
		l.Pools = append(l.Pools, syncPool{Port: p.Port, Proto: p.Proto, Mode: p.Mode, Name: p.Name,
			Check: p.Check, CheckEvery: p.CheckEvery, NoFailback: p.NoFailback})
	}
	if l.Tunnels == nil {
		l.Tunnels = []syncTunnel{}
	}
	return l
}

// ---- the bundle on the hub channel ----

// The hub channel is plain HTTP, signed but not secret, and a bundle holds the
// tunnel's token. So the bundle is sealed with the cluster secret (AES-GCM)
// before it crosses the channel: a listener between the two Iran servers sees
// nothing it could dial with.

func syncSealKey(secret string) []byte {
	k := sha256.Sum256([]byte("hashem-hub-bundle-v1\n" + secret))
	return k[:]
}

func syncSeal(secret, plain string) (string, error) {
	b, err := aes.NewCipher(syncSealKey(secret))
	if err != nil {
		return "", err
	}
	g, err := cipher.NewGCM(b)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(g.Seal(nonce, nonce, []byte(plain), nil)), nil
}

func syncOpen(secret, sealed string) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(sealed)
	if err != nil {
		return "", errors.New("the bundle is not sealed")
	}
	b, err := aes.NewCipher(syncSealKey(secret))
	if err != nil {
		return "", err
	}
	g, err := cipher.NewGCM(b)
	if err != nil {
		return "", err
	}
	if len(raw) < g.NonceSize() {
		return "", errors.New("the bundle is not sealed")
	}
	plain, err := g.Open(nil, raw[:g.NonceSize()], raw[g.NonceSize():], nil)
	if err != nil {
		return "", errors.New("the bundle cannot be opened (different cluster secret)")
	}
	return string(plain), nil
}

// ---- the answering hub ----

// meshAuthed reads and verifies a signed request of another hub of this
// cluster. It answers a bare 404 (like every other hub route) otherwise.
func meshAuthed(w http.ResponseWriter, r *http.Request, limit int64) (ClusterConfig, HubPeer, []byte, bool) {
	c := loadClusterConfig()
	body, err := io.ReadAll(io.LimitReader(r.Body, limit))
	if err != nil || c.Secret == "" || meshVerify(c.Secret, r.Header, body, time.Now()) != nil {
		http.NotFound(w, r)
		return c, HubPeer{}, nil, false
	}
	var who struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(body, &who) != nil || who.ID == "" || who.ID == c.NodeID {
		http.NotFound(w, r)
		return c, HubPeer{}, nil, false
	}
	for _, h := range c.Hubs {
		if h.ID == who.ID {
			return c, h, body, true
		}
	}
	http.NotFound(w, r) // a hub this one does not know (it was unlinked)
	return c, HubPeer{}, nil, false
}

func meshAnswer(w http.ResponseWriter, secret string, v any) {
	data, _ := json.Marshal(v)
	meshSetSig(w.Header(), secret, data)
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(data)
}

// POST /_hc/tunnels: this hub's tunnels and pools.
func handleMeshTunnels(w http.ResponseWriter, r *http.Request) {
	c, _, _, ok := meshAuthed(w, r, 1<<12)
	if !ok {
		return
	}
	meshAnswer(w, c.Secret, syncLocalList())
}

type syncDeliverReq struct {
	ID     string `json:"id"` // the asking hub
	Remote string `json:"remote"`
	Bundle string `json:"bundle"` // sealed with the cluster secret (syncSeal)
	Name   string `json:"name"`
}

type syncDeliverAns struct {
	OK     bool   `json:"ok"`
	Status string `json:"status,omitempty"` // ok | already
	Error  string `json:"error,omitempty"`
}

// syncPeerCall sends the bundle to a foreign server over the tunnel's Peer
// Link (a var so tests need no real foreign server).
var syncPeerCall = func(tunnelID int, payload map[string]string) ([]byte, error) {
	t, err := resolveSwapTunnel(tunnelID)
	if err != nil {
		return nil, err
	}
	return tunnelPeerCall(t, http.MethodPost, "/api/peer/join-hub", payload, syncDeliverTO)
}

// syncTunnelFor finds this hub's tunnel to the foreign server remote: its id
// and what it forwards.
func syncTunnelFor(remote string) (int, syncTunnel, bool) {
	var have syncTunnel
	for _, t := range syncLocalTunnels() {
		if t.Remote == remote {
			have = t
		}
	}
	if have.Remote == "" {
		return 0, have, false
	}
	for _, p := range loadPeers() {
		if p.RemotePub == remote {
			return p.ID, have, true
		}
	}
	if st := localStatus(); st.RemotePub != "" && CleanHost(st.RemotePub) == remote {
		return 0, have, true
	}
	return 0, have, false
}

// syncBundleCheck: the bundle exposes what the tunnel it is for forwards and
// nothing else, with the same engine. Without it a linked hub could send a
// bundle that publishes other ports of the foreign server (its panel, SSH, a
// database) to that hub.
func syncBundleCheck(b setupBundle, have syncTunnel) error {
	engine, want := b.Engine, have.Engine
	if engine == "" {
		engine = "frp"
	}
	if want == "" {
		want = "frp"
	}
	if engine != want {
		return fmt.Errorf("the bundle is %s, this hub's tunnel is %s", engine, want)
	}
	got := append([]int{}, b.Ports...)
	exp := append([]int{}, have.Ports...)
	slices.Sort(got)
	slices.Sort(exp)
	if !slices.Equal(slices.Compact(got), slices.Compact(exp)) {
		return errors.New("the bundle forwards other ports than this hub's tunnel to that server")
	}
	return nil
}

// POST /_hc/deliver: hand a bundle to the foreign server of one of this hub's
// tunnels, so that it also serves the hub that sent it.
func handleMeshDeliver(w http.ResponseWriter, r *http.Request) {
	c, from, body, ok := meshAuthed(w, r, 1<<15)
	if !ok {
		return
	}
	var req syncDeliverReq
	ans := syncDeliverAns{}
	fail := func(msg string) {
		ans.Error = msg
		meshAnswer(w, c.Secret, ans)
	}
	if json.Unmarshal(body, &req) != nil || req.Remote == "" || req.Bundle == "" {
		fail("bad request")
		return
	}
	bundle, err := syncOpen(c.Secret, req.Bundle)
	if err != nil {
		fail(err.Error())
		return
	}
	bundle = strings.TrimSpace(bundle)
	b, err := ParseBundle(bundle)
	if err != nil {
		fail("the bundle cannot be read: " + err.Error())
		return
	}
	// only a bundle that names the hub that asked: a hub cannot use this one
	// to send a foreign server to a third address
	if from.PublicIP == "" || b.IranPub != from.PublicIP {
		fail("the bundle names " + b.IranPub + ", which is not the hub that asked")
		return
	}
	id, have, found := syncTunnelFor(req.Remote)
	if !found {
		fail("this hub has no tunnel to " + req.Remote)
		return
	}
	if err := syncBundleCheck(b, have); err != nil {
		fail(err.Error())
		return
	}
	name := strings.TrimSpace(req.Name)
	if len(name) > 32 || strings.ContainsAny(name, "\"'`$\\\n") {
		name = ""
	}
	data, err := syncPeerCall(id, map[string]string{"bundle": bundle, "name": name})
	if err != nil {
		msg := err.Error()
		if strings.Contains(msg, "HTTP 404") {
			msg = "the foreign server " + req.Remote + " does not know this request: " + syncUpdateAdvice() + ", then try again"
		}
		fail(msg)
		return
	}
	var res struct {
		Status string `json:"status"`
	}
	_ = json.Unmarshal(data, &res)
	ans.OK, ans.Status = true, res.Status
	clusterEventf("info", "Iran hub %s asked %s to serve it too.", hubLabel(from), req.Remote)
	meshAnswer(w, c.Secret, ans)
}

// ---- the foreign server ----

// POST /_hp/api/peer/join-hub: the same as Cluster → Join Another Iran Hub,
// sent by a hub this server already serves (a Peer Link request). A hub it
// already serves is answered with "already" and nothing is changed.
func handlePeerJoinHub(w http.ResponseWriter, r *http.Request) {
	if proRequired(w, r, "cluster", "Cluster") {
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<13))
	if err != nil {
		writeAPIError(w, r, "E-CLUSTER-01", "")
		return
	}
	var req struct {
		Bundle string `json:"bundle"`
	}
	if json.Unmarshal(data, &req) != nil {
		writeAPIError(w, r, "E-CLUSTER-01", "")
		return
	}
	if b, err := ParseBundle(strings.TrimSpace(req.Bundle)); err == nil {
		for _, h := range joinedHubsView() {
			if h.IranPub == b.IranPub {
				writeJSON(w, map[string]any{"status": "already"})
				return
			}
		}
	}
	r.Body = io.NopCloser(bytes.NewReader(data))
	handleClusterJoinHub(w, r)
}

// ---- the asking hub ----

// syncUpdateAdvice says how to bring another server to this hub's version. A
// plain "hashem update" would be wrong while this hub runs a dev build: the
// stable channel is older and has no hub channel at all.
func syncUpdateAdvice() string {
	if strings.Contains(panelVersion, "dev") {
		return "update it to this hub's version " + panelVersion + " (hashem update-channel dev, then hashem update)"
	}
	return "update it to this hub's version " + panelVersion + " (hashem update)"
}

// meshCall sends a signed request to another hub and decodes its signed answer.
func meshCall(h HubPeer, secret, path string, in, out any, timeout time.Duration) error {
	body, _ := json.Marshal(in)
	req, err := http.NewRequest("POST", strings.TrimRight(h.URL, "/")+meshRoutePrefix+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	meshSetSig(req.Header, secret, body)
	resp, err := (&http.Client{Timeout: timeout}).Do(req)
	if err != nil {
		return fmt.Errorf("unreachable: %s", shortNetErr(err))
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return errors.New("the other hub did not accept the request: " + syncUpdateAdvice() + ", or the hubs are not linked both ways")
	case resp.StatusCode != http.StatusOK:
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if err := meshVerify(secret, resp.Header, data, time.Now()); err != nil {
		return fmt.Errorf("answer not trusted: %v", err)
	}
	return json.Unmarshal(data, out)
}

// syncStep is what happened to one foreign server.
type syncStep struct {
	Name   string `json:"name"`
	Remote string `json:"remote"`
	State  string `json:"state"` // done | skipped | failed
	Detail string `json:"detail,omitempty"`
}

type syncState struct {
	Running  bool       `json:"running"`
	Both     bool       `json:"both,omitempty"` // this hub also asks the other one to copy from it
	Hub      string     `json:"hub,omitempty"`
	HubName  string     `json:"hub_name,omitempty"`
	Started  int64      `json:"started,omitempty"`
	Ended    int64      `json:"ended,omitempty"`
	Error    string     `json:"error,omitempty"`
	Info     string     `json:"info,omitempty"`
	Steps    []syncStep `json:"steps"`           // tunnels made on this hub
	Other    []syncStep `json:"other,omitempty"` // tunnels the other hub made from this one
	OtherErr string     `json:"other_error,omitempty"`
	Pools    []int      `json:"pools,omitempty"` // pools made here
}

var syncJob struct {
	sync.Mutex
	s syncState
}

func syncSnapshot() syncState {
	syncJob.Lock()
	defer syncJob.Unlock()
	s := syncJob.s
	s.Steps = append([]syncStep{}, s.Steps...)
	s.Other = append([]syncStep(nil), s.Other...)
	return s
}

func syncUpdate(fn func(s *syncState)) {
	syncJob.Lock()
	defer syncJob.Unlock()
	fn(&syncJob.s)
}

// hubLabel names a hub for a person: two hubs can have the same host name.
func hubLabel(h HubPeer) string {
	n := strings.TrimSpace(h.Name)
	switch {
	case n == "" && h.PublicIP == "":
		return h.ID
	case h.PublicIP == "" || strings.Contains(n, h.PublicIP):
		return n
	case n == "":
		return h.PublicIP
	}
	return n + " (" + h.PublicIP + ")"
}

// startHubSync starts the copy with hub id, in the background. With both it
// also asks that hub to copy what this one has and it lacks. It refuses while
// a copy is running.
func startHubSync(id string, both bool) error {
	c := loadClusterConfig()
	var hub HubPeer
	for _, h := range c.Hubs {
		if h.ID == id {
			hub = h
		}
	}
	if hub.ID == "" {
		return fmt.Errorf("no hub with id %s", id)
	}
	syncJob.Lock()
	if syncJob.s.Running {
		syncJob.Unlock()
		return errors.New("a copy of tunnels is already running here: wait for it to end")
	}
	syncJob.s = syncState{Running: true, Both: both, Hub: hub.ID, HubName: hubLabel(hub), Started: time.Now().Unix(), Steps: []syncStep{}}
	syncJob.Unlock()
	go func() {
		err := runHubSync(c, hub, both)
		syncUpdate(func(s *syncState) {
			s.Running = false
			s.Ended = time.Now().Unix()
			if err != nil {
				s.Error = err.Error()
			}
		})
	}()
	return nil
}

// syncPlan is this server's plan for a new tunnel (a var for tests).
var syncPlan = buildSetupPlan

// syncSetup makes one tunnel the way Setup does (a var for tests). It returns
// the bundle and the new tunnel's id.
var syncSetup = func(body setupRequest) (bundle string, id int, err error) {
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/setup", bytes.NewReader(raw))
	rec := httptest.NewRecorder()
	handleSetupPost(rec, req)
	var res struct {
		Bundle string `json:"bundle"`
		Error  string `json:"error"`
		Hint   string `json:"hint"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &res)
	if rec.Code != http.StatusOK || res.Bundle == "" {
		msg := res.Error
		if msg == "" {
			msg = strings.TrimSpace(rec.Body.String())
		}
		if res.Hint != "" {
			msg += " (" + res.Hint + ")"
		}
		return "", 0, errors.New(msg)
	}
	if body.Role == "iran" {
		return res.Bundle, 0, nil
	}
	for _, p := range loadPeers() {
		if p.RemotePub == body.RemotePub && p.ID > id {
			id = p.ID
		}
	}
	return res.Bundle, id, nil
}

// syncRemove removes a tunnel again (a var for tests).
var syncRemove = func(id int) error {
	_, err := runAction("remove-tunnel", id)
	return err
}

// syncGrePair picks the first inner address pair that neither this hub, the
// other hub's tunnel nor the foreign server uses.
func syncGrePair(used []string, avoid ...string) (string, string) {
	taken := map[string]bool{}
	for _, a := range append(append([]string{}, used...), avoid...) {
		if a != "" {
			taken[a] = true
		}
	}
	pairs := [][2]string{{defaultIranGRE, defaultForeignGRE}}
	for k := 1; k <= 89; k++ {
		pairs = append(pairs, [2]string{fmt.Sprintf("10.1%d.0.2", k), fmt.Sprintf("10.1%d.0.1", k)})
	}
	for _, p := range pairs {
		if !taken[p[0]] && !taken[p[1]] {
			return p[0], p[1]
		}
	}
	return "", ""
}

func syncPortsText(t syncTunnel) string {
	if t.Engine != "frp" && len(t.RawPorts) > 0 {
		return strings.Join(t.RawPorts, ", ")
	}
	var s []string
	for _, p := range t.Ports {
		s = append(s, strconv.Itoa(p))
	}
	return strings.Join(s, ", ")
}

func syncName(t syncTunnel) string {
	n := strings.TrimSpace(t.Name)
	if n == "" || strings.HasPrefix(n, "Tunnel \u00b7") || validLinkName(n) != nil { // the first tunnel is called "Tunnel · IP"
		n = t.Remote
	}
	return n
}

// syncKnownRemotes is every foreign server this hub already has a tunnel to.
func syncKnownRemotes() map[string]bool {
	known := map[string]bool{}
	for _, p := range loadPeers() {
		known[p.RemotePub] = true
	}
	if st := localStatus(); st.RemotePub != "" {
		known[CleanHost(st.RemotePub)] = true
	}
	return known
}

func runHubSync(c ClusterConfig, hub HubPeer, both bool) error {
	var list syncList
	if err := meshCall(hub, c.Secret, "/tunnels", map[string]string{"id": c.NodeID}, &list, syncListTO); err != nil {
		return fmt.Errorf("cannot read the tunnels of %s: %v", hubLabel(hub), err)
	}
	mine := syncLocalTunnels()
	if len(list.Tunnels) == 0 && (!both || len(mine) == 0) {
		if both {
			return errors.New("neither hub has a tunnel yet: add a foreign server in Setup on one of them first")
		}
		return fmt.Errorf("%s has no tunnel to copy", hubLabel(hub))
	}
	known := syncKnownRemotes()
	step := func(t syncTunnel, state, detail string) {
		syncUpdate(func(s *syncState) {
			s.Steps = append(s.Steps, syncStep{Name: syncName(t), Remote: t.Remote, State: state, Detail: detail})
		})
	}
	for _, t := range list.Tunnels {
		if known[t.Remote] {
			step(t, "skipped", "this hub already has a tunnel to it")
			continue
		}
		if len(t.Ports) == 0 && len(t.RawPorts) == 0 {
			step(t, "failed", hubLabel(hub)+" does not know the ports of this tunnel right now: is the foreign server connected to it? Press the button again when it is")
			continue
		}
		if detail, err := syncOne(c, hub, t); err != nil {
			step(t, "failed", err.Error())
		} else {
			known[t.Remote] = true
			step(t, "done", detail)
		}
	}
	made := syncMirrorPools(list.Pools)
	syncUpdate(func(s *syncState) { s.Pools = made })

	// the other way: what this hub has and the other lacks is copied there
	theirs := map[string]bool{}
	for _, t := range list.Tunnels {
		theirs[t.Remote] = true
	}
	lacking := 0
	for _, t := range mine {
		if !theirs[t.Remote] {
			lacking++
		}
	}
	if both && lacking > 0 {
		syncAskPull(c, hub, list.Version)
	}

	snap := syncSnapshot()
	nHere, nThere := 0, 0
	for _, x := range snap.Steps {
		if x.State == "done" {
			nHere++
		}
	}
	for _, x := range snap.Other {
		if x.State == "done" {
			nThere++
		}
	}
	if nHere == 0 && nThere == 0 && snap.OtherErr == "" && len(made) == 0 {
		failed := false
		for _, x := range append(snap.Steps, snap.Other...) {
			failed = failed || x.State == "failed"
		}
		if !failed {
			syncUpdate(func(s *syncState) { s.Info = "Both hubs already serve the same foreign servers: nothing to copy." })
		}
	}
	if nHere == 0 && nThere == 0 && len(made) == 0 && snap.OtherErr != "" {
		// nothing was made on either side: that is a failure, not a quiet success
		return errors.New(snap.OtherErr)
	}
	clusterEventf("info", "Synced tunnels with Iran hub %s: %d made here, %d made there, %d pool(s).", hubLabel(hub), nHere, nThere, len(made))
	return nil
}

type syncPullAns struct {
	OK      bool   `json:"ok"`
	Error   string `json:"error,omitempty"`
	Started int64  `json:"started,omitempty"`
}

// syncPullWait is how long this hub follows the other hub's copy.
var syncPullWait = 30 * time.Minute

// syncAskPull asks the other hub to copy this hub's tunnels, and follows its
// progress into this job's "other" list.
func syncAskPull(c ClusterConfig, hub HubPeer, theirVersion string) {
	fail := func(msg string) { syncUpdate(func(s *syncState) { s.OtherErr = msg }) }
	var ans syncPullAns
	if err := meshCall(hub, c.Secret, "/pull", map[string]string{"id": c.NodeID}, &ans, syncListTO); err != nil {
		ver := ""
		if theirVersion != "" {
			ver = " (it runs " + theirVersion + ", this hub " + panelVersion + ")"
		}
		fail("could not ask " + hubLabel(hub) + ver + " to copy the tunnels of this hub: " + err.Error() + ". Then press the button again.")
		return
	}
	if !ans.OK {
		fail(hubLabel(hub) + " did not start: " + ans.Error)
		return
	}
	deadline := time.Now().Add(syncPullWait)
	misses := 0
	var lost time.Time // since when the peer shows another copy than the asked one
	for time.Now().Before(deadline) {
		time.Sleep(syncPollEvery)
		var st syncState
		if err := meshCall(hub, c.Secret, "/syncstate", map[string]string{"id": c.NodeID}, &st, syncListTO); err != nil {
			if misses++; misses > 5 {
				fail("lost contact with " + hubLabel(hub) + " while it copied: " + err.Error())
				return
			}
			continue
		}
		misses = 0
		if st.Started != ans.Started || st.Hub != c.NodeID {
			// not the copy this hub asked for (yet), or the peer restarted and forgot it
			if lost.IsZero() {
				lost = time.Now()
			} else if time.Since(lost) > syncLostWait {
				fail(hubLabel(hub) + " no longer shows the copy it started (its panel may have restarted): look at its Cluster tab")
				return
			}
			continue
		}
		lost = time.Time{}
		syncUpdate(func(s *syncState) { s.Other = st.Steps })
		if !st.Running {
			if st.Error != "" {
				fail(hubLabel(hub) + ": " + st.Error)
			}
			return
		}
	}
	fail(hubLabel(hub) + " is still copying: look at its Cluster tab")
}

// syncLostWait is how long the other hub may show another copy than the one it
// was asked for before this hub stops waiting (a var for tests).
var syncLostWait = 90 * time.Second

// syncPollEvery is how often a hub looks at the other hub's copy (a var for tests).
var syncPollEvery = 3 * time.Second

// POST /_hc/pull: the asking hub wants this hub to copy the asking hub's
// tunnels (the same as pressing the button here, one way).
func handleMeshPull(w http.ResponseWriter, r *http.Request) {
	c, from, _, ok := meshAuthed(w, r, 1<<12)
	if !ok {
		return
	}
	ans := syncPullAns{}
	if err := startHubSync(from.ID, false); err != nil {
		ans.Error = err.Error()
	} else {
		ans.OK, ans.Started = true, syncSnapshot().Started
		clusterEventf("info", "Iran hub %s asked this hub to copy its tunnels.", hubLabel(from))
	}
	meshAnswer(w, c.Secret, ans)
}

// POST /_hc/syncstate: how this hub's copy is going.
func handleMeshSyncState(w http.ResponseWriter, r *http.Request) {
	c, _, _, ok := meshAuthed(w, r, 1<<12)
	if !ok {
		return
	}
	meshAnswer(w, c.Secret, syncSnapshot())
}

// syncOne makes this hub's tunnel to one foreign server and has the foreign
// server join this hub. It leaves nothing behind when it fails.
func syncOne(c ClusterConfig, hub HubPeer, t syncTunnel) (string, error) {
	if t.Remote == "" || len(t.Ports) == 0 {
		return "", errors.New("the other hub's tunnel has no address or ports")
	}
	plan := syncPlan(syncPortsText(t), 0)
	if plan.Public == "" {
		return "", errors.New("this server's public address is not known")
	}
	if plan.RelayPort == 0 {
		return "", errors.New("no free control port on this server")
	}
	body := setupRequest{Role: "add-peer", Engine: t.Engine, Transport: t.Transport, Name: syncName(t),
		LocalPub: plan.Public, RemotePub: t.Remote, FrpPort: plan.RelayPort, Ports: syncPortsText(t), Autogen: true,
		PoolOnClash: true, ProxyProtocol: t.ProxyProtocol, UseEncryption: t.UseEncryption, UseCompression: t.UseCompression}
	if t.Engine == "frp" {
		body.Engine = ""
		body.FRPTransport = t.FRPTransport
		body.Transport = ""
	}
	if !plan.Exists && len(plan.Peers) == 0 {
		body.Role = "iran" // a hub with no tunnel yet: this is its first
	}
	if t.Engine != "backhaul" {
		body.LocalGre, body.PeerGre = syncGrePair(plan.GreUsed, t.LocalGre, t.PeerGre)
		if body.LocalGre == "" {
			return "", errors.New("no free GRE address pair")
		}
	}
	had := false
	for _, p := range loadPeers() {
		had = had || p.RemotePub == t.Remote
	}
	bundle, id, err := syncSetup(body)
	if err != nil {
		// the installer may have made the tunnel before it failed: remove what
		// this copy added (a tunnel to this foreign server that was not there)
		if body.Role == "add-peer" && !had {
			for _, p := range loadPeers() {
				if p.RemotePub == t.Remote {
					if rerr := syncRemove(p.ID); rerr != nil {
						return "", fmt.Errorf("could not make the tunnel here: %v; removing what was made failed too (%v): check the Tunnel tab", err, rerr)
					}
				}
			}
		}
		return "", fmt.Errorf("could not make the tunnel here: %v", err)
	}
	var ans syncDeliverAns
	sealed, derr := syncSeal(c.Secret, bundle)
	if derr == nil {
		derr = meshCall(hub, c.Secret, "/deliver", syncDeliverReq{ID: c.NodeID, Remote: t.Remote, Bundle: sealed, Name: hubShortName(c)}, &ans, syncDeliverTO+10*time.Second)
	}
	if derr == nil && !ans.OK {
		derr = errors.New(ans.Error)
	}
	if derr == nil && ans.Status == "already" {
		// The foreign server already serves an Iran hub with this address, from an
		// older join: it would keep dialing that one, never the tunnel just made
		// here (a new token). Remove this tunnel and leave the old join alone.
		derr = errors.New("the foreign server already serves a hub at this address from an earlier join: remove that one first (hashem leave-hub on the foreign server)")
	}
	if derr != nil {
		if rerr := syncRemove(id); rerr != nil {
			return "", fmt.Errorf("the foreign server did not join (%v); removing the tunnel here failed too (%v): remove it in the Tunnel tab", derr, rerr)
		}
		return "", fmt.Errorf("the foreign server did not join (%v); the tunnel made here was removed again", derr)
	}
	return "tunnel made, foreign server joined", nil
}

func hubShortName(c ClusterConfig) string {
	n := strings.TrimSpace(c.Name)
	if n == "" || len(n) > 32 || strings.ContainsAny(n, "\"'`$\\\n") {
		return "hub"
	}
	return n
}

// syncMirrorPools makes the pools of the other hub that this hub has none for,
// when one of its tunnels has the port. The members join by themselves
// (lbAutoJoin). It returns the ports of the pools made.
func syncMirrorPools(want []syncPool) []int {
	var made []int
	links := map[int]bool{}
	for _, p := range loadPeers() {
		for _, port := range p.Ports {
			links[port] = true
		}
	}
	if st := localStatus(); len(st.Ports) > 0 {
		for _, port := range st.Ports {
			links[port] = true
		}
	}
	_, _ = updateClusterConfig(func(c *ClusterConfig) error {
		for _, sp := range want {
			if !links[sp.Port] || !lbProtoOK(sp.Proto) || !lbModeOK(sp.Mode) {
				continue
			}
			p := LBPool{Port: sp.Port, Proto: sp.Proto, Mode: sp.Mode, Name: sp.Name, Check: sp.Check,
				CheckEvery: sp.CheckEvery, NoFailback: sp.NoFailback}
			if code, _ := validatePool(*c, p, -1); code != "" {
				continue // a pool or something else already holds the port here
			}
			c.Pools = append(c.Pools, p)
			made = append(made, p.Port)
			clusterEventf("info", "%s created (mode %s): copied from a linked hub.", poolLabel(p), p.Mode)
		}
		sort.Slice(c.Pools, func(i, j int) bool { return c.Pools[i].Port < c.Pools[j].Port })
		return nil
	})
	slices.Sort(made)
	return made
}

// ---- the panel's API ----

// POST /api/cluster/hubs/sync {id}: make this hub and a linked hub serve the
// same foreign servers.
func handleClusterHubSync(w http.ResponseWriter, r *http.Request) {
	if proRequired(w, r, "cluster", "Cluster") {
		return
	}
	var req struct {
		ID     string `json:"id"`
		OneWay bool   `json:"one_way"` // only copy here: do not ask the other hub to copy from this one
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req) != nil || req.ID == "" {
		writeAPIError(w, r, "E-CLUSTER-01", "id of a linked hub")
		return
	}
	if err := startHubSync(req.ID, !req.OneWay); err != nil {
		writeAPIError(w, r, "E-CLUSTER-05", err.Error())
		return
	}
	writeJSON(w, map[string]any{"status": "started"})
}

// GET /api/cluster/hubs/sync: how the copy is going.
func handleClusterHubSyncStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, syncSnapshot())
}
