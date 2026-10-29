package main

// Cluster: redundancy across several servers.
//
//   - Pools (cluster_lb.go): one public port on this Iran hub served by several
//     foreign servers, with failover, weighted balance, per-user stickiness,
//     lowest latency or least connections; a one-second health check per
//     link, an optional service check through each member, standby members
//     and connection limits.
//   - Hubs (cluster_mesh.go): other Iran hubs this one trusts. They exchange
//     signed heartbeats; when every member of a pool here is down, the port is
//     forwarded to a hub where the same pool is healthy.
//   - DNS failover (cluster_dns.go): a domain whose A records list the healthy
//     hubs, so users move to a working Iran server when one dies.
//
// A foreign server can join several hubs (hashem join-hub), which gives the
// many-Iran-to-one-foreign shape; pools give one-Iran-to-many-foreign; both
// together give a full mesh.

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ClusterConfig is /etc/gre-panel/cluster.json (version 2).
type ClusterConfig struct {
	Version    int       `json:"version"`
	Pools      []LBPool  `json:"pools"`
	Health     LBHealth  `json:"health"`
	NodeID     string    `json:"node_id"`
	Name       string    `json:"name,omitempty"`
	Secret     string    `json:"secret,omitempty"`
	PublicIP   string    `json:"public_ip,omitempty"`
	Hubs       []HubPeer `json:"hubs"`
	HubForward bool      `json:"hub_forward"`
	DNS        DNSConfig `json:"dns"`
	Updated    string    `json:"updated,omitempty"`
}

// LBPool is one public port served by several links.
type LBPool struct {
	Port     int        `json:"port"`
	Proto    string     `json:"proto"` // tcp | udp | both
	Name     string     `json:"name,omitempty"`
	Mode     string     `json:"mode"` // failover | balance | sticky | latency | least
	Disabled bool       `json:"disabled,omitempty"`
	Members  []LBMember `json:"members"`
	// Check "tcp": every CheckEvery seconds a connection is opened through
	// each member's relay to the service on the foreign server; a member
	// whose service refuses or drops it at once is taken out.
	Check      string `json:"check,omitempty"`
	CheckEvery int    `json:"check_every,omitempty"`
	// NoFailback (failover mode): traffic stays on the member it moved to
	// while that one works. Bumping Failback moves it back now.
	NoFailback bool `json:"no_failback,omitempty"`
	Failback   int  `json:"failback,omitempty"`
	// Excluded links were removed by hand: they are not joined back
	// automatically even though their ports include this one.
	Excluded []int `json:"excluded,omitempty"`
}

// LBMember is one link (tunnel to a foreign server) in a pool.
type LBMember struct {
	Link     int    `json:"link"`             // 0 = main tunnel, N = peer N
	Remote   string `json:"remote,omitempty"` // foreign IP when added; a reused peer id shows up
	Port     int    `json:"port,omitempty"`   // the link's port for this service (default: the pool port)
	Weight   int    `json:"weight"`
	Priority int    `json:"priority"`
	Drain    bool   `json:"drain,omitempty"`
	// Backup (standby): new connections only when no primary member is
	// healthy and has room.
	Backup bool `json:"backup,omitempty"`
	// MaxConn: open connections at which it takes no new ones (0 = no limit).
	MaxConn int `json:"max_conn,omitempty"`
}

// lbCheckEvery is the pool's service check interval.
func lbCheckEvery(p LBPool) time.Duration {
	if p.CheckEvery < 1 || p.CheckEvery > 60 {
		return 3 * time.Second
	}
	return time.Duration(p.CheckEvery) * time.Second
}

// LBHealth tunes the per-link health check.
type LBHealth struct {
	IntervalMs int `json:"interval_ms"`
	Fall       int `json:"fall"` // failed checks in a row before a link is taken out
	Rise       int `json:"rise"` // good checks in a row before it is put back
}

func (h LBHealth) norm() LBHealth {
	if h.IntervalMs < 500 || h.IntervalMs > 10000 {
		h.IntervalMs = 1000
	}
	if h.Fall < 1 || h.Fall > 30 {
		h.Fall = 3
	}
	if h.Rise < 1 || h.Rise > 60 {
		h.Rise = 3
	}
	return h
}

func (p LBPool) key() string { return p.Proto + "/" + strconv.Itoa(p.Port) }

// overlaps reports whether two pools claim the same port and protocol.
func (p LBPool) overlaps(q LBPool) bool {
	if p.Port != q.Port {
		return false
	}
	return p.Proto == q.Proto || p.Proto == "both" || q.Proto == "both"
}

func (p *LBPool) member(link int) *LBMember {
	for i := range p.Members {
		if p.Members[i].Link == link {
			return &p.Members[i]
		}
	}
	return nil
}

var (
	clusterMu    sync.Mutex
	clusterCache *ClusterConfig
	// clusterMod is cluster.json's mtime when it was read or written here: a
	// change by the CLI (gre-panel cluster ...) is picked up on the next read.
	clusterMod time.Time
)

func clusterConfigFile() string { return filepath.Join(configDir, "cluster.json") }

func defaultClusterConfig() ClusterConfig {
	host, _ := os.Hostname()
	return ClusterConfig{
		Version:    2,
		NodeID:     "hub-" + randHex(4),
		Name:       host,
		Health:     LBHealth{}.norm(),
		HubForward: true,
		DNS:        DNSConfig{TTL: 60},
	}
}

func isClusterLicensed() bool { return hasPro("cluster") }

func cloneClusterConfig(c ClusterConfig) ClusterConfig {
	out := c
	out.Pools = make([]LBPool, len(c.Pools))
	for i, p := range c.Pools {
		p.Members = append([]LBMember(nil), p.Members...)
		p.Excluded = append([]int(nil), p.Excluded...)
		out.Pools[i] = p
	}
	out.Hubs = append([]HubPeer(nil), c.Hubs...)
	out.DNS.Records = append([]string(nil), c.DNS.Records...)
	return out
}

// loadClusterConfig returns a private copy.
func loadClusterConfig() ClusterConfig {
	clusterMu.Lock()
	defer clusterMu.Unlock()
	var mod time.Time
	if fi, err := os.Stat(clusterConfigFile()); err == nil {
		mod = fi.ModTime()
	}
	if clusterCache == nil || !mod.Equal(clusterMod) {
		c := readClusterConfig()
		clusterCache, clusterMod = &c, mod
	}
	return cloneClusterConfig(*clusterCache)
}

// readClusterConfig reads cluster.json, upgrading the first design (v1).
func readClusterConfig() ClusterConfig {
	data, err := os.ReadFile(clusterConfigFile())
	if err != nil || len(data) == 0 {
		return defaultClusterConfig()
	}
	var c ClusterConfig
	if json.Unmarshal(data, &c) != nil {
		return defaultClusterConfig()
	}
	if c.Version < 2 {
		c = upgradeClusterV1(data)
	}
	c.Health = c.Health.norm()
	if c.NodeID == "" {
		c.NodeID = "hub-" + randHex(4)
	}
	if c.DNS.TTL <= 0 {
		c.DNS.TTL = 60
	}
	for i := range c.Pools {
		if !lbModeOK(c.Pools[i].Mode) {
			c.Pools[i].Mode = lbFailover
		}
		if !lbProtoOK(c.Pools[i].Proto) {
			c.Pools[i].Proto = "tcp"
		}
	}
	return c
}

// upgradeClusterV1 keeps the hub identity and the peer hubs of the first
// design. Its foreign-server pool is dropped: it sent users straight to the
// foreign servers' public IPs, outside the tunnel.
func upgradeClusterV1(data []byte) ClusterConfig {
	var v1 struct {
		NodeID        string `json:"node_id"`
		ClusterSecret string `json:"cluster_secret"`
		PublicIP      string `json:"public_ip"`
		Nodes         map[string]struct {
			Name     string `json:"name"`
			APIURL   string `json:"api_url"`
			PublicIP string `json:"public_ip"`
		} `json:"nodes"`
		ForeignNodes map[string]json.RawMessage `json:"foreign_nodes"`
	}
	_ = json.Unmarshal(data, &v1)
	c := defaultClusterConfig()
	if v1.NodeID != "" {
		c.NodeID = v1.NodeID
	}
	c.Secret, c.PublicIP = v1.ClusterSecret, v1.PublicIP
	ids := make([]string, 0, len(v1.Nodes))
	for id := range v1.Nodes {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		n := v1.Nodes[id]
		c.Hubs = append(c.Hubs, HubPeer{ID: id, Name: n.Name, URL: n.APIURL, PublicIP: n.PublicIP})
	}
	if len(v1.ForeignNodes) > 0 {
		clusterEventf("warn", "Cluster upgraded. The old foreign-server list (%d servers) was removed: it sent users straight to foreign IPs, outside the tunnel. Make a pool from your tunnels instead.", len(v1.ForeignNodes))
	}
	return c
}

func saveClusterConfig(c ClusterConfig) error {
	clusterMu.Lock()
	defer clusterMu.Unlock()
	c.Version = 2
	c.Updated = time.Now().Format("2006-01-02 15:04:05")
	_ = os.MkdirAll(configDir, 0o700)
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := clusterConfigFile() + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, clusterConfigFile()); err != nil {
		return err
	}
	saved := cloneClusterConfig(c)
	clusterCache = &saved
	if fi, err := os.Stat(clusterConfigFile()); err == nil {
		clusterMod = fi.ModTime()
	}
	writeLBSideFiles(saved)
	clusterWake()
	return nil
}

// updateClusterConfig applies fn to the latest config and saves it.
func updateClusterConfig(fn func(c *ClusterConfig) error) (ClusterConfig, error) {
	c := loadClusterConfig()
	if err := fn(&c); err != nil {
		return c, err
	}
	return c, saveClusterConfig(c)
}

// writeLBSideFiles writes the pool ports for hashem.sh (lb-ports).
func writeLBSideFiles(c ClusterConfig) {
	var b strings.Builder
	for _, p := range c.Pools {
		if p.Disabled {
			continue
		}
		for _, proto := range lbProtos(p.Proto) {
			fmt.Fprintf(&b, "%d/%s\n", p.Port, proto)
		}
	}
	if b.Len() == 0 {
		_ = os.Remove(lbPooledPortsFile())
		return
	}
	_ = os.WriteFile(lbPooledPortsFile(), []byte(b.String()), 0o644)
}

// ---- events ----

type clusterEvent struct {
	At    string `json:"at"`
	Level string `json:"level"` // info | warn | error
	Text  string `json:"text"`
}

var (
	clusterEvMu  sync.Mutex
	clusterEvs   []clusterEvent
	clusterEvMax = 200
	clusterEvOK  bool // loaded from disk
)

func clusterEventsFile() string { return filepath.Join(configDir, "cluster-events.json") }

func clusterEventf(level, f string, a ...any) {
	e := clusterEvent{At: time.Now().Format("2006-01-02 15:04:05"), Level: level, Text: fmt.Sprintf(f, a...)}
	log.Printf("[cluster] %s", e.Text)
	clusterEvMu.Lock()
	defer clusterEvMu.Unlock()
	clusterEventsLoadLocked()
	clusterEvs = append(clusterEvs, e)
	if len(clusterEvs) > clusterEvMax {
		clusterEvs = clusterEvs[len(clusterEvs)-clusterEvMax:]
	}
	if data, err := json.Marshal(clusterEvs); err == nil {
		tmp := clusterEventsFile() + ".tmp"
		if os.WriteFile(tmp, data, 0o600) == nil {
			_ = os.Rename(tmp, clusterEventsFile())
		}
	}
}

func clusterEventsLoadLocked() {
	if clusterEvOK {
		return
	}
	clusterEvOK = true
	if data, err := os.ReadFile(clusterEventsFile()); err == nil {
		_ = json.Unmarshal(data, &clusterEvs)
	}
}

// clusterEvents returns the newest n events, newest first.
func clusterEvents(n int) []clusterEvent {
	clusterEvMu.Lock()
	defer clusterEvMu.Unlock()
	clusterEventsLoadLocked()
	out := make([]clusterEvent, 0, n)
	for i := len(clusterEvs) - 1; i >= 0 && len(out) < n; i-- {
		out = append(out, clusterEvs[i])
	}
	return out
}

// ---- links ----

// lbLink is one tunnel on this hub that can serve a pool.
type lbLink struct {
	ID         int
	Name       string
	Remote     string
	Svc        string
	Engine     string
	Transport  string
	CtrlPort   int
	PeerGre    string
	NoGre      bool
	Ports      []int
	SnapHealth string
	LatencyMs  float64
	Addr       string
}

// lbLinksFrom lists the hub's relays (frps / backhaul-server units). A spoke
// has none. When the main tunnel and the legacy peer 1 are the same relay,
// the peer record wins.
func lbLinksFrom(s *HubSnapshot) []lbLink {
	if s == nil {
		return nil
	}
	bySvc := map[string]lbLink{}
	for _, l := range s.All() {
		svc := l.FrpsSvc
		if l.ID == mainTunnelID && svc == "" {
			svc = s.Local.FrpSvc
		}
		addr := lbAddrFor(svc)
		if addr == "" {
			continue
		}
		if old, dup := bySvc[svc]; dup && old.ID != mainTunnelID {
			continue
		}
		tr := l.FRPTransport
		if tr == "" {
			tr = l.Transport
		}
		_, engine := lbConfFor(svc)
		bySvc[svc] = lbLink{ID: l.ID, Name: l.Name, Remote: l.RemotePub, Svc: svc, Engine: engine, Transport: tr,
			CtrlPort: l.FrpPort, PeerGre: l.PeerGre, NoGre: l.NoGre, Ports: append([]int(nil), l.Ports...),
			SnapHealth: l.HealthState, LatencyMs: l.LatencyMs, Addr: addr}
	}
	out := make([]lbLink, 0, len(bySvc))
	for _, l := range bySvc {
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func lbLinkName(l lbLink) string {
	if l.Name != "" {
		return l.Name
	}
	if l.ID == mainTunnelID {
		return xrayOr(linkLabel("main"), "Main tunnel")
	}
	return fmt.Sprintf("peer-%d", l.ID)
}

// ---- health ----

// lbLinkRT is the debounced health of one link.
type lbLinkRT struct {
	Known      bool
	Up         bool
	okStreak   int
	failStreak int
	Since      time.Time
	Session    bool
	Remote     string // where the control session comes from
	ICMPms     float64
	icmpGoodAt time.Time
	LatencyMs  float64 // smoothed, -1 unknown
	Reason     string
}

// lbIcmpTrust is how long a link that answered ping is expected to keep
// answering: inside it, lost pings take the link out; after it, ICMP counts
// as filtered and only the session decides.
const lbIcmpTrust = 10 * time.Minute

// lbObserve feeds one check into the link's state. It returns +1 when the
// link came up, -1 when it went down, 0 otherwise.
func (rt *lbLinkRT) lbObserve(now time.Time, session bool, icmpMs float64, icmpUsable bool, h LBHealth) int {
	rt.Session, rt.ICMPms = session, icmpMs
	if icmpMs >= 0 {
		rt.icmpGoodAt = now
		if rt.LatencyMs < 0 {
			rt.LatencyMs = icmpMs
		} else {
			rt.LatencyMs = round1(rt.LatencyMs*0.7 + icmpMs*0.3)
		}
	}
	trusted := icmpUsable && !rt.icmpGoodAt.IsZero() && now.Sub(rt.icmpGoodAt) < lbIcmpTrust
	good := session && !(trusted && icmpMs < 0)
	switch {
	case !session:
		rt.Reason = "the foreign client is not connected (no control session)"
	case !good:
		rt.Reason = "the foreign server stopped answering ping on the tunnel path"
	default:
		rt.Reason = ""
	}
	if good {
		rt.okStreak, rt.failStreak = rt.okStreak+1, 0
	} else {
		rt.okStreak, rt.failStreak = 0, rt.failStreak+1
	}
	if !rt.Known {
		rt.Known, rt.Up, rt.Since = true, good, now
		return 0
	}
	if rt.Up && rt.failStreak >= h.Fall {
		rt.Up, rt.Since = false, now
		return -1
	}
	if !rt.Up && rt.okStreak >= h.Rise {
		rt.Up, rt.Since = true, now
		return 1
	}
	return 0
}

// lbSvcRT is the debounced service check of one pool member.
type lbSvcRT struct {
	Known      bool
	Up         bool
	okStreak   int
	failStreak int
	At         time.Time // last check started
	Busy       bool
	Reason     string
}

// observe feeds one check result: +1 when the service came back, -1 when it
// was taken out.
func (s *lbSvcRT) observe(ok bool, reason string, h LBHealth) int {
	s.Busy, s.Reason = false, reason
	if ok {
		s.okStreak, s.failStreak = s.okStreak+1, 0
	} else {
		s.okStreak, s.failStreak = 0, s.failStreak+1
	}
	switch {
	case !s.Known:
		s.Known, s.Up = true, ok
	case s.Up && s.failStreak >= h.Fall:
		s.Up = false
		return -1
	case !s.Up && s.okStreak >= h.Rise:
		s.Up = true
		return 1
	}
	return 0
}

// lbMemberInfo is what the tick learned about one pool member, for the API.
type lbMemberInfo struct {
	Conns       int
	Check       string // "", "ok", "fail", "pending"
	CheckReason string
	Full        bool
}

// lbSessionOf finds the link's control session among the host's sockets.
// Sessions from loopback (the WSS front relaying to frps) count, but the
// remote reported is a real one when there is any.
func lbSessionOf(socks []sockInfo, ctrlPort int) (bool, string) {
	if ctrlPort <= 0 {
		return false, ""
	}
	ports := map[uint16]bool{}
	for _, p := range controlPorts(ctrlPort) {
		ports[uint16(p)] = true
	}
	found, remote := false, ""
	for _, s := range socks {
		if s.Proto != "tcp" || s.State != sockEstablished || !ports[s.Local.Port()] {
			continue
		}
		found = true
		if a := s.Remote.Addr(); !a.IsLoopback() && remote == "" {
			remote = a.String()
		}
	}
	return found, remote
}

// lbListening lists the ports each address listens on: TCP LISTEN sockets and
// bound UDP sockets.
func lbListening(socks []sockInfo) map[string]map[string][]int {
	out := map[string]map[string][]int{}
	for _, s := range socks {
		ok := (s.Proto == "tcp" && s.State == sockListen) || (s.Proto == "udp" && s.State == sockUDPBound)
		if !ok {
			continue
		}
		a := s.Local.Addr().String()
		if out[a] == nil {
			out[a] = map[string][]int{}
		}
		out[a][s.Proto] = append(out[a][s.Proto], int(s.Local.Port()))
	}
	return out
}

func hasInt(xs []int, v int) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

// ---- runtime ----

type clusterRuntime struct {
	mu        sync.Mutex
	links     map[int]*lbLinkRT
	view      []lbLinkView
	pools     map[string]*lbPoolRT
	plans     map[string]lbPoolPlan
	poolState map[string]string
	pass      []lbPortRange
	warnings  []string
	rules     string
	chains    []string
	applyErr  string
	appliedAt time.Time
	hooksAt   time.Time
	// hadAddrs: hashem-lb carried addresses after the last check; addrsSeen:
	// the interface was checked once since start (it outlives a restart).
	hadAddrs  bool
	addrsSeen bool
	bindAt    time.Time
	bindErr   map[string]string
	targeted  map[string]map[int]bool
	members   map[string]map[int]lbMemberInfo
	icmpOK    bool
	ticks     uint64
}

var clusterRT = newClusterRuntime()

func newClusterRuntime() *clusterRuntime {
	return &clusterRuntime{links: map[int]*lbLinkRT{}, pools: map[string]*lbPoolRT{}, plans: map[string]lbPoolPlan{},
		poolState: map[string]string{}, bindErr: map[string]string{}, targeted: map[string]map[int]bool{},
		members: map[string]map[int]lbMemberInfo{}}
}

// lbLinkView is a link as the API shows it.
type lbLinkView struct {
	ID        int     `json:"id"`
	Name      string  `json:"name"`
	Remote    string  `json:"remote"`
	Engine    string  `json:"engine"`
	Svc       string  `json:"svc"`
	Addr      string  `json:"addr"`
	Bound     bool    `json:"bound"`
	Up        bool    `json:"up"`
	Session   bool    `json:"session"`
	LatencyMs float64 `json:"latency_ms"`
	ICMPMs    float64 `json:"icmp_ms"`
	Since     string  `json:"since,omitempty"`
	Reason    string  `json:"reason,omitempty"`
	Ports     []int   `json:"ports"`
	ListenTCP []int   `json:"listen_tcp"`
	ListenUDP []int   `json:"listen_udp"`
	BindError string  `json:"bind_error,omitempty"`
}

var clusterWakeCh = make(chan struct{}, 1)

// clusterWake runs the next tick now (after a config change).
func clusterWake() {
	select {
	case clusterWakeCh <- struct{}{}:
	default:
	}
}

// startClusterMonitor runs the health and rules loop for the life of the panel.
func startClusterMonitor() {
	lbClearLegacyV1()
	writeLBSideFiles(loadClusterConfig())
	for {
		wait := time.Duration(loadClusterConfig().Health.IntervalMs) * time.Millisecond
		if clusterTick(time.Now()) {
			wait = 3 * time.Second
		}
		select {
		case <-time.After(wait):
		case <-clusterWakeCh:
		}
	}
}

// Seams for tests.
var (
	lbSnapshot   = currentSnapshot
	lbApply      = lbApplyRules
	lbClear      = lbClearRules
	lbAddrs      = lbEnsureAddrs
	lbBind       = lbSetRelayBind
	lbIsBound    = lbRelayBound
	lbForget     = lbConntrackForget
	lbHubForward = meshForwardTarget
	lbProbe      = lbTCPProbe
	lbGo         = func(f func()) { go f() }
)

// clusterTick is one pass: health, membership, binding, rules. Without any
// pool, rule or bound relay (also left from before a restart) it only lists
// the links with the snapshot's health, and reports idle.
func clusterTick(now time.Time) (idle bool) {
	cfg := loadClusterConfig()
	rt := clusterRT
	links := lbLinksFrom(lbSnapshot())
	rt.mu.Lock()
	idle = len(cfg.Pools) == 0 && rt.rules == "" && !rt.hadAddrs && !fileExists(lbBindsFile()) && !fileExists(lbRulesFile())
	if idle {
		rt.view = lbIdleView(links)
		rt.mu.Unlock()
		return true
	}
	rt.mu.Unlock()
	socks := readSockets()
	listen := lbListening(socks)

	// Links whose ports include a pool port join that pool by themselves.
	if joined := lbAutoJoin(&cfg, links); joined {
		if err := saveClusterConfig(cfg); err != nil {
			clusterEventf("error", "Cannot save cluster.json: %v", err)
		}
	}

	// Ping each link where its control session comes from (the path the
	// relay really uses), else its GRE peer or public IP.
	rt.mu.Lock()
	targets := map[int]string{}
	var pingList []string
	sess := map[int]bool{}
	for _, l := range links {
		s, remote := lbSessionOf(socks, l.CtrlPort)
		if !s && (l.Transport == "kcp" || l.Transport == "quic" || l.Transport == "udp") {
			// UDP transports hold no TCP session: use the snapshot's verdict.
			s = l.SnapHealth == stateHealthy || l.SnapHealth == stateDegraded
		}
		sess[l.ID] = s
		t := remote
		if t == "" {
			t = l.PeerGre
		}
		if t == "" {
			t = l.Remote
		}
		if t != "" {
			targets[l.ID] = t
			pingList = append(pingList, t)
		}
		if rt.links[l.ID] == nil {
			rt.links[l.ID] = &lbLinkRT{LatencyMs: -1, ICMPms: -1}
		}
		rt.links[l.ID].Remote = remote
	}
	h := cfg.Health
	rt.mu.Unlock()

	timeout := time.Duration(h.IntervalMs) * time.Millisecond * 8 / 10
	if timeout > 900*time.Millisecond {
		timeout = 900 * time.Millisecond
	}
	pings, icmpOK := lbPinger(pingList, timeout)

	// Service checks start once the lock is released (they report under it).
	var jobs []func()
	defer func() {
		for _, j := range jobs {
			lbGo(j)
		}
	}()
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.ticks++
	rt.icmpOK = icmpOK
	alive := map[int]bool{}
	for _, l := range links {
		alive[l.ID] = true
		ms := -1.0
		if t, ok := targets[l.ID]; ok {
			ms = pings[t]
		}
		lr := rt.links[l.ID]
		switch lr.lbObserve(now, sess[l.ID], ms, icmpOK, h) {
		case -1:
			clusterEventf("warn", "%s is down: %s.", lbLinkName(l), lr.Reason)
		case 1:
			clusterEventf("info", "%s is back up.", lbLinkName(l))
		}
	}
	for id := range rt.links {
		if !alive[id] {
			delete(rt.links, id)
		}
	}

	// Relays of pool members listen on their private address. A disabled
	// pool's relays stay there too: its port passes through to one of them
	// (the lowest link id) instead of every relay restarting to fight for it.
	want := map[string]string{}
	member := map[int]bool{}
	for _, p := range cfg.Pools {
		for _, m := range p.Members {
			member[m.Link] = true
		}
	}
	bound := map[int]bool{}
	checkBinds := now.Sub(rt.bindAt) >= 5*time.Second
	for _, l := range links {
		if member[l.ID] {
			want[l.Svc] = l.Addr
		}
	}
	addrs := make([]string, 0, len(want))
	for _, a := range want {
		addrs = append(addrs, a)
	}
	if checkBinds {
		rt.bindAt = now
		if len(addrs) > 0 || rt.hadAddrs || !rt.addrsSeen {
			if err := lbAddrs(addrs); err != nil {
				clusterEventf("error", "Private addresses: %v", err)
			}
			rt.hadAddrs, rt.addrsSeen = len(addrs) > 0, true
		}
		lbWriteBinds(want)
	}
	for _, l := range links {
		isBound := lbIsBound(l.Svc, l.Addr)
		switch {
		case checkBinds && member[l.ID] && !isBound:
			changed, err := lbBind(l.Svc, l.Addr)
			if err != nil {
				rt.bindErr[l.Svc] = err.Error()
				clusterEventf("error", "%s: cannot move its ports behind the cluster: %v", lbLinkName(l), err)
			} else {
				delete(rt.bindErr, l.Svc)
				isBound = true
				if changed {
					clusterEventf("info", "%s now serves its ports through the cluster (%s restarted, listening on %s).", lbLinkName(l), l.Svc, l.Addr)
				}
			}
		case checkBinds && !member[l.ID] && isBound:
			if _, err := lbBind(l.Svc, ""); err != nil {
				rt.bindErr[l.Svc] = err.Error()
				clusterEventf("error", "%s: cannot give its ports back: %v", lbLinkName(l), err)
			} else {
				delete(rt.bindErr, l.Svc)
				isBound = false
				clusterEventf("info", "%s left every pool and listens on its public ports again (%s restarted).", lbLinkName(l), l.Svc)
			}
		}
		bound[l.ID] = isBound
	}

	// Plan.
	byID := map[int]lbLink{}
	for _, l := range links {
		byID[l.ID] = l
	}
	plan := lbPlan{}
	pooled := map[string]bool{}
	rt.plans = map[string]lbPoolPlan{}
	rt.members = map[string]map[int]lbMemberInfo{}
	conns := lbConnCounts(socks)
	for _, p := range cfg.Pools {
		if !p.Disabled {
			for _, proto := range lbProtos(p.Proto) {
				pooled[proto+"/"+strconv.Itoa(p.Port)] = true
			}
		}
		prt := rt.pools[p.key()]
		if prt == nil {
			prt = newPoolRT()
			rt.pools[p.key()] = prt
		}
		checking := p.Check == "tcp" && p.Proto != "udp" && !p.Disabled
		info := map[int]lbMemberInfo{}
		var ms []lbMemberState
		for _, m := range p.Members {
			st := lbMemberState{LBMember: m, LatencyMs: -1, Conns: -1}
			mi := lbMemberInfo{Conns: -1}
			if l, ok := byID[m.Link]; ok && bound[m.Link] {
				st.Name, st.Addr = lbLinkName(l), l.Addr
				if lr := rt.links[m.Link]; lr != nil {
					st.Up, st.LatencyMs = lr.Up, lr.LatencyMs
				}
				port := memberPort(p, m)
				ls := listen[l.Addr]
				st.Listening = (p.Proto != "udp" && hasInt(ls["tcp"], port)) || (p.Proto == "udp" && hasInt(ls["udp"], port))
				if p.Proto != "udp" {
					st.Conns = conns[l.Addr+":"+strconv.Itoa(port)]
					mi.Conns = st.Conns
				}
				if checking && st.Listening {
					sv := prt.Svc[m.Link]
					if sv == nil {
						sv = &lbSvcRT{}
						prt.Svc[m.Link] = sv
					}
					if !sv.Busy && now.Sub(sv.At) >= lbCheckEvery(p) {
						sv.Busy, sv.At = true, now
						jobs = append(jobs, lbCheckJob(sv, l.Addr, port, poolLabel(p), lbLinkName(l), h))
					}
					switch {
					case !sv.Known:
						mi.Check = "pending"
					case sv.Up:
						mi.Check = "ok"
					default:
						mi.Check, mi.CheckReason = "fail", sv.Reason
						st.Up = false
					}
				}
			}
			ms = append(ms, st)
			info[m.Link] = mi
		}
		if !checking {
			prt.Svc = map[int]*lbSvcRT{}
		}
		ts, state := lbPickTargets(p, ms, prt)
		for link := range prt.Full {
			mi := info[link]
			mi.Full = true
			info[link] = mi
		}
		rt.members[p.key()] = info
		if (state == poolDown || state == poolFailOpen) && cfg.HubForward {
			if to := lbHubForward(cfg, p); to != "" {
				plan.Forward = append(plan.Forward, lbForward{Port: p.Port, Proto: p.Proto, To: to})
				ts, state = nil, poolForward
			}
		}
		pp := lbPoolPlan{Port: p.Port, Proto: p.Proto, Mode: p.Mode, State: state, Targets: ts}
		plan.Pools = append(plan.Pools, pp)
		rt.plans[p.key()] = pp
		lbPoolTransition(rt, p, state, ts, byID)
	}
	listenByLink := map[int]map[string][]int{}
	addrByLink := map[int]string{}
	for _, l := range links {
		if bound[l.ID] {
			listenByLink[l.ID] = listen[l.Addr]
			addrByLink[l.ID] = l.Addr
		}
	}
	plan.Pass, rt.warnings = lbPassRanges(listenByLink, addrByLink, pooled)
	rt.pass = plan.Pass

	// Apply when something changed, and re-check the hooks now and then.
	active := len(cfg.Pools) > 0 || len(addrByLink) > 0
	switch {
	case !active && (rt.rules != "" || fileExists(lbRulesFile())):
		lbClear(rt.chains)
		rt.rules, rt.chains, rt.applyErr = "", nil, ""
		clusterEventf("info", "No pools left: cluster rules removed.")
	case active:
		text := lbRulesText(plan)
		if text != rt.rules || now.Sub(rt.hooksAt) >= 30*time.Second {
			if err := lbApply(text, rt.chains); err != nil {
				if rt.applyErr != err.Error() {
					clusterEventf("error", "Cannot apply the cluster rules: %v", err)
				}
				rt.applyErr = err.Error()
			} else {
				rt.rules, rt.chains, rt.applyErr, rt.appliedAt = text, lbChainsIn(text), "", now
			}
			rt.hooksAt = now
		}
	}

	// The API view.
	rt.view = rt.view[:0]
	for _, l := range links {
		lr := rt.links[l.ID]
		v := lbLinkView{ID: l.ID, Name: lbLinkName(l), Remote: l.Remote, Engine: l.Engine, Svc: l.Svc, Addr: l.Addr,
			Bound: bound[l.ID], Ports: l.Ports, LatencyMs: -1, ICMPMs: -1, BindError: rt.bindErr[l.Svc]}
		if lr != nil {
			v.Up, v.Session, v.LatencyMs, v.ICMPMs, v.Reason = lr.Up, lr.Session, lr.LatencyMs, lr.ICMPms, lr.Reason
			if !lr.Since.IsZero() {
				v.Since = lr.Since.Format("2006-01-02 15:04:05")
			}
		}
		if bound[l.ID] {
			v.ListenTCP, v.ListenUDP = sortedCopy(listen[l.Addr]["tcp"]), sortedCopy(listen[l.Addr]["udp"])
		}
		rt.view = append(rt.view, v)
	}
	return false
}

// lbCheckJob runs one service check of a member and feeds the result back.
func lbCheckJob(sv *lbSvcRT, addr string, port int, pool, name string, h LBHealth) func() {
	return func() {
		ok, why := lbProbe(addr, port, 3*time.Second)
		clusterRT.mu.Lock()
		change := sv.observe(ok, why, h)
		clusterRT.mu.Unlock()
		switch change {
		case -1:
			clusterEventf("warn", "%s, %s: the service check failed: %s.", pool, name, why)
			clusterWake()
		case 1:
			clusterEventf("info", "%s, %s: the service check passes again.", pool, name)
			clusterWake()
		}
	}
}

// lbConnCounts counts the open TCP connections on each private relay
// address:port ("169.254.77.2:443").
func lbConnCounts(socks []sockInfo) map[string]int {
	out := map[string]int{}
	for _, s := range socks {
		if s.Proto != "tcp" || s.State != sockEstablished {
			continue
		}
		if a := s.Local.Addr(); a.Is4() && a.As4()[0] == 169 && a.As4()[1] == 254 && a.As4()[2] == 77 {
			out[s.Local.String()]++
		}
	}
	return out
}

// lbIdleView lists the links with the snapshot's verdict (no pool runs, so
// the one-second check does not either).
func lbIdleView(links []lbLink) []lbLinkView {
	out := make([]lbLinkView, 0, len(links))
	for _, l := range links {
		up := l.SnapHealth == stateHealthy || l.SnapHealth == stateDegraded
		out = append(out, lbLinkView{ID: l.ID, Name: lbLinkName(l), Remote: l.Remote, Engine: l.Engine, Svc: l.Svc, Addr: l.Addr,
			Up: up, Session: up, LatencyMs: l.LatencyMs, ICMPMs: -1, Ports: l.Ports})
	}
	return out
}

func sortedCopy(xs []int) []int {
	out := append([]int(nil), xs...)
	sort.Ints(out)
	return out
}

// lbPoolTransition records state changes, alerts on them and drops the UDP
// flows of members that stopped receiving traffic.
func lbPoolTransition(rt *clusterRuntime, p LBPool, state string, ts []lbTarget, byID map[int]lbLink) {
	k := p.key()
	now := map[int]bool{}
	for _, t := range ts {
		now[t.Link] = true
	}
	if p.Proto != "tcp" {
		for link := range rt.targeted[k] {
			if !now[link] {
				if l, ok := byID[link]; ok {
					go lbForget(l.Addr)
				}
			}
		}
	}
	rt.targeted[k] = now
	old, seen := rt.poolState[k]
	rt.poolState[k] = state
	if !seen || old == state {
		return
	}
	var names []string
	for _, t := range ts {
		if l, ok := byID[t.Link]; ok {
			names = append(names, lbLinkName(l))
		}
	}
	where := strings.Join(names, ", ")
	label := poolLabel(p)
	switch state {
	case poolOK:
		clusterEventf("info", "%s: every member is healthy again (%s).", label, where)
	case poolDegraded:
		clusterEventf("warn", "%s: some members are out; traffic goes to %s.", label, where)
	case poolFailOpen:
		clusterEventf("error", "%s: no member passes the health check; trying every member that still listens.", label)
	case poolForward:
		clusterEventf("warn", "%s: no member works here; forwarded to another Iran hub.", label)
	case poolDown:
		clusterEventf("error", "%s: nothing can serve it.", label)
	}
	poolAlert(label, old, state, where)
}

func poolLabel(p LBPool) string {
	s := fmt.Sprintf("Pool %d/%s", p.Port, p.Proto)
	if p.Name != "" {
		s += " (" + p.Name + ")"
	}
	return s
}

// poolAlert sends a pool state change through the alert channels (Settings ->
// Alerts), with the link states' vocabulary.
func poolAlert(label, from, to, where string) {
	cfg := loadAlertConfig()
	if !cfg.Enabled || from == poolOff || to == poolOff {
		return
	}
	m := map[string]string{poolOK: stateHealthy, poolDegraded: stateDegraded, poolForward: stateDegraded,
		poolFailOpen: stateDown, poolDown: stateDown}
	if !cfg.NotifyDegrad && m[from] != stateDown && m[to] != stateDown {
		return
	}
	why := "now on: " + where
	if where == "" {
		why = to
	}
	go alertSend(cfg, []alertEvent{{Link: label, From: m[from], To: m[to], Why: why, At: time.Now().Format(time.RFC3339)}})
}

// lbAutoJoin adds every link whose ports include a pool port to that pool
// (unless it was removed from it by hand). It reports a change.
func lbAutoJoin(c *ClusterConfig, links []lbLink) bool {
	changed := false
	for i := range c.Pools {
		p := &c.Pools[i]
		if p.Disabled {
			continue
		}
		for _, l := range links {
			if !hasInt(l.Ports, p.Port) || p.member(l.ID) != nil || hasInt(p.Excluded, l.ID) {
				continue
			}
			p.Members = append(p.Members, LBMember{Link: l.ID, Remote: l.Remote, Weight: 1, Priority: nextPriority(*p)})
			clusterEventf("info", "%s joined %s (its ports include %d).", lbLinkName(l), poolLabel(*p), p.Port)
			changed = true
		}
	}
	return changed
}

func nextPriority(p LBPool) int {
	n := 0
	for _, m := range p.Members {
		if m.Priority >= n {
			n = m.Priority + 1
		}
	}
	return n
}

// lbWriteBinds tells hashem.sh which relays are bound.
func lbWriteBinds(want map[string]string) {
	if len(want) == 0 {
		_ = os.Remove(lbBindsFile())
		return
	}
	svcs := make([]string, 0, len(want))
	for s := range want {
		svcs = append(svcs, s)
	}
	sort.Strings(svcs)
	var b strings.Builder
	for _, s := range svcs {
		fmt.Fprintf(&b, "%s %s\n", s, want[s])
	}
	_ = os.WriteFile(lbBindsFile(), []byte(b.String()), 0o644)
}

// ---- API ----

type clusterPoolView struct {
	LBPool
	State   string         `json:"state"`
	Targets []lbTarget     `json:"targets"`
	Status  []memberStatus `json:"member_status"`
}

type memberStatus struct {
	Link        int     `json:"link"`
	Name        string  `json:"name"`
	Up          bool    `json:"up"`
	Listening   bool    `json:"listening"`
	Share       float64 `json:"share"`
	LatencyMs   float64 `json:"latency_ms"`
	Conns       int     `json:"conns"` // -1 unknown (UDP)
	Check       string  `json:"check,omitempty"`
	CheckReason string  `json:"check_reason,omitempty"`
	Full        bool    `json:"full,omitempty"`
	Stale       bool    `json:"stale"` // the peer id now belongs to another foreign IP
	Missing     bool    `json:"missing"`
}

func handleClusterStatus(w http.ResponseWriter, r *http.Request) {
	cfg := loadClusterConfig()
	rt := clusterRT
	rt.mu.Lock()
	links := append([]lbLinkView(nil), rt.view...)
	pools := make([]clusterPoolView, 0, len(cfg.Pools))
	byID := map[int]lbLinkView{}
	for _, l := range links {
		byID[l.ID] = l
	}
	for _, p := range cfg.Pools {
		pl := rt.plans[p.key()]
		v := clusterPoolView{LBPool: p, State: pl.State, Targets: pl.Targets}
		if v.State == "" {
			v.State = "starting"
		}
		share := map[int]float64{}
		for _, t := range pl.Targets {
			share[t.Link] = t.Share
		}
		for _, m := range p.Members {
			l, ok := byID[m.Link]
			mi, seen := rt.members[p.key()][m.Link]
			if !seen {
				mi.Conns = -1
			}
			ms := memberStatus{Link: m.Link, Name: l.Name, Up: l.Up && mi.Check != "fail", LatencyMs: l.LatencyMs, Share: share[m.Link], Missing: !ok,
				Conns: mi.Conns, Check: mi.Check, CheckReason: mi.CheckReason, Full: mi.Full}
			if ok {
				port := memberPort(p, m)
				ms.Listening = (p.Proto != "udp" && hasInt(l.ListenTCP, port)) || (p.Proto == "udp" && hasInt(l.ListenUDP, port))
				ms.Stale = m.Remote != "" && l.Remote != "" && m.Remote != l.Remote
			}
			v.Status = append(v.Status, ms)
		}
		pools = append(pools, v)
	}
	resp := map[string]any{
		"licensed":    isClusterLicensed(),
		"node_id":     cfg.NodeID,
		"name":        cfg.Name,
		"public_ip":   cfg.PublicIP,
		"health":      cfg.Health,
		"hub_forward": cfg.HubForward,
		"pools":       pools,
		"links":       links,
		"warnings":    append([]string(nil), rt.warnings...),
		"apply_error": rt.applyErr,
		"icmp":        rt.icmpOK,
		"events":      clusterEvents(60),
		"hubs":        meshView(cfg),
		"dns":         dnsView(cfg),
		"joined_hubs": joinedHubsView(),
	}
	if !rt.appliedAt.IsZero() {
		resp["applied_at"] = rt.appliedAt.Format("2006-01-02 15:04:05")
	}
	rt.mu.Unlock()
	writeJSON(w, resp)
}

// clusterPrometheus adds the pools and linked hubs to /metrics (nothing when
// the cluster is not used).
func clusterPrometheus() string {
	cfg := loadClusterConfig()
	if len(cfg.Pools) == 0 && len(cfg.Hubs) == 0 {
		return ""
	}
	var b strings.Builder
	rt := clusterRT
	rt.mu.Lock()
	up := map[int]bool{}
	for _, l := range rt.view {
		up[l.ID] = l.Up
	}
	b.WriteString("# HELP hashem_cluster_pool_state Pool state: 2 ok, 1 degraded or forwarded to another hub, 0 down or fail-open.\n# TYPE hashem_cluster_pool_state gauge\n")
	for _, p := range cfg.Pools {
		if p.Disabled {
			continue
		}
		v := 0
		switch rt.plans[p.key()].State {
		case poolOK:
			v = 2
		case poolDegraded, poolForward:
			v = 1
		}
		fmt.Fprintf(&b, "hashem_cluster_pool_state{pool=\"%s\"} %d\n", p.key(), v)
	}
	b.WriteString("# HELP hashem_cluster_member_up 1 when the pool member passes its health and service checks.\n# TYPE hashem_cluster_member_up gauge\n")
	b.WriteString("# HELP hashem_cluster_member_connections Open TCP connections of the pool member.\n# TYPE hashem_cluster_member_connections gauge\n")
	b.WriteString("# HELP hashem_cluster_member_share Fraction of new connections the member gets now.\n# TYPE hashem_cluster_member_share gauge\n")
	for _, p := range cfg.Pools {
		if p.Disabled {
			continue
		}
		share := map[int]float64{}
		for _, t := range rt.plans[p.key()].Targets {
			share[t.Link] = t.Share
		}
		for _, m := range p.Members {
			mi, seen := rt.members[p.key()][m.Link]
			v := 0
			if up[m.Link] && mi.Check != "fail" {
				v = 1
			}
			lbl := fmt.Sprintf("pool=\"%s\",link=\"%d\"", p.key(), m.Link)
			fmt.Fprintf(&b, "hashem_cluster_member_up{%s} %d\n", lbl, v)
			if seen && mi.Conns >= 0 {
				fmt.Fprintf(&b, "hashem_cluster_member_connections{%s} %d\n", lbl, mi.Conns)
			}
			fmt.Fprintf(&b, "hashem_cluster_member_share{%s} %g\n", lbl, share[m.Link])
		}
	}
	rt.mu.Unlock()
	if len(cfg.Hubs) > 0 {
		b.WriteString("# HELP hashem_cluster_hub_up 1 when the linked Iran hub answers its heartbeat.\n# TYPE hashem_cluster_hub_up gauge\n")
		for _, h := range meshView(cfg) {
			v := 0
			if h.Up {
				v = 1
			}
			fmt.Fprintf(&b, "hashem_cluster_hub_up{hub=\"%s\"} %d\n", promEsc(h.Name), v)
		}
	}
	return b.String()
}

// handleClusterRules shows the kernel rules the cluster keeps (read only).
func handleClusterRules(w http.ResponseWriter, r *http.Request) {
	clusterRT.mu.Lock()
	text := clusterRT.rules
	clusterRT.mu.Unlock()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(text))
}

// validatePool checks a pool against the others and the hub's own ports.
func validatePool(c ClusterConfig, p LBPool, skip int) (string, string) {
	if p.Port < 1 || p.Port > 65535 {
		return "E-CLUSTER-02", "the port must be 1-65535"
	}
	if !lbProtoOK(p.Proto) {
		return "E-CLUSTER-02", "protocol must be tcp, udp or both"
	}
	if !lbModeOK(p.Mode) {
		return "E-CLUSTER-02", "mode must be " + lbModes
	}
	if p.Check != "" && p.Check != "tcp" {
		return "E-CLUSTER-02", "the service check is tcp or off"
	}
	if p.CheckEvery < 0 || p.CheckEvery > 60 {
		return "E-CLUSTER-02", "check every 1-60 seconds"
	}
	for i, q := range c.Pools {
		if i != skip && q.overlaps(p) {
			return "E-CLUSTER-03", fmt.Sprintf("port %d already has a pool (%s)", p.Port, q.Proto)
		}
	}
	if p.Port == cfg.Port {
		return "E-CLUSTER-03", fmt.Sprintf("port %d is the panel's own port", p.Port)
	}
	// a pool spreads tunnels' user ports; anything else Hashem binds there
	// (ports_registry.go) cannot be shared
	claims := hashemPortClaims()
	for _, proto := range lbProtos(p.Proto) {
		if owner := claimOwner(claims, proto, p.Port, func(c portClaim) bool {
			return c.Kind == claimPeer || c.Kind == claimPool || c.Kind == claimRelay
		}); owner != "" {
			return "E-CLUSTER-03", fmt.Sprintf("port %d is already used by %s", p.Port, owner)
		}
	}
	for _, l := range lbLinksFrom(lbSnapshot()) {
		if hasInt(controlPorts(l.CtrlPort), p.Port) {
			return "E-CLUSTER-03", fmt.Sprintf("port %d is the control port of %s; the foreign server dials it", p.Port, lbLinkName(l))
		}
	}
	seen := map[int]bool{}
	for _, m := range p.Members {
		if seen[m.Link] {
			return "E-CLUSTER-02", fmt.Sprintf("link %d is listed twice", m.Link)
		}
		seen[m.Link] = true
		if m.Port < 0 || m.Port > 65535 || m.Weight < 0 || m.Weight > 100 || m.Priority < 0 || m.Priority > 1000 || m.MaxConn < 0 || m.MaxConn > 1000000 {
			return "E-CLUSTER-02", "member port 1-65535, weight 1-100, priority 0-1000, connection limit 0-1000000"
		}
	}
	return "", ""
}

func normMembers(p *LBPool, links []lbLink) {
	remote := map[int]string{}
	for _, l := range links {
		remote[l.ID] = l.Remote
	}
	for i := range p.Members {
		m := &p.Members[i]
		if m.Weight <= 0 {
			m.Weight = 1
		}
		if m.Remote == "" {
			m.Remote = remote[m.Link]
		}
	}
}

// handleClusterPool creates or replaces a pool. Body: an LBPool, plus
// "orig_port"/"orig_proto" when an existing pool changes its port.
func handleClusterPool(w http.ResponseWriter, r *http.Request) {
	if proRequired(w, r, "cluster", "Cluster") {
		return
	}
	var req struct {
		LBPool
		OrigPort  int    `json:"orig_port"`
		OrigProto string `json:"orig_proto"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		writeAPIError(w, r, "E-CLUSTER-01", "")
		return
	}
	p := req.LBPool
	p.Proto = strings.ToLower(strings.TrimSpace(p.Proto))
	if p.Proto == "" {
		p.Proto = "tcp"
	}
	p.Mode = strings.ToLower(strings.TrimSpace(p.Mode))
	if p.Mode == "" {
		p.Mode = lbFailover
	}
	p.Name = strings.TrimSpace(p.Name)
	if len(p.Name) > 40 {
		p.Name = p.Name[:40]
	}
	p.Check = strings.ToLower(strings.TrimSpace(p.Check))
	if p.Check == "off" || p.Check == "none" {
		p.Check = ""
	}
	links := lbLinksFrom(lbSnapshot())
	known := map[int]bool{}
	for _, l := range links {
		known[l.ID] = true
	}
	for _, m := range p.Members {
		if !known[m.Link] {
			writeAPIError(w, r, "E-CLUSTER-04", fmt.Sprintf("link %d is not a tunnel on this server", m.Link))
			return
		}
	}
	normMembers(&p, links)
	var code, msg string
	_, err := updateClusterConfig(func(c *ClusterConfig) error {
		idx := -1
		op, opr := req.OrigPort, req.OrigProto
		if op == 0 {
			op, opr = p.Port, p.Proto
		}
		for i, q := range c.Pools {
			if q.Port == op && (opr == "" || q.Proto == opr) {
				idx = i
			}
		}
		if code, msg = validatePool(*c, p, idx); code != "" {
			return fmt.Errorf("%s", msg)
		}
		if idx >= 0 {
			if p.Excluded == nil {
				p.Excluded = c.Pools[idx].Excluded
			}
			c.Pools[idx] = p
			clusterEventf("info", "%s changed (mode %s, %d members).", poolLabel(p), p.Mode, len(p.Members))
		} else {
			c.Pools = append(c.Pools, p)
			clusterEventf("info", "%s created (mode %s, %d members).", poolLabel(p), p.Mode, len(p.Members))
		}
		sort.Slice(c.Pools, func(i, j int) bool { return c.Pools[i].Port < c.Pools[j].Port })
		return nil
	})
	if code != "" {
		writeAPIError(w, r, code, msg)
		return
	}
	if err != nil {
		writeAPIError(w, r, "E-CLUSTER-06", err.Error())
		return
	}
	writeJSON(w, map[string]any{"status": "ok"})
}

func handleClusterPoolDelete(w http.ResponseWriter, r *http.Request) {
	if proRequired(w, r, "cluster", "Cluster") {
		return
	}
	var req struct {
		Port  int    `json:"port"`
		Proto string `json:"proto"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req) != nil {
		writeAPIError(w, r, "E-CLUSTER-01", "")
		return
	}
	found := false
	_, err := updateClusterConfig(func(c *ClusterConfig) error {
		out := c.Pools[:0]
		for _, p := range c.Pools {
			if p.Port == req.Port && (req.Proto == "" || p.Proto == req.Proto) {
				found = true
				clusterEventf("info", "%s deleted.", poolLabel(p))
				continue
			}
			out = append(out, p)
		}
		c.Pools = out
		return nil
	})
	if !found {
		writeAPIError(w, r, "E-CLUSTER-05", "")
		return
	}
	if err != nil {
		writeAPIError(w, r, "E-CLUSTER-06", err.Error())
		return
	}
	writeJSON(w, map[string]any{"status": "ok"})
}

// handleClusterPoolFailback moves a no-failback pool back to its first member.
func handleClusterPoolFailback(w http.ResponseWriter, r *http.Request) {
	if proRequired(w, r, "cluster", "Cluster") {
		return
	}
	var req struct {
		Port  int    `json:"port"`
		Proto string `json:"proto"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req) != nil {
		writeAPIError(w, r, "E-CLUSTER-01", "")
		return
	}
	found := false
	_, err := updateClusterConfig(func(c *ClusterConfig) error {
		for i := range c.Pools {
			if c.Pools[i].Port == req.Port && (req.Proto == "" || c.Pools[i].Proto == req.Proto) {
				c.Pools[i].Failback++
				found = true
				clusterEventf("info", "%s: failback asked.", poolLabel(c.Pools[i]))
			}
		}
		return nil
	})
	if !found {
		writeAPIError(w, r, "E-CLUSTER-05", "")
		return
	}
	if err != nil {
		writeAPIError(w, r, "E-CLUSTER-06", err.Error())
		return
	}
	writeJSON(w, map[string]any{"status": "ok"})
}

// handleClusterMember changes one member: add, remove, drain, resume or set
// (weight, priority, port).
func handleClusterMember(w http.ResponseWriter, r *http.Request) {
	if proRequired(w, r, "cluster", "Cluster") {
		return
	}
	var req lbMemberReq
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req) != nil {
		writeAPIError(w, r, "E-CLUSTER-01", "")
		return
	}
	code, msg := lbMemberChange(req)
	if code != "" {
		writeAPIError(w, r, code, msg)
		return
	}
	writeJSON(w, map[string]any{"status": "ok"})
}

// lbMemberReq is one member change: add, remove, drain, resume or set.
type lbMemberReq struct {
	Port     int    `json:"port"`
	Proto    string `json:"proto"`
	Link     int    `json:"link"`
	Action   string `json:"action"`
	Weight   int    `json:"weight"`
	Priority *int   `json:"priority"`
	LinkPort int    `json:"link_port"`
	Backup   *bool  `json:"backup"`
	MaxConn  *int   `json:"max_conn"`
}

// lbMemberChange is shared by the API and the CLI.
func lbMemberChange(q lbMemberReq) (string, string) {
	port, proto, link, action, weight, prio, linkPort := q.Port, q.Proto, q.Link, q.Action, q.Weight, q.Priority, q.LinkPort
	links := lbLinksFrom(lbSnapshot())
	var ln *lbLink
	for i := range links {
		if links[i].ID == link {
			ln = &links[i]
		}
	}
	var code, msg string
	_, err := updateClusterConfig(func(c *ClusterConfig) error {
		var p *LBPool
		for i := range c.Pools {
			if c.Pools[i].Port == port && (proto == "" || c.Pools[i].Proto == proto) {
				p = &c.Pools[i]
			}
		}
		if p == nil {
			code, msg = "E-CLUSTER-05", fmt.Sprintf("no pool on port %d", port)
			return fmt.Errorf("%s", msg)
		}
		m := p.member(link)
		name := fmt.Sprintf("link %d", link)
		if ln != nil {
			name = lbLinkName(*ln)
		}
		switch action {
		case "add":
			if ln == nil {
				code, msg = "E-CLUSTER-04", fmt.Sprintf("link %d is not a tunnel on this server", link)
				return fmt.Errorf("%s", msg)
			}
			if m != nil {
				return nil
			}
			nm := LBMember{Link: link, Remote: ln.Remote, Weight: max(weight, 1), Priority: nextPriority(*p), Port: linkPort}
			if prio != nil {
				nm.Priority = *prio
			}
			if q.Backup != nil {
				nm.Backup = *q.Backup
			}
			if q.MaxConn != nil && *q.MaxConn >= 0 {
				nm.MaxConn = *q.MaxConn
			}
			p.Members = append(p.Members, nm)
			ex := p.Excluded[:0]
			for _, x := range p.Excluded {
				if x != link {
					ex = append(ex, x)
				}
			}
			p.Excluded = ex
			clusterEventf("info", "%s added to %s.", name, poolLabel(*p))
		case "remove":
			if m == nil {
				return nil
			}
			out := p.Members[:0]
			for _, x := range p.Members {
				if x.Link != link {
					out = append(out, x)
				}
			}
			p.Members = out
			if !hasInt(p.Excluded, link) {
				p.Excluded = append(p.Excluded, link)
			}
			clusterEventf("info", "%s removed from %s.", name, poolLabel(*p))
		case "drain", "resume":
			if m == nil {
				code, msg = "E-CLUSTER-04", name+" is not in this pool"
				return fmt.Errorf("%s", msg)
			}
			m.Drain = action == "drain"
			if m.Drain {
				clusterEventf("info", "%s drained in %s: no new connections, open ones finish.", name, poolLabel(*p))
			} else {
				clusterEventf("info", "%s takes new connections again in %s.", name, poolLabel(*p))
			}
		case "set":
			if m == nil {
				code, msg = "E-CLUSTER-04", name+" is not in this pool"
				return fmt.Errorf("%s", msg)
			}
			if weight < 0 || weight > 100 || linkPort < 0 || linkPort > 65535 || (prio != nil && (*prio < 0 || *prio > 1000)) ||
				(q.MaxConn != nil && (*q.MaxConn < 0 || *q.MaxConn > 1000000)) {
				code, msg = "E-CLUSTER-02", "weight 1-100, priority 0-1000, port 1-65535, connection limit 0-1000000"
				return fmt.Errorf("%s", msg)
			}
			if q.Backup != nil {
				m.Backup = *q.Backup
			}
			if q.MaxConn != nil {
				m.MaxConn = *q.MaxConn
			}
			if weight > 0 {
				m.Weight = weight
			}
			if prio != nil {
				m.Priority = *prio
			}
			if linkPort > 0 {
				m.Port = linkPort
			}
		default:
			code, msg = "E-CLUSTER-01", "action must be add, remove, drain, resume or set"
			return fmt.Errorf("%s", msg)
		}
		return nil
	})
	if code != "" {
		return code, msg
	}
	if err != nil {
		return "E-CLUSTER-06", err.Error()
	}
	return "", ""
}

// handleClusterSettings changes health tuning, hub forwarding and identity.
func handleClusterSettings(w http.ResponseWriter, r *http.Request) {
	if proRequired(w, r, "cluster", "Cluster") {
		return
	}
	var req struct {
		Health     *LBHealth `json:"health"`
		HubForward *bool     `json:"hub_forward"`
		Name       *string   `json:"name"`
		PublicIP   *string   `json:"public_ip"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req) != nil {
		writeAPIError(w, r, "E-CLUSTER-01", "")
		return
	}
	if req.PublicIP != nil && *req.PublicIP != "" && !isIPv4(*req.PublicIP) {
		writeAPIError(w, r, "E-CLUSTER-02", "public IP must be an IPv4 address")
		return
	}
	_, err := updateClusterConfig(func(c *ClusterConfig) error {
		if req.Health != nil {
			c.Health = req.Health.norm()
		}
		if req.HubForward != nil {
			c.HubForward = *req.HubForward
		}
		if req.Name != nil {
			c.Name = strings.TrimSpace(*req.Name)
		}
		if req.PublicIP != nil {
			c.PublicIP = strings.TrimSpace(*req.PublicIP)
		}
		return nil
	})
	if err != nil {
		writeAPIError(w, r, "E-CLUSTER-06", err.Error())
		return
	}
	writeJSON(w, map[string]any{"status": "ok"})
}

// ---- CLI ----

func cliCluster(args []string) int {
	sub := "status"
	if len(args) > 0 {
		sub = args[0]
	}
	if sub == "reset" { // uninstall: works even when panel.json is gone
		if v := os.Getenv("GRE_PANEL_DIR"); v != "" {
			configDir = v
		}
		lbClearRules(lbChainsIn(readFileString(lbRulesFile())))
		lbClearLegacyV1()
		_ = lbEnsureAddrs(nil)
		fmt.Println("[OK] Cluster rules and private addresses removed; the panel puts them back on start while pools exist.")
		return 0
	}
	// the panel's port and the license (join codes, validation)
	if !cliStart() {
		return 1
	}
	cfg := loadClusterConfig()
	switch sub {
	case "status":
		fmt.Printf("Hub:          %s (%s)\n", cfg.Name, cfg.NodeID)
		fmt.Printf("Health check: every %d ms, out after %d failures, back after %d passes\n", cfg.Health.IntervalMs, cfg.Health.Fall, cfg.Health.Rise)
		if len(cfg.Pools) == 0 {
			fmt.Println("Pools:        none (gre-panel cluster pool add PORT)")
		}
		for _, p := range cfg.Pools {
			state := ""
			if p.Disabled {
				state = " [disabled]"
			}
			if p.Check != "" {
				state += fmt.Sprintf(" [service check %s every %s]", p.Check, lbCheckEvery(p))
			}
			if p.NoFailback && p.Mode == lbFailover {
				state += " [no automatic failback]"
			}
			fmt.Printf("%s: %s%s\n", poolLabel(p), p.Mode, state)
			for _, m := range p.Members {
				extra := ""
				if m.Drain {
					extra += " drained"
				}
				if m.Backup {
					extra += " backup"
				}
				if m.MaxConn > 0 {
					extra += fmt.Sprintf(" max %d connections", m.MaxConn)
				}
				fmt.Printf("  - link %d  weight %d  priority %d  port %d%s\n", m.Link, max(m.Weight, 1), m.Priority, memberPort(p, m), extra)
			}
		}
		fmt.Printf("Iran hubs:    %d\n", len(cfg.Hubs))
		for _, h := range cfg.Hubs {
			fmt.Printf("  - %s (%s) %s\n", h.Name, h.ID, h.PublicIP)
		}
		if cfg.DNS.Enabled {
			fmt.Printf("DNS failover: %s on %s\n", cfg.DNS.Name, cfg.DNS.Provider)
		}
		fmt.Println("Live state:   the panel's Cluster tab, or: curl the panel's /api/cluster/status")
		return 0
	case "pool":
		return cliClusterPool(args[1:])
	case "member":
		return cliClusterMember(args[1:])
	case "rules":
		data, err := os.ReadFile(lbRulesFile())
		if err != nil {
			fmt.Println("No cluster rules applied.")
			return 0
		}
		fmt.Print(string(data))
		return 0
	case "events":
		for _, e := range clusterEvents(40) {
			fmt.Printf("%s  %-5s  %s\n", e.At, e.Level, e.Text)
		}
		return 0
	case "join-code":
		code, err := meshJoinCode(cfg)
		if err != nil {
			fmt.Println("[!]", err)
			return 1
		}
		fmt.Println(code)
		return 0
	case "add-hub":
		if len(args) < 2 {
			fmt.Println("Usage: gre-panel cluster add-hub <join code from the other hub>")
			return 1
		}
		h, err := meshAddHub(args[1])
		if err != nil {
			fmt.Println("[!]", err)
			return 1
		}
		fmt.Printf("[OK] Linked with hub %s (%s).\n", h.Name, h.PublicIP)
		return 0
	case "remove-hub":
		if len(args) < 2 {
			fmt.Println("Usage: gre-panel cluster remove-hub <id>")
			return 1
		}
		if !meshRemoveHub(args[1]) {
			fmt.Println("[!] No hub with id", args[1])
			return 1
		}
		fmt.Println("[OK] Hub removed.")
		return 0
	}
	fmt.Println("Usage: gre-panel cluster [status | pool add|set|rm|mode|enable|disable|failback | member add|rm|drain|resume|set | rules | events | join-code | add-hub CODE | remove-hub ID | reset]")
	return 1
}

func readFileString(p string) string {
	b, _ := os.ReadFile(p)
	return string(b)
}

// cliFlags parses "--key value" pairs after positional args.
func cliFlags(args []string) (pos []string, flags map[string]string) {
	flags = map[string]string{}
	for i := 0; i < len(args); i++ {
		if strings.HasPrefix(args[i], "--") && i+1 < len(args) {
			flags[strings.TrimPrefix(args[i], "--")] = args[i+1]
			i++
			continue
		}
		pos = append(pos, args[i])
	}
	return pos, flags
}

// lbParsePorts reads "443", "443,8443" or "2000-2005" (at most 50 ports).
func lbParsePorts(s string) ([]int, error) {
	var out []int
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		lo, hi, isRange := strings.Cut(f, "-")
		a, err1 := strconv.Atoi(strings.TrimSpace(lo))
		b := a
		var err2 error
		if isRange {
			b, err2 = strconv.Atoi(strings.TrimSpace(hi))
		}
		if err1 != nil || err2 != nil || a < 1 || b > 65535 || b < a {
			return nil, fmt.Errorf("%q is not a port or a range of ports", f)
		}
		for p := a; p <= b; p++ {
			if !hasInt(out, p) {
				out = append(out, p)
			}
		}
		if len(out) > 50 {
			return nil, fmt.Errorf("at most 50 ports at once")
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no port given")
	}
	return out, nil
}

// cliYes reads yes/no flags.
func cliYes(s string) (bool, bool) {
	switch strings.ToLower(s) {
	case "yes", "y", "on", "true", "1":
		return true, true
	case "no", "n", "off", "false", "0":
		return false, true
	}
	return false, false
}

// cliPoolOptions applies --mode --name --check --check-every --no-failback.
func cliPoolOptions(p *LBPool, fl map[string]string) error {
	if v, ok := fl["mode"]; ok {
		p.Mode = v
	}
	if v, ok := fl["name"]; ok {
		p.Name = v
	}
	if v, ok := fl["check"]; ok {
		p.Check = strings.ToLower(v)
		if p.Check == "off" || p.Check == "none" {
			p.Check = ""
		}
	}
	if v, ok := fl["check-every"]; ok {
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("--check-every takes seconds")
		}
		p.CheckEvery = n
	}
	if v, ok := fl["no-failback"]; ok {
		b, valid := cliYes(v)
		if !valid {
			return fmt.Errorf("--no-failback takes yes or no")
		}
		p.NoFailback = b
	}
	return nil
}

func cliClusterPool(args []string) int {
	usage := "Usage: gre-panel cluster pool add PORTS [--proto tcp|udp|both] [--mode " + strings.ReplaceAll(lbModes, ", ", "|") + "]\n" +
		"            [--links 0,2,3] [--name N] [--check tcp|off] [--check-every SEC] [--no-failback yes|no]\n" +
		"         PORTS: 443, or 443,8443, or 2000-2005 (one pool per port)\n" +
		"       gre-panel cluster pool set PORT [--mode M] [--name N] [--check tcp|off] [--check-every SEC] [--no-failback yes|no]\n" +
		"       gre-panel cluster pool rm|enable|disable|failback PORT [--proto P]\n" +
		"       gre-panel cluster pool mode PORT MODE [--proto P]"
	pos, fl := cliFlags(args)
	if len(pos) < 2 {
		fmt.Println(usage)
		return 1
	}
	proto := fl["proto"]
	if pos[0] == "add" {
		ports, err := lbParsePorts(pos[1])
		if err != nil {
			fmt.Println("[!]", err)
			return 1
		}
		links := lbLinksFrom(directSnapshot())
		lbSnapshotOverride(links)
		c := loadClusterConfig()
		for _, port := range ports {
			p := LBPool{Port: port, Proto: proto, Mode: lbFailover}
			if p.Proto == "" {
				p.Proto = "tcp"
			}
			if err := cliPoolOptions(&p, fl); err != nil {
				fmt.Println("[!]", err)
				return 1
			}
			if s := fl["links"]; s != "" {
				for _, f := range strings.Split(s, ",") {
					id, err := strconv.Atoi(strings.TrimSpace(f))
					if err != nil {
						fmt.Println("[!] --links takes link ids: 0 is the main tunnel, N is peer N")
						return 1
					}
					p.Members = append(p.Members, LBMember{Link: id, Weight: 1, Priority: len(p.Members)})
				}
			} else {
				for _, l := range links {
					if hasInt(l.Ports, port) {
						p.Members = append(p.Members, LBMember{Link: l.ID, Weight: 1, Priority: len(p.Members)})
					}
				}
			}
			normMembers(&p, links)
			if code, msg := validatePool(c, p, -1); code != "" {
				fmt.Printf("[!] port %d: %s\n", port, msg)
				return 1
			}
			c.Pools = append(c.Pools, p)
			fmt.Printf("[OK] %s: %s, %d members.\n", poolLabel(p), p.Mode, len(p.Members))
		}
		sort.Slice(c.Pools, func(i, j int) bool { return c.Pools[i].Port < c.Pools[j].Port })
		if err := saveClusterConfig(c); err != nil {
			fmt.Println("[!]", err)
			return 1
		}
		fmt.Println("The panel applies it within a second.")
		return 0
	}
	port, err := strconv.Atoi(pos[1])
	if err != nil {
		fmt.Println(usage)
		return 1
	}
	switch pos[0] {
	case "rm", "enable", "disable", "mode", "set", "failback":
	default:
		fmt.Println(usage)
		return 1
	}
	if pos[0] == "mode" {
		if len(pos) < 3 || !lbModeOK(pos[2]) {
			fmt.Println("[!] Mode must be " + lbModes + ".")
			return 1
		}
		fl["mode"] = pos[2]
	}
	lbSnapshotOverride(lbLinksFrom(directSnapshot()))
	c := loadClusterConfig()
	idx := -1
	for i, p := range c.Pools {
		if p.Port == port && (proto == "" || p.Proto == proto) {
			idx = i
		}
	}
	if idx < 0 {
		fmt.Println("[!] No pool on port", port)
		return 1
	}
	p := c.Pools[idx]
	switch pos[0] {
	case "rm":
		c.Pools = append(c.Pools[:idx], c.Pools[idx+1:]...)
		clusterEventf("info", "%s deleted (CLI).", poolLabel(p))
	case "enable", "disable":
		c.Pools[idx].Disabled = pos[0] == "disable"
	case "failback":
		c.Pools[idx].Failback++
		clusterEventf("info", "%s: failback asked (CLI).", poolLabel(p))
	case "mode", "set":
		if err := cliPoolOptions(&p, fl); err != nil {
			fmt.Println("[!]", err)
			return 1
		}
		if code, msg := validatePool(c, p, idx); code != "" {
			fmt.Println("[!]", msg)
			return 1
		}
		c.Pools[idx] = p
	}
	if err := saveClusterConfig(c); err != nil {
		fmt.Println("[!]", err)
		return 1
	}
	fmt.Println("[OK] Saved.")
	return 0
}

func cliClusterMember(args []string) int {
	usage := "Usage: gre-panel cluster member add|rm|drain|resume|set PORT LINK [--weight N] [--priority N] [--port N]\n" +
		"            [--backup yes|no] [--max-conn N] [--proto P]"
	pos, fl := cliFlags(args)
	if len(pos) < 3 {
		fmt.Println(usage)
		return 1
	}
	port, err1 := strconv.Atoi(pos[1])
	link, err2 := strconv.Atoi(pos[2])
	if err1 != nil || err2 != nil {
		fmt.Println(usage)
		return 1
	}
	action := map[string]string{"rm": "remove"}[pos[0]]
	if action == "" {
		action = pos[0]
	}
	q := lbMemberReq{Port: port, Proto: fl["proto"], Link: link, Action: action}
	q.Weight, _ = strconv.Atoi(fl["weight"])
	q.LinkPort, _ = strconv.Atoi(fl["port"])
	for _, k := range []string{"priority", "max-conn"} {
		s, ok := fl[k]
		if !ok {
			continue
		}
		n, err := strconv.Atoi(s)
		if err != nil {
			fmt.Println(usage)
			return 1
		}
		if k == "priority" {
			q.Priority = &n
		} else {
			q.MaxConn = &n
		}
	}
	if s, ok := fl["backup"]; ok {
		b, valid := cliYes(s)
		if !valid {
			fmt.Println(usage)
			return 1
		}
		q.Backup = &b
	}
	lbSnapshotOverride(lbLinksFrom(directSnapshot()))
	if code, msg := lbMemberChange(q); code != "" {
		if msg == "" {
			msg = errCatalog[code].Msg
		}
		fmt.Println("[!]", msg)
		return 1
	}
	fmt.Println("[OK] Saved.")
	return 0
}

// directSnapshot builds a snapshot without the background collector (CLI).
func directSnapshot() *HubSnapshot {
	return buildSnapshot()
}

// lbSnapshotOverride makes the CLI's validation see the links it just listed.
func lbSnapshotOverride(links []lbLink) {
	s := &HubSnapshot{}
	for _, l := range links {
		pl := peerLive{peerRecord: peerRecord{ID: l.ID, Name: l.Name, RemotePub: l.Remote, FrpPort: l.CtrlPort,
			FrpsSvc: l.Svc, Ports: l.Ports, PeerGre: l.PeerGre, NoGre: l.NoGre}}
		if l.ID == mainTunnelID {
			s.Main = &pl
			s.Local.FrpSvc = l.Svc
		} else {
			s.Peers = append(s.Peers, pl)
		}
	}
	lbSnapshot = func() *HubSnapshot { return s }
}
