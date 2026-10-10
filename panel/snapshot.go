package main

// Shared hub snapshot. ONE collector goroutine builds a HubSnapshot every
// snapshotEvery and publishes it through an atomic pointer; dashboard, fleet,
// peers, status and the fleet sampler only READ it, so request cost is O(1) in
// the number of spokes and browsers and HTTP handlers never fork.
//
// Per tick the collector runs a fixed set of host commands, independent of the
// peer count: one `ss -Htin state established` (parsed once, indexed by local
// port), one `ip tunnel show`, one `ip -o -4 addr show`, one
// `systemctl is-active <all units>`, one read of /proc/net/dev, and a streaming
// count of /proc/net/{tcp,udp}[6]. Per-peer extras (active TCP connect probe
// and background ICMP) run through a bounded worker pool with hard timeouts and
// never block a tick; ICMP is refreshed at most once per minute per peer, with
// per-peer offsets, and skipped while the peer's control session is live.
//
// Callers allowed to BYPASS the snapshot (they need a fresh synchronous read
// of the host and are user-initiated or one-shot, never polled):
//   - livePeers() / localStatus(): the collector's building blocks; also used
//     right after a user action (add/remove peer, carrier switch, engine
//     switch) and by the doctor, the benchmark and the TLS port check.
//   - runAction / peerPingTarget (explicit "ping" and restart actions).
//
// Every polling reader (handleDashboard, handleFleet, handlePeersGet,
// handleStatus, the fleet sampler, watchdog/rescue port discovery) goes through
// currentSnapshot() / currentLocal().

import (
	"context"
	"hash/fnv"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// snapshotEvery and icmpEvery are vars only so the load lab can compress time.
var (
	snapshotEvery = 5 * time.Second
	icmpEvery     = 60 * time.Second
	// snapFirstWait caps the synchronous build the first request may trigger.
	snapFirstWait = 3 * time.Second
)

const (
	icmpFirstJitter  = 3 * time.Second
	icmpRepeatJitter = 5 * time.Second
	probeOKTTL       = 15 * time.Second
	probeFailTTL     = 30 * time.Second
	snapTaskTimeout  = 6 * time.Second
)

// baseUnits are the base tunnel services, in role-detection order.
var baseUnits = []string{"frps", "frpc", "backhaul-server", "backhaul-client"}

// icmpResult is one ICMP measurement; Known=false means none exists yet.
type icmpResult struct {
	OK    bool
	Ms    float64
	Known bool
}

type devCounters struct{ rx, tx uint64 }

// hostView is everything the pure builders (localStatusFrom, livePeersFrom,
// mainTunnelFrom) need from the host, collected once.
type hostView struct {
	sessions   []ssSession
	tunnelShow string
	tunnelOK   bool
	inner      map[string]string // ifname -> first inet CIDR
	active     map[string]bool   // unit -> active
	devData    string            // raw /proc/net/dev
	dev        map[string]devCounters
	flowing    map[string]bool // iface counters moved since the previous tick
	owners     map[int]int
	icmp       func(target string) icmpResult
	connect    func(id int) connectResult
}

func (v *hostView) icmpFor(target string) icmpResult {
	if target == "" || v.icmp == nil {
		return icmpResult{}
	}
	return v.icmp(target)
}

func (v *hostView) traffic(ifname string) (rx, tx *uint64) {
	c, ok := v.dev[ifname]
	if !ok {
		return nil, nil
	}
	r, t := c.rx, c.tx
	return &r, &t
}

// ---- parsing helpers ----

// parseAddrShow parses `ip -o -4 addr show`: ifname -> first inet CIDR.
func parseAddrShow(out string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		name := strings.TrimSuffix(f[1], ":")
		if i := strings.IndexByte(name, '@'); i >= 0 {
			name = name[:i]
		}
		for i := 2; i+1 < len(f); i++ {
			if f[i] == "inet" {
				if _, seen := m[name]; !seen {
					m[name] = f[i+1]
				}
				break
			}
		}
	}
	return m
}

// parseIsActive maps `systemctl is-active a b c` output (one line per unit,
// same order) onto the unit names; ok=false when the line count does not match.
func parseIsActive(units []string, out string) (map[string]bool, bool) {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != len(units) {
		return nil, false
	}
	m := make(map[string]bool, len(units))
	for i, u := range units {
		m[u] = strings.TrimSpace(lines[i]) == "active"
	}
	return m, true
}

func parseNetDev(data string) map[string]devCounters {
	m := map[string]devCounters{}
	for _, line := range strings.Split(data, "\n") {
		name, rest, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		f := strings.Fields(rest)
		if len(f) < 9 {
			continue
		}
		r, e1 := strconv.ParseUint(f[0], 10, 64)
		t, e2 := strconv.ParseUint(f[8], 10, 64)
		if e1 != nil || e2 != nil {
			continue
		}
		m[strings.TrimSpace(name)] = devCounters{r, t}
	}
	return m
}

func unitsFor(recs []peerRecord) []string {
	units := append([]string{}, baseUnits...)
	seen := map[string]bool{}
	for _, u := range units {
		seen[u] = true
	}
	for _, p := range recs {
		if p.FrpsSvc != "" && !seen[p.FrpsSvc] {
			seen[p.FrpsSvc] = true
			units = append(units, p.FrpsSvc)
		}
	}
	return units
}

func controlPortsOf(recs []peerRecord, extra ...int) []int {
	var ports []int
	for _, p := range recs {
		ports = append(ports, p.FrpPort)
	}
	return append(ports, extra...)
}

// timedStep runs one collector sub-step and records its cost for /api/selfstats.
func timedStep(name string, f func()) {
	t := time.Now()
	f()
	recordSampler("snapshot."+name, time.Since(t))
}

// collectHost gathers the per-tick host view with a fixed number of commands.
func collectHost(recs []peerRecord, prev map[string]devCounters) *hostView {
	v := &hostView{inner: map[string]string{}, active: map[string]bool{}, flowing: map[string]bool{}}
	timedStep("ss", func() {
		if out, err := runCmdTimeoutOut(5*time.Second, "ss", "-Htin", "state", "established"); err == nil {
			v.sessions = parseSS(string(out))
		}
	})
	timedStep("ip_tunnel", func() {
		if out, err := runCmdTimeout(5*time.Second, "ip", "tunnel", "show"); err == nil {
			v.tunnelShow, v.tunnelOK = string(out), true
		}
	})
	timedStep("ip_addr", func() {
		if out, err := runCmdTimeoutOut(5*time.Second, "ip", "-o", "-4", "addr", "show"); err == nil {
			v.inner = parseAddrShow(string(out))
		}
	})
	timedStep("systemctl", func() {
		units := unitsFor(recs)
		out, _ := runCmdTimeoutOut(5*time.Second, "systemctl", append([]string{"is-active"}, units...)...)
		if m, ok := parseIsActive(units, string(out)); ok {
			v.active = m
			return
		}
		for _, u := range units { // unexpected output shape: fall back to one call per unit
			o, _ := runCmdTimeoutOut(5*time.Second, "systemctl", "is-active", u)
			v.active[u] = strings.TrimSpace(string(o)) == "active"
		}
	})
	timedStep("netdev", func() {
		if b, err := os.ReadFile(filepath.Join(procRoot, "net/dev")); err == nil {
			v.devData = string(b)
			v.dev = parseNetDev(v.devData)
		}
		for name, c := range v.dev {
			if p, ok := prev[name]; ok && p != c {
				v.flowing[name] = true
			}
		}
	})
	v.owners = portOwners(controlPortsOf(recs))
	return v
}

// pingOnce is one ICMP echo with a hard timeout; ms is the wall time.
func pingOnce(target string) (bool, float64) {
	start := time.Now()
	if _, err := runCmdTimeout(4*time.Second, "ping", "-c", "1", "-W", "2", target); err != nil {
		return false, -1
	}
	return true, float64(time.Since(start).Microseconds()) / 1000
}

// directView collects a view with inline ICMP, for fresh synchronous reads
// (livePeers / localStatus). It never runs the connect probe.
func directView(recs []peerRecord) *hostView {
	v := collectHost(recs, nil)
	v.icmp = func(target string) icmpResult {
		ok, d := pingOnce(target)
		return icmpResult{OK: ok, Ms: d, Known: true}
	}
	return v
}

// mainTunnelFrom describes the base tunnel as a hub spoke, or nil when this
// machine is not an Iran hub or has no base tunnel configured.
func mainTunnelFrom(st tunnelStatus, v *hostView) *peerLive {
	if !strings.HasPrefix(st.Role, "iran") || !(st.Gre.Exists || st.FrpUp || len(st.Proxies) > 0) {
		return nil
	}
	name := "Tunnel"
	if st.RemotePub != "" {
		name = "Tunnel · " + st.RemotePub
	}
	rec := peerRecord{ID: mainTunnelID, Name: name, RemotePub: st.RemotePub, Engine: st.Engine,
		Transport: st.Transport, FrpPort: st.BindPort, Ports: st.ProxyPorts}
	l := &peerLive{peerRecord: rec, GreUp: st.Gre.Exists, FrpUp: st.FrpUp, GreInner: st.Gre.Inner}
	sig := LinkSignals{ServiceActive: st.FrpUp, GreIfUp: st.Gre.Exists}
	if st.FrpUp {
		r := controlSessionIn(v.sessions, ctrlQuery{ID: mainTunnelID, Port: st.BindPort}, v.owners)
		l.Linked, sig.Session, sig.TCPRTTms = r.Linked, r.Linked, r.RTTms
		if !r.Linked && v.connect != nil {
			if c := v.connect(mainTunnelID); c.OK {
				sig.ConnectRTTms = c.RTTms
			}
		}
	}
	if st.Gre.Inner != "" {
		l.icmpTarget = grePeerInner(st.Gre.Inner)
	}
	sig.TrafficFlowing = v.flowing["gre-tunnel"]
	l.applyHealth(sig, v.icmpFor(l.icmpTarget))
	return l
}

// ---- snapshot ----

type HubSnapshot struct {
	At      time.Time
	Seq     uint64
	BuildMs float64
	Local   tunnelStatus
	Main    *peerLive
	Peers   []peerLive
	Traffic map[string]any
	// LocalSession/LocalRTT: this machine's own tunnel session. On a hub it is
	// the main tunnel's control session; on a spoke, the outbound client
	// connection to the hub's control port.
	LocalSession bool
	LocalRTT     float64
	ActiveConns  any
	PublicIP     string
	FrpSince     string
}

// AgeMs is the snapshot age in milliseconds, -1 for the empty snapshot.
func (s *HubSnapshot) AgeMs() int64 {
	if s == nil || s.At.IsZero() {
		return -1
	}
	return time.Since(s.At).Milliseconds()
}

// All returns the main tunnel (when present) followed by the peers. The records
// are copies carrying this request's snapshot age; the snapshot stays immutable.
func (s *HubSnapshot) All() []peerLive {
	age := s.AgeMs()
	out := make([]peerLive, 0, len(s.Peers)+1)
	if s.Main != nil {
		out = append(out, *s.Main)
	}
	out = append(out, s.Peers...)
	for i := range out {
		out[i].SnapshotAgeMs = age
	}
	return out
}

// PeersAged is Peers (without the main tunnel) with the snapshot age set.
func (s *HubSnapshot) PeersAged() []peerLive {
	age := s.AgeMs()
	out := append([]peerLive(nil), s.Peers...)
	for i := range out {
		out[i].SnapshotAgeMs = age
	}
	return out
}

var (
	snapPtr      atomic.Pointer[HubSnapshot]
	snapBuilding atomic.Bool
	snapSkipped  atomic.Uint64
	snapTicks    atomic.Uint64
	snapSeq      atomic.Uint64
	snapSyncMu   sync.Mutex
	snapGaveUp   atomic.Int64 // unix nanos of the last failed first build
	snapDeb      = newHealthDebouncer()
	snapPrevDev  = struct {
		sync.Mutex
		m map[string]devCounters
	}{}
	snapPool  = newWorkPool(min(runtime.NumCPU(), 4))
	snapIcmp  = newIcmpState()
	snapProbe = newProbeState()
	snapSince = struct {
		sync.Mutex
		svc string
		val string
		at  time.Time
	}{}
)

// frpSinceCached is `systemctl show <svc> -p ActiveEnterTimestamp`, refreshed
// at most once a minute (collector only).
func frpSinceCached(svc string) string {
	if svc == "" {
		return ""
	}
	snapSince.Lock()
	defer snapSince.Unlock()
	if snapSince.svc == svc && time.Since(snapSince.at) < time.Minute {
		return snapSince.val
	}
	val := ""
	if out, err := runCmdTimeoutOut(5*time.Second, "systemctl", "show", svc, "-p", "ActiveEnterTimestamp", "--value"); err == nil {
		if s := strings.TrimSpace(string(out)); s != "" && s != "n/a" {
			val = s
		}
	}
	snapSince.svc, snapSince.val, snapSince.at = svc, val, time.Now()
	return val
}

// buildSnapshot runs one collection. It is the only place that touches the host.
func buildSnapshot() *HubSnapshot {
	t0 := time.Now()
	recs := loadPeers()
	snapPrevDev.Lock()
	prev := snapPrevDev.m
	snapPrevDev.Unlock()
	v := collectHost(recs, prev)
	snapPrevDev.Lock()
	snapPrevDev.m = v.dev
	snapPrevDev.Unlock()

	local := localStatusFrom(v)
	v.owners = portOwners(controlPortsOf(recs, local.BindPort))
	v.icmp = snapIcmp.lookup
	v.connect = snapProbe.lookup

	s := &HubSnapshot{Local: local, Seq: snapSeq.Add(1)}
	timedStep("peers", func() {
		s.Peers = livePeersFrom(v, recs)
		s.Main = mainTunnelFrom(local, v)
	})
	// Debounce: the published state only changes after healthDebounceN
	// consecutive snapshots agree. First sight of a peer publishes immediately.
	alive := map[int]bool{}
	debounce := func(l *peerLive) {
		alive[l.ID] = true
		l.HealthState, l.Reasons = snapDeb.observe(l.ID, LinkHealth{State: l.HealthState, Reasons: l.Reasons})
	}
	for i := range s.Peers {
		debounce(&s.Peers[i])
	}
	if s.Main != nil {
		debounce(s.Main)
	}
	snapDeb.prune(alive)

	s.LocalSession, s.LocalRTT = localSessionFrom(local, s.Main, v)

	timedStep("traffic", func() {
		s.Traffic = greTrafficFrom(v.devData)
		s.ActiveConns = activeConns()
	})
	s.PublicIP = detectPublicIPCached()
	s.FrpSince = frpSinceCached(local.FrpSvc)

	snapIcmp.setTargets(icmpTargets(s))
	snapProbe.schedule(time.Now(), probeQueries(s))

	s.At = time.Now()
	s.BuildMs = ms(time.Since(t0))
	recordSampler("snapshot", time.Since(t0))
	return s
}

// localSessionFrom reports this machine's own tunnel session (see HubSnapshot).
func localSessionFrom(st tunnelStatus, main *peerLive, v *hostView) (bool, float64) {
	if main != nil {
		if main.LatencyKind == "tcp" {
			return main.Linked, main.LatencyMs
		}
		return main.Linked, -1
	}
	if !st.FrpUp || st.BindPort <= 0 || st.RemotePub == "" {
		return false, -1
	}
	remote := normHost(st.RemotePub)
	var found []ssSession
	for _, c := range v.sessions {
		if c.RHost == remote && c.RPort == st.BindPort {
			found = append(found, c)
		}
	}
	return len(found) > 0, minRTT(found)
}

func icmpTargets(s *HubSnapshot) map[string]bool {
	m := map[string]bool{}
	if s.Local.Gre.Inner != "" {
		m[grePeerInner(s.Local.Gre.Inner)] = s.LocalSession
	}
	for _, l := range s.All() {
		if l.icmpTarget != "" {
			m[l.icmpTarget] = m[l.icmpTarget] || (l.FrpUp && l.Linked)
		}
	}
	return m
}

// probeQueries lists the links that need an active connect probe: service
// active, but no control session visible in ss.
func probeQueries(s *HubSnapshot) []ctrlQuery {
	var qs []ctrlQuery
	for _, l := range s.All() {
		if l.FrpUp && !l.Linked && l.FrpPort > 0 {
			q := ctrlQuery{ID: l.ID, Port: l.FrpPort, RemotePub: l.RemotePub, PeerGre: l.PeerGre}
			if l.ID == mainTunnelID {
				q.PeerGre = l.icmpTarget
			}
			qs = append(qs, q)
		}
	}
	return qs
}

// snapshotTick builds and publishes one snapshot. If the previous tick is still
// running the tick is skipped (counted), so slow hosts never pile up work.
func snapshotTick() bool {
	if !snapBuilding.CompareAndSwap(false, true) {
		snapSkipped.Add(1)
		return false
	}
	defer snapBuilding.Store(false)
	snap := buildSnapshot()
	snapPtr.Store(snap)
	snapTicks.Add(1)
	alertsOnSnapshot(snap)
	return true
}

// currentSnapshot returns the latest snapshot. Before the first one exists the
// first caller triggers one synchronous build capped at snapFirstWait; callers
// arriving meanwhile (or after a failed build, for a few seconds) get the empty
// snapshot instead of queueing up.
func currentSnapshot() *HubSnapshot {
	if s := snapPtr.Load(); s != nil {
		return s
	}
	if time.Since(time.Unix(0, snapGaveUp.Load())) < snapshotEvery {
		return &HubSnapshot{}
	}
	snapSyncMu.Lock()
	defer snapSyncMu.Unlock()
	if s := snapPtr.Load(); s != nil {
		return s
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		snapshotTick()
	}()
	select {
	case <-done:
	case <-time.After(snapFirstWait):
	}
	if s := snapPtr.Load(); s != nil {
		return s
	}
	snapGaveUp.Store(time.Now().UnixNano())
	return &HubSnapshot{}
}

// setSnapshotAgeHeader tells clients how old the data they are served is.
func setSnapshotAgeHeader(w http.ResponseWriter, s *HubSnapshot) {
	w.Header().Set("X-Snapshot-Age-Ms", strconv.FormatInt(s.AgeMs(), 10))
}

// currentLocal is the base tunnel status for display/read-only callers: the
// snapshot's copy when one exists, else a fresh read (cold start only).
func currentLocal() tunnelStatus {
	if s := snapPtr.Load(); s != nil {
		return s.Local
	}
	if s := currentSnapshot(); !s.At.IsZero() {
		return s.Local
	}
	return localStatus()
}

// startSnapshotCollector runs the single collector and the background ICMP loop
// until ctx ends.
func startSnapshotCollector(ctx context.Context) {
	go func() {
		snapshotTick()
		tk := time.NewTicker(snapshotEvery)
		defer tk.Stop()
		for {
			select {
			case <-tk.C:
				snapshotTick()
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		tk := time.NewTicker(snapshotEvery)
		defer tk.Stop()
		for {
			select {
			case now := <-tk.C:
				snapIcmp.pass(now)
			case <-ctx.Done():
				return
			}
		}
	}()
}

// ---- bounded worker pool ----

type workPool struct {
	sem  chan struct{}
	wg   sync.WaitGroup
	mu   sync.Mutex
	busy map[string]bool
}

func newWorkPool(n int) *workPool {
	return &workPool{sem: make(chan struct{}, max(n, 1)), busy: map[string]bool{}}
}

// submit queues fn under key (a key already queued or running is dropped). At
// most cap(sem) tasks run at once; each is abandoned after d.
func (p *workPool) submit(key string, d time.Duration, fn func()) {
	p.mu.Lock()
	if p.busy[key] {
		p.mu.Unlock()
		return
	}
	p.busy[key] = true
	p.mu.Unlock()
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		p.sem <- struct{}{}
		defer func() {
			<-p.sem
			p.mu.Lock()
			delete(p.busy, key)
			p.mu.Unlock()
		}()
		done := make(chan struct{})
		go func() { defer close(done); fn() }()
		select {
		case <-done:
		case <-time.After(d):
		}
	}()
}

func (p *workPool) wait() { p.wg.Wait() }

// jitter is a stable per-key offset in [0, span).
func jitter(key string, span time.Duration) time.Duration {
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	return time.Duration(h.Sum32()) % span
}

// ---- background ICMP ----

type icmpState struct {
	mu      sync.Mutex
	res     map[string]icmpResult
	due     map[string]time.Time
	targets map[string]bool // address -> control session live
}

func newIcmpState() *icmpState {
	return &icmpState{res: map[string]icmpResult{}, due: map[string]time.Time{}, targets: map[string]bool{}}
}

func (c *icmpState) lookup(target string) icmpResult {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.res[target]
}

func (c *icmpState) setTargets(m map[string]bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.targets = m
	for k := range c.res {
		if _, ok := m[k]; !ok {
			delete(c.res, k)
			delete(c.due, k)
		}
	}
}

// pass submits a ping for every target that is due and has no live session.
// Each target runs at most once per icmpEvery (+ jitter); the cached result is
// reused in between. Never called from a request path.
func (c *icmpState) pass(now time.Time) {
	c.mu.Lock()
	var due []string
	for addr, sess := range c.targets {
		if sess {
			continue
		}
		d, ok := c.due[addr]
		if !ok {
			d = now.Add(jitter(addr, icmpFirstJitter))
			c.due[addr] = d
		}
		if !now.Before(d) {
			c.due[addr] = now.Add(icmpEvery + jitter(addr, icmpRepeatJitter))
			due = append(due, addr)
		}
	}
	c.mu.Unlock()
	for _, addr := range due {
		addr := addr
		snapPool.submit("icmp:"+addr, snapTaskTimeout, func() {
			ok, d := pingOnce(addr)
			c.mu.Lock()
			c.res[addr] = icmpResult{OK: ok, Ms: d, Known: true}
			c.mu.Unlock()
		})
	}
}

// ---- active connect probe cache ----

type probeEntry struct {
	r  connectResult
	at time.Time
}

type probeState struct {
	mu  sync.Mutex
	res map[int]probeEntry
}

func newProbeState() *probeState { return &probeState{res: map[int]probeEntry{}} }

func (c *probeState) lookup(id int) connectResult {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.res[id].r
}

// schedule queues a connect probe for each query whose cached result is stale.
func (c *probeState) schedule(now time.Time, qs []ctrlQuery) {
	keep := map[int]bool{}
	for _, q := range qs {
		keep[q.ID] = true
	}
	c.mu.Lock()
	for id := range c.res {
		if !keep[id] {
			delete(c.res, id)
		}
	}
	var stale []ctrlQuery
	for _, q := range qs {
		e, ok := c.res[q.ID]
		ttl := probeFailTTL
		if e.r.OK {
			ttl = probeOKTTL
		}
		if !ok || now.Sub(e.at) >= ttl {
			stale = append(stale, q)
		}
	}
	c.mu.Unlock()
	for _, q := range stale {
		q := q
		snapPool.submit("probe:"+strconv.Itoa(q.ID), snapTaskTimeout, func() {
			r := connectProbe(q)
			c.mu.Lock()
			c.res[q.ID] = probeEntry{r, time.Now()}
			c.mu.Unlock()
		})
	}
}

// ---- self stats ----

type snapStatsJSON struct {
	Ready        bool    `json:"ready"`
	At           string  `json:"at,omitempty"`
	AgeMs        int64   `json:"age_ms"`
	BuildMs      float64 `json:"last_build_ms"`
	Ticks        uint64  `json:"ticks"`
	SkippedTicks uint64  `json:"skipped_ticks"`
	Building     bool    `json:"building"`
}

func snapshotStats() snapStatsJSON {
	st := snapStatsJSON{AgeMs: -1, Ticks: snapTicks.Load(), SkippedTicks: snapSkipped.Load(), Building: snapBuilding.Load()}
	if s := snapPtr.Load(); s != nil {
		st.Ready, st.At, st.AgeMs, st.BuildMs = true, s.At.UTC().Format(time.RFC3339), s.AgeMs(), s.BuildMs
	}
	return st
}

// resetSnapshotState clears all collector state (tests).
func resetSnapshotState() {
	snapPool.wait()
	snapPtr.Store(nil)
	snapGaveUp.Store(0)
	snapDeb = newHealthDebouncer()
	snapIcmp = newIcmpState()
	snapProbe = newProbeState()
	snapPrevDev.Lock()
	snapPrevDev.m = nil
	snapPrevDev.Unlock()
	snapSince.Lock()
	snapSince.svc, snapSince.val = "", ""
	snapSince.Unlock()
	lastRemote.Lock()
	lastRemote.m = map[int]string{}
	lastRemote.Unlock()
	snapTicks.Store(0)
	snapSkipped.Store(0)
}
