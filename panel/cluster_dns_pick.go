package main

// Which hub writes the domain, and which hubs it points to.
//
// Writer: every hub with DNS failover on tells in its heartbeat whether it can
// reach the provider. The writer is the best of the hubs that answer: one that
// can reach the provider first, then the controller, then the lowest id. All
// hubs use the same rule on the same beats, so exactly one writes; when it is
// cut off, or only its way to Cloudflare is, the next one goes on.
//
// Where the domain points:
//   - failover: the first working hub of the order. Back to an earlier one
//     only when it has worked for dnsFailbackAfter.
//   - balance, equal shares: every working hub. Plain DNS gives no promise
//     about who gets more users (a resolver keeps one answer for thousands of
//     phones, phones sort addresses their own way, a VPN session stays for
//     hours), so the traffic each hub really carries is measured, and while it
//     is off the shares the record points to one hub at a time, longer to the
//     ones below their share.
//   - balance, different shares: one hub at a time always, by the shares,
//     corrected the same way.

import (
	"errors"
	"math"
	"net"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const (
	dnsBalance  = "balance"
	dnsFailover = "failover"
)

func dnsMode(d DNSConfig) string {
	if d.Mode == dnsFailover {
		return dnsFailover
	}
	return dnsBalance
}

// ---- the writer ----

// dnsCand is a hub that may write the record.
type dnsCand struct {
	ID      string
	Master  bool
	NoReach bool // it cannot reach the provider
}

// dnsPickWriter is the one rule every hub uses.
func dnsPickWriter(cs []dnsCand) string {
	var best *dnsCand
	for i := range cs {
		x := &cs[i]
		switch {
		case best == nil:
		case x.NoReach != best.NoReach:
			if x.NoReach {
				continue
			}
		case x.Master != best.Master:
			if !x.Master {
				continue
			}
		case x.ID >= best.ID:
			continue
		}
		best = x
	}
	if best == nil {
		return ""
	}
	return best.ID
}

// dnsWriter is the hub that writes the record now, as this hub sees it.
func dnsWriter(c ClusterConfig) string {
	cs := []dnsCand{{ID: c.NodeID, Master: c.DNS.Master, NoReach: dnsReachDown(c.DNS)}}
	meshMu.Lock()
	for _, h := range c.Hubs {
		st := meshState[h.ID]
		if st == nil || st.Beat.DNS != c.DNS.Name {
			continue
		}
		// A master that stopped answering a moment ago may be back at once: the
		// others wait dnsTakeoverAfter before they write in its place.
		if st.Up || (st.Beat.Master && !c.DNS.Master && time.Since(st.LastSeen) < dnsTakeoverAfter) {
			cs = append(cs, dnsCand{ID: h.ID, Master: st.Beat.Master, NoReach: st.Beat.DNSDown})
		}
	}
	meshMu.Unlock()
	return dnsPickWriter(cs)
}

// dnsLeading: this hub wrote the record last and still leads (its beat then
// carries the record, so the others know it when they take over).
var dnsLeading atomic.Bool

// dnsAdoptRecords: a hub that does not write keeps what the writer's beat says
// the record holds, to show it and to start from it when it takes over.
func dnsAdoptRecords(c ClusterConfig, writer string) ClusterConfig {
	meshMu.Lock()
	var recs []string
	if st := meshState[writer]; st != nil && st.Up {
		recs = append(recs, st.Beat.DNSRecs...)
	}
	meshMu.Unlock()
	known := dnsKnownIPs(c)
	owned := c.DNS.Owned
	for ip := range known {
		if !slices.Contains(owned, ip) && len(owned) < 64 {
			owned = append(append([]string(nil), owned...), ip)
		}
	}
	if (len(recs) == 0 || slices.Equal(recs, c.DNS.Records)) && len(owned) == len(c.DNS.Owned) {
		return c
	}
	if n, err := updateClusterConfig(func(x *ClusterConfig) error {
		if len(recs) > 0 {
			x.DNS.Records = recs
		}
		x.DNS.Owned = owned
		return nil
	}); err == nil {
		return n
	}
	return c
}

// dnsKnownIPs are the addresses of this cluster's hubs as far as this hub
// knows: the one a hub was linked with and the one its beat reports now.
func dnsKnownIPs(c ClusterConfig) map[string]bool {
	out := map[string]bool{}
	add := func(ips ...string) {
		for _, ip := range ips {
			if ip != "" {
				out[ip] = true
			}
		}
	}
	self := meshSelfBeat(c)
	add(self.IP, self.IP6)
	meshMu.Lock()
	defer meshMu.Unlock()
	for _, h := range c.Hubs {
		add(h.PublicIP)
		if st := meshState[h.ID]; st != nil {
			add(st.Beat.IP, st.Beat.IP6)
		}
	}
	return out
}

// hubIP4 is a hub's address for users: the one its beat reports (it may have
// changed since the hubs were linked), else the one it was linked with.
func hubIP4(h HubPeer, st *hubRT) string {
	if st != nil && isIPv4(st.Beat.IP) {
		return st.Beat.IP
	}
	return h.PublicIP
}

// ---- can this hub reach the provider ----

// reachErr is an error on the way to the provider (not the provider's answer
// about the settings): another hub may still get through.
type reachErr struct{ error }

func (e reachErr) Unwrap() error { return e.error }

const (
	dnsReachFails = 2 // failures in a row before another hub takes over
	dnsReachEvery = 60 * time.Second
	dnsReachRetry = 20 * time.Second
)

var dnsReach struct {
	sync.Mutex
	key   string
	fails int
	down  bool
	err   string
	at    time.Time
	busy  bool
}

func dnsReachKey(d DNSConfig) string {
	k := d.Provider + "|" + d.Name + "|" + d.URL + "|" + dnsRoute(d)
	if d.TunnelID != nil {
		k += "|" + strconv.Itoa(*d.TunnelID)
	}
	return k
}

func dnsReachDown(d DNSConfig) bool {
	dnsReach.Lock()
	defer dnsReach.Unlock()
	return dnsReach.down && dnsReach.key == dnsReachKey(d)
}

// dnsReachNote takes in how a call to the provider went.
func dnsReachNote(d DNSConfig, err error) {
	var re reachErr
	bad := errors.As(err, &re)
	dnsReach.Lock()
	if k := dnsReachKey(d); dnsReach.key != k {
		dnsReach.key, dnsReach.fails, dnsReach.down, dnsReach.err = k, 0, false, ""
	}
	was := dnsReach.down
	dnsReach.at = time.Now()
	if bad {
		dnsReach.fails++
		dnsReach.err = err.Error()
		dnsReach.down = dnsReach.fails >= dnsReachFails
	} else {
		dnsReach.fails, dnsReach.down, dnsReach.err = 0, false, ""
	}
	now := dnsReach.down
	dnsReach.Unlock()
	switch {
	case now && !was:
		clusterEventf("warn", "DNS failover: this hub cannot reach the provider (%v): another hub that can writes the domain.", err)
	case was && !now:
		clusterEventf("info", "DNS failover: this hub reaches the provider again.")
	}
}

// dnsReachGo runs the check (tests run it in place).
var dnsReachGo = func(f func()) { go f() }

// dnsReachTick checks, on a hub that does not write, whether it could.
func dnsReachTick(d DNSConfig) {
	dnsReach.Lock()
	every := dnsReachEvery
	if dnsReach.fails > 0 {
		every = dnsReachRetry
	}
	due := !dnsReach.busy && (time.Since(dnsReach.at) >= every || dnsReach.key != dnsReachKey(d))
	if due {
		dnsReach.busy = true
	}
	dnsReach.Unlock()
	if !due {
		return
	}
	dnsReachGo(func() {
		err := dnsReachProbe(d)
		dnsReachNote(d, err)
		dnsReach.Lock()
		dnsReach.busy = false
		dnsReach.Unlock()
	})
}

// dnsReachProbe is one check: Cloudflare is asked for the zone, a webhook's
// host is dialled (its URL is called only to write).
var dnsReachProbe = func(d DNSConfig) error {
	if d.Provider != "webhook" {
		_, err := cfZone(d, d.Name)
		return err
	}
	u, err := url.Parse(d.URL)
	if err != nil {
		return nil
	}
	port := u.Port()
	if port == "" {
		port = map[string]string{"http": "80"}[u.Scheme]
		if port == "" {
			port = "443"
		}
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(u.Hostname(), port), 8*time.Second)
	if err != nil {
		return reachErr{redactErr(err, d.Token)}
	}
	conn.Close()
	return nil
}

// ---- failover order ----

// dnsFailbackAfter: how long a hub earlier in the order must have worked
// before users move back to it.
var dnsFailbackAfter = 60 * time.Second

// dnsSince is since when each hub works (DNS loop only).
var dnsSince = map[string]time.Time{}

func dnsTrackWorking(groups []dnsGroup, now time.Time) {
	seen := map[string]bool{}
	for _, g := range groups {
		seen[g.Key] = true
		if _, ok := dnsSince[g.Key]; !ok {
			dnsSince[g.Key] = now
		}
	}
	for k := range dnsSince {
		if !seen[k] {
			delete(dnsSince, k)
		}
	}
}

// dnsOrdered is every hub id in the failover order; hubs the order does not
// name follow by id.
func dnsOrdered(c ClusterConfig) []string {
	all := []string{c.NodeID}
	for _, h := range c.Hubs {
		all = append(all, h.ID)
	}
	sort.Strings(all)
	var out []string
	for _, id := range c.DNS.Order {
		if slices.Contains(all, id) && !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	for _, id := range all {
		if !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	return out
}

// dnsFailoverPick is the hub the record points to in failover mode.
func dnsFailoverPick(c ClusterConfig, groups []dnsGroup, now time.Time) *dnsGroup {
	byID := map[string]*dnsGroup{}
	var cur *dnsGroup
	for i := range groups {
		g := &groups[i]
		byID[g.Key] = g
		for _, ip := range g.IPs {
			// only when the record points to this hub alone: a record left by
			// the balance mode holds several
			if len(c.DNS.Records) > 0 && slices.Contains(c.DNS.Records, ip) && dnsAllOf(c.DNS.Records, g.IPs) {
				cur = g
			}
		}
	}
	for _, id := range dnsOrdered(c) {
		g := byID[id]
		if g == nil {
			continue
		}
		if cur == nil || g == cur || now.Sub(dnsSince[id]) >= dnsFailbackAfter {
			return g
		}
	}
	return cur
}

func dnsAllOf(have, of []string) bool {
	for _, x := range have {
		if !slices.Contains(of, x) {
			return false
		}
	}
	return true
}

// ---- measured shares ----

const (
	dnsLoadTau   = 5 * time.Minute // how slowly the measured traffic follows
	dnsLoadReady = 3 * time.Minute // measured at least this long before it counts
	dnsLoadFloor = 64 << 10        // bytes/s of all hubs together; below it a share means nothing
	dnsOffStart  = 0.03            // correct when a hub is this far off its share
	dnsOffKeep   = 6 * time.Hour   // and go on for this long after it last was
	dnsStuckWait = 30 * time.Minute
	dnsStuckHold = 2 * time.Hour
)

type dnsLoad struct {
	bps         float64
	first, last time.Time
}

type dnsStuckT struct {
	since time.Time // corrected in its favour since
	share float64   // its share then
	until time.Time // no correction before this
}

// dnsBal is the balance loop's state (its own lock: the view reads it).
var dnsBal struct {
	sync.Mutex
	load   map[string]*dnsLoad
	active bool
	offAt  time.Time // when a hub was last off its share
	stuck  map[string]*dnsStuckT
}

// dnsLoadSample takes in the traffic each working hub reports.
func dnsLoadSample(c ClusterConfig, groups []dnsGroup, now time.Time) {
	self := meshSelfBeat(c)
	got := map[string]float64{}
	meshMu.Lock()
	for _, g := range groups {
		b := &self
		if g.Key != c.NodeID {
			if st := meshState[g.Key]; st != nil && st.Up {
				b = &st.Beat
			} else {
				continue
			}
		}
		if b.Load != nil && *b.Load >= 0 {
			got[g.Key] = *b.Load
		}
	}
	meshMu.Unlock()
	dnsBal.Lock()
	defer dnsBal.Unlock()
	if dnsBal.load == nil {
		dnsBal.load = map[string]*dnsLoad{}
	}
	for id, v := range got {
		l := dnsBal.load[id]
		if l == nil || now.Sub(l.last) > time.Minute {
			dnsBal.load[id] = &dnsLoad{bps: v, first: now, last: now}
			continue
		}
		// the average settles as fast as it has data (a plain mean at first)
		tau := min(dnsLoadTau, max(now.Sub(l.first), time.Second))
		a := 1 - math.Exp(-float64(now.Sub(l.last))/float64(tau))
		l.bps += a * (v - l.bps)
		l.last = now
	}
	for id, l := range dnsBal.load {
		if now.Sub(l.last) > time.Minute {
			delete(dnsBal.load, id)
		}
	}
}

// dnsActual is the share of the traffic each working hub really carries; ok
// only when every one of them is measured long enough and there is traffic.
func dnsActual(keys []string, now time.Time) (share map[string]float64, ok bool) {
	dnsBal.Lock()
	defer dnsBal.Unlock()
	return dnsActualLocked(keys, now)
}

func dnsActualLocked(keys []string, now time.Time) (map[string]float64, bool) {
	if len(keys) < 2 {
		return nil, false
	}
	sum := 0.0
	for _, k := range keys {
		l := dnsBal.load[k]
		if l == nil || now.Sub(l.last) > time.Minute || l.last.Sub(l.first) < dnsLoadReady {
			return nil, false
		}
		sum += l.bps
	}
	if sum < dnsLoadFloor {
		return nil, false
	}
	out := map[string]float64{}
	for _, k := range keys {
		out[k] = dnsBal.load[k].bps / sum
	}
	return out, true
}

// dnsCorrect gives the hubs the weights that bring their measured shares to
// the wanted ones; active is false while they are close enough (or nothing can
// be measured) and the groups come back as they are.
func dnsCorrect(groups []dnsGroup, now time.Time) (out []dnsGroup, active bool) {
	dnsBal.Lock()
	defer dnsBal.Unlock()
	keys, sum := make([]string, 0, len(groups)), 0.0
	for _, g := range groups {
		keys = append(keys, g.Key)
		sum += float64(g.Weight)
	}
	share, ok := dnsActualLocked(keys, now)
	if !ok {
		dnsBal.active, dnsBal.stuck = false, nil
		return groups, false
	}
	off := 0.0
	for _, g := range groups {
		off = max(off, math.Abs(share[g.Key]-float64(g.Weight)/sum))
	}
	// One address at a time also takes away the cause (phones and resolvers
	// that like one of several addresses), so it goes on for a while when the
	// shares are right: back to all addresses at once, they would drift again.
	if off >= dnsOffStart {
		dnsBal.active, dnsBal.offAt = true, now
	} else if now.Sub(dnsBal.offAt) >= dnsOffKeep {
		dnsBal.active = false
	}
	if !dnsBal.active {
		dnsBal.stuck = nil
		return groups, false
	}
	if dnsBal.stuck == nil {
		dnsBal.stuck = map[string]*dnsStuckT{}
	}
	held := false
	for _, g := range groups {
		target, s := float64(g.Weight)/sum, share[g.Key]
		st := dnsBal.stuck[g.Key]
		if s >= target/4 {
			delete(dnsBal.stuck, g.Key)
			continue
		}
		switch {
		case st == nil:
			dnsBal.stuck[g.Key] = &dnsStuckT{since: now, share: s}
		case now.Before(st.until):
			held = true
		case !st.until.IsZero(): // waited: try again
			dnsBal.stuck[g.Key] = &dnsStuckT{since: now, share: s}
		case now.Sub(st.since) >= dnsStuckWait:
			if s-st.share < 0.02 {
				// The domain points to it and still nobody comes: its address or
				// ports may be blocked for users. Sending it even more would
				// only cut more of them off.
				st.until = now.Add(dnsStuckHold)
				held = true
				clusterEventf("warn", "DNS failover: a hub gets almost no traffic though the domain points to it (%s): check that users can reach its ports.", g.IPs)
			} else {
				dnsBal.stuck[g.Key] = &dnsStuckT{since: now, share: s}
			}
		}
	}
	if held {
		return groups, false
	}
	w, total := make([]float64, len(groups)), 0.0
	for i, g := range groups {
		target := float64(g.Weight) / sum
		f := target / max(share[g.Key], target/4)
		w[i] = target * min(max(f*f, 0.2), 5)
		total += w[i]
	}
	out = make([]dnsGroup, len(groups))
	for i, g := range groups {
		out[i] = g
		// every hub keeps a tenth of its turns at least
		out[i].Weight = max(int(math.Round(1000*w[i]/total)), int(math.Round(100*float64(g.Weight)/sum)), 1)
	}
	return out, true
}

// dnsStuckIDs are the hubs held back as "users do not reach it".
func dnsStuckIDs(now time.Time) map[string]bool {
	dnsBal.Lock()
	defer dnsBal.Unlock()
	out := map[string]bool{}
	for id, s := range dnsBal.stuck {
		if now.Before(s.until) {
			out[id] = true
		}
	}
	return out
}

// dnsIPs is what the record holds for these hubs. An IPv6 address goes in only
// when every one of them has one: else all IPv6 users would go to the hub that
// has it.
func dnsIPs(groups []dnsGroup) []string {
	all6 := len(groups) > 0
	for _, g := range groups {
		all6 = all6 && slices.ContainsFunc(g.IPs, func(ip string) bool { return ipFamily(ip) == 6 })
	}
	var ips []string
	for _, g := range groups {
		only6 := !slices.ContainsFunc(g.IPs, isIPv4)
		for _, ip := range g.IPs {
			if all6 || only6 || isIPv4(ip) {
				ips = append(ips, ip)
			}
		}
	}
	sort.Strings(ips)
	return ips
}

// dnsChoose is what the record holds now, by the mode (DNS loop only).
func dnsChoose(c ClusterConfig, groups []dnsGroup, now time.Time) []string {
	if len(groups) == 0 {
		return nil
	}
	if dnsMode(c.DNS) == dnsFailover {
		g := dnsFailoverPick(c, groups, now)
		if g == nil {
			return nil
		}
		return dnsIPs([]dnsGroup{*g})
	}
	if c.DNS.Provider == "webhook" { // its receiver splits by the weights
		return dnsIPs(groups)
	}
	w, active := dnsCorrect(groups, now)
	if !active && !dnsUnequal(groups) {
		return dnsIPs(groups)
	}
	ips := dnsRotate(w, time.Duration(max(c.DNS.TTL, 60))*time.Second, now)
	sort.Strings(ips)
	return ips
}
