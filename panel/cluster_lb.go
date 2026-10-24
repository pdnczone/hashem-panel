package main

// Cluster pools: one public port on this Iran hub served by several foreign
// servers. Each member link's relay (frps / backhaul-server) binds its public
// ports to a private address on the hashem-lb dummy interface instead of
// 0.0.0.0, and kernel DNAT sends each new connection to a healthy member. The
// client's real address reaches the relay (PROXY protocol keeps working), and
// nothing is copied in user space, so a panel restart never drops traffic.
//
// Everything that decides what the kernel does is pure (lbPlanPools,
// lbRulesText, frpsWithBind, backhaulWithBind) and covered by tests; the
// apply functions below only hand the result to iptables-restore and ip.

import (
	"fmt"
	"hash/fnv"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	lbNet    = "169.254.77.0/24"
	lbIface  = "hashem-lb"
	lbChain  = "HASHEM-LB"
	lbEntry  = "HASHEM-LB-ENTRY"
	lbFilter = "HASHEM-LB-FILTER"
	lbPost   = "HASHEM-LB-POST"
	lbFwd    = "HASHEM-LB-FWD"
	// sticky mode spreads users by the low 6 bits of their IPv4 address
	lbBuckets = 64
)

// Pool modes.
const (
	lbFailover = "failover" // all traffic to the first healthy member by priority
	lbBalance  = "balance"  // each new connection to a member, by weight
	lbSticky   = "sticky"   // each user (source IP) always to the same member, by weight
	lbLatency  = "latency"  // all traffic to the healthy member with the lowest latency
	lbLeast    = "least"    // new connections to the members with the fewest open ones, by weight
)

func lbModeOK(m string) bool {
	return m == lbFailover || m == lbBalance || m == lbSticky || m == lbLatency || m == lbLeast
}

// lbModes lists the modes for messages.
const lbModes = "failover, balance, sticky, latency or least"

func lbProtoOK(p string) bool { return p == "tcp" || p == "udp" || p == "both" }

func lbProtos(p string) []string {
	if p == "both" {
		return []string{"tcp", "udp"}
	}
	return []string{p}
}

// lbAddrFor is the private address the relay unit svc binds its public ports
// to: the main tunnel's relay (frps / backhaul-server) gets .1, peer N's
// (frps-N / backhaul-server-N) gets .N+1. hashem.sh derives the same address.
func lbAddrFor(svc string) string {
	switch svc {
	case "frps", "backhaul-server":
		return "169.254.77.1"
	}
	for _, pre := range []string{"frps-", "backhaul-server-"} {
		if !strings.HasPrefix(svc, pre) {
			continue
		}
		if n, err := strconv.Atoi(strings.TrimPrefix(svc, pre)); err == nil && n >= 1 && n <= 250 {
			return fmt.Sprintf("169.254.77.%d", n+1)
		}
	}
	return ""
}

// lbConfFor is the relay config file of unit svc and its engine.
func lbConfFor(svc string) (path, engine string) {
	switch {
	case svc == "frps":
		return filepath.Join(frpDir, "frps.toml"), "frp"
	case strings.HasPrefix(svc, "frps-"):
		return filepath.Join(frpDir, svc+".toml"), "frp"
	case svc == "backhaul-server":
		return filepath.Join(backhaulDir, "config.toml"), "backhaul"
	case strings.HasPrefix(svc, "backhaul-server-"):
		return filepath.Join(backhaulDir, "server-"+strings.TrimPrefix(svc, "backhaul-server-")+".toml"), "backhaul"
	}
	return "", ""
}

// ---- binding a relay to its private address ----

// frpsWithBind returns the frps config with proxyBindAddr set to addr, or
// removed when addr is "". It goes after bindPort (top level), never inside a
// table.
func frpsWithBind(conf, addr string) string {
	lines := strings.Split(conf, "\n")
	out := make([]string, 0, len(lines)+1)
	at, afterAddr := -1, -1
	for _, l := range lines {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "proxyBindAddr") && strings.Contains(t, "=") {
			continue
		}
		out = append(out, l)
		if !strings.Contains(t, "=") {
			continue
		}
		if at < 0 && strings.HasPrefix(t, "bindPort") {
			at = len(out)
		}
		if afterAddr < 0 && strings.HasPrefix(t, "bindAddr") {
			afterAddr = len(out)
		}
	}
	if at < 0 {
		at = afterAddr
	}
	if addr == "" {
		return strings.Join(out, "\n")
	}
	if at < 0 {
		at = 0
		for i, l := range out {
			if strings.HasPrefix(strings.TrimSpace(l), "[") {
				break
			}
			at = i + 1
		}
		if at > 0 && strings.TrimSpace(out[at-1]) == "" {
			at--
		}
	}
	line := `proxyBindAddr = "` + addr + `"`
	out = append(out[:at], append([]string{line}, out[at:]...)...)
	return strings.Join(out, "\n")
}

var (
	bhArrayStart = regexp.MustCompile(`^\s*(ports|mapping)\s*=\s*\[`)
	bhQuoted     = regexp.MustCompile(`"([^"]*)"`)
	lbAddrRe     = regexp.MustCompile(`^169\.254\.77\.\d{1,3}$`)
)

// backhaulWithBind returns the Backhaul config with every port entry listening
// on addr ("169.254.77.2:443=443"), or back on all addresses when addr is "".
// Entries with another explicit listen address are the user's and stay.
func backhaulWithBind(conf, addr string) string {
	lines := strings.Split(conf, "\n")
	in := false
	for i, l := range lines {
		if !in && bhArrayStart.MatchString(l) {
			in = true
		}
		if !in {
			continue
		}
		lines[i] = bhQuoted.ReplaceAllStringFunc(l, func(q string) string {
			return `"` + bhEntryBind(strings.Trim(q, `"`), addr) + `"`
		})
		if strings.Contains(stripTomlComment(l), "]") {
			in = false
		}
	}
	return strings.Join(lines, "\n")
}

func bhEntryBind(e, addr string) string {
	left, right, hasRight := strings.Cut(e, "=")
	if i := strings.LastIndex(left, ":"); i >= 0 {
		host := left[:i]
		if host != "0.0.0.0" && !lbAddrRe.MatchString(host) {
			return e // the user's own listen address
		}
		left = left[i+1:]
	}
	if strings.TrimSpace(left) == "" {
		return e
	}
	if addr != "" {
		left = addr + ":" + left
	}
	if hasRight {
		return left + "=" + right
	}
	return left
}

// relayWithBind dispatches on the engine.
func relayWithBind(engine, conf, addr string) string {
	if engine == "backhaul" {
		return backhaulWithBind(conf, addr)
	}
	return frpsWithBind(conf, addr)
}

// ---- planning ----

// lbMemberState is one member as the planner sees it this tick.
type lbMemberState struct {
	LBMember
	Name      string
	Addr      string  // private address of the member's relay ("" = link gone)
	Up        bool    // link health and, with a service check, the service (debounced)
	Listening bool    // the relay listens on Addr:Port right now
	LatencyMs float64 // -1 unknown
	Conns     int     // open TCP connections the relay holds on Addr:Port, -1 unknown
}

// lbTarget is one DNAT destination with its weight.
type lbTarget struct {
	Link   int     `json:"link"`
	Addr   string  `json:"-"`
	Port   int     `json:"port"`
	Weight int     `json:"weight"`
	Share  float64 `json:"share"` // fraction of new connections/users, 0..1
}

// lbPoolRT is per-pool state the planner keeps between ticks.
type lbPoolRT struct {
	Current int // failover and latency mode: the link now chosen (-1 none)
	Better  int // a faster candidate
	Streak  int // ticks the candidate has stayed faster
	// Full: members at their connection limit; they get new connections
	// again below 90% of it.
	Full map[int]bool
	// least-connections weights, recomputed every lbLeastEvery ticks
	LeastW    map[int]int
	LeastTick int
	// Failback: the pool's failback request last acted on.
	Failback int
	// Svc: the service check of each member.
	Svc map[int]*lbSvcRT
}

func newPoolRT() *lbPoolRT {
	return &lbPoolRT{Current: -1, Better: -1, Full: map[int]bool{}, Svc: map[int]*lbSvcRT{}}
}

// Pool states shown to the user.
const (
	poolOK       = "ok"        // every member healthy
	poolDegraded = "degraded"  // some members out, traffic on the rest
	poolFailOpen = "fail-open" // no healthy member: sending to every listening member
	poolForward  = "forward"   // no healthy member: forwarded to another Iran hub
	poolDown     = "down"      // nothing can serve it
	poolOff      = "disabled"
)

// lbLatencyStreak is how many ticks a faster member must stay faster before
// latency mode moves to it, so it does not flap between two close members.
const lbLatencyStreak = 10

// lbLeastEvery is how many ticks least-connections mode keeps its weights:
// re-weighting every second would rewrite the rules every second.
const lbLeastEvery = 5

// lbPickTargets decides where a pool's new connections go. Healthy members
// with room come first, standby (backup) members only when no primary one
// has room, and members at their connection limit only when nobody else can
// take the connection.
func lbPickTargets(pool LBPool, ms []lbMemberState, rt *lbPoolRT) ([]lbTarget, string) {
	if pool.Disabled {
		return nil, poolOff
	}
	if rt == nil {
		rt = newPoolRT()
	}
	if rt.Full == nil {
		rt.Full = map[int]bool{}
	}
	var ok, open []lbMemberState
	for _, m := range ms {
		if m.Addr == "" || !m.Listening || m.Drain {
			delete(rt.Full, m.Link)
			continue
		}
		open = append(open, m)
		if m.Up {
			ok = append(ok, m)
		}
		switch {
		case m.MaxConn <= 0 || m.Conns < 0:
			delete(rt.Full, m.Link)
		case m.Conns >= m.MaxConn:
			rt.Full[m.Link] = true
		case m.Conns < m.MaxConn*9/10:
			delete(rt.Full, m.Link)
		}
	}
	state := poolOK
	var use []lbMemberState
	switch {
	case len(ok) == 0 && len(open) == 0:
		rt.Current = -1
		return nil, poolDown
	case len(ok) == 0:
		// Health says no member works but relays still listen: better to try
		// them than to refuse every connection (health can be wrong, e.g.
		// ICMP filtered on the way back).
		use, state = open, poolFailOpen
	default:
		var prim, back []lbMemberState
		for _, m := range ok {
			switch {
			case rt.Full[m.Link]:
			case m.Backup:
				back = append(back, m)
			default:
				prim = append(prim, m)
			}
		}
		switch {
		case len(prim) > 0:
			use = prim
		case len(back) > 0:
			use = back
		default:
			use = ok // everyone is full: still better than refusing
		}
		if len(ok) < countActive(ms) {
			state = poolDegraded
		}
	}
	sort.SliceStable(use, func(i, j int) bool {
		if use[i].Priority != use[j].Priority {
			return use[i].Priority < use[j].Priority
		}
		return use[i].Link < use[j].Link
	})
	tgt := func(m lbMemberState, w int) lbTarget {
		if w <= 0 {
			w = 1
		}
		return lbTarget{Link: m.Link, Addr: m.Addr, Port: memberPort(pool, m.LBMember), Weight: w}
	}
	spread := func(weight func(lbMemberState) int) []lbTarget {
		out := make([]lbTarget, 0, len(use))
		sum := 0
		for _, m := range use {
			t := tgt(m, weight(m))
			sum += t.Weight
			out = append(out, t)
		}
		for i := range out {
			out[i].Share = float64(out[i].Weight) / float64(sum)
		}
		return out
	}
	one := func(m lbMemberState) []lbTarget {
		t := tgt(m, m.Weight)
		t.Share = 1
		return []lbTarget{t}
	}
	switch pool.Mode {
	case lbBalance, lbSticky:
		rt.Current = -1
		return spread(func(m lbMemberState) int { return m.Weight }), state
	case lbLeast:
		rt.Current = -1
		w := lbLeastWeights(use, rt)
		return spread(func(m lbMemberState) int { return w[m.Link] }), state
	case lbLatency:
		return one(lbLatencyPick(use, rt)), state
	default: // failover
		pick := use[0]
		if pool.NoFailback && state != poolFailOpen && rt.Failback == pool.Failback {
			// stay on the member traffic moved to while it is healthy and has room
			for _, m := range ok {
				if m.Link == rt.Current && !rt.Full[m.Link] {
					pick = m
				}
			}
		}
		rt.Failback = pool.Failback
		rt.Current = pick.Link
		return one(pick), state
	}
}

// countActive is the number of members that should serve: in the pool, the
// tunnel still there and not drained.
func countActive(ms []lbMemberState) int {
	n := 0
	for _, m := range ms {
		if m.Addr != "" && !m.Drain {
			n++
		}
	}
	return n
}

func memberPort(p LBPool, m LBMember) int {
	if m.Port > 0 {
		return m.Port
	}
	return p.Port
}

// lbLeastWeights keeps least-connections weights for lbLeastEvery ticks, or
// until the members change.
func lbLeastWeights(use []lbMemberState, rt *lbPoolRT) map[int]int {
	rt.LeastTick++
	same := len(rt.LeastW) == len(use)
	for _, m := range use {
		if _, ok := rt.LeastW[m.Link]; !ok {
			same = false
		}
	}
	if same && rt.LeastTick < lbLeastEvery {
		return rt.LeastW
	}
	rt.LeastTick = 0
	rt.LeastW = lbLeastShares(use)
	return rt.LeastW
}

// lbLeastShares splits the connections expected before the next re-weighting
// so that open connections per unit of weight even out (water filling): a
// member far below the others gets most of them, one far above only the
// minimum (1%). Members whose connections are unknown (UDP) count as empty.
func lbLeastShares(use []lbMemberState) map[int]int {
	out := map[int]int{}
	total := 0
	for _, m := range use {
		total += max(m.Conns, 0)
	}
	batch := max(8*len(use), total/4)
	fill := func(level float64) float64 {
		s := 0.0
		for _, m := range use {
			s += math.Max(0, level*float64(max(m.Weight, 1))-float64(max(m.Conns, 0)))
		}
		return s
	}
	lo, hi := 0.0, float64(total+batch)
	for i := 0; i < 60; i++ {
		mid := (lo + hi) / 2
		if fill(mid) < float64(batch) {
			lo = mid
		} else {
			hi = mid
		}
	}
	for _, m := range use {
		give := math.Max(0, hi*float64(max(m.Weight, 1))-float64(max(m.Conns, 0)))
		out[m.Link] = max(1, int(math.Round(100*give/float64(batch))))
	}
	return out
}

// lbLatencyPick keeps the current member unless it is gone or another one has
// been clearly faster (20% and 10 ms) for lbLatencyStreak ticks in a row.
func lbLatencyPick(use []lbMemberState, rt *lbPoolRT) lbMemberState {
	lat := func(m lbMemberState) float64 {
		if m.LatencyMs < 0 {
			return math.MaxFloat64
		}
		return m.LatencyMs
	}
	best := use[0]
	for _, m := range use[1:] {
		if lat(m) < lat(best) {
			best = m
		}
	}
	if rt == nil {
		return best
	}
	var cur *lbMemberState
	for i := range use {
		if use[i].Link == rt.Current {
			cur = &use[i]
		}
	}
	if cur == nil {
		rt.Current, rt.Better, rt.Streak = best.Link, -1, 0
		return best
	}
	if best.Link != cur.Link && lat(best) < lat(*cur)*0.8 && lat(*cur)-lat(best) >= 10 {
		if rt.Better == best.Link {
			rt.Streak++
		} else {
			rt.Better, rt.Streak = best.Link, 1
		}
		if rt.Streak >= lbLatencyStreak {
			rt.Current, rt.Better, rt.Streak = best.Link, -1, 0
			return best
		}
	} else {
		rt.Better, rt.Streak = -1, 0
	}
	return *cur
}

// lbStickyBuckets assigns each of the lbBuckets source buckets to a target by
// weighted rendezvous hashing: when a member leaves, only its own users move.
func lbStickyBuckets(ts []lbTarget) []int {
	out := make([]int, lbBuckets)
	for b := 0; b < lbBuckets; b++ {
		bestI, bestS := 0, math.Inf(-1)
		for i, t := range ts {
			h := fnv.New64a()
			fmt.Fprintf(h, "%d/%d", b, t.Link)
			u := (float64(mix64(h.Sum64())>>11) + 0.5) / float64(1<<53) // (0,1)
			s := -float64(t.Weight) / math.Log(u)
			if s > bestS {
				bestI, bestS = i, s
			}
		}
		out[b] = bestI
	}
	return out
}

// mix64 is the splitmix64 finalizer: FNV alone leaves the high bits of
// near-identical keys ("3/1", "3/2") close together.
func mix64(x uint64) uint64 {
	x ^= x >> 30
	x *= 0xbf58476d1ce4e5b9
	x ^= x >> 27
	x *= 0x94d049bb133111eb
	return x ^ x>>31
}

// lbPortRange is a run of ports on one link that passes straight through to
// the link's relay (its ports that are not part of any pool).
type lbPortRange struct {
	Proto    string
	From, To int
	Addr     string
	Link     int
}

// lbPassRanges turns each bound link's listening ports (minus pool ports) into
// contiguous ranges. A port two links listen on goes to the lower link id and
// is reported.
func lbPassRanges(listen map[int]map[string][]int, addrs map[int]string, pooled map[string]bool) ([]lbPortRange, []string) {
	owner := map[string]int{}
	var warn []string
	links := make([]int, 0, len(listen))
	for l := range listen {
		links = append(links, l)
	}
	sort.Ints(links)
	per := map[int]map[string][]int{}
	for _, l := range links {
		for _, proto := range []string{"tcp", "udp"} {
			for _, p := range listen[l][proto] {
				k := proto + "/" + strconv.Itoa(p)
				if pooled[k] {
					continue
				}
				if o, taken := owner[k]; taken {
					warn = append(warn, fmt.Sprintf("%s port %d is served by link %d and link %d; only link %d gets it. Put it in a pool to use both.", proto, p, o, l, o))
					continue
				}
				owner[k] = l
				if per[l] == nil {
					per[l] = map[string][]int{}
				}
				per[l][proto] = append(per[l][proto], p)
			}
		}
	}
	var out []lbPortRange
	for _, l := range links {
		for _, proto := range []string{"tcp", "udp"} {
			ps := append([]int(nil), per[l][proto]...)
			sort.Ints(ps)
			for i := 0; i < len(ps); {
				j := i
				for j+1 < len(ps) && ps[j+1] == ps[j]+1 {
					j++
				}
				out = append(out, lbPortRange{Proto: proto, From: ps[i], To: ps[j], Addr: addrs[l], Link: l})
				i = j + 1
			}
		}
	}
	return out, warn
}

// lbPlan is everything the kernel needs this tick.
type lbPlan struct {
	Pools []lbPoolPlan
	Pass  []lbPortRange
	// Forward: pools sent to another Iran hub (no healthy member here).
	Forward []lbForward
}

type lbPoolPlan struct {
	Port    int
	Proto   string
	Mode    string
	State   string
	Targets []lbTarget
}

type lbForward struct {
	Port  int
	Proto string
	To    string // the other hub's public IPv4
}

func lbChainName(proto string, port int) string {
	return fmt.Sprintf("HLB-%s%d", strings.ToUpper(proto[:1]), port)
}

// lbRulesText renders the plan as iptables-restore input (with --noflush only
// the chains named here are replaced, atomically per table).
func lbRulesText(p lbPlan) string {
	var b strings.Builder
	nat := []string{}
	chains := []string{lbEntry, lbChain, lbPost}
	add := func(f string, a ...any) { nat = append(nat, fmt.Sprintf(f, a...)) }

	add("-A %s -d 127.0.0.0/8 -j RETURN", lbEntry)
	add("-A %s -d %s -j RETURN", lbEntry, lbNet)
	add("-A %s -j %s", lbEntry, lbChain)

	for _, pp := range p.Pools {
		if len(pp.Targets) == 0 {
			continue
		}
		for _, proto := range lbProtos(pp.Proto) {
			ch := lbChainName(proto, pp.Port)
			chains = append(chains, ch)
			add("-A %s -p %s --dport %d -j %s", lbChain, proto, pp.Port, ch)
			ts := pp.Targets
			// DNAT to a port needs the protocol in the same rule
			dst := func(t lbTarget) string {
				return fmt.Sprintf("-p %s -j DNAT --to-destination %s:%d", proto, t.Addr, t.Port)
			}
			switch {
			case len(ts) == 1:
				add("-A %s %s", ch, dst(ts[0]))
			case pp.Mode == lbSticky:
				buckets := lbStickyBuckets(ts)
				for i, t := range ts {
					var rs []string
					for b := 0; b < lbBuckets; {
						if buckets[b] != i {
							b++
							continue
						}
						e := b
						for e+1 < lbBuckets && buckets[e+1] == i {
							e++
						}
						if b == e {
							rs = append(rs, strconv.Itoa(b))
						} else {
							rs = append(rs, fmt.Sprintf("%d:%d", b, e))
						}
						b = e + 1
					}
					for len(rs) > 0 { // u32 takes at most 10 ranges per test
						n := min(10, len(rs))
						add(`-A %s -m u32 --u32 "12&0x3F=%s" %s`, ch, strings.Join(rs[:n], ","), dst(t))
						rs = rs[n:]
					}
				}
				add("-A %s %s", ch, dst(ts[buckets[0]]))
			default: // balance: each rule takes its share of what is left
				left := 0
				for _, t := range ts {
					left += t.Weight
				}
				for i, t := range ts {
					if i == len(ts)-1 {
						add("-A %s %s", ch, dst(t))
						break
					}
					add("-A %s -m statistic --mode random --probability %.5f %s", ch, float64(t.Weight)/float64(left), dst(t))
					left -= t.Weight
				}
			}
		}
	}
	for _, f := range p.Forward {
		for _, proto := range lbProtos(f.Proto) {
			add("-A %s -p %s --dport %d -j DNAT --to-destination %s:%d", lbChain, proto, f.Port, f.To, f.Port)
			add("-A %s -d %s -p %s --dport %d -j MASQUERADE", lbPost, f.To, proto, f.Port)
		}
	}
	for _, r := range p.Pass {
		if r.From == r.To {
			add("-A %s -p %s --dport %d -j DNAT --to-destination %s", lbChain, r.Proto, r.From, r.Addr)
		} else {
			add("-A %s -p %s --dport %d:%d -j DNAT --to-destination %s", lbChain, r.Proto, r.From, r.To, r.Addr)
		}
	}

	b.WriteString("*nat\n")
	for _, c := range chains {
		fmt.Fprintf(&b, ":%s - [0:0]\n", c)
	}
	for _, l := range nat {
		b.WriteString(l + "\n")
	}
	b.WriteString("COMMIT\n*filter\n")
	fmt.Fprintf(&b, ":%s - [0:0]\n:%s - [0:0]\n", lbFilter, lbFwd)
	fmt.Fprintf(&b, "-A %s -d %s -m conntrack --ctstate DNAT -j ACCEPT\n", lbFilter, lbNet)
	fmt.Fprintf(&b, "-A %s -d %s ! -i lo -j DROP\n", lbFilter, lbNet)
	for _, f := range p.Forward {
		fmt.Fprintf(&b, "-A %s -d %s -m conntrack --ctstate DNAT -j ACCEPT\n", lbFwd, f.To)
		fmt.Fprintf(&b, "-A %s -s %s -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n", lbFwd, f.To)
	}
	b.WriteString("COMMIT\n")
	return b.String()
}

// lbChainsIn lists the per-pool chains a rules text declares.
func lbChainsIn(text string) []string {
	var out []string
	for _, l := range strings.Split(text, "\n") {
		if strings.HasPrefix(l, ":HLB-") {
			out = append(out, strings.Fields(l[1:])[0])
		}
	}
	return out
}

// ---- applying ----

// lbHooks are the jumps from the built-in chains into ours.
var lbHooks = [][]string{
	{"-t", "nat", "PREROUTING", "-m", "addrtype", "--dst-type", "LOCAL", "-j", lbEntry},
	{"-t", "nat", "OUTPUT", "-m", "addrtype", "--dst-type", "LOCAL", "-j", lbEntry},
	{"-t", "nat", "POSTROUTING", "-j", lbPost},
	{"-t", "filter", "INPUT", "-j", lbFilter},
	{"-t", "filter", "FORWARD", "-j", lbFwd},
}

func lbRulesFile() string { return filepath.Join(configDir, "cluster-rules.v4") }

// lbApplyRules replaces our chains atomically and makes sure the built-in
// chains jump to them. Chains of pools that are gone are removed.
func lbApplyRules(text string, oldChains []string) error {
	_ = os.MkdirAll(configDir, 0o700)
	f := lbRulesFile()
	if err := os.WriteFile(f, []byte(text), 0o600); err != nil {
		return err
	}
	if out, err := runCmdTimeout(15*time.Second, "iptables-restore", "-w", "5", "-n", f); err != nil {
		return fmt.Errorf("iptables-restore: %s", strings.TrimSpace(string(out)))
	}
	lbEnsureHooks()
	keep := map[string]bool{}
	for _, c := range lbChainsIn(text) {
		keep[c] = true
	}
	for _, c := range oldChains {
		if !keep[c] {
			_, _ = runCmdTimeout(5*time.Second, "iptables", "-w", "5", "-t", "nat", "-F", c)
			_, _ = runCmdTimeout(5*time.Second, "iptables", "-w", "5", "-t", "nat", "-X", c)
		}
	}
	if strings.Contains(text, "-j MASQUERADE") {
		_, _ = runCmdTimeout(5*time.Second, "sysctl", "-w", "net.ipv4.ip_forward=1")
	}
	return nil
}

// lbEnsureHooks inserts each jump at the top of its built-in chain once.
// Something that flushes the chains (a firewall reload) is repaired on the
// next check.
func lbEnsureHooks() {
	for _, h := range lbHooks {
		tbl, chain, rule := h[:2], h[2], h[3:]
		check := append(append([]string{"-w", "5"}, tbl...), append([]string{"-C", chain}, rule...)...)
		if _, err := runCmdTimeout(5*time.Second, "iptables", check...); err != nil {
			ins := append(append([]string{"-w", "5"}, tbl...), append([]string{"-I", chain, "1"}, rule...)...)
			_, _ = runCmdTimeout(5*time.Second, "iptables", ins...)
		}
	}
}

// lbClearRules removes every rule and chain the cluster made (also the v1
// cluster's chains, which sent traffic straight to foreign IPs).
func lbClearRules(oldChains []string) {
	ipt := func(a ...string) {
		_, _ = runCmdTimeout(5*time.Second, "iptables", append([]string{"-w", "5"}, a...)...)
	}
	for _, h := range lbHooks {
		tbl, chain, rule := h[:2], h[2], h[3:]
		for i := 0; i < 3; i++ { // a hook inserted twice by hand
			if _, err := runCmdTimeout(5*time.Second, "iptables", append(append([]string{"-w", "5"}, tbl...), append([]string{"-D", chain}, rule...)...)...); err != nil {
				break
			}
		}
	}
	for _, c := range append([]string{lbEntry, lbChain, lbPost}, oldChains...) {
		ipt("-t", "nat", "-F", c)
		ipt("-t", "nat", "-X", c)
	}
	for _, c := range []string{lbFilter, lbFwd} {
		ipt("-t", "filter", "-F", c)
		ipt("-t", "filter", "-X", c)
	}
	_ = os.Remove(lbRulesFile())
}

// lbClearLegacyV1 removes the chains of the first cluster design.
func lbClearLegacyV1() {
	for _, c := range []string{"HASHEM-CLUSTER-PREROUTING", "HASHEM-CLUSTER-POSTROUTING"} {
		base := strings.TrimPrefix(c, "HASHEM-CLUSTER-")
		_, _ = runCmdTimeout(5*time.Second, "iptables", "-w", "5", "-t", "nat", "-D", base, "-j", c)
		_, _ = runCmdTimeout(5*time.Second, "iptables", "-w", "5", "-t", "nat", "-F", c)
		_, _ = runCmdTimeout(5*time.Second, "iptables", "-w", "5", "-t", "nat", "-X", c)
	}
}

// lbConntrackForget drops the conntrack entries of a member that left, so UDP
// flows move to a working member instead of waiting for a timeout.
func lbConntrackForget(addr string) {
	_, _ = runCmdTimeout(5*time.Second, "conntrack", "-D", "--reply-src", addr)
}

// ---- private addresses ----

const lbUnit = "hashem-lb-net.service"

// lbUnitDir is where the unit goes; lab tests point it elsewhere.
var lbUnitDir = "/etc/systemd/system"

func lbUnitPath() string { return filepath.Join(lbUnitDir, lbUnit) }

// lbBindsFile tells hashem.sh which relays are bound (one "svc addr" per
// line), so a peer it rewrites keeps listening on its private address.
func lbBindsFile() string { return filepath.Join(configDir, "lb-binds") }

// lbPooledPortsFile lists the pool ports ("443/tcp" per line): hashem.sh lets a
// new peer claim one of them and binds that peer privately.
func lbPooledPortsFile() string { return filepath.Join(configDir, "lb-ports") }

// lbUnitText is the oneshot unit that recreates the addresses at boot, before
// the relays start.
func lbUnitText(addrs []string) string {
	var cmd strings.Builder
	cmd.WriteString("ip link add " + lbIface + " type dummy 2>/dev/null; ip link set " + lbIface + " up")
	for _, a := range addrs {
		cmd.WriteString("; ip addr replace " + a + "/32 dev " + lbIface)
	}
	return "[Unit]\nDescription=Hashem cluster: private relay addresses\nDefaultDependencies=no\nAfter=local-fs.target\n" +
		"Before=network-online.target frps.service backhaul-server.service\n\n" +
		"[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/bin/sh -c '" + cmd.String() + "'\n\n" +
		"[Install]\nWantedBy=multi-user.target\n"
}

// lbEnsureAddrs makes hashem-lb carry exactly addrs and keeps the boot unit in
// step. With no addresses the interface and unit go away.
func lbEnsureAddrs(addrs []string) error {
	sort.Strings(addrs)
	if len(addrs) == 0 {
		_, _ = runCmdTimeout(5*time.Second, "ip", "link", "del", lbIface)
		if fileExists(lbUnitPath()) {
			_, _ = runCmdTimeout(10*time.Second, "systemctl", "disable", lbUnit)
			_ = os.Remove(lbUnitPath())
			_, _ = runCmdTimeout(10*time.Second, "systemctl", "daemon-reload")
		}
		return nil
	}
	if _, err := runCmdTimeout(5*time.Second, "ip", "link", "show", lbIface); err != nil {
		if out, err := runCmdTimeout(5*time.Second, "ip", "link", "add", lbIface, "type", "dummy"); err != nil {
			return fmt.Errorf("cannot create %s: %s", lbIface, strings.TrimSpace(string(out)))
		}
	}
	_, _ = runCmdTimeout(5*time.Second, "ip", "link", "set", lbIface, "up")
	have := map[string]bool{}
	if out, err := runCmdTimeoutOut(5*time.Second, "ip", "-o", "-4", "addr", "show", "dev", lbIface); err == nil {
		for _, l := range strings.Split(string(out), "\n") {
			f := strings.Fields(l)
			for i := 0; i+1 < len(f); i++ {
				if f[i] == "inet" {
					have[strings.Split(f[i+1], "/")[0]] = true
				}
			}
		}
	}
	want := map[string]bool{}
	for _, a := range addrs {
		want[a] = true
		if !have[a] {
			if out, err := runCmdTimeout(5*time.Second, "ip", "addr", "add", a+"/32", "dev", lbIface); err != nil {
				return fmt.Errorf("cannot add %s: %s", a, strings.TrimSpace(string(out)))
			}
		}
	}
	for a := range have {
		if !want[a] {
			_, _ = runCmdTimeout(5*time.Second, "ip", "addr", "del", a+"/32", "dev", lbIface)
		}
	}
	unit := lbUnitText(addrs)
	if old, _ := os.ReadFile(lbUnitPath()); string(old) != unit {
		if err := os.WriteFile(lbUnitPath(), []byte(unit), 0o644); err == nil {
			_, _ = runCmdTimeout(10*time.Second, "systemctl", "daemon-reload")
			_, _ = runCmdTimeout(10*time.Second, "systemctl", "enable", lbUnit)
		}
	}
	return nil
}

// lbSetRelayBind rewrites unit svc's config to listen on addr ("" = all
// addresses again) and restarts it when the file changed. changed reports a
// restart.
func lbSetRelayBind(svc, addr string) (changed bool, err error) {
	path, engine := lbConfFor(svc)
	if path == "" {
		return false, fmt.Errorf("%s is not a relay the cluster can bind", svc)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	next := relayWithBind(engine, string(data), addr)
	if next == string(data) {
		return false, nil
	}
	tmp := path + ".hashem-lb"
	if err := os.WriteFile(tmp, []byte(next), 0o600); err != nil {
		return false, err
	}
	if err := os.Rename(tmp, path); err != nil {
		return false, err
	}
	if out, err := runCmdTimeout(30*time.Second, "systemctl", "restart", svc); err != nil {
		return true, fmt.Errorf("%s did not restart: %s", svc, strings.TrimSpace(string(out)))
	}
	return true, nil
}

// lbRelayBound reports whether svc's config already listens on addr.
func lbRelayBound(svc, addr string) bool {
	path, engine := lbConfFor(svc)
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return relayWithBind(engine, string(data), addr) == string(data) && strings.Contains(string(data), addr)
}
