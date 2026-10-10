package main

// Reverse Path Doctor, Phase 1: READ-ONLY. Collects hub-side facts, classifies
// them with a pure function, and reports. Nothing here writes sysctl, routes,
// iptables or restarts a unit; fixes are text only.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Probe layers.
const (
	LayerICMPGre64     = "icmp_gre_64"
	LayerICMPGre1300   = "icmp_gre_1300df"
	LayerICMPPublic    = "icmp_public"
	LayerTCPCtrlInner  = "tcp_ctrl_inner"
	LayerTCPCtrlPublic = "tcp_ctrl_public"
	LayerTCPWSS        = "tcp_wss"
)

var revPathLayers = []string{LayerICMPGre64, LayerICMPGre1300, LayerICMPPublic, LayerTCPCtrlInner, LayerTCPCtrlPublic, LayerTCPWSS}

// Probe directions. "unprobed" marks a placeholder: nobody measured it.
const (
	DirHubToSpoke = "hub_to_spoke"
	DirSpokeToHub = "spoke_to_hub"
	DirUnprobed   = "unprobed"
)

type ProbeResult struct {
	Layer     string  `json:"layer"`
	Direction string  `json:"direction"`
	OK        bool    `json:"ok"`
	RTTms     float64 `json:"rtt_ms"`
	Err       string  `json:"err,omitempty"`
	Size      int     `json:"size,omitempty"`
	DF        bool    `json:"df,omitempty"`
}

// ProbeMatrix holds both directions. GRE packet-counter deltas are nil when
// not measured. Deltas include concurrent tunnel traffic, so they are only
// meaningful as "zero vs non-zero".
type ProbeMatrix struct {
	Results []ProbeResult `json:"results"`

	HubRxDelta   *uint64 `json:"hub_gre_rx_delta,omitempty"`
	HubTxDelta   *uint64 `json:"hub_gre_tx_delta,omitempty"`
	SpokeRxDelta *uint64 `json:"spoke_gre_rx_delta,omitempty"`
	SpokeTxDelta *uint64 `json:"spoke_gre_tx_delta,omitempty"`
}

// get returns a measured result; placeholders count as absent.
func (m ProbeMatrix) get(dir, layer string) (ProbeResult, bool) {
	for _, r := range m.Results {
		if r.Direction == dir && r.Layer == layer {
			return r, true
		}
	}
	return ProbeResult{}, false
}

func (m ProbeMatrix) ok(dir, layer string) bool {
	r, found := m.get(dir, layer)
	return found && r.OK
}

// failed is true only for a measured failure (absent != failed).
func (m ProbeMatrix) failed(dir, layer string) bool {
	r, found := m.get(dir, layer)
	return found && !r.OK
}

// LocalSnapshot is what the hub can read about itself. Int fields use -1 for
// unknown; the *Checked/*Known booleans say whether a boolean is a real
// observation or a zero value.
type LocalSnapshot struct {
	GreIf           string `json:"gre_if"`
	InnerLocal      string `json:"inner_local,omitempty"`
	RPFilterAll     int    `json:"rp_filter_all"`
	RPFilterDefault int    `json:"rp_filter_default"`
	RPFilterIface   int    `json:"rp_filter_iface"`
	IPForward       bool   `json:"ip_forward"`
	GreMTU          int    `json:"gre_mtu"`

	FwChecked         bool `json:"fw_checked"`
	InputDropsProto47 bool `json:"input_drops_proto47"`
	FwDropsICMP       bool `json:"fw_drops_icmp"`

	ConntrackKnown         bool `json:"conntrack_known"`
	ConntrackInvalidRising bool `json:"conntrack_invalid_rising"`

	RouteKnown      bool   `json:"route_known"`
	RouteBackViaGre bool   `json:"route_back_via_gre"`
	SrcAddrOnReply  string `json:"src_addr_on_reply,omitempty"`
}

// rpStrict mirrors the kernel: the effective value is max(all, iface).
func (s LocalSnapshot) rpStrict() bool {
	eff := s.RPFilterAll
	if s.RPFilterIface > eff {
		eff = s.RPFilterIface
	}
	return eff == 1
}

type Verdict string

const (
	VerdictRPFilter         Verdict = "RP_FILTER"
	VerdictSrcSelect        Verdict = "SRC_SELECT"
	VerdictNoReturnRoute    Verdict = "NO_RETURN_ROUTE"
	VerdictFwInput          Verdict = "FW_INPUT"
	VerdictMTUBlackhole     Verdict = "MTU_BLACKHOLE"
	VerdictConntrackInvalid Verdict = "CONNTRACK_INVALID"
	VerdictISPICMPOneWay    Verdict = "ISP_ICMP_ONE_WAY"
	VerdictISPGreBlock      Verdict = "ISP_GRE_BLOCK"
	VerdictCloudSG          Verdict = "CLOUD_SG"
	VerdictHealthy          Verdict = "HEALTHY"
	VerdictUnknown          Verdict = "UNKNOWN"
)

type RevPathDiagnosis struct {
	Verdict      Verdict  `json:"verdict"`
	Confidence   string   `json:"confidence"` // "high" | "medium" | "low"
	Evidence     []string `json:"evidence"`
	SuggestedFix string   `json:"suggested_fix,omitempty"` // text only in Phase 1
	AutoFixable  bool     `json:"auto_fixable"`
}

var revPathFixText = map[Verdict]string{
	VerdictRPFilter:         "Set net.ipv4.conf.{all,default,<gre-if>}.rp_filter=2 (loose) and persist it in /etc/sysctl.d.",
	VerdictSrcSelect:        "Pin the GRE route source: ip route replace <peer-inner> dev <gre-if> src <local-inner>.",
	VerdictNoReturnRoute:    "Add a route to the peer inner address via the GRE interface and persist it in the gre unit.",
	VerdictFwInput:          "Allow proto 47, ICMP and the GRE interface in INPUT/FORWARD (use a dedicated chain, never edit user rules).",
	VerdictMTUBlackhole:     "Lower the GRE MTU stepwise (1380 -> 1360 -> 1340 -> 1300) and re-check the MSS clamp.",
	VerdictConntrackInvalid: "Exempt proto 47 / the GRE interface from conntrack (raw table NOTRACK).",
	VerdictISPICMPOneWay:    "No local fix: ICMP is filtered upstream. Rely on the TCP/session signal; do not restart the tunnel.",
	VerdictISPGreBlock:      "Proto 47 is not delivered one way while TCP over the public path works: switch the carrier to WSS.",
	VerdictCloudSG:          "Cloud security group / provider firewall: allow IP protocol 47 and ICMP from the hub IP on the spoke.",
}

var revPathAutoFixable = map[Verdict]bool{
	VerdictRPFilter: true, VerdictSrcSelect: true, VerdictNoReturnRoute: true,
	VerdictFwInput: true, VerdictMTUBlackhole: true, VerdictConntrackInvalid: true,
}

func finishDiag(v Verdict, conf string, ev []string) RevPathDiagnosis {
	d := RevPathDiagnosis{Verdict: v, Confidence: conf, Evidence: ev, SuggestedFix: revPathFixText[v]}
	d.AutoFixable = revPathAutoFixable[v] && conf != "low"
	if d.Evidence == nil {
		d.Evidence = []string{}
	}
	return d
}

func u64(p *uint64) (uint64, bool) {
	if p == nil {
		return 0, false
	}
	return *p, true
}

// localRisks lists hub-side settings that could break the reverse path.
func (s LocalSnapshot) localRisks() []string {
	var r []string
	if s.rpStrict() {
		r = append(r, "rp_filter is strict (1) on all/"+s.GreIf)
	}
	if s.InputDropsProto47 {
		r = append(r, "firewall drops proto 47 on INPUT/FORWARD")
	}
	if s.FwDropsICMP {
		r = append(r, "firewall drops ICMP on INPUT/FORWARD")
	}
	if s.ConntrackInvalidRising {
		r = append(r, "conntrack INVALID counter is rising")
	}
	if s.RouteKnown && !s.RouteBackViaGre {
		r = append(r, "route to the peer inner address does not use "+s.GreIf)
	}
	if s.srcMismatch() {
		r = append(r, "route source "+s.SrcAddrOnReply+" differs from inner address "+s.InnerLocal)
	}
	return r
}

func (s LocalSnapshot) srcMismatch() bool {
	return s.SrcAddrOnReply != "" && s.InnerLocal != "" && s.SrcAddrOnReply != s.InnerLocal
}

// classifyRevPath is pure and deterministic. It names a cause only when the
// evidence points to exactly one; anything ambiguous is UNKNOWN and carries
// the candidates in Evidence so nobody applies a guessed fix.
func classifyRevPath(m ProbeMatrix, s LocalSnapshot) RevPathDiagnosis {
	dirs := []string{DirHubToSpoke, DirSpokeToHub}
	var ev []string
	probed := map[string]bool{}
	for _, d := range dirs {
		_, probed[d] = m.get(d, LayerICMPGre64)
	}
	if !probed[DirHubToSpoke] && !probed[DirSpokeToHub] {
		return finishDiag(VerdictUnknown, "low", []string{"no ICMP-over-GRE probe results"})
	}
	spokeKnown := probed[DirSpokeToHub]
	if !spokeKnown {
		ev = append(ev, "spoke->hub direction not probed: run the probe on the spoke to confirm the reverse path")
	}

	var verdicts []Verdict
	conf := "high"
	lower := func(c string) {
		if c == "low" || (c == "medium" && conf == "high") {
			conf = c
		}
	}
	for _, d := range dirs {
		if !probed[d] {
			continue
		}
		v, c, e := classifyDirection(d, m, s)
		ev = append(ev, e...)
		if v == "" {
			continue
		}
		verdicts = append(verdicts, v)
		lower(c)
	}

	if len(verdicts) == 0 {
		risks := s.localRisks()
		if !spokeKnown {
			if len(risks) > 0 {
				ev = append(ev, "hub->spoke is fine but local risks exist: "+strings.Join(risks, "; "))
				return finishDiag(VerdictUnknown, "low", ev)
			}
			return finishDiag(VerdictHealthy, "low", ev)
		}
		ev = append(ev, "ICMP over GRE answers in both directions")
		if len(risks) > 0 {
			ev = append(ev, "both directions answer; local risks noted: "+strings.Join(risks, "; "))
		}
		return finishDiag(VerdictHealthy, "high", ev)
	}

	first := verdicts[0]
	for _, v := range verdicts[1:] {
		if v != first {
			ev = append(ev, "directions disagree on the cause")
			return finishDiag(VerdictUnknown, "low", ev)
		}
	}
	if first == VerdictUnknown {
		return finishDiag(VerdictUnknown, "low", ev)
	}
	if !spokeKnown {
		lower("medium")
	}
	return finishDiag(first, conf, ev)
}

// classifyDirection looks at one direction. It returns "" when that direction
// is healthy, VerdictUnknown when it is broken for an unidentified/ambiguous
// reason.
func classifyDirection(dir string, m ProbeMatrix, s LocalSnapshot) (Verdict, string, []string) {
	p64, _ := m.get(dir, LayerICMPGre64)
	label := map[string]string{DirHubToSpoke: "hub->spoke", DirSpokeToHub: "spoke->hub"}[dir]

	if p64.OK {
		if m.failed(dir, LayerICMPGre1300) {
			return VerdictMTUBlackhole, "high", []string{fmt.Sprintf("%s: 64B ICMP ok but 1300B DF ICMP fails (GRE mtu %d)", label, s.GreMTU)}
		}
		return "", "", nil
	}

	ev := []string{label + ": ICMP over GRE fails"}
	hubRx, hubRxKnown := u64(m.HubRxDelta)
	hubTx, hubTxKnown := u64(m.HubTxDelta)
	spokeRx, spokeRxKnown := u64(m.SpokeRxDelta)
	pubICMPOK := m.ok(dir, LayerICMPPublic)
	pubICMPFail := m.failed(dir, LayerICMPPublic)
	pubTCPOK := m.ok(dir, LayerTCPCtrlPublic) || m.ok(dir, LayerTCPWSS)
	innerTCPOK := m.ok(dir, LayerTCPCtrlInner)

	if innerTCPOK {
		// TCP crosses GRE in this direction, so routing/rp_filter/source are
		// not the problem; only ICMP-specific filtering remains.
		ev = append(ev, label+": TCP to the control port over the inner address works")
		var c []Verdict
		if s.FwDropsICMP {
			c = append(c, VerdictFwInput)
			ev = append(ev, "hub firewall drops ICMP")
		}
		if pubICMPFail {
			c = append(c, VerdictISPICMPOneWay)
			ev = append(ev, label+": ICMP over the public path fails too")
		}
		if len(c) == 1 {
			return c[0], "medium", ev
		}
		return VerdictUnknown, "low", append(ev, "cannot single out an ICMP-only cause")
	}

	if hubRxKnown && hubRx > 0 {
		// Packets arrive on the GRE interface yet the exchange fails: a hub-local drop.
		ev = append(ev, fmt.Sprintf("hub GRE rx counter moved (+%d) while the probe failed", hubRx))
		var c []Verdict
		if s.rpStrict() {
			c = append(c, VerdictRPFilter)
			ev = append(ev, "rp_filter strict (1)")
		}
		if s.InputDropsProto47 || s.FwDropsICMP {
			c = append(c, VerdictFwInput)
			ev = append(ev, "firewall drops proto 47 / ICMP")
		}
		if s.srcMismatch() {
			c = append(c, VerdictSrcSelect)
			ev = append(ev, "route source "+s.SrcAddrOnReply+" != inner "+s.InnerLocal)
		}
		if s.RouteKnown && !s.RouteBackViaGre {
			c = append(c, VerdictNoReturnRoute)
			ev = append(ev, "route to the peer inner address bypasses "+s.GreIf)
		}
		if s.ConntrackInvalidRising {
			c = append(c, VerdictConntrackInvalid)
			ev = append(ev, "conntrack INVALID counter rising")
		}
		if len(c) == 1 {
			return c[0], "high", ev
		}
		if len(c) > 1 {
			return VerdictUnknown, "low", append(ev, "several local causes match; not guessing")
		}
		return VerdictUnknown, "low", append(ev, "no local setting explains it; spoke-side data needed")
	}

	if dir == DirSpokeToHub && hubRxKnown && hubRx == 0 && pubTCPOK {
		ev = append(ev, "hub GRE rx counter did not move, TCP over the public path works")
		return VerdictISPGreBlock, "medium", ev
	}
	if dir == DirHubToSpoke && hubRxKnown && hubRx == 0 && hubTxKnown && hubTx > 0 &&
		spokeRxKnown && spokeRx == 0 && pubICMPOK && !s.localBlocksOutbound() {
		ev = append(ev, "hub sent GRE packets, spoke rx counter stayed 0, public ICMP reaches the spoke, hub rules clean")
		return VerdictCloudSG, "medium", ev
	}
	return VerdictUnknown, "low", append(ev, "evidence is ambiguous; spoke-side data needed")
}

func (s LocalSnapshot) localBlocksOutbound() bool {
	return s.InputDropsProto47 || s.FwDropsICMP
}

// ---- parsers (pure, fixture-tested) ----

// parseIntFile parses a one-integer sysctl file; -1 if unreadable/garbled.
func parseIntFile(content string) int {
	v, err := strconv.Atoi(strings.TrimSpace(content))
	if err != nil {
		return -1
	}
	return v
}

// parseLinkMTU extracts "mtu N" from `ip -o link show <if>`.
func parseLinkMTU(out string) int {
	f := strings.Fields(out)
	for i, w := range f {
		if w == "mtu" && i+1 < len(f) {
			if v, err := strconv.Atoi(f[i+1]); err == nil {
				return v
			}
		}
	}
	return -1
}

// parseRouteGet extracts src and dev from `ip route get <ip>`.
func parseRouteGet(out string) (src, dev string) {
	f := strings.Fields(out)
	for i, w := range f {
		if i+1 >= len(f) {
			break
		}
		switch w {
		case "src":
			src = f[i+1]
		case "dev":
			dev = f[i+1]
		}
	}
	return
}

// parseNetDevPackets returns rx/tx packet counters for iface from /proc/net/dev.
func parseNetDevPackets(content, iface string) (rx, tx uint64, ok bool) {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		rest, found := strings.CutPrefix(line, iface+":")
		if !found {
			continue
		}
		f := strings.Fields(rest)
		if len(f) < 10 {
			return 0, 0, false
		}
		r, e1 := strconv.ParseUint(f[1], 10, 64)
		t, e2 := strconv.ParseUint(f[9], 10, 64)
		if e1 != nil || e2 != nil {
			return 0, 0, false
		}
		return r, t, true
	}
	return 0, 0, false
}

// parseIptablesSave looks at the filter table's INPUT/FORWARD chains. It is a
// heuristic (rule order and source/dest qualifiers are ignored): an explicit
// DROP/REJECT for proto 47 or ICMP counts, and so does a DROP chain policy
// with no ACCEPT for that traffic (proto, icmp, or -i greIf).
func parseIptablesSave(text, greIf string) (drops47, dropsICMP bool) {
	policyDrop := map[string]bool{}
	accept47, acceptICMP := map[string]bool{}, map[string]bool{}
	inFilter := false
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "*") {
			inFilter = line == "*filter"
			continue
		}
		if !inFilter {
			continue
		}
		if strings.HasPrefix(line, ":") {
			f := strings.Fields(line)
			if len(f) >= 2 && (f[0] == ":INPUT" || f[0] == ":FORWARD") && f[1] == "DROP" {
				policyDrop[strings.TrimPrefix(f[0], ":")] = true
			}
			continue
		}
		f := strings.Fields(line)
		if len(f) < 4 || f[0] != "-A" || (f[1] != "INPUT" && f[1] != "FORWARD") {
			continue
		}
		chain := f[1]
		joined := " " + strings.Join(f, " ") + " "
		is47 := strings.Contains(joined, " -p 47 ") || strings.Contains(joined, " -p gre ")
		isICMP := strings.Contains(joined, " -p icmp ")
		viaGre := greIf != "" && strings.Contains(joined, " -i "+greIf+" ")
		deny := strings.Contains(joined, " -j DROP ") || strings.Contains(joined, " -j REJECT ")
		allow := strings.Contains(joined, " -j ACCEPT ")
		switch {
		case deny && is47:
			drops47 = true
		case deny && isICMP:
			dropsICMP = true
		case allow && (is47 || viaGre):
			accept47[chain] = true
			acceptICMP[chain] = acceptICMP[chain] || viaGre
		case allow && isICMP:
			acceptICMP[chain] = true
		}
	}
	for chain := range policyDrop {
		if !accept47[chain] {
			drops47 = true
		}
		if !acceptICMP[chain] {
			dropsICMP = true
		}
	}
	return
}

// parseConntrackInvalid sums the "invalid" column over all CPU rows of
// /proc/net/stat/nf_conntrack (hex values, first line is the header).
func parseConntrackInvalid(content string) (uint64, bool) {
	lines := strings.Split(strings.TrimSpace(content), "\n")
	if len(lines) < 2 {
		return 0, false
	}
	col := -1
	for i, h := range strings.Fields(lines[0]) {
		if h == "invalid" {
			col = i
		}
	}
	if col < 0 {
		return 0, false
	}
	var sum uint64
	for _, l := range lines[1:] {
		f := strings.Fields(l)
		if col >= len(f) {
			continue
		}
		v, err := strconv.ParseUint(f[col], 16, 64)
		if err != nil {
			return 0, false
		}
		sum += v
	}
	return sum, true
}

// parsePingRTT extracts "time=X ms" from ping output; -1 if absent.
func parsePingRTT(out string) float64 {
	i := strings.Index(out, "time=")
	if i < 0 {
		return -1
	}
	v := out[i+5:]
	if j := strings.IndexAny(v, " m"); j >= 0 {
		v = v[:j]
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return -1
	}
	return f
}

// ---- read-only collectors ----

// procRoot is swapped by tests to point at fixture files.
var procRoot = "/proc"

func readProcFile(rel string) (string, bool) {
	b, err := os.ReadFile(filepath.Join(procRoot, rel))
	if err != nil {
		return "", false
	}
	return string(b), true
}

func readRPFilter(scope string) int {
	s, ok := readProcFile("sys/net/ipv4/conf/" + scope + "/rp_filter")
	if !ok {
		return -1
	}
	return parseIntFile(s)
}

var (
	conntrackMu   sync.Mutex
	conntrackLast = map[string]uint64{}
)

func collectLocalSnapshot(p peerRecord) LocalSnapshot {
	s := LocalSnapshot{GreIf: p.GreIf, GreMTU: -1,
		RPFilterAll: readRPFilter("all"), RPFilterDefault: readRPFilter("default"), RPFilterIface: -1,
		InnerLocal: strings.SplitN(p.LocalGre, "/", 2)[0]}
	if p.GreIf != "" {
		s.RPFilterIface = readRPFilter(p.GreIf)
		if out, err := runCmdTimeout(3*time.Second, "ip", "-o", "link", "show", p.GreIf); err == nil {
			s.GreMTU = parseLinkMTU(string(out))
		}
	}
	if v, ok := readProcFile("sys/net/ipv4/ip_forward"); ok {
		s.IPForward = parseIntFile(v) == 1
	}
	if p.PeerGre != "" {
		if out, err := runCmdTimeout(3*time.Second, "ip", "route", "get", p.PeerGre); err == nil {
			src, dev := parseRouteGet(string(out))
			s.RouteKnown = dev != ""
			s.RouteBackViaGre = dev == p.GreIf
			s.SrcAddrOnReply = src
		}
	}
	if out, err := runCmdTimeout(5*time.Second, "iptables-save"); err == nil {
		s.FwChecked = true
		s.InputDropsProto47, s.FwDropsICMP = parseIptablesSave(string(out), p.GreIf)
	}
	if ct, ok := readProcFile("net/stat/nf_conntrack"); ok {
		if n, ok := parseConntrackInvalid(ct); ok {
			s.ConntrackKnown = true
			conntrackMu.Lock()
			prev, seen := conntrackLast[p.GreIf]
			conntrackLast[p.GreIf] = n
			conntrackMu.Unlock()
			s.ConntrackInvalidRising = seen && n > prev
		}
	}
	return s
}

func greCounters(iface string) (rx, tx uint64, ok bool) {
	c, found := readProcFile("net/dev")
	if !found {
		return 0, 0, false
	}
	return parseNetDevPackets(c, iface)
}

func pingProbe(layer string, size int, df bool, src, dst string) ProbeResult {
	r := ProbeResult{Layer: layer, Direction: DirHubToSpoke, Size: size, DF: df}
	args := []string{"-c", "1", "-W", "2"}
	if df {
		args = append(args, "-M", "do")
	}
	if size > 0 {
		args = append(args, "-s", strconv.Itoa(size-28))
	}
	if src != "" {
		args = append(args, "-I", src)
	}
	args = append(args, dst)
	start := time.Now()
	out, err := runCmdTimeout(4*time.Second, "ping", args...)
	if err != nil {
		r.Err = strings.TrimSpace(firstLine(string(out)))
		if r.Err == "" {
			r.Err = err.Error()
		}
		return r
	}
	r.OK = true
	r.RTTms = parsePingRTT(string(out))
	if r.RTTms < 0 {
		r.RTTms = ms(time.Since(start))
	}
	return r
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// probeHubToSpoke runs the hub-side half of the matrix. The spoke->hub half is
// filled with "unprobed" placeholders, except TCP layers that the hub can
// observe passively from live ESTABLISHED sessions.
func probeHubToSpoke(p peerRecord, s LocalSnapshot) ProbeMatrix {
	var m ProbeMatrix
	peerInner := p.PeerGre
	rx0, tx0, have := greCounters(p.GreIf)
	if peerInner != "" {
		m.Results = append(m.Results,
			pingProbe(LayerICMPGre64, 64, false, s.InnerLocal, peerInner),
			pingProbe(LayerICMPGre1300, 1300, true, s.InnerLocal, peerInner))
	}
	if p.RemotePub != "" {
		m.Results = append(m.Results, pingProbe(LayerICMPPublic, 0, false, "", p.RemotePub))
	}
	if rx1, tx1, ok := greCounters(p.GreIf); have && ok {
		dr, dt := rx1-rx0, tx1-tx0
		m.HubRxDelta, m.HubTxDelta = &dr, &dt
	}
	for _, l := range revPathLayers {
		if _, ok := m.get(DirHubToSpoke, l); !ok {
			m.Results = append(m.Results, ProbeResult{Layer: l, Direction: DirUnprobed})
		}
	}
	// Passive spoke->hub TCP: the spoke dialed us, so an ESTABLISHED session
	// proves that path in that direction.
	if p.FrpPort > 0 {
		all := parseSS(ssEstablished())
		add := func(layer string, ports []int, remote string) {
			if remote == "" {
				return
			}
			if ss := sessionsOn(all, ports, remote); len(ss) > 0 {
				m.Results = append(m.Results, ProbeResult{Layer: layer, Direction: DirSpokeToHub, OK: true, RTTms: minRTT(ss)})
			}
		}
		add(LayerTCPCtrlInner, []int{p.FrpPort}, p.PeerGre)
		add(LayerTCPCtrlPublic, []int{p.FrpPort}, p.RemotePub)
		add(LayerTCPWSS, []int{p.FrpPort + 2}, p.RemotePub)
	}
	return m
}

// ---- per-peer diagnosis, cache, API ----

type revPathEntry struct {
	PeerID    int              `json:"peer_id"`
	Name      string           `json:"name"`
	Checked   string           `json:"checked"`
	Diagnosis RevPathDiagnosis `json:"diagnosis"`
	Matrix    ProbeMatrix      `json:"matrix"`
	Snapshot  LocalSnapshot    `json:"snapshot"`
	checkedAt time.Time
}

const revPathTTL = 60 * time.Second

var (
	revPathMu    sync.Mutex // guards revPathCache
	revPathCache = map[int]*revPathEntry{}
	revPathRun   sync.Mutex // serialises collection so concurrent calls never fan out
)

func diagnosePeer(p peerRecord) *revPathEntry {
	e := &revPathEntry{PeerID: p.ID, Name: p.Name, checkedAt: time.Now()}
	e.Checked = e.checkedAt.UTC().Format(time.RFC3339)
	if p.NoGre || p.GreIf == "" {
		e.Diagnosis = finishDiag(VerdictUnknown, "low", []string{"peer has no GRE interface (standalone); nothing to diagnose"})
		return e
	}
	e.Snapshot = collectLocalSnapshot(p)
	e.Matrix = probeHubToSpoke(p, e.Snapshot)
	e.Diagnosis = classifyRevPath(e.Matrix, e.Snapshot)
	return e
}

// revPathRefresh returns entries for the wanted peers (all when ids is
// empty). Fresh cache entries are reused unless force is set; a forced call
// still reuses a result produced while it was waiting for the run lock.
func revPathRefresh(ids []int, force bool) []revPathEntry {
	arrived := time.Now()
	peers := loadPeers()
	want := map[int]bool{}
	for _, id := range ids {
		want[id] = true
	}
	var todo []peerRecord
	for _, p := range peers {
		if len(want) == 0 || want[p.ID] {
			todo = append(todo, p)
		}
	}
	revPathRun.Lock()
	defer revPathRun.Unlock()
	res := make([]revPathEntry, 0, len(todo))
	for _, p := range todo {
		revPathMu.Lock()
		c := revPathCache[p.ID]
		revPathMu.Unlock()
		reuse := c != nil && (c.checkedAt.After(arrived) || (!force && time.Since(c.checkedAt) < revPathTTL))
		if !reuse {
			c = diagnosePeer(p)
			revPathMu.Lock()
			revPathCache[p.ID] = c
			revPathMu.Unlock()
		}
		res = append(res, *c)
	}
	sort.Slice(res, func(i, j int) bool { return res[i].PeerID < res[j].PeerID })
	return res
}

// revPathCached is the probe-free view used by the doctor report.
func revPathCached() []revPathEntry {
	revPathMu.Lock()
	defer revPathMu.Unlock()
	res := make([]revPathEntry, 0, len(revPathCache))
	for _, c := range revPathCache {
		res = append(res, *c)
	}
	sort.Slice(res, func(i, j int) bool { return res[i].PeerID < res[j].PeerID })
	return res
}

func handleRevPathGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"peers": revPathRefresh(nil, false), "phase": 1, "read_only": true})
}

func handleRevPathRun(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PeerID int `json:"peer_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.PeerID <= 0 {
		http.Error(w, `{"error":"peer_id required"}`, http.StatusBadRequest)
		return
	}
	if findPeer(req.PeerID) == nil {
		http.Error(w, `{"error":"unknown peer"}`, http.StatusNotFound)
		return
	}
	res := revPathRefresh([]int{req.PeerID}, true)
	writeJSON(w, map[string]any{"peers": res, "phase": 1, "read_only": true})
}
