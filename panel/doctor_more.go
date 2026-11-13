package main

// Diagnostics, the parts the first version could not see:
//
//	reach      TCP (and TLS on TLS transports) to the other server's ports:
//	           tells a filtered port from a filtered IP and a server that is off
//	clock      this server's time sync and the other server's clock
//	trace      the route hop by hop (mtr, else traceroute), on demand
//	stability  a 1 to 5 minute ping (or TCP connect) run, on demand
//	ports      every forwarded port of every tunnel and customer, on demand
//	history    the last reports on disk, an optional schedule, and the
//	           rating fed to the alerts as a link named "diagnostics"
//
// Reach and clock run with every diagnosis (a few seconds, in parallel with
// the rest). Trace and stability are background jobs the page polls: one of
// each at a time, cancellable, never under doctorRunMu. Everything that
// touches the network or the host is a var, so tests never do.

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ---------- reach ----------

type reachProbe struct {
	Host   string  `json:"host"`
	Port   int     `json:"port"`
	Label  string  `json:"label"` // "tunnel", "panel", "https", "ssh"
	Anchor bool    `json:"anchor"`
	State  string  `json:"state"`         // "open", "refused", "timeout", "reset", "unreachable", "error"
	TLS    string  `json:"tls,omitempty"` // "ok", "cut", "plain" ("" = not tried)
	Ms     float64 `json:"ms"`
	Detail string  `json:"detail,omitempty"`
}

type reachSummary struct {
	Tested   bool         `json:"tested"`
	Probes   []reachProbe `json:"probes"`
	Verdict  string       `json:"verdict"`             // "open", "port_blocked", "port_closed", "tcp_blocked", "down", "tls_cut", ""
	TunnelOK bool         `json:"tunnel_ok,omitempty"` // the main tunnel works anyway: the verdict is no tunnel fault
}

type reachTarget struct {
	host   string
	port   int
	label  string
	anchor bool // a port that should answer: the tunnel port (spoke) or the peer's panel port (hub)
	tls    bool
}

const reachTimeout = 3 * time.Second

var (
	doctorReachFn = probeReach
	reachDial     = func(addr string, to time.Duration) (net.Conn, error) { return net.DialTimeout("tcp", addr, to) }
)

func isSpoke(st tunnelStatus) bool {
	return st.FrpSvc == "frpc" || strings.HasPrefix(strings.ToLower(st.Role), "foreign") || strings.ToLower(st.Role) == "kharej"
}

func tlsTransport(t string) bool {
	t = strings.ToLower(t)
	return strings.HasPrefix(t, "wss") || t == "tls"
}

// reachTargets: the anchor is the address and port this server really dials.
// On the dialing side (spoke) that is the engine's own server address and
// port (frpc serverAddr, Backhaul remote_addr); it gets no anchor when that is
// loopback (a local carrier client, such as WSS) or the GRE peer (the engine
// runs inside GRE: the GRE findings speak for that path). On the hub nothing
// listens on the foreign server's tunnel port, so the anchor is the Peer
// Link's panel port. 443 and 22 on the same address tell a filtered port from
// a filtered IP. Without an anchor the public address is probed for
// information only, and nothing is judged.
func reachTargets(st tunnelStatus, peer string, pc PeerConfig) []reachTarget {
	host, aPort, aLabel, aTLS := "", 0, "", false
	if isSpoke(st) {
		dial := normHost(st.RemotePub)
		ip := net.ParseIP(dial)
		inner := st.Gre.Inner != "" && dial == grePeerInner(st.Gre.Inner)
		if dial != "" && st.BindPort > 0 && !inner && !(ip != nil && ip.IsLoopback()) {
			host, aPort, aLabel, aTLS = dial, st.BindPort, "tunnel", tlsTransport(st.Transport)
		}
	} else if u := strings.TrimSpace(pc.PeerURL); u != "" {
		if !strings.Contains(u, "://") {
			u = "http://" + u
		}
		if p, err := url.Parse(u); err == nil && p.Hostname() != "" {
			port, _ := strconv.Atoi(p.Port())
			if port == 0 && p.Scheme == "https" {
				port = 443
			} else if port == 0 {
				port = 80
			}
			host, aPort, aLabel = normHost(p.Hostname()), port, "panel"
		}
	}
	if host == "" {
		host = peer
	}
	if host == "" {
		return nil
	}
	var out []reachTarget
	seen := map[int]bool{}
	add := func(port int, label string, anchor, tlsOn bool) {
		if port > 0 && port < 65536 && !seen[port] {
			seen[port] = true
			out = append(out, reachTarget{host, port, label, anchor, tlsOn})
		}
	}
	add(aPort, aLabel, true, aTLS)
	if aPort == 0 && isSpoke(st) && host == peer {
		add(st.BindPort, "tunnel", false, false) // shown, not judged
	}
	add(443, "https", false, false)
	add(22, "ssh", false, false)
	return out
}

func probeReach(ts []reachTarget) reachSummary {
	r := reachSummary{Tested: len(ts) > 0, Probes: make([]reachProbe, len(ts))}
	var wg sync.WaitGroup
	for i, t := range ts {
		wg.Add(1)
		go func(i int, t reachTarget) {
			defer wg.Done()
			r.Probes[i] = reachOne(t)
		}(i, t)
	}
	wg.Wait()
	return r
}

func reachOne(t reachTarget) reachProbe {
	p := reachProbe{Host: t.host, Port: t.port, Label: t.label, Anchor: t.anchor}
	start := time.Now()
	c, err := reachDial(net.JoinHostPort(t.host, strconv.Itoa(t.port)), reachTimeout)
	p.State = reachState(err)
	if p.State == "open" || p.State == "refused" {
		p.Ms = round1(float64(time.Since(start).Microseconds()) / 1000)
	}
	if err != nil && p.State == "error" {
		p.Detail = err.Error()
	}
	if c != nil {
		if t.tls {
			p.TLS = tlsHandshakeState(c, t.host)
		}
		_ = c.Close()
	}
	return p
}

func reachState(err error) string {
	switch {
	case err == nil:
		return "open"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "refused"
	case errors.Is(err, syscall.ECONNRESET):
		return "reset"
	case isTimeout(err):
		return "timeout"
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH):
		return "unreachable"
	}
	return "error"
}

// tlsHandshakeState: "ok" when the server answered TLS (a finished handshake
// or a TLS alert), "plain" when it answered something else, "cut" when the
// connection died before any answer.
func tlsHandshakeState(c net.Conn, host string) string {
	conf := &tls.Config{InsecureSkipVerify: true} // only asks whether TLS gets through; nothing is sent over it
	if net.ParseIP(host) == nil {
		conf.ServerName = host
	}
	_ = c.SetDeadline(time.Now().Add(4 * time.Second))
	err := tls.Client(c, conf).Handshake()
	switch {
	case err == nil, strings.Contains(err.Error(), "remote error"):
		return "ok"
	case strings.Contains(err.Error(), "does not look like a TLS handshake"), strings.Contains(err.Error(), "first record"):
		return "plain"
	}
	return "cut"
}

// reachVerdict reads the probes. Only an anchor port is expected to answer:
// a foreign server's firewall may well drop 443 and 22.
func reachVerdict(ps []reachProbe, icmpOK bool) (verdict string, at reachProbe) {
	var anchor *reachProbe
	for i := range ps {
		if ps[i].Anchor && anchor == nil {
			anchor = &ps[i]
		}
	}
	if anchor == nil {
		return "", reachProbe{}
	}
	answered := false
	for _, p := range ps {
		if p.Host == anchor.Host && (p.State == "open" || p.State == "refused") {
			answered = true
		}
	}
	switch {
	case !answered && icmpOK:
		return "tcp_blocked", *anchor
	case !answered:
		return "down", *anchor
	case anchor.State == "refused":
		return "port_closed", *anchor
	case anchor.State != "open":
		return "port_blocked", *anchor
	case anchor.TLS == "cut":
		return "tls_cut", *anchor
	}
	return "open", *anchor
}

func reachFinding(verdict string, p reachProbe) (doctorFinding, bool) {
	host, port := p.Host, strconv.Itoa(p.Port)
	switch verdict {
	case "tcp_blocked":
		return newFinding("warning", "path", 10, false,
			"{0} answers ping but no TCP port: TCP to this IP is filtered",
			"If its firewall allows port {1}, the route filters TCP to this IP. Change the foreign server's IP, or carry the tunnel over another route (Benchmark tab)", host, port), true
	case "down":
		return newFinding("warning", "path", 10, false,
			"{0} answers neither ping nor any TCP port",
			"The server is off, or its IP is blocked entirely. Check it from its provider's console", host), true
	case "port_closed":
		return newFinding("warning", "path", 10, false,
			"{0} refuses port {1}: nothing listens there",
			"The server is up, but the service on that port is not running. Check it on that server, and that both servers use port {1}", host, port), true
	case "port_blocked":
		fix := "Move the tunnel to another port with Setup on both servers"
		if p.Label == "panel" {
			fix = "The panel link to that server uses this port: open it in that server's firewall, or change its panel port"
		}
		return newFinding("warning", "path", 10, false,
			"Port {1} on {0} does not answer while other ports do: that port is filtered", fix, host, port), true
	case "tls_cut":
		return newFinding("warning", "path", 10, false,
			"TCP to {0}:{1} connects but the TLS handshake is cut",
			"Something on the route interferes with TLS. Try another transport for this tunnel", host, port), true
	}
	return doctorFinding{}, false
}

// ---------- clock ----------

type clockSummary struct {
	Tested     bool    `json:"tested"`
	NTP        string  `json:"ntp"` // "yes", "no", "" = unknown
	PeerKnown  bool    `json:"peer_known"`
	PeerSkewMs float64 `json:"peer_skew_ms"` // the other server's clock minus this one
	PeerErrMs  float64 `json:"peer_err_ms"`  // the measurement's uncertainty (half the call)
}

var doctorClockFn = probeClock

func probeClock() clockSummary {
	c := clockSummary{Tested: true}
	if out, err := runCmdTimeoutOut(3*time.Second, "timedatectl", "show", "-p", "NTPSynchronized", "--value"); err == nil {
		switch strings.TrimSpace(string(out)) {
		case "yes":
			c.NTP = "yes"
		case "no":
			c.NTP = "no"
		}
	}
	if strings.TrimSpace(loadPeerConfig().PeerURL) == "" {
		return c
	}
	t0 := time.Now()
	resp, err := sendToPeer("/api/peer/ping", "POST", map[string]string{"frp_version": localFrpVersion()})
	t1 := time.Now()
	if err != nil {
		return c
	}
	var pong struct {
		Time int64 `json:"time"`
	}
	if json.Unmarshal(resp, &pong) != nil || pong.Time <= 0 {
		return c
	}
	c.PeerKnown = true
	c.PeerSkewMs, c.PeerErrMs = clockSkew(t0, t1, pong.Time)
	return c
}

// clockSkew compares the peer's clock with the middle of the call.
func clockSkew(t0, t1 time.Time, peerNano int64) (skewMs, errMs float64) {
	mid := t0.Add(t1.Sub(t0) / 2)
	skew := time.Unix(0, peerNano).Sub(mid)
	return round1(float64(skew.Microseconds()) / 1000), round1(float64(t1.Sub(t0).Microseconds()) / 2000)
}

func clockFindings(c clockSummary) []doctorFinding {
	var out []doctorFinding
	if c.PeerKnown {
		off := math.Abs(c.PeerSkewMs) - c.PeerErrMs
		secs := strconv.Itoa(int(math.Round(math.Abs(c.PeerSkewMs) / 1000)))
		switch {
		case off > 60000:
			out = append(out, newFinding("warning", "config", 10, false, "The two servers' clocks differ by {0} seconds",
				"VMess, TLS and two-step sign-in codes fail when clocks are this far apart. Turn on time sync on both servers: timedatectl set-ntp true", secs))
		case off > 5000:
			out = append(out, newFinding("minor", "config", 3, false, "The two servers' clocks differ by {0} seconds",
				"Small now, but drift grows. Turn on time sync on both servers: timedatectl set-ntp true", secs))
		}
	}
	return out
}

// clockNote: NTP off is only a note. Containers and a fresh boot report it
// while the clock is right, and set-ntp cannot change it there; a clock that
// is really off shows as drift against the other server.
func clockNote(c clockSummary) string {
	if c.NTP == "no" {
		return "This server's clock is not synced to a time server (timedatectl set-ntp true turns it on)"
	}
	return ""
}

// ---------- targets (trace and stability go only to addresses from the config) ----------

type docTarget struct {
	ID    string `json:"id"`
	Host  string `json:"host"`
	Label string `json:"label"`
	Inner bool   `json:"inner,omitempty"` // inside the GRE tunnel
	Port  int    `json:"port,omitempty"`  // a TCP port expected to answer (stability without ping)
}

var doctorTargetsFn = doctorTargets

func doctorTargets() []docTarget {
	st := currentLocal() // the snapshot's copy: the page polls this while a test runs
	var out []docTarget
	seen := map[string]bool{}
	add := func(t docTarget) {
		if t.Host != "" && !seen[t.Host] && len(out) < 12 {
			seen[t.Host] = true
			out = append(out, t)
		}
	}
	if st.Gre.Exists && st.Gre.Inner != "" {
		add(docTarget{ID: "gre", Host: grePeerInner(st.Gre.Inner), Label: "Inside the GRE tunnel", Inner: true})
	}
	pub := normHost(st.Gre.PeerIP)
	if pub == "" {
		pub = normHost(st.RemotePub)
	}
	port := 0
	for _, t := range reachTargets(st, pub, loadPeerConfig()) {
		if t.anchor {
			port = t.port
		}
	}
	add(docTarget{ID: "peer", Host: pub, Label: "The other server", Port: port})
	if s := currentSnapshot(); s != nil {
		for _, p := range s.Peers {
			name := p.Name
			if name == "" {
				name = "peer-" + strconv.Itoa(p.ID)
			}
			add(docTarget{ID: "peer-" + strconv.Itoa(p.ID), Host: normHost(p.RemotePub), Label: name})
		}
	}
	return out
}

func findTarget(id string, inner bool) (docTarget, bool) {
	for _, t := range doctorTargetsFn() {
		if t.ID == id && (inner || !t.Inner) {
			return t, true
		}
	}
	return docTarget{}, false
}

// ---------- background jobs ----------

type docJob struct {
	Kind     string  `json:"kind"`
	Running  bool    `json:"running"`
	Started  string  `json:"started,omitempty"`
	Finished string  `json:"finished,omitempty"`
	Target   string  `json:"target,omitempty"`
	Progress float64 `json:"progress"` // 0..1
	Error    string  `json:"error,omitempty"`
	Result   any     `json:"result,omitempty"`
	cancel   context.CancelFunc
}

var (
	docJobsMu sync.Mutex
	docJobs   = map[string]*docJob{}
)

// docJobStart runs fn in the background; one job of a kind at a time.
func docJobStart(kind, target string, limit time.Duration, fn func(ctx context.Context, set func(progress float64, partial any)) (any, error)) error {
	docJobsMu.Lock()
	if j := docJobs[kind]; j != nil && j.Running {
		docJobsMu.Unlock()
		return fmt.Errorf("a %s test is already running", kind)
	}
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	j := &docJob{Kind: kind, Running: true, Started: time.Now().UTC().Format(time.RFC3339), Target: target, cancel: cancel}
	docJobs[kind] = j
	docJobsMu.Unlock()
	go func() {
		defer cancel()
		set := func(p float64, partial any) {
			docJobsMu.Lock()
			j.Progress = math.Min(1, math.Max(0, p))
			if partial != nil {
				j.Result = partial
			}
			docJobsMu.Unlock()
		}
		res, err := func() (res any, err error) {
			defer func() {
				if r := recover(); r != nil {
					err = fmt.Errorf("internal error: %v", r)
				}
			}()
			return fn(ctx, set)
		}()
		docJobsMu.Lock()
		j.Running, j.Progress, j.Finished = false, 1, time.Now().UTC().Format(time.RFC3339)
		if res != nil {
			j.Result = res
		}
		if err != nil {
			j.Error = err.Error()
		}
		docJobsMu.Unlock()
	}()
	return nil
}

func docJobView(kind string) *docJob {
	docJobsMu.Lock()
	defer docJobsMu.Unlock()
	j := docJobs[kind]
	if j == nil {
		return nil
	}
	c := *j
	c.cancel = nil
	return &c
}

func docJobStop(kind string) {
	docJobsMu.Lock()
	defer docJobsMu.Unlock()
	if j := docJobs[kind]; j != nil && j.Running && j.cancel != nil {
		j.cancel()
	}
}

// ---------- trace ----------

type traceHop struct {
	N     int     `json:"n"`
	Host  string  `json:"host"` // "" = no answer
	Loss  float64 `json:"loss"`
	Sent  int     `json:"sent"`
	Avg   float64 `json:"avg"`
	Best  float64 `json:"best"`
	Worst float64 `json:"worst"`
}

type traceResult struct {
	Target    string     `json:"target"`
	Tool      string     `json:"tool"` // "mtr", "traceroute"
	Mode      string     `json:"mode"` // "icmp", "tcp"
	Port      int        `json:"port,omitempty"`
	Hops      []traceHop `json:"hops"`
	Verdict   string     `json:"verdict"`              // "clean", "loss", "no_reply_end", ""
	LossFrom  int        `json:"loss_from,omitempty"`  // the hop where loss that lasts to the end starts
	BorderHop int        `json:"border_hop,omitempty"` // the hop with the biggest jump in latency (the long link)
	Installed bool       `json:"installed,omitempty"`  // mtr was installed for this run
}

var (
	lookPath    = exec.LookPath
	traceRunFn  = runTraceCmd
	installMtrF = func() error {
		_, _ = runCmdTimeout(90*time.Second, "apt-get", "update", "-qq")
		_, err := runCmdTimeout(150*time.Second, "env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "install", "-y", "-qq", "mtr-tiny")
		return err
	}
	errTraceMissing = errors.New("neither mtr nor traceroute is installed on this server")
)

func runTraceCmd(ctx context.Context, name string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, name, args...).Output()
	return string(out), err
}

func runTrace(ctx context.Context, t docTarget, mode string, port int, install bool) (*traceResult, error) {
	res := &traceResult{Target: t.Host, Mode: mode}
	if mode == "tcp" {
		res.Port = port
	}
	if _, err := lookPath("mtr"); err != nil && install {
		if ierr := installMtrF(); ierr == nil {
			if _, err := lookPath("mtr"); err == nil {
				res.Installed = true
			}
		}
	}
	if _, err := lookPath("mtr"); err == nil {
		res.Tool = "mtr"
		args := []string{"-n", "-r", "-w", "-c", "20", "-i", "0.5", "-m", "30"}
		if mode == "tcp" {
			args = append(args, "-T", "-P", strconv.Itoa(port))
		}
		out, err := traceRunFn(ctx, "mtr", append(args, t.Host)...)
		res.Hops = parseMtrReport(out)
		if len(res.Hops) == 0 {
			if err == nil {
				err = errors.New("mtr printed no hops")
			}
			return nil, fmt.Errorf("mtr failed: %w", err)
		}
	} else if _, err := lookPath("traceroute"); err == nil {
		res.Tool = "traceroute"
		args := []string{"-n", "-q", "3", "-w", "2", "-m", "30"}
		if mode == "tcp" {
			args = append(args, "-T", "-p", strconv.Itoa(port))
		}
		out, err := traceRunFn(ctx, "traceroute", append(args, t.Host)...)
		res.Hops = parseTraceroute(out)
		if len(res.Hops) == 0 {
			if err == nil {
				err = errors.New("traceroute printed no hops")
			}
			return nil, fmt.Errorf("traceroute failed: %w", err)
		}
	} else {
		return nil, errTraceMissing
	}
	res.Verdict, res.LossFrom, res.BorderHop = traceVerdict(res.Hops, t.Host)
	return res, nil
}

var mtrLine = regexp.MustCompile(`^\s*(\d+)\.\s*\|--\s+(\S+)\s+([\d.]+)%?\s+(\d+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)`)

// parseMtrReport reads `mtr -r -w -n` output.
func parseMtrReport(out string) []traceHop {
	var hops []traceHop
	for _, line := range strings.Split(out, "\n") {
		m := mtrLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		h := traceHop{Host: m[2]}
		h.N, _ = strconv.Atoi(m[1])
		h.Loss, _ = strconv.ParseFloat(m[3], 64)
		h.Sent, _ = strconv.Atoi(m[4])
		h.Avg, _ = strconv.ParseFloat(m[6], 64)
		h.Best, _ = strconv.ParseFloat(m[7], 64)
		h.Worst, _ = strconv.ParseFloat(m[8], 64)
		if h.Host == "???" {
			h.Host, h.Loss = "", 100
		}
		hops = append(hops, h)
	}
	return hops
}

// parseTraceroute reads `traceroute -n -q 3` output.
func parseTraceroute(out string) []traceHop {
	var hops []traceHop
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		n, err := strconv.Atoi(f[0])
		if err != nil {
			continue
		}
		h := traceHop{N: n}
		var rtts []float64
		stars := 0
		for i := 1; i < len(f); i++ {
			switch {
			case f[i] == "*":
				stars++
			case f[i] == "ms":
			case net.ParseIP(f[i]) != nil:
				if h.Host == "" {
					h.Host = f[i]
				}
			default:
				if v, err := strconv.ParseFloat(f[i], 64); err == nil && i+1 < len(f) && f[i+1] == "ms" {
					rtts = append(rtts, v)
				}
			}
		}
		h.Sent = len(rtts) + stars
		if h.Sent > 0 {
			h.Loss = round1(float64(stars) * 100 / float64(h.Sent))
		}
		if len(rtts) > 0 {
			sort.Float64s(rtts)
			sum := 0.0
			for _, v := range rtts {
				sum += v
			}
			h.Avg, h.Best, h.Worst = round1(sum/float64(len(rtts))), rtts[0], rtts[len(rtts)-1]
		}
		if h.Host == "" {
			h.Loss = 100
		}
		hops = append(hops, h)
	}
	return hops
}

// traceVerdict: loss at a middle hop that does not last to the end is a
// router that rate-limits its replies, not lost traffic. Only loss that runs
// to the destination counts; it starts where that run starts. traceLossMin is
// two of mtr's 20 probes: one lost probe is noise.
const traceLossMin = 10.0

func traceVerdict(hops []traceHop, target string) (verdict string, lossFrom, border int) {
	last := -1
	for i, h := range hops {
		if h.Host != "" {
			last = i
		}
	}
	if last < 0 {
		return "no_reply_end", 1, 0
	}
	prev, bestJump := -1.0, 40.0
	for _, h := range hops[:last+1] {
		if h.Host == "" || h.Loss >= 100 {
			continue
		}
		if prev >= 0 && h.Avg-prev > bestJump {
			bestJump, border = h.Avg-prev, h.N
		}
		prev = h.Avg
	}
	if hops[last].Host != target {
		if last+1 < len(hops) {
			return "no_reply_end", hops[last+1].N, border
		}
		return "no_reply_end", hops[last].N + 1, border
	}
	if hops[last].Loss < traceLossMin {
		return "clean", 0, border
	}
	from := hops[last].N
	for i := last - 1; i >= 0; i-- {
		h := hops[i]
		if h.Host == "" {
			continue // no answer here says nothing
		}
		if h.Loss < traceLossMin {
			break
		}
		from = h.N
	}
	return "loss", from, border
}

// ---------- stability ----------

type stabilityResult struct {
	Target     string    `json:"target"`
	Mode       string    `json:"mode"` // "icmp", "tcp"
	Port       int       `json:"port,omitempty"`
	Interval   float64   `json:"interval"` // seconds between samples
	Seconds    int       `json:"seconds"`
	Samples    []float64 `json:"samples"` // ms, -1 = lost
	Sent       int       `json:"sent"`
	Lost       int       `json:"lost"`
	LossPct    float64   `json:"loss_pct"`
	Avg        float64   `json:"avg"`
	P50        float64   `json:"p50"`
	P95        float64   `json:"p95"`
	Max        float64   `json:"max"`
	Jitter     float64   `json:"jitter"`
	Drops      int       `json:"drops"`       // runs of lost samples
	LongestGap float64   `json:"longest_gap"` // seconds of the longest run
	Spikes     int       `json:"spikes"`
	Verdict    string    `json:"verdict"` // "stable", "spiky", "lossy", "drops", ""
}

var (
	stabPingFn = stabilityPing
	stabTCPFn  = stabilityTCP
	stabPingOK = func(host string) bool {
		_, err := runCmdTimeout(4*time.Second, "ping", "-n", "-c", "2", "-i", "0.3", "-W", "1", host)
		return err == nil
	}
)

func runStability(ctx context.Context, t docTarget, secs int, set func(float64, any)) (*stabilityResult, error) {
	r := &stabilityResult{Target: t.Host, Seconds: secs}
	start := time.Now()
	progress := func(samples []float64) {
		p := *r
		p.Samples = append([]float64(nil), samples...)
		summarizeStability(&p)
		set(time.Since(start).Seconds()/float64(secs), &p)
	}
	var err error
	if stabPingOK(t.Host) {
		r.Mode, r.Interval = "icmp", 0.5
		r.Samples, err = stabPingFn(ctx, t.Host, secs, progress)
	} else if t.Port > 0 {
		r.Mode, r.Interval, r.Port = "tcp", 1, t.Port
		r.Samples, err = stabTCPFn(ctx, net.JoinHostPort(t.Host, strconv.Itoa(t.Port)), secs, progress)
	} else {
		return nil, errors.New("this address answers neither ping nor a known TCP port; run Diagnostics and check the reachability card")
	}
	if len(r.Samples) == 0 {
		if err == nil {
			err = errors.New("no samples")
		}
		return nil, err
	}
	if ctx.Err() == context.Canceled {
		r.Seconds = int(time.Since(start).Seconds())
	}
	summarizeStability(r)
	return r, nil
}

var pingReply = regexp.MustCompile(`icmp_seq=(\d+).*time=([\d.]+)`)

func stabilityPing(ctx context.Context, host string, secs int, progress func([]float64)) ([]float64, error) {
	cmd := exec.CommandContext(ctx, "ping", "-n", "-O", "-i", "0.5", "-W", "1", "-w", strconv.Itoa(secs), host)
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	got := map[int]float64{}
	maxSeq := 0
	snapshot := func() []float64 {
		s := make([]float64, maxSeq)
		for i := range s {
			if v, ok := got[i+1]; ok {
				s[i] = v
			} else {
				s[i] = -1
			}
		}
		return s
	}
	sc := bufio.NewScanner(out)
	last := time.Now()
	for sc.Scan() {
		line := sc.Text()
		if m := pingReply.FindStringSubmatch(line); m != nil {
			seq, _ := strconv.Atoi(m[1])
			v, _ := strconv.ParseFloat(m[2], 64)
			got[seq] = v
			maxSeq = max(maxSeq, seq)
		} else if i := strings.Index(line, "no answer yet for icmp_seq="); i >= 0 {
			seq, _ := strconv.Atoi(strings.TrimSpace(line[i+len("no answer yet for icmp_seq="):]))
			maxSeq = max(maxSeq, seq)
		}
		if time.Since(last) > time.Second {
			last = time.Now()
			progress(snapshot())
		}
	}
	_ = cmd.Wait() // exit 1 = some packets lost: still a result
	return snapshot(), nil
}

func stabilityTCP(ctx context.Context, addr string, secs int, progress func([]float64)) ([]float64, error) {
	var s []float64
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	end := time.Now().Add(time.Duration(secs) * time.Second)
	for time.Now().Before(end) {
		start := time.Now()
		c, err := reachDial(addr, 1500*time.Millisecond)
		if err == nil {
			s = append(s, round1(float64(time.Since(start).Microseconds())/1000))
			_ = c.Close()
		} else if reachState(err) == "refused" {
			s = append(s, round1(float64(time.Since(start).Microseconds())/1000)) // the host answered
		} else {
			s = append(s, -1)
		}
		progress(s)
		select {
		case <-ctx.Done():
			return s, nil
		case <-tick.C:
		}
	}
	return s, nil
}

// summarizeStability fills the numbers and the verdict from the samples.
func summarizeStability(r *stabilityResult) {
	r.Sent, r.Lost, r.Drops, r.LongestGap, r.Spikes = len(r.Samples), 0, 0, 0, 0
	r.Avg, r.P50, r.P95, r.Max, r.Jitter, r.LossPct, r.Verdict = 0, 0, 0, 0, 0, 0, ""
	if r.Sent == 0 {
		return
	}
	var ok []float64
	run, prev, jsum, jn := 0, -1.0, 0.0, 0
	for _, v := range r.Samples {
		if v < 0 {
			r.Lost++
			if run == 0 {
				r.Drops++
			}
			run++
			r.LongestGap = math.Max(r.LongestGap, float64(run)*r.Interval)
			continue
		}
		run = 0
		ok = append(ok, v)
		if prev >= 0 {
			jsum += math.Abs(v - prev)
			jn++
		}
		prev = v
	}
	r.LossPct = round1(float64(r.Lost) * 100 / float64(r.Sent))
	r.LongestGap = round1(r.LongestGap)
	if len(ok) > 0 {
		sorted := append([]float64(nil), ok...)
		sort.Float64s(sorted)
		sum := 0.0
		for _, v := range ok {
			sum += v
		}
		r.Avg = round1(sum / float64(len(ok)))
		r.P50 = sorted[len(sorted)/2]
		r.P95 = sorted[min(len(sorted)-1, int(math.Ceil(float64(len(sorted))*0.95))-1)]
		r.Max = sorted[len(sorted)-1]
		if jn > 0 {
			r.Jitter = round1(jsum / float64(jn))
		}
		limit := math.Max(r.P50*2, r.P50+50)
		for _, v := range ok {
			if v > limit {
				r.Spikes++
			}
		}
	}
	switch {
	case r.LongestGap >= 3 || r.LossPct >= 5:
		r.Verdict = "drops"
	case r.LossPct >= 1:
		r.Verdict = "lossy"
	case float64(r.Spikes) > float64(r.Sent)*0.05:
		r.Verdict = "spiky"
	default:
		r.Verdict = "stable"
	}
}

// ---------- forwarded ports ----------

type docPort struct {
	Key    string  `json:"key"`
	Group  string  `json:"group"`
	Kind   string  `json:"kind"` // "tunnel", "customer"
	Engine string  `json:"engine,omitempty"`
	Port   int     `json:"port"`
	State  string  `json:"state,omitempty"` // "ok", "fail" ("" = not tested)
	Ms     float64 `json:"ms,omitempty"`
	Detail string  `json:"detail,omitempty"`
	UDP    bool    `json:"udp,omitempty"` // the link forwards UDP too; only TCP is tested
	hosts  []string
}

const docPortsMax = 80

var docPortsFn = docPortList

func docPortList() []docPort {
	var out []docPort
	if s := currentSnapshot(); s != nil {
		for _, t := range thTargets(s) {
			name := t.name
			if name == "" {
				name = "tunnel-" + strconv.Itoa(t.id)
			}
			for _, p := range t.ports {
				out = append(out, docPort{Key: "t" + strconv.Itoa(t.id) + ":" + strconv.Itoa(p), Group: name, Kind: "tunnel", Engine: t.engine, Port: p, hosts: t.hosts})
			}
		}
	}
	custs.Lock()
	custLoadLocked()
	for _, c := range custs.f.Customers {
		if c.Cut != "" {
			continue
		}
		for _, l := range c.Links {
			g := c.Name
			if l.Name != "" {
				g += " · " + l.Name
			}
			for _, p := range l.Ports {
				out = append(out, docPort{Key: "c" + strconv.Itoa(c.ID) + "-" + strconv.Itoa(l.ID) + ":" + strconv.Itoa(p), Group: g, Kind: "customer", Engine: l.Engine, Port: p, UDP: l.UDP, hosts: []string{"127.0.0.1"}})
			}
		}
	}
	custs.Unlock()
	if len(out) > docPortsMax {
		out = out[:docPortsMax]
	}
	return out
}

var docPortProbe = dataProbe

// testDocPorts probes the given ports (all when keys is empty), 8 at a time.
func testDocPorts(keys []string) []docPort {
	all := docPortsFn()
	want := map[string]bool{}
	for _, k := range keys {
		want[k] = true
	}
	var list []docPort
	for _, p := range all {
		if len(want) == 0 || want[p.Key] {
			list = append(list, p)
		}
	}
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for i := range list {
		wg.Add(1)
		sem <- struct{}{}
		go func(p *docPort) {
			defer wg.Done()
			defer func() { <-sem }()
			rtt, detail, err := docPortProbe(p.hosts, p.Port)
			if err != nil {
				p.State, p.Detail = "fail", err.Error()
				return
			}
			p.State, p.Ms, p.Detail = "ok", round1(rtt), detail
		}(&list[i])
	}
	wg.Wait()
	return list
}

// ---------- history and schedule ----------

type docHistEntry struct {
	T        int64    `json:"t"`
	Score    int      `json:"score"`
	Rating   string   `json:"rating"`
	Findings int      `json:"findings"`
	Crit     int      `json:"crit"`
	RTT      float64  `json:"rtt"`  // through the tunnel, else the public IP; -1 = no reply / not measured
	Loss     float64  `json:"loss"` // -1 = not measured
	Mbps     float64  `json:"mbps,omitempty"`
	Auto     bool     `json:"auto,omitempty"` // a scheduled run
	TopTpl   string   `json:"top_tpl,omitempty"`
	TopArgs  []string `json:"top_args,omitempty"`
}

type docSchedule struct {
	EveryHours int  `json:"every_hours"` // 0 = off
	Alert      bool `json:"alert"`       // the rating feeds the alerts (Settings > Alerts)
}

type docHistFile struct {
	V        int            `json:"v"`
	Schedule docSchedule    `json:"schedule"`
	Entries  []docHistEntry `json:"entries"`
}

const docHistMax = 60

var (
	docHistMu     sync.Mutex
	docHist       docHistFile
	docHistLoaded bool
)

func docHistPath() string { return filepath.Join(configDir, "doctor_history.json") }

func docHistLoadLocked() {
	if docHistLoaded {
		return
	}
	docHistLoaded = true
	docHist = docHistFile{V: 1}
	if b, err := os.ReadFile(docHistPath()); err == nil {
		var f docHistFile
		if json.Unmarshal(b, &f) == nil && f.V == 1 {
			docHist = f
		}
	}
	if len(docHist.Entries) > docHistMax {
		docHist.Entries = docHist.Entries[len(docHist.Entries)-docHistMax:]
	}
}

func docHistSaveLocked() {
	b, err := json.Marshal(docHist)
	if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(docHistPath()), 0700)
	tmp := docHistPath() + ".tmp"
	if os.WriteFile(tmp, b, 0600) == nil {
		_ = os.Rename(tmp, docHistPath()) // a crash never leaves half a file
	}
}

func docHistEntryOf(rep *doctorReport, auto bool) docHistEntry {
	e := docHistEntry{Score: rep.Score, Rating: rep.Rating, Findings: len(rep.Findings), RTT: -1, Loss: -1, Auto: auto}
	if t, err := time.Parse(time.RFC3339, rep.Timestamp); err == nil {
		e.T = t.Unix()
	} else {
		e.T = time.Now().Unix()
	}
	for _, f := range rep.Findings {
		if f.Severity == "critical" {
			e.Crit++
		}
	}
	if len(rep.Findings) > 0 {
		e.TopTpl, e.TopArgs = rep.Findings[0].TitleTpl, rep.Findings[0].Args
	}
	p := rep.PingResult
	if !p.Tested {
		p = rep.Underlay
	}
	if p.Tested {
		e.Loss = p.PacketLoss
		if p.Success {
			e.RTT = round1(p.AvgRTT)
		}
	}
	if rep.SpeedResult.Tested {
		e.Mbps = rep.SpeedResult.ThroughputMbps
	}
	return e
}

func docHistRecord(rep *doctorReport, auto bool) {
	if rep == nil || !rep.Configured {
		return
	}
	docHistMu.Lock()
	defer docHistMu.Unlock()
	docHistLoadLocked()
	docHist.Entries = append(docHist.Entries, docHistEntryOf(rep, auto))
	if len(docHist.Entries) > docHistMax {
		docHist.Entries = docHist.Entries[len(docHist.Entries)-docHistMax:]
	}
	docHistSaveLocked()
}

func docHistView() docHistFile {
	docHistMu.Lock()
	defer docHistMu.Unlock()
	docHistLoadLocked()
	c := docHist
	c.Entries = append([]docHistEntry(nil), docHist.Entries...)
	return c
}

func docScheduleSet(s docSchedule) (docSchedule, error) {
	switch s.EveryHours {
	case 0, 1, 3, 6, 12, 24:
	default:
		return docSchedule{}, errors.New("every_hours must be 0, 1, 3, 6, 12 or 24")
	}
	docHistMu.Lock()
	defer docHistMu.Unlock()
	docHistLoadLocked()
	docHist.Schedule = s
	docHistSaveLocked()
	return s, nil
}

// docScheduleDue: a scheduled run is due when the last run (manual or not)
// is at least EveryHours old.
func docScheduleDue(now time.Time, s docSchedule, lastRun time.Time) bool {
	if s.EveryHours <= 0 {
		return false
	}
	return lastRun.IsZero() || now.Sub(lastRun) >= time.Duration(s.EveryHours)*time.Hour
}

// startDoctorScheduler runs scheduled diagnoses (only with the Pro license,
// checked on every tick) and never under tests: main() starts it.
func startDoctorScheduler() {
	time.Sleep(2 * time.Minute) // let the tunnels settle after a start or an update
	for {
		doctorScheduleTick(time.Now())
		time.Sleep(time.Minute)
	}
}

func doctorScheduleTick(now time.Time) {
	if !hasPro(proDiagnostics) {
		return
	}
	h := docHistView()
	last := time.Time{}
	if n := len(h.Entries); n > 0 {
		last = time.Unix(h.Entries[n-1].T, 0)
	}
	lastDoctorMu.RLock()
	if lastDoctorAt.After(last) {
		last = lastDoctorAt
	}
	lastDoctorMu.RUnlock()
	if docScheduleDue(now, h.Schedule, last) {
		doctorRefreshAuto(true)
	}
}

// doctorAlertLink is the last diagnosis as an alert link: critical = down,
// needs attention = degraded. Present only when the schedule asks for alerts.
func doctorAlertLink() (linkSnap, bool) {
	if !hasPro(proDiagnostics) {
		return linkSnap{}, false
	}
	docHistMu.Lock()
	docHistLoadLocked()
	s := docHist.Schedule
	docHistMu.Unlock()
	if !s.Alert || s.EveryHours == 0 {
		return linkSnap{}, false
	}
	lastDoctorMu.RLock()
	rep := lastDoctorReport
	lastDoctorMu.RUnlock()
	if rep == nil || !rep.Configured {
		return linkSnap{}, false
	}
	return doctorLinkOf(rep), true
}

func doctorLinkOf(rep *doctorReport) linkSnap {
	l := linkSnap{Name: "diagnostics", State: stateHealthy}
	switch rep.Rating {
	case "critical":
		l.State = stateDown
	case "warning":
		l.State = stateDegraded
	}
	l.Why = fmt.Sprintf("score %d/100", rep.Score)
	if len(rep.Findings) > 0 {
		l.Why += ": " + rep.Findings[0].Title
	}
	return l
}

// ---------- API ----------

type doctorExtraView struct {
	Targets   []docTarget `json:"targets"`
	History   docHistFile `json:"history"`
	Ports     []docPort   `json:"ports"`
	Trace     *docJob     `json:"trace"`
	Stability *docJob     `json:"stability"`
	MtrFound  bool        `json:"mtr_found"`
	Alerts    struct {
		Enabled  bool `json:"enabled"`
		Degraded bool `json:"degraded"` // "needs attention" changes alert too
	} `json:"alerts"`
	TraceTool string       `json:"trace_tool"` // "mtr", "traceroute", ""
	Clock     clockSummary `json:"clock"`
}

// GET /api/doctor/extra: everything the second half of the page shows.
func handleDoctorExtraGet(w http.ResponseWriter, r *http.Request) {
	if proRequired(w, r, proDiagnostics, "Diagnostics") {
		return
	}
	v := doctorExtraView{Targets: doctorTargetsFn(), History: docHistView(), Ports: docPortsFn(),
		Trace: docJobView("trace"), Stability: docJobView("stability")}
	ac := loadAlertConfig()
	v.Alerts.Enabled, v.Alerts.Degraded = ac.Enabled, ac.NotifyDegrad
	if _, err := lookPath("mtr"); err == nil {
		v.MtrFound, v.TraceTool = true, "mtr"
	} else if _, err := lookPath("traceroute"); err == nil {
		v.TraceTool = "traceroute"
	}
	if v.Targets == nil {
		v.Targets = []docTarget{}
	}
	if v.Ports == nil {
		v.Ports = []docPort{}
	}
	writeJSON(w, v)
}

// doctorPostMore handles the actions added here; false = not one of them.
func doctorPostMore(w http.ResponseWriter, r *http.Request, req doctorPostRequest) bool {
	switch req.Action {
	case "trace":
		t, ok := findTarget(req.Target, false)
		if !ok {
			writeAPIError(w, r, "E-ACTION-02", "unknown trace target")
			return true
		}
		mode, port := "icmp", 0
		if req.Mode == "tcp" {
			if t.Port == 0 {
				writeAPIError(w, r, "E-ACTION-02", "no TCP port is known for this server")
				return true
			}
			mode, port = "tcp", t.Port
		}
		err := docJobStart("trace", t.Host, 4*time.Minute, func(ctx context.Context, set func(float64, any)) (any, error) {
			stop := make(chan struct{})
			defer close(stop)
			go func() { // mtr prints only at the end: show time passing
				start := time.Now()
				for {
					select {
					case <-stop:
						return
					case <-time.After(time.Second):
						set(time.Since(start).Seconds()/20, nil)
					}
				}
			}()
			res, err := runTrace(ctx, t, mode, port, req.Install)
			if res == nil {
				return nil, err
			}
			return res, err
		})
		if err != nil {
			writeAPIError(w, r, "E-ACTION-03", err.Error())
			return true
		}
		writeJSON(w, map[string]any{"status": "ok", "job": docJobView("trace")})
	case "stability":
		t, ok := findTarget(req.Target, true)
		if !ok {
			writeAPIError(w, r, "E-ACTION-02", "unknown stability target")
			return true
		}
		secs := req.Seconds
		if secs != 60 && secs != 180 && secs != 300 {
			writeAPIError(w, r, "E-ACTION-02", "seconds must be 60, 180 or 300")
			return true
		}
		err := docJobStart("stability", t.Host, time.Duration(secs+30)*time.Second, func(ctx context.Context, set func(float64, any)) (any, error) {
			res, err := runStability(ctx, t, secs, set)
			if res == nil {
				return nil, err
			}
			return res, err
		})
		if err != nil {
			writeAPIError(w, r, "E-ACTION-03", err.Error())
			return true
		}
		writeJSON(w, map[string]any{"status": "ok", "job": docJobView("stability")})
	case "trace-stop", "stability-stop":
		kind := strings.TrimSuffix(req.Action, "-stop")
		docJobStop(kind)
		writeJSON(w, map[string]any{"status": "ok", "job": docJobView(kind)})
	case "ports":
		if len(req.Keys) > docPortsMax {
			writeAPIError(w, r, "E-ACTION-02", "too many ports")
			return true
		}
		writeJSON(w, map[string]any{"status": "ok", "ports": testDocPorts(req.Keys)})
	case "schedule":
		s, err := docScheduleSet(docSchedule{EveryHours: req.EveryHours, Alert: req.Alert})
		if err != nil {
			writeAPIError(w, r, "E-ACTION-02", err.Error())
			return true
		}
		writeJSON(w, map[string]any{"status": "ok", "schedule": s})
	default:
		return false
	}
	return true
}
