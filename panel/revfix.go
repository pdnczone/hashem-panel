package main

// Reverse-path auto-fix engine + spoke-side probes (Phase 4).
//
// Two halves:
//  1. Spoke probes: the hub asks a spoke (over the existing Peer Link
//     channel, same secret as /api/peer/ping) to run the spoke->hub half of
//     the matrix against its own view of the hub, and merges the result.
//  2. Auto-fix: for AutoFixable verdicts with confidence != low, a fix plan
//     (dry-run -> snapshot -> apply -> re-probe -> rollback if worse) using
//     only sysctl writes, `ip route` changes and our own iptables chain
//     HASHEM-REVPATH. Never restarts services. Report-only by default;
//     `revpath_auto` in the panel config (or HASHEM_REVPATH_AUTO=1) enables
//     automatic application, rate-limited to 1 fix / peer / 10 min and 3 /
//     hour globally.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ---------- config ----------

func revPathAutoEnabled() bool {
	if os.Getenv("HASHEM_REVPATH_AUTO") == "1" {
		return true
	}
	return cfg.RevPathAuto
}

// ---------- spoke-side probe transport ----------

// SpokeProbeRequest tells the spoke what to probe: the hub's inner + public
// address and the control port, as the hub sees them.
type SpokeProbeRequest struct {
	HubInner    string `json:"hub_inner"`
	HubPublic   string `json:"hub_public"`
	ControlPort int    `json:"control_port"`
}

// SpokeProbeReport is the spoke's answer: its local snapshot plus the
// spoke->hub half of the matrix.
type SpokeProbeReport struct {
	OK       bool          `json:"ok"`
	Error    string        `json:"error,omitempty"`
	Matrix   ProbeMatrix   `json:"matrix"`
	Snapshot LocalSnapshot `json:"snapshot"`
	SpokeGre string        `json:"spoke_gre,omitempty"`
	Checked  string        `json:"checked"`
}

// POST /api/peer/revpath-probe (peer auth): run the spoke->hub half locally.
func handlePeerRevPathProbe(w http.ResponseWriter, r *http.Request) {
	var req SpokeProbeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeAPIError(w, r, "E-ACTION-01", "invalid probe json")
		return
	}
	st := currentLocal()
	spokeInner := strings.SplitN(st.Gre.Inner, "/", 2)[0]
	snap := LocalSnapshot{
		GreIf:           "gre-tunnel",
		InnerLocal:      spokeInner,
		RPFilterAll:     readRPFilter("all"),
		RPFilterDefault: readRPFilter("default"),
		RPFilterIface:   readRPFilter("gre-tunnel"),
		GreMTU:          -1,
	}
	if v, ok := readProcFile("sys/net/ipv4/ip_forward"); ok {
		snap.IPForward = parseIntFile(v) == 1
	}
	if out, err := runCmdTimeout(3*time.Second, "ip", "-o", "link", "show", "gre-tunnel"); err == nil {
		snap.GreMTU = parseLinkMTU(string(out))
	}
	if req.HubInner != "" {
		if out, err := runCmdTimeout(3*time.Second, "ip", "route", "get", req.HubInner); err == nil {
			src, dev := parseRouteGet(string(out))
			snap.RouteKnown = dev != ""
			snap.RouteBackViaGre = dev == "gre-tunnel"
			snap.SrcAddrOnReply = src
		}
	}
	if out, err := runCmdTimeout(5*time.Second, "iptables-save"); err == nil {
		snap.FwChecked = true
		snap.InputDropsProto47, snap.FwDropsICMP = parseIptablesSave(string(out), "gre-tunnel")
	}
	m := probeFromSpoke(req, snap)
	writeJSON(w, SpokeProbeReport{OK: true, Matrix: m, Snapshot: snap,
		SpokeGre: spokeInner, Checked: time.Now().UTC().Format(time.RFC3339)})
}

// probeFromSpoke builds the spoke->hub matrix against the hub addresses the
// hub sent. Runs on the spoke; read-only.
func probeFromSpoke(req SpokeProbeRequest, snap LocalSnapshot) ProbeMatrix {
	var m ProbeMatrix
	rx0, tx0, have := greCounters("gre-tunnel")
	if req.HubInner != "" {
		m.Results = append(m.Results,
			spokePing(LayerICMPGre64, 64, false, snap.InnerLocal, req.HubInner),
			spokePing(LayerICMPGre1300, 1300, true, snap.InnerLocal, req.HubInner))
		if req.ControlPort > 0 {
			m.Results = append(m.Results, spokeTCP(LayerTCPCtrlInner, req.HubInner, req.ControlPort))
		}
	}
	if req.HubPublic != "" {
		m.Results = append(m.Results, spokePing(LayerICMPPublic, 0, false, "", req.HubPublic))
		if req.ControlPort > 0 {
			m.Results = append(m.Results, spokeTCP(LayerTCPCtrlPublic, req.HubPublic, req.ControlPort))
		}
	}
	if req.HubPublic != "" {
		// WSS front is control port + 2 by convention.
		if req.ControlPort > 0 {
			m.Results = append(m.Results, spokeTCP(LayerTCPWSS, req.HubPublic, req.ControlPort+2))
		}
	}
	if rx1, tx1, ok := greCounters("gre-tunnel"); have && ok {
		dr, dt := rx1-rx0, tx1-tx0
		m.SpokeRxDelta, m.SpokeTxDelta = &dr, &dt
	}
	return m
}

func spokePing(layer string, size int, df bool, src, dst string) ProbeResult {
	r := ProbeResult{Layer: layer, Direction: DirSpokeToHub, Size: size, DF: df}
	args := []string{"-c", "1", "-W", "2"}
	if df {
		args = append(args, "-M", "do")
	}
	if size > 0 {
		args = append(args, "-s", fmt.Sprint(size-28))
	}
	if src != "" {
		args = append(args, "-I", src)
	}
	args = append(args, dst)
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
	return r
}

func spokeTCP(layer, host string, port int) ProbeResult {
	r := ProbeResult{Layer: layer, Direction: DirSpokeToHub}
	c, err := dialFn("tcp", fmt.Sprintf("%s:%d", host, port), connectProbeTimeout)
	if err == nil {
		_ = c.Close()
		r.OK = true
		return r
	}
	if isRefusedErr(err) {
		// A refusal proves the path answers (spoke client, not a listener).
		r.OK = true
		return r
	}
	r.Err = err.Error()
	return r
}

// isRefusedErr reports a TCP connection refusal (path answers, no listener).
func isRefusedErr(err error) bool { return errors.Is(err, syscall.ECONNREFUSED) }

// spokeFetcher is the seam for the spoke half of the matrix: the real
// implementation dials the spoke's panel over HTTP; tests swap it.
var spokeFetcher = requestSpokeProbe

// requestSpokeProbe asks one spoke for its half of the matrix. It reuses the
// peer-link addressing (InternalIP then PeerURL) via a targeted send: the
// payload carries the spoke's own addresses so the spoke probes the right hub.
func requestSpokeProbe(p peerRecord) *SpokeProbeReport {
	c := loadPeerConfig()
	if c.PeerSecret == "" {
		return nil
	}
	hubInner := strings.SplitN(p.LocalGre, "/", 2)[0]
	if hubInner == "" {
		// Fall back to this hub's own inner address (single-tunnel layout).
		st := currentLocal()
		hubInner = strings.SplitN(st.Gre.Inner, "/", 2)[0]
	}
	req := SpokeProbeRequest{HubInner: hubInner, HubPublic: p.LocalPub, ControlPort: p.FrpPort}
	body, _ := json.Marshal(req)
	// Target the spoke directly: its panel answers on the GRE inner address
	// (peer tunnel IP) or its public address, same secret as other peer calls.
	urls := []string{}
	if p.PeerGre != "" {
		urls = append(urls, fmt.Sprintf("http://%s:%d%s/api/peer/revpath-probe", p.PeerGre, cfg.Port, "/"+cfg.BasePath))
	}
	if p.RemotePub != "" {
		urls = append(urls, fmt.Sprintf("http://%s:%d%s/api/peer/revpath-probe", p.RemotePub, cfg.Port, "/"+cfg.BasePath))
	}
	if len(urls) == 0 {
		return nil
	}
	client := &http.Client{Timeout: 15 * time.Second}
	for _, u := range urls {
		u = strings.Replace(u, "//api/", "/api/", 1)
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		hr, err := http.NewRequestWithContext(ctx, "POST", u, bytes.NewReader(body))
		if err != nil {
			cancel()
			continue
		}
		hr.Header.Set("Content-Type", "application/json")
		hr.Header.Set("X-Peer-Secret", c.PeerSecret)
		resp, err := client.Do(hr)
		cancel()
		if err != nil {
			continue
		}
		var rep SpokeProbeReport
		derr := json.NewDecoder(resp.Body).Decode(&rep)
		_ = resp.Body.Close()
		if derr != nil || !rep.OK {
			continue
		}
		return &rep
	}
	return nil
}

// mergeSpokeReport folds the spoke's half into the hub entry: spoke->hub
// results replace placeholders, spoke counters are attached, and the verdict
// is recomputed with both directions genuinely probed.
func mergeSpokeReport(e *revPathEntry, rep *SpokeProbeReport) {
	if rep == nil {
		return
	}
	keep := e.Matrix.Results[:0]
	for _, r := range e.Matrix.Results {
		if r.Direction == DirSpokeToHub || r.Direction == DirUnprobed {
			continue
		}
		keep = append(keep, r)
	}
	e.Matrix.Results = append(keep, rep.Matrix.Results...)
	e.Matrix.SpokeRxDelta = rep.Matrix.SpokeRxDelta
	e.Matrix.SpokeTxDelta = rep.Matrix.SpokeTxDelta
	e.Diagnosis = classifyRevPath(e.Matrix, e.Snapshot)
}

// ---------- auto-fix engine ----------

// FixStep is one applied change, recorded for the report and rollback.
type FixStep struct {
	At      string  `json:"at"`
	Verdict Verdict `json:"verdict"`
	Action  string  `json:"action"`
	Detail  string  `json:"detail"`
	OK      bool    `json:"ok"`
	Error   string  `json:"error,omitempty"`
}

// FixReport is the per-peer history returned by the API.
type FixReport struct {
	PeerID      int       `json:"peer_id"`
	Auto        bool      `json:"auto"`
	Steps       []FixStep `json:"steps"`
	LastRun     string    `json:"last_run,omitempty"`
	LastVerdict Verdict   `json:"last_verdict,omitempty"`
}

var (
	fixMu      sync.Mutex
	fixReports = map[int]*FixReport{}
	fixLastRun = map[int]time.Time{} // per-peer rate limit
	fixHour    = []time.Time{}       // global rate limit window
)

const (
	fixPeerCooldown = 10 * time.Minute
	fixHourMax      = 3
	revChain        = "HASHEM-REVPATH"
)

// fixAllowed reports whether a fix may run now (rate limits).
func fixAllowed(peerID int, now time.Time) bool {
	fixMu.Lock()
	defer fixMu.Unlock()
	if t, ok := fixLastRun[peerID]; ok && now.Sub(t) < fixPeerCooldown {
		return false
	}
	kept := fixHour[:0]
	for _, t := range fixHour {
		if now.Sub(t) < time.Hour {
			kept = append(kept, t)
		}
	}
	fixHour = kept
	return len(fixHour) < fixHourMax
}

func fixMarkRun(peerID int, now time.Time) {
	fixMu.Lock()
	defer fixMu.Unlock()
	fixLastRun[peerID] = now
	fixHour = append(fixHour, now)
}

func fixRecord(peerID int, s FixStep, auto bool, v Verdict) {
	fixMu.Lock()
	defer fixMu.Unlock()
	r := fixReports[peerID]
	if r == nil {
		r = &FixReport{PeerID: peerID}
		fixReports[peerID] = r
	}
	r.Auto = auto
	r.Steps = append(r.Steps, s)
	if len(r.Steps) > 20 {
		r.Steps = r.Steps[len(r.Steps)-20:]
	}
	r.LastRun = s.At
	r.LastVerdict = v
}

// revpathSysctlConf is the persist file for reverse-path sysctl fixes.
// Tests point it at a throwaway dir (same pattern as frpDir/backhaulDir);
// production keeps /etc/sysctl.d. Overridable with GRE_SYSCTL_CONF.
var revpathSysctlConf = "/etc/sysctl.d/99-hashem-revpath.conf"

// sysctlPersist writes key=value via sysctl -w and persists it to
// revpathSysctlConf. Returns a rollback closure.
func sysctlPersist(key, value string) (rollback func(), err error) {
	old, _ := runCmdTimeout(3*time.Second, "sysctl", "-n", key)
	oldVal := strings.TrimSpace(string(old))
	if _, err := runCmdTimeout(5*time.Second, "sysctl", "-w", key+"="+value); err != nil {
		return nil, err
	}
	conf := revpathSysctlConf
	rb := func() {
		_, _ = runCmdTimeout(5*time.Second, "sysctl", "-w", key+"="+oldVal)
	}
	if oldVal == value {
		return rb, nil
	}
	prev, _ := os.ReadFile(conf)
	lines := []string{}
	for _, l := range strings.Split(string(prev), "\n") {
		if strings.TrimSpace(l) == "" || strings.HasPrefix(strings.TrimSpace(l), "#") {
			lines = append(lines, l)
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(l), key+" ") || strings.HasPrefix(strings.TrimSpace(l), key+"=") {
			continue
		}
		lines = append(lines, l)
	}
	lines = append(lines, key+" = "+value)
	if err := os.MkdirAll(filepath.Dir(conf), 0755); err != nil {
		return rb, err
	}
	if err := os.WriteFile(conf, []byte(strings.Join(lines, "\n")), 0644); err != nil {
		return rb, err
	}
	return rb, nil
}

// chainEnsure makes sure our dedicated iptables chain exists and is
// referenced from INPUT and FORWARD. All auto-fix firewall rules live here;
// user rules are never touched.
func chainEnsure() error {
	if _, err := runCmdTimeout(3*time.Second, "iptables", "-n", "-L", revChain); err != nil {
		if _, err := runCmdTimeout(3*time.Second, "iptables", "-N", revChain); err != nil {
			return err
		}
	}
	for _, parent := range []string{"INPUT", "FORWARD"} {
		out, _ := runCmdTimeout(3*time.Second, "iptables", "-C", parent, "-j", revChain)
		_ = out
		if _, err := runCmdTimeout(3*time.Second, "iptables", "-C", parent, "-j", revChain); err != nil {
			if _, err := runCmdTimeout(3*time.Second, "iptables", "-I", parent, "1", "-j", revChain); err != nil {
				return err
			}
		}
	}
	return nil
}

// fixPlan builds the ordered actions for a diagnosis. Every action returns
// (description, apply func, rollback func).
func fixPlan(p peerRecord, snap LocalSnapshot, d RevPathDiagnosis) []fixAction {
	switch d.Verdict {
	case VerdictRPFilter:
		ifaces := []string{"net.ipv4.conf.all.rp_filter", "net.ipv4.conf.default.rp_filter"}
		if p.GreIf != "" {
			ifaces = append(ifaces, "net.ipv4.conf."+p.GreIf+".rp_filter")
		}
		var acts []fixAction
		for _, k := range ifaces {
			k := k
			acts = append(acts, fixAction{
				desc: "sysctl " + k + "=2 (loose)",
				apply: func() (func(), error) {
					return sysctlPersist(k, "2")
				},
			})
		}
		return acts
	case VerdictSrcSelect:
		return []fixAction{{
			desc: "pin GRE route source to " + snap.InnerLocal,
			apply: func() (func(), error) {
				old, _ := runCmdTimeout(3*time.Second, "ip", "route", "show", p.PeerGre)
				oldStr := strings.TrimSpace(string(old))
				args := []string{"route", "replace", p.PeerGre, "dev", p.GreIf}
				if snap.InnerLocal != "" {
					args = append(args, "src", snap.InnerLocal)
				}
				if _, err := runCmdTimeout(5*time.Second, "ip", args...); err != nil {
					return nil, err
				}
				return func() {
					if oldStr != "" {
						_, _ = runCmdTimeout(5*time.Second, "ip", "route", "replace", p.PeerGre, "dev", p.GreIf)
					} else {
						_, _ = runCmdTimeout(5*time.Second, "ip", "route", "del", p.PeerGre)
					}
				}, nil
			},
		}}
	case VerdictNoReturnRoute:
		return []fixAction{{
			desc: "add return route to " + p.PeerGre + " via " + p.GreIf,
			apply: func() (func(), error) {
				if _, err := runCmdTimeout(5*time.Second, "ip", "route", "replace", p.PeerGre, "dev", p.GreIf); err != nil {
					return nil, err
				}
				return func() {
					_, _ = runCmdTimeout(5*time.Second, "ip", "route", "del", p.PeerGre)
				}, nil
			},
		}}
	case VerdictFwInput:
		return []fixAction{{
			desc: "allow proto 47 + ICMP + " + p.GreIf + " in " + revChain,
			apply: func() (func(), error) {
				if err := chainEnsure(); err != nil {
					return nil, err
				}
				added := [][]string{}
				rules := [][]string{
					{"-p", "47", "-j", "ACCEPT"},
					{"-p", "icmp", "-j", "ACCEPT"},
				}
				if p.GreIf != "" {
					rules = append(rules, []string{"-i", p.GreIf, "-j", "ACCEPT"})
				}
				for _, r := range rules {
					if _, err := runCmdTimeout(3*time.Second, "iptables", append([]string{"-C", revChain}, r...)...); err != nil {
						args := append([]string{"-A", revChain}, r...)
						if _, err := runCmdTimeout(3*time.Second, "iptables", args...); err != nil {
							return nil, err
						}
						added = append(added, r)
					}
				}
				return func() {
					for _, r := range added {
						_, _ = runCmdTimeout(3*time.Second, "iptables", append([]string{"-D", revChain}, r...)...)
					}
				}, nil
			},
		}}
	case VerdictMTUBlackhole:
		steps := []int{1360, 1340, 1300}
		cur := snap.GreMTU
		next := 0
		for _, m := range steps {
			if cur <= 0 || m < cur {
				next = m
				break
			}
		}
		if next == 0 {
			return nil
		}
		return []fixAction{{
			desc: fmt.Sprintf("lower %s MTU %d -> %d", p.GreIf, cur, next),
			apply: func() (func(), error) {
				if _, err := runCmdTimeout(5*time.Second, "ip", "link", "set", "dev", p.GreIf, "mtu", fmt.Sprint(next)); err != nil {
					return nil, err
				}
				return func() {
					if cur > 0 {
						_, _ = runCmdTimeout(5*time.Second, "ip", "link", "set", "dev", p.GreIf, "mtu", fmt.Sprint(cur))
					}
				}, nil
			},
		}}
	case VerdictConntrackInvalid:
		return []fixAction{{
			desc: "NOTRACK proto 47 on " + p.GreIf + " (raw table)",
			apply: func() (func(), error) {
				chain := []string{"-t", "raw", "-p", "47", "-j", "NOTRACK"}
				rule := append([]string{}, chain...)
				if p.GreIf != "" {
					rule = []string{"-i", p.GreIf, "-p", "47", "-j", "NOTRACK"}
				}
				check := append([]string{"-t", "raw", "-C", "PREROUTING"}, rule...)
				if _, err := runCmdTimeout(3*time.Second, "iptables", check...); err != nil {
					if _, err := runCmdTimeout(3*time.Second, "iptables", append([]string{"-t", "raw", "-A", "PREROUTING"}, rule...)...); err != nil {
						return nil, err
					}
					return func() {
						_, _ = runCmdTimeout(3*time.Second, "iptables", append([]string{"-t", "raw", "-D", "PREROUTING"}, rule...)...)
					}, nil
				}
				return func() {}, nil
			},
		}}
	}
	return nil
}

type fixAction struct {
	desc  string
	apply func() (rollback func(), err error)
}

// worseAfter reports whether the re-probe is worse than before: a verdict
// that moved away from HEALTHY, or (same verdict class) still failing.
func worseAfter(before, after RevPathDiagnosis) bool {
	if before.Verdict == VerdictHealthy && after.Verdict != VerdictHealthy {
		return true
	}
	return false
}

// applyFix runs the plan for one peer: dry-run builds the plan only;
// otherwise snapshot -> apply -> re-probe -> rollback if worse. Every applied
// step is recorded. Service units are never restarted.
func applyFix(p peerRecord, snap LocalSnapshot, d RevPathDiagnosis, auto bool, dryRun bool) ([]FixStep, RevPathDiagnosis) {
	plan := fixPlan(p, snap, d)
	now := time.Now().UTC().Format(time.RFC3339)
	var steps []FixStep
	if dryRun {
		for _, a := range plan {
			steps = append(steps, FixStep{At: now, Verdict: d.Verdict, Action: "plan", Detail: a.desc, OK: true})
		}
		if len(plan) == 0 {
			steps = append(steps, FixStep{At: now, Verdict: d.Verdict, Action: "plan", Detail: "no local fix available (" + string(d.Verdict) + ")", OK: false})
		}
		return steps, d
	}
	if !fixAllowed(p.ID, time.Now()) {
		steps = append(steps, FixStep{At: now, Verdict: d.Verdict, Action: "rate-limited", Detail: "max 1 fix / peer / 10 min, 3 / hour; skipped", OK: false})
		return steps, d
	}
	type applied struct {
		desc string
		rb   func()
	}
	var done []applied
	rollbackAll := func() {
		for i := len(done) - 1; i >= 0; i-- {
			done[i].rb()
		}
	}
	for _, a := range plan {
		rb, err := a.apply()
		st := FixStep{At: now, Verdict: d.Verdict, Action: "apply", Detail: a.desc, OK: err == nil}
		if err != nil {
			st.Error = err.Error()
			steps = append(steps, st)
			rollbackAll()
			steps = append(steps, FixStep{At: now, Verdict: d.Verdict, Action: "rollback", Detail: "apply failed; reverted", OK: true})
			for _, s := range steps {
				fixRecord(p.ID, s, auto, d.Verdict)
			}
			return steps, d
		}
		steps = append(steps, st)
		done = append(done, applied{a.desc, rb})
	}
	fixMarkRun(p.ID, time.Now())
	// Re-probe and compare.
	after := diagnosePeer(p)
	if rep := spokeFetcher(p); rep != nil {
		mergeSpokeReport(after, rep)
		revPathMu.Lock()
		revPathCache[p.ID] = after
		revPathMu.Unlock()
	}
	if worseAfter(d, after.Diagnosis) {
		rollbackAll()
		steps = append(steps, FixStep{At: now, Verdict: d.Verdict, Action: "rollback", Detail: "re-probe worse (" + string(after.Diagnosis.Verdict) + "); reverted", OK: true})
		for _, s := range steps {
			fixRecord(p.ID, s, auto, d.Verdict)
		}
		return steps, after.Diagnosis
	}
	steps = append(steps, FixStep{At: now, Verdict: d.Verdict, Action: "verify", Detail: "re-probe: " + string(after.Diagnosis.Verdict), OK: true})
	for _, s := range steps {
		fixRecord(p.ID, s, auto, d.Verdict)
	}
	return steps, after.Diagnosis
}

// ---------- API ----------

// POST /api/revpath/fix {peer_id, apply?:bool} — dry-run plan by default;
// apply:true runs the fix (allowed only when revpath_auto is on, or when the
// operator clicks explicitly: explicit clicks bypass the auto flag but not
// the rate limits).
func handleRevPathFix(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PeerID int  `json:"peer_id"`
		Apply  bool `json:"apply"`
		Auto   bool `json:"auto"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.PeerID <= 0 {
		writeAPIError(w, r, "E-ACTION-01", "peer_id required")
		return
	}
	p := findPeer(req.PeerID)
	if p == nil {
		writeAPIError(w, r, "E-ACTION-01", "unknown peer")
		return
	}
	entries := revPathRefresh([]int{req.PeerID}, true)
	if len(entries) == 0 {
		writeAPIError(w, r, "E-SYS-01", "diagnosis failed")
		return
	}
	e := entries[0]
	if !req.Apply {
		steps, _ := applyFix(*p, e.Snapshot, e.Diagnosis, false, true)
		writeJSON(w, map[string]any{"peer_id": p.ID, "dry_run": true, "auto_enabled": revPathAutoEnabled(), "diagnosis": e.Diagnosis, "steps": steps})
		return
	}
	if req.Auto && !revPathAutoEnabled() {
		writeAPIError(w, r, "E-ACTION-01", "automatic fixes are off (revpath_auto)")
		return
	}
	steps, after := applyFix(*p, e.Snapshot, e.Diagnosis, req.Auto, false)
	writeJSON(w, map[string]any{"peer_id": p.ID, "dry_run": false, "auto": req.Auto, "before": e.Diagnosis, "after": after, "steps": steps})
}

// GET /api/revpath/fixes?peer_id=N — applied-fix history per peer (or all).
func handleRevPathFixes(w http.ResponseWriter, r *http.Request) {
	fixMu.Lock()
	defer fixMu.Unlock()
	q := r.URL.Query().Get("peer_id")
	if q != "" {
		for id, rep := range fixReports {
			if fmt.Sprint(id) == q {
				writeJSON(w, map[string]any{"fixes": []FixReport{*rep}, "auto_enabled": revPathAutoEnabled()})
				return
			}
		}
		writeJSON(w, map[string]any{"fixes": []FixReport{}, "auto_enabled": revPathAutoEnabled()})
		return
	}
	out := make([]FixReport, 0, len(fixReports))
	for _, rep := range fixReports {
		out = append(out, *rep)
	}
	writeJSON(w, map[string]any{"fixes": out, "auto_enabled": revPathAutoEnabled()})
}
