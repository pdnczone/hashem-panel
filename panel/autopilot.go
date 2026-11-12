package main

// Autopilot (Hashem Pro): when a tunnel stays down, find a carrier that gets
// through and move the tunnel to it, on both servers, without the admin.
//
// It only connects what already exists:
//
//  1. The health model says a tunnel is down (snapshot.go). Autopilot waits
//     until it was down for down_minutes, and only for a tunnel it has seen up
//     before (a tunnel still being set up is nobody's to switch).
//  2. The path test (pathtest.go) is started on this server and the foreign
//     server is told to join it over the peer API, so every transport is
//     measured between the two servers as they are right now.
//  3. The carrier swap (carrier_swap.go) moves the tunnel to the best carrier
//     that got through. The swap itself puts both servers back when the tunnel
//     does not reconnect, so Autopilot can try the next carrier.
//
// Limits keep it from flapping: a cooldown per tunnel, a number of runs per
// day, quiet hours, and at most apMaxTries carriers per run. Everything it
// does is written to its history and sent to the alert channels.
//
// It runs on the Iran server (the side that swaps). The foreign panel must
// answer on its public address: with the tunnel down there is no other way to
// tell it.

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type autopilotConfig struct {
	Enabled     bool     `json:"enabled"`
	DownMinutes int      `json:"down_minutes"`     // down this long before Autopilot acts
	CooldownMin int      `json:"cooldown_minutes"` // per tunnel, between two runs
	MaxPerDay   int      `json:"max_per_day"`      // per tunnel, runs in 24 hours
	PathTest    bool     `json:"path_test"`        // measure the carriers first
	Notify      bool     `json:"notify"`           // webhook / Telegram of the alerts
	Carriers    []string `json:"carriers"`         // allowed carriers; empty: every one the tunnel can run
	Skip        []int    `json:"skip"`             // tunnels Autopilot leaves alone
	QuietFrom   int      `json:"quiet_from"`       // no switching from this hour (server time) ...
	QuietTo     int      `json:"quiet_to"`         // ... to this one; equal: no quiet hours
}

const (
	apMaxTries   = 3                // carriers tried in one run
	apFailMemory = 6 * time.Hour    // a carrier that failed is tried last for this long
	apMaxEvents  = 100              // history kept
	apUpEvery    = 10 * time.Minute // how often "seen up" is written to disk
)

func autopilotConfigPath() string { return filepath.Join(configDir, "autopilot.json") }
func autopilotStatePath() string  { return filepath.Join(configDir, "autopilot_state.json") }

func defaultAutopilotConfig() autopilotConfig {
	return autopilotConfig{DownMinutes: 5, CooldownMin: 30, MaxPerDay: 6, PathTest: true, Notify: true,
		Carriers: []string{}, Skip: []int{}}
}

func loadAutopilotConfig() autopilotConfig {
	c := defaultAutopilotConfig()
	if b, err := os.ReadFile(autopilotConfigPath()); err == nil {
		_ = json.Unmarshal(b, &c)
	}
	c, _ = cleanAutopilotConfig(c)
	return c
}

// cleanAutopilotConfig puts every value in its range and reports the first
// one a person got wrong (the file is read with the same function, so a
// damaged file never makes Autopilot act faster than its limits).
func cleanAutopilotConfig(c autopilotConfig) (autopilotConfig, error) {
	var first error
	bad := func(format string, a ...any) {
		if first == nil {
			first = fmt.Errorf(format, a...)
		}
	}
	if c.DownMinutes < 2 || c.DownMinutes > 720 {
		bad("minutes down must be 2-720")
		c.DownMinutes = 5
	}
	if c.CooldownMin < 10 || c.CooldownMin > 1440 {
		bad("the pause between two runs must be 10-1440 minutes")
		c.CooldownMin = 30
	}
	if c.MaxPerDay < 1 || c.MaxPerDay > 24 {
		bad("runs per day must be 1-24")
		c.MaxPerDay = 6
	}
	if c.QuietFrom < 0 || c.QuietFrom > 23 || c.QuietTo < 0 || c.QuietTo > 23 {
		bad("quiet hours must be 0-23")
		c.QuietFrom, c.QuietTo = 0, 0
	}
	seen := map[string]bool{}
	out := []string{}
	for _, id := range c.Carriers {
		ch, err := parseCarrierChoice(id)
		if err != nil {
			bad("%v", err)
			continue
		}
		if !seen[ch.ID()] {
			seen[ch.ID()] = true
			out = append(out, ch.ID())
		}
	}
	c.Carriers = out
	skip := []int{}
	for _, id := range c.Skip {
		if id >= 0 {
			skip = append(skip, id)
		}
	}
	c.Skip = skip
	return c, first
}

func saveAutopilotConfig(c autopilotConfig) error {
	_ = os.MkdirAll(configDir, 0700)
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(autopilotConfigPath(), b, 0600)
}

// ---- state ----

type apEvent struct {
	At     string `json:"at"`
	Tunnel int    `json:"tunnel"`
	Name   string `json:"name"`
	Kind   string `json:"kind"` // switched | failed | skipped | recovered
	From   string `json:"from,omitempty"`
	To     string `json:"to,omitempty"`
	Text   string `json:"text"`
}

type apTunnelState struct {
	Key     string           `json:"key,omitempty"`      // apKey: which tunnel this id is
	LastUp  int64            `json:"last_up,omitempty"`  // seen healthy or degraded
	LastRun int64            `json:"last_run,omitempty"` // the cooldown counts from here
	Runs    []int64          `json:"runs,omitempty"`     // runs of the last 24 hours
	Failed  map[string]int64 `json:"failed,omitempty"`   // carrier -> when it last did not connect
}

type apState struct {
	Tunnels map[int]*apTunnelState `json:"tunnels"`
	Events  []apEvent              `json:"events"`
}

func (s *apState) tun(id int) *apTunnelState {
	if s.Tunnels == nil {
		s.Tunnels = map[int]*apTunnelState{}
	}
	t := s.Tunnels[id]
	if t == nil {
		t = &apTunnelState{}
		s.Tunnels[id] = t
	}
	return t
}

// runsSince drops the runs older than a day and returns how many are left.
func (t *apTunnelState) runsToday(now time.Time) int {
	keep := t.Runs[:0]
	for _, r := range t.Runs {
		if now.Unix()-r < 86400 {
			keep = append(keep, r)
		}
	}
	t.Runs = keep
	return len(keep)
}

type autopilot struct {
	mu        sync.Mutex
	st        *apState
	downSince map[int]time.Time
	wait      map[int]string // why Autopilot is not acting on a down tunnel yet
	running   bool
	runID     int
	phase     string
}

var ap = &autopilot{downSince: map[int]time.Time{}, wait: map[int]string{}}

// Seams: tests replace them. The ones that reach the swap and the path test
// are set in init (they lead back to the snapshot, an initialization cycle).
var (
	apNow        = time.Now
	apResolve    func(int) (swapTunnel, error)
	apPathTestFn func(swapTunnel) ([]ptCheck, error)
	apSwapFn     func(swapTunnel, carrierChoice) (string, string)
	apPingFn     func(swapTunnel) error
	apLinkedFn   func(swapTunnel) bool
	apNotifyFn   = apNotifyReal
	apAsync      = func(f func()) { go f() }
	apTestWait   = 150 * time.Second
	apSwapWait   = 4 * time.Minute
)

func init() {
	apResolve, apPathTestFn, apSwapFn = resolveSwapTunnel, apPathTestReal, apSwapReal
	apPingFn = func(t swapTunnel) error {
		_, err := swapCall(t, "POST", "/api/peer/ping", map[string]string{"action": "ping"}, 8*time.Second)
		return err
	}
	apLinkedFn = func(t swapTunnel) bool { return swapLinkedFn(t, t.Current) }
}

func (a *autopilot) stateLocked() *apState {
	if a.st == nil {
		a.st = &apState{}
		if b, err := os.ReadFile(autopilotStatePath()); err == nil {
			_ = json.Unmarshal(b, a.st)
		}
	}
	return a.st
}

func (a *autopilot) saveLocked() {
	if a.st == nil {
		return
	}
	_ = os.MkdirAll(configDir, 0700)
	if b, err := json.MarshalIndent(a.st, "", "  "); err == nil {
		_ = os.WriteFile(autopilotStatePath(), b, 0600)
	}
}

// eventLocked adds e to the history. The same thing said again about the same
// tunnel (a foreign panel that stays unreachable) is not repeated.
func (a *autopilot) eventLocked(e apEvent) bool {
	st := a.stateLocked()
	for i := len(st.Events) - 1; i >= 0; i-- {
		if st.Events[i].Tunnel != e.Tunnel {
			continue
		}
		if st.Events[i].Kind == e.Kind && st.Events[i].Text == e.Text && e.Kind == "skipped" {
			return false
		}
		break
	}
	st.Events = append(st.Events, e)
	if n := len(st.Events) - apMaxEvents; n > 0 {
		st.Events = append([]apEvent(nil), st.Events[n:]...)
	}
	return true
}

func (a *autopilot) setPhase(p string) {
	a.mu.Lock()
	a.phase = p
	a.mu.Unlock()
}

// ---- deciding ----

func apSwappable(engine string) bool {
	switch strings.ToLower(engine) {
	case "", "frp", "backhaul", "gre-backhaul":
		return true
	}
	return false
}

func apQuiet(c autopilotConfig, now time.Time) bool {
	if c.QuietFrom == c.QuietTo {
		return false
	}
	h := now.Hour()
	if c.QuietFrom < c.QuietTo {
		return h >= c.QuietFrom && h < c.QuietTo
	}
	return h >= c.QuietFrom || h < c.QuietTo // over midnight
}

// apGate says why Autopilot does not act on down tunnel l now ("" when it
// does). It is pure: the limits are all here.
func apGate(c autopilotConfig, now time.Time, l peerLive, ts *apTunnelState, downSince time.Time) string {
	for _, id := range c.Skip {
		if id == l.ID {
			return "left alone in the settings"
		}
	}
	if !apSwappable(l.Engine) {
		return "a " + l.Engine + " tunnel has no carrier to swap"
	}
	if !l.FrpUp {
		return "its service is not running on this server, which is not a blocked path"
	}
	if ts.LastUp == 0 {
		return "it has not been up yet since Autopilot was turned on"
	}
	need := time.Duration(c.DownMinutes) * time.Minute
	if d := now.Sub(downSince); d < need {
		return fmt.Sprintf("down for %d of %d minutes", int(d/time.Minute), c.DownMinutes)
	}
	if apQuiet(c, now) {
		return fmt.Sprintf("quiet hours (%02d:00-%02d:00)", c.QuietFrom, c.QuietTo)
	}
	if left := time.Duration(c.CooldownMin)*time.Minute - now.Sub(time.Unix(ts.LastRun, 0)); ts.LastRun > 0 && left > 0 {
		return fmt.Sprintf("next run in %d minutes", int(left/time.Minute)+1)
	}
	if ts.runsToday(now) >= c.MaxPerDay {
		return fmt.Sprintf("%d runs in the last 24 hours: the limit", c.MaxPerDay)
	}
	return ""
}

// apCandidates lists the carriers tunnel t may be moved to, most promising
// first. A tunnel that is down on a GRE carrier first leaves GRE (protocol 47
// being blocked is the usual reason, and another transport inside the same
// GRE link does not help), and a tunnel without GRE first stays without it.
// Carriers that did not connect lately go last.
func apCandidates(t swapTunnel, c autopilotConfig, failed map[string]int64, now time.Time, hasBin func(string) bool, backhaulOK bool) []carrierChoice {
	allowed := map[string]bool{}
	for _, id := range c.Carriers {
		allowed[id] = true
	}
	var plain, gre []carrierChoice
	if hasBin("backhaul") && (backhaulOK || t.Current.Engine != "frp") {
		for _, tr := range []string{"tcpmux", "wssmux", "wsmux", "wss", "ws", "tcp", "udp"} {
			plain = append(plain, carrierChoice{"backhaul", tr})
			if t.GreOK {
				gre = append(gre, carrierChoice{"gre-backhaul", tr})
			}
		}
	}
	if t.GreOK && hasBin("frps") {
		var frp []carrierChoice
		for _, tr := range frpProtocols {
			frp = append(frp, carrierChoice{"frp", tr})
		}
		gre = append(frp, gre...)
	}
	all := append(plain, gre...)
	var fresh, tired []carrierChoice
	for _, ch := range all {
		if ch == t.Current || (len(allowed) > 0 && !allowed[ch.ID()]) {
			continue
		}
		if at := failed[ch.ID()]; at > 0 && now.Sub(time.Unix(at, 0)) < apFailMemory {
			tired = append(tired, ch)
		} else {
			fresh = append(fresh, ch)
		}
	}
	return append(fresh, tired...)
}

// apRank orders the candidates by what the path test measured: a carrier
// whose transport did not get through is dropped, the ones that did go first
// (fastest first), and what the test could not tell stays last. A GRE carrier
// needs the GRE row; when the tunnel's GRE link is wrapped (WSS, 6to4, 4in6)
// the plain GRE row says nothing about it.
func apRank(cands []carrierChoice, checks []ptCheck, greDirect bool) ([]carrierChoice, string) {
	row := map[string]ptCheck{}
	for _, c := range checks {
		row[c.ID] = c
	}
	inner := func(ch carrierChoice) ptCheck {
		if ch.Engine == "frp" {
			return row["frp-"+ch.Transport]
		}
		return row["bh-"+ch.Transport]
	}
	type scored struct {
		ch   carrierChoice
		mbps float64
		rtt  float64
	}
	var proven []scored
	var unknown []carrierChoice
	dropped := 0
	for _, ch := range cands {
		r := inner(ch)
		verdict := r.Status
		if ch.needsGRE() {
			verdict = row["gre"].Status
			if !greDirect {
				verdict = ""
			}
		}
		switch verdict {
		case "ok":
			s := scored{ch: ch, rtt: r.RTTMs}
			if r.Status == "ok" {
				s.mbps = r.Mbps
			}
			proven = append(proven, s)
		case "fail":
			dropped++
		default:
			unknown = append(unknown, ch)
		}
	}
	sort.SliceStable(proven, func(i, j int) bool {
		if proven[i].mbps != proven[j].mbps {
			return proven[i].mbps > proven[j].mbps
		}
		return proven[i].rtt < proven[j].rtt
	})
	out := make([]carrierChoice, 0, len(proven)+len(unknown))
	for _, s := range proven {
		out = append(out, s.ch)
	}
	out = append(out, unknown...)
	return out, fmt.Sprintf("path test: %d of %d carriers got through", len(proven), len(proven)+dropped)
}

// apLinks lists every tunnel of snapshot s once. The first tunnel is also a
// peers.json record on some servers (the legacy peer 1, or a hub whose only
// units are a peer's): Autopilot then follows the record, so one tunnel never
// gets two runs.
func apLinks(s *HubSnapshot) []peerLive {
	links := append([]peerLive(nil), s.Peers...)
	if s.Main == nil {
		return links
	}
	recs := make([]peerRecord, 0, len(s.Peers))
	for _, p := range s.Peers {
		recs = append(recs, p.peerRecord)
	}
	if basePeer(recs) != nil || perPeerUnitRe.MatchString(s.Local.FrpSvc) {
		return links
	}
	return append([]peerLive{*s.Main}, links...)
}

// apKey names what a tunnel id stands for. When it changes (the tunnel was
// removed and its id given to a new one, or it points at another server) what
// Autopilot knew about the id is forgotten, so the new tunnel has to be seen
// up before it is ever switched.
func apKey(l peerLive) string { return fmt.Sprintf("%s|%d", l.RemotePub, l.FrpPort) }

// ---- the tick ----

// autopilotOnSnapshot is called after every snapshot build.
func autopilotOnSnapshot(s *HubSnapshot) {
	cfg := loadAutopilotConfig()
	now := apNow()
	ap.mu.Lock()
	// The Iran server swaps; a foreign server follows it.
	iran := strings.Contains(strings.ToLower(s.Local.Role), "iran") || len(s.Peers) > 0
	if !cfg.Enabled || !iran || !hasPro(proAutopilot) {
		ap.downSince, ap.wait = map[int]time.Time{}, map[int]string{}
		ap.mu.Unlock()
		return
	}
	st := ap.stateLocked()
	dirty := false
	seen := map[int]bool{}
	live := map[int]peerLive{}
	for _, l := range apLinks(s) {
		seen[l.ID] = true
		live[l.ID] = l
		if ts := st.tun(l.ID); ts.Key != apKey(l) {
			if ts.Key != "" {
				*ts = apTunnelState{}
				delete(ap.downSince, l.ID)
			}
			ts.Key = apKey(l)
			dirty = true
		}
		switch l.HealthState {
		case stateDown:
			if _, ok := ap.downSince[l.ID]; !ok {
				ap.downSince[l.ID] = now
			}
		case stateHealthy, stateDegraded:
			delete(ap.downSince, l.ID)
			if ts := st.tun(l.ID); now.Sub(time.Unix(ts.LastUp, 0)) > apUpEvery {
				ts.LastUp = now.Unix()
				dirty = true
			}
		}
	}
	for id := range ap.downSince {
		if !seen[id] {
			delete(ap.downSince, id)
		}
	}
	ap.wait = map[int]string{}
	due, dueSince := -1, now
	ids := make([]int, 0, len(ap.downSince))
	for id := range ap.downSince {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	for _, id := range ids {
		why := apGate(cfg, now, live[id], st.tun(id), ap.downSince[id])
		if why != "" {
			ap.wait[id] = why
			continue
		}
		if ap.downSince[id].Before(dueSince) { // the tunnel down longest goes first
			due, dueSince = id, ap.downSince[id]
		}
	}
	start := due >= 0 && !ap.running
	if start {
		ap.running, ap.runID, ap.phase = true, due, "Starting"
		st.tun(due).LastRun = now.Unix()
		dirty = true
	}
	if dirty {
		ap.saveLocked()
	}
	ap.mu.Unlock()
	if start {
		name := live[due].Name
		apAsync(func() { autopilotRun(cfg, due, name, now.Sub(dueSince)) })
	}
}

// ---- one run ----

func autopilotRun(cfg autopilotConfig, id int, name string, downFor time.Duration) {
	now := apNow()
	ev := apEvent{At: now.Format(time.RFC3339), Tunnel: id, Name: name}
	counted := false
	defer func() {
		if r := recover(); r != nil {
			recordError("E-ACTION-02", "autopilot", fmt.Sprintf("run for tunnel %d stopped: %v", id, r))
			ap.mu.Lock()
			ap.running, ap.phase = false, ""
			ap.mu.Unlock()
		}
	}()
	finish := func(kind, text string) {
		ev.Kind, ev.Text = kind, text
		ap.mu.Lock()
		if counted {
			ts := ap.stateLocked().tun(id)
			ts.Runs = append(ts.Runs, now.Unix())
		}
		added := ap.eventLocked(ev)
		ap.running, ap.phase = false, ""
		ap.saveLocked()
		ap.mu.Unlock()
		LogSecurityAudit("autopilot_"+kind, "autopilot", "127.0.0.1", fmt.Sprintf("tunnel=%d from=%s to=%s %s", id, ev.From, ev.To, text))
		if added && cfg.Notify && (kind == "switched" || kind == "failed") {
			apNotifyFn(ev)
		}
	}

	t, err := apResolve(id)
	if err != nil {
		finish("skipped", err.Error())
		return
	}
	if t.Name != "" {
		ev.Name = t.Name
	}
	if !apSwappable(t.Current.Engine) {
		finish("skipped", "a "+t.Current.Engine+" tunnel has no carrier to swap")
		return
	}
	from := t.Current
	ev.From = from.ID()

	ap.setPhase("Reaching the foreign panel")
	if err := apPingFn(t); err != nil {
		finish("skipped", "the foreign panel does not answer from this server, so nothing was changed (the foreign server may be off, or its panel port is closed to this server): "+err.Error())
		return
	}
	counted = true

	ap.mu.Lock()
	failed := map[string]int64{}
	for k, v := range ap.stateLocked().tun(id).Failed {
		failed[k] = v
	}
	ap.mu.Unlock()
	cands := apCandidates(t, cfg, failed, now, engineBinaryPresent, hasPro(proBackhaul))
	if len(cands) == 0 {
		finish("skipped", "no other carrier is allowed or installed for this tunnel")
		return
	}

	note := ""
	if cfg.PathTest {
		ap.setPhase("Testing the path")
		checks, err := apPathTestFn(t)
		if err != nil {
			note = "path test skipped (" + err.Error() + ")"
		} else {
			direct := t.rec == nil || t.rec.Carrier == "" || t.rec.Carrier == "direct"
			if t.Main {
				direct = loadCarrierConfig().ActiveCarrier == "direct"
			}
			cands, note = apRank(cands, checks, direct)
			if len(cands) == 0 {
				finish("failed", fmt.Sprintf("down for %d minutes on %s, and no other allowed carrier got through the path test", int(downFor/time.Minute), carrierLabel(from)))
				return
			}
		}
	}

	var tried []string
	for i, to := range cands {
		if i >= apMaxTries {
			break
		}
		if apLinkedFn(t) {
			finish("recovered", "the tunnel came back on "+carrierLabel(t.Current)+" by itself")
			return
		}
		ap.setPhase("Moving to " + carrierLabel(to))
		state, why := apSwapFn(t, to)
		if state == "ok" {
			ev.To = to.ID()
			text := fmt.Sprintf("moved from %s to %s after %d minutes down", carrierLabel(from), carrierLabel(to), int(downFor/time.Minute))
			if note != "" {
				text += " (" + note + ")"
			}
			finish("switched", text)
			return
		}
		if state == "busy" {
			finish("skipped", why)
			return
		}
		tried = append(tried, carrierLabel(to)+": "+why)
		if state != "reverted" {
			// Not undone cleanly (the foreign server could not be told, this
			// server could not switch, or going back failed): a person has to
			// look before anything else is changed.
			finish("failed", fmt.Sprintf("down for %d minutes on %s; stopped at %s", int(downFor/time.Minute), carrierLabel(from), strings.Join(tried, "; ")))
			return
		}
		ap.mu.Lock()
		ts := ap.stateLocked().tun(id)
		if ts.Failed == nil {
			ts.Failed = map[string]int64{}
		}
		ts.Failed[to.ID()] = apNow().Unix()
		ap.mu.Unlock()
		if nt, err := apResolve(id); err == nil { // where the swap left the tunnel
			t = nt
		}
	}
	text := fmt.Sprintf("down for %d minutes on %s; tried %s", int(downFor/time.Minute), carrierLabel(from), strings.Join(tried, "; "))
	if note != "" {
		text += " (" + note + ")"
	}
	finish("failed", text)
}

// apSwapReal runs one carrier swap and waits for its end: "ok", the swap's own
// state ("reverted", "failed") with what went wrong, or "busy" when it could
// not start because another swap is running.
func apSwapReal(t swapTunnel, to carrierChoice) (string, string) {
	if _, err := startSwap(t, to, false); err != nil {
		return "busy", err.Error()
	}
	deadline := time.Now().Add(apSwapWait)
	for time.Now().Before(deadline) {
		time.Sleep(swapPollEvery)
		if j := swapJobView(t.ID); j != nil && j.State != "running" {
			// A tunnel that was down before the swap stays down after both
			// servers went back: the swap calls that "failed", and for
			// Autopilot it is a clean way back to try the next carrier from.
			if j.State == "failed" && j.Back {
				return "reverted", j.Error
			}
			return j.State, j.Error
		}
	}
	return "failed", "the swap did not finish in time"
}

// ptActive: a path test is running on this server.
func ptActive() *ptSession {
	ptMu.Lock()
	s := ptCur
	ptMu.Unlock()
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase == "done" {
		return nil
	}
	return s
}

// apPathTestReal runs a path test between this server and tunnel t's foreign
// server: this server is the hub, the foreign server is told to join.
func apPathTestReal(t swapTunnel) ([]ptCheck, error) {
	if !hasPro(proPathTest) {
		return nil, errors.New("the license does not include the path test")
	}
	if ptActive() != nil {
		return nil, errors.New("another path test is running")
	}
	s, err := ptStartHub(ptHubRequest{ForeignIP: t.RemotePub, IranIP: t.LocalPub, IranIP6: "-", Minutes: 5})
	if err != nil {
		return nil, err
	}
	defer func() {
		if ptActive() == s { // not a test the admin started meanwhile
			ptStop()
		}
		_, _ = swapCall(t, "POST", "/api/peer/pathtest-join", map[string]string{"action": "stop"}, 6*time.Second)
	}()
	if _, err := swapCall(t, "POST", "/api/peer/pathtest-join", map[string]string{"action": "join", "code": s.code}, 20*time.Second); err != nil {
		if strings.Contains(err.Error(), "HTTP 404") {
			return nil, errors.New("the foreign panel is older than Autopilot: update it")
		}
		return nil, err
	}
	deadline := time.Now().Add(apTestWait)
	for time.Now().Before(deadline) && s.ctx.Err() == nil {
		if s.results().Settled {
			break
		}
		time.Sleep(2 * time.Second)
	}
	r := s.results()
	if !r.Joined {
		return nil, errors.New("the foreign server did not reach this server's test ports")
	}
	return r.Checks, nil
}

// POST /api/peer/pathtest-join {action: join|stop, code} (foreign side): the
// Iran server's Autopilot asks this server to join its path test.
func handlePeerPathTestJoin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Action string `json:"action"`
		Code   string `json:"code"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&req); err != nil {
		writeAPIError(w, r, "E-ACTION-01", "invalid request json")
		return
	}
	switch req.Action {
	case "stop":
		if s := ptActive(); s != nil && s.role == "foreign" {
			ptStop()
		}
		writeJSON(w, map[string]any{"status": "stopped"})
	case "join":
		if proRequired(w, r, proPathTest, "The path test") {
			return
		}
		if s := ptActive(); s != nil && s.role == "iran" {
			writeAPIError(w, r, "E-PATHTEST-01", "this server is running its own path test")
			return
		}
		s, err := ptStartSpoke(req.Code)
		if err != nil {
			writeAPIError(w, r, "E-PATHTEST-01", err.Error())
			return
		}
		markPeerSeen()
		LogSecurityAudit("pathtest_join", "autopilot", clientIP(r), fmt.Sprintf("base=%d", s.base))
		writeJSON(w, map[string]any{"status": "joined"})
	default:
		writeAPIError(w, r, "E-ACTION-01", "unknown path test action")
	}
}

// ---- telling the admin ----

func apEventText(e apEvent, host string) string {
	icon := map[string]string{"switched": "🛫", "failed": "⚠️", "recovered": "🟢"}[e.Kind]
	return strings.TrimSpace(fmt.Sprintf("%s [%s] Autopilot, tunnel %q: %s", icon, host, e.Name, e.Text))
}

func apNotifyReal(e apEvent) {
	host, _ := os.Hostname()
	text := apEventText(e, host)
	if a := loadAlertConfig(); a.WebhookURL != "" {
		b, _ := json.Marshal(map[string]any{"text": text, "autopilot": e, "host": host})
		req, err := http.NewRequest("POST", a.WebhookURL, strings.NewReader(string(b)))
		if err == nil {
			req.Header.Set("Content-Type", "application/json")
			resp, err := alertClient.Do(req)
			if err != nil {
				recordError("E-WD-01", "autopilot", "webhook failed: "+redactErr(err, a.WebhookURL).Error())
			} else {
				_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
				_ = resp.Body.Close()
				if resp.StatusCode >= 300 {
					recordError("E-WD-01", "autopilot", fmt.Sprintf("webhook returned HTTP %d", resp.StatusCode))
				}
			}
		}
	}
	if wd := loadWatchdogConfig(); wd.TGBotToken != "" && wd.TGChatID != "" {
		if err := sendTelegram(wd, text); err != nil {
			recordError("E-WD-01", "autopilot", "telegram failed: "+err.Error())
		}
	}
}

// ---- API ----

type apTunnelView struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Carrier  string `json:"carrier,omitempty"`
	State    string `json:"state"`
	DownSec  int    `json:"down_sec,omitempty"`
	Waiting  string `json:"waiting,omitempty"`
	Skipped  bool   `json:"skipped"`
	CanSwap  bool   `json:"can_swap"`
	RunsDay  int    `json:"runs_day"`
	LastRun  string `json:"last_run,omitempty"`
	SeenUp   bool   `json:"seen_up"`
	IsMain   bool   `json:"main"`
	Engine   string `json:"engine,omitempty"`
	Running  bool   `json:"running"`
	Progress string `json:"progress,omitempty"`
	Step     int    `json:"step,omitempty"` // 1 reach the foreign panel, 2 test the path, 3 swap
}

func apCarrierOf(l peerLive, main bool, st tunnelStatus) string {
	if main {
		if id := mainCarrierID(st); id != "" {
			return id
		}
	}
	if !apSwappable(l.Engine) {
		return ""
	}
	return peerCarrier(l.peerRecord).ID()
}

func apStep(phase string) int {
	switch {
	case strings.HasPrefix(phase, "Testing"):
		return 2
	case strings.HasPrefix(phase, "Moving"):
		return 3
	}
	return 1
}

func autopilotView() map[string]any {
	cfg := loadAutopilotConfig()
	now := apNow()
	snap := currentSnapshot()
	st := snap.Local
	iran := strings.Contains(strings.ToLower(st.Role), "iran") || len(snap.Peers) > 0
	skip := map[int]bool{}
	for _, id := range cfg.Skip {
		skip[id] = true
	}
	ap.mu.Lock()
	state := ap.stateLocked()
	tunnels := []apTunnelView{}
	for _, l := range apLinks(snap) {
		main := snap.Main != nil && l.ID == snap.Main.ID && l.ID == mainTunnelID
		v := apTunnelView{ID: l.ID, Name: l.Name, State: l.HealthState, Skipped: skip[l.ID], CanSwap: apSwappable(l.Engine),
			IsMain: main, Engine: l.Engine, Carrier: apCarrierOf(l, main, st)}
		if v.Name == "" {
			v.Name = fmt.Sprintf("peer-%d", l.ID)
		}
		if ts := state.Tunnels[l.ID]; ts != nil {
			v.RunsDay = ts.runsToday(now)
			v.SeenUp = ts.LastUp > 0
			if ts.LastRun > 0 {
				v.LastRun = time.Unix(ts.LastRun, 0).Format(time.RFC3339)
			}
		}
		if since, ok := ap.downSince[l.ID]; ok {
			v.DownSec = int(now.Sub(since) / time.Second)
			v.Waiting = ap.wait[l.ID]
		}
		if ap.running && ap.runID == l.ID {
			v.Running, v.Progress, v.Waiting, v.Step = true, ap.phase, "", apStep(ap.phase)
		}
		tunnels = append(tunnels, v)
	}
	events := append([]apEvent(nil), state.Events...)
	ap.mu.Unlock()
	switched, failedRuns := 0, 0
	for _, e := range events {
		if at, err := time.Parse(time.RFC3339, e.At); err == nil && now.Sub(at) < 24*time.Hour {
			switch e.Kind {
			case "switched":
				switched++
			case "failed":
				failedRuns++
			}
		}
	}
	for i, j := 0, len(events)-1; i < j; i, j = i+1, j-1 { // newest first
		events[i], events[j] = events[j], events[i]
	}
	if len(events) > 30 {
		events = events[:30]
	}
	var all []string
	for _, tr := range frpProtocols {
		all = append(all, "frp:"+tr)
	}
	for _, e := range []string{"backhaul", "gre-backhaul"} {
		for _, tr := range backhaulTransports {
			all = append(all, e+":"+tr)
		}
	}
	wd := loadWatchdogConfig()
	return map[string]any{
		"config": cfg, "licensed": hasPro(proAutopilot), "iran": iran, "tunnels": tunnels, "events": events,
		"carriers": all, "notify_ready": loadAlertConfig().WebhookURL != "" || (wd.TGBotToken != "" && wd.TGChatID != ""),
		"path_test_licensed": hasPro(proPathTest),
		"switched_day":       switched, "failed_day": failedRuns,
	}
}

// GET /api/autopilot
func handleAutopilotGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, autopilotView())
}

// POST /api/autopilot: the settings. Turning Autopilot on needs the license;
// turning it off never does.
func handleAutopilotPost(w http.ResponseWriter, r *http.Request) {
	c := loadAutopilotConfig()
	was := c.Enabled
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&c); err != nil {
		writeAPIError(w, r, "E-ACTION-01", "invalid json")
		return
	}
	if c.Enabled && proRequired(w, r, proAutopilot, "Autopilot") {
		return
	}
	c, err := cleanAutopilotConfig(c)
	if err != nil {
		writeAPIError(w, r, "E-ACTION-01", err.Error())
		return
	}
	if err := saveAutopilotConfig(c); err != nil {
		writeAPIError(w, r, "E-ACTION-01", err.Error())
		return
	}
	if was != c.Enabled {
		LogSecurityAudit("autopilot_config", "admin", clientIP(r), fmt.Sprintf("enabled=%v", c.Enabled))
	}
	writeJSON(w, autopilotView())
}

// ---- CLI: gre-panel autopilot status|on|off ----

func cliAutopilot(args []string) int {
	sub := "status"
	if len(args) > 0 {
		sub = args[0]
		args = args[1:]
	}
	loadLicenseFromDisk()
	c := loadAutopilotConfig()
	switch sub {
	case "on", "enable":
		if !hasPro(proAutopilot) {
			fmt.Fprintln(os.Stderr, "Autopilot is a Hashem Pro feature: activate a license first (hashem license activate KEY)")
			return 1
		}
		fs := flag.NewFlagSet("autopilot on", flag.ContinueOnError)
		down := fs.Int("down", c.DownMinutes, "minutes a tunnel must be down")
		cool := fs.Int("cooldown", c.CooldownMin, "minutes between two runs for one tunnel")
		perDay := fs.Int("per-day", c.MaxPerDay, "runs per tunnel in 24 hours")
		noTest := fs.Bool("no-path-test", !c.PathTest, "try the carriers in order instead of testing the path first")
		if err := fs.Parse(args); err != nil {
			return 2
		}
		c.Enabled, c.DownMinutes, c.CooldownMin, c.MaxPerDay, c.PathTest = true, *down, *cool, *perDay, !*noTest
		c, err := cleanAutopilotConfig(c)
		if err != nil {
			fmt.Fprintln(os.Stderr, "autopilot:", err)
			return 2
		}
		if err := saveAutopilotConfig(c); err != nil {
			fmt.Fprintln(os.Stderr, "autopilot:", err)
			return 1
		}
		fmt.Printf("Autopilot is on: a tunnel down for %d minutes is moved to a carrier that gets through (at most %d runs a day, %d minutes apart).\n", c.DownMinutes, c.MaxPerDay, c.CooldownMin)
		return 0
	case "off", "disable":
		c.Enabled = false
		if err := saveAutopilotConfig(c); err != nil {
			fmt.Fprintln(os.Stderr, "autopilot:", err)
			return 1
		}
		fmt.Println("Autopilot is off.")
		return 0
	case "status":
		state := "off"
		if c.Enabled {
			state = "on"
			if !hasPro(proAutopilot) {
				state = "on, but waiting for a license"
			}
		}
		fmt.Printf("Autopilot: %s\n", state)
		fmt.Printf("  down for %d min -> switch, %d min between runs, %d runs a day, path test first: %v\n", c.DownMinutes, c.CooldownMin, c.MaxPerDay, c.PathTest)
		if c.QuietFrom != c.QuietTo {
			fmt.Printf("  quiet hours: %02d:00-%02d:00\n", c.QuietFrom, c.QuietTo)
		}
		if len(c.Carriers) > 0 {
			fmt.Printf("  allowed carriers: %s\n", strings.Join(c.Carriers, ", "))
		}
		st := &apState{}
		if b, err := os.ReadFile(autopilotStatePath()); err == nil {
			_ = json.Unmarshal(b, st)
		}
		if len(st.Events) == 0 {
			fmt.Println("  history: nothing yet")
			return 0
		}
		fmt.Println("  history (newest first):")
		for i := len(st.Events) - 1; i >= 0 && i >= len(st.Events)-10; i-- {
			e := st.Events[i]
			fmt.Printf("    %s  %-9s %s: %s\n", e.At, e.Kind, e.Name, e.Text)
		}
		return 0
	}
	fmt.Fprintln(os.Stderr, "usage: gre-panel autopilot [status | on [-down 5] [-cooldown 30] [-per-day 6] [-no-path-test] | off]")
	return 2
}
