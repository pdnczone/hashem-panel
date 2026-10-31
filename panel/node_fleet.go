package main

// Nodes N4: the central's view of all its servers.
//
//   - Overview: every server's health, tunnels and traffic on one page, read
//     live from each (its /api/dashboard). Fleet traffic is the Iran
//     servers' plus that of foreign servers with no tunnel to one of them,
//     so a tunnel between two of the central's servers is counted once.
//   - Alerts: a node keeps its recent alert events (its own alert settings
//     aside); the central asks for new ones with every info call and sends
//     them with its own Telegram bot or webhook, named by the node.
//   - Updates: chosen nodes one at a time, each waited for until it is back
//     on its new version; the first failure stops the rest. The central
//     itself is updated on its own Update page.
//   - Backups: the central keeps a copy of each node's newest encrypted
//     backup (the node's Watchdog makes them, with its own key) for 14 days.
//   - Customers: every server's customers in one list; actions open on the
//     server that holds the customer.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---- alerts: kept on a node for its central ----

const nodeAlertKeep = 50

var nodeAlertTrk = newAlertTracker()

var nodeAlerts struct {
	sync.Mutex
	seq    uint64
	events []nodeAlertEvent
}

type nodeAlertEvent struct {
	Seq uint64 `json:"seq"`
	alertEvent
}

// nodeAlertsObserve keeps this node's alert events while it is linked to a
// central (the central decides whether and where they go).
func nodeAlertsObserve(now time.Time, links []linkSnap) {
	// kept while the channel is down too (a cut is when they matter); the
	// central decides about degraded ones with its own setting
	ev := nodeAlertTrk.observe(now, links, alertConfig{MinGapSec: 120, NotifyDegrad: true})
	if len(ev) == 0 {
		return
	}
	nodeAlerts.Lock()
	defer nodeAlerts.Unlock()
	for _, e := range ev {
		nodeAlerts.seq++
		nodeAlerts.events = append(nodeAlerts.events, nodeAlertEvent{Seq: nodeAlerts.seq, alertEvent: e})
	}
	if n := len(nodeAlerts.events) - nodeAlertKeep; n > 0 {
		nodeAlerts.events = nodeAlerts.events[n:]
	}
}

// nodeAlertsSince answers the central's "alerts" call: the events after
// since, and the last seq (since < 0: only the seq, to start from).
func nodeAlertsSince(raw json.RawMessage) (json.RawMessage, error) {
	var q struct {
		Since int64 `json:"since"`
	}
	_ = json.Unmarshal(raw, &q)
	nodeAlerts.Lock()
	defer nodeAlerts.Unlock()
	out := struct {
		Boot   string           `json:"boot"` // this run of the panel: seqs start again after a restart
		Seq    uint64           `json:"seq"`
		Events []nodeAlertEvent `json:"events"`
	}{Boot: nodeBootID, Seq: nodeAlerts.seq, Events: []nodeAlertEvent{}}
	if q.Since >= 0 {
		for _, e := range nodeAlerts.events {
			if e.Seq > uint64(q.Since) {
				out.Events = append(out.Events, e)
			}
		}
	}
	return json.Marshal(out)
}

// nodeBootID names this run of the panel.
var nodeBootID = strconv.FormatInt(time.Now().UnixNano(), 36)

// nodeAlertPull: on the central, per node, the run and seq read last; a
// reconnect goes on from there, a restarted node from its start.
type nodeAlertMark struct {
	boot string
	seq  int64
}

var nodeAlertPull = struct {
	sync.Mutex
	seq map[int]nodeAlertMark
}{seq: map[int]nodeAlertMark{}}

// nodeAlertsForward asks node s for new alert events and sends them with
// the central's own alert settings.
func nodeAlertsForward(s *nodeSession, name string) {
	cfg := loadAlertConfig()
	if !cfg.Enabled || (!cfg.Telegram && cfg.WebhookURL == "") {
		return
	}
	nodeAlertPull.Lock()
	mark, ok := nodeAlertPull.seq[s.id]
	nodeAlertPull.Unlock()
	since := mark.seq
	if !ok {
		since = -1 // first seen by this central run: start from now
	}
	ctx, cancel := context.WithTimeout(context.Background(), nodeCallTO)
	raw, err := s.call(ctx, "alerts", map[string]int64{"since": since})
	cancel()
	if err != nil {
		return // an older node has no "alerts"
	}
	var res struct {
		Boot   string           `json:"boot"`
		Seq    uint64           `json:"seq"`
		Events []nodeAlertEvent `json:"events"`
	}
	if json.Unmarshal(raw, &res) != nil {
		return
	}
	if ok && res.Boot != mark.boot { // the node restarted: its events start at 1 again
		ctx, cancel := context.WithTimeout(context.Background(), nodeCallTO)
		raw, err = s.call(ctx, "alerts", map[string]int64{"since": 0})
		cancel()
		if err != nil || json.Unmarshal(raw, &res) != nil {
			return
		}
	}
	nodeAlertPull.Lock()
	nodeAlertPull.seq[s.id] = nodeAlertMark{boot: res.Boot, seq: int64(res.Seq)}
	nodeAlertPull.Unlock()
	if len(res.Events) > 10 {
		res.Events = res.Events[len(res.Events)-10:] // a node is not a firehose
	}
	evs := make([]alertEvent, 0, len(res.Events))
	for _, e := range res.Events {
		if ev, ok := nodeAlertClean(e.alertEvent); ok && isAlertWorthy(ev.From, ev.To, cfg.NotifyDegrad) && nodeAlertAllow(s.id, time.Now()) {
			evs = append(evs, ev)
		}
	}
	if len(evs) == 0 {
		return
	}
	// sent beside the info loop (a slow webhook must not stall it), one
	// batch per node at a time
	nodeAlertBusy.Lock()
	if nodeAlertBusy.m[s.id] {
		nodeAlertBusy.Unlock()
		return
	}
	nodeAlertBusy.m[s.id] = true
	nodeAlertBusy.Unlock()
	go func(id int) {
		defer func() {
			nodeAlertBusy.Lock()
			delete(nodeAlertBusy.m, id)
			nodeAlertBusy.Unlock()
		}()
		nodeAlertDeliver(cfg, name, evs)
	}(s.id)
}

var nodeAlertBusy = struct {
	sync.Mutex
	m map[int]bool
}{m: map[int]bool{}}

// nodeAlertClean: a node's event as the central sends it, or false. The
// states must be known ones; text is one short line with no direction
// tricks or mentions; the time is this server's when it is not a time.
func nodeAlertClean(e alertEvent) (alertEvent, bool) {
	known := func(s string) bool { return s == "" || s == stateHealthy || s == stateDegraded || s == stateDown }
	if !known(e.From) || !known(e.To) {
		return e, false
	}
	clean := func(s string, n int) string {
		s = strings.Map(func(r rune) rune {
			if r == 0x2028 || r == 0x2029 || r >= 0x202A && r <= 0x202E || r >= 0x2066 && r <= 0x2069 ||
				r >= 0x200B && r <= 0x200F || r == 0x061C || r == 0xFEFF {
				return -1
			}
			return r
		}, nodeLogText([]byte(s)))
		if r := []rune(s); len(r) > n {
			s = string(r[:n]) + "…"
		}
		// no mentions a chat would act on (a zero-width joiner after @), no <...> markup
		s = strings.NewReplacer("@", "@\u200d", "<", "‹", ">", "›").Replace(strings.TrimSpace(s))
		return s
	}
	e.Link, e.Why = clean(e.Link, 80), clean(e.Why, 160)
	if _, err := time.Parse(time.RFC3339, e.At); err != nil || len(e.At) > 40 {
		e.At = time.Now().UTC().Format(time.RFC3339)
	}
	return e, true
}

// nodeAlertAllow: at most nodeAlertPerNode an hour per node and
// nodeAlertAll an hour in all, so no node can flood the bot.
const (
	nodeAlertPerNode = 12.0
	nodeAlertAll     = 60.0
)

var nodeAlertBucket = struct {
	sync.Mutex
	node map[int][2]float64 // tokens, unix seconds
	all  [2]float64
}{node: map[int][2]float64{}}

func nodeAlertAllow(id int, now time.Time) bool {
	nodeAlertBucket.Lock()
	defer nodeAlertBucket.Unlock()
	t := float64(now.UnixNano()) / 1e9
	take := func(b [2]float64, per float64) ([2]float64, bool) {
		if b[1] == 0 {
			b = [2]float64{per, t}
		}
		b[0] = min(per, b[0]+(t-b[1])*per/3600)
		b[1] = t
		if b[0] < 1 {
			return b, false
		}
		b[0]--
		return b, true
	}
	nb, ok := take(nodeAlertBucket.node[id], nodeAlertPerNode)
	if !ok {
		nodeAlertBucket.node[id] = nb
		return false
	}
	ab, ok := take(nodeAlertBucket.all, nodeAlertAll)
	nodeAlertBucket.all = ab
	if !ok {
		return false
	}
	nodeAlertBucket.node[id] = nb
	return true
}

// nodeAlertDeliver sends events as from node name (tests replace it).
var nodeAlertDeliver = func(cfg alertConfig, name string, evs []alertEvent) {
	wd := loadWatchdogConfig()
	for _, e := range evs {
		e.Host = "node " + name
		if cfg.WebhookURL != "" {
			if err := sendWebhook(cfg.WebhookURL, e); err != nil {
				recordError("E-WD-01", "alerts", "webhook failed: "+err.Error())
			}
		}
		if cfg.Telegram {
			if err := sendTelegram(wd, alertText(e)); err != nil {
				recordError("E-WD-01", "alerts", "telegram failed: "+err.Error())
			}
		}
	}
}

// nodeAlertsForget: a removed node.
func nodeAlertsForget(id int) {
	nodeAlertPull.Lock()
	delete(nodeAlertPull.seq, id)
	nodeAlertPull.Unlock()
}

// ---- overview ----

// nodeFleetParallel: servers read at once (each answer may be large).
const nodeFleetParallel = 8

type nodeFleetServer struct {
	ID        int               `json:"id"` // 0: the central
	Name      string            `json:"name"`
	Online    bool              `json:"online"`
	Error     string            `json:"error,omitempty"`
	Health    string            `json:"health,omitempty"`
	Role      string            `json:"role,omitempty"`
	Public    string            `json:"public,omitempty"`
	Tunnels   int               `json:"tunnels"`
	Traffic   *nodeFleetTraffic `json:"traffic,omitempty"`
	System    map[string]any    `json:"system,omitempty"`
	Conns     any               `json:"conns,omitempty"`
	Counted   bool              `json:"counted"`           // its traffic is in the totals
	Partial   bool              `json:"partial,omitempty"` // counted at its Iran server, but it has other tunnels too
	CPU       float64           `json:"cpu_pct"`           // from its info (-1: not known)
	Mem       float64           `json:"mem_pct"`
	Disk      float64           `json:"disk_pct"`
	Version   string            `json:"version,omitempty"`
	Held      bool              `json:"held,omitempty"`
	LicenseOK bool              `json:"license_ok"`
}

// nodeFleetTraffic: a server's traffic as its dashboard gives it (bytes, bytes/s).
type nodeFleetTraffic struct {
	Up        float64 `json:"up"`
	Down      float64 `json:"down"`
	Total     float64 `json:"total"`
	SpeedUp   float64 `json:"speed_up"`
	SpeedDown float64 `json:"speed_down"`
}

type nodeFleetView struct {
	Servers []nodeFleetServer `json:"servers"`
	Totals  map[string]uint64 `json:"totals"` // total (bytes), speed (bytes/s, both ways)
	Online  int               `json:"online"`
	Errors  []string          `json:"errors,omitempty"`
}

func nodeFleetOverview(ctx context.Context) nodeFleetView {
	type srv struct {
		id                int
		name, version     string
		online, held, lic bool
		info              nodeInfo
	}
	list := []srv{{id: 0, name: "this server (the central)", version: panelVersion, online: true, info: nodeInfoFn()}}
	activeLicenseMu.RLock()
	list[0].lic = activeLicense != nil
	activeLicenseMu.RUnlock()
	nodesMu.Lock()
	nodesLoadLocked()
	for _, r := range nodesF.Nodes {
		list = append(list, srv{id: r.ID, name: r.Name, version: r.Info.Version, online: nodeSessions[r.ID] != nil,
			held: r.Held, lic: r.Info.License.Active, info: r.Info})
	}
	nodesMu.Unlock()
	out := nodeFleetView{Servers: make([]nodeFleetServer, len(list)), Totals: map[string]uint64{}}
	// which tunnels join two of these servers: read beside the dashboards,
	// with time of its own
	var links []nodeTunLink
	var lerr []string
	var plans map[int]setupPlan
	linksDone := make(chan struct{})
	go func() {
		defer close(linksDone)
		lctx, cancel := context.WithTimeout(context.Background(), nodeTunPlanTO)
		defer cancel()
		links, lerr, plans = nodeTunLinksPlans(lctx)
	}()
	var wg sync.WaitGroup
	lim := make(chan struct{}, nodeFleetParallel)
	for i, x := range list {
		out.Servers[i] = nodeFleetServer{ID: x.id, Name: x.name, Online: x.online, Version: x.version, Held: x.held, LicenseOK: x.lic,
			CPU: x.info.CPUPct, Mem: x.info.MemPct, Disk: x.info.DiskPct}
		if !x.online || x.held {
			continue
		}
		wg.Add(1)
		go func(fs *nodeFleetServer) {
			defer wg.Done()
			lim <- struct{}{}
			defer func() { <-lim }()
			var d struct {
				Health    string            `json:"health_state"`
				Role      string            `json:"role"`
				Public    string            `json:"local_pub"`
				PeerCount int               `json:"peer_count"`
				Online    bool              `json:"online"`
				Traffic   *nodeFleetTraffic `json:"traffic"`
				System    map[string]any    `json:"system"`
				Conns     any               `json:"conns"`
			}
			if err := nodeAPIJSON(ctx, fs.ID, http.MethodGet, "/api/dashboard?range=1h", nil, &d); err != nil {
				fs.Error = err.Error()
				return
			}
			fs.Health, fs.Role, fs.Public, fs.Traffic, fs.System, fs.Conns = d.Health, d.Role, d.Public, d.Traffic, d.System, d.Conns
			fs.Tunnels = d.PeerCount
			if fs.Tunnels == 0 && d.Role != "" {
				fs.Tunnels = 1 // the first tunnel alone
			}
		}(&out.Servers[i])
	}
	wg.Wait()
	<-linksDone
	// a tunnel between two of these servers is counted at its Iran end
	out.Errors = append(out.Errors, lerr...)
	clientOfFleet := map[int]int{} // proven uplinks to a fleet server
	for _, l := range links {
		clientOfFleet[l.Client]++
	}
	num := func(v float64) uint64 {
		if v > 0 && v < 1e18 {
			return uint64(v)
		}
		return 0
	}
	for i := range out.Servers {
		fs := &out.Servers[i]
		if fs.Online && !fs.Held && fs.Error == "" {
			out.Online++
		}
		if p, ok := plans[fs.ID]; ok { // the plan knows the first tunnel and joined hubs too
			fs.Tunnels = len(p.Peers) + len(p.Uplinks)
		}
		if fs.Traffic == nil {
			continue
		}
		if n := clientOfFleet[fs.ID]; n > 0 {
			if p, ok := plans[fs.ID]; ok && len(p.Uplinks) > n {
				fs.Partial = true // its other tunnels' traffic is in no total
			}
			continue
		}
		fs.Counted = true
		// up and down are each server's own view: only their sum adds up
		out.Totals["total"] += num(fs.Traffic.Up) + num(fs.Traffic.Down)
		out.Totals["speed"] += num(fs.Traffic.SpeedUp) + num(fs.Traffic.SpeedDown)
	}
	return out
}

// ---- updates ----

var (
	nodeUpdateWait   = 5 * time.Minute  // a node back on its new version
	nodeUpdateCallTO = 10 * time.Minute // its update call (a download on a slow link)
)

// nodeFleetUpdate updates nodes ids one at a time; the first failure stops it.
func nodeFleetUpdate(ctx context.Context, j *nodeTunJob, ids []int) error {
	for n, id := range ids {
		nodesMu.Lock()
		rec := nodeFindLocked(id)
		var before string
		if rec != nil {
			before = rec.Info.Version
		}
		oldSess := nodeSessions[id]
		nodesMu.Unlock()
		if rec == nil {
			return errNodeUnknown(id)
		}
		j.logf("(%d/%d) updating %s (now %s)", n+1, len(ids), nodeTunName(id), displayVersion(before))
		var res struct {
			Detail string `json:"detail"`
		}
		uctx, cancel := context.WithTimeout(ctx, nodeUpdateCallTO)
		err := nodeAPIJSON(uctx, id, http.MethodPost, "/api/update", map[string]any{}, &res)
		cancel()
		if err != nil {
			if errors.Is(err, errNodeOffline) {
				err = nil // the node restarted on the new version before it answered
			} else {
				return fmt.Errorf("%v; the rest were not updated", err)
			}
		}
		if strings.Contains(res.Detail, "already latest") {
			j.logf("%s is already on the newest version", nodeTunName(id))
			continue
		}
		// it restarts: wait for it to be back on another version
		deadline := time.Now().Add(nodeUpdateWait)
		for {
			nodesMu.Lock()
			r := nodeFindLocked(id)
			// back: on a new connection (it restarted) and another version
			now := nodeSessions[id]
			back := r != nil && now != nil && now != oldSess && r.Info.Version != "" && r.Info.Version != before
			ver := ""
			if r != nil {
				ver = r.Info.Version
			}
			nodesMu.Unlock()
			if back {
				j.logf("%s is back on %s", nodeTunName(id), displayVersion(ver))
				break
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("%s did not come back on a new version within %s; the rest were not updated", nodeTunName(id), nodeUpdateWait)
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(2 * time.Second):
			}
		}
	}
	return nil
}

// ---- backups ----

const (
	nodeBackupKeep  = 14 * 24 * time.Hour
	nodeBackupMax   = 3 // copies per node
	nodeBackupEvery = 6 * time.Hour
)

func nodeBackupDir(id int) string {
	return filepath.Join(configDir, "node-backups", strconv.Itoa(id))
}

type nodeBackupFile struct {
	Node int    `json:"node"`
	Name string `json:"name"`
	Size int64  `json:"size"`
	Time int64  `json:"time"`
}

// nodeBackupsList: the copies kept here, newest first.
func nodeBackupsList() []nodeBackupFile {
	out := []nodeBackupFile{}
	dirs, _ := os.ReadDir(filepath.Join(configDir, "node-backups"))
	for _, d := range dirs {
		id, err := strconv.Atoi(d.Name())
		if err != nil || !d.IsDir() {
			continue
		}
		files, _ := os.ReadDir(nodeBackupDir(id))
		for _, f := range files {
			if st, err := f.Info(); err == nil && !f.IsDir() && nodeBackupName(f.Name()) {
				out = append(out, nodeBackupFile{Node: id, Name: f.Name(), Size: st.Size(), Time: st.ModTime().Unix()})
			}
		}
	}
	slices.SortFunc(out, func(a, b nodeBackupFile) int { return int(b.Time - a.Time) })
	return out
}

// nodeBackupName: a backup file name a node may send (its Watchdog's form).
func nodeBackupName(s string) bool {
	if len(s) < 5 || len(s) > 120 || !strings.HasSuffix(s, ".enc") || filepath.Base(s) != s || strings.Contains(s, "..") {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// nodeBackupPull copies node id's newest backup here, if it is new, and
// drops copies older than nodeBackupKeep.
func nodeBackupPull(ctx context.Context, id int) (string, error) {
	var wd struct {
		Backups []backupItem `json:"backups"`
	}
	if err := nodeAPIJSON(ctx, id, http.MethodGet, "/api/watchdog", nil, &wd); err != nil {
		return "", err
	}
	var newest backupItem
	for _, b := range wd.Backups {
		if nodeBackupName(b.Name) && strings.HasPrefix(b.Name, "hashem-backup-") && b.Time > newest.Time {
			newest = b
		}
	}
	dir := nodeBackupDir(id)
	defer nodeBackupPrune(dir)
	if newest.Name == "" {
		return "", nil // no backups there (its Watchdog makes them, Pro)
	}
	if _, err := os.Stat(filepath.Join(dir, newest.Name)); err == nil {
		return "", nil // kept already
	}
	st, body, err := nodeAPIFn(ctx, id, http.MethodGet, "/api/watchdog/backup-download?f="+url.QueryEscape(newest.Name), nil)
	if err != nil {
		return "", err
	}
	if st != http.StatusOK || len(body) == 0 {
		return "", fmt.Errorf("%s: the backup download answered %d", nodeTunName(id), st)
	}
	// only what the Watchdog makes: openssl's encrypted form, of a sane size
	if len(body) > nodeRelayBodyMax || !bytes.HasPrefix(body, []byte("Salted__")) {
		return "", fmt.Errorf("%s: that is not an encrypted Watchdog backup", nodeTunName(id))
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return newest.Name, writeFile0600(filepath.Join(dir, newest.Name), body)
}

// nodeBackupPrune keeps a node's copies younger than nodeBackupKeep, and
// at most nodeBackupMax of them (the newest).
func nodeBackupPrune(dir string) {
	files, _ := os.ReadDir(dir)
	type kept struct {
		name string
		at   time.Time
	}
	var keep []kept
	for _, f := range files {
		st, err := f.Info()
		if err != nil {
			continue
		}
		if strings.HasSuffix(f.Name(), ".tmp") && time.Since(st.ModTime()) < 10*time.Minute {
			continue // a copy being written now
		}
		if f.IsDir() || time.Since(st.ModTime()) > nodeBackupKeep || !nodeBackupName(f.Name()) {
			_ = os.RemoveAll(filepath.Join(dir, f.Name()))
			continue
		}
		keep = append(keep, kept{f.Name(), st.ModTime()})
	}
	slices.SortFunc(keep, func(a, b kept) int { return b.at.Compare(a.at) })
	for i := nodeBackupMax; i < len(keep); i++ {
		_ = os.Remove(filepath.Join(dir, keep[i].name))
	}
}

// nodeBackupPruneAll prunes every node's copies and drops those of nodes
// that are gone.
func nodeBackupPruneAll() {
	dirs, _ := os.ReadDir(filepath.Join(configDir, "node-backups"))
	nodesMu.Lock()
	nodesLoadLocked()
	bad := nodesEr != ""
	known := map[int]bool{}
	for _, r := range nodesF.Nodes {
		known[r.ID] = true
	}
	nodesMu.Unlock()
	if bad {
		return // the list cannot be read: not a reason to drop every node's copies
	}
	for _, d := range dirs {
		id, err := strconv.Atoi(d.Name())
		if err != nil || !known[id] {
			_ = os.RemoveAll(filepath.Join(configDir, "node-backups", d.Name()))
			continue
		}
		nodeBackupPrune(nodeBackupDir(id))
	}
}

// startNodeBackups: on a central, every nodeBackupEvery.
func startNodeBackups() {
	time.Sleep(10 * time.Minute)
	for {
		if s, err := nodeSelfLoad(); err == nil && s.Role == nodeRoleCentral {
			nodeBackupPruneAll()
			nodesMu.Lock()
			var ids []int
			for _, r := range nodesF.Nodes {
				if nodeSessions[r.ID] != nil && !r.Held {
					ids = append(ids, r.ID)
				}
			}
			nodesMu.Unlock()
			for _, id := range ids {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
				if name, err := nodeBackupPull(ctx, id); err != nil {
					log.Printf("nodes: backup of node %d: %v", id, err)
				} else if name != "" {
					log.Printf("nodes: kept node %d's backup %s", id, name)
				}
				cancel()
			}
		}
		time.Sleep(nodeBackupEvery)
	}
}

// handleNodeBackupGet: GET /api/nodes/backup?node=N&f=NAME on the central.
func handleNodeBackupGet(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.URL.Query().Get("node"))
	f := r.URL.Query().Get("f")
	if err != nil || id < 1 || !nodeBackupName(f) {
		writeAPIError(w, r, "E-NODE-01", "bad backup")
		return
	}
	path := filepath.Join(nodeBackupDir(id), f)
	if st, err := os.Stat(path); err != nil || st.IsDir() {
		writeAPIError(w, r, "E-NODE-03", "no such backup")
		return
	}
	mu.Lock()
	user := cfg.Username
	mu.Unlock()
	LogSecurityAudit("node_backup_download", user, ClientIP(r), fmt.Sprintf("node=%d file=%s", id, f))
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", "node"+strconv.Itoa(id)+"-"+f))
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeFile(w, r, path)
}

// ---- customers ----

type nodeFleetCustomer struct {
	Server    int     `json:"server"`
	ID        int     `json:"id"`
	Name      string  `json:"name"`
	Note      string  `json:"note,omitempty"`
	ExpiresAt int64   `json:"expires_at"`
	QuotaGB   float64 `json:"quota_gb"`
	UsedRx    uint64  `json:"used_rx"`
	UsedTx    uint64  `json:"used_tx"`
	Cut       string  `json:"cut,omitempty"`
}

// nodeFleetCustomers: every server's customers (the fields the list shows).
func nodeFleetCustomers(ctx context.Context) ([]nodeFleetCustomer, []string) {
	ids := []int{0}
	nodesMu.Lock()
	nodesLoadLocked()
	for _, r := range nodesF.Nodes {
		if nodeSessions[r.ID] != nil && !r.Held {
			ids = append(ids, r.ID)
		}
	}
	nodesMu.Unlock()
	var mu sync.Mutex
	var wg sync.WaitGroup
	out := []nodeFleetCustomer{}
	var errs []string
	lim := make(chan struct{}, nodeFleetParallel)
	for _, id := range ids {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			lim <- struct{}{}
			defer func() { <-lim }()
			var v struct {
				Customers []nodeFleetCustomer `json:"customers"`
				Licensed  *bool               `json:"licensed"`
			}
			err := nodeAPIJSON(ctx, id, http.MethodGet, "/api/customers", nil, &v)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if e := apiErrOf(err); e == nil || e.Code != "E-LIC-01" { // no Customers license there: nothing to list
					errs = append(errs, err.Error())
				}
				return
			}
			if v.Licensed != nil && !*v.Licensed {
				return // Customers is Pro there: nothing it sells
			}
			if len(v.Customers) > 1000 {
				v.Customers = v.Customers[:1000]
			}
			for _, c := range v.Customers {
				c.Server = id
				out = append(out, c)
			}
		}(id)
	}
	wg.Wait()
	slices.SortFunc(out, func(a, b nodeFleetCustomer) int {
		if a.Server != b.Server {
			return a.Server - b.Server
		}
		return a.ID - b.ID
	})
	slices.Sort(errs)
	return out, errs
}

var errNodeFleetIDs = errors.New("pick the nodes to update")
