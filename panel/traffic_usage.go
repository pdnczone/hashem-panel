package main

// Per-peer traffic ledger.
//
// What it stores: for every link (the main tunnel and each foreign-server
// peer) one point per minute holding the bytes received/sent *in that
// minute*, kept for 7 days, plus per-day totals for the same 7 days, plus the
// same series for the hub as a whole. It lives on disk (traffic_peers.json)
// so a panel restart, update, crash or reboot never loses it.
//
// Why deltas and not the kernel counters: /proc/net/dev counters restart from
// zero whenever the interface is recreated, the tunnel is removed and re-added,
// or the host reboots. The ledger therefore remembers the last raw reading per
// link and adds only the forward movement; a reading that went *down* is a
// counter reset, and the new reading itself is the traffic since that reset.
//
// Identity: links are keyed by peer ID ("main" for the base tunnel), not by
// name, so renaming a peer keeps its history. The name is stored as a label
// that follows renames. A link that disappears keeps its history for the full
// retention window (a peer that is removed and added back must not lose data;
// old data simply ages out).

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	usageStep      = time.Minute        // one point per link per minute
	usageKeep      = 7 * 24 * time.Hour // retention
	usageSaveEvery = 60 * time.Second   // periodic flush
	usageMaxLinks  = 64                 // sanity cap, far above GRE_MAX_PEERS
	usageFileVer   = 1
	usageTotalKey  = "total" // the whole hub
	usageMainKey   = "main"  // the base tunnel
	usageHostKey   = "host"  // all tunnel interfaces on this machine
	usageDayLayout = "2006-01-02"
)

func usageFile() string { return filepath.Join(configDir, "traffic_peers.json") }

// usagePoint is the traffic of one minute. T is the minute start (unix s).
type usagePoint struct {
	T  int64  `json:"t"`
	Rx uint64 `json:"rx"` // bytes received by the hub from this link in that minute
	Tx uint64 `json:"tx"` // bytes sent by the hub to this link in that minute
}

// usageLink is the persisted state of one link.
type usageLink struct {
	Name   string       `json:"name"`
	Points []usagePoint `json:"points"`
	// Days maps "YYYY-MM-DD" (UTC) to {rx, tx}. Totals since the first sample.
	Days map[string]usageDay `json:"days"`
	// LastRx/LastTx are the last raw kernel counters seen; Have says they are
	// valid. They are persisted so a restart does not lose the interval
	// between the last sample and the first one after start.
	LastRx uint64 `json:"last_rx"`
	LastTx uint64 `json:"last_tx"`
	Have   bool   `json:"have"`
	// LastIf: per-interface raw counters of a link made of several
	// (the "host" series), each delta taken on its own.
	LastIf map[string][2]uint64 `json:"last_if,omitempty"`
	Seen   int64                `json:"seen"` // last unix time this link produced a sample
}

type usageDay struct {
	Rx uint64 `json:"rx"`
	Tx uint64 `json:"tx"`
}

type usageDisk struct {
	Version int                   `json:"v"`
	SavedAt int64                 `json:"saved_at"`
	Links   map[string]*usageLink `json:"links"`
}

type usageStore struct {
	mu    sync.Mutex
	links map[string]*usageLink
	dirty bool
}

var trafficUsage = &usageStore{links: map[string]*usageLink{}}

// usageKey is the stable key of a link.
func usageKey(l peerLive) string {
	if l.ID == mainTunnelID {
		return usageMainKey
	}
	return "p" + strconv.Itoa(l.ID)
}

func minuteOf(t time.Time) int64 { return t.Unix() / 60 * 60 }

func dayOf(unix int64) string { return time.Unix(unix, 0).UTC().Format(usageDayLayout) }

// delta returns the traffic since the previous raw reading and whether the
// reading is usable. A reading below the previous one is a counter reset: the
// new value is itself the traffic accumulated since the reset.
func usageDelta(prev, cur uint64, have bool) uint64 {
	if !have {
		return 0 // first reading: no baseline, nothing to attribute
	}
	if cur >= prev {
		return cur - prev
	}
	return cur
}

// observe feeds one raw counter reading for a link. rx/tx nil means the
// counters are unavailable right now (interface down, standalone Backhaul):
// the baseline is kept so the gap is not turned into a bogus spike when the
// counters come back.
func (s *usageStore) observe(key, name string, now time.Time, rx, tx *uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	l := s.links[key]
	if l == nil {
		if len(s.links) >= usageMaxLinks {
			return
		}
		l = &usageLink{Days: map[string]usageDay{}}
		s.links[key] = l
	}
	if name != "" {
		l.Name = name
	}
	if rx == nil || tx == nil {
		return
	}
	dRx := usageDelta(l.LastRx, *rx, l.Have)
	dTx := usageDelta(l.LastTx, *tx, l.Have)
	l.LastRx, l.LastTx, l.Have = *rx, *tx, true
	s.addLocked(l, now, dRx, dTx)
}

// observeIfs feeds the raw counters of several interfaces that make up one
// link. Summing them first went wrong: when one interface went away (a peer
// removed, GRE recreated) the smaller sum was taken for a counter reset and
// every other interface's whole counter was counted again, and a new
// interface's existing counter was counted as traffic.
func (s *usageStore) observeIfs(key, name string, now time.Time, cur map[string][2]uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	l := s.links[key]
	if l == nil {
		if len(s.links) >= usageMaxLinks {
			return
		}
		l = &usageLink{Days: map[string]usageDay{}}
		s.links[key] = l
	}
	if name != "" {
		l.Name = name
	}
	if len(cur) == 0 {
		return // nothing readable now: keep the baselines for when it comes back
	}
	if _, ok := cur[carrierKey]; !ok { // a failed carrier reading keeps its baseline (see trafficSample)
		if prev, seen := l.LastIf[carrierKey]; seen {
			cur[carrierKey] = prev
		}
	}
	var dRx, dTx uint64
	for ifname, c := range cur {
		if prev, ok := l.LastIf[ifname]; ok {
			dRx += counterDelta(prev[0], c[0])
			dTx += counterDelta(prev[1], c[1])
		}
	}
	l.LastIf = make(map[string][2]uint64, len(cur))
	for k, v := range cur {
		l.LastIf[k] = v
	}
	s.addLocked(l, now, dRx, dTx)
}

// addLocked books dRx/dTx in the link's minute and day.
func (s *usageStore) addLocked(l *usageLink, now time.Time, dRx, dTx uint64) {
	l.Seen = now.Unix()
	if dRx == 0 && dTx == 0 {
		// still advance "seen" and make sure a minute bucket exists lazily
		// only when traffic flows; idle minutes need no point.
		return
	}
	m := minuteOf(now)
	if n := len(l.Points); n > 0 && l.Points[n-1].T == m {
		l.Points[n-1].Rx += dRx
		l.Points[n-1].Tx += dTx
	} else {
		l.Points = append(l.Points, usagePoint{T: m, Rx: dRx, Tx: dTx})
	}
	d := dayOf(now.Unix())
	day := l.Days[d]
	day.Rx += dRx
	day.Tx += dTx
	l.Days[d] = day
	s.dirty = true
}

// prune drops points and days older than the retention window.
func (s *usageStore) prune(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cut := now.Add(-usageKeep).Unix()
	cutDay := dayOf(cut)
	for k, l := range s.links {
		i := 0
		for i < len(l.Points) && l.Points[i].T < cut {
			i++
		}
		if i > 0 {
			l.Points = append([]usagePoint(nil), l.Points[i:]...)
			s.dirty = true
		}
		for d := range l.Days {
			if d < cutDay {
				delete(l.Days, d)
				s.dirty = true
			}
		}
		if len(l.Points) == 0 && len(l.Days) == 0 && l.Seen < cut {
			delete(s.links, k) // nothing left and not seen for the whole window
			s.dirty = true
		}
	}
}

// ---- persistence -----------------------------------------------------------

func (s *usageStore) save(path string, now time.Time) error {
	s.prune(now)
	s.mu.Lock()
	d := usageDisk{Version: usageFileVer, SavedAt: now.Unix(), Links: s.links}
	b, err := json.Marshal(d)
	s.dirty = false
	s.mu.Unlock()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil { // data is on disk before the rename publishes it
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// load restores the ledger. A missing, corrupt or unknown-version file is
// ignored (history is never allowed to stop the panel). Data already in memory
// is kept: counters seen before load finishes are not overwritten.
func (s *usageStore) load(path string, now time.Time) int {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	var d usageDisk
	if json.Unmarshal(b, &d) != nil || d.Version != usageFileVer {
		// keep the unreadable file for inspection instead of overwriting it
		_ = os.Rename(path, path+".bad")
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for k, l := range d.Links {
		if l == nil || s.links[k] != nil {
			continue
		}
		if l.Days == nil {
			l.Days = map[string]usageDay{}
		}
		sort.Slice(l.Points, func(i, j int) bool { return l.Points[i].T < l.Points[j].T })
		s.links[k] = l
		n++
	}
	return n
}

// ---- queries ---------------------------------------------------------------

// usageSeries is a link's series for the API.
type usageSeries struct {
	Key    string        `json:"key"`
	Name   string        `json:"name"`
	Rx     uint64        `json:"rx"` // sum over the requested window
	Tx     uint64        `json:"tx"`
	Points []usagePoint  `json:"points"`
	Days   []usageDayRow `json:"days"`
}

type usageDayRow struct {
	Day string `json:"day"`
	Rx  uint64 `json:"rx"`
	Tx  uint64 `json:"tx"`
}

// usageRange resolves ?range= to a window and a bucket size in seconds.
func usageRange(r string) (time.Duration, int64) {
	switch r {
	case "1h":
		return time.Hour, 60
	case "6h":
		return 6 * time.Hour, 300
	case "24h":
		return 24 * time.Hour, 900
	default: // "7d"
		return usageKeep, 3600
	}
}

// bucketize merges per-minute points into buckets of `step` seconds.
func bucketize(pts []usagePoint, since, step int64) []usagePoint {
	var out []usagePoint
	for _, p := range pts {
		if p.T < since {
			continue
		}
		b := p.T / step * step
		if n := len(out); n > 0 && out[n-1].T == b {
			out[n-1].Rx += p.Rx
			out[n-1].Tx += p.Tx
		} else {
			out = append(out, usagePoint{T: b, Rx: p.Rx, Tx: p.Tx})
		}
	}
	return out
}

// series returns one link's series for the window.
func (s *usageStore) series(key string, now time.Time, window time.Duration, step int64) (usageSeries, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.seriesLocked(key, now, window, step)
}

func (s *usageStore) seriesLocked(key string, now time.Time, window time.Duration, step int64) (usageSeries, bool) {
	l := s.links[key]
	if l == nil {
		return usageSeries{}, false
	}
	since := now.Add(-window).Unix()
	pts := bucketize(l.Points, since, step)
	out := usageSeries{Key: key, Name: l.Name, Points: pts}
	if out.Points == nil {
		out.Points = []usagePoint{}
	}
	for _, p := range pts {
		out.Rx += p.Rx
		out.Tx += p.Tx
	}
	cutDay := dayOf(since)
	days := make([]string, 0, len(l.Days))
	for d := range l.Days {
		if d >= cutDay {
			days = append(days, d)
		}
	}
	sort.Strings(days)
	out.Days = []usageDayRow{}
	for _, d := range days {
		out.Days = append(out.Days, usageDayRow{Day: d, Rx: l.Days[d].Rx, Tx: l.Days[d].Tx})
	}
	return out, true
}

// all returns every link's series plus the hub total, newest data included.
func (s *usageStore) all(now time.Time, window time.Duration, step int64) []usageSeries {
	s.mu.Lock()
	defer s.mu.Unlock()
	keys := make([]string, 0, len(s.links))
	for k := range s.links {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		// host, then main, then peers by numeric id
		rank := func(k string) int {
			switch k {
			case usageHostKey:
				return 0
			case usageMainKey:
				return 1
			}
			return 2
		}
		if ri, rj := rank(keys[i]), rank(keys[j]); ri != rj {
			return ri < rj
		}
		a, _ := strconv.Atoi(strings.TrimPrefix(keys[i], "p"))
		b, _ := strconv.Atoi(strings.TrimPrefix(keys[j], "p"))
		return a < b
	})
	var out []usageSeries
	tot := usageSeries{Key: usageTotalKey, Name: "All links", Points: []usagePoint{}, Days: []usageDayRow{}}
	byMin := map[int64]*usagePoint{}
	byDay := map[string]*usageDayRow{}
	// The hub total is the sum of the per-link series. "host" is the raw sum
	// of all tunnel interfaces and would count every byte twice if it were
	// added too; it is only the total when there are no per-link series at all
	// (a foreign spoke, which has one tunnel and no peer list).
	haveLinks := false
	for _, k := range keys {
		if k != usageHostKey {
			haveLinks = true
		}
	}
	for _, k := range keys {
		sr, ok := s.seriesLocked(k, now, window, step)
		if !ok {
			continue
		}
		out = append(out, sr)
		if k == usageHostKey && haveLinks {
			continue
		}
		tot.Rx += sr.Rx
		tot.Tx += sr.Tx
		for _, p := range sr.Points {
			if t := byMin[p.T]; t != nil {
				t.Rx += p.Rx
				t.Tx += p.Tx
			} else {
				c := p
				byMin[p.T] = &c
			}
		}
		for _, d := range sr.Days {
			if t := byDay[d.Day]; t != nil {
				t.Rx += d.Rx
				t.Tx += d.Tx
			} else {
				c := d
				byDay[d.Day] = &c
			}
		}
	}
	ts := make([]int64, 0, len(byMin))
	for t := range byMin {
		ts = append(ts, t)
	}
	sort.Slice(ts, func(i, j int) bool { return ts[i] < ts[j] })
	for _, t := range ts {
		tot.Points = append(tot.Points, *byMin[t])
	}
	ds := make([]string, 0, len(byDay))
	for d := range byDay {
		ds = append(ds, d)
	}
	sort.Strings(ds)
	for _, d := range ds {
		tot.Days = append(tot.Days, *byDay[d])
	}
	// The links can count less than the machine carried: a tunnel whose own
	// counter is not readable (a foreign spoke's FRP-only link) adds 0, and
	// the total read 0 B next to hundreds of GB on "This server". The total
	// is never below what the tunnel interfaces carried.
	for _, sr := range out {
		if sr.Key == usageHostKey && sr.Rx+sr.Tx > tot.Rx+tot.Tx {
			tot.Rx, tot.Tx, tot.Points, tot.Days = sr.Rx, sr.Tx, sr.Points, sr.Days
		}
	}
	return append([]usageSeries{tot}, out...)
}

// ---- wiring ----------------------------------------------------------------

// usageOnSnapshot is called after every snapshot build, like historyOnSnapshot.
//
// Two things are recorded:
//   - every link the snapshot knows (hub: the main tunnel and each peer);
//   - "host": the sum of all tunnel interfaces on this machine, taken straight
//     from /proc/net/dev. This is the only series that exists on a foreign
//     spoke (which has one tunnel and no peer list), and on a hub it is the
//     overall total that also covers interfaces the peer list does not name.
func usageOnSnapshot(s *HubSnapshot) {
	now := time.Now()
	for _, l := range s.All() {
		trafficUsage.observe(usageKey(l), linkName(l), now, l.Rx, l.Tx)
	}
	// every tunnel interface, plus the Backhaul/Bagher port counters, each
	// on its own (the chains count only what no interface does)
	cur := trafficTunnelIfs(s.DevData)
	if s.CarrierOK {
		cur[carrierKey] = [2]uint64{s.CarrierRx, s.CarrierTx}
	}
	trafficUsage.observeIfs(usageHostKey, "This server (all tunnels)", now, cur)
}

// tunnelRawTotals sums rx/tx over every tunnel interface in a /proc/net/dev
// dump. nil,nil when there is no tunnel interface (nothing to attribute).
func tunnelRawTotals(dev string) (rx, tx *uint64) {
	var r, t uint64
	var have bool
	for _, line := range strings.Split(dev, "\n") {
		line = strings.TrimSpace(line)
		i := strings.Index(line, ":")
		if i < 0 {
			continue
		}
		ifname := strings.TrimSpace(line[:i])
		if !isTunnelInterface(ifname) {
			continue
		}
		f := strings.Fields(line[i+1:])
		if len(f) < 9 {
			continue
		}
		a, e1 := strconv.ParseUint(f[0], 10, 64)
		b, e2 := strconv.ParseUint(f[8], 10, 64)
		if e1 != nil || e2 != nil {
			continue
		}
		r += a
		t += b
		have = true
	}
	if !have {
		return nil, nil
	}
	return &r, &t
}

// startUsagePersistence loads the ledger and saves it periodically and on stop.
func startUsagePersistence(stop <-chan struct{}) {
	trafficUsage.load(usageFile(), time.Now())
	go func() {
		t := time.NewTicker(usageSaveEvery)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				trafficUsage.mu.Lock()
				dirty := trafficUsage.dirty
				trafficUsage.mu.Unlock()
				if dirty {
					_ = trafficUsage.save(usageFile(), time.Now())
				}
			case <-stop:
				_ = trafficUsage.save(usageFile(), time.Now())
				return
			}
		}
	}()
}

// GET /api/traffic/usage?range=1h|6h|24h|7d  — admin only (requireAuth).
func handleUsageGet(w http.ResponseWriter, r *http.Request) {
	win, step := usageRange(r.URL.Query().Get("range"))
	writeJSON(w, map[string]any{
		"range":     r.URL.Query().Get("range"),
		"keep_days": int(usageKeep / (24 * time.Hour)),
		"step_sec":  step,
		"now":       time.Now().Unix(),
		"links":     trafficUsage.all(time.Now(), win, step),
	})
}
