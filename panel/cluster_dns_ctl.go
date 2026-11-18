package main

// DNS failover with one controller.
//
// Turning DNS failover on in one Iran hub makes that hub the controller: it
// sends its settings (the domain, the provider and its token, the TTL and
// every hub's share of users) to every linked hub, sealed with the cluster
// secret, over the signed hub channel (POST /_hc/dnsconf). Each hub then
// follows them: it keeps the same record, takes over the writes while the
// controller is down, and shows the settings without letting them change
// there. A hub linked later, or one that was down, gets them as soon as its
// heartbeat shows it lacks them (DNSBy / DNSVer in the beat).
//
// Only the route to the provider (direct or through one of its own tunnels)
// stays each hub's own: tunnels differ from hub to hub. Each hub checks with
// its own route that it can reach the provider and says so in its answer, so
// the controller shows which hubs could take over.
//
// A follower does not rely on a message to stop: when its controller is
// unlinked, or answers with a heartbeat that no longer controls the record
// (turned off, or another hub took over), it lets the settings go itself.

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// ---- the loop ----

var dnsWakeCh = make(chan struct{}, 1)

// dnsWake runs the DNS loop now (after a save), not at its next tick.
func dnsWake() {
	select {
	case dnsWakeCh <- struct{}{}:
	default:
	}
}

// startDNSLoop keeps the record and the followers up to date. It runs on its
// own (not in the hub heartbeat loop), so a hub with no linked hub keeps its
// record too.
func startDNSLoop() {
	for {
		select {
		case <-time.After(meshEvery):
		case <-dnsWakeCh:
		}
		c := loadClusterConfig()
		dnsFollowerCheck(c)
		dnsControl(c)
		dnsTick(loadClusterConfig())
	}
}

// ---- sealing (its own key: a sealed setting never opens as a bundle) ----

func dnsSealKey(secret string) []byte {
	k := sha256.Sum256([]byte("hashem-dns-settings-v1\n" + secret))
	return k[:]
}

func dnsSeal(secret string, v any) (string, error) {
	plain, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	b, err := aes.NewCipher(dnsSealKey(secret))
	if err != nil {
		return "", err
	}
	g, err := cipher.NewGCM(b)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(g.Seal(nonce, nonce, plain, nil)), nil
}

func dnsOpen(secret, sealed string, v any) error {
	raw, err := base64.RawURLEncoding.DecodeString(sealed)
	if err != nil {
		return errors.New("the settings are not sealed")
	}
	b, err := aes.NewCipher(dnsSealKey(secret))
	if err != nil {
		return err
	}
	g, err := cipher.NewGCM(b)
	if err != nil {
		return err
	}
	if len(raw) < g.NonceSize() {
		return errors.New("the settings are not sealed")
	}
	plain, err := g.Open(nil, raw[:g.NonceSize()], raw[g.NonceSize():], nil)
	if err != nil {
		return errors.New("the settings cannot be opened (different cluster secret)")
	}
	return json.Unmarshal(plain, v)
}

// ---- what travels ----

// dnsPush is the controller's settings as a follower receives them.
type dnsPush struct {
	Type     string         `json:"type"` // always "dnsconf"
	From     string         `json:"from"`
	FromName string         `json:"from_name"`
	Version  int64          `json:"version"`
	Enabled  bool           `json:"enabled"`
	Provider string         `json:"provider"`
	Token    string         `json:"token"`
	URL      string         `json:"url"`
	Name     string         `json:"name"`
	TTL      int            `json:"ttl"`
	Weights  map[string]int `json:"weights"` // hub id -> share, the controller's own included
}

type dnsConfReq struct {
	ID     string `json:"id"`
	Sealed string `json:"sealed"`
}

// dnsConfAns is a follower's answer. ReachErr is what its own check of the
// provider found ("" = it can reach it).
type dnsConfAns struct {
	OK       bool   `json:"ok"`
	Error    string `json:"error,omitempty"`
	Checked  bool   `json:"checked,omitempty"`
	ReachErr string `json:"reach_error,omitempty"`
	// Newer: the hub controls DNS failover itself with newer settings (it was
	// turned on there later): this hub will follow it, nothing is wrong.
	Newer bool `json:"newer,omitempty"`
}

// dnsPushFor builds what the controller sends.
func dnsPushFor(c ClusterConfig) dnsPush {
	w := map[string]int{c.NodeID: dnsWeight(c.DNS.Weight)}
	for id, v := range c.DNS.HubWeights {
		w[id] = dnsWeight(v)
	}
	return dnsPush{Type: "dnsconf", From: c.NodeID, FromName: hubLabel(HubPeer{Name: c.Name, PublicIP: meshSelfBeat(c).IP}),
		Version: c.DNS.Version, Enabled: c.DNS.Enabled, Provider: c.DNS.Provider, Token: c.DNS.Token, URL: c.DNS.URL,
		Name: c.DNS.Name, TTL: dnsClampTTL(c.DNS.TTL), Weights: w}
}

// ---- the controller side ----

// dnsFollowState is what the controller knows about one hub's copy.
type dnsFollowState struct {
	Ver      int64     // the version last sent
	At       time.Time // when
	OK       bool      // the hub took it
	Err      string    // why not
	Old      bool      // the hub's panel has no /dnsconf: it needs an update
	ReachErr string    // the hub cannot reach the provider with its own route
	Checked  bool
	busy     bool
}

var (
	dnsFollowMu sync.Mutex
	dnsFollow   = map[string]*dnsFollowState{}
	// dnsPushRetry is how soon a hub that did not take the settings is tried again.
	dnsPushRetry = 30 * time.Second
	// dnsPushCall sends the settings to one hub (a var for tests).
	dnsPushCall = func(h HubPeer, secret string, req dnsConfReq) (dnsConfAns, error) {
		var ans dnsConfAns
		err := meshCall(h, secret, "/dnsconf", req, &ans, 25*time.Second)
		return ans, err
	}
)

// dnsIsController: this hub's settings are its own and it has saved them in
// the new way (a version), on or just turned off.
func dnsIsController(c ClusterConfig) bool {
	return c.DNS.ManagedBy == "" && c.DNS.Version > 0
}

// dnsControl sends the settings to every hub that answers and lacks them: on,
// to each hub not following this one at this version; off, to each hub that
// still follows this one (so it stops at once, not at its next check).
func dnsControl(c ClusterConfig) {
	if !dnsIsController(c) || c.Secret == "" {
		return
	}
	for _, h := range c.Hubs {
		meshMu.Lock()
		st := meshState[h.ID]
		var by string
		var ver int64
		up := st != nil && st.Up
		if st != nil {
			by, ver = st.Beat.DNSBy, st.Beat.DNSVer
		}
		meshMu.Unlock()
		if !up {
			continue
		}
		need := false
		if c.DNS.Enabled {
			need = by != c.NodeID || ver != c.DNS.Version
		} else {
			need = by == c.NodeID
		}
		if !need {
			dnsFollowMu.Lock()
			if f := dnsFollow[h.ID]; f != nil && f.Ver == c.DNS.Version && !f.OK && f.Err == "" {
				f.OK = true // its beat shows it follows: the answer was lost
			}
			dnsFollowMu.Unlock()
			continue
		}
		dnsFollowMu.Lock()
		f := dnsFollow[h.ID]
		if f == nil {
			f = &dnsFollowState{}
			dnsFollow[h.ID] = f
		}
		if f.busy || (f.Ver == c.DNS.Version && time.Since(f.At) < dnsPushRetry) {
			dnsFollowMu.Unlock()
			continue
		}
		f.busy, f.Ver, f.At = true, c.DNS.Version, time.Now()
		dnsFollowMu.Unlock()
		go dnsSendTo(c, h)
	}
}

func dnsSendTo(c ClusterConfig, h HubPeer) {
	res := dnsFollowState{Ver: c.DNS.Version, At: time.Now()}
	sealed, err := dnsSeal(c.Secret, dnsPushFor(c))
	var ans dnsConfAns
	if err == nil {
		ans, err = dnsPushCall(h, c.Secret, dnsConfReq{ID: c.NodeID, Sealed: sealed})
	}
	switch {
	case err != nil && strings.Contains(err.Error(), "did not accept the request"):
		res.Old, res.Err = true, "its panel is older: "+syncUpdateAdvice()
	case err != nil:
		res.Err = err.Error()
	case !ans.OK && ans.Newer:
		res.Err = "it controls DNS failover itself now"
		dnsFollowMu.Lock()
		dnsFollow[h.ID] = &res
		dnsFollowMu.Unlock()
		return
	case !ans.OK:
		res.Err = ans.Error
	default:
		res.OK, res.Checked, res.ReachErr = true, ans.Checked, ans.ReachErr
	}
	dnsFollowMu.Lock()
	old := dnsFollow[h.ID]
	changed := old == nil || old.Err != res.Err || old.OK != res.OK || old.Ver != res.Ver
	dnsFollowMu.Unlock()
	// stored last: until then the hub counts as busy (no second send meanwhile)
	defer func() {
		dnsFollowMu.Lock()
		dnsFollow[h.ID] = &res
		dnsFollowMu.Unlock()
	}()
	if changed {
		switch {
		case res.OK && c.DNS.Enabled:
			clusterEventf("info", "DNS failover: %s follows this hub's settings now.", hubLabel(h))
		case res.OK:
			clusterEventf("info", "DNS failover: %s turned it off too.", hubLabel(h))
		default:
			clusterEventf("warn", "DNS failover: %s did not take this hub's settings: %s", hubLabel(h), res.Err)
		}
	}
}

// ---- the follower side ----

// POST /_hc/dnsconf: a linked hub sends its DNS failover settings.
func handleMeshDNSConf(w http.ResponseWriter, r *http.Request) {
	c, from, body, ok := meshAuthed(w, r, 1<<14)
	if !ok {
		return
	}
	var req dnsConfReq
	var p dnsPush
	ans := dnsConfAns{}
	if json.Unmarshal(body, &req) != nil {
		ans.Error = "bad request"
	} else if err := dnsOpen(c.Secret, req.Sealed, &p); err != nil {
		ans.Error = err.Error()
	} else if p.Type != "dnsconf" || p.From != from.ID {
		ans.Error = "the settings are not from the hub that sent them"
	} else {
		ans = dnsTakeSettings(from, p)
	}
	meshAnswer(w, c.Secret, ans)
}

// dnsTakeSettings applies what a controller sent.
func dnsTakeSettings(from HubPeer, p dnsPush) dnsConfAns {
	var ans dnsConfAns
	var took *DNSConfig
	c, err := updateClusterConfig(func(x *ClusterConfig) error {
		d := x.DNS
		if !p.Enabled {
			if d.ManagedBy == from.ID { // the controller turned it off: so does this hub
				dnsRelease(&d)
				d.Version = p.Version
				x.DNS = d
			}
			return nil
		}
		// Two hubs turned on: the later decision wins.
		if dnsIsController(*x) && x.DNS.Enabled && x.DNS.Version >= p.Version {
			return errDNSNewer
		}
		if !validDNSName(p.Name) || (p.Provider != "webhook" && p.Token == "") || (p.Provider == "webhook" && !validWebhookURL(p.URL)) {
			return fmt.Errorf("the settings are incomplete")
		}
		d.Enabled, d.Master = true, false
		d.Provider, d.Token, d.URL, d.Name = p.Provider, p.Token, p.URL, p.Name
		if d.Provider != "webhook" {
			d.Provider = "cloudflare"
		}
		d.TTL = dnsClampTTL(p.TTL)
		d.Version, d.ManagedBy, d.ManagedName = p.Version, from.ID, p.FromName
		d.HubWeights = map[string]int{}
		for id, v := range p.Weights {
			if id == x.NodeID {
				d.Weight = dnsWeight(v)
				continue
			}
			d.HubWeights[id] = dnsWeight(v)
		}
		// d.Route, d.TunnelID and d.TunnelPort stay this hub's own.
		x.DNS = d
		took = &d
		return nil
	})
	if err != nil {
		ans.Error, ans.Newer = err.Error(), errors.Is(err, errDNSNewer)
		return ans
	}
	ans.OK = true
	if took == nil {
		return ans
	}
	dnsTookMu.Lock()
	dnsTookAt = time.Now()
	dnsTookMu.Unlock()
	if c.DNS.ManagedBy == from.ID {
		clusterEventf("info", "DNS failover: this hub follows the settings of %s (%s).", c.DNS.ManagedName, c.DNS.Name)
	}
	if took.Provider == "cloudflare" {
		ans.Checked = true
		if _, err := cfZone(*took, took.Name); err != nil {
			ans.ReachErr = err.Error()
		}
	}
	dnsWake()
	return ans
}

var errDNSNewer = errors.New("this hub controls DNS failover itself, with newer settings")

// dnsRelease lets a controller's settings go: off, no token kept.
func dnsRelease(d *DNSConfig) {
	d.Enabled, d.Master, d.Token = false, false, ""
	d.ManagedBy, d.ManagedName = "", ""
	d.HubWeights = nil
}

var (
	dnsTookMu sync.Mutex
	// dnsTookAt is when this hub last took a controller's settings. A
	// controller beat this hub recorded before (or just after, still in
	// flight) shows the state from before the settings were sent, so only
	// beats seen dnsFollowMargin later can say the controller let them go.
	dnsTookAt       time.Time
	dnsFollowMargin = 2*meshEvery + 3*time.Second
)

// dnsFollowerCheck: a follower stops by itself when its controller is gone
// (unlinked) or answers but no longer controls the record.
func dnsFollowerCheck(c ClusterConfig) {
	ctl := c.DNS.ManagedBy
	if ctl == "" {
		return
	}
	why := ""
	linked := false
	for _, h := range c.Hubs {
		linked = linked || h.ID == ctl
	}
	if !linked {
		why = "the hub that controlled it is no longer linked"
	} else {
		dnsTookMu.Lock()
		fresh := dnsTookAt.Add(dnsFollowMargin)
		dnsTookMu.Unlock()
		meshMu.Lock()
		if st := meshState[ctl]; st != nil && st.Up && st.Beat.DNSBy != ctl && st.LastSeen.After(fresh) {
			why = "the hub that controlled it turned it off or handed it over"
		}
		meshMu.Unlock()
	}
	if why == "" {
		return
	}
	name := c.DNS.ManagedName
	_, _ = updateClusterConfig(func(x *ClusterConfig) error {
		if x.DNS.ManagedBy == ctl {
			dnsRelease(&x.DNS)
		}
		return nil
	})
	clusterEventf("info", "DNS failover: off on this hub too (%s: %s).", why, name)
}

func dnsManagedLabel(c ClusterConfig) string {
	if c.DNS.ManagedName != "" {
		return c.DNS.ManagedName
	}
	for _, h := range c.Hubs {
		if h.ID == c.DNS.ManagedBy {
			return hubLabel(h)
		}
	}
	return "another hub"
}

// ---- the ports each hub serves (users on a port a hub lacks would fail there) ----

var dnsPortsCache struct {
	sync.Mutex
	at      time.Time
	busy    bool
	mine    []int
	hubs    map[string][]int // nil: not known
	tunnels map[string]int   // how many tunnels the hub has
}

// dnsPortsGo runs the background refresh (tests run it in place, so it never
// outlives the test that swapped the functions it reads).
var dnsPortsGo = func(f func()) { go f() }

// dnsPortsFor returns, for each hub, the ports this hub serves and it does not
// (known hubs only). It refreshes in the background at most every 30 s.
func dnsPortsFor(c ClusterConfig) map[string][]int {
	dnsPortsCache.Lock()
	stale := time.Since(dnsPortsCache.at) > 30*time.Second && !dnsPortsCache.busy
	if stale {
		dnsPortsCache.busy = true
	}
	mine, hubs := dnsPortsCache.mine, dnsPortsCache.hubs
	dnsPortsCache.Unlock()
	if stale {
		dnsPortsGo(func() { dnsPortsRefresh(c) })
	}
	out := map[string][]int{}
	for id, theirs := range hubs {
		var miss []int
		for _, p := range mine {
			if !hasInt(theirs, p) {
				miss = append(miss, p)
			}
		}
		if len(miss) > 0 {
			out[id] = miss
		}
	}
	return out
}

func syncPortsUnion(ts []syncTunnel) []int {
	var out []int
	for _, t := range ts {
		for _, p := range t.Ports {
			if !hasInt(out, p) {
				out = append(out, p)
			}
		}
	}
	sort.Ints(out)
	return out
}

func dnsPortsRefresh(c ClusterConfig) {
	mine := syncPortsUnion(syncLocalTunnels())
	hubs := map[string][]int{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	for _, h := range c.Hubs {
		meshMu.Lock()
		up := meshState[h.ID] != nil && meshState[h.ID].Up
		meshMu.Unlock()
		if !up {
			continue
		}
		wg.Add(1)
		go func(h HubPeer) {
			defer wg.Done()
			var l syncList
			if meshCall(h, c.Secret, "/tunnels", map[string]string{"id": c.NodeID}, &l, 6*time.Second) == nil && ctx.Err() == nil {
				mu.Lock()
				hubs[h.ID] = syncPortsUnion(l.Tunnels)
				mu.Unlock()
			}
		}(h)
	}
	wg.Wait()
	dnsPortsCache.Lock()
	dnsPortsCache.at, dnsPortsCache.busy, dnsPortsCache.mine, dnsPortsCache.hubs = time.Now(), false, mine, hubs
	dnsPortsCache.Unlock()
}
