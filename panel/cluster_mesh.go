package main

// Iran hubs that back each other up. Hubs are linked once with a join code;
// after that every hub sends every other hub a signed heartbeat every few
// seconds with the state of its pools. A pool that has no working member here
// is forwarded (DNAT + MASQUERADE, Iran to Iran) to a hub where the same pool
// is healthy, so users keep working while this hub's foreign links are down.
//
// Heartbeats travel over plain HTTP on the panel port, at a fixed path that
// does not reveal the panel. Each request and answer is signed with the
// cluster secret (HMAC-SHA256 over a timestamp, a nonce and the body); stale
// timestamps and reused nonces are refused.

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// HubPeer is another Iran hub in the cluster.
type HubPeer struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	URL      string `json:"url"` // http://IP:PORT
	PublicIP string `json:"public_ip"`
}

// meshRoutePrefix is fixed (not under the panel's random base path) because
// other hubs cannot know that path. Unsigned requests get a plain 404.
const meshRoutePrefix = "/_hc"

const (
	meshEvery    = 3 * time.Second
	meshFall     = 3 // missed heartbeats before a hub counts as down
	meshMaxSkew  = 90 * time.Second
	meshCodeHead = "hc1_"
)

// meshPoolState is one pool as a heartbeat reports it.
type meshPoolState struct {
	State   string `json:"state"`
	Healthy int    `json:"healthy"`
	Members int    `json:"members"`
}

type meshBeat struct {
	ID      string                   `json:"id"`
	Name    string                   `json:"name"`
	IP      string                   `json:"ip"`
	IP6     string                   `json:"ip6,omitempty"` // the hub's public IPv6 (DNS failover's AAAA)
	Port    int                      `json:"port"`
	Healthy bool                     `json:"healthy"`
	Pools   map[string]meshPoolState `json:"pools"`
	Hubs    []HubPeer                `json:"hubs,omitempty"` // in hello answers: the hubs to link with
	DNS     string                   `json:"dns,omitempty"`  // record this hub keeps (DNS failover)
	Version string                   `json:"version"`
	Bye     bool                     `json:"bye,omitempty"`

	Weight int  `json:"weight,omitempty"` // this hub's share of users (1..100)
	Master bool `json:"master,omitempty"` // this hub is DNS failover's master

	// DNSBy is the hub whose DNS failover settings this hub uses: its own id
	// when it controls them, the controller's when it follows (cluster_dns.go).
	// DNSVer is the version of those settings, so the controller sees who has
	// the latest ones.
	DNSBy  string `json:"dns_by,omitempty"`
	DNSVer int64  `json:"dns_ver,omitempty"`

	// DNSDown: the hub cannot reach the DNS provider, so another one writes the
	// domain. DNSRecs is what the domain points to, from the hub that writes it.
	DNSDown bool     `json:"dns_down,omitempty"`
	DNSRecs []string `json:"dns_recs,omitempty"`
	// Starting: the panel has just started and does not know yet whether its
	// tunnels work (Healthy says nothing).
	Starting bool `json:"starting,omitempty"`
	// Load is the traffic of the hub's tunnels in bytes per second, nil when it
	// is not measured for every one of them.
	Load *float64 `json:"load,omitempty"`

	// Links are the hub's foreign servers, for the cluster map of the other
	// hubs (which foreign server each Iran hub reaches).
	Links []meshLink `json:"links,omitempty"`
}

// meshLink is one foreign server of a hub, as the cluster map shows it.
type meshLink struct {
	ID     int     `json:"id"`
	Name   string  `json:"name"`
	Remote string  `json:"remote"`
	Engine string  `json:"engine,omitempty"`
	Up     bool    `json:"up"`
	Ms     float64 `json:"ms,omitempty"`
	Bps    float64 `json:"bps"` // traffic both ways, bytes per second
}

// linkRates turns the tunnels' byte counters into traffic per second for the
// map. The beat and the status poll both read it; a rate is measured over at
// least 2 s and smoothed, so it does not jump between polls.
var linkRates = struct {
	sync.Mutex
	m map[string]*linkRate
}{m: map[string]*linkRate{}}

type linkRate struct {
	bytes uint64
	at    time.Time
	bps   float64
	seen  time.Time
}

func linkBps(key string, rx, tx *uint64, now time.Time) float64 {
	if rx == nil || tx == nil {
		return 0
	}
	total := *rx + *tx
	linkRates.Lock()
	defer linkRates.Unlock()
	r := linkRates.m[key]
	if r == nil {
		if len(linkRates.m) > 512 { // tunnels come and go: forget the old ones
			for k, v := range linkRates.m {
				if now.Sub(v.seen) > 10*time.Minute {
					delete(linkRates.m, k)
				}
			}
		}
		linkRates.m[key] = &linkRate{bytes: total, at: now, seen: now}
		return 0
	}
	r.seen = now
	dt := now.Sub(r.at).Seconds()
	if dt < 2 {
		return r.bps
	}
	if total < r.bytes { // the counter restarted (service or interface)
		r.bytes, r.at = total, now
		return r.bps
	}
	cur := float64(total-r.bytes) / dt
	if r.bps == 0 || dt > 30 {
		r.bps = cur
	} else {
		r.bps = 0.6*cur + 0.4*r.bps
	}
	r.bytes, r.at = total, now
	return math.Round(r.bps)
}

// meshLinksOf lists the tunnels of a snapshot as the beat carries them
// (healthy or degraded counts as up: it carries users).
func meshLinksOf(s *HubSnapshot) []meshLink {
	if s == nil {
		return nil
	}
	var out []meshLink
	for _, l := range s.All() {
		if l.RemotePub == "" {
			continue
		}
		if len(out) == 200 { // the beat stays far below its 64 KiB limit
			break
		}
		ml := meshLink{ID: l.ID, Name: l.Name, Remote: l.RemotePub, Engine: l.Engine, Up: l.HealthState == stateHealthy || l.HealthState == stateDegraded}
		ml.Bps = linkBps(strconv.Itoa(l.ID)+"|"+l.RemotePub, l.Rx, l.Tx, time.Now())
		if ml.Up && l.LatencyMs > 0 {
			ml.Ms = math.Round(l.LatencyMs*10) / 10
		}
		out = append(out, ml)
	}
	return out
}

// meshLoad is the traffic of all tunnels together, nil when one that works has
// no counters (the others' sum would say nothing about the hub's share).
func meshLoad(s *HubSnapshot, links []meshLink) *float64 {
	if s == nil || len(links) == 0 {
		return nil
	}
	for _, l := range s.All() {
		if l.RemotePub != "" && (l.HealthState == stateHealthy || l.HealthState == stateDegraded) && (l.Rx == nil || l.Tx == nil) {
			return nil
		}
	}
	sum := 0.0
	for _, l := range links {
		sum += l.Bps
	}
	return &sum
}

// meshWarmup: how long after its start a panel may need to see its tunnels.
const meshWarmup = 20 * time.Second

// panelUptime is how long the panel runs (a var for tests).
var panelUptime = func() time.Duration { return time.Since(panelStartedAt) }

// hubRT is what this hub knows about another one right now.
type hubRT struct {
	Up        bool
	Misses    int
	LastSeen  time.Time
	LatencyMs float64
	Beat      meshBeat
	Err       string
}

var (
	meshMu     sync.Mutex
	meshState  = map[string]*hubRT{}
	meshNonces = map[string]time.Time{}
	meshClient = &http.Client{Timeout: 2500 * time.Millisecond}
)

// ---- signing ----

func meshSign(secret, ts, nonce string, body []byte) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(ts + "\n" + nonce + "\n"))
	m.Write(body)
	return hex.EncodeToString(m.Sum(nil))
}

// meshVerify checks the signature headers of a request or answer.
func meshVerify(secret string, h http.Header, body []byte, now time.Time) error {
	if secret == "" {
		return fmt.Errorf("no cluster secret")
	}
	ts, nonce, sig := h.Get("X-Hashem-Ts"), h.Get("X-Hashem-Nonce"), h.Get("X-Hashem-Sig")
	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || len(nonce) < 16 || sig == "" {
		return fmt.Errorf("unsigned")
	}
	if d := now.Sub(time.Unix(sec, 0)); d > meshMaxSkew || d < -meshMaxSkew {
		return fmt.Errorf("clock differs by %s (set NTP on both hubs)", d.Round(time.Second))
	}
	want := meshSign(secret, ts, nonce, body)
	if subtle.ConstantTimeCompare([]byte(want), []byte(sig)) != 1 {
		return fmt.Errorf("bad signature (different cluster secret)")
	}
	meshMu.Lock()
	defer meshMu.Unlock()
	for n, at := range meshNonces {
		if now.Sub(at) > 2*meshMaxSkew {
			delete(meshNonces, n)
		}
	}
	if _, seen := meshNonces[nonce]; seen {
		return fmt.Errorf("replayed request")
	}
	meshNonces[nonce] = now
	return nil
}

func meshSetSig(h http.Header, secret string, body []byte) {
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := randHex(12)
	h.Set("X-Hashem-Ts", ts)
	h.Set("X-Hashem-Nonce", nonce)
	h.Set("X-Hashem-Sig", meshSign(secret, ts, nonce, body))
}

// meshPost sends a signed beat to another hub and returns its signed answer.
func meshPost(url, path, secret string, beat meshBeat) (meshBeat, float64, error) {
	body, _ := json.Marshal(beat)
	req, err := http.NewRequest("POST", strings.TrimRight(url, "/")+meshRoutePrefix+path, bytes.NewReader(body))
	if err != nil {
		return meshBeat{}, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	meshSetSig(req.Header, secret, body)
	start := time.Now()
	resp, err := meshClient.Do(req)
	if err != nil {
		return meshBeat{}, 0, fmt.Errorf("unreachable: %s", shortNetErr(err))
	}
	defer resp.Body.Close()
	lat := float64(time.Since(start).Microseconds()) / 1000
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotFound {
			return meshBeat{}, lat, fmt.Errorf("refused: the other hub has a different cluster secret or an older panel")
		}
		return meshBeat{}, lat, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if err := meshVerify(secret, resp.Header, data, time.Now()); err != nil {
		return meshBeat{}, lat, fmt.Errorf("answer not trusted: %v", err)
	}
	var out meshBeat
	if err := json.Unmarshal(data, &out); err != nil {
		return meshBeat{}, lat, err
	}
	return out, lat, nil
}

func shortNetErr(err error) string {
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i >= 0 {
		s = s[i+2:]
	}
	return s
}

// ---- own state ----

func meshSelfURL(c ClusterConfig) string {
	ip := c.PublicIP
	if ip == "" {
		ip = detectPublicIPCached()
	}
	if ip == "" {
		return ""
	}
	return "http://" + net.JoinHostPort(ip, strconv.Itoa(cfg.Port))
}

// meshSelfBeat describes this hub.
func meshSelfBeat(c ClusterConfig) meshBeat {
	ip := c.PublicIP
	if ip == "" {
		ip = detectPublicIPCached()
	}
	b := meshBeat{ID: c.NodeID, Name: c.Name, IP: ip, IP6: meshIP6(), Port: cfg.Port, Pools: map[string]meshPoolState{}, Version: panelVersion}
	clusterRT.mu.Lock()
	anyOK, pools := false, 0
	for _, p := range c.Pools {
		pl := clusterRT.plans[p.key()]
		healthy := 0
		for _, t := range pl.Targets {
			if lr := clusterRT.links[t.Link]; lr != nil && lr.Up {
				healthy++
			}
		}
		if !p.Disabled {
			pools++
		}
		if pl.State == poolOK || pl.State == poolDegraded {
			anyOK = true
		}
		for _, proto := range lbProtos(p.Proto) {
			b.Pools[proto+"/"+strconv.Itoa(p.Port)] = meshPoolState{State: pl.State, Healthy: healthy, Members: len(p.Members)}
		}
	}
	clusterRT.mu.Unlock()
	snap := lbSnapshot()
	if pools == 0 {
		// Without (enabled) pools the cluster monitor is idle and its link list stops
		// being updated (it keeps what it had when the last pool went): the
		// live snapshot says whether a tunnel works.
		anyOK = snapAnyLinkWorks(snap)
	}
	b.Links = meshLinksOf(snap)
	b.Load = meshLoad(snap, b.Links)
	b.Healthy = anyOK
	b.Starting = !anyOK && (snap == nil || snap.AgeMs() < 0 || panelUptime() < meshWarmup)
	if c.DNS.Enabled {
		b.DNS = c.DNS.Name
		b.DNSBy, b.DNSVer = dnsControllerID(c), c.DNS.Version
		b.DNSDown = dnsReachDown(c.DNS)
		if dnsLeading.Load() {
			b.DNSRecs = c.DNS.Records
		}
	}
	b.Weight = dnsWeight(c.DNS.Weight)
	b.Master = c.DNS.Enabled && c.DNS.Master
	return b
}

// snapAnyLinkWorks: one of the tunnels of the snapshot is healthy or degraded
// (degraded still carries users). No snapshot or no tunnel: false.
func snapAnyLinkWorks(s *HubSnapshot) bool {
	if s == nil {
		return false
	}
	for _, l := range s.All() {
		if l.HealthState == stateHealthy || l.HealthState == stateDegraded {
			return true
		}
	}
	return false
}

// ---- join ----

type meshCode struct {
	ID     string `json:"i"`
	Name   string `json:"n"`
	URL    string `json:"u"`
	IP     string `json:"a"`
	Secret string `json:"s"`
}

// meshJoinCode makes the code another hub pastes to link with this one. The
// cluster secret is created on first use.
func meshJoinCode(c ClusterConfig) (string, error) {
	if c.Secret == "" {
		var err error
		c, err = updateClusterConfig(func(x *ClusterConfig) error {
			if x.Secret == "" {
				x.Secret = randHex(32)
			}
			return nil
		})
		if err != nil {
			return "", err
		}
	}
	url := meshSelfURL(c)
	if url == "" {
		return "", fmt.Errorf("this hub's public IP is unknown: set it in Cluster settings")
	}
	b := meshSelfBeat(c)
	data, _ := json.Marshal(meshCode{ID: c.NodeID, Name: c.Name, URL: url, IP: b.IP, Secret: c.Secret})
	return meshCodeHead + base64.RawURLEncoding.EncodeToString(data), nil
}

func parseMeshCode(s string) (meshCode, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, meshCodeHead) {
		return meshCode{}, fmt.Errorf("not a hub join code (it starts with %s)", meshCodeHead)
	}
	data, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(s, meshCodeHead))
	if err != nil {
		return meshCode{}, fmt.Errorf("the code is damaged: copy it again")
	}
	var c meshCode
	if json.Unmarshal(data, &c) != nil || c.ID == "" || c.URL == "" || len(c.Secret) < 32 {
		return meshCode{}, fmt.Errorf("the code is damaged: copy it again")
	}
	return c, nil
}

// meshAddHub links this hub with the one that made code, and with every hub
// that one already knows.
func meshAddHub(code string) (HubPeer, error) {
	mc, err := parseMeshCode(code)
	if err != nil {
		return HubPeer{}, err
	}
	c := loadClusterConfig()
	if mc.ID == c.NodeID {
		return HubPeer{}, fmt.Errorf("this is this hub's own code: paste it on another Iran server")
	}
	secret := mc.Secret
	if c.Secret != "" && c.Secret != mc.Secret && len(c.Hubs) > 0 {
		// This hub already has a cluster and the new hub made its code with
		// a secret of its own (its first Show Join Code): the new hub takes
		// this cluster's secret, so a third, fourth or fifth hub can be
		// linked from any hub of the cluster.
		if err := meshAdopt(c, mc); err != nil {
			return HubPeer{}, err
		}
		secret = c.Secret
	}
	self := meshSelfBeat(c)
	self.Hubs = c.Hubs // the new hub links with them too (meshMeet)
	ans, _, err := meshPost(mc.URL, "/hello", secret, self)
	if err != nil {
		return HubPeer{}, fmt.Errorf("cannot reach %s: %v", mc.URL, err)
	}
	if ans.ID != mc.ID {
		return HubPeer{}, fmt.Errorf("the hub at %s answered as %s, not %s", mc.URL, ans.ID, mc.ID)
	}
	h := HubPeer{ID: ans.ID, Name: ans.Name, URL: mc.URL, PublicIP: ans.IP}
	_, err = updateClusterConfig(func(x *ClusterConfig) error {
		x.Secret = secret
		meshUpsert(x, h)
		for _, o := range ans.Hubs {
			if o.ID != x.NodeID && o.ID != h.ID {
				meshUpsert(x, o)
			}
		}
		return nil
	})
	if err != nil {
		return HubPeer{}, err
	}
	clusterEventf("info", "Linked with Iran hub %s (%s).", h.Name, h.PublicIP)
	// Introduce ourselves to the hubs we learned about.
	for _, o := range ans.Hubs {
		if o.ID != c.NodeID && o.ID != h.ID {
			if _, _, err := meshPost(o.URL, "/hello", secret, self); err != nil {
				clusterEventf("warn", "Hub %s could not be told about this hub yet: %v", o.Name, err)
			}
		}
	}
	return h, nil
}

// meshAdoptReq asks a hub that has no other hub yet to take this cluster's
// secret (sealed with the secret of its own join code).
type meshAdoptReq struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Secret string `json:"secret"`
}

type meshAdoptAns struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// meshAdopt gives the hub of code mc this cluster's secret. The request is
// signed with the secret of that hub's code, so only who has its join code
// can ask, as for linking itself.
func meshAdopt(c ClusterConfig, mc meshCode) error {
	sealed, err := syncSeal(mc.Secret, c.Secret)
	if err != nil {
		return err
	}
	var ans meshAdoptAns
	err = meshCall(HubPeer{ID: mc.ID, URL: mc.URL}, mc.Secret, "/adopt", meshAdoptReq{ID: c.NodeID, Name: c.Name, Secret: sealed}, &ans, 10*time.Second)
	if err != nil {
		if errors.Is(err, errMeshRefused) {
			return fmt.Errorf("the hub at %s runs an older panel: update it to this hub's version, or press Show Join Code on this hub and paste that code on it", mc.URL)
		}
		return fmt.Errorf("cannot reach %s: %v", mc.URL, err)
	}
	if !ans.OK {
		return errors.New(ans.Error)
	}
	return nil
}

// POST /_hc/adopt: another hub adds this one to its cluster. Signed with this
// hub's own secret (the one in its join code); accepted only while this hub
// has no other hub, so it never leaves a cluster it is in.
func handleMeshAdopt(w http.ResponseWriter, r *http.Request) {
	c := loadClusterConfig()
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<12))
	if err != nil || c.Secret == "" || meshVerify(c.Secret, r.Header, body, time.Now()) != nil {
		http.NotFound(w, r)
		return
	}
	var req meshAdoptReq
	if json.Unmarshal(body, &req) != nil || req.ID == "" || req.ID == c.NodeID {
		http.NotFound(w, r)
		return
	}
	ans := meshAdoptAns{}
	newSecret, err := syncOpen(c.Secret, req.Secret)
	if err != nil || len(newSecret) < 32 {
		ans.Error = "the request cannot be read"
		meshAnswer(w, c.Secret, ans)
		return
	}
	_, err = updateClusterConfig(func(x *ClusterConfig) error {
		if x.Secret != c.Secret {
			return errors.New("this hub's cluster secret changed meanwhile: try again")
		}
		if len(x.Hubs) > 0 && x.Secret != newSecret {
			return errors.New("this hub is already linked with other hubs: show its join code and paste it on the other hub instead, or unlink its hubs first")
		}
		x.Secret = newSecret
		return nil
	})
	if err != nil {
		ans.Error = err.Error()
	} else {
		ans.OK = true
		clusterEventf("info", "Iran hub %s adds this hub to its cluster.", req.Name)
	}
	meshAnswer(w, c.Secret, ans) // the asking hub checks it with the code's secret
}

// meshMeet links this hub with the hubs that a new hub's hello names (the
// hub that added this one by its code knows the rest of the cluster). Each
// is kept only when it answers a signed hello as itself.
func meshMeet(hubs []HubPeer) {
	c := loadClusterConfig()
	self := meshSelfBeat(c)
	for _, o := range hubs {
		if o.ID == "" || o.ID == c.NodeID || o.URL == "" {
			continue
		}
		known := false
		for _, h := range c.Hubs {
			known = known || h.ID == o.ID
		}
		if known {
			continue
		}
		ans, _, err := meshPost(o.URL, "/hello", c.Secret, self)
		if err != nil || ans.ID != o.ID {
			clusterEventf("warn", "Hub %s could not be linked yet: %v", o.Name, err)
			continue
		}
		h := HubPeer{ID: ans.ID, Name: ans.Name, URL: o.URL, PublicIP: ans.IP}
		_, _ = updateClusterConfig(func(x *ClusterConfig) error { meshUpsert(x, h); return nil })
		clusterEventf("info", "Linked with Iran hub %s (%s).", h.Name, h.PublicIP)
	}
}

func meshUpsert(c *ClusterConfig, h HubPeer) {
	for i := range c.Hubs {
		if c.Hubs[i].ID == h.ID {
			c.Hubs[i] = h
			return
		}
	}
	c.Hubs = append(c.Hubs, h)
	sort.Slice(c.Hubs, func(i, j int) bool { return c.Hubs[i].ID < c.Hubs[j].ID })
}

// meshRemoveHub forgets a hub here and asks it to forget this one.
func meshRemoveHub(id string) bool {
	var gone *HubPeer
	c, _ := updateClusterConfig(func(x *ClusterConfig) error {
		out := x.Hubs[:0]
		for _, h := range x.Hubs {
			if h.ID == id {
				hh := h
				gone = &hh
				continue
			}
			out = append(out, h)
		}
		x.Hubs = out
		return nil
	})
	if gone == nil {
		return false
	}
	meshMu.Lock()
	delete(meshState, id)
	meshMu.Unlock()
	b := meshSelfBeat(c)
	b.Bye = true
	go func() { _, _, _ = meshPost(gone.URL, "/beat", c.Secret, b) }()
	clusterEventf("info", "Unlinked from Iran hub %s.", gone.Name)
	return true
}

// ---- server side ----

// mountMeshRoutes serves the hub-to-hub API.
func mountMeshRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST "+meshRoutePrefix+"/hello", meshHandler(true))
	mux.HandleFunc("POST "+meshRoutePrefix+"/beat", meshHandler(false))
	mux.HandleFunc("POST "+meshRoutePrefix+"/adopt", handleMeshAdopt)
	mux.HandleFunc("POST "+meshRoutePrefix+"/update", handleMeshUpdate)       // update_remote.go
	mux.HandleFunc("POST "+meshRoutePrefix+"/tunnels", handleMeshTunnels)     // cluster_sync.go
	mux.HandleFunc("POST "+meshRoutePrefix+"/deliver", handleMeshDeliver)     // cluster_sync.go
	mux.HandleFunc("POST "+meshRoutePrefix+"/pull", handleMeshPull)           // cluster_sync.go
	mux.HandleFunc("POST "+meshRoutePrefix+"/syncstate", handleMeshSyncState) // cluster_sync.go
	mux.HandleFunc("POST "+meshRoutePrefix+"/dnsconf", handleMeshDNSConf)     // cluster_dns_ctl.go
}

func meshHandler(hello bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c := loadClusterConfig()
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
		if err != nil || c.Secret == "" || meshVerify(c.Secret, r.Header, body, time.Now()) != nil {
			http.NotFound(w, r)
			return
		}
		var in meshBeat
		if json.Unmarshal(body, &in) != nil || in.ID == "" || in.ID == c.NodeID {
			http.Error(w, "bad beat", http.StatusBadRequest)
			return
		}
		known := false
		for _, h := range c.Hubs {
			known = known || h.ID == in.ID
		}
		switch {
		case in.Bye:
			if known {
				c, _ = updateClusterConfig(func(x *ClusterConfig) error {
					out := x.Hubs[:0]
					for _, h := range x.Hubs {
						if h.ID != in.ID {
							out = append(out, h)
						}
					}
					x.Hubs = out
					return nil
				})
				clusterEventf("info", "Iran hub %s unlinked itself.", in.Name)
			}
		case hello || !known:
			if !hello && !known {
				// A hub that still knows us after we removed it: do not
				// re-add it silently.
				http.NotFound(w, r)
				return
			}
			ip := in.IP
			if ip == "" {
				ip, _, _ = net.SplitHostPort(r.RemoteAddr)
			}
			h := HubPeer{ID: in.ID, Name: in.Name, URL: "http://" + net.JoinHostPort(ip, strconv.Itoa(in.Port)), PublicIP: ip}
			c, _ = updateClusterConfig(func(x *ClusterConfig) error { meshUpsert(x, h); return nil })
			if !known {
				clusterEventf("info", "Iran hub %s (%s) linked with this hub.", h.Name, h.PublicIP)
			}
			if hello && len(in.Hubs) > 0 {
				go meshMeet(in.Hubs)
			}
		}
		meshRecord(in, 0, nil)
		out := meshSelfBeat(c)
		if hello {
			out.Hubs = c.Hubs
		}
		data, _ := json.Marshal(out)
		meshSetSig(w.Header(), c.Secret, data)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
	}
}

// meshRecord stores what a beat (sent or received) told about a hub.
func meshRecord(b meshBeat, lat float64, err error) {
	meshMu.Lock()
	defer meshMu.Unlock()
	st := meshState[b.ID]
	if st == nil {
		st = &hubRT{}
		meshState[b.ID] = st
	}
	if err != nil {
		st.Misses++
		st.Err = err.Error()
		if st.Up && st.Misses >= meshFall {
			st.Up = false
			name, msg := st.Beat.Name, err.Error()
			go clusterEventf("warn", "Iran hub %s stopped answering: %s", name, msg)
		}
		return
	}
	if !st.Up && !st.LastSeen.IsZero() {
		name := b.Name
		go clusterEventf("info", "Iran hub %s answers again.", name)
	}
	st.Up, st.Misses, st.Err, st.LastSeen, st.Beat = true, 0, "", time.Now(), b
	if lat > 0 {
		st.LatencyMs = round1(lat)
	}
}

// ---- client side ----

// startMeshLoop sends a beat to every hub every meshEvery.
func startMeshLoop() {
	for {
		time.Sleep(meshEvery)
		c := loadClusterConfig()
		if c.Secret == "" || len(c.Hubs) == 0 {
			continue
		}
		clusterGreRefresh(c)
		self := meshSelfBeat(c)
		var wg sync.WaitGroup
		for _, h := range c.Hubs {
			wg.Add(1)
			go func(h HubPeer) {
				defer wg.Done()
				ans, lat, err := meshPost(h.URL, "/beat", c.Secret, self)
				if err == nil && ans.ID != h.ID {
					err = fmt.Errorf("answered as %s", ans.ID)
				}
				if err != nil {
					meshRecord(meshBeat{ID: h.ID, Name: h.Name}, 0, err)
					return
				}
				meshRecord(ans, lat, nil)
			}(h)
		}
		wg.Wait()
	}
}

// meshForwardTarget picks the hub to forward a pool to: up, with the same
// pool working there (not itself forwarded, which could loop), lowest
// latency. It returns that hub's public IPv4 or "".
func meshForwardTarget(c ClusterConfig, p LBPool) string {
	meshMu.Lock()
	defer meshMu.Unlock()
	best, bestLat := "", 0.0
	for _, h := range c.Hubs {
		st := meshState[h.ID]
		if st == nil || !st.Up || !isIPv4(hubIP4(h, st)) {
			continue
		}
		okAll := true
		for _, proto := range lbProtos(p.Proto) {
			ps, ok := st.Beat.Pools[proto+"/"+strconv.Itoa(p.Port)]
			if !ok || (ps.State != poolOK && ps.State != poolDegraded) {
				okAll = false
			}
		}
		if okAll && (best == "" || st.LatencyMs < bestLat) {
			best, bestLat = hubIP4(h, st), st.LatencyMs
		}
	}
	return best
}

type hubView struct {
	HubPeer
	Up        bool                     `json:"up"`
	Healthy   bool                     `json:"healthy"`
	LatencyMs float64                  `json:"latency_ms"`
	LastSeen  string                   `json:"last_seen,omitempty"`
	Error     string                   `json:"error,omitempty"`
	Pools     map[string]meshPoolState `json:"pools"`
	Version   string                   `json:"version,omitempty"`
	Links     []meshLink               `json:"links"` // its foreign servers (cluster map)
	// VersionDiffers: the hub answers with another panel version (or one too
	// old to send it). The cluster needs the same version on every hub.
	VersionDiffers bool `json:"version_differs,omitempty"`
}

func meshView(c ClusterConfig) []hubView {
	meshMu.Lock()
	defer meshMu.Unlock()
	out := make([]hubView, 0, len(c.Hubs))
	for _, h := range c.Hubs {
		v := hubView{HubPeer: h}
		if st := meshState[h.ID]; st != nil {
			v.Up, v.Healthy, v.LatencyMs, v.Error, v.Pools, v.Version = st.Up, st.Beat.Healthy, st.LatencyMs, st.Err, st.Beat.Pools, st.Beat.Version
			v.Links = st.Beat.Links
			if !st.LastSeen.IsZero() {
				v.LastSeen = st.LastSeen.Format("2006-01-02 15:04:05")
				v.VersionDiffers = st.Beat.Version != panelVersion
			}
		}
		out = append(out, v)
	}
	return out
}

// meshIP6 is this hub's public IPv6 for its beat (swapped in tests).
var meshIP6 = detectPublicIP6Cached

func isIPv4(s string) bool {
	ip := net.ParseIP(strings.TrimSpace(s))
	return ip != nil && ip.To4() != nil
}

// ---- API ----

func handleClusterJoinCode(w http.ResponseWriter, r *http.Request) {
	if proRequired(w, r, "cluster", "Cluster") {
		return
	}
	code, err := meshJoinCode(loadClusterConfig())
	if err != nil {
		writeAPIError(w, r, "E-CLUSTER-08", err.Error())
		return
	}
	writeJSON(w, map[string]any{"code": code})
}

func handleClusterHubAdd(w http.ResponseWriter, r *http.Request) {
	if proRequired(w, r, "cluster", "Cluster") {
		return
	}
	var req struct {
		Code        string `json:"code"`
		SyncTunnels bool   `json:"sync_tunnels"` // also copy the hub's tunnels here (cluster_sync.go)
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<13)).Decode(&req) != nil {
		writeAPIError(w, r, "E-CLUSTER-01", "")
		return
	}
	if _, err := parseMeshCode(req.Code); err != nil {
		writeAPIError(w, r, "E-CLUSTER-07", err.Error())
		return
	}
	h, err := meshAddHub(req.Code)
	if err != nil {
		writeAPIError(w, r, "E-CLUSTER-08", err.Error())
		return
	}
	out := map[string]any{"status": "ok", "hub": h}
	if req.SyncTunnels {
		if serr := startHubSync(h.ID, true); serr != nil {
			out["sync_error"] = serr.Error()
		} else {
			out["sync"] = "started"
		}
	}
	writeJSON(w, out)
}

func handleClusterHubDelete(w http.ResponseWriter, r *http.Request) {
	if proRequired(w, r, "cluster", "Cluster") {
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req) != nil {
		writeAPIError(w, r, "E-CLUSTER-01", "")
		return
	}
	if !meshRemoveHub(req.ID) {
		writeAPIError(w, r, "E-CLUSTER-05", "no hub with id "+req.ID)
		return
	}
	writeJSON(w, map[string]any{"status": "ok"})
}
