package main

// DNS failover: a domain whose A records are the public IPs of the Iran hubs
// that work right now (and AAAA records for the IPv6 addresses of the hubs
// without load-balanced pools, which each hub reports in its beat). Users who connect by name move to a working hub when
// one dies (after the record's TTL). Cloudflare is built in (the record must
// be DNS only, grey cloud, since the proxy would not carry tunnels); any other
// DNS provider or script can take a webhook with the list of working hubs.
//
// Every hub with DNS failover on reports the record name in its heartbeat;
// the one with the lowest id among the reachable ones writes the records, so
// two hubs never fight. Records whose IP is not one of the cluster's hubs are
// never touched, and the last record is never removed.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

type DNSConfig struct {
	Enabled  bool     `json:"enabled"`
	Provider string   `json:"provider,omitempty"` // "cloudflare" | "webhook"
	Token    string   `json:"token,omitempty"`    // Cloudflare: API token with Zone.DNS edit; webhook: optional bearer secret
	URL      string   `json:"url,omitempty"`      // webhook: where the list of working hubs is POSTed
	Name     string   `json:"name,omitempty"`     // full record name, e.g. vpn.example.com
	TTL      int      `json:"ttl"`
	Records  []string `json:"records,omitempty"` // IPs the record had after the last write

	// Weight is this hub's share when the webhook receiver splits users between
	// hubs (1..100, relative to the other hubs' weights; 0 counts as 1). Each
	// hub reports its own in its heartbeat. Cloudflare DNS records have no weight.
	Weight int `json:"weight,omitempty"`

	// Master: this hub is the one that writes the record while it is reachable,
	// and its HubWeights set the other hubs' shares (hub id -> 1..100), so the
	// token and the percentages live on one panel. Another hub with DNS failover
	// on takes over only while the master is unreachable.
	Master     bool           `json:"master,omitempty"`
	HubWeights map[string]int `json:"hub_weights,omitempty"`

	// Route "tunnel": the calls to Cloudflare go out through the tunnel
	// TunnelID (picked from the list; the foreign server makes the call), for an
	// Iran server that cannot reach Cloudflare directly. TunnelPort is the local
	// SOCKS5 bridge port the panel derived, or a manual port saved by an older
	// version. "direct" (default): straight out.
	Route      string `json:"route,omitempty"`
	TunnelPort int    `json:"tunnel_port,omitempty"` // the local SOCKS5 port; set by the panel for a chosen tunnel
	TunnelID   *int   `json:"tunnel_id,omitempty"`

	// Version is when these settings were last saved on the hub that controls
	// them (Unix ms). The controller sends its settings to every linked hub
	// (cluster_dns_ctl.go); a hub that follows keeps ManagedBy (the
	// controller's id) and ManagedName, and its settings change only through
	// the controller.
	Version     int64  `json:"version,omitempty"`
	ManagedBy   string `json:"managed_by,omitempty"`
	ManagedName string `json:"managed_name,omitempty"`

	// Mode: "balance" (default; users are split by the shares) or "failover"
	// (the domain points to the first working hub of Order, hub ids; hubs the
	// order does not name come last). cluster_dns_pick.go.
	Mode  string   `json:"mode,omitempty"`
	Order []string `json:"order,omitempty"`
	// Owned are the hub addresses this cluster may have put in the record, also
	// of hubs unlinked since or whose address changed: the writer takes out the
	// ones that no longer belong there.
	Owned []string `json:"owned,omitempty"`
}

// dnsControllerID is the hub whose settings this hub uses: the controller it
// follows, itself when it controls, "" when it does neither.
func dnsControllerID(c ClusterConfig) string {
	switch {
	case c.DNS.ManagedBy != "":
		return c.DNS.ManagedBy
	case c.DNS.Master:
		return c.NodeID
	}
	return ""
}

// dnsClampTTL keeps a TTL Cloudflare and the failover can use: 60..3600 s.
func dnsClampTTL(t int) int { return min(max(t, 60), 3600) }

var (
	dnsMu      sync.Mutex
	dnsLastRun time.Time
	dnsLastErr string
	dnsLeader  bool
	dnsWant    []string
	dnsExtra   []string // addresses in the record that are no hub's
	dnsLastSig string   // what the webhook last got: working hubs and their weights
	dnsEvery   = 30 * time.Second
	// dnsRetryAfter: how soon a failed write is tried again.
	dnsRetryAfter = 10 * time.Second
	// dnsTakeoverAfter: how long the master must be silent before another hub
	// writes the record (a short break of the link between hubs is no reason
	// to change the record twice). Two hubs that cannot reach each other at
	// all both write: nothing on two hubs alone can tell that from a dead one.
	dnsTakeoverAfter = 20 * time.Second
	cfAPI            = "https://api.cloudflare.com/client/v4"
	cfClient         = &http.Client{Timeout: 15 * time.Second}
)

// dnsHubWeight is hub id's share: the master's own setting for it, else what
// the hub reports in its heartbeat.
func dnsHubWeight(c ClusterConfig, id string, reported int) int {
	if c.DNS.Master || c.DNS.ManagedBy != "" { // the controller's shares travel with its settings
		if w := c.DNS.HubWeights[id]; w > 0 {
			return dnsWeight(w)
		}
	}
	return dnsWeight(reported)
}

// dnsGroup is one working hub and the addresses it puts in the record.
type dnsGroup struct {
	Key    string // hub id
	IPs    []string
	Weight int
}

// dnsBeatIPs is what a hub with this heartbeat adds to the record: its IPv4
// address, and its IPv6 one only when it has no pools (the load balancer is
// IPv4 NAT, so an IPv6 user would reach no pooled port).
func dnsBeatIPs(b meshBeat, v4 string) []string {
	var ips []string
	if !b.Healthy {
		return ips
	}
	if isIPv4(v4) {
		ips = append(ips, v4)
	}
	if ipFamily(b.IP6) == 6 && len(b.Pools) == 0 {
		ips = append(ips, b.IP6)
	}
	return ips
}

// dnsKeepSilent: a hub in the record that stopped answering stays in it this
// long (its panel may only be restarting; its tunnels run on).
const dnsKeepSilent = 15 * time.Second

// dnsHealthyGroups lists the working hubs (this one included) and whether this
// hub leads the writes. A hub in the record whose panel has just started and
// does not know its own state yet stays in it.
func dnsHealthyGroups(c ClusterConfig) (groups []dnsGroup, leader bool) {
	inRecord := func(ip string) bool { return ip != "" && slices.Contains(c.DNS.Records, ip) }
	self := meshSelfBeat(c)
	if self.Starting && inRecord(self.IP) {
		self.Healthy = true
	}
	if ips := dnsBeatIPs(self, self.IP); len(ips) > 0 {
		groups = append(groups, dnsGroup{Key: c.NodeID, IPs: ips, Weight: dnsWeight(c.DNS.Weight)})
	}
	meshMu.Lock()
	for _, h := range c.Hubs {
		st := meshState[h.ID]
		if st == nil {
			continue
		}
		b, ip := st.Beat, hubIP4(h, st)
		if !st.Up && (!inRecord(ip) || time.Since(st.LastSeen) >= dnsKeepSilent) {
			continue
		}
		if b.Starting && inRecord(ip) {
			b.Healthy = true
		}
		if ips := dnsBeatIPs(b, ip); len(ips) > 0 {
			groups = append(groups, dnsGroup{Key: h.ID, IPs: ips, Weight: dnsHubWeight(c, h.ID, b.Weight)})
		}
	}
	meshMu.Unlock()
	return groups, dnsWriter(c) == c.NodeID
}

// dnsHealthyIPs is the set of hub IPs the record should hold, and whether
// this hub leads the writes.
func dnsHealthyIPs(c ClusterConfig) (ips []string, leader bool) {
	groups, leader := dnsHealthyGroups(c)
	return dnsIPs(groups), leader
}

// dnsUnequal: the working hubs do not all have the same weight.
func dnsUnequal(groups []dnsGroup) bool {
	for _, g := range groups {
		if g.Weight != groups[0].Weight {
			return true
		}
	}
	return false
}

// dnsRotT is the rotation behind weighted Cloudflare records (guarded by dnsMu).
var dnsRot struct {
	cur  map[string]int // smooth weighted round-robin credit per hub
	pick string         // the hub the record points to now
	at   time.Time      // when it started
	set  string         // the working hubs it was chosen from
}

// dnsRotate picks the one hub the record points to. Cloudflare's plain DNS
// has no weights, so the record points to one hub at a time and moves to the
// next every slot: over many slots each hub gets its share of the time, and so
// of the users who look the name up. The order is smooth weighted round-robin
// (70/30 gives A A B A A B A A B A), so shares even out fast. A change in the
// working hubs picks again at once.
func dnsRotate(groups []dnsGroup, slot time.Duration, now time.Time) []string {
	dnsMu.Lock()
	defer dnsMu.Unlock()
	byKey := map[string]dnsGroup{}
	keys := make([]string, 0, len(groups))
	for _, g := range groups {
		byKey[g.Key] = g
		keys = append(keys, g.Key)
	}
	sort.Strings(keys)
	set := strings.Join(keys, ",")
	if dnsRot.set == set && now.Sub(dnsRot.at) < slot {
		if g, ok := byKey[dnsRot.pick]; ok {
			return append([]string(nil), g.IPs...)
		}
	}
	if dnsRot.set != set || dnsRot.cur == nil {
		dnsRot.cur, dnsRot.set = map[string]int{}, set
	}
	sum, best := 0, ""
	for _, k := range keys {
		dnsRot.cur[k] += byKey[k].Weight
		sum += byKey[k].Weight
		if best == "" || dnsRot.cur[k] > dnsRot.cur[best] {
			best = k
		}
	}
	dnsRot.cur[best] -= sum
	dnsRot.pick, dnsRot.at = best, now
	return append([]string(nil), byKey[best].IPs...)
}

// dnsWeight clamps a hub weight to 1..100.
func dnsWeight(n int) int {
	return min(max(n, 1), 100)
}

// dnsIPWeights maps every known hub address (IPv4 and IPv6) to its hub's weight.
func dnsIPWeights(c ClusterConfig) map[string]int {
	w := map[string]int{}
	self := meshSelfBeat(c)
	sw := dnsWeight(c.DNS.Weight)
	if self.IP != "" {
		w[self.IP] = sw
	}
	if self.IP6 != "" {
		w[self.IP6] = sw
	}
	meshMu.Lock()
	for _, h := range c.Hubs {
		st := meshState[h.ID]
		if st == nil {
			continue
		}
		hw := dnsHubWeight(c, h.ID, st.Beat.Weight)
		if ip := hubIP4(h, st); ip != "" {
			w[ip] = hw
		}
		if st.Beat.IP6 != "" {
			w[st.Beat.IP6] = hw
		}
	}
	meshMu.Unlock()
	return w
}

// dnsSig is the webhook's state in one string, so a weight change sends again.
func dnsSig(ips []string, w map[string]int) string {
	parts := make([]string, 0, len(ips))
	for _, ip := range ips {
		parts = append(parts, fmt.Sprintf("%s=%d", ip, w[ip]))
	}
	return strings.Join(parts, ",")
}

// dnsTick reconciles the record when this hub leads and the set changed, or
// every dnsEvery.
func dnsTick(c ClusterConfig) {
	if !dnsReady(c.DNS) {
		dnsLeading.Store(false)
		return
	}
	now := time.Now()
	writer := dnsWriter(c)
	if writer != c.NodeID {
		c = dnsAdoptRecords(c, writer)
	}
	groups, leader := dnsHealthyGroups(c)
	dnsTrackWorking(groups, now)
	dnsLoadSample(c, groups, now)
	// want is what the record holds (cluster_dns_pick.go)
	want := dnsChoose(c, groups, now)
	hook := c.DNS.Provider == "webhook"
	var weights map[string]int
	sig := ""
	if hook {
		weights = dnsIPWeights(c)
		sig = dnsSig(want, weights)
	}
	shown := want
	if dnsMode(c.DNS) == dnsBalance {
		shown = dnsIPs(groups) // in a rotation the others wait for their turn
	}
	dnsMu.Lock()
	dnsLeader, dnsWant = leader, shown
	due := time.Since(dnsLastRun) >= dnsEvery || strings.Join(want, ",") != strings.Join(c.DNS.Records, ",") || (hook && sig != dnsLastSig)
	if dnsLastErr != "" && time.Since(dnsLastRun) < dnsRetryAfter {
		due = false // a failing provider is not called on every tick
	}
	if !leader {
		dnsLastErr = "" // what failed while this hub wrote is the writer's business now
	}
	dnsMu.Unlock()
	if !leader {
		dnsLeading.Store(false)
		dnsReachTick(c.DNS)
		return
	}
	if !due || len(want) == 0 || !dnsSettled(c) {
		return
	}
	var got, extra []string
	var err error
	if hook {
		dnsMu.Lock()
		dnsLastSig = sig
		dnsMu.Unlock()
		got, err = dnsWebhookW(c, want, weights, false)
	} else {
		hubIPs := dnsKnownIPs(c)
		for _, ip := range c.DNS.Owned {
			hubIPs[ip] = true
		}
		got, extra, err = cfSyncA(c.DNS, want, hubIPs)
	}
	dnsReachNote(c.DNS, err)
	dnsMu.Lock()
	dnsLastRun = time.Now()
	old := dnsLastErr
	dnsLastErr = ""
	if err != nil {
		dnsLastErr = err.Error()
	} else {
		dnsExtra = extra
	}
	dnsMu.Unlock()
	if err != nil {
		if old != err.Error() {
			clusterEventf("error", "DNS failover: %v", err)
		}
		return
	}
	if !dnsLeading.Swap(true) && !c.DNS.Master {
		clusterEventf("info", "DNS failover: this hub writes the domain now (%s).", c.DNS.Name)
	}
	// what the hubs' addresses are now: anything else was taken out
	owned := make([]string, 0, 8)
	for ip := range dnsKnownIPs(c) {
		owned = append(owned, ip)
	}
	sort.Strings(owned)
	moved := strings.Join(got, ",") != strings.Join(c.DNS.Records, ",")
	if moved {
		clusterEventf("info", "DNS failover: %s now points to %s.", c.DNS.Name, strings.Join(got, ", "))
	}
	if moved || !slices.Equal(owned, c.DNS.Owned) {
		_, _ = updateClusterConfig(func(x *ClusterConfig) error { x.DNS.Records, x.DNS.Owned = got, owned; return nil })
	}
}

// dnsSettled: this hub knows enough to write the record. Right after the panel
// starts its own health is not known yet (no snapshot) and a linked hub has
// not answered or missed enough beats to count as down: writing then would
// take working hubs out of the record.
func dnsSettled(c ClusterConfig) bool {
	if s := lbSnapshot(); s == nil || s.AgeMs() < 0 {
		return false
	}
	if self := meshSelfBeat(c); self.IP == "" && panelUptime() < time.Minute {
		return false // its own address is not found yet
	}
	meshMu.Lock()
	defer meshMu.Unlock()
	for _, h := range c.Hubs {
		st := meshState[h.ID]
		if st == nil || (!st.Up && st.Misses < meshFall) {
			return false
		}
	}
	return true
}

// dnsReady: DNS failover is on and has what its provider needs.
func dnsReady(d DNSConfig) bool {
	if !d.Enabled || d.Name == "" {
		return false
	}
	if d.Provider == "webhook" {
		return d.URL != ""
	}
	return d.Token != ""
}

// ---- webhook ----

// dnsWebhook POSTs {"name","ips","ips6","weights","ttl","hub","at"} to the configured
// URL (with "Authorization: Bearer <token>" when a token is set): ips are the
// IPv4 addresses (A), ips6 the IPv6 ones (AAAA), weights each address's hub
// weight (1..100) for a receiver that splits users by percentage. Any 2xx answer counts as
// done. test adds "test": true so the receiver can ignore it.
func dnsWebhook(c ClusterConfig, ips []string, test bool) ([]string, error) {
	return dnsWebhookW(c, ips, nil, test)
}

// dnsWebhookW is dnsWebhook with the hubs' weights (nil: none are sent).
func dnsWebhookW(c ClusterConfig, ips []string, weights map[string]int, test bool) ([]string, error) {
	v4, v6 := []string{}, []string{}
	for _, ip := range ips {
		if ipFamily(ip) == 6 {
			v6 = append(v6, ip)
		} else {
			v4 = append(v4, ip)
		}
	}
	body := map[string]any{"name": c.DNS.Name, "ips": v4, "ips6": v6, "ttl": c.DNS.TTL, "hub": c.NodeID,
		"at": time.Now().UTC().Format(time.RFC3339)}
	if weights != nil {
		wm := map[string]int{}
		for _, ip := range ips {
			wm[ip] = dnsWeight(weights[ip])
		}
		body["weights"] = wm
	}
	if test {
		body["test"] = true
	}
	b, _ := json.Marshal(body)
	req, err := http.NewRequest("POST", c.DNS.URL, bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("webhook URL: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "hashem-panel/"+panelVersion)
	if c.DNS.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.DNS.Token)
	}
	resp, err := cfClient.Do(req)
	if err != nil {
		return nil, reachErr{redactErr(fmt.Errorf("webhook unreachable: %v", err), c.DNS.Token)}
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("webhook answered HTTP %d", resp.StatusCode)
	}
	return ips, nil
}

// ---- Cloudflare ----

type cfResp struct {
	Success bool                       `json:"success"`
	Errors  []struct{ Message string } `json:"errors"`
	Result  json.RawMessage            `json:"result"`
}

// dnsRoute is how this hub reaches Cloudflare: "auto" (directly, and when that
// fails through this hub's tunnels), "direct_only", or "tunnel" (one chosen
// tunnel). "direct", what older versions saved by default, is "auto".
func dnsRoute(d DNSConfig) string {
	switch d.Route {
	case "tunnel", "direct_only":
		return d.Route
	}
	return "auto"
}

// cfRoutes are the ways to Cloudflare in the order to try; the one that worked
// last is tried first for an hour (tests replace it).
var cfRoutes = func(d DNSConfig) []tgRoute {
	direct := tgRoute{key: "direct", name: "directly", connect: tgDirectConnect,
		client: func(time.Duration) (*http.Client, error) { return cfClient, nil }}
	if dnsRoute(d) == "direct_only" {
		return []tgRoute{direct}
	}
	out := append([]tgRoute{direct}, tgAutoTunnels()...)
	cfGood.Lock()
	key, fresh := cfGood.key, time.Since(cfGood.at) < tgRouteKeep
	cfGood.Unlock()
	for i, r := range out {
		if fresh && r.key == key && i > 0 {
			copy(out[1:i+1], out[:i])
			out[0] = r
			break
		}
	}
	return out
}

// cfGood is the tunnel that reached Cloudflare when the direct way did not.
var cfGood struct {
	sync.Mutex
	key string
	at  time.Time
}

func cfGoodSet(key string, ok bool) {
	cfGood.Lock()
	defer cfGood.Unlock()
	switch {
	case !ok && cfGood.key == key:
		cfGood.key = ""
	case ok && (cfGood.key != key || time.Since(cfGood.at) >= tgRouteKeep):
		cfGood.key, cfGood.at = key, time.Now()
	}
}

// cfSend makes one API call with this client. connect > 0: given up when it is
// not connected by then (a blocked way must not hold the others up).
func cfSend(cl *http.Client, connect time.Duration, token, method, path string, body []byte) ([]byte, int, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if connect > 0 {
		slow := time.AfterFunc(connect, cancel)
		defer slow.Stop()
		ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{GotConn: func(httptrace.GotConnInfo) { slow.Stop() }})
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, cfAPI+path, rd)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := cl.Do(req)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			err = fmt.Errorf("no connection within %d seconds", int(connect/time.Second))
		}
		return nil, 0, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return data, resp.StatusCode, err
}

// cfAnswer reads an API answer. An answer that is not the API's (a block page,
// a gateway error) or that refuses this server's address says the way is bad,
// not the settings: reachErr.
func cfAnswer(data []byte, status int) (json.RawMessage, error) {
	var r cfResp
	if json.Unmarshal(data, &r) != nil {
		return nil, reachErr{fmt.Errorf("Cloudflare answered HTTP %d", status)}
	}
	if r.Success {
		return r.Result, nil
	}
	var msgs []string
	for _, e := range r.Errors {
		msgs = append(msgs, e.Message)
	}
	if len(msgs) == 0 {
		msgs = append(msgs, fmt.Sprintf("HTTP %d", status))
	}
	err := fmt.Errorf("Cloudflare: %s", strings.Join(msgs, "; "))
	if status >= 500 || strings.Contains(err.Error(), "from location") { // a token limited to some addresses
		return nil, reachErr{err}
	}
	return nil, err
}

func cfCall(d DNSConfig, method, path string, body any) (json.RawMessage, error) {
	token := d.Token
	var b []byte
	if body != nil {
		b, _ = json.Marshal(body)
	}
	if dnsRoute(d) == "tunnel" {
		return cfCallTunnel(d, method, path, b)
	}
	var whys []string
	for _, r := range cfRoutes(d) {
		cl, err := r.client(25 * time.Second)
		var res json.RawMessage
		if err == nil {
			var data []byte
			var status int
			data, status, err = cfSend(cl, r.connect, token, method, path, b)
			if err == nil {
				var re reachErr
				res, err = cfAnswer(data, status)
				if !errors.As(err, &re) {
					cfGoodSet(r.key, true)
					return res, err
				}
			}
		}
		cfGoodSet(r.key, false)
		why := redactErr(err, token).Error()
		if r.tunnel != nil {
			if w := routeWhy(r.tunnel); w != "" {
				why = w
			}
			why = "through " + r.name + ": " + why
		}
		whys = append(whys, why)
	}
	if len(whys) == 1 && strings.HasPrefix(whys[0], "Cloudflare") {
		return nil, reachErr{errors.New(whys[0])}
	}
	return nil, reachErr{errors.New("Cloudflare unreachable: " + tgCut(strings.Join(whys, "; "), 600))}
}

// cfCallTunnel is cfCall through the one chosen tunnel.
func cfCallTunnel(d DNSConfig, method, path string, body []byte) (json.RawMessage, error) {
	port, err := routePort(d.TunnelID, d.TunnelPort)
	if err == nil && d.TunnelID == nil { // an old manual port: say now if it is no SOCKS5 proxy
		err = tunnelProxyReady(port)
	}
	if err != nil {
		return nil, reachErr{fmt.Errorf("Cloudflare tunnel route: %v", err)}
	}
	data, status, err := cfSend(tunnelProxyClient(port, 25*time.Second), 0, d.Token, method, path, body)
	if err != nil {
		if d.TunnelID != nil {
			if why := routeWhy(d.TunnelID); why != "" {
				return nil, reachErr{fmt.Errorf("Cloudflare tunnel route: %s", why)}
			}
		}
		return nil, reachErr{redactErr(fmt.Errorf("Cloudflare unreachable through the tunnel: %v", err), d.Token)}
	}
	return cfAnswer(data, status)
}

// cfZone finds the zone that holds name by trying its parent domains.
func cfZone(d DNSConfig, name string) (string, error) {
	id, _, err := cfZoneFind(d, name)
	return id, err
}

// cfZoneFind is cfZone with the zone's name (blackoc.ir for vpn.blackoc.ir).
func cfZoneFind(d DNSConfig, name string) (id, zone string, err error) {
	parts := strings.Split(strings.TrimSuffix(name, "."), ".")
	for i := 0; i+2 <= len(parts); i++ {
		zone := strings.Join(parts[i:], ".")
		res, err := cfCall(d, "GET", "/zones?name="+url.QueryEscape(zone), nil)
		if err != nil {
			return "", "", err
		}
		var zs []struct{ ID string }
		if json.Unmarshal(res, &zs) == nil && len(zs) > 0 {
			return zs[0].ID, zone, nil
		}
	}
	return "", "", fmt.Errorf("no Cloudflare zone holds %s for this token: add the domain to this Cloudflare account, or give the token access to its zone", name)
}

type cfRecord struct {
	ID      string `json:"id"`
	Content string `json:"content"`
	Proxied bool   `json:"proxied"`
	TTL     int    `json:"ttl"`
}

// cfListA lists name's A and AAAA records.
func cfListA(d DNSConfig, zone, name string) ([]cfRecord, error) {
	var all []cfRecord
	for _, typ := range []string{"A", "AAAA"} {
		res, err := cfCall(d, "GET", "/zones/"+zone+"/dns_records?type="+typ+"&per_page=100&name="+url.QueryEscape(name), nil)
		if err != nil {
			return nil, err
		}
		var rs []cfRecord
		if err := json.Unmarshal(res, &rs); err != nil {
			return nil, err
		}
		all = append(all, rs...)
	}
	return all, nil
}

// cfSyncA makes name's A and AAAA records equal want. Records whose IP is not
// a hub's are left alone (extra lists them); got is the hub IPs the record
// holds afterwards.
func cfSyncA(d DNSConfig, want []string, hubIPs map[string]bool) (got, extra []string, err error) {
	zone, err := cfZone(d, d.Name)
	if err != nil {
		return nil, nil, err
	}
	have, err := cfListA(d, zone, d.Name)
	if err != nil {
		return nil, nil, err
	}
	wantSet := map[string]bool{}
	for _, ip := range want {
		wantSet[ip] = true
	}
	haveSet := map[string]bool{}
	for _, r := range have {
		haveSet[r.Content] = true
		if !hubIPs[r.Content] && !wantSet[r.Content] && !slices.Contains(extra, r.Content) {
			extra = append(extra, r.Content)
		}
		if r.Proxied {
			return nil, nil, fmt.Errorf("%s is proxied (orange cloud); tunnels need DNS only (grey cloud)", d.Name)
		}
	}
	ttl := d.TTL
	if ttl < 60 {
		ttl = 60
	}
	for _, ip := range want {
		if !haveSet[ip] {
			if _, err := cfCall(d, "POST", "/zones/"+zone+"/dns_records", map[string]any{
				"type": dnsRecordType(ip), "name": d.Name, "content": ip, "ttl": ttl, "proxied": false,
			}); err != nil {
				return nil, nil, err
			}
		}
	}
	for _, r := range have {
		// a TTL changed in the panel reaches the records already there
		if wantSet[r.Content] && hubIPs[r.Content] && r.TTL != ttl {
			if _, err := cfCall(d, "PATCH", "/zones/"+zone+"/dns_records/"+r.ID, map[string]any{"ttl": ttl}); err != nil {
				return nil, nil, err
			}
		}
		if hubIPs[r.Content] && !wantSet[r.Content] {
			if _, err := cfCall(d, "DELETE", "/zones/"+zone+"/dns_records/"+r.ID, nil); err != nil {
				return nil, nil, err
			}
		}
	}
	return want, extra, nil
}

// dnsRecordType is A for an IPv4 address, AAAA for an IPv6 one.
func dnsRecordType(ip string) string {
	if ipFamily(ip) == 6 {
		return "AAAA"
	}
	return "A"
}

// ---- API ----

type dnsViewT struct {
	Enabled  bool     `json:"enabled"`
	Provider string   `json:"provider"`
	URL      string   `json:"url,omitempty"`
	Name     string   `json:"name"`
	TTL      int      `json:"ttl"`
	HasToken bool     `json:"has_token"`
	Records  []string `json:"records"`
	Want     []string `json:"want"`
	Leader   bool     `json:"leader"`
	LastRun  string   `json:"last_run,omitempty"`
	Error    string   `json:"error,omitempty"`

	Weight  int         `json:"weight"`
	Shares  []dnsShare  `json:"shares"`
	Master  bool        `json:"master"`
	Members []dnsMember `json:"members"`

	Route      string         `json:"route"`
	TunnelID   *int           `json:"tunnel_id"`
	TunnelPort int            `json:"tunnel_port"` // an older version's manual port (no TunnelID)
	Tunnels    []tunnelChoice `json:"tunnels"`

	// Role: "controller" (its settings go to every hub), "follower" (it uses
	// ManagedName's), "solo" (on, from an older version, not sent to the
	// others) or "off".
	Role string `json:"role"`
	// Mode and Order: see DNSConfig (Order lists every hub). Writer is the hub
	// that writes the domain now. Extra are addresses in the record that belong
	// to no hub: users go there too. Balancing: the record is moved to bring the
	// measured shares to the wanted ones.
	Mode      string          `json:"mode"`
	Order     []string        `json:"order"`
	Writer    string          `json:"writer,omitempty"`
	Extra     []string        `json:"extra,omitempty"`
	Balancing bool            `json:"balancing,omitempty"`
	Stuck     map[string]bool `json:"stuck,omitempty"`

	ManagedName string `json:"managed_name,omitempty"`
	ManagedBy   string `json:"managed_by,omitempty"`
	SelfID      string `json:"self_id"`
}

// dnsMember is a hub of the cluster as the master's share table lists it.
type dnsMember struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	IP     string `json:"ip,omitempty"`
	Weight int    `json:"weight"`
	Self   bool   `json:"self,omitempty"`
	Up     bool   `json:"up"`
	// DNSOn: the hub keeps the same record (DNS failover on there, with this
	// name), so it takes over the writes when the writing hub goes down.
	DNSOn   bool `json:"dns_on"`
	Healthy bool `json:"healthy"` // its foreign servers work: it belongs in the record

	// On the controller: how the hub takes this hub's settings.
	Follows  bool   `json:"follows,omitempty"`    // its beat shows this hub's settings, latest version
	FollowEr string `json:"follow_err,omitempty"` // why it did not take them
	Old      bool   `json:"old,omitempty"`        // its panel needs an update first
	ReachErr string `json:"reach_err,omitempty"`  // it cannot reach the provider with its own route
	// NoReach: its heartbeat says it cannot reach the provider now.
	NoReach bool `json:"no_reach,omitempty"`
	// MissingPorts: ports this hub serves and that hub does not: users sent
	// there on them would fail (Sync Tunnels fixes it).
	MissingPorts []int  `json:"missing_ports,omitempty"`
	Version      string `json:"version,omitempty"`
}

// dnsMembers lists this hub and every linked hub with the share the master
// has for it (a hub that is down keeps its last known share).
func dnsMembers(c ClusterConfig) []dnsMember {
	self := meshSelfBeat(c)
	out := []dnsMember{{ID: c.NodeID, Name: c.Name, IP: self.IP, Weight: dnsWeight(c.DNS.Weight), Self: true, Up: true,
		DNSOn: dnsReady(c.DNS), Healthy: self.Healthy}}
	meshMu.Lock()
	defer meshMu.Unlock()
	for _, h := range c.Hubs {
		m := dnsMember{ID: h.ID, Name: h.Name, IP: hubIP4(h, meshState[h.ID]), Weight: dnsHubWeight(c, h.ID, 0)}
		if st := meshState[h.ID]; st != nil {
			m.Up = st.Up
			m.Weight = dnsHubWeight(c, h.ID, st.Beat.Weight)
			m.NoReach = st.Up && st.Beat.DNSDown
			m.DNSOn = st.Up && c.DNS.Name != "" && st.Beat.DNS == c.DNS.Name
			m.Healthy = st.Up && st.Beat.Healthy
			m.Follows = st.Up && st.Beat.DNSBy == c.NodeID && st.Beat.DNSVer == c.DNS.Version && dnsIsController(c)
			m.Version = st.Beat.Version
		}
		out = append(out, m)
	}
	return out
}

// dnsMembersFollow adds, on the controller, how each hub took its settings and
// the ports it lacks. Called without meshMu held.
func dnsMembersFollow(c ClusterConfig, ms []dnsMember) {
	missing := dnsPortsFor(c)
	dnsFollowMu.Lock()
	defer dnsFollowMu.Unlock()
	for i := range ms {
		m := &ms[i]
		if m.Self {
			continue
		}
		m.MissingPorts = missing[m.ID]
		if !dnsIsController(c) {
			continue
		}
		if f := dnsFollow[m.ID]; f != nil && f.Ver == c.DNS.Version {
			if !m.Follows {
				m.FollowEr, m.Old = f.Err, f.Old
			}
			if f.OK || m.Follows {
				m.ReachErr = f.ReachErr
			}
		}
	}
}

// dnsShare is one working hub and the share of users its weight gives it.
type dnsShare struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	IP      string `json:"ip"`
	Weight  int    `json:"weight"`
	Percent int    `json:"percent"`
	// Actual is the share of the traffic the hub really carries (the last few
	// minutes), nil while it is not measured.
	Actual *float64 `json:"actual,omitempty"`
	Self   bool     `json:"self,omitempty"`
}

// dnsShares lists the working hubs (this one included) with their percentages.
func dnsShares(c ClusterConfig) []dnsShare {
	self := meshSelfBeat(c)
	var out []dnsShare
	if self.Healthy && isIPv4(self.IP) {
		out = append(out, dnsShare{ID: c.NodeID, Name: c.Name, IP: self.IP, Weight: dnsWeight(c.DNS.Weight), Self: true})
	}
	meshMu.Lock()
	for _, h := range c.Hubs {
		if st := meshState[h.ID]; st != nil && st.Up && st.Beat.Healthy && isIPv4(hubIP4(h, st)) {
			out = append(out, dnsShare{ID: h.ID, Name: h.Name, IP: hubIP4(h, st), Weight: dnsHubWeight(c, h.ID, st.Beat.Weight)})
		}
	}
	meshMu.Unlock()
	sum := 0
	for _, s := range out {
		sum += s.Weight
	}
	keys := make([]string, 0, len(out))
	for _, s := range out {
		keys = append(keys, s.ID)
	}
	actual, ok := dnsActual(keys, time.Now())
	for i := range out {
		if ok {
			v := math.Round(1000*actual[out[i].ID]) / 10
			out[i].Actual = &v
		}
		out[i].Percent = int(math.Round(100 * float64(out[i].Weight) / float64(sum)))
	}
	return out
}

func dnsView(c ClusterConfig) dnsViewT {
	// all of these read other state (the mesh, the snapshot): built before dnsMu is held
	shares, members, tunnels := dnsShares(c), dnsMembers(c), tunnelChoices()
	dnsMembersFollow(c, members)
	role := "off"
	switch {
	case c.DNS.ManagedBy != "":
		role = "follower"
	case c.DNS.Enabled && c.DNS.Master:
		role = "controller"
	case c.DNS.Enabled:
		role = "solo"
	}
	writer := ""
	if dnsReady(c.DNS) {
		writer = dnsWriter(c)
	}
	dnsBal.Lock()
	balancing := dnsBal.active && dnsMode(c.DNS) == dnsBalance && c.DNS.Provider != "webhook"
	dnsBal.Unlock()
	stuck := dnsStuckIDs(time.Now())
	reachWhy := ""
	if dnsReachDown(c.DNS) {
		dnsReach.Lock()
		reachWhy = dnsReach.err
		dnsReach.Unlock()
	}
	dnsMu.Lock()
	defer dnsMu.Unlock()
	v := dnsViewT{Mode: dnsMode(c.DNS), Order: dnsOrdered(c), Writer: writer, Balancing: balancing, Stuck: stuck,
		Enabled: c.DNS.Enabled, Provider: c.DNS.Provider, URL: c.DNS.URL, Name: c.DNS.Name, TTL: c.DNS.TTL,
		HasToken: c.DNS.Token != "", Records: c.DNS.Records, Want: dnsWant, Leader: dnsLeader, Error: dnsLastErr, Weight: dnsWeight(c.DNS.Weight), Shares: shares, Master: c.DNS.Master, Members: members,
		Route: dnsRoute(c.DNS), TunnelID: c.DNS.TunnelID, TunnelPort: c.DNS.TunnelPort, Tunnels: tunnels,
		Role: role, ManagedName: dnsManagedLabel(c), ManagedBy: c.DNS.ManagedBy, SelfID: c.NodeID}
	if role != "follower" {
		v.ManagedName = ""
	}
	if v.Leader {
		v.Extra = dnsExtra
	}
	for i := range v.Members {
		if v.Members[i].Self && reachWhy != "" {
			v.Members[i].ReachErr = reachWhy
		}
	}
	if !dnsLastRun.IsZero() {
		v.LastRun = dnsLastRun.Format("2006-01-02 15:04:05")
	}
	return v
}

func validDNSName(n string) bool {
	if len(n) < 3 || len(n) > 253 || !strings.Contains(n, ".") {
		return false
	}
	for _, l := range strings.Split(n, ".") {
		if l == "" || len(l) > 63 || strings.HasPrefix(l, "-") || strings.HasSuffix(l, "-") {
			return false
		}
		for _, ch := range l {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
				return false
			}
		}
	}
	return true
}

// handleClusterDNS saves the DNS failover settings; "test": true checks the
// token and the zone without writing anything.
//
// Turning it on makes this hub the controller: its settings (and every hub's
// share) go to every linked hub, which then follows them (cluster_dns_ctl.go).
// A hub that follows changes nothing here but "take_over": true, which makes
// it the controller instead.
func handleClusterDNS(w http.ResponseWriter, r *http.Request) {
	if proRequired(w, r, "cluster", "Cluster") {
		return
	}
	var req struct {
		Enabled    *bool          `json:"enabled"`
		Provider   *string        `json:"provider"`
		Token      *string        `json:"token"`
		URL        *string        `json:"url"`
		Name       *string        `json:"name"`
		TTL        int            `json:"ttl"`
		Weight     int            `json:"weight"`
		Route      *string        `json:"route"`
		TunnelPort int            `json:"tunnel_port"`
		TunnelID   *int           `json:"tunnel_id"`
		Master     *bool          `json:"master"` // older pages; turning it on makes the controller anyway
		HubWeights map[string]int `json:"hub_weights"`
		Test       bool           `json:"test"`
		TakeOver   bool           `json:"take_over"`
		Mode       *string        `json:"mode"`
		Order      []string       `json:"order"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<13)).Decode(&req) != nil {
		writeAPIError(w, r, "E-CLUSTER-01", "")
		return
	}
	c := loadClusterConfig()
	d := c.DNS
	following := d.ManagedBy != ""
	if following && !req.Test && !req.TakeOver {
		// only the route to the provider is this hub's own
		if req.Enabled != nil || req.Provider != nil || req.Token != nil || req.URL != nil || req.Name != nil || req.TTL > 0 || req.Weight > 0 || req.HubWeights != nil || req.Mode != nil || req.Order != nil {
			writeAPIError(w, r, "E-CLUSTER-02", "this hub follows the DNS failover settings of "+dnsManagedLabel(c)+": change them there, or take over here")
			return
		}
	}
	if req.TakeOver {
		d.ManagedBy, d.ManagedName = "", ""
		on := true
		req.Enabled = &on
	}
	if req.Token != nil && strings.TrimSpace(*req.Token) != "" {
		d.Token = strings.TrimSpace(*req.Token)
	}
	if req.Name != nil {
		d.Name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(*req.Name), "."))
	}
	if req.TTL > 0 {
		d.TTL = dnsClampTTL(req.TTL)
	}
	if d.TTL == 0 {
		d.TTL = 60
	}
	if req.Weight > 0 {
		d.Weight = dnsWeight(req.Weight)
	}
	if req.Route != nil {
		if !slices.Contains([]string{"auto", "direct", "direct_only", "tunnel"}, *req.Route) {
			writeAPIError(w, r, "E-CLUSTER-02", "the route to Cloudflare is auto, direct_only or tunnel")
			return
		}
		d.Route = *req.Route
	}
	if req.TunnelID != nil {
		port, err := bridgeEnsure(*req.TunnelID)
		if err != nil {
			writeAPIError(w, r, "E-CLUSTER-02", err.Error())
			return
		}
		d.TunnelID, d.TunnelPort = req.TunnelID, port
	} else if req.TunnelPort != 0 {
		if req.TunnelPort < 1 || req.TunnelPort > 65535 {
			writeAPIError(w, r, "E-CLUSTER-02", "the tunnel proxy port is a number from 1 to 65535")
			return
		}
		d.TunnelID, d.TunnelPort = nil, req.TunnelPort // an old manual port
	}
	if d.Route == "tunnel" && d.TunnelID == nil && d.TunnelPort == 0 && d.Provider != "webhook" {
		writeAPIError(w, r, "E-CLUSTER-02", "choose a tunnel, or choose Automatic")
		return
	}
	if req.HubWeights != nil && !following {
		known := map[string]bool{}
		for _, h := range c.Hubs {
			known[h.ID] = true
		}
		d.HubWeights = map[string]int{}
		for id, share := range req.HubWeights {
			if id == c.NodeID {
				if share < 1 || share > 100 {
					writeAPIError(w, r, "E-CLUSTER-02", "a share is a number from 1 to 100")
					return
				}
				d.Weight = share
				continue
			}
			if !known[id] {
				continue // not a hub of this cluster
			}
			if share < 1 || share > 100 {
				writeAPIError(w, r, "E-CLUSTER-02", "a share is a number from 1 to 100")
				return
			}
			d.HubWeights[id] = share
		}
	}
	if req.Mode != nil && !following {
		if *req.Mode != dnsBalance && *req.Mode != dnsFailover {
			writeAPIError(w, r, "E-CLUSTER-02", "the mode is balance or failover")
			return
		}
		d.Mode = *req.Mode
	}
	if req.Order != nil && !following {
		known := dnsOrdered(c)
		d.Order = nil
		for _, id := range req.Order {
			if slices.Contains(known, id) && !slices.Contains(d.Order, id) {
				d.Order = append(d.Order, id)
			}
		}
	}
	if req.Enabled != nil {
		d.Enabled = *req.Enabled
	}
	if req.Provider != nil && !following {
		if *req.Provider != d.Provider {
			d.Token = "" // a secret is never carried to another provider
			if req.Token != nil {
				d.Token = strings.TrimSpace(*req.Token)
			}
		}
		d.Provider = *req.Provider
	}
	if req.URL != nil && !following {
		d.URL = strings.TrimSpace(*req.URL)
	}
	if d.Provider != "webhook" {
		d.Provider = "cloudflare"
	}
	if (d.Enabled || req.Test) && !validDNSName(d.Name) {
		writeAPIError(w, r, "E-CLUSTER-02", "the domain must be a full name such as vpn.example.com")
		return
	}
	if d.Provider == "webhook" {
		if (d.Enabled || req.Test) && (d.URL == "" || !validWebhookURL(d.URL)) {
			writeAPIError(w, r, "E-CLUSTER-02", "the webhook needs an http(s) URL")
			return
		}
	} else if (d.Enabled || req.Test) && d.Token == "" {
		writeAPIError(w, r, "E-CLUSTER-02", "a Cloudflare API token is needed (template Edit zone DNS)")
		return
	}
	if req.Test && d.Provider == "webhook" {
		c.DNS = d
		ips, _ := dnsHealthyIPs(c)
		if _, err := dnsWebhookW(c, ips, dnsIPWeights(c), true); err != nil {
			writeAPIError(w, r, "E-CLUSTER-10", err.Error())
			return
		}
		writeJSON(w, map[string]any{"status": "ok", "records": ips})
		return
	}
	if req.Test {
		zone, zoneName, err := cfZoneFind(d, d.Name)
		if err != nil {
			writeAPIError(w, r, "E-CLUSTER-10", err.Error())
			return
		}
		recs, err := cfListA(d, zone, d.Name)
		if err != nil {
			writeAPIError(w, r, "E-CLUSTER-10", err.Error())
			return
		}
		ips, proxied := []string{}, false
		for _, x := range recs {
			ips = append(ips, x.Content)
			proxied = proxied || x.Proxied
		}
		writeJSON(w, map[string]any{"status": "ok", "zone": zoneName, "records": ips, "proxied": proxied})
		return
	}
	if !following || req.TakeOver {
		// This hub controls its settings: on, it is the controller and every
		// linked hub follows; off, the hubs that followed it stop too.
		d.Master = d.Enabled
		d.Version = time.Now().UnixMilli()
		if d.Version <= c.DNS.Version {
			d.Version = c.DNS.Version + 1
		}
	}
	if _, err := updateClusterConfig(func(x *ClusterConfig) error {
		d.Records, d.Owned = x.DNS.Records, x.DNS.Owned // the loop may have written them meanwhile
		x.DNS = d
		return nil
	}); err != nil {
		writeAPIError(w, r, "E-CLUSTER-06", err.Error())
		return
	}
	dnsMu.Lock()
	dnsLastRun = time.Time{}
	dnsMu.Unlock()
	if req.TakeOver {
		clusterEventf("info", "DNS failover: this hub took over the settings; the other hubs follow it now.")
	}
	dnsWake()
	writeJSON(w, map[string]any{"status": "ok"})
}
