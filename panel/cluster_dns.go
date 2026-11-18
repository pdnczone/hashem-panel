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
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
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
	dnsLastSig string // what the webhook last got: working hubs and their weights
	dnsEvery   = 30 * time.Second
	// dnsTakeoverAfter: how long the master must be silent before another hub
	// writes the record (a short break of the link between hubs is no reason
	// to change the record twice). Two hubs that cannot reach each other at
	// all both write: nothing on two hubs alone can tell that from a dead one.
	dnsTakeoverAfter = 30 * time.Second
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

// dnsHealthyGroups lists the working hubs (this one included) and whether this
// hub leads the writes.
func dnsHealthyGroups(c ClusterConfig) (groups []dnsGroup, leader bool) {
	self := meshSelfBeat(c)
	if ips := dnsBeatIPs(self, self.IP); len(ips) > 0 {
		groups = append(groups, dnsGroup{Key: c.NodeID, IPs: ips, Weight: dnsWeight(c.DNS.Weight)})
	}
	leader = true
	meshMu.Lock()
	for _, h := range c.Hubs {
		st := meshState[h.ID]
		if st == nil {
			continue
		}
		if !st.Up {
			// A master that stopped answering a moment ago may be back at once:
			// the others wait dnsTakeoverAfter before they write in its place.
			if st.Beat.Master && st.Beat.DNS == c.DNS.Name && !c.DNS.Master && time.Since(st.LastSeen) < dnsTakeoverAfter {
				leader = false
			}
			continue
		}
		if st.Beat.DNS == c.DNS.Name {
			switch {
			case st.Beat.Master && !c.DNS.Master:
				leader = false // a master that answers writes, whatever the ids
			case !st.Beat.Master && c.DNS.Master:
				// I am the master; they do not outrank me
			case st.Beat.ID < c.NodeID:
				leader = false // same kind: the lowest id writes
			}
		}
		if ips := dnsBeatIPs(st.Beat, h.PublicIP); len(ips) > 0 {
			groups = append(groups, dnsGroup{Key: h.ID, IPs: ips, Weight: dnsHubWeight(c, h.ID, st.Beat.Weight)})
		}
	}
	meshMu.Unlock()
	return groups, leader
}

// dnsHealthyIPs is the set of hub IPs the record should hold, and whether
// this hub leads the writes.
func dnsHealthyIPs(c ClusterConfig) (ips []string, leader bool) {
	groups, leader := dnsHealthyGroups(c)
	for _, g := range groups {
		ips = append(ips, g.IPs...)
	}
	sort.Strings(ips)
	return ips, leader
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
		if h.PublicIP != "" {
			w[h.PublicIP] = hw
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
		return
	}
	groups, leader := dnsHealthyGroups(c)
	var ips []string
	for _, g := range groups {
		ips = append(ips, g.IPs...)
	}
	sort.Strings(ips)
	hook := c.DNS.Provider == "webhook"
	// want is what the record holds: every working hub, or with Cloudflare and
	// different shares only the hub whose turn it is
	want := ips
	if !hook && leader && dnsUnequal(groups) {
		want = dnsRotate(groups, time.Duration(max(c.DNS.TTL, 60))*time.Second, time.Now())
		sort.Strings(want)
	}
	var weights map[string]int
	sig := ""
	if hook {
		weights = dnsIPWeights(c)
		sig = dnsSig(ips, weights)
	}
	dnsMu.Lock()
	dnsLeader, dnsWant = leader, ips
	due := time.Since(dnsLastRun) >= dnsEvery || strings.Join(want, ",") != strings.Join(c.DNS.Records, ",") || (hook && sig != dnsLastSig)
	dnsMu.Unlock()
	if !leader || !due || len(want) == 0 || !dnsSettled(c) {
		return
	}
	hubIPs := map[string]bool{}
	if self := meshSelfBeat(c); self.IP != "" {
		hubIPs[self.IP] = true
		if self.IP6 != "" {
			hubIPs[self.IP6] = true
		}
	}
	meshMu.Lock()
	for _, h := range c.Hubs {
		hubIPs[h.PublicIP] = true
		if st := meshState[h.ID]; st != nil && st.Beat.IP6 != "" {
			hubIPs[st.Beat.IP6] = true
		}
	}
	meshMu.Unlock()
	var got []string
	var err error
	if hook {
		dnsMu.Lock()
		dnsLastSig = sig // a failing receiver is retried every dnsEvery, not every tick
		dnsMu.Unlock()
		got, err = dnsWebhookW(c, ips, weights, false)
	} else {
		got, err = cfSyncA(c.DNS, want, hubIPs)
	}
	dnsMu.Lock()
	dnsLastRun = time.Now()
	old := dnsLastErr
	dnsLastErr = ""
	if err != nil {
		dnsLastErr = err.Error()
	}
	dnsMu.Unlock()
	if err != nil {
		if old != err.Error() {
			clusterEventf("error", "DNS failover: %v", err)
		}
		return
	}
	if strings.Join(got, ",") != strings.Join(c.DNS.Records, ",") {
		clusterEventf("info", "DNS failover: %s now points to %s.", c.DNS.Name, strings.Join(got, ", "))
		_, _ = updateClusterConfig(func(x *ClusterConfig) error { x.DNS.Records = got; return nil })
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
		return nil, redactErr(fmt.Errorf("webhook unreachable: %v", err), c.DNS.Token)
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

func dnsRoute(d DNSConfig) string {
	if d.Route == "tunnel" {
		return "tunnel"
	}
	return "direct"
}

// dnsClient is the HTTP client for Cloudflare: direct, or through the tunnel's
// SOCKS5 proxy ("socks5h": the name is resolved on the foreign side too).
func dnsClient(d DNSConfig) *http.Client {
	if d.Route == "tunnel" {
		if port, err := routePort(d.TunnelID, d.TunnelPort); err == nil {
			return tunnelProxyClient(port, 25*time.Second)
		}
	}
	return cfClient
}

func cfCall(d DNSConfig, method, path string, body any) (json.RawMessage, error) {
	token := d.Token
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, cfAPI+path, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	viaTunnel := d.Route == "tunnel"
	if viaTunnel {
		port, err := routePort(d.TunnelID, d.TunnelPort)
		if err != nil {
			return nil, fmt.Errorf("Cloudflare tunnel route: %v", err)
		}
		if d.TunnelID == nil { // an old manual port: say now if it is no SOCKS5 proxy
			if err := tunnelProxyReady(port); err != nil {
				return nil, fmt.Errorf("Cloudflare tunnel route: %v", err)
			}
		}
	}
	resp, err := dnsClient(d).Do(req)
	if err != nil {
		if viaTunnel {
			if d.TunnelID != nil {
				if why := routeWhy(d.TunnelID); why != "" {
					return nil, fmt.Errorf("Cloudflare tunnel route: %s", why)
				}
			}
			return nil, redactErr(fmt.Errorf("Cloudflare unreachable through the tunnel: %v", err), token)
		}
		return nil, redactErr(fmt.Errorf("Cloudflare unreachable: %v", err), token)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var r cfResp
	if json.Unmarshal(data, &r) != nil {
		return nil, fmt.Errorf("Cloudflare answered HTTP %d", resp.StatusCode)
	}
	if !r.Success {
		var msgs []string
		for _, e := range r.Errors {
			msgs = append(msgs, e.Message)
		}
		if len(msgs) == 0 {
			msgs = append(msgs, fmt.Sprintf("HTTP %d", resp.StatusCode))
		}
		return nil, fmt.Errorf("Cloudflare: %s", strings.Join(msgs, "; "))
	}
	return r.Result, nil
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
// a hub's are left alone; the result is the hub IPs the record holds afterwards.
func cfSyncA(d DNSConfig, want []string, hubIPs map[string]bool) ([]string, error) {
	zone, err := cfZone(d, d.Name)
	if err != nil {
		return nil, err
	}
	have, err := cfListA(d, zone, d.Name)
	if err != nil {
		return nil, err
	}
	wantSet := map[string]bool{}
	for _, ip := range want {
		wantSet[ip] = true
	}
	haveSet := map[string]bool{}
	for _, r := range have {
		haveSet[r.Content] = true
		if r.Proxied {
			return nil, fmt.Errorf("%s is proxied (orange cloud); tunnels need DNS only (grey cloud)", d.Name)
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
				return nil, err
			}
		}
	}
	for _, r := range have {
		// a TTL changed in the panel reaches the records already there
		if wantSet[r.Content] && hubIPs[r.Content] && r.TTL != ttl {
			if _, err := cfCall(d, "PATCH", "/zones/"+zone+"/dns_records/"+r.ID, map[string]any{"ttl": ttl}); err != nil {
				return nil, err
			}
		}
		if hubIPs[r.Content] && !wantSet[r.Content] {
			if _, err := cfCall(d, "DELETE", "/zones/"+zone+"/dns_records/"+r.ID, nil); err != nil {
				return nil, err
			}
		}
	}
	return want, nil
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
	Role        string `json:"role"`
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
		m := dnsMember{ID: h.ID, Name: h.Name, IP: h.PublicIP, Weight: dnsHubWeight(c, h.ID, 0)}
		if st := meshState[h.ID]; st != nil {
			m.Up = st.Up
			m.Weight = dnsHubWeight(c, h.ID, st.Beat.Weight)
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
	Name    string `json:"name"`
	IP      string `json:"ip"`
	Weight  int    `json:"weight"`
	Percent int    `json:"percent"`
	Self    bool   `json:"self,omitempty"`
}

// dnsShares lists the working hubs (this one included) with their percentages.
func dnsShares(c ClusterConfig) []dnsShare {
	self := meshSelfBeat(c)
	var out []dnsShare
	if self.Healthy && isIPv4(self.IP) {
		out = append(out, dnsShare{Name: c.Name, IP: self.IP, Weight: dnsWeight(c.DNS.Weight), Self: true})
	}
	meshMu.Lock()
	for _, h := range c.Hubs {
		if st := meshState[h.ID]; st != nil && st.Up && st.Beat.Healthy && isIPv4(h.PublicIP) {
			out = append(out, dnsShare{Name: h.Name, IP: h.PublicIP, Weight: dnsHubWeight(c, h.ID, st.Beat.Weight)})
		}
	}
	meshMu.Unlock()
	sum := 0
	for _, s := range out {
		sum += s.Weight
	}
	for i := range out {
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
	dnsMu.Lock()
	defer dnsMu.Unlock()
	v := dnsViewT{Enabled: c.DNS.Enabled, Provider: c.DNS.Provider, URL: c.DNS.URL, Name: c.DNS.Name, TTL: c.DNS.TTL,
		HasToken: c.DNS.Token != "", Records: c.DNS.Records, Want: dnsWant, Leader: dnsLeader, Error: dnsLastErr, Weight: dnsWeight(c.DNS.Weight), Shares: shares, Master: c.DNS.Master, Members: members,
		Route: dnsRoute(c.DNS), TunnelID: c.DNS.TunnelID, TunnelPort: c.DNS.TunnelPort, Tunnels: tunnels,
		Role: role, ManagedName: dnsManagedLabel(c), ManagedBy: c.DNS.ManagedBy, SelfID: c.NodeID}
	if role != "follower" {
		v.ManagedName = ""
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
		if req.Enabled != nil || req.Provider != nil || req.Token != nil || req.URL != nil || req.Name != nil || req.TTL > 0 || req.Weight > 0 || req.HubWeights != nil {
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
		if *req.Route != "direct" && *req.Route != "tunnel" {
			writeAPIError(w, r, "E-CLUSTER-02", "the route to Cloudflare is direct or tunnel")
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
		writeAPIError(w, r, "E-CLUSTER-02", "choose a tunnel, or choose Direct")
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
	if _, err := updateClusterConfig(func(x *ClusterConfig) error { x.DNS = d; return nil }); err != nil {
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
