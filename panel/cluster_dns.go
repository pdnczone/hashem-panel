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
}

var (
	dnsMu      sync.Mutex
	dnsLastRun time.Time
	dnsLastErr string
	dnsLeader  bool
	dnsWant    []string
	dnsEvery   = 30 * time.Second
	cfAPI      = "https://api.cloudflare.com/client/v4"
	cfClient   = &http.Client{Timeout: 15 * time.Second}
)

// dnsHealthyIPs is the set of hub IPs the record should hold, and whether
// this hub leads the writes.
func dnsHealthyIPs(c ClusterConfig) (ips []string, leader bool) {
	self := meshSelfBeat(c)
	if self.Healthy && isIPv4(self.IP) {
		ips = append(ips, self.IP)
	}
	// AAAA only for a hub without pools: the load balancer is IPv4 NAT, so an
	// IPv6 user would reach no pooled port
	if self.Healthy && ipFamily(self.IP6) == 6 && len(self.Pools) == 0 {
		ips = append(ips, self.IP6)
	}
	leader = true
	meshMu.Lock()
	for _, h := range c.Hubs {
		st := meshState[h.ID]
		if st == nil || !st.Up {
			continue
		}
		if st.Beat.DNS == c.DNS.Name && st.Beat.ID < c.NodeID {
			leader = false
		}
		if st.Beat.Healthy && isIPv4(h.PublicIP) {
			ips = append(ips, h.PublicIP)
		}
		if st.Beat.Healthy && ipFamily(st.Beat.IP6) == 6 && len(st.Beat.Pools) == 0 {
			ips = append(ips, st.Beat.IP6)
		}
	}
	meshMu.Unlock()
	sort.Strings(ips)
	return ips, leader
}

// dnsTick reconciles the record when this hub leads and the set changed, or
// every dnsEvery.
func dnsTick(c ClusterConfig) {
	if !dnsReady(c.DNS) {
		return
	}
	ips, leader := dnsHealthyIPs(c)
	dnsMu.Lock()
	dnsLeader, dnsWant = leader, ips
	due := time.Since(dnsLastRun) >= dnsEvery || strings.Join(ips, ",") != strings.Join(c.DNS.Records, ",")
	dnsMu.Unlock()
	if !leader || !due || len(ips) == 0 {
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
	if c.DNS.Provider == "webhook" {
		got, err = dnsWebhook(c, ips, false)
	} else {
		got, err = cfSyncA(c.DNS, ips, hubIPs)
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

// dnsWebhook POSTs {"name","ips","ips6","ttl","hub","at"} to the configured
// URL (with "Authorization: Bearer <token>" when a token is set): ips are the
// IPv4 addresses (A), ips6 the IPv6 ones (AAAA). Any 2xx answer counts as
// done. test adds "test": true so the receiver can ignore it.
func dnsWebhook(c ClusterConfig, ips []string, test bool) ([]string, error) {
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

func cfCall(token, method, path string, body any) (json.RawMessage, error) {
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
	resp, err := cfClient.Do(req)
	if err != nil {
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
func cfZone(token, name string) (string, error) {
	parts := strings.Split(strings.TrimSuffix(name, "."), ".")
	for i := 0; i+2 <= len(parts); i++ {
		zone := strings.Join(parts[i:], ".")
		res, err := cfCall(token, "GET", "/zones?name="+url.QueryEscape(zone), nil)
		if err != nil {
			return "", err
		}
		var zs []struct{ ID string }
		if json.Unmarshal(res, &zs) == nil && len(zs) > 0 {
			return zs[0].ID, nil
		}
	}
	return "", fmt.Errorf("no Cloudflare zone holds %s for this token", name)
}

type cfRecord struct {
	ID      string `json:"id"`
	Content string `json:"content"`
	Proxied bool   `json:"proxied"`
}

// cfListA lists name's A and AAAA records.
func cfListA(token, zone, name string) ([]cfRecord, error) {
	var all []cfRecord
	for _, typ := range []string{"A", "AAAA"} {
		res, err := cfCall(token, "GET", "/zones/"+zone+"/dns_records?type="+typ+"&per_page=100&name="+url.QueryEscape(name), nil)
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
	zone, err := cfZone(d.Token, d.Name)
	if err != nil {
		return nil, err
	}
	have, err := cfListA(d.Token, zone, d.Name)
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
			if _, err := cfCall(d.Token, "POST", "/zones/"+zone+"/dns_records", map[string]any{
				"type": dnsRecordType(ip), "name": d.Name, "content": ip, "ttl": ttl, "proxied": false,
			}); err != nil {
				return nil, err
			}
		}
	}
	for _, r := range have {
		if hubIPs[r.Content] && !wantSet[r.Content] {
			if _, err := cfCall(d.Token, "DELETE", "/zones/"+zone+"/dns_records/"+r.ID, nil); err != nil {
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
}

func dnsView(c ClusterConfig) dnsViewT {
	dnsMu.Lock()
	defer dnsMu.Unlock()
	v := dnsViewT{Enabled: c.DNS.Enabled, Provider: c.DNS.Provider, URL: c.DNS.URL, Name: c.DNS.Name, TTL: c.DNS.TTL,
		HasToken: c.DNS.Token != "", Records: c.DNS.Records, Want: dnsWant, Leader: dnsLeader, Error: dnsLastErr}
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
func handleClusterDNS(w http.ResponseWriter, r *http.Request) {
	if proRequired(w, r, "cluster", "Cluster") {
		return
	}
	var req struct {
		Enabled  *bool   `json:"enabled"`
		Provider *string `json:"provider"`
		Token    *string `json:"token"`
		URL      *string `json:"url"`
		Name     *string `json:"name"`
		TTL      int     `json:"ttl"`
		Test     bool    `json:"test"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<13)).Decode(&req) != nil {
		writeAPIError(w, r, "E-CLUSTER-01", "")
		return
	}
	c := loadClusterConfig()
	d := c.DNS
	if req.Token != nil && strings.TrimSpace(*req.Token) != "" {
		d.Token = strings.TrimSpace(*req.Token)
	}
	if req.Name != nil {
		d.Name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(*req.Name), "."))
	}
	if req.TTL > 0 {
		d.TTL = req.TTL
	}
	if req.Enabled != nil {
		d.Enabled = *req.Enabled
	}
	if req.Provider != nil {
		if *req.Provider != d.Provider {
			d.Token = "" // a secret is never carried to another provider
			if req.Token != nil {
				d.Token = strings.TrimSpace(*req.Token)
			}
		}
		d.Provider = *req.Provider
	}
	if req.URL != nil {
		d.URL = strings.TrimSpace(*req.URL)
	}
	if d.Provider != "webhook" {
		d.Provider = "cloudflare"
	}
	if (d.Enabled || req.Test) && !validDNSName(d.Name) {
		writeAPIError(w, r, "E-CLUSTER-02", "the record must be a full name such as vpn.example.com")
		return
	}
	if d.Provider == "webhook" {
		if (d.Enabled || req.Test) && (d.URL == "" || !validWebhookURL(d.URL)) {
			writeAPIError(w, r, "E-CLUSTER-02", "the webhook needs an http(s) URL")
			return
		}
	} else if (d.Enabled || req.Test) && d.Token == "" {
		writeAPIError(w, r, "E-CLUSTER-02", "a Cloudflare API token is needed (Zone > DNS > Edit)")
		return
	}
	if req.Test && d.Provider == "webhook" {
		c.DNS = d
		ips, _ := dnsHealthyIPs(c)
		if _, err := dnsWebhook(c, ips, true); err != nil {
			writeAPIError(w, r, "E-CLUSTER-10", err.Error())
			return
		}
		writeJSON(w, map[string]any{"status": "ok", "records": ips})
		return
	}
	if req.Test {
		zone, err := cfZone(d.Token, d.Name)
		if err != nil {
			writeAPIError(w, r, "E-CLUSTER-10", err.Error())
			return
		}
		recs, err := cfListA(d.Token, zone, d.Name)
		if err != nil {
			writeAPIError(w, r, "E-CLUSTER-10", err.Error())
			return
		}
		ips := []string{}
		for _, x := range recs {
			ips = append(ips, x.Content)
		}
		writeJSON(w, map[string]any{"status": "ok", "records": ips})
		return
	}
	if _, err := updateClusterConfig(func(x *ClusterConfig) error { x.DNS = d; return nil }); err != nil {
		writeAPIError(w, r, "E-CLUSTER-06", err.Error())
		return
	}
	dnsMu.Lock()
	dnsLastRun = time.Time{}
	dnsMu.Unlock()
	writeJSON(w, map[string]any{"status": "ok"})
}
