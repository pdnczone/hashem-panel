package main

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// dnsCtlFresh forgets what earlier tests left in the mesh and follow state.
func dnsCtlFresh(t *testing.T) {
	t.Helper()
	reset := func() {
		meshMu.Lock()
		meshState = map[string]*hubRT{}
		meshMu.Unlock()
		dnsFollowMu.Lock()
		dnsFollow = map[string]*dnsFollowState{}
		dnsFollowMu.Unlock()
	}
	reset()
	t.Cleanup(reset)
}

func setBeat(id string, up bool, b meshBeat) {
	meshMu.Lock()
	defer meshMu.Unlock()
	b.ID = id
	meshState[id] = &hubRT{Up: up, Beat: b, LastSeen: time.Now()}
}

// A hub with no pools takes its health from the live snapshot, not from the
// cluster monitor's link list (frozen since the last pool went away).
func TestSnapAnyLinkWorks(t *testing.T) {
	if snapAnyLinkWorks(nil) {
		t.Fatal("no snapshot: not healthy")
	}
	s := &HubSnapshot{At: time.Now(), Peers: []peerLive{{HealthState: stateDown}}}
	if snapAnyLinkWorks(s) {
		t.Fatal("only a dead tunnel: not healthy")
	}
	s.Main = &peerLive{HealthState: stateDegraded}
	if !snapAnyLinkWorks(s) {
		t.Fatal("a degraded tunnel still carries users")
	}
	f := newClusterFixture(t, true)
	clusterRT.mu.Lock()
	clusterRT.links[42] = &lbLinkRT{Up: true} // stale: left from a pool removed long ago
	clusterRT.mu.Unlock()
	defer func() { clusterRT.mu.Lock(); delete(clusterRT.links, 42); clusterRT.mu.Unlock() }()
	f.snap = &HubSnapshot{At: time.Now(), Main: &peerLive{HealthState: stateDown}}
	if meshSelfBeat(loadClusterConfig()).Healthy {
		t.Fatal("the hub reported itself healthy from a stale link while its only tunnel is down")
	}
}

// The DNS settings are sealed with their own key: a sealed bundle is no
// settings, and sealed settings are no bundle.
func TestDNSSealKeyIsItsOwn(t *testing.T) {
	sealed, err := dnsSeal(syncTestSecret, dnsPush{Type: "dnsconf", Token: "tok"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := syncOpen(syncTestSecret, sealed); err == nil {
		t.Fatal("DNS settings opened as a bundle")
	}
	b, _ := syncSeal(syncTestSecret, "hsh1_x")
	var p dnsPush
	if dnsOpen(syncTestSecret, b, &p) == nil {
		t.Fatal("a bundle opened as DNS settings")
	}
	if dnsOpen("another-secret-another-secret-12", sealed, &p) == nil {
		t.Fatal("opened with another cluster secret")
	}
}

func pushTo(t *testing.T, p dnsPush) dnsConfAns {
	t.Helper()
	sealed, err := dnsSeal(syncTestSecret, p)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	syncMux().ServeHTTP(rec, syncSigned(t, "/dnsconf", dnsConfReq{ID: "hub-a", Sealed: sealed}))
	if rec.Code != 200 {
		t.Fatalf("dnsconf answered %d", rec.Code)
	}
	var ans dnsConfAns
	_ = json.Unmarshal(rec.Body.Bytes(), &ans)
	return ans
}

func ctlPush(ver int64) dnsPush {
	return dnsPush{Type: "dnsconf", From: "hub-a", FromName: "mashhad (203.0.113.9)", Version: ver, Enabled: true,
		Provider: "webhook", URL: "https://hook.example.com/x", Name: "vpn.example.com", TTL: 5,
		Weights: map[string]int{"hub-a": 70, "hub-self": 30}}
}

// A linked hub sends its settings: this hub follows them, keeps its own route,
// takes its share from them, and a turned-off controller turns it off too.
func TestDNSFollowerTakesSettings(t *testing.T) {
	newClusterFixture(t, true)
	dnsCtlFresh(t)
	syncHub(t, "203.0.113.9")
	tid := 3
	_, _ = updateClusterConfig(func(c *ClusterConfig) error { c.DNS.Route, c.DNS.TunnelID = "tunnel", &tid; return nil })

	if ans := pushTo(t, ctlPush(1000)); !ans.OK {
		t.Fatalf("not taken: %+v", ans)
	}
	d := loadClusterConfig().DNS
	if !d.Enabled || d.Master || d.ManagedBy != "hub-a" || d.Name != "vpn.example.com" || d.Provider != "webhook" ||
		d.TTL != 60 || d.Weight != 30 || d.HubWeights["hub-a"] != 70 || d.Version != 1000 {
		t.Fatalf("follower settings: %+v", d)
	}
	if d.Route != "tunnel" || d.TunnelID == nil || *d.TunnelID != 3 {
		t.Fatalf("the route is this hub's own and must stay: %+v", d)
	}
	if dnsHubWeight(loadClusterConfig(), "hub-a", 1) != 70 {
		t.Fatal("a follower uses the controller's shares")
	}
	b := meshSelfBeat(loadClusterConfig())
	if b.DNSBy != "hub-a" || b.DNSVer != 1000 || b.Master || b.DNS != "vpn.example.com" {
		t.Fatalf("beat: %+v", b)
	}

	// the API refuses changes here, but lets the route change and allows a take-over
	rr := httptest.NewRecorder()
	handleClusterDNS(rr, httptest.NewRequest("POST", "/", strings.NewReader(`{"name":"x.example.com"}`)))
	if rr.Code != 400 || !strings.Contains(rr.Body.String(), "mashhad") {
		t.Fatalf("a follower changed the settings: %d %s", rr.Code, rr.Body)
	}

	// turned off on the controller: off here, no secret kept
	off := ctlPush(2000)
	off.Enabled = false
	if ans := pushTo(t, off); !ans.OK {
		t.Fatalf("%+v", ans)
	}
	if d := loadClusterConfig().DNS; d.Enabled || d.ManagedBy != "" || d.Token != "" {
		t.Fatalf("still following after the controller turned off: %+v", d)
	}
}

// A hub that controls DNS failover with newer settings does not follow older ones.
func TestDNSFollowerRefusesOlderSettings(t *testing.T) {
	newClusterFixture(t, true)
	dnsCtlFresh(t)
	syncHub(t, "203.0.113.9")
	_, _ = updateClusterConfig(func(c *ClusterConfig) error {
		c.DNS = DNSConfig{Enabled: true, Master: true, Provider: "webhook", URL: "https://h.example.com/", Name: "vpn.example.com", TTL: 60, Version: 5000}
		return nil
	})
	if ans := pushTo(t, ctlPush(4000)); ans.OK || !ans.Newer {
		t.Fatalf("older settings taken: %+v", ans)
	}
	if ans := pushTo(t, ctlPush(6000)); !ans.OK {
		t.Fatalf("newer settings (turned on later there) refused: %+v", ans)
	}
	if d := loadClusterConfig().DNS; d.ManagedBy != "hub-a" || d.Master {
		t.Fatalf("%+v", d)
	}
	// settings sealed by one hub cannot be sent as another's
	p := ctlPush(7000)
	p.From = "hub-x"
	if ans := pushTo(t, p); ans.OK {
		t.Fatal("settings from another hub taken")
	}
}

// A follower lets the settings go by itself: its controller unlinked, or
// answering without controlling them any more.
func TestDNSFollowerReleasesItself(t *testing.T) {
	newClusterFixture(t, true)
	dnsCtlFresh(t)
	syncHub(t, "203.0.113.9")
	follow := func() {
		_, _ = updateClusterConfig(func(c *ClusterConfig) error {
			c.DNS = DNSConfig{Enabled: true, Provider: "cloudflare", Token: "t", Name: "vpn.example.com", TTL: 60, Version: 1, ManagedBy: "hub-a"}
			return nil
		})
	}
	follow()
	setBeat("hub-a", true, meshBeat{DNSBy: "hub-a", DNSVer: 1, DNS: "vpn.example.com", Master: true})
	dnsFollowerCheck(loadClusterConfig())
	if !loadClusterConfig().DNS.Enabled {
		t.Fatal("released while the controller still controls")
	}
	setBeat("hub-a", false, meshBeat{})
	dnsFollowerCheck(loadClusterConfig())
	if !loadClusterConfig().DNS.Enabled {
		t.Fatal("released because the controller is down: then nobody would write the record")
	}
	setBeat("hub-a", true, meshBeat{}) // answers, DNS failover off there
	meshMu.Lock()
	meshState["hub-a"].LastSeen = time.Now().Add(dnsFollowMargin + time.Second)
	meshMu.Unlock()
	dnsFollowerCheck(loadClusterConfig())
	if d := loadClusterConfig().DNS; d.Enabled || d.Token != "" {
		t.Fatalf("still on after the controller turned it off: %+v", d)
	}
	follow()
	_, _ = updateClusterConfig(func(c *ClusterConfig) error { c.Hubs = nil; return nil })
	dnsFollowerCheck(loadClusterConfig())
	if loadClusterConfig().DNS.Enabled {
		t.Fatal("still on after the controller was unlinked")
	}
}

// The controller sends its settings to each answering hub that lacks them,
// once per version (retrying after a while), and when off only to its followers.
func TestDNSControlPushes(t *testing.T) {
	newClusterFixture(t, true)
	dnsCtlFresh(t)
	_, _ = updateClusterConfig(func(c *ClusterConfig) error {
		c.NodeID, c.Name, c.Secret = "hub-self", "tehran", syncTestSecret
		c.Hubs = []HubPeer{{ID: "hub-a", Name: "a"}, {ID: "hub-b", Name: "b"}, {ID: "hub-c", Name: "c"}, {ID: "hub-d", Name: "d"}}
		c.DNS = DNSConfig{Enabled: true, Master: true, Provider: "webhook", URL: "https://h.example.com/", Name: "vpn.example.com", TTL: 60, Version: 77, Weight: 40, HubWeights: map[string]int{"hub-a": 60}}
		return nil
	})
	var mu sync.Mutex
	got := map[string]dnsPush{}
	old := dnsPushCall
	defer func() { dnsPushCall = old }()
	dnsPushCall = func(h HubPeer, secret string, req dnsConfReq) (dnsConfAns, error) {
		var p dnsPush
		if err := dnsOpen(secret, req.Sealed, &p); err != nil {
			t.Error(err)
		}
		mu.Lock()
		got[h.ID] = p
		mu.Unlock()
		if h.ID == "hub-c" {
			return dnsConfAns{}, errors.New("the other hub did not accept the request: update it")
		}
		return dnsConfAns{OK: true, Checked: true, ReachErr: map[string]string{"hub-b": "no Cloudflare zone holds vpn.example.com"}[h.ID]}, nil
	}
	setBeat("hub-a", true, meshBeat{})                              // knows nothing yet
	setBeat("hub-b", true, meshBeat{DNSBy: "hub-self", DNSVer: 76}) // an older version
	setBeat("hub-c", true, meshBeat{})                              // an older panel
	setBeat("hub-d", true, meshBeat{DNSBy: "hub-self", DNSVer: 77}) // up to date
	wait := func() {
		for i := 0; i < 200; i++ {
			dnsFollowMu.Lock()
			busy := false
			for _, f := range dnsFollow {
				busy = busy || f.busy
			}
			dnsFollowMu.Unlock()
			if !busy {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	dnsControl(loadClusterConfig())
	wait()
	mu.Lock()
	if len(got) != 3 || got["hub-d"].Version != 0 {
		t.Fatalf("pushed to %v", got)
	}
	if p := got["hub-a"]; p.Version != 77 || p.Weights["hub-self"] != 40 || p.Weights["hub-a"] != 60 || !p.Enabled || p.From != "hub-self" {
		t.Fatalf("push: %+v", p)
	}
	mu.Unlock()

	// the view says who follows, who cannot reach the provider, who needs an update
	setBeat("hub-a", true, meshBeat{DNSBy: "hub-self", DNSVer: 77})
	ms := dnsMembers(loadClusterConfig())
	dnsMembersFollow(loadClusterConfig(), ms)
	by := map[string]dnsMember{}
	for _, m := range ms {
		by[m.ID] = m
	}
	if !by["hub-a"].Follows || by["hub-b"].ReachErr == "" || !by["hub-c"].Old || by["hub-c"].FollowEr == "" {
		t.Fatalf("members: %+v", ms)
	}

	// not again at once for the same version
	mu.Lock()
	got = map[string]dnsPush{}
	mu.Unlock()
	dnsControl(loadClusterConfig())
	wait()
	mu.Lock()
	if len(got) != 0 {
		t.Fatalf("pushed again at once: %v", got)
	}
	mu.Unlock()

	// turned off: only the hubs that follow are told
	_, _ = updateClusterConfig(func(c *ClusterConfig) error {
		c.DNS.Enabled, c.DNS.Master, c.DNS.Version = false, false, 78
		return nil
	})
	dnsControl(loadClusterConfig())
	wait()
	mu.Lock()
	defer mu.Unlock()
	if _, ok := got["hub-a"]; !ok || got["hub-a"].Enabled {
		t.Fatalf("the follower was not told to stop: %v", got)
	}
	if _, ok := got["hub-c"]; ok {
		t.Fatal("a hub that never followed was told to stop")
	}
}

// Turning it on makes this hub the controller with a new version; a follower
// can take over; the TTL is kept in 60..3600.
func TestDNSSaveMakesController(t *testing.T) {
	newClusterFixture(t, true)
	dnsCtlFresh(t)
	syncHub(t, "203.0.113.9")
	rr := httptest.NewRecorder()
	handleClusterDNS(rr, httptest.NewRequest("POST", "/", strings.NewReader(`{"enabled":true,"provider":"webhook","url":"https://h.example.com/","name":"vpn.example.com","ttl":99999}`)))
	if rr.Code != 200 {
		t.Fatalf("%d %s", rr.Code, rr.Body)
	}
	d := loadClusterConfig().DNS
	if !d.Master || d.Version == 0 || d.TTL != 3600 || d.ManagedBy != "" {
		t.Fatalf("%+v", d)
	}
	// follower take-over
	_, _ = updateClusterConfig(func(c *ClusterConfig) error {
		c.DNS.ManagedBy, c.DNS.Master, c.DNS.Version = "hub-a", false, d.Version+50
		return nil
	})
	rr = httptest.NewRecorder()
	handleClusterDNS(rr, httptest.NewRequest("POST", "/", strings.NewReader(`{"take_over":true}`)))
	if rr.Code != 200 {
		t.Fatalf("%d %s", rr.Code, rr.Body)
	}
	if d2 := loadClusterConfig().DNS; !d2.Master || !d2.Enabled || d2.ManagedBy != "" || d2.Version <= d.Version+50 {
		t.Fatalf("take-over: %+v", d2)
	}
}

// Right after a start nothing is written: the hub's own health and the other
// hubs' state are not known yet.
func TestDNSSettled(t *testing.T) {
	f := newClusterFixture(t, true)
	dnsCtlFresh(t)
	c := ClusterConfig{Hubs: []HubPeer{{ID: "hub-a"}}}
	f.snap = nil
	if dnsSettled(c) {
		t.Fatal("settled without a snapshot")
	}
	f.snap = &HubSnapshot{At: time.Now()}
	if dnsSettled(c) {
		t.Fatal("settled before hub-a answered or missed enough beats")
	}
	meshMu.Lock()
	meshState["hub-a"] = &hubRT{Misses: 1}
	meshMu.Unlock()
	if dnsSettled(c) {
		t.Fatal("one missed beat is not down yet")
	}
	meshMu.Lock()
	meshState["hub-a"].Misses = meshFall
	meshMu.Unlock()
	if !dnsSettled(c) {
		t.Fatal("hub-a counts as down now: settled")
	}
}

// Another hub waits a little before it writes in place of a master that just
// stopped answering.
func TestDNSTakeoverWaits(t *testing.T) {
	newClusterFixture(t, true)
	dnsCtlFresh(t)
	a := ClusterConfig{NodeID: "hub-a", PublicIP: "6.6.6.6", DNS: DNSConfig{Enabled: true, Name: "vpn.example.com"}, Hubs: []HubPeer{{ID: "hub-z", PublicIP: "5.5.5.5"}}}
	meshMu.Lock()
	meshState["hub-z"] = &hubRT{Up: false, LastSeen: time.Now(), Beat: meshBeat{ID: "hub-z", DNS: "vpn.example.com", Master: true}}
	meshMu.Unlock()
	if _, leader := dnsHealthyIPs(a); leader {
		t.Fatal("took over the moment the master stopped answering")
	}
	meshMu.Lock()
	meshState["hub-z"].LastSeen = time.Now().Add(-dnsTakeoverAfter - time.Second)
	meshMu.Unlock()
	if _, leader := dnsHealthyIPs(a); !leader {
		t.Fatal("the master has been silent long enough: hub-a writes")
	}
}

// Right after a hub takes the settings, the controller beat it recorded before
// still shows the old state: that is no reason to let them go again. Only a
// beat seen well after can say the controller turned it off.
func TestDNSFollowerKeepsFreshSettings(t *testing.T) {
	newClusterFixture(t, true)
	dnsCtlFresh(t)
	syncHub(t, "203.0.113.9")
	setBeat("hub-a", true, meshBeat{}) // the beat from before it was turned on there
	if ans := pushTo(t, ctlPush(1000)); !ans.OK {
		t.Fatalf("%+v", ans)
	}
	dnsFollowerCheck(loadClusterConfig())
	if d := loadClusterConfig().DNS; !d.Enabled || d.ManagedBy != "hub-a" {
		t.Fatalf("let the settings go on a beat from before they came: %+v", d)
	}
	// later, the controller answers with DNS failover off: now it is released
	meshMu.Lock()
	meshState["hub-a"].LastSeen = time.Now().Add(dnsFollowMargin + time.Second)
	meshMu.Unlock()
	dnsFollowerCheck(loadClusterConfig())
	if d := loadClusterConfig().DNS; d.Enabled {
		t.Fatalf("still on after the controller turned it off: %+v", d)
	}

	// hand-over: this hub controlled, hub-a took over and sends its settings;
	// the beat this hub has of hub-a still shows it following this hub
	_, _ = updateClusterConfig(func(c *ClusterConfig) error {
		c.DNS = DNSConfig{Enabled: true, Master: true, Provider: "webhook", URL: "https://h.example.com/", Name: "vpn.example.com", TTL: 60, Version: 3000}
		return nil
	})
	setBeat("hub-a", true, meshBeat{DNSBy: "hub-self", DNSVer: 3000, DNS: "vpn.example.com"})
	if ans := pushTo(t, ctlPush(4000)); !ans.OK {
		t.Fatalf("%+v", ans)
	}
	dnsFollowerCheck(loadClusterConfig())
	if d := loadClusterConfig().DNS; !d.Enabled || d.ManagedBy != "hub-a" {
		t.Fatalf("the old controller let the new settings go at once: %+v", d)
	}
}

// The beat lists the hub's foreign servers for the other hubs' map.
func TestMeshLinksOf(t *testing.T) {
	if meshLinksOf(nil) != nil {
		t.Fatal("links without a snapshot")
	}
	s := &HubSnapshot{Peers: []peerLive{
		{peerRecord: peerRecord{Name: "de", RemotePub: "203.0.113.5"}, HealthState: stateHealthy, LatencyMs: 41.27},
		{peerRecord: peerRecord{Name: "fi", RemotePub: "203.0.113.6"}, HealthState: stateDown, LatencyMs: 9},
		{peerRecord: peerRecord{Name: "none"}, HealthState: stateHealthy},
	}}
	got := meshLinksOf(s)
	if len(got) != 2 || got[0] != (meshLink{Name: "de", Remote: "203.0.113.5", Up: true, Ms: 41.3}) || got[1].Up || got[1].Ms != 0 {
		t.Fatalf("%+v", got)
	}
}

// A tunnel's traffic per second comes from its byte counters, over at least
// 2 s, and survives a counter restart.
func TestLinkBps(t *testing.T) {
	u := func(v uint64) *uint64 { return &v }
	linkRates.Lock()
	delete(linkRates.m, "t|x")
	linkRates.Unlock()
	t0 := time.Now()
	if linkBps("t|x", u(1000), u(0), t0) != 0 || linkBps("t|x", nil, u(1), t0) != 0 {
		t.Fatal("a first reading has no rate")
	}
	if got := linkBps("t|x", u(3000), u(2000), t0.Add(time.Second)); got != 0 {
		t.Fatalf("measured over less than 2 s: %v", got)
	}
	if got := linkBps("t|x", u(11000), u(10000), t0.Add(4*time.Second)); got != 5000 {
		t.Fatalf("20000 bytes in 4 s: %v", got)
	}
	if got := linkBps("t|x", u(10), u(0), t0.Add(8*time.Second)); got != 5000 {
		t.Fatalf("a restarted counter changed the rate: %v", got)
	}
}
