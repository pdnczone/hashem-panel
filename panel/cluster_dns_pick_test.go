package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// dnsStateReset forgets the DNS loop's state between tests.
func dnsStateReset() {
	dnsMu.Lock()
	dnsLastRun, dnsLastErr, dnsLeader, dnsWant, dnsExtra, dnsLastSig = time.Time{}, "", false, nil, nil, ""
	dnsRot.cur, dnsRot.pick, dnsRot.set, dnsRot.at = nil, "", "", time.Time{}
	dnsMu.Unlock()
	dnsReach.Lock()
	dnsReach.key, dnsReach.fails, dnsReach.down, dnsReach.err, dnsReach.at, dnsReach.busy = "", 0, false, "", time.Time{}, false
	dnsReach.Unlock()
	dnsBal.Lock()
	dnsBal.load, dnsBal.active, dnsBal.stuck = nil, false, nil
	dnsBal.Unlock()
	dnsSince = map[string]time.Time{}
	dnsLeading.Store(false)
	cfGood.Lock()
	cfGood.key = ""
	cfGood.Unlock()
}

// Whatever the hubs' state, all of them that see each other name the same one
// hub as the writer, and it can reach the provider when any of them can.
func TestDNSOneWriter(t *testing.T) {
	newClusterFixture(t, true)
	dnsCtlFresh(t)
	ids := []string{"hub-a", "hub-b", "hub-c"}
	const name = "vpn.example.com"
	for n := 2; n <= 3; n++ {
		for master := -1; master < n; master++ {
			for down := 0; down < 1<<n; down++ {
				writers := map[string]bool{}
				for i := 0; i < n; i++ {
					c := ClusterConfig{NodeID: ids[i], DNS: DNSConfig{Enabled: true, Name: name, Token: "x", Master: i == master}}
					dnsStateReset()
					if down&(1<<i) != 0 {
						dnsReachNote(c.DNS, reachErr{errors.New("blocked")})
						dnsReachNote(c.DNS, reachErr{errors.New("blocked")})
					}
					for j := 0; j < n; j++ {
						if j == i {
							continue
						}
						c.Hubs = append(c.Hubs, HubPeer{ID: ids[j]})
						setBeat(ids[j], true, meshBeat{DNS: name, Master: j == master, DNSDown: down&(1<<j) != 0})
					}
					w := dnsWriter(c)
					writers[w] = true
					if k := slices.Index(ids, w); down != 1<<n-1 && down&(1<<k) != 0 {
						t.Fatalf("n=%d master=%d down=%b: %s cannot reach the provider and still writes", n, master, down, w)
					}
				}
				if len(writers) != 1 {
					t.Fatalf("n=%d master=%d down=%b: writers %v", n, master, down, writers)
				}
			}
		}
	}
	// a beat of an older panel has no dns_down: it counts as able to write
	var old meshBeat
	_ = json.Unmarshal([]byte(`{"id":"hub-a","dns":"vpn.example.com","master":true}`), &old)
	if old.DNSDown || old.Starting || old.Load != nil {
		t.Fatalf("%+v", old)
	}
	// one failure is not enough, and one success brings it back
	dnsStateReset()
	d := DNSConfig{Enabled: true, Name: name, Token: "x"}
	dnsReachNote(d, reachErr{errors.New("x")})
	if dnsReachDown(d) {
		t.Fatal("one failure")
	}
	dnsReachNote(d, errors.New("Cloudflare: Invalid API Token")) // it answered
	dnsReachNote(d, reachErr{errors.New("x")})
	if dnsReachDown(d) {
		t.Fatal("not two in a row")
	}
	dnsReachNote(d, reachErr{errors.New("x")})
	if !dnsReachDown(d) {
		t.Fatal("two in a row")
	}
	if d2 := d; func() bool { d2.Route = "direct_only"; return dnsReachDown(d2) }() {
		t.Fatal("another route is not known to be down")
	}
	dnsReachNote(d, nil)
	if dnsReachDown(d) {
		t.Fatal("it answers again")
	}
}

// fakeCF is a Cloudflare API with one zone.
type fakeCF struct {
	mu   sync.Mutex
	next int
	recs map[string]cfRecord
	down bool
}

func newFakeCF(t *testing.T) *fakeCF {
	f := &fakeCF{recs: map[string]cfRecord{}}
	srv := httptest.NewServer(f)
	old := cfAPI
	cfAPI = srv.URL
	t.Cleanup(func() { cfAPI = old; srv.Close() })
	return f
}

func (f *fakeCF) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		w.WriteHeader(502)
		_, _ = io.WriteString(w, "<html>blocked</html>")
		return
	}
	ok := func(v any) { b, _ := json.Marshal(map[string]any{"success": true, "result": v}); _, _ = w.Write(b) }
	switch {
	case strings.HasPrefix(r.URL.Path, "/zones") && strings.Count(r.URL.Path, "/") == 1:
		if r.URL.Query().Get("name") == "example.com" {
			ok([]map[string]string{{"id": "z1"}})
		} else {
			ok([]string{})
		}
	case r.Method == "GET":
		out := []cfRecord{}
		for _, x := range f.recs {
			if dnsRecordType(x.Content) == r.URL.Query().Get("type") {
				out = append(out, x)
			}
		}
		ok(out)
	case r.Method == "POST":
		var x cfRecord
		_ = json.NewDecoder(r.Body).Decode(&x)
		f.next++
		x.ID = fmt.Sprintf("r%d", f.next)
		f.recs[x.ID] = x
		ok(x)
	case r.Method == "DELETE":
		delete(f.recs, filepath.Base(r.URL.Path))
		ok(map[string]string{})
	default:
		ok(map[string]string{})
	}
}

func (f *fakeCF) add(ip string) {
	f.mu.Lock()
	f.next++
	id := fmt.Sprintf("r%d", f.next)
	f.recs[id] = cfRecord{ID: id, Content: ip, TTL: 60}
	f.mu.Unlock()
}

func (f *fakeCF) ips() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, x := range f.recs {
		out = append(out, x.Content)
	}
	slices.Sort(out)
	return strings.Join(out, ",")
}

// dnsHub is a hub-a fixture whose tunnel works, linked with hub-b.
func dnsHub(t *testing.T, d DNSConfig) (*clusterFixture, *fakeCF) {
	f := newClusterFixture(t, true)
	dnsCtlFresh(t)
	oldIP6, oldUp, oldGo := meshIP6, panelUptime, dnsReachGo
	meshIP6 = func() string { return "" }
	panelUptime = func() time.Duration { return time.Hour }
	dnsReachGo = func(fn func()) { fn() }
	t.Cleanup(func() { meshIP6, panelUptime, dnsReachGo = oldIP6, oldUp, oldGo })
	f.peer(1, 7000, "9.9.9.1", 443)
	f.snap.Peers[0].HealthState = stateHealthy
	d.Enabled, d.Name, d.Token, d.TTL = true, "vpn.example.com", "tok", 60
	c := defaultClusterConfig()
	c.NodeID, c.PublicIP, c.DNS = "hub-a", "5.5.5.5", d
	c.Hubs = []HubPeer{{ID: "hub-b", PublicIP: "6.6.6.6"}}
	if err := saveClusterConfig(c); err != nil {
		t.Fatal(err)
	}
	return f, newFakeCF(t)
}

func dnsRunNow() {
	dnsMu.Lock()
	dnsLastRun = time.Time{}
	dnsMu.Unlock()
	dnsTick(loadClusterConfig())
}

func TestDNSTickRecord(t *testing.T) {
	f, cf := dnsHub(t, DNSConfig{Master: true, Owned: []string{"8.8.8.8"}})
	cf.add("8.8.8.8") // a hub unlinked long ago
	cf.add("1.2.3.4") // not a hub's
	setBeat("hub-b", true, meshBeat{Healthy: true, IP: "6.6.6.7", DNS: "vpn.example.com"})
	dnsRunNow()
	// hub-b's address changed since it was linked; the old hub's is taken out
	if got := cf.ips(); got != "1.2.3.4,5.5.5.5,6.6.6.7" {
		t.Fatal(got)
	}
	if v := dnsView(loadClusterConfig()); !slices.Equal(v.Extra, []string{"1.2.3.4"}) || v.Writer != "hub-a" {
		t.Fatalf("%+v", v)
	}
	// IPv6 only when every hub has it
	meshIP6 = func() string { return "2001:db8::5" }
	dnsRunNow()
	if got := cf.ips(); got != "1.2.3.4,5.5.5.5,6.6.6.7" {
		t.Fatalf("one hub with IPv6 would take all IPv6 users: %s", got)
	}
	setBeat("hub-b", true, meshBeat{Healthy: true, IP: "6.6.6.7", IP6: "2001:db8::6", DNS: "vpn.example.com"})
	dnsRunNow()
	if got := cf.ips(); got != "1.2.3.4,2001:db8::5,2001:db8::6,5.5.5.5,6.6.6.7" {
		t.Fatal(got)
	}
	meshIP6 = func() string { return "" }
	// hub-b's panel restarts: it stays, whatever it does not know yet
	setBeat("hub-b", true, meshBeat{Starting: true, IP: "6.6.6.7", DNS: "vpn.example.com"})
	dnsRunNow()
	if got := cf.ips(); got != "1.2.3.4,5.5.5.5,6.6.6.7" {
		t.Fatal(got)
	}
	// it stops answering: kept for a moment, then out
	meshMu.Lock()
	meshState["hub-b"].Up, meshState["hub-b"].Misses = false, meshFall
	meshState["hub-b"].Beat.Healthy = true
	meshState["hub-b"].LastSeen = time.Now().Add(-dnsKeepSilent + 3*time.Second)
	meshMu.Unlock()
	dnsRunNow()
	if got := cf.ips(); got != "1.2.3.4,5.5.5.5,6.6.6.7" {
		t.Fatal(got)
	}
	meshMu.Lock()
	meshState["hub-b"].LastSeen = time.Now().Add(-dnsKeepSilent)
	meshMu.Unlock()
	dnsRunNow()
	if got := cf.ips(); got != "1.2.3.4,5.5.5.5" {
		t.Fatal(got)
	}
	// the last hub is never taken out
	f.snap.Peers[0].HealthState = stateDown
	dnsRunNow()
	if got := cf.ips(); got != "1.2.3.4,5.5.5.5" {
		t.Fatal(got)
	}
}

// A hub whose pools are all disabled works through its tunnels.
func TestMeshHealthDisabledPools(t *testing.T) {
	f, _ := dnsHub(t, DNSConfig{})
	_, _ = updateClusterConfig(func(c *ClusterConfig) error {
		c.Pools = []LBPool{{Port: 443, Proto: "tcp", Mode: lbFailover, Disabled: true}}
		return nil
	})
	if b := meshSelfBeat(loadClusterConfig()); !b.Healthy {
		t.Fatalf("%+v", b)
	}
	f.snap.Peers[0].HealthState = stateDown
	if b := meshSelfBeat(loadClusterConfig()); b.Healthy || b.Starting {
		t.Fatalf("%+v", b)
	}
	panelUptime = func() time.Duration { return time.Second }
	if b := meshSelfBeat(loadClusterConfig()); b.Healthy || !b.Starting {
		t.Fatalf("just started: %+v", b)
	}
}

// The controller loses only its way to Cloudflare: the other hub writes.
func TestDNSWriterHandover(t *testing.T) {
	_, cf := dnsHub(t, DNSConfig{Master: true})
	setBeat("hub-b", true, meshBeat{Healthy: true, DNS: "vpn.example.com"})
	dnsRunNow()
	if cf.ips() != "5.5.5.5,6.6.6.6" || !meshSelfBeat(loadClusterConfig()).Master {
		t.Fatal(cf.ips())
	}
	if b := meshSelfBeat(loadClusterConfig()); strings.Join(b.DNSRecs, ",") != "5.5.5.5,6.6.6.6" {
		t.Fatalf("%+v", b)
	}
	cf.down = true
	dnsRunNow()
	if b := meshSelfBeat(loadClusterConfig()); b.DNSDown {
		t.Fatal("one failure")
	}
	dnsRunNow()
	dnsMu.Lock()
	dnsLastRun = time.Now().Add(-dnsRetryAfter)
	dnsMu.Unlock()
	dnsTick(loadClusterConfig())
	b := meshSelfBeat(loadClusterConfig())
	if !b.DNSDown {
		t.Fatalf("%+v", b)
	}
	if w := dnsWriter(loadClusterConfig()); w != "hub-b" {
		t.Fatal(w)
	}
	// hub-b writes: this hub takes over what its beat says
	setBeat("hub-b", true, meshBeat{Healthy: true, DNS: "vpn.example.com", DNSRecs: []string{"6.6.6.6"}})
	dnsTick(loadClusterConfig())
	if b := meshSelfBeat(loadClusterConfig()); b.DNSRecs != nil {
		t.Fatal("it does not write, so it says nothing about the record")
	}
	if r := loadClusterConfig().DNS.Records; strings.Join(r, ",") != "6.6.6.6" {
		t.Fatal(r)
	}
	// its way is back: it takes the record again
	cf.down = false
	dnsReach.Lock()
	dnsReach.at = time.Time{}
	dnsReach.Unlock()
	dnsTick(loadClusterConfig()) // the check
	dnsRunNow()
	if w := dnsWriter(loadClusterConfig()); w != "hub-a" || cf.ips() != "5.5.5.5,6.6.6.6" {
		t.Fatal(w, cf.ips())
	}
}

func TestDNSFailoverMode(t *testing.T) {
	f, cf := dnsHub(t, DNSConfig{Master: true, Mode: dnsFailover, Order: []string{"hub-b", "gone"}})
	b := meshBeat{Healthy: true, DNS: "vpn.example.com"}
	setBeat("hub-b", true, b)
	dnsRunNow()
	if cf.ips() != "6.6.6.6" {
		t.Fatal(cf.ips())
	}
	b.Healthy = false // its tunnels are down
	setBeat("hub-b", true, b)
	dnsRunNow()
	if cf.ips() != "5.5.5.5" {
		t.Fatal(cf.ips())
	}
	b.Healthy = true // back, but users return only when it stays up
	setBeat("hub-b", true, b)
	dnsRunNow()
	if cf.ips() != "5.5.5.5" {
		t.Fatal("moved back at once")
	}
	dnsSince["hub-b"] = time.Now().Add(-dnsFailbackAfter)
	dnsRunNow()
	if cf.ips() != "6.6.6.6" {
		t.Fatal(cf.ips())
	}
	// both down: the record keeps its last address
	b.Healthy = false
	setBeat("hub-b", true, b)
	f.snap.Peers[0].HealthState = stateDown
	dnsRunNow()
	if cf.ips() != "6.6.6.6" {
		t.Fatal(cf.ips())
	}
	if o := dnsOrdered(loadClusterConfig()); !slices.Equal(o, []string{"hub-b", "hub-a"}) {
		t.Fatal(o)
	}
}

func TestDNSModeAPIAndPush(t *testing.T) {
	dnsHub(t, DNSConfig{Master: true, Version: 5, Records: []string{"5.5.5.5"}, Owned: []string{"8.8.8.8"}})
	post := func(body string) int {
		rr := httptest.NewRecorder()
		handleClusterDNS(rr, httptest.NewRequest("POST", "/", strings.NewReader(body)))
		return rr.Code
	}
	if post(`{"mode":"x"}`) != 400 {
		t.Fatal("a bad mode")
	}
	if c := post(`{"mode":"failover","order":["hub-b","nope","hub-b","hub-a"],"route":"direct_only"}`); c != 200 {
		t.Fatal(c)
	}
	c := loadClusterConfig()
	if c.DNS.Mode != dnsFailover || !slices.Equal(c.DNS.Order, []string{"hub-b", "hub-a"}) || len(c.DNS.Records) != 1 {
		t.Fatalf("%+v", c.DNS)
	}
	p := dnsPushFor(c)
	// the other side follows them
	c2 := defaultClusterConfig()
	c2.NodeID = "hub-b"
	c2.Hubs = []HubPeer{{ID: "hub-a", PublicIP: "5.5.5.5"}}
	if err := saveClusterConfig(c2); err != nil {
		t.Fatal(err)
	}
	if a := dnsTakeSettings(c2.Hubs[0], p); !a.OK {
		t.Fatalf("%+v", a)
	}
	if d := loadClusterConfig().DNS; d.Mode != dnsFailover || !slices.Equal(d.Order, c.DNS.Order) || !slices.Contains(d.Owned, "8.8.8.8") {
		t.Fatalf("%+v", d)
	}
	if post(`{"mode":"balance"}`) != 400 {
		t.Fatal("a follower does not change the mode")
	}
}

// The measured traffic brings the hubs to their shares: users come by what the
// record says (with a bias to one hub, as phones have), stay for long, and the
// loop still ends at the wanted split and does not swing around it.
func TestDNSBalanceConverges(t *testing.T) {
	for _, tc := range []struct {
		wa, wb int
		bias   float64 // how many users take the first address when there are two
	}{{50, 50, 0.8}, {50, 50, 0.5}, {70, 30, 0.5}, {50, 50, 1}} {
		dnsStateReset()
		rng := rand.New(rand.NewSource(1))
		type user struct{ hub, left int }
		var users []user
		for i := 0; i < 400; i++ { // the start: nearly all on a
			h := 0
			if i%10 == 0 {
				h = 1
			}
			users = append(users, user{h, rng.Intn(240)})
		}
		groups := []dnsGroup{{Key: "a", IPs: []string{"1.1.1.1"}, Weight: tc.wa}, {Key: "b", IPs: []string{"2.2.2.2"}, Weight: tc.wb}}
		c := ClusterConfig{NodeID: "x"}
		for _, g := range groups {
			c.Hubs = append(c.Hubs, HubPeer{ID: g.Key})
		}
		now := time.Unix(1_700_000_000, 0)
		// the users' resolvers: each keeps an answer for 1 to 6 minutes
		type resolver struct {
			ans   []string
			until int
		}
		res := make([]resolver, 20)
		worst, sum, cnt := 0.0, 0.0, 0.0
		for step := 0; step < 60*24*2; step++ { // minutes, two days
			now = now.Add(time.Minute)
			n := [2]float64{}
			for _, u := range users {
				n[u.hub]++
			}
			meshMu.Lock()
			for i, k := range []string{"a", "b"} {
				l := n[i] * 100_000 * (0.8 + 0.4*rng.Float64())
				meshState[k] = &hubRT{Up: true, LastSeen: now, Beat: meshBeat{ID: k, Healthy: true, Load: &l}}
			}
			meshMu.Unlock()
			for s := 0; s < 20; s++ {
				dnsLoadSample(c, groups, now.Add(time.Duration(s*3-57)*time.Second))
			}
			want := dnsChoose(c, groups, now)
			for i := range res {
				if step >= res[i].until {
					res[i] = resolver{want, step + 1 + rng.Intn(6)}
				}
			}
			for i := range users {
				if users[i].left--; users[i].left > 0 {
					continue
				}
				h, cached := 0, res[rng.Intn(len(res))].ans
				if len(cached) == 1 {
					if cached[0] == "2.2.2.2" {
						h = 1
					}
				} else if rng.Float64() >= tc.bias {
					h = 1
				}
				users[i] = user{h, 30 + rng.Intn(240)}
			}
			if step > 60*12 {
				got := n[0] / (n[0] + n[1])
				worst = max(worst, abs(got-float64(tc.wa)/float64(tc.wa+tc.wb)))
				sum, cnt = sum+got, cnt+1
			}
		}
		mean := sum / cnt
		t.Logf("%d/%d bias %.1f: after 12 h hub a has %.1f%% on average, furthest off %.1f%%", tc.wa, tc.wb, tc.bias, 100*mean, 100*worst)
		if abs(mean-float64(tc.wa)/float64(tc.wa+tc.wb)) > 0.015 {
			t.Errorf("%d/%d bias %.1f: %.1f%% on average", tc.wa, tc.wb, tc.bias, 100*mean)
		}
		if worst > 0.09 {
			t.Errorf("%d/%d bias %.1f: off by %.1f%%", tc.wa, tc.wb, tc.bias, 100*worst)
		}
	}
	dnsCtlFresh(t)
}

func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}

// A hub users cannot reach is not given more and more of them, and nothing is
// corrected without traffic or a measure.
func TestDNSBalanceGuards(t *testing.T) {
	newClusterFixture(t, true)
	groups := []dnsGroup{{Key: "a", IPs: []string{"1.1.1.1"}, Weight: 50}, {Key: "b", IPs: []string{"2.2.2.2"}, Weight: 50}}
	c := ClusterConfig{NodeID: "x", Hubs: []HubPeer{{ID: "a"}, {ID: "b"}}}
	now := time.Unix(1_700_000_000, 0)
	run := func(d time.Duration, a, b *float64) {
		for end := now.Add(d); now.Before(end); now = now.Add(3 * time.Second) {
			meshMu.Lock()
			meshState["a"] = &hubRT{Up: true, Beat: meshBeat{Load: a}}
			meshState["b"] = &hubRT{Up: true, Beat: meshBeat{Load: b}}
			meshMu.Unlock()
			dnsLoadSample(c, groups, now)
			dnsChoose(c, groups, now)
		}
	}
	p := func(x float64) *float64 { return &x }
	run(5*time.Minute, p(1000), p(0))
	if _, on := dnsCorrect(groups, now); on {
		t.Fatal("no traffic to speak of")
	}
	dnsStateReset()
	run(5*time.Minute, p(5e6), nil)
	if _, on := dnsCorrect(groups, now); on {
		t.Fatal("hub b is not measured")
	}
	dnsStateReset()
	run(2*time.Minute, p(5e6), p(0))
	if _, on := dnsCorrect(groups, now); on {
		t.Fatal("not measured long enough")
	}
	run(8*time.Minute, p(5e6), p(0))
	w, on := dnsCorrect(groups, now)
	if !on || w[1].Weight < 4*w[0].Weight || w[0].Weight < 50 {
		t.Fatalf("%v %+v", on, w)
	}
	run(31*time.Minute, p(5e6), p(0))
	if _, on := dnsCorrect(groups, now); on || !dnsStuckIDs(now)["b"] {
		t.Fatal("nobody reaches b: stop sending it more")
	}
	run(2*time.Hour+time.Minute, p(5e6), p(0))
	if _, on := dnsCorrect(groups, now); !on {
		t.Fatal("tried again later")
	}
}

func TestLbSessionOfNeighbours(t *testing.T) {
	a := lbLink{ID: 1, CtrlPort: 7001, Remote: "1.1.1.1"}
	b := lbLink{ID: 2, CtrlPort: 7003, Remote: "2.2.2.2"}
	all := []lbLink{a, b}
	sock := func(lp uint16, r string) sockInfo {
		return sockInfo{Proto: "tcp", State: sockEstablished, Local: netip.AddrPortFrom(netip.MustParseAddr("5.5.5.5"), lp), Remote: netip.AddrPortFrom(netip.MustParseAddr(r), 40000)}
	}
	only2 := []sockInfo{sock(7003, "2.2.2.2")}
	if ok, _ := lbSessionOf(only2, a, all); ok {
		t.Fatal("link 2's session is not link 1's")
	}
	if ok, r := lbSessionOf(only2, b, all); !ok || r != "2.2.2.2" {
		t.Fatal(ok, r)
	}
	// a client behind NAT on its own port, and the WSS front of link 1
	if ok, r := lbSessionOf([]sockInfo{sock(7001, "100.64.0.1")}, a, all); !ok || r != "100.64.0.1" {
		t.Fatal(ok, r)
	}
	if ok, _ := lbSessionOf([]sockInfo{sock(7003, "1.1.1.1")}, a, all); !ok {
		t.Fatal("link 1's own foreign server")
	}
	if ok, _ := lbSessionOf([]sockInfo{sock(6999, "100.64.0.1")}, a, all); !ok {
		t.Fatal("a port only link 1 can own")
	}
	if ok, r := lbSessionOf([]sockInfo{sock(7001, "127.0.0.1"), sock(7001, "1.1.1.1")}, a, all); !ok || r != "1.1.1.1" {
		t.Fatal(ok, r)
	}
}

// A setting saved while the monitor lets a tunnel join its pool is kept.
func TestAutoJoinKeepsOtherSettings(t *testing.T) {
	f := newClusterFixture(t, true)
	f.peer(1, 7000, "9.9.9.1", 443)
	c := defaultClusterConfig()
	c.Pools = []LBPool{{Port: 443, Proto: "tcp", Mode: lbFailover}}
	_ = saveClusterConfig(c)
	stale := loadClusterConfig()
	_, _ = updateClusterConfig(func(x *ClusterConfig) error { x.DNS.Name = "vpn.example.com"; return nil })
	_ = stale
	clusterTick(time.Now())
	got := loadClusterConfig()
	if got.DNS.Name != "vpn.example.com" || len(got.Pools[0].Members) != 1 {
		t.Fatalf("%+v", got)
	}
	n := 0
	for _, e := range clusterEvents(50) {
		if strings.Contains(e.Text, "joined") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d join events", n)
	}
}

// Cloudflare is blocked here: the call goes through a tunnel, and that way is
// tried first from then on.
func TestCloudflareAutoRoute(t *testing.T) {
	dnsStateReset()
	cf := newFakeCF(t)
	old := cfRoutes
	defer func() { cfRoutes = old }()
	direct, tun := 0, 0
	cfRoutes = func(d DNSConfig) []tgRoute {
		dr := tgRoute{key: "direct", name: "directly", client: func(time.Duration) (*http.Client, error) { direct++; return nil, errors.New("blocked") }}
		tr := tgRoute{key: "tunnel:3", name: "de", client: func(time.Duration) (*http.Client, error) { tun++; return cfClient, nil }}
		if cfGood.key == "tunnel:3" {
			return []tgRoute{tr, dr}
		}
		return []tgRoute{dr, tr}
	}
	d := DNSConfig{Name: "vpn.example.com", Token: "tok", Route: "direct"}
	if _, err := cfZone(d, d.Name); err != nil || direct != 1 || tun < 1 {
		t.Fatal(err, direct, tun)
	}
	if _, err := cfZone(d, d.Name); err != nil || direct != 1 {
		t.Fatal(err, direct)
	}
	cf.down = true // a block page on every way
	var re reachErr
	if _, err := cfZone(d, d.Name); !errors.As(err, &re) || strings.Contains(err.Error(), "tok ") {
		t.Fatal(err)
	}
	cf.down = false
	d.Name = "vpn.other.org"
	if _, err := cfZone(d, d.Name); err == nil || errors.As(err, &re) {
		t.Fatalf("an answer about the settings is no reason to hand over: %v", err)
	}
	for r, want := range map[string]string{"": "auto", "direct": "auto", "auto": "auto", "direct_only": "direct_only", "tunnel": "tunnel"} {
		if got := dnsRoute(DNSConfig{Route: r}); got != want {
			t.Errorf("%q: %s", r, got)
		}
	}
}
