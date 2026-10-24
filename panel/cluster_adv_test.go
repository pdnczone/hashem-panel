package main

// Pool features beyond the modes: standby members, connection limits, least
// connections, failback by hand, the service check, the DNS webhook and the
// Prometheus lines.

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestLBBackupMembers(t *testing.T) {
	for _, mode := range []string{lbFailover, lbBalance, lbSticky, lbLeast, lbLatency} {
		p := LBPool{Port: 443, Proto: "tcp", Mode: mode}
		b := mem(3, 0, 1, true, true, 5) // the fastest, but standby
		b.Backup = true
		ts, st := lbPickTargets(p, members(mem(1, 0, 1, true, true, 50), mem(2, 1, 1, true, true, 60), b), nil)
		for _, x := range ts {
			if x.Link == 3 {
				t.Fatalf("%s: a standby member got traffic while primaries work: %+v", mode, ts)
			}
		}
		if st != poolOK {
			t.Fatalf("%s: %s", mode, st)
		}
		ts, st = lbPickTargets(p, members(mem(1, 0, 1, false, true, 50), mem(2, 1, 1, false, true, 60), b), nil)
		if len(ts) != 1 || ts[0].Link != 3 || st != poolDegraded {
			t.Fatalf("%s: no primary works, the standby must take it: %v %+v", mode, st, ts)
		}
	}
}

func TestLBConnectionLimit(t *testing.T) {
	p := LBPool{Port: 443, Proto: "tcp", Mode: lbBalance}
	rt := newPoolRT()
	m1, m2, b := mem(1, 0, 1, true, true, 1), mem(2, 0, 1, true, true, 1), mem(3, 0, 1, true, true, 1)
	m1.MaxConn, m1.Conns = 100, 100
	m2.Conns = 10
	b.Backup = true
	ts, _ := lbPickTargets(p, members(m1, m2, b), rt)
	if len(ts) != 1 || ts[0].Link != 2 {
		t.Fatalf("a full member takes no new connections: %+v", ts)
	}
	// it comes back only below 90% of its limit
	m1.Conns = 95
	if ts, _ = lbPickTargets(p, members(m1, m2, b), rt); len(ts) != 1 {
		t.Fatalf("back too early: %+v", ts)
	}
	m1.Conns = 89
	if ts, _ = lbPickTargets(p, members(m1, m2, b), rt); len(ts) != 2 {
		t.Fatalf("not back below 90%%: %+v", ts)
	}
	// every primary full: the overflow goes to the standby member
	m1.Conns, m2.MaxConn, m2.Conns = 100, 10, 10
	ts, _ = lbPickTargets(p, members(m1, m2, b), rt)
	if len(ts) != 1 || ts[0].Link != 3 {
		t.Fatalf("overflow: %+v", ts)
	}
	// everyone full: still served rather than refused
	b.MaxConn, b.Conns = 1, 1
	if ts, _ = lbPickTargets(p, members(m1, m2, b), rt); len(ts) != 3 {
		t.Fatalf("all full: %+v", ts)
	}
}

func TestLBLeastConnections(t *testing.T) {
	a, b := mem(1, 0, 1, true, true, 1), mem(2, 0, 1, true, true, 1)
	a.Conns, b.Conns = 200, 0
	w := lbLeastShares(members(a, b))
	if w[2] < 90 || w[1] != 1 {
		t.Fatalf("the empty member must get nearly everything: %v", w)
	}
	a.Conns, b.Conns = 50, 50
	if w = lbLeastShares(members(a, b)); w[1] != w[2] {
		t.Fatalf("equal load, equal share: %v", w)
	}
	// weight 3 carries three times the connections at the same level
	a.Weight, a.Conns, b.Conns = 3, 150, 50
	if w = lbLeastShares(members(a, b)); w[1] < 2*w[2] {
		t.Fatalf("by weight: %v", w)
	}
	// UDP (unknown counts) is plain weighted balance
	a.Conns, b.Conns = -1, -1
	if w = lbLeastShares(members(a, b)); w[1] != 3*w[2] {
		t.Fatalf("unknown counts: %v", w)
	}

	// the weights hold for lbLeastEvery ticks, so the rules do not change every second
	p := LBPool{Port: 443, Proto: "tcp", Mode: lbLeast}
	rt := newPoolRT()
	a, b = mem(1, 0, 1, true, true, 1), mem(2, 0, 1, true, true, 1)
	a.Conns, b.Conns = 100, 0
	first, _ := lbPickTargets(p, members(a, b), rt)
	a.Conns, b.Conns = 0, 100
	for i := 1; i < lbLeastEvery; i++ {
		ts, _ := lbPickTargets(p, members(a, b), rt)
		if ts[0].Weight != first[0].Weight {
			t.Fatalf("re-weighted after %d ticks", i)
		}
	}
	ts, _ := lbPickTargets(p, members(a, b), rt)
	if ts[0].Weight <= ts[1].Weight {
		t.Fatalf("not re-weighted: %+v", ts)
	}
	// a member leaving re-weights at once
	ts, _ = lbPickTargets(p, members(a), rt)
	if len(ts) != 1 || ts[0].Share != 1 {
		t.Fatalf("%+v", ts)
	}
}

func TestLBNoFailback(t *testing.T) {
	p := LBPool{Port: 443, Proto: "tcp", Mode: lbFailover, NoFailback: true}
	rt := newPoolRT()
	pick := func(up1 bool) int {
		ts, _ := lbPickTargets(p, members(mem(1, 0, 1, up1, true, 1), mem(2, 1, 1, true, true, 1)), rt)
		return ts[0].Link
	}
	if pick(true) != 1 || pick(false) != 2 {
		t.Fatal("failover itself must still work")
	}
	if pick(true) != 2 {
		t.Fatal("moved back by itself with failback off")
	}
	p.Failback++ // the user presses Fail Back Now
	if pick(true) != 1 || pick(true) != 1 {
		t.Fatal("failback asked but not done")
	}
	p.NoFailback = false
	pick(false)
	if pick(true) != 1 {
		t.Fatal("automatic failback")
	}
}

func TestLBParsePorts(t *testing.T) {
	got, err := lbParsePorts("443, 8443,2000-2002,443")
	if err != nil || fmt.Sprint(got) != "[443 8443 2000 2001 2002]" {
		t.Fatalf("%v %v", got, err)
	}
	for _, bad := range []string{"", "x", "0", "70000", "5-3", "1-60"} {
		if _, err := lbParsePorts(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// The service check on real sockets: a service that answers, one that waits
// for the client (TLS), one that closes at once (the foreign service is down
// and the relay drops the connection) and a closed port.
func TestLBTCPProbe(t *testing.T) {
	serve := func(h func(net.Conn)) int {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go h(c)
			}
		}()
		return ln.Addr().(*net.TCPAddr).Port
	}
	talks := serve(func(c net.Conn) { _, _ = c.Write([]byte("SSH-2.0\r\n")); time.Sleep(time.Second); c.Close() })
	waits := serve(func(c net.Conn) { time.Sleep(3 * time.Second); c.Close() })
	drops := serve(func(c net.Conn) { c.Close() })
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	if ok, why := lbTCPProbe("127.0.0.1", talks, time.Second); !ok {
		t.Fatalf("answering service: %s", why)
	}
	if ok, why := lbTCPProbe("127.0.0.1", waits, time.Second); !ok {
		t.Fatalf("waiting service: %s", why)
	}
	if ok, why := lbTCPProbe("127.0.0.1", drops, time.Second); ok || !strings.Contains(why, "closed at once") {
		t.Fatalf("dropped connection passed: %v %s", ok, why)
	}
	if ok, _ := lbTCPProbe("127.0.0.1", closed, time.Second); ok {
		t.Fatal("closed port passed")
	}
}

func TestClusterServiceCheck(t *testing.T) {
	f := newClusterFixture(t, true)
	f.peer(1, 7001, "1.1.1.1", 443)
	f.peer(2, 7002, "2.2.2.2", 443)
	f.pings = map[string]float64{"10.0.1.2": 30, "10.0.2.2": 60}
	// three users on link 1, one on link 2
	f.sockets([]string{"169.254.77.2:443", "169.254.77.3:443"}, []string{"7001>10.0.1.2", "7002>10.0.2.2",
		"169.254.77.2:443>5.1.1.1", "169.254.77.2:443>5.1.1.2", "169.254.77.2:443>5.1.1.3", "169.254.77.3:443>5.1.1.4"})
	var mu sync.Mutex
	svcOK := map[string]bool{"169.254.77.2": true, "169.254.77.3": true}
	probes := 0
	oldProbe, oldGo := lbProbe, lbGo
	lbProbe = func(addr string, port int, _ time.Duration) (bool, string) {
		mu.Lock()
		defer mu.Unlock()
		probes++
		if port != 443 {
			t.Errorf("probe port %d", port)
		}
		if svcOK[addr] {
			return true, ""
		}
		return false, "the connection was closed at once"
	}
	lbGo = func(fn func()) { fn() }
	defer func() { lbProbe, lbGo = oldProbe, oldGo }()

	_ = saveClusterConfig(ClusterConfig{Version: 2, NodeID: "hub-a", Health: LBHealth{}.norm(),
		Pools: []LBPool{{Port: 443, Proto: "tcp", Mode: lbFailover, Check: "tcp", CheckEvery: 1,
			Members: []LBMember{{Link: 1, Weight: 1}, {Link: 2, Weight: 1, Priority: 1}}}}})
	now := time.Now()
	tick := func() { now = now.Add(time.Second); clusterTick(now) }
	tick()
	tick()
	if !strings.Contains(f.lastRules(), "--to-destination 169.254.77.2:443") || probes == 0 {
		t.Fatalf("probes %d, rules:\n%s", probes, f.lastRules())
	}
	// xray on the first foreign server stops: the tunnel is fine, the service is not
	mu.Lock()
	svcOK["169.254.77.2"] = false
	mu.Unlock()
	for i := 0; i < 4; i++ {
		tick()
	}
	if !strings.Contains(f.lastRules(), "-A HLB-T443 -p tcp -j DNAT --to-destination 169.254.77.3:443") {
		t.Fatalf("no failover on a dead service:\n%s", f.lastRules())
	}
	rr := httptest.NewRecorder()
	handleClusterStatus(rr, httptest.NewRequest("GET", "/api/cluster/status", nil))
	var st struct {
		Pools []clusterPoolView `json:"pools"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &st)
	m := st.Pools[0].Status
	if m[0].Check != "fail" || m[0].Up || m[0].CheckReason == "" || m[1].Check != "ok" || m[0].Conns != 3 || m[1].Conns != 1 {
		t.Fatalf("status %+v", m)
	}
	if !strings.Contains(fmt.Sprint(clusterEvents(10)), "service check failed") {
		t.Fatalf("events %v", clusterEvents(10))
	}
	// metrics carry the same
	prom := clusterPrometheus()
	for _, want := range []string{`hashem_cluster_pool_state{pool="tcp/443"} 1`, `hashem_cluster_member_up{pool="tcp/443",link="1"} 0`,
		`hashem_cluster_member_connections{pool="tcp/443",link="1"} 3`, `hashem_cluster_member_share{pool="tcp/443",link="2"} 1`} {
		if !strings.Contains(prom, want) {
			t.Fatalf("metrics miss %s:\n%s", want, prom)
		}
	}
	// back after Rise good checks
	mu.Lock()
	svcOK["169.254.77.2"] = true
	mu.Unlock()
	for i := 0; i < 4; i++ {
		tick()
	}
	if !strings.Contains(f.lastRules(), "-A HLB-T443 -p tcp -j DNAT --to-destination 169.254.77.2:443") {
		t.Fatalf("did not come back:\n%s", f.lastRules())
	}
}

func TestClusterPoolAPIAdvanced(t *testing.T) {
	f := newClusterFixture(t, true)
	f.peer(1, 7001, "1.1.1.1", 443)
	f.peer(2, 7002, "2.2.2.2", 443)
	_ = saveClusterConfig(defaultClusterConfig())
	post := func(h http.HandlerFunc, body string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		h(rr, httptest.NewRequest("POST", "/", strings.NewReader(body)))
		return rr
	}
	if rr := post(handleClusterPool, `{"port":443,"proto":"tcp","mode":"least","check":"TCP","check_every":5,"members":[{"link":1},{"link":2,"backup":true,"max_conn":500}]}`); rr.Code != 200 {
		t.Fatalf("%d %s", rr.Code, rr.Body)
	}
	p := loadClusterConfig().Pools[0]
	if p.Mode != lbLeast || p.Check != "tcp" || p.CheckEvery != 5 || !p.Members[1].Backup || p.Members[1].MaxConn != 500 {
		t.Fatalf("%+v", p)
	}
	for body, want := range map[string]string{
		`{"port":443,"proto":"tcp","mode":"x"}`:                                            "least",
		`{"port":443,"proto":"tcp","mode":"balance","check":"http"}`:                       "tcp or off",
		`{"port":443,"proto":"tcp","mode":"balance","members":[{"link":1,"max_conn":-1}]}`: "connection limit",
	} {
		if rr := post(handleClusterPool, body); rr.Code != 400 || !strings.Contains(rr.Body.String(), want) {
			t.Errorf("%s: %d %s", body, rr.Code, rr.Body)
		}
	}
	if rr := post(handleClusterMember, `{"port":443,"proto":"tcp","link":2,"action":"set","backup":false,"max_conn":0}`); rr.Code != 200 {
		t.Fatalf("%d %s", rr.Code, rr.Body)
	}
	if m := loadClusterConfig().Pools[0].Members[1]; m.Backup || m.MaxConn != 0 {
		t.Fatalf("%+v", m)
	}
	if rr := post(handleClusterPoolFailback, `{"port":443,"proto":"tcp"}`); rr.Code != 200 || loadClusterConfig().Pools[0].Failback != 1 {
		t.Fatalf("%d %s", rr.Code, rr.Body)
	}
	if rr := post(handleClusterPoolFailback, `{"port":444}`); rr.Code != 404 {
		t.Fatalf("unknown pool: %d", rr.Code)
	}
}

func TestDNSWebhook(t *testing.T) {
	var got map[string]any
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&got)
		if got["name"] == "fail.example.com" {
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()
	c := ClusterConfig{NodeID: "hub-a", DNS: DNSConfig{Enabled: true, Provider: "webhook", URL: srv.URL, Token: "sec", Name: "vpn.example.com", TTL: 60}}
	ips, err := dnsWebhook(c, []string{"5.5.5.5", "6.6.6.6"}, false)
	if err != nil || len(ips) != 2 || auth != "Bearer sec" || got["name"] != "vpn.example.com" || fmt.Sprint(got["ips"]) != "[5.5.5.5 6.6.6.6]" || got["hub"] != "hub-a" || got["test"] != nil {
		t.Fatalf("%v %v %q %v", ips, err, auth, got)
	}
	c.DNS.Name = "fail.example.com"
	if _, err := dnsWebhook(c, nil, true); err == nil || !strings.Contains(err.Error(), "HTTP 500") || got["test"] != true {
		t.Fatalf("%v %v", err, got)
	}
	if !dnsReady(DNSConfig{Enabled: true, Provider: "webhook", URL: "https://x", Name: "a.b"}) || dnsReady(DNSConfig{Enabled: true, Provider: "webhook", Name: "a.b"}) {
		t.Fatal("dnsReady")
	}

	// the API keeps a secret from leaking to another provider
	newClusterFixture(t, true)
	cc := defaultClusterConfig()
	cc.DNS = DNSConfig{Provider: "cloudflare", Token: "cf-token", Name: "vpn.example.com"}
	_ = saveClusterConfig(cc)
	rr := httptest.NewRecorder()
	handleClusterDNS(rr, httptest.NewRequest("POST", "/", strings.NewReader(`{"enabled":true,"provider":"webhook","url":"`+srv.URL+`","name":"vpn.example.com"}`)))
	if rr.Code != 200 {
		t.Fatalf("%d %s", rr.Code, rr.Body)
	}
	if d := loadClusterConfig().DNS; d.Provider != "webhook" || d.Token != "" || d.URL != srv.URL {
		t.Fatalf("%+v", d)
	}
	rr = httptest.NewRecorder()
	handleClusterDNS(rr, httptest.NewRequest("POST", "/", strings.NewReader(`{"enabled":true,"provider":"webhook","url":"ftp://x","name":"vpn.example.com"}`)))
	if rr.Code != 400 {
		t.Fatalf("bad URL accepted: %d", rr.Code)
	}
}

// Disabling a pool keeps its relays where they are: the port goes to one of
// them (the lowest link id) and nothing restarts.
func TestClusterDisabledPoolPassesThrough(t *testing.T) {
	f := newClusterFixture(t, true)
	f.peer(1, 7001, "1.1.1.1", 443)
	f.peer(2, 7002, "2.2.2.2", 443)
	f.pings = map[string]float64{"10.0.1.2": 30, "10.0.2.2": 60}
	f.sockets([]string{"169.254.77.2:443", "169.254.77.3:443"}, []string{"7001>10.0.1.2", "7002>10.0.2.2"})
	_ = saveClusterConfig(ClusterConfig{Version: 2, NodeID: "hub-a", Health: LBHealth{}.norm(),
		Pools: []LBPool{{Port: 443, Proto: "tcp", Mode: lbBalance, Members: []LBMember{{Link: 1, Weight: 1}, {Link: 2, Weight: 1}}}}})
	now := time.Now()
	clusterTick(now)
	clusterTick(now.Add(time.Second))
	if !strings.Contains(f.lastRules(), "statistic") {
		t.Fatalf("not balanced:\n%s", f.lastRules())
	}
	restarts := len(f.bindLog)
	c := loadClusterConfig()
	c.Pools[0].Disabled = true
	_ = saveClusterConfig(c)
	clusterTick(now.Add(10 * time.Second))
	clusterTick(now.Add(11 * time.Second))
	r := f.lastRules()
	if len(f.bindLog) != restarts || f.binds["frps-1"] == "" || f.binds["frps-2"] == "" {
		t.Fatalf("relays moved: %v", f.bindLog)
	}
	if strings.Contains(r, "HLB-T443") || !strings.Contains(r, "--dport 443 -j DNAT --to-destination 169.254.77.2\n") {
		t.Fatalf("disabled pool must pass through to link 1:\n%s", r)
	}
}

// A second tunnel may take a port a pool covers (Setup and Edit Peer use the
// same check); a port with no pool stays one tunnel's.
func TestPeerPortClashAllowsPooledPorts(t *testing.T) {
	newClusterFixture(t, true)
	peers := `{"peers": [{"id": 1, "name": "de", "ports": [443, 2083]}]}`
	if err := os.WriteFile(peersFile(), []byte(peers), 0o600); err != nil {
		t.Fatal(err)
	}
	if c := peerPortClash([]int{443}, -1); c != "443 (peer de)" {
		t.Fatalf("no pool yet: %q", c)
	}
	c := defaultClusterConfig()
	c.Pools = []LBPool{{Port: 443, Proto: "tcp", Mode: lbFailover, Members: []LBMember{{Link: 1, Weight: 1}}}}
	_ = saveClusterConfig(c)
	if c := peerPortClash([]int{443}, -1); c != "" {
		t.Fatalf("pooled port refused: %q", c)
	}
	if c := peerPortClash([]int{443, 2083}, -1); c != "2083 (peer de)" {
		t.Fatalf("a port with no pool must still clash: %q", c)
	}
}
