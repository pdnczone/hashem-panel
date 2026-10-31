package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// nodeTunFake stands in for the servers' APIs: each has a plan, and every
// call is logged as "<id> <METHOD> <path>".
type nodeTunFake struct {
	mu    sync.Mutex
	plans map[int]*setupPlan
	calls []string
	fail  map[string]int // "<id> <path>" -> status to answer
	body  map[string]map[string]any
}

func (f *nodeTunFake) call(_ context.Context, id int, method, path string, body any) (int, []byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, _, _ := strings.Cut(path, "?")
	f.calls = append(f.calls, fmt.Sprintf("%d %s %s", id, method, p))
	if body != nil {
		b, _ := json.Marshal(body)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		f.body[fmt.Sprintf("%d %s", id, p)] = m
	}
	if st := f.fail[fmt.Sprintf("%d %s", id, p)]; st != 0 {
		return st, []byte(`{"error_code":"E-TEST","error":"failed on purpose"}`), nil
	}
	pl := f.plans[id]
	switch p {
	case "/api/setup/plan":
		b, _ := json.Marshal(pl)
		return 200, b, nil
	case "/api/setup":
		m := f.body[fmt.Sprintf("%d %s", id, p)]
		if m["role"] == "foreign" {
			pl.Exists, pl.Side = true, "foreign"
			pl.Uplinks = append(pl.Uplinks, setupPlanUplink{Hub: 1, IranPub: "198.51.100.1"})
			return 200, []byte(`{"status":"ok"}`), nil
		}
		id := 0 // the first tunnel: no peer record (setup_plan.go)
		if m["role"] == "add-peer" {
			id = 3
		}
		pl.Exists, pl.Side = true, "iran"
		pl.Peers = append(pl.Peers, setupPlanPeer{ID: id, RemotePub: m["remote_public"].(string)})
		return 200, []byte(`{"status":"ok","bundle":"hsh1_test"}`), nil
	case "/api/cluster/join-hub":
		pl.Uplinks = append(pl.Uplinks, setupPlanUplink{Hub: len(pl.Uplinks) + 1, IranPub: "198.51.100.1"})
		return 200, []byte(`{"status":"ok"}`), nil
	case "/api/action", "/api/cluster/leave-hub":
		return 200, []byte(`{"status":"ok"}`), nil
	}
	return 404, []byte(`{"error_code":"E-NODE-06","error":"not here"}`), nil
}

func (f *nodeTunFake) seen() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Join(f.calls, "\n")
}

// nodeTunTest: this panel is a central with nodes 1 and 2 online; server 1
// is an Iran server, server 2 a fresh foreign one.
func nodeTunTest(t *testing.T) *nodeTunFake {
	t.Helper()
	nodeTestInvite(t, nodeTestCentral(t), "x")
	nodesMu.Lock()
	nodesF.Nodes = append(nodesF.Nodes, nodeRecord{ID: 1, Name: `Iran "1"`, Key: "K1"}, nodeRecord{ID: 2, Name: "DE", Key: "K2"})
	for _, id := range []int{1, 2} {
		a, b := net.Pipe()
		t.Cleanup(func() { _ = b.Close() })
		nodeSessions[id] = &nodeSession{id: id, conn: &nodeConn{c: a}, done: make(chan struct{})}
	}
	nodesMu.Unlock()
	f := &nodeTunFake{fail: map[string]int{}, body: map[string]map[string]any{}, plans: map[int]*setupPlan{
		0: {Public: "203.0.113.9", Side: "", GreUsed: []string{}},
		1: {Public: "198.51.100.1", Side: "", RelayPort: 7001, GreUsed: []string{"10.10.10.2"}},
		2: {Public: "192.0.2.7", Side: "", RelayPort: 7001, GreUsed: []string{"10.11.0.1"}},
	}}
	old := nodeAPIFn
	nodeAPIFn = f.call
	t.Cleanup(func() {
		nodeAPIFn = old
		nodeTun.Lock()
		nodeTun.jobs, nodeTun.busy = nil, nil
		nodeTun.Unlock()
	})
	return f
}

func nodeTunWait(t *testing.T, id int) nodeTunJob {
	t.Helper()
	for i := 0; i < 200; i++ {
		for _, j := range nodeTunJobsView() {
			if j.ID == id && j.State != "running" {
				return j
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the job did not end")
	return nodeTunJob{}
}

func TestNodeTunDraft(t *testing.T) {
	f := nodeTunTest(t)
	q := nodeTunReq{Server: 1, Client: 2, Engine: "frp", Ports: "443, 2083"}
	if err := q.check(); err != nil {
		t.Fatal(err)
	}
	d, err := nodeTunDraftFor(context.Background(), q)
	if err != nil || len(d.Problems) > 0 {
		t.Fatalf("%v %v", err, d.Problems)
	}
	// 10.10.10.x is taken on the server, 10.11.0.1 on the client
	if d.ServerRole != "iran" || d.ClientMode != "foreign" || d.LocalGre != "10.12.0.2" || d.PeerGre != "10.12.0.1" || d.FrpPort != 7001 {
		t.Fatalf("draft: %+v", d)
	}
	f.plans[2].Uplinks = []setupPlanUplink{{Hub: 1, IranPub: "203.0.113.50"}}
	f.plans[1].Peers = []setupPlanPeer{{ID: 1, RemotePub: "203.0.113.50"}}
	f.plans[1].Clashes = map[string]string{"443": "peer 1"}
	d, _ = nodeTunDraftFor(context.Background(), q)
	if d.ServerRole != "add-peer" || d.ClientMode != "join-hub" || len(d.Problems) != 1 || !strings.Contains(d.Problems[0], "443") {
		t.Fatalf("draft with tunnels: %+v", d)
	}
	// the wrong way round, and an IPv6 address over GRE
	d, _ = nodeTunDraftFor(context.Background(), nodeTunReq{Server: 2, Client: 1, Engine: "frp", Ports: "443"})
	if len(d.Problems) < 2 {
		t.Fatalf("server and client swapped: %v", d.Problems)
	}
	f.plans[0].Public = "192.0.2.7"
	if d, _ = nodeTunDraftFor(context.Background(), nodeTunReq{Server: 0, Client: 2, Engine: "frp", Ports: "443"}); !strings.Contains(strings.Join(d.Problems, ";"), "same public address") {
		t.Fatalf("the same server twice: %v", d.Problems)
	}
	f.plans[0].Public = "2001:db8::1"
	d, _ = nodeTunDraftFor(context.Background(), nodeTunReq{Server: 0, Client: 2, Engine: "frp", Ports: "443"})
	if !strings.Contains(strings.Join(d.Problems, ";"), "IPv4") {
		t.Fatalf("IPv6 over GRE: %v", d.Problems)
	}
	for _, bad := range []nodeTunReq{{Server: 1, Client: 1}, {Server: 1, Client: 9}, {Server: 1, Client: 2, Engine: "x"},
		{Server: 1, Client: 2, Ports: "443; rm -rf /"}, {Server: 1, Client: 2, Transport: "TCP$"}} {
		if bad.check() == nil {
			t.Errorf("accepted: %+v", bad)
		}
	}
}

func TestNodeTunCreate(t *testing.T) {
	f := nodeTunTest(t)
	q := nodeTunReq{Server: 1, Client: 2, Engine: "frp", Ports: "443"}
	id, err := nodeTunStart("create", 1, 2, func(j *nodeTunJob) error { return nodeTunCreate(context.Background(), j, q) })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := nodeTunStart("create", 2, 0, func(*nodeTunJob) error { return nil }); err == nil {
		t.Fatal("a second job on a busy server")
	}
	if j := nodeTunWait(t, id); j.State != "done" {
		t.Fatalf("job: %+v", j)
	}
	want := "1 GET /api/setup/plan\n2 GET /api/setup/plan\n1 POST /api/setup\n2 POST /api/setup"
	if got := f.seen(); got != want {
		t.Fatalf("calls:\n%s\nwant:\n%s", got, want)
	}
	s, c := f.body["1 /api/setup"], f.body["2 /api/setup"]
	if s["role"] != "iran" || s["remote_public"] != "192.0.2.7" || s["local_public"] != "198.51.100.1" || s["name"] != "Iran 1" && s["name"] != "DE" {
		t.Fatalf("server end: %v", s)
	}
	if s["name"] != "DE" || c["role"] != "foreign" || c["token"] != "hsh1_test" || c["local_public"] != "192.0.2.7" || c["name"] != "Iran 1" {
		t.Fatalf("client end: %v / %v", s, c)
	}
	// the pair is now listed, and removed client end first
	links, errs := nodeTunLinks(context.Background())
	if len(errs) > 0 || len(links) != 1 || links[0].Server != 1 || links[0].Client != 2 || links[0].PeerID != 0 || links[0].Hub != 1 {
		t.Fatalf("links: %+v %v", links, errs)
	}
	f.calls = nil
	id, _ = nodeTunStart("remove", 1, 2, func(j *nodeTunJob) error {
		return nodeTunRemove(context.Background(), j, nodeTunRemoveReq{Server: 1, Client: 2, PeerID: 0, Hub: 1})
	})
	if j := nodeTunWait(t, id); j.State != "done" {
		t.Fatalf("remove: %+v", j)
	}
	got := f.seen()
	if !strings.HasSuffix(got, "2 POST /api/action\n1 POST /api/action") || f.body["1 /api/action"]["peer_id"] != float64(0) {
		t.Fatalf("remove calls:\n%s", got)
	}
	// a pair that is not there is not removed
	f.calls = nil
	id, _ = nodeTunStart("remove", 1, 2, func(j *nodeTunJob) error {
		return nodeTunRemove(context.Background(), j, nodeTunRemoveReq{Server: 1, Client: 2, PeerID: 9, Hub: 1})
	})
	if j := nodeTunWait(t, id); j.State != "failed" || strings.Contains(f.seen(), "POST") {
		t.Fatalf("a wrong pair: %+v\n%s", j, f.seen())
	}
}

func TestNodeTunRollback(t *testing.T) {
	f := nodeTunTest(t)
	f.plans[1].Exists, f.plans[1].Side = true, "iran"
	f.plans[1].Peers = []setupPlanPeer{{ID: 1, RemotePub: "203.0.113.50"}}
	f.fail["2 /api/setup"] = 500
	q := nodeTunReq{Server: 1, Client: 2, Engine: "frp", Ports: "443"}
	id, _ := nodeTunStart("create", 1, 2, func(j *nodeTunJob) error { return nodeTunCreate(context.Background(), j, q) })
	j := nodeTunWait(t, id)
	if j.State != "failed" || !strings.Contains(j.Log, "failed on purpose") || !strings.Contains(j.Log, "removed again") {
		t.Fatalf("job: %+v", j)
	}
	got := f.seen()
	if !strings.HasSuffix(got, "2 POST /api/setup\n2 POST /api/action\n1 POST /api/action") || f.body["1 /api/action"]["peer_id"] != float64(3) {
		t.Fatalf("rollback calls:\n%s", got)
	}
	// the rollback fails too: the server end is listed as left over
	f.calls = nil
	f.plans[1].Peers = []setupPlanPeer{{ID: 1, RemotePub: "203.0.113.50"}}
	f.fail["1 /api/action"] = 500
	id, _ = nodeTunStart("create", 1, 2, func(j *nodeTunJob) error { return nodeTunCreate(context.Background(), j, q) })
	if j := nodeTunWait(t, id); j.State != "failed" || !strings.Contains(j.Log, "left over") {
		t.Fatalf("job: %+v", j)
	}
	nodesMu.Lock()
	left := append([]nodeTunLeft{}, nodesF.Left...)
	nodesMu.Unlock()
	if len(left) != 1 || left[0].Server != 1 || left[0].PeerID != 3 || left[0].ClientIP != "192.0.2.7" {
		t.Fatalf("left over: %+v", left)
	}
	// removing it later: the server end, then the record
	delete(f.fail, "1 /api/action")
	id, _ = nodeTunStart("remove", 1, 2, func(j *nodeTunJob) error {
		return nodeTunRemove(context.Background(), j, nodeTunRemoveReq{Server: 1, Client: 2, PeerID: 3, Left: left[0].ID})
	})
	if j := nodeTunWait(t, id); j.State != "done" {
		t.Fatalf("remove left over: %+v", j)
	}
	nodesMu.Lock()
	n := len(nodesF.Left)
	nodesMu.Unlock()
	if n != 0 {
		t.Fatal("the left-over record stayed")
	}
}

// The client's first tunnel is not removed while it also serves other hubs.
func TestNodeTunRemoveFirstWithHubs(t *testing.T) {
	f := nodeTunTest(t)
	f.plans[1].Peers = []setupPlanPeer{{ID: 3, RemotePub: "192.0.2.7"}}
	f.plans[2].Uplinks = []setupPlanUplink{{Hub: 1, IranPub: "198.51.100.1"}, {Hub: 2, IranPub: "203.0.113.50"}}
	id, _ := nodeTunStart("remove", 1, 2, func(j *nodeTunJob) error {
		return nodeTunRemove(context.Background(), j, nodeTunRemoveReq{Server: 1, Client: 2, PeerID: 3, Hub: 1})
	})
	if j := nodeTunWait(t, id); j.State != "failed" || strings.Contains(f.seen(), "POST") {
		t.Fatalf("job: %+v\n%s", j, f.seen())
	}
	// a joined hub goes with leave-hub
	f.plans[2].Uplinks = []setupPlanUplink{{Hub: 1, IranPub: "203.0.113.50"}, {Hub: 2, IranPub: "198.51.100.1"}}
	f.calls = nil
	id, _ = nodeTunStart("remove", 1, 2, func(j *nodeTunJob) error {
		return nodeTunRemove(context.Background(), j, nodeTunRemoveReq{Server: 1, Client: 2, PeerID: 3, Hub: 2})
	})
	if j := nodeTunWait(t, id); j.State != "done" || !strings.Contains(f.seen(), "2 POST /api/cluster/leave-hub") {
		t.Fatalf("leave-hub: %+v\n%s", j, f.seen())
	}
}

func TestSetupPlan(t *testing.T) {
	old, oldInfo, oldListen := configDir, nodeInfoFn, setupPlanListening
	configDir = t.TempDir()
	t.Cleanup(func() { configDir, nodeInfoFn, setupPlanListening = old, oldInfo, oldListen })
	nodeInfoFn = func() nodeInfo { return nodeInfo{PublicIP: "198.51.100.1", Side: "iran"} }
	setupPlanListening = func(port int) bool { return port == 7001 }
	peers := `{"peers":[{"id":2,"name":"de","remote_pub":"192.0.2.7","frp_port":7002,"local_gre":"10.11.0.2","peer_gre":"10.11.0.1","ports":[443],"gre_if":"gre-t2","frps_svc":"frps-2"}]}`
	if err := os.WriteFile(filepath.Join(configDir, "peers.json"), []byte(peers), 0600); err != nil {
		t.Fatal(err)
	}
	p := buildSetupPlan("443, 8443, x")
	if p.Public != "198.51.100.1" || len(p.Peers) != 1 || p.Peers[0].ID != 2 || p.Peers[0].RemotePub != "192.0.2.7" {
		t.Fatalf("plan: %+v", p)
	}
	// 7001 listens, 7002 is peer 2's control port
	if p.RelayPort != 7003 {
		t.Fatalf("relay port: %d", p.RelayPort)
	}
	if p.Clashes["443"] == "" || p.Clashes["8443"] != "" {
		t.Fatalf("clashes: %v", p.Clashes)
	}
	gre := strings.Join(p.GreUsed, ",")
	if !strings.Contains(gre, "10.11.0.2") || !strings.Contains(gre, "10.11.0.1") {
		t.Fatalf("gre used: %v", p.GreUsed)
	}
	hubs := `{"hubs":[{"id":1,"iran_pub":"203.0.113.5","engine":"frp"},{"id":2,"iran_pub":"203.0.113.6","iran_gre":"10.12.0.2"}]}`
	_ = os.WriteFile(filepath.Join(configDir, "hubs.json"), []byte(hubs), 0600)
	joinedMu.Lock()
	joinedAt = time.Time{}
	joinedMu.Unlock()
	if p := buildSetupPlan(""); len(p.Uplinks) != 2 || p.Uplinks[1].Hub != 2 || p.Uplinks[1].IranPub != "203.0.113.6" {
		t.Fatalf("uplinks: %+v", p.Uplinks)
	}
}
