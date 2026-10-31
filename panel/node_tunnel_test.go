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
	mu     sync.Mutex
	plans  map[int]*setupPlan
	calls  []string
	fail   map[string]string // "<id> <path>" -> error code to answer with
	body   map[string]map[string]any
	bundle func(m map[string]any) string // the server end's bundle (default: what was asked)
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
	pl := f.plans[id]
	if code := f.fail[fmt.Sprintf("%d %s", id, p)]; code != "" {
		if code == "E-INSTALL-02" && p == "/api/setup" && f.body[fmt.Sprintf("%d %s", id, p)]["role"] == "add-peer" {
			// the installer ran half-way: the peer record is there
			pl.Peers = append(pl.Peers, setupPlanPeer{ID: 3, RemotePub: f.body[fmt.Sprintf("%d %s", id, p)]["remote_public"].(string)})
		}
		return 500, []byte(`{"error_code":"` + code + `","error":"failed on purpose"}`), nil
	}
	switch p {
	case "/api/setup/plan":
		cp := *pl
		if _, q, _ := strings.Cut(path, "?"); strings.HasPrefix(q, "proof=") { // every tunnel here shares one token
			n := strings.TrimPrefix(q, "proof=")
			cp.Peers = append([]setupPlanPeer{}, pl.Peers...)
			cp.Uplinks = append([]setupPlanUplink{}, pl.Uplinks...)
			for i := range cp.Peers {
				cp.Peers[i].Proof = setupPlanProof("tok", n)
			}
			for i := range cp.Uplinks {
				cp.Uplinks[i].Proof = setupPlanProof("tok", n)
			}
		}
		b, _ := json.Marshal(cp)
		return 200, b, nil
	case "/api/setup":
		m := f.body[fmt.Sprintf("%d %s", id, p)]
		if m["role"] == "foreign" {
			pl.Exists, pl.Side = true, "foreign"
			pl.Uplinks = append(pl.Uplinks, setupPlanUplink{Hub: 1, IranPub: "198.51.100.1"})
			return 200, []byte(`{"status":"ok"}`), nil
		}
		pid := 0 // the first tunnel: no peer record (setup_plan.go)
		if m["role"] == "add-peer" {
			pid = 3
		}
		pl.Exists, pl.Side = true, "iran"
		pl.Peers = append(pl.Peers, setupPlanPeer{ID: pid, RemotePub: m["remote_public"].(string)})
		bundle := MakeBundle(fmt.Sprint(m["local_public"]), int(m["frp_port"].(float64)), fmt.Sprint(m["local_gre"]), fmt.Sprint(m["peer_gre"]),
			"tok123", parsePorts(fmt.Sprint(m["ports"])))
		if f.bundle != nil {
			bundle = f.bundle(m)
		}
		b, _ := json.Marshal(map[string]string{"status": "ok", "bundle": bundle})
		return 200, b, nil
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

func (f *nodeTunFake) reset() {
	f.mu.Lock()
	f.calls = nil
	f.mu.Unlock()
}

// nodeTunTest: this panel is a central with nodes 1 and 2 online; server 1
// is an Iran server, server 2 a fresh foreign one; both have Pro.
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
	pro := func() map[string]bool { return map[string]bool{"backhaul": true, "cluster": true} }
	f := &nodeTunFake{fail: map[string]string{}, body: map[string]map[string]any{}, plans: map[int]*setupPlan{
		0: {Public: "203.0.113.9", GreUsed: []string{}, Pro: pro()},
		1: {Public: "198.51.100.1", RelayPort: 7001, GreUsed: []string{"10.10.10.2"}, Pro: pro()},
		2: {Public: "192.0.2.7", RelayPort: 7001, GreUsed: []string{"10.11.0.1"}, Pro: pro()},
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
	for i := 0; i < 300; i++ {
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

func nodeTunRun(t *testing.T, kind string, server, client int, fn func(j *nodeTunJob) error) nodeTunJob {
	t.Helper()
	id, err := nodeTunStart(kind, server, client, fn)
	if err != nil {
		t.Fatal(err)
	}
	return nodeTunWait(t, id)
}

func nodeTunCreateRun(t *testing.T, q nodeTunReq) nodeTunJob {
	return nodeTunRun(t, "create", q.Server, q.Client, func(j *nodeTunJob) error { return nodeTunCreate(context.Background(), j, q) })
}

func nodeTunLeftNow() []nodeTunLeft {
	nodesMu.Lock()
	defer nodesMu.Unlock()
	return append([]nodeTunLeft{}, nodesF.Left...)
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
	// a client already dialling this server; Cluster or Backhaul without a license
	f.plans[1].Clashes = nil
	f.plans[2].Uplinks = append(f.plans[2].Uplinks, setupPlanUplink{Hub: 2, IranPub: "198.51.100.1"})
	f.plans[2].Pro["cluster"], f.plans[1].Pro["backhaul"] = false, false
	d, _ = nodeTunDraftFor(context.Background(), nodeTunReq{Server: 1, Client: 2, Engine: "backhaul", Ports: "443"})
	all := strings.Join(d.Problems, ";")
	if !strings.Contains(all, "already dials") || !strings.Contains(all, "Cluster") || !strings.Contains(all, "Backhaul is a Pro feature") || d.LocalGre != "" {
		t.Fatalf("license and dial problems: %v (%+v)", d.Problems, d)
	}
	// a control port that is taken
	f.plans[1].RelayTaken = "peer 1"
	d, _ = nodeTunDraftFor(context.Background(), nodeTunReq{Server: 1, Client: 2, Engine: "frp", Ports: "443", FrpPort: 7002})
	if !strings.Contains(strings.Join(d.Problems, ";"), "control port 7002") {
		t.Fatalf("a taken control port: %v", d.Problems)
	}
	// the wrong way round, the same server twice, IPv6 over GRE
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
		{Server: 1, Client: 2, Ports: "443; rm -rf /"}, {Server: 1, Client: 2, Transport: "TCP$"},
		{Server: 1, Client: 2, Engine: "frp", Transport: "tcpmux", Ports: "443"}} {
		if bad.check() == nil {
			t.Errorf("accepted: %+v", bad)
		}
	}
	// labels: no quotes or $, and join-hub's 32 bytes on a rune boundary
	nodesMu.Lock()
	nodesF.Nodes[len(nodesF.Nodes)-1].Name = "سرور آلمان شماره یک $x"
	nodesMu.Unlock()
	if l := nodeTunLabel(2, 32); len(l) > 32 || strings.ContainsAny(l, "$") || !utf8Valid(l) {
		t.Fatalf("join-hub label: %q (%d bytes)", l, len(l))
	}
	if l := nodeTunLabel(1, 40); l != "Iran 1" {
		t.Fatalf("label: %q", l)
	}
}

func utf8Valid(s string) bool { return strings.ToValidUTF8(s, "?") == s }

func TestNodeTunCreate(t *testing.T) {
	f := nodeTunTest(t)
	q := nodeTunReq{Server: 1, Client: 2, Engine: "frp", Ports: "443"}
	if j := nodeTunCreateRun(t, q); j.State != "done" {
		t.Fatalf("job: %+v", j)
	}
	if _, err := nodeTunStart("create", 1, 0, func(*nodeTunJob) error { time.Sleep(50 * time.Millisecond); return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := nodeTunStart("create", 1, 2, func(*nodeTunJob) error { return nil }); err == nil {
		t.Fatal("a second job on a busy server")
	}
	time.Sleep(100 * time.Millisecond)
	want := "1 GET /api/setup/plan\n2 GET /api/setup/plan\n1 POST /api/setup\n1 GET /api/setup/plan\n2 POST /api/setup"
	if got := f.seen(); got != want {
		t.Fatalf("calls:\n%s\nwant:\n%s", got, want)
	}
	s, c := f.body["1 /api/setup"], f.body["2 /api/setup"]
	if s["role"] != "iran" || s["remote_public"] != "192.0.2.7" || s["local_public"] != "198.51.100.1" || s["name"] != "DE" {
		t.Fatalf("server end: %v", s)
	}
	if c["role"] != "foreign" || !strings.HasPrefix(fmt.Sprint(c["token"]), "hsh1_198.51.100.1_7001_") || c["local_public"] != "192.0.2.7" || c["name"] != "Iran 1" {
		t.Fatalf("client end: %v", c)
	}
	// the pair is now listed, and removed client end first
	links, errs := nodeTunLinks(context.Background())
	if len(errs) > 0 || len(links) != 1 || links[0].Server != 1 || links[0].Client != 2 || links[0].PeerID != 0 || links[0].Hub != 1 {
		t.Fatalf("links: %+v %v", links, errs)
	}
	f.reset()
	if j := nodeTunRun(t, "remove", 1, 2, func(j *nodeTunJob) error {
		return nodeTunRemove(context.Background(), j, nodeTunRemoveReq{Server: 1, Client: 2, PeerID: 0, Hub: 1})
	}); j.State != "done" {
		t.Fatalf("remove: %+v", j)
	}
	got := f.seen()
	if !strings.HasSuffix(got, "2 POST /api/action\n1 POST /api/action") || f.body["1 /api/action"]["peer_id"] != float64(0) {
		t.Fatalf("remove calls:\n%s", got)
	}
	// a pair that is not there is not removed
	f.reset()
	if j := nodeTunRun(t, "remove", 1, 2, func(j *nodeTunJob) error {
		return nodeTunRemove(context.Background(), j, nodeTunRemoveReq{Server: 1, Client: 2, PeerID: 9, Hub: 1})
	}); j.State != "failed" || strings.Contains(f.seen(), "POST") {
		t.Fatalf("a wrong pair: %+v\n%s", j, f.seen())
	}
}

// A node whose plan claims another server's address cannot get a real
// tunnel of that server listed (or removed) under its name.
func TestNodeTunLinksClaimedTwice(t *testing.T) {
	f := nodeTunTest(t)
	// a real tunnel 1 -> 2, and node 3 claiming to be server 2
	f.plans[1].Peers = []setupPlanPeer{{ID: 4, RemotePub: "192.0.2.7"}}
	f.plans[2].Uplinks = []setupPlanUplink{{Hub: 1, IranPub: "198.51.100.1"}}
	nodesMu.Lock()
	nodesF.Nodes = append(nodesF.Nodes, nodeRecord{ID: 3, Name: "evil", Key: "K3"})
	a, b := net.Pipe()
	t.Cleanup(func() { _ = b.Close() })
	nodeSessions[3] = &nodeSession{id: 3, conn: &nodeConn{c: a}, done: make(chan struct{})}
	nodesMu.Unlock()
	f.plans[3] = &setupPlan{Public: "192.0.2.7", Uplinks: []setupPlanUplink{{Hub: 1, IranPub: "198.51.100.1"}}}
	links, errs := nodeTunLinks(context.Background())
	if len(links) != 0 || len(errs) != 1 || !strings.Contains(errs[0], "192.0.2.7") {
		t.Fatalf("links %+v errs %v", links, errs)
	}
	if j := nodeTunRun(t, "remove", 1, 3, func(j *nodeTunJob) error {
		return nodeTunRemove(context.Background(), j, nodeTunRemoveReq{Server: 1, Client: 3, PeerID: 4, Hub: 1})
	}); j.State != "failed" || strings.Contains(f.seen(), "POST") {
		t.Fatalf("removed through a claimed address: %+v\n%s", j, f.seen())
	}
}

// A server end whose bundle is not what was planned is not given to the
// client, and is removed again.
func TestNodeTunBundleChecked(t *testing.T) {
	f := nodeTunTest(t)
	f.bundle = func(m map[string]any) string {
		return MakeBundle("203.0.113.66", 7001, fmt.Sprint(m["local_gre"]), fmt.Sprint(m["peer_gre"]), "tok", []int{443})
	}
	j := nodeTunCreateRun(t, nodeTunReq{Server: 1, Client: 2, Engine: "frp", Ports: "443"})
	if j.State != "failed" || !strings.Contains(j.Log, "names 203.0.113.66") || strings.Contains(f.seen(), "2 POST") ||
		!strings.HasSuffix(f.seen(), "1 POST /api/action") {
		t.Fatalf("job: %+v\n%s", j, f.seen())
	}
	f.bundle = func(m map[string]any) string {
		return MakeBundle(fmt.Sprint(m["local_public"]), 7001, fmt.Sprint(m["local_gre"]), fmt.Sprint(m["peer_gre"]), "tok", []int{443, 22})
	}
	f.plans[1].Peers, f.plans[1].Exists = nil, false
	if j := nodeTunCreateRun(t, nodeTunReq{Server: 1, Client: 2, Engine: "frp", Ports: "443"}); j.State != "failed" || !strings.Contains(j.Log, "other ports") {
		t.Fatalf("other ports: %+v", j)
	}
}

func TestNodeTunRollback(t *testing.T) {
	f := nodeTunTest(t)
	f.plans[1].Exists, f.plans[1].Side = true, "iran"
	f.plans[1].Peers = []setupPlanPeer{{ID: 1, RemotePub: "203.0.113.50"}}
	q := nodeTunReq{Server: 1, Client: 2, Engine: "frp", Ports: "443"}
	// refused before installing (no license, a validation error): the
	// client is not touched, the server end is removed again
	f.fail["2 /api/setup"] = "E-LIC-01"
	j := nodeTunCreateRun(t, q)
	if j.State != "failed" || !strings.Contains(j.Log, "failed on purpose") || !strings.Contains(j.Log, "removed again") {
		t.Fatalf("job: %+v", j)
	}
	if got := f.seen(); !strings.HasSuffix(got, "2 POST /api/setup\n1 POST /api/action") || f.body["1 /api/action"]["peer_id"] != float64(3) {
		t.Fatalf("rollback calls:\n%s", got)
	}
	// the client's installer ran and failed: its half-made end is cleaned too
	f.reset()
	f.plans[1].Peers = []setupPlanPeer{{ID: 1, RemotePub: "203.0.113.50"}}
	f.fail["2 /api/setup"] = "E-INSTALL-02"
	if j := nodeTunCreateRun(t, q); j.State != "failed" || !strings.HasSuffix(f.seen(), "2 POST /api/setup\n2 POST /api/action\n1 POST /api/action") {
		t.Fatalf("install failed on the client: %+v\n%s", j, f.seen())
	}
	// the rollback fails too: the server end is listed as left over, by the client's address
	f.reset()
	f.plans[1].Peers = []setupPlanPeer{{ID: 1, RemotePub: "203.0.113.50"}}
	f.fail["1 /api/action"] = "E-ACTION-03"
	if j := nodeTunCreateRun(t, q); j.State != "failed" || !strings.Contains(j.Log, "left over") {
		t.Fatalf("job: %+v", j)
	}
	left := nodeTunLeftNow()
	if len(left) != 1 || left[0].Server != 1 || left[0].ServerRole != "add-peer" || left[0].ClientIP != "192.0.2.7" {
		t.Fatalf("left over: %+v", left)
	}
	// removing it later: found again on the server (peer 3), then the record goes
	delete(f.fail, "1 /api/action")
	f.reset()
	if j := nodeTunRun(t, "remove", 1, 2, func(j *nodeTunJob) error {
		return nodeTunRemove(context.Background(), j, nodeTunRemoveReq{Left: left[0].ID})
	}); j.State != "done" || f.body["1 /api/action"]["peer_id"] != float64(3) {
		t.Fatalf("remove left over: %+v %v", j, f.body["1 /api/action"])
	}
	if len(nodeTunLeftNow()) != 0 {
		t.Fatal("the left-over record stayed")
	}
}

// The server's installer failed half-way: the half-made end is listed.
func TestNodeTunServerHalfMade(t *testing.T) {
	f := nodeTunTest(t)
	f.plans[1].Exists, f.plans[1].Side = true, "iran"
	f.plans[1].Peers = []setupPlanPeer{{ID: 1, RemotePub: "203.0.113.50"}}
	f.fail["1 /api/setup"] = "E-INSTALL-02"
	if j := nodeTunCreateRun(t, nodeTunReq{Server: 1, Client: 2, Engine: "frp", Ports: "443"}); j.State != "failed" || !strings.Contains(j.Log, "left over") {
		t.Fatalf("job: %+v", j)
	}
	if l := nodeTunLeftNow(); len(l) != 1 || l[0].ClientIP != "192.0.2.7" {
		t.Fatalf("left: %+v", l)
	}
	// refused outright (a validation error): nothing is listed
	f.fail["1 /api/setup"] = "E-SETUP-03"
	f.plans[1].Peers = []setupPlanPeer{{ID: 1, RemotePub: "203.0.113.50"}}
	nodesMu.Lock()
	nodesF.Left = nil
	nodesMu.Unlock()
	if j := nodeTunCreateRun(t, nodeTunReq{Server: 1, Client: 2, Engine: "frp", Ports: "443"}); j.State != "failed" || len(nodeTunLeftNow()) != 0 {
		t.Fatalf("refused: %+v %+v", j, nodeTunLeftNow())
	}
}

// A left-over record never removes a first tunnel it did not make, and one
// that is gone from its server is only forgotten.
func TestNodeTunLeftSafe(t *testing.T) {
	f := nodeTunTest(t)
	nodeTunKeep(nodeTunReq{Server: 1, Client: 2}, "add-peer", "192.0.2.7", "x")
	nodeTunKeep(nodeTunReq{Server: 1, Client: 2}, "add-peer", "192.0.2.99", "y")
	left := nodeTunLeftNow()
	// the address now belongs to the server's first tunnel (id 0)
	f.plans[1].Peers = []setupPlanPeer{{ID: 0, RemotePub: "192.0.2.7"}}
	for _, l := range left {
		f.reset()
		if j := nodeTunRun(t, "remove", 1, 2, func(j *nodeTunJob) error {
			return nodeTunRemove(context.Background(), j, nodeTunRemoveReq{Left: l.ID})
		}); j.State != "failed" || strings.Contains(f.seen(), "POST") {
			t.Fatalf("left %d: %+v\n%s", l.ID, j, f.seen())
		}
	}
	// ids are never reused
	nodesMu.Lock()
	nodesF.Left = nil
	nodesMu.Unlock()
	nodeTunKeep(nodeTunReq{Server: 1, Client: 2}, "add-peer", "192.0.2.7", "z")
	if l := nodeTunLeftNow(); l[0].ID <= left[1].ID {
		t.Fatalf("a left-over id reused: %d", l[0].ID)
	}
}

// The client's first tunnel is not removed while it also serves other hubs.
func TestNodeTunRemoveFirstWithHubs(t *testing.T) {
	f := nodeTunTest(t)
	f.plans[1].Peers = []setupPlanPeer{{ID: 3, RemotePub: "192.0.2.7"}}
	f.plans[2].Uplinks = []setupPlanUplink{{Hub: 1, IranPub: "198.51.100.1"}, {Hub: 2, IranPub: "203.0.113.50"}}
	if j := nodeTunRun(t, "remove", 1, 2, func(j *nodeTunJob) error {
		return nodeTunRemove(context.Background(), j, nodeTunRemoveReq{Server: 1, Client: 2, PeerID: 3, Hub: 1})
	}); j.State != "failed" || strings.Contains(f.seen(), "POST") {
		t.Fatalf("job: %+v\n%s", j, f.seen())
	}
	// a joined hub goes with leave-hub
	f.plans[2].Uplinks = []setupPlanUplink{{Hub: 1, IranPub: "203.0.113.50"}, {Hub: 2, IranPub: "198.51.100.1"}}
	f.reset()
	if j := nodeTunRun(t, "remove", 1, 2, func(j *nodeTunJob) error {
		return nodeTunRemove(context.Background(), j, nodeTunRemoveReq{Server: 1, Client: 2, PeerID: 3, Hub: 2})
	}); j.State != "done" || !strings.Contains(f.seen(), "2 POST /api/cluster/leave-hub") {
		t.Fatalf("leave-hub: %+v\n%s", j, f.seen())
	}
	// the server end then fails: listed as left over
	f.fail["1 /api/action"] = "E-ACTION-03"
	if j := nodeTunRun(t, "remove", 1, 2, func(j *nodeTunJob) error {
		return nodeTunRemove(context.Background(), j, nodeTunRemoveReq{Server: 1, Client: 2, PeerID: 3, Hub: 2})
	}); j.State != "failed" || len(nodeTunLeftNow()) != 1 {
		t.Fatalf("server end failed: %+v %+v", j, nodeTunLeftNow())
	}
}

// An older panel answers the plan path with its page.
func TestNodeTunPlanOlder(t *testing.T) {
	nodeTunTest(t)
	nodeAPIFn = func(context.Context, int, string, string, any) (int, []byte, error) {
		return 200, []byte("<!doctype html>"), nil
	}
	if _, err := nodeTunPlan(context.Background(), 1, "", 0); err == nil || !strings.Contains(err.Error(), "older Hashem") {
		t.Fatalf("an older node: %v", err)
	}
}

func TestSetupPlan(t *testing.T) {
	old, oldInfo, oldListen, oldFT := configDir, nodeInfoFn, setupPlanListening, firstTunnelInfo
	configDir = t.TempDir()
	t.Cleanup(func() { configDir, nodeInfoFn, setupPlanListening, firstTunnelInfo = old, oldInfo, oldListen, oldFT })
	nodeInfoFn = func() nodeInfo { return nodeInfo{PublicIP: "198.51.100.1", Side: "iran"} }
	firstTunnelInfo = func() firstTunnel {
		return firstTunnel{Exists: true, Side: "iran", RemotePub: "192.0.2.5", LocalGre: "10.10.10.2", PeerGre: "10.10.10.1"}
	}
	setupPlanListening = func(port int) bool { return port == 7001 }
	peers := `{"peers":[{"id":2,"name":"de","remote_pub":"192.0.2.7","frp_port":7002,"local_gre":"10.11.0.2","peer_gre":"10.11.0.1","ports":[443],"token":"secret-tok","gre_if":"gre-t2","frps_svc":"frps-2"}]}`
	if err := os.WriteFile(filepath.Join(configDir, "peers.json"), []byte(peers), 0600); err != nil {
		t.Fatal(err)
	}
	p := buildSetupPlan("443, 8443, x", 7002)
	// peer 2, and the first tunnel (no peer record) as id 0
	if p.Public != "198.51.100.1" || len(p.Peers) != 2 || p.Peers[0].ID != 2 || p.Peers[1].ID != 0 || p.Peers[1].RemotePub != "192.0.2.5" {
		t.Fatalf("plan: %+v", p)
	}
	b, _ := json.Marshal(p)
	if strings.Contains(string(b), "secret-tok") {
		t.Fatal("a token in the plan")
	}
	// 7001 listens, 7002 is peer 2's control port
	if p.RelayPort != 7003 || p.RelayTaken == "" {
		t.Fatalf("relay port: %d (7002 taken by %q)", p.RelayPort, p.RelayTaken)
	}
	if p.Clashes["443"] == "" || p.Clashes["8443"] != "" {
		t.Fatalf("clashes: %v", p.Clashes)
	}
	gre := strings.Join(p.GreUsed, ",")
	for _, a := range []string{"10.11.0.2", "10.11.0.1", "10.10.10.2", "10.10.10.1"} {
		if !strings.Contains(gre, a) {
			t.Fatalf("gre used: %v (no %s)", p.GreUsed, a)
		}
	}
	if _, ok := p.Pro["backhaul"]; !ok {
		t.Fatalf("pro: %v", p.Pro)
	}
	// a foreign server: its first tunnel is Hub 1, then the joined hubs (2 and up)
	_ = os.Remove(filepath.Join(configDir, "peers.json"))
	nodeInfoFn = func() nodeInfo { return nodeInfo{PublicIP: "192.0.2.7", Side: "foreign"} }
	firstTunnelInfo = func() firstTunnel { return firstTunnel{Exists: true, Side: "foreign", RemotePub: "203.0.113.5"} }
	hubs := `{"hubs":[{"id":2,"iran_pub":"203.0.113.6","iran_gre":"10.12.0.2"}]}`
	_ = os.WriteFile(filepath.Join(configDir, "hubs.json"), []byte(hubs), 0600)
	joinedMu.Lock()
	joinedAt = time.Time{}
	joinedMu.Unlock()
	p = buildSetupPlan("", 0)
	if len(p.Uplinks) != 2 || p.Uplinks[0].Hub != 1 || p.Uplinks[0].IranPub != "203.0.113.5" || p.Uplinks[1].Hub != 2 || len(p.Peers) != 0 {
		t.Fatalf("uplinks: %+v peers %+v", p.Uplinks, p.Peers)
	}
}

// The live state wins over the record; the record fills in only for the same side.
func TestFirstTunnelFrom(t *testing.T) {
	rec := firstTunnelRec{Side: "foreign", RemotePub: "203.0.113.1", LocalGre: "10.10.10.1", PeerGre: "10.10.10.2", Engine: "frp"}
	for _, c := range []struct {
		name string
		st   tunnelStatus
		want firstTunnel
	}{
		{"gre-tunnel's remote", tunnelStatus{Role: "foreign", GrePeer: "198.51.100.9", Gre: greState{Inner: "10.12.0.1/30"}, Engine: "frp"},
			firstTunnel{Exists: true, Side: "foreign", RemotePub: "198.51.100.9", LocalGre: "10.12.0.1", PeerGre: "10.12.0.2", Engine: "frp"}},
		{"Backhaul without GRE: its config before the record", tunnelStatus{Role: "foreign", RemotePub: "198.51.100.7", Engine: "backhaul"},
			firstTunnel{Exists: true, Side: "foreign", RemotePub: "198.51.100.7", LocalGre: "10.10.10.1", PeerGre: "10.10.10.2", Engine: "backhaul"}},
		{"a private remote: the record", tunnelStatus{Role: "foreign", RemotePub: "10.10.10.2"},
			firstTunnel{Exists: true, Side: "foreign", RemotePub: "203.0.113.1", LocalGre: "10.10.10.1", PeerGre: "10.10.10.2", Engine: "frp"}},
		{"the record of the other side is not used", tunnelStatus{Role: "iran"},
			firstTunnel{Exists: true, Side: "iran"}},
	} {
		if got := firstTunnelFrom(c.st, rec); got != c.want {
			t.Errorf("%s: %+v, want %+v", c.name, got, c.want)
		}
	}
}

// Two ends are paired only when they prove the same token.
func TestNodeTunLinksProof(t *testing.T) {
	f := nodeTunTest(t)
	f.plans[1].Peers = []setupPlanPeer{{ID: 4, RemotePub: "192.0.2.7"}}
	f.plans[2].Uplinks = []setupPlanUplink{{Hub: 1, IranPub: "198.51.100.1"}}
	proofs := map[int]string{1: "tok-a", 2: "tok-a"}
	old := f.call
	nodeAPIFn = func(ctx context.Context, id int, method, path string, body any) (int, []byte, error) {
		st, b, err := old(ctx, id, method, path, body)
		_, q, _ := strings.Cut(path, "?")
		if n := strings.TrimPrefix(q, "proof="); strings.HasPrefix(q, "proof=") && st == 200 {
			var p setupPlan
			_ = json.Unmarshal(b, &p)
			for i := range p.Peers {
				p.Peers[i].Proof = setupPlanProof(proofs[id], n)
			}
			for i := range p.Uplinks {
				p.Uplinks[i].Proof = setupPlanProof(proofs[id], n)
			}
			b, _ = json.Marshal(p)
		}
		return st, b, err
	}
	if links, _ := nodeTunLinks(context.Background()); len(links) != 1 {
		t.Fatalf("the same token: %+v", links)
	}
	proofs[2] = "tok-b" // a server that only claims the address
	if links, _ := nodeTunLinks(context.Background()); len(links) != 0 {
		t.Fatalf("another token: %+v", links)
	}
	if setupPlanProof("", "n") != "" || setupPlanProof("x", "n1") == setupPlanProof("x", "n2") {
		t.Fatal("proofs")
	}
}

func TestNodeTunBundleTransport(t *testing.T) {
	d := nodeTunDraft{Server: setupPlan{Public: "198.51.100.1"}, FrpPort: 7001, LocalGre: "10.12.0.2", PeerGre: "10.12.0.1"}
	q := nodeTunReq{Engine: "frp", Ports: "443"}
	if err := nodeTunBundleCheck(MakeBundle("198.51.100.1", 7001, "10.12.0.2", "10.12.0.1", "tok", []int{443}), q, d); err != nil {
		t.Fatal(err)
	}
	if err := nodeTunBundleCheck(MakeBundle("198.51.100.1", 7001, "10.12.0.2", "10.12.0.1", "tok", []int{443}, "kcp"), q, d); err == nil {
		t.Fatal("another transport")
	}
	if (&nodeTunReq{Server: 1, Client: 0, Engine: "frp", Ports: "1000-1002"}).check() == nil {
		t.Fatal("a port range for FRP")
	}
	if err := (&nodeTunReq{Server: 0, Client: 0, Engine: "backhaul", Ports: "8080=80"}).check(); err == nil || !strings.Contains(err.Error(), "two different") {
		t.Fatalf("backhaul mapping: %v", err)
	}
}

// A config without a running tunnel is a problem before anything is made.
func TestNodeTunStaleConfig(t *testing.T) {
	f := nodeTunTest(t)
	f.plans[2].Exists = true
	d, _ := nodeTunDraftFor(context.Background(), nodeTunReq{Server: 1, Client: 2, Engine: "frp", Ports: "443"})
	if !strings.Contains(strings.Join(d.Problems, ";"), "no running tunnel") {
		t.Fatalf("problems: %v", d.Problems)
	}
}
