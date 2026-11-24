package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// Two hubs as two processes: the real heartbeats, settings push and DNS loops
// over HTTP, against a fake Cloudflare that can be blocked for one of them.
// About 4 minutes, so only with HASHEM_DNS_LAB=1.
func TestDNSTwoHubsLab(t *testing.T) {
	if os.Getenv("HASHEM_DNS_HUB") != "" {
		dnsLabHub(t)
		return
	}
	if os.Getenv("HASHEM_DNS_LAB") == "" {
		t.Skip("set HASHEM_DNS_LAB=1")
	}
	cf := &fakeCF{recs: map[string]cfRecord{}}
	var mu sync.Mutex
	blocked, writes := map[string]bool{}, map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := strings.Split(r.URL.Path, "/")[1]
		mu.Lock()
		b := blocked[id]
		if r.Method != "GET" && !b {
			writes[id]++
		}
		mu.Unlock()
		if b {
			c, _, _ := w.(http.Hijacker).Hijack()
			c.Close() // reset, as a filter does
			return
		}
		http.StripPrefix("/"+id, cf).ServeHTTP(w, r)
	}))
	defer srv.Close()
	block := func(id string, on bool) { mu.Lock(); blocked[id] = on; mu.Unlock() }
	last := func() map[string]int {
		mu.Lock()
		defer mu.Unlock()
		return map[string]int{"a": writes["a"], "b": writes["b"]}
	}
	dir := t.TempDir()
	ports := map[string]string{}
	for _, id := range []string{"a", "b"} {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		ports[id] = l.Addr().String()
		l.Close()
	}
	ips := map[string]string{"a": "5.5.5.5", "b": "6.6.6.6"}
	other := map[string]string{"a": "b", "b": "a"}
	health := func(id, s string) { _ = os.WriteFile(filepath.Join(dir, id+".health"), []byte(s), 0o600) }
	for id := range ips {
		_ = os.MkdirAll(filepath.Join(dir, id), 0o700)
		health(id, stateHealthy)
		c := defaultClusterConfig()
		c.NodeID, c.Name, c.PublicIP, c.Secret = "hub-"+id, "hub "+id, ips[id], syncTestSecret
		o := other[id]
		c.Hubs = []HubPeer{{ID: "hub-" + o, Name: "hub " + o, PublicIP: ips[o], URL: "http://" + ports[o]}}
		if id == "a" {
			c.DNS = DNSConfig{Enabled: true, Master: true, Version: 100, Provider: "cloudflare", Token: "tok", Name: "vpn.example.com", TTL: 60}
		}
		b, _ := json.Marshal(c)
		_ = os.WriteFile(filepath.Join(dir, id, "cluster.json"), b, 0o600)
	}
	procs := map[string]*exec.Cmd{}
	start := func(id string) {
		c := exec.Command(os.Args[0], "-test.run", "^TestDNSTwoHubsLab$", "-test.timeout", "20m")
		c.Env = append(os.Environ(), "HASHEM_DNS_HUB="+id, "HASHEM_DNS_DIR="+dir, "HASHEM_DNS_ADDR="+ports[id], "HASHEM_DNS_CF="+srv.URL+"/"+id)
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		procs[id] = c
	}
	kill := func(id string) { _ = procs[id].Process.Kill(); _ = procs[id].Wait() }
	defer func() {
		for id := range procs {
			kill(id)
		}
	}()
	conf := func(id string) (c ClusterConfig) {
		b, _ := os.ReadFile(filepath.Join(dir, id, "cluster.json"))
		_ = json.Unmarshal(b, &c)
		return
	}
	wait := func(what string, max time.Duration, ok func() bool) {
		t.Helper()
		from := time.Now()
		for !ok() {
			if time.Since(from) > max {
				for _, id := range []string{"a", "b"} {
					b, _ := os.ReadFile(filepath.Join(dir, id, "cluster-events.json"))
					t.Logf("%s %+v\n%s", id, conf(id).DNS, b)
				}
				t.Fatalf("%s: not within %s; record %s, writes %v", what, max, cf.ips(), last())
			}
			time.Sleep(200 * time.Millisecond)
		}
		t.Logf("%s: after %.0f s (record %s, writes %v)", what, time.Since(from).Seconds(), cf.ips(), last())
	}
	start("a")
	start("b")
	wait("both hubs in the record, b follows", 60*time.Second, func() bool {
		return cf.ips() == "5.5.5.5,6.6.6.6" && conf("b").DNS.ManagedBy == "hub-a" && slices.Equal(conf("b").DNS.Records, []string{"5.5.5.5", "6.6.6.6"})
	})
	if w := last(); w["b"] != 0 {
		t.Fatal("only the controller writes", w)
	}
	// a's way to Cloudflare is cut, then its tunnels: only b can take it out
	block("a", true)
	health("a", stateDown)
	wait("a is cut off: b writes", 2*time.Minute, func() bool { return cf.ips() == "6.6.6.6" && last()["b"] > 0 })
	health("a", stateHealthy)
	wait("a works again, its way to Cloudflare does not: b puts it back", 60*time.Second, func() bool { return cf.ips() == "5.5.5.5,6.6.6.6" })
	block("a", false)
	time.Sleep(40 * time.Second) // a takes the writing back
	n := last()
	health("b", stateDown)
	wait("b's tunnels are down: a writes again", 60*time.Second, func() bool { return cf.ips() == "5.5.5.5" })
	if w := last(); w["a"] <= n["a"] || w["b"] != n["b"] {
		t.Fatal("a must write again", n, w)
	}
	health("b", stateHealthy)
	wait("b is back", 60*time.Second, func() bool { return cf.ips() == "5.5.5.5,6.6.6.6" })
	// a's panel restarts: nothing is taken out
	kill("a")
	start("a")
	for i := 0; i < 100; i++ {
		if got := cf.ips(); got != "5.5.5.5,6.6.6.6" {
			t.Fatal("a restart changed the record:", got)
		}
		time.Sleep(200 * time.Millisecond)
	}
	// a dies
	kill("a")
	wait("a is off: b takes it out", 90*time.Second, func() bool { return cf.ips() == "6.6.6.6" })
	// failover mode, b first
	c := conf("a")
	c.DNS.Mode, c.DNS.Order, c.DNS.Version = dnsFailover, []string{"hub-b", "hub-a"}, 200
	b, _ := json.Marshal(c)
	_ = os.WriteFile(filepath.Join(dir, "a", "cluster.json"), b, 0o600)
	start("a")
	wait("b follows the failover order", 60*time.Second, func() bool { return conf("b").DNS.Mode == dnsFailover })
	time.Sleep(25 * time.Second)
	if cf.ips() != "6.6.6.6" {
		t.Fatal(cf.ips())
	}
	health("b", stateDown)
	wait("b, the first, is down: a", 60*time.Second, func() bool { return cf.ips() == "5.5.5.5" })
	health("b", stateHealthy)
	from := time.Now()
	wait("b is back for a minute: b", 2*time.Minute, func() bool { return cf.ips() == "6.6.6.6" })
	if time.Since(from) < 50*time.Second {
		t.Fatal("moved back too soon")
	}
}

// dnsLabHub is one of the two hubs.
func dnsLabHub(t *testing.T) {
	id, dir := os.Getenv("HASHEM_DNS_HUB"), os.Getenv("HASHEM_DNS_DIR")
	withPro(t)
	configDir = filepath.Join(dir, id)
	resetClusterState()
	cfAPI = os.Getenv("HASHEM_DNS_CF")
	meshIP6 = func() string { return "" }
	started := time.Now()
	lbSnapshot = func() *HubSnapshot {
		if time.Since(started) < 5*time.Second {
			return nil // as after a panel start
		}
		h, _ := os.ReadFile(filepath.Join(dir, id+".health"))
		rx := uint64(time.Since(started).Seconds() * 1000)
		s := &HubSnapshot{At: time.Now()}
		p := peerLive{peerRecord: peerRecord{ID: 1, Name: "de", RemotePub: "9.9.9.9", FrpPort: 7000, Ports: []int{443}}, Rx: &rx, Tx: &rx}
		p.HealthState = string(h)
		s.Peers = []peerLive{p}
		return s
	}
	mux := http.NewServeMux()
	mountMeshRoutes(mux)
	go startMeshLoop()
	go startDNSLoop()
	fmt.Fprintln(os.Stderr, http.ListenAndServe(os.Getenv("HASHEM_DNS_ADDR"), mux))
}
