package main

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestTrafficLab runs in the hub namespace of tests/test_traffic_lab.sh with
// the real kernel: a GRE main tunnel (gre-tunnel), a GRE peer (gre-p2), a
// Backhaul peer without GRE (port 3090, iptables counters) and a Bagher link
// (this server dials the foreign sshd port). The lab's script moves exact
// byte counts over each; the panel's own snapshot, /api/status,
// /api/dashboard and /api/traffic/usage must report them.
//
//	TRAFFIC_LAB_SCRIPT=<script> TRAFFIC_LAB_FOREIGN=<foreign ip> \
//	TRAFFIC_LAB_EXPECT=main=RX:TX,p2=RX:TX,p3=RX:TX,bagher=RX:TX go test -run TestTrafficLab
func TestTrafficLab(t *testing.T) {
	script := os.Getenv("TRAFFIC_LAB_SCRIPT")
	if script == "" {
		t.Skip("set TRAFFIC_LAB_SCRIPT to run the traffic accuracy lab")
	}
	foreign := os.Getenv("TRAFFIC_LAB_FOREIGN")
	expect := map[string][2]float64{}
	for _, kv := range strings.Split(os.Getenv("TRAFFIC_LAB_EXPECT"), ",") {
		k, v, _ := strings.Cut(kv, "=")
		a, b, _ := strings.Cut(v, ":")
		rx, _ := strconv.ParseFloat(a, 64)
		tx, _ := strconv.ParseFloat(b, 64)
		expect[k] = [2]float64{rx, tx}
	}

	oldRunner, oldCfg, oldBh, oldFrp, oldUsage, oldCC := runner, configDir, backhaulDir, frpDir, trafficUsage, carrierCounters
	runner = execRunner                   // the real host: this test runs inside the lab's namespace
	carrierCounters = readCarrierCounters // TestMain stubs it for the unit tests
	configDir, backhaulDir, frpDir = t.TempDir(), t.TempDir(), t.TempDir()
	trafficUsage = newUsage()
	resetCarrier := func() {
		carrierState.Lock()
		carrierState.at, carrierState.lastFailed = time.Time{}, time.Time{}
		carrierState.Unlock()
	}
	t.Cleanup(func() {
		carrierDrop()
		runner, configDir, backhaulDir, frpDir, trafficUsage, carrierCounters = oldRunner, oldCfg, oldBh, oldFrp, oldUsage, oldCC
		carrierState.Lock()
		carrierState.sig, carrierState.at, carrierState.tags, carrierState.ok = "", time.Time{}, nil, false
		carrierState.Unlock()
	})
	trafficStateMu.Lock()
	trafficStateInit, lifetimeUp, lifetimeDown, lastRawIf, lastSampleAt, lastReadAt = false, 0, 0, nil, time.Time{}, time.Time{}
	speedDeltaUp, speedDeltaDown, currentSpeedUp, currentSpeedDown = 0, 0, 0, 0
	trafficStateMu.Unlock()

	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	peers := `{"peers":[` +
		`{"id":2,"name":"p2","remote_pub":"` + foreign + `","gre_if":"gre-p2","peer_gre":"10.11.0.2","frps_svc":"frps-2","engine":"frp"},` +
		`{"id":3,"name":"p3","remote_pub":"` + foreign + `","frp_port":3090,"frps_svc":"backhaul-server-3","engine":"backhaul","no_gre":true}]}`
	must(os.WriteFile(peersFile(), []byte(peers), 0o600))
	must(os.WriteFile(filepath.Join(backhaulDir, "server-3.toml"), []byte("[server]\nbind_addr = \"0.0.0.0:3090\"\n"), 0o600))
	bcfg := defaultSSHFwdConfig()
	bcfg.Enabled, bcfg.Role, bcfg.RemoteHost, bcfg.RemoteSSHPort = true, "iran", foreign, 2222
	sshFwdMu.Lock()
	must(saveSSHFwdConfigLocked(bcfg))
	sshFwdMu.Unlock()
	// an Xray link in direct mode: this server dials the foreign tunnel port
	must(saveXrayState(xrayState{NextID: 2, Links: []XrayLink{{ID: 1, Mode: xrayModeDirect, Side: xraySideIran,
		Remote: foreign, TunnelPort: 4433, Ports: []int{2053}, Profile: XrayProfile{Transport: "raw", Security: "reality"}}}}))

	tick := func() *HubSnapshot {
		resetCarrier()
		if !snapshotTick() {
			t.Fatal("snapshot not built")
		}
		return snapPtr.Load()
	}
	getJSON := func(h func(w *httptest.ResponseRecorder), v any) {
		rec := httptest.NewRecorder()
		h(rec)
		must(json.Unmarshal(rec.Body.Bytes(), v))
	}
	type counters struct{ Rx, Tx *uint64 }
	type status struct {
		Local      counters   `json:"local"`
		Peers      []peerLive `json:"peers"`
		CountersAt int64      `json:"counters_at"`
	}
	readStatus := func() status {
		var s status
		getJSON(func(w *httptest.ResponseRecorder) { handleStatus(w, httptest.NewRequest("GET", "/api/status", nil)) }, &s)
		return s
	}
	type dash struct {
		Traffic    map[string]float64 `json:"traffic"`
		CountersAt int64              `json:"counters_at"`
	}
	readDash := func() dash {
		var d dash
		getJSON(func(w *httptest.ResponseRecorder) {
			handleDashboard(w, httptest.NewRequest("GET", "/api/dashboard", nil))
		}, &d)
		return d
	}
	readHost := func() [2]float64 {
		rec := httptest.NewRecorder()
		handleUsageGet(rec, httptest.NewRequest("GET", "/api/traffic/usage?range=1h", nil))
		var raw struct {
			Links []map[string]any `json:"links"`
		}
		must(json.Unmarshal(rec.Body.Bytes(), &raw))
		for _, l := range raw.Links {
			if l["key"] == usageHostKey {
				rx, _ := l["rx"].(float64)
				tx, _ := l["tx"].(float64)
				return [2]float64{rx, tx}
			}
		}
		return [2]float64{}
	}
	peerOf := func(s status, id int) counters {
		for _, p := range s.Peers {
			if p.ID == id {
				return counters{p.Rx, p.Tx}
			}
		}
		return counters{}
	}
	sub := func(a, b *uint64) float64 {
		if a == nil || b == nil {
			return -1
		}
		return float64(*b) - float64(*a)
	}
	run := func(phase string) {
		out, err := exec.Command("bash", script, phase).CombinedOutput()
		if err != nil {
			t.Fatalf("traffic %s: %v\n%s", phase, err, out)
		}
	}
	// within: measured bytes against payload: IP/TCP headers and the ACKs of
	// the other direction add a few percent, never less than the payload.
	report := []string{}
	within := func(what string, got, want float64) {
		ratio := got / want
		report = append(report, fmt.Sprintf("%s: %.0f B for %.0f B payload (x%.3f)", what, got, want, ratio))
		if ratio < 0.999 || ratio > 1.15 {
			t.Errorf("%s: %.0f B for %.0f B payload (x%.3f), want x1.000..1.150", what, got, want, ratio)
		}
	}
	defer func() { t.Log("traffic lab:\n  " + strings.Join(report, "\n  ")) }()

	// ---- 1. exact transfers over every kind of link ----------------------
	tick() // builds the iptables chains (their counters start at 0)
	time.Sleep(time.Second)
	tick()
	st0, d0, h0, s0 := readStatus(), readDash(), readHost(), snapPtr.Load()
	run("bulk")
	s1 := tick()
	st1, d1, h1 := readStatus(), readDash(), readHost()

	within("main rx (gre-tunnel)", sub(st0.Local.Rx, st1.Local.Rx), expect["main"][0])
	within("main tx (gre-tunnel)", sub(st0.Local.Tx, st1.Local.Tx), expect["main"][1])
	p2a, p2b := peerOf(st0, 2), peerOf(st1, 2)
	within("peer 2 rx (gre-p2)", sub(p2a.Rx, p2b.Rx), expect["p2"][0])
	within("peer 2 tx (gre-p2)", sub(p2a.Tx, p2b.Tx), expect["p2"][1])
	p3a, p3b := peerOf(st0, 3), peerOf(st1, 3)
	within("peer 3 rx (Backhaul port, no GRE)", sub(p3a.Rx, p3b.Rx), expect["p3"][0])
	within("peer 3 tx (Backhaul port, no GRE)", sub(p3a.Tx, p3b.Tx), expect["p3"][1])
	bg0, bg1 := s0.CarrierTags["bagher-1"], s1.CarrierTags["bagher-1"]
	within("Bagher rx (SSH port)", float64(bg1[0])-float64(bg0[0]), expect["bagher"][0])
	within("Bagher tx (SSH port)", float64(bg1[1])-float64(bg0[1]), expect["bagher"][1])
	xr0, xr1 := s0.CarrierTags["xray-1"], s1.CarrierTags["xray-1"]
	within("Xray rx (tunnel port)", float64(xr1[0])-float64(xr0[0]), expect["xray"][0])
	within("Xray tx (tunnel port)", float64(xr1[1])-float64(xr0[1]), expect["xray"][1])
	var wantRx, wantTx float64
	for _, v := range expect {
		wantRx, wantTx = wantRx+v[0], wantTx+v[1]
	}
	within("dashboard total down", d1.Traffic["down"]-d0.Traffic["down"], wantRx)
	within("dashboard total up", d1.Traffic["up"]-d0.Traffic["up"], wantTx)
	within("usage ledger, this server rx", h1[0]-h0[0], wantRx)
	within("usage ledger, this server tx", h1[1]-h0[1], wantTx)
	if st1.CountersAt <= st0.CountersAt || d1.CountersAt != st1.CountersAt {
		t.Errorf("counters_at: status %d -> %d, dashboard %d", st0.CountersAt, st1.CountersAt, d1.CountersAt)
	}

	// ---- 2. live speed: 2 MB/s paced over the main tunnel ----------------
	const rate = 2_000_000.0
	// a fresh speed window: the bulk phase took under a second, too short
	// for one, so its bytes would be averaged into the first paced sample
	time.Sleep(1100 * time.Millisecond)
	tick()
	paced := exec.Command("bash", script, "paced")
	must(paced.Start())
	time.Sleep(2 * time.Second)
	var dashSpeeds, linkSpeeds []float64
	prev := readStatus()
	for i := 0; i < 4; i++ {
		time.Sleep(3 * time.Second)
		tick()
		cur, d := readStatus(), readDash()
		dashSpeeds = append(dashSpeeds, d.Traffic["speed_down"])
		// what the Tunnel tab computes: bytes over the server's reading times
		if dt := float64(cur.CountersAt-prev.CountersAt) / 1000; dt > 0 {
			linkSpeeds = append(linkSpeeds, sub(prev.Local.Rx, cur.Local.Rx)/dt)
		}
		prev = cur
	}
	_ = paced.Wait()
	med := func(v []float64) float64 {
		sort.Float64s(v)
		return v[len(v)/2]
	}
	for what, v := range map[string][]float64{"dashboard live speed": dashSpeeds, "main tunnel link speed": linkSpeeds} {
		m := med(v)
		report = append(report, fmt.Sprintf("%s: %.2f MB/s for a %.2f MB/s transfer (samples %v)", what, m/1e6, rate/1e6, v))
		if m < rate*0.9 || m > rate*1.2 {
			t.Errorf("%s: median %.0f B/s for %.0f B/s paced (samples %v)", what, m, rate, v)
		}
	}

	// ---- 3. a panel restart: what moves while it is stopped counts -------
	tick()
	dBefore := readDash()
	flushHistoryIfDirty() // saves traffic_state.json, as the panel does every 30 s
	trafficStateMu.Lock()
	trafficStateInit, lifetimeUp, lifetimeDown, lastRawIf, lastSampleAt, lastReadAt = false, 0, 0, nil, time.Time{}, time.Time{}
	trafficStateMu.Unlock()
	run("main3")
	tick()
	dAfter := readDash()
	within("bytes moved while the panel was stopped (main rx)", dAfter.Traffic["down"]-dBefore.Traffic["down"], 3<<20)
}
