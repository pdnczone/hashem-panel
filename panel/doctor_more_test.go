package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http/httptest"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

func probe(label string, anchor bool, state string) reachProbe {
	return reachProbe{Host: "203.0.113.9", Port: map[string]int{"tunnel": 7000, "panel": 8080, "https": 443, "ssh": 22}[label], Label: label, Anchor: anchor, State: state}
}

func TestReachVerdict(t *testing.T) {
	for _, c := range []struct {
		name   string
		ps     []reachProbe
		icmp   bool
		want   string
		atPort int
	}{
		{"all open", []reachProbe{probe("tunnel", true, "open"), probe("https", false, "refused")}, true, "open", 7000},
		{"tunnel port filtered, host answers", []reachProbe{probe("tunnel", true, "timeout"), probe("ssh", false, "open")}, true, "port_blocked", 7000},
		{"reset counts as filtered", []reachProbe{probe("tunnel", true, "reset"), probe("https", false, "refused")}, false, "port_blocked", 7000},
		{"nothing listens", []reachProbe{probe("tunnel", true, "refused"), probe("ssh", false, "open")}, true, "port_closed", 7000},
		{"ping passes, no TCP", []reachProbe{probe("tunnel", true, "timeout"), probe("https", false, "timeout")}, true, "tcp_blocked", 7000},
		{"nothing at all", []reachProbe{probe("panel", true, "timeout"), probe("ssh", false, "unreachable")}, false, "down", 8080},
		{"no anchor: no verdict", []reachProbe{probe("https", false, "timeout"), probe("ssh", false, "timeout")}, true, "", 0},
	} {
		v, at := reachVerdict(c.ps, c.icmp)
		if v != c.want || at.Port != c.atPort {
			t.Errorf("%s: got %q at %d, want %q at %d", c.name, v, at.Port, c.want, c.atPort)
		}
	}
	other := probe("ssh", false, "open")
	other.Host = "198.51.100.4"
	if v, _ := reachVerdict([]reachProbe{probe("tunnel", true, "timeout"), other}, true); v != "tcp_blocked" {
		t.Errorf("an answer from another address says nothing about this one: got %q", v)
	}
	p := probe("tunnel", true, "open")
	p.TLS = "cut"
	if v, _ := reachVerdict([]reachProbe{p}, true); v != "tls_cut" {
		t.Errorf("cut TLS: got %q", v)
	}
}

func TestReachTargets(t *testing.T) {
	spoke := tunnelStatus{Role: "foreign (client)", FrpSvc: "frpc", BindPort: 7000, Transport: "wss", RemotePub: "198.51.100.4"}
	ts := reachTargets(spoke, "198.51.100.4", PeerConfig{})
	if len(ts) != 3 || ts[0].port != 7000 || !ts[0].anchor || !ts[0].tls || ts[1].port != 443 || ts[1].anchor {
		t.Fatalf("spoke: %+v", ts)
	}
	// frpc dials the hub inside GRE (the default route): the public port says nothing about the tunnel
	spoke.Gre.Inner, spoke.RemotePub = "10.10.10.2/30", "10.10.10.1"
	for _, x := range reachTargets(spoke, "198.51.100.4", PeerConfig{}) {
		if x.anchor || x.host != "198.51.100.4" {
			t.Fatalf("inside GRE: no anchor, public address for information: %+v", x)
		}
	}
	spoke.Gre.Inner, spoke.RemotePub = "", "127.0.0.1" // a local carrier client (WSS)
	for _, x := range reachTargets(spoke, "198.51.100.4", PeerConfig{}) {
		if x.anchor {
			t.Fatalf("loopback: no anchor: %+v", x)
		}
	}
	hub := tunnelStatus{Role: "iran (server)", FrpSvc: "frps", BindPort: 7000}
	ts = reachTargets(hub, "203.0.113.9", PeerConfig{PeerURL: "http://203.0.113.9:2053"})
	if len(ts) != 3 || ts[0].port != 2053 || ts[0].label != "panel" || !ts[0].anchor {
		t.Fatalf("hub: nothing listens on the foreign tunnel port, the panel port is the anchor: %+v", ts)
	}
	ts = reachTargets(hub, "203.0.113.9", PeerConfig{PeerURL: "http://10.10.10.2:2053"})
	for _, x := range ts {
		if x.host != "10.10.10.2" {
			t.Fatalf("every probe goes to the address the Peer Link dials: %+v", ts)
		}
	}
	if reachTargets(hub, "", PeerConfig{}) != nil {
		t.Fatal("no peer, no probes")
	}
}

func TestReachState(t *testing.T) {
	op := func(e error) error {
		return &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", e)}
	}
	for err, want := range map[error]string{
		nil:                            "open",
		op(syscall.ECONNREFUSED):       "refused",
		op(syscall.ECONNRESET):         "reset",
		op(syscall.EHOSTUNREACH):       "unreachable",
		errors.New("strange"):          "error",
		context.DeadlineExceeded:       "timeout",
		&net.DNSError{IsTimeout: true}: "timeout",
	} {
		if got := reachState(err); got != want {
			t.Errorf("%v: got %q, want %q", err, got, want)
		}
	}
}

// A working tunnel gets no reach finding; a broken one is told why.
func TestDoctorReachFindings(t *testing.T) {
	in := greInputs()
	in.reach = reachSummary{Tested: true, Probes: []reachProbe{probe("panel", true, "timeout"), probe("ssh", false, "open")}}
	rep := evaluateDoctor(in)
	if rep.Reach.Verdict != "port_blocked" || len(rep.Findings) != 0 {
		t.Fatalf("working tunnel: verdict %q, findings:\n%s", rep.Reach.Verdict, findingTitles(rep))
	}
	in.health.Tunnels[0].Verdict, in.health.Tunnels[0].Layers.Session = VerdictFail, layerFail
	rep = evaluateDoctor(in)
	if !strings.Contains(findingTitles(rep), "Port 8080 on 203.0.113.9 does not answer while other ports do") {
		t.Fatalf("broken tunnel must name the filtered port:\n%s", findingTitles(rep))
	}
	for _, f := range rep.Findings {
		if strings.HasPrefix(f.TitleTpl, "Port {1}") && !strings.Contains(f.Fix, "panel link") {
			t.Fatalf("the panel port's fix speaks of the panel link: %q", f.Fix)
		}
	}
}

func TestClockFindings(t *testing.T) {
	in := greInputs()
	in.clock = clockSummary{Tested: true, NTP: "yes", PeerKnown: true, PeerSkewMs: 2000, PeerErrMs: 40}
	if rep := evaluateDoctor(in); len(rep.Findings) != 0 {
		t.Fatalf("2 s is fine:\n%s", findingTitles(rep))
	}
	in.clock.PeerSkewMs = -95000
	rep := evaluateDoctor(in)
	if len(rep.Findings) != 1 || rep.Findings[0].Severity != "warning" || rep.Findings[0].Args[0] != "95" {
		t.Fatalf("95 s apart:\n%s", findingTitles(rep))
	}
	in.clock = clockSummary{Tested: true, NTP: "no", PeerKnown: true, PeerSkewMs: 5400, PeerErrMs: 1000}
	rep = evaluateDoctor(in)
	if len(rep.Findings) != 0 || len(rep.Notes) != 1 || !strings.Contains(rep.Notes[0], "not synced") {
		t.Fatalf("5.4 s ± 1 s is within the margin; NTP off is a note (containers report it):\n%s %v", findingTitles(rep), rep.Notes)
	}
	t0 := time.Unix(1000, 0)
	skew, e := clockSkew(t0, t0.Add(200*time.Millisecond), t0.Add(100*time.Millisecond+3*time.Second).UnixNano())
	if skew != 3000 || e != 100 {
		t.Fatalf("skew %v err %v", skew, e)
	}
}

const mtrFixture = `Start: 2026-11-13T10:00:00+0000
HOST: ir-hub                      Loss%   Snt   Last   Avg  Best  Wrst StDev
  1.|-- 10.0.0.1                   0.0%    10    0.4   0.4   0.3   0.6   0.1
  2.|-- 185.1.2.3                 30.0%    10    2.1   2.3   1.9   3.0   0.3
  3.|-- ???                       100.0    10    0.0   0.0   0.0   0.0   0.0
  4.|-- 80.81.82.83                0.0%    10   78.1  78.3  77.9  80.0   0.6
  5.|-- 203.0.113.9                0.0%    10   80.2  80.4  79.9  82.0   0.5
`

func TestParseMtrAndVerdict(t *testing.T) {
	hops := parseMtrReport(mtrFixture)
	if len(hops) != 5 || hops[2].Host != "" || hops[2].Loss != 100 || hops[1].Loss != 30 || hops[4].Avg != 80.4 {
		t.Fatalf("parsed %+v", hops)
	}
	v, from, border := traceVerdict(hops, "203.0.113.9")
	if v != "clean" || from != 0 || border != 4 {
		t.Fatalf("loss at hop 2 that does not last is rate limiting: %s from %d border %d", v, from, border)
	}
	hops[1].Loss, hops[3].Loss, hops[4].Loss = 0, 20, 25
	if v, from, _ := traceVerdict(hops, "203.0.113.9"); v != "loss" || from != 4 {
		t.Fatalf("loss that lasts to the end starts at hop 4: %s from %d", v, from)
	}
	hops[1].Loss = 22
	if v, from, _ := traceVerdict(hops, "203.0.113.9"); v != "loss" || from != 2 {
		t.Fatalf("an unanswered hop in the run says nothing: %s from %d", v, from)
	}
	if v, from, _ := traceVerdict(hops[:4], "203.0.113.9"); v != "no_reply_end" || from != 5 {
		t.Fatalf("destination never answered: %s from %d", v, from)
	}
}

func TestParseTraceroute(t *testing.T) {
	out := `traceroute to 203.0.113.9 (203.0.113.9), 30 hops max, 60 byte packets
 1  10.0.0.1  0.311 ms  0.271 ms  0.250 ms
 2  * * *
 3  185.1.2.3  5.1 ms * 5.3 ms
 4  203.0.113.9  80.1 ms  80.5 ms  80.3 ms
`
	hops := parseTraceroute(out)
	if len(hops) != 4 || hops[1].Host != "" || hops[1].Loss != 100 || hops[2].Loss != 33.3 || hops[2].Avg != 5.2 || hops[3].Host != "203.0.113.9" {
		t.Fatalf("parsed %+v", hops)
	}
}

func TestRunTraceTools(t *testing.T) {
	oldLook, oldRun, oldInst := lookPath, traceRunFn, installMtrF
	t.Cleanup(func() { lookPath, traceRunFn, installMtrF = oldLook, oldRun, oldInst })
	have := map[string]bool{}
	lookPath = func(n string) (string, error) {
		if have[n] {
			return "/usr/bin/" + n, nil
		}
		return "", errors.New("missing")
	}
	var ran []string
	traceRunFn = func(_ context.Context, name string, args ...string) (string, error) {
		ran = append(ran, name+" "+strings.Join(args, " "))
		return mtrFixture, nil
	}
	installed := false
	installMtrF = func() error { installed, have["mtr"] = true, true; return nil }
	tg := docTarget{ID: "peer", Host: "203.0.113.9", Port: 7000}

	if _, err := runTrace(context.Background(), tg, "icmp", 0, false); !errors.Is(err, errTraceMissing) || installed {
		t.Fatalf("no tool and no install asked: %v installed=%v", err, installed)
	}
	res, err := runTrace(context.Background(), tg, "tcp", 7000, true)
	if err != nil || !res.Installed || res.Tool != "mtr" || res.Verdict != "clean" || len(res.Hops) != 5 {
		t.Fatalf("install on request: %+v %v", res, err)
	}
	if !strings.Contains(ran[0], "-T -P 7000 203.0.113.9") {
		t.Fatalf("TCP mode: %q", ran[0])
	}
}

func TestSummarizeStability(t *testing.T) {
	r := &stabilityResult{Interval: 0.5, Samples: []float64{40, 41, 40, -1, -1, -1, -1, -1, -1, -1, 42, 40, 300, 41}}
	summarizeStability(r)
	if r.Sent != 14 || r.Lost != 7 || r.Drops != 1 || r.LongestGap != 3.5 || r.Spikes != 1 || r.Verdict != "drops" || r.Max != 300 {
		t.Fatalf("%+v", r)
	}
	r = &stabilityResult{Interval: 1, Samples: []float64{40, 41, 40, 42, 40, 41}}
	summarizeStability(r)
	if r.Verdict != "stable" || r.LossPct != 0 || r.Avg != 40.7 {
		t.Fatalf("%+v", r)
	}
}

func TestRunStabilityFallsBackToTCP(t *testing.T) {
	oldOK, oldTCP := stabPingOK, stabTCPFn
	t.Cleanup(func() { stabPingOK, stabTCPFn = oldOK, oldTCP })
	stabPingOK = func(string) bool { return false }
	var addr string
	stabTCPFn = func(_ context.Context, a string, secs int, progress func([]float64)) ([]float64, error) {
		addr = a
		progress([]float64{10})
		return []float64{10, 11, -1, 10}, nil
	}
	set := func(float64, any) {}
	if _, err := runStability(context.Background(), docTarget{Host: "203.0.113.9"}, 60, set); err == nil {
		t.Fatal("no ping and no known port: an error, not an empty run")
	}
	r, err := runStability(context.Background(), docTarget{Host: "203.0.113.9", Port: 7000}, 60, set)
	if err != nil || r.Mode != "tcp" || addr != "203.0.113.9:7000" || r.Lost != 1 || r.Verdict != "drops" {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestDocJobOneAtATime(t *testing.T) {
	release := make(chan struct{})
	err := docJobStart("testjob", "x", time.Minute, func(ctx context.Context, set func(float64, any)) (any, error) {
		<-release
		return "done", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := docJobStart("testjob", "x", time.Minute, nil); err == nil {
		t.Fatal("a second job of the same kind must wait")
	}
	close(release)
	for i := 0; i < 100; i++ {
		if j := docJobView("testjob"); !j.Running {
			if j.Result != "done" || j.Progress != 1 {
				t.Fatalf("%+v", j)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("job did not finish")
}

func TestTestDocPorts(t *testing.T) {
	oldList, oldProbe := docPortsFn, docPortProbe
	t.Cleanup(func() { docPortsFn, docPortProbe = oldList, oldProbe })
	docPortsFn = func() []docPort {
		return []docPort{{Key: "t0:443", Port: 443, hosts: []string{"127.0.0.1"}}, {Key: "t0:2083", Port: 2083, hosts: []string{"127.0.0.1"}}}
	}
	docPortProbe = func(_ []string, port int) (float64, string, error) {
		if port == 443 {
			return 12.34, "server sent a banner", nil
		}
		return -1, "", errors.New("connection closed right after connect")
	}
	got := testDocPorts(nil)
	if len(got) != 2 || got[0].State != "ok" || got[0].Ms != 12.3 || got[1].State != "fail" {
		t.Fatalf("%+v", got)
	}
	if got = testDocPorts([]string{"t0:2083", "t9:1"}); len(got) != 1 || got[0].Port != 2083 {
		t.Fatalf("only listed keys are tested: %+v", got)
	}
}

func TestDocHistoryAndSchedule(t *testing.T) {
	docHistMu.Lock()
	docHistLoaded = false
	docHistMu.Unlock()
	_ = os.Remove(docHistPath())
	t.Cleanup(func() {
		_ = os.Remove(docHistPath())
		docHistMu.Lock()
		docHistLoaded = false
		docHistMu.Unlock()
	})
	rep := evaluateDoctor(greInputs())
	for i := 0; i < docHistMax+5; i++ {
		docHistRecord(rep, i%2 == 0)
	}
	docHistRecord(&doctorReport{}, false) // unconfigured: not recorded
	h := docHistView()
	if len(h.Entries) != docHistMax || h.Entries[0].Score != 100 || h.Entries[0].RTT != 40 || h.Entries[0].Loss != 0 {
		t.Fatalf("%d entries, first %+v", len(h.Entries), h.Entries[0])
	}
	if _, err := docScheduleSet(docSchedule{EveryHours: 5}); err == nil {
		t.Fatal("5 hours is not offered")
	}
	if _, err := docScheduleSet(docSchedule{EveryHours: 6, Alert: true}); err != nil {
		t.Fatal(err)
	}
	docHistMu.Lock()
	docHistLoaded = false // read back from disk
	docHistMu.Unlock()
	if h := docHistView(); h.Schedule.EveryHours != 6 || !h.Schedule.Alert || len(h.Entries) != docHistMax {
		t.Fatalf("not persisted: %+v", h.Schedule)
	}
	now := time.Now()
	s := docSchedule{EveryHours: 6}
	if !docScheduleDue(now, s, time.Time{}) || docScheduleDue(now, s, now.Add(-5*time.Hour)) || !docScheduleDue(now, s, now.Add(-6*time.Hour)) {
		t.Fatal("due rule")
	}
	if docScheduleDue(now, docSchedule{}, time.Time{}) {
		t.Fatal("off is never due")
	}
}

func TestDoctorLinkOf(t *testing.T) {
	for rating, want := range map[string]string{"excellent": stateHealthy, "good": stateHealthy, "warning": stateDegraded, "critical": stateDown} {
		l := doctorLinkOf(&doctorReport{Rating: rating, Score: 50, Findings: []doctorFinding{{Title: "x"}}})
		if l.State != want || l.Name != "diagnostics" || l.Why != "score 50/100: x" {
			t.Errorf("%s: %+v", rating, l)
		}
	}
}

func TestDoctorPostMoreValidates(t *testing.T) {
	withPro(t)
	oldT := doctorTargetsFn
	t.Cleanup(func() { doctorTargetsFn = oldT })
	doctorTargetsFn = func() []docTarget {
		return []docTarget{{ID: "gre", Host: "10.10.0.2", Inner: true}, {ID: "peer", Host: "203.0.113.9"}}
	}
	post := func(body string) (int, string) {
		rr := httptest.NewRecorder()
		handleDoctorPost(rr, httptest.NewRequest("POST", "/api/doctor", strings.NewReader(body)))
		var m map[string]any
		_ = json.Unmarshal(rr.Body.Bytes(), &m)
		e, _ := m["error"].(string)
		return rr.Code, e
	}
	for body, want := range map[string]string{
		`{"action":"trace","target":"evil"}`:                     "unknown trace target",
		`{"action":"trace","target":"gre"}`:                      "unknown trace target", // inside GRE: one hop, no trace
		`{"action":"trace","target":"peer","mode":"tcp"}`:        "no TCP port",
		`{"action":"stability","target":"peer","seconds":7}`:     "seconds must be",
		`{"action":"stability","target":"1.1.1.1","seconds":60}`: "unknown stability target",
		`{"action":"schedule","every_hours":2}`:                  "every_hours",
	} {
		if code, e := post(body); code != 400 || !strings.Contains(e, want) {
			t.Errorf("%s: %d %q, want 400 %q", body, code, e, want)
		}
	}
}
