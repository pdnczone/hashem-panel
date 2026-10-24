package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func fixTestPeer() peerRecord {
	return peerRecord{ID: 7, Name: "t7", LocalGre: "10.10.10.1/30", PeerGre: "10.10.10.2",
		RemotePub: "198.51.100.7", LocalPub: "203.0.113.5", FrpPort: 7091, GreIf: "gre-t7", FrpsSvc: "frps-7"}
}

// writeStubHost installs a runner that ALLOWS writes (for the fix engine)
// and records every call. Complements newFakeHost, which forbids writes.
type writeStubHost struct {
	mu    sync.Mutex
	calls []string
}

func newWriteStubHost(t *testing.T) *writeStubHost {
	t.Helper()
	h := &writeStubHost{}
	old := runner
	runner = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		h.mu.Lock()
		h.calls = append(h.calls, name+" "+strings.Join(args, " "))
		h.mu.Unlock()
		// sysctl -n reads succeed with a plausible value; everything else
		// that would change state succeeds silently.
		if name == "sysctl" && len(args) > 0 && args[0] == "-n" {
			return []byte("1\n"), nil
		}
		return []byte(""), nil
	}
	t.Cleanup(func() { runner = old })
	return h
}

func (h *writeStubHost) has(substr string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, c := range h.calls {
		if strings.Contains(c, substr) {
			return true
		}
	}
	return false
}

func resetFixState() {
	fixMu.Lock()
	fixLastRun = map[int]time.Time{}
	fixHour = nil
	fixReports = map[int]*FixReport{}
	fixMu.Unlock()
}

// The fix API must refuse to guess: UNKNOWN verdicts produce a plan with no
// local fix, never an apply.
func TestFixPlanUnknownHasNoActions(t *testing.T) {
	p := fixTestPeer()
	snap := LocalSnapshot{GreIf: p.GreIf, InnerLocal: "10.10.10.1"}
	d := RevPathDiagnosis{Verdict: VerdictUnknown, Confidence: "low"}
	if acts := fixPlan(p, snap, d); len(acts) != 0 {
		t.Fatalf("unknown verdict must plan nothing, got %d actions", len(acts))
	}
	steps, _ := applyFix(p, snap, d, false, true)
	if len(steps) != 1 || steps[0].OK {
		t.Fatalf("dry-run of unknown must be one failed plan step: %+v", steps)
	}
}

// Non-fixable verdicts (ISP / cloud) plan nothing.
func TestFixPlanNonFixableEmpty(t *testing.T) {
	p := fixTestPeer()
	snap := LocalSnapshot{GreIf: p.GreIf}
	for _, v := range []Verdict{VerdictISPICMPOneWay, VerdictISPGreBlock, VerdictCloudSG, VerdictHealthy} {
		if acts := fixPlan(p, snap, RevPathDiagnosis{Verdict: v}); len(acts) != 0 {
			t.Fatalf("%s must plan nothing, got %d", v, len(acts))
		}
	}
}

// Each fixable verdict plans the right shape of actions (dry-run only).
func TestFixPlanShapes(t *testing.T) {
	p := fixTestPeer()
	snap := LocalSnapshot{GreIf: p.GreIf, InnerLocal: "10.10.10.1", GreMTU: 1380}
	cases := map[Verdict]int{
		VerdictRPFilter:         3, // all, default, iface
		VerdictSrcSelect:        1,
		VerdictNoReturnRoute:    1,
		VerdictFwInput:          1,
		VerdictMTUBlackhole:     1,
		VerdictConntrackInvalid: 1,
	}
	for v, n := range cases {
		acts := fixPlan(p, snap, RevPathDiagnosis{Verdict: v, Confidence: "high"})
		if len(acts) != n {
			t.Errorf("%s: %d actions, want %d", v, len(acts), n)
		}
	}
	// MTU already at the floor: nothing to do.
	snap.GreMTU = 1280
	if acts := fixPlan(p, snap, RevPathDiagnosis{Verdict: VerdictMTUBlackhole}); len(acts) != 0 {
		t.Errorf("mtu at floor must plan nothing, got %d", len(acts))
	}
}

// worseAfter: only a move away from HEALTHY counts as worse.
func TestWorseAfter(t *testing.T) {
	h := RevPathDiagnosis{Verdict: VerdictHealthy}
	b := RevPathDiagnosis{Verdict: VerdictRPFilter}
	if !worseAfter(h, RevPathDiagnosis{Verdict: VerdictFwInput}) {
		t.Error("healthy -> broken is worse")
	}
	if worseAfter(b, h) {
		t.Error("broken -> healthy is not worse")
	}
	if worseAfter(b, RevPathDiagnosis{Verdict: VerdictFwInput}) {
		t.Error("broken -> broken is not worse (re-probe decides by verdict)")
	}
}

// A full apply against the write stub runs the exact commands, re-probes,
// and records history. The stub re-probe answers the same world, so the
// verdict is unchanged (not worse) and no rollback happens.
func TestFixApplyRunsExactCommands(t *testing.T) {
	resetFixState()
	h := newWriteStubHost(t)
	p := fixTestPeer()
	snap := LocalSnapshot{GreIf: p.GreIf, InnerLocal: "10.10.10.1"}
	d := RevPathDiagnosis{Verdict: VerdictNoReturnRoute, Confidence: "high"}
	steps, _ := applyFix(p, snap, d, false, false)
	var sawApply, sawVerify bool
	for _, s := range steps {
		if s.Action == "apply" && s.OK {
			sawApply = true
		}
		if s.Action == "verify" {
			sawVerify = true
		}
		if s.Action == "rollback" {
			t.Fatalf("unchanged re-probe must not roll back: %+v", steps)
		}
	}
	if !sawApply || !sawVerify {
		t.Fatalf("expected apply+verify: %+v", steps)
	}
	if !h.has("ip route replace 10.10.10.2 dev gre-t7") {
		t.Fatalf("return route not added: %v", h.calls)
	}
	fixMu.Lock()
	rep := fixReports[p.ID]
	fixMu.Unlock()
	if rep == nil || len(rep.Steps) == 0 {
		t.Fatal("history must be recorded")
	}
	resetFixState()
}

// RPFilter apply writes exactly the three sysctl keys, nothing else.
func TestFixApplyRPFilterKeys(t *testing.T) {
	resetFixState()
	h := newWriteStubHost(t)
	p := fixTestPeer()
	snap := LocalSnapshot{GreIf: p.GreIf}
	d := RevPathDiagnosis{Verdict: VerdictRPFilter, Confidence: "high"}
	applyFix(p, snap, d, false, false)
	for _, k := range []string{"net.ipv4.conf.all.rp_filter=2", "net.ipv4.conf.default.rp_filter=2", "net.ipv4.conf.gre-t7.rp_filter=2"} {
		if !h.has("sysctl -w " + k) {
			t.Errorf("missing %s in %v", k, h.calls)
		}
	}
	resetFixState()
}

// A failed apply rolls back the earlier steps in reverse order.
func TestFixRollbackOnFailure(t *testing.T) {
	resetFixState()
	calls := []string{}
	old := runner
	runner = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		if name == "sysctl" && len(args) > 0 && args[0] == "-n" {
			return []byte("1\n"), nil
		}
		// Fail the route replace, succeed everything else.
		if name == "ip" {
			return nil, errors.New("RTNETLINK answers: No such process")
		}
		return []byte(""), nil
	}
	defer func() { runner = old }()
	p := fixTestPeer()
	snap := LocalSnapshot{GreIf: p.GreIf, InnerLocal: "10.10.10.1"}
	d := RevPathDiagnosis{Verdict: VerdictSrcSelect, Confidence: "high"}
	steps, _ := applyFix(p, snap, d, false, false)
	var sawFail, sawRollback bool
	for _, s := range steps {
		if s.Action == "apply" && !s.OK {
			sawFail = true
		}
		if s.Action == "rollback" {
			sawRollback = true
		}
	}
	if !sawFail || !sawRollback {
		t.Fatalf("expected failed apply + rollback: %+v", steps)
	}
	resetFixState()
}

// Rate limits: second immediate fix is refused; dry-runs never consume quota.
func TestFixRateLimit(t *testing.T) {
	resetFixState()
	newWriteStubHost(t)
	p := fixTestPeer()
	snap := LocalSnapshot{GreIf: p.GreIf, InnerLocal: "10.10.10.1"}
	d := RevPathDiagnosis{Verdict: VerdictNoReturnRoute, Confidence: "high"}
	applyFix(p, snap, d, false, true) // dry-run: no quota consumed
	applyFix(p, snap, d, false, false)
	steps, _ := applyFix(p, snap, d, false, false)
	sawLimit := false
	for _, s := range steps {
		if s.Action == "rate-limited" {
			sawLimit = true
		}
	}
	if !sawLimit {
		t.Fatalf("second immediate fix must be rate-limited: %+v", steps)
	}
	resetFixState()
}

// mergeSpokeReport: spoke results replace placeholders and reclassify.
func TestMergeSpokeReport(t *testing.T) {
	e := &revPathEntry{PeerID: 1}
	e.Matrix.Results = []ProbeResult{
		res(DirHubToSpoke, LayerICMPGre64, true),
		{Layer: LayerICMPGre64, Direction: DirUnprobed},
	}
	rep := &SpokeProbeReport{
		Matrix: ProbeMatrix{Results: []ProbeResult{
			res(DirSpokeToHub, LayerICMPGre64, true),
		}},
	}
	mergeSpokeReport(e, rep)
	if _, ok := e.Matrix.get(DirUnprobed, LayerICMPGre64); ok {
		t.Fatal("placeholders must be replaced")
	}
	r, ok := e.Matrix.get(DirSpokeToHub, LayerICMPGre64)
	if !ok || !r.OK {
		t.Fatalf("spoke result must be present: %+v", e.Matrix.Results)
	}
	if e.Diagnosis.Verdict != VerdictHealthy {
		t.Fatalf("both directions ok => healthy, got %+v", e.Diagnosis)
	}
	mergeSpokeReport(e, nil) // nil report is a no-op
	if e.Diagnosis.Verdict != VerdictHealthy {
		t.Fatal("nil merge must not change the diagnosis")
	}
}

// The spoke probe handler answers with a matrix and snapshot.
func TestSpokeProbeHandler(t *testing.T) {
	body, _ := json.Marshal(SpokeProbeRequest{HubInner: "10.10.10.1", HubPublic: "203.0.113.5", ControlPort: 7091})
	req := httptest.NewRequest("POST", "/api/peer/revpath-probe", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	handlePeerRevPathProbe(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	var rep SpokeProbeReport
	if err := json.Unmarshal(rr.Body.Bytes(), &rep); err != nil || !rep.OK {
		t.Fatalf("bad report: %v %s", err, rr.Body.String())
	}
	found := false
	for _, r := range rep.Matrix.Results {
		if r.Direction == DirSpokeToHub {
			found = true
		}
	}
	if !found {
		t.Fatalf("no spoke->hub results: %+v", rep.Matrix.Results)
	}
}

// probeFromSpoke is read-only: stub runner fails everything, so every layer
// must report failure, never success — and no write commands may appear.
func TestProbeFromSpokeReadOnly(t *testing.T) {
	var calls []string
	prev := runner
	runner = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return nil, fmt.Errorf("no host")
	}
	defer func() { runner = prev }()
	m := probeFromSpoke(SpokeProbeRequest{HubInner: "10.10.10.1", HubPublic: "203.0.113.5", ControlPort: 7091}, LocalSnapshot{InnerLocal: "10.10.10.2"})
	if len(m.Results) == 0 {
		t.Fatal("expected layers even when all fail")
	}
	for _, r := range m.Results {
		if r.OK {
			t.Fatalf("stubbed host must fail every layer: %+v", r)
		}
		if r.Direction != DirSpokeToHub {
			t.Fatalf("wrong direction: %+v", r)
		}
	}
	for _, c := range calls {
		fields := strings.Fields(c)
		if len(fields) == 0 {
			continue
		}
		name, args := fields[0], fields[1:]
		if forbiddenCmd(name, args) {
			t.Fatalf("write command in read-only probe: %s", c)
		}
	}
}

// The fix handler dry-run path returns a plan without touching the host.
func TestFixHandlerDryRun(t *testing.T) {
	newFakeHost(t, "")
	writePeersFile(t, fixTestPeer())
	body, _ := json.Marshal(map[string]any{"peer_id": 7})
	req := httptest.NewRequest("POST", "/api/revpath/fix", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	handleRevPathFix(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	var out struct {
		DryRun    bool             `json:"dry_run"`
		Diagnosis RevPathDiagnosis `json:"diagnosis"`
		Steps     []FixStep        `json:"steps"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil || !out.DryRun {
		t.Fatalf("bad dry-run response: %v %s", err, rr.Body.String())
	}
}

// Auto apply with the flag off is refused.
func TestFixHandlerAutoOff(t *testing.T) {
	newFakeHost(t, "")
	writePeersFile(t, fixTestPeer())
	body, _ := json.Marshal(map[string]any{"peer_id": 7, "apply": true, "auto": true})
	req := httptest.NewRequest("POST", "/api/revpath/fix", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	handleRevPathFix(rr, req)
	if rr.Code == http.StatusOK {
		t.Fatalf("auto fix with flag off must be refused: %s", rr.Body.String())
	}
}
