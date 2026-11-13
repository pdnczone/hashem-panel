package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// nodeProbeFake: the tunnel 1 (Iran) -> 2 (foreign) of nodeManageFake, with
// each server's path test and benchmark; posts are recorded "id path body".
func nodeProbeFake(t *testing.T, joinFails bool) *[]string {
	t.Helper()
	nodeManageFake(t)
	var calls []string
	inner := nodeAPIFn
	nodeAPIFn = func(ctx context.Context, id int, method, path string, body any) (int, []byte, error) {
		switch path {
		case "/api/pathtest":
			b, _ := json.Marshal(body)
			calls = append(calls, fmt.Sprintf("%d %s %s", id, method, b))
			var q map[string]any
			_ = json.Unmarshal(b, &q)
			switch {
			case method == "GET":
				return 200, []byte(`{"active":true,"role":"hub","code":"SECRET","joined":true,"checks":[{"id":"tcp","engine":"frp","name":"TCP","proto":"tcp","status":"ok","rtt_ms":40}]}`), nil
			case q["action"] == "start":
				return 200, []byte(`{"active":true,"role":"hub","code":"CODE-` + fmt.Sprint(id) + `"}`), nil
			case q["action"] == "join" && joinFails:
				return 402, []byte(`{"error_code":"E-PRO-01","error":"The path test needs a license"}`), nil
			}
			return 200, []byte(`{"active":true}`), nil
		case "/api/benchmark/run":
			b, _ := json.Marshal(body)
			calls = append(calls, fmt.Sprintf("%d %s %s", id, method, b))
			return 200, []byte(`{"best_carrier":"frp:tcp","metrics":[{"id":"frp:tcp","status":"healthy","score":90,"error_detail":"` + strings.Repeat("x", 900) + `"}]}`), nil
		}
		return inner(ctx, id, method, path, body)
	}
	return &calls
}

func TestNodePathTestFromCentral(t *testing.T) {
	calls := nodeProbeFake(t, false)
	v, err := nodePathTestStart(context.Background(), 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	if v.Code != "" {
		t.Errorf("the code reached the page: %q", v.Code)
	}
	got := strings.Join(*calls, "\n")
	start := strings.Index(got, `1 POST {"action":"start","foreign_ip":"192.0.2.7","iran_ip":"198.51.100.1","minutes":10}`)
	join := strings.Index(got, `2 POST {"action":"join","code":"CODE-1"}`)
	if start < 0 || join < start {
		t.Fatalf("calls:\n%s", got)
	}
	if v, err := nodePathTestView(context.Background(), 1); err != nil || v.Code != "" || len(v.Checks) != 1 {
		t.Fatalf("view: %+v %v", v, err)
	}
}

func TestNodePathTestJoinFailsStopsTheIranSide(t *testing.T) {
	calls := nodeProbeFake(t, true)
	_, err := nodePathTestStart(context.Background(), 1, 2)
	if err == nil || !strings.Contains(err.Error(), "license") {
		t.Fatalf("err: %v", err)
	}
	if last := (*calls)[len(*calls)-1]; last != `1 POST {"action":"stop"}` {
		t.Fatalf("the Iran side was not stopped: %s", strings.Join(*calls, "\n"))
	}
}

func TestNodeProbePair(t *testing.T) {
	nodeProbeFake(t, false)
	nodesMu.Lock()
	nodesF.Nodes = append(nodesF.Nodes, nodeRecord{ID: 5, Name: "held", Key: "K5", Held: true})
	nodesMu.Unlock()
	for _, c := range []struct{ s, c int }{{1, 1}, {1, 9}, {5, 1}, {-1, 2}} {
		if err := nodeProbePair(c.s, c.c); err == nil {
			t.Errorf("%d -> %d accepted", c.s, c.c)
		}
	}
	if err := nodeProbePair(0, 2); err != nil {
		t.Errorf("central -> 2: %v", err)
	}
}

func TestNodeBenchRunAimsAtTheTunnel(t *testing.T) {
	calls := nodeProbeFake(t, false)
	rep, err := nodeBenchRun(context.Background(), 1, 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(*calls, "\n"); !strings.Contains(got, `1 POST {"target_host":"192.0.2.7"}`) {
		t.Fatalf("calls: %s", got)
	}
	if rep.BestCarrier != "frp:tcp" || len(rep.Metrics[0].ErrorDetail) > nodeProbeMaxNote+4 {
		t.Fatalf("report: %+v", rep)
	}
	if _, err := nodeBenchRun(context.Background(), 2, 1, 0); err == nil || !strings.Contains(err.Error(), "no tunnel") {
		t.Fatalf("no tunnel the other way: %v", err)
	}
}
