package main

// Testing the way between two of the central's servers from the Nodes page,
// with nothing to copy between them:
//
//   - the path test (pathtest.go), before or without a tunnel: the central
//     starts it on the Iran server with the foreign server's address, then
//     joins the foreign server with the code that answer carries. The page
//     reads the Iran server's results (GET /api/nodes?view=pathtest);
//   - the carrier benchmark (benchmark.go) of a tunnel between the two: run
//     on its Iran server, aimed at that tunnel's foreign server.
//
// Each server checks its own license, as when the test is run on its page.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"
)

const (
	nodeProbeTO      = 2 * time.Minute // starting or stopping a path test
	nodeBenchTO      = 6 * time.Minute // one benchmark run
	nodePathMinutes  = 10              // a path test's lifetime on the servers
	nodeProbeMaxNote = 300
)

// nodeProbePair checks that server and client are two different servers this
// central may use (online and approved; 0 is the central itself).
func nodeProbePair(server, client int) error {
	if server == client {
		return errors.New("pick two different servers")
	}
	for _, id := range []int{server, client} {
		if id < 0 {
			return errors.New("pick both servers")
		}
		if id == 0 {
			continue
		}
		nodesMu.Lock()
		nodesLoadLocked()
		held, known := false, false
		for _, rec := range nodesF.Nodes {
			if rec.ID == id {
				known, held = true, rec.Held
			}
		}
		nodesMu.Unlock()
		switch {
		case !known:
			return fmt.Errorf("server %d is not a node of this panel", id)
		case held:
			return fmt.Errorf("%s is not approved yet", nodeTunName(id))
		case nodeSessionFor(id) == nil:
			return fmt.Errorf("%s is offline", nodeTunName(id))
		}
	}
	return nil
}

// nodePathTestStart starts the path test on server (the Iran side) and joins
// client to it. A failed join stops the server's half again.
func nodePathTestStart(ctx context.Context, server, client int) (ptView, error) {
	var v ptView
	if err := nodeProbePair(server, client); err != nil {
		return v, err
	}
	sp, err := nodeTunPlanProof(ctx, server, "", 0, "")
	if err != nil {
		return v, err
	}
	cp, err := nodeTunPlanProof(ctx, client, "", 0, "")
	if err != nil {
		return v, err
	}
	if cp.Public == "" {
		return v, fmt.Errorf("%s does not know its public IP", nodeTunName(client))
	}
	// a test left running from before is replaced
	_ = nodeAPIJSON(ctx, server, http.MethodPost, "/api/pathtest", map[string]any{"action": "stop"}, nil)
	_ = nodeAPIJSON(ctx, client, http.MethodPost, "/api/pathtest", map[string]any{"action": "stop"}, nil)
	start := map[string]any{"action": "start", "foreign_ip": cp.Public, "iran_ip": sp.Public, "minutes": nodePathMinutes}
	if err := nodeAPIJSON(ctx, server, http.MethodPost, "/api/pathtest", start, &v); err != nil {
		return v, err
	}
	if v.Code == "" {
		_ = nodeAPIJSON(ctx, server, http.MethodPost, "/api/pathtest", map[string]any{"action": "stop"}, nil)
		return v, fmt.Errorf("%s gave no code for the test", nodeTunName(server))
	}
	if err := nodeAPIJSON(ctx, client, http.MethodPost, "/api/pathtest", map[string]any{"action": "join", "code": v.Code}, nil); err != nil {
		_ = nodeAPIJSON(ctx, server, http.MethodPost, "/api/pathtest", map[string]any{"action": "stop"}, nil)
		return v, err
	}
	v.Code = "" // the page needs no code: both ends are set up
	return v, nil
}

// nodePathTestView is the path test as the Iran server sees it now.
func nodePathTestView(ctx context.Context, server int) (ptView, error) {
	var v ptView
	if server != 0 && nodeSessionFor(server) == nil {
		return v, fmt.Errorf("%s is offline", nodeTunName(server))
	}
	err := nodeAPIJSON(ctx, server, http.MethodGet, "/api/pathtest", nil, &v)
	v.Code = ""
	return v, err
}

// nodePathTestStop stops the test on both servers (either may be gone).
func nodePathTestStop(ctx context.Context, server, client int) {
	for _, id := range []int{client, server} {
		if id == 0 || (id > 0 && nodeSessionFor(id) != nil) {
			_ = nodeAPIJSON(ctx, id, http.MethodPost, "/api/pathtest", map[string]any{"action": "stop"}, nil)
		}
	}
}

// nodeBenchRun runs the carrier benchmark of the tunnel between server and
// client (peer: its id on the server, 0 for any one of them) on the server.
func nodeBenchRun(ctx context.Context, server, client, peer int) (BenchmarkReport, error) {
	var rep BenchmarkReport
	if err := nodeProbePair(server, client); err != nil {
		return rep, err
	}
	pctx, cancel := context.WithTimeout(ctx, nodeTunPlanTO)
	links, _, plans := nodeTunLinksPlans(pctx)
	cancel()
	var link *nodeTunLink
	for i := range links {
		l := &links[i]
		if l.Server == server && l.Client == client && (peer == 0 || l.PeerID == peer) {
			link = l
			break
		}
	}
	if link == nil {
		return rep, errors.New("there is no tunnel between these servers: test the paths instead, it needs none")
	}
	req := BenchmarkRunRequest{TargetHost: link.ClientIP}
	for _, p := range plans[server].Peers {
		if p.ID == link.PeerID && p.FrpPort > 0 {
			req.FrpPort = p.FrpPort
		}
	}
	bctx, cancel := context.WithTimeout(ctx, nodeBenchTO)
	defer cancel()
	err := nodeAPIJSON(bctx, server, http.MethodPost, "/api/benchmark/run", req, &rep)
	for i := range rep.Metrics { // a server's own words: kept short on this page
		rep.Metrics[i].ErrorDetail = nodeClipLen(rep.Metrics[i].ErrorDetail, nodeProbeMaxNote)
	}
	return rep, err
}

func nodeClipLen(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
