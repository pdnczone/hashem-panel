package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// nodeManageFake: a tunnel 1 (Iran) -> 2 (foreign) and each server's
// Autopilot view; posts are recorded as "id path body".
func nodeManageFake(t *testing.T) (*nodeTunFake, *[]string) {
	t.Helper()
	f := nodeTunTest(t)
	f.plans[1].Peers = []setupPlanPeer{{ID: 4, RemotePub: "192.0.2.7", Engine: "frp"}}
	f.plans[2].Uplinks = []setupPlanUplink{{Hub: 1, IranPub: "198.51.100.1"}}
	views := map[int]*nodeApView{
		1: {Iran: true, Licensed: true, Config: autopilotConfig{Enabled: true, Skip: []int{9}},
			Tunnels: []apTunnelView{{ID: 4, Name: "de", State: "down", CanSwap: true, Carrier: "frp:tcp"}, {ID: 9, Name: "out", State: "healthy", CanSwap: true}},
			Events:  []apEvent{{At: "2026-11-13T10:00:00Z", Tunnel: 4, Kind: "switched", Text: strings.Repeat("x", 2000)}}},
		2: {Iran: false, Tunnels: []apTunnelView{{ID: 0, Name: "main"}}},
	}
	var posts []string
	nodeFleetFake(t, f, nil, func(id int, path string) (int, []byte, bool) { return 0, nil, false })
	inner := nodeAPIFn
	nodeAPIFn = func(ctx context.Context, id int, method, path string, body any) (int, []byte, error) {
		if method == "POST" {
			b, _ := json.Marshal(body)
			posts = append(posts, fmt.Sprintf("%d %s %s", id, path, b))
		}
		switch path {
		case "/api/autopilot":
			v := views[id]
			if v == nil {
				return 404, []byte(`{"error":"not found"}`), nil // a version before Autopilot
			}
			if method == "POST" {
				b, _ := json.Marshal(body)
				_ = json.Unmarshal(b, &v.Config)
			}
			b, _ := json.Marshal(v)
			return 200, b, nil
		case "/api/action":
			return 200, []byte(`{"output":"ok"}`), nil
		}
		return inner(ctx, id, method, path, body)
	}
	return f, &posts
}

func TestNodeTunLinksLive(t *testing.T) {
	nodeManageFake(t)
	links, _ := nodeTunLinksLive(context.Background())
	if len(links) != 1 {
		t.Fatalf("links: %+v", links)
	}
	l := links[0]
	if l.State != "down" || l.Carrier != "frp:tcp" || !l.CanSwap || l.Auto != "on" {
		t.Fatalf("live: %+v", l)
	}
}

func TestNodeApFleet(t *testing.T) {
	nodeManageFake(t)
	ctx := context.Background()
	views, errs := nodeApViews(ctx)
	if len(views) != 2 || len(errs) != 1 { // the central (0) has no Autopilot here
		t.Fatalf("views %d, errors %v", len(views), errs)
	}
	links, _ := nodeTunLinks(ctx)
	fleet := nodeApFleet(views, links)
	if len(fleet) != 1 || fleet[0].ID != 1 || !fleet[0].Enabled {
		t.Fatalf("only the Iran server is listed: %+v", fleet)
	}
	s := fleet[0]
	if len(s.Tunnels) != 2 || s.Tunnels[0].Client != 2 || s.Tunnels[1].Client != -1 {
		t.Fatalf("tunnels: %+v", s.Tunnels)
	}
	if len(s.Events) != 1 || len(s.Events[0].Text) > nodeApTextMax {
		t.Fatalf("events: %+v", s.Events)
	}
}

func TestNodeApSet(t *testing.T) {
	_, posts := nodeManageFake(t)
	ctx := context.Background()
	if err := nodeApSet(ctx, 1, nil, false); err != nil {
		t.Fatal(err)
	}
	four, nine, none := 4, 9, 77
	if err := nodeApSet(ctx, 1, &four, false); err != nil {
		t.Fatal(err)
	}
	if err := nodeApSet(ctx, 1, &nine, true); err != nil {
		t.Fatal(err)
	}
	if err := nodeApSet(ctx, 1, &four, true); err != nil {
		t.Fatal(err)
	}
	want := []string{
		`1 /api/autopilot {"enabled":false}`,
		`1 /api/autopilot {"skip":[9,4]}`,
		`1 /api/autopilot {"skip":[4]}`,
		`1 /api/autopilot {"skip":[]}`,
	}
	if strings.Join(*posts, "\n") != strings.Join(want, "\n") {
		t.Fatalf("posts:\n%s", strings.Join(*posts, "\n"))
	}
	if err := nodeApSet(ctx, 1, &none, false); err == nil {
		t.Fatal("a tunnel the server does not have")
	}
}

func TestNodeTunRestart(t *testing.T) {
	_, posts := nodeManageFake(t)
	ctx := context.Background()
	j := &nodeTunJob{}
	if err := nodeTunRestart(ctx, j, nodeTunRemoveReq{Server: 1, Client: 2, PeerID: 4, Hub: 1}); err != nil {
		t.Fatal(err)
	}
	want := `1 /api/action {"action":"restart-engine","peer_id":4}` + "\n" + `2 /api/action {"action":"restart-engine","peer_id":0}`
	if strings.Join(*posts, "\n") != want {
		t.Fatalf("posts:\n%s", strings.Join(*posts, "\n"))
	}
	*posts = nil
	if err := nodeTunRestart(ctx, j, nodeTunRemoveReq{Server: 1, Client: 2, PeerID: 5, Hub: 1}); err == nil || len(*posts) != 0 {
		t.Fatalf("a tunnel that is not listed: %v %v", err, *posts)
	}
}
