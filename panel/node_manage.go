package main

// Nodes: what the central does with a tunnel between two of its servers
// after it is made, and Autopilot seen across every server.
//
// Autopilot itself runs on each tunnel's Iran server, as before: that server
// sees the tunnel go down and holds its ports and tokens. The central only
// reads every server's own Autopilot view (GET /api/autopilot) and changes
// its settings with that server's own API, so the server's license check
// and audit apply as if its own page had asked.
//
// A tunnel's carrier, ports and path test stay with the Iran server's own
// pages: the central opens them in that server's view (app.js). What is
// done from here directly is what needs both ends: a restart, and removal
// (node_tunnel.go).

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sync"
)

const (
	nodeApEventsMax = 10 // a server's newest Autopilot events the central shows
	nodeApTextMax   = 300
)

// nodeApTunnel is a tunnel in a server's Autopilot view. Client is the
// server at its other end when that is one of the central's (-1: it is not).
type nodeApTunnel struct {
	apTunnelView
	Client int `json:"client"`
}

type nodeApServer struct {
	ID       int            `json:"id"` // 0: the central
	Name     string         `json:"name"`
	Licensed bool           `json:"licensed"`
	Enabled  bool           `json:"enabled"`
	Tunnels  []nodeApTunnel `json:"tunnels"`
	Events   []apEvent      `json:"events"`
	Switched int            `json:"switched_day"`
	Failed   int            `json:"failed_day"`
}

// nodeApView is what a server's GET /api/autopilot answers, as far as the
// central reads it.
type nodeApView struct {
	Config   autopilotConfig `json:"config"`
	Licensed bool            `json:"licensed"`
	Iran     bool            `json:"iran"`
	Tunnels  []apTunnelView  `json:"tunnels"`
	Events   []apEvent       `json:"events"`
	Switched int             `json:"switched_day"`
	Failed   int             `json:"failed_day"`
}

func nodeClip(s string) string {
	if len(s) > nodeApTextMax {
		s = s[:nodeApTextMax]
	}
	return nodeLogText([]byte(s))
}

// nodeOnlineIDs: the central and every node that is online and approved.
func nodeOnlineIDs() []int {
	ids := []int{0}
	nodesMu.Lock()
	nodesLoadLocked()
	for _, rec := range nodesF.Nodes {
		if nodeSessions[rec.ID] != nil && !rec.Held {
			ids = append(ids, rec.ID)
		}
	}
	nodesMu.Unlock()
	return ids
}

// nodeApViews reads every online server's Autopilot view.
func nodeApViews(ctx context.Context) (map[int]nodeApView, []string) {
	views := map[int]nodeApView{}
	var errs []string
	var mu sync.Mutex
	var wg sync.WaitGroup
	lim := make(chan struct{}, nodeFleetParallel)
	for _, id := range nodeOnlineIDs() {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			lim <- struct{}{}
			defer func() { <-lim }()
			var v nodeApView
			err := nodeAPIJSON(ctx, id, http.MethodGet, "/api/autopilot", nil, &v)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err.Error())
				return
			}
			v.Tunnels = capList(v.Tunnels)
			views[id] = v
		}(id)
	}
	wg.Wait()
	slices.Sort(errs)
	return views, errs
}

// nodeApFleet is Autopilot on every Iran server of the central: its
// tunnels, whether it is on, and its newest events. links name the other
// end of a tunnel.
func nodeApFleet(views map[int]nodeApView, links []nodeTunLink) []nodeApServer {
	client := map[[2]int]int{}
	for _, l := range links {
		client[[2]int{l.Server, l.PeerID}] = l.Client
	}
	out := []nodeApServer{}
	for id, v := range views {
		if !v.Iran {
			continue // Autopilot runs on the Iran side only
		}
		s := nodeApServer{ID: id, Name: nodeTunName(id), Licensed: v.Licensed, Enabled: v.Config.Enabled,
			Tunnels: []nodeApTunnel{}, Events: []apEvent{}, Switched: v.Switched, Failed: v.Failed}
		for _, t := range v.Tunnels {
			t.Name, t.Carrier, t.State, t.Waiting, t.Progress = nodeClip(t.Name), nodeClip(t.Carrier), nodeClip(t.State), nodeClip(t.Waiting), nodeClip(t.Progress)
			t.Engine, t.LastRun = nodeClip(t.Engine), nodeClip(t.LastRun)
			c, ok := client[[2]int{id, t.ID}]
			if !ok {
				c = -1
			}
			s.Tunnels = append(s.Tunnels, nodeApTunnel{apTunnelView: t, Client: c})
		}
		for i, e := range v.Events { // newest first
			if i == nodeApEventsMax {
				break
			}
			e.At, e.Name, e.Kind, e.From, e.To, e.Text = nodeClip(e.At), nodeClip(e.Name), nodeClip(e.Kind), nodeClip(e.From), nodeClip(e.To), nodeClip(e.Text)
			s.Events = append(s.Events, e)
		}
		out = append(out, s)
	}
	slices.SortFunc(out, func(a, b nodeApServer) int { return a.ID - b.ID })
	return out
}

// nodeApSet turns Autopilot on or off on server id, or (tunnel set) has it
// watch or leave one tunnel. The server's own handler decides: turning it
// on needs that server's license.
func nodeApSet(ctx context.Context, id int, tunnel *int, on bool) error {
	if tunnel == nil {
		return nodeAPIJSON(ctx, id, http.MethodPost, "/api/autopilot", map[string]any{"enabled": on}, nil)
	}
	var v nodeApView
	if err := nodeAPIJSON(ctx, id, http.MethodGet, "/api/autopilot", nil, &v); err != nil {
		return err
	}
	if !slices.ContainsFunc(v.Tunnels, func(t apTunnelView) bool { return t.ID == *tunnel }) {
		return fmt.Errorf("%s has no tunnel %d (any more): refresh the list", nodeTunName(id), *tunnel)
	}
	skip := slices.DeleteFunc(slices.Clone(v.Config.Skip), func(x int) bool { return x == *tunnel })
	if !on {
		skip = append(skip, *tunnel)
	}
	if skip == nil {
		skip = []int{}
	}
	return nodeAPIJSON(ctx, id, http.MethodPost, "/api/autopilot", map[string]any{"skip": skip}, nil)
}

// nodeTunLinksLive is nodeTunLinks with what each tunnel's Iran server says
// about it now. A server that does not answer its Autopilot view (an older
// version) leaves its tunnels without a state; that is not an error here.
func nodeTunLinksLive(ctx context.Context) ([]nodeTunLink, []string) {
	var views map[int]nodeApView
	done := make(chan struct{})
	go func() {
		defer close(done)
		views, _ = nodeApViews(ctx)
	}()
	links, errs := nodeTunLinks(ctx)
	<-done
	for i := range links {
		l := &links[i]
		v, ok := views[l.Server]
		if !ok {
			continue
		}
		for _, t := range v.Tunnels {
			if t.ID != l.PeerID {
				continue
			}
			l.State, l.Carrier, l.CanSwap = nodeClip(t.State), nodeClip(t.Carrier), t.CanSwap
			l.Working = t.Running
			l.Auto = "off"
			if v.Config.Enabled && v.Licensed && t.CanSwap && !t.Skipped {
				l.Auto = "on"
			}
		}
	}
	return links, errs
}

// nodeTunFindLink finds the tunnel q names: it must be listed exactly once
// from both servers' plans.
func nodeTunFindLink(ctx context.Context, q nodeTunRemoveReq) (nodeTunLink, error) {
	pctx, cancel := context.WithTimeout(ctx, nodeTunPlanTO)
	links, _ := nodeTunLinks(pctx)
	cancel()
	var link nodeTunLink
	n := 0
	for _, l := range links {
		if l.Server == q.Server && l.Client == q.Client && l.PeerID == q.PeerID && l.Hub == q.Hub {
			link = l
			n++
		}
	}
	if n != 1 {
		return link, errors.New("this tunnel is not listed between these servers (any more): refresh the list")
	}
	return link, nil
}

// nodeTunRestart restarts the tunnel's engine on its Iran server, then on
// the foreign one. A foreign server that joined this Iran server as one
// more hub is left alone: its client reconnects by itself.
func nodeTunRestart(ctx context.Context, j *nodeTunJob, q nodeTunRemoveReq) error {
	if _, err := nodeTunFindLink(ctx, q); err != nil {
		return err
	}
	j.logf("restarting the tunnel's engine on %s", nodeTunName(q.Server))
	sctx, cancel := context.WithTimeout(ctx, nodeTunActionTO)
	err := nodeAPIJSON(sctx, q.Server, http.MethodPost, "/api/action", map[string]any{"action": "restart-engine", "peer_id": q.PeerID}, nil)
	cancel()
	if err != nil {
		return fmt.Errorf("%v; the foreign server was not touched", err)
	}
	if q.Hub != 1 {
		j.logf("%s dials this tunnel as one more hub: its client reconnects by itself", nodeTunName(q.Client))
		return nil
	}
	j.logf("restarting the tunnel's engine on %s", nodeTunName(q.Client))
	cctx, cancel := context.WithTimeout(ctx, nodeTunActionTO)
	err = nodeAPIJSON(cctx, q.Client, http.MethodPost, "/api/action", map[string]any{"action": "restart-engine", "peer_id": 0}, nil)
	cancel()
	if err != nil {
		return fmt.Errorf("the Iran server's end was restarted; the foreign server's: %v", err)
	}
	nodeAuditf("node_tunnel_restarted", "server=%d client=%d peer=%d", q.Server, q.Client, q.PeerID)
	return nil
}
