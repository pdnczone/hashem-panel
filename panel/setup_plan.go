package main

// GET /api/setup/plan: what a central needs to make a tunnel to or from this
// server (nodes N3): its address, whether it already has a tunnel, the Iran
// servers it dials, the GRE inner addresses it uses, a free control port,
// and which of the wanted user ports another of Hashem's configs holds (the
// port registry, ports_registry.go). It only reads.

import (
	"net"
	"net/http"
	"strconv"
	"strings"
)

type setupPlanPeer struct {
	ID        int    `json:"id"`
	Name      string `json:"name,omitempty"`
	RemotePub string `json:"remote_pub"`
	LocalGre  string `json:"local_gre,omitempty"`
	PeerGre   string `json:"peer_gre,omitempty"`
	FrpPort   int    `json:"frp_port,omitempty"`
	Engine    string `json:"engine,omitempty"`
}

// setupPlanUplink is a tunnel this server dials as the foreign side: the
// first tunnel (Hub 1) or a hub it joined.
type setupPlanUplink struct {
	Hub     int    `json:"hub"` // 1: the first tunnel; 2 and up: leave-hub id
	IranPub string `json:"iran_pub"`
	Engine  string `json:"engine,omitempty"`
}

type setupPlan struct {
	Public    string            `json:"public"`
	Exists    bool              `json:"exists"` // a first tunnel is set up here
	Side      string            `json:"side,omitempty"`
	Peers     []setupPlanPeer   `json:"peers"`   // tunnels this server serves (Iran side)
	Uplinks   []setupPlanUplink `json:"uplinks"` // tunnels this server dials (foreign side)
	GreUsed   []string          `json:"gre_used"`
	RelayPort int               `json:"relay_port"`        // a free control port
	Clashes   map[string]string `json:"clashes,omitempty"` // wanted port -> who holds it
}

const setupPlanPortMin, setupPlanPortMax = 7001, 7999

// setupPlanListening is a test hook: whether something listens on tcp port.
var setupPlanListening = func(port int) bool {
	l, err := net.Listen("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		return true
	}
	_ = l.Close()
	return false
}

func handleSetupPlan(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, buildSetupPlan(r.URL.Query().Get("ports")))
}

func buildSetupPlan(wanted string) setupPlan {
	info := nodeInfoFn()
	p := setupPlan{Public: info.PublicIP, Side: info.Side, Exists: tunnelExists(),
		Peers: []setupPlanPeer{}, Uplinks: []setupPlanUplink{}, GreUsed: []string{}}
	if p.Public == "" {
		p.Public = detectPublicIP()
	}
	gre := map[string]bool{}
	for _, x := range loadPeers() {
		p.Peers = append(p.Peers, setupPlanPeer{ID: x.ID, Name: x.Name, RemotePub: x.RemotePub, LocalGre: x.LocalGre,
			PeerGre: x.PeerGre, FrpPort: x.FrpPort, Engine: x.Engine})
		gre[x.LocalGre], gre[x.PeerGre] = true, true
	}
	// the first tunnel of an Iran server that has no peer record of its own
	if peers := loadPeers(); p.Exists && p.Side == "iran" && basePeer(peers) == nil {
		if m := readSetupMeta(); m.RemotePub != "" {
			p.Peers = append(p.Peers, setupPlanPeer{ID: 0, RemotePub: m.RemotePub, LocalGre: m.IranGre, PeerGre: m.ForeignGre, Engine: m.Engine})
		}
	}
	for _, h := range readJoinedHubs() {
		p.Uplinks = append(p.Uplinks, setupPlanUplink{Hub: h.ID, IranPub: h.IranPub, Engine: h.Engine})
		gre[h.IranGre] = true
	}
	if len(p.Uplinks) == 0 && p.Side == "foreign" {
		if m := readSetupMeta(); m.RemotePub != "" {
			p.Uplinks = append(p.Uplinks, setupPlanUplink{Hub: 1, IranPub: m.RemotePub, Engine: m.Engine})
		}
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ip, _, err := net.ParseCIDR(a.String()); err == nil && ip.To4() != nil {
				gre[ip.String()] = true
			}
		}
	}
	for a := range gre {
		if a != "" {
			p.GreUsed = append(p.GreUsed, a)
		}
	}
	claims := indexClaims(hashemPortClaims())
	for port := setupPlanPortMin; port <= setupPlanPortMax; port++ {
		if claims.owner("tcp", port, nil) == "" && !setupPlanListening(port) {
			p.RelayPort = port
			break
		}
	}
	for _, f := range strings.Split(wanted, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(f))
		if err != nil || n < 1 || n > 65535 {
			continue
		}
		if who := claims.owner("tcp", n, nil); who != "" {
			if p.Clashes == nil {
				p.Clashes = map[string]string{}
			}
			p.Clashes[strconv.Itoa(n)] = who
		}
	}
	return p
}
