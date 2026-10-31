package main

// GET /api/setup/plan: what a central needs to make a tunnel to or from this
// server (nodes N3): its address, its tunnels (the first one included), the
// Iran servers it dials, the GRE inner addresses it uses, a free control
// port, which of the wanted user ports another of Hashem's configs holds
// (the port registry, ports_registry.go), and what its own license allows.
// It only reads.

import (
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type setupPlanPeer struct {
	ID        int    `json:"id"` // 0: the first tunnel (no peer record)
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
	Public     string            `json:"public"`
	Exists     bool              `json:"exists"` // a first tunnel is set up here
	Side       string            `json:"side,omitempty"`
	Peers      []setupPlanPeer   `json:"peers"`   // tunnels this server serves (Iran side)
	Uplinks    []setupPlanUplink `json:"uplinks"` // tunnels this server dials (foreign side)
	GreUsed    []string          `json:"gre_used"`
	RelayPort  int               `json:"relay_port"`            // a free control port
	RelayTaken string            `json:"relay_taken,omitempty"` // ?relay=N: why N is not free
	Clashes    map[string]string `json:"clashes,omitempty"`     // wanted port -> who holds it
	Pro        map[string]bool   `json:"pro"`                   // what this server's own license allows (read only)
}

const setupPlanPortMin, setupPlanPortMax = 7001, 7999

// setupPlanListening is a test hook: whether something holds port (TCP or UDP).
var setupPlanListening = func(port int) bool {
	l, err := net.Listen("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		return true
	}
	_ = l.Close()
	u, err := net.ListenPacket("udp", ":"+strconv.Itoa(port)) // FRP kcp/quic and Backhaul's UDP companion
	if err != nil {
		return true
	}
	_ = u.Close()
	return false
}

func handleSetupPlan(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	relay, _ := strconv.Atoi(q.Get("relay"))
	writeJSON(w, buildSetupPlan(q.Get("ports"), relay))
}

// ---- the first tunnel ----

// firstTunnelRec is first_tunnel.json, written by a successful Setup of the
// first tunnel (handleSetupPost). The live state wins where it has an answer.
type firstTunnelRec struct {
	Side      string `json:"side"` // iran | foreign
	LocalPub  string `json:"local_public,omitempty"`
	RemotePub string `json:"remote_public,omitempty"`
	LocalGre  string `json:"local_gre,omitempty"`
	PeerGre   string `json:"peer_gre,omitempty"`
	Engine    string `json:"engine,omitempty"`
}

func firstTunnelFile() string { return filepath.Join(configDir, "first_tunnel.json") }

func firstTunnelSave(r firstTunnelRec) {
	b, _ := json.Marshal(r)
	_ = writeFile0600(firstTunnelFile(), b)
}

// firstTunnelForget: the first tunnel was removed.
func firstTunnelForget() { _ = os.Remove(firstTunnelFile()) }

// firstTunnel is the first tunnel as the plan sees it.
type firstTunnel struct {
	Exists            bool
	Side              string
	RemotePub         string // the other server's public address ("" when not known)
	LocalGre, PeerGre string
	Engine            string
}

var firstTunnelInfo = func() firstTunnel {
	var rec firstTunnelRec
	if b, err := os.ReadFile(firstTunnelFile()); err == nil {
		_ = json.Unmarshal(b, &rec)
	}
	ft := firstTunnel{Exists: tunnelExists()}
	if !ft.Exists {
		return ft
	}
	st := currentLocal()
	switch r := strings.ToLower(st.Role); {
	case strings.Contains(r, "iran") || r == "master":
		ft.Side = "iran"
	case strings.Contains(r, "foreign") || strings.Contains(r, "kharej"):
		ft.Side = "foreign"
	default:
		ft.Side = rec.Side
	}
	ft.Engine = st.Engine
	// the other server: gre-tunnel's outer remote, then the record (when it
	// is about the same side), then a public address in the engine's config
	pub := func(s string) bool { return validPublicIP(s, 0) }
	switch {
	case pub(st.GrePeer):
		ft.RemotePub = st.GrePeer
	case rec.Side == ft.Side && pub(rec.RemotePub):
		ft.RemotePub = rec.RemotePub
	case pub(st.RemotePub):
		ft.RemotePub = st.RemotePub
	}
	if in := strings.SplitN(st.Gre.Inner, "/", 2)[0]; in != "" {
		ft.LocalGre, ft.PeerGre = in, grePeerInner(st.Gre.Inner)
	} else if rec.Side == ft.Side {
		ft.LocalGre, ft.PeerGre = rec.LocalGre, rec.PeerGre
	}
	if ft.Engine == "" && rec.Side == ft.Side {
		ft.Engine = rec.Engine
	}
	return ft
}

func buildSetupPlan(wanted string, relay int) setupPlan {
	info := nodeInfoFn()
	ft := firstTunnelInfo()
	p := setupPlan{Public: info.PublicIP, Side: info.Side, Exists: ft.Exists,
		Peers: []setupPlanPeer{}, Uplinks: []setupPlanUplink{}, GreUsed: []string{},
		Pro: map[string]bool{"backhaul": hasPro(proBackhaul), "cluster": hasPro("cluster")}}
	if p.Public == "" {
		p.Public = detectPublicIP()
	}
	if p.Public == "" {
		p.Public = detectPublicIP6() // an IPv6-only server
	}
	if p.Side == "" {
		p.Side = ft.Side
	}
	gre := map[string]bool{ft.LocalGre: true, ft.PeerGre: true}
	peers := loadPeers()
	for _, x := range peers {
		p.Peers = append(p.Peers, setupPlanPeer{ID: x.ID, Name: x.Name, RemotePub: x.RemotePub, LocalGre: x.LocalGre,
			PeerGre: x.PeerGre, FrpPort: x.FrpPort, Engine: x.Engine})
		gre[x.LocalGre], gre[x.PeerGre] = true, true
	}
	// the first tunnel of an Iran server, unless a peer record is it
	if ft.Exists && ft.Side == "iran" && basePeer(peers) == nil {
		p.Peers = append(p.Peers, setupPlanPeer{ID: 0, RemotePub: ft.RemotePub, LocalGre: ft.LocalGre, PeerGre: ft.PeerGre, Engine: ft.Engine})
	}
	// a foreign server: its first tunnel is Hub 1, joined hubs are 2 and up
	if ft.Exists && ft.Side == "foreign" {
		p.Uplinks = append(p.Uplinks, setupPlanUplink{Hub: 1, IranPub: ft.RemotePub, Engine: ft.Engine})
	}
	for _, h := range readJoinedHubs() {
		if h.ID >= 2 {
			p.Uplinks = append(p.Uplinks, setupPlanUplink{Hub: h.ID, IranPub: h.IranPub, Engine: h.Engine})
		}
		gre[h.IranGre] = true
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
	if relay > 0 && relay <= 65535 {
		if who := claims.owner("tcp", relay, nil); who != "" {
			p.RelayTaken = who
		} else if setupPlanListening(relay) {
			p.RelayTaken = "another program on this server"
		}
	}
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
