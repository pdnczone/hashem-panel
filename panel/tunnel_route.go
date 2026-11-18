package main

// The "route" setting of the Telegram alerts and the DNS failover: Direct, or
// one of this server's tunnels picked from a list (tunnel_egress.go does the
// carrying). A chosen tunnel is stored by its id; the panel derives the local
// SOCKS5 port itself, so nobody types one. A setup saved by an older version
// has only a port: it keeps working as it was.

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// tunnelChoice is one entry of the picker.
type tunnelChoice struct {
	ID     int    `json:"id"`
	Name   string `json:"name"`
	Remote string `json:"remote"`
	State  string `json:"state"` // healthy | degraded | down
	Engine string `json:"engine,omitempty"`
}

// tunnelChoices lists the tunnels a route can use: the main tunnel and every
// peer. A foreign server has none (its calls already leave from there).
func tunnelChoices() []tunnelChoice {
	out := []tunnelChoice{}
	snap := currentSnapshot()
	if snap == nil {
		return out
	}
	for _, p := range snap.All() {
		name := strings.TrimSpace(p.Name)
		if p.ID == mainTunnelID {
			name = xrayOr(linkLabel("main"), name)
		}
		if name == "" {
			name = "Tunnel " + strconv.Itoa(p.ID)
		}
		state := p.HealthState
		if state == "" {
			state = stateDown
		}
		out = append(out, tunnelChoice{ID: p.ID, Name: name, Remote: p.RemotePub, State: state, Engine: p.Engine})
	}
	return out
}

func tunnelChoiceName(id int) string {
	for _, c := range tunnelChoices() {
		if c.ID == id {
			return c.Name
		}
	}
	return "tunnel " + strconv.Itoa(id)
}

// routePort is the local SOCKS5 port a stored route uses: the bridge of the
// chosen tunnel (started now if needed), or the old manual port.
func routePort(id *int, port int) (int, error) {
	if id != nil {
		return bridgeEnsure(*id)
	}
	if port > 0 && port <= 65535 {
		return port, nil
	}
	return 0, errors.New("no tunnel is chosen")
}

// routeTarget is the host a route is tested against.
func routeTarget(kind string) string {
	if kind == "cloudflare" {
		return "api.cloudflare.com"
	}
	return "api.telegram.org"
}

// probeRoute checks a route with a real connection to host:443 out of the
// chosen tunnel (or, for an old manual port, a SOCKS5 greeting). via says which
// address of the foreign panel carried it.
func probeRoute(id *int, port int, host string) (ok bool, via, why string) {
	if id == nil {
		if port <= 0 {
			return false, "", "no tunnel is chosen"
		}
		_, ok, why = probeTunnelProxy(port)
		return ok, tunnelProxyAddr(port), why
	}
	t, err := egressTunnel(*id)
	if err != nil {
		if errors.Is(err, errSwapForeign) {
			return false, "", "this server has no tunnels to route through: it is the foreign end, and its calls already leave from here"
		}
		return false, "", fmt.Sprintf("%s is not available: %v", tunnelChoiceName(*id), err)
	}
	conn, via, err := egressDial(t, net.JoinHostPort(host, "443"), 12*time.Second)
	if err != nil {
		return false, via, fmt.Sprintf("%s: %v", tunnelChoiceName(*id), err)
	}
	conn.Close()
	return true, via, ""
}

// routeWhy explains a failed call on a route in words: the reason the bridge
// recorded when it could not carry the connection ("" when it has none).
func routeWhy(id *int) string {
	if id == nil {
		return ""
	}
	return egressWhy(*id)
}

// handleProxyProbe checks a route for the Telegram and DNS cards:
// POST {"tunnel": N, "for": "telegram"|"cloudflare"} (or the old {"port": N})
// answers {"ok", "via", "why"}.
func handleProxyProbe(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Tunnel *int   `json:"tunnel"`
		Port   int    `json:"port"`
		For    string `json:"for"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&req) != nil || (req.Tunnel == nil && (req.Port < 1 || req.Port > 65535)) {
		writeAPIError(w, r, "E-ACTION-03", "choose a tunnel")
		return
	}
	ok, via, why := probeRoute(req.Tunnel, req.Port, routeTarget(req.For))
	writeJSON(w, map[string]any{"ok": ok, "via": via, "addr": via, "why": why})
}

// startRouteBridges brings up the bridge of every tunnel a saved route uses,
// so Telegram alerts (and hashem.sh's watchdog) work right after a restart.
func startRouteBridges() {
	if wd := loadWatchdogConfig(); wd.TGRoute == "tunnel" && wd.TGTunnelID != nil {
		if _, err := bridgeEnsure(*wd.TGTunnelID); err != nil {
			log.Printf("tunnel route (Telegram): %v", err)
		}
	}
	if d := loadClusterConfig().DNS; d.Route == "tunnel" && d.TunnelID != nil {
		if _, err := bridgeEnsure(*d.TunnelID); err != nil {
			log.Printf("tunnel route (Cloudflare): %v", err)
		}
	}
}
