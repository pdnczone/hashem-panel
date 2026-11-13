package main

// A foreign server that serves several Iran hubs. The first hub is the
// server's own tunnel (frpc / backhaul-client); each extra hub gets its own
// client unit (frpc-hN / backhaul-client-hN), set up by hashem join-hub and
// listed in hubs.json. If one Iran server dies, users who connect through the
// others keep working.

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

type joinedHub struct {
	ID      int    `json:"id"`
	Name    string `json:"name"`
	IranPub string `json:"iran_pub"`
	Engine  string `json:"engine"`
	Svc     string `json:"svc"`
	GreIf   string `json:"gre_if"`
	Port    int    `json:"port"`
	IranGre string `json:"iran_gre"`
	Dial    string `json:"dial"`
	Ports   []int  `json:"ports"`
	Active  bool   `json:"active"`
	Session bool   `json:"session"`
	First   bool   `json:"first,omitempty"`
	Conf    string `json:"-"` // its client config (holds its token: setup_plan.go link proofs)
}

func hubsFile() string { return filepath.Join(configDir, "hubs.json") }

func readJoinedHubs() []joinedHub {
	data, err := os.ReadFile(hubsFile())
	if err != nil {
		return nil
	}
	var v struct {
		Hubs []struct {
			ID      int    `json:"id"`
			Name    string `json:"name"`
			IranPub string `json:"iran_pub"`
			Engine  string `json:"engine"`
			Svc     string `json:"svc"`
			GreIf   string `json:"gre_if"`
			Port    int    `json:"port"`
			IranGre string `json:"iran_gre"`
			Dial    string `json:"dial"`
			Ports   []int  `json:"ports"`
			Conf    string `json:"conf"`
		} `json:"hubs"`
	}
	if json.Unmarshal(data, &v) != nil {
		return nil
	}
	out := make([]joinedHub, 0, len(v.Hubs))
	for _, h := range v.Hubs {
		out = append(out, joinedHub{ID: h.ID, Name: h.Name, IranPub: h.IranPub, Engine: h.Engine, Svc: h.Svc,
			GreIf: h.GreIf, Port: h.Port, IranGre: h.IranGre, Dial: h.Dial, Ports: h.Ports, Conf: h.Conf})
	}
	return out
}

var (
	joinedMu    sync.Mutex
	joinedCache []joinedHub
	joinedAt    time.Time
)

// joinedHubsView lists the hubs a foreign server serves, the first one
// included; empty on a hub. Cached for 5 s (it asks systemctl).
func joinedHubsView() []joinedHub {
	joinedMu.Lock()
	defer joinedMu.Unlock()
	if time.Since(joinedAt) < 5*time.Second {
		return joinedCache
	}
	joinedAt = time.Now()
	s := lbSnapshot()
	var out []joinedHub
	if s != nil && strings.HasPrefix(s.Local.Role, "foreign") {
		out = append(out, joinedHub{ID: 1, Name: "First hub", IranPub: s.Local.RemotePub, Svc: s.Local.FrpSvc,
			Port: s.Local.BindPort, Active: s.Local.FrpUp, Session: s.LocalSession, First: true})
	}
	extra := readJoinedHubs()
	if len(extra) > 0 {
		units := make([]string, 0, len(extra))
		for _, h := range extra {
			units = append(units, h.Svc)
		}
		active := map[string]bool{}
		if o, _ := runCmdTimeoutOut(5*time.Second, "systemctl", append([]string{"is-active"}, units...)...); len(o) > 0 {
			for i, l := range strings.Split(strings.TrimSpace(string(o)), "\n") {
				if i < len(units) {
					active[units[i]] = strings.TrimSpace(l) == "active"
				}
			}
		}
		socks := readSockets()
		for _, h := range extra {
			h.Active = active[h.Svc]
			for _, sk := range socks {
				rp := int(sk.Remote.Port())
				ra := sk.Remote.Addr().String()
				if sk.Proto == "tcp" && sk.State == sockEstablished && (rp == h.Port || rp == h.Port+2) && (ra == h.IranPub || ra == h.IranGre) {
					h.Session = true
				}
			}
			out = append(out, h)
		}
	}
	joinedCache = out
	return out
}

// hubFrpcGlued is the line join-hub of 3.0.x and 3.1 wrote into frpc-hN.toml:
// the tcpMux line ran into the next one ("transport.tcpMux = falsetransport.
// heartbeatInterval = 15"), so frpc refused the file and never started.
var hubFrpcGlued = regexp.MustCompile(`(?m)^(transport\.tcpMux(?:KeepaliveInterval)? = (?:true|false|\d+))(transport\.)`)

// fixHubFrpc splits the glued line; false when there is none.
func fixHubFrpc(b []byte) ([]byte, bool) {
	if !hubFrpcGlued.Match(b) {
		return b, false
	}
	return hubFrpcGlued.ReplaceAll(b, []byte("$1\n$2")), true
}

// repairHubFrpc fixes the frpc config of every extra FRP hub on start and
// restarts its client (issue 14).
func repairHubFrpc() {
	for _, h := range readJoinedHubs() {
		if h.Engine != "frp" || h.Conf == "" || !strings.HasPrefix(h.Svc, "frpc-h") {
			continue
		}
		b, err := os.ReadFile(h.Conf)
		if err != nil {
			continue
		}
		fixed, ok := fixHubFrpc(b)
		if !ok || os.WriteFile(h.Conf, fixed, 0600) != nil {
			continue
		}
		log.Printf("[cluster] %s: fixed a broken line in %s, restarting it", h.Svc, h.Conf)
		_, _ = runCmdTimeout(30*time.Second, "systemctl", "restart", h.Svc)
	}
}

// runHashemCluster runs a hashem.sh subcommand for the cluster (join-hub,
// leave-hub), which installs units and may download a core.
func runHashemCluster(timeout time.Duration, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var cmd *exec.Cmd
	if script, err := greScriptPath(); err == nil {
		cmd = exec.CommandContext(ctx, "bash", append([]string{script}, args...)...)
	} else if fileExists("/usr/local/bin/hashem") {
		cmd = exec.CommandContext(ctx, "/usr/local/bin/hashem", args...)
	} else {
		return "", fmt.Errorf("hashem script not found")
	}
	cmd.Env = append(os.Environ(), "GRE_SKIP_PANEL=1", "TERM=dumb", "GRE_PANEL_DIR="+configDir)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(stripANSI(string(out))), err
}

func handleClusterJoinHub(w http.ResponseWriter, r *http.Request) {
	if proRequired(w, r, "cluster", "Cluster") {
		return
	}
	var req struct {
		Bundle string `json:"bundle"`
		Name   string `json:"name"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<13)).Decode(&req) != nil {
		writeAPIError(w, r, "E-CLUSTER-01", "")
		return
	}
	req.Bundle = strings.TrimSpace(req.Bundle)
	if _, err := ParseBundle(req.Bundle); err != nil {
		writeAPIError(w, r, "E-CLUSTER-07", "not a valid bundle: "+err.Error())
		return
	}
	args := []string{"join-hub", "--bundle", req.Bundle}
	if n := strings.TrimSpace(req.Name); n != "" {
		if len(n) > 32 || strings.ContainsAny(n, "\"'`$\\\n") {
			writeAPIError(w, r, "E-CLUSTER-02", "name: up to 32 plain characters")
			return
		}
		args = append(args, "--name", n)
	}
	out, err := runHashemCluster(4*time.Minute, args...)
	joinedMu.Lock()
	joinedAt = time.Time{}
	joinedMu.Unlock()
	if err != nil {
		writeAPIError(w, r, "E-CLUSTER-11", lastLines(out, 6))
		return
	}
	clusterEventf("info", "This server now also serves another Iran hub.")
	writeJSON(w, map[string]any{"status": "ok", "output": lastLines(out, 8)})
}

func handleClusterLeaveHub(w http.ResponseWriter, r *http.Request) {
	if proRequired(w, r, "cluster", "Cluster") {
		return
	}
	var req struct {
		ID int `json:"id"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req) != nil || req.ID < 2 {
		writeAPIError(w, r, "E-CLUSTER-01", "id of an extra hub (2 or more)")
		return
	}
	out, err := runHashemCluster(time.Minute, "leave-hub", "--id", fmt.Sprint(req.ID))
	joinedMu.Lock()
	joinedAt = time.Time{}
	joinedMu.Unlock()
	if err != nil {
		writeAPIError(w, r, "E-CLUSTER-11", lastLines(out, 6))
		return
	}
	writeJSON(w, map[string]any{"status": "ok"})
}
