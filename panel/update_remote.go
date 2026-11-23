package main

// Updating the other servers from this one: the Iran hubs linked in the
// Cluster, and the foreign servers of this server's tunnels. Nodes of a
// central have their own "Update nodes" (node_fleet.go).
//
//   - A linked hub is asked over the signed hub channel (POST /_hc/update).
//   - A foreign server is asked over its tunnel's Peer Link
//     (POST /_hp/api/peer/update), which it takes from the Iran hubs it
//     serves: its Peer Link secret, or the token of a hub it joined.
//
// The server that is asked updates itself through panelUpdate, exactly as
// its own Update button does: an official release only, checked against the
// release's checksums, with the rollback guard. It is told this server's
// release and installs it only when that is newer than what it runs, so a
// remote request never downgrades a server. Tunnels are not restarted: only
// the panel is.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	remoteUpdCallTO  = 12 * time.Minute // the server downloads the release before it answers
	remoteUpdBackTO  = 6 * time.Minute  // back on its new version
	remoteUpdCheckTO = 8 * time.Second
	remoteUpdListTTL = 30 * time.Second
)

// remoteUpdReq is what the asking server sends. Tag is its own release (""
// for a build from source: the asked server then takes the newest of its
// channel); Check only asks for the version.
type remoteUpdReq struct {
	ID    string `json:"id,omitempty"` // the asking hub (hub channel)
	Tag   string `json:"tag,omitempty"`
	Check bool   `json:"check,omitempty"`
}

type remoteUpdAns struct {
	OK       bool   `json:"ok"`
	Version  string `json:"version"`
	Updating bool   `json:"updating,omitempty"` // installed: it restarts now
	Detail   string `json:"detail,omitempty"`
	Error    string `json:"error,omitempty"`
}

// remoteUpdateApply runs a request on the server that is asked.
func remoteUpdateApply(req remoteUpdReq, who, ip string) remoteUpdAns {
	ans := remoteUpdAns{Version: displayVersion(panelVersion)}
	if req.Check {
		ans.OK = true
		return ans
	}
	tag := strings.TrimSpace(req.Tag)
	if tag != "" {
		if !validTag(tag) {
			ans.Error = "unexpected release tag"
			return ans
		}
		ka, _ := parseVersion(tag)
		kb, _ := parseVersion(panelVersion)
		if kb != 0 && ka != kb {
			ans.Error = "this server runs " + displayVersion(panelVersion) + ", the asking one " + displayVersion(tag) +
				": they are on different update channels. Set the same channel on both (hashem update-channel dev or stable), then update"
			return ans
		}
		if compareVersions(tag, panelVersion) <= 0 {
			ans.OK = true
			ans.Detail = "already on " + displayVersion(panelVersion)
			return ans
		}
	}
	res, _, err := panelUpdate(tag, who, ip)
	if err != nil {
		ans.Error = err.Error()
		return ans
	}
	ans.OK, ans.Detail, ans.Updating = true, res.Detail, !res.Already
	return ans
}

// POST /_hc/update: a linked hub asks this hub to update.
func handleMeshUpdate(w http.ResponseWriter, r *http.Request) {
	c, from, body, ok := meshAuthed(w, r, 1<<12)
	if !ok {
		return
	}
	var req remoteUpdReq
	_ = json.Unmarshal(body, &req)
	if !req.Check {
		LogSecurityAudit("remote_update_asked", "hub:"+from.Name, ClientIP(r), "tag="+req.Tag)
	}
	ans := remoteUpdateApply(req, "hub:"+from.Name, ClientIP(r))
	meshAnswer(w, c.Secret, ans)
	if ans.Updating {
		restartSoon()
	}
}

// POST /api/peer/update: an Iran hub of this server's tunnels asks it to
// update (or, with check, for its version).
func handlePeerUpdate(w http.ResponseWriter, r *http.Request) {
	var req remoteUpdReq
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req)
	if !req.Check {
		LogSecurityAudit("remote_update_asked", "peer", ClientIP(r), "tag="+req.Tag)
	}
	ans := remoteUpdateApply(req, "peer", ClientIP(r))
	writeJSON(w, ans)
	if ans.Updating {
		restartSoon()
	}
}

// ---- who may ask (the foreign server) ----

var hubTokenRe = regexp.MustCompile(`(?m)^[ \t]*(?:auth\.)?token[ \t]*=[ \t]*"([^"\n]+)"`)

// servedHubTokens are the tunnel tokens of the extra Iran hubs this foreign
// server serves (join-hub), read from their client configs. A var for tests.
var servedHubTokens = func() []string {
	var out []string
	for _, h := range readJoinedHubs() {
		if h.Conf == "" {
			continue
		}
		data, err := os.ReadFile(h.Conf)
		if err != nil {
			continue
		}
		if m := hubTokenRe.FindSubmatch(data); m != nil && len(m[1]) >= 16 {
			out = append(out, string(m[1]))
		}
	}
	return out
}

// requireServedHubSecretHidden guards what any Iran hub this server serves
// may ask (join one more hub, update): its Peer Link secret (the first
// hub's), or the token of a hub it joined later. Every failure is a bare 404.
func requireServedHubSecretHidden(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		got := strings.TrimSpace(r.Header.Get("X-Peer-Secret"))
		if got == "" {
			if h := r.Header.Get("Authorization"); strings.HasPrefix(strings.ToLower(h), "bearer ") {
				got = strings.TrimSpace(h[7:])
			}
		}
		if got != "" {
			if c := loadPeerConfig(); c.PeerSecret != "" && ConstantTimeCompare(c.PeerSecret, got) {
				next(w, r)
				return
			}
			for _, t := range servedHubTokens() {
				if ConstantTimeCompare(t, got) {
					next(w, r)
					return
				}
			}
			LogSecurityAudit("peer_auth_rejected", "peer", ClientIP(r), "path="+r.URL.Path)
		}
		http.NotFound(w, r)
	}
}

// ---- the asking server ----

// remoteTarget is a server this one can update.
type remoteTarget struct {
	Key       string `json:"key"`  // hub:<id> | tunnel:<id>
	Kind      string `json:"kind"` // hub | foreign
	Name      string `json:"name"`
	Addr      string `json:"addr,omitempty"`
	Version   string `json:"version,omitempty"`
	Reachable bool   `json:"reachable"`
	Differs   bool   `json:"differs"` // another version than this server's
	Error     string `json:"error,omitempty"`

	hub    HubPeer
	tunnel int
}

// remoteUpdCall asks a foreign server over its tunnel's Peer Link (a var
// for tests).
var remoteUpdCall = func(tunnelID int, req remoteUpdReq, timeout time.Duration) (remoteUpdAns, error) {
	t, err := resolveSwapTunnel(tunnelID)
	if err != nil {
		return remoteUpdAns{}, err
	}
	data, err := tunnelPeerCall(t, http.MethodPost, "/api/peer/update", req, timeout)
	if err != nil {
		if strings.Contains(err.Error(), "HTTP 404") || errors.Is(err, errNoPeerLink) {
			return remoteUpdAns{}, errRemoteOld
		}
		return remoteUpdAns{}, err
	}
	var ans remoteUpdAns
	if json.Unmarshal(data, &ans) != nil {
		return remoteUpdAns{}, errors.New("the answer cannot be read")
	}
	return ans, nil
}

// remoteHubCall asks a linked hub (a var for tests).
var remoteHubCall = func(h HubPeer, req remoteUpdReq, timeout time.Duration) (remoteUpdAns, error) {
	c := loadClusterConfig()
	req.ID = c.NodeID
	var ans remoteUpdAns
	if err := meshCall(h, c.Secret, "/update", req, &ans, timeout); err != nil {
		if strings.Contains(err.Error(), "did not accept") {
			return ans, errRemoteOld
		}
		return ans, err
	}
	return ans, nil
}

var errRemoteOld = errors.New("it runs a panel from before remote updates: update it by hand once (hashem update on it); after that it is updated from here")

// remoteTunnels lists this server's tunnels to foreign servers (a var for tests).
var remoteTunnels = func() []remoteTarget {
	s := lbSnapshot()
	if s == nil {
		return nil
	}
	var out []remoteTarget
	for _, l := range s.All() {
		if l.RemotePub == "" {
			continue
		}
		if _, err := resolveSwapTunnel(l.ID); err != nil {
			continue // a foreign server's own tunnel to its hub, or no Peer Link
		}
		name := strings.TrimSpace(l.Name)
		if name == "" {
			name = l.RemotePub
		}
		out = append(out, remoteTarget{Key: "tunnel:" + strconv.Itoa(l.ID), Kind: "foreign", Name: name, Addr: l.RemotePub, tunnel: l.ID})
	}
	return out
}

var remoteList struct {
	sync.Mutex
	at  time.Time
	out []remoteTarget
}

// remoteTargets lists the servers with their versions: hubs from their
// heartbeats, foreign servers asked live (cached remoteUpdListTTL).
func remoteTargets(fresh bool) []remoteTarget {
	remoteList.Lock()
	if !fresh && time.Since(remoteList.at) < remoteUpdListTTL && remoteList.out != nil {
		out := append([]remoteTarget(nil), remoteList.out...)
		remoteList.Unlock()
		return remoteHubsLive(out)
	}
	remoteList.Unlock()
	var out []remoteTarget
	c := loadClusterConfig()
	for _, h := range meshView(c) {
		name := h.Name
		if name == "" {
			name = h.ID
		}
		out = append(out, remoteTarget{Key: "hub:" + h.ID, Kind: "hub", Name: name, Addr: h.PublicIP, hub: h.HubPeer})
	}
	tun := remoteTunnels()
	var wg sync.WaitGroup
	for i := range tun {
		wg.Add(1)
		go func(t *remoteTarget) {
			defer wg.Done()
			ans, err := remoteUpdCall(t.tunnel, remoteUpdReq{Check: true}, remoteUpdCheckTO)
			switch {
			case err != nil:
				t.Error = err.Error()
			case !ans.OK:
				t.Error = ans.Error
			default:
				t.Reachable, t.Version = true, ans.Version
				t.Differs = ans.Version != displayVersion(panelVersion)
			}
		}(&tun[i])
	}
	wg.Wait()
	out = append(out, tun...)
	remoteList.Lock()
	remoteList.at, remoteList.out = time.Now(), append([]remoteTarget(nil), out...)
	remoteList.Unlock()
	return remoteHubsLive(out)
}

// remoteHubsLive fills the hubs' state from their latest heartbeat.
func remoteHubsLive(out []remoteTarget) []remoteTarget {
	meshMu.Lock()
	defer meshMu.Unlock()
	for i := range out {
		if out[i].Kind != "hub" {
			continue
		}
		out[i].Reachable, out[i].Version, out[i].Differs, out[i].Error = false, "", false, ""
		st := meshState[out[i].hub.ID]
		if st == nil || !st.Up {
			out[i].Error = "not answering its heartbeat"
			if st != nil && st.Err != "" {
				out[i].Error += ": " + st.Err
			}
			continue
		}
		out[i].Reachable, out[i].Version = true, displayVersion(st.Beat.Version)
		out[i].Differs = st.Beat.Version != panelVersion
	}
	return out
}

// ---- the job ----

type remoteStep struct {
	Key    string `json:"key"`
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	State  string `json:"state"` // waiting | updating | done | failed
	Detail string `json:"detail,omitempty"`
}

type remoteJobState struct {
	Running bool         `json:"running"`
	Started int64        `json:"started,omitempty"`
	Ended   int64        `json:"ended,omitempty"`
	Steps   []remoteStep `json:"steps"`
}

var remoteJob struct {
	sync.Mutex
	s remoteJobState
}

func remoteJobSnapshot() remoteJobState {
	remoteJob.Lock()
	defer remoteJob.Unlock()
	s := remoteJob.s
	s.Steps = append([]remoteStep{}, s.Steps...)
	return s
}

func remoteJobStep(i int, state, detail string) {
	remoteJob.Lock()
	defer remoteJob.Unlock()
	if i < len(remoteJob.s.Steps) {
		remoteJob.s.Steps[i].State, remoteJob.s.Steps[i].Detail = state, detail
	}
}

// remoteUpdPoll is how often a server is asked whether it is back (a var for tests).
var remoteUpdPoll = 5 * time.Second

// remoteUpdBack waits for t to answer on another version than before.
var remoteUpdBack = func(ctx context.Context, t remoteTarget, before string) (string, error) {
	deadline := time.Now().Add(remoteUpdBackTO)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(remoteUpdPoll):
		}
		if t.Kind == "hub" {
			for _, x := range remoteHubsLive([]remoteTarget{t}) {
				if x.Reachable && x.Version != "" && x.Version != before {
					return x.Version, nil
				}
			}
			continue
		}
		ans, err := remoteUpdCall(t.tunnel, remoteUpdReq{Check: true}, remoteUpdCheckTO)
		if err == nil && ans.OK && ans.Version != "" && ans.Version != before {
			return ans.Version, nil
		}
	}
	return "", fmt.Errorf("it did not come back on a new version within %s: look at it (journalctl -u gre-panel on it)", remoteUpdBackTO)
}

// remoteUpdateOne updates one server and waits for it.
func remoteUpdateOne(ctx context.Context, t remoteTarget, i int) {
	before := t.Version
	req := remoteUpdReq{Tag: runningReleaseTag()}
	remoteJobStep(i, "updating", "downloading the release there")
	var ans remoteUpdAns
	var err error
	if t.Kind == "hub" {
		ans, err = remoteHubCall(t.hub, req, remoteUpdCallTO)
	} else {
		ans, err = remoteUpdCall(t.tunnel, req, remoteUpdCallTO)
	}
	if err == nil && !ans.OK {
		err = errors.New(ans.Error)
	}
	if err != nil {
		remoteJobStep(i, "failed", err.Error())
		return
	}
	if !ans.Updating {
		remoteJobStep(i, "done", ans.Detail)
		return
	}
	remoteJobStep(i, "updating", ans.Detail+"; waiting for it to come back")
	ver, err := remoteUpdBack(ctx, t, before)
	if err != nil {
		remoteJobStep(i, "failed", err.Error())
		return
	}
	remoteJobStep(i, "done", "back on "+ver)
}

// remoteUpdateStart updates targets one at a time, foreign servers first
// (an Iran hub that is newer than its foreign servers keeps its tunnels; the
// order only keeps the window of mixed versions short). A failure does not
// stop the rest.
func remoteUpdateStart(targets []remoteTarget, who, ip string) error {
	if len(targets) == 0 {
		return errors.New("no server to update: every one runs this version, or none answers")
	}
	sort.SliceStable(targets, func(i, j int) bool { return targets[i].Kind == "foreign" && targets[j].Kind == "hub" })
	remoteJob.Lock()
	if remoteJob.s.Running {
		remoteJob.Unlock()
		return errors.New("an update of the other servers is running already")
	}
	steps := make([]remoteStep, len(targets))
	names := make([]string, len(targets))
	for i, t := range targets {
		steps[i] = remoteStep{Key: t.Key, Name: t.Name, Kind: t.Kind, State: "waiting"}
		names[i] = t.Name
	}
	remoteJob.s = remoteJobState{Running: true, Started: time.Now().Unix(), Steps: steps}
	remoteJob.Unlock()
	LogSecurityAudit("remote_update", who, ip, "servers="+strings.Join(names, ","))
	go func() {
		ctx := context.Background()
		for i, t := range targets {
			remoteUpdateOne(ctx, t, i)
		}
		remoteJob.Lock()
		remoteJob.s.Running, remoteJob.s.Ended = false, time.Now().Unix()
		remoteJob.Unlock()
		remoteList.Lock()
		remoteList.at = time.Time{}
		remoteList.Unlock()
		done, failed := 0, 0
		for _, s := range remoteJobSnapshot().Steps {
			if s.State == "done" {
				done++
			} else {
				failed++
			}
		}
		log.Printf("[update] the other servers: %d updated, %d failed", done, failed)
	}()
	return nil
}

// ---- API ----

// GET /api/update/remote[?refresh=1]: the servers and the running job.
func handleRemoteUpdateGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"servers": remoteTargets(r.URL.Query().Get("refresh") == "1"), "job": remoteJobSnapshot(),
		"version": displayVersion(panelVersion)})
}

// POST /api/update/remote {"keys":[...]} or {"all":true} (every server that
// answers on another version).
func handleRemoteUpdatePost(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Keys []string `json:"keys"`
		All  bool     `json:"all"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<14)).Decode(&req) != nil || (!req.All && len(req.Keys) == 0) {
		writeAPIError(w, r, "E-UPDATE-11", "pick the servers to update")
		return
	}
	all := remoteTargets(true)
	var pick []remoteTarget
	for _, t := range all {
		if req.All {
			if t.Reachable && t.Differs && (t.Kind != "hub" || hasPro("cluster")) {
				pick = append(pick, t)
			}
			continue
		}
		for _, k := range req.Keys {
			if k == t.Key {
				if t.Kind == "hub" && proRequired(w, r, "cluster", "Cluster") {
					return
				}
				pick = append(pick, t)
			}
		}
	}
	if !req.All && len(pick) != len(req.Keys) {
		writeAPIError(w, r, "E-UPDATE-11", "a server asked for is not one of this server's linked hubs or tunnels")
		return
	}
	if err := remoteUpdateStart(pick, cfg.Username, ClientIP(r)); err != nil {
		writeAPIError(w, r, "E-UPDATE-11", err.Error())
		return
	}
	writeJSON(w, map[string]any{"status": "ok", "job": remoteJobSnapshot()})
}
