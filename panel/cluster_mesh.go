package main

// Iran hubs that back each other up. Hubs are linked once with a join code;
// after that every hub sends every other hub a signed heartbeat every few
// seconds with the state of its pools. A pool that has no working member here
// is forwarded (DNAT + MASQUERADE, Iran to Iran) to a hub where the same pool
// is healthy, so users keep working while this hub's foreign links are down.
//
// Heartbeats travel over plain HTTP on the panel port, at a fixed path that
// does not reveal the panel. Each request and answer is signed with the
// cluster secret (HMAC-SHA256 over a timestamp, a nonce and the body); stale
// timestamps and reused nonces are refused.

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// HubPeer is another Iran hub in the cluster.
type HubPeer struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	URL      string `json:"url"` // http://IP:PORT
	PublicIP string `json:"public_ip"`
}

// meshRoutePrefix is fixed (not under the panel's random base path) because
// other hubs cannot know that path. Unsigned requests get a plain 404.
const meshRoutePrefix = "/_hc"

const (
	meshEvery    = 3 * time.Second
	meshFall     = 3 // missed heartbeats before a hub counts as down
	meshMaxSkew  = 90 * time.Second
	meshCodeHead = "hc1_"
)

// meshPoolState is one pool as a heartbeat reports it.
type meshPoolState struct {
	State   string `json:"state"`
	Healthy int    `json:"healthy"`
	Members int    `json:"members"`
}

type meshBeat struct {
	ID      string                   `json:"id"`
	Name    string                   `json:"name"`
	IP      string                   `json:"ip"`
	Port    int                      `json:"port"`
	Healthy bool                     `json:"healthy"`
	Pools   map[string]meshPoolState `json:"pools"`
	Hubs    []HubPeer                `json:"hubs,omitempty"` // in hello answers: the hubs to link with
	DNS     string                   `json:"dns,omitempty"`  // record this hub keeps (DNS failover)
	Version string                   `json:"version"`
	Bye     bool                     `json:"bye,omitempty"`
}

// hubRT is what this hub knows about another one right now.
type hubRT struct {
	Up        bool
	Misses    int
	LastSeen  time.Time
	LatencyMs float64
	Beat      meshBeat
	Err       string
}

var (
	meshMu     sync.Mutex
	meshState  = map[string]*hubRT{}
	meshNonces = map[string]time.Time{}
	meshClient = &http.Client{Timeout: 2500 * time.Millisecond}
)

// ---- signing ----

func meshSign(secret, ts, nonce string, body []byte) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(ts + "\n" + nonce + "\n"))
	m.Write(body)
	return hex.EncodeToString(m.Sum(nil))
}

// meshVerify checks the signature headers of a request or answer.
func meshVerify(secret string, h http.Header, body []byte, now time.Time) error {
	if secret == "" {
		return fmt.Errorf("no cluster secret")
	}
	ts, nonce, sig := h.Get("X-Hashem-Ts"), h.Get("X-Hashem-Nonce"), h.Get("X-Hashem-Sig")
	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || len(nonce) < 16 || sig == "" {
		return fmt.Errorf("unsigned")
	}
	if d := now.Sub(time.Unix(sec, 0)); d > meshMaxSkew || d < -meshMaxSkew {
		return fmt.Errorf("clock differs by %s (set NTP on both hubs)", d.Round(time.Second))
	}
	want := meshSign(secret, ts, nonce, body)
	if subtle.ConstantTimeCompare([]byte(want), []byte(sig)) != 1 {
		return fmt.Errorf("bad signature (different cluster secret)")
	}
	meshMu.Lock()
	defer meshMu.Unlock()
	for n, at := range meshNonces {
		if now.Sub(at) > 2*meshMaxSkew {
			delete(meshNonces, n)
		}
	}
	if _, seen := meshNonces[nonce]; seen {
		return fmt.Errorf("replayed request")
	}
	meshNonces[nonce] = now
	return nil
}

func meshSetSig(h http.Header, secret string, body []byte) {
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := randHex(12)
	h.Set("X-Hashem-Ts", ts)
	h.Set("X-Hashem-Nonce", nonce)
	h.Set("X-Hashem-Sig", meshSign(secret, ts, nonce, body))
}

// meshPost sends a signed beat to another hub and returns its signed answer.
func meshPost(url, path, secret string, beat meshBeat) (meshBeat, float64, error) {
	body, _ := json.Marshal(beat)
	req, err := http.NewRequest("POST", strings.TrimRight(url, "/")+meshRoutePrefix+path, bytes.NewReader(body))
	if err != nil {
		return meshBeat{}, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	meshSetSig(req.Header, secret, body)
	start := time.Now()
	resp, err := meshClient.Do(req)
	if err != nil {
		return meshBeat{}, 0, fmt.Errorf("unreachable: %s", shortNetErr(err))
	}
	defer resp.Body.Close()
	lat := float64(time.Since(start).Microseconds()) / 1000
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotFound {
			return meshBeat{}, lat, fmt.Errorf("refused: the other hub has a different cluster secret or an older panel")
		}
		return meshBeat{}, lat, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if err := meshVerify(secret, resp.Header, data, time.Now()); err != nil {
		return meshBeat{}, lat, fmt.Errorf("answer not trusted: %v", err)
	}
	var out meshBeat
	if err := json.Unmarshal(data, &out); err != nil {
		return meshBeat{}, lat, err
	}
	return out, lat, nil
}

func shortNetErr(err error) string {
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i >= 0 {
		s = s[i+2:]
	}
	return s
}

// ---- own state ----

func meshSelfURL(c ClusterConfig) string {
	ip := c.PublicIP
	if ip == "" {
		ip = detectPublicIPCached()
	}
	if ip == "" {
		return ""
	}
	return "http://" + net.JoinHostPort(ip, strconv.Itoa(cfg.Port))
}

// meshSelfBeat describes this hub.
func meshSelfBeat(c ClusterConfig) meshBeat {
	ip := c.PublicIP
	if ip == "" {
		ip = detectPublicIPCached()
	}
	b := meshBeat{ID: c.NodeID, Name: c.Name, IP: ip, Port: cfg.Port, Pools: map[string]meshPoolState{}, Version: panelVersion}
	clusterRT.mu.Lock()
	anyOK := false
	for _, p := range c.Pools {
		pl := clusterRT.plans[p.key()]
		healthy := 0
		for _, t := range pl.Targets {
			if lr := clusterRT.links[t.Link]; lr != nil && lr.Up {
				healthy++
			}
		}
		if pl.State == poolOK || pl.State == poolDegraded {
			anyOK = true
		}
		for _, proto := range lbProtos(p.Proto) {
			b.Pools[proto+"/"+strconv.Itoa(p.Port)] = meshPoolState{State: pl.State, Healthy: healthy, Members: len(p.Members)}
		}
	}
	if len(c.Pools) == 0 {
		for _, lr := range clusterRT.links {
			if lr.Up {
				anyOK = true
			}
		}
		if len(clusterRT.links) == 0 {
			if s := lbSnapshot(); s != nil && s.Main != nil && s.Main.HealthState == stateHealthy {
				anyOK = true
			}
		}
	}
	clusterRT.mu.Unlock()
	b.Healthy = anyOK
	if c.DNS.Enabled {
		b.DNS = c.DNS.Name
	}
	return b
}

// ---- join ----

type meshCode struct {
	ID     string `json:"i"`
	Name   string `json:"n"`
	URL    string `json:"u"`
	IP     string `json:"a"`
	Secret string `json:"s"`
}

// meshJoinCode makes the code another hub pastes to link with this one. The
// cluster secret is created on first use.
func meshJoinCode(c ClusterConfig) (string, error) {
	if c.Secret == "" {
		var err error
		c, err = updateClusterConfig(func(x *ClusterConfig) error {
			if x.Secret == "" {
				x.Secret = randHex(32)
			}
			return nil
		})
		if err != nil {
			return "", err
		}
	}
	url := meshSelfURL(c)
	if url == "" {
		return "", fmt.Errorf("this hub's public IP is unknown: set it in Cluster settings")
	}
	b := meshSelfBeat(c)
	data, _ := json.Marshal(meshCode{ID: c.NodeID, Name: c.Name, URL: url, IP: b.IP, Secret: c.Secret})
	return meshCodeHead + base64.RawURLEncoding.EncodeToString(data), nil
}

func parseMeshCode(s string) (meshCode, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, meshCodeHead) {
		return meshCode{}, fmt.Errorf("not a hub join code (it starts with %s)", meshCodeHead)
	}
	data, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(s, meshCodeHead))
	if err != nil {
		return meshCode{}, fmt.Errorf("the code is damaged: copy it again")
	}
	var c meshCode
	if json.Unmarshal(data, &c) != nil || c.ID == "" || c.URL == "" || len(c.Secret) < 32 {
		return meshCode{}, fmt.Errorf("the code is damaged: copy it again")
	}
	return c, nil
}

// meshAddHub links this hub with the one that made code, and with every hub
// that one already knows.
func meshAddHub(code string) (HubPeer, error) {
	mc, err := parseMeshCode(code)
	if err != nil {
		return HubPeer{}, err
	}
	c := loadClusterConfig()
	if mc.ID == c.NodeID {
		return HubPeer{}, fmt.Errorf("this is this hub's own code: paste it on another Iran server")
	}
	if c.Secret != "" && c.Secret != mc.Secret && len(c.Hubs) > 0 {
		return HubPeer{}, fmt.Errorf("this hub is already linked with other hubs under another secret; remove them first")
	}
	self := meshSelfBeat(c)
	ans, _, err := meshPost(mc.URL, "/hello", mc.Secret, self)
	if err != nil {
		return HubPeer{}, fmt.Errorf("cannot reach %s: %v", mc.URL, err)
	}
	if ans.ID != mc.ID {
		return HubPeer{}, fmt.Errorf("the hub at %s answered as %s, not %s", mc.URL, ans.ID, mc.ID)
	}
	h := HubPeer{ID: ans.ID, Name: ans.Name, URL: mc.URL, PublicIP: ans.IP}
	_, err = updateClusterConfig(func(x *ClusterConfig) error {
		x.Secret = mc.Secret
		meshUpsert(x, h)
		for _, o := range ans.Hubs {
			if o.ID != x.NodeID && o.ID != h.ID {
				meshUpsert(x, o)
			}
		}
		return nil
	})
	if err != nil {
		return HubPeer{}, err
	}
	clusterEventf("info", "Linked with Iran hub %s (%s).", h.Name, h.PublicIP)
	// Introduce ourselves to the hubs we learned about.
	for _, o := range ans.Hubs {
		if o.ID != c.NodeID && o.ID != h.ID {
			if _, _, err := meshPost(o.URL, "/hello", mc.Secret, self); err != nil {
				clusterEventf("warn", "Hub %s could not be told about this hub yet: %v", o.Name, err)
			}
		}
	}
	return h, nil
}

func meshUpsert(c *ClusterConfig, h HubPeer) {
	for i := range c.Hubs {
		if c.Hubs[i].ID == h.ID {
			c.Hubs[i] = h
			return
		}
	}
	c.Hubs = append(c.Hubs, h)
	sort.Slice(c.Hubs, func(i, j int) bool { return c.Hubs[i].ID < c.Hubs[j].ID })
}

// meshRemoveHub forgets a hub here and asks it to forget this one.
func meshRemoveHub(id string) bool {
	var gone *HubPeer
	c, _ := updateClusterConfig(func(x *ClusterConfig) error {
		out := x.Hubs[:0]
		for _, h := range x.Hubs {
			if h.ID == id {
				hh := h
				gone = &hh
				continue
			}
			out = append(out, h)
		}
		x.Hubs = out
		return nil
	})
	if gone == nil {
		return false
	}
	meshMu.Lock()
	delete(meshState, id)
	meshMu.Unlock()
	b := meshSelfBeat(c)
	b.Bye = true
	go func() { _, _, _ = meshPost(gone.URL, "/beat", c.Secret, b) }()
	clusterEventf("info", "Unlinked from Iran hub %s.", gone.Name)
	return true
}

// ---- server side ----

// mountMeshRoutes serves the hub-to-hub API.
func mountMeshRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST "+meshRoutePrefix+"/hello", meshHandler(true))
	mux.HandleFunc("POST "+meshRoutePrefix+"/beat", meshHandler(false))
}

func meshHandler(hello bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c := loadClusterConfig()
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
		if err != nil || c.Secret == "" || meshVerify(c.Secret, r.Header, body, time.Now()) != nil {
			http.NotFound(w, r)
			return
		}
		var in meshBeat
		if json.Unmarshal(body, &in) != nil || in.ID == "" || in.ID == c.NodeID {
			http.Error(w, "bad beat", http.StatusBadRequest)
			return
		}
		known := false
		for _, h := range c.Hubs {
			known = known || h.ID == in.ID
		}
		switch {
		case in.Bye:
			if known {
				c, _ = updateClusterConfig(func(x *ClusterConfig) error {
					out := x.Hubs[:0]
					for _, h := range x.Hubs {
						if h.ID != in.ID {
							out = append(out, h)
						}
					}
					x.Hubs = out
					return nil
				})
				clusterEventf("info", "Iran hub %s unlinked itself.", in.Name)
			}
		case hello || !known:
			if !hello && !known {
				// A hub that still knows us after we removed it: do not
				// re-add it silently.
				http.NotFound(w, r)
				return
			}
			ip := in.IP
			if ip == "" {
				ip, _, _ = net.SplitHostPort(r.RemoteAddr)
			}
			h := HubPeer{ID: in.ID, Name: in.Name, URL: "http://" + net.JoinHostPort(ip, strconv.Itoa(in.Port)), PublicIP: ip}
			c, _ = updateClusterConfig(func(x *ClusterConfig) error { meshUpsert(x, h); return nil })
			if !known {
				clusterEventf("info", "Iran hub %s (%s) linked with this hub.", h.Name, h.PublicIP)
			}
		}
		meshRecord(in, 0, nil)
		out := meshSelfBeat(c)
		if hello {
			out.Hubs = c.Hubs
		}
		data, _ := json.Marshal(out)
		meshSetSig(w.Header(), c.Secret, data)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
	}
}

// meshRecord stores what a beat (sent or received) told about a hub.
func meshRecord(b meshBeat, lat float64, err error) {
	meshMu.Lock()
	defer meshMu.Unlock()
	st := meshState[b.ID]
	if st == nil {
		st = &hubRT{}
		meshState[b.ID] = st
	}
	if err != nil {
		st.Misses++
		st.Err = err.Error()
		if st.Up && st.Misses >= meshFall {
			st.Up = false
			name, msg := st.Beat.Name, err.Error()
			go clusterEventf("warn", "Iran hub %s stopped answering: %s", name, msg)
		}
		return
	}
	if !st.Up && !st.LastSeen.IsZero() {
		name := b.Name
		go clusterEventf("info", "Iran hub %s answers again.", name)
	}
	st.Up, st.Misses, st.Err, st.LastSeen, st.Beat = true, 0, "", time.Now(), b
	if lat > 0 {
		st.LatencyMs = round1(lat)
	}
}

// ---- client side ----

// startMeshLoop sends a beat to every hub every meshEvery.
func startMeshLoop() {
	for {
		time.Sleep(meshEvery)
		c := loadClusterConfig()
		if c.Secret == "" || len(c.Hubs) == 0 {
			continue
		}
		self := meshSelfBeat(c)
		var wg sync.WaitGroup
		for _, h := range c.Hubs {
			wg.Add(1)
			go func(h HubPeer) {
				defer wg.Done()
				ans, lat, err := meshPost(h.URL, "/beat", c.Secret, self)
				if err == nil && ans.ID != h.ID {
					err = fmt.Errorf("answered as %s", ans.ID)
				}
				if err != nil {
					meshRecord(meshBeat{ID: h.ID, Name: h.Name}, 0, err)
					return
				}
				meshRecord(ans, lat, nil)
			}(h)
		}
		wg.Wait()
		dnsTick(c)
	}
}

// meshForwardTarget picks the hub to forward a pool to: up, with the same
// pool working there (not itself forwarded, which could loop), lowest
// latency. It returns that hub's public IPv4 or "".
func meshForwardTarget(c ClusterConfig, p LBPool) string {
	meshMu.Lock()
	defer meshMu.Unlock()
	best, bestLat := "", 0.0
	for _, h := range c.Hubs {
		st := meshState[h.ID]
		if st == nil || !st.Up || !isIPv4(h.PublicIP) {
			continue
		}
		okAll := true
		for _, proto := range lbProtos(p.Proto) {
			ps, ok := st.Beat.Pools[proto+"/"+strconv.Itoa(p.Port)]
			if !ok || (ps.State != poolOK && ps.State != poolDegraded) {
				okAll = false
			}
		}
		if okAll && (best == "" || st.LatencyMs < bestLat) {
			best, bestLat = h.PublicIP, st.LatencyMs
		}
	}
	return best
}

type hubView struct {
	HubPeer
	Up        bool                     `json:"up"`
	Healthy   bool                     `json:"healthy"`
	LatencyMs float64                  `json:"latency_ms"`
	LastSeen  string                   `json:"last_seen,omitempty"`
	Error     string                   `json:"error,omitempty"`
	Pools     map[string]meshPoolState `json:"pools"`
	Version   string                   `json:"version,omitempty"`
	// VersionDiffers: the hub answers with another panel version (or one too
	// old to send it). The cluster needs the same version on every hub.
	VersionDiffers bool `json:"version_differs,omitempty"`
}

func meshView(c ClusterConfig) []hubView {
	meshMu.Lock()
	defer meshMu.Unlock()
	out := make([]hubView, 0, len(c.Hubs))
	for _, h := range c.Hubs {
		v := hubView{HubPeer: h}
		if st := meshState[h.ID]; st != nil {
			v.Up, v.Healthy, v.LatencyMs, v.Error, v.Pools, v.Version = st.Up, st.Beat.Healthy, st.LatencyMs, st.Err, st.Beat.Pools, st.Beat.Version
			if !st.LastSeen.IsZero() {
				v.LastSeen = st.LastSeen.Format("2006-01-02 15:04:05")
				v.VersionDiffers = st.Beat.Version != panelVersion
			}
		}
		out = append(out, v)
	}
	return out
}

func isIPv4(s string) bool {
	ip := net.ParseIP(strings.TrimSpace(s))
	return ip != nil && ip.To4() != nil
}

// ---- API ----

func handleClusterJoinCode(w http.ResponseWriter, r *http.Request) {
	if proRequired(w, r, "cluster", "Cluster") {
		return
	}
	code, err := meshJoinCode(loadClusterConfig())
	if err != nil {
		writeAPIError(w, r, "E-CLUSTER-08", err.Error())
		return
	}
	writeJSON(w, map[string]any{"code": code})
}

func handleClusterHubAdd(w http.ResponseWriter, r *http.Request) {
	if proRequired(w, r, "cluster", "Cluster") {
		return
	}
	var req struct {
		Code string `json:"code"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<13)).Decode(&req) != nil {
		writeAPIError(w, r, "E-CLUSTER-01", "")
		return
	}
	if _, err := parseMeshCode(req.Code); err != nil {
		writeAPIError(w, r, "E-CLUSTER-07", err.Error())
		return
	}
	h, err := meshAddHub(req.Code)
	if err != nil {
		writeAPIError(w, r, "E-CLUSTER-08", err.Error())
		return
	}
	writeJSON(w, map[string]any{"status": "ok", "hub": h})
}

func handleClusterHubDelete(w http.ResponseWriter, r *http.Request) {
	if proRequired(w, r, "cluster", "Cluster") {
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req) != nil {
		writeAPIError(w, r, "E-CLUSTER-01", "")
		return
	}
	if !meshRemoveHub(req.ID) {
		writeAPIError(w, r, "E-CLUSTER-05", "no hub with id "+req.ID)
		return
	}
	writeJSON(w, map[string]any{"status": "ok"})
}
