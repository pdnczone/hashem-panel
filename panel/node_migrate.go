package main

// Nodes N5: moving an existing install to the node system. An Iran panel
// with foreign servers offers it once (Yes / Not now = 7 days / Don't ask
// again). On yes it becomes the central and opens the migration: each of
// its foreign servers, once updated, asks for an offer over the existing
// Peer Link route (GET /_hp/api/peer/node-offer, authenticated by the tunnel
// token the two already share) and joins.
//
// Trust comes from the tunnel token the two already share:
//
//   - the offer is {url, key, nonce} with mac = HMAC(token, offer fields), so
//     the foreign server only trusts a central key the token holder made, at
//     the address it reached its Iran panel on;
//   - the join secret is HMAC(token, nonce, key), which both sides compute;
//     the central keeps it as an ordinary one-time invite (hash only, 30
//     minutes), so the join is the normal enrollment over the pinned channel.
//
// The Peer Link sends the token itself in clear (X-Peer-Secret), so someone
// on the path can learn it. What limits that (the owner chose an automatic
// move over a confirmation on each foreign server):
//
//   - the move is open for 7 days at most, and closes when every foreign
//     server has joined; a foreign server that joined once is never offered
//     again, even after it was removed;
//   - the foreign server joins only a central at the address it reached;
//   - a server that joined by the move gets no license copy until the
//     admin approves it on the central (nodeRecord.Held);
//   - a foreign server looks for an offer only for 14 days after this
//     version first runs on it (node_migrate_watch; `hashem node move`
//     starts that again), not forever: a forged offer can only be tried
//     while it is looking.
//
// Tunnels are not touched. A foreign server joins by itself only once: if it
// leaves or is removed later, it stays standalone (node_migrated marker).

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	nodeMigrateLater = 7 * 24 * time.Hour
	nodeMigrateOpen  = 7 * 24 * time.Hour  // the longest the move stays open
	nodeMigrateWatch = 14 * 24 * time.Hour // a foreign server looks for an offer this long (node move: again)
	nodeMigratePoll  = 5 * time.Minute
)

// nodeMigrateState is node_migrate.json on an Iran panel.
type nodeMigrateState struct {
	Open       bool  `json:"open,omitempty"` // foreign servers may join by their token
	OpenedAt   int64 `json:"opened_at,omitempty"`
	LaterUntil int64 `json:"later_until,omitempty"`
	Never      bool  `json:"never,omitempty"`
}

var nodeMigrateMu sync.Mutex

func nodeMigrateFile() string { return filepath.Join(configDir, "node_migrate.json") }

func nodeMigrateLoad() nodeMigrateState {
	var s nodeMigrateState
	if b, err := os.ReadFile(nodeMigrateFile()); err == nil {
		_ = json.Unmarshal(b, &s)
	}
	return s
}

func nodeMigrateSave(s nodeMigrateState) error {
	b, _ := json.Marshal(s)
	return writeFile0600(nodeMigrateFile(), b)
}

// nodeMigratePeer is a foreign server this Iran panel has a tunnel with.
type nodeMigratePeer struct {
	Key    string `json:"key"` // "main" | "peer:<id>"
	Name   string `json:"name"`
	IP     string `json:"ip"`
	Joined int    `json:"joined,omitempty"` // its node id once it joined
	Ever   bool   `json:"ever,omitempty"`   // it joined by the move once (it is not offered again)
	token  string
}

// nodeMigratePeers: the first tunnel's foreign server (its token is the
// Peer Link secret) and every peer with a token of its own.
func nodeMigratePeers() []nodeMigratePeer {
	var out []nodeMigratePeer
	// a saved Peer Link (not the made-up default) and a first tunnel set up
	if c := loadPeerConfig(); nodeMigrateLinked() && c.Role == "master" && c.PeerSecret != "" {
		if ft := firstTunnelInfo(); ft.Exists && ft.Side == "iran" {
			ip := ft.RemotePub
			name := linkLabel("main")
			if name == "" {
				name = "Foreign server"
			}
			out = append(out, nodeMigratePeer{Key: "main", Name: name, IP: ip, token: c.PeerSecret})
		}
	}
	for _, p := range loadPeers() {
		if p.Legacy || p.Token == "" || basePeer([]peerRecord{p}) != nil {
			continue // the first tunnel under a peer record: its token is the main one
		}
		name := p.Name
		if name == "" {
			name = "peer " + strconv.Itoa(p.ID)
		}
		out = append(out, nodeMigratePeer{Key: "peer:" + strconv.Itoa(p.ID), Name: name, IP: p.RemotePub, token: p.Token})
	}
	nodesMu.Lock()
	nodesLoadLocked()
	for i := range out {
		for _, r := range nodesF.Nodes {
			if r.Peer == out[i].Key {
				out[i].Joined = r.ID
			}
		}
		// a server added by hand (no move tag) is joined too: by its address
		for _, r := range nodesF.Nodes {
			if out[i].Joined == 0 && out[i].IP != "" && r.Info.PublicIP == out[i].IP {
				out[i].Joined = r.ID
			}
		}
		out[i].Ever = out[i].Joined > 0 || slices.Contains(nodesF.Migrated, out[i].Key)
	}
	nodesMu.Unlock()
	return out
}

// nodeMigrateCloseLocked closes the move when its time is up or every
// foreign server has joined; it reports whether the move is open.
func nodeMigrateCloseLocked(st *nodeMigrateState, peers []nodeMigratePeer) bool {
	if !st.Open {
		return false
	}
	all := len(peers) > 0 // a list that could not be read is not "all joined"
	for _, p := range peers {
		all = all && p.Ever
	}
	if all || time.Since(time.Unix(st.OpenedAt, 0)) > nodeMigrateOpen {
		st.Open = false
		_ = nodeMigrateSave(*st)
		return false
	}
	return true
}

// nodeMigrateView is what GET /api/nodes says about the move.
func nodeMigrateView(self nodeSelf) map[string]any {
	if self.Role == nodeRoleNode {
		return nil
	}
	peers := nodeMigratePeers()
	if len(peers) == 0 {
		return nil
	}
	nodeMigrateMu.Lock()
	st := nodeMigrateLoad()
	open := nodeMigrateCloseLocked(&st, peers)
	nodeMigrateMu.Unlock()
	offer := self.Role == "" && !open && !st.Never && st.OpenedAt == 0 && time.Now().Unix() >= st.LaterUntil
	return map[string]any{"offer": offer, "open": open && self.Role == nodeRoleCentral, "never": st.Never, "peers": peers}
}

// nodeMigrateAction: migrate-start | migrate-later | migrate-never | migrate-stop.
func nodeMigrateAction(self nodeSelf, action string) error {
	nodeMigrateMu.Lock()
	defer nodeMigrateMu.Unlock()
	st := nodeMigrateLoad()
	switch action {
	case "migrate-start":
		if self.Role == nodeRoleNode {
			return nodeErr{"E-NODE-02", "this panel is a node of another central"}
		}
		if len(nodeMigratePeers()) == 0 {
			return nodeErr{"E-NODE-01", "this panel has no foreign servers to move"}
		}
		if self.Role == "" {
			nodesMu.Lock()
			nodesLoadLocked()
			bad := nodesEr
			var err error
			if bad == "" {
				err = nodeSelfSave(nodeSelf{Role: nodeRoleCentral})
			}
			nodesMu.Unlock()
			if bad != "" {
				return fmt.Errorf("nodes.json cannot be read (%s): fix or remove it first", bad)
			}
			if err != nil {
				return err
			}
		}
		st = nodeMigrateState{Open: true, OpenedAt: time.Now().Unix()}
	case "migrate-later":
		st.LaterUntil = time.Now().Add(nodeMigrateLater).Unix()
	case "migrate-never":
		st.Never = true
	case "migrate-stop":
		st.Open = false
		nodesMu.Lock()
		nodesLoadLocked()
		keep := nodesF.Invites[:0]
		for _, iv := range nodesF.Invites {
			if iv.Peer == "" {
				keep = append(keep, iv)
			}
		}
		nodesF.Invites = keep
		err := nodesSaveLocked()
		nodesMu.Unlock()
		if err != nil {
			return err
		}
	default:
		return nodeErr{"E-NODE-01", "unknown action"}
	}
	return nodeMigrateSave(st)
}

// nodeMigrateLinked: the Peer Link was saved by a tunnel's setup (without
// the file, loadPeerConfig makes up a default with a random secret).
func nodeMigrateLinked() bool {
	_, err := os.Stat(peerConfigFile())
	return err == nil
}

// ---- the offer (Iran side) ----

// nodeMigrateOffer is what a foreign server gets.
type nodeMigrateOffer struct {
	URL   string `json:"url"`
	Key   string `json:"key"`
	Nonce string `json:"nonce"`
	MAC   string `json:"mac"`
}

func nodeMigrateMAC(token, label string, parts ...string) string {
	m := hmac.New(sha256.New, []byte(token))
	m.Write([]byte("hashem-node-migrate:" + label))
	for _, p := range parts {
		m.Write([]byte{0})
		m.Write([]byte(p))
	}
	return hex.EncodeToString(m.Sum(nil))
}

func (o nodeMigrateOffer) mac(token string) string {
	return nodeMigrateMAC(token, "offer", o.URL, o.Key, o.Nonce)
}

// secret is the join secret both sides compute from the token.
func (o nodeMigrateOffer) secret(token string) string {
	return nodeMigrateMAC(token, "join", o.Key, o.Nonce)
}

// handlePeerNodeOffer is GET /_hp/api/peer/node-offer, behind
// requireTunnelSecretHidden. Anything but an open migration is a bare 404.
func handlePeerNodeOffer(w http.ResponseWriter, r *http.Request) {
	// held throughout: a Stop between the check and the invite leaves none
	nodeMigrateMu.Lock()
	defer nodeMigrateMu.Unlock()
	self, err := nodeSelfLoad()
	st := nodeMigrateLoad()
	peers := nodeMigratePeers()
	if err != nil || self.Role != nodeRoleCentral || !nodeMigrateCloseLocked(&st, peers) {
		http.NotFound(w, r)
		return
	}
	// whose token opened the route: a peer's (context) or the Peer Link's
	want := "main"
	if id, _ := r.Context().Value(tunnelCtxKey{}).(int); id > 0 {
		want = "peer:" + strconv.Itoa(id)
	}
	var peer *nodeMigratePeer
	for _, p := range peers {
		if p.Key == want {
			peer = &p
			break
		}
	}
	if peer == nil || peer.Ever {
		http.NotFound(w, r)
		return
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	central, err := nodeCentralURL(scheme + "://" + r.Host) // the address this server was reached on
	if err != nil {
		http.NotFound(w, r)
		return
	}
	pub, err := nodePub()
	if err != nil {
		http.Error(w, "no key", http.StatusInternalServerError)
		return
	}
	var nb [16]byte
	_, _ = rand.Read(nb[:])
	o := nodeMigrateOffer{URL: central, Key: pub, Nonce: hex.EncodeToString(nb[:])}
	o.MAC = o.mac(peer.token)
	now := time.Now()
	nodesMu.Lock()
	nodesLoadLocked()
	if nodesEr != "" {
		nodesMu.Unlock()
		http.Error(w, "nodes.json cannot be read", http.StatusServiceUnavailable)
		return
	}
	nodeInvitesPruneLocked(now)
	keep := nodesF.Invites[:0] // one open offer per foreign server
	for _, iv := range nodesF.Invites {
		if iv.Peer != peer.Key {
			keep = append(keep, iv)
		}
	}
	nodesF.Invites = append(keep, nodeInvite{Hash: nodeSecretHash(o.secret(peer.token)), Name: peer.Name, Peer: peer.Key,
		Created: now.Unix(), Expires: now.Add(nodeInviteTTL).Unix()})
	err = nodesSaveLocked()
	nodesMu.Unlock()
	if err != nil {
		http.Error(w, "cannot save", http.StatusInternalServerError)
		return
	}
	writeJSON(w, o)
}

// ---- joining by the offer (foreign side) ----

func nodeMigratedFile() string { return filepath.Join(configDir, "node_migrated") }

// nodeMigrateTry asks this server's Iran panel for an offer and joins by it.
// "" when there is nothing to do.
// It answers the offer and the host it was reached on. The Iran server's
// public address is tried first: the central's address then does not
// depend on the tunnel it may have to repair.
var nodeMigrateFetch = func(ctx context.Context) ([]byte, string, error) {
	// not sendToPeer: a 404 (no offer) is the usual answer and must not mark
	// the Peer Link as down
	c := loadPeerConfig()
	tr := &http.Transport{TLSClientConfig: peerTLSConfig(&c)}
	defer tr.CloseIdleConnections()
	client := &http.Client{Timeout: 10 * time.Second, Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	urls := peerTargetURLs(c, "/api/peer/node-offer")
	if pu, err := url.Parse(c.PeerURL); err == nil && pu.Hostname() != "" {
		slices.SortStableFunc(urls, func(a, b string) int {
			pa := strings.Contains(a, "://"+pu.Host) || strings.Contains(a, "://"+pu.Hostname()+":")
			pb := strings.Contains(b, "://"+pu.Host) || strings.Contains(b, "://"+pu.Hostname()+":")
			switch {
			case pa && !pb:
				return -1
			case pb && !pa:
				return 1
			}
			return 0
		})
	}
	for _, u := range urls {
		if ctx.Err() != nil {
			break
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		req.Header.Set("X-Peer-Secret", c.PeerSecret)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK && json.Valid(b) {
			return b, req.URL.Hostname(), nil
		}
	}
	return nil, "", errors.New("no offer")
}

func nodeMigrateTry(ctx context.Context) (string, error) {
	if _, err := os.Stat(nodeMigratedFile()); err == nil {
		return "", nil // joined once already: never again by itself
	}
	nodesMu.Lock()
	self, err := nodeSelfLoad()
	nodesMu.Unlock()
	c := loadPeerConfig()
	if err != nil || self.Role != "" || !nodeMigrateLinked() || c.Role != "worker" || c.PeerSecret == "" {
		return "", nil
	}
	if ft := firstTunnelInfo(); !ft.Exists || ft.Side != "foreign" {
		return "", nil // the Peer Link of a tunnel that is gone
	}
	if !nodeMigrateWatching(time.Now()) {
		return "", nil // its 14 days are over (node move starts them again)
	}
	b, reached, err := nodeMigrateFetch(ctx)
	if err != nil {
		return "", nil // no offer (404), an old Iran panel, or not reachable now
	}
	var o nodeMigrateOffer
	if json.Unmarshal(b, &o) != nil || o.URL == "" || o.Key == "" || o.Nonce == "" {
		return "", errors.New("a bad offer")
	}
	if !hmac.Equal([]byte(o.MAC), []byte(o.mac(c.PeerSecret))) {
		return "", errors.New("an offer not made with this tunnel's token: ignored")
	}
	// only a central at the address this server reached its Iran panel on
	if u, err := url.Parse(o.URL); err != nil || !strings.EqualFold(u.Hostname(), reached) {
		return "", fmt.Errorf("an offer for a central at %s, not at %s where the Iran panel answered: ignored", o.URL, reached)
	}
	code := nodeCode{URL: o.URL, Key: o.Key, Secret: o.secret(c.PeerSecret)}
	host, _ := os.Hostname()
	s, err := nodeJoin(ctx, code.String(), host)
	if err != nil {
		return "", err
	}
	if err := writeFile0600(nodeMigratedFile(), []byte(time.Now().UTC().Format(time.RFC3339)+"\n")); err != nil {
		log.Printf("nodes: cannot write %s (%v): this server may join again by itself after it leaves", nodeMigratedFile(), err)
	}
	LogSecurityAudit("node_migrated", "node", "", "central="+s.Central+" id="+strconv.Itoa(s.ID))
	return s.Central, nil
}

// ---- how long a foreign server looks for an offer ----

func nodeMigrateWatchFile() string { return filepath.Join(configDir, "node_migrate_watch") }

// nodeMigrateWatching: within 14 days of the first look (the file is made
// then), or of `node move`.
func nodeMigrateWatching(now time.Time) bool {
	b, err := os.ReadFile(nodeMigrateWatchFile())
	if err != nil {
		if os.IsNotExist(err) {
			_ = nodeMigrateWatchReset()
			return true
		}
		return false
	}
	since, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	return err == nil && now.Sub(time.Unix(since, 0)) < nodeMigrateWatch
}

func nodeMigrateWatchReset() error {
	return writeFile0600(nodeMigrateWatchFile(), []byte(strconv.FormatInt(time.Now().Unix(), 10)+"\n"))
}

// startNodeMigrateWatch: a foreign server checks for its Iran panel's offer
// now and then while it is standalone.
func startNodeMigrateWatch() {
	time.Sleep(time.Minute)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), nodeHandshakeTO*3)
		central, err := nodeMigrateTry(ctx)
		cancel()
		if err != nil {
			log.Printf("nodes: moving to the node system: %v", err)
		} else if central != "" {
			log.Printf("nodes: joined %s as a node (moved by the Iran panel; tunnels untouched)", strings.TrimSpace(central))
		}
		time.Sleep(nodeMigratePoll)
	}
}
