package main

// Nodes N5: moving an existing install to the node system. An Iran panel
// with foreign servers offers it once (Yes / Not now = 7 days / Don't ask
// again). On yes it becomes the central and opens the migration: each of
// its foreign servers, once updated, asks for an offer over the existing
// Peer Link route (GET /_hp/api/peer/node-offer, authenticated by the tunnel
// token the two already share) and joins.
//
// Trust comes from the tunnel token, which never crosses the network:
//
//   - the offer is {url, key, nonce} with mac = HMAC(token, offer fields), so
//     the foreign server only trusts a central key the token holder made;
//   - the join secret is HMAC(token, nonce, key), which both sides compute;
//     the central keeps it as an ordinary one-time invite (hash only, 30
//     minutes), so the join is the normal enrollment over the pinned
//     channel. Someone who sees the offer cannot join without the token.
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
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	nodeMigrateLater = 7 * 24 * time.Hour
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
	token  string
}

// nodeMigratePeers: the first tunnel's foreign server (its token is the
// Peer Link secret) and every peer with a token of its own.
func nodeMigratePeers() []nodeMigratePeer {
	var out []nodeMigratePeer
	// a saved Peer Link (not the made-up default) and a first tunnel set up
	if c := loadPeerConfig(); nodeMigrateLinked() && c.Role == "master" && c.PeerSecret != "" {
		if ip := readSetupMeta().RemotePub; ip != "" {
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
	}
	nodesMu.Unlock()
	return out
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
	nodeMigrateMu.Unlock()
	offer := self.Role == "" && !st.Open && !st.Never && time.Now().Unix() >= st.LaterUntil
	return map[string]any{"offer": offer, "open": st.Open && self.Role == nodeRoleCentral, "never": st.Never, "peers": peers}
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
	self, err := nodeSelfLoad()
	nodeMigrateMu.Lock()
	st := nodeMigrateLoad()
	nodeMigrateMu.Unlock()
	if err != nil || self.Role != nodeRoleCentral || !st.Open {
		http.NotFound(w, r)
		return
	}
	// whose token opened the route: a peer's (context) or the Peer Link's
	want := "main"
	if id, _ := r.Context().Value(tunnelCtxKey{}).(int); id > 0 {
		want = "peer:" + strconv.Itoa(id)
	}
	var peer *nodeMigratePeer
	for _, p := range nodeMigratePeers() {
		if p.Key == want {
			peer = &p
			break
		}
	}
	if peer == nil || peer.Joined > 0 {
		http.NotFound(w, r)
		return
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	url, err := nodeCentralURL(scheme + "://" + r.Host) // the address this server was reached on
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
	o := nodeMigrateOffer{URL: url, Key: pub, Nonce: hex.EncodeToString(nb[:])}
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
var nodeMigrateFetch = func() ([]byte, error) {
	// not sendToPeer: a 404 (no offer) is the usual answer and must not mark
	// the Peer Link as down
	c := loadPeerConfig()
	tr := &http.Transport{TLSClientConfig: peerTLSConfig(&c)}
	defer tr.CloseIdleConnections()
	client := &http.Client{Timeout: 10 * time.Second, Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for _, u := range peerTargetURLs(c, "/api/peer/node-offer") {
		req, err := http.NewRequest(http.MethodGet, u, nil)
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
			return b, nil
		}
	}
	return nil, errors.New("no offer")
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
	b, err := nodeMigrateFetch()
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
	code := nodeCode{URL: o.URL, Key: o.Key, Secret: o.secret(c.PeerSecret)}
	host, _ := os.Hostname()
	s, err := nodeJoin(ctx, code.String(), host)
	if err != nil {
		return "", err
	}
	_ = writeFile0600(nodeMigratedFile(), []byte(time.Now().UTC().Format(time.RFC3339)+"\n"))
	LogSecurityAudit("node_migrated", "node", "", "central="+s.Central+" id="+strconv.Itoa(s.ID))
	return s.Central, nil
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
