package main

// Nodes: one panel (the central) drives other servers (nodes) over a channel
// each node dials. docs/PLAN_NODES.md is the design; this file holds the
// roles, the keys and the files, node_link.go the channel and node_api.go
// the panel API and the CLI.
//
// Roles: no node.json = standalone (as before). node.json says "central" or
// "node". A central keeps nodes.json: its nodes and the open invites. Each
// panel has one Ed25519 key (node.key); the channel is TLS with both ends
// pinned to the other's key, so there is no CA and no domain to set up.
//
// A node is the source of truth for its own state: the central keeps no
// copy of tunnels, only who its nodes are and what they last reported.

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
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
	nodeProto       = 1           // channel protocol version
	nodeLinkPath    = "/_hn/link" // fixed: a node cannot know the central's base path
	nodeInviteTTL   = 30 * time.Minute
	nodeInvitesMax  = 20
	nodesMax        = 200
	nodeNameMax     = 40
	nodeCodePrefix  = "hn1."
	nodeRoleCentral = "central"
	nodeRoleNode    = "node"
)

// nodeSelf is node.json: this panel's role.
type nodeSelf struct {
	Role string `json:"role"` // central | node
	// node only:
	ID         int    `json:"id,omitempty"`          // the id the central gave this node
	Central    string `json:"central,omitempty"`     // the central's panel URL (http://IP:PORT)
	CentralKey string `json:"central_key,omitempty"` // the central's public key (base64)
	Name       string `json:"name,omitempty"`
	JoinedAt   int64  `json:"joined_at,omitempty"`
	// Refused: the central did not know this node on the last try (it was
	// removed while this node was away, or its list was lost). The node keeps
	// trying, slowly, until it is joined again or leaves.
	Refused string `json:"refused,omitempty"`
}

// nodeRecord is one node in the central's nodes.json.
type nodeRecord struct {
	ID       int      `json:"id"`
	Name     string   `json:"name"`
	Key      string   `json:"key"` // the node's public key (base64)
	Added    int64    `json:"added"`
	LastSeen int64    `json:"last_seen,omitempty"`
	Addr     string   `json:"addr,omitempty"` // where it connected from
	Info     nodeInfo `json:"info"`
	// LicensePushed: nodeKeyHash of the central's key the central put on
	// this node (so a renewal replaces it, and a node's own key is left alone)
	LicensePushed string `json:"license_pushed,omitempty"`
	Peer          string `json:"peer,omitempty"` // joined by a move to nodes: its tunnel on this server
	Held          bool   `json:"held,omitempty"` // joined by the move and not approved yet: no license copy
}

// nodeInvite is a one-time join code; only its hash is kept.
type nodeInvite struct {
	Hash    string `json:"hash"`
	Name    string `json:"name,omitempty"`
	Created int64  `json:"created"`
	Expires int64  `json:"expires"`
	Peer    string `json:"peer,omitempty"` // a move to nodes: the foreign server's tunnel ("main" | "peer:<id>")
}

type nodesFile struct {
	Nodes    []nodeRecord  `json:"nodes"`
	Invites  []nodeInvite  `json:"invites,omitempty"`
	NextID   int           `json:"next_id,omitempty"` // ids are never given out twice
	Left     []nodeTunLeft `json:"left,omitempty"`    // server ends of tunnels whose making failed half-way (node_tunnel.go)
	LeftNext int           `json:"left_next,omitempty"`
	Migrated []string      `json:"migrated,omitempty"` // tunnels whose foreign server joined by the move (node_migrate.go)
}

// nodeInfo is what a node reports about itself (the "info" call).
type nodeInfo struct {
	Proto       int         `json:"proto"`
	Version     string      `json:"version"`
	Hostname    string      `json:"hostname"`
	PublicIP    string      `json:"public_ip,omitempty"`
	Side        string      `json:"side,omitempty"` // iran | foreign | "" (not set up)
	Tunnels     int         `json:"tunnels"`
	CPUPct      float64     `json:"cpu_pct"` // -1: not known yet
	MemPct      float64     `json:"mem_pct"`
	DiskPct     float64     `json:"disk_pct"`
	UptimeSec   int64       `json:"uptime_sec"` // the panel's
	MachineHash string      `json:"machine_hash"`
	License     nodeLicense `json:"license"`
	At          int64       `json:"at"`
}

// nodeLicense: the license state a node reports (its own check decides it).
type nodeLicense struct {
	Active   bool     `json:"active"`
	Customer string   `json:"customer,omitempty"`
	Expires  int64    `json:"expires,omitempty"`
	Locked   bool     `json:"locked,omitempty"` // locked to this machine
	Features []string `json:"features,omitempty"`
	KeyHash  string   `json:"key_hash,omitempty"` // nodeKeyHash of its key (never the key)
	Reported bool     `json:"reported,omitempty"` // a node that reports KeyHash (N2 and later)
}

var (
	nodesMu  sync.Mutex // nodes.json, node.json writes, the sessions
	nodesF   nodesFile
	nodesOK  bool      // nodesF was loaded
	nodesMod time.Time // nodes.json's mtime when loaded or saved: the CLI may change it
	nodesEr  string    // why nodes.json could not be read ("" = fine)

	nodeKeyMu   sync.Mutex
	nodeKeyPriv ed25519.PrivateKey
	nodeCertTLS *tls.Certificate
)

func nodeSelfPath() string                  { return filepath.Join(configDir, "node.json") }
func nodesPath() string                     { return filepath.Join(configDir, "nodes.json") }
func nodeKeyPath() string                   { return filepath.Join(configDir, "node.key") }
func nodeKeyB64(k ed25519.PublicKey) string { return base64.StdEncoding.EncodeToString(k) }

// nodeFingerprint is a short form of a key, for people to compare.
func nodeFingerprint(keyB64 string) string {
	h := sha256.Sum256([]byte(keyB64))
	return hex.EncodeToString(h[:8])
}

// writeFile0600 writes path atomically: a temp file of its own (the CLI and
// the service may write at once), synced before it takes the name.
func writeFile0600(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, err = f.Write(data)
	if err == nil {
		err = f.Chmod(0600)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		_ = os.Remove(tmp)
	}
	return err
}

// nodeSelfLoad reads node.json; a missing file is standalone.
func nodeSelfLoad() (nodeSelf, error) {
	var s nodeSelf
	data, err := os.ReadFile(nodeSelfPath())
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(data, &s); err != nil {
		return nodeSelf{}, fmt.Errorf("node.json: %v", err)
	}
	if s.Role != nodeRoleCentral && s.Role != nodeRoleNode {
		return nodeSelf{}, fmt.Errorf("node.json: unknown role %q", s.Role)
	}
	return s, nil
}

func nodeSelfSave(s nodeSelf) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return writeFile0600(nodeSelfPath(), data)
}

// nodeSelfClear makes this panel standalone again.
func nodeSelfClear() error {
	err := os.Remove(nodeSelfPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// nodeKey is this panel's key pair, made on first use. Two processes (the
// service and the CLI) may race to make it: O_EXCL lets one win, the other
// reads the winner's key.
func nodeKey() (ed25519.PrivateKey, error) {
	nodeKeyMu.Lock()
	defer nodeKeyMu.Unlock()
	if nodeKeyPriv != nil {
		return nodeKeyPriv, nil
	}
	read := func() (ed25519.PrivateKey, error) {
		data, err := os.ReadFile(nodeKeyPath())
		if err != nil {
			return nil, err
		}
		seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
		if err != nil || len(seed) != ed25519.SeedSize {
			return nil, fmt.Errorf("node.key is damaged")
		}
		return ed25519.NewKeyFromSeed(seed), nil
	}
	k, err := read()
	if errors.Is(err, os.ErrNotExist) {
		_, priv, gerr := ed25519.GenerateKey(rand.Reader)
		if gerr != nil {
			return nil, gerr
		}
		if err := os.MkdirAll(configDir, 0700); err != nil {
			return nil, err
		}
		f, ferr := os.OpenFile(nodeKeyPath(), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if ferr == nil {
			_, werr := f.WriteString(base64.StdEncoding.EncodeToString(priv.Seed()) + "\n")
			if cerr := f.Close(); werr == nil {
				werr = cerr
			}
			if werr != nil {
				_ = os.Remove(nodeKeyPath())
				return nil, werr
			}
		} else if !errors.Is(ferr, os.ErrExist) {
			return nil, ferr
		}
		k, err = read()
	}
	if err != nil {
		return nil, err
	}
	nodeKeyPriv = k
	return k, nil
}

// nodePub is this panel's public key (base64).
func nodePub() (string, error) {
	k, err := nodeKey()
	if err != nil {
		return "", err
	}
	return nodeKeyB64(k.Public().(ed25519.PublicKey)), nil
}

// nodeCert is a self-signed certificate for this panel's key. Only the key
// counts (the other end pins it); names and dates are filler.
func nodeCert() (*tls.Certificate, error) {
	k, err := nodeKey()
	if err != nil {
		return nil, err
	}
	nodeKeyMu.Lock()
	defer nodeKeyMu.Unlock()
	if nodeCertTLS != nil {
		return nodeCertTLS, nil
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		return nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "hashem-node"},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(20 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, k.Public(), k)
	if err != nil {
		return nil, err
	}
	nodeCertTLS = &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
	return nodeCertTLS, nil
}

// nodePeerKey is the Ed25519 key of the other end's certificate.
func nodePeerKey(raw [][]byte) (string, error) {
	if len(raw) == 0 {
		return "", errors.New("no certificate")
	}
	c, err := x509.ParseCertificate(raw[0])
	if err != nil {
		return "", err
	}
	pk, ok := c.PublicKey.(ed25519.PublicKey)
	if !ok {
		return "", errors.New("not an Ed25519 key")
	}
	return nodeKeyB64(pk), nil
}

// nodeTLSConfig: TLS 1.3 with the other end's key checked by verify (the
// usual chain checks do not apply to self-signed keys).
func nodeTLSConfig(server bool, verify func(peerKey string) error) (*tls.Config, error) {
	cert, err := nodeCert()
	if err != nil {
		return nil, err
	}
	c := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		Certificates:       []tls.Certificate{*cert},
		InsecureSkipVerify: true, // replaced by VerifyPeerCertificate: the key is pinned
		// no resumption: every connection is a full handshake, so the key is
		// always checked and always in the connection state
		SessionTicketsDisabled: true,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			k, err := nodePeerKey(raw)
			if err != nil {
				return err
			}
			return verify(k)
		},
	}
	if server {
		c.ClientAuth = tls.RequireAnyClientCert
	}
	return c, nil
}

// ---- invite codes ----

// nodeCode is what an invite gives the new node: where the central is, its
// key (so the node pins it from the first byte) and the one-time secret.
type nodeCode struct {
	URL    string `json:"u"`
	Key    string `json:"k"`
	Secret string `json:"s"`
}

func (c nodeCode) String() string {
	b, _ := json.Marshal(c)
	return nodeCodePrefix + base64.RawURLEncoding.EncodeToString(b)
}

func parseNodeCode(s string) (nodeCode, error) {
	var c nodeCode
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, nodeCodePrefix) {
		return c, errors.New("not a node join code (it starts with hn1.)")
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(s, nodeCodePrefix))
	if err != nil || json.Unmarshal(b, &c) != nil {
		return nodeCode{}, errors.New("the join code is damaged: copy it again")
	}
	if _, err := nodeCentralURL(c.URL); err != nil {
		return nodeCode{}, err
	}
	if k, err := base64.StdEncoding.DecodeString(c.Key); err != nil || len(k) != ed25519.PublicKeySize {
		return nodeCode{}, errors.New("the join code is damaged: copy it again")
	}
	if len(c.Secret) < 20 {
		return nodeCode{}, errors.New("the join code is damaged: copy it again")
	}
	return c, nil
}

// nodeCentralURL checks a central's address: http(s)://host[:port], no
// path. A bare host[:port] is taken as http.
func nodeCentralURL(s string) (string, error) {
	s = strings.TrimRight(strings.TrimSpace(s), "/")
	if s == "" {
		return "", errors.New("the central's address is empty")
	}
	if !strings.Contains(s, "://") {
		s = "http://" + s
	}
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.User != nil || u.Fragment != "" {
		return "", fmt.Errorf("the central's address %q is not http(s)://host:port", s)
	}
	host := u.Hostname()
	if host == "" || strings.ContainsAny(host, " /\\") {
		return "", fmt.Errorf("the central's address %q has no host", s)
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return "", fmt.Errorf("the central's address %q has a bad port", s)
		}
	}
	return u.Scheme + "://" + u.Host, nil
}

// nodeLinkURL is the channel's websocket URL at a central.
func nodeLinkURL(central string) string {
	if strings.HasPrefix(central, "https://") {
		return "wss://" + strings.TrimPrefix(central, "https://") + nodeLinkPath
	}
	return "ws://" + strings.TrimPrefix(central, "http://") + nodeLinkPath
}

// nodeDefaultURL is the address a new node is told to dial: this panel's
// public IP and HTTP port.
func nodeDefaultURL() string {
	ip := detectPublicIPCached()
	if ip == "" {
		return ""
	}
	return "http://" + net.JoinHostPort(ip, strconv.Itoa(cfg.Port))
}

func nodeSecretHash(secret string) string {
	h := sha256.Sum256([]byte("hashem-node-invite:" + secret))
	return hex.EncodeToString(h[:])
}

// ---- nodes.json (central) ----

// nodesLoadLocked reads nodes.json once. A file that cannot be read is
// kept as it is (nodesEr), nothing is saved over it, and it is read again
// on the next call.
func nodesLoadLocked() {
	fi, statErr := os.Stat(nodesPath())
	if nodesOK && nodesEr == "" && (statErr != nil || fi.ModTime().Equal(nodesMod)) {
		return // a file that could not be read, or was changed by the CLI, is read again
	}
	nodesOK, nodesEr, nodesF = true, "", nodesFile{}
	if statErr == nil {
		nodesMod = fi.ModTime()
	}
	data, err := os.ReadFile(nodesPath())
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err == nil {
		err = json.Unmarshal(data, &nodesF)
	}
	if err != nil {
		nodesEr = err.Error()
		nodesF = nodesFile{}
	}
}

func nodesSaveLocked() error {
	if nodesEr != "" {
		return fmt.Errorf("nodes.json cannot be read (%s): fix or remove it first", nodesEr)
	}
	data, err := json.MarshalIndent(nodesF, "", "  ")
	if err != nil {
		return err
	}
	if err := writeFile0600(nodesPath(), data); err != nil {
		return err
	}
	if fi, err := os.Stat(nodesPath()); err == nil {
		nodesMod = fi.ModTime()
	}
	return nil
}

func nodeFindLocked(id int) *nodeRecord {
	for i := range nodesF.Nodes {
		if nodesF.Nodes[i].ID == id {
			return &nodesF.Nodes[i]
		}
	}
	return nil
}

func nodeFindKeyLocked(key string) *nodeRecord {
	for i := range nodesF.Nodes {
		if nodesF.Nodes[i].Key == key {
			return &nodesF.Nodes[i]
		}
	}
	return nil
}

// nodeInvitesPruneLocked drops expired invites.
func nodeInvitesPruneLocked(now time.Time) {
	kept := nodesF.Invites[:0]
	for _, iv := range nodesF.Invites {
		if iv.Expires > now.Unix() {
			kept = append(kept, iv)
		}
	}
	nodesF.Invites = kept
}

// nodeInviteLocked makes a one-time code for a new node.
func nodeInviteLocked(name, central string, now time.Time) (nodeCode, nodeInvite, error) {
	pub, err := nodePub()
	if err != nil {
		return nodeCode{}, nodeInvite{}, err
	}
	nodeInvitesPruneLocked(now)
	if len(nodesF.Invites) >= nodeInvitesMax {
		return nodeCode{}, nodeInvite{}, fmt.Errorf("at most %d open join codes: cancel some first", nodeInvitesMax)
	}
	if len(nodesF.Nodes) >= nodesMax {
		return nodeCode{}, nodeInvite{}, fmt.Errorf("at most %d nodes", nodesMax)
	}
	secret := randomToken(24)
	iv := nodeInvite{Hash: nodeSecretHash(secret), Name: name, Created: now.Unix(), Expires: now.Add(nodeInviteTTL).Unix()}
	nodesF.Invites = append(nodesF.Invites, iv)
	return nodeCode{URL: central, Key: pub, Secret: secret}, iv, nil
}

// nodeEnrollLocked takes an invite's secret and adds the node with key, or
// gives back the id it already has (a join run twice). The invite is used up.
func nodeEnrollLocked(secret, key, name, addr string, now time.Time) (int, error) {
	nodeInvitesPruneLocked(now)
	h := nodeSecretHash(secret)
	at := -1
	for i, iv := range nodesF.Invites {
		if ConstantTimeCompare(iv.Hash, h) {
			at = i
		}
	}
	if at < 0 {
		return 0, errors.New("the join code is not valid: it was used, cancelled or is older than 30 minutes")
	}
	iv := nodesF.Invites[at]
	nodesF.Invites = append(nodesF.Invites[:at], nodesF.Invites[at+1:]...)
	if r := nodeFindKeyLocked(key); r != nil {
		return r.ID, nil
	}
	if len(nodesF.Nodes) >= nodesMax {
		return 0, fmt.Errorf("at most %d nodes", nodesMax)
	}
	if iv.Name != "" {
		name = iv.Name
	}
	if name == "" {
		name = "node"
	}
	id := max(nodesF.NextID, 1)
	for _, r := range nodesF.Nodes {
		if r.ID >= id {
			id = r.ID + 1
		}
	}
	nodesF.NextID = id + 1 // a removed node's id is not given to the next one
	nodesF.Nodes = append(nodesF.Nodes, nodeRecord{ID: id, Name: name, Key: key, Added: now.Unix(), LastSeen: now.Unix(), Addr: addr,
		Peer: iv.Peer, Held: iv.Peer != ""})
	if iv.Peer != "" && !slices.Contains(nodesF.Migrated, iv.Peer) {
		nodesF.Migrated = append(nodesF.Migrated, iv.Peer)
	}
	return id, nil
}

// nodeCleanName keeps a node name short and printable.
func nodeCleanName(s string) (string, error) {
	s = strings.TrimSpace(s)
	if len([]rune(s)) > nodeNameMax {
		return "", fmt.Errorf("name: at most %d characters", nodeNameMax)
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f || r == '<' || r == '>' {
			return "", errors.New("name: letters, digits, spaces and simple marks only")
		}
	}
	return s, nil
}
