package main

// Carrier swap: change how one tunnel travels (its engine and transport) on
// both of its servers, started from the Iran side.
//
//  1. The foreign server is told first, over the peer API: the main tunnel's
//     Peer Link, or the peer's own token for every other tunnel. It accepts,
//     answers at once and switches a moment later, so the answer is never lost
//     to its own switch.
//  2. This server switches the tunnel's units (with the engine switch's
//     rollback when a unit does not come up).
//  3. The swap only counts once the tunnel's control session is back. When it
//     is not back within swapVerifyWait, both servers are put back on the old
//     carrier, so a carrier the network blocks cannot strand the tunnel.
//
// When the foreign panel cannot be reached the admin may still swap this side
// alone ("manual"): the answer carries the new bundle for the foreign server.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// carrierChoice is one way a tunnel can travel: "frp:kcp", "backhaul:tcpmux",
// "gre-backhaul:wssmux", ...
type carrierChoice struct {
	Engine    string `json:"engine"`
	Transport string `json:"transport"`
}

func (c carrierChoice) ID() string     { return c.Engine + ":" + c.Transport }
func (c carrierChoice) needsGRE() bool { return c.Engine == "frp" || c.Engine == "gre-backhaul" }

func parseCarrierChoice(id string) (carrierChoice, error) {
	e, t, _ := strings.Cut(strings.ToLower(strings.TrimSpace(id)), ":")
	switch e {
	case "frp":
		if t == "" {
			t = "tcp"
		}
		if t == "ws" {
			t = "websocket"
		}
		if !frpProtocolOK(t) {
			return carrierChoice{}, fmt.Errorf("unknown FRP transport %q: want one of %s", t, strings.Join(frpProtocols, ", "))
		}
	case "backhaul", "gre-backhaul":
		if t == "" {
			t = "tcpmux"
		}
		if !backhaulTransportOK(t) {
			return carrierChoice{}, fmt.Errorf("unknown Backhaul transport %q: want one of %s", t, strings.Join(backhaulTransports, ", "))
		}
	default:
		return carrierChoice{}, fmt.Errorf("unknown carrier %q: want frp:<transport>, backhaul:<transport> or gre-backhaul:<transport>", id)
	}
	return carrierChoice{Engine: e, Transport: t}, nil
}

// swapTunnel is everything a swap needs to know about one tunnel.
type swapTunnel struct {
	ID        int           `json:"id"`
	Name      string        `json:"name"`
	Main      bool          `json:"main"`
	Current   carrierChoice `json:"current"`
	GreOK     bool          `json:"gre_ok"` // GRE carriers are possible (the tunnel has GRE addresses and a GRE unit)
	Port      int           `json:"port"`
	RemotePub string        `json:"remote_pub"`
	Ports     []int         `json:"-"`
	Raw       []string      `json:"-"`
	LocalPub  string        `json:"-"`
	LocalGre  string        `json:"-"`
	PeerGre   string        `json:"-"`
	Token     string        `json:"-"`
	rec       *peerRecord
}

var errSwapForeign = errors.New("swap the carrier from the Iran server: it switches this server too")

var perPeerUnitRe = regexp.MustCompile(`^(?:frps|backhaul-server)-(\d+)$`)

// isMainUnit: the base tunnel's own units (peers have frps-N / backhaul-server-N).
func isMainUnit(svc string) bool {
	switch svc {
	case "frps", "frpc", "backhaul-server", "backhaul-client":
		return true
	}
	return false
}

// resolveSwapTunnel finds tunnel id: 0 is the base tunnel, N a peers.json record.
func resolveSwapTunnel(id int) (swapTunnel, error) {
	st := localStatus()
	peers := loadPeers()
	iran := strings.Contains(strings.ToLower(st.Role), "iran") || len(peers) > 0
	if !iran {
		return swapTunnel{}, errSwapForeign
	}
	if id <= 0 {
		// A hub with only per-peer units shows that peer as its "main" card.
		if m := perPeerUnitRe.FindStringSubmatch(st.FrpSvc); m != nil {
			n, _ := strconv.Atoi(m[1])
			return resolveSwapTunnel(n)
		}
		if !isMainUnit(st.FrpSvc) {
			return swapTunnel{}, fmt.Errorf("no tunnel on this server yet")
		}
		for _, p := range peers {
			if p.Legacy {
				return mainSwapTunnel(st, &p), nil
			}
		}
		return mainSwapTunnel(st, nil), nil
	}
	for _, p := range peers {
		if p.ID != id {
			continue
		}
		if p.Legacy {
			return mainSwapTunnel(st, &p), nil
		}
		return peerSwapTunnel(p), nil
	}
	return swapTunnel{}, fmt.Errorf("tunnel %d not found", id)
}

func mainSwapTunnel(st tunnelStatus, legacy *peerRecord) swapTunnel {
	t := swapTunnel{ID: 0, Name: xrayOr(linkLabel("main"), "Main tunnel"), Main: true, rec: legacy}
	t.Port = st.BindPort
	if t.Port <= 0 {
		t.Port = st.FrpPort
	}
	t.RemotePub, t.LocalPub = CleanHost(st.RemotePub), st.LocalPub
	if st.Gre.Inner != "" {
		t.LocalGre = strings.SplitN(st.Gre.Inner, "/", 2)[0]
		t.PeerGre = grePeerInner(st.Gre.Inner)
	}
	meta := readSetupMeta()
	if t.LocalGre == "" || t.PeerGre == "" {
		t.LocalGre, t.PeerGre = meta.IranGre, meta.ForeignGre
	}
	if t.LocalPub == "" {
		t.LocalPub = meta.LocalPub
	}
	if t.RemotePub == "" || t.RemotePub == t.PeerGre {
		if meta.RemotePub != "" {
			t.RemotePub = meta.RemotePub
		}
	}
	eng := st.Engine
	if eng == "" {
		eng = "frp"
	}
	t.Current = carrierChoice{Engine: eng, Transport: st.Transport}
	if eng == "frp" {
		t.Current.Transport = mainFRPProtocol(legacy)
	} else if t.Current.Transport == "" {
		t.Current.Transport = "tcpmux"
	}
	// Ports: Backhaul lists them on this side; FRP keeps them in the foreign
	// frpc, so take the record, then the setup.
	for _, p := range st.Proxies {
		if isValidPortOrRangeOrMapping(p) {
			t.Raw = append(t.Raw, p)
		}
	}
	if len(t.Raw) == 0 && legacy != nil {
		t.Raw = recordRawPorts(*legacy)
	}
	if len(t.Raw) == 0 {
		t.Raw = splitPortList(meta.Ports)
	}
	t.Ports = extractNumericPorts(t.Raw)
	t.GreOK = t.LocalGre != "" && t.PeerGre != "" && (st.Gre.Exists || unitFileExists("gre-tunnel"))
	t.Token = meta.Token
	return t
}

func peerSwapTunnel(p peerRecord) swapTunnel {
	t := swapTunnel{ID: p.ID, Name: p.Name, rec: &p, Port: p.FrpPort, RemotePub: p.RemotePub, LocalPub: p.LocalPub,
		LocalGre: p.LocalGre, PeerGre: p.PeerGre, Token: p.Token}
	if t.Name == "" {
		t.Name = "peer-" + strconv.Itoa(p.ID)
	}
	t.Current = peerCarrier(p)
	t.Raw = recordRawPorts(p)
	t.Ports = extractNumericPorts(t.Raw)
	gif := p.GreIf
	if gif == "" || gif == "none" {
		gif = fmt.Sprintf("gre-t%d", p.ID)
	}
	t.GreOK = p.LocalGre != "" && p.PeerGre != "" && unitFileExists(gif)
	return t
}

// peerCarrier is the carrier a peers.json record runs on.
func peerCarrier(p peerRecord) carrierChoice {
	eng := strings.ToLower(p.Engine)
	if eng == "" {
		eng = "frp"
		if strings.HasPrefix(p.FrpsSvc, "backhaul") {
			eng = "gre-backhaul"
			if p.NoGre {
				eng = "backhaul"
			}
		}
	}
	if eng == "frp" {
		t := strings.ToLower(p.FRPTransport)
		if !frpProtocolOK(t) {
			t = "tcp"
		}
		return carrierChoice{Engine: eng, Transport: t}
	}
	t := strings.ToLower(p.Transport)
	if !backhaulTransportOK(t) {
		t = "tcpmux"
	}
	return carrierChoice{Engine: eng, Transport: t}
}

// mainFRPProtocol is the FRP client protocol of the base tunnel as far as the
// Iran side knows it: the last swap, the record, the carrier setting.
func mainFRPProtocol(legacy *peerRecord) string {
	if c := loadSwapState()[0]; strings.HasPrefix(c, "frp:") && frpProtocolOK(strings.TrimPrefix(c, "frp:")) {
		return strings.TrimPrefix(c, "frp:")
	}
	if legacy != nil && frpProtocolOK(legacy.FRPTransport) {
		return legacy.FRPTransport
	}
	if a := loadCarrierConfig().ActiveCarrier; strings.HasPrefix(a, "frp:") {
		if p := strings.TrimPrefix(a, "frp:"); frpProtocolOK(p) {
			return p
		} else if p == "ws" {
			return "websocket"
		}
	}
	return "tcp"
}

// mainCarrierID is the base tunnel's carrier for /api/status (file reads only).
func mainCarrierID(st tunnelStatus) string {
	if !isMainUnit(st.FrpSvc) || st.Engine == "" {
		return ""
	}
	if st.Engine != "frp" {
		t := st.Transport
		if !backhaulTransportOK(t) {
			t = "tcpmux"
		}
		return st.Engine + ":" + t
	}
	if st.FrpSvc == "frpc" { // the foreign side knows its own protocol
		if data, err := os.ReadFile(filepath.Join(frpDir, "frpc.toml")); err == nil {
			for _, l := range strings.Split(string(data), "\n") {
				if k, v, ok := strings.Cut(strings.TrimSpace(l), "="); ok && strings.TrimSpace(k) == "transport.protocol" {
					if p := strings.Trim(strings.TrimSpace(v), `"'`); frpProtocolOK(p) {
						return "frp:" + p
					}
				}
			}
		}
		return "frp:tcp"
	}
	var legacy *peerRecord
	for _, p := range loadPeers() {
		if p.Legacy {
			c := p
			legacy = &c
			break
		}
	}
	return "frp:" + mainFRPProtocol(legacy)
}

func recordRawPorts(p peerRecord) []string {
	if len(p.RawPorts) > 0 {
		return append([]string(nil), p.RawPorts...)
	}
	var out []string
	for _, n := range p.Ports {
		out = append(out, strconv.Itoa(n))
	}
	return out
}

func splitPortList(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' }) {
		if isValidPortOrRangeOrMapping(f) {
			out = append(out, f)
		}
	}
	return out
}

type setupMeta struct {
	LocalPub   string `json:"local_public"`
	RemotePub  string `json:"remote_public"`
	Token      string `json:"token"`
	IranGre    string `json:"iran_gre"`
	ForeignGre string `json:"foreign_gre"`
	Ports      string `json:"ports"`
}

func readSetupMeta() setupMeta {
	var m setupMeta
	if data, err := os.ReadFile(filepath.Join(configDir, "setup.json")); err == nil {
		_ = json.Unmarshal(data, &m)
	}
	return m
}

func unitFileExists(unit string) bool {
	_, err := os.Stat(filepath.Join(engineUnitDir, strings.TrimSuffix(unit, ".service")+".service"))
	return err == nil
}

// ---- swap state: the carrier each tunnel was last swapped to ----

func swapStatePath() string { return filepath.Join(configDir, "carrier_swap.json") }

var swapStateMu sync.Mutex

func loadSwapState() map[int]string {
	swapStateMu.Lock()
	defer swapStateMu.Unlock()
	m := map[int]string{}
	if data, err := os.ReadFile(swapStatePath()); err == nil {
		_ = json.Unmarshal(data, &m)
	}
	return m
}

func saveSwapState(id int, carrier string) {
	swapStateMu.Lock()
	defer swapStateMu.Unlock()
	m := map[int]string{}
	if data, err := os.ReadFile(swapStatePath()); err == nil {
		_ = json.Unmarshal(data, &m)
	}
	m[id] = carrier
	if data, err := json.MarshalIndent(m, "", "  "); err == nil {
		_ = os.WriteFile(swapStatePath(), data, 0600)
	}
}

// ---- this server's half ----

// swapLocalFn switches this server's side of a tunnel; a var for tests.
var swapLocalFn = swapLocal

func swapLocal(t swapTunnel, to carrierChoice) (string, error) {
	if to.needsGRE() && !t.GreOK {
		return "", fmt.Errorf("%s needs GRE, and this tunnel was set up without it", carrierLabel(to))
	}
	if t.Main {
		out, err := switchTunnelEngineWith(to.Engine, to.Transport, engineOpts{Ports: t.Ports, Raw: t.Raw})
		if err != nil {
			return out, err
		}
		if t.rec != nil {
			updatePeerRecord(t.rec.ID, func(p *peerRecord) { recordCarrier(p, to, mainUnitFor(to)) })
		}
		openCarrierFirewall(t.Port, to)
		return out, nil
	}
	return switchPeerCarrier(*t.rec, to)
}

func mainUnitFor(to carrierChoice) string {
	if to.Engine == "frp" {
		return "frps"
	}
	return "backhaul-server"
}

func recordCarrier(p *peerRecord, to carrierChoice, svc string) {
	p.Engine, p.FrpsSvc = to.Engine, svc
	p.NoGre = to.Engine == "backhaul"
	if to.Engine == "frp" {
		p.FRPTransport, p.Transport = to.Transport, ""
		if to.Transport == "tcp" {
			p.FRPTransport = ""
		}
	} else {
		p.Transport, p.FRPTransport = to.Transport, ""
	}
}

// openCarrierFirewall opens the control port for the new carrier: UDP too
// (kcp, quic, Backhaul udp), and quic's port+1.
func openCarrierFirewall(port int, to carrierChoice) {
	if port <= 0 {
		return
	}
	ports := []int{port}
	if to.Engine == "frp" && to.Transport == "quic" {
		q := port + 1
		if q > 65535 {
			q = port - 1
		}
		ports = append(ports, q)
	}
	allowUFWPorts(ports)
}

// updatePeerRecord rewrites one peers.json record.
func updatePeerRecord(id int, fn func(p *peerRecord)) error {
	data, err := os.ReadFile(peersFile())
	if err != nil {
		return err
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil {
		return err
	}
	var peers []peerRecord
	if raw, ok := doc["peers"]; ok {
		if err := json.Unmarshal(raw, &peers); err != nil {
			return err
		}
	}
	found := false
	for i := range peers {
		if peers[i].ID == id {
			fn(&peers[i])
			found = true
		}
	}
	if !found {
		return fmt.Errorf("peer %d not found", id)
	}
	raw, err := json.Marshal(peers)
	if err != nil {
		return err
	}
	doc["peers"] = raw
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	if err := writeTokenFile(peersFile(), append(out, '\n')); err != nil {
		return err
	}
	invalidatePeerIfsCache()
	return nil
}

func engineBinaryPath(name string) string {
	for _, d := range engineBinDirs {
		if p := filepath.Join(d, name); executableFile(p) {
			return p
		}
	}
	if name == "backhaul" {
		for _, p := range backhaulExtraBins {
			if executableFile(p) {
				return p
			}
		}
	}
	return filepath.Join("/usr/local/bin", name)
}

// switchPeerCarrier moves peer p (frps-N or backhaul-server-N) onto another
// carrier: the new unit and config are written, the old engine's unit and
// config are removed once the new one runs, and any failure puts the old
// ones back.
func switchPeerCarrier(p peerRecord, to carrierChoice) (string, error) {
	cur := peerCarrier(p)
	id := p.ID
	frpSvc, bhSvc := fmt.Sprintf("frps-%d", id), fmt.Sprintf("backhaul-server-%d", id)
	newSvc := frpSvc
	if to.Engine != "frp" {
		newSvc = bhSvc
	}
	oldSvc := p.FrpsSvc
	if oldSvc == "" {
		oldSvc = frpSvc
		if cur.Engine != "frp" {
			oldSvc = bhSvc
		}
	}
	bin := "frps"
	if to.Engine != "frp" {
		bin = "backhaul"
	}
	if !engineBinaryPresent(bin) {
		return "", fmt.Errorf("%s binary not found (install it with `hashem` first); nothing was changed", bin)
	}
	token := p.Token
	if token == "" {
		return "", fmt.Errorf("tunnel %d has no token in peers.json; nothing was changed", id)
	}
	if p.FrpPort <= 0 {
		return "", fmt.Errorf("tunnel %d has no control port; nothing was changed", id)
	}
	greIf := p.GreIf
	if greIf == "" || greIf == "none" {
		greIf = fmt.Sprintf("gre-t%d", id)
	}
	udpSvc := backhaulUDPUnit(bhSvc)
	tx := newUnitSwitchTx([]string{greIf, frpSvc, bhSvc, udpSvc})

	var out strings.Builder
	fmt.Fprintf(&out, "Switching tunnel %d to %s...\n", id, carrierLabel(to))
	_ = runSystemctl("stop", oldSvc)
	if newSvc != oldSvc {
		_ = runSystemctl("stop", newSvc)
	}
	if to.needsGRE() {
		if err := runSystemctl("start", greIf+".service"); err != nil {
			return out.String(), tx.rollback(fmt.Errorf("start %s: %w", greIf, err))
		}
	}

	unitPath := filepath.Join(engineUnitDir, newSvc+".service")
	tx.backup(unitPath)
	after := ""
	if to.needsGRE() {
		after = " " + greIf + ".service"
	}
	switch to.Engine {
	case "frp":
		conf := filepath.Join(frpDir, frpSvc+".toml")
		tx.backup(conf)
		if err := writeEngineFile(frpDir, frpSvc+".toml", frpsServerToml(p.FrpPort, token)); err != nil {
			return out.String(), tx.rollback(err)
		}
		if err := writeUnitFile(unitPath, engineUnit("FRP Server Service (peer "+strconv.Itoa(id)+")", after,
			engineBinaryPath("frps")+" -c "+conf)); err != nil {
			return out.String(), tx.rollback(err)
		}
	default:
		conf := filepath.Join(backhaulDir, fmt.Sprintf("server-%d.toml", id))
		tx.backup(conf)
		raw := recordRawPorts(p)
		if err := writeBackhaulServerConfig(conf, fmt.Sprintf("0.0.0.0:%d", p.FrpPort), to.Transport, token, raw); err != nil {
			return out.String(), tx.rollback(fmt.Errorf("write backhaul config: %w", err))
		}
		if err := writeUnitFile(unitPath, engineUnit("Backhaul Server Tunnel ("+bhSvc+")", after,
			engineBinaryPath("backhaul")+" -c "+conf)); err != nil {
			return out.String(), tx.rollback(err)
		}
	}
	_ = runSystemctl("daemon-reload")
	if err := tx.start(newSvc); err != nil {
		return out.String(), tx.rollback(err)
	}
	fmt.Fprintf(&out, "%s configured and started.\n", newSvc)

	// The old engine goes away for good, so it does not grab the control
	// port at the next boot. Its files stay in tx until the swap is done.
	if newSvc != oldSvc {
		_ = runSystemctl("disable", oldSvc)
		oldConf := filepath.Join(frpDir, frpSvc+".toml")
		if cur.Engine != "frp" {
			oldConf = filepath.Join(backhaulDir, fmt.Sprintf("server-%d.toml", id))
			_ = runSystemctl("disable", "--now", udpSvc)
			for _, f := range []string{filepath.Join(engineUnitDir, udpSvc+".service"), filepath.Join(backhaulDir, "udp", bhSvc+".toml")} {
				tx.backup(f)
				_ = os.Remove(f)
			}
		}
		for _, f := range []string{filepath.Join(engineUnitDir, oldSvc+".service"), oldConf} {
			tx.backup(f)
			_ = os.Remove(f)
		}
		_ = runSystemctl("daemon-reload")
	}
	if err := updatePeerRecord(id, func(r *peerRecord) {
		recordCarrier(r, to, newSvc)
		if r.GreIf == "" || r.GreIf == "none" {
			if to.needsGRE() {
				r.GreIf = greIf
			}
		}
	}); err != nil {
		return out.String(), tx.rollback(fmt.Errorf("update peers.json: %w", err))
	}
	openCarrierFirewall(p.FrpPort, to)
	return out.String(), nil
}

// frpsServerToml is the frps config hashem.sh peer_write_frps writes.
func frpsServerToml(port int, token string) string {
	_, maxPool := effectivePoolValues()
	quic := port + 1
	if quic > 65535 {
		quic = port - 1
	}
	return fmt.Sprintf(`bindAddr = "0.0.0.0"
bindPort = %d
kcpBindPort = %d
quicBindPort = %d
auth.method = "token"
auth.token = %q
%stransport.tcpKeepalive = 15
transport.heartbeatTimeout = 45
transport.maxPoolCount = %d
`, port, port, quic, token, tcpMuxTomlLines(), maxPool)
}

func engineUnit(desc, after, exec string) string {
	return fmt.Sprintf(`[Unit]
Description=%s
After=network.target network-online.target%s
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=%s
Restart=always
RestartSec=3s
LimitNOFILE=1048576
LimitNPROC=512000
TasksMax=infinity
CPUWeight=100

[Install]
WantedBy=multi-user.target
`, desc, after, exec)
}

func writeUnitFile(path, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0644)
}

// newUnitSwitchTx is newEngineSwitchTx for a given unit list (the first one is
// the GRE unit, which a rollback leaves running).
func newUnitSwitchTx(svcs []string) *engineSwitchTx {
	tx := &engineSwitchTx{wasActive: map[string]bool{}, files: map[string][]byte{}, svcs: svcs}
	for _, s := range svcs {
		tx.wasActive[s] = engineServiceActive(s)
	}
	return tx
}

func carrierLabel(c carrierChoice) string {
	switch c.Engine {
	case "frp":
		return "GRE + FRP (" + c.Transport + ")"
	case "gre-backhaul":
		return "Backhaul over GRE (" + c.Transport + ")"
	}
	return "Backhaul (" + c.Transport + ")"
}

// ---- the foreign server's half ----

// peerSwapRequest asks a foreign server to move its tunnel to a carrier.
type peerSwapRequest struct {
	Engine    string   `json:"engine"`
	Transport string   `json:"transport"`
	Port      int      `json:"port,omitempty"`
	Ports     []int    `json:"ports,omitempty"`
	Raw       []string `json:"raw,omitempty"`
	Remote    string   `json:"remote,omitempty"`   // the Iran server's public address
	PeerGre   string   `json:"peer_gre,omitempty"` // the Iran server's GRE inner address
	DelayMs   int      `json:"delay_ms,omitempty"`
}

type foreignSwapState struct {
	State   string `json:"state"` // "", "switching", "ok", "failed"
	Carrier string `json:"carrier,omitempty"`
	Error   string `json:"error,omitempty"`
	At      string `json:"at,omitempty"`
	Seq     int    `json:"seq"`
}

var (
	foreignSwapMu  sync.Mutex
	foreignSwapNow foreignSwapState
	// foreignSwitchFn is the foreign side's switch; a var for tests.
	foreignSwitchFn = switchTunnelEngineWith
)

// POST /api/peer/swap-carrier (foreign side)
func handlePeerSwapCarrier(w http.ResponseWriter, r *http.Request) {
	var req peerSwapRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req); err != nil {
		writeAPIError(w, r, "E-ACTION-01", "invalid request json")
		return
	}
	to, err := parseCarrierChoice(req.Engine + ":" + req.Transport)
	if err != nil {
		writeAPIError(w, r, "E-ACTION-01", err.Error())
		return
	}
	if st := localStatus(); strings.Contains(strings.ToLower(st.Role), "iran") {
		writeAPIError(w, r, "E-ACTION-01", "this is the Iran side of the tunnel; only a foreign server follows a swap")
		return
	}
	if backhaulLocked(to.Engine) && proRequired(w, r, proBackhaul, "Backhaul") {
		return
	}
	if err := preflightEngineSwitch(to.Engine, false); err != nil {
		writeAPIError(w, r, "E-ENGINE-01", err.Error())
		return
	}
	delay := time.Duration(req.DelayMs) * time.Millisecond
	if delay < 0 || delay > 10*time.Second {
		delay = 1500 * time.Millisecond
	}
	foreignSwapMu.Lock()
	if foreignSwapNow.State == "switching" {
		foreignSwapMu.Unlock()
		writeAPIError(w, r, "E-ACTION-01", "a carrier swap is already running on this server")
		return
	}
	foreignSwapNow = foreignSwapState{State: "switching", Carrier: to.ID(), At: time.Now().Format(time.RFC3339), Seq: foreignSwapNow.Seq + 1}
	seq := foreignSwapNow.Seq
	foreignSwapMu.Unlock()
	markPeerSeen()
	log.Printf("[PeerSync] carrier swap to %s requested by the Iran server", to.ID())
	writeJSON(w, map[string]any{"status": "accepted", "carrier": to.ID(), "seq": seq})

	opts := engineOpts{Port: req.Port, Ports: req.Ports, Raw: req.Raw, Remote: req.Remote, PeerGre: req.PeerGre}
	go func() {
		time.Sleep(delay)
		out, err := foreignSwitchFn(to.Engine, to.Transport, opts)
		foreignSwapMu.Lock()
		defer foreignSwapMu.Unlock()
		if foreignSwapNow.Seq != seq {
			return
		}
		foreignSwapNow.At = time.Now().Format(time.RFC3339)
		if err != nil {
			foreignSwapNow.State, foreignSwapNow.Error = "failed", err.Error()
			log.Printf("[PeerSync] carrier swap to %s failed: %v (%s)", to.ID(), err, strings.TrimSpace(out))
			return
		}
		foreignSwapNow.State = "ok"
	}()
}

// GET /api/peer/swap-status (foreign side): the last swap and this tunnel's ports.
func handlePeerSwapStatus(w http.ResponseWriter, r *http.Request) {
	foreignSwapMu.Lock()
	s := foreignSwapNow
	foreignSwapMu.Unlock()
	st := localStatus()
	writeJSON(w, map[string]any{"swap": s, "engine": st.Engine, "transport": st.Transport, "ports": st.ProxyPorts})
}

// ---- reaching a tunnel's foreign panel ----

var errNoPeerLink = errors.New("no Peer Link to the foreign server")

// swapCall sends one peer API request to the foreign server of t; a var so
// tests never reach a real panel.
var swapCall = swapCallReal

func swapCallReal(t swapTunnel, method, path string, payload any, timeout time.Duration) ([]byte, error) {
	if t.Main {
		c := loadPeerConfig()
		if c.Role != "master" || c.PeerSecret == "" {
			return nil, errNoPeerLink
		}
		return sendToPeerTimeout(path, method, payload, timeout)
	}
	return tunnelPeerCall(t, method, path, payload, timeout)
}

// tunnelLink is what this hub learned about one peer's foreign panel (from
// that panel's handshake, or the last call that worked).
type tunnelLink struct {
	PanelPort  int    `json:"panel_port,omitempty"`
	BasePath   string `json:"base_path,omitempty"`
	InternalIP string `json:"internal_ip,omitempty"`
	PublicIP   string `json:"public_ip,omitempty"`
	LastURL    string `json:"last_url,omitempty"`
	TLSPin     string `json:"tls_pin,omitempty"`
	Seen       string `json:"seen,omitempty"`
}

func tunnelLinksPath() string { return filepath.Join(configDir, "tunnel_links.json") }

var tunnelLinksMu sync.Mutex

func loadTunnelLinks() map[int]tunnelLink {
	tunnelLinksMu.Lock()
	defer tunnelLinksMu.Unlock()
	return readTunnelLinksLocked()
}

func readTunnelLinksLocked() map[int]tunnelLink {
	m := map[int]tunnelLink{}
	if data, err := os.ReadFile(tunnelLinksPath()); err == nil {
		_ = json.Unmarshal(data, &m)
	}
	return m
}

func updateTunnelLink(id int, fn func(l *tunnelLink)) {
	tunnelLinksMu.Lock()
	defer tunnelLinksMu.Unlock()
	m := readTunnelLinksLocked()
	l := m[id]
	fn(&l)
	m[id] = l
	if data, err := json.MarshalIndent(m, "", "  "); err == nil {
		_ = os.WriteFile(tunnelLinksPath(), data, 0600)
	}
}

// tunnelPeerBases lists the foreign panel's base URLs, best first: the one
// that worked last, then the GRE inner address and the public one on the
// learned port and the usual ones, plain HTTP before HTTPS.
func tunnelPeerBases(t swapTunnel, l tunnelLink) []string {
	var hosts []string
	seenH := map[string]bool{}
	for _, h := range []string{t.PeerGre, l.InternalIP, t.RemotePub, l.PublicIP} {
		if h = CleanHost(h); h != "" && !seenH[h] {
			seenH[h] = true
			hosts = append(hosts, h)
		}
	}
	var ports []int
	seenP := map[int]bool{}
	for _, p := range []int{l.PanelPort, 7777, cfg.Port} {
		if p > 0 && p <= 65535 && !seenP[p] {
			seenP[p] = true
			ports = append(ports, p)
		}
	}
	var out []string
	if l.LastURL != "" {
		out = append(out, l.LastURL)
	}
	for _, h := range hosts {
		for _, p := range ports {
			for _, s := range []string{"http", "https"} {
				u := fmt.Sprintf("%s://%s", s, net.JoinHostPort(h, strconv.Itoa(p)))
				if u != l.LastURL {
					out = append(out, u)
				}
			}
		}
	}
	return out
}

func tunnelPeerCall(t swapTunnel, method, path string, payload any, timeout time.Duration) ([]byte, error) {
	var body []byte
	if payload != nil {
		var err error
		if body, err = json.Marshal(payload); err != nil {
			return nil, err
		}
	}
	secrets := []string{}
	if t.Token != "" {
		secrets = append(secrets, t.Token)
	}
	if c := loadPeerConfig(); c.PeerSecret != "" && c.PeerSecret != t.Token {
		secrets = append(secrets, c.PeerSecret)
	}
	if len(secrets) == 0 {
		return nil, errNoPeerLink
	}
	l := loadTunnelLinks()[t.ID]
	pin := l.TLSPin
	tr := &http.Transport{
		DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // checked against the pin below (trust on first use)
			VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
				if len(raw) == 0 {
					return errors.New("no TLS certificate")
				}
				sum := sha256.Sum256(raw[0])
				got := hex.EncodeToString(sum[:])
				if pin == "" {
					pin = got
					updateTunnelLink(t.ID, func(x *tunnelLink) { x.TLSPin = got })
					return nil
				}
				if subtle.ConstantTimeCompare([]byte(pin), []byte(got)) != 1 {
					return errors.New("foreign panel TLS certificate changed (pinned fingerprint does not match)")
				}
				return nil
			},
		},
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Timeout: timeout, Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	var lastErr error
	dead := map[string]bool{}
	for _, base := range tunnelPeerBases(t, l) {
		host := base
		if i := strings.Index(base, "://"); i >= 0 {
			host = base[i+3:]
		}
		if dead[host] {
			continue
		}
		for _, sec := range secrets {
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			req, err := http.NewRequestWithContext(ctx, method, base+peerRoutePrefix+path, bytes.NewReader(body))
			if err != nil {
				cancel()
				return nil, err
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Peer-Secret", sec)
			resp, err := client.Do(req)
			if err != nil {
				cancel()
				lastErr = err
				var ne net.Error
				if errors.As(err, &ne) || strings.Contains(err.Error(), "refused") {
					dead[host] = true
				}
				break
			}
			data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			_ = resp.Body.Close()
			cancel()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 && json.Valid(data) {
				if l.LastURL != base {
					updateTunnelLink(t.ID, func(x *tunnelLink) { x.LastURL = base })
				}
				return data, nil
			}
			lastErr = fmt.Errorf("foreign panel answered HTTP %d: %s", resp.StatusCode, truncateForError(data))
			if resp.StatusCode != http.StatusNotFound {
				break // the secret was right; another one will not help
			}
		}
	}
	if lastErr == nil {
		lastErr = errNoPeerLink
	}
	return nil, lastErr
}

// tunnelTokenOwner is the peer whose tunnel token is secret (0: none). The
// main tunnel's token is the Peer Link secret and is handled before this.
func tunnelTokenOwner(secret string) int {
	if secret == "" {
		return 0
	}
	for _, p := range loadPeers() {
		if !p.Legacy && p.Token != "" && ConstantTimeCompare(p.Token, secret) {
			return p.ID
		}
	}
	return 0
}

type tunnelCtxKey struct{}

// requireTunnelSecretHidden lets a peer's foreign server (which holds that
// peer's token, not the Peer Link secret) introduce itself and ping, so the
// hub learns where its panel answers. Every failure is a bare 404.
func requireTunnelSecretHidden(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		got := strings.TrimSpace(r.Header.Get("X-Peer-Secret"))
		if got == "" {
			if h := r.Header.Get("Authorization"); strings.HasPrefix(strings.ToLower(h), "bearer ") {
				got = strings.TrimSpace(h[7:])
			}
		}
		if c := loadPeerConfig(); c.PeerSecret != "" && got != "" && ConstantTimeCompare(c.PeerSecret, got) {
			next(w, r)
			return
		}
		if id := tunnelTokenOwner(got); id > 0 {
			next(w, r.WithContext(context.WithValue(r.Context(), tunnelCtxKey{}, id)))
			return
		}
		if got != "" {
			LogSecurityAudit("peer_auth_rejected", "peer", ClientIP(r), "path="+r.URL.Path)
		}
		http.NotFound(w, r)
	}
}

// tunnelHandshake records a peer's foreign panel (port, base path, addresses).
func tunnelHandshake(w http.ResponseWriter, id int, req PeerHandshakeRequest) {
	updateTunnelLink(id, func(l *tunnelLink) {
		if req.PanelPort > 0 && req.PanelPort <= 65535 {
			l.PanelPort = req.PanelPort
		}
		if bp := strings.Trim(req.BasePath, "/"); bp != "" {
			l.BasePath = bp
		}
		if ip := CleanHost(req.InternalIP); ip != "" {
			l.InternalIP = ip
		}
		if ip := CleanHost(req.PublicIP); ip != "" {
			l.PublicIP = ip
		}
		l.Seen = time.Now().Format(time.RFC3339)
	})
	writeJSON(w, map[string]any{
		"status": "ok", "role": "master", "version": panelVersion, "timestamp": time.Now().Unix(),
		"base_path": strings.Trim(cfg.BasePath, "/"), "panel_port": cfg.Port,
	})
}

// ---- the swap job ----

type swapStep struct {
	Key    string `json:"key"`   // check | foreign | local | verify | revert
	State  string `json:"state"` // pending | run | ok | fail | skip
	Detail string `json:"detail,omitempty"`
}

type swapJob struct {
	ID       int        `json:"id"`
	Name     string     `json:"name"`
	From     string     `json:"from"`
	To       string     `json:"to"`
	Manual   bool       `json:"manual"`
	State    string     `json:"state"` // running | ok | failed | reverted | manual
	Error    string     `json:"error,omitempty"`
	Note     string     `json:"note,omitempty"`
	Bundle   string     `json:"bundle,omitempty"`
	Steps    []swapStep `json:"steps"`
	Started  string     `json:"started"`
	Finished string     `json:"finished,omitempty"`
	TookMs   int64      `json:"took_ms,omitempty"`
	started  time.Time
}

var (
	swapJobsMu sync.Mutex
	swapJobs   = map[int]*swapJob{}
	// Waits and polls; vars so tests run in milliseconds.
	swapVerifyWait  = 45 * time.Second
	swapRevertWait  = 30 * time.Second
	swapPollEvery   = time.Second
	swapForeignWait = 1500 * time.Millisecond
	// swapLinkedFn reports whether tunnel t's control session is up.
	swapLinkedFn = swapLinked
)

func (j *swapJob) step(key, state, detail string) {
	swapJobsMu.Lock()
	defer swapJobsMu.Unlock()
	for i := range j.Steps {
		if j.Steps[i].Key == key {
			j.Steps[i].State = state
			if detail != "" {
				j.Steps[i].Detail = detail
			}
			return
		}
	}
	j.Steps = append(j.Steps, swapStep{Key: key, State: state, Detail: detail})
}

func (j *swapJob) finish(state, errMsg string) {
	swapJobsMu.Lock()
	defer swapJobsMu.Unlock()
	j.State, j.Error = state, errMsg
	j.Finished = time.Now().Format(time.RFC3339)
	j.TookMs = time.Since(j.started).Milliseconds()
}

func swapJobView(id int) *swapJob {
	swapJobsMu.Lock()
	defer swapJobsMu.Unlock()
	j := swapJobs[id]
	if j == nil {
		return nil
	}
	c := *j
	c.Steps = append([]swapStep(nil), j.Steps...)
	return &c
}

// swapLinked: the tunnel's control session is established (all carriers keep
// one on TCP, Backhaul's udp transport included); for FRP also a forwarded
// port that frps opened, which it only does once frpc logged in.
func swapLinked(t swapTunnel, to carrierChoice) bool {
	q := ctrlQuery{ID: t.ID, Port: t.Port, RemotePub: t.RemotePub, PeerGre: t.PeerGre}
	var ctrl []int
	if t.Port > 0 {
		ctrl = append(ctrl, t.Port)
	}
	for _, p := range loadPeers() {
		if p.FrpPort > 0 && p.FrpPort != t.Port {
			ctrl = append(ctrl, p.FrpPort)
		}
	}
	if controlSessionIn(parseSS(ssEstablished()), q, portOwners(ctrl)).Linked {
		return true
	}
	if to.Engine == "frp" {
		for i, p := range t.Ports {
			if i >= 4 {
				break
			}
			if c, err := dialFn("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(p)), 500*time.Millisecond); err == nil {
				_ = c.Close()
				return true
			}
		}
	}
	return false
}

func (t swapTunnel) foreignRequest(to carrierChoice) peerSwapRequest {
	return peerSwapRequest{Engine: to.Engine, Transport: to.Transport, Port: t.Port, Ports: t.Ports, Raw: t.Raw,
		Remote: t.LocalPub, PeerGre: t.LocalGre, DelayMs: int(swapForeignWait / time.Millisecond)}
}

// tellForeign asks the foreign server to switch. ok=false: it could not be
// reached or refused, err says why. An older panel without swap-carrier is
// sent the old apply-engine (it answers only after switching, so that call
// runs in the background).
func tellForeign(t swapTunnel, to carrierChoice) (string, error) {
	_, err := swapCall(t, "POST", "/api/peer/swap-carrier", t.foreignRequest(to), 10*time.Second)
	if err == nil {
		return "accepted", nil
	}
	if !strings.Contains(err.Error(), "HTTP 404") {
		return "", err
	}
	if _, perr := swapCall(t, "POST", "/api/peer/ping", map[string]string{"action": "ping"}, 6*time.Second); perr != nil {
		return "", err
	}
	go func() {
		if _, e := swapCall(t, "POST", "/api/peer/apply-engine", PeerApplyEngineRequest{Engine: to.Engine, Transport: to.Transport}, 60*time.Second); e != nil {
			log.Printf("carrier swap: older foreign panel: %v", e)
		}
	}()
	return "sent (older foreign panel)", nil
}

// foreignFailed reports a failure the foreign server recorded for this swap.
func foreignFailed(t swapTunnel, to carrierChoice) string {
	data, err := swapCall(t, "GET", "/api/peer/swap-status", nil, 4*time.Second)
	if err != nil {
		return ""
	}
	var v struct {
		Swap foreignSwapState `json:"swap"`
	}
	if json.Unmarshal(data, &v) == nil && v.Swap.State == "failed" && v.Swap.Carrier == to.ID() {
		return v.Swap.Error
	}
	return ""
}

// waitLinked polls until the tunnel is linked, the foreign side reports a
// failure, or wait runs out.
func waitLinked(t swapTunnel, to carrierChoice, wait time.Duration, askForeign bool) (bool, string) {
	deadline := time.Now().Add(wait)
	n := 0
	for {
		if swapLinkedFn(t, to) {
			return true, ""
		}
		n++
		if askForeign && n%3 == 0 {
			if e := foreignFailed(t, to); e != "" {
				return false, "the foreign server could not switch: " + e
			}
		}
		if time.Now().After(deadline) {
			return false, ""
		}
		time.Sleep(swapPollEvery)
	}
}

func startSwap(t swapTunnel, to carrierChoice, manual bool) (*swapJob, error) {
	swapJobsMu.Lock()
	if j := swapJobs[t.ID]; j != nil && j.State == "running" {
		swapJobsMu.Unlock()
		return nil, fmt.Errorf("a carrier swap of this tunnel is already running")
	}
	for _, j := range swapJobs {
		if j.State == "running" {
			swapJobsMu.Unlock()
			return nil, fmt.Errorf("another tunnel's carrier swap is still running; wait for it to finish")
		}
	}
	now := time.Now()
	j := &swapJob{ID: t.ID, Name: t.Name, From: t.Current.ID(), To: to.ID(), Manual: manual, State: "running",
		Started: now.Format(time.RFC3339), started: now}
	for _, k := range []string{"foreign", "local", "verify"} {
		j.Steps = append(j.Steps, swapStep{Key: k, State: "pending"})
	}
	swapJobs[t.ID] = j
	swapJobsMu.Unlock()
	go runSwap(j, t, to, manual)
	return j, nil
}

func runSwap(j *swapJob, t swapTunnel, to carrierChoice, manual bool) {
	from := t.Current
	LogSecurityAudit("carrier_swap", "admin", "127.0.0.1", fmt.Sprintf("tunnel=%d from=%s to=%s manual=%v", t.ID, from.ID(), to.ID(), manual))

	// 1. The foreign server.
	if manual {
		j.step("foreign", "skip", "Not reachable: apply the new bundle on the foreign server")
	} else {
		j.step("foreign", "run", "")
		how, err := tellForeign(t, to)
		if err != nil {
			j.step("foreign", "fail", err.Error())
			j.step("local", "skip", "")
			j.step("verify", "skip", "")
			j.finish("failed", "The foreign server could not be told, so nothing was changed: "+err.Error())
			return
		}
		j.step("foreign", "ok", how)
	}

	// 2. This server.
	j.step("local", "run", "")
	if _, err := swapLocalFn(t, to); err != nil {
		j.step("local", "fail", err.Error())
		j.step("verify", "skip", "")
		if !manual {
			_, _ = tellForeign(t, from) // the foreign side goes back with us
		}
		j.finish("failed", "This server could not switch, so both sides stay on "+carrierLabel(from)+": "+err.Error())
		return
	}
	j.step("local", "ok", "")
	saveSwapState(t.ID, to.ID())

	if manual {
		j.step("verify", "skip", "")
		if b := swapBundle(t, to); b != "" {
			swapJobsMu.Lock()
			j.Bundle = b
			swapJobsMu.Unlock()
		}
		j.finish("manual", "")
		go runTunnelHealthOnce()
		return
	}

	// 3. The tunnel must come back on the new carrier.
	j.step("verify", "run", "")
	ok, why := waitLinked(t, to, swapVerifyWait, true)
	if ok {
		j.step("verify", "ok", "")
		j.finish("ok", "")
		go runTunnelHealthOnce()
		return
	}
	if why == "" {
		why = fmt.Sprintf("the tunnel did not connect on %s within %ds", carrierLabel(to), int(swapVerifyWait/time.Second))
	}
	j.step("verify", "fail", why)

	// 4. Both sides back to the old carrier.
	j.step("revert", "run", "")
	_, ferr := tellForeign(t, from)
	back := t
	back.Current = to
	if _, err := swapLocalFn(back, from); err != nil {
		j.step("revert", "fail", err.Error())
		j.finish("failed", why+"; switching back failed too: "+err.Error())
		return
	}
	saveSwapState(t.ID, from.ID())
	if ok, _ := waitLinked(t, from, swapRevertWait, false); ok {
		j.step("revert", "ok", "")
		j.finish("reverted", why)
		go runTunnelHealthOnce()
		return
	}
	detail := "this server is back on " + carrierLabel(from) + ", but the tunnel has not reconnected yet"
	if ferr != nil {
		detail += " (the foreign server could not be reached: " + ferr.Error() + ")"
	}
	j.step("revert", "fail", detail)
	j.finish("failed", why+"; "+detail)
}

// swapBundle is the setup bundle for the foreign server on the new carrier.
func swapBundle(t swapTunnel, to carrierChoice) string {
	if t.Token == "" || t.LocalPub == "" || t.Port <= 0 {
		return ""
	}
	tr := backhaulBundleTransport(to.Transport, 0)
	switch to.Engine {
	case "backhaul":
		return MakeBackhaulBundle(t.LocalPub, t.Port, tr, t.Token, t.Raw)
	case "gre-backhaul":
		return MakeGreBackhaulBundle(t.LocalPub, t.Port, t.LocalGre, t.PeerGre, tr, t.Token, t.Raw)
	}
	return MakeBundle(t.LocalPub, t.Port, t.LocalGre, t.PeerGre, t.Token, t.Ports, to.Transport)
}

// ---- HTTP ----

// GET /api/tunnel/swap?id=N[&probe=1]
func handleSwapGet(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(r.URL.Query().Get("id"))
	probe := r.URL.Query().Get("probe") == "1"
	resp := swapView(id, probe)
	if fs, _ := resp["foreign_side"].(bool); fs {
		resp = foreignSwapView(id, probe)
	}
	writeJSON(w, resp)
}

// swapView is what the swap dialog needs about tunnel id on this server.
func swapView(id int, probe bool) map[string]any {
	resp := map[string]any{"id": id}
	t, err := resolveSwapTunnel(id)
	if err != nil {
		resp["error"] = err.Error()
		resp["foreign_side"] = errors.Is(err, errSwapForeign)
		return resp
	}
	resp["tunnel"] = t
	resp["current"] = t.Current.ID()
	resp["backhaul_pro"] = hasPro(proBackhaul) || t.Current.Engine != "frp"
	resp["bins"] = map[string]bool{"frps": engineBinaryPresent("frps"), "backhaul": engineBinaryPresent("backhaul")}
	if j := swapJobView(t.ID); j != nil {
		resp["job"] = j
	}
	if probe {
		_, perr := swapCall(t, "POST", "/api/peer/ping", map[string]string{"action": "ping"}, 6*time.Second)
		resp["follow"] = perr == nil
		if perr != nil {
			resp["follow_error"] = perr.Error()
		}
	}
	return resp
}

// POST /api/tunnel/swap {"id": N, "carrier": "backhaul:wssmux", "manual": false}
func handleSwapPost(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID      int    `json:"id"`
		Carrier string `json:"carrier"`
		Manual  bool   `json:"manual"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&req); err != nil {
		writeAPIError(w, r, "E-ACTION-01", "invalid json")
		return
	}
	to, err := parseCarrierChoice(req.Carrier)
	if err != nil {
		writeAPIError(w, r, "E-ACTION-01", err.Error())
		return
	}
	t, err := resolveSwapTunnel(req.ID)
	if errors.Is(err, errSwapForeign) {
		relaySwapToIran(w, r, to)
		return
	}
	if err != nil {
		writeAPIError(w, r, "E-ACTION-01", err.Error())
		return
	}
	startSwapOn(w, r, t, to, req.Manual)
}

// startSwapOn checks that tunnel t can move to carrier to and starts the swap.
func startSwapOn(w http.ResponseWriter, r *http.Request, t swapTunnel, to carrierChoice, manual bool) {
	if to == t.Current {
		writeAPIError(w, r, "E-ACTION-01", "the tunnel already runs on "+carrierLabel(to))
		return
	}
	if to.needsGRE() && !t.GreOK {
		writeAPIError(w, r, "E-ACTION-01", carrierLabel(to)+" needs GRE, and this tunnel was set up without it")
		return
	}
	if to.Engine != "frp" && t.Current.Engine == "frp" && !hasPro(proBackhaul) && proRequired(w, r, proBackhaul, "Backhaul") {
		return
	}
	bin := "frps"
	if to.Engine != "frp" {
		bin = "backhaul"
	}
	if !engineBinaryPresent(bin) {
		writeAPIError(w, r, "E-ENGINE-01", bin+" is not installed on this server (install it with `hashem` first); nothing was changed")
		return
	}
	if _, err := startSwap(t, to, manual); err != nil {
		writeAPIError(w, r, "E-ACTION-01", err.Error())
		return
	}
	// a copy: runSwap is already changing the job
	writeJSON(w, map[string]any{"status": "started", "job": swapJobView(t.ID)})
}

// ---- swapping from the foreign server ----
//
// The foreign panel cannot run a swap itself: the Iran side holds the ports,
// the tokens and the other tunnels. It asks the Iran server instead, which
// runs the swap as if it was started there (the foreign server is told
// first, both switch, both go back when the tunnel does not reconnect). The
// Iran server knows the caller by its secret: the Peer Link secret is the
// main tunnel, a peer's own token that peer's tunnel.

var errOldIranPanel = errors.New("the Iran server did not take the request: it runs an older panel, or its Peer Link secret differs from this server's. Update it, or do this from the Iran server")

// peerCallJSON sends one request to the Iran server over the Peer Link and
// stops at the first JSON answer, whatever its status, so a request that
// starts something is never sent twice. Status 404 with no data: no address
// knew the route (an older panel). A var so tests never reach a real panel.
var peerCallJSON = peerCallJSONReal

func peerCallJSONReal(method, path string, payload any, timeout time.Duration) (int, []byte, error) {
	c := loadPeerConfig()
	if c.PeerSecret == "" {
		return 0, nil, errNoPeerLink
	}
	var body []byte
	if payload != nil {
		var err error
		if body, err = json.Marshal(payload); err != nil {
			return 0, nil, err
		}
	}
	tr := &http.Transport{TLSClientConfig: peerTLSConfig(&c)}
	defer tr.CloseIdleConnections()
	client := &http.Client{Timeout: timeout, Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	var lastErr error
	notFound := false
	dead := map[string]bool{}
	for _, target := range peerTargetURLs(c, path) {
		host := target
		if i := strings.Index(host, "://"); i >= 0 {
			host = host[i+3:]
		}
		if i := strings.Index(host, "/"); i >= 0 {
			host = host[:i]
		}
		if dead[host] {
			continue
		}
		req, err := http.NewRequest(method, target, bytes.NewReader(body))
		if err != nil {
			return 0, nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Peer-Secret", c.PeerSecret)
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			dead[host] = true
			continue
		}
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		if json.Valid(data) {
			markPeerSeen()
			return resp.StatusCode, data, nil
		}
		if resp.StatusCode == http.StatusNotFound {
			notFound = true
		}
	}
	if notFound {
		return http.StatusNotFound, nil, nil
	}
	if lastErr == nil {
		lastErr = errNoPeerLink
	}
	return 0, nil, lastErr
}

// peerAnswerErr is the error an Iran panel answered with.
func peerAnswerErr(data []byte) error {
	var v struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(data, &v) == nil && v.Error != "" {
		return errors.New(v.Error)
	}
	return fmt.Errorf("the Iran server answered: %s", truncateForError(data))
}

// foreignSwapView is the swap dialog on a foreign server: the Iran server's
// view of this tunnel, minus what this server lacks.
func foreignSwapView(id int, probe bool) map[string]any {
	path := "/api/peer/swap-request"
	if probe {
		path += "?probe=1"
	}
	fail := func(err error) map[string]any {
		return map[string]any{"id": id, "foreign_side": true, "error": err.Error()}
	}
	status, data, err := peerCallJSON("GET", path, nil, 12*time.Second)
	switch {
	case err != nil:
		return fail(fmt.Errorf("the Iran server's panel cannot be reached from here (%v): swap the carrier from the Iran server", err))
	case status == http.StatusNotFound && data == nil:
		return fail(errOldIranPanel)
	case status != http.StatusOK:
		return fail(peerAnswerErr(data))
	}
	var v map[string]any
	if json.Unmarshal(data, &v) != nil {
		return fail(errors.New("the Iran server's answer could not be read"))
	}
	if e, _ := v["error"].(string); e != "" {
		return fail(errors.New(e))
	}
	v["id"] = id
	v["via_iran"] = true
	// Both servers run the new engine: frps there, frpc here.
	if bins, ok := v["bins"].(map[string]any); ok {
		here := map[string]string{"frps": "frpc", "backhaul": "backhaul"}
		for k, b := range bins {
			bins[k] = b == true && engineBinaryPresent(here[k])
		}
	}
	if cur, _ := v["current"].(string); strings.HasPrefix(cur, "frp:") && !hasPro(proBackhaul) {
		v["backhaul_pro"] = false
	}
	return v
}

// relaySwapToIran asks the Iran server to swap this tunnel's carrier.
func relaySwapToIran(w http.ResponseWriter, r *http.Request, to carrierChoice) {
	if backhaulLocked(to.Engine) && proRequired(w, r, proBackhaul, "Backhaul") {
		return
	}
	bin := "frpc"
	if to.Engine != "frp" {
		bin = "backhaul"
	}
	if !engineBinaryPresent(bin) {
		writeAPIError(w, r, "E-ENGINE-01", bin+" is not installed on this server (install it with `hashem` first); nothing was changed")
		return
	}
	status, data, err := peerCallJSON("POST", "/api/peer/swap-request", map[string]string{"carrier": to.ID()}, 20*time.Second)
	switch {
	case err != nil:
		writeAPIError(w, r, "E-ACTION-01", "the Iran server's panel cannot be reached from here ("+err.Error()+"): swap the carrier from the Iran server")
		return
	case status == http.StatusNotFound && data == nil:
		writeAPIError(w, r, "E-ACTION-01", errOldIranPanel.Error())
		return
	case status != http.StatusOK:
		writeAPIError(w, r, "E-ACTION-01", peerAnswerErr(data).Error())
		return
	}
	LogSecurityAudit("carrier_swap_requested", "admin", ClientIP(r), "to="+to.ID())
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(data)
}

// swapCallerTunnel is the tunnel whose foreign server sent r: a peer's token
// names that peer, the Peer Link secret the main tunnel.
func swapCallerTunnel(r *http.Request) int {
	id, _ := r.Context().Value(tunnelCtxKey{}).(int)
	return id
}

// GET /api/peer/swap-request[?probe=1] (Iran side)
func handlePeerSwapRequestGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, swapView(swapCallerTunnel(r), r.URL.Query().Get("probe") == "1"))
}

// POST /api/peer/swap-request {"carrier": "backhaul:wssmux"} (Iran side)
func handlePeerSwapRequest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Carrier string `json:"carrier"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&req); err != nil {
		writeAPIError(w, r, "E-ACTION-01", "invalid json")
		return
	}
	to, err := parseCarrierChoice(req.Carrier)
	if err != nil {
		writeAPIError(w, r, "E-ACTION-01", err.Error())
		return
	}
	t, err := resolveSwapTunnel(swapCallerTunnel(r))
	if err != nil {
		writeAPIError(w, r, "E-ACTION-01", err.Error())
		return
	}
	log.Printf("[PeerSync] the foreign server of tunnel %d asks for a carrier swap to %s", t.ID, to.ID())
	startSwapOn(w, r, t, to, false)
}
