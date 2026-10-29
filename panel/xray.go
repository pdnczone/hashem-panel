package main

// Xray tunnel: the links this server keeps (xray.json), the bundle the Iran
// server hands the foreign server, bringing a link up step by step, its
// health, and /api/xray. Configs come from xray_config.go, ports and
// neighbouring Xray panels from xray_coexist.go.
//
// Pro feature ("xray"): reading is free, every action is gated. The license
// checks themselves are never touched here.

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// xrayMu guards xray.json, the link configs and their units.
var xrayMu sync.Mutex

// xrayState is every Xray link on this server. Link IDs are never reused, so
// an old unit name never points at a new link.
type xrayState struct {
	Links  []XrayLink `json:"links"`
	NextID int        `json:"next_id"`
	// PublicIP is this server's address as the bundles carry it.
	PublicIP string `json:"public_ip,omitempty"`
}

func xrayStatePath() string { return filepath.Join(configDir, "xray.json") }
func xrayConfDir() string   { return filepath.Join(configDir, "xray") }
func xrayLinkConfPath(id int) string {
	return filepath.Join(xrayConfDir(), fmt.Sprintf("link-%d.json", id))
}
func xrayUnitName(id int) string { return fmt.Sprintf("hashem-xray-%d", id) }
func xrayUnitPath(id int) string { return filepath.Join(engineUnitDir, xrayUnitName(id)+".service") }
func xrayTag(id int) string      { return fmt.Sprintf("xray-%d", id) }

func loadXrayState() xrayState {
	var s xrayState
	if data, err := os.ReadFile(xrayStatePath()); err == nil {
		_ = json.Unmarshal(data, &s)
	}
	for _, l := range s.Links {
		if l.ID >= s.NextID {
			s.NextID = l.ID + 1
		}
	}
	if s.NextID < 1 {
		s.NextID = 1
	}
	return s
}

func saveXrayState(s xrayState) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(xrayStatePath(), data, 0o600)
}

// writeFileAtomic writes through a temp file and a rename, so a crash never
// leaves half a config.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (s *xrayState) index(id int) int {
	for i, l := range s.Links {
		if l.ID == id {
			return i
		}
	}
	return -1
}

func (s *xrayState) add(l XrayLink) XrayLink {
	l.ID = s.NextID
	s.NextID++
	s.Links = append(s.Links, l)
	return l
}

// ---- the bundle: one string the Iran server hands the foreign server ----

const xrayBundlePrefix = "xr1_"

type xrayBundle struct {
	V    int      `json:"v"`
	Link XrayLink `json:"link"` // as the foreign server keeps it
}

// makeXrayBundle turns an Iran link into what the foreign server imports: its
// side, Iran's address, and only the keys that end needs. Expert JSON stays
// on each end: it is written against that end's config, and so is the name.
func makeXrayBundle(l XrayLink, iranIP string) (string, error) {
	f := l
	f.ID, f.Name, f.Side, f.Remote, f.ProbePort, f.Listen, f.Disabled, f.Expert = 0, "", xraySideForeign, CleanHost(iranIP), 0, "", false, nil
	if !f.serverEnd() {
		f.Keys.PrivateKey, f.Keys.TLSKey = "", "" // reverse: the foreign server only dials
	}
	if f.Mode == xrayModeReverse && f.Remote == "" {
		return "", fmt.Errorf("this server's public IP is unknown, so the foreign server could not reach it: set it first")
	}
	if err := f.validate(); err != nil {
		return "", err
	}
	raw, err := json.Marshal(xrayBundle{V: 1, Link: f})
	if err != nil {
		return "", err
	}
	return xrayBundlePrefix + base64.RawURLEncoding.EncodeToString(raw), nil
}

// parseXrayBundle reads a pasted bundle; every field is validated before it
// can reach a config file.
func parseXrayBundle(s string) (XrayLink, error) {
	s = strings.Join(strings.Fields(s), "")
	enc, ok := strings.CutPrefix(s, xrayBundlePrefix)
	if !ok {
		return XrayLink{}, fmt.Errorf("not an Xray tunnel bundle (want a string starting with %s)", xrayBundlePrefix)
	}
	if len(enc) > 32<<10 {
		return XrayLink{}, fmt.Errorf("the bundle is too long")
	}
	raw, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		return XrayLink{}, fmt.Errorf("the bundle is damaged (copy all of it)")
	}
	var b xrayBundle
	if err := json.Unmarshal(raw, &b); err != nil || b.V != 1 {
		return XrayLink{}, fmt.Errorf("the bundle is not valid (made by a newer panel?)")
	}
	l := b.Link
	if l.Side != xraySideForeign {
		return XrayLink{}, fmt.Errorf("this bundle is for the foreign server")
	}
	l.ID, l.ProbePort, l.Expert, l.Disabled = 0, 0, nil, false
	if err := l.validate(); err != nil {
		return XrayLink{}, err
	}
	return l, nil
}

// importXrayLink adds a bundle's link, or replaces the one with the same
// UUID (a new bundle for a link that exists keeps its local ID and unit).
func importXrayLink(s *xrayState, b XrayLink) (XrayLink, bool) {
	for i, l := range s.Links {
		if l.Keys.UUID == b.Keys.UUID {
			b.ID, b.Expert, b.Name = l.ID, l.Expert, xrayOr(b.Name, l.Name)
			s.Links[i] = b
			return b, true
		}
	}
	return s.add(b), false
}

// ---- bringing a link up ----

// xrayStep is one stage of bringing a link up, for the stepper in the UI.
type xrayStep struct {
	Key    string `json:"key"` // core | ports | config | service | link
	OK     bool   `json:"ok"`
	Wait   bool   `json:"wait,omitempty"` // not a failure: the other server's turn
	Detail string `json:"detail,omitempty"`
}

// xrayApplyError carries the API error code of the step that failed.
type xrayApplyError struct {
	Code string
	Msg  string
}

func (e *xrayApplyError) Error() string { return e.Msg }

var (
	// xrayVerifyDelay is how long a link must stay up after its start: a bad
	// config makes Xray exit a moment after systemd says "started".
	xrayVerifyDelay = 2 * time.Second
	// xrayLinkWait is how long the bring-up waits to see the link work.
	xrayLinkWait = 8 * time.Second
)

// xrayUnit is the link's service. The log rate limit keeps journald from
// filling when the other end refuses connections: Xray's pre-connect redials
// at once after a failure and logs a warning each time.
func xrayUnit(l XrayLink) string {
	return fmt.Sprintf(`[Unit]
Description=Hashem Xray tunnel, link %d (%s, %s end)
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Environment=XRAY_LOCATION_ASSET=%s
# Go listens with MPTCP by default, and Linux refuses TCP_USER_TIMEOUT on an
# MPTCP socket: Xray then skips the rest of the inbound sockopt, and the Iran
# end keeps a dead reverse connection for minutes.
Environment=GODEBUG=multipathtcp=0
ExecStart=%s run -c %s
Restart=always
RestartSec=3s
LimitNOFILE=1048576
LogRateLimitIntervalSec=30s
LogRateLimitBurst=200

[Install]
WantedBy=multi-user.target
`, l.ID, l.Mode, l.Side, xrayDir, xrayBinPath, xrayLinkConfPath(l.ID))
}

// xrayClaimedPorts are the ports another tunnel's config takes on this
// server even while it is down: Bagher's on the Iran server.
func xrayClaimedPorts(l XrayLink) map[string]string {
	m := map[string]string{}
	if l.Side != xraySideIran {
		return m
	}
	sshFwdMu.Lock()
	cfg := loadSSHFwdConfigLocked()
	sshFwdMu.Unlock()
	if !cfg.Enabled || cfg.Role == "foreign" || cfg.Role == "server" {
		return m
	}
	for _, p := range l.Ports {
		if owner := bagherPortOwner(cfg, p, 0); owner != 0 {
			m["tcp:"+strconv.Itoa(p)] = fmt.Sprintf("Bagher (foreign server %d)", owner)
			if cfg.UDP {
				m["udp:"+strconv.Itoa(p)] = fmt.Sprintf("Bagher (foreign server %d)", owner)
			}
		}
	}
	return m
}

// xrayPortsError explains taken ports, with a free tunnel port to use.
func xrayPortsError(l XrayLink, cs []xrayConflict, ls []xrayListener) string {
	msgs := make([]string, len(cs))
	tunnelTaken := false
	for i, c := range cs {
		msgs[i] = c.String()
		tunnelTaken = tunnelTaken || c.Port == l.TunnelPort
	}
	msg := strings.Join(msgs, "; ")
	if tunnelTaken {
		proto := "tcp"
		if l.Profile.Transport == "kcp" {
			proto = "udp"
		}
		if p := xraySuggestPort(proto, ls, l.Ports); p > 0 {
			msg += fmt.Sprintf(". Use tunnel port %d instead", p)
		}
	}
	return msg
}

// xrayTestConfig asks Xray itself whether it accepts a config.
func xrayTestConfig(path string) error {
	out, err := runCmdTimeout(30*time.Second, xrayBinPath, "run", "-test", "-c", path)
	if err != nil || !strings.Contains(string(out), "Configuration OK") {
		msg := strings.TrimSpace(stripANSI(string(out)))
		if i := strings.LastIndex(msg, "Failed to start"); i >= 0 {
			msg = msg[i:]
		}
		if len(msg) > 600 {
			msg = msg[len(msg)-600:]
		}
		if msg == "" && err != nil {
			msg = err.Error()
		}
		return fmt.Errorf("%s", msg)
	}
	return nil
}

// applyXrayLink writes link l's config and unit and (re)starts it. The steps
// say how far it got; the error names the step that failed.
func applyXrayLink(l XrayLink, others []XrayLink) ([]xrayStep, error) {
	var steps []xrayStep
	fail := func(key, code, msg string) ([]xrayStep, error) {
		steps = append(steps, xrayStep{Key: key, Detail: msg})
		return steps, &xrayApplyError{code, msg}
	}
	if !fileExists(xrayBinPath) {
		return fail("core", "E-XRAY-02", "Xray-core is not installed on this server yet")
	}
	steps = append(steps, xrayStep{Key: "core", OK: true, Detail: xrayVersion()})

	ls := xrayListeners()
	if cs := xrayPortConflicts(l, others, ls, xrayClaimedPorts(l)); len(cs) > 0 {
		return fail("ports", "E-XRAY-03", xrayPortsError(l, cs, ls))
	}
	steps = append(steps, xrayStep{Key: "ports", OK: true})

	cfg, err := buildXrayConfig(l)
	if err != nil {
		return fail("config", "E-XRAY-01", err.Error())
	}
	raw, _ := json.MarshalIndent(cfg, "", "  ")
	path := xrayLinkConfPath(l.ID)
	// Xray picks the config format from the extension: "link-1.json.new" fails
	// with "Failed to get format", so the test copy keeps .json.
	tmp := strings.TrimSuffix(path, ".json") + ".new.json"
	if err := writeFileAtomic(tmp, raw, 0o600); err != nil {
		return fail("config", "E-XRAY-04", err.Error())
	}
	if err := xrayTestConfig(tmp); err != nil {
		_ = os.Remove(tmp)
		return fail("config", "E-XRAY-04", err.Error())
	}
	if err := os.Rename(tmp, path); err != nil {
		return fail("config", "E-XRAY-04", err.Error())
	}
	steps = append(steps, xrayStep{Key: "config", OK: true})

	unit := xrayUnitName(l.ID)
	if err := writeUnitFile(xrayUnitPath(l.ID), xrayUnit(l)); err != nil {
		return fail("service", "E-XRAY-05", err.Error())
	}
	tcp, udp := l.listens()
	var open []int // the probe port listens on 127.0.0.1 only: nothing to open
	for _, p := range append(tcp, udp...) {
		if p != l.ProbePort {
			open = append(open, p)
		}
	}
	allowUFWPorts(open)
	_ = runSystemctl("daemon-reload")
	_ = runSystemctl("enable", unit)
	if err := runSystemctl("restart", unit); err != nil {
		return fail("service", "E-XRAY-05", "systemctl restart "+unit+": "+err.Error()+xrayJournalTail(unit))
	}
	time.Sleep(xrayVerifyDelay)
	if !engineServiceActive(unit) {
		return fail("service", "E-XRAY-05", unit+" stopped right after it started"+xrayJournalTail(unit))
	}
	steps = append(steps, xrayStep{Key: "service", OK: true})

	// The link itself: Iran probes it; the foreign server can only wait in
	// direct mode, and sees its own link to Iran in reverse mode.
	h := xrayCheckHealth(l, xrayLinkWait)
	switch {
	case h.Link == "up":
		steps = append(steps, xrayStep{Key: "link", OK: true, Detail: xrayHealthText(h)})
	case l.Side == xraySideForeign && l.Mode == xrayModeDirect:
		steps = append(steps, xrayStep{Key: "link", Wait: true, Detail: "ready: the Iran server connects and checks the link"})
	default:
		steps = append(steps, xrayStep{Key: "link", Wait: true, Detail: xrayOr(h.Error, "waiting for the other server")})
	}
	return steps, nil
}

func xrayJournalTail(unit string) string {
	out, err := runCmdTimeoutOut(5*time.Second, "journalctl", "-u", unit, "-n", "8", "--no-pager", "-o", "cat")
	if err != nil || len(strings.TrimSpace(string(out))) == 0 {
		return ""
	}
	return ":\n" + strings.TrimSpace(stripANSI(string(out)))
}

// stopXrayLink stops a link's unit; removeFiles also deletes its unit and
// config.
func stopXrayLink(id int, removeFiles bool) {
	unit := xrayUnitName(id)
	_ = runSystemctl("disable", "--now", unit)
	if removeFiles {
		_ = os.Remove(xrayUnitPath(id))
		_ = os.Remove(xrayLinkConfPath(id))
		_ = runSystemctl("daemon-reload")
	}
	xrayHealthDrop(id)
}

// migrateXrayConfigs rewrites the config and unit of every running link that
// this version builds differently and restarts it, so a new default (such as
// pre-connect, or the server end's wait for it) reaches links made before the
// update. A config Xray does not accept is left as it was.
func migrateXrayConfigs() int {
	if !fileExists(xrayBinPath) {
		return 0
	}
	xrayMu.Lock()
	defer xrayMu.Unlock()
	n := 0
	for _, l := range loadXrayState().Links {
		path := xrayLinkConfPath(l.ID)
		if l.Disabled || !fileExists(path) {
			continue
		}
		cfg, err := buildXrayConfig(l)
		if err != nil {
			continue
		}
		raw, _ := json.MarshalIndent(cfg, "", "  ")
		oldCfg, _ := os.ReadFile(path)
		oldUnit, _ := os.ReadFile(xrayUnitPath(l.ID))
		if bytes.Equal(oldCfg, raw) && string(oldUnit) == xrayUnit(l) {
			continue
		}
		tmp := strings.TrimSuffix(path, ".json") + ".new.json"
		if writeFileAtomic(tmp, raw, 0o600) != nil {
			continue
		}
		if err := xrayTestConfig(tmp); err != nil {
			_ = os.Remove(tmp)
			log.Printf("xray: link %d keeps its old config: %v", l.ID, err)
			continue
		}
		if os.Rename(tmp, path) != nil || writeUnitFile(xrayUnitPath(l.ID), xrayUnit(l)) != nil {
			continue
		}
		_ = runSystemctl("daemon-reload")
		_ = runSystemctl("try-restart", xrayUnitName(l.ID))
		xrayHealthDrop(l.ID)
		n++
	}
	return n
}

// xrayFreeLoopbackPort is a TCP port free on 127.0.0.1 for the probe.
func xrayFreeLoopbackPort(avoid []int) int {
	for i := 0; i < 20; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return 0
		}
		p := ln.Addr().(*net.TCPAddr).Port
		ln.Close()
		if !xrayHasPort(avoid, p) {
			return p
		}
	}
	return 0
}

// ---- health ----

// xrayHealth is how a link is doing, as this end sees it.
type xrayHealth struct {
	Active  bool    `json:"active"`
	Link    string  `json:"link"` // up | down | listening | off
	PingMS  float64 `json:"ping_ms,omitempty"`
	ProbeMS float64 `json:"probe_ms,omitempty"` // a request through the link and back
	Conns   int     `json:"conns"`              // tunnel connections open now
	Error   string  `json:"error,omitempty"`
	At      int64   `json:"at"`
}

var xrayHealthCache = struct {
	sync.Mutex
	m    map[int]xrayHealth
	busy map[int]bool
}{m: map[int]xrayHealth{}, busy: map[int]bool{}}

func xrayHealthDrop(id int) {
	xrayHealthCache.Lock()
	delete(xrayHealthCache.m, id)
	xrayHealthCache.Unlock()
}

// xrayCachedHealth is the link's last check; a check older than 5 s is
// redone in the background, so a slow or broken link never holds up the page.
// The first call waits up to a second for the first check.
func xrayCachedHealth(l XrayLink) xrayHealth { return xrayHealthWait(l, time.Second) }

// xrayHealthWait is xrayCachedHealth waiting up to firstWait for a link never
// checked before (0: answer "checking" at once).
func xrayHealthWait(l XrayLink, firstWait time.Duration) xrayHealth {
	xrayHealthCache.Lock()
	h, ok := xrayHealthCache.m[l.ID]
	stale := !ok || time.Since(time.UnixMilli(h.At)) >= 5*time.Second
	var done chan struct{}
	if stale && !xrayHealthCache.busy[l.ID] {
		xrayHealthCache.busy[l.ID] = true
		done = make(chan struct{})
		go func() {
			nh := xrayCheckHealth(l, 0)
			xrayHealthCache.Lock()
			xrayHealthCache.m[l.ID], xrayHealthCache.busy[l.ID] = nh, false
			xrayHealthCache.Unlock()
			close(done)
		}()
	}
	xrayHealthCache.Unlock()
	if !ok {
		if done != nil {
			select {
			case <-done:
			case <-time.After(firstWait):
			}
		}
		xrayHealthCache.Lock()
		h, ok = xrayHealthCache.m[l.ID]
		xrayHealthCache.Unlock()
		if !ok {
			return xrayHealth{Link: "checking", At: time.Now().UnixMilli()}
		}
	}
	return h
}

// xrayProbe sends a request into the link's probe port; the other end's Xray
// answers it (HTTP 403 from its blackhole). It returns the round trip.
var xrayProbe = func(port int) (float64, error) {
	start := time.Now()
	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 2*time.Second)
	if err != nil {
		return 0, fmt.Errorf("the probe port is closed: is the link's Xray running?")
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(6 * time.Second))
	if _, err := io.WriteString(c, "GET / HTTP/1.1\r\nHost: "+xrayProbeHost+"\r\n\r\n"); err != nil {
		return 0, err
	}
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return 0, fmt.Errorf("no answer from the other end through the link")
	}
	if !strings.HasPrefix(line, "HTTP/1.1 403") {
		return 0, fmt.Errorf("unexpected answer through the link")
	}
	return float64(time.Since(start).Microseconds()) / 1000, nil
}

// xrayTCPPing is one TCP handshake to host:port: the network's round trip.
var xrayTCPPing = func(host string, port int) (float64, error) {
	start := time.Now()
	c, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), 3*time.Second)
	if err != nil {
		return 0, err
	}
	c.Close()
	return float64(time.Since(start).Microseconds()) / 1000, nil
}

// xrayConns counts the tunnel's open TCP connections: to the other server's
// tunnel port on the dialing end, on our tunnel port on the listening end.
var xrayConns = func(l XrayLink) int {
	filter := fmt.Sprintf("( sport = :%d )", l.TunnelPort)
	if !l.serverEnd() {
		// only to the other server: other programs dial port 443 too
		filter = fmt.Sprintf("( dport = :%d )", l.TunnelPort)
		if ip := carrierIP(xrayDialAddress(l)); ip != "" {
			filter = fmt.Sprintf("( dport = :%d and dst %s )", l.TunnelPort, urlHost(ip))
		}
	}
	out, err := runCmdTimeoutOut(3*time.Second, "ss", "-Htn", "state", "established", filter)
	if err != nil {
		return 0
	}
	n := 0
	for _, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(line) != "" {
			n++
		}
	}
	return n
}

// xrayCheckHealth checks a link now; wait > 0 retries the probe that long
// (a link just started may need a moment).
func xrayCheckHealth(l XrayLink, wait time.Duration) xrayHealth {
	h := xrayHealth{At: time.Now().UnixMilli()}
	if l.Disabled {
		h.Link = "off"
		return h
	}
	h.Active = engineServiceActive(xrayUnitName(l.ID))
	if !h.Active {
		h.Link, h.Error = "down", "the link's Xray is not running"
		return h
	}
	if l.Profile.Transport != "kcp" {
		h.Conns = xrayConns(l)
	}
	deadline := time.Now().Add(wait)
	switch {
	case l.Side == xraySideIran && l.ProbePort > 0:
		for {
			ms, err := xrayProbe(l.ProbePort)
			if err == nil {
				h.Link, h.ProbeMS, h.Error = "up", ms, ""
				break
			}
			h.Link, h.Error = "down", err.Error()
			if l.Mode == xrayModeReverse {
				h.Error = "the foreign server has not connected yet: import the bundle there"
			}
			if time.Now().After(deadline) {
				break
			}
			time.Sleep(time.Second)
		}
		if l.Mode == xrayModeDirect && l.Profile.Transport != "kcp" {
			if ms, err := xrayTCPPing(xrayDialAddress(l), l.TunnelPort); err == nil {
				h.PingMS = ms
			}
		} else if h.Link == "up" {
			h.PingMS = h.ProbeMS // reverse: one round trip down the open link
		}
	case l.Side == xraySideForeign && l.Mode == xrayModeReverse && l.Profile.Transport == "kcp":
		// mKCP is UDP: no connection to count or connect to; Iran's probe
		// checks the link
		h.Link = "listening"
	case l.Side == xraySideForeign && l.Mode == xrayModeReverse:
		for {
			if h.Conns = xrayConns(l); h.Conns > 0 {
				break
			}
			if time.Now().After(deadline) {
				break
			}
			time.Sleep(time.Second)
		}
		if ms, err := xrayTCPPing(xrayDialAddress(l), l.TunnelPort); err == nil {
			h.PingMS = ms
			if h.Conns > 0 {
				h.Link = "up"
			}
		}
		if h.Link == "" {
			h.Link, h.Error = "down", "cannot reach the Iran server's tunnel port"
		}
	default:
		h.Link = "listening" // the foreign end in direct mode: Iran checks the link
	}
	return h
}

func xrayHealthText(h xrayHealth) string {
	if h.PingMS > 0 {
		return fmt.Sprintf("ping %.0f ms", h.PingMS)
	}
	if h.ProbeMS > 0 {
		return fmt.Sprintf("answered in %.0f ms", h.ProbeMS)
	}
	return ""
}

// ---- traffic ----

// xrayCarrierEnds are the links' tunnel connections, counted per link as
// "xray-N" by the panel's own counters (carrier_traffic.go).
func xrayCarrierEnds() []carrierEnd {
	var ends []carrierEnd
	for _, l := range loadXrayState().Links {
		if l.Disabled {
			continue
		}
		udp := l.Profile.Transport == "kcp"
		ip := carrierIP(xrayDialAddress(l))
		if l.serverEnd() {
			// listening: count only the other server, when its address is known
			from := ""
			if l.Remote != "" && !l.Profile.CDN { // through a CDN they come from its addresses
				from = carrierIP(l.Remote)
			}
			ends = append(ends, carrierEnd{Port: l.TunnelPort, From: from, UDP: udp, Tag: xrayTag(l.ID)})
		} else if ip != "" {
			ends = append(ends, carrierEnd{Port: l.TunnelPort, Remote: ip, UDP: udp, Tag: xrayTag(l.ID)})
		}
	}
	return ends
}

// ---- core: version and install ----

var xrayVersionCache = struct {
	sync.Mutex
	mod time.Time
	v   string
}{}

// xrayVersion is the installed core's version line ("Xray 26.3.27 ...").
func xrayVersion() string {
	st, err := os.Stat(xrayBinPath)
	if err != nil {
		return ""
	}
	xrayVersionCache.Lock()
	defer xrayVersionCache.Unlock()
	if st.ModTime().Equal(xrayVersionCache.mod) && xrayVersionCache.v != "" {
		return xrayVersionCache.v
	}
	out, err := runCmdTimeoutOut(10*time.Second, xrayBinPath, "version")
	if err != nil {
		return ""
	}
	line, _, _ := strings.Cut(strings.TrimSpace(string(out)), "\n")
	if f := strings.Fields(line); len(f) >= 2 {
		line = f[0] + " " + f[1]
	}
	xrayVersionCache.mod, xrayVersionCache.v = st.ModTime(), line
	return line
}

var xrayInstall = struct {
	sync.Mutex
	Running bool
	Done    bool
	OK      bool
	Log     string
}{}

// xrayInstallCmd installs the pinned core through hashem.sh; swappable for tests.
var xrayInstallCmd = func() (string, error) { return runHashemCluster(15*time.Minute, "xray", "install") }

// startXrayInstall runs the install in the background; GET /api/xray shows it.
func startXrayInstall() bool {
	xrayInstall.Lock()
	defer xrayInstall.Unlock()
	if xrayInstall.Running {
		return false
	}
	xrayInstall.Running, xrayInstall.Done, xrayInstall.OK, xrayInstall.Log = true, false, false, ""
	go func() {
		out, err := xrayInstallCmd()
		xrayInstall.Lock()
		defer xrayInstall.Unlock()
		if len(out) > 4000 {
			out = out[len(out)-4000:]
		}
		xrayInstall.Running, xrayInstall.Done, xrayInstall.Log = false, true, out
		xrayInstall.OK = err == nil && fileExists(xrayBinPath)
		if err != nil && out == "" {
			xrayInstall.Log = err.Error()
		}
	}()
	return true
}

func xrayInstallView() map[string]any {
	xrayInstall.Lock()
	defer xrayInstall.Unlock()
	return map[string]any{"running": xrayInstall.Running, "done": xrayInstall.Done, "ok": xrayInstall.OK, "log": xrayInstall.Log}
}

// ---- SNI tester ----

// xraySNIResult says whether a site can lend Reality its handshake: TLS 1.3
// with h2, reached from this server.
type xraySNIResult struct {
	SNI   string  `json:"sni"`
	OK    bool    `json:"ok"`
	TLS13 bool    `json:"tls13"`
	H2    bool    `json:"h2"`
	MS    float64 `json:"ms,omitempty"`
	Error string  `json:"error,omitempty"`
}

var xraySNIDial = func(sni string) xraySNIResult {
	r := xraySNIResult{SNI: sni}
	start := time.Now()
	c, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", net.JoinHostPort(sni, "443"),
		&tls.Config{ServerName: sni, NextProtos: []string{"h2", "http/1.1"}, MinVersion: tls.VersionTLS12})
	if err != nil {
		r.Error = err.Error()
		if len(r.Error) > 160 {
			r.Error = r.Error[:160]
		}
		return r
	}
	st := c.ConnectionState()
	c.Close()
	r.MS = float64(time.Since(start).Microseconds()) / 1000
	r.TLS13, r.H2 = st.Version == tls.VersionTLS13, st.NegotiatedProtocol == "h2"
	r.OK = r.TLS13 && r.H2
	if !r.OK {
		r.Error = "needs TLS 1.3 and h2"
	}
	return r
}

// xrayTestSNIs tests up to 10 sites at once, best (working, fastest) first.
func xrayTestSNIs(snis []string) []xraySNIResult {
	if len(snis) > 10 {
		snis = snis[:10]
	}
	out := make([]xraySNIResult, len(snis))
	var wg sync.WaitGroup
	for i, s := range snis {
		if !validBagherHost(s) || net.ParseIP(s) != nil {
			out[i] = xraySNIResult{SNI: s, Error: "not a domain name"}
			continue
		}
		wg.Add(1)
		go func(i int, s string) {
			defer wg.Done()
			out[i] = xraySNIDial(s)
		}(i, s)
	}
	wg.Wait()
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].OK != out[j].OK {
			return out[i].OK
		}
		return out[i].OK && out[i].MS < out[j].MS
	})
	return out
}

// ---- HTTP ----

// xrayLinkView is a link as GET /api/xray shows it: no private key.
func xrayLinkView(l XrayLink, snap *HubSnapshot, withHealth bool) map[string]any {
	v := l
	v.Keys.PrivateKey, v.Keys.TLSKey = "", ""
	raw, _ := json.Marshal(v)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	m["unit"] = xrayUnitName(l.ID)
	m["server_end"] = l.serverEnd()
	tcp, udp := l.listens()
	m["listens"] = map[string]any{"tcp": tcp, "udp": udp}
	if withHealth {
		m["health"] = xrayCachedHealth(l)
	}
	if snap != nil {
		if c, ok := snap.CarrierTags[xrayTag(l.ID)]; ok {
			m["rx"], m["tx"] = c[0], c[1]
		}
	}
	return m
}

// xrayDashLinks are the links as the dashboard map shows them. It never
// waits for a check: the map is drawn every few seconds anyway.
func xrayDashLinks(snap *HubSnapshot) []map[string]any {
	out := []map[string]any{}
	for _, l := range loadXrayState().Links {
		h := xrayHealthWait(l, 0)
		if l.Disabled {
			h = xrayHealth{Link: "off"}
		}
		m := map[string]any{
			"id": l.ID, "name": l.Name, "mode": l.Mode, "side": l.Side, "remote": l.Remote,
			"transport": l.Profile.Transport, "security": l.Profile.Security, "cdn": l.Profile.CDN,
			"link": h.Link, "ping_ms": h.PingMS,
		}
		if snap != nil {
			if c, ok := snap.CarrierTags[xrayTag(l.ID)]; ok {
				m["rx"], m["tx"] = c[0], c[1]
			}
		}
		out = append(out, m)
	}
	return out
}

func handleXrayGet(w http.ResponseWriter, r *http.Request) {
	xrayMu.Lock()
	st := loadXrayState()
	xrayMu.Unlock()
	snap := currentSnapshot()
	views := make([]map[string]any, len(st.Links))
	var wg sync.WaitGroup
	for i, l := range st.Links {
		wg.Add(1)
		go func(i int, l XrayLink) {
			defer wg.Done()
			views[i] = xrayLinkView(l, snap, true)
		}(i, l)
	}
	wg.Wait()
	presets := make([]string, 0, len(xrayPresets))
	for k := range xrayPresets {
		presets = append(presets, k)
	}
	sort.Strings(presets)
	writeJSON(w, map[string]any{
		"installed":   fileExists(xrayBinPath),
		"version":     xrayVersion(),
		"pro":         hasPro(proXray),
		"install":     xrayInstallView(),
		"panels":      detectXrayPanels(),
		"public_ip":   xrayOr(st.PublicIP, savedPublicIP()),
		"links":       views,
		"presets":     presets,
		"preset_defs": xrayPresets,
		"sni":         map[string]any{"direct": xraySNIDirect, "reverse": xraySNIReverse},
		"options": map[string]any{
			"transports": xrayTransports, "securities": xraySecurities, "fingerprints": xrayFingerprints,
			"xhttp_modes": xrayXHTTPModes, "congestions": xrayCongestions, "ports": xrayPortCandidates,
		},
		"counters_at": countersAtMs(snap),
	})
}

// xrayPostRequest carries one action and the fields it needs.
type xrayPostRequest struct {
	Action     string          `json:"action"`
	ID         int             `json:"id,omitempty"`
	Name       string          `json:"name,omitempty"`
	Mode       string          `json:"mode,omitempty"`
	Preset     string          `json:"preset,omitempty"`
	Remote     string          `json:"remote,omitempty"`
	TunnelPort int             `json:"tunnel_port,omitempty"`
	Ports      []int           `json:"ports,omitempty"`
	UDP        bool            `json:"udp,omitempty"`
	Listen     string          `json:"listen,omitempty"`
	PublicIP   string          `json:"public_ip,omitempty"`
	Profile    *XrayProfile    `json:"profile,omitempty"`
	Expert     json.RawMessage `json:"expert,omitempty"`
	Bundle     string          `json:"bundle,omitempty"`
	SNI        []string        `json:"sni,omitempty"`
}

// xrayDraft builds an Iran link from a create/update/check request.
func xrayDraft(req xrayPostRequest, base XrayLink) (XrayLink, error) {
	l := base
	l.Side = xraySideIran
	l.Mode = xrayOr(req.Mode, l.Mode)
	l.Name = strings.TrimSpace(req.Name)
	if len(l.Name) > 40 || strings.ContainsAny(l.Name, "<>\"'`\\\n") {
		return l, fmt.Errorf("name: up to 40 plain characters")
	}
	l.Remote = CleanHost(req.Remote)
	l.TunnelPort, l.Ports, l.UDP, l.Listen = req.TunnelPort, req.Ports, req.UDP, strings.TrimSpace(req.Listen)
	if req.Profile == nil && req.Preset == "" && l.Profile.Transport == "" {
		req.Preset = "reality"
	}
	switch {
	case req.Profile != nil:
		keepPreset := l.Profile.Preset
		l.Profile = *req.Profile
		l.Profile.Preset = xrayOr(l.Profile.Preset, keepPreset)
	case req.Preset != "":
		p, ok := xrayPresets[req.Preset]
		if !ok {
			return l, fmt.Errorf("unknown preset %q", req.Preset)
		}
		if p.Transport != l.Profile.Transport || p.Security != l.Profile.Security {
			l.Keys.PrivateKey, l.Keys.PublicKey, l.Profile.Path = "", "", ""
		}
		sni := l.Profile.SNI
		l.Profile = p
		if p.Security == "reality" {
			l.Profile.SNI = sni
		}
	}
	if l.Profile.Security != "reality" {
		l.Keys.PrivateKey, l.Keys.PublicKey, l.Keys.ShortID = "", "", ""
	}
	if req.Expert != nil {
		if s := strings.TrimSpace(string(req.Expert)); s == "" || s == "null" || s == "{}" || s == `""` {
			l.Expert = nil
		} else {
			l.Expert = req.Expert
		}
	}
	return newXrayLink(l)
}

func handleXrayPost(w http.ResponseWriter, r *http.Request) {
	var req xrayPostRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 128<<10)).Decode(&req); err != nil {
		writeAPIError(w, r, "E-XRAY-01", "invalid json")
		return
	}
	// Every Xray tunnel action beyond reading is Pro.
	if proRequired(w, r, proXray, "Xray Tunnel") {
		return
	}
	action := strings.ToLower(strings.TrimSpace(req.Action))
	switch action {
	case "install":
		if !startXrayInstall() {
			writeAPIError(w, r, "E-XRAY-07", "")
			return
		}
		writeJSON(w, map[string]any{"status": "ok", "install": xrayInstallView()})
		return
	case "snitest":
		writeJSON(w, map[string]any{"status": "ok", "results": xrayTestSNIs(req.SNI)})
		return
	}

	xrayMu.Lock()
	defer xrayMu.Unlock()
	st := loadXrayState()
	if ip := CleanHost(req.PublicIP); ip != "" {
		if net.ParseIP(ip) == nil {
			writeAPIError(w, r, "E-XRAY-01", "this server's public IP is not a valid IP")
			return
		}
		st.PublicIP = ip
	}
	iranIP := xrayOr(st.PublicIP, savedPublicIP())
	others := func(id int) []XrayLink {
		var o []XrayLink
		for _, l := range st.Links {
			if l.ID != id && !l.Disabled {
				o = append(o, l)
			}
		}
		return o
	}
	find := func() (int, bool) {
		i := st.index(req.ID)
		if i < 0 {
			writeAPIError(w, r, "E-XRAY-06", "")
		}
		return i, i >= 0
	}
	// taken refuses a link whose ports something else holds, before it is saved.
	taken := func(l XrayLink) bool {
		ls := xrayListeners()
		if cs := xrayPortConflicts(l, others(l.ID), ls, xrayClaimedPorts(l)); len(cs) > 0 {
			writeAPIError(w, r, "E-XRAY-03", xrayPortsError(l, cs, ls))
			return true
		}
		return false
	}
	// up applies link i and answers with its steps (and the bundle on Iran).
	up := func(i int, extra map[string]any) {
		if xrayMoveProbe(&st.Links[i], st, xrayListeners()) {
			_ = saveXrayState(st)
		}
		l := st.Links[i]
		steps, err := applyXrayLink(l, others(l.ID))
		resp := map[string]any{"status": "ok", "steps": steps}
		if err != nil {
			resp["status"], resp["error"] = "error", err.Error()
			if ae, ok := err.(*xrayApplyError); ok {
				resp["error_code"] = ae.Code
			}
		}
		xrayHealthDrop(l.ID)
		resp["link"] = xrayLinkView(l, currentSnapshot(), false)
		for k, v := range extra {
			resp[k] = v
		}
		writeJSON(w, resp)
	}

	switch action {
	case "check":
		// The wizard's live check: taken ports and a free tunnel port.
		l, err := xrayDraft(req, XrayLink{ID: req.ID})
		if err != nil {
			writeAPIError(w, r, "E-XRAY-01", err.Error())
			return
		}
		ls := xrayListeners()
		cs := xrayPortConflicts(l, others(req.ID), ls, xrayClaimedPorts(l))
		resp := map[string]any{"status": "ok", "conflicts": cs, "valid": ""}
		if err := l.validate(); err != nil {
			resp["valid"] = err.Error()
		}
		if p := xraySuggestPort("tcp", ls, l.Ports); p > 0 {
			resp["suggest_tunnel_port"] = p
		}
		writeJSON(w, resp)

	case "create":
		l, err := xrayDraft(req, XrayLink{})
		if err == nil {
			l.ProbePort = xrayFreeLoopbackPort(append(append([]int{l.TunnelPort}, l.Ports...), xrayUsedProbePorts(st)...))
			err = l.validate()
		}
		if err != nil {
			writeAPIError(w, r, "E-XRAY-01", err.Error())
			return
		}
		if taken(l) {
			return
		}
		bundle, err := makeXrayBundle(l, iranIP)
		if err != nil {
			writeAPIError(w, r, "E-XRAY-01", err.Error())
			return
		}
		l = st.add(l)
		if err := saveXrayState(st); err != nil {
			writeAPIError(w, r, "E-XRAY-01", err.Error())
			return
		}
		up(len(st.Links)-1, map[string]any{"bundle": bundle})

	case "update":
		i, ok := find()
		if !ok {
			return
		}
		old := st.Links[i]
		if old.Side != xraySideIran {
			writeAPIError(w, r, "E-XRAY-01", "this link is set up on the Iran server: change it there and import its new bundle here")
			return
		}
		l, err := xrayDraft(req, old)
		if err == nil {
			xrayMoveProbe(&l, st, xrayListeners())
			err = l.validate()
		}
		if err != nil {
			writeAPIError(w, r, "E-XRAY-01", err.Error())
			return
		}
		if taken(l) {
			return
		}
		before, _ := makeXrayBundle(old, iranIP)
		bundle, err := makeXrayBundle(l, iranIP)
		if err != nil {
			writeAPIError(w, r, "E-XRAY-01", err.Error())
			return
		}
		l.Disabled = false
		st.Links[i] = l
		if err := saveXrayState(st); err != nil {
			writeAPIError(w, r, "E-XRAY-01", err.Error())
			return
		}
		up(i, map[string]any{"bundle": bundle, "bundle_changed": bundle != before})

	case "bundle":
		i, ok := find()
		if !ok {
			return
		}
		if st.Links[i].Side != xraySideIran {
			writeAPIError(w, r, "E-XRAY-01", "the bundle is made on the Iran server")
			return
		}
		bundle, err := makeXrayBundle(st.Links[i], iranIP)
		if err != nil {
			writeAPIError(w, r, "E-XRAY-01", err.Error())
			return
		}
		_ = saveXrayState(st) // keeps a public IP the request set
		writeJSON(w, map[string]any{"status": "ok", "bundle": bundle})

	case "import":
		b, err := parseXrayBundle(req.Bundle)
		if err != nil {
			writeAPIError(w, r, "E-XRAY-01", err.Error())
			return
		}
		b.Name = strings.TrimSpace(req.Name)
		if i := xrayIndexByUUID(st, b.Keys.UUID); i >= 0 {
			b.ID = st.Links[i].ID // its own ports are not a conflict
		}
		if taken(b) {
			return
		}
		l, updated := importXrayLink(&st, b)
		if err := saveXrayState(st); err != nil {
			writeAPIError(w, r, "E-XRAY-01", err.Error())
			return
		}
		up(st.index(l.ID), map[string]any{"updated": updated})

	case "apply", "start":
		i, ok := find()
		if !ok {
			return
		}
		st.Links[i].Disabled = false
		_ = saveXrayState(st)
		up(i, nil)

	case "stop":
		i, ok := find()
		if !ok {
			return
		}
		stopXrayLink(st.Links[i].ID, false)
		st.Links[i].Disabled = true
		_ = saveXrayState(st)
		writeJSON(w, map[string]any{"status": "ok"})

	case "remove":
		i, ok := find()
		if !ok {
			return
		}
		stopXrayLink(st.Links[i].ID, true)
		st.Links = append(st.Links[:i], st.Links[i+1:]...)
		_ = saveXrayState(st)
		writeJSON(w, map[string]any{"status": "ok"})

	default:
		writeAPIError(w, r, "E-ACTION-01", "unknown action: want check, create, update, bundle, import, apply, stop, remove, install or snitest")
	}
}

func xrayUsedProbePorts(st xrayState) []int {
	var out []int
	for _, l := range st.Links {
		if l.ProbePort > 0 {
			out = append(out, l.ProbePort)
		}
	}
	return out
}

func xrayIndexByUUID(st xrayState, id string) int {
	for i, l := range st.Links {
		if l.Keys.UUID == id {
			return i
		}
	}
	return -1
}

// xrayMoveProbe gives link l a new probe port when another program took its
// own (the user never picks it, so it must never block the link). It reports
// whether the port changed.
func xrayMoveProbe(l *XrayLink, st xrayState, ls []xrayListener) bool {
	if l.Side != xraySideIran || l.ProbePort == 0 {
		return false
	}
	for _, x := range ls {
		if x.Proto == "tcp" && x.Port == l.ProbePort && !xrayOwnPath(x.Exe) {
			avoid := append(append([]int{l.TunnelPort}, l.Ports...), xrayUsedProbePorts(st)...)
			for _, y := range ls {
				avoid = append(avoid, y.Port)
			}
			if p := xrayFreeLoopbackPort(avoid); p > 0 {
				l.ProbePort = p
				return true
			}
			return false
		}
	}
	return false
}
