package main

// Path test: which transports get through between an Iran server and a foreign
// server, before any tunnel exists.
//
// The Iran side ("hub", where tunnels listen) starts throwaway servers: a plain
// TCP/UDP control port, one frps for FRP tcp/websocket/kcp/quic (+ the same TLS
// front the wss transport uses in production), one Backhaul server per
// transport, and a GRE interface. The foreign side pastes the hub's code and
// dials every one of them with the real cores (frpc, backhaul), exactly the way
// a tunnel would. Each client forwards a loopback port on the hub to an echo
// service on the foreign server, so the hub pushes data through every transport
// and reports what really came back. Bagher's SSH path (Iran -> foreign) is
// checked by reading the foreign server's SSH banner.
//
// Nothing is installed or changed for good: the processes run under `timeout`,
// the GRE interface and firewall openings are removed when the test ends.
//
// Port layout from the first port B (all on the Iran server):
//
//	B        plain TCP (HTTP control) and plain UDP
//	B+1      frps: tcp, websocket (TCP) and kcp (UDP)
//	B+2      frps quic (UDP)
//	B+3      TLS front for FRP wss
//	B+4..10  Backhaul tcp, tcpmux, ws, wss, wsmux, wssmux, udp
//	B+19     echo service (loopback, on the foreign server)
//	B+20..31 loopback ports carrying each transport's data (hub)

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	ptCodePrefix = "HPT1-"
	ptOffFRP     = 1
	ptOffQUIC    = 2
	ptOffWSS     = 3
	ptOffBH      = 4
	ptOffEcho    = 19
	ptOffFwd     = 20
	ptSpan       = 31
	ptDefBase    = 41000
	ptGREIf      = "hpt0"
	ptGREKey     = "18512"
	ptGREHub     = "10.254.77.1"
	ptGRESpoke   = "10.254.77.2"
	ptSpeedBytes = 1 << 20
)

var (
	ptFRPTransports = []string{"tcp", "websocket", "wss", "kcp", "quic"}
	ptBHTransports  = []string{"tcp", "tcpmux", "ws", "wss", "wsmux", "wssmux", "udp"}
	// ptGrace: how long after the foreign server shows up a transport may stay
	// silent before it counts as blocked (clients retry every few seconds).
	ptGrace = 60 * time.Second
)

type ptCheck struct {
	ID     string  `json:"id"`
	Engine string  `json:"engine"`
	Name   string  `json:"name"`
	Port   int     `json:"port,omitempty"`
	Proto  string  `json:"proto"`
	Status string  `json:"status"` // waiting | ok | fail | skip
	RTTMs  float64 `json:"rtt_ms,omitempty"`
	Mbps   float64 `json:"mbps,omitempty"`
	Note   string  `json:"note,omitempty"`
	Fwd    int     `json:"-"` // hub: loopback port carrying this transport's data
	speed  bool    // hub: throughput still to measure
}

// ptChecks lists every check of a session whose first port is base.
func ptChecks(base, sshPort int) []*ptCheck {
	cs := []*ptCheck{
		{ID: "tcp", Engine: "Network", Name: "TCP", Port: base, Proto: "tcp"},
		{ID: "udp", Engine: "Network", Name: "UDP", Port: base, Proto: "udp"},
		{ID: "gre", Engine: "GRE", Name: "GRE", Proto: "gre"},
		{ID: "ssh", Engine: "Bagher", Name: "SSH", Port: sshPort, Proto: "tcp"},
	}
	for i, t := range ptFRPTransports {
		p, proto := ptFRPPort(base, t)
		cs = append(cs, &ptCheck{ID: "frp-" + t, Engine: "FRP", Name: t, Port: p, Proto: proto, Fwd: base + ptOffFwd + i})
	}
	for i, t := range ptBHTransports {
		proto := "tcp"
		if t == "udp" {
			proto = "udp"
		}
		cs = append(cs, &ptCheck{ID: "bh-" + t, Engine: "Backhaul", Name: t, Port: base + ptOffBH + i, Proto: proto,
			Fwd: base + ptOffFwd + len(ptFRPTransports) + i})
	}
	for _, c := range cs {
		c.Status = "waiting"
	}
	return cs
}

// ptDataProto is what crosses a check's data port: TCP, except over Backhaul's
// udp transport (FRP kcp/quic carry TCP even though they dial over UDP).
func ptDataProto(c ptCheck) string {
	if c.ID == "bh-udp" {
		return "udp"
	}
	return "tcp"
}

// ptFRPPort is the hub port an frpc of transport t dials (as in production:
// quic on control+1 is shifted here to B+2, wss goes through the TLS front).
func ptFRPPort(base int, t string) (int, string) {
	switch t {
	case "kcp":
		return base + ptOffFRP, "udp"
	case "quic":
		return base + ptOffQUIC, "udp"
	case "wss":
		return base + ptOffWSS, "tcp"
	}
	return base + ptOffFRP, "tcp"
}

type ptCode struct {
	Host    string `json:"h"`
	Base    int    `json:"p"`
	Token   string `json:"t"`
	Minutes int    `json:"m"`
}

func ptEncodeCode(c ptCode) string {
	b, _ := json.Marshal(c)
	return ptCodePrefix + base64.RawURLEncoding.EncodeToString(b)
}

func ptDecodeCode(s string) (ptCode, error) {
	var c ptCode
	s = strings.Join(strings.Fields(s), "")
	if !strings.HasPrefix(s, ptCodePrefix) {
		return c, fmt.Errorf("not a path test code (it starts with %s)", ptCodePrefix)
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(s, ptCodePrefix))
	if err != nil || json.Unmarshal(b, &c) != nil {
		return c, fmt.Errorf("the code is damaged; copy it again from the Iran server")
	}
	if net.ParseIP(c.Host) == nil || c.Base < 1024 || c.Base > 65535-ptSpan || len(c.Token) < 16 {
		return c, fmt.Errorf("the code is damaged; copy it again from the Iran server")
	}
	if c.Minutes < 1 || c.Minutes > 60 {
		c.Minutes = 10
	}
	return c, nil
}

type ptSession struct {
	mu        sync.Mutex
	role      string // "iran" | "foreign"
	code      string
	iranIP    string
	foreignIP string
	base      int
	sshPort   int
	token     string
	phase     string // starting | running | done
	expires   time.Time
	joined    time.Time // hub: first sign of the foreign server
	checks    []*ptCheck
	remote    *ptResults // foreign: the hub's results, when its control port answers
	notes     []string
	greTried  bool
	greUp     bool
	ctx       context.Context
	cancel    context.CancelFunc
	dir       string
	ufw       []string
	procs     sync.WaitGroup
	done      chan struct{}
}

// ptResults is what the hub serves to the foreign server (no code, no token).
type ptResults struct {
	Joined    bool      `json:"joined"`
	Settled   bool      `json:"settled"`
	ExpiresIn int       `json:"expires_in"`
	Checks    []ptCheck `json:"checks"`
}

type ptView struct {
	Active    bool       `json:"active"`
	Role      string     `json:"role,omitempty"`
	Phase     string     `json:"phase,omitempty"`
	Code      string     `json:"code,omitempty"`
	IranIP    string     `json:"iran_ip,omitempty"`
	ForeignIP string     `json:"foreign_ip,omitempty"`
	Base      int        `json:"base_port,omitempty"`
	ExpiresIn int        `json:"expires_in,omitempty"`
	Joined    bool       `json:"joined"`
	Settled   bool       `json:"settled"`
	Checks    []ptCheck  `json:"checks,omitempty"`
	Remote    *ptResults `json:"remote,omitempty"`
	Notes     []string   `json:"notes,omitempty"`
	RoleHint  string     `json:"role_hint,omitempty"`
	IPHint    string     `json:"ip_hint,omitempty"`
}

var (
	ptMu  sync.Mutex
	ptCur *ptSession
)

func (s *ptSession) note(format string, a ...any) {
	s.mu.Lock()
	s.notes = append(s.notes, fmt.Sprintf(format, a...))
	s.mu.Unlock()
}

func (s *ptSession) check(id string) *ptCheck {
	for _, c := range s.checks {
		if c.ID == id {
			return c
		}
	}
	return nil
}

// set updates one check under the lock.
func (s *ptSession) set(id, status string, rtt float64, note string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c := s.check(id); c != nil {
		c.Status, c.Note = status, note
		if rtt > 0 {
			c.RTTMs = rttRound(rtt)
		}
	}
}

func rttRound(ms float64) float64 { return float64(int(ms*10+0.5)) / 10 }

func (s *ptSession) settledLocked() bool {
	for _, c := range s.checks {
		if c.Status == "waiting" || c.speed {
			return false
		}
	}
	return true
}

func (s *ptSession) copyChecksLocked() []ptCheck {
	out := make([]ptCheck, len(s.checks))
	for i, c := range s.checks {
		out[i] = *c
	}
	return out
}

func (s *ptSession) results() ptResults {
	s.mu.Lock()
	defer s.mu.Unlock()
	return ptResults{Joined: !s.joined.IsZero(), Settled: s.settledLocked(), ExpiresIn: s.expiresIn(), Checks: s.copyChecksLocked()}
}

func (s *ptSession) expiresIn() int {
	if s.phase == "done" {
		return 0
	}
	if d := int(time.Until(s.expires).Seconds()); d > 0 {
		return d
	}
	return 0
}

func (s *ptSession) view() ptView {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := ptView{Active: s.phase != "done", Role: s.role, Phase: s.phase, IranIP: s.iranIP, ForeignIP: s.foreignIP,
		Base: s.base, ExpiresIn: s.expiresIn(), Joined: !s.joined.IsZero(), Settled: s.settledLocked(),
		Checks: s.copyChecksLocked(), Notes: append([]string(nil), s.notes...)}
	if s.role == "iran" {
		v.Code = s.code
	}
	if s.remote != nil {
		r := *s.remote
		v.Remote = &r
		v.Joined = true
	}
	return v
}

// sawForeign records the first sign of the foreign server (hub side).
func (s *ptSession) sawForeign(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.joined.IsZero() {
		s.joined = time.Now()
	}
	if s.foreignIP == "" && net.ParseIP(ip) != nil && !net.ParseIP(ip).IsLoopback() {
		s.foreignIP = ip
	}
}

func ptRandToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *ptSession) tokenOK(t string) bool {
	return subtle.ConstantTimeCompare([]byte(t), []byte(s.token)) == 1
}

// ---------- cores and processes ----------

func ptCore(name string) string {
	for _, d := range []string{os.Getenv("HASHEM_CORE_DIR"), "/usr/local/bin"} {
		if d == "" {
			continue
		}
		p := filepath.Join(d, name)
		if st, err := os.Stat(p); err == nil && !st.IsDir() && st.Mode()&0111 != 0 {
			return p
		}
	}
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	return ""
}

// ptEnsureCores returns the paths of the cores this side needs, downloading
// them once with `hashem download-cores` when one is missing.
func (s *ptSession) ptEnsureCores(names ...string) map[string]string {
	find := func() (map[string]string, bool) {
		m, all := map[string]string{}, true
		for _, n := range names {
			if m[n] = ptCore(n); m[n] == "" {
				all = false
			}
		}
		return m, all
	}
	m, all := find()
	if all {
		return m
	}
	if script, err := greScriptPath(); err == nil {
		s.mu.Lock()
		s.phase = "cores"
		s.mu.Unlock()
		ctx, cancel := context.WithTimeout(s.ctx, 5*time.Minute)
		cmd := exec.CommandContext(ctx, "bash", script, "download-cores")
		cmd.Env = append(os.Environ(), "GRE_SKIP_PANEL=1", "TERM=dumb", "GRE_PANEL_DIR="+configDir)
		_ = cmd.Run()
		cancel()
		s.mu.Lock()
		if s.phase == "cores" {
			s.phase = "starting"
		}
		s.mu.Unlock()
		m, _ = find()
	}
	for _, n := range names {
		if m[n] == "" {
			s.note("%s is not installed and could not be downloaded; its checks are skipped (run: hashem download-cores)", n)
		}
	}
	return m
}

// ptStart runs bin -c conf until the session ends. `timeout` stops it even if
// the panel itself dies; SIGTERM reaches it through timeout on a normal stop.
func (s *ptSession) ptStart(name, bin, conf string) {
	secs := int(time.Until(s.expires).Seconds()) + 5
	logf, err := os.Create(filepath.Join(s.dir, name+".log"))
	if err != nil {
		return
	}
	cmd := exec.CommandContext(s.ctx, "timeout", strconv.Itoa(secs), bin, "-c", conf)
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = 5 * time.Second
	if err := cmd.Start(); err != nil {
		logf.Close()
		s.note("%s did not start: %v", name, err)
		return
	}
	s.procs.Add(1)
	go func() {
		defer s.procs.Done()
		_ = cmd.Wait()
		logf.Close()
	}()
}

func ptWrite(path, body string) error { return os.WriteFile(path, []byte(body), 0600) }

func ptFrpsConf(base int, token string) string {
	return fmt.Sprintf(`bindAddr = "0.0.0.0"
bindPort = %d
kcpBindPort = %d
quicBindPort = %d
proxyBindAddr = "127.0.0.1"
auth.method = "token"
auth.token = "%s"
`, base+ptOffFRP, base+ptOffFRP, base+ptOffQUIC, token)
}

func ptFrpcConf(host string, base int, t, token string) string {
	port, _ := ptFRPPort(base, t)
	fwd := 0
	for i, x := range ptFRPTransports {
		if x == t {
			fwd = base + ptOffFwd + i
		}
	}
	return fmt.Sprintf(`serverAddr = "%s"
serverPort = %d
loginFailExit = false
auth.method = "token"
auth.token = "%s"
transport.protocol = "%s"
transport.heartbeatInterval = 10
transport.heartbeatTimeout = 30

[[proxies]]
name = "hpt-%s"
type = "tcp"
localIP = "127.0.0.1"
localPort = %d
remotePort = %d
`, host, port, token, t, t, base+ptOffEcho, fwd)
}

// Backhaul v0.7 flat schema, the same keys hashem.sh writes.
func ptBHServerConf(base, i int, token, dir string) string {
	t := ptBHTransports[i]
	var b strings.Builder
	fmt.Fprintf(&b, "[server]\nbind_addr = \"0.0.0.0:%d\"\ntransport = \"%s\"\ntoken = \"%s\"\n", base+ptOffBH+i, t, token)
	b.WriteString("keepalive_period = 75\nnodelay = true\nheartbeat = 40\nchannel_size = 2048\nsniffer = false\nweb_port = 0\nlog_level = \"info\"\n")
	if t == "wss" || t == "wssmux" {
		fmt.Fprintf(&b, "tls_cert = \"%s\"\ntls_key = \"%s\"\n", filepath.Join(dir, "bh.crt"), filepath.Join(dir, "bh.key"))
	}
	fmt.Fprintf(&b, "ports = [\"127.0.0.1:%d=%d\"]\n", base+ptOffFwd+len(ptFRPTransports)+i, base+ptOffEcho)
	return b.String()
}

func ptBHClientConf(host string, base, i int, token string) string {
	return fmt.Sprintf("[client]\nremote_addr = \"%s\"\ntransport = \"%s\"\ntoken = \"%s\"\n"+
		"connection_pool = 4\nnodelay = true\nretry_interval = 3\nkeepalive_period = 75\nsniffer = false\nweb_port = 0\nlog_level = \"info\"\n",
		net.JoinHostPort(host, strconv.Itoa(base+ptOffBH+i)), ptBHTransports[i], token)
}

func ptBackhaulV2(bin string) bool {
	out, _ := runCmdTimeout(5*time.Second, bin, "-v")
	v := strings.TrimSpace(string(out))
	return strings.HasPrefix(v, "v2.") || strings.HasPrefix(v, "2.")
}

func ptWriteCert(dir string) error {
	cert, err := generateSelfSignedCert("")
	if err != nil {
		return err
	}
	key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		return err
	}
	if err := ptWrite(filepath.Join(dir, "bh.crt"), string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}))); err != nil {
		return err
	}
	return ptWrite(filepath.Join(dir, "bh.key"), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})))
}

// ptPortsFree checks the TCP and UDP ports this side will bind.
func ptPortsFree(host string, ports ...int) error {
	for _, p := range ports {
		addr := net.JoinHostPort(host, strconv.Itoa(p))
		l, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("port %d is in use on this server; pick another first port", p)
		}
		l.Close()
		u, err := net.ListenPacket("udp", addr)
		if err != nil {
			return fmt.Errorf("UDP port %d is in use on this server; pick another first port", p)
		}
		u.Close()
	}
	return nil
}

// ptUfwOpen opens the public test ports when ufw is active, as setup does.
func (s *ptSession) ptUfwOpen() {
	out, err := runCmdTimeout(5*time.Second, "ufw", "status")
	if err != nil || !strings.Contains(string(out), "Status: active") {
		return
	}
	rng := fmt.Sprintf("%d:%d", s.base, s.base+ptOffBH+len(ptBHTransports)-1)
	for _, r := range []string{rng + "/tcp", rng + "/udp"} {
		// "Skipping adding existing rule": it was there before, so it stays after.
		if out, err := runCmdTimeout(10*time.Second, "ufw", "allow", r); err == nil && !strings.Contains(string(out), "Skipping") {
			s.ufw = append(s.ufw, r)
		}
	}
}

func ptGREUp(remote, inner string) error {
	_, _ = runCmdTimeout(5*time.Second, "ip", "link", "del", ptGREIf)
	steps := [][]string{
		{"ip", "tunnel", "add", ptGREIf, "mode", "gre", "remote", remote, "key", ptGREKey, "ttl", "255"},
		{"ip", "addr", "add", inner + "/30", "dev", ptGREIf},
		{"ip", "link", "set", ptGREIf, "up", "mtu", "1400"},
	}
	for _, a := range steps {
		if out, err := runCmdTimeout(5*time.Second, a[0], a[1:]...); err != nil {
			_, _ = runCmdTimeout(5*time.Second, "ip", "link", "del", ptGREIf)
			return fmt.Errorf("%s: %s", strings.Join(a, " "), strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// ptCleanup runs once when the session ends (stop or expiry).
func (s *ptSession) ptCleanup() {
	s.procs.Wait()
	s.mu.Lock()
	greUp, rules, dir := s.greUp || s.greTried, s.ufw, s.dir
	s.phase = "done"
	s.mu.Unlock()
	if greUp {
		_, _ = runCmdTimeout(5*time.Second, "ip", "link", "del", ptGREIf)
	}
	for _, r := range rules {
		_, _ = runCmdTimeout(10*time.Second, "ufw", "delete", "allow", r)
	}
	if dir != "" {
		_ = os.RemoveAll(dir)
	}
	close(s.done)
}

// ---------- data probes ----------

// ptProbe pushes data through addr and checks it comes back byte-exact.
// It returns the average round trip of three small echoes.
func ptProbe(proto, addr string, timeout time.Duration) (float64, error) {
	c, err := net.DialTimeout(proto, addr, timeout)
	if err != nil {
		return 0, err
	}
	defer c.Close()
	msg, got := make([]byte, 64), make([]byte, 64)
	var total time.Duration
	ok := 0
	for i := 0; i < 4; i++ {
		_, _ = rand.Read(msg)
		_ = c.SetDeadline(time.Now().Add(timeout))
		start := time.Now()
		if _, err := c.Write(msg); err != nil {
			return 0, err
		}
		var n int
		if proto == "udp" {
			n, err = c.Read(got)
		} else {
			n, err = io.ReadFull(c, got)
		}
		if err != nil {
			if proto == "udp" && i < 3 {
				continue // a lost datagram is retried, the tunnel may still work
			}
			if ok > 0 {
				break
			}
			return 0, err
		}
		if !bytes.Equal(got[:n], msg) {
			return 0, fmt.Errorf("data came back changed")
		}
		if i > 0 || proto == "udp" {
			total += time.Since(start)
			ok++
		}
	}
	if ok == 0 {
		return 0, fmt.Errorf("no answer")
	}
	return float64(total.Microseconds()) / 1000 / float64(ok), nil
}

// ptSpeed echoes n bytes through a TCP addr and returns Mbit/s.
func ptSpeed(addr string, n int, timeout time.Duration) (float64, error) {
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return 0, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))
	msg := make([]byte, n)
	_, _ = rand.Read(msg)
	start := time.Now()
	werr := make(chan error, 1)
	go func() { _, err := c.Write(msg); werr <- err }()
	got := make([]byte, n)
	if _, err := io.ReadFull(c, got); err != nil {
		return 0, err
	}
	if err := <-werr; err != nil {
		return 0, err
	}
	if !bytes.Equal(got, msg) {
		return 0, fmt.Errorf("data came back changed")
	}
	return ptMbps(n, time.Since(start)), nil
}

// ptMbps turns n bytes moved in d into Mbit/s, rounded to 0.1. Windows'
// clock is coarse enough that a fast loopback run can read 0: dividing by
// that gave +Inf, and int(+Inf) wrapped to a huge negative speed. A floor
// of 1ms keeps the result finite and positive (a lower bound in that case).
func ptMbps(n int, d time.Duration) float64 {
	if d < time.Millisecond {
		d = time.Millisecond
	}
	return math.Round(float64(n)*8/d.Seconds()/1e6*10) / 10
}

// ptSSH reads the SSH banner of host:port (Bagher dials it from Iran).
func ptSSH(host string, port int) (float64, error) {
	start := time.Now()
	c, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), 5*time.Second)
	if err != nil {
		return 0, err
	}
	defer c.Close()
	rtt := float64(time.Since(start).Microseconds()) / 1000
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	b := make([]byte, 64)
	n, _ := io.ReadAtLeast(c, b, 4)
	if !strings.HasPrefix(string(b[:n]), "SSH-") {
		return 0, fmt.Errorf("port answers but it is not SSH")
	}
	return rtt, nil
}

func ptPing(ctx context.Context, ip string) (float64, bool) {
	avg, _, _, loss, _, err := probePing(ctx, ip, 3)
	return avg, err == nil && loss < 100
}

func ptErrText(err error) string {
	s := err.Error()
	switch {
	case strings.Contains(s, "refused"):
		return "connection refused"
	case strings.Contains(s, "timeout"), strings.Contains(s, "i/o timeout"):
		return "no answer"
	case strings.Contains(s, "reset"):
		return "connection reset"
	case strings.Contains(s, "EOF"):
		return "closed with no data"
	}
	return s
}

// ---------- Iran side (hub) ----------

type ptHubRequest struct {
	ForeignIP string `json:"foreign_ip"`
	IranIP    string `json:"iran_ip"`
	BasePort  int    `json:"base_port"`
	SSHPort   int    `json:"ssh_port"`
	Minutes   int    `json:"minutes"`
}

func ptNewSession(role string, base, minutes int) *ptSession {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Duration(minutes)*time.Minute))
	return &ptSession{role: role, base: base, phase: "starting", expires: time.Now().Add(time.Duration(minutes) * time.Minute),
		ctx: ctx, cancel: cancel, done: make(chan struct{})}
}

// ptHubPortsFree checks every port a hub on first port b binds.
func ptHubPortsFree(b int) error {
	ports := []int{}
	for p := b; p <= b+ptOffBH+len(ptBHTransports)-1; p++ {
		ports = append(ports, p)
	}
	if err := ptPortsFree("", ports...); err != nil {
		return err
	}
	fwd := []int{}
	for p := b + ptOffFwd; p <= b+ptSpan; p++ {
		fwd = append(fwd, p)
	}
	return ptPortsFree("127.0.0.1", fwd...)
}

// ptPickBase returns the first port block to use. A port the admin chose must
// be free; with none chosen the first free block from 41000 is taken, so a test
// next to a running tunnel never touches the tunnel's ports.
func ptPickBase(want int) (int, error) {
	if want != 0 {
		if err := ptHubPortsFree(want); err != nil {
			return 0, fmt.Errorf("%v (a running tunnel or another service uses it); leave the first port empty to pick free ports automatically", err)
		}
		return want, nil
	}
	for b := ptDefBase; b <= 65535-ptSpan; b += ptSpan + 9 {
		if ptHubPortsFree(b) == nil {
			return b, nil
		}
	}
	return 0, fmt.Errorf("no free block of %d ports found from %d", ptSpan+1, ptDefBase)
}

func ptStartHub(req ptHubRequest) (*ptSession, error) {
	if req.BasePort != 0 && (req.BasePort < 1024 || req.BasePort > 65535-ptSpan) {
		return nil, fmt.Errorf("first port must be 1024-%d", 65535-ptSpan)
	}
	if req.SSHPort == 0 {
		req.SSHPort = 22
	}
	if req.SSHPort < 1 || req.SSHPort > 65535 {
		return nil, fmt.Errorf("SSH port must be 1-65535")
	}
	if req.Minutes <= 0 {
		req.Minutes = 10
	}
	if req.Minutes > 60 {
		return nil, fmt.Errorf("a test runs at most 60 minutes")
	}
	foreign := strings.TrimSpace(req.ForeignIP)
	if foreign != "" {
		if net.ParseIP(foreign) == nil {
			ips, err := net.LookupIP(foreign)
			if err != nil || len(ips) == 0 {
				return nil, fmt.Errorf("foreign server address %q does not resolve", foreign)
			}
			foreign = ips[0].String()
		}
	}
	iranIP := strings.TrimSpace(req.IranIP)
	if iranIP == "" {
		iranIP = detectPublicIP()
	}
	if net.ParseIP(iranIP) == nil {
		return nil, fmt.Errorf("enter this server's public IP (it could not be detected)")
	}
	ptStop()
	b, err := ptPickBase(req.BasePort)
	if err != nil {
		return nil, err
	}

	s := ptNewSession("iran", b, req.Minutes)
	s.iranIP, s.foreignIP, s.sshPort, s.token = iranIP, foreign, req.SSHPort, ptRandToken()
	s.code = ptEncodeCode(ptCode{Host: iranIP, Base: b, Token: s.token, Minutes: req.Minutes})
	s.checks = ptChecks(b, req.SSHPort)
	if b != ptDefBase && req.BasePort == 0 {
		s.notes = append(s.notes, fmt.Sprintf("ports from %d are in use on this server, so the test uses %d-%d", ptDefBase, b, b+ptOffBH+len(ptBHTransports)-1))
	}
	dir, err := os.MkdirTemp("", "hashem-pathtest-")
	if err != nil {
		s.cancel()
		return nil, err
	}
	s.dir = dir

	ctl, err := net.Listen("tcp", net.JoinHostPort("", strconv.Itoa(b)))
	if err != nil {
		s.cancel()
		os.RemoveAll(dir)
		return nil, fmt.Errorf("port %d: %v", b, err)
	}
	udp, err := net.ListenPacket("udp", net.JoinHostPort("", strconv.Itoa(b)))
	if err != nil {
		ctl.Close()
		s.cancel()
		os.RemoveAll(dir)
		return nil, fmt.Errorf("UDP port %d: %v", b, err)
	}
	ptMu.Lock()
	ptCur = s
	ptMu.Unlock()

	srv := &http.Server{Handler: s.hubMux(), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ctl) }()
	go s.hubUDP(udp)
	go func() {
		<-s.ctx.Done()
		_ = srv.Close()
		_ = udp.Close()
	}()
	go s.hubRun()
	return s, nil
}

func (s *ptSession) hubMux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/hpt/hello", func(w http.ResponseWriter, r *http.Request) {
		if !s.tokenOK(r.URL.Query().Get("t")) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		s.sawForeign(host)
		rtt, _ := strconv.ParseFloat(r.URL.Query().Get("rtt"), 64)
		s.set("tcp", "ok", rtt, "")
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/hpt/results", func(w http.ResponseWriter, r *http.Request) {
		if !s.tokenOK(r.URL.Query().Get("t")) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(s.results())
	})
	return mux
}

// hubUDP answers "HPT <token> [rtt]" datagrams from the foreign server.
func (s *ptSession) hubUDP(pc net.PacketConn) {
	buf := make([]byte, 512)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		f := strings.Fields(string(buf[:n]))
		if len(f) < 2 || f[0] != "HPT" || !s.tokenOK(f[1]) {
			continue
		}
		_, _ = pc.WriteTo([]byte("HPT ok"), from)
		if ua, ok := from.(*net.UDPAddr); ok {
			s.sawForeign(ua.IP.String())
		}
		rtt := 0.0
		if len(f) > 2 {
			rtt, _ = strconv.ParseFloat(f[2], 64)
		}
		s.set("udp", "ok", rtt, "")
	}
}

func (s *ptSession) hubRun() {
	defer s.ptCleanup()
	s.ptUfwOpen()
	// TLS front for FRP wss: the same terminator production runs (tls-proxy).
	if cert, err := generateSelfSignedCert(""); err == nil {
		if ln, err := tls.Listen("tcp", net.JoinHostPort("", strconv.Itoa(s.base+ptOffWSS)),
			&tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}); err == nil {
			go serveTLSProxy(ln, net.JoinHostPort("127.0.0.1", strconv.Itoa(s.base+ptOffFRP)))
			go func() { <-s.ctx.Done(); ln.Close() }()
		}
	}
	cores := s.ptEnsureCores("frps", "backhaul")
	if s.ctx.Err() != nil {
		return
	}
	if cores["frps"] != "" {
		conf := filepath.Join(s.dir, "frps.toml")
		if ptWrite(conf, ptFrpsConf(s.base, s.token)) == nil {
			s.ptStart("frps", cores["frps"], conf)
		}
	} else {
		s.skipEngine("FRP", "frps not installed")
	}
	if bh := cores["backhaul"]; bh != "" && !ptBackhaulV2(bh) {
		if err := ptWriteCert(s.dir); err != nil {
			s.note("TLS certificate for Backhaul wss: %v", err)
		}
		for i, t := range ptBHTransports {
			conf := filepath.Join(s.dir, "bh-"+t+".toml")
			if ptWrite(conf, ptBHServerConf(s.base, i, s.token, s.dir)) == nil {
				s.ptStart("bh-"+t, bh, conf)
			}
		}
	} else if bh != "" {
		s.skipEngine("Backhaul", "the installed Backhaul is v2; this test drives the v0.7 core")
	} else {
		s.skipEngine("Backhaul", "backhaul not installed")
	}
	s.mu.Lock()
	s.phase = "running"
	s.mu.Unlock()

	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		s.hubTick()
		select {
		case <-s.ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func (s *ptSession) skipEngine(engine, why string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.checks {
		if c.Engine == engine {
			c.Status, c.Note = "skip", why
		}
	}
}

func (s *ptSession) hubTick() {
	s.mu.Lock()
	var probe []ptCheck
	for _, c := range s.checks {
		if c.Fwd > 0 && c.Status != "ok" && c.Status != "skip" {
			probe = append(probe, *c)
		}
	}
	foreign, greTried, greUp := s.foreignIP, s.greTried, s.greUp
	ssh := s.check("ssh")
	sshDone := ssh.Status == "ok"
	sshPort := s.sshPort
	s.mu.Unlock()

	var wg sync.WaitGroup
	for _, c := range probe {
		wg.Add(1)
		go func(c ptCheck) {
			defer wg.Done()
			rtt, err := ptProbe(ptDataProto(c), net.JoinHostPort("127.0.0.1", strconv.Itoa(c.Fwd)), 3*time.Second)
			if err != nil {
				return
			}
			s.mu.Lock()
			if x := s.check(c.ID); x != nil {
				x.Status, x.RTTMs, x.Note, x.speed = "ok", rttRound(rtt), "", ptDataProto(c) == "tcp"
			}
			if s.joined.IsZero() {
				s.joined = time.Now()
			}
			s.mu.Unlock()
		}(c)
	}
	if foreign != "" {
		if !greTried {
			err := ptGREUp(foreign, ptGREHub)
			s.mu.Lock()
			s.greTried, s.greUp = true, err == nil
			if err != nil {
				if c := s.check("gre"); c != nil {
					c.Status, c.Note = "skip", "could not create a GRE interface here: "+err.Error()
				}
			}
			greUp = s.greUp
			s.mu.Unlock()
		}
		if greUp && s.statusOf("gre") != "ok" {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ctx, cancel := context.WithTimeout(s.ctx, 6*time.Second)
				defer cancel()
				if rtt, ok := ptPing(ctx, ptGRESpoke); ok {
					s.set("gre", "ok", rtt, "")
				}
			}()
		}
		if !sshDone {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if rtt, err := ptSSH(foreign, sshPort); err == nil {
					s.set("ssh", "ok", rtt, "")
				} else {
					s.set("ssh", "fail", 0, ptErrText(err))
				}
			}()
		}
	}
	wg.Wait()

	// Throughput, one transport at a time so they do not share the link.
	for {
		s.mu.Lock()
		var c *ptCheck
		for _, x := range s.checks {
			if x.speed {
				c = x
				break
			}
		}
		s.mu.Unlock()
		if c == nil || s.ctx.Err() != nil {
			break
		}
		mbps, err := ptSpeed(net.JoinHostPort("127.0.0.1", strconv.Itoa(c.Fwd)), ptSpeedBytes, 30*time.Second)
		s.mu.Lock()
		c.speed = false
		if err == nil {
			c.Mbps = mbps
		} else {
			c.Note = "connected, but 1 MiB did not cross: " + ptErrText(err)
		}
		s.mu.Unlock()
	}

	s.mu.Lock()
	if !s.joined.IsZero() && time.Since(s.joined) > ptGrace {
		for _, c := range s.checks {
			if c.Status == "waiting" {
				c.Status = "fail"
				if (c.ID == "gre" || c.ID == "ssh") && s.foreignIP == "" {
					c.Note = "foreign server IP unknown"
				} else if c.Note == "" {
					c.Note = "nothing came through"
				}
			}
		}
	}
	s.mu.Unlock()
}

func (s *ptSession) statusOf(id string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c := s.check(id); c != nil {
		return c.Status
	}
	return ""
}

// ---------- foreign side (spoke) ----------

func ptStartSpoke(code string) (*ptSession, error) {
	c, err := ptDecodeCode(code)
	if err != nil {
		return nil, err
	}
	ptStop()
	echo := c.Base + ptOffEcho
	if err := ptPortsFree("127.0.0.1", echo); err != nil {
		return nil, err
	}
	s := ptNewSession("foreign", c.Base, c.Minutes)
	s.iranIP, s.token = c.Host, c.Token
	s.checks = []*ptCheck{
		{ID: "tcp", Engine: "Network", Name: "TCP", Port: c.Base, Proto: "tcp", Status: "waiting"},
		{ID: "udp", Engine: "Network", Name: "UDP", Port: c.Base, Proto: "udp", Status: "waiting"},
		{ID: "gre", Engine: "GRE", Name: "GRE", Proto: "gre", Status: "waiting"},
	}
	dir, err := os.MkdirTemp("", "hashem-pathtest-")
	if err != nil {
		s.cancel()
		return nil, err
	}
	s.dir = dir
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(echo))
	tl, err := net.Listen("tcp", addr)
	if err != nil {
		s.cancel()
		os.RemoveAll(dir)
		return nil, err
	}
	ul, err := net.ListenPacket("udp", addr)
	if err != nil {
		tl.Close()
		s.cancel()
		os.RemoveAll(dir)
		return nil, err
	}
	go ptEchoTCP(tl)
	go ptEchoUDP(ul)
	go func() { <-s.ctx.Done(); tl.Close(); ul.Close() }()
	ptMu.Lock()
	ptCur = s
	ptMu.Unlock()
	go s.spokeRun()
	return s, nil
}

func ptEchoTCP(l net.Listener) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			_, _ = io.Copy(c, c)
		}()
	}
}

func ptEchoUDP(pc net.PacketConn) {
	buf := make([]byte, 65535)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		_, _ = pc.WriteTo(buf[:n], from)
	}
}

func (s *ptSession) spokeRun() {
	defer s.ptCleanup()
	if err := ptGREUp(s.iranIP, ptGRESpoke); err != nil {
		s.set("gre", "skip", 0, "could not create a GRE interface here: "+err.Error())
	} else {
		s.mu.Lock()
		s.greUp = true
		s.mu.Unlock()
	}
	cores := s.ptEnsureCores("frpc", "backhaul")
	if s.ctx.Err() != nil {
		return
	}
	if bin := cores["frpc"]; bin != "" {
		for _, t := range ptFRPTransports {
			conf := filepath.Join(s.dir, "frpc-"+t+".toml")
			if ptWrite(conf, ptFrpcConf(s.iranIP, s.base, t, s.token)) == nil {
				s.ptStart("frpc-"+t, bin, conf)
			}
		}
	}
	if bin := cores["backhaul"]; bin != "" && !ptBackhaulV2(bin) {
		for i, t := range ptBHTransports {
			conf := filepath.Join(s.dir, "bhc-"+t+".toml")
			if ptWrite(conf, ptBHClientConf(s.iranIP, s.base, i, s.token)) == nil {
				s.ptStart("bhc-"+t, bin, conf)
			}
		}
	}
	s.mu.Lock()
	s.phase = "running"
	s.mu.Unlock()

	hub := "http://" + net.JoinHostPort(s.iranIP, strconv.Itoa(s.base))
	cl := &http.Client{Timeout: 6 * time.Second, Transport: &http.Transport{DisableKeepAlives: true, Proxy: nil}}
	tick := time.NewTicker(3 * time.Second)
	defer tick.Stop()
	for {
		s.spokeTick(cl, hub)
		select {
		case <-s.ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func (s *ptSession) spokeTick(cl *http.Client, hub string) {
	var wg sync.WaitGroup
	wg.Add(3)
	go func() { // plain TCP: connect time, then tell the hub and read its results
		defer wg.Done()
		start := time.Now()
		c, err := net.DialTimeout("tcp", strings.TrimPrefix(hub, "http://"), 5*time.Second)
		if err != nil {
			s.set("tcp", "fail", 0, ptErrText(err))
			return
		}
		rtt := float64(time.Since(start).Microseconds()) / 1000
		c.Close()
		resp, err := cl.Get(hub + "/hpt/hello?t=" + s.token + "&rtt=" + strconv.FormatFloat(rtt, 'f', 1, 64))
		if err != nil {
			s.set("tcp", "fail", 0, "port open, no HTTP answer: "+ptErrText(err))
			return
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			s.set("tcp", "fail", 0, "another service answers on this port")
			return
		}
		s.set("tcp", "ok", rtt, "")
		resp, err = cl.Get(hub + "/hpt/results?t=" + s.token)
		if err != nil {
			return
		}
		defer resp.Body.Close()
		var r ptResults
		if json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&r) == nil && len(r.Checks) > 0 {
			s.mu.Lock()
			s.remote = &r
			s.mu.Unlock()
		}
	}()
	go func() { // plain UDP
		defer wg.Done()
		c, err := net.DialTimeout("udp", strings.TrimPrefix(hub, "http://"), 3*time.Second)
		if err != nil {
			return
		}
		defer c.Close()
		last := 0.0
		if x := s.statusOf("udp"); x == "ok" {
			s.mu.Lock()
			last = s.check("udp").RTTMs
			s.mu.Unlock()
		}
		for i := 0; i < 3; i++ {
			start := time.Now()
			_, _ = c.Write([]byte("HPT " + s.token + " " + strconv.FormatFloat(last, 'f', 1, 64)))
			_ = c.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
			b := make([]byte, 64)
			if n, err := c.Read(b); err == nil && strings.HasPrefix(string(b[:n]), "HPT ok") {
				s.set("udp", "ok", float64(time.Since(start).Microseconds())/1000, "")
				return
			}
		}
		if s.statusOf("udp") != "ok" {
			s.set("udp", "fail", 0, "no answer")
		}
	}()
	go func() { // GRE: ping the hub's inner address
		defer wg.Done()
		if s.statusOf("gre") == "skip" {
			return
		}
		ctx, cancel := context.WithTimeout(s.ctx, 6*time.Second)
		defer cancel()
		if rtt, ok := ptPing(ctx, ptGREHub); ok {
			s.set("gre", "ok", rtt, "")
		} else if s.statusOf("gre") != "ok" {
			s.set("gre", "fail", 0, "no reply over GRE yet (the Iran side creates its end when it sees this server)")
		}
	}()
	wg.Wait()
}

// ---------- control ----------

func ptStop() {
	ptMu.Lock()
	s := ptCur
	ptMu.Unlock()
	if s == nil {
		return
	}
	s.cancel()
	select {
	case <-s.done:
	case <-time.After(15 * time.Second):
	}
}

// GET /api/pathtest
func handlePathTestGet(w http.ResponseWriter, r *http.Request) {
	ptMu.Lock()
	s := ptCur
	ptMu.Unlock()
	var v ptView
	if s != nil {
		v = s.view()
	}
	if !v.Active {
		st := localStatus()
		v.RoleHint = st.Role
		if strings.HasPrefix(st.Role, "iran") {
			v.IPHint = st.GrePeer
			for _, p := range loadPeers() {
				if v.IPHint == "" && p.RemotePub != "" {
					v.IPHint = p.RemotePub
				}
			}
		}
	}
	writeJSON(w, v)
}

// POST /api/pathtest {action: start|join|stop, ...}
func handlePathTestPost(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Action string `json:"action"`
		Code   string `json:"code"`
		ptHubRequest
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		writeAPIError(w, r, "E-ACTION-02", "invalid json")
		return
	}
	if (req.Action == "start" || req.Action == "join") && proRequired(w, r, proPathTest, "The path test") {
		return
	}
	var s *ptSession
	var err error
	switch req.Action {
	case "start":
		s, err = ptStartHub(req.ptHubRequest)
	case "join":
		s, err = ptStartSpoke(req.Code)
	case "stop":
		ptStop()
		handlePathTestGet(w, r)
		return
	default:
		writeAPIError(w, r, "E-ACTION-01", "unknown path test action")
		return
	}
	if err != nil {
		writeAPIError(w, r, "E-PATHTEST-01", err.Error())
		return
	}
	LogSecurityAudit("pathtest_"+req.Action, "admin", clientIP(r), fmt.Sprintf("base=%d", s.base))
	writeJSON(w, s.view())
}

// ---------- CLI: gre-panel pathtest serve|join ----------

func cliPathTest(args []string) int {
	usage := func() int {
		fmt.Fprintln(os.Stderr, "usage: gre-panel pathtest serve [-port 41000] [-foreign IP] [-ip THIS_IP] [-ssh 22] [-minutes 10]")
		fmt.Fprintln(os.Stderr, "       gre-panel pathtest join CODE")
		return 2
	}
	if len(args) == 0 {
		return usage()
	}
	if v := os.Getenv("GRE_PANEL_DIR"); v != "" {
		configDir = v
	}
	loadOrInit()
	loadLicenseFromDisk()
	if !hasPro(proPathTest) {
		fmt.Fprintln(os.Stderr, "pathtest: the path test is a Hashem Pro feature; activate a license (hashem license activate KEY). Machine: "+getMachineHash())
		return 1
	}
	if d, err := time.ParseDuration(os.Getenv("HASHEM_PT_GRACE")); err == nil && d > 0 {
		ptGrace = d // labs: settle sooner on blocked transports
	}
	var s *ptSession
	var err error
	switch args[0] {
	case "serve":
		fs := flag.NewFlagSet("serve", flag.ContinueOnError)
		var req ptHubRequest
		fs.IntVar(&req.BasePort, "port", 0, "first port (default: first free block from 41000)")
		fs.StringVar(&req.ForeignIP, "foreign", "", "foreign server IP (GRE and SSH checks)")
		fs.StringVar(&req.IranIP, "ip", "", "this server's public IP")
		fs.IntVar(&req.SSHPort, "ssh", 22, "SSH port on the foreign server")
		fs.IntVar(&req.Minutes, "minutes", 10, "how long the test servers run")
		if fs.Parse(args[1:]) != nil {
			return 2
		}
		if s, err = ptStartHub(req); err == nil {
			fmt.Println("CODE " + s.code)
			fmt.Println("Paste the code on the foreign server: gre-panel pathtest join CODE")
		}
	case "join":
		if len(args) < 2 {
			return usage()
		}
		s, err = ptStartSpoke(args[1])
	default:
		return usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "pathtest:", err)
		return 1
	}
	// Run until every check has an answer (or the time is up, or Ctrl-C), then
	// clean up and print them. The Iran side keeps answering a few seconds more
	// so the foreign side can read the final results.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sig)
wait:
	for {
		select {
		case <-s.done:
			break wait
		case <-sig:
			break wait
		case <-time.After(2 * time.Second):
			v := s.view()
			if v.Settled && v.Joined && (s.role == "iran" || (v.Remote != nil && v.Remote.Settled)) {
				if s.role == "iran" {
					time.Sleep(7 * time.Second)
				}
				break wait
			}
		}
	}
	s.cancel()
	<-s.done
	v := s.view()
	out := v.Checks
	if v.Remote != nil {
		out = v.Remote.Checks
	}
	ptPrint(out)
	for _, n := range v.Notes {
		fmt.Println("NOTE " + n)
	}
	b, _ := json.Marshal(out)
	fmt.Println("JSON " + string(b))
	return 0
}

func ptPrint(cs []ptCheck) {
	sorted := append([]ptCheck(nil), cs...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Status == "ok" && sorted[j].Status != "ok" })
	for _, c := range sorted {
		line := fmt.Sprintf("%-8s %-10s %-5s %-7s", c.Engine, c.Name, c.Proto, c.Status)
		if c.RTTMs > 0 {
			line += fmt.Sprintf(" %6.1f ms", c.RTTMs)
		}
		if c.Mbps > 0 {
			line += fmt.Sprintf(" %7.1f Mbit/s", c.Mbps)
		}
		if c.Note != "" {
			line += "  " + c.Note
		}
		fmt.Println(line)
	}
}
