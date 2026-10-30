package main

// bagher-carrier: the SSH leg of a Bagher tunnel, in place of `ssh -N -R`.
//
//	gre-panel bagher-carrier [-link N] [-known-hosts FILE]
//
// The Iran server dials the Foreign server's sshd, asks it to listen on
// 127.0.0.1:FRP (the frpc there connects to it) and pipes every forwarded
// connection to the local frps. Two things OpenSSH's `ssh -N` cannot do:
//
//   - sshd up to OpenSSH 10.0 sets TCP_NODELAY on its socket only when a
//     session starts, and `ssh -N` opens none. Every small packet from the
//     Foreign server then waited for the ACK of the previous one (Nagle),
//     adding up to a round trip to each reply: the high ping of a Bagher
//     tunnel. The carrier runs one exec request (the key's forced
//     /bin/false), which makes sshd set TCP_NODELAY; the connection outlives it.
//   - The keepalive round trip is the tunnel's real ping (it queues behind
//     the tunnel's own data), written to a status file the panel shows.

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// bagherCarrierTarget is everything one carrier needs about its link.
type bagherCarrierTarget struct {
	ID       int
	Host     string
	Port     int
	User     string
	KeyPath  string
	FRPPort  int           // listen port on Foreign and frps port on Iran
	Local    string        // frps address to pipe to; empty: 127.0.0.1:FRPPort
	Alive    time.Duration // keepalive interval
	AliveMax int           // missed keepalives before reconnecting
	// Strict: only the host keys already in known_hosts (a sold link's,
	// from the customer's reply code); nothing is trusted on first use.
	Strict bool
}

func (t bagherCarrierTarget) addr() string {
	return net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
}

// bagherCarrierStatus is what the carrier reports to the panel.
type bagherCarrierStatus struct {
	Connected bool    `json:"connected"`
	RTTMs     float64 `json:"rtt_ms"`
	Since     int64   `json:"since,omitempty"` // unix time the session came up
	At        int64   `json:"at"`              // unix time of this report
	Error     string  `json:"error,omitempty"`
}

func bagherCarrierStatusPath(id int) string {
	return filepath.Join(configDir, fmt.Sprintf("bagher-carrier-%d.json", id))
}

func writeBagherCarrierStatus(id int, st bagherCarrierStatus) {
	if id <= 0 {
		return // a sold link's carrier (sell-bagher) reports nothing here
	}
	st.At = time.Now().Unix()
	b, _ := json.Marshal(st)
	p := bagherCarrierStatusPath(id)
	if err := os.WriteFile(p+".tmp", b, 0600); err == nil {
		_ = os.Rename(p+".tmp", p)
	}
}

// readBagherCarrierStatus returns the carrier's last report if it is fresh.
func readBagherCarrierStatus(id int, maxAge time.Duration) (bagherCarrierStatus, bool) {
	var st bagherCarrierStatus
	b, err := os.ReadFile(bagherCarrierStatusPath(id))
	if err != nil || json.Unmarshal(b, &st) != nil {
		return st, false
	}
	if time.Since(time.Unix(st.At, 0)) > maxAge {
		return st, false
	}
	return st, true
}

func bagherCarrierCmd(args []string) int {
	fs := flag.NewFlagSet("bagher-carrier", flag.ContinueOnError)
	link := fs.Int("link", 1, "Bagher link id (1 is the first foreign server)")
	known := fs.String("known-hosts", "", "known_hosts file (default ~/.ssh/known_hosts)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if v := os.Getenv("GRE_PANEL_DIR"); v != "" {
		configDir = v
	}
	cfg := loadSSHFwdConfigLocked() // read-only here; the panel owns the file
	t, ok := bagherCarrierTargetFor(cfg, *link)
	if !ok {
		log.Printf("bagher-carrier: no Bagher link %d in %s", *link, sshFwdConfigFile())
		return 2
	}
	if *known == "" {
		home, _ := os.UserHomeDir()
		*known = filepath.Join(home, ".ssh", "known_hosts")
	}
	log.Printf("bagher-carrier: link %d -> %s@%s, 127.0.0.1:%d on both sides", t.ID, t.User, t.addr(), t.FRPPort)
	runBagherCarrier(context.Background(), t, *known)
	return 0
}

// bagherCarrierTargetFor picks link id from the config: 1 is the main
// foreign server, higher ids are cfg.Links.
func bagherCarrierTargetFor(cfg SSHFwdConfig, id int) (bagherCarrierTarget, bool) {
	t := bagherCarrierTarget{ID: id, KeyPath: cfg.KeyPath, FRPPort: cfg.FRPBindPort,
		Alive: time.Duration(cfg.ServerAliveInterval) * time.Second, AliveMax: cfg.ServerAliveCountMax}
	if id == 1 {
		t.Host, t.Port, t.User = cfg.RemoteHost, cfg.RemoteSSHPort, cfg.RemoteUser
	} else {
		l, ok := findBagherLink(cfg, id)
		if !ok {
			return t, false
		}
		// an empty SSH port or user is the first foreign server's, as in
		// the link's bundle
		lc := bagherLinkCfg(cfg, l)
		t.Host, t.Port, t.User = lc.RemoteHost, lc.RemoteSSHPort, lc.RemoteUser
	}
	if t.Port <= 0 {
		t.Port = 22
	}
	if t.User == "" {
		t.User = "root"
	}
	if t.Alive <= 0 {
		t.Alive = 10 * time.Second
	}
	if t.AliveMax <= 0 {
		t.AliveMax = 3
	}
	return t, t.Host != "" && t.FRPPort > 0
}

// runBagherCarrier keeps one session up until ctx ends, reconnecting with
// a backoff from 2 s to 15 s (sshd's MaxStartups and fail2ban see few tries).
func runBagherCarrier(ctx context.Context, t bagherCarrierTarget, knownHosts string) {
	backoff := 2 * time.Second
	for ctx.Err() == nil {
		start := time.Now()
		err := bagherCarrierSession(ctx, t, knownHosts)
		if ctx.Err() != nil {
			return
		}
		log.Printf("bagher-carrier: link %d: %v", t.ID, err)
		writeBagherCarrierStatus(t.ID, bagherCarrierStatus{Error: err.Error()})
		if time.Since(start) > time.Minute {
			backoff = 2 * time.Second
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > 15*time.Second {
			backoff = 15 * time.Second
		}
	}
}

// bagherHostKeyCallback trusts a host on first use, like
// StrictHostKeyChecking=accept-new, in the same file ssh used.
func bagherHostKeyCallback(path string) (ssh.HostKeyCallback, error) {
	_ = os.MkdirAll(filepath.Dir(path), 0700)
	if f, err := os.OpenFile(path, os.O_CREATE|os.O_RDONLY, 0600); err == nil {
		_ = f.Close()
	}
	repairKnownHostsIPv6(path)
	check, err := knownhosts.New(path)
	if err != nil {
		return nil, err
	}
	return func(host string, remote net.Addr, key ssh.PublicKey) error {
		err := check(host, remote, key)
		var ke *knownhosts.KeyError
		if errors.As(err, &ke) && len(ke.Want) == 0 {
			f, ferr := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
			if ferr != nil {
				return ferr
			}
			defer f.Close()
			_, ferr = fmt.Fprintln(f, knownHostsEntry(host)+" "+strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))))
			return ferr
		}
		return err
	}, nil
}

// knownHostsEntry is host:port as OpenSSH writes it in known_hosts: the bare
// host on port 22 (an IPv6 one too), [host]:port otherwise. knownhosts.Line
// writes "[v6]" for port 22, a line its own parser then rejects, and with it
// the whole file (every link's carrier).
func knownHostsEntry(address string) string {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		host, port = strings.Trim(address, "[]"), "22"
	}
	if port == "22" {
		return host
	}
	return "[" + host + "]:" + port
}

// repairKnownHostsIPv6 rewrites "[v6]" host patterns (no port) that older
// carriers wrote into the bare form, so the file parses again.
func repairKnownHostsIPv6(path string) {
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	lines := strings.Split(string(b), "\n")
	changed := false
	for i, l := range lines {
		f := strings.SplitN(l, " ", 2)
		if len(f) != 2 || !strings.Contains(f[0], "[") {
			continue
		}
		pats := strings.Split(f[0], ",")
		for j, p := range pats {
			neg := strings.HasPrefix(p, "!")
			q := strings.TrimPrefix(p, "!")
			if strings.HasPrefix(q, "[") && strings.HasSuffix(q, "]") {
				if _, _, err := net.SplitHostPort(q); err != nil {
					q = strings.Trim(q, "[]")
					if neg {
						q = "!" + q
					}
					pats[j], changed = q, true
				}
			}
		}
		lines[i] = strings.Join(pats, ",") + " " + f[1]
	}
	if changed {
		_ = os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0600)
	}
}

func bagherCarrierSession(ctx context.Context, t bagherCarrierTarget, knownHosts string) error {
	keyPEM, err := os.ReadFile(t.KeyPath)
	if err != nil {
		return fmt.Errorf("reading key: %w", err)
	}
	signer, err := ssh.ParsePrivateKey(keyPEM)
	if err != nil {
		return fmt.Errorf("parsing key: %w", err)
	}
	var hostKey ssh.HostKeyCallback
	if t.Strict {
		hostKey, err = knownhosts.New(knownHosts)
	} else {
		hostKey, err = bagherHostKeyCallback(knownHosts)
	}
	if err != nil {
		return fmt.Errorf("known_hosts: %w", err)
	}
	conf := &ssh.ClientConfig{
		User:            t.User,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: hostKey,
		Timeout:         8 * time.Second,
	}
	conf.Ciphers = []string{"aes128-gcm@openssh.com", "chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com", "aes128-ctr"}

	d := net.Dialer{Timeout: 8 * time.Second, KeepAlive: 15 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", t.addr())
	if err != nil {
		return err
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true) // Go's default; stated because it is the point
	}
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	c, chans, reqs, err := ssh.NewClientConn(conn, t.addr(), conf)
	if err != nil {
		_ = conn.Close()
		return err
	}
	_ = conn.SetDeadline(time.Time{})
	client := ssh.NewClient(c, chans, reqs)
	defer client.Close()

	// Like ExitOnForwardFailure: after an outage sshd may still hold the
	// port for the dead session, so fail and retry until it lets go.
	ln, err := client.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(t.FRPPort)))
	if err != nil {
		return fmt.Errorf("remote listen on 127.0.0.1:%d: %w", t.FRPPort, err)
	}
	defer ln.Close()
	go bagherNudgeNoDelay(client)

	since := time.Now().Unix()
	rtt, err := bagherPing(client, t.Alive)
	if err != nil {
		return err
	}
	writeBagherCarrierStatus(t.ID, bagherCarrierStatus{Connected: true, RTTMs: rtt, Since: since})
	log.Printf("bagher-carrier: link %d up, rtt %.1f ms", t.ID, rtt)

	done := make(chan error, 2)
	local := t.Local
	if local == "" {
		local = net.JoinHostPort("127.0.0.1", strconv.Itoa(t.FRPPort))
	}
	sctx, stop := context.WithCancel(ctx)
	go func() { done <- bagherServe(ln, local) }()
	go func() { done <- bagherKeepalive(sctx, client, t, since) }()
	left := 2
	select {
	case <-ctx.Done():
		err = ctx.Err()
	case err = <-done:
		left--
	}
	// End both before returning, so no status write follows this session's.
	stop()
	_ = ln.Close()
	_ = client.Close()
	for ; left > 0; left-- {
		<-done
	}
	return err
}

// bagherNudgeNoDelay runs one exec request. sshd sets TCP_NODELAY on the
// connection when a session runs a command (before OpenSSH 10.1 only then).
// The key's forced command is /bin/false; "true" is for keys without one.
func bagherNudgeNoDelay(client *ssh.Client) {
	s, err := client.NewSession()
	if err != nil {
		return
	}
	defer s.Close()
	_ = s.Run("true")
}

// bagherPing is one keepalive@openssh.com round trip: sshd answers it (with
// a failure) behind any tunnel data already queued, so it is the tunnel's ping.
func bagherPing(client *ssh.Client, timeout time.Duration) (float64, error) {
	t0 := time.Now()
	res := make(chan error, 1)
	go func() {
		_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
		res <- err
	}()
	select {
	case err := <-res:
		if err != nil {
			return 0, err
		}
		// at least 0.01 ms: 0 means "no measurement" to the panel, and a
		// coarse clock can read 0 on loopback
		return math.Max(float64(time.Since(t0).Microseconds())/1000, 0.01), nil
	case <-time.After(timeout):
		return 0, fmt.Errorf("keepalive timed out after %v", timeout)
	}
}

func bagherKeepalive(ctx context.Context, client *ssh.Client, t bagherCarrierTarget, since int64) error {
	tick := time.NewTicker(t.Alive)
	defer tick.Stop()
	missed := 0
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
		rtt, err := bagherPing(client, t.Alive)
		if err != nil {
			if missed++; missed >= t.AliveMax {
				return fmt.Errorf("%d keepalives missed: %v", missed, err)
			}
			continue
		}
		missed = 0
		writeBagherCarrierStatus(t.ID, bagherCarrierStatus{Connected: true, RTTMs: rtt, Since: since})
	}
}

// bagherServe pipes each connection sshd forwards to the local frps.
func bagherServe(ln net.Listener, target string) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("forward closed: %w", err)
		}
		go func() {
			defer c.Close()
			up, err := net.DialTimeout("tcp", target, 5*time.Second)
			if err != nil {
				return
			}
			defer up.Close()
			bagherPipe(c, up)
		}()
	}
}

// bagherPipe copies both ways with half-close, so one side's EOF reaches
// the other while the reverse direction drains.
func bagherPipe(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = dst.Close()
		}
	}
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
}
