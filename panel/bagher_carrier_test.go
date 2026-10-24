package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// fakeSSHD is a minimal sshd for the carrier: public-key auth, tcpip-forward
// (listening on 127.0.0.1 like sshd's -R), keepalive replies and exec.
type fakeSSHD struct {
	addr    string
	execs   atomic.Int32
	fwdPort atomic.Int32
	ln      net.Listener
}

func startFakeSSHD(t *testing.T, clientKey ssh.PublicKey) *fakeSSHD {
	t.Helper()
	_, hostPriv, _ := ed25519.GenerateKey(rand.Reader)
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatal(err)
	}
	conf := &ssh.ServerConfig{PublicKeyCallback: func(c ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		if string(k.Marshal()) == string(clientKey.Marshal()) && c.User() == "root" {
			return nil, nil
		}
		return nil, io.EOF
	}}
	conf.AddHostKey(hostSigner)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &fakeSSHD{addr: ln.Addr().String(), ln: ln}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(c, conf)
		}
	}()
	return s
}

func (s *fakeSSHD) serve(c net.Conn, conf *ssh.ServerConfig) {
	sc, chans, reqs, err := ssh.NewServerConn(c, conf)
	if err != nil {
		return
	}
	defer sc.Close()
	go func() {
		for ch := range chans {
			if ch.ChannelType() != "session" {
				_ = ch.Reject(ssh.UnknownChannelType, "no")
				continue
			}
			sess, sreqs, _ := ch.Accept()
			go func() {
				for r := range sreqs {
					if r.Type == "exec" {
						s.execs.Add(1)
						_ = r.Reply(true, nil)
						_, _ = sess.SendRequest("exit-status", false, ssh.Marshal(struct{ C uint32 }{1}))
						_ = sess.Close()
						continue
					}
					_ = r.Reply(false, nil)
				}
			}()
		}
	}()
	for r := range reqs {
		switch r.Type {
		case "tcpip-forward":
			var m struct {
				Addr string
				Port uint32
			}
			if ssh.Unmarshal(r.Payload, &m) != nil || m.Addr != "127.0.0.1" {
				_ = r.Reply(false, nil)
				continue
			}
			fl, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(m.Port))))
			if err != nil {
				_ = r.Reply(false, nil)
				continue
			}
			defer fl.Close()
			s.fwdPort.Store(int32(fl.Addr().(*net.TCPAddr).Port))
			_ = r.Reply(true, nil)
			go func() {
				for {
					fc, err := fl.Accept()
					if err != nil {
						return
					}
					ra := fc.RemoteAddr().(*net.TCPAddr)
					payload := ssh.Marshal(struct {
						Addr       string
						Port       uint32
						OriginAddr string
						OriginPort uint32
					}{m.Addr, m.Port, ra.IP.String(), uint32(ra.Port)})
					ch, creqs, err := sc.OpenChannel("forwarded-tcpip", payload)
					if err != nil {
						fc.Close()
						continue
					}
					go ssh.DiscardRequests(creqs)
					go func() {
						defer fc.Close()
						defer ch.Close()
						go func() { _, _ = io.Copy(ch, fc); _ = ch.CloseWrite() }()
						_, _ = io.Copy(fc, ch)
					}()
				}
			}()
		default: // keepalive@openssh.com and anything else: failure, as sshd does
			if r.WantReply {
				_ = r.Reply(false, nil)
			}
		}
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func TestBagherCarrierEndToEnd(t *testing.T) {
	dir := t.TempDir()
	old := configDir
	configDir = dir
	t.Cleanup(func() { configDir = old })

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "id")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(block), 0600); err != nil {
		t.Fatal(err)
	}
	sshPub, _ := ssh.NewPublicKey(pub)
	sshd := startFakeSSHD(t, sshPub)

	// The "frps" on Iran: answers each connection with a greeting and an echo.
	frpPort := freePort(t)
	frps, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(frpPort)))
	if err != nil {
		t.Fatal(err)
	}
	defer frps.Close()
	go func() {
		for {
			c, err := frps.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = c.Write([]byte("frps\n"))
				_, _ = io.Copy(c, c)
			}()
		}
	}()

	host, portStr, _ := net.SplitHostPort(sshd.addr)
	port, _ := strconv.Atoi(portStr)
	fwd := freePort(t)
	tg := bagherCarrierTarget{ID: 2, Host: host, Port: port, User: "root", KeyPath: keyPath,
		FRPPort: fwd, Alive: 200 * time.Millisecond, AliveMax: 3,
		Local: net.JoinHostPort("127.0.0.1", strconv.Itoa(frpPort))} // one host plays both sides
	ctx, cancel := context.WithCancel(context.Background())
	known := filepath.Join(dir, "known_hosts")
	stopped := make(chan struct{})
	go func() { runBagherCarrier(ctx, tg, known); close(stopped) }()
	defer func() { cancel(); <-stopped }() // before configDir is restored

	deadline := time.Now().Add(5 * time.Second)
	for sshd.fwdPort.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if int(sshd.fwdPort.Load()) != fwd {
		t.Fatalf("remote forward on %d, want %d", sshd.fwdPort.Load(), fwd)
	}
	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(fwd)), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 5)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "frps\n" {
		t.Fatalf("greeting through the tunnel: %q %v", buf, err)
	}
	msg := make([]byte, 8)
	binary.BigEndian.PutUint64(msg, 0xB46E)
	_, _ = c.Write(msg)
	got := make([]byte, 8)
	if _, err := io.ReadFull(c, got); err != nil || string(got) != string(msg) {
		t.Fatalf("echo through the tunnel: %v %v", got, err)
	}

	for time.Now().Before(deadline) && sshd.execs.Load() == 0 {
		time.Sleep(20 * time.Millisecond)
	}
	if sshd.execs.Load() != 1 {
		t.Fatalf("the carrier must run one exec (sshd's TCP_NODELAY), got %d", sshd.execs.Load())
	}
	var st bagherCarrierStatus
	for time.Now().Before(deadline) {
		if s, ok := readBagherCarrierStatus(2, time.Minute); ok && s.Connected && s.RTTMs > 0 {
			st = s
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !st.Connected || st.RTTMs <= 0 || st.Since == 0 {
		t.Fatalf("carrier status: %+v", st)
	}
	kh, _ := os.ReadFile(known)
	if !strings.Contains(string(kh), "ssh-ed25519") {
		t.Fatalf("host key not recorded on first use: %q", kh)
	}
}

func TestBagherHostKeyMismatchRefused(t *testing.T) {
	dir := t.TempDir()
	known := filepath.Join(dir, "known_hosts")
	cb, err := bagherHostKeyCallback(known)
	if err != nil {
		t.Fatal(err)
	}
	k1pub, _, _ := ed25519.GenerateKey(rand.Reader)
	k2pub, _, _ := ed25519.GenerateKey(rand.Reader)
	s1, _ := ssh.NewPublicKey(k1pub)
	s2, _ := ssh.NewPublicKey(k2pub)
	addr := &net.TCPAddr{IP: net.ParseIP("198.51.100.9"), Port: 22}
	if err := cb("198.51.100.9:22", addr, s1); err != nil {
		t.Fatalf("first use must be accepted: %v", err)
	}
	cb, _ = bagherHostKeyCallback(known)
	if err := cb("198.51.100.9:22", addr, s1); err != nil {
		t.Fatalf("known key refused: %v", err)
	}
	if err := cb("198.51.100.9:22", addr, s2); err == nil {
		t.Fatal("a changed host key must be refused")
	}
}

func TestBagherCarrierTargetFor(t *testing.T) {
	cfg := defaultSSHFwdConfig()
	cfg.RemoteHost, cfg.RemoteSSHPort = "198.51.100.1", 2222
	cfg.RemoteUser = "tunnel"
	cfg.Links = []BagherLink{{ID: 2, RemoteHost: "198.51.100.2", Ports: []int{8443}},
		{ID: 3, RemoteHost: "198.51.100.3", Ports: []int{9443}, RemoteSSHPort: 2200, RemoteUser: "bagher"}}
	t1, ok := bagherCarrierTargetFor(cfg, 1)
	if !ok || t1.Host != "198.51.100.1" || t1.Port != 2222 || t1.User != "tunnel" || t1.FRPPort != 55400 {
		t.Fatalf("link 1: %+v %v", t1, ok)
	}
	// no port or user of its own: the first foreign server's, as its bundle says
	t2, ok := bagherCarrierTargetFor(cfg, 2)
	if !ok || t2.Host != "198.51.100.2" || t2.Port != 2222 || t2.User != "tunnel" {
		t.Fatalf("link 2: %+v %v", t2, ok)
	}
	t3, ok := bagherCarrierTargetFor(cfg, 3)
	if !ok || t3.Port != 2200 || t3.User != "bagher" {
		t.Fatalf("link 3: %+v %v", t3, ok)
	}
	if _, ok := bagherCarrierTargetFor(cfg, 7); ok {
		t.Fatal("unknown link must not resolve")
	}
}
