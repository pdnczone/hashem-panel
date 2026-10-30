package main

// sell-bagher: one sold Bagher link on the seller's server, run by its
// hsell-<customer>-<link> unit from a copy of this binary:
//
//	hashem-relay sell-bagher -frps BIN -conf FRPS.toml -host H -port P -user U \
//	    -frp-port N -key KEY -known KNOWN_HOSTS
//
// It runs the link's frps (bound to 127.0.0.1:N) and the SSH carrier that
// dials the customer's sshd, asks it to listen on its 127.0.0.1:N and pipes
// what arrives there to this frps. The customer's frpc connects to that
// port. The host key must be one of the reply code's (KNOWN_HOSTS): no key
// is trusted on first use. Everything comes from the flags; the process
// reads no panel state.

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"
)

func custBagherRelayCmd(args []string) int {
	fs := flag.NewFlagSet("sell-bagher", flag.ContinueOnError)
	frps := fs.String("frps", "", "frps binary")
	conf := fs.String("conf", "", "frps config")
	host := fs.String("host", "", "the customer's server")
	port := fs.Int("port", 22, "its sshd port")
	user := fs.String("user", "hcust", "the SSH user")
	frpPort := fs.Int("frp-port", 0, "frps port, on 127.0.0.1 on both servers")
	key := fs.String("key", "", "this link's SSH private key")
	known := fs.String("known", "", "known_hosts with the customer's host keys")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	switch {
	case *frps == "" || *conf == "" || *key == "" || *known == "":
		log.Print("sell-bagher: -frps, -conf, -key and -known are required")
		return 2
	case !validBagherHost(*host):
		log.Printf("sell-bagher: bad host %q", *host)
		return 2
	case !bagherUserRe.MatchString(*user):
		log.Printf("sell-bagher: bad user %q", *user)
		return 2
	case *port < 1 || *port > 65535 || *frpPort < 1 || *frpPort > 65535:
		log.Print("sell-bagher: bad port")
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	cmd := exec.Command(*frps, "-c", *conf)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	// frps dies with this process, whatever ends it
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if err := cmd.Start(); err != nil {
		log.Printf("sell-bagher: frps: %v", err)
		return 1
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()

	t := bagherCarrierTarget{Host: *host, Port: *port, User: *user, KeyPath: *key, FRPPort: *frpPort,
		Alive: 10 * time.Second, AliveMax: 3, Strict: true}
	log.Printf("sell-bagher: %s@%s, 127.0.0.1:%d on both sides", t.User, t.addr(), t.FRPPort)
	carrier := make(chan struct{})
	go func() {
		runBagherCarrier(ctx, t, *known)
		close(carrier)
	}()

	select {
	case err := <-exited:
		// systemd restarts the unit, frps and carrier together
		stop()
		<-carrier
		log.Printf("sell-bagher: frps ended: %v", err)
		return 1
	case <-ctx.Done():
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-exited:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-exited
		}
		<-carrier
		fmt.Fprintln(os.Stderr, "sell-bagher: stopped")
		return 0
	}
}
