package main

import (
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestNodesLab runs in the central's namespace of tests/test_nodes_lab.sh;
// the node is this test binary in the other namespace (NODES_LAB_NODE_NS),
// over a veth, with the real kernel and firewall:
//
//   - a node joins with a code and the central gets its info,
//
//   - the channel is cut by a firewall (DROP, no reset): the central marks
//     it offline, and it comes back by itself when the path opens,
//
//   - the central restarts: the node dials it again,
//
//   - the node is removed on the central: it goes back to standalone.
//
//     NODES_LAB_NODE_NS=<ns> NODES_LAB_ADDR=<central ip> go test -run TestNodesLab
func TestNodesLab(t *testing.T) {
	ns, ip := os.Getenv("NODES_LAB_NODE_NS"), os.Getenv("NODES_LAB_ADDR")
	if ns == "" || ip == "" {
		t.Skip("set NODES_LAB_NODE_NS and NODES_LAB_ADDR to run the nodes lab")
	}
	nodeLabFast()
	old := configDir
	configDir = t.TempDir()
	t.Cleanup(func() { configDir = old })
	addr := net.JoinHostPort(ip, "18470")
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+nodeLinkPath, handleNodeLink)
	serve := func() *http.Server {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second}
		go func() { _ = srv.Serve(ln) }()
		return srv
	}
	srv := serve()
	central := "http://" + addr
	nd, err := os.MkdirTemp("", "nodes-lab-node-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(nd)
	node := func(cmd, code string, wait time.Duration) *exec.Cmd {
		c := exec.Command("ip", "netns", "exec", ns, os.Args[0], "-test.run=^TestNodeHelperProcess$")
		c.Env = append(os.Environ(), "NODE_HELPER=1", "NODE_HELPER_FAST=1", "NODE_HELPER_DIR="+nd, "NODE_HELPER_CMD="+cmd,
			"NODE_HELPER_CODE="+code, "NODE_HELPER_WAIT="+wait.String())
		return c
	}
	fw := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("ip", append([]string{"netns", "exec", ns, "iptables"}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("iptables %v: %v %s", args, err, out)
		}
	}
	online := func() bool { return nodeSessionFor(1) != nil }
	wait := func(what string, d time.Duration, ok func() bool) {
		t.Helper()
		end := time.Now().Add(d)
		for time.Now().Before(end) {
			if ok() {
				t.Logf("ok: %s", what)
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatalf("timed out: %s", what)
	}

	// a wrong address: a clear error, nothing written
	bad := nodeTestInvite(t, "http://"+net.JoinHostPort(ip, "18471"), "x")
	if out, _ := node("join", bad, 0).CombinedOutput(); !strings.Contains(string(out), "cannot reach the central") {
		t.Fatalf("join at a closed port: %s", out)
	}
	if _, err := os.Stat(filepath.Join(nd, "node.json")); !os.IsNotExist(err) {
		t.Fatal("a failed join wrote node.json")
	}

	if out, err := node("join", nodeTestInvite(t, central, "lab node"), 0).CombinedOutput(); err != nil {
		t.Fatalf("join: %v\n%s", err, out)
	}
	loop := node("loop", "", 60*time.Second)
	var logs strings.Builder
	loop.Stdout, loop.Stderr = &logs, &logs
	if err := loop.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = loop.Process.Kill(); _ = loop.Wait() }()
	wait("the node online with its info", 15*time.Second, func() bool {
		nodesMu.Lock()
		defer nodesMu.Unlock()
		r := nodeFindLocked(1)
		return nodeSessions[1] != nil && r != nil && r.Info.Version == "helper-v1" && r.Addr != ""
	})

	// the path drops packets silently (no reset)
	fw("-I", "OUTPUT", "-d", ip, "-j", "DROP")
	wait("the central sees the node offline", 15*time.Second, func() bool { return !online() })
	fw("-D", "OUTPUT", "-d", ip, "-j", "DROP")
	wait("the node back by itself", 20*time.Second, online)

	// the central restarts
	_ = srv.Close()
	nodesMu.Lock()
	for _, s := range nodeSessions {
		s.close()
	}
	nodesOK = false // read nodes.json again, as a new process would
	nodesMu.Unlock()
	wait("the session gone", 10*time.Second, func() bool { return !online() })
	srv = serve()
	defer srv.Close()
	wait("the node back after the central restarted", 20*time.Second, online)

	// removed: the node is told and leaves
	nodesMu.Lock()
	nodesF.Nodes = nil
	_ = nodesSaveLocked()
	nodesMu.Unlock()
	nodeKick(1)
	wait("node.json gone on the node", 10*time.Second, func() bool {
		_, err := os.Stat(filepath.Join(nd, "node.json"))
		return os.IsNotExist(err)
	})
	time.Sleep(3 * time.Second)
	if online() {
		t.Fatal("a removed node came back")
	}
}
