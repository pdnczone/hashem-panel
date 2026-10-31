package main

// Nodes: the panel API (/api/nodes), adding a node over SSH, and the CLI
// (gre-panel node ...). node.go and node_link.go are the rest.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	nodeInstallURL = "https://raw.githubusercontent.com/pdnczone/hashem-panel/main/install.sh"
	nodeSSHTimeout = 20 * time.Minute // installing Hashem on a fresh server takes a while
	nodeSSHLogMax  = 32 << 10
	nodeSSHJobsMax = 20
)

// nodeView is one node as the panel shows it.
type nodeView struct {
	nodeRecord
	KeyFP     string `json:"key_fp"`
	Online    bool   `json:"online"`
	Since     int64  `json:"since,omitempty"` // connected since
	LinkVer   string `json:"link_version,omitempty"`
	KeyHidden string `json:"key,omitempty"` // shadows nodeRecord.Key: not sent
}

func handleNodesGet(w http.ResponseWriter, r *http.Request) {
	self, err := nodeSelfLoad()
	out := map[string]any{"role": "standalone", "default_url": nodeDefaultURL(), "version": panelVersion}
	if err != nil {
		out["error"] = err.Error()
		writeJSON(w, out)
		return
	}
	if pub, err := nodePub(); err == nil {
		out["key_fp"] = nodeFingerprint(pub)
	}
	switch self.Role {
	case nodeRoleCentral:
		out["role"] = nodeRoleCentral
		nodesMu.Lock()
		nodesLoadLocked()
		nodeInvitesPruneLocked(time.Now())
		list := make([]nodeView, 0, len(nodesF.Nodes))
		for _, rec := range nodesF.Nodes {
			v := nodeView{nodeRecord: rec, KeyFP: nodeFingerprint(rec.Key)}
			if s := nodeSessions[rec.ID]; s != nil {
				v.Online, v.Since, v.LinkVer = true, s.since.Unix(), s.version
			}
			list = append(list, v)
		}
		invites := make([]map[string]any, 0, len(nodesF.Invites))
		for _, iv := range nodesF.Invites {
			invites = append(invites, map[string]any{"name": iv.Name, "created": iv.Created, "expires": iv.Expires})
		}
		left := append([]nodeTunLeft{}, nodesF.Left...)
		loadErr := nodesEr
		nodesMu.Unlock()
		sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
		out["nodes"], out["invites"], out["jobs"] = list, invites, nodeSSHJobsView()
		out["tunnel_jobs"], out["left"] = nodeTunJobsView(), left
		if loadErr != "" {
			out["error"] = "nodes.json cannot be read: " + loadErr
		}
	case nodeRoleNode:
		out["role"] = nodeRoleNode
		nodeLinkState.Lock()
		c := map[string]any{"url": self.Central, "key_fp": nodeFingerprint(self.CentralKey), "id": self.ID, "name": self.Name,
			"joined_at": self.JoinedAt, "connected": nodeLinkState.Connected, "last_error": nodeLinkState.LastErr, "refused": self.Refused}
		if nodeLinkState.Connected {
			c["since"] = nodeLinkState.Since.Unix()
		}
		nodeLinkState.Unlock()
		out["central"] = c
	}
	if m := nodeMigrateView(self); m != nil {
		out["migrate"] = m
	}
	writeJSON(w, out)
}

type nodeRequest struct {
	Action   string `json:"action"`
	ID       int    `json:"id"`
	Name     string `json:"name"`
	URL      string `json:"url"`
	Code     string `json:"code"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	User     string `json:"user"`
	Password string `json:"password"`
	SSHKey   string `json:"ssh_key"`
	HostKey  string `json:"host_key"`
	// tunnels between servers (node_tunnel.go)
	nodeTunReq
	PeerID int `json:"peer_id"`
	Hub    int `json:"hub"`
	Left   int `json:"left"`
}

func handleNodesPost(w http.ResponseWriter, r *http.Request) {
	var req nodeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeAPIError(w, r, "E-NODE-01", "invalid JSON")
		return
	}
	self, err := nodeSelfLoad()
	if err != nil {
		writeAPIError(w, r, "E-NODE-05", err.Error())
		return
	}
	isCentral := func() bool {
		if self.Role != nodeRoleCentral {
			writeAPIError(w, r, "E-NODE-02", "this panel is not a central")
			return false
		}
		return true
	}
	switch req.Action {
	case "invite":
		if self.Role == nodeRoleNode {
			writeAPIError(w, r, "E-NODE-02", "this panel is a node of another central: leave it first to make this panel a central")
			return
		}
		code, iv, err := nodeNewInvite(self, req.Name, req.URL)
		if err != nil {
			writeAPIError(w, r, nodeErrCode(err), err.Error())
			return
		}
		LogSecurityAudit("node_invite", cfg.Username, ClientIP(r), "name="+iv.Name)
		writeJSON(w, map[string]any{"code": code.String(), "url": code.URL, "expires": iv.Expires,
			"command": nodeJoinCommand(code, iv.Name, false), "install_command": nodeJoinCommand(code, iv.Name, true)})
		return
	case "cancel-invites":
		if !isCentral() {
			return
		}
		nodesMu.Lock()
		nodesLoadLocked()
		nodesF.Invites = nil
		err = nodesSaveLocked()
		nodesMu.Unlock()
	case "view": // a token for the node's sandboxed frame (node_relay.go)
		if !isCentral() {
			return
		}
		nodesMu.Lock()
		nodesLoadLocked()
		known := nodeFindLocked(req.ID) != nil
		nodesMu.Unlock()
		c, cerr := r.Cookie("gre_session")
		if !known || cerr != nil || c.Value == "" {
			writeAPIError(w, r, "E-NODE-03", fmt.Sprintf("no node %d", req.ID))
			return
		}
		writeJSON(w, map[string]any{"status": "ok", "token": nodeViewNew(c.Value, req.ID)})
		return
	case "rename":
		if !isCentral() {
			return
		}
		name, nerr := nodeCleanName(req.Name)
		if nerr != nil || name == "" {
			writeAPIError(w, r, "E-NODE-01", "name: 1 to 40 characters")
			return
		}
		nodesMu.Lock()
		nodesLoadLocked()
		if rec := nodeFindLocked(req.ID); rec == nil {
			err = errNodeUnknown(req.ID)
		} else {
			rec.Name = name
			err = nodesSaveLocked()
		}
		nodesMu.Unlock()
	case "remove":
		if !isCentral() {
			return
		}
		nodesMu.Lock()
		nodesLoadLocked()
		at := -1
		for i, rec := range nodesF.Nodes {
			if rec.ID == req.ID {
				at = i
			}
		}
		if at < 0 {
			err = errNodeUnknown(req.ID)
		} else {
			nodesF.Nodes = append(nodesF.Nodes[:at], nodesF.Nodes[at+1:]...)
			err = nodesSaveLocked()
		}
		nodesMu.Unlock()
		if err == nil {
			nodeKick(req.ID)
			LogSecurityAudit("node_removed", cfg.Username, ClientIP(r), "id="+strconv.Itoa(req.ID))
		}
	case "leave":
		err = nodeLeave(self)
		if err == nil {
			LogSecurityAudit("node_leave", cfg.Username, ClientIP(r), "role="+self.Role)
		}
	case "join":
		if self.Role != "" {
			writeAPIError(w, r, "E-NODE-02", "this panel already is a "+self.Role+": leave first")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
		_, err = nodeJoin(ctx, req.Code, req.Name)
		cancel()
		if err == nil {
			LogSecurityAudit("node_joined", cfg.Username, ClientIP(r), "")
		}
	case "ssh":
		if self.Role == nodeRoleNode {
			writeAPIError(w, r, "E-NODE-02", "this panel is a node of another central")
			return
		}
		res, serr := nodeSSHStart(self, req)
		if serr != nil {
			writeAPIError(w, r, nodeErrCode(serr), serr.Error())
			return
		}
		if res.HostKey == "" {
			LogSecurityAudit("node_ssh_add", cfg.Username, ClientIP(r), "host="+req.Host+" user="+req.User)
		}
		writeJSON(w, res)
		return
	case "tunnel-plan", "tunnel-create": // a tunnel between two servers (node_tunnel.go)
		if !isCentral() {
			return
		}
		q := req.nodeTunReq
		if cerr := q.check(); cerr != nil {
			writeAPIError(w, r, nodeErrCode(cerr), cerr.Error())
			return
		}
		if req.Action == "tunnel-plan" {
			ctx, cancel := context.WithTimeout(r.Context(), 2*nodeTunPlanTO)
			d, derr := nodeTunDraftFor(ctx, q)
			cancel()
			if derr != nil {
				writeAPIError(w, r, "E-NODE-04", derr.Error())
				return
			}
			writeJSON(w, d)
			return
		}
		id, jerr := nodeTunStart("create", q.Server, q.Client, func(j *nodeTunJob) error { return nodeTunCreate(context.Background(), j, q) })
		if jerr != nil {
			writeAPIError(w, r, nodeErrCode(jerr), jerr.Error())
			return
		}
		LogSecurityAudit("node_tunnel_create", cfg.Username, ClientIP(r), fmt.Sprintf("server=%d client=%d engine=%s ports=%s", q.Server, q.Client, q.Engine, q.Ports))
		writeJSON(w, map[string]any{"status": "ok", "job": id})
		return
	case "tunnel-list":
		if !isCentral() {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), nodeTunPlanTO)
		links, errs := nodeTunLinks(ctx)
		cancel()
		writeJSON(w, map[string]any{"links": links, "errors": errs})
		return
	case "tunnel-remove":
		if !isCentral() {
			return
		}
		q := nodeTunRemoveReq{Server: req.Server, Client: req.Client, PeerID: req.PeerID, Hub: req.Hub, Left: req.Left}
		if q.Left > 0 {
			nodesMu.Lock()
			nodesLoadLocked()
			i := slices.IndexFunc(nodesF.Left, func(l nodeTunLeft) bool { return l.ID == q.Left })
			if i >= 0 {
				q.Server, q.Client = nodesF.Left[i].Server, nodesF.Left[i].Client
			}
			nodesMu.Unlock()
			if i < 0 {
				writeAPIError(w, r, "E-NODE-01", "no such left-over tunnel")
				return
			}
		} else if q.Server == q.Client || q.Server < 0 || q.Client < 0 || q.PeerID < 0 || q.Hub < 1 {
			writeAPIError(w, r, "E-NODE-01", "bad tunnel")
			return
		}
		id, jerr := nodeTunStart("remove", q.Server, q.Client, func(j *nodeTunJob) error { return nodeTunRemove(context.Background(), j, q) })
		if jerr != nil {
			writeAPIError(w, r, nodeErrCode(jerr), jerr.Error())
			return
		}
		LogSecurityAudit("node_tunnel_remove", cfg.Username, ClientIP(r), fmt.Sprintf("server=%d client=%d peer=%d hub=%d left=%d", q.Server, q.Client, q.PeerID, q.Hub, q.Left))
		writeJSON(w, map[string]any{"status": "ok", "job": id})
		return
	case "migrate-start", "migrate-later", "migrate-never", "migrate-stop": // moving to nodes (node_migrate.go)
		err = nodeMigrateAction(self, req.Action)
		if err == nil {
			LogSecurityAudit("node_"+strings.ReplaceAll(req.Action, "-", "_"), cfg.Username, ClientIP(r), "")
		}
	case "tunnel-forget": // a left-over server end removed by hand on its server
		if !isCentral() {
			return
		}
		nodesMu.Lock()
		nodesLoadLocked()
		n := len(nodesF.Left)
		nodesF.Left = slices.DeleteFunc(nodesF.Left, func(l nodeTunLeft) bool { return l.ID == req.Left })
		changed := len(nodesF.Left) != n
		if changed {
			err = nodesSaveLocked()
		}
		nodesMu.Unlock()
		if err == nil && changed {
			LogSecurityAudit("node_tunnel_forget", cfg.Username, ClientIP(r), fmt.Sprintf("left=%d", req.Left))
		}
	default:
		writeAPIError(w, r, "E-NODE-01", "unknown action")
		return
	}
	if err != nil {
		writeAPIError(w, r, nodeErrCode(err), err.Error())
		return
	}
	handleNodesGet(w, r)
}

type nodeErr struct {
	code string
	msg  string
}

func (e nodeErr) Error() string { return e.msg }

func errNodeUnknown(id int) error { return nodeErr{"E-NODE-03", fmt.Sprintf("no node %d", id)} }

func nodeErrCode(err error) string {
	var ne nodeErr
	if errors.As(err, &ne) {
		return ne.code
	}
	return "E-NODE-05"
}

// nodeNewInvite makes a join code; a standalone panel becomes a central.
func nodeNewInvite(self nodeSelf, name, url string) (nodeCode, nodeInvite, error) {
	name, err := nodeCleanName(name)
	if err != nil {
		return nodeCode{}, nodeInvite{}, nodeErr{"E-NODE-01", err.Error()}
	}
	if url == "" {
		url = nodeDefaultURL()
	}
	if url == "" {
		return nodeCode{}, nodeInvite{}, nodeErr{"E-NODE-01", "this server's public IP is not known: type the address nodes should dial"}
	}
	url, err = nodeCentralURL(url)
	if err != nil {
		return nodeCode{}, nodeInvite{}, nodeErr{"E-NODE-01", err.Error()}
	}
	nodesMu.Lock()
	defer nodesMu.Unlock()
	nodesLoadLocked()
	if nodesEr != "" {
		return nodeCode{}, nodeInvite{}, fmt.Errorf("nodes.json cannot be read (%s): fix or remove it first", nodesEr)
	}
	if self.Role == "" {
		if err := nodeSelfSave(nodeSelf{Role: nodeRoleCentral}); err != nil {
			return nodeCode{}, nodeInvite{}, err
		}
	}
	code, iv, err := nodeInviteLocked(name, url, time.Now())
	if err != nil {
		return nodeCode{}, nodeInvite{}, nodeErr{"E-NODE-02", err.Error()}
	}
	if err := nodesSaveLocked(); err != nil {
		return nodeCode{}, nodeInvite{}, err
	}
	return code, iv, nil
}

// nodeLeave: a node leaves its central (its link says goodbye); a central
// with no nodes left becomes standalone. Tunnels are not touched.
func nodeLeave(self nodeSelf) error {
	nodesMu.Lock()
	defer nodesMu.Unlock()
	switch self.Role {
	case nodeRoleNode:
		return nodeSelfClear()
	case nodeRoleCentral:
		nodesLoadLocked()
		if nodesEr != "" { // its nodes are not known: leaving would cut them off unseen
			return nodeErr{"E-NODE-05", "nodes.json cannot be read (" + nodesEr + "): fix or remove it first"}
		}
		if len(nodesF.Nodes) > 0 {
			return nodeErr{"E-NODE-02", fmt.Sprintf("this central still has %d node(s): remove them first", len(nodesF.Nodes))}
		}
		nodesF.Invites = nil
		if nodesEr == "" {
			_ = nodesSaveLocked()
		}
		return nodeSelfClear()
	}
	return nodeErr{"E-NODE-02", "this panel is standalone"}
}

// shellQuote quotes s for a POSIX shell.
func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// nodeJoinCommand is the line a new node runs: hashem node-join on a server
// that has Hashem, or the installer (which installs it and joins) on one
// that has not.
func nodeJoinCommand(c nodeCode, name string, install bool) string {
	return nodeJoinCommandArg(shellQuote(c.String()), name, install)
}

// nodeJoinCommandArg is nodeJoinCommand with the code argument as given
// ("-": read it from stdin).
func nodeJoinCommandArg(code, name string, install bool) string {
	args := "node-join " + code
	if name != "" {
		args += " --name " + shellQuote(name)
	}
	if install {
		return "bash <(curl -fsSL " + nodeInstallURL + ") " + args
	}
	return "hashem " + args
}

// ---- adding a node over SSH ----

type nodeSSHJob struct {
	ID      int    `json:"id"`
	Host    string `json:"host"`
	Name    string `json:"name,omitempty"`
	State   string `json:"state"` // running | done | failed
	Log     string `json:"log"`
	Started int64  `json:"started"`
	Ended   int64  `json:"ended,omitempty"`
}

var nodeSSH struct {
	sync.Mutex
	jobs []*nodeSSHJob
	next int
}

func nodeSSHJobsView() []nodeSSHJob {
	nodeSSH.Lock()
	defer nodeSSH.Unlock()
	out := make([]nodeSSHJob, 0, len(nodeSSH.jobs))
	for i := len(nodeSSH.jobs) - 1; i >= 0; i-- {
		out = append(out, *nodeSSH.jobs[i])
	}
	return out
}

type nodeSSHResult struct {
	HostKey string `json:"host_key,omitempty"` // confirm this, then send it back
	Job     int    `json:"job,omitempty"`
}

var ansiRe = regexp.MustCompile(`\x1b\[[0-9;?]*[A-Za-z]|\r`)

// nodeSSHClientConfig: password or private key; the host key must match
// want (an SHA256 fingerprint). With want empty, the server's key is put in
// *got and the login stops before any secret is sent.
func nodeSSHClientConfig(req nodeRequest, want string, got *string) (*ssh.ClientConfig, error) {
	cc := &ssh.ClientConfig{User: req.User, Timeout: 15 * time.Second}
	if req.SSHKey != "" {
		signer, err := ssh.ParsePrivateKey([]byte(req.SSHKey))
		if err != nil {
			return nil, nodeErr{"E-NODE-01", "the SSH private key cannot be read (a key with a passphrase is not supported)"}
		}
		cc.Auth = append(cc.Auth, ssh.PublicKeys(signer))
	}
	if req.Password != "" {
		pw := req.Password
		cc.Auth = append(cc.Auth, ssh.Password(pw), ssh.KeyboardInteractive(func(_, _ string, qs []string, _ []bool) ([]string, error) {
			ans := make([]string, len(qs))
			for i := range ans {
				ans[i] = pw
			}
			return ans, nil
		}))
	}
	cc.HostKeyCallback = func(_ string, _ net.Addr, key ssh.PublicKey) error {
		fp := ssh.FingerprintSHA256(key)
		if want == "" {
			*got = fp
			return errors.New("host key to confirm")
		}
		if fp != want {
			return fmt.Errorf("the server's SSH host key is %s, not the one you confirmed (%s)", fp, want)
		}
		return nil
	}
	return cc, nil
}

var nodeHostRe = regexp.MustCompile(`^[A-Za-z0-9.:\-\[\]]{1,253}$`)
var nodeUserRe = regexp.MustCompile(`^[a-z_][a-z0-9_.\-]{0,31}$`)

// nodeSSHStart: without a host key, connects only to read the server's host
// key for the user to confirm. With one, starts a job that logs in, installs
// Hashem if it is missing, and joins the server to this central.
func nodeSSHStart(self nodeSelf, req nodeRequest) (nodeSSHResult, error) {
	req.Host = strings.Trim(strings.TrimSpace(req.Host), "[]")
	if !nodeHostRe.MatchString(req.Host) {
		return nodeSSHResult{}, nodeErr{"E-NODE-01", "server address: an IP or a host name"}
	}
	if req.Port == 0 {
		req.Port = 22
	}
	if req.Port < 1 || req.Port > 65535 {
		return nodeSSHResult{}, nodeErr{"E-NODE-01", "SSH port: 1 to 65535"}
	}
	if req.User == "" {
		req.User = "root"
	}
	if !nodeUserRe.MatchString(req.User) {
		return nodeSSHResult{}, nodeErr{"E-NODE-01", "SSH user: a Linux user name"}
	}
	// the first call only reads the host key: it needs no password or key
	if req.HostKey != "" && req.Password == "" && req.SSHKey == "" {
		return nodeSSHResult{}, nodeErr{"E-NODE-01", "give the SSH password or a private key"}
	}
	addr := net.JoinHostPort(req.Host, strconv.Itoa(req.Port))
	if req.HostKey == "" {
		var got string
		cc, err := nodeSSHClientConfig(req, "", &got)
		if err != nil {
			return nodeSSHResult{}, err
		}
		c, err := ssh.Dial("tcp", addr, cc)
		if c != nil {
			_ = c.Close()
		}
		if got == "" {
			return nodeSSHResult{}, nodeErr{"E-NODE-04", fmt.Sprintf("cannot reach SSH at %s: %v", addr, err)}
		}
		return nodeSSHResult{HostKey: got}, nil
	}
	cc, err := nodeSSHClientConfig(req, req.HostKey, nil)
	if err != nil {
		return nodeSSHResult{}, err
	}
	name, err := nodeCleanName(req.Name)
	if err != nil {
		return nodeSSHResult{}, nodeErr{"E-NODE-01", err.Error()}
	}
	if name == "" {
		name = req.Host
		if n, err := nodeCleanName(name); err == nil {
			name = n
		}
	}
	nodeSSH.Lock()
	running := 0
	for _, j := range nodeSSH.jobs {
		if j.State == "running" {
			running++
		}
	}
	nodeSSH.Unlock()
	if running >= 5 {
		return nodeSSHResult{}, nodeErr{"E-NODE-02", "5 servers are being added already: wait for one to finish"}
	}
	code, _, err := nodeNewInvite(self, name, req.URL)
	if err != nil {
		return nodeSSHResult{}, err
	}
	nodeSSH.Lock()
	nodeSSH.next++
	job := &nodeSSHJob{ID: nodeSSH.next, Host: req.Host, Name: name, State: "running", Started: time.Now().Unix()}
	nodeSSH.jobs = append(nodeSSH.jobs, job)
	if n := len(nodeSSH.jobs) - nodeSSHJobsMax; n > 0 {
		nodeSSH.jobs = append([]*nodeSSHJob(nil), nodeSSH.jobs[n:]...)
	}
	nodeSSH.Unlock()
	cmd := nodeSSHCommand(name, req.User != "root")
	go nodeSSHRun(job, addr, cc, cmd, code.String())
	return nodeSSHResult{Job: job.ID}, nil
}

// nodeSSHCommand: hashem node-join when Hashem is there, else the installer.
// The code goes on stdin ("-"), not in the command line, where other users
// of the server (ps, the sudo log) could read it.
func nodeSSHCommand(name string, sudo bool) string {
	// a Hashem older than nodes has no node-join: the installer brings the
	// current one (and keeps the tunnels)
	script := "set -e; if command -v hashem >/dev/null 2>&1 && hashem help 2>/dev/null | grep -q 'node-join.*code | ->'; then " + nodeJoinCommandArg("-", name, false) +
		"; else " + nodeJoinCommandArg("-", name, true) + "; fi"
	cmd := "bash -c " + shellQuote(script)
	if sudo {
		cmd = "sudo -n " + cmd
	}
	return cmd
}

// nodeSSHLog collects the remote output, keeping the tail.
type nodeSSHLog struct {
	job *nodeSSHJob
}

func (l nodeSSHLog) Write(p []byte) (int, error) {
	nodeSSH.Lock()
	s := l.job.Log + ansiRe.ReplaceAllString(string(p), "")
	if len(s) > nodeSSHLogMax {
		s = s[len(s)-nodeSSHLogMax:]
	}
	l.job.Log = s
	nodeSSH.Unlock()
	return len(p), nil
}

func nodeSSHRun(job *nodeSSHJob, addr string, cc *ssh.ClientConfig, cmd, code string) {
	fail := func(msg string) {
		nodeSSH.Lock()
		job.State, job.Ended = "failed", time.Now().Unix()
		job.Log += "\n[!] " + msg + "\n"
		nodeSSH.Unlock()
	}
	logw := nodeSSHLog{job}
	_, _ = logw.Write([]byte("[*] connecting to " + addr + "\n"))
	c, err := ssh.Dial("tcp", addr, cc)
	if err != nil {
		fail("SSH login failed: " + err.Error())
		return
	}
	defer c.Close()
	sess, err := c.NewSession()
	if err != nil {
		fail(err.Error())
		return
	}
	defer sess.Close()
	sess.Stdout, sess.Stderr, sess.Stdin = logw, logw, strings.NewReader(code+"\n")
	_, _ = logw.Write([]byte("[*] logged in; installing or updating Hashem and joining this central\n"))
	done := make(chan error, 1)
	go func() { done <- sess.Run(cmd) }()
	select {
	case err = <-done:
	case <-time.After(nodeSSHTimeout):
		_ = c.Close()
		err = errors.New("timed out")
	}
	if err != nil {
		fail("the setup on the server failed: " + err.Error())
		return
	}
	nodeSSH.Lock()
	job.State, job.Ended = "done", time.Now().Unix()
	nodeSSH.Unlock()
}

// ---- CLI: gre-panel node ... ----

func cliNode(args []string) int {
	if v := os.Getenv("GRE_PANEL_DIR"); v != "" {
		configDir = v
	}
	sub := "status"
	if len(args) > 0 {
		sub, args = args[0], args[1:]
	}
	switch sub {
	case "join":
		code, name := "", ""
		for i := 0; i < len(args); i++ {
			switch {
			case args[i] == "--name" && i+1 < len(args):
				name = args[i+1]
				i++
			case strings.HasPrefix(args[i], "--name="):
				name = strings.TrimPrefix(args[i], "--name=")
			case code == "":
				code = args[i]
			}
		}
		if code == "-" { // on stdin: not visible in the process list
			line, _ := bufio.NewReader(io.LimitReader(os.Stdin, 4096)).ReadString('\n')
			code = strings.TrimSpace(line)
		}
		if code == "" {
			fmt.Fprintln(os.Stderr, "Usage: gre-panel node join <hn1.code | -> [--name NAME]")
			return 2
		}
		loadOrInitQuiet()
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		s, err := nodeJoin(ctx, code, name)
		cancel()
		if err != nil {
			fmt.Fprintln(os.Stderr, "[!] "+err.Error())
			return 1
		}
		fmt.Printf("[OK] joined the central at %s as node %d (%s). The panel connects within a few seconds; tunnels are not touched.\n", s.Central, s.ID, s.Name)
		return 0
	case "leave":
		s, err := nodeSelfLoad()
		if err != nil {
			fmt.Fprintln(os.Stderr, "[!] "+err.Error())
			return 1
		}
		if err := nodeLeave(s); err != nil {
			fmt.Fprintln(os.Stderr, "[!] "+err.Error())
			return 1
		}
		fmt.Println("[OK] this panel is standalone again; tunnels are not touched.")
		return 0
	case "status":
		s, err := nodeSelfLoad()
		if err != nil {
			fmt.Fprintln(os.Stderr, "[!] "+err.Error())
			return 1
		}
		pub, _ := nodePub()
		switch s.Role {
		case "":
			fmt.Println("role: standalone")
		case nodeRoleCentral:
			nodesMu.Lock()
			nodesLoadLocked()
			n, er := len(nodesF.Nodes), nodesEr
			nodesMu.Unlock()
			fmt.Printf("role: central\nnodes: %d\n", n)
			if er != "" {
				fmt.Println("nodes.json: " + er)
			}
		case nodeRoleNode:
			fmt.Printf("role: node %d (%s)\ncentral: %s (key %s)\n", s.ID, s.Name, s.Central, nodeFingerprint(s.CentralKey))
			if s.Refused != "" {
				fmt.Println("the central did not know this node at " + s.Refused + ": join again with a new code, or leave")
			}
		}
		if pub != "" {
			fmt.Println("this panel's key: " + nodeFingerprint(pub))
		}
		return 0
	}
	fmt.Fprintln(os.Stderr, "Usage: gre-panel node [status | join <hn1.code> [--name NAME] | leave]")
	return 2
}

// loadOrInitQuiet loads panel.json for a CLI command that needs cfg (the
// version and port) without the service's start-up work.
func loadOrInitQuiet() {
	if data, err := os.ReadFile(cfgPath()); err == nil {
		_ = json.NewDecoder(bytes.NewReader(data)).Decode(&cfg)
	}
}
