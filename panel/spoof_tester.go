package main

// Spoof IP tester: drives the `spoof tester` subcommand to find which source
// IPs the infrastructure firewall lets through for spoofing. It runs on two
// servers — one sender, one receiver — and the receiver's passing IPs become
// the other server's spoof-IP list. The panel runs the binary as a managed
// process and parses its output; all packet work stays in the binary.

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type spoofTesterResult struct {
	IP       string  `json:"ip"`
	Received int     `json:"received"`
	Sent     int     `json:"sent"`
	LossPct  float64 `json:"loss_pct"`
}

type spoofTesterStatus struct {
	Status   string              `json:"status"` // idle | running | done | stopped | error
	Mode     string              `json:"mode"`   // sender | receiver
	Protocol string              `json:"protocol"`
	Error    string              `json:"error,omitempty"`
	Progress int                 `json:"progress"` // 0-100 (elapsed/timeout estimate)
	Passed   []spoofTesterResult `json:"passed"`
	Started  string              `json:"started,omitempty"`
	Finished string              `json:"finished,omitempty"`
}

var (
	spoofTesterMu     sync.Mutex
	spoofTesterCur    spoofTesterStatus
	spoofTesterCancel context.CancelFunc
	spoofTesterStart  time.Time
	spoofTesterDur    time.Duration
	// spoofTesterWG tracks the run goroutine so tests can wait for it.
	spoofTesterWG sync.WaitGroup
	// spoofTesterRun starts the process; a var so tests never spawn the binary.
	spoofTesterRun = spoofTesterRunReal
)

var spoofTesterLine = regexp.MustCompile(`^(\d{1,3}(?:\.\d{1,3}){3})\s+(\d+)/(\d+)\s+([\d.]+)%`)

func spoofTesterView() spoofTesterStatus {
	spoofTesterMu.Lock()
	defer spoofTesterMu.Unlock()
	s := spoofTesterCur
	if s.Status == "running" && spoofTesterDur > 0 {
		p := int(time.Since(spoofTesterStart) * 100 / spoofTesterDur)
		if p > 99 {
			p = 99
		}
		s.Progress = p
	}
	if s.Passed == nil {
		s.Passed = []spoofTesterResult{}
	}
	return s
}

// spoofTesterRequest is one tester run.
type spoofTesterRequest struct {
	Action      string   `json:"action"`   // start | stop | clear
	Mode        string   `json:"mode"`     // sender | receiver
	Protocol    string   `json:"protocol"` // tcp | icmp
	Sources     []string `json:"sources"`  // IPs / ranges / CIDRs (one per entry or line)
	DstIP       string   `json:"dst_ip"`   // sender: the receiver server's IP
	DstPort     int      `json:"dst_port"`
	Timeout     int      `json:"timeout"`      // receiver timeout (s)
	PacketCount int      `json:"packet_count"` // packets per source IP
	MaxLoss     float64  `json:"max_loss"`     // max accepted packet loss %
}

func (r spoofTesterRequest) normalize() spoofTesterRequest {
	if r.Protocol != "tcp" && r.Protocol != "icmp" {
		r.Protocol = "icmp"
	}
	if r.DstPort <= 0 {
		r.DstPort = 80
	}
	if r.Timeout <= 0 {
		r.Timeout = 30
	}
	if r.PacketCount <= 0 {
		r.PacketCount = 10
	}
	// 0 is valid (only IPs that lost nothing); the core takes 0-100.
	if r.MaxLoss < 0 || r.MaxLoss > 100 {
		r.MaxLoss = 20
	}
	return r
}

func handleSpoofTester(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		writeJSON(w, spoofTesterView())
		return
	}
	if proRequired(w, r, proSpoof, "Spoof Tunnel") {
		return
	}
	var req spoofTesterRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeAPIError(w, r, "E-ACTION-01", "invalid json")
		return
	}
	switch strings.ToLower(strings.TrimSpace(req.Action)) {
	case "stop":
		stopSpoofTester()
		writeJSON(w, map[string]any{"status": "ok"})
	case "clear":
		spoofTesterMu.Lock()
		if spoofTesterCur.Status != "running" {
			spoofTesterCur = spoofTesterStatus{Status: "idle"}
		}
		spoofTesterMu.Unlock()
		writeJSON(w, map[string]any{"status": "ok"})
	case "start":
		if err := startSpoofTester(req.normalize()); err != nil {
			writeAPIError(w, r, "E-ACTION-01", err.Error())
			return
		}
		writeJSON(w, map[string]any{"status": "started", "tester": spoofTesterView()})
	default:
		writeAPIError(w, r, "E-ACTION-01", "unknown action: want start, stop or clear")
	}
}

func startSpoofTester(req spoofTesterRequest) error {
	if req.Mode != "sender" && req.Mode != "receiver" {
		return fmt.Errorf("mode must be sender or receiver")
	}
	if req.Mode == "sender" && CleanHost(req.DstIP) == "" {
		return fmt.Errorf("the destination IP (the receiver server) is required in sender mode")
	}
	if len(req.Sources) == 0 {
		return fmt.Errorf("add at least one source IP, range or CIDR")
	}
	if !engineBinaryPresent(spoofBinName) {
		return fmt.Errorf("the spoof binary is not installed (install it with `hashem spoof` first)")
	}

	spoofTesterMu.Lock()
	if spoofTesterCur.Status == "running" {
		spoofTesterMu.Unlock()
		return fmt.Errorf("a tester run is already in progress")
	}
	if err := os.MkdirAll(spoofDir, 0700); err != nil {
		spoofTesterMu.Unlock()
		return err
	}
	srcFile := filepath.Join(spoofDir, "tester-sources.txt")
	if err := os.WriteFile(srcFile, []byte(strings.Join(req.Sources, "\n")+"\n"), 0600); err != nil {
		spoofTesterMu.Unlock()
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	spoofTesterCancel = cancel
	spoofTesterStart = time.Now()
	spoofTesterDur = time.Duration(req.Timeout) * time.Second
	spoofTesterCur = spoofTesterStatus{Status: "running", Mode: req.Mode, Protocol: req.Protocol,
		Started: spoofTesterStart.Format(time.RFC3339), Passed: []spoofTesterResult{}}
	spoofTesterMu.Unlock()

	args := []string{"tester", "--mode", req.Mode, "--protocol", req.Protocol, "--src-list", srcFile,
		"--timeout", strconv.Itoa(req.Timeout), "--packet-count", strconv.Itoa(req.PacketCount),
		"--max-loss", strconv.FormatFloat(req.MaxLoss, 'f', -1, 64)}
	if req.Mode == "sender" {
		args = append(args, "--dst-ip", CleanHost(req.DstIP), "--dst-port", strconv.Itoa(req.DstPort))
	}

	run := spoofTesterRun
	spoofTesterWG.Add(1)
	go func() {
		defer spoofTesterWG.Done()
		out, err := run(ctx, args)
		passed := parseSpoofTesterOutput(out)
		spoofTesterMu.Lock()
		defer spoofTesterMu.Unlock()
		if ctx.Err() != nil {
			// Stopped: stopSpoofTester recorded it, and a newer run may own
			// the state by now, so touch nothing.
			return
		}
		spoofTesterCancel = nil
		spoofTesterCur.Finished = time.Now().Format(time.RFC3339)
		spoofTesterCur.Progress = 100
		spoofTesterCur.Passed = passed
		if err != nil {
			spoofTesterCur.Status = "error"
			spoofTesterCur.Error = spoofTesterErr(out, err)
			return
		}
		spoofTesterCur.Status = "done"
	}()
	return nil
}

// stopSpoofTester aborts a run. The binary prints its results only when the
// receiver's timeout ends, so a stopped run has none.
func stopSpoofTester() {
	spoofTesterMu.Lock()
	cancel := spoofTesterCancel
	if spoofTesterCur.Status == "running" {
		spoofTesterCur.Status = "stopped"
		spoofTesterCur.Finished = time.Now().Format(time.RFC3339)
	}
	spoofTesterMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// parseSpoofTesterOutput reads the receiver's "IP recv/sent loss%" lines.
func parseSpoofTesterOutput(out string) []spoofTesterResult {
	var res []spoofTesterResult
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		m := spoofTesterLine.FindStringSubmatch(strings.TrimSpace(sc.Text()))
		if m == nil {
			continue
		}
		recv, _ := strconv.Atoi(m[2])
		sent, _ := strconv.Atoi(m[3])
		loss, _ := strconv.ParseFloat(m[4], 64)
		res = append(res, spoofTesterResult{IP: m[1], Received: recv, Sent: sent, LossPct: loss})
	}
	return res
}

// spoofTesterErr is the binary's last log line (its log.Fatalf reason) or err.
func spoofTesterErr(out string, err error) string {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if last := strings.TrimSpace(lines[len(lines)-1]); last != "" {
		return last
	}
	return err.Error()
}

// spoofTesterRunReal runs the tester binary and returns its combined output.
func spoofTesterRunReal(ctx context.Context, args []string) (string, error) {
	cmd := exec.CommandContext(ctx, engineBinaryPath(spoofBinName), args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}
