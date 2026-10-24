package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// 6to4 and 4in6: the GRE tunnel rides on IPv6 (hashem.sh gre6_rebuild).
//
//	6to4  a sit tunnel (IP protocol 41) between the two IPv4 addresses carries
//	      a private IPv6 /64; the GRE device runs on it as ip6gre.
//	4in6  the GRE device runs as ip6gre between the servers' public IPv6
//	      addresses.
//
// The interface keeps its name and inner IPv4, so FRP, Backhaul and the rest
// do not notice. Both ends must use the same carrier: switchCarrier changes
// both, waits for the inner address to answer and puts both back otherwise.
const (
	carrier6to4 = "6to4"
	carrier4in6 = "4in6"
)

func isCarrier6(t string) bool { return t == carrier6to4 || t == carrier4in6 }

// gre6Env reads the ends hashem.sh keeps for GRE interface ifname
// (gre6/IF.env: REMOTE4, LOCAL4, REMOTE6, LOCAL6). An ip6gre device no longer
// shows its IPv4 ends, so this is where they are read from.
func gre6Env(ifname string) map[string]string {
	m := map[string]string{}
	data, err := os.ReadFile(filepath.Join(configDir, "gre6", ifname+".env"))
	if err != nil {
		return m
	}
	for _, l := range strings.Split(string(data), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(l), "="); ok && ipFamily(v) != 0 {
			m[k] = v
		}
	}
	return m
}

// gre6Ends is "remote, local" of an ip6gre interface as public addresses:
// the IPv4 ends under 6to4, the IPv6 ones under 4in6.
func gre6Ends(ifname string) (remote, local string) {
	e := gre6Env(ifname)
	if loadCarrierConfig().ActiveCarrier == carrier4in6 && e["REMOTE6"] != "" {
		return e["REMOTE6"], e["LOCAL6"]
	}
	if e["REMOTE4"] != "" {
		return e["REMOTE4"], e["LOCAL4"]
	}
	return e["REMOTE6"], e["LOCAL6"]
}

// carrier6Opts are the IPv6 ends of a 4in6 tunnel, seen from this server.
type carrier6Opts struct {
	Local6  string `json:"local6,omitempty"`
	Remote6 string `json:"remote6,omitempty"`
}

func (o carrier6Opts) args() []string {
	var a []string
	if o.Local6 != "" {
		a = append(a, "--local6", o.Local6)
	}
	if o.Remote6 != "" {
		a = append(a, "--remote6", o.Remote6)
	}
	return a
}

func (o carrier6Opts) swapped() carrier6Opts {
	return carrier6Opts{Local6: o.Remote6, Remote6: o.Local6}
}

func (o carrier6Opts) validate() error {
	for _, v := range []string{o.Local6, o.Remote6} {
		if v != "" && !validPublicIP(v, 6) {
			return fmt.Errorf("%q is not a public IPv6 address", v)
		}
	}
	return nil
}

// POST /api/peer/carrier-info: what the master needs from this server before
// a switch.
func handlePeerCarrierInfo(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]string{"public_ip6": detectPublicIP6()})
}

func peerPublicIP6() string {
	raw, err := sendToPeer("/api/peer/carrier-info", "POST", struct{}{})
	if err != nil {
		return ""
	}
	var info struct {
		PublicIP6 string `json:"public_ip6"`
	}
	if json.Unmarshal(raw, &info) != nil || !validPublicIP(info.PublicIP6, 6) {
		return ""
	}
	return info.PublicIP6
}

func syncCarrierToPeerOpts(carrier string, o carrier6Opts) error {
	if loadPeerConfig().Role != "master" {
		return nil
	}
	log.Printf("[PeerSync] Commanding peer worker to apply carrier: %s", carrier)
	_, err := sendToPeerTimeout("/api/peer/apply-carrier", "POST", PeerApplyCarrierRequest{Carrier: carrier, Local6: o.Local6, Remote6: o.Remote6}, 40*time.Second)
	return err
}

var (
	carrierVerifyWait = 45 * time.Second
	carrierVerifyTick = 3 * time.Second
	// carrierLinkUp: the peer's inner GRE address answers; swappable for tests.
	carrierLinkUp = func() bool { st, _ := getCarrierPingStatus(); return st == "ok" }
	// peerIP6: the worker's public IPv6; swappable for tests.
	peerIP6 = peerPublicIP6
)

func waitCarrierUp(d time.Duration) bool {
	for end := time.Now().Add(d); ; {
		if carrierLinkUp() {
			return true
		}
		if time.Now().After(end) {
			return false
		}
		time.Sleep(carrierVerifyTick)
	}
}

func peerLinked() bool {
	pc := loadPeerConfig()
	return pc.Role == "master" && pc.PeerSecret != "" && (pc.IsConnected || pc.LastSync != "")
}

// switchCarrier moves the main tunnel to target on this server and, over the
// Peer Link, on the other one. When the carrier changes, the peer's inner
// address must answer within carrierVerifyWait, or both servers go back to
// the carrier they had.
func switchCarrier(target string, o carrier6Opts) (string, error) {
	target = strings.TrimSpace(target)
	if err := carrierApplicable(target); err != nil {
		return "", err
	}
	if strings.HasPrefix(target, "frp:") {
		return applyBenchmarkCarrier(target)
	}
	// A foreign server asks the Iran server, which switches both.
	why := ""
	if pc := loadPeerConfig(); pc.Role == "worker" && pc.PeerSecret != "" {
		detail, asked, err := switchCarrierViaIran(target, o)
		if asked {
			return detail, err
		}
		why = err.Error()
	}
	linked := peerLinked()
	if target == carrier4in6 {
		if o.Local6 == "" {
			o.Local6 = detectPublicIP6()
		}
		if o.Remote6 == "" && linked {
			o.Remote6 = peerIP6()
		}
		if o.Local6 == "" {
			return "", fmt.Errorf("4in6 needs a public IPv6 address on this server; none was found")
		}
		if o.Remote6 == "" {
			return "", fmt.Errorf("4in6 needs the public IPv6 address of the other server")
		}
	}
	if err := o.validate(); err != nil {
		return "", err
	}
	prev := loadCarrierConfig().ActiveCarrier
	if out, err := applyCarrierModeOpts(target, o); err != nil && !strings.Contains(err.Error(), "script not found") {
		return "", fmt.Errorf("this server could not switch to %s: %v %s", target, err, strings.TrimSpace(out))
	}
	if !linked {
		if why != "" {
			return "Applied carrier " + target + " on this server only (" + why + "): apply the same carrier on the Iran server", nil
		}
		return "Applied carrier " + target + " on this server only (no Peer Link): apply the same carrier on the other server", nil
	}
	back := func() {
		if prev != "" && prev != target {
			_, _ = applyCarrierMode(prev)
		}
	}
	if err := syncCarrierToPeerOpts(target, o.swapped()); err != nil {
		back()
		return "", fmt.Errorf("the other server could not switch to %s (%v); this server is back on %s", target, err, prev)
	}
	if prev != target && !waitCarrierUp(carrierVerifyWait) {
		_ = syncCarrierToPeerOpts(prev, carrier6Opts{})
		back()
		LogSecurityAudit("carrier_switch_undone", "admin", "127.0.0.1", "target="+target+" back="+prev)
		return "", fmt.Errorf("the tunnel did not answer over %s within %s; both servers are back on %s", target, carrierVerifyWait, prev)
	}
	LogSecurityAudit("carrier_switched", "admin", "127.0.0.1", "target="+target)
	return "Both servers now use " + target, nil
}

// ---- switching the wrap from the foreign server ----

// wrapRequest is a GRE wrap switch one server asks the other for; the IPv6
// ends are seen from the receiver.
type wrapRequest struct {
	Target string `json:"target"`
	carrier6Opts
}

// wrapJob is the GRE wrap switch the foreign server asked this Iran server for.
type wrapJob struct {
	State  string `json:"state"` // running | ok | failed
	Target string `json:"target"`
	Detail string `json:"detail,omitempty"`
	Error  string `json:"error,omitempty"`
	Seq    int    `json:"seq"`
}

var (
	wrapJobMu  sync.Mutex
	wrapJobNow wrapJob
	// vars for tests
	wrapSwitchFn  = switchCarrier
	wrapPollEvery = 2 * time.Second
)

// switchCarrierViaIran asks the Iran server to switch the GRE wrap of the
// main tunnel on both servers and waits for the end. asked=false: the Iran
// panel could not be asked (err says why) and nothing changed.
func switchCarrierViaIran(target string, o carrier6Opts) (detail string, asked bool, err error) {
	req := wrapRequest{Target: target, carrier6Opts: o.swapped()}
	if target == carrier4in6 && req.Remote6 == "" {
		req.Remote6 = detectPublicIP6()
	}
	status, data, err := peerCallJSON("POST", "/api/peer/wrap-request", req, 15*time.Second)
	switch {
	case err != nil:
		return "", false, fmt.Errorf("the Iran server's panel could not be reached: %v", err)
	case status == http.StatusNotFound && data == nil:
		return "", false, errOldIranPanel
	case status != http.StatusOK:
		return "", true, peerAnswerErr(data)
	}
	var acc struct {
		Seq int `json:"seq"`
	}
	_ = json.Unmarshal(data, &acc)
	log.Printf("[PeerSync] the Iran server switches the GRE wrap to %s", target)
	// The Iran server waits up to carrierVerifyWait for the tunnel, then as
	// long again to put both back.
	for end := time.Now().Add(2*carrierVerifyWait + 90*time.Second); time.Now().Before(end); {
		time.Sleep(wrapPollEvery)
		_, d, err := peerCallJSON("GET", "/api/peer/wrap-request", nil, 5*time.Second)
		var j wrapJob
		if err != nil || json.Unmarshal(d, &j) != nil || j.Seq != acc.Seq {
			continue // the link may drop for a moment while the wrap changes
		}
		switch j.State {
		case "ok":
			return j.Detail, true, nil
		case "failed":
			return "", true, errors.New(j.Error)
		}
	}
	return "", true, errors.New("the Iran server did not report the end of the switch in time: check the GRE wrap on both servers")
}

// POST /api/peer/wrap-request (Iran side): the foreign server of the main
// tunnel asks for a GRE wrap switch. It runs as if it was started on this
// panel; the foreign server polls GET for the end.
func handlePeerWrapRequest(w http.ResponseWriter, r *http.Request) {
	var req wrapRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&req); err != nil {
		writeAPIError(w, r, "E-ACTION-01", "invalid json")
		return
	}
	t := strings.TrimSpace(req.Target)
	if err := carrierApplicable(t); err != nil || strings.HasPrefix(t, "frp:") {
		writeAPIError(w, r, "E-ACTION-01", fmt.Sprintf("not a GRE wrap: %q", t))
		return
	}
	if swapCallerTunnel(r) > 0 {
		writeAPIError(w, r, "E-ACTION-01", "the GRE wrap of this tunnel is changed on the Iran server (Edit peer)")
		return
	}
	if loadPeerConfig().Role != "master" {
		writeAPIError(w, r, "E-ACTION-01", "this server is not the Iran side of the Peer Link")
		return
	}
	wrapJobMu.Lock()
	if wrapJobNow.State == "running" {
		wrapJobMu.Unlock()
		writeAPIError(w, r, "E-ACTION-01", "a GRE wrap switch is already running")
		return
	}
	wrapJobNow = wrapJob{State: "running", Target: t, Seq: wrapJobNow.Seq + 1}
	seq := wrapJobNow.Seq
	wrapJobMu.Unlock()
	LogSecurityAudit("carrier_switch_requested", "peer", ClientIP(r), "target="+t)
	writeJSON(w, map[string]any{"status": "accepted", "seq": seq})

	go func() {
		detail, err := wrapSwitchFn(t, req.carrier6Opts)
		wrapJobMu.Lock()
		defer wrapJobMu.Unlock()
		if wrapJobNow.Seq != seq {
			return
		}
		if err != nil {
			wrapJobNow.State, wrapJobNow.Error = "failed", err.Error()
			return
		}
		wrapJobNow.State, wrapJobNow.Detail = "ok", detail
	}()
}

// GET /api/peer/wrap-request (Iran side): the last requested switch.
func handlePeerWrapStatus(w http.ResponseWriter, r *http.Request) {
	wrapJobMu.Lock()
	j := wrapJobNow
	wrapJobMu.Unlock()
	writeJSON(w, j)
}
