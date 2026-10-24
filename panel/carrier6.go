package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
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
