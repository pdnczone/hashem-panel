package main

// The frp version on this server and on the servers at the other end of its
// tunnels. Each side sends its own with the Peer Link handshake and ping;
// Diagnostics warns when they differ (a hub on 0.71.0 with peers on 0.61.1
// was seen in the field: the pair works, but options and fixes of the newer
// one are missing on the other side).

import (
	"context"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

var frpVersionRe = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

// cleanFrpVersion is v when it looks like an frp version ("0.61.1"), else "".
// What a peer sends is shown in Diagnostics, so nothing else gets through.
func cleanFrpVersion(v string) string {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if frpVersionRe.MatchString(v) {
		return v
	}
	return ""
}

var (
	frpVerMu   sync.Mutex
	frpVerVal  string
	frpVerAt   time.Time
	frpVerOnce bool

	// frpVersionRun asks an frp binary for its version; a var for tests.
	frpVersionRun = func(bin string) string {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, bin, "--version").Output()
		if err != nil {
			return ""
		}
		return cleanFrpVersion(string(out))
	}
)

// localFrpVersion is the installed frp ("" when there is none), read from
// frps or frpc at most every 10 minutes.
func localFrpVersion() string {
	frpVerMu.Lock()
	defer frpVerMu.Unlock()
	if frpVerOnce && time.Since(frpVerAt) < 10*time.Minute {
		return frpVerVal
	}
	v := ""
	for _, name := range []string{"frps", "frpc"} {
		if !engineBinaryPresent(name) {
			continue
		}
		if v = frpVersionRun(engineBinaryPath(name)); v != "" {
			break
		}
	}
	frpVerVal, frpVerAt, frpVerOnce = v, time.Now(), true
	return v
}

// frpVersionDrift lists the other servers whose frp differs from local, as
// "name version" (sorted by peer). Empty when local is unknown.
func frpVersionDrift(local, mainPeer string, links map[int]tunnelLink, peers []peerRecord) []string {
	if local == "" {
		return nil
	}
	var out []string
	if mainPeer != "" && mainPeer != local {
		out = append(out, "main tunnel "+mainPeer)
	}
	for _, p := range peers {
		if v := links[p.ID].FrpVersion; v != "" && v != local {
			name := p.Name
			if name == "" {
				name = "peer " + strconv.Itoa(p.ID)
			}
			out = append(out, name+" "+v)
		}
	}
	return out
}
