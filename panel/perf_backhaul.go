package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
)

// Backhaul connection pool: how many connections the foreign server (the
// Backhaul client) keeps open to the Iran server, ready for new users. Saved in
// perf.json as backhaul_pool, so a new setup from the panel or hashem.sh
// (backhaul_pool_size) writes the same value.
const (
	bhPoolDefault        = 8
	bhPoolMin, bhPoolMax = 1, 64
)

var bhPoolLine = regexp.MustCompile(`(?m)^([ \t]*connection_pool[ \t]*=[ \t]*)\d+`)

func backhaulPoolSize() int {
	if n := loadPerfConfig().BackhaulPool; n >= bhPoolMin && n <= bhPoolMax {
		return n
	}
	return bhPoolDefault
}

// backhaulConfigs lists this server's Backhaul configs for one service
// ("backhaul-client" or "backhaul-server").
func backhaulConfigs(svc string) []string {
	var out []string
	for _, c := range staleConfigCandidates() {
		if c.svc == svc && fileExists(c.path) {
			out = append(out, c.path)
		}
	}
	return out
}

// backhaulRole is "foreign" when this server dials (Backhaul client), "iran"
// when it listens, "" without Backhaul.
func backhaulRole() string {
	if len(backhaulConfigs("backhaul-client")) > 0 {
		return "foreign"
	}
	if len(backhaulConfigs("backhaul-server")) > 0 {
		return "iran"
	}
	return ""
}

// liveBackhaulPool is connection_pool in the running client config, 0 when none.
func liveBackhaulPool() int {
	for _, p := range backhaulConfigs("backhaul-client") {
		if data, err := os.ReadFile(p); err == nil {
			if n := tomlInt(string(data), "connection_pool"); n > 0 {
				return n
			}
		}
	}
	return 0
}

// applyBackhaulPool writes n into each client config and restarts
// backhaul-client only when a file changed.
func applyBackhaulPool(n int) (bool, error) {
	paths := backhaulConfigs("backhaul-client")
	if len(paths) == 0 {
		return false, nil
	}
	changed := false
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			return changed, err
		}
		if !bhPoolLine.Match(data) {
			return changed, fmt.Errorf("%s has no connection_pool line: set the tunnel up again", p)
		}
		out := bhPoolLine.ReplaceAll(data, []byte("${1}"+strconv.Itoa(n)))
		if bytes.Equal(out, data) {
			continue
		}
		if err := writeTokenFile(p, out); err != nil {
			return changed, err
		}
		changed = true
	}
	if changed {
		if err := runSystemctl("restart", "backhaul-client"); err != nil {
			return true, errors.New("backhaul-client did not restart: " + err.Error())
		}
	}
	return changed, nil
}
