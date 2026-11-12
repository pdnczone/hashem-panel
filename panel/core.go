package main

// The node core (hashem-node): this same program built with -tags nodecore,
// for a server that is only a node of a central panel. It has no web page,
// no login and no terminal. The central manages it over the node channel
// (node_relay.go), which runs each request inside this process, so the core
// needs no page of its own.
//
// What a core still answers on its port is server-to-server only: the Peer
// Link (the other end of a tunnel: carrier swap, path test, Autopilot), the
// cluster's heartbeats, a sold tunnel's status page and frps's plugin calls.
// Every one of those checks its own secret. Anything else is a plain 404, as
// if nothing were there.
//
// The license check, the Pro gates and the audit log are the panel's own,
// unchanged: a core is the panel without its page, not a second program.
//
// The core keeps the panel's files (/etc/gre-panel) and unit, so a server
// can go from core to panel and back by swapping the binary.

import (
	"net/http"
	"strings"
)

const nodeKindCore = "core"

// nodeLocalKind is what this build reports to its central: a panel reports
// nothing, as the panels from before the core do.
func nodeLocalKind() string {
	if nodeCore {
		return nodeKindCore
	}
	return ""
}

// binName is this build's name in help and logs.
func binName() string {
	if nodeCore {
		return "hashem-node"
	}
	return "gre-panel"
}

// coreNetPrefixes: what a core answers from the network (see the top).
var coreNetPrefixes = []string{peerRoutePrefix + "/", meshRoutePrefix + "/", "/_hs/", "/_hsplugin/"}

// coreNetPath reports whether a core serves path to the network. base is the
// panel's base path without slashes: a peer set up before the fixed prefix
// existed still calls the Peer Link under it.
func coreNetPath(path, base string) bool {
	if strings.Contains(path, "..") || strings.Contains(path, "//") {
		return false
	}
	for _, p := range coreNetPrefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return base != "" && strings.HasPrefix(path, "/"+base+"/api/peer/")
}

// coreGate is the core's front door: on a panel build it is next itself.
func coreGate(next http.Handler) http.Handler { return coreGateFor(nodeCore, next) }

func coreGateFor(core bool, next http.Handler) http.Handler {
	if !core {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		base := cfg.BasePath
		mu.Unlock()
		if !coreNetPath(r.URL.Path, strings.Trim(base, "/")) {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}
