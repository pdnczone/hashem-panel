package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Per-proxy FRP options set in the Performance tab of the foreign server. They
// live in frpc.toml (frps only accepts the proxies), so the Iran server cannot
// set them: perf apply writes them into every [[proxies]] block.
//
//   - PROXY protocol (tcp): frpc puts the user's real IP in front of each
//     connection to the local service. The service must accept it (Xray:
//     acceptProxyProtocol), or every connection fails.
//   - Bandwidth limit (tcp and udp): a cap per forwarded port.
//   - Health check (tcp): frpc checks the local service and takes the port off
//     the Iran server while it is down, so users fail fast instead of hanging.
const perfBandwidthMax = 10000 // MB/s

func validProxyProtocol(v string) bool { return v == "off" || v == "v1" || v == "v2" }

// frpcProxyExtras renders the option lines for one proxy block.
func frpcProxyExtras(c perfConfig, tcp bool) string {
	var b strings.Builder
	if tcp && (c.ProxyProtocol == "v1" || c.ProxyProtocol == "v2") {
		fmt.Fprintf(&b, "transport.proxyProtocolVersion = %q\n", c.ProxyProtocol)
	}
	if c.BandwidthMB > 0 {
		fmt.Fprintf(&b, "transport.bandwidthLimit = \"%dMB\"\ntransport.bandwidthLimitMode = \"client\"\n", c.BandwidthMB)
	}
	if tcp && c.HealthCheck {
		b.WriteString("healthCheck.type = \"tcp\"\nhealthCheck.timeoutSeconds = 3\nhealthCheck.maxFailed = 3\nhealthCheck.intervalSeconds = 10\n")
	}
	return b.String()
}

// liveProxyProtocol is the PROXY protocol version in the running frpc.toml:
// "v1", "v2", "off", or "" without frpc.toml.
func liveProxyProtocol() string {
	data, err := os.ReadFile(filepath.Join(frpDir, "frpc.toml"))
	if err != nil {
		return ""
	}
	s := string(data)
	switch {
	case strings.Contains(s, `proxyProtocolVersion = "v2"`):
		return "v2"
	case strings.Contains(s, `proxyProtocolVersion = "v1"`):
		return "v1"
	}
	return "off"
}
