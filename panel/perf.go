package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type perfConfig struct {
	ProxyEncryption  bool `json:"proxy_encryption"`
	ProxyCompression bool `json:"proxy_compression"`
	// AutoPool: true (default, also when the key is missing) lets hashem.sh size the pool;
	// false applies FRPPoolCount / FRPMaxPool as typed.
	AutoPool     bool `json:"auto_pool"`
	FRPPoolCount int  `json:"frp_pool_count"`
	FRPMaxPool   int  `json:"frp_max_pool"`
	// TCPMux: nil = never configured (live tomls are left untouched on apply);
	// false = speed-first (default for new tunnels); true = frp tcpMux on.
	TCPMux *bool `json:"tcp_mux,omitempty"`
	// BackhaulPool: connection_pool of the Backhaul client; 0 = default (8).
	BackhaulPool int `json:"backhaul_pool,omitempty"`
	// FRP proxy options (perf_frp.go). ProxyProtocol "" = leave frpc.toml as it is.
	ProxyProtocol string `json:"proxy_protocol,omitempty"`
	BandwidthMB   int    `json:"bandwidth_limit_mb,omitempty"`
	HealthCheck   bool   `json:"health_check,omitempty"`
}

// autoPoolState mirrors the auto_pool.json that hashem.sh autopool_tick maintains.
type autoPoolState struct {
	Pool              int    `json:"pool"`
	MaxPool           int    `json:"max_pool"`
	AppliedPool       int    `json:"applied_pool"`
	QuietTicks        int    `json:"quiet_ticks"`
	LastTick          int64  `json:"last_tick"`
	LastChange        int64  `json:"last_change"`
	LastRestart       int64  `json:"last_restart"`
	LastDecision      string `json:"last_decision"`
	LastReason        string `json:"last_reason"`
	ErrorsLastTick    int    `json:"errors_last_tick"`
	ActiveConns       int    `json:"active_conns"`
	FRPSRestartNeeded bool   `json:"frps_restart_needed"`
}

type perfStatusResponse struct {
	ProxyEncryption   bool            `json:"proxy_encryption"`
	ProxyCompression  bool            `json:"proxy_compression"`
	AutoPool          bool            `json:"auto_pool"`
	FRPPoolCount      int             `json:"frp_pool_count"`
	FRPMaxPool        int             `json:"frp_max_pool"`
	EffectivePool     int             `json:"effective_pool_count"`
	EffectiveMaxPool  int             `json:"effective_max_pool"`
	AutoPoolState     autoPoolState   `json:"auto_pool_state"`
	TCPMux            bool            `json:"tcp_mux"`
	TCPMuxSet         bool            `json:"tcp_mux_set"`
	TCPMuxLive        string          `json:"tcp_mux_live"`
	InSync            bool            `json:"in_sync"`
	SyncDetails       string          `json:"sync_details"`
	Role              string          `json:"role"`
	Engine            string          `json:"engine"` // "frp", "backhaul" or "" (no tunnel)
	Overridden        map[string]bool `json:"overridden,omitempty"`
	Net               netStackStatus  `json:"net"`
	BackhaulPool      int             `json:"backhaul_pool"`       // saved (or default) pool
	BackhaulPoolLive  int             `json:"backhaul_pool_live"`  // in the running client config, 0 = none
	BackhaulRole      string          `json:"backhaul_role"`       // "foreign", "iran" or ""
	ProxyProtocol     string          `json:"proxy_protocol"`      // saved, or what frpc.toml runs when never saved
	ProxyProtocolLive string          `json:"proxy_protocol_live"` // "v1", "v2", "off" or "" (no frpc.toml)
	BandwidthMB       int             `json:"bandwidth_limit_mb"`
	HealthCheck       bool            `json:"health_check"`
}

// netStackStatus is the kernel side of throughput: what Optimize Network sets.
type netStackStatus struct {
	Known        bool   `json:"known"`
	CC           string `json:"cc"`
	Qdisc        string `json:"qdisc"`
	RmemMax      int    `json:"rmem_max"`
	WmemMax      int    `json:"wmem_max"`
	Conntrack    int    `json:"conntrack"`
	ConntrackMax int    `json:"conntrack_max"`
	GREMTU       int    `json:"gre_mtu"`
	PathMTU      int    `json:"path_mtu,omitempty"` // saved by Quick Repair when 1380 does not cross
	MSSRule      string `json:"mss_rule"`           // "1340", "pmtu" or ""
	Persisted    bool   `json:"persisted"`
	Backup       bool   `json:"backup"`
}

// Pool bounds, shared by the API and the inputs in the Performance tab.
const (
	perfPoolMin, perfPoolMax       = 2, 1000
	perfMaxPoolMin, perfMaxPoolMax = 10, 2000
)

type perfPostRequest struct {
	Action           string  `json:"action"`
	ProxyEncryption  *bool   `json:"proxy_encryption,omitempty"`
	ProxyCompression *bool   `json:"proxy_compression,omitempty"`
	AutoPool         *bool   `json:"auto_pool,omitempty"`
	FRPPoolCount     *int    `json:"frp_pool_count,omitempty"`
	FRPMaxPool       *int    `json:"frp_max_pool,omitempty"`
	TCPMux           *bool   `json:"tcp_mux,omitempty"`
	BackhaulPool     *int    `json:"backhaul_pool,omitempty"`
	ProxyProtocol    *string `json:"proxy_protocol,omitempty"`
	BandwidthMB      *int    `json:"bandwidth_limit_mb,omitempty"`
	HealthCheck      *bool   `json:"health_check,omitempty"`
}

func perfConfigPath() string {
	return filepath.Join(configDir, "perf.json")
}

func defaultPerfConfig() perfConfig {
	return perfConfig{
		AutoPool:     true,
		FRPPoolCount: 20,
		FRPMaxPool:   60,
	}
}

func boolPtr(b bool) *bool { return &b }

// loadPerfConfig reads perf.json. Keys of removed features are ignored and disappear on the next save.
func loadPerfConfig() perfConfig {
	def := defaultPerfConfig()
	data, err := os.ReadFile(perfConfigPath())
	if err != nil {
		return def
	}
	var raw struct {
		ProxyEncryption  *bool  `json:"proxy_encryption"`
		ProxyCompression *bool  `json:"proxy_compression"`
		AutoPool         *bool  `json:"auto_pool"`
		FRPPoolCount     *int   `json:"frp_pool_count"`
		FRPMaxPool       *int   `json:"frp_max_pool"`
		TCPMux           *bool  `json:"tcp_mux"`
		BackhaulPool     *int   `json:"backhaul_pool"`
		ProxyProtocol    string `json:"proxy_protocol"`
		BandwidthMB      int    `json:"bandwidth_limit_mb"`
		HealthCheck      bool   `json:"health_check"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return def
	}
	c := def
	if raw.ProxyEncryption != nil {
		c.ProxyEncryption = *raw.ProxyEncryption
	}
	if raw.ProxyCompression != nil {
		c.ProxyCompression = *raw.ProxyCompression
	}
	if raw.AutoPool != nil {
		c.AutoPool = *raw.AutoPool
	}
	if raw.FRPPoolCount != nil && *raw.FRPPoolCount >= 2 {
		c.FRPPoolCount = *raw.FRPPoolCount
	}
	if raw.FRPMaxPool != nil && *raw.FRPMaxPool >= 10 {
		c.FRPMaxPool = *raw.FRPMaxPool
	}
	if raw.TCPMux != nil {
		v := *raw.TCPMux
		c.TCPMux = &v
	}
	if raw.BackhaulPool != nil && *raw.BackhaulPool >= bhPoolMin && *raw.BackhaulPool <= bhPoolMax {
		c.BackhaulPool = *raw.BackhaulPool
	}
	if validProxyProtocol(raw.ProxyProtocol) {
		c.ProxyProtocol = raw.ProxyProtocol
	}
	if raw.BandwidthMB > 0 && raw.BandwidthMB <= perfBandwidthMax {
		c.BandwidthMB = raw.BandwidthMB
	}
	c.HealthCheck = raw.HealthCheck
	return c
}

func autoPoolStatePath() string {
	return filepath.Join(configDir, "auto_pool.json")
}

func loadAutoPoolState() autoPoolState {
	var st autoPoolState
	if data, err := os.ReadFile(autoPoolStatePath()); err == nil {
		_ = json.Unmarshal(data, &st)
	}
	return st
}

// saveAutoPoolState writes st atomically to auto_pool.json.
func saveAutoPoolState(st autoPoolState) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp := autoPoolStatePath() + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, autoPoolStatePath())
}

// effectivePoolValues returns the poolCount / maxPoolCount every frps/frpc writer must use.
// Auto mode follows auto_pool.json if populated, falling back to 20/60.
// Manual mode follows perf.json FRPPoolCount / FRPMaxPool.
// maxPoolCount is never below 1.5 * poolCount.
func effectivePoolValues() (int, int) {
	c := loadPerfConfig()
	pool, maxPool := c.FRPPoolCount, c.FRPMaxPool
	if c.AutoPool {
		st := loadAutoPoolState()
		pool, maxPool = 20, 60
		if st.Pool > 0 {
			pool = st.Pool
		}
		if st.MaxPool > 0 {
			maxPool = st.MaxPool
		}
	}
	if need := (pool*3 + 1) / 2; maxPool < need {
		maxPool = need
	}
	return pool, maxPool
}

// tcpMuxEnabled is the value NEW frps/frpc tomls get: speed-first default is OFF
// (measured: tcpMux halves FRP throughput over GRE) unless the operator turned it on.
func tcpMuxEnabled() bool {
	c := loadPerfConfig()
	return c.TCPMux != nil && *c.TCPMux
}

// tcpMuxTomlLines renders the tcpMux lines for a freshly written toml.
func tcpMuxTomlLines() string { return tcpMuxTomlLinesFor(tcpMuxEnabled()) }

// tcpMuxTomlLinesFor renders the tcpMux lines for an explicit value.
func tcpMuxTomlLinesFor(mux bool) string {
	if mux {
		return "transport.tcpMux = true\ntransport.tcpMuxKeepaliveInterval = 30\n"
	}
	return "transport.tcpMux = false\n"
}

// liveTCPMux reports the tcpMux value found in the live frp tomls: "on", "off",
// "mixed" (hub and peers disagree) or "" when no toml exists. frp treats a missing
// key as true, so only an explicit "false" counts as off.
func liveTCPMux() string {
	files, _ := filepath.Glob(filepath.Join(frpDir, "frp[sc]*.toml"))
	seenOn, seenOff := false, false
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		off := false
		for _, ln := range strings.Split(string(data), "\n") {
			ln = strings.TrimSpace(ln)
			if strings.HasPrefix(ln, "transport.tcpMux") && !strings.HasPrefix(ln, "transport.tcpMuxKeepalive") {
				parts := strings.SplitN(ln, "=", 2)
				if len(parts) == 2 && strings.TrimSpace(parts[1]) == "false" {
					off = true
				}
			}
		}
		if off {
			seenOff = true
		} else {
			seenOn = true
		}
	}
	switch {
	case seenOn && seenOff:
		return "mixed"
	case seenOff:
		return "off"
	case seenOn:
		return "on"
	}
	return ""
}

func savePerfConfig(c perfConfig) error {
	_ = os.MkdirAll(configDir, 0700)
	if c.FRPMaxPool <= 0 {
		c.FRPMaxPool = 60
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(perfConfigPath(), append(data, '\n'), 0600)
}

func effectivePerfConfig() (perfConfig, map[string]bool) {
	c := loadPerfConfig()
	overridden := map[string]bool{}
	if v := os.Getenv("PERF_ENC"); v != "" {
		c.ProxyEncryption = (v == "1" || strings.ToLower(v) == "true")
		overridden["proxy_encryption"] = true
	}
	if v := os.Getenv("PERF_COMP"); v != "" {
		c.ProxyCompression = (v == "1" || strings.ToLower(v) == "true")
		overridden["proxy_compression"] = true
	}
	return c, overridden
}

// tomlInt returns the integer value of a top-level "key = N" line, 0 when absent.
func tomlInt(content, key string) int {
	for _, ln := range strings.Split(content, "\n") {
		ln = strings.TrimSpace(ln)
		if !strings.HasPrefix(ln, key) {
			continue
		}
		parts := strings.SplitN(ln, "=", 2)
		if len(parts) == 2 && strings.TrimSpace(parts[0]) == key {
			var n int
			if _, err := fmt.Sscanf(strings.TrimSpace(parts[1]), "%d", &n); err == nil {
				return n
			}
		}
	}
	return 0
}

func checkLiveTomlSync(c perfConfig) (bool, string, string) {
	if c.TCPMux != nil {
		want := "on"
		if !*c.TCPMux {
			want = "off"
		}
		if live := liveTCPMux(); live != "" && live != want {
			role := "none"
			if _, err := os.Stat(filepath.Join(frpDir, "frpc.toml")); err == nil {
				role = "foreign"
			} else if matches, _ := filepath.Glob(filepath.Join(frpDir, "frps*.toml")); len(matches) > 0 {
				role = "iran"
			}
			return false, fmt.Sprintf("TCP multiplexing (%s) does not match live toml (%s)", want, live), role
		}
	}
	role := "none"
	if _, err := os.Stat(filepath.Join(frpDir, "frpc.toml")); err == nil {
		role = "foreign"
	} else if matches, _ := filepath.Glob(filepath.Join(frpDir, "frps*.toml")); len(matches) > 0 {
		role = "iran"
	}

	switch role {
	case "foreign":
		data, err := os.ReadFile(filepath.Join(frpDir, "frpc.toml"))
		if err != nil {
			return false, "cannot read " + filepath.Join(frpDir, "frpc.toml"), role
		}
		content := string(data)
		hasEnc := strings.Contains(content, "transport.useEncryption = true") || strings.Contains(content, "transport.useEncryption=true")
		hasComp := strings.Contains(content, "transport.useCompression = true") || strings.Contains(content, "transport.useCompression=true")

		if c.ProxyEncryption != hasEnc {
			return false, fmt.Sprintf("Proxy encryption (%v) does not match frpc.toml (%v)", c.ProxyEncryption, hasEnc), role
		}
		if c.ProxyCompression != hasComp {
			return false, fmt.Sprintf("Proxy compression (%v) does not match frpc.toml (%v)", c.ProxyCompression, hasComp), role
		}
		if live := liveProxyProtocol(); c.ProxyProtocol != "" && live != c.ProxyProtocol {
			return false, fmt.Sprintf("PROXY protocol (%s) does not match frpc.toml (%s)", c.ProxyProtocol, live), role
		}
		if hasBW := strings.Contains(content, fmt.Sprintf("transport.bandwidthLimit = \"%dMB\"", c.BandwidthMB)); c.BandwidthMB > 0 && !hasBW || c.BandwidthMB == 0 && strings.Contains(content, "transport.bandwidthLimit") {
			return false, "Bandwidth limit does not match frpc.toml", role
		}
		if hasHC := strings.Contains(content, "healthCheck.type"); hasHC != c.HealthCheck {
			return false, fmt.Sprintf("Health check (%v) does not match frpc.toml (%v)", c.HealthCheck, hasHC), role
		}
		if !c.AutoPool {
			if live := tomlInt(content, "transport.poolCount"); live != c.FRPPoolCount {
				return false, fmt.Sprintf("poolCount (%d) does not match frpc.toml (%d)", c.FRPPoolCount, live), role
			}
		}
		return true, "All settings match live frpc.toml", role
	case "iran":
		hub := filepath.Join(frpDir, "frps.toml")
		if !fileExists(hub) {
			if matches, _ := filepath.Glob(filepath.Join(frpDir, "frps*.toml")); len(matches) > 0 {
				hub = matches[0]
			}
		}
		data, err := os.ReadFile(hub)
		if err != nil {
			return false, "cannot read " + hub, role
		}
		if !c.AutoPool {
			if live := tomlInt(string(data), "transport.maxPoolCount"); live != c.FRPMaxPool {
				return false, fmt.Sprintf("maxPoolCount (%d) does not match %s (%d)", c.FRPMaxPool, filepath.Base(hub), live), role
			}
		}
		return true, "All settings match live " + filepath.Base(hub), role
	default:
		return true, "No tunnel configured yet", role
	}
}

func runPerfCmd(args ...string) (string, error) {
	script, err := greScriptPath()
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", append([]string{script}, args...)...)
	cmd.Env = append(os.Environ(), "GRE_SKIP_PANEL=1", "TERM=dumb", "GRE_PANEL_DIR="+configDir)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	runErr := cmd.Run()
	return strings.TrimSpace(buf.String()), runErr
}

func handlePerfGet(w http.ResponseWriter, r *http.Request) {
	if proRequired(w, r, proPerformance, "Performance") {
		return
	}
	c, over := effectivePerfConfig()
	inSync, details, role := checkLiveTomlSync(c)
	ePool, eMax := effectivePoolValues()

	resp := perfStatusResponse{
		ProxyEncryption:   c.ProxyEncryption,
		ProxyCompression:  c.ProxyCompression,
		AutoPool:          c.AutoPool,
		FRPPoolCount:      c.FRPPoolCount,
		FRPMaxPool:        c.FRPMaxPool,
		EffectivePool:     ePool,
		EffectiveMaxPool:  eMax,
		AutoPoolState:     loadAutoPoolState(),
		TCPMux:            c.TCPMux != nil && *c.TCPMux,
		TCPMuxSet:         c.TCPMux != nil,
		TCPMuxLive:        liveTCPMux(),
		InSync:            inSync,
		SyncDetails:       details,
		Role:              role,
		Engine:            perfEngine(),
		Overridden:        over,
		Net:               readNetStack(),
		BackhaulPool:      backhaulPoolSize(),
		BackhaulPoolLive:  liveBackhaulPool(),
		BackhaulRole:      backhaulRole(),
		ProxyProtocol:     c.ProxyProtocol,
		ProxyProtocolLive: liveProxyProtocol(),
		BandwidthMB:       c.BandwidthMB,
		HealthCheck:       c.HealthCheck,
	}
	if resp.ProxyProtocol == "" { // never set here: show what runs
		resp.ProxyProtocol = resp.ProxyProtocolLive
	}
	writeJSON(w, resp)
}

// perfEngine names the tunnel engine from its config files, without running
// a command: "frp", "backhaul", or "" when no tunnel is set up.
func perfEngine() string {
	if m, _ := filepath.Glob(filepath.Join(frpDir, "frp[sc]*.toml")); len(m) > 0 {
		return "frp"
	}
	for _, c := range staleConfigCandidates() {
		if c.engine == "backhaul" && fileExists(c.path) {
			return "backhaul"
		}
	}
	return ""
}

func procInt(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	v, _ := strconv.Atoi(strings.TrimSpace(string(data)))
	return v
}

func procStr(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// readNetStack reads the live kernel values that Optimize Network changes.
func readNetStack() netStackStatus {
	if runtime.GOOS == "windows" { // local development: show a tuned host
		return netStackStatus{Known: true, CC: "bbr", Qdisc: "fq", RmemMax: 16777216, WmemMax: 16777216,
			Conntrack: 1834, ConntrackMax: 262144, GREMTU: 1380, MSSRule: "1340", Persisted: true, Backup: true}
	}
	ns := netStackStatus{
		CC:        procStr("/proc/sys/net/ipv4/tcp_congestion_control"),
		Qdisc:     procStr("/proc/sys/net/core/default_qdisc"),
		RmemMax:   procInt("/proc/sys/net/core/rmem_max"),
		WmemMax:   procInt("/proc/sys/net/core/wmem_max"),
		GREMTU:    interfaceMTU("gre-tunnel"),
		PathMTU:   savedPathMTU(),
		Persisted: fileExists("/etc/sysctl.d/99-gre-tune.conf"),
		Backup:    fileExists(filepath.Join(configDir, "tune.bak")),
	}
	ns.Known = ns.CC != ""
	ns.Conntrack = procInt("/proc/sys/net/netfilter/nf_conntrack_count")
	if ns.ConntrackMax = procInt("/proc/sys/net/netfilter/nf_conntrack_max"); ns.ConntrackMax == 0 {
		ns.ConntrackMax = procInt("/proc/sys/net/nf_conntrack_max")
	}
	if out, err := runCmdTimeoutOut(3*time.Second, "iptables-save", "-t", "mangle"); err == nil {
		ns.MSSRule = mssRuleFrom(string(out))
	}
	return ns
}

// validPoolValues checks typed pool sizes; nil values were not sent.
func validPoolValues(pool, maxPool *int) error {
	if pool != nil && (*pool < perfPoolMin || *pool > perfPoolMax) {
		return fmt.Errorf("pool count must be between %d and %d", perfPoolMin, perfPoolMax)
	}
	if maxPool != nil && (*maxPool < perfMaxPoolMin || *maxPool > perfMaxPoolMax) {
		return fmt.Errorf("max pool count must be between %d and %d", perfMaxPoolMin, perfMaxPoolMax)
	}
	return nil
}

func handlePerfPost(w http.ResponseWriter, r *http.Request) {
	if proRequired(w, r, proPerformance, "Performance") {
		return
	}
	var body perfPostRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeAPIError(w, r, "E-PERF-01", "invalid request body")
		return
	}

	c := loadPerfConfig()
	if err := validPoolValues(body.FRPPoolCount, body.FRPMaxPool); err != nil {
		writeAPIError(w, r, "E-PERF-01", err.Error())
		return
	}
	if body.ProxyProtocol != nil && !validProxyProtocol(*body.ProxyProtocol) {
		writeAPIError(w, r, "E-PERF-01", "proxy_protocol must be off, v1 or v2")
		return
	}
	if body.BandwidthMB != nil && (*body.BandwidthMB < 0 || *body.BandwidthMB > perfBandwidthMax) {
		writeAPIError(w, r, "E-PERF-01", fmt.Sprintf("the bandwidth limit must be from 0 (none) to %d MB/s", perfBandwidthMax))
		return
	}
	// FRP proxy options, for the actions that save the FRP Transport card
	frpOpts := func() {
		if body.ProxyProtocol != nil {
			c.ProxyProtocol = *body.ProxyProtocol
		}
		if body.BandwidthMB != nil {
			c.BandwidthMB = *body.BandwidthMB
		}
		if body.HealthCheck != nil {
			c.HealthCheck = *body.HealthCheck
		}
	}

	switch body.Action {
	case "update":
		if body.ProxyEncryption != nil {
			c.ProxyEncryption = *body.ProxyEncryption
		}
		if body.ProxyCompression != nil {
			c.ProxyCompression = *body.ProxyCompression
		}
		if body.FRPPoolCount != nil {
			c.FRPPoolCount = *body.FRPPoolCount
		}
		if body.FRPMaxPool != nil {
			c.FRPMaxPool = *body.FRPMaxPool
		}
		if body.TCPMux != nil {
			v := *body.TCPMux
			c.TCPMux = &v
		}
		frpOpts()
		if body.AutoPool != nil {
			c.AutoPool = *body.AutoPool
			if c.AutoPool {
				// Auto-Pool runs from the hashem-watchdog timer (autopool_tick).
				defer ensureWatchdogTimer()
			}
		}
		if err := savePerfConfig(c); err != nil {
			writeAPIError(w, r, "E-PERF-02", "failed to save config: "+err.Error())
			return
		}
		recordError("E-PERF-00", "perf", "Performance settings updated")
		writeJSON(w, map[string]string{"status": "ok", "detail": "Settings updated in perf.json"})

	case "set-tuning":
		if body.FRPPoolCount != nil {
			c.FRPPoolCount = *body.FRPPoolCount
		}
		if body.FRPMaxPool != nil {
			c.FRPMaxPool = *body.FRPMaxPool
		}
		if body.AutoPool != nil {
			c.AutoPool = *body.AutoPool
			if c.AutoPool {
				// Auto-Pool runs from the hashem-watchdog timer (autopool_tick).
				defer ensureWatchdogTimer()
			}
		}
		if err := savePerfConfig(c); err != nil {
			writeAPIError(w, r, "E-PERF-02", "failed to save config: "+err.Error())
			return
		}
		out, err := runPerfCmd("perf", "apply")
		if err != nil {
			recordError("E-PERF-03", "perf", "Apply failed: "+out)
			writeAPIError(w, r, "E-PERF-03", out)
			return
		}
		recordError("E-PERF-00", "perf", "FRP capacity tuning updated and applied")
		writeJSON(w, map[string]string{"status": "ok", "detail": "Capacity tuning applied successfully"})

	case "apply":
		if body.AutoPool != nil {
			c.AutoPool = *body.AutoPool
			if c.AutoPool {
				// Auto-Pool runs from the hashem-watchdog timer (autopool_tick).
				defer ensureWatchdogTimer()
			}
		}
		if body.ProxyEncryption != nil {
			c.ProxyEncryption = *body.ProxyEncryption
		}
		if body.ProxyCompression != nil {
			c.ProxyCompression = *body.ProxyCompression
		}
		if body.TCPMux != nil {
			v := *body.TCPMux
			c.TCPMux = &v
		}
		frpOpts()
		if err := savePerfConfig(c); err != nil {
			writeAPIError(w, r, "E-PERF-02", "failed to save config: "+err.Error())
			return
		}

		out, err := runPerfCmd("perf", "apply")
		if err != nil {
			recordError("E-PERF-03", "perf", "Apply failed: "+out)
			writeAPIError(w, r, "E-PERF-03", out)
			return
		}
		recordError("E-PERF-00", "perf", "Performance settings applied and tunnels restarted")
		writeJSON(w, map[string]string{"status": "ok", "detail": out})

	case "backhaul-pool":
		if body.BackhaulPool == nil || *body.BackhaulPool < bhPoolMin || *body.BackhaulPool > bhPoolMax {
			writeAPIError(w, r, "E-PERF-01", fmt.Sprintf("the Backhaul pool must be a whole number from %d to %d", bhPoolMin, bhPoolMax))
			return
		}
		c.BackhaulPool = *body.BackhaulPool
		if err := savePerfConfig(c); err != nil {
			writeAPIError(w, r, "E-PERF-02", "failed to save config: "+err.Error())
			return
		}
		changed, err := applyBackhaulPool(c.BackhaulPool)
		if err != nil {
			recordError("E-PERF-03", "perf", "Backhaul pool: "+err.Error())
			writeAPIError(w, r, "E-PERF-03", err.Error())
			return
		}
		detail := "Saved: a Backhaul tunnel set up on this server will use it."
		if changed {
			detail = "Saved and applied: backhaul-client restarted."
		} else if backhaulRole() == "foreign" {
			detail = "Saved: the running tunnel already uses it."
		}
		recordError("E-PERF-00", "perf", fmt.Sprintf("Backhaul pool set to %d", c.BackhaulPool))
		writeJSON(w, map[string]any{"status": "ok", "detail": detail, "restarted": changed})

	case "reset":
		// The reset is about speed: it leaves the Backhaul pool alone, and the
		// PROXY protocol too, since the local service is set up to expect it.
		bhPool, pp := c.BackhaulPool, c.ProxyProtocol
		c = defaultPerfConfig()
		c.BackhaulPool, c.ProxyProtocol = bhPool, pp
		c.TCPMux = boolPtr(false) // safe/speed-first defaults pin tcpMux off explicitly
		if err := savePerfConfig(c); err != nil {
			writeAPIError(w, r, "E-PERF-02", "failed to save config: "+err.Error())
			return
		}
		out, err := runPerfCmd("perf", "reset")
		if err != nil {
			recordError("E-PERF-03", "perf", "Reset failed: "+out)
			writeAPIError(w, r, "E-PERF-03", out)
			return
		}
		recordError("E-PERF-00", "perf", "Performance settings reset to safe defaults")
		writeJSON(w, map[string]string{"status": "ok", "detail": "Settings reset to safe wire-speed defaults."})

	default:
		writeAPIError(w, r, "E-PERF-01", "unknown action: "+body.Action)
	}
}
