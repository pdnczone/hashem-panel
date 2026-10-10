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
}

// autoPoolState mirrors the auto_pool.json that hashem.sh autopool_tick maintains.
type autoPoolState struct {
	Pool             int    `json:"pool"`
	MaxPool          int    `json:"max_pool"`
	AppliedPool      int    `json:"applied_pool"`
	QuietTicks       int    `json:"quiet_ticks"`
	LastTick         int64  `json:"last_tick"`
	LastChange       int64  `json:"last_change"`
	LastRestart      int64  `json:"last_restart"`
	LastDecision     string `json:"last_decision"`
	LastReason       string `json:"last_reason"`
	ErrorsLastTick   int    `json:"errors_last_tick"`
	ActiveConns      int    `json:"active_conns"`
	FRPSRestartNeeded bool  `json:"frps_restart_needed"`
}

type perfStatusResponse struct {
	ProxyEncryption  bool            `json:"proxy_encryption"`
	ProxyCompression bool            `json:"proxy_compression"`
	AutoPool         bool            `json:"auto_pool"`
	FRPPoolCount     int             `json:"frp_pool_count"`
	FRPMaxPool       int             `json:"frp_max_pool"`
	EffectivePool    int             `json:"effective_pool_count"`
	EffectiveMaxPool int             `json:"effective_max_pool"`
	AutoPoolState    autoPoolState   `json:"auto_pool_state"`
	TCPMux           bool            `json:"tcp_mux"`
	TCPMuxSet        bool            `json:"tcp_mux_set"`
	TCPMuxLive       string          `json:"tcp_mux_live"`
	InSync           bool            `json:"in_sync"`
	SyncDetails      string          `json:"sync_details"`
	Role             string          `json:"role"`
	Overridden       map[string]bool `json:"overridden,omitempty"`
}

type perfPostRequest struct {
	Action           string `json:"action"`
	ProxyEncryption  *bool  `json:"proxy_encryption,omitempty"`
	ProxyCompression *bool  `json:"proxy_compression,omitempty"`
	AutoPool         *bool  `json:"auto_pool,omitempty"`
	FRPPoolCount     *int   `json:"frp_pool_count,omitempty"`
	FRPMaxPool       *int   `json:"frp_max_pool,omitempty"`
	TCPMux           *bool  `json:"tcp_mux,omitempty"`
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
		ProxyEncryption  *bool `json:"proxy_encryption"`
		ProxyCompression *bool `json:"proxy_compression"`
		AutoPool         *bool `json:"auto_pool"`
		FRPPoolCount     *int  `json:"frp_pool_count"`
		FRPMaxPool       *int  `json:"frp_max_pool"`
		TCPMux           *bool `json:"tcp_mux"`
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

// effectivePoolValues returns the poolCount / maxPoolCount every frps/frpc writer must use.
// The decision lives in hashem.sh (`perf pool`); the fallback only covers a missing script and
// follows the same rules from the files: auto => the state file, manual => perf.json, and
// maxPoolCount is never below 1.5 * poolCount.
func effectivePoolValues() (int, int) {
	if script, err := greScriptPath(); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "bash", script, "perf", "pool")
		cmd.Env = append(os.Environ(), "GRE_SKIP_PANEL=1", "TERM=dumb", "GRE_PANEL_DIR="+configDir)
		if out, err := cmd.Output(); err == nil {
			var pool, maxPool int
			if n, _ := fmt.Sscanf(strings.TrimSpace(string(out)), "%d %d", &pool, &maxPool); n == 2 && pool > 0 && maxPool > 0 {
				return pool, maxPool
			}
		}
	}
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
	} else if _, err := os.Stat(filepath.Join(frpDir, "frps.toml")); err == nil {
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
		if !c.AutoPool {
			if live := tomlInt(content, "transport.poolCount"); live != c.FRPPoolCount {
				return false, fmt.Sprintf("poolCount (%d) does not match frpc.toml (%d)", c.FRPPoolCount, live), role
			}
		}
		return true, "All settings match live frpc.toml", role
	case "iran":
		data, err := os.ReadFile(filepath.Join(frpDir, "frps.toml"))
		if err != nil {
			return false, "cannot read " + filepath.Join(frpDir, "frps.toml"), role
		}
		if !c.AutoPool {
			if live := tomlInt(string(data), "transport.maxPoolCount"); live != c.FRPMaxPool {
				return false, fmt.Sprintf("maxPoolCount (%d) does not match frps.toml (%d)", c.FRPMaxPool, live), role
			}
		}
		return true, "All settings match live frps.toml", role
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
	c, over := effectivePerfConfig()
	inSync, details, role := checkLiveTomlSync(c)
	ePool, eMax := effectivePoolValues()

	resp := perfStatusResponse{
		ProxyEncryption:  c.ProxyEncryption,
		ProxyCompression: c.ProxyCompression,
		AutoPool:         c.AutoPool,
		FRPPoolCount:     c.FRPPoolCount,
		FRPMaxPool:       c.FRPMaxPool,
		EffectivePool:    ePool,
		EffectiveMaxPool: eMax,
		AutoPoolState:    loadAutoPoolState(),
		TCPMux:           c.TCPMux != nil && *c.TCPMux,
		TCPMuxSet:        c.TCPMux != nil,
		TCPMuxLive:       liveTCPMux(),
		InSync:           inSync,
		SyncDetails:      details,
		Role:             role,
		Overridden:       over,
	}
	writeJSON(w, resp)
}

func handlePerfPost(w http.ResponseWriter, r *http.Request) {
	var body perfPostRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeAPIError(w, r, "E-PERF-01", "invalid request body")
		return
	}

	c := loadPerfConfig()

	switch body.Action {
	case "update":
		if body.ProxyEncryption != nil {
			c.ProxyEncryption = *body.ProxyEncryption
		}
		if body.ProxyCompression != nil {
			c.ProxyCompression = *body.ProxyCompression
		}
		if body.FRPPoolCount != nil && *body.FRPPoolCount >= 2 {
			c.FRPPoolCount = *body.FRPPoolCount
		}
		if body.FRPMaxPool != nil && *body.FRPMaxPool >= 10 {
			c.FRPMaxPool = *body.FRPMaxPool
		}
		if body.TCPMux != nil {
			v := *body.TCPMux
			c.TCPMux = &v
		}
		if body.AutoPool != nil {
			c.AutoPool = *body.AutoPool
		}
		if err := savePerfConfig(c); err != nil {
			writeAPIError(w, r, "E-PERF-02", "failed to save config: "+err.Error())
			return
		}
		recordError("E-PERF-00", "perf", "Performance settings updated")
		writeJSON(w, map[string]string{"status": "ok", "detail": "Settings updated in perf.json"})

	case "set-tuning":
		if body.FRPPoolCount != nil && *body.FRPPoolCount >= 2 {
			c.FRPPoolCount = *body.FRPPoolCount
		}
		if body.FRPMaxPool != nil && *body.FRPMaxPool >= 10 {
			c.FRPMaxPool = *body.FRPMaxPool
		}
		if body.AutoPool != nil {
			c.AutoPool = *body.AutoPool
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

	case "reset":
		c = defaultPerfConfig()
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
