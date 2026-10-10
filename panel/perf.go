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
	ProxyEncryption  bool   `json:"proxy_encryption"`
	ProxyCompression bool   `json:"proxy_compression"`
	ForceTLS         bool   `json:"force_tls"`
	ChaffProfile     string `json:"chaff_profile"`
	DPIEnabled       bool   `json:"dpi_enabled"`
	DPIRate          string `json:"dpi_rate"`
	DPIBurst         int    `json:"dpi_burst"`
	FRPPoolCount     int    `json:"frp_pool_count"`
	FRPMaxPool       int    `json:"frp_max_pool"`
	AutoTune         bool   `json:"auto_tune"`
	TuningProfile    string `json:"tuning_profile"`
	// TCPMux: nil = never configured (live tomls are left untouched on apply);
	// false = speed-first (default for new tunnels); true = frp tcpMux on.
	TCPMux *bool `json:"tcp_mux,omitempty"`
}

type perfStatusResponse struct {
	ProxyEncryption  bool            `json:"proxy_encryption"`
	ProxyCompression bool            `json:"proxy_compression"`
	ForceTLS         bool            `json:"force_tls"`
	ChaffProfile     string          `json:"chaff_profile"`
	DPIEnabled       bool            `json:"dpi_enabled"`
	DPIRate          string          `json:"dpi_rate"`
	DPIBurst         int             `json:"dpi_burst"`
	FRPPoolCount     int             `json:"frp_pool_count"`
	FRPMaxPool       int             `json:"frp_max_pool"`
	AutoTune         bool            `json:"auto_tune"`
	TuningProfile    string          `json:"tuning_profile"`
	TCPMux           bool            `json:"tcp_mux"`
	TCPMuxSet        bool            `json:"tcp_mux_set"`
	TCPMuxLive       string          `json:"tcp_mux_live"`
	InSync           bool            `json:"in_sync"`
	SyncDetails      string          `json:"sync_details"`
	Role             string          `json:"role"`
	DPIActive        bool            `json:"dpi_active"`
	ChaffActive      bool            `json:"chaff_active"`
	Overridden       map[string]bool `json:"overridden,omitempty"`
}

type perfPostRequest struct {
	Action           string  `json:"action"`
	ProxyEncryption  *bool   `json:"proxy_encryption,omitempty"`
	ProxyCompression *bool   `json:"proxy_compression,omitempty"`
	ForceTLS         *bool   `json:"force_tls,omitempty"`
	ChaffProfile     *string `json:"chaff_profile,omitempty"`
	DPIEnabled       *bool   `json:"dpi_enabled,omitempty"`
	DPIRate          *string `json:"dpi_rate,omitempty"`
	DPIBurst         *int    `json:"dpi_burst,omitempty"`
	FRPPoolCount     *int    `json:"frp_pool_count,omitempty"`
	FRPMaxPool       *int    `json:"frp_max_pool,omitempty"`
	AutoTune         *bool   `json:"auto_tune,omitempty"`
	TuningProfile    *string `json:"tuning_profile,omitempty"`
	TCPMux           *bool   `json:"tcp_mux,omitempty"`
}

func perfConfigPath() string {
	return filepath.Join(configDir, "perf.json")
}

func defaultPerfConfig() perfConfig {
	return perfConfig{
		ProxyEncryption:  false,
		ProxyCompression: false,
		ForceTLS:         false,
		ChaffProfile:     "off",
		DPIEnabled:       false,
		DPIRate:          "60/sec",
		DPIBurst:         120,
		FRPPoolCount:     20,
		FRPMaxPool:       60,
		AutoTune:         false,
		TuningProfile:    "standard",
	}
}

func boolPtr(b bool) *bool { return &b }

func loadPerfConfig() perfConfig {
	def := defaultPerfConfig()
	data, err := os.ReadFile(perfConfigPath())
	if err != nil {
		return def
	}
	var raw struct {
		ProxyEncryption  *bool   `json:"proxy_encryption"`
		ProxyCompression *bool   `json:"proxy_compression"`
		ForceTLS         *bool   `json:"force_tls"`
		ChaffProfile     *string `json:"chaff_profile"`
		DPIEnabled       *bool   `json:"dpi_enabled"`
		DPIRate          *string `json:"dpi_rate"`
		DPIBurst         *int    `json:"dpi_burst"`
		FRPPoolCount     *int    `json:"frp_pool_count"`
		FRPMaxPool       *int    `json:"frp_max_pool"`
		AutoTune         *bool   `json:"auto_tune"`
		TuningProfile    *string `json:"tuning_profile"`
		TCPMux           *bool   `json:"tcp_mux"`
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
	if raw.ForceTLS != nil {
		c.ForceTLS = *raw.ForceTLS
	}
	if raw.ChaffProfile != nil {
		p := strings.ToLower(strings.TrimSpace(*raw.ChaffProfile))
		if p == "off" || p == "low" || p == "mid" {
			c.ChaffProfile = p
		}
	}
	if raw.DPIEnabled != nil {
		c.DPIEnabled = *raw.DPIEnabled
	}
	if raw.DPIRate != nil && strings.TrimSpace(*raw.DPIRate) != "" {
		c.DPIRate = strings.TrimSpace(*raw.DPIRate)
	}
	if raw.DPIBurst != nil && *raw.DPIBurst > 0 {
		c.DPIBurst = *raw.DPIBurst
	}
	if raw.FRPPoolCount != nil && *raw.FRPPoolCount >= 2 {
		c.FRPPoolCount = *raw.FRPPoolCount
	}
	if raw.FRPMaxPool != nil && *raw.FRPMaxPool >= 10 {
		c.FRPMaxPool = *raw.FRPMaxPool
	}
	if raw.AutoTune != nil {
		c.AutoTune = *raw.AutoTune
	}
	if raw.TuningProfile != nil && strings.TrimSpace(*raw.TuningProfile) != "" {
		c.TuningProfile = strings.TrimSpace(*raw.TuningProfile)
	}
	if raw.TCPMux != nil {
		v := *raw.TCPMux
		c.TCPMux = &v
	}
	return c
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
	if c.ChaffProfile == "" {
		c.ChaffProfile = "off"
	}
	if c.DPIRate == "" {
		c.DPIRate = "300/min"
	}
	if c.DPIBurst <= 0 {
		c.DPIBurst = 100
	}
	if c.FRPMaxPool <= 0 {
		c.FRPMaxPool = 100
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
	if v := os.Getenv("PERF_TLS"); v != "" {
		c.ForceTLS = (v == "1" || strings.ToLower(v) == "true")
		overridden["force_tls"] = true
	}
	return c, overridden
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
		hasTLSByte := strings.Contains(content, "transport.tls.disableCustomTLSFirstByte = true") || strings.Contains(content, "transport.tls.disableCustomTLSFirstByte=true")
		hasEnc := strings.Contains(content, "transport.useEncryption = true") || strings.Contains(content, "transport.useEncryption=true")
		hasComp := strings.Contains(content, "transport.useCompression = true") || strings.Contains(content, "transport.useCompression=true")

		if c.ForceTLS != hasTLSByte {
			return false, fmt.Sprintf("TLS setting (%v) does not match frpc.toml (%v)", c.ForceTLS, hasTLSByte), role
		}
		if c.ProxyEncryption != hasEnc {
			return false, fmt.Sprintf("Proxy encryption (%v) does not match frpc.toml (%v)", c.ProxyEncryption, hasEnc), role
		}
		if c.ProxyCompression != hasComp {
			return false, fmt.Sprintf("Proxy compression (%v) does not match frpc.toml (%v)", c.ProxyCompression, hasComp), role
		}
		return true, "All settings match live frpc.toml", role
	case "iran":
		data, err := os.ReadFile(filepath.Join(frpDir, "frps.toml"))
		if err != nil {
			return false, "cannot read " + filepath.Join(frpDir, "frps.toml"), role
		}
		content := string(data)
		hasTLSForce := strings.Contains(content, "transport.tls.force = true") || strings.Contains(content, "transport.tls.force=true")
		if c.ForceTLS != hasTLSForce {
			return false, fmt.Sprintf("Force TLS setting (%v) does not match frps.toml (%v)", c.ForceTLS, hasTLSForce), role
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

	dpiActive := false
	if out, err := exec.Command("iptables", "-L", "HASHEM-DPI", "-n").CombinedOutput(); err == nil {
		dpiActive = strings.Contains(string(out), "HASHEM-DPI")
	}

	chaffActive := false
	if out, err := exec.Command("systemctl", "is-active", "gre-chaff").CombinedOutput(); err == nil && strings.TrimSpace(string(out)) == "active" {
		chaffActive = true
	} else if out, err := exec.Command("systemctl", "list-units", "--type=service", "--state=running").CombinedOutput(); err == nil && strings.Contains(string(out), "gre-chaff") {
		chaffActive = true
	}

	resp := perfStatusResponse{
		ProxyEncryption:  c.ProxyEncryption,
		ProxyCompression: c.ProxyCompression,
		ForceTLS:         c.ForceTLS,
		ChaffProfile:     c.ChaffProfile,
		DPIEnabled:       c.DPIEnabled,
		DPIRate:          c.DPIRate,
		DPIBurst:         c.DPIBurst,
		FRPPoolCount:     c.FRPPoolCount,
		FRPMaxPool:       c.FRPMaxPool,
		AutoTune:         c.AutoTune,
		TuningProfile:    c.TuningProfile,
		TCPMux:           c.TCPMux != nil && *c.TCPMux,
		TCPMuxSet:        c.TCPMux != nil,
		TCPMuxLive:       liveTCPMux(),
		InSync:           inSync,
		SyncDetails:      details,
		Role:             role,
		DPIActive:        dpiActive,
		ChaffActive:      chaffActive,
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
		if body.ForceTLS != nil {
			c.ForceTLS = *body.ForceTLS
		}
		if body.ChaffProfile != nil {
			p := strings.ToLower(strings.TrimSpace(*body.ChaffProfile))
			if p == "off" || p == "low" || p == "mid" {
				c.ChaffProfile = p
			}
		}
		if body.DPIEnabled != nil {
			c.DPIEnabled = *body.DPIEnabled
		}
		if body.DPIRate != nil && strings.TrimSpace(*body.DPIRate) != "" {
			c.DPIRate = strings.TrimSpace(*body.DPIRate)
		}
		if body.DPIBurst != nil && *body.DPIBurst > 0 {
			c.DPIBurst = *body.DPIBurst
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
		if body.AutoTune != nil {
			c.AutoTune = *body.AutoTune
		}
		if body.TuningProfile != nil {
			c.TuningProfile = *body.TuningProfile
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
		if body.AutoTune != nil {
			c.AutoTune = *body.AutoTune
		}
		if body.TuningProfile != nil {
			c.TuningProfile = *body.TuningProfile
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
		if body.ProxyEncryption != nil {
			c.ProxyEncryption = *body.ProxyEncryption
		}
		if body.ProxyCompression != nil {
			c.ProxyCompression = *body.ProxyCompression
		}
		if body.ForceTLS != nil {
			c.ForceTLS = *body.ForceTLS
		}
		if body.ChaffProfile != nil {
			p := strings.ToLower(strings.TrimSpace(*body.ChaffProfile))
			if p == "off" || p == "low" || p == "mid" {
				c.ChaffProfile = p
			}
		}
		if body.DPIEnabled != nil {
			c.DPIEnabled = *body.DPIEnabled
		}
		if body.DPIRate != nil && strings.TrimSpace(*body.DPIRate) != "" {
			c.DPIRate = strings.TrimSpace(*body.DPIRate)
		}
		if body.DPIBurst != nil && *body.DPIBurst > 0 {
			c.DPIBurst = *body.DPIBurst
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

	case "set-chaff":
		if body.ChaffProfile == nil {
			writeAPIError(w, r, "E-PERF-01", "chaff_profile required")
			return
		}
		p := strings.ToLower(strings.TrimSpace(*body.ChaffProfile))
		if p != "off" && p != "low" && p != "mid" {
			writeAPIError(w, r, "E-PERF-01", "invalid chaff_profile: must be off, low, or mid")
			return
		}
		c.ChaffProfile = p
		if err := savePerfConfig(c); err != nil {
			writeAPIError(w, r, "E-PERF-02", "failed to save config: "+err.Error())
			return
		}
		out, err := runPerfCmd("perf", "chaff", p)
		if err != nil {
			writeAPIError(w, r, "E-PERF-03", out)
			return
		}
		recordError("E-PERF-00", "perf", "Chaff profile set to "+p)
		writeJSON(w, map[string]string{"status": "ok", "detail": out})

	case "set-dpi":
		if body.DPIEnabled == nil {
			writeAPIError(w, r, "E-PERF-01", "dpi_enabled required")
			return
		}
		c.DPIEnabled = *body.DPIEnabled
		if err := savePerfConfig(c); err != nil {
			writeAPIError(w, r, "E-PERF-02", "failed to save config: "+err.Error())
			return
		}
		action := "off"
		if c.DPIEnabled {
			action = "on"
		}
		out, err := runPerfCmd("perf", "dpi", action)
		if err != nil {
			writeAPIError(w, r, "E-PERF-03", out)
			return
		}
		recordError("E-PERF-00", "perf", "DPI shield set to "+action)
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
