package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Dial route (foreign side): the client may reach the Iran hub over the GRE
// inner address or straight to the hub's public IP. When GRE is blocked on one
// path, "public" keeps FRP alive without GRE ping. Logic lives in hashem.sh
// (`hashem dial`); this is a thin, validated wrapper.

func runHashemDial(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	var cmd *exec.Cmd
	if script, err := greScriptPath(); err == nil {
		cmd = exec.CommandContext(ctx, "bash", append([]string{script, "dial"}, args...)...)
	} else if fileExists("/usr/local/bin/hashem") {
		cmd = exec.CommandContext(ctx, "/usr/local/bin/hashem", append([]string{"dial"}, args...)...)
	} else {
		return "", fmt.Errorf("hashem script not found")
	}
	cmd.Env = append(os.Environ(), "GRE_SKIP_PANEL=1", "TERM=dumb", "GRE_PANEL_DIR="+configDir)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(stripANSI(string(out))), err
}

func parseDialStatus(out string) map[string]any {
	m := map[string]any{"available": false}
	for _, l := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(l), "=")
		if !ok {
			continue
		}
		if k == "available" {
			m["available"] = v == "1"
			continue
		}
		switch k {
		case "mode", "active", "addr", "port", "gre", "public", "kind":
			m[k] = v
		}
	}
	return m
}

func handleDialGet(w http.ResponseWriter, r *http.Request) {
	out, _ := runHashemDial("status")
	writeJSON(w, parseDialStatus(out))
}

func validDialMode(m string) bool { return m == "auto" || m == "gre" || m == "public" }

func handleDialPost(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Mode string `json:"mode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		writeAPIError(w, r, "E-ACTION-01", "invalid json")
		return
	}
	b.Mode = strings.ToLower(strings.TrimSpace(b.Mode))
	if !validDialMode(b.Mode) {
		writeAPIError(w, r, "E-ACTION-01", "mode must be auto, gre or public")
		return
	}
	out, err := runHashemDial(b.Mode)
	if err != nil {
		writeAPIError(w, r, "E-ACTION-01", "dial change failed: "+out)
		return
	}
	st, _ := runHashemDial("status")
	res := parseDialStatus(st)
	res["ok"] = true
	writeJSON(w, res)
}
