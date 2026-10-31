package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type SentinelConfig struct {
	Installed     bool   `json:"installed"`
	Running       bool   `json:"running"`
	Port          int    `json:"port"`
	Path          string `json:"path"`
	URL           string `json:"url"`
	Password      string `json:"password"`
	IsIran        bool   `json:"is_iran"`
	IsIranDecided bool   `json:"is_iran_decided"`
	HasLicense    bool   `json:"has_license"`
	Version       string `json:"version"`
}

// sentinelMu guards the locality config file. Installs take sentinelInstallMu
// instead, so a multi-minute install never blocks GET /api/sentinel.
var (
	sentinelMu        sync.Mutex
	sentinelInstallMu sync.Mutex
)

const (
	sentinelDir         = "/opt/sentinel"
	sentinelUnitPath    = "/etc/systemd/system/sentinel.service"
	sentinelInstallTime = 15 * time.Minute
	sentinelStartWait   = 25 * time.Second
)

// CheckSentinelEligibility validates that the license has "sentinel" feature.
// Region blocking is removed so Sentinel works smoothly anywhere.
func CheckSentinelEligibility(serverRole, countryCode string) (bool, string) {
	if !(HasFeature("sentinel") || HasFeature("*") || HasFeature("all")) {
		return false, "Sentinel is included in Community edition"
	}
	return true, ""
}

// DetectServerCountry returns a fallback country code without slow/failing external network calls.
func DetectServerCountry() string {
	return "IR"
}

// PickRandomSentinelPort selects a free random port in the given range.
func PickRandomSentinelPort(minPort, maxPort int) (int, error) {
	delta := maxPort - minPort + 1
	for attempts := 0; attempts < 100; attempts++ {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(delta)))
		if err != nil {
			return 0, err
		}
		cand := minPort + int(n.Int64())
		// Ensure port is available for TCP listening
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", cand))
		if err == nil {
			_ = ln.Close()
			return cand, nil
		}
	}
	return 0, fmt.Errorf("could not find free port in range %d-%d after 100 attempts", minPort, maxPort)
}

func sentinelCredentialsPath() string {
	return filepath.Join(sentinelDir, "credentials.txt")
}

// sentinelInstalled reports whether the systemd unit exists. Uninstall removes
// only the unit and keeps /opt/sentinel (database, credentials), so file
// presence alone does not mean installed.
func sentinelInstalled() bool {
	st, err := os.Stat(sentinelUnitPath)
	return err == nil && !st.IsDir()
}

// readSentinelCredentials parses credentials.txt written by app.py.
func readSentinelCredentials() (port int, path, password string, ok bool) {
	data, err := os.ReadFile(sentinelCredentialsPath())
	if err != nil {
		return 0, "", "", false
	}
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), "=", 2)
		if len(parts) != 2 {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(parts[0])) {
		case "port":
			fmt.Sscanf(strings.TrimSpace(parts[1]), "%d", &port)
		case "path":
			path = strings.TrimSpace(parts[1])
		case "password":
			password = strings.TrimSpace(parts[1])
		}
	}
	return port, path, password, true
}

func sentinelPortOpen(port int) bool {
	if port <= 0 {
		return false
	}
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 400*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// waitSentinelPort polls until the panel port reaches the wanted state. The
// port is re-read each round because a fresh install writes credentials.txt
// only once app.py has started.
func waitSentinelPort(want bool, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		port, _, _, _ := readSentinelCredentials()
		if port > 0 && sentinelPortOpen(port) == want {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// sentinelJournalTail returns the last service log lines for error messages.
func sentinelJournalTail() string {
	out, err := runCmdTimeout(5*time.Second, "journalctl", "-u", "sentinel.service", "-n", "25", "--no-pager")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func sentinelSystemctl(action string) error {
	out, err := runCmdTimeout(30*time.Second, "systemctl", action, "sentinel.service")
	if err != nil {
		return fmt.Errorf("systemctl %s sentinel: %v %s", action, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func sentinelConfigPath() string {
	return filepath.Join(configDir, "sentinel.json")
}

//go:embed sentinel_bundle.tar.gz
var sentinelBundleFS []byte

func extractEmbeddedSentinel(destDir string) error {
	if len(sentinelBundleFS) == 0 {
		return fmt.Errorf("embedded sentinel bundle is empty")
	}
	gzr, err := gzip.NewReader(bytes.NewReader(sentinelBundleFS))
	if err != nil {
		return fmt.Errorf("invalid gzip bundle: %v", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("tar read error: %v", err)
		}

		cleanRel := filepath.Clean(header.Name)
		if strings.HasPrefix(cleanRel, "..") || strings.HasPrefix(cleanRel, "/") {
			continue
		}
		target := filepath.Join(destDir, cleanRel)

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR|os.O_TRUNC, os.FileMode(header.Mode))
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return err
			}
			f.Close()
			if strings.HasSuffix(target, ".sh") || strings.HasSuffix(target, ".py") {
				_ = os.Chmod(target, 0755)
			}
		}
	}
	return nil
}

// ensureSentinelInstallScript unpacks the embedded bundle over /opt/sentinel on
// every install so a reinstall also upgrades stale code. The bundle carries no
// database or credentials, so user data is preserved.
func ensureSentinelInstallScript() (string, error) {
	p := filepath.Join(sentinelDir, "install.sh")
	if err := os.MkdirAll(sentinelDir, 0755); err != nil {
		return "", fmt.Errorf("cannot create %s: %v", sentinelDir, err)
	}
	if err := extractEmbeddedSentinel(sentinelDir); err != nil {
		// Fall back to files left by an earlier install.
		if st, statErr := os.Stat(p); statErr == nil && !st.IsDir() {
			_ = os.Chmod(p, 0755)
			return p, nil
		}
		return "", fmt.Errorf("failed unpacking embedded sentinel files: %v", err)
	}
	if st, err := os.Stat(p); err == nil && !st.IsDir() {
		_ = os.Chmod(p, 0755)
		return p, nil
	}
	return "", fmt.Errorf("installer not found after bundle extraction")
}

// GetSentinelStatus gathers current Sentinel state and credentials.
func GetSentinelStatus() SentinelConfig {
	st := localStatus()
	isIran := true
	sentinelMu.Lock()
	pData, err := os.ReadFile(sentinelConfigPath())
	sentinelMu.Unlock()
	if err == nil {
		var pState struct {
			IsIran *bool `json:"is_iran"`
		}
		if err := json.Unmarshal(pData, &pState); err == nil && pState.IsIran != nil {
			isIran = *pState.IsIran
		}
	} else if strings.Contains(strings.ToLower(st.Role), "foreign") {
		isIran = false
	}

	cfg := SentinelConfig{
		Installed:     false,
		Running:       false,
		HasLicense:    HasFeature("sentinel") || HasFeature("*") || HasFeature("all"),
		IsIran:        isIran,
		IsIranDecided: true,
		Version:       "1.2.0",
	}

	cfg.Installed = sentinelInstalled()
	if !cfg.Installed {
		return cfg
	}
	cfg.Port, cfg.Path, cfg.Password, _ = readSentinelCredentials()

	if cfg.Port > 0 {
		cfg.Running = sentinelPortOpen(cfg.Port)
		pubHost := st.LocalPub
		if pubHost == "" {
			pubHost = detectPublicIPCached()
		}
		if pubHost == "" {
			pubHost = "127.0.0.1"
		}
		cleanPath := "/" + strings.Trim(cfg.Path, "/") + "/"
		cfg.Path = cleanPath
		cfg.URL = "http://" + hostPort(pubHost, cfg.Port) + cleanPath
	}

	return cfg
}

// handleSentinelGet handles GET /api/sentinel.
func handleSentinelGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, GetSentinelStatus())
}

// handleSentinelPost handles POST /api/sentinel actions.
func handleSentinelPost(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Action string `json:"action"`
		IsIran *bool  `json:"is_iran"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeAPIError(w, r, "E-SENTINEL-06", "invalid json body")
		return
	}

	act := strings.ToLower(strings.TrimSpace(body.Action))
	st := localStatus()

	eligible, reason := CheckSentinelEligibility(st.Role, "")
	if !eligible && act == "install" {
		writeAPIError(w, r, "E-SENTINEL-01", reason)
		return
	}

	switch act {
	case "status":
		writeJSON(w, GetSentinelStatus())

	case "set_locality":
		if body.IsIran == nil {
			writeAPIError(w, r, "E-SENTINEL-06", "missing is_iran boolean field")
			return
		}
		sentinelMu.Lock()
		_ = os.MkdirAll(configDir, 0700)
		pData, _ := json.Marshal(map[string]any{
			"is_iran": *body.IsIran,
		})
		if err := os.WriteFile(sentinelConfigPath(), pData, 0600); err != nil {
			sentinelMu.Unlock()
			writeAPIError(w, r, "E-SENTINEL-03", fmt.Sprintf("failed writing sentinel config: %v", err))
			return
		}
		sentinelMu.Unlock()

		writeJSON(w, map[string]any{
			"status":  "ok",
			"message": "Sentinel server locality updated",
			"data":    GetSentinelStatus(),
		})

	case "install":
		if !sentinelInstallMu.TryLock() {
			writeAPIError(w, r, "E-SENTINEL-05", "")
			return
		}
		defer sentinelInstallMu.Unlock()

		port, err := PickRandomSentinelPort(30000, 39999)
		if err != nil {
			writeAPIError(w, r, "E-SENTINEL-02", fmt.Sprintf("failed allocating random port: %v", err))
			return
		}

		installScript, err := ensureSentinelInstallScript()
		if err != nil {
			writeAPIError(w, r, "E-SENTINEL-02", fmt.Sprintf("Sentinel setup failed: %v", err))
			return
		}

		// The installer only honors --port on the first install; an existing
		// database keeps its port, so the reported port is read back below.
		out, err := runCmdTimeout(sentinelInstallTime, "bash", installScript, "--yes", "--port", fmt.Sprintf("%d", port))
		if err != nil {
			writeAPIError(w, r, "E-SENTINEL-02", fmt.Sprintf("Sentinel install failed: %v\n%s", err, trimLen(strings.TrimSpace(string(out)), 2000)))
			return
		}

		if !waitSentinelPort(true, sentinelStartWait) {
			writeAPIError(w, r, "E-SENTINEL-03", "Sentinel was installed but its web panel did not start listening.\n"+sentinelJournalTail())
			return
		}

		stNow := GetSentinelStatus()
		writeJSON(w, map[string]any{
			"status":  "ok",
			"message": fmt.Sprintf("Sentinel successfully installed on port %d", stNow.Port),
			"data":    stNow,
		})

	case "start", "stop", "restart":
		if !sentinelInstalled() {
			writeAPIError(w, r, "E-SENTINEL-04", "")
			return
		}
		if err := sentinelSystemctl(act); err != nil {
			writeAPIError(w, r, "E-SENTINEL-03", err.Error())
			return
		}
		want := act != "stop"
		if !waitSentinelPort(want, 10*time.Second) && want {
			writeAPIError(w, r, "E-SENTINEL-03", "Sentinel service did not come up.\n"+sentinelJournalTail())
			return
		}
		writeJSON(w, map[string]any{"status": "ok", "message": "Sentinel " + act + " done", "data": GetSentinelStatus()})

	case "uninstall":
		if !sentinelInstalled() {
			writeAPIError(w, r, "E-SENTINEL-04", "")
			return
		}
		_, _ = runCmdTimeout(30*time.Second, "systemctl", "disable", "--now", "sentinel.service")
		if err := os.Remove(sentinelUnitPath); err != nil && !os.IsNotExist(err) {
			writeAPIError(w, r, "E-SENTINEL-03", fmt.Sprintf("cannot remove %s: %v", sentinelUnitPath, err))
			return
		}
		_, _ = runCmdTimeout(30*time.Second, "systemctl", "daemon-reload")
		writeJSON(w, map[string]any{
			"status":  "ok",
			"message": "Sentinel uninstalled. Its data is kept in " + sentinelDir + " and is reused on reinstall.",
			"data":    GetSentinelStatus(),
		})

	default:
		writeAPIError(w, r, "E-SENTINEL-06", fmt.Sprintf("unsupported action %q", act))
	}
}
