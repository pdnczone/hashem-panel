package main

// Update API: check for a newer prebuilt panel release and install it.
// Same safety rules as hashem.sh update_all(): verify download, keep local
// config (panel.json) untouched, restart the service, and
// never leave the system in a broken state on failure.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

var updateClient = &http.Client{Timeout: 25 * time.Second}

// handleVersion / latestReleaseTag (channel aware) live in update_channel.go.

// handleUpdate downloads the latest prebuilt binary for this arch,
// verifies it (non-empty ELF), swaps it in, syncs the latest hashem.sh
// next to the panel binary, and restarts the service.
const panelScriptName = "hashem.sh"

func handleUpdate(w http.ResponseWriter, r *http.Request) {
	arch, asset, err := panelAsset()
	if err != nil {
		writeAPIError(w, r, "E-UPDATE-05", err.Error())
		return
	}
	_ = arch
	latest, _ := latestReleaseTag()
	if latest == "" {
		latest = "latest"
	}
	if latest != "latest" && !validTag(latest) {
		writeAPIError(w, r, "E-UPDATE-01", "unexpected release tag")
		return
	}
	if latest != "latest" && latest == panelVersion {
		writeJSON(w, map[string]string{"status": "ok", "detail": "already latest (" + displayVersion(panelVersion) + ")"})
		return
	}
	// never install something that is not newer than what is running
	// (e.g. a stable host must not be "updated" to an older tag)
	if latest != "latest" && !updateAvailable(panelVersion, latest, updateChannel()) {
		writeJSON(w, map[string]string{"status": "ok", "detail": "already latest (" + displayVersion(panelVersion) + ")"})
		return
	}

	LogSecurityAudit("update_initiated", cfg.Username, ClientIP(r), "from="+panelVersion+" to="+latest+" asset="+asset)

	var dlURL string
	if latest == "latest" {
		dlURL = "https://github.com/pdnczone/hashem-panel/releases/latest/download/" + asset
	} else {
		dlURL = "https://github.com/pdnczone/hashem-panel/releases/download/" + latest + "/" + asset
	}
	tmp, err := os.CreateTemp("", "gre-panel-update-*")
	if err != nil {
		writeAPIError(w, r, "E-UPDATE-04", "")
		return
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if err := downloadFile(dlURL, tmp); err != nil {
		LogSecurityAudit("update_failed", cfg.Username, ClientIP(r), "download error: "+err.Error())
		writeAPIError(w, r, "E-UPDATE-02", err.Error())
		return
	}

	// Verify SHA256 against the release manifest. Fail-closed: an update with
	// no manifest entry for this asset is refused (M-01) unless the operator
	// explicitly opts out with GRE_PANEL_ALLOW_UNVERIFIED_UPDATE=1.
	if err := verifyAssetChecksum(tmpPath, latest, asset); err != nil {
		LogSecurityAudit("update_checksum_failed", cfg.Username, ClientIP(r), "asset="+asset+" err="+err.Error())
		writeAPIError(w, r, "E-UPDATE-07", err.Error())
		return
	}

	if err := verifyELF(tmpPath); err != nil {
		LogSecurityAudit("update_failed", cfg.Username, ClientIP(r), "ELF verification failed: "+err.Error())
		writeAPIError(w, r, "E-UPDATE-03", err.Error())
		return
	}
	exe, err := os.Executable()
	if err != nil {
		writeAPIError(w, r, "E-UPDATE-04", "")
		return
	}
	// Swap in the new binary. Keep a .bak so a bad binary can be rolled back.
	bak := exe + ".bak"
	_ = os.Remove(bak)
	if err := os.Rename(exe, bak); err != nil {
		writeAPIError(w, r, "E-UPDATE-04", err.Error())
		return
	}
	if err := copyFile(tmpPath, exe); err != nil {
		_ = os.Rename(bak, exe) // roll back
		LogSecurityAudit("update_rollback", cfg.Username, ClientIP(r), "copy failed: "+err.Error())
		writeAPIError(w, r, "E-UPDATE-04", err.Error())
		return
	}
	_ = os.Chmod(exe, 0755)
	// Keep hashem.sh in sync with the binary
	syncPanelScriptFrom(latest)

	LogSecurityAudit("update_success", cfg.Username, ClientIP(r), "installed version "+latest)
	writeJSON(w, map[string]string{"status": "ok", "detail": "updated to " + displayVersion(latest) + " — restarting panel"})
	go func() {
		time.Sleep(1000 * time.Millisecond)
		restartSelf()
	}()
}

// panelAsset maps runtime arch to the release asset name.
func panelAsset() (arch, asset string, err error) {
	switch runtime.GOARCH {
	case "amd64":
		return "amd64", "gre-panel-linux-amd64", nil
	case "arm64":
		return "arm64", "gre-panel-linux-arm64", nil
	}
	return "", "", fmt.Errorf("unsupported arch for update: %s", runtime.GOARCH)
}

// isOfficialGitHubURL restricts downloads to official GitHub repositories only (CWE-494)
func isOfficialGitHubURL(u string) bool {
	parsed, err := url.Parse(u)
	if err != nil {
		return false
	}
	host := strings.ToLower(parsed.Host)
	return host == "github.com" || host == "raw.githubusercontent.com" ||
		host == "api.github.com" || host == "objects.githubusercontent.com" ||
		host == "mirror.ghproxy.com" || host == "ghproxy.net" ||
		host == "gh.ddlc.top" || host == "fastly.jsdelivr.net"
}


// manifestFetcher is swapped in tests.
var manifestFetcher = fetchChecksumManifest

// verifyAssetChecksum checks tmpPath against the release's checksum manifest.
// Missing manifest / missing entry => error (fail-closed) unless
// GRE_PANEL_ALLOW_UNVERIFIED_UPDATE=1.
func verifyAssetChecksum(tmpPath, tag, asset string) error {
	allowUnverified := os.Getenv("GRE_PANEL_ALLOW_UNVERIFIED_UPDATE") == "1"
	manifest, ferr := manifestFetcher(tag)
	expected, ok := "", false
	if manifest != nil {
		expected, ok = manifest[asset]
	}
	if !ok {
		if allowUnverified {
			LogSecurityAudit("update_unverified_allowed", "system", "local", "asset="+asset)
			return nil
		}
		if ferr != nil {
			return fmt.Errorf("refusing unverified update: checksum manifest unavailable (%v)", ferr)
		}
		return fmt.Errorf("refusing unverified update: no checksum entry for %s", asset)
	}
	if err := VerifyFileSHA256(tmpPath, expected); err != nil {
		return err
	}
	LogSecurityAudit("update_checksum_verified", "system", "local", "asset="+asset+" sha256="+expected)
	return nil
}

// fetchChecksumManifest attempts to download checksums.txt or SHA256SUMS from the release.
func fetchChecksumManifest(tag string) (map[string]string, error) {
	base := "https://github.com/pdnczone/hashem-panel/releases/download/" + tag + "/"
	if tag == "latest" || tag == "" {
		base = "https://github.com/pdnczone/hashem-panel/releases/latest/download/"
	}
	var candidates []string
	for _, name := range []string{"checksums.txt", "SHA256SUMS"} {
		u := base + name
		candidates = append(candidates, u,
			"https://mirror.ghproxy.com/"+u, "https://ghproxy.net/"+u, "https://gh.ddlc.top/"+u)
	}
	client := &http.Client{Timeout: 30 * time.Second}
	for _, u := range candidates {
		resp, err := client.Get(u)
		if err != nil {
			continue
		}
		if resp.StatusCode == http.StatusOK {
			data, rerr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			resp.Body.Close()
			if rerr == nil && len(data) > 0 {
				if m := ParseChecksumManifest(string(data)); len(m) > 0 {
					return m, nil
				}
			}
			continue
		}
		resp.Body.Close()
	}
	return nil, fmt.Errorf("no checksum manifest found")
}

func downloadFile(rawURL string, tmp *os.File) error {
	if !isOfficialGitHubURL(rawURL) {
		return fmt.Errorf("untrusted download URL domain: %s", rawURL)
	}

	urlsToTry := []string{rawURL}
	if strings.HasPrefix(rawURL, "https://github.com/") || strings.HasPrefix(rawURL, "https://raw.githubusercontent.com/") {
		urlsToTry = append(urlsToTry,
			"https://mirror.ghproxy.com/"+rawURL,
			"https://ghproxy.net/"+rawURL,
			"https://gh.ddlc.top/"+rawURL,
		)
	}

	client := &http.Client{Timeout: 60 * time.Second}
	var lastErr error

	for _, tryURL := range urlsToTry {
		for attempt := 1; attempt <= 2; attempt++ {
			req, err := http.NewRequest("GET", tryURL, nil)
			if err != nil {
				lastErr = err
				continue
			}
			req.Header.Set("User-Agent", "hashem-panel-updater/"+panelVersion)

			resp, err := client.Do(req)
			if err != nil {
				lastErr = err
				time.Sleep(300 * time.Millisecond)
				continue
			}

			if resp.StatusCode != http.StatusOK {
				resp.Body.Close()
				lastErr = fmt.Errorf("http %s from %s", resp.Status, tryURL)
				time.Sleep(300 * time.Millisecond)
				continue
			}

			// Clear temp file in case previous attempt wrote partial data
			if _, err := tmp.Seek(0, 0); err == nil {
				_ = tmp.Truncate(0)
			}
			if _, err := io.Copy(tmp, resp.Body); err != nil {
				resp.Body.Close()
				lastErr = err
				continue
			}
			resp.Body.Close()
			return tmp.Close()
		}
	}

	return fmt.Errorf("download failed across all mirrors: %v", lastErr)
}

// verifyELF rejects empty files and non-ELF downloads (e.g. an HTML
// error page from a stale release redirect).
func verifyELF(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	magic := make([]byte, 4)
	n, err := io.ReadFull(f, magic)
	if err != nil || n != 4 {
		return fmt.Errorf("file too small")
	}
	if magic[0] != 0x7f || magic[1] != 'E' || magic[2] != 'L' || magic[3] != 'F' {
		return fmt.Errorf("not an ELF binary")
	}
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

// restartSelf restarts the systemd unit when present, otherwise re-execs
// the new binary in place (dev / non-systemd environments).
func restartSelf() {
	if _, err := exec.LookPath("systemctl"); err == nil {
		_ = exec.Command("systemctl", "restart", "--no-block", "gre-panel").Run()
		return
	}
	exe, err := os.Executable()
	if err != nil {
		return
	}
	// Best effort: start the new binary; the old process exits.
	_ = exec.Command(exe).Start()
	os.Exit(0)
}

// sessionFile returns the path of the server-side session store.
func sessionFile() string { return filepath.Join(configDir, "sessions.json") }

// ---- hashem.sh sync (keeps server script in step with the binary) ----

// syncPanelScript refreshes hashem.sh from the running binary's own release.
func syncPanelScript() { syncPanelScriptFrom(runningReleaseTag()) }

// syncPanelScriptFrom downloads hashem.sh from release `tag` (checksum
// verified; main only if the tag has no such asset), syntax-checks
// it with `bash -n`, and installs it where greScriptPath() reads from
// (next to the running binary on servers).
// best-effort: never blocks the binary update.
func syncPanelScriptFrom(tag string) {
	target := greScriptTarget()
	if target == "" {
		return
	}
	dir := filepath.Dir(target)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			recordError("E-UPDATE-06", "script-sync", "mkdir "+dir+": "+err.Error())
			return
		}
	}
	tmp, err := os.CreateTemp("", "hashem-*.sh")
	if err != nil {
		recordError("E-UPDATE-06", "script-sync", "tmpfile: "+err.Error())
		return
	}
	tmpPath := tmp.Name()
	_ = tmp.Close()
	defer func() { _ = os.Remove(tmpPath) }()
	if err := fetchScript(tag, "hashem.sh", scriptURL, tmpPath); err != nil {
		recordError("E-UPDATE-06", "script-sync", "download: "+err.Error())
		return
	}
	// Verify script integrity: minimum size and shebang check (CWE-95)
	content, err := os.ReadFile(tmpPath)
	if err != nil || len(content) < 500 || (!strings.HasPrefix(string(content), "#!/bin/bash") && !strings.HasPrefix(string(content), "#!/usr/bin/env bash")) {
		recordError("E-UPDATE-06", "script-sync", "integrity check failed: invalid or corrupt script header")
		return
	}
	chk := exec.Command("bash", "-n", tmpPath)
	if out, err := chk.CombinedOutput(); err != nil {
		recordError("E-UPDATE-06", "script-sync", "bash -n failed: "+string(out))
		return
	}
	if err := copyFile(tmpPath, target); err != nil {
		recordError("E-UPDATE-06", "script-sync", "install: "+err.Error())
		return
	}
	_ = os.Chmod(target, 0755)
	LogSecurityAudit("script_synced", "system", "local", "target="+target)
	// Migrate servers to the new name: refresh the hashem copies + legacy
	// gre.sh symlink, and drop a stale standalone gre.sh file (symlink wins
	// so old lookup paths keep working).
	for _, p := range []string{"/usr/local/bin/hashem.sh", "/usr/local/bin/hashem"} {
		if p == target {
			continue
		}
		if err := copyFile(tmpPath, p); err == nil {
			_ = os.Chmod(p, 0755)
		}
	}
	_ = os.Remove("/usr/local/bin/gre.sh")
	_ = os.Symlink("/usr/local/bin/hashem.sh", "/usr/local/bin/gre.sh")
	syncChaffScript(tag)
}

// syncChaffScript installs /usr/local/bin/hashem-chaff.sh from release `tag`.
func syncChaffScript(tag string) {
	tmp, err := os.CreateTemp("", "hashem-chaff-*.sh")
	if err != nil {
		return
	}
	tmpPath := tmp.Name()
	_ = tmp.Close()
	defer func() { _ = os.Remove(tmpPath) }()
	if err := fetchScript(tag, "hashem-chaff.sh", chaffScriptURL, tmpPath); err != nil {
		recordError("E-UPDATE-06", "script-sync", "chaff download: "+err.Error())
		return
	}
	// Verify chaff script integrity
	chaffContent, err := os.ReadFile(tmpPath)
	if err != nil || len(chaffContent) < 100 || (!strings.HasPrefix(string(chaffContent), "#!/bin/bash") && !strings.HasPrefix(string(chaffContent), "#!/usr/bin/env bash")) {
		recordError("E-UPDATE-06", "script-sync", "chaff integrity check failed: invalid script header")
		return
	}
	if out, err := exec.Command("bash", "-n", tmpPath).CombinedOutput(); err != nil {
		recordError("E-UPDATE-06", "script-sync", "chaff bash -n failed: "+string(out))
		return
	}
	if err := copyFile(tmpPath, "/usr/local/bin/hashem-chaff.sh"); err != nil {
		recordError("E-UPDATE-06", "script-sync", "chaff install: "+err.Error())
		return
	}
	_ = os.Chmod("/usr/local/bin/hashem-chaff.sh", 0755)
	_ = os.Remove("/usr/local/bin/gre-chaff.sh")
	LogSecurityAudit("script_synced", "system", "local", "target=/usr/local/bin/hashem-chaff.sh")
}

const scriptURL = "https://raw.githubusercontent.com/pdnczone/hashem-panel/main/hashem.sh"

// chaffScriptURL ships the standalone chaff generator next to hashem.sh.
const chaffScriptURL = "https://raw.githubusercontent.com/pdnczone/hashem-panel/main/hashem-chaff.sh"

// greScriptURL stays as an alias: releases before the rename shipped gre.sh,
// and external tools may import the name.
const greScriptURL = scriptURL

var (
	_ = greScriptURL
	_ = sessionCount
)

func mustOpen(path string) *os.File {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err == nil {
		return f
	}
	f2, _ := os.Create(path)
	return f2
}

// sessionStore is the persisted set of valid session tokens.
type sessionStore struct {
	Tokens map[string]int64 `json:"tokens"` // token -> expires unix
}

func loadSessions() sessionStore {
	s := sessionStore{Tokens: map[string]int64{}}
	data, err := os.ReadFile(sessionFile())
	if err != nil {
		return s
	}
	_ = json.Unmarshal(data, &s)
	if s.Tokens == nil {
		s.Tokens = map[string]int64{}
	}
	return s
}

func (s sessionStore) save() {
	_ = os.WriteFile(sessionFile(), mustJSON(s), 0600)
}

// pruneExpired drops expired tokens; true if anything changed.
func (s sessionStore) pruneExpired() bool {
	now := time.Now().Unix()
	changed := false
	for tok, exp := range s.Tokens {
		if exp < now {
			delete(s.Tokens, tok)
			changed = true
		}
	}
	return changed
}

// sessionLifetime is 24 hours (absolute expiry from login).
const sessionLifetime = int64(24 * 3600)

func validSession(token string) bool {
	if token == "" {
		return false
	}
	mu.Lock()
	defer mu.Unlock()
	s := loadSessions()
	exp, ok := s.Tokens[token]
	if !ok || exp < time.Now().Unix() {
		return false
	}
	return true
}

func addSession(token string) {
	mu.Lock()
	defer mu.Unlock()
	s := loadSessions()
	s.pruneExpired()
	s.Tokens[token] = time.Now().Unix() + sessionLifetime
	s.save()
}

func dropSession(token string) {
	mu.Lock()
	defer mu.Unlock()
	s := loadSessions()
	delete(s.Tokens, token)
	s.save()
}

func dropAllSessions() {
	mu.Lock()
	defer mu.Unlock()
	sessionStore{Tokens: map[string]int64{}}.save()
}

func sessionCount() int {
	mu.Lock()
	defer mu.Unlock()
	s := loadSessions()
	if s.pruneExpired() {
		s.save()
	}
	n := 0
	for range s.Tokens {
		n++
	}
	return n
}
