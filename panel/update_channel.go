package main

// Update channels: "stable" (semver vX.Y.Z releases, default) and "dev"
// (dev-rN prereleases built from the dev branch). The channel decides which
// release the version check, the updater and the script sync follow.
// hashem.sh (update_pick_tag) reads the same <configDir>/update.json.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
)

const (
	channelStable = "stable"
	channelDev    = "dev"

	// Installs up to panel-r148 are the first stable release: users see
	// legacyDisplay instead of the internal panel-rN tag.
	legacyPanelRBase = 148
	legacyDisplay    = "v1.0.0"
)

var (
	semverRe   = regexp.MustCompile(`^v(\d+)\.(\d+)\.(\d+)$`)
	devTagRe   = regexp.MustCompile(`^dev-r(\d+)$`)
	legacyRRe  = regexp.MustCompile(`^panel-r(\d+)$`)
	releaseAPI = "https://api.github.com/repos/pdnczone/hashem-panel/releases"
)

// validTag is the only shape of release tag the updater will ever put into a
// URL: vX.Y.Z, dev-rN or panel-rN. Anything else (slashes, "..", "?", quotes,
// spaces) is rejected before it reaches a download URL.
func validTag(t string) bool {
	return semverRe.MatchString(t) || devTagRe.MatchString(t) || legacyRRe.MatchString(t)
}

func updateConfigPath() string { return filepath.Join(configDir, "update.json") }

// updateChannel returns the configured channel; anything unreadable or
// invalid means stable.
func updateChannel() string {
	data, err := os.ReadFile(updateConfigPath())
	if err != nil {
		return channelStable
	}
	var c struct {
		Channel string `json:"channel"`
	}
	if json.Unmarshal(data, &c) != nil || c.Channel != channelDev {
		return channelStable
	}
	return channelDev
}

func saveUpdateChannel(ch string) error {
	if ch != channelStable && ch != channelDev {
		return fmt.Errorf("invalid channel")
	}
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(configDir, "update.json.*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if _, err := f.Write(mustJSON(map[string]string{"channel": ch})); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	f.Close()
	if err := os.Chmod(tmp, 0600); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, updateConfigPath()); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

func handleUpdateChannelGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]string{"channel": updateChannel()})
}

func handleUpdateChannelPost(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Channel string `json:"channel"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&req); err != nil ||
		(req.Channel != channelStable && req.Channel != channelDev) {
		writeAPIError(w, r, "E-UPDATE-08", "")
		return
	}
	if err := saveUpdateChannel(req.Channel); err != nil {
		writeAPIError(w, r, "E-UPDATE-04", err.Error())
		return
	}
	LogSecurityAudit("update_channel", cfg.Username, ClientIP(r), "channel="+req.Channel)
	writeJSON(w, map[string]string{"status": "ok", "channel": req.Channel})
}

// ghRelease is the subset of the GitHub release object the updater needs.
type ghRelease struct {
	Tag         string `json:"tag_name"`
	Name        string `json:"name"`
	Draft       bool   `json:"draft"`
	Prerelease  bool   `json:"prerelease"`
	PublishedAt string `json:"published_at"`
}

// releasesFetcher / latestTagFetcher are swapped in tests.
var (
	releasesFetcher  = fetchReleases
	latestTagFetcher = fetchLatestTag
)

func apiURLs(path string) []string {
	u := releaseAPI + path
	return []string{u, "https://mirror.ghproxy.com/" + u, "https://ghproxy.net/" + u}
}

// getJSON tries the API URL and its mirrors until one decodes into out.
func getJSON(path string, out any) error {
	var lastErr error
	for _, u := range apiURLs(path) {
		req, err := http.NewRequest("GET", u, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "hashem-panel-updater/"+panelVersion)
		resp, err := updateClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			lastErr = fmt.Errorf("github api: %s", resp.Status)
			continue
		}
		err = json.NewDecoder(resp.Body).Decode(out)
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		return nil
	}
	return lastErr
}

func fetchReleases() ([]ghRelease, error) {
	var rels []ghRelease
	if err := getJSON("?per_page=30", &rels); err != nil {
		return nil, err
	}
	return rels, nil
}

func fetchLatestTag() (string, error) {
	var rel ghRelease
	if err := getJSON("/latest", &rel); err != nil {
		return "", err
	}
	return rel.Tag, nil
}

// latestReleaseTag returns the newest release tag of the active channel.
// Empty string = could not determine (offline / rate-limited / none yet).
func latestReleaseTag() (string, error) {
	ch := updateChannel()
	rels, err := releasesFetcher()
	if err == nil {
		if tag := pickChannelTag(ch, rels); tag != "" && validTag(tag) {
			return tag, nil
		}
	}
	if ch == channelDev {
		return "", err // never fall back across channels
	}
	// stable: GitHub's "Latest" release is the last resort
	tag, lerr := latestTagFetcher()
	if tag != "" && !validTag(tag) {
		return "", fmt.Errorf("refusing unexpected release tag")
	}
	if tag == "" && lerr == nil {
		lerr = err
	}
	return tag, lerr
}

// pickChannelTag selects from a release list (any order).
// stable: highest vX.Y.Z non-prerelease, else newest non-prerelease/non-draft.
// dev: highest dev-rN prerelease.
func pickChannelTag(ch string, rels []ghRelease) string {
	best, bestTag, firstStable := -1, "", ""
	for _, rel := range rels {
		if rel.Draft {
			continue
		}
		if ch == channelDev {
			if m := devTagRe.FindStringSubmatch(rel.Tag); m != nil && rel.Prerelease {
				if n, _ := strconv.Atoi(m[1]); n > best {
					best, bestTag = n, rel.Tag
				}
			}
			continue
		}
		if rel.Prerelease {
			continue
		}
		if firstStable == "" && rel.Tag != "" {
			firstStable = rel.Tag
		}
		if semverRe.MatchString(rel.Tag) && (bestTag == "" || compareVersions(rel.Tag, bestTag) > 0) {
			bestTag = rel.Tag
		}
	}
	if ch == channelStable && bestTag == "" {
		return firstStable // list is newest-first from the API
	}
	return bestTag
}

// parseVersion returns the release family (3 semver, 2 dev-rN, 1 panel-rN,
// 0 unknown) and its numbers.
func parseVersion(v string) (kind int, nums [3]int) {
	if m := semverRe.FindStringSubmatch(v); m != nil {
		for i := 0; i < 3; i++ {
			nums[i], _ = strconv.Atoi(m[i+1])
		}
		return 3, nums
	}
	if m := devTagRe.FindStringSubmatch(v); m != nil {
		nums[0], _ = strconv.Atoi(m[1])
		return 2, nums
	}
	if m := legacyRRe.FindStringSubmatch(v); m != nil {
		nums[0], _ = strconv.Atoi(m[1])
		return 1, nums
	}
	return 0, nums
}

// compareVersions returns -1/0/+1. Same family compares numerically; across
// families semver > dev-rN > panel-rN > unknown.
func compareVersions(a, b string) int {
	ka, na := parseVersion(a)
	kb, nb := parseVersion(b)
	if ka != kb {
		if ka < kb {
			return -1
		}
		return 1
	}
	for i := 0; i < 3; i++ {
		if na[i] != nb[i] {
			if na[i] < nb[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

// displayVersion hides internal panel-rN tags: builds up to legacyPanelRBase
// are the first stable release.
func displayVersion(v string) string {
	if m := legacyRRe.FindStringSubmatch(v); m != nil {
		if n, _ := strconv.Atoi(m[1]); n <= legacyPanelRBase {
			return legacyDisplay
		}
	}
	return v
}

// updateAvailable: is latest strictly newer than current under channel rules?
// On dev, a host not running a dev build is offered the newest dev build
// (that is what switching channel is for).
func updateAvailable(current, latest, ch string) bool {
	if latest == "" || latest == current {
		return false
	}
	if ch == channelDev {
		if k, _ := parseVersion(current); k != 2 {
			return true
		}
	}
	return compareVersions(latest, current) > 0
}

func handleVersion(w http.ResponseWriter, r *http.Request) {
	latest, _ := latestReleaseTag()
	ch := updateChannel()
	writeJSON(w, map[string]any{
		"current":          displayVersion(panelVersion),
		"latest":           displayVersion(latest),
		"channel":          ch,
		"update_available": updateAvailable(panelVersion, latest, ch),
	})
}

// handleReleases lists the last 20 releases of a channel for the UI.
func handleReleases(w http.ResponseWriter, r *http.Request) {
	ch := r.URL.Query().Get("channel")
	if ch == "" {
		ch = updateChannel()
	}
	if ch != channelStable && ch != channelDev {
		writeAPIError(w, r, "E-UPDATE-08", "")
		return
	}
	rels, err := releasesFetcher()
	if err != nil {
		writeAPIError(w, r, "E-UPDATE-01", err.Error())
		return
	}
	out := []map[string]any{}
	sort.SliceStable(rels, func(i, j int) bool { return compareVersions(rels[i].Tag, rels[j].Tag) > 0 })
	for _, rel := range rels {
		if rel.Draft {
			continue
		}
		if ch == channelDev {
			if !rel.Prerelease || !devTagRe.MatchString(rel.Tag) {
				continue
			}
		} else if rel.Prerelease || !(semverRe.MatchString(rel.Tag) || legacyRRe.MatchString(rel.Tag)) {
			continue
		}
		out = append(out, map[string]any{
			"tag": rel.Tag, "name": rel.Name, "date": rel.PublishedAt, "prerelease": rel.Prerelease,
		})
		if len(out) == 20 {
			break
		}
	}
	writeJSON(w, map[string]any{"channel": ch, "releases": out})
}

// ---- script sync from the release being installed ----

// scriptDownloader is swapped in tests.
var scriptDownloader = downloadFile

// runningReleaseTag is the release the running binary came from, usable as a
// script source; "" for dev/source builds.
func runningReleaseTag() string {
	if semverRe.MatchString(panelVersion) || devTagRe.MatchString(panelVersion) {
		return panelVersion
	}
	return ""
}

func releaseAssetURL(tag, name string) string {
	return "https://github.com/pdnczone/hashem-panel/releases/download/" + tag + "/" + name
}

// fetchScript downloads name into dst from release `tag` and verifies it
// against that tag's checksums.txt (fail-closed). Only a missing asset of a
// stable/legacy tag falls back to mainURL; a checksum failure never does and
// a dev tag never does.
func fetchScript(tag, name, mainURL, dst string) error {
	if tag != "" && tag != "latest" {
		if !validTag(tag) {
			return fmt.Errorf("refusing unexpected release tag")
		}
		f := mustOpen(dst)
		err := scriptDownloader(releaseAssetURL(tag, name), f)
		_ = f.Close()
		if err == nil {
			return verifyAssetChecksum(dst, tag, name)
		}
		if devTagRe.MatchString(tag) {
			return err // a dev build never pulls scripts from main
		}
	}
	f := mustOpen(dst)
	err := scriptDownloader(mainURL, f)
	_ = f.Close()
	return err
}
