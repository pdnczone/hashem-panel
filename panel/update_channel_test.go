package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func withTmpConfig(t *testing.T) string {
	t.Helper()
	old := configDir
	configDir = t.TempDir()
	t.Cleanup(func() { configDir = old })
	return configDir
}

func canned(rels []ghRelease, err error) func() ([]ghRelease, error) {
	return func() ([]ghRelease, error) { return rels, err }
}

func swapFetchers(t *testing.T, rf func() ([]ghRelease, error), lf func() (string, error)) {
	t.Helper()
	or, ol := releasesFetcher, latestTagFetcher
	releasesFetcher, latestTagFetcher = rf, lf
	t.Cleanup(func() { releasesFetcher, latestTagFetcher = or, ol })
}

var sampleReleases = []ghRelease{
	{Tag: "dev-r30", Prerelease: true},
	{Tag: "dev-r9", Prerelease: true},
	{Tag: "v1.0.1", Prerelease: true}, // prerelease semver must never be stable
	{Tag: "v1.0.0"},
	{Tag: "v1.0.10", Draft: true},
	{Tag: "v.0.1.1"},
	{Tag: "v1.0.2-rc1"},
	{Tag: "v0.9.0"},
	{Tag: "panel-r200"},
	{Tag: "panel-r148"},
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"panel-r148", "v1.0.0", -1},
		{"v1.0.0", "v1.0.1", -1},
		{"v1.0.1", "v1.1.0", -1},
		{"v1.0.9", "v1.0.10", -1},
		{"v1.0.0", "v1.0.0", 0},
		{"v1.1.0", "v1.0.1", 1},
		{"dev-r5", "dev-r12", -1},
		{"dev-r12", "dev-r5", 1},
		{"dev-r7", "dev-r7", 0},
		{"dev-r999", "v1.0.0", -1},
		{"v1.0.0", "dev-r999", 1},
		{"panel-r10", "panel-r148", -1},
		{"junk", "panel-r1", -1},
	}
	for _, c := range cases {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compareVersions(%q,%q)=%d want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestDisplayVersion(t *testing.T) {
	cases := map[string]string{
		"panel-r148": "v1.0.0",
		"panel-r10":  "v1.0.0",
		"panel-r149": "panel-r149",
		"v1.2.3":     "v1.2.3",
		"dev-r12":    "dev-r12",
		"":           "",
	}
	for in, want := range cases {
		if got := displayVersion(in); got != want {
			t.Errorf("displayVersion(%q)=%q want %q", in, got, want)
		}
	}
}

func TestLatestReleaseTagStable(t *testing.T) {
	withTmpConfig(t)
	swapFetchers(t, canned(sampleReleases, nil), func() (string, error) { t.Fatal("latest fallback used"); return "", nil })
	got, _ := latestReleaseTag()
	if got != "v1.0.0" {
		t.Fatalf("stable picked %q, want v1.0.0", got)
	}
	// higher semver wins regardless of list order
	rels := append([]ghRelease{{Tag: "v1.2.0"}, {Tag: "v1.10.0"}, {Tag: "v1.9.9"}}, sampleReleases...)
	swapFetchers(t, canned(rels, nil), nil)
	if got, _ := latestReleaseTag(); got != "v1.10.0" {
		t.Fatalf("stable picked %q, want v1.10.0", got)
	}
}

func TestLatestReleaseTagStableFallbacks(t *testing.T) {
	withTmpConfig(t)
	// no semver stable: newest non-prerelease/non-draft (list is newest first)
	rels := []ghRelease{{Tag: "dev-r3", Prerelease: true}, {Tag: "panel-r149"}, {Tag: "panel-r148"}}
	swapFetchers(t, canned(rels, nil), func() (string, error) { return "X", nil })
	if got, _ := latestReleaseTag(); got != "panel-r149" {
		t.Fatalf("pre-v1 fallback picked %q, want panel-r149", got)
	}
	// nothing usable: releases/latest
	swapFetchers(t, canned([]ghRelease{{Tag: "dev-r3", Prerelease: true}}, nil), func() (string, error) { return "panel-r150", nil })
	if got, _ := latestReleaseTag(); got != "panel-r150" {
		t.Fatalf("latest fallback picked %q", got)
	}
	// list fetch failed: releases/latest
	swapFetchers(t, canned(nil, errors.New("down")), func() (string, error) { return "v1.0.0", nil })
	if got, _ := latestReleaseTag(); got != "v1.0.0" {
		t.Fatalf("list-down fallback picked %q", got)
	}
	// everything down: empty + error
	swapFetchers(t, canned(nil, errors.New("down")), func() (string, error) { return "", errors.New("down2") })
	if got, err := latestReleaseTag(); got != "" || err == nil {
		t.Fatalf("expected empty+err, got %q %v", got, err)
	}
}

func TestLatestReleaseTagDev(t *testing.T) {
	withTmpConfig(t)
	if err := saveUpdateChannel("dev"); err != nil {
		t.Fatal(err)
	}
	swapFetchers(t, canned(sampleReleases, nil), func() (string, error) { t.Fatal("dev must not use releases/latest"); return "", nil })
	if got, _ := latestReleaseTag(); got != "dev-r30" {
		t.Fatalf("dev picked %q, want dev-r30 (numeric, not lexical)", got)
	}
	// dev tag that is NOT a prerelease is ignored; no dev build => empty, never stable
	swapFetchers(t, canned([]ghRelease{{Tag: "dev-r5"}, {Tag: "v1.0.0"}}, nil), nil)
	if got, _ := latestReleaseTag(); got != "" {
		t.Fatalf("dev must not fall back to stable, got %q", got)
	}
}

func TestUpdateAvailableMatrix(t *testing.T) {
	cases := []struct {
		cur, latest, ch string
		want            bool
	}{
		{"panel-r148", "v1.0.0", "stable", true},
		{"panel-r10", "v1.0.0", "stable", true},
		{"v1.0.0", "v1.0.0", "stable", false},
		{"v1.0.0", "v1.0.1", "stable", true},
		{"v1.1.0", "v1.0.1", "stable", false},
		{"dev-r40", "v1.0.0", "stable", true},
		{"v1.0.0", "", "stable", false},
		{"panel-r148", "panel-r148", "stable", false},
		{"dev-r5", "dev-r12", "dev", true},
		{"dev-r12", "dev-r12", "dev", false},
		{"dev-r12", "dev-r5", "dev", false},
		{"v1.0.0", "dev-r3", "dev", true}, // switching to dev offers newest dev build
	}
	for _, c := range cases {
		if got := updateAvailable(c.cur, c.latest, c.ch); got != c.want {
			t.Errorf("updateAvailable(%q,%q,%q)=%v want %v", c.cur, c.latest, c.ch, got, c.want)
		}
	}
}

func TestHandleVersionNormalisesLegacy(t *testing.T) {
	withTmpConfig(t)
	old := panelVersion
	panelVersion = "panel-r148"
	t.Cleanup(func() { panelVersion = old })
	swapFetchers(t, canned(sampleReleases, nil), nil)
	rec := httptest.NewRecorder()
	handleVersion(rec, httptest.NewRequest("GET", "/api/version", nil))
	body := rec.Body.String()
	if strings.Contains(body, "panel-r") || !strings.Contains(body, `"current":"v1.0.0"`) ||
		!strings.Contains(body, `"latest":"v1.0.0"`) || !strings.Contains(body, `"update_available":true`) {
		t.Fatalf("unexpected /api/version: %s", body)
	}
}

func TestUpdateChannelDefaultsAndInvalid(t *testing.T) {
	dir := withTmpConfig(t)
	if updateChannel() != "stable" {
		t.Fatal("default must be stable")
	}
	for _, raw := range []string{`{"channel":"beta"}`, `{"channel":"../x"}`, `{"channel":""}`, `garbage`, `{"channel":5}`} {
		_ = os.WriteFile(filepath.Join(dir, "update.json"), []byte(raw), 0600)
		if updateChannel() != "stable" {
			t.Fatalf("%s must read as stable", raw)
		}
	}
	_ = os.WriteFile(filepath.Join(dir, "update.json"), []byte(`{"channel":"dev"}`), 0600)
	if updateChannel() != "dev" {
		t.Fatal("dev not read")
	}
}

func TestUpdateChannelEndpoint(t *testing.T) {
	dir := withTmpConfig(t)
	post := func(body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		handleUpdateChannelPost(rec, httptest.NewRequest("POST", "/api/update/channel", strings.NewReader(body)))
		return rec
	}
	for _, bad := range []string{`{"channel":"beta"}`, `{"channel":"../x"}`, `{"channel":""}`, `{}`, `nope`, `{"channel":"Dev"}`} {
		if rec := post(bad); rec.Code != http.StatusBadRequest {
			t.Errorf("%s => %d, want 400", bad, rec.Code)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "update.json")); err == nil {
		t.Fatal("update.json written by rejected requests")
	}
	if rec := post(`{"channel":"dev"}`); rec.Code != http.StatusOK {
		t.Fatalf("valid dev => %d %s", rec.Code, rec.Body.String())
	}
	st, err := os.Stat(filepath.Join(dir, "update.json"))
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("update.json missing or mode %v (%v)", st, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "update.json.tmp")); err == nil {
		t.Fatal("tmp file left behind")
	}
	rec := httptest.NewRecorder()
	handleUpdateChannelGet(rec, httptest.NewRequest("GET", "/api/update/channel", nil))
	if !strings.Contains(rec.Body.String(), `"channel":"dev"`) {
		t.Fatalf("GET => %s", rec.Body.String())
	}
}

func TestHandleReleasesFiltersChannel(t *testing.T) {
	withTmpConfig(t)
	swapFetchers(t, canned(sampleReleases, nil), nil)
	get := func(q string) string {
		rec := httptest.NewRecorder()
		handleReleases(rec, httptest.NewRequest("GET", "/api/releases"+q, nil))
		return rec.Body.String()
	}
	dev := get("?channel=dev")
	if !strings.Contains(dev, "dev-r30") || strings.Contains(dev, "v1.0.0") {
		t.Fatalf("dev list wrong: %s", dev)
	}
	st := get("?channel=stable")
	if !strings.Contains(st, "v1.0.0") || strings.Contains(st, "dev-r") || strings.Contains(st, `"v1.0.1"`) ||
		strings.Contains(st, "v1.0.10") || strings.Contains(st, "v.0.1.1") {
		t.Fatalf("stable list wrong: %s", st)
	}
	rec := httptest.NewRecorder()
	handleReleases(rec, httptest.NewRequest("GET", "/api/releases?channel=beta", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("beta => %d", rec.Code)
	}
}

func TestFetchScriptPrefersReleaseTag(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "s.sh")
	od, om := scriptDownloader, manifestFetcher
	t.Cleanup(func() { scriptDownloader, manifestFetcher = od, om })
	var urls []string
	body := "#!/bin/bash\necho hi\n"
	scriptDownloader = func(u string, f *os.File) error {
		urls = append(urls, u)
		_, _ = f.WriteString(body)
		return f.Close()
	}
	sum := "e4e8b2ce2e22e6b1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f70819"
	manifestFetcher = func(string) (map[string]string, error) { return map[string]string{"hashem.sh": sum}, nil }

	// checksum mismatch: error, and main is NOT tried
	if err := fetchScript("v1.0.0", "hashem.sh", scriptURL, dst); err == nil {
		t.Fatal("expected checksum failure")
	}
	if len(urls) != 1 || urls[0] != "https://github.com/pdnczone/hashem-panel/releases/download/v1.0.0/hashem.sh" {
		t.Fatalf("urls=%v", urls)
	}

	// correct checksum passes
	h, _ := ComputeSHA256(strings.NewReader(body))
	manifestFetcher = func(string) (map[string]string, error) { return map[string]string{"hashem.sh": h}, nil }
	urls = nil
	if err := fetchScript("dev-r7", "hashem.sh", scriptURL, dst); err != nil {
		t.Fatal(err)
	}
	if len(urls) != 1 || !strings.Contains(urls[0], "/download/dev-r7/hashem.sh") {
		t.Fatalf("urls=%v", urls)
	}

	// missing tag asset => legacy main URL
	urls = nil
	scriptDownloader = func(u string, f *os.File) error {
		urls = append(urls, u)
		if strings.Contains(u, "/releases/download/") {
			return errors.New("404")
		}
		return f.Close()
	}
	if err := fetchScript("v1.0.0", "hashem-chaff.sh", chaffScriptURL, dst); err != nil {
		t.Fatal(err)
	}
	if len(urls) != 2 || urls[1] != chaffScriptURL {
		t.Fatalf("urls=%v", urls)
	}

	// no tag (source build) => main directly
	urls = nil
	if err := fetchScript("", "hashem.sh", scriptURL, dst); err != nil || len(urls) != 1 || urls[0] != scriptURL {
		t.Fatalf("urls=%v err=%v", urls, err)
	}
}

func TestRunningReleaseTag(t *testing.T) {
	old := panelVersion
	t.Cleanup(func() { panelVersion = old })
	for v, want := range map[string]string{"v1.0.0": "v1.0.0", "dev-r3": "dev-r3", "panel-r148": "", "dev": ""} {
		panelVersion = v
		if got := runningReleaseTag(); got != want {
			t.Errorf("runningReleaseTag(%q)=%q want %q", v, got, want)
		}
	}
}

func TestHandleUpdateRefusesNotNewer(t *testing.T) {
	old := panelVersion
	defer func() { panelVersion = old }()
	defer func(f func() ([]ghRelease, error)) { releasesFetcher = f }(releasesFetcher)
	releasesFetcher = func() ([]ghRelease, error) {
		return []ghRelease{{Tag: "v1.0.0"}}, nil
	}
	panelVersion = "v1.0.1" // running newer than the channel's latest
	rr := httptest.NewRecorder()
	handleUpdate(rr, httptest.NewRequest("POST", "/api/update", nil))
	if !strings.Contains(rr.Body.String(), "already latest") {
		t.Fatalf("a newer running build must not be 'updated' to an older tag: %s", rr.Body.String())
	}
}

func TestValidTagRejectsURLTricks(t *testing.T) {
	for _, bad := range []string{"", "../x", "v1.0.0/../../o", "v1.0.0?x=1", "v1.0.0#f", "v1.0.0 evil", "v1.0.0\"", "x/y", "%2e%2e", "latest", "v1.0", "panel-r", "dev-rx"} {
		if validTag(bad) {
			t.Errorf("validTag(%q) = true", bad)
		}
	}
	for _, ok := range []string{"v1.0.0", "v12.3.45", "dev-r7", "panel-r148"} {
		if !validTag(ok) {
			t.Errorf("validTag(%q) = false", ok)
		}
	}
}

func TestLatestFallbackRejectsOddTag(t *testing.T) {
	defer func(a func() ([]ghRelease, error), b func() (string, error)) { releasesFetcher, latestTagFetcher = a, b }(releasesFetcher, latestTagFetcher)
	releasesFetcher = func() ([]ghRelease, error) { return nil, errors.New("api down") }
	latestTagFetcher = func() (string, error) { return "x/../../../other/repo/releases/download/t", nil }
	if tag, _ := latestReleaseTag(); tag != "" {
		t.Fatalf("odd fallback tag must be refused, got %q", tag)
	}
}

func TestFetchScriptDevTagNeverFallsBackToMain(t *testing.T) {
	defer func(f func(string, *os.File) error) { scriptDownloader = f }(scriptDownloader)
	var urls []string
	scriptDownloader = func(u string, f *os.File) error { urls = append(urls, u); return errors.New("404") }
	dst := filepath.Join(t.TempDir(), "h.sh")
	if err := fetchScript("dev-r5", "hashem.sh", "https://raw.githubusercontent.com/x/main/hashem.sh", dst); err == nil {
		t.Fatal("expected error")
	}
	for _, u := range urls {
		if strings.Contains(u, "/main/") {
			t.Fatalf("dev tag fell back to main: %v", urls)
		}
	}
	urls = nil
	_ = fetchScript("v1.0.0", "hashem.sh", "https://raw.githubusercontent.com/x/main/hashem.sh", dst)
	if len(urls) != 2 || !strings.Contains(urls[1], "/main/") {
		t.Fatalf("stable tag should still fall back to main for a missing asset: %v", urls)
	}
}

func TestSaveUpdateChannelPerms(t *testing.T) {
	if err := saveUpdateChannel("dev"); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(updateConfigPath())
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("update.json perms: %v %v", st, err)
	}
	if left, _ := filepath.Glob(filepath.Join(configDir, "update.json.*")); len(left) != 0 {
		t.Fatalf("temp files left behind: %v", left)
	}
}
