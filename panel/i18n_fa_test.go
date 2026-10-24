package main

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
)

// faText loads the Persian phrase map from i18n-fa.js (window.FA_TEXT = {...};).
func faText(t *testing.T) map[string]string {
	t.Helper()
	src := readUI(t, "i18n-fa.js")
	i := strings.Index(src, "window.FA_TEXT = ")
	if i < 0 {
		t.Fatal("i18n-fa.js must assign window.FA_TEXT")
	}
	body := strings.TrimSuffix(strings.TrimSpace(src[i+len("window.FA_TEXT = "):]), ";")
	m := map[string]string{}
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatalf("i18n-fa.js is not a JSON object: %v", err)
	}
	return m
}

var persian = regexp.MustCompile(`[\x{0600}-\x{06FF}]`)

// Every Persian entry is Persian (a copied English value would silently show English).
func TestI18nFaValuesArePersian(t *testing.T) {
	m := faText(t)
	if len(m) < 1000 {
		t.Fatalf("only %d phrases; the map looks truncated", len(m))
	}
	for en, fa := range m {
		if !persian.MatchString(fa) {
			t.Errorf("%q -> %q has no Persian text", en, fa)
		}
	}
}

// Every keyed English string has a Persian phrase, except technical names that stay Latin.
func TestI18nFaCoversDictionary(t *testing.T) {
	m := faText(t)
	js := readUI(t, "app.js")
	start := strings.Index(js, "const I18N = {")
	end := strings.Index(js[start:], "\n};")
	if start < 0 || end < 0 {
		t.Fatal("I18N block not found")
	}
	if strings.Contains(js[start:start+end], "\n  fa: {") {
		t.Error("I18N.fa is back: Persian lives in i18n-fa.js, keyed strings go through tr()")
	}
	latin := map[string]bool{"CPU": true, "RAM": true, "GRE + FRP": true, "GRE + Backhaul": true, "FA / EN": true,
		"Ctrl K": true, "Backhaul": true, "GRE+Backhaul": true, "Mux": true, "TCP/UDP": true, "UDP):": true,
		"2FA": true, "PROXY Protocol v2": true, "Xray": true, "(AES/TLS)": true, "(Snappy)": true, "HTTPS:": true}
	val := regexp.MustCompile(`(?m)\b[a-z_0-9]+: "((?:\\.|[^"\\])*)"`)
	for _, mm := range val.FindAllStringSubmatch(js[start:start+end], -1) {
		v := strings.NewReplacer(`\"`, `"`, `\'`, `'`).Replace(mm[1])
		if !regexp.MustCompile(`[A-Za-z]{2}`).MatchString(v) || latin[v] || strings.Contains(v, "\\u") {
			continue
		}
		if _, ok := m[v]; !ok {
			t.Errorf("no Persian for %q", v)
		}
	}
}

// The phrase file is served and embedded like app.js.
func TestI18nFaServed(t *testing.T) {
	if !strings.Contains(readUI(t, "main.go"), `"/i18n-fa.js", serveAsset("i18n-fa.js"`) {
		t.Error("i18n-fa.js must be routed")
	}
	if !strings.Contains(readUI(t, "main.go"), "app.js i18n-fa.js") {
		t.Error("i18n-fa.js must be embedded")
	}
}

// UI source text is English; Persian lives only in i18n-fa.js. Persian written into
// the markup or app.js shows untranslated to English users.
func TestI18nSourceIsEnglish(t *testing.T) {
	for _, f := range []string{"index.html", "app.js"} {
		for i, line := range strings.Split(readUI(t, f), "\n") {
			if persian.MatchString(line) {
				t.Errorf("%s:%d: Persian text in UI source: %.80s", f, i+1, strings.TrimSpace(line))
			}
		}
	}
}

// A Persian phrase must not hold its own English key: the page translates text
// it shows, so "Path" -> "مسیر (Path)" grows forever and freezes the browser.
func TestI18nFaValuesDoNotHoldTheirKey(t *testing.T) {
	for en, fa := range faText(t) {
		if strings.Contains(fa, en) {
			t.Errorf("%q -> %q holds its own key", en, fa)
		}
	}
}
