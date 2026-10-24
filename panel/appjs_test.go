package main

import (
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// The UI script was extracted from index.html into app.js: the page must load
// it, the server must serve it, and it must not be left behind inline.
func TestAppJSExtracted(t *testing.T) {
	html, err := os.ReadFile("index.html")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(html), `<script src="app.js"></script>`) {
		t.Error("index.html must load app.js")
	}
	if strings.Count(string(html), "<script") != 2 { // theme-before-paint inline + app.js
		t.Errorf("unexpected number of <script> tags: %d", strings.Count(string(html), "<script"))
	}
	if strings.Contains(string(html), "async function api(") {
		t.Error("UI code must live in app.js, not inline")
	}
}

func TestAppJSServedWithJSContentType(t *testing.T) {
	rr := httptest.NewRecorder()
	serveAsset("app.js", "text/javascript; charset=utf-8")(rr, httptest.NewRequest("GET", "/app.js", nil))
	if rr.Code != 200 || !strings.HasPrefix(rr.Header().Get("Content-Type"), "text/javascript") {
		t.Fatalf("%d %q", rr.Code, rr.Header().Get("Content-Type"))
	}
	if !strings.Contains(rr.Body.String(), "async function api(") {
		t.Error("app.js body missing the api() helper")
	}
}

func TestIndexCacheBustsAppJS(t *testing.T) {
	old := cfg
	defer func() { cfg = old }()
	cfg.BasePath = "x"
	rr := httptest.NewRecorder()
	serveIndex(rr, httptest.NewRequest("GET", "/x/", nil))
	if !strings.Contains(rr.Body.String(), `src="app.js?v=`) {
		t.Error("app.js must be cache-busted per build")
	}
}
