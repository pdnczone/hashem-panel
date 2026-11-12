package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCoreNetPath(t *testing.T) {
	for _, c := range []struct {
		path string
		want bool
	}{
		{"/_hp/api/peer/ping", true},
		{"/_hc/beat", true},
		{"/_hs/abc", true},
		{"/_hsplugin/k", true},
		{"/secret/api/peer/apply-engine", true},
		{"/", false},
		{"/secret/", false},
		{"/secret/app.js", false},
		{"/secret/api/login", false},
		{"/secret/api/health", false},
		{"/secret/api/status", false},
		{"/secret/api/term/ws", false},
		{"/secret/metrics", false},
		{"/_hn/link", false},
		{"/other/api/peer/ping", false},
		{"/_hp/../secret/api/login", false},
		{"/secret/api/peer/../login", false},
		{"/_hp", false},
	} {
		if got := coreNetPath(c.path, "secret"); got != c.want {
			t.Errorf("coreNetPath(%q) = %v, want %v", c.path, got, c.want)
		}
	}
	if coreNetPath("//api/peer/ping", "") {
		t.Error("an empty base path must not open /api/peer")
	}
}

// A core answers the network on its server-to-server paths only; what the
// central relays runs on the mux itself and never meets the gate.
func TestCoreGate(t *testing.T) {
	mu.Lock()
	old := cfg.BasePath
	cfg.BasePath = "secret"
	mu.Unlock()
	defer func() { mu.Lock(); cfg.BasePath = old; mu.Unlock() }()

	mux := http.NewServeMux()
	hit := func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("in")) }
	for _, p := range []string{"/_hp/api/peer/ping", "/secret/api/status", "/secret/api/login", "/secret/", "/"} {
		mux.HandleFunc(p, hit)
	}
	get := func(h http.Handler, path string) (int, string) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		return rec.Code, rec.Body.String()
	}

	core := coreGateFor(true, mux)
	if code, body := get(core, "/_hp/api/peer/ping"); code != 200 || body != "in" {
		t.Errorf("core: the Peer Link answered %d %q", code, body)
	}
	for _, p := range []string{"/secret/api/status", "/secret/api/login", "/secret/", "/", "/anything"} {
		code, body := get(core, p)
		if code != http.StatusNotFound || strings.Contains(body, "in") {
			t.Errorf("core: %s answered %d %q, want a plain 404", p, code, body)
		}
	}
	// the relay's way in: the mux itself
	if code, _ := get(mux, "/secret/api/status"); code != 200 {
		t.Errorf("relayed call on a core answered %d", code)
	}

	panel := coreGateFor(false, mux)
	for _, p := range []string{"/secret/api/status", "/secret/", "/_hp/api/peer/ping"} {
		if code, _ := get(panel, p); code != 200 {
			t.Errorf("panel: %s answered %d", p, code)
		}
	}
}

func TestNodeInfoKind(t *testing.T) {
	if got := nodeInfoClean(nodeInfo{Kind: nodeKindCore}).Kind; got != nodeKindCore {
		t.Errorf("a core's kind became %q", got)
	}
	if got := nodeInfoClean(nodeInfo{Kind: "<b>x</b>"}).Kind; got != "" {
		t.Errorf("an unknown kind was kept: %q", got)
	}
	want := ""
	if nodeCore {
		want = nodeKindCore
	}
	if got := nodeLocalKind(); got != want {
		t.Errorf("this build reports kind %q, want %q", got, want)
	}
}

// The two builds differ in what is embedded and in the update asset's name.
func TestCoreBuild(t *testing.T) {
	_, err := panelFS.ReadFile("index.html")
	if nodeCore && err == nil {
		t.Error("a core build has the web page in it")
	}
	if !nodeCore && err != nil {
		t.Errorf("a panel build has no web page: %v", err)
	}
	_, asset, err := panelAsset()
	if err != nil {
		t.Skip(err) // an arch with no release
	}
	if !strings.HasPrefix(asset, binName()+"-linux-") {
		t.Errorf("update asset %q is not this build's (%s)", asset, binName())
	}
	if nodeCore != (binName() == "hashem-node") {
		t.Errorf("binName %q on nodeCore=%v", binName(), nodeCore)
	}
}
