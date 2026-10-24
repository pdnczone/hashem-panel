package main

// Step 1: access settings (port / username / base_path) with validation,
// conflict checks against tunnel ports, and restart of only gre-panel.
import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func accessLab(t *testing.T) {
	t.Helper()
	oldCfg := cfg
	oldPorts := accessTunnelPorts
	t.Cleanup(func() {
		mu.Lock()
		cfg = oldCfg
		saveCfg()
		mu.Unlock()
		accessTunnelPorts = oldPorts
	})
	mu.Lock()
	cfg.Username = "admin"
	cfg.PassHash = hashPassword("Test-Pass-1234!")
	cfg.Port = 17777
	cfg.BasePath = "testbase1234"
	saveCfg()
	mu.Unlock()
	// deterministic tunnel-port view: FRP on 19999, a proxy on 24443
	accessTunnelPorts = func() map[int]string {
		return map[int]string{19999: "FRP Port", 24443: "Tunnel Proxy Port (24443)"}
	}
}

func postAccess(t *testing.T, body string) (int, map[string]any) {
	t.Helper()
	rr := httptest.NewRecorder()
	handleAccessPost(rr, httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(body)))
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return rr.Code, out
}

func TestAccessValidation(t *testing.T) {
	accessLab(t)
	if code, _ := postAccess(t, `{bad`); code != 400 {
		t.Errorf("bad json = %d, want 400", code)
	}
	if code, _ := postAccess(t, `{"port":18888}`); code != 401 {
		t.Errorf("missing password = %d, want 401", code)
	}
	if code, _ := postAccess(t, `{"current_password":"nope","port":18888}`); code != 401 {
		t.Errorf("wrong password = %d, want 401", code)
	}
	if code, _ := postAccess(t, `{"current_password":"Test-Pass-1234!","port":99999}`); code != 400 {
		t.Errorf("bad port = %d, want 400", code)
	}
	if code, _ := postAccess(t, `{"current_password":"Test-Pass-1234!","port":80}`); code != 409 {
		t.Errorf("port 80 = %d, want 409", code)
	}
	if code, _ := postAccess(t, `{"current_password":"Test-Pass-1234!","port":443}`); code != 409 {
		t.Errorf("port 443 = %d, want 409", code)
	}
	if code, _ := postAccess(t, `{"current_password":"Test-Pass-1234!","base_path":"ab"}`); code != 400 {
		t.Errorf("short base = %d, want 400", code)
	}
	if code, _ := postAccess(t, `{"current_password":"Test-Pass-1234!","base_path":"has space"}`); code != 400 {
		t.Errorf("space in base = %d, want 400", code)
	}
	if code, _ := postAccess(t, `{"current_password":"Test-Pass-1234!","username":"x"}`); code != 400 {
		t.Errorf("short username = %d, want 400", code)
	}
	if code, _ := postAccess(t, `{"current_password":"Test-Pass-1234!"}`); code != 400 {
		t.Errorf("empty change = %d, want 400", code)
	}
}

func TestAccessTunnelPortConflict(t *testing.T) {
	accessLab(t)
	if code, out := postAccess(t, `{"current_password":"Test-Pass-1234!","port":19999}`); code != 409 {
		t.Errorf("FRP port clash = %d %+v, want 409", code, out)
	}
	if code, _ := postAccess(t, `{"current_password":"Test-Pass-1234!","port":24443}`); code != 409 {
		t.Errorf("proxy port clash = %d, want 409", code)
	}
}

func TestAccessSuccess(t *testing.T) {
	accessLab(t)
	code, out := postAccess(t, `{"current_password":"Test-Pass-1234!","port":18888,"username":"opsadmin","base_path":"ops-panel-1"}`)
	if code != 200 {
		t.Fatalf("happy path = %d %+v, want 200", code, out)
	}
	mu.Lock()
	got := cfg
	mu.Unlock()
	if got.Port != 18888 || got.Username != "opsadmin" || got.BasePath != "ops-panel-1" {
		t.Errorf("cfg not updated: %+v", got)
	}
	raw, _ := os.ReadFile(filepath.Join(configDir, "panel.json"))
	var saved panelConfig
	_ = json.Unmarshal(raw, &saved)
	if saved.Port != 18888 || saved.Username != "opsadmin" || saved.BasePath != "ops-panel-1" {
		t.Errorf("not persisted: %+v", saved)
	}
	// response carries the new URL so the UI can redirect after restart
	if out["http_url"] == nil || !strings.Contains(out["http_url"].(string), ":18888/ops-panel-1") {
		t.Errorf("response must carry new URL for redirect: %+v", out)
	}
}

func TestAccessPartialUpdateKeepsRest(t *testing.T) {
	accessLab(t)
	if code, _ := postAccess(t, `{"current_password":"Test-Pass-1234!","username":"onlyname"}`); code != 200 {
		t.Fatalf("username-only change must succeed")
	}
	mu.Lock()
	defer mu.Unlock()
	if cfg.Username != "onlyname" || cfg.Port != 17777 || cfg.BasePath != "testbase1234" {
		t.Errorf("partial update clobbered other fields: %+v", cfg)
	}
}

func TestAccessGet(t *testing.T) {
	accessLab(t)
	rr := httptest.NewRecorder()
	handleAccessGet(rr, httptest.NewRequest(http.MethodGet, "/x", nil))
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if out["username"] != "admin" || out["http_port"] != float64(17777) || out["base_path"] != "testbase1234" {
		t.Errorf("unexpected GET payload: %+v", out)
	}
	if _, hasHash := out["pass_hash"]; hasHash {
		t.Error("pass_hash must never be exposed")
	}
}

func TestValidBasePath(t *testing.T) {
	for _, bad := range []string{"", "ab", "has space", "a/b", "a?b", ".hidden", "-lead", strings.Repeat("x", 65)} {
		if validBasePath(bad) {
			t.Errorf("%q must be rejected", bad)
		}
	}
	for _, good := range []string{"abcd", "ops-panel_1", "Panel99", strings.Repeat("y", 64)} {
		if !validBasePath(good) {
			t.Errorf("%q must be accepted", good)
		}
	}
}

func TestValidUsername(t *testing.T) {
	for _, bad := range []string{"", "ab", "has space", "a/b", strings.Repeat("z", 65)} {
		if validUsername(bad) {
			t.Errorf("%q must be rejected", bad)
		}
	}
	if !validUsername("ops-admin_1") {
		t.Error("ops-admin_1 must be accepted")
	}
}

func TestAccessConcurrentReadsDoNotRace(t *testing.T) {
	accessLab(t)
	done := make(chan struct{})
	go func() {
		for i := 0; i < 50; i++ {
			rr := httptest.NewRecorder()
			handleAccessGet(rr, httptest.NewRequest(http.MethodGet, "/x", nil))
		}
		close(done)
	}()
	for i := 0; i < 50; i++ {
		_, _ = postAccess(t, `{"current_password":"Test-Pass-1234!","username":"raceuser"}`)
		mu.Lock()
		cfg.Username = "admin"
		saveCfg()
		mu.Unlock()
	}
	<-done
}
