package main

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The Tunnel tab sends target_engine / target_transport. The handler read
// only engine / transport, so every live switch failed with `invalid engine ""`.
func TestSwitchEngineActionReadsTargetEngine(t *testing.T) {
	for _, body := range []string{
		`{"action":"switch-engine","target_engine":"bogus","target_transport":"tcpmux"}`,
		`{"action":"switch-engine","engine":"bogus"}`,
	} {
		rr := httptest.NewRecorder()
		handleAction(rr, httptest.NewRequest("POST", "/api/action", strings.NewReader(body)))
		if !strings.Contains(rr.Body.String(), `invalid engine \"bogus\"`) {
			t.Fatalf("%s: engine not read: %d %s", body, rr.Code, rr.Body.String())
		}
	}
}

// Removing the first tunnel while other tunnels exist removes it alone: the
// full removal stops every frps*, backhaul* and gre-t* and drops peers.json.
func TestRemoveFirstTunnelKeepsOtherTunnels(t *testing.T) {
	dir := t.TempDir()
	old := configDir
	configDir = dir
	t.Cleanup(func() { configDir = old })
	script := filepath.Join(dir, "hashem.sh")
	if err := os.WriteFile(script, []byte("echo \"$@\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HASHEM_SCRIPT", script)
	peers := func(s string) {
		if err := os.WriteFile(peersFile(), []byte(`{"peers":[`+s+`]}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	second := `{"id":2,"gre_if":"gre-t2","frps_svc":"frps-2"}`
	for _, c := range []struct{ name, peers, want string }{
		{"no other tunnel", "", "remove-tunnel --force"},
		{"first from Setup", second, "remove-tunnel --base"},
		{"first as legacy peer 1", `{"id":1,"gre_if":"gre-tunnel","frps_svc":"frps","legacy":true},` + second, "remove-peer --id 1 --force"},
		{"first as a peer on gre-tunnel", `{"id":1,"gre_if":"gre-tunnel","frps_svc":"backhaul-server-1"},` + second, "remove-peer --id 1 --force"},
	} {
		peers(c.peers)
		out, err := runAction("remove-tunnel", 0)
		if err != nil || out != c.want {
			t.Errorf("%s: ran %q (%v), want %q", c.name, out, err, c.want)
		}
	}
}
