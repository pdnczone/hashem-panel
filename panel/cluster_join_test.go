package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// shellFunc returns the definition of the hashem.sh function name.
func shellFunc(t *testing.T, script, name string) string {
	t.Helper()
	var b strings.Builder
	in := false
	for _, l := range strings.Split(script, "\n") {
		if !in && strings.HasPrefix(l, name+"() {") {
			in = true
		}
		if in {
			b.WriteString(l + "\n")
			if l == "}" {
				return b.String()
			}
		}
	}
	t.Fatalf("%s not found in hashem.sh", name)
	return ""
}

// Issue 14: join-hub wrote the tcpMux line and the next one on one line, so
// the extra hub's frpc refused its config. Every line must be a TOML line.
func TestHubWriteFrpcIsValidToml(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("no bash")
	}
	b, err := os.ReadFile(filepath.Join("..", "hashem.sh"))
	if err != nil {
		t.Skip("hashem.sh not found:", err)
	}
	script := string(b)
	toml := regexp.MustCompile(`^([A-Za-z][A-Za-z.]* = ("[^"]*"|true|false|\d+)|\[\[proxies\]\])$`)
	for _, mux := range []string{"true", "false"} {
		conf := filepath.Join(t.TempDir(), "frpc-h2.toml")
		src := shellFunc(t, script, "perf_tcpmux_lines") + shellFunc(t, script, "hub_write_frpc") + `
perf_tcpmux_new() { echo ` + mux + `; }
pool_effective_values() { echo "8 64"; }
perf_get_str() { echo off; }
perf_get_enc() { echo 0; }
perf_get_comp() { echo 0; }
perf_frpc_extra_lines() { return 0; }
hub_write_frpc "$1" 203.0.113.9 7000 tok tcp "443 8443" 127.0.0.1
`
		if out, err := exec.Command("bash", "-c", src, "bash", conf).CombinedOutput(); err != nil {
			t.Fatalf("tcpMux %s: %v\n%s", mux, err, out)
		}
		data, err := os.ReadFile(conf)
		if err != nil {
			t.Fatal(err)
		}
		for i, l := range strings.Split(string(data), "\n") {
			if l != "" && !toml.MatchString(l) {
				t.Errorf("tcpMux %s, line %d is not TOML: %q", mux, i+1, l)
			}
		}
	}
}

func TestFixHubFrpc(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"transport.tcpMux = falsetransport.heartbeatInterval = 15\n",
			"transport.tcpMux = false\ntransport.heartbeatInterval = 15\n"},
		{"transport.tcpMux = true\ntransport.tcpMuxKeepaliveInterval = 30transport.heartbeatInterval = 15\n",
			"transport.tcpMux = true\ntransport.tcpMuxKeepaliveInterval = 30\ntransport.heartbeatInterval = 15\n"},
	} {
		got, ok := fixHubFrpc([]byte(c.in))
		if !ok || string(got) != c.want {
			t.Errorf("fixHubFrpc(%q) = %q, %v", c.in, got, ok)
		}
	}
	good := "transport.tcpMux = false\ntransport.heartbeatInterval = 15\n"
	if _, ok := fixHubFrpc([]byte(good)); ok {
		t.Error("a good config was changed")
	}
}
