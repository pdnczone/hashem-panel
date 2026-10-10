package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// staleLab points the binary lookup at an empty temp dir and writes stale
// backhaul + frpc configs; cleanup removes everything it touched.
func staleLab(t *testing.T) (binDir string) {
	t.Helper()
	binDir = t.TempDir()
	oldDirs, oldExtra := engineBinDirs, backhaulExtraBins
	engineBinDirs, backhaulExtraBins = []string{binDir}, nil
	files := []string{
		filepath.Join(backhaulDir, "client.toml"),
		filepath.Join(frpDir, "frpc.toml"),
	}
	for _, f := range files {
		if err := os.MkdirAll(filepath.Dir(f), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f, []byte("# stale\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		engineBinDirs, backhaulExtraBins = oldDirs, oldExtra
		for _, f := range files {
			_ = os.Remove(f)
		}
	})
	return binDir
}

func fakeBinary(t *testing.T, dir, name string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, name), mode); err != nil {
		t.Fatal(err)
	}
}

func staleIssues(rep *doctorReport) []string {
	var out []string
	for _, i := range rep.Issues {
		if strings.HasPrefix(i, "Stale ") {
			out = append(out, i)
		}
	}
	return out
}

func TestStaleConfigNoBinaryRoleUnknown(t *testing.T) {
	staleLab(t)
	st := localStatusFrom(&hostView{active: map[string]bool{}})
	if st.Role != "" || st.FrpSvc != "" || st.Engine != "" {
		t.Fatalf("stale configs without binaries must be unknown, got role=%q svc=%q engine=%q", st.Role, st.FrpSvc, st.Engine)
	}
}

func TestStaleConfigBackhaulBinaryRestoresRole(t *testing.T) {
	bin := staleLab(t)
	// non-executable file does not count
	fakeBinary(t, bin, "backhaul", 0o644)
	if st := localStatusFrom(&hostView{active: map[string]bool{}}); st.Role != "" {
		t.Fatalf("non-executable binary must not count, got role=%q", st.Role)
	}
	fakeBinary(t, bin, "backhaul", 0o755)
	st := localStatusFrom(&hostView{active: map[string]bool{}})
	if st.Role != "foreign (backhaul)" || st.FrpSvc != "backhaul-client" || st.Engine != "backhaul" {
		t.Fatalf("got role=%q svc=%q engine=%q", st.Role, st.FrpSvc, st.Engine)
	}
}

func TestStaleConfigFrpcBinaryRestoresRole(t *testing.T) {
	bin := staleLab(t)
	fakeBinary(t, bin, "frpc", 0o755)
	st := localStatusFrom(&hostView{active: map[string]bool{}})
	if st.Role != "foreign (client)" || st.FrpSvc != "frpc" {
		t.Fatalf("got role=%q svc=%q", st.Role, st.FrpSvc)
	}
}

func TestStaleConfigBackhaulCoreLocation(t *testing.T) {
	staleLab(t)
	extra := filepath.Join(t.TempDir(), "backhaul_premium")
	if err := os.WriteFile(extra, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	backhaulExtraBins = []string{extra}
	if !engineBinaryPresent("backhaul") {
		t.Fatal("backhaul-core location should count")
	}
}

func TestStaleConfigActiveServiceWins(t *testing.T) {
	staleLab(t)
	st := localStatusFrom(&hostView{active: map[string]bool{"frpc": true}})
	if st.Role != "foreign (client)" || st.FrpSvc != "frpc" || !st.FrpUp {
		t.Fatalf("active service must win, got role=%q svc=%q up=%v", st.Role, st.FrpSvc, st.FrpUp)
	}
}

func TestStaleConfigDoctorIssue(t *testing.T) {
	bin := staleLab(t)
	rep := runFullDiagnostics()
	issues := staleIssues(rep)
	if len(issues) != 2 {
		t.Fatalf("want 2 stale issues (backhaul + frpc), got %v", issues)
	}
	joined := strings.Join(issues, "\n")
	for _, want := range []string{"client.toml", "frpc.toml", "backhaul binary is not installed", "frpc binary is not installed", "role is reported as unknown"} {
		if !strings.Contains(joined, want) {
			t.Errorf("issues missing %q: %v", want, issues)
		}
	}
	if !strings.Contains(strings.Join(rep.Recommendations, "\n"), "Remove the stale config or reinstall the engine (Setup tab)") {
		t.Errorf("missing recommendation: %v", rep.Recommendations)
	}

	fakeBinary(t, bin, "backhaul", 0o755)
	fakeBinary(t, bin, "frpc", 0o755)
	if got := staleIssues(runFullDiagnostics()); len(got) != 0 {
		t.Fatalf("no stale issue expected with binaries present, got %v", got)
	}
}
