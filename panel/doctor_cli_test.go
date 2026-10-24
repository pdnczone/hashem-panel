package main

import (
	"strings"
	"testing"
)

func TestDoctorCLIFixRunsQuickRepair(t *testing.T) {
	prev := applyFixesFn
	t.Cleanup(func() { applyFixesFn = prev })
	calls := 0
	applyFixesFn = func() map[string]any {
		calls++
		return map[string]any{"applied": []string{"Enabled IPv4 packet forwarding"}}
	}

	var out strings.Builder
	if code := runDoctorCLI(&out, false); code != 0 || calls != 0 {
		t.Fatalf("check: exit %d, %d repairs; it must only diagnose", code, calls)
	}
	if !strings.HasPrefix(out.String(), "Diagnosis: ") {
		t.Errorf("check output starts with %q", out.String())
	}

	out.Reset()
	if code := runDoctorCLI(&out, true); code != 0 || calls != 1 {
		t.Fatalf("fix: exit %d, %d repairs, want one", code, calls)
	}
	s := out.String()
	if !strings.Contains(s, "[OK] Enabled IPv4 packet forwarding") {
		t.Errorf("fix output misses the applied step:\n%s", s)
	}
	if strings.Count(s, "Diagnosis: ") != 2 {
		t.Errorf("fix should diagnose before and after the repair:\n%s", s)
	}
}
