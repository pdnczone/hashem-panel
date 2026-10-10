package main

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestMatchLogCodeBackhaul(t *testing.T) {
	cases := map[string]string{
		"[WARNING] invalid security token received: ***":                                         "E-BH-01",
		"[ERROR] failed to receive control channel response: failed to read message length: EOF": "E-BH-02",
		"[FATAL] neither server nor client configuration is properly set.":                       "E-BH-03",
	}
	for line, want := range cases {
		code, hint := matchLogCode(line)
		if code != want || hint == "" {
			t.Errorf("%q -> %q (hint %q), want %s", line, code, hint, want)
		}
	}
	if code, _ := matchLogCode("[INFO] control channel established successfully"); code != "" {
		t.Errorf("healthy line must not classify, got %q", code)
	}
}

func TestClassifyBackhaulLogNewestWins(t *testing.T) {
	bad := "[WARNING] invalid security token received: x"
	ok := "[INFO] control channel established successfully"
	if c := classifyBackhaulLog(strings.Join([]string{ok, bad}, "\n")); c != "E-BH-01" {
		t.Errorf("failure after success must report, got %q", c)
	}
	if c := classifyBackhaulLog(strings.Join([]string{bad, ok}, "\n")); c != "" {
		t.Errorf("recovered tunnel must not report, got %q", c)
	}
	if c := classifyBackhaulLog(""); c != "" {
		t.Errorf("empty log -> %q", c)
	}
}

func TestBackhaulDoctorIssue(t *testing.T) {
	st := tunnelStatus{FrpSvc: "backhaul-client"}
	runner = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "journalctl" && len(args) > 1 && args[1] == "backhaul-client" {
			return []byte("[ERROR] failed to receive control channel response: EOF\n"), nil
		}
		return nil, errors.New("no")
	}
	issue, rec := backhaulDoctorIssue(st)
	if issue == "" || rec == "" {
		t.Fatalf("expected issue+hint, got %q %q", issue, rec)
	}
	if i, _ := backhaulDoctorIssue(tunnelStatus{FrpSvc: "frpc"}); i != "" {
		t.Errorf("non-backhaul role must be skipped, got %q", i)
	}
}
