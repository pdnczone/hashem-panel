package main

import (
	"strings"
	"testing"
)

func TestRedactLogSecrets(t *testing.T) {
	cases := []struct{ in, mustNot string }{
		{`ERROR invalid security token received: s3cr3tNearMiss`, "s3cr3tNearMiss"},
		{`token = "abcDEF123456"`, "abcDEF123456"},
		{`auth.token="abcDEF123456"`, "abcDEF123456"},
		{`login with token=abcDEF123456 failed`, "abcDEF123456"},
		{`password: hunter2xx`, "hunter2xx"},
		{`Authorization: Bearer eyJhbGciOi.payload.sig`, "eyJhbGciOi"},
		{`--token abcDEF123456 --server x`, "abcDEF123456"},
	}
	for _, c := range cases {
		got := redactLogSecrets(c.in)
		if strings.Contains(got, c.mustNot) {
			t.Errorf("secret leaked: in=%q out=%q", c.in, got)
		}
		if !strings.Contains(got, "***") {
			t.Errorf("no mask marker: %q", got)
		}
	}
}

func TestRedactLogSecretsKeepsNormalLines(t *testing.T) {
	in := "frpc[1]: start proxy success\nbackhaul: restarting client... in 2s\ntokens processed: 4"
	if got := redactLogSecrets(in); got != in {
		t.Errorf("normal text changed: %q", got)
	}
}
