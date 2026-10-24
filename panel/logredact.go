package main

import "regexp"

// logSecretRes mask credentials that service logs may print verbatim, e.g.
// Backhaul echoes the rejected client's token ("invalid security token
// received: <token>"), which is usually a near-miss of the real secret.
var logSecretRes = []struct {
	re   *regexp.Regexp
	repl string
}{
	{regexp.MustCompile(`(?i)(security token received\s*:?\s*)\S+`), "${1}***"},
	{regexp.MustCompile(`(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+`), "${1}***"},
	{regexp.MustCompile(`(?i)(\b(?:auth\.)?(?:token|password|passwd|secret)\b["']?\s*[=:]\s*)("[^"\n]*"|'[^'\n]*'|[^\s,;]+)`), "${1}***"},
	{regexp.MustCompile(`(?i)(--(?:token|password|passwd|secret)[ =])\S+`), "${1}***"},
}

// redactLogSecrets masks credentials in raw log text before it leaves the host
// through the panel API.
func redactLogSecrets(s string) string {
	for _, r := range logSecretRes {
		s = r.re.ReplaceAllString(s, r.repl)
	}
	return s
}
