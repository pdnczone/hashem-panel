package main

import (
	"net/http/httptest"
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
