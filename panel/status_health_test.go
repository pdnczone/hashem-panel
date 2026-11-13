package main

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"
)

// A foreign server has no hub link (snap.Main): its status carries the health
// of its own session, so a live tunnel is not shown weak for want of a ping
// (a live session is never pinged, see TestICMPBackgroundPolicy).
func TestStatusForeignHealthFromSession(t *testing.T) {
	t.Cleanup(resetSnapshotState)
	local := tunnelStatus{Role: "foreign (client)", FrpUp: true, FrpSvc: "frpc", Engine: "frp", RemotePub: "10.10.10.2", BindPort: 7000}
	local.Gre.Exists, local.Gre.Inner = true, "10.10.10.1/30"
	for _, c := range []struct {
		session bool
		want    string
		lat     float64
	}{{true, stateHealthy, 12.3}, {false, stateDegraded, -1}} {
		snapPtr.Store(&HubSnapshot{Local: local, LocalSession: c.session, LocalRTT: 12.3, At: time.Now(), PublicIP: "203.0.113.9"})
		rr := httptest.NewRecorder()
		handleStatus(rr, httptest.NewRequest("GET", "/api/status", nil))
		var s struct {
			Local struct {
				PingOK      bool    `json:"ping_ok"`
				HealthState string  `json:"health_state"`
				LatencyMs   float64 `json:"latency_ms"`
				LatencyKind string  `json:"latency_kind"`
			} `json:"local"`
			Server map[string]string `json:"server"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &s); err != nil {
			t.Fatal(err)
		}
		if s.Local.PingOK || s.Local.HealthState != c.want || s.Local.LatencyMs != c.lat {
			t.Errorf("session %v: %+v, want %s and latency %v", c.session, s.Local, c.want, c.lat)
		}
		if s.Server["public_ip"] != "203.0.113.9" { // the topbar names this server
			t.Errorf("server: %v", s.Server)
		}
	}
}
