package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type dangerFakes struct{ calls []string }

func fakeDanger(t *testing.T) *dangerFakes {
	t.Helper()
	f := &dangerFakes{}
	oB, oH, oX, oG, oS, oT := dangerBackup, dangerRemoveHubs, dangerRemoveXray, dangerRemoveBagher, dangerRemoveSpoof, dangerRemoveTunnels
	t.Cleanup(func() {
		dangerBackup, dangerRemoveHubs, dangerRemoveXray, dangerRemoveBagher, dangerRemoveSpoof, dangerRemoveTunnels = oB, oH, oX, oG, oS, oT
	})
	dangerBackup = func() (string, error) { f.calls = append(f.calls, "backup"); return "backup written", nil }
	dangerRemoveHubs = func() (int, error) { f.calls = append(f.calls, "hubs"); return 2, nil }
	dangerRemoveXray = func() (int, error) { f.calls = append(f.calls, "xray"); return 1, errors.New("unit stuck") }
	dangerRemoveBagher = func() (int, error) { f.calls = append(f.calls, "bagher"); return 0, nil }
	dangerRemoveSpoof = func() (int, error) { f.calls = append(f.calls, "spoof"); return 0, nil }
	dangerRemoveTunnels = func() (string, error) { f.calls = append(f.calls, "tunnels"); return "[OK] Tunnel removed", nil }
	return f
}

func dangerAsk(t *testing.T, body string) (int, map[string]any) {
	t.Helper()
	rec := httptest.NewRecorder()
	handleDangerResetTunnels(rec, httptest.NewRequest(http.MethodPost, "/api/danger/reset-tunnels", strings.NewReader(body)))
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

// Nothing is removed without the exact phrase and the login password.
func TestDangerResetNeedsPhraseAndPassword(t *testing.T) {
	dangerPassword(t, "right-password-1")
	f := fakeDanger(t)
	for _, body := range []string{
		`{"password":"right-password-1","confirm":"delete all tunnels"}`,
		`{"password":"right-password-1","confirm":"DELETE ALL"}`,
		`{"password":"right-password-1"}`,
		`{"password":"wrong","confirm":"DELETE ALL TUNNELS"}`,
		`{"confirm":"DELETE ALL TUNNELS"}`,
		`not json`,
	} {
		if code, _ := dangerAsk(t, body); code == 200 {
			t.Fatalf("%s: removed", body)
		}
	}
	if len(f.calls) != 0 {
		t.Fatalf("parts ran: %v", f.calls)
	}
}

// Every part runs, in order, even when one fails, and the answer says which.
func TestDangerResetRemovesEveryKind(t *testing.T) {
	dangerPassword(t, "right-password-1")
	f := fakeDanger(t)
	code, out := dangerAsk(t, `{"password":"right-password-1","confirm":" DELETE ALL TUNNELS "}`)
	if code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	if strings.Join(f.calls, ",") != "backup,hubs,xray,bagher,spoof,tunnels" {
		t.Fatalf("parts: %v", f.calls)
	}
	if out["failed"].(float64) != 1 {
		t.Fatalf("failed: %v", out)
	}
	steps := out["steps"].([]any)
	x := steps[2].(map[string]any)
	if x["ok"] != false || !strings.Contains(x["detail"].(string), "unit stuck") {
		t.Fatalf("xray step: %v", x)
	}
	if steps[1].(map[string]any)["detail"] != "2 removed" {
		t.Fatalf("hubs step: %v", steps[1])
	}
}

// A backup that fails stops everything; without a backup it goes straight on.
func TestDangerResetBackupFirst(t *testing.T) {
	dangerPassword(t, "right-password-1")
	f := fakeDanger(t)
	dangerBackup = func() (string, error) { f.calls = append(f.calls, "backup"); return "", errors.New("watchdog is off") }
	_, out := dangerAsk(t, `{"password":"right-password-1","confirm":"DELETE ALL TUNNELS"}`)
	if out["error"] == nil || strings.Join(f.calls, ",") != "backup" {
		t.Fatalf("after a failed backup: %v %v", out, f.calls)
	}
	f.calls = nil
	_, out = dangerAsk(t, `{"password":"right-password-1","confirm":"DELETE ALL TUNNELS","backup":false}`)
	if out["error"] != nil || strings.Join(f.calls, ",") != "hubs,xray,bagher,spoof,tunnels" {
		t.Fatalf("without a backup: %v %v", out, f.calls)
	}
}

// The reset is never relayed from a central, so the Telegram bot and a node's
// central cannot reach it either.
func TestDangerResetIsNotRelayed(t *testing.T) {
	if nodeRelayAllowed("/api/danger/reset-tunnels") || tgBotAllowed(http.MethodPost, "/api/danger/reset-tunnels") {
		t.Fatal("the reset can be relayed")
	}
}

func dangerPassword(t *testing.T, pw string) {
	t.Helper()
	mu.Lock()
	old := cfg.PassHash
	cfg.PassHash = hashPassword(pw)
	mu.Unlock()
	t.Cleanup(func() { mu.Lock(); cfg.PassHash = old; mu.Unlock() })
}
