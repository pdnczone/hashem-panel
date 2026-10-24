package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMaskBotToken(t *testing.T) {
	if m := maskBotToken(""); m != "" {
		t.Fatalf("expected empty, got %q", m)
	}
	tok := "123456789:ABCdefGhIJKlmNoPQRsTUVwxyZ"
	m := maskBotToken(tok)
	if m == tok {
		t.Fatalf("token was not masked: %s", m)
	}
	if !strings.Contains(m, "...") {
		t.Fatalf("expected ... in masked token, got %s", m)
	}
	// Middle must be masked
	if strings.Contains(m, "GhIJKlm") {
		t.Fatalf("middle part of token was not masked: %s", m)
	}
}

func TestWatchdogAPIEndpoints(t *testing.T) {
	withPro(t)
	tmpDir, err := os.MkdirTemp("", "wd-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	oldConfigDir := configDir
	configDir = tmpDir
	defer func() { configDir = oldConfigDir }()

	// Save test watchdog.json
	cfg := watchdogConfig{
		Enabled:          true,
		IntervalSec:      60,
		FailThreshold:    2,
		TGBotToken:       "123456789:ABCdefGhIJKlmNoPQRsTUVwxyZ",
		TGChatID:         "987654321",
		TGRoute:          "tunnel",
		TGTunnelPort:     10808,
		BackupEveryHours: 6,
	}
	if err := saveWatchdogConfig(cfg); err != nil {
		t.Fatal(err)
	}

	// Create dummy backup
	backupDir := t.TempDir()
	os.Setenv("GRE_BACKUP_DIR", backupDir)
	defer os.Unsetenv("GRE_BACKUP_DIR")
	dummyBackup := filepath.Join(backupDir, "hashem-backup-20260927-120000.enc")
	_ = os.WriteFile(dummyBackup, []byte("ENCRYPTED-DATA"), 0600)
	defer os.Remove(dummyBackup)

	// 1. GET /api/watchdog
	req := httptest.NewRequest("GET", "/api/watchdog", nil)
	rr := httptest.NewRecorder()
	handleWatchdogGet(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/watchdog returned %d: %s", rr.Code, rr.Body.String())
	}
	var resp watchdogStatusResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.TGBotTokenMasked == cfg.TGBotToken {
		t.Fatalf("bot token leaked in API response: %s", resp.TGBotTokenMasked)
	}
	if !resp.Enabled {
		t.Fatalf("expected enabled=true")
	}
	if resp.TGRoute != "tunnel" || resp.TGTunnelPort != 10808 {
		t.Fatalf("unexpected route settings: route=%s port=%d", resp.TGRoute, resp.TGTunnelPort)
	}
	if resp.ScheduleHuman != "Every 6 hours" {
		t.Fatalf("unexpected schedule: %s", resp.ScheduleHuman)
	}

	// 2. POST /api/watchdog - set-schedule daily
	schedBody := watchdogPostRequest{
		Action: "set-schedule",
		Mode:   "daily",
		At:     "04:30",
	}
	bData, _ := json.Marshal(schedBody)
	req = httptest.NewRequest("POST", "/api/watchdog", bytes.NewReader(bData))
	rr = httptest.NewRecorder()
	handleWatchdogPost(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("set-schedule returned %d: %s", rr.Code, rr.Body.String())
	}

	updated := loadWatchdogConfig()
	if updated.BackupDailyAt != "04:30" || updated.BackupEveryHours != 0 {
		t.Fatalf("daily schedule not saved: daily_at=%s every=%d", updated.BackupDailyAt, updated.BackupEveryHours)
	}

	// 2b. POST /api/watchdog - set-autorestart
	autoTrue := true
	arBody := watchdogPostRequest{
		Action:      "set-autorestart",
		AutoRestart: &autoTrue,
	}
	bARData, _ := json.Marshal(arBody)
	req = httptest.NewRequest("POST", "/api/watchdog", bytes.NewReader(bARData))
	rr = httptest.NewRecorder()
	handleWatchdogPost(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("set-autorestart returned %d: %s", rr.Code, rr.Body.String())
	}
	updatedAR := loadWatchdogConfig()
	if !updatedAR.AutoRestart {
		t.Fatalf("expected auto_restart=true")
	}

	// 2c. POST /api/watchdog - set-restart-schedule
	hVal := 4
	restartSchedBody := watchdogPostRequest{
		Action:       "set-restart-schedule",
		RestartHours: &hVal,
	}
	bSchedData, _ := json.Marshal(restartSchedBody)
	req = httptest.NewRequest("POST", "/api/watchdog", bytes.NewReader(bSchedData))
	rr = httptest.NewRecorder()
	handleWatchdogPost(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("set-restart-schedule returned %d: %s", rr.Code, rr.Body.String())
	}
	updatedSched := loadWatchdogConfig()
	if updatedSched.RestartEveryHours != 4 {
		t.Fatalf("expected restart_every_hours=4, got %d", updatedSched.RestartEveryHours)
	}

	// 3. POST /api/watchdog - bad action
	req = httptest.NewRequest("POST", "/api/watchdog", bytes.NewReader([]byte(`{"action":"bogus"}`)))
	rr = httptest.NewRecorder()
	handleWatchdogPost(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for bogus action, got %d", rr.Code)
	}

	// 4. Download backup - security check for path traversal
	req = httptest.NewRequest("GET", "/api/watchdog/backup-download?f=../../etc/passwd", nil)
	rr = httptest.NewRecorder()
	handleBackupDownload(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("path traversal was not blocked, got %d", rr.Code)
	}

	// Valid backup download
	req = httptest.NewRequest("GET", "/api/watchdog/backup-download?f=hashem-backup-20260927-120000.enc", nil)
	rr = httptest.NewRecorder()
	handleBackupDownload(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("valid download failed with %d", rr.Code)
	}
	if rr.Body.String() != "ENCRYPTED-DATA" {
		t.Fatalf("unexpected downloaded content: %s", rr.Body.String())
	}
}

func TestWatchdogDefaultDisabled(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "wd-default-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	oldConfigDir := configDir
	configDir = tmpDir
	defer func() { configDir = oldConfigDir }()

	def := loadWatchdogConfig()
	if def.Enabled {
		t.Fatalf("expected watchdog to be disabled by default, got enabled=true")
	}
}
