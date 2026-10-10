package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type watchdogConfig struct {
	Enabled           bool   `json:"enabled"`
	IntervalSec       int    `json:"interval_sec"`
	FailThreshold     int    `json:"fail_threshold"`
	AutoRestart       bool   `json:"auto_restart"`
	RestartEveryHours int    `json:"restart_every_hours"`
	LastRestart       int64  `json:"last_restart,omitempty"`
	LastRestartDate   string `json:"last_restart_date,omitempty"`
	TGBotToken        string `json:"tg_bot_token"`
	TGChatID          string `json:"tg_chat_id"`
	TGRoute           string `json:"tg_route"`
	TGTunnelPort      int    `json:"tg_tunnel_port"`
	BackupEveryHours  int    `json:"backup_every_hours"`
	BackupDailyAt     string `json:"backup_daily_at"`
	LastCheck         string `json:"last_check"`
	ConsecFails       int    `json:"consec_fails"`
	LastAlert         string `json:"last_alert"`
	DownSince         int64  `json:"down_since,omitempty"`
	LastBackup        int64  `json:"last_backup,omitempty"`
	LastBackupDate    string `json:"last_backup_date,omitempty"`
}

type backupItem struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
	Time string `json:"time"`
}

type watchdogStatusResponse struct {
	Enabled           bool         `json:"enabled"`
	Status            string       `json:"status"`
	CheckResult       string       `json:"check_result"`
	LastCheck         string       `json:"last_check"`
	ConsecFails       int          `json:"consec_fails"`
	FailThreshold     int          `json:"fail_threshold"`
	AutoRestart       bool         `json:"auto_restart"`
	RestartEveryHours int          `json:"restart_every_hours"`
	LastRestart       int64        `json:"last_restart"`
	LastRestartDate   string       `json:"last_restart_date"`
	NextRestartHuman  string       `json:"next_restart_human"`
	TGBotTokenMasked  string       `json:"tg_bot_token_masked"`
	TGChatID          string       `json:"tg_chat_id"`
	TGRoute           string       `json:"tg_route"`
	TGTunnelPort      int          `json:"tg_tunnel_port"`
	ScheduleMode      string       `json:"schedule_mode"`
	BackupEveryHours  int          `json:"backup_every_hours"`
	BackupDailyAt     string       `json:"backup_daily_at"`
	ScheduleHuman     string       `json:"schedule_human"`
	Backups           []backupItem `json:"backups"`
	TunnelPorts       []int        `json:"tunnel_ports"`
	RecentEvents      []errEvent   `json:"recent_events"`
}

type watchdogPostRequest struct {
	Action       string `json:"action"`
	BotToken     string `json:"bot_token,omitempty"`
	ChatID       string `json:"chat_id,omitempty"`
	Route        string `json:"route,omitempty"`
	TunnelPort   int    `json:"tunnel_port,omitempty"`
	Mode         string `json:"mode,omitempty"`
	Hours        int    `json:"hours,omitempty"`
	At           string `json:"at,omitempty"`
	File         string `json:"file,omitempty"`
	AutoRestart  *bool  `json:"auto_restart,omitempty"`
	RestartHours *int   `json:"restart_hours,omitempty"`
}

func watchdogConfigPath() string {
	return filepath.Join(configDir, "watchdog.json")
}

func loadWatchdogConfig() watchdogConfig {
	def := watchdogConfig{
		Enabled:       false,
		IntervalSec:   60,
		FailThreshold: 2,
		TGRoute:       "direct",
	}
	data, err := os.ReadFile(watchdogConfigPath())
	if err != nil {
		return def
	}
	var c watchdogConfig
	if err := json.Unmarshal(data, &c); err != nil {
		return def
	}
	if c.IntervalSec <= 0 {
		c.IntervalSec = 60
	}
	if c.FailThreshold <= 0 {
		c.FailThreshold = 2
	}
	if c.TGRoute == "" {
		c.TGRoute = "direct"
	}
	return c
}

func saveWatchdogConfig(c watchdogConfig) error {
	_ = os.MkdirAll(configDir, 0700)
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(watchdogConfigPath(), append(data, '\n'), 0600)
}

func maskBotToken(token string) string {
	token = strings.TrimSpace(token)
	if token == "" {
		return ""
	}
	parts := strings.SplitN(token, ":", 2)
	if len(parts) == 2 && len(parts[1]) > 6 {
		p2 := parts[1]
		return parts[0] + ":" + p2[:3] + "..." + p2[len(p2)-3:]
	}
	if len(token) > 10 {
		return token[:4] + "..." + token[len(token)-4:]
	}
	return "******"
}

func formatSchedule(c watchdogConfig) string {
	if c.BackupEveryHours > 0 {
		return fmt.Sprintf("Every %d hours", c.BackupEveryHours)
	}
	if c.BackupDailyAt != "" {
		return fmt.Sprintf("Daily at %s", c.BackupDailyAt)
	}
	return "Disabled"
}

func formatRestartSchedule(c watchdogConfig) string {
	if c.RestartEveryHours <= 0 {
		return "Disabled"
	}
	if c.LastRestart <= 0 {
		return fmt.Sprintf("Every %d hours (pending)", c.RestartEveryHours)
	}
	nextTime := time.Unix(c.LastRestart, 0).Add(time.Duration(c.RestartEveryHours) * time.Hour)
	diff := time.Until(nextTime)
	if diff <= 0 {
		return fmt.Sprintf("Every %d hours (due now)", c.RestartEveryHours)
	}
	mins := int(diff.Minutes())
	if mins < 60 {
		return fmt.Sprintf("Every %d hours (in %dm)", c.RestartEveryHours, mins)
	}
	hours := mins / 60
	remMins := mins % 60
	return fmt.Sprintf("Every %d hours (in %dh %dm)", c.RestartEveryHours, hours, remMins)
}

func listBackups() []backupItem {
	dir := "/var/backups/hashem"
	entries, err := os.ReadDir(dir)
	if err != nil {
		return []backupItem{}
	}
	var items []backupItem
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasPrefix(name, "hashem-backup-") && strings.HasSuffix(name, ".enc") {
			info, err := e.Info()
			if err != nil {
				continue
			}
			items = append(items, backupItem{
				Name: name,
				Size: info.Size(),
				Time: info.ModTime().Format("2006-01-02 15:04:05"),
			})
		}
	}
	// Sort newest first
	sort.Slice(items, func(i, j int) bool {
		return items[i].Name > items[j].Name
	})
	return items
}

func collectTunnelPorts() []int {
	ports := currentLocal().ProxyPorts
	for _, p := range loadPeers() {
		ports = append(ports, p.Ports...)
	}
	return uniqInts(ports)
}

func collectWatchdogEvents() []errEvent {
	var events []errEvent
	f, err := os.Open(errorLogPath())
	if err == nil {
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			var ev errEvent
			if json.Unmarshal(scanner.Bytes(), &ev) == nil {
				if ev.Endpoint == "watchdog" || strings.HasPrefix(ev.Code, "E-WD-") || strings.Contains(strings.ToLower(ev.Detail), "watchdog") {
					events = append(events, ev)
				}
			}
		}
		if scanErr := scanner.Err(); scanErr != nil {
			_ = scanErr
		}
	}
	if len(events) == 0 {
		errMu.Lock()
		for _, ev := range errEvents {
			if ev.Endpoint == "watchdog" || strings.HasPrefix(ev.Code, "E-WD-") || strings.Contains(strings.ToLower(ev.Detail), "watchdog") {
				events = append(events, ev)
			}
		}
		errMu.Unlock()
	}
	if len(events) > 10 {
		events = events[len(events)-10:]
	}
	// Reverse to show newest first
	for i, j := 0, len(events)-1; i < j; i, j = i+1, j-1 {
		events[i], events[j] = events[j], events[i]
	}
	return events
}

func runWatchdogCmd(args ...string) (string, error) {
	script, err := greScriptPath()
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", append([]string{script}, args...)...)
	cmd.Env = append(os.Environ(), "GRE_SKIP_PANEL=1", "TERM=dumb", "GRE_PANEL_DIR="+configDir)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	runErr := cmd.Run()
	return strings.TrimSpace(buf.String()), runErr
}

func handleWatchdogGet(w http.ResponseWriter, r *http.Request) {
	c := loadWatchdogConfig()
	checkResult, _ := runWatchdogCmd("watchdog", "check")

	status := "disabled"
	if c.Enabled {
		if strings.Contains(checkResult, "status=up") {
			status = "up"
		} else {
			status = "down"
		}
	}

	mode := "off"
	if c.BackupEveryHours > 0 {
		mode = "interval"
	} else if c.BackupDailyAt != "" {
		mode = "daily"
	}

	resp := watchdogStatusResponse{
		Enabled:          c.Enabled,
		Status:           status,
		CheckResult:      checkResult,
		LastCheck:        c.LastCheck,
		ConsecFails:      c.ConsecFails,
		FailThreshold:     c.FailThreshold,
		AutoRestart:       c.AutoRestart,
		RestartEveryHours: c.RestartEveryHours,
		LastRestart:       c.LastRestart,
		LastRestartDate:   c.LastRestartDate,
		NextRestartHuman:  formatRestartSchedule(c),
		TGBotTokenMasked:  maskBotToken(c.TGBotToken),
		TGChatID:         c.TGChatID,
		TGRoute:          c.TGRoute,
		TGTunnelPort:     c.TGTunnelPort,
		ScheduleMode:     mode,
		BackupEveryHours: c.BackupEveryHours,
		BackupDailyAt:    c.BackupDailyAt,
		ScheduleHuman:    formatSchedule(c),
		Backups:          listBackups(),
		TunnelPorts:      collectTunnelPorts(),
		RecentEvents:     collectWatchdogEvents(),
	}

	writeJSON(w, resp)
}

func isValidTimeHHMM(s string) bool {
	if len(s) != 5 || s[2] != ':' {
		return false
	}
	h, err1 := strconv.Atoi(s[:2])
	m, err2 := strconv.Atoi(s[3:])
	return err1 == nil && err2 == nil && h >= 0 && h <= 23 && m >= 0 && m <= 59
}

func handleWatchdogPost(w http.ResponseWriter, r *http.Request) {
	var body watchdogPostRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeAPIError(w, r, "E-WD-01", "invalid request body")
		return
	}

	switch body.Action {
	case "on":
		out, err := runWatchdogCmd("watchdog", "on")
		if err != nil {
			writeAPIError(w, r, "E-ACTION-03", out)
			return
		}
		c := loadWatchdogConfig()
		c.Enabled = true
		_ = saveWatchdogConfig(c)
		recordError("E-WD-00", "watchdog", "Watchdog enabled")
		writeJSON(w, map[string]string{"status": "ok", "detail": "Watchdog enabled"})

	case "off":
		out, err := runWatchdogCmd("watchdog", "off")
		if err != nil {
			writeAPIError(w, r, "E-ACTION-03", out)
			return
		}
		c := loadWatchdogConfig()
		c.Enabled = false
		_ = saveWatchdogConfig(c)
		recordError("E-WD-00", "watchdog", "Watchdog disabled")
		writeJSON(w, map[string]string{"status": "ok", "detail": "Watchdog disabled"})

	case "test":
		out, err := runWatchdogCmd("watchdog", "test")
		if err != nil {
			code := "E-WD-02"
			lower := strings.ToLower(out)
			if strings.Contains(lower, "socks") || strings.Contains(lower, "route") || strings.Contains(lower, "tunnel") {
				code = "E-WD-05"
			}
			recordError(code, "watchdog", "Telegram test failed: "+out)
			writeAPIError(w, r, code, out)
			return
		}
		recordError("E-WD-00", "watchdog", "Telegram test message sent successfully")
		writeJSON(w, map[string]string{"status": "ok", "detail": out})

	case "backup-now":
		out, err := runWatchdogCmd("backup", "now")
		if err != nil {
			recordError("E-WD-03", "watchdog", "Backup failed: "+out)
			writeAPIError(w, r, "E-WD-03", out)
			return
		}
		recordError("E-WD-00", "watchdog", "Backup created successfully")
		writeJSON(w, map[string]string{"status": "ok", "detail": out})

	case "restore":
		base := filepath.Base(body.File)
		if body.File == "" || base != body.File || !strings.HasSuffix(base, ".enc") || strings.Contains(base, "..") {
			writeAPIError(w, r, "E-WD-01", "invalid backup file name")
			return
		}
		path := filepath.Join("/var/backups/hashem", base)
		if _, err := os.Stat(path); err != nil {
			writeAPIError(w, r, "E-WD-01", "backup file not found")
			return
		}
		out, err := runWatchdogCmd("backup", "restore", path)
		if err != nil {
			recordError("E-WD-04", "watchdog", "Restore failed: "+out)
			writeAPIError(w, r, "E-WD-04", out)
			return
		}
		recordError("E-WD-00", "watchdog", "Backup restored: "+base)
		writeJSON(w, map[string]string{"status": "ok", "detail": out})

	case "set-telegram":
		c := loadWatchdogConfig()
		if body.BotToken != "" && !strings.Contains(body.BotToken, "...") {
			c.TGBotToken = strings.TrimSpace(body.BotToken)
		}
		c.TGChatID = strings.TrimSpace(body.ChatID)
		if body.Route == "direct" || body.Route == "tunnel" {
			c.TGRoute = body.Route
		}
		c.TGTunnelPort = body.TunnelPort
		if err := saveWatchdogConfig(c); err != nil {
			writeAPIError(w, r, "E-WD-01", "failed to save config: "+err.Error())
			return
		}
		recordError("E-WD-00", "watchdog", "Telegram settings updated")
		writeJSON(w, map[string]string{"status": "ok", "detail": "Telegram settings saved"})

	case "set-schedule":
		c := loadWatchdogConfig()
		switch body.Mode {
		case "interval":
			if body.Hours < 1 || body.Hours > 168 {
				writeAPIError(w, r, "E-WD-01", "interval hours must be between 1 and 168")
				return
			}
			c.BackupEveryHours = body.Hours
			c.BackupDailyAt = ""
		case "daily":
			if !isValidTimeHHMM(body.At) {
				writeAPIError(w, r, "E-WD-01", "daily time must be in HH:MM format (24h)")
				return
			}
			c.BackupEveryHours = 0
			c.BackupDailyAt = body.At
		case "off":
			c.BackupEveryHours = 0
			c.BackupDailyAt = ""
		default:
			writeAPIError(w, r, "E-WD-01", "unknown schedule mode: "+body.Mode)
			return
		}
		if err := saveWatchdogConfig(c); err != nil {
			writeAPIError(w, r, "E-WD-01", "failed to save schedule: "+err.Error())
			return
		}
		recordError("E-WD-00", "watchdog", "Backup schedule updated: "+formatSchedule(c))
		writeJSON(w, map[string]string{"status": "ok", "detail": "Backup schedule saved"})

	case "set-autorestart":
		c := loadWatchdogConfig()
		if body.AutoRestart != nil {
			c.AutoRestart = *body.AutoRestart
		}
		if err := saveWatchdogConfig(c); err != nil {
			writeAPIError(w, r, "E-WD-01", "failed to save config: "+err.Error())
			return
		}
		recordError("E-WD-00", "watchdog", fmt.Sprintf("Watchdog auto-restart set to %v", c.AutoRestart))
		writeJSON(w, map[string]any{"status": "ok", "auto_restart": c.AutoRestart, "detail": "Watchdog auto-restart updated"})

	case "set-restart-schedule":
		c := loadWatchdogConfig()
		if body.RestartHours != nil {
			c.RestartEveryHours = *body.RestartHours
		} else if body.Hours > 0 {
			c.RestartEveryHours = body.Hours
		}
		if c.RestartEveryHours < 0 {
			c.RestartEveryHours = 0
		}
		if err := saveWatchdogConfig(c); err != nil {
			writeAPIError(w, r, "E-WD-01", "failed to save config: "+err.Error())
			return
		}
		msg := "Tunnel auto-restart disabled"
		if c.RestartEveryHours > 0 {
			msg = fmt.Sprintf("Tunnel auto-restart scheduled every %d hours", c.RestartEveryHours)
		}
		recordError("E-WD-00", "watchdog", msg)
		writeJSON(w, map[string]any{"status": "ok", "restart_every_hours": c.RestartEveryHours, "detail": msg})

	case "restart-tunnel-now":
		out, err := runWatchdogCmd("tunnel-restart-lite")
		if err != nil {
			recordError("E-WD-04", "watchdog", "Tunnel restart failed: "+out)
			writeAPIError(w, r, "E-WD-04", "restart failed: "+out)
			return
		}
		c := loadWatchdogConfig()
		c.LastRestart = time.Now().Unix()
		c.LastRestartDate = time.Now().Format("2006-01-02 15:04:05")
		_ = saveWatchdogConfig(c)
		recordError("E-WD-00", "watchdog", "Tunnel restarted gracefully by user")
		writeJSON(w, map[string]string{"status": "ok", "detail": "Tunnel services restarted successfully"})

	default:
		writeAPIError(w, r, "E-WD-01", "unknown action: "+body.Action)
	}
}

func getBackupDir() string {
	if v := os.Getenv("GRE_BACKUP_DIR"); v != "" {
		return v
	}
	return "/var/backups/hashem"
}

func handleBackupDownload(w http.ResponseWriter, r *http.Request) {
	f := r.URL.Query().Get("f")
	base := filepath.Base(f)
	if f == "" || base != f || !strings.HasSuffix(base, ".enc") || strings.Contains(base, "..") {
		writeAPIError(w, r, "E-WD-01", "invalid backup file name")
		return
	}
	path := filepath.Join(getBackupDir(), base)
	st, err := os.Stat(path)
	if err != nil || st.IsDir() {
		writeAPIError(w, r, "E-WD-01", "backup file not found")
		return
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", base))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(st.Size(), 10))
	http.ServeFile(w, r, path)
}
