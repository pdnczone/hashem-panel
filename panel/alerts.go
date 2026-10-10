package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// External alerts: a webhook and/or Telegram message when a link CHANGES
// state (healthy/degraded/down), never on every tick. Link states are already
// debounced by health.go; on top of that the first snapshot after start only
// records a baseline, and each link has a minimum gap between alerts.

type alertConfig struct {
	Enabled      bool   `json:"enabled"`
	WebhookURL   string `json:"webhook_url,omitempty"`
	Telegram     bool   `json:"telegram"`              // reuse bot token/chat from watchdog.json
	NotifyDegrad bool   `json:"notify_degraded"`       // also alert on healthy<->degraded
	MinGapSec    int    `json:"min_gap_sec,omitempty"` // per-link minimum between alerts (default 120)
}

type alertEvent struct {
	Link string `json:"link"`
	From string `json:"from"`
	To   string `json:"to"`
	Why  string `json:"why,omitempty"`
	At   string `json:"at"`
	Host string `json:"host"`
}

func alertConfigPath() string { return filepath.Join(configDir, "alerts.json") }

func loadAlertConfig() alertConfig {
	c := alertConfig{MinGapSec: 120}
	if b, err := os.ReadFile(alertConfigPath()); err == nil {
		_ = json.Unmarshal(b, &c)
	}
	if c.MinGapSec < 10 {
		c.MinGapSec = 120
	}
	return c
}

func saveAlertConfig(c alertConfig) error {
	_ = os.MkdirAll(configDir, 0700)
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(alertConfigPath(), b, 0600)
}

func validWebhookURL(u string) bool {
	if u == "" {
		return true
	}
	p, err := url.Parse(u)
	return err == nil && (p.Scheme == "http" || p.Scheme == "https") && p.Host != "" && len(u) <= 512
}

// ---- state-change tracker (pure, tested) ----

type linkSnap struct{ Name, State, Why string }

type alertTracker struct {
	mu       sync.Mutex
	last     map[string]string
	lastSent map[string]time.Time
	primed   bool
}

func newAlertTracker() *alertTracker {
	return &alertTracker{last: map[string]string{}, lastSent: map[string]time.Time{}}
}

func isAlertWorthy(from, to string, degraded bool) bool {
	if from == to || from == "" || to == "" {
		return false
	}
	if degraded {
		return true
	}
	return from == stateDown || to == stateDown
}

// observe returns the events to send for this tick.
func (t *alertTracker) observe(now time.Time, links []linkSnap, cfg alertConfig) []alertEvent {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []alertEvent
	seen := map[string]bool{}
	for _, l := range links {
		if l.State == "" {
			continue
		}
		seen[l.Name] = true
		prev := t.last[l.Name]
		t.last[l.Name] = l.State
		if !t.primed || prev == l.State || !isAlertWorthy(prev, l.State, cfg.NotifyDegrad) {
			continue
		}
		gap := time.Duration(cfg.MinGapSec) * time.Second
		if now.Sub(t.lastSent[l.Name]) < gap && !t.lastSent[l.Name].IsZero() {
			continue // flapping: suppress, state is still recorded
		}
		t.lastSent[l.Name] = now
		out = append(out, alertEvent{Link: l.Name, From: prev, To: l.State, Why: l.Why, At: now.UTC().Format(time.RFC3339)})
	}
	for k := range t.last {
		if !seen[k] {
			delete(t.last, k)
			delete(t.lastSent, k)
		}
	}
	t.primed = true
	return out
}

// ---- senders (swappable in tests) ----

var (
	alertTrk    = newAlertTracker()
	alertClient = &http.Client{Timeout: 10 * time.Second}
	alertSend   = deliverAlerts
)

func alertText(e alertEvent) string {
	icon := map[string]string{stateDown: "🔴", stateHealthy: "🟢", stateDegraded: "🟡"}[e.To]
	s := fmt.Sprintf("%s [%s] link %q: %s → %s", icon, e.Host, e.Link, e.From, e.To)
	if e.Why != "" {
		s += " (" + e.Why + ")"
	}
	return s
}

func sendWebhook(raw string, e alertEvent) error {
	b, _ := json.Marshal(map[string]any{"text": alertText(e), "event": e})
	req, err := http.NewRequest("POST", raw, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := alertClient.Do(req)
	if err != nil {
		return redactErr(err, raw)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func sendTelegram(wd watchdogConfig, text string) error {
	if wd.TGBotToken == "" || wd.TGChatID == "" {
		return fmt.Errorf("telegram bot token/chat id not configured (Watchdog tab)")
	}
	client := alertClient
	if wd.TGRoute == "tunnel" && wd.TGTunnelPort > 0 {
		pu, _ := url.Parse(fmt.Sprintf("socks5h://127.0.0.1:%d", wd.TGTunnelPort))
		client = &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(pu)}}
	}
	api := "https://api.telegram.org/bot" + wd.TGBotToken + "/sendMessage"
	resp, err := client.PostForm(api, url.Values{"chat_id": {wd.TGChatID}, "text": {text}})
	if err != nil {
		return redactErr(err, wd.TGBotToken)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("telegram returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// redactErr keeps secrets out of error strings (net/url errors embed the URL).
func redactErr(err error, secrets ...string) error {
	m := err.Error()
	for _, s := range secrets {
		if s != "" {
			m = strings.ReplaceAll(m, s, "***")
		}
	}
	if u, perr := url.Parse(strings.TrimSpace(secretsFirst(secrets))); perr == nil && u.Host != "" {
		m = strings.ReplaceAll(m, u.Path, "/***")
	}
	return fmt.Errorf("%s", m)
}

func secretsFirst(s []string) string {
	if len(s) > 0 {
		return s[0]
	}
	return ""
}

func deliverAlerts(cfg alertConfig, events []alertEvent) {
	host, _ := os.Hostname()
	wd := loadWatchdogConfig()
	for _, e := range events {
		e.Host = host
		if cfg.WebhookURL != "" {
			if err := sendWebhook(cfg.WebhookURL, e); err != nil {
				recordError("E-WD-01", "alerts", "webhook failed: "+err.Error())
			}
		}
		if cfg.Telegram {
			if err := sendTelegram(wd, alertText(e)); err != nil {
				recordError("E-WD-01", "alerts", "telegram failed: "+err.Error())
			}
		}
	}
}

// alertsOnSnapshot is called after every snapshot build.
func alertsOnSnapshot(s *HubSnapshot) {
	cfg := loadAlertConfig()
	if !cfg.Enabled {
		return
	}
	var links []linkSnap
	for _, l := range s.All() {
		name := l.Name
		if name == "" {
			name = fmt.Sprintf("peer-%d", l.ID)
		}
		links = append(links, linkSnap{Name: name, State: l.HealthState, Why: reasonsText(l.Reasons)})
	}
	if ev := alertTrk.observe(time.Now(), links, cfg); len(ev) > 0 {
		go alertSend(cfg, ev)
	}
}

// ---- API ----

func handleAlertsGet(w http.ResponseWriter, r *http.Request) {
	c := loadAlertConfig()
	wd := loadWatchdogConfig()
	writeJSON(w, map[string]any{
		"enabled": c.Enabled, "webhook_url": maskURL(c.WebhookURL), "telegram": c.Telegram,
		"notify_degraded": c.NotifyDegrad, "min_gap_sec": c.MinGapSec,
		"telegram_configured": wd.TGBotToken != "" && wd.TGChatID != "",
	})
}

func maskURL(u string) string {
	p, err := url.Parse(u)
	if err != nil || p.Host == "" {
		return ""
	}
	return p.Scheme + "://" + p.Host + "/…"
}

func handleAlertsPost(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Action       string  `json:"action"`
		Enabled      *bool   `json:"enabled"`
		WebhookURL   *string `json:"webhook_url"`
		Telegram     *bool   `json:"telegram"`
		NotifyDegrad *bool   `json:"notify_degraded"`
		MinGapSec    *int    `json:"min_gap_sec"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeAPIError(w, r, "E-WD-01", "invalid request")
		return
	}
	c := loadAlertConfig()
	if body.Action == "test" {
		host, _ := os.Hostname()
		ev := alertEvent{Link: "test", From: stateDown, To: stateHealthy, Why: "test alert from the panel", At: time.Now().UTC().Format(time.RFC3339), Host: host}
		var errs []string
		if c.WebhookURL != "" {
			if err := sendWebhook(c.WebhookURL, ev); err != nil {
				errs = append(errs, "webhook: "+err.Error())
			}
		}
		if c.Telegram {
			if err := sendTelegram(loadWatchdogConfig(), alertText(ev)); err != nil {
				errs = append(errs, "telegram: "+err.Error())
			}
		}
		if c.WebhookURL == "" && !c.Telegram {
			errs = append(errs, "no destination configured")
		}
		if len(errs) > 0 {
			writeAPIError(w, r, "E-WD-01", strings.Join(errs, "; "))
			return
		}
		writeJSON(w, map[string]string{"status": "ok", "detail": "test alert sent"})
		return
	}
	if body.WebhookURL != nil {
		if !validWebhookURL(strings.TrimSpace(*body.WebhookURL)) {
			writeAPIError(w, r, "E-WD-01", "webhook URL must be http(s)://host/…")
			return
		}
		if !strings.Contains(*body.WebhookURL, "…") { // masked value echoed back = unchanged
			c.WebhookURL = strings.TrimSpace(*body.WebhookURL)
		}
	}
	if body.Enabled != nil {
		c.Enabled = *body.Enabled
	}
	if body.Telegram != nil {
		c.Telegram = *body.Telegram
	}
	if body.NotifyDegrad != nil {
		c.NotifyDegrad = *body.NotifyDegrad
	}
	if body.MinGapSec != nil && *body.MinGapSec >= 10 && *body.MinGapSec <= 86400 {
		c.MinGapSec = *body.MinGapSec
	}
	if err := saveAlertConfig(c); err != nil {
		writeAPIError(w, r, "E-WD-01", "failed to save: "+err.Error())
		return
	}
	writeJSON(w, map[string]string{"status": "ok"})
}
