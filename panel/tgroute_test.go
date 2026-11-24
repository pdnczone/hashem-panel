package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// tgBlocked: this server cannot reach Telegram directly.
func tgBlocked(t *testing.T) *int {
	t.Helper()
	old, n := alertClient, 0
	alertClient = &http.Client{Transport: tgRT(func(*http.Request) (*http.Response, error) {
		n++
		return nil, errors.New("connection reset by peer")
	})}
	tgGoodReset()
	t.Cleanup(func() { alertClient = old; tgGoodReset() })
	return &n
}

func withSnap(t *testing.T, s *HubSnapshot) {
	t.Helper()
	old := snapPtr.Load()
	snapPtr.Store(s)
	t.Cleanup(func() { snapPtr.Store(old) })
}

// The automatic route on an Iran server where Telegram is blocked: nothing is
// chosen anywhere, and the request goes out through a tunnel. The way that
// worked is tried first from then on.
func TestTelegramAutoGoesThroughATunnel(t *testing.T) {
	id, seen := egressLab(t)
	direct := tgBlocked(t)
	old := tgAPIBase
	tgAPIBase = "http://api.telegram.org:443"
	defer func() { tgAPIBase = old }()
	withSnap(t, &HubSnapshot{At: time.Now(), Local: tunnelStatus{Role: "iran (server)", FrpSvc: "frps-2"},
		Peers: []peerLive{
			{peerRecord: peerRecord{ID: 9, Name: "down", FrpsSvc: "frps-9"}, HealthState: stateDown},
			{peerRecord: peerRecord{ID: id, Name: "nl", FrpsSvc: "frps-2"}, HealthState: stateHealthy}}})
	wd := watchdogConfig{TGBotToken: "123:secret", TGChatID: "42", TGRoute: "auto"}
	for i := 1; i <= 3; i++ {
		if err := sendTelegram(wd, "hello"); err != nil {
			t.Fatal(err)
		}
		if len(*seen) != i || (*seen)[i-1] != "POST /bot123:secret/sendMessage" {
			t.Fatalf("Telegram got %v", *seen)
		}
	}
	if *direct != 1 {
		t.Fatalf("direct was tried %d times, want once and then the tunnel first", *direct)
	}
	if key, name := tgVia(); key != fmt.Sprintf("tunnel:%d", id) || name != "nl" {
		t.Fatalf("via %q %q", key, name)
	}
	// Direct only means direct only
	wd.TGRoute = "direct"
	if err := sendTelegram(wd, "x"); err == nil || len(*seen) != 3 {
		t.Fatalf("direct only: %v, %d", err, len(*seen))
	}
}

// Where Telegram answers directly no tunnel is touched, and the order is
// direct, then the tunnels by health, at most tgMaxTunnels.
func TestTelegramAutoOrder(t *testing.T) {
	tgGoodReset()
	var peers []peerLive
	for i, st := range []string{stateDown, stateHealthy, stateDegraded, stateHealthy, stateHealthy, stateHealthy} {
		peers = append(peers, peerLive{peerRecord: peerRecord{ID: i + 1, FrpsSvc: fmt.Sprintf("frps-%d", i+1)}, HealthState: st})
	}
	withSnap(t, &HubSnapshot{At: time.Now(), Local: tunnelStatus{Role: "iran (server)"}, Peers: peers})
	keys := func(wd watchdogConfig) string {
		var k []string
		for _, r := range tgRoutes(wd) {
			k = append(k, r.key)
		}
		return strings.Join(k, " ")
	}
	if got := keys(watchdogConfig{TGRoute: "auto"}); got != "direct tunnel:2 tunnel:4 tunnel:5 tunnel:6" {
		t.Fatal(got)
	}
	tgGoodSet(tgRoute{key: "tunnel:5"})
	if got := keys(watchdogConfig{TGRoute: "auto"}); got != "tunnel:5 direct tunnel:2 tunnel:4 tunnel:6" {
		t.Fatal(got)
	}
	three := 3
	if got := keys(watchdogConfig{TGRoute: "tunnel", TGTunnelID: &three}); got != "tunnel:3 direct" {
		t.Fatal(got)
	}
	tgGoodReset()
	// a foreign server has no tunnel to send through: it is already outside
	withSnap(t, &HubSnapshot{At: time.Now(), Local: tunnelStatus{Role: "foreign (client)", FrpSvc: "frpc", FrpUp: true}})
	if got := keys(watchdogConfig{TGRoute: "auto"}); got != "direct" {
		t.Fatal(got)
	}
}

// A route that never connects is given up quickly, also under a long poll.
func TestTelegramBlockedRouteDoesNotHoldTheBot(t *testing.T) {
	hang := tgRoute{key: "direct", connect: 100 * time.Millisecond, client: func(timeout time.Duration) (*http.Client, error) {
		return &http.Client{Timeout: timeout, Transport: tgRT(func(r *http.Request) (*http.Response, error) {
			<-r.Context().Done()
			return nil, r.Context().Err()
		})}, nil
	}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { // connected, and slow to answer
		time.Sleep(300 * time.Millisecond)
		_, _ = io.WriteString(w, `{"ok":true,"result":true}`)
	}))
	defer srv.Close()
	old := tgAPIBase
	tgAPIBase = srv.URL
	defer func() { tgAPIBase = old; tgGoodReset() }()
	ok := tgRoute{key: "tunnel:1", connect: 100 * time.Millisecond, client: func(d time.Duration) (*http.Client, error) { return &http.Client{Timeout: d}, nil }}
	t0 := time.Now()
	if err := tgDoOn([]tgRoute{hang, ok}, "1:x", "getUpdates", nil, "", 40*time.Second, nil); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(t0); d > 5*time.Second {
		t.Fatalf("took %s", d)
	}
}

// One bot: an alert goes to the paired accounts and the extra chat, each
// once; a muted account gets none; a locked or switched-off bot only serves
// the chat that was set by hand.
func TestTelegramAlertReceivers(t *testing.T) {
	f := newTGHarness(t, true)
	wd := watchdogConfig{TGChatID: "42", TGRoute: "direct"}
	if got := strings.Join(tgReceivers(wd), ","); got != "42,43" {
		t.Fatal(got)
	}
	if err := saveWatchdogConfig(watchdogConfig{TGBotToken: tgTestToken, TGChatID: "-100200", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := wdSendReal("🔴 Tunnel DOWN: nl"); err != nil {
		t.Fatal(err)
	}
	to := []string{}
	for _, m := range f.sent {
		to = append(to, fmt.Sprint(m["chat_id"]))
	}
	if strings.Join(to, ",") != "-100200,42,43" || !strings.Contains(f.texts(), "Tunnel DOWN: nl") {
		t.Fatalf("%v\n%s", to, f.texts())
	}
	// a viewer mutes its own alerts from the bot
	c := loadTGBotConfig()
	if s := tgOnButton(c, c.user(43), 43, "al:mute"); strings.TrimSpace(s.Text) == "" || !loadTGBotConfig().user(43).Mute {
		t.Fatal("mute")
	}
	if got := strings.Join(tgReceivers(loadWatchdogConfig()), ","); got != "-100200,42" {
		t.Fatal(got)
	}
	_, _ = updateTGBotConfig(func(c *tgBotConfig) error { c.Enabled = false; return nil })
	if got := strings.Join(tgReceivers(loadWatchdogConfig()), ","); got != "-100200" {
		t.Fatal(got)
	}
	_, _ = updateTGBotConfig(func(c *tgBotConfig) error { c.Enabled = true; return nil })
	apLicense(t, false)
	if got := strings.Join(tgReceivers(loadWatchdogConfig()), ","); got != "-100200" {
		t.Fatalf("without a license: %s", got)
	}
}

// Two bots of an older version become one, once, and nothing is lost.
func TestTelegramMigrateToOneBot(t *testing.T) {
	const a, b = "111111111:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "222222222:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	for _, x := range []struct {
		name, wdTok, botTok string
		enabled             bool
		users               int
		want, kept          string
	}{
		{"only the watchdog's", a, "", true, 1, a, ""},
		{"only the bot's", "", b, true, 1, b, ""},
		{"the same twice", a, a, true, 1, a, ""},
		{"two, the bot is in use", a, b, true, 1, b, a},
		{"two, the bot is off", a, b, false, 1, a, b},
		{"two, nobody is paired", a, b, true, 0, a, b},
	} {
		t.Run(x.name, func(t *testing.T) {
			restore := withTempConfigDir(t)
			defer restore()
			old, _ := json.Marshal(map[string]any{"tg_bot_token": x.wdTok, "tg_chat_id": "-1", "tg_route": "direct", "enabled": true})
			if err := os.WriteFile(watchdogConfigPath(), old, 0600); err != nil {
				t.Fatal(err)
			}
			_, _ = updateTGBotConfig(func(c *tgBotConfig) error {
				c.Token, c.Enabled = x.botTok, x.enabled
				for i := 0; i < x.users; i++ {
					c.Users = append(c.Users, tgBotUser{ID: int64(i + 1), Role: "admin"})
				}
				return nil
			})
			tgMigrateOneBot()
			wd, c := loadWatchdogConfig(), loadTGBotConfig()
			if wd.TGBotToken != x.want || c.Token != "" || c.OldToken != x.kept || wd.TGRoute != "auto" || wd.TGChatID != "-1" || !wd.Enabled {
				t.Fatalf("%+v %+v", wd, c)
			}
			// a later choice of Direct stays
			wd.TGRoute = "direct"
			_ = saveWatchdogConfig(wd)
			tgMigrateOneBot()
			if loadWatchdogConfig().TGRoute != "direct" || tgToken(loadWatchdogConfig()) != x.want {
				t.Fatal("the migration ran twice")
			}
		})
	}
	t.Run("nothing set up", func(t *testing.T) {
		restore := withTempConfigDir(t)
		defer restore()
		tgMigrateOneBot()
		if _, err := os.Stat(watchdogConfigPath()); err == nil {
			t.Fatal("a file was made for nothing")
		}
	})
}

// The Settings card sets the whole bot: token, route and alert chat; without
// a license none of it.
func TestTelegramBotSettings(t *testing.T) {
	newTGHarness(t, true)
	post := func(body string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		handleTGBotPost(rr, httptest.NewRequest("POST", "/api/telegram-bot", strings.NewReader(body)))
		return rr
	}
	if rr := post(`{"action":"save","token":"` + tgTestToken + `","chat_id":"-100123","route":"direct"}`); rr.Code != 200 || strings.Contains(rr.Body.String(), tgTestToken) {
		t.Fatalf("%d %s", rr.Code, rr.Body)
	}
	wd := loadWatchdogConfig()
	if wd.TGBotToken != tgTestToken || wd.TGChatID != "-100123" || wd.TGRoute != "direct" || loadTGBotConfig().Token != "" {
		t.Fatalf("%+v", wd)
	}
	// the masked token that came back changes nothing; an empty chat clears it
	if rr := post(`{"action":"save","token":"` + maskBotToken(tgTestToken) + `","chat_id":"","route":"auto"}`); rr.Code != 200 {
		t.Fatal(rr.Body)
	}
	if wd = loadWatchdogConfig(); wd.TGBotToken != tgTestToken || wd.TGChatID != "" || wd.TGRoute != "auto" {
		t.Fatalf("%+v", wd)
	}
	for _, bad := range []string{`{"token":"nope"}`, `{"chat_id":"hello there"}`, `{"route":"tunnel"}`} {
		if rr := post(bad); rr.Code == 200 {
			t.Errorf("%s was accepted", bad)
		}
	}
	apLicense(t, false)
	if rr := post(`{"action":"save","chat_id":"5"}`); rr.Code == 200 || loadWatchdogConfig().TGChatID != "" {
		t.Fatalf("without a license: %d", rr.Code)
	}
	if rr := post(`{"action":"save","enabled":false,"lang":"fa"}`); rr.Code != 200 {
		t.Fatal("switching it off needs no license")
	}
}
