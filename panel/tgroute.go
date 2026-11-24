package main

// One Telegram bot for the whole panel, and how it reaches Telegram.
//
// There were two: the Telegram bot (Settings) with its own token, and the
// watchdog's alerts with another token, a chat ID and a route of their own
// that the bot only borrowed. Now there is one token, one route and one list
// of receivers. They stay in watchdog.json, because hashem.sh's watchdog
// reads them too; telegram_bot.json keeps the paired accounts.
//
//   - An alert (watchdog, Autopilot, external alerts) goes to every paired
//     account that did not mute alerts, and to the extra chat when one is set
//     (a group, say).
//   - The route is "auto" unless the user picked another: straight from this
//     server, and when Telegram is blocked here, through this server's
//     tunnels, one after the other (tunnel_egress.go carries it). The way
//     that worked is tried first for the next hour. "tunnel" is one chosen
//     tunnel, then direct; "direct" is direct only.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptrace"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// tgRoute is one way to Telegram.
type tgRoute struct {
	key     string // "direct", "tunnel:N" or "port:N"
	name    string
	tunnel  *int
	connect time.Duration // how long it may take until it is connected
	client  func(timeout time.Duration) (*http.Client, error)
}

const (
	tgDirectConnect = 7 * time.Second // a blocked Telegram must not hold the bot up
	tgTunnelConnect = 18 * time.Second
	tgRouteKeep     = time.Hour
	tgMaxTunnels    = 4 // tunnels tried for one request on the auto route
)

// tgGood is the route that worked last, and since when it is tried first.
var tgGood = struct {
	sync.Mutex
	key, name string
	at        time.Time
}{}

func tgGoodSet(r tgRoute) {
	tgGood.Lock()
	if tgGood.key != r.key || time.Since(tgGood.at) > tgRouteKeep {
		tgGood.at = time.Now()
	}
	tgGood.key, tgGood.name = r.key, r.name
	tgGood.Unlock()
}

func tgGoodForget(key string) {
	tgGood.Lock()
	if tgGood.key == key {
		tgGood.key, tgGood.name = "", ""
	}
	tgGood.Unlock()
}

// tgGoodReset: the settings changed, so the order starts afresh.
func tgGoodReset() {
	tgGood.Lock()
	tgGood.key, tgGood.name = "", ""
	tgGood.Unlock()
}

// tgVia is the name of the route that worked last ("" = none yet).
func tgVia() (key, name string) {
	tgGood.Lock()
	defer tgGood.Unlock()
	return tgGood.key, tgGood.name
}

func tgDirectRoute() tgRoute {
	return tgRoute{key: "direct", name: "direct", connect: tgDirectConnect, client: func(timeout time.Duration) (*http.Client, error) {
		return &http.Client{Timeout: timeout, Transport: alertClient.Transport}, nil
	}}
}

func tgTunnelRoute(id int, name string) tgRoute {
	return tgRoute{key: "tunnel:" + strconv.Itoa(id), name: name, tunnel: &id, connect: tgTunnelConnect, client: func(timeout time.Duration) (*http.Client, error) {
		port, err := bridgeEnsure(id)
		if err != nil {
			return nil, err
		}
		return tunnelProxyClient(port, timeout), nil
	}}
}

// tgPortRoute is a SOCKS5 port saved by an older version.
func tgPortRoute(port int) tgRoute {
	return tgRoute{key: "port:" + strconv.Itoa(port), name: "port " + strconv.Itoa(port), connect: tgTunnelConnect, client: func(timeout time.Duration) (*http.Client, error) {
		if err := tunnelProxyReady(port); err != nil { // say now if it is no SOCKS5 proxy
			return nil, err
		}
		return tunnelProxyClient(port, timeout), nil
	}}
}

// tgAutoTunnels are this server's tunnels the relay can go through, best
// first. It reads the last snapshot and never builds one: alerts are sent
// from the snapshot's own hooks.
func tgAutoTunnels() []tgRoute {
	s := snapPtr.Load()
	if s == nil {
		return nil
	}
	links := apLinks(s)
	rank := map[string]int{stateHealthy: 0, stateDegraded: 1, "": 2, stateDown: 3}
	sort.SliceStable(links, func(i, j int) bool { return rank[links[i].HealthState] < rank[links[j].HealthState] })
	var out []tgRoute
	for _, l := range links {
		if len(out) >= tgMaxTunnels {
			break
		}
		out = append(out, tgTunnelRoute(l.ID, tgLinkName(l)))
	}
	return out
}

// tgRoutes are the ways to Telegram in the order to try (tests replace it).
var tgRoutes = func(wd watchdogConfig) []tgRoute {
	switch wd.TGRoute {
	case "direct":
		return []tgRoute{tgDirectRoute()}
	case "tunnel":
		// the chosen tunnel may be the one that is down: then directly
		switch {
		case wd.TGTunnelID != nil:
			name := "tunnel " + strconv.Itoa(*wd.TGTunnelID)
			if s := snapPtr.Load(); s != nil {
				for _, l := range apLinks(s) {
					if l.ID == *wd.TGTunnelID {
						name = tgLinkName(l)
					}
				}
			}
			return []tgRoute{tgTunnelRoute(*wd.TGTunnelID, name), tgDirectRoute()}
		case wd.TGTunnelPort > 0:
			return []tgRoute{tgPortRoute(wd.TGTunnelPort), tgDirectRoute()}
		}
		return []tgRoute{tgDirectRoute()}
	}
	out := append([]tgRoute{tgDirectRoute()}, tgAutoTunnels()...)
	tgGood.Lock()
	key, fresh := tgGood.key, time.Since(tgGood.at) < tgRouteKeep
	tgGood.Unlock()
	for i, r := range out {
		if fresh && r.key == key && i > 0 {
			copy(out[1:i+1], out[:i])
			out[0] = r
			break
		}
	}
	return out
}

// tgDo sends one Bot API request (body is JSON, or a multipart form when
// ctype is given) over the first route that works and decodes its result
// into out.
func tgDo(token, method string, body []byte, ctype string, timeout time.Duration, out any) error {
	return tgDoOn(tgRoutes(loadWatchdogConfig()), token, method, body, ctype, timeout, out)
}

func tgDoOn(routes []tgRoute, token, method string, body []byte, ctype string, timeout time.Duration, out any) error {
	if ctype == "" {
		ctype = "application/json"
	}
	var whys []string
	for _, r := range routes {
		data, status, err := tgAttempt(r, token, method, body, ctype, timeout)
		if err != nil { // the next route
			tgGoodForget(r.key)
			why := redactErr(err, token).Error()
			if r.tunnel != nil {
				if w := routeWhy(r.tunnel); w != "" {
					why = w
				}
			}
			if r.key == "direct" {
				whys = append(whys, "directly: "+why)
			} else {
				whys = append(whys, "telegram tunnel route ("+r.name+"): "+why)
			}
			continue
		}
		var a struct {
			OK          bool            `json:"ok"`
			Result      json.RawMessage `json:"result"`
			Description string          `json:"description"`
			Parameters  struct {
				RetryAfter int `json:"retry_after"`
			} `json:"parameters"`
		}
		if json.Unmarshal(data, &a) != nil {
			return fmt.Errorf("telegram returned HTTP %d", status)
		}
		tgGoodSet(r)
		if !a.OK {
			return &tgAPIError{Code: status, Desc: redactText(a.Description, token), RetryAfter: a.Parameters.RetryAfter}
		}
		if out != nil && len(a.Result) > 0 {
			return json.Unmarshal(a.Result, out)
		}
		return nil
	}
	if len(whys) == 0 {
		return errors.New("no route to Telegram")
	}
	return errors.New("cannot reach Telegram " + tgCut(strings.Join(whys, "; "), 700))
}

// tgAttempt makes the request on one route. A route that is not connected in
// time is given up, so a long poll's timeout never waits on a blocked one.
func tgAttempt(r tgRoute, token, method string, body []byte, ctype string, timeout time.Duration) ([]byte, int, error) {
	c, err := r.client(timeout)
	if err != nil {
		return nil, 0, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	slow := time.AfterFunc(r.connect, cancel)
	defer slow.Stop()
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{GotConn: func(httptrace.GotConnInfo) { slow.Stop() }})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tgAPIBase+"/bot"+token+"/"+method, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", ctype)
	resp, err := c.Do(req)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			err = fmt.Errorf("no connection within %d seconds", int(r.connect/time.Second))
		}
		return nil, 0, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	return data, resp.StatusCode, err
}

// ---- who gets the alerts ----

// tgToken is the panel's bot token. A token still in telegram_bot.json is
// one a newer version has not moved yet (tgMigrateOneBot).
func tgToken(wd watchdogConfig) string {
	if t := strings.TrimSpace(wd.TGBotToken); t != "" {
		return t
	}
	return strings.TrimSpace(loadTGBotConfig().Token)
}

// tgReceivers are the chats an alert goes to, each once.
func tgReceivers(wd watchdogConfig) []string {
	var out []string
	if id := strings.TrimSpace(wd.TGChatID); id != "" {
		out = append(out, id)
	}
	if c := loadTGBotConfig(); c.Enabled && hasPro(proTelegramBot) {
		for _, u := range c.Users {
			id := strconv.FormatInt(u.ID, 10)
			if !u.Mute && (len(out) == 0 || out[0] != id) {
				out = append(out, id)
			}
		}
	}
	return out
}

// tgAlertReady: alerts have a bot and someone to go to.
func tgAlertReady() bool {
	wd := loadWatchdogConfig()
	return tgToken(wd) != "" && len(tgReceivers(wd)) > 0
}

// sendTelegram sends an alert to every receiver. It fails when none got it.
func sendTelegram(wd watchdogConfig, text string) error {
	_, err := sendTelegramCount(wd, text)
	return err
}

func sendTelegramCount(wd watchdogConfig, text string) (int, error) {
	tok, to := tgToken(wd), tgReceivers(wd)
	if tok == "" {
		return 0, errors.New("no Telegram bot token is set (Settings → Telegram bot)")
	}
	if len(to) == 0 {
		return 0, errors.New("no one to send to: pair a Telegram account or set an alert chat (Settings → Telegram bot)")
	}
	sent := 0
	var errs []string
	for _, id := range to {
		body, _ := json.Marshal(map[string]any{"chat_id": id, "text": tgCut(text, tgMaxText)})
		if err := tgDoOn(tgRoutes(wd), tok, "sendMessage", body, "", 25*time.Second, nil); err != nil {
			var ae *tgAPIError
			if !errors.As(err, &ae) { // not reached: it will not be for the others either
				errs = append(errs, err.Error())
				break
			}
			errs = append(errs, "chat "+id+": "+err.Error())
			continue
		}
		sent++
	}
	if sent == 0 {
		return 0, errors.New(strings.Join(errs, "; "))
	}
	if len(errs) > 0 {
		recordError("E-WD-02", "watchdog", "an alert did not reach every chat: "+strings.Join(errs, "; "))
	}
	return sent, nil
}

// ---- settings ----

var tgChatRe = regexp.MustCompile(`^(-?[0-9]{1,20}|@[A-Za-z][A-Za-z0-9_]{3,63})$`)

// tgSetRoute puts a route choice into c.
func tgSetRoute(c *watchdogConfig, route string, tunnel *int, port int) error {
	switch route {
	case "auto", "direct", "tunnel":
		c.TGRoute = route
	}
	if tunnel != nil {
		p, err := bridgeEnsure(*tunnel)
		if err != nil {
			return err
		}
		c.TGTunnelID, c.TGTunnelPort = tunnel, p
	} else if port > 0 && port <= 65535 {
		c.TGTunnelID, c.TGTunnelPort = nil, port // an old manual port
	}
	if c.TGRoute == "tunnel" && c.TGTunnelID == nil && c.TGTunnelPort == 0 {
		return errors.New("choose a tunnel, or choose Automatic or Direct")
	}
	return nil
}

// tgMigrateOneBot makes one bot of the two an older version had, once.
//
// The bot's own token moves to watchdog.json. When both had one, the bot that
// is on and has paired accounts stays (they are in a chat with it, and they
// get the alerts now); otherwise the watchdog's does. The other token is kept
// in telegram_bot.json, unused. A "direct" route becomes "auto": direct was
// the value nobody picked, and auto is direct as long as that works.
func tgMigrateOneBot() {
	if _, err := os.Stat(watchdogConfigPath()); err != nil && loadTGBotConfig().Token == "" {
		return // nothing is set up
	}
	wd := loadWatchdogConfig()
	if wd.TGOneBot && loadTGBotConfig().Token == "" {
		return
	}
	if !wd.TGOneBot && wd.TGRoute == "direct" {
		wd.TGRoute = "auto"
	}
	c := loadTGBotConfig()
	own, old := strings.TrimSpace(c.Token), strings.TrimSpace(wd.TGBotToken)
	unused := ""
	switch {
	case own == "" || own == old:
	case old == "":
		wd.TGBotToken = own
	case c.Enabled && len(c.Users) > 0:
		wd.TGBotToken, unused = own, old
	default:
		unused = own
	}
	if err := saveWatchdogConfig(wd); err != nil {
		log.Printf("telegram bot: cannot save %s: %v", watchdogConfigPath(), err)
		return // nothing is lost: the bot goes on with its own token
	}
	if own == "" {
		return
	}
	if _, err := updateTGBotConfig(func(c *tgBotConfig) error {
		c.Token = ""
		if unused != "" {
			c.OldToken = unused
		}
		return nil
	}); err != nil {
		log.Printf("telegram bot: cannot save %s: %v", tgBotPath(), err)
	}
	if unused != "" {
		recordError("E-TG-05", "telegram-bot", "the bot and the watchdog's alerts are one bot now: "+maskBotToken(wd.TGBotToken)+" ("+maskBotToken(unused)+" is no longer used)")
	}
}
