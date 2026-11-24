package main

// Telegram bot (Hashem Pro): the panel from a Telegram chat.
//
// The bot long-polls Telegram's Bot API (getUpdates) from this server,
// directly or through one of its tunnels (tgroute.go), so it also works where
// api.telegram.org is blocked. It is the panel's only bot: the watchdog's and
// every other alert go out through it.
//
// Who may use it: only Telegram accounts paired from the panel (Settings →
// Telegram bot → Pair: a one-time code the account sends as /start <code>),
// only in a private chat with the bot. An "admin" may do everything the bot
// offers, a "viewer" only reads. Nobody becomes an admin by writing first.
//
// What it runs: every action goes through the panel's own API handlers, in
// process (serveInProcess, node_relay.go), so their validation, Pro gates and
// audit apply exactly as for the page. Only the API groups the node relay
// allows are reachable (no terminal, login, password, 2FA or access
// settings), and the bot never takes a license key or turns the panel into a
// node core. Anything that removes, restores, updates or restarts much is
// asked again with a one-time button that lasts two minutes.
//
// Safety: the backlog of updates is dropped every time the bot starts, so a
// command sent while the panel was down (or replayed after a restart) never
// runs. The token is never logged: every error is redacted.

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	tgPollTimeout  = 25 // seconds Telegram holds a getUpdates open
	tgConfirmTTL   = 2 * time.Minute
	tgInputTTL     = 5 * time.Minute
	tgPairTTL      = 10 * time.Minute
	tgMaxText      = 3900 // Telegram allows 4096; leave room
	tgMaxUsers     = 20
	tgMaxPending   = 256
	tgMaxWorkers   = 8
	tgPairAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
)

// botRelayKey marks a request the bot runs in process (requireAuth and
// requireCSRF let it through, like the node relay's).
type botRelayCtx struct{}

var botRelayKey botRelayCtx

func botRelayed(r *http.Request) bool {
	_, ok := r.Context().Value(botRelayKey).(string)
	return ok
}

type tgBotUser struct {
	ID    int64  `json:"id"`
	Name  string `json:"name"`
	Role  string `json:"role"` // "admin" | "viewer"
	Added int64  `json:"added"`
	Mute  bool   `json:"mute,omitempty"` // no alerts to this account
}

func (u *tgBotUser) admin() bool { return u != nil && u.Role == "admin" }

// tgNotify: after a self-update the panel restarts; this says which chat to
// tell when it is back.
type tgNotify struct {
	Chat int64  `json:"chat"`
	From string `json:"from"`
	At   int64  `json:"at"`
}

type tgBotConfig struct {
	Enabled bool        `json:"enabled"`
	Token   string      `json:"token,omitempty"` // an older version's: it moves to watchdog.json (tgMigrateOneBot)
	Lang    string      `json:"lang"`            // "fa" | "en"
	Users   []tgBotUser `json:"users"`
	Notify  *tgNotify   `json:"notify,omitempty"`
	// OldToken: the second bot's token of an older version, kept but unused.
	OldToken string `json:"old_token,omitempty"`
}

func tgBotPath() string { return filepath.Join(configDir, "telegram_bot.json") }

var tgCfgMu sync.Mutex

func loadTGBotConfig() tgBotConfig {
	tgCfgMu.Lock()
	defer tgCfgMu.Unlock()
	return loadTGBotConfigLocked()
}

func loadTGBotConfigLocked() tgBotConfig {
	c := tgBotConfig{Lang: "fa"}
	if data, err := os.ReadFile(tgBotPath()); err == nil {
		if err := json.Unmarshal(data, &c); err != nil {
			log.Printf("telegram bot: %s is unreadable: %v", tgBotPath(), err)
		}
	}
	if c.Lang != "en" {
		c.Lang = "fa"
	}
	if c.Users == nil {
		c.Users = []tgBotUser{}
	}
	return c
}

func saveTGBotConfigLocked(c tgBotConfig) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(tgBotPath(), data, 0600)
}

// updateTGBotConfig changes the saved config under the lock.
func updateTGBotConfig(f func(c *tgBotConfig) error) (tgBotConfig, error) {
	tgCfgMu.Lock()
	defer tgCfgMu.Unlock()
	c := loadTGBotConfigLocked()
	if err := f(&c); err != nil {
		return c, err
	}
	return c, saveTGBotConfigLocked(c)
}

func (c tgBotConfig) user(id int64) *tgBotUser {
	for i := range c.Users {
		if c.Users[i].ID == id {
			u := c.Users[i]
			return &u
		}
	}
	return nil
}

// ---- runtime state ----

type tgPending struct {
	user  int64
	exp   time.Time
	label string
	run   func(u *tgBotUser) string
}

type tgInput struct {
	exp    time.Time
	prompt string
	run    func(u *tgBotUser, text string) tgScreen
}

type tgPair struct {
	role string
	exp  time.Time
}

var tgBot = struct {
	sync.Mutex
	state     string // off | locked | starting | running | error
	lastErr   string
	lastErrAt time.Time
	username  string
	token     string // the token the offset belongs to
	offset    int64
	pairs     map[string]tgPair
	pending   map[string]tgPending
	inputs    map[int64]tgInput
	strangers map[int64]time.Time // last "not allowed" answer
	badPair   map[int64][]time.Time
}{pairs: map[string]tgPair{}, pending: map[string]tgPending{}, inputs: map[int64]tgInput{},
	strangers: map[int64]time.Time{}, badPair: map[int64][]time.Time{}}

// tgSetState records the bot's state. It reports whether why is news (not
// the same error again within ten minutes), so a bot that cannot reach
// Telegram does not fill the error log.
func tgSetState(state, why string) bool {
	tgBot.Lock()
	defer tgBot.Unlock()
	tgBot.state = state
	if why == "" {
		if state == "running" {
			tgBot.lastErr = ""
		}
		return false
	}
	news := why != tgBot.lastErr || time.Since(tgBot.lastErrAt) > 10*time.Minute
	if news {
		log.Printf("telegram bot: %s", why)
		tgBot.lastErr, tgBot.lastErrAt = why, time.Now()
	}
	return news
}

func tgNonce() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// tgAddPending keeps a confirm button's action; it returns the nonce.
func tgAddPending(user int64, label string, run func(u *tgBotUser) string) string {
	tgBot.Lock()
	defer tgBot.Unlock()
	now := time.Now()
	for k, p := range tgBot.pending {
		if now.After(p.exp) {
			delete(tgBot.pending, k)
		}
	}
	for len(tgBot.pending) >= tgMaxPending {
		var ok string
		var ot time.Time
		for k, p := range tgBot.pending {
			if ok == "" || p.exp.Before(ot) {
				ok, ot = k, p.exp
			}
		}
		delete(tgBot.pending, ok)
	}
	n := tgNonce()
	tgBot.pending[n] = tgPending{user: user, exp: now.Add(tgConfirmTTL), label: label, run: run}
	return n
}

// tgTakePending returns the action of nonce once, for the user who was asked.
func tgTakePending(n string, user int64) (tgPending, bool) {
	tgBot.Lock()
	defer tgBot.Unlock()
	p, ok := tgBot.pending[n]
	if !ok || p.user != user {
		return tgPending{}, false
	}
	delete(tgBot.pending, n)
	if time.Now().After(p.exp) {
		return tgPending{}, false
	}
	return p, true
}

func tgSetInput(user int64, prompt string, run func(u *tgBotUser, text string) tgScreen) {
	tgBot.Lock()
	tgBot.inputs[user] = tgInput{exp: time.Now().Add(tgInputTTL), prompt: prompt, run: run}
	tgBot.Unlock()
}

func tgTakeInput(user int64) (tgInput, bool) {
	tgBot.Lock()
	defer tgBot.Unlock()
	in, ok := tgBot.inputs[user]
	delete(tgBot.inputs, user)
	if !ok || time.Now().After(in.exp) {
		return tgInput{}, false
	}
	return in, true
}

// tgNewPairCode makes a one-time code that pairs a Telegram account.
func tgNewPairCode(role string) string {
	tgBot.Lock()
	defer tgBot.Unlock()
	now := time.Now()
	for k, p := range tgBot.pairs {
		if now.After(p.exp) {
			delete(tgBot.pairs, k)
		}
	}
	for len(tgBot.pairs) >= 5 { // a few at a time
		for k := range tgBot.pairs {
			delete(tgBot.pairs, k)
			break
		}
	}
	b := make([]byte, 10)
	_, _ = rand.Read(b)
	code := make([]byte, len(b))
	for i, v := range b {
		code[i] = tgPairAlphabet[int(v)%len(tgPairAlphabet)]
	}
	s := string(code)
	tgBot.pairs[s] = tgPair{role: role, exp: now.Add(tgPairTTL)}
	return s
}

// tgUsePairCode spends code; it reports the role it gives. A Telegram
// account that sends five wrong codes in ten minutes is not heard for a while.
func tgUsePairCode(user int64, code string) (string, bool) {
	code = strings.ToUpper(strings.TrimSpace(code))
	tgBot.Lock()
	defer tgBot.Unlock()
	now := time.Now()
	var recent []time.Time
	for _, t := range tgBot.badPair[user] {
		if now.Sub(t) < 10*time.Minute {
			recent = append(recent, t)
		}
	}
	if len(recent) >= 5 {
		tgBot.badPair[user] = recent
		return "", false
	}
	for k, p := range tgBot.pairs {
		if subtle.ConstantTimeCompare([]byte(k), []byte(code)) == 1 && now.Before(p.exp) {
			delete(tgBot.pairs, k)
			delete(tgBot.badPair, user)
			return p.role, true
		}
	}
	if len(tgBot.badPair) > 1000 {
		tgBot.badPair = map[int64][]time.Time{}
	}
	tgBot.badPair[user] = append(recent, now)
	return "", false
}

// ---- Telegram's Bot API ----

type tgUser struct {
	ID        int64  `json:"id"`
	IsBot     bool   `json:"is_bot"`
	Username  string `json:"username"`
	FirstName string `json:"first_name"`
}

func (u tgUser) display() string {
	if u.Username != "" {
		return "@" + u.Username
	}
	if u.FirstName != "" {
		return u.FirstName
	}
	return strconv.FormatInt(u.ID, 10)
}

type tgChat struct {
	ID   int64  `json:"id"`
	Type string `json:"type"`
}

type tgMessage struct {
	MessageID int64   `json:"message_id"`
	From      *tgUser `json:"from"`
	Chat      tgChat  `json:"chat"`
	Text      string  `json:"text"`
}

type tgCallback struct {
	ID      string     `json:"id"`
	From    tgUser     `json:"from"`
	Message *tgMessage `json:"message"`
	Data    string     `json:"data"`
}

type tgUpdate struct {
	UpdateID int64       `json:"update_id"`
	Message  *tgMessage  `json:"message"`
	Callback *tgCallback `json:"callback_query"`
}

type tgAPIError struct {
	Code       int
	Desc       string
	RetryAfter int
}

func (e *tgAPIError) Error() string {
	return fmt.Sprintf("telegram said: %s (HTTP %d)", e.Desc, e.Code)
}

func tgCall(token, method string, params map[string]any, out any) error {
	body, err := json.Marshal(params)
	if err != nil {
		return err
	}
	return tgDo(token, method, body, "", 30*time.Second, out)
}

type tgBtn struct {
	Text string `json:"text"`
	Data string `json:"callback_data,omitempty"`
	URL  string `json:"url,omitempty"`
}

// tgScreen is one answer: text, buttons, and maybe a file.
type tgScreen struct {
	Text    string
	Keys    [][]tgBtn
	DocName string
	Doc     []byte
}

// tgTag marks this server's buttons. Two servers polling one bot token
// share its updates: a button pressed under one server's message may reach
// the other, which must not act on its own tunnel with that ID.
func tgTag() string {
	h := sha256.Sum256([]byte("hashem-tgbot:" + getMachineHash()))
	return hex.EncodeToString(h[:2]) + "|"
}

func tgMarkup(keys [][]tgBtn) map[string]any {
	if len(keys) == 0 {
		return map[string]any{"inline_keyboard": [][]tgBtn{}}
	}
	tag := tgTag()
	out := make([][]tgBtn, len(keys))
	for i, row := range keys {
		out[i] = make([]tgBtn, len(row))
		for j, b := range row {
			if b.Data != "" {
				b.Data = tag + b.Data
			}
			out[i][j] = b
		}
	}
	return map[string]any{"inline_keyboard": out}
}

// tgSendDoc sends data as a file.
func tgSendDoc(token string, chat int64, name string, data []byte, caption string) error {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("chat_id", strconv.FormatInt(chat, 10))
	if caption != "" {
		_ = mw.WriteField("caption", tgCut(caption, 1000))
	}
	fw, err := mw.CreateFormFile("document", name)
	if err != nil {
		return err
	}
	_, _ = fw.Write(data)
	if err := mw.Close(); err != nil {
		return err
	}
	return tgDo(token, "sendDocument", buf.Bytes(), mw.FormDataContentType(), 2*time.Minute, nil)
}

func tgCut(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

// tgShow sends a screen to chat, or edits message msg (a button's message)
// into it. A text too long for one message goes as a file.
func tgShow(token string, chat, msg int64, s tgScreen) {
	text := s.Text
	if strings.TrimSpace(text) == "" {
		text = "…"
	}
	if s.Doc == nil && len([]rune(text)) > tgMaxText {
		s.Doc, s.DocName = []byte(text), "hashem.txt"
		text = tgCut(text, 600) + "\n\n(the full text is in the file)"
	}
	params := map[string]any{"chat_id": chat, "text": text, "reply_markup": tgMarkup(s.Keys),
		"link_preview_options": map[string]any{"is_disabled": true}}
	var err error
	if msg != 0 {
		params["message_id"] = msg
		err = tgCall(token, "editMessageText", params, nil)
		var ae *tgAPIError
		if errors.As(err, &ae) && strings.Contains(ae.Desc, "not modified") {
			err = nil
		} else if err != nil { // too old to edit, or gone: send it anew
			delete(params, "message_id")
			err = tgCall(token, "sendMessage", params, nil)
		}
	} else {
		err = tgCall(token, "sendMessage", params, nil)
	}
	if err != nil {
		recordError("E-TG-02", "telegram-bot", "send failed: "+err.Error())
	}
	if s.Doc != nil {
		name := s.DocName
		if name == "" {
			name = "hashem.txt"
		}
		if err := tgSendDoc(token, chat, name, s.Doc, ""); err != nil {
			recordError("E-TG-02", "telegram-bot", "file not sent: "+err.Error())
		}
	}
}

// ---- the poller ----

// tgAsync runs an update's handler (tests run it in line).
var tgAsync = func(f func()) { go f() }

var tgWorkers = make(chan struct{}, tgMaxWorkers)

var tgSleep = time.Sleep

func startTelegramBot() {
	var backoff time.Duration
	for {
		d := tgBotTick(&backoff)
		if d > 0 {
			tgSleep(d)
		}
	}
}

// tgBotTick is one round of the poller: it reports how long to wait before
// the next.
func tgBotTick(backoff *time.Duration) time.Duration {
	c := loadTGBotConfig()
	tok := tgToken(loadWatchdogConfig())
	switch {
	case !c.Enabled:
		tgSetState("off", "")
		tgForget()
		return 10 * time.Second
	case !hasPro(proTelegramBot):
		tgSetState("locked", "")
		tgForget()
		return 30 * time.Second
	case tok == "":
		tgSetState("error", "no bot token: set one in Settings → Telegram bot")
		tgForget()
		return 30 * time.Second
	}
	fail := func(err error) time.Duration {
		why := err.Error()
		var ae *tgAPIError
		if errors.As(err, &ae) {
			switch ae.Code {
			case http.StatusConflict:
				why = "another program reads this bot's messages (the same token on another server, or a webhook): give each server a bot of its own"
			case http.StatusUnauthorized, http.StatusNotFound:
				why = "Telegram does not know this bot token"
				tgForget()
			case http.StatusTooManyRequests:
				if ae.RetryAfter > 0 {
					*backoff = time.Duration(ae.RetryAfter) * time.Second
				}
			}
		}
		if tgSetState("error", why) {
			recordError("E-TG-01", "telegram-bot", why)
		}
		if *backoff < 5*time.Second {
			*backoff = 5 * time.Second
		} else if *backoff < time.Minute {
			*backoff *= 2
			if *backoff > time.Minute {
				*backoff = time.Minute
			}
		}
		return *backoff
	}
	tgBot.Lock()
	known, offset := tgBot.token == tok, tgBot.offset
	tgBot.Unlock()
	if !known { // first start or a new token: who is it, and drop the backlog
		tgSetState("starting", "")
		var me tgUser
		if err := tgCall(tok, "getMe", map[string]any{}, &me); err != nil {
			return fail(err)
		}
		var last []tgUpdate
		if err := tgCall(tok, "getUpdates", map[string]any{"offset": -1, "timeout": 0}, &last); err != nil {
			return fail(err)
		}
		offset = 0
		if len(last) > 0 {
			offset = last[len(last)-1].UpdateID + 1
		}
		tgBot.Lock()
		tgBot.token, tgBot.offset, tgBot.username = tok, offset, me.Username
		tgBot.Unlock()
		_ = tgCall(tok, "setMyCommands", map[string]any{"commands": tgCommandList(c)}, nil)
		tgAfterRestart(tok, c)
	}
	var ups []tgUpdate
	params := map[string]any{"timeout": tgPollTimeout, "allowed_updates": []string{"message", "callback_query"}}
	if offset > 0 {
		params["offset"] = offset
	}
	body, _ := json.Marshal(params)
	if err := tgDo(tok, "getUpdates", body, "", (tgPollTimeout+15)*time.Second, &ups); err != nil {
		return fail(err)
	}
	*backoff = 0
	tgSetState("running", "")
	for _, u := range ups {
		if u.UpdateID >= offset {
			offset = u.UpdateID + 1
		}
		u := u
		tgWorkers <- struct{}{}
		tgAsync(func() {
			defer func() {
				<-tgWorkers
				if p := recover(); p != nil {
					recordError("E-TG-03", "telegram-bot", fmt.Sprintf("an update failed: %v", p))
				}
			}()
			tgHandle(tok, u)
		})
	}
	tgBot.Lock()
	if tgBot.token == tok {
		tgBot.offset = offset
	}
	tgBot.Unlock()
	return 0
}

// tgForget makes the next start drop the backlog again.
func tgForget() {
	tgBot.Lock()
	tgBot.token, tgBot.offset = "", 0
	tgBot.Unlock()
}

// tgAfterRestart tells the chat that asked for an update that the panel is back.
func tgAfterRestart(tok string, c tgBotConfig) {
	n := c.Notify
	if n == nil {
		return
	}
	_, _ = updateTGBotConfig(func(c *tgBotConfig) error { c.Notify = nil; return nil })
	if time.Since(time.Unix(n.At, 0)) > time.Hour {
		return
	}
	text := tgT(c, "✅ پنل دوباره بالا آمد. نسخه: ", "✅ The panel is back. Version: ") + displayVersion(panelVersion)
	if n.From != "" && n.From != panelVersion {
		text += tgT(c, " (قبلی: ", " (was ") + displayVersion(n.From) + ")"
	} else if n.From == panelVersion {
		text += tgT(c, "\n⚠️ نسخه عوض نشد: لاگ آپدیت را در پنل ببینید.", "\n⚠️ The version did not change: see the update log in the panel.")
	}
	tgShow(tok, n.Chat, 0, tgScreen{Text: text, Keys: [][]tgBtn{{{Text: tgT(c, "🏠 منو", "🏠 Menu"), Data: "m"}}}})
}

// tgHandle answers one update.
func tgHandle(tok string, u tgUpdate) {
	c := loadTGBotConfig()
	if m := u.Message; m != nil {
		if m.Chat.Type != "private" || m.From == nil || m.From.IsBot {
			return // groups and channels: never (anyone there could send commands)
		}
		text := strings.TrimSpace(m.Text)
		if code, ok := strings.CutPrefix(text, "/start "); ok && strings.TrimSpace(code) != "" {
			tgPairFrom(tok, c, *m.From, m.Chat.ID, code)
			return
		}
		usr := c.user(m.From.ID)
		if usr == nil {
			tgStranger(tok, c, *m.From, m.Chat.ID)
			return
		}
		tgShow(tok, m.Chat.ID, 0, tgOnText(c, usr, m.Chat.ID, text))
		return
	}
	cb := u.Callback
	if cb == nil {
		return
	}
	answer := func(text string) {
		p := map[string]any{"callback_query_id": cb.ID}
		if text != "" {
			p["text"], p["show_alert"] = text, true
		}
		_ = tgCall(tok, "answerCallbackQuery", p, nil)
	}
	if cb.Message == nil || cb.Message.Chat.Type != "private" || cb.From.IsBot {
		answer("")
		return
	}
	usr := c.user(cb.From.ID)
	if usr == nil {
		answer(tgT(c, "اجازه ندارید.", "Not allowed."))
		return
	}
	chat, msg := cb.Message.Chat.ID, cb.Message.MessageID
	data, mine := strings.CutPrefix(cb.Data, tgTag())
	if !mine {
		answer(tgT(c, "این دکمه مال سرور دیگری است که همین ربات را دارد (یا از نسخه‌ی قبلی است): از /menu همین سرور شروع کنید. برای هر سرور یک ربات جدا بسازید.",
			"This button belongs to another server that uses this bot (or to an older version): start from this server's /menu. Give each server a bot of its own."))
		return
	}
	if n, ok := strings.CutPrefix(data, "ok:"); ok {
		p, ok := tgTakePending(n, usr.ID)
		if !ok {
			answer(tgT(c, "این دکمه منقضی شده یا قبلاً استفاده شده؛ دوباره از منو انجام دهید.", "This button has expired or was used: do it again from the menu."))
			return
		}
		if !usr.admin() {
			answer(tgT(c, "فقط ادمین.", "Admins only."))
			return
		}
		answer("")
		tgShow(tok, chat, msg, tgScreen{Text: "⏳ " + p.label})
		out := p.run(usr)
		tgShow(tok, chat, msg, tgScreen{Text: out, Keys: [][]tgBtn{{{Text: tgT(c, "🏠 منو", "🏠 Menu"), Data: "m"}}}})
		return
	}
	if n, ok := strings.CutPrefix(data, "no:"); ok {
		tgTakePending(n, usr.ID)
		answer("")
		tgShow(tok, chat, msg, tgMenu(c, usr))
		return
	}
	answer("")
	if tgSlow(data) {
		tgShow(tok, chat, msg, tgScreen{Text: tgT(c, "⏳ لطفاً صبر کنید…", "⏳ Working…")})
	}
	tgShow(tok, chat, msg, tgOnButton(c, usr, chat, data))
}

// tgSlow: buttons that take a while (they say so first).
func tgSlow(data string) bool {
	key, arg, _ := strings.Cut(data, ":")
	switch key {
	case "tr", "tg", "tp", "lg", "bks", "xs", "nd":
		return true
	case "dr":
		return arg == "run"
	case "to":
		return arg == "health" || arg == "tune"
	case "up":
		return arg == "chk" || arg == "os" || arg == "osr" // os: each foreign server is asked
	case "wd":
		return arg == "test" || arg == "bkn"
	}
	return false
}

// tgStranger answers an account that is not paired, now and then: its ID
// helps the admin, and nothing else is said.
func tgStranger(tok string, c tgBotConfig, from tgUser, chat int64) {
	tgBot.Lock()
	last, seen := tgBot.strangers[from.ID]
	if len(tgBot.strangers) > 1000 {
		tgBot.strangers = map[int64]time.Time{}
	}
	tgBot.strangers[from.ID] = time.Now()
	tgBot.Unlock()
	if seen && time.Since(last) < 10*time.Minute {
		return
	}
	tgShow(tok, chat, 0, tgScreen{Text: tgT(c,
		"⛔ این حساب به پنل وصل نیست.\nشناسه تلگرام شما: ",
		"⛔ This account is not paired with the panel.\nYour Telegram ID: ") + strconv.FormatInt(from.ID, 10) +
		tgT(c, "\nدر پنل: Settings → Telegram bot → Pair، و کد را این‌طور بفرستید: /start CODE",
			"\nIn the panel: Settings → Telegram bot → Pair, then send the code as /start CODE")})
}

func tgPairFrom(tok string, c tgBotConfig, from tgUser, chat int64, code string) {
	role, ok := tgUsePairCode(from.ID, code)
	if !ok {
		tgShow(tok, chat, 0, tgScreen{Text: tgT(c, "⛔ کد اشتباه است یا منقضی شده. از پنل کد تازه بگیرید.",
			"⛔ Wrong or expired code. Get a new one from the panel.")})
		return
	}
	nc, err := updateTGBotConfig(func(c *tgBotConfig) error {
		for i := range c.Users {
			if c.Users[i].ID == from.ID {
				c.Users[i].Role, c.Users[i].Name = role, from.display()
				return nil
			}
		}
		if len(c.Users) >= tgMaxUsers {
			return fmt.Errorf("at most %d accounts", tgMaxUsers)
		}
		c.Users = append(c.Users, tgBotUser{ID: from.ID, Name: from.display(), Role: role, Added: time.Now().Unix()})
		return nil
	})
	if err != nil {
		tgShow(tok, chat, 0, tgScreen{Text: "⛔ " + err.Error()})
		return
	}
	LogSecurityAudit("telegram_bot_paired", from.display(), "telegram", fmt.Sprintf("id=%d role=%s", from.ID, role))
	for _, o := range nc.Users { // the other admins hear of it
		if o.ID != from.ID && o.Role == "admin" {
			tgShow(tok, o.ID, 0, tgScreen{Text: tgT(nc, "🔐 حساب تازه به ربات وصل شد: ", "🔐 A new account was paired with the bot: ") +
				from.display() + " (" + strconv.FormatInt(from.ID, 10) + ", " + role + ")"})
		}
	}
	usr := nc.user(from.ID)
	s := tgMenu(nc, usr)
	s.Text = tgT(nc, "✅ وصل شدید (نقش: ", "✅ Paired (role: ") + role + ")\n\n" + s.Text
	tgShow(tok, chat, 0, s)
}

// ---- calling the panel ----

// tgBotAllowed: what the bot may call. The node relay's list (no terminal,
// logins, password, 2FA or access settings), and never a license key or
// turning the panel into a node core.
func tgBotAllowed(method, path string) bool {
	if !nodeRelayMethod(method) || !nodeRelayAllowed(path) {
		return false
	}
	if method != http.MethodGet && (path == "/api/license" || strings.HasPrefix(path, "/api/update/kind")) {
		return false
	}
	return true
}

// tgAPI runs one panel API request as usr. It returns the answer's status
// and body.
func tgAPI(usr *tgBotUser, method, pathQuery string, body any) (int, []byte, error) {
	path, query, _ := strings.Cut(pathQuery, "?")
	if !tgBotAllowed(method, path) {
		return 0, nil, fmt.Errorf("%s %s is not available from the bot: open the panel for it", method, path)
	}
	if method != http.MethodGet && !usr.admin() {
		return 0, nil, errors.New("this account may only look (viewer): an admin can do this")
	}
	var raw []byte
	if body != nil {
		var err error
		if raw, err = json.Marshal(body); err != nil {
			return 0, nil, err
		}
	}
	who := "telegram:" + usr.Name
	res, err := serveInProcess(botRelayKey, who, nodeHTTPReq{Method: method, Path: path, Query: query, Type: "application/json", Body: raw, User: who})
	if err != nil {
		return 0, nil, err
	}
	if method != http.MethodGet {
		LogSecurityAudit("via_telegram", who, "telegram", fmt.Sprintf("%s %s -> %d", method, path, res.Status))
	}
	return res.Status, res.Body, nil
}

// tgAPIJSON runs a request and decodes a good answer into out; a refused
// one comes back as an error with the panel's own message.
func tgAPIJSON(usr *tgBotUser, method, pathQuery string, body, out any) error {
	code, data, err := tgAPI(usr, method, pathQuery, body)
	if err != nil {
		return err
	}
	if code >= 300 {
		return errors.New(tgAPIErrText(code, data))
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("unexpected answer: %v", err)
		}
	}
	return nil
}

func tgAPIErrText(code int, data []byte) string {
	var e struct {
		Code  string `json:"error_code"`
		Error string `json:"error"`
		Hint  string `json:"hint"`
	}
	if json.Unmarshal(data, &e) == nil && e.Error != "" {
		s := e.Error
		if e.Code != "" {
			s = e.Code + ": " + s
		}
		if e.Hint != "" {
			s += "\n" + e.Hint
		}
		return s
	}
	return fmt.Sprintf("HTTP %d: %s", code, tgCut(strings.TrimSpace(string(data)), 300))
}

// ---- the panel's page: GET/POST /api/telegram-bot ----

func tgBotView() map[string]any {
	c := loadTGBotConfig()
	tgBot.Lock()
	state, lastErr, username := tgBot.state, tgBot.lastErr, tgBot.username
	tgBot.Unlock()
	if state == "" {
		state = "off"
	}
	users := append([]tgBotUser(nil), c.Users...)
	sort.Slice(users, func(i, j int) bool { return users[i].Added < users[j].Added })
	wd := loadWatchdogConfig()
	tok := tgToken(wd)
	via, viaName := tgVia()
	return map[string]any{
		"enabled": c.Enabled, "lang": c.Lang, "licensed": hasPro(proTelegramBot),
		"token_set": tok != "", "token_masked": maskBotToken(tok),
		"chat_id": wd.TGChatID, "route": wd.TGRoute, "tunnel_id": wd.TGTunnelID, "tunnel_port": wd.TGTunnelPort, "tunnels": tunnelChoices(),
		"via": via, "via_name": viaName, "alerts_to": len(tgReceivers(wd)),
		"state": state, "error": lastErr, "username": username, "users": users,
	}
}

func tgBotUsername() string {
	tgBot.Lock()
	defer tgBot.Unlock()
	return tgBot.username
}

func handleTGBotGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, tgBotView())
}

func handleTGBotPost(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Action  string  `json:"action"`
		Enabled *bool   `json:"enabled"`
		Token   *string `json:"token"`
		Lang    string  `json:"lang"`
		Role    string  `json:"role"`
		ID      int64   `json:"id"`
		// the one bot's other settings (watchdog.json)
		ChatID     *string `json:"chat_id"`
		Route      string  `json:"route"`
		TunnelID   *int    `json:"tunnel_id"`
		TunnelPort int     `json:"tunnel_port"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&body); err != nil {
		writeAPIError(w, r, "E-TG-04", "invalid json")
		return
	}
	switch body.Action {
	case "", "save":
		if body.Enabled != nil && *body.Enabled && proRequired(w, r, proTelegramBot, "The Telegram bot") {
			return
		}
		transport := body.Token != nil || body.ChatID != nil || body.Route != "" || body.TunnelID != nil || body.TunnelPort > 0
		if transport {
			if proRequired(w, r, proTelegramBot, "The Telegram bot") {
				return
			}
			wd := loadWatchdogConfig()
			if body.Token != nil && !strings.Contains(*body.Token, "...") { // the masked one came back: unchanged
				t := strings.TrimSpace(*body.Token)
				if t != "" && !tgTokenShape(t) {
					writeAPIError(w, r, "E-TG-04", "this is not a bot token (it looks like 123456:ABC-...)")
					return
				}
				wd.TGBotToken = t
			}
			if body.ChatID != nil {
				id := strings.TrimSpace(*body.ChatID)
				if id != "" && !tgChatRe.MatchString(id) {
					writeAPIError(w, r, "E-TG-04", "the alert chat is a chat ID (123456789, -100123456789) or @channel")
					return
				}
				wd.TGChatID = id
			}
			if err := tgSetRoute(&wd, body.Route, body.TunnelID, body.TunnelPort); err != nil {
				writeAPIError(w, r, "E-TG-04", err.Error())
				return
			}
			if err := saveWatchdogConfig(wd); err != nil {
				writeAPIError(w, r, "E-TG-04", err.Error())
				return
			}
			tgGoodReset()
		}
		_, err := updateTGBotConfig(func(c *tgBotConfig) error {
			if body.Enabled != nil {
				c.Enabled = *body.Enabled
			}
			if body.Token != nil {
				c.Token = "" // the one token is in watchdog.json
			}
			if body.Lang == "en" || body.Lang == "fa" {
				c.Lang = body.Lang
			}
			return nil
		})
		if err != nil {
			writeAPIError(w, r, "E-TG-04", err.Error())
			return
		}
		LogSecurityAudit("telegram_bot_config", cfg.Username, clientIP(r), fmt.Sprintf("enabled=%v", loadTGBotConfig().Enabled))
	case "pair":
		if proRequired(w, r, proTelegramBot, "The Telegram bot") {
			return
		}
		role := body.Role
		if role != "viewer" {
			role = "admin"
		}
		code := tgNewPairCode(role)
		LogSecurityAudit("telegram_bot_pair_code", cfg.Username, clientIP(r), "role="+role)
		v := tgBotView()
		v["code"], v["code_role"], v["code_ttl_sec"] = code, role, int(tgPairTTL/time.Second)
		if u, _ := v["username"].(string); u != "" {
			v["link"] = "https://t.me/" + u + "?start=" + code
		}
		writeJSON(w, v)
		return
	case "remove-user", "set-role", "mute", "unmute":
		_, err := updateTGBotConfig(func(c *tgBotConfig) error {
			for i := range c.Users {
				if c.Users[i].ID != body.ID {
					continue
				}
				if body.Action == "remove-user" {
					c.Users = append(c.Users[:i], c.Users[i+1:]...)
				} else if body.Action == "mute" || body.Action == "unmute" {
					c.Users[i].Mute = body.Action == "mute"
				} else if body.Role == "admin" || body.Role == "viewer" {
					c.Users[i].Role = body.Role
				}
				return nil
			}
			return errors.New("no such account")
		})
		if err != nil {
			writeAPIError(w, r, "E-TG-04", err.Error())
			return
		}
		tgBot.Lock()
		delete(tgBot.inputs, body.ID)
		for k, p := range tgBot.pending { // a removed account's buttons die with it
			if p.user == body.ID {
				delete(tgBot.pending, k)
			}
		}
		tgBot.Unlock()
		LogSecurityAudit("telegram_bot_"+body.Action, cfg.Username, clientIP(r), fmt.Sprintf("id=%d role=%s", body.ID, body.Role))
	case "test":
		if proRequired(w, r, proTelegramBot, "The Telegram bot") {
			return
		}
		c := loadTGBotConfig()
		tok := tgToken(loadWatchdogConfig())
		if tok == "" {
			writeAPIError(w, r, "E-TG-01", "no bot token: paste it above and save")
			return
		}
		var me tgUser
		if err := tgCall(tok, "getMe", map[string]any{}, &me); err != nil {
			writeAPIError(w, r, "E-TG-01", err.Error())
			return
		}
		sent, err := 0, error(nil)
		if wd := loadWatchdogConfig(); len(tgReceivers(wd)) > 0 {
			if sent, err = sendTelegramCount(wd, tgT(c, "✅ پیام آزمایشی از پنل هاشم", "✅ Test message from the Hashem panel")); err != nil {
				writeAPIError(w, r, "E-TG-02", err.Error())
				return
			}
		}
		v := tgBotView()
		v["test_bot"], v["test_sent"] = me.Username, sent
		writeJSON(w, v)
		return
	default:
		writeAPIError(w, r, "E-TG-04", "unknown action")
		return
	}
	writeJSON(w, tgBotView())
}

// tgTokenShape: <digits>:<35 or so of [A-Za-z0-9_-]>.
func tgTokenShape(t string) bool {
	id, key, ok := strings.Cut(t, ":")
	if !ok || len(id) < 3 || len(key) < 20 || len(t) > 100 {
		return false
	}
	if _, err := strconv.ParseInt(id, 10, 64); err != nil {
		return false
	}
	for _, r := range key {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

// tgT picks the bot's language.
func tgT(c tgBotConfig, fa, en string) string {
	if c.Lang == "en" {
		return en
	}
	return fa
}
