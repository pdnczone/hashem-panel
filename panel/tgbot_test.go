package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const tgTestToken = "123456789:AAEtesttokentesttokentesttokentestXY"

// tgFake is Telegram's Bot API as far as the bot uses it.
type tgFake struct {
	mu      sync.Mutex
	queue   []tgUpdate // waiting for getUpdates
	calls   []string   // method names, in order
	sent    []map[string]any
	docs    int
	status  int    // answer every call with this status (0: ok)
	desc    string // and this description
	actions []string
}

func (f *tgFake) handler(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	method := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
	f.calls = append(f.calls, method)
	if f.status != 0 {
		w.WriteHeader(f.status)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error_code": f.status, "description": f.desc})
		return
	}
	var p map[string]any
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		_ = json.NewDecoder(r.Body).Decode(&p)
	} else {
		_, _ = io.Copy(io.Discard, r.Body)
	}
	var result any = true
	switch method {
	case "getMe":
		result = map[string]any{"id": 1, "is_bot": true, "username": "hashem_test_bot"}
	case "getUpdates":
		ups := []tgUpdate{}
		if off, _ := p["offset"].(float64); off < 0 { // the backlog's last update; everything before it is forgotten
			if n := len(f.queue); n > 0 {
				ups = f.queue[n-1:]
			}
			f.queue = nil
		} else {
			for _, u := range f.queue {
				if float64(u.UpdateID) >= off {
					ups = append(ups, u)
				}
			}
			f.queue = nil
		}
		result = ups
	case "sendMessage", "editMessageText":
		f.sent = append(f.sent, p)
	case "sendDocument":
		f.docs++
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "result": result})
}

func (f *tgFake) texts() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var b strings.Builder
	for _, m := range f.sent {
		b.WriteString(m["text"].(string) + "\n---\n")
	}
	return b.String()
}

func (f *tgFake) push(u ...tgUpdate) {
	f.mu.Lock()
	f.queue = append(f.queue, u...)
	f.mu.Unlock()
}

func (f *tgFake) lastKeys() [][]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := len(f.sent) - 1; i >= 0; i-- {
		if rm, ok := f.sent[i]["reply_markup"].(map[string]any); ok {
			if rows, ok := rm["inline_keyboard"].([]any); ok && len(rows) > 0 {
				out := [][]any{}
				for _, r := range rows {
					out = append(out, r.([]any))
				}
				return out
			}
		}
	}
	return nil
}

// tgButton finds the callback data of the button whose text holds label.
func (f *tgFake) button(t *testing.T, label string) string {
	t.Helper()
	for _, row := range f.lastKeys() {
		for _, b := range row {
			m := b.(map[string]any)
			if strings.Contains(m["text"].(string), label) {
				return m["callback_data"].(string)
			}
		}
	}
	t.Fatalf("no %q button in %v", label, f.lastKeys())
	return ""
}

func newTGHarness(t *testing.T, licensed bool) *tgFake {
	t.Helper()
	apLicense(t, licensed)
	restore := withTempConfigDir(t)
	f := &tgFake{}
	srv := httptest.NewServer(http.HandlerFunc(f.handler))
	oBase, oClients, oAsync, oMux, oBP := tgAPIBase, tgBotClients, tgAsync, nodeRelayMux, cfg.BasePath
	tgAPIBase = srv.URL
	tgBotClients = func(timeout time.Duration) []*http.Client { return []*http.Client{{Timeout: 5 * time.Second}} }
	tgAsync = func(fn func()) { fn() }
	cfg.BasePath = "x"
	m := http.NewServeMux()
	m.HandleFunc("POST /x/api/action", requireAuth(requireCSRF(func(w http.ResponseWriter, r *http.Request) {
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b)
		f.mu.Lock()
		f.actions = append(f.actions, b["action"].(string))
		f.mu.Unlock()
		writeJSON(w, map[string]string{"status": "ok", "output": "done"})
	})))
	m.HandleFunc("GET /x/api/customers", requireAuth(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"customers": []map[string]any{{"id": 1, "name": "shop", "quota_gb": 100, "used_rx": 5e9, "links": []any{}}}})
	}))
	m.HandleFunc("POST /x/api/customers", requireAuth(requireCSRF(func(w http.ResponseWriter, r *http.Request) {
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b)
		f.mu.Lock()
		f.actions = append(f.actions, fmt.Sprintf("%v days=%v reset=%v", b["action"], b["days"], b["reset_usage"]))
		f.mu.Unlock()
		writeJSON(w, map[string]string{"status": "ok"})
	})))
	m.HandleFunc("GET /x/api/status", requireAuth(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"role": "iran", "bot": botRelayed(r)})
	}))
	nodeRelayMux = func() http.Handler { return m }
	oSnap := snapPtr.Load()
	snapPtr.Store(&HubSnapshot{At: time.Now(), Local: tunnelStatus{Role: "iran (server)", FrpSvc: "frps"},
		Main:  &peerLive{peerRecord: peerRecord{ID: mainTunnelID, Name: "Tunnel", RemotePub: "198.51.100.1"}, HealthState: stateHealthy},
		Peers: []peerLive{{peerRecord: peerRecord{ID: 3, Name: "nl", RemotePub: "198.51.100.3", GreIf: "gre-t3", FrpsSvc: "frps-3"}, HealthState: stateDegraded}}})
	tgBot.Lock()
	tgBot.token, tgBot.offset, tgBot.pending, tgBot.inputs, tgBot.pairs = "", 0, map[string]tgPending{}, map[int64]tgInput{}, map[string]tgPair{}
	tgBot.strangers, tgBot.badPair, tgBot.lastErr = map[int64]time.Time{}, map[int64][]time.Time{}, ""
	tgBot.Unlock()
	t.Cleanup(func() {
		srv.Close()
		tgAPIBase, tgBotClients, tgAsync, nodeRelayMux, cfg.BasePath = oBase, oClients, oAsync, oMux, oBP
		tgForget()
		snapPtr.Store(oSnap)
		restore()
	})
	if _, err := updateTGBotConfig(func(c *tgBotConfig) error {
		c.Enabled, c.Token, c.Lang = true, tgTestToken, "en"
		c.Users = []tgBotUser{{ID: 42, Name: "@boss", Role: "admin"}, {ID: 43, Name: "@eye", Role: "viewer"}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return f
}

func tgMsg(id int64, from int64, chatType, text string) tgUpdate {
	return tgUpdate{UpdateID: id, Message: &tgMessage{MessageID: id, From: &tgUser{ID: from, Username: "u"}, Chat: tgChat{ID: from, Type: chatType}, Text: text}}
}

func tgPress(id int64, from int64, data string) tgUpdate {
	if !strings.HasPrefix(data, tgTag()) && !strings.HasPrefix(data, "raw:") {
		data = tgTag() + data
	}
	data = strings.TrimPrefix(data, "raw:")
	return tgUpdate{UpdateID: id, Callback: &tgCallback{ID: "cb", From: tgUser{ID: from}, Data: data,
		Message: &tgMessage{MessageID: 7, Chat: tgChat{ID: from, Type: "private"}}}}
}

func tgTick(t *testing.T) time.Duration {
	t.Helper()
	var b time.Duration
	return tgBotTick(&b)
}

// A command sent while the panel was down (or one Telegram hands out again
// after a restart) never runs: the backlog is dropped at every start.
func TestTGBotDropsTheBacklog(t *testing.T) {
	f := newTGHarness(t, true)
	f.push(tgMsg(10, 42, "private", `/api POST /api/action {"action":"restart-gre"}`), tgPress(11, 42, "tr:0"))
	tgTick(t) // start: getMe, drop the backlog, then poll
	tgTick(t)
	if len(f.actions) != 0 {
		t.Fatalf("an old update ran: %v", f.actions)
	}
	// a new one runs
	f.push(tgPress(12, 42, "tp:0"))
	tgTick(t)
	if strings.Join(f.actions, ",") != "ping" {
		t.Fatalf("a new update: %v", f.actions)
	}
}

func TestTGBotOnlyPairedAccountsInPrivateChats(t *testing.T) {
	f := newTGHarness(t, true)
	tgTick(t)
	f.push(tgMsg(1, 42, "group", "/status"), tgMsg(2, 42, "supergroup", "/menu"))
	tgTick(t)
	if len(f.sent) != 0 {
		t.Fatalf("a group chat was answered: %v", f.texts())
	}
	f.push(tgMsg(3, 99, "private", "/status"), tgMsg(4, 99, "private", "/status"), tgPress(5, 99, "tp:0"))
	tgTick(t)
	if n := strings.Count(f.texts(), "not paired"); n != 1 {
		t.Fatalf("a stranger gets one short answer, got %d: %s", n, f.texts())
	}
	if len(f.actions) != 0 {
		t.Fatalf("a stranger's button ran: %v", f.actions)
	}
	f.push(tgMsg(6, 42, "private", "/status"))
	tgTick(t)
	if !strings.Contains(f.texts(), "📊") {
		t.Fatalf("the admin's /status: %s", f.texts())
	}
}

func TestTGBotPairing(t *testing.T) {
	f := newTGHarness(t, true)
	tgTick(t)
	rr := httptest.NewRecorder()
	handleTGBotPost(rr, httptest.NewRequest("POST", "/api/telegram-bot", strings.NewReader(`{"action":"pair","role":"viewer"}`)))
	var v struct {
		Code string `json:"code"`
		Link string `json:"link"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &v)
	if len(v.Code) != 10 || !strings.Contains(v.Link, "hashem_test_bot?start="+v.Code) {
		t.Fatalf("pair: %s", rr.Body.String())
	}
	f.push(tgMsg(1, 77, "private", "/start "+strings.ToLower(v.Code)))
	tgTick(t)
	u := loadTGBotConfig().user(77)
	if u == nil || u.Role != "viewer" {
		t.Fatalf("not paired: %+v", loadTGBotConfig().Users)
	}
	if !strings.Contains(f.texts(), "new account was paired") {
		t.Fatalf("the admins hear of a new account: %s", f.texts())
	}
	// the code works once
	f.push(tgMsg(2, 78, "private", "/start "+v.Code))
	tgTick(t)
	if loadTGBotConfig().user(78) != nil {
		t.Fatal("a code paired twice")
	}
	// guessing stops after five tries, even with a good code
	for i := 0; i < 5; i++ {
		tgUsePairCode(79, "WRONGCODE1")
	}
	good := tgNewPairCode("admin")
	if _, ok := tgUsePairCode(79, good); ok {
		t.Fatal("an account that guessed five times is still heard")
	}
	// unlicensed: no codes
	apLicense(t, false)
	rr = httptest.NewRecorder()
	handleTGBotPost(rr, httptest.NewRequest("POST", "/api/telegram-bot", strings.NewReader(`{"action":"pair"}`)))
	if rr.Code < 400 || !strings.Contains(rr.Body.String(), "E-LIC-01") {
		t.Fatalf("pairing without the license: %d %s", rr.Code, rr.Body.String())
	}
}

// Remove asks again; the confirm button works once, only for the account it
// was shown to, and not after it expires.
func TestTGBotConfirmOnce(t *testing.T) {
	f := newTGHarness(t, true)
	tgTick(t)
	f.push(tgPress(1, 42, "tx:0"))
	tgTick(t)
	if len(f.actions) != 0 {
		t.Fatalf("remove ran without a confirm: %v", f.actions)
	}
	ok := f.button(t, "Yes")
	f.push(tgPress(2, 43, ok)) // another account presses it
	tgTick(t)
	if len(f.actions) != 0 {
		t.Fatalf("another account's press ran it: %v", f.actions)
	}
	// the viewer's press did not use it up? It did not: the nonce belongs to 42
	f.push(tgPress(3, 42, ok), tgPress(4, 42, ok))
	tgTick(t)
	if strings.Join(f.actions, ",") != "remove-tunnel" {
		t.Fatalf("confirm once: %v", f.actions)
	}
	// expired
	n := tgAddPending(42, "x", func(u *tgBotUser) string { return tgRunAction(loadTGBotConfig(), u, "ping", 0) })
	tgBot.Lock()
	p := tgBot.pending[n]
	p.exp = time.Now().Add(-time.Second)
	tgBot.pending[n] = p
	tgBot.Unlock()
	f.push(tgPress(5, 42, "ok:"+n))
	tgTick(t)
	if len(f.actions) != 1 {
		t.Fatalf("an expired button ran: %v", f.actions)
	}
}

func TestTGBotViewerOnlyReads(t *testing.T) {
	f := newTGHarness(t, true)
	tgTick(t)
	viewer := loadTGBotConfig().user(43)
	if _, _, err := tgAPI(viewer, http.MethodPost, "/api/action", map[string]any{"action": "ping"}); err == nil {
		t.Fatal("a viewer changed something")
	}
	f.push(tgPress(1, 43, "tr:0"), tgMsg(2, 43, "private", `/api POST /api/action {"action":"ping"}`))
	tgTick(t)
	if len(f.actions) != 0 {
		t.Fatalf("a viewer ran %v", f.actions)
	}
	code, body, err := tgAPI(viewer, http.MethodGet, "/api/status", nil)
	if err != nil || code != 200 || !strings.Contains(string(body), `"bot":true`) {
		t.Fatalf("a viewer reads, in process: %d %s %v", code, body, err)
	}
}

func TestTGBotRawAPI(t *testing.T) {
	f := newTGHarness(t, true)
	tgTick(t)
	f.push(tgMsg(1, 42, "private", "/api GET /api/status"))
	tgTick(t)
	if !strings.Contains(f.texts(), `"role": "iran"`) {
		t.Fatalf("/api GET: %s", f.texts())
	}
	f.push(tgMsg(2, 42, "private", `/api POST /api/action {"action":"restart-gre","peer_id":3}`))
	tgTick(t)
	if len(f.actions) != 0 {
		t.Fatal("/api POST ran without a confirm")
	}
	f.push(tgPress(3, 42, f.button(t, "Yes")))
	tgTick(t)
	if strings.Join(f.actions, ",") != "restart-gre" {
		t.Fatalf("/api POST after the confirm: %v", f.actions)
	}
	for _, q := range []string{"/api POST /api/term/enable {}", "/api POST /api/password {}", `/api POST /api/license {"key":"x"}`,
		"/api POST /api/update/kind {}", "/api GET /api/access", "/api GET /api/../api/term/status"} {
		f.push(tgMsg(4, 42, "private", q))
		tgTick(t)
		if !strings.Contains(f.texts()[strings.LastIndex(strings.TrimSuffix(f.texts(), "\n---\n"), "---"):], "not available") {
			t.Fatalf("%s must be refused: %s", q, f.texts())
		}
	}
}

// The in-process key is the only way past the login: a network request
// without a session is still refused.
func TestTGBotBypassIsInProcessOnly(t *testing.T) {
	newTGHarness(t, true)
	rr := httptest.NewRecorder()
	nodeRelayMux().ServeHTTP(rr, httptest.NewRequest("POST", "/x/api/action", strings.NewReader(`{"action":"ping"}`)))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("no session: %d", rr.Code)
	}
}

func TestTGBotLicenseAndOff(t *testing.T) {
	f := newTGHarness(t, false)
	if d := tgTick(t); d != 30*time.Second || len(f.calls) != 0 {
		t.Fatalf("unlicensed: wait %v, calls %v", d, f.calls)
	}
	if tgBotView()["state"] != "locked" {
		t.Fatalf("state %v", tgBotView()["state"])
	}
	apLicense(t, true)
	_, _ = updateTGBotConfig(func(c *tgBotConfig) error { c.Enabled = false; return nil })
	if d := tgTick(t); d != 10*time.Second || len(f.calls) != 0 {
		t.Fatalf("off: wait %v, calls %v", d, f.calls)
	}
	// turning it on without the license is refused
	apLicense(t, false)
	rr := httptest.NewRecorder()
	handleTGBotPost(rr, httptest.NewRequest("POST", "/api/telegram-bot", strings.NewReader(`{"enabled":true}`)))
	if !strings.Contains(rr.Body.String(), "E-LIC-01") {
		t.Fatalf("enable without the license: %s", rr.Body.String())
	}
}

func TestTGBotErrorsAreClearAndRedacted(t *testing.T) {
	f := newTGHarness(t, true)
	f.status, f.desc = http.StatusConflict, "Conflict: terminated by other getUpdates request"
	if d := tgTick(t); d < 5*time.Second {
		t.Fatalf("backoff %v", d)
	}
	if e, _ := tgBotView()["error"].(string); !strings.Contains(e, "another program reads this bot") {
		t.Fatalf("409: %q", e)
	}
	f.status, f.desc = http.StatusBadRequest, "bad thing for bot"+tgTestToken
	err := tgCall(tgTestToken, "sendMessage", map[string]any{}, nil)
	if err == nil || strings.Contains(err.Error(), tgTestToken) || strings.Contains(err.Error(), "AAEtest") {
		t.Fatalf("the token must never show: %v", err)
	}
}

func TestTGBotLongTextGoesAsAFile(t *testing.T) {
	f := newTGHarness(t, true)
	tgShow(tgTestToken, 42, 0, tgScreen{Text: strings.Repeat("x", 5000)})
	if f.docs != 1 || len(f.sent) != 1 || len([]rune(f.sent[0]["text"].(string))) > tgMaxText {
		t.Fatalf("docs %d sent %d", f.docs, len(f.sent))
	}
}

func TestTGBotRenameAndRenew(t *testing.T) {
	f := newTGHarness(t, true)
	tgTick(t)
	// a question waits for the answer; /cancel drops it
	tgSetInput(42, "x", func(u *tgBotUser, text string) tgScreen { return tgScreen{Text: "got " + text} })
	f.push(tgMsg(1, 42, "private", "/cancel"), tgMsg(2, 42, "private", "hello"))
	tgTick(t)
	if strings.Contains(f.texts(), "got hello") {
		t.Fatal("/cancel did not drop the question")
	}
	tgSetInput(42, "x", func(u *tgBotUser, text string) tgScreen { return tgScreen{Text: "got " + text} })
	f.push(tgMsg(3, 42, "private", "hello"))
	tgTick(t)
	if !strings.Contains(f.texts(), "got hello") {
		t.Fatalf("the answer to a question: %s", f.texts())
	}
	if tgDigits("۳۰") != "30" || tgDigits("٧") != "7" {
		t.Fatal("Persian digits")
	}
}

func TestTGTokenShape(t *testing.T) {
	newTGHarness(t, true)
	if !tgTokenShape(tgTestToken) || tgTokenShape("hello") || tgTokenShape("12:short") || tgTokenShape("abc:AAEtesttokentesttokentesttoken") {
		t.Fatal("token shape")
	}
	var buf bytes.Buffer
	_ = json.NewEncoder(&buf).Encode(tgBotView())
	if strings.Contains(buf.String(), tgTestToken) {
		t.Fatal("the view shows the token")
	}
}

// Every menu renders for both roles (the test panel answers 404 for most of
// the API, so the error screens render too), and every button fits
// Telegram's 64-byte callback_data.
func TestTGBotEveryMenuRenders(t *testing.T) {
	newTGHarness(t, true)
	c := loadTGBotConfig()
	for _, id := range []int64{42, 43} {
		usr := c.user(id)
		for _, d := range []string{"m", "st", "tl", "t:0", "t:3", "t:99", "tr:3", "tn:3", "tx:3", "wd", "wd:rst", "bk", "bks:0", "ap", "al",
			"cu", "c:1", "cw:1", "dr", "dr:fix", "to", "to:opt", "to:adv", "lg", "er", "up", "up:go", "up:os", "up:osgo", "cl", "li", "h", "zz"} {
			s := tgOnButton(c, usr, id, d)
			if strings.TrimSpace(s.Text) == "" {
				t.Errorf("%s (%d): empty screen", d, id)
			}
			for _, row := range s.Keys {
				for _, b := range row {
					if len(tgTag()+b.Data) > 64 || (b.Data == "" && b.URL == "") {
						t.Errorf("%s (%d): button %q data %q", d, id, b.Text, b.Data)
					}
				}
			}
		}
		for _, cmd := range []string{"/start", "/menu", "/help", "/id", "/api", "/nope", "/status@hashem_test_bot"} {
			if s := tgOnText(c, usr, id, cmd); strings.TrimSpace(s.Text) == "" {
				t.Errorf("%s: empty", cmd)
			}
		}
	}
	if n := len(tgCommandList(c)); n == 0 || n > 100 {
		t.Fatal("commands")
	}
}

// Renew asks how many days (Persian digits work), then offers two choices;
// one renewal runs, and the other choice dies with it.
func TestTGBotRenewCustomer(t *testing.T) {
	f := newTGHarness(t, true)
	tgTick(t)
	f.push(tgPress(1, 42, "cw:1"))
	tgTick(t)
	f.push(tgMsg(2, 42, "private", "۳۰"))
	tgTick(t)
	only, both := f.button(t, "Renew only"), f.button(t, "reset usage")
	f.push(tgPress(3, 42, only), tgPress(4, 42, both))
	tgTick(t)
	if strings.Join(f.actions, ",") != "renew days=30 reset=false" {
		t.Fatalf("renew: %v", f.actions)
	}
}

// A viewer reads the curated menus only: /api and whole-answer dumps can
// hold tunnel tokens and keys.
func TestTGBotViewerGetsNoRawAnswers(t *testing.T) {
	f := newTGHarness(t, true)
	tgTick(t)
	f.push(tgMsg(1, 43, "private", "/api GET /api/peer/config"), tgPress(2, 43, "cl"), tgPress(3, 43, "to:adv"))
	tgTick(t)
	if n := strings.Count(f.texts(), "dmin"); n != 3 {
		t.Fatalf("a viewer must be refused 3 times: %s", f.texts())
	}
	for _, row := range tgTools(loadTGBotConfig(), loadTGBotConfig().user(43), "").Keys {
		for _, b := range row {
			if strings.HasPrefix(b.Data, "to:") {
				t.Fatalf("a viewer sees %q", b.Data)
			}
		}
	}
}

// Two servers on one bot token: a button from the other server's message
// (another tag) does nothing here.
func TestTGBotButtonsBelongToTheirServer(t *testing.T) {
	f := newTGHarness(t, true)
	tgTick(t)
	f.push(tgPress(1, 42, "raw:ffff|tp:0"), tgPress(2, 42, "raw:tp:0"))
	tgTick(t)
	if len(f.actions) != 0 {
		t.Fatalf("another server's button ran here: %v", f.actions)
	}
	f.push(tgPress(3, 42, "tp:0"))
	tgTick(t)
	if strings.Join(f.actions, ",") != "ping" {
		t.Fatalf("this server's button: %v", f.actions)
	}
	if tgSlow("tp:0") != true || tgSlow("m") {
		t.Fatal("slow buttons")
	}
}
