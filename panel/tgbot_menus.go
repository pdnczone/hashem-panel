package main

// The Telegram bot's menus (tgbot.go has the poller, pairing and safety).
// Reading uses this process's own state (the snapshot) or the panel's GET
// handlers; every change goes through the panel's API handlers (tgAPI).

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

func tgCommandList(c tgBotConfig) []map[string]string {
	cmd := func(name, fa, en string) map[string]string {
		return map[string]string{"command": name, "description": tgT(c, fa, en)}
	}
	return []map[string]string{
		cmd("menu", "منوی اصلی", "Main menu"),
		cmd("status", "وضعیت تونل‌ها", "Tunnel status"),
		cmd("tunnels", "تونل‌ها و کارهایشان", "Tunnels and their actions"),
		cmd("watchdog", "نگهبان", "Watchdog"),
		cmd("autopilot", "Autopilot", "Autopilot"),
		cmd("customers", "مشتری‌ها", "Customers"),
		cmd("doctor", "عیب‌یابی", "Doctor"),
		cmd("errors", "خطاهای اخیر", "Recent errors"),
		cmd("logs", "لاگ سرویس‌ها (فایل)", "Service logs (file)"),
		cmd("update", "نسخه و آپدیت", "Version and update"),
		cmd("api", "هر درخواست دیگر به API پنل", "Any other panel API request"),
		cmd("cancel", "لغو پرسش در انتظار", "Cancel a pending question"),
		cmd("help", "راهنما و محدودیت‌ها", "Help and limits"),
	}
}

func tgHost() string {
	h, _ := os.Hostname()
	if h == "" {
		h = "server"
	}
	return h
}

func tgBack(c tgBotConfig, to string) []tgBtn {
	row := []tgBtn{{Text: tgT(c, "🏠 منو", "🏠 Menu"), Data: "m"}}
	if to != "" && to != "m" {
		row = append([]tgBtn{{Text: tgT(c, "◀️ برگشت", "◀️ Back"), Data: to}}, row...)
	}
	return row
}

// tgConfirm asks once more before run, with a one-time button.
func tgConfirm(c tgBotConfig, usr *tgBotUser, question, label string, run func(u *tgBotUser) string) tgScreen {
	if !usr.admin() {
		return tgScreen{Text: tgT(c, "⛔ فقط ادمین می‌تواند این کار را بکند.", "⛔ Only an admin can do this."), Keys: [][]tgBtn{tgBack(c, "m")}}
	}
	n := tgAddPending(usr.ID, label, run)
	return tgScreen{Text: "⚠️ " + question + tgT(c, "\n\n(این دکمه ۲ دقیقه اعتبار دارد)", "\n\n(this button lasts 2 minutes)"),
		Keys: [][]tgBtn{{{Text: tgT(c, "✅ بله، انجام بده", "✅ Yes, do it"), Data: "ok:" + n}, {Text: tgT(c, "✖️ نه", "✖️ No"), Data: "no:" + n}}}}
}

func tgErrScreen(c tgBotConfig, back string, err error) tgScreen {
	return tgScreen{Text: "❌ " + err.Error(), Keys: [][]tgBtn{tgBack(c, back)}}
}

func tgStateIcon(state string) string {
	switch state {
	case stateHealthy:
		return "🟢"
	case stateDegraded:
		return "🟡"
	case stateDown:
		return "🔴"
	}
	return "⚪️"
}

func tgLinkName(l peerLive) string {
	n := strings.TrimSpace(l.Name)
	if n == "" {
		n = fmt.Sprintf("peer-%d", l.ID)
	}
	if l.RemotePub != "" && !strings.Contains(n, l.RemotePub) {
		n += " (" + l.RemotePub + ")"
	}
	return n
}

func tgLinks() (*HubSnapshot, []peerLive) {
	s := currentSnapshot()
	return s, apLinks(s)
}

func tgFindLink(id int) (*HubSnapshot, *peerLive) {
	s, links := tgLinks()
	for i := range links {
		if links[i].ID == id {
			return s, &links[i]
		}
	}
	return s, nil
}

// ---- entry points ----

// tgOnText answers a message from a paired account.
func tgOnText(c tgBotConfig, usr *tgBotUser, chat int64, text string) tgScreen {
	cmd, rest, _ := strings.Cut(text, " ")
	cmd = strings.ToLower(cmd)
	if i := strings.Index(cmd, "@"); i > 0 { // /status@my_bot
		cmd = cmd[:i]
	}
	if cmd == "/cancel" {
		tgTakeInput(usr.ID)
		s := tgMenu(c, usr)
		s.Text = tgT(c, "لغو شد.\n\n", "Cancelled.\n\n") + s.Text
		return s
	}
	if !strings.HasPrefix(text, "/") {
		if in, ok := tgTakeInput(usr.ID); ok {
			return in.run(usr, text)
		}
	}
	switch cmd {
	case "/start", "/menu":
		return tgMenu(c, usr)
	case "/status":
		return tgOnButton(c, usr, chat, "st")
	case "/tunnels":
		return tgOnButton(c, usr, chat, "tl")
	case "/watchdog":
		return tgOnButton(c, usr, chat, "wd")
	case "/autopilot":
		return tgOnButton(c, usr, chat, "ap")
	case "/customers":
		return tgOnButton(c, usr, chat, "cu")
	case "/doctor":
		return tgOnButton(c, usr, chat, "dr")
	case "/errors":
		return tgOnButton(c, usr, chat, "er")
	case "/logs":
		return tgOnButton(c, usr, chat, "lg")
	case "/update":
		return tgOnButton(c, usr, chat, "up")
	case "/help":
		return tgOnButton(c, usr, chat, "h")
	case "/id":
		return tgScreen{Text: fmt.Sprintf("%d · %s · %s", usr.ID, usr.Name, usr.Role)}
	case "/api":
		return tgRawAPI(c, usr, strings.TrimSpace(rest))
	}
	s := tgMenu(c, usr)
	s.Text = tgT(c, "دستور را نشناختم. از منو انتخاب کنید یا /help را بزنید.\n\n", "Unknown command. Pick from the menu or send /help.\n\n") + s.Text
	return s
}

func tgMenu(c tgBotConfig, usr *tgBotUser) tgScreen {
	s, links := tgLinks()
	up, bad, down := 0, 0, 0
	for _, l := range links {
		switch l.HealthState {
		case stateHealthy:
			up++
		case stateDown:
			down++
		default:
			bad++
		}
	}
	role := s.Local.Role
	if role == "" {
		role = "—"
	}
	text := fmt.Sprintf("🖥 Hashem · %s\n%s · %s\n", tgHost(), role, displayVersion(panelVersion))
	if len(links) == 0 {
		text += tgT(c, "هنوز تونلی نیست.", "No tunnels yet.")
	} else {
		text += fmt.Sprintf(tgT(c, "تونل‌ها: %d  ·  🟢 %d  🟡 %d  🔴 %d", "Tunnels: %d  ·  🟢 %d  🟡 %d  🔴 %d"), len(links), up, bad, down)
	}
	if !usr.admin() {
		text += tgT(c, "\n(دسترسی شما فقط دیدن است)", "\n(your access is read-only)")
	}
	b := func(fa, en, data string) tgBtn { return tgBtn{Text: tgT(c, fa, en), Data: data} }
	return tgScreen{Text: text, Keys: [][]tgBtn{
		{b("📊 وضعیت", "📊 Status", "st"), b("🔗 تونل‌ها", "🔗 Tunnels", "tl")},
		{b("🐶 نگهبان", "🐶 Watchdog", "wd"), b("🤖 Autopilot", "🤖 Autopilot", "ap")},
		{b("👥 مشتری‌ها", "👥 Customers", "cu"), b("🔔 هشدارها", "🔔 Alerts", "al")},
		{b("🩺 عیب‌یابی", "🩺 Doctor", "dr"), b("🛠 ابزارها", "🛠 Tools", "to")},
		{b("💾 نسخه پشتیبان", "💾 Backups", "bk"), b("⬆️ آپدیت", "⬆️ Update", "up")},
		{b("🌐 کلاستر", "🌐 Cluster", "cl"), b("🔑 لایسنس", "🔑 License", "li")},
		{b("📜 لاگ", "📜 Logs", "lg"), b("❗️ خطاها", "❗️ Errors", "er"), b("❓ راهنما", "❓ Help", "h")},
	}}
}

// tgOnButton answers a button (or the command that stands for one).
func tgOnButton(c tgBotConfig, usr *tgBotUser, chat int64, data string) tgScreen {
	key, arg, _ := strings.Cut(data, ":")
	id, _ := strconv.Atoi(arg)
	switch key {
	case "m":
		return tgMenu(c, usr)
	case "st":
		return tgStatus(c)
	case "tl":
		return tgTunnels(c)
	case "t":
		return tgTunnel(c, usr, id)
	case "tr", "tg", "tp", "tn", "tx":
		return tgTunnelAction(c, usr, key, id)
	case "wd":
		return tgWatchdog(c, usr, arg)
	case "bk", "bks", "bkr":
		return tgBackups(c, usr, key, id, arg)
	case "ap":
		return tgAutopilot(c, usr, arg)
	case "al":
		return tgAlerts(c, usr, arg)
	case "cu":
		return tgCustomers(c, usr)
	case "c", "cc", "cr", "cz", "cw", "cx":
		return tgCustomer(c, usr, key, id)
	case "dr":
		return tgDoctor(c, usr, arg)
	case "to":
		return tgTools(c, usr, arg)
	case "lg":
		return tgLogs(c, usr)
	case "er":
		return tgErrors(c, usr)
	case "up":
		return tgUpdateMenu(c, usr, chat, arg)
	case "cl":
		return tgGeneric(c, usr, "🌐 Cluster", "/api/cluster/status")
	case "li":
		return tgLicense(c, usr)
	case "h":
		return tgHelp(c)
	}
	return tgMenu(c, usr)
}

// ---- status and tunnels ----

func tgStatus(c tgBotConfig) tgScreen {
	s, links := tgLinks()
	var b strings.Builder
	fmt.Fprintf(&b, "📊 %s · %s\n", tgHost(), s.Local.Role)
	if s.PublicIP != "" {
		fmt.Fprintf(&b, "IP: %s\n", s.PublicIP)
	}
	if !s.At.IsZero() {
		fmt.Fprintf(&b, tgT(c, "به‌روز: %s\n", "As of: %s\n"), s.At.Local().Format("15:04:05"))
	}
	b.WriteString("\n")
	if len(links) == 0 {
		b.WriteString(tgT(c, "هنوز تونلی نیست.", "No tunnels yet."))
	}
	for _, l := range links {
		fmt.Fprintf(&b, "%s %s", tgStateIcon(l.HealthState), tgLinkName(l))
		if l.LatencyMs > 0 {
			fmt.Fprintf(&b, " · %.0f ms", l.LatencyMs)
		}
		if l.Rx != nil && l.Tx != nil {
			fmt.Fprintf(&b, " · ↓%s ↑%s", fmtBytesDec(*l.Rx), fmtBytesDec(*l.Tx))
		}
		b.WriteString("\n")
		if l.HealthState != stateHealthy && len(l.Reasons) > 0 {
			fmt.Fprintf(&b, "   ↳ %s\n", strings.Join(l.Reasons, "; "))
		}
	}
	return tgScreen{Text: b.String(), Keys: [][]tgBtn{{{Text: tgT(c, "🔄 تازه کن", "🔄 Refresh"), Data: "st"}, {Text: tgT(c, "🔗 تونل‌ها", "🔗 Tunnels"), Data: "tl"}}, tgBack(c, "m")}}
}

func tgTunnels(c tgBotConfig) tgScreen {
	_, links := tgLinks()
	var keys [][]tgBtn
	for _, l := range links {
		keys = append(keys, []tgBtn{{Text: tgStateIcon(l.HealthState) + " " + tgCut(tgLinkName(l), 50), Data: "t:" + strconv.Itoa(l.ID)}})
	}
	keys = append(keys, tgBack(c, "m"))
	text := tgT(c, "🔗 یک تونل را انتخاب کنید:", "🔗 Pick a tunnel:")
	if len(links) == 0 {
		text = tgT(c, "هنوز تونلی نیست. ساختن تونل از ربات ممکن نیست: از پنل بسازید.", "No tunnels yet. Tunnels are created in the panel, not from the bot.")
	}
	return tgScreen{Text: text, Keys: keys}
}

func tgTunnel(c tgBotConfig, usr *tgBotUser, id int) tgScreen {
	_, l := tgFindLink(id)
	if l == nil {
		return tgScreen{Text: tgT(c, "این تونل دیگر نیست.", "This tunnel is gone."), Keys: [][]tgBtn{tgBack(c, "tl")}}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s\n", tgStateIcon(l.HealthState), tgLinkName(*l))
	if l.ID == mainTunnelID {
		b.WriteString(tgT(c, "تونل اول این سرور\n", "This server's first tunnel\n"))
	} else {
		fmt.Fprintf(&b, "ID: %d\n", l.ID)
	}
	eng := l.Engine
	if eng == "" {
		eng = "frp"
	}
	if l.Transport != "" {
		eng += " / " + l.Transport
	}
	fmt.Fprintf(&b, tgT(c, "موتور: %s\n", "Engine: %s\n"), eng)
	if l.FrpPort > 0 {
		fmt.Fprintf(&b, tgT(c, "پورت کنترل: %d\n", "Control port: %d\n"), l.FrpPort)
	}
	if len(l.Ports) > 0 {
		ps := make([]string, 0, len(l.Ports))
		for _, p := range l.Ports {
			ps = append(ps, strconv.Itoa(p))
		}
		fmt.Fprintf(&b, tgT(c, "پورت‌ها: %s\n", "Ports: %s\n"), tgCut(strings.Join(ps, ", "), 300))
	}
	yes := func(v bool) string {
		if v {
			return "✅"
		}
		return "❌"
	}
	fmt.Fprintf(&b, tgT(c, "سرویس %s · GRE %s · سشن %s · پینگ %s\n", "Relay %s · GRE %s · session %s · ping %s\n"), yes(l.FrpUp), yes(l.GreUp || l.NoGre), yes(l.Linked), yes(l.PingOK))
	if l.LatencyMs > 0 {
		fmt.Fprintf(&b, tgT(c, "تأخیر: %.1f ms\n", "Latency: %.1f ms\n"), l.LatencyMs)
	}
	if l.Rx != nil && l.Tx != nil {
		fmt.Fprintf(&b, tgT(c, "ترافیک: ↓%s ↑%s\n", "Traffic: ↓%s ↑%s\n"), fmtBytesDec(*l.Rx), fmtBytesDec(*l.Tx))
	}
	if len(l.Reasons) > 0 {
		fmt.Fprintf(&b, "↳ %s\n", strings.Join(l.Reasons, "; "))
	}
	sid := strconv.Itoa(id)
	keys := [][]tgBtn{}
	if usr.admin() {
		row := []tgBtn{{Text: tgT(c, "🔁 ری‌استارت تونل", "🔁 Restart relay"), Data: "tr:" + sid}}
		if !l.NoGre {
			row = append(row, tgBtn{Text: tgT(c, "🔁 ری‌استارت GRE", "🔁 Restart GRE"), Data: "tg:" + sid})
		}
		keys = append(keys, row)
		row = []tgBtn{{Text: tgT(c, "📶 پینگ", "📶 Ping"), Data: "tp:" + sid}}
		if id != mainTunnelID {
			row = append(row, tgBtn{Text: tgT(c, "✏️ تغییر نام", "✏️ Rename"), Data: "tn:" + sid})
		}
		keys = append(keys, row, []tgBtn{{Text: tgT(c, "🗑 حذف تونل", "🗑 Remove tunnel"), Data: "tx:" + sid}})
	}
	keys = append(keys, []tgBtn{{Text: tgT(c, "🔄 تازه کن", "🔄 Refresh"), Data: "t:" + sid}}, tgBack(c, "tl"))
	return tgScreen{Text: b.String(), Keys: keys}
}

// tgActionBody is /api/action's body for a tunnel (the first tunnel has no peer_id).
func tgActionBody(action string, id int) map[string]any {
	b := map[string]any{"action": action}
	if id != mainTunnelID {
		b["peer_id"] = id
	}
	return b
}

func tgRunAction(c tgBotConfig, usr *tgBotUser, action string, id int) string {
	var out struct {
		Output string `json:"output"`
	}
	if err := tgAPIJSON(usr, http.MethodPost, "/api/action", tgActionBody(action, id), &out); err != nil {
		return "❌ " + err.Error()
	}
	msg := "✅ " + tgT(c, "انجام شد", "Done")
	if o := strings.TrimSpace(out.Output); o != "" {
		msg += "\n\n" + tgCut(o, 3000)
	}
	return msg
}

func tgTunnelAction(c tgBotConfig, usr *tgBotUser, key string, id int) tgScreen {
	_, l := tgFindLink(id)
	if l == nil {
		return tgScreen{Text: tgT(c, "این تونل دیگر نیست.", "This tunnel is gone."), Keys: [][]tgBtn{tgBack(c, "tl")}}
	}
	if !usr.admin() {
		return tgScreen{Text: tgT(c, "⛔ فقط ادمین.", "⛔ Admins only."), Keys: [][]tgBtn{tgBack(c, "t:"+strconv.Itoa(id))}}
	}
	name, back := tgLinkName(*l), [][]tgBtn{tgBack(c, "t:"+strconv.Itoa(id))}
	switch key {
	case "tr":
		return tgScreen{Text: tgRunAction(c, usr, "restart-engine", id), Keys: back}
	case "tg":
		return tgScreen{Text: tgRunAction(c, usr, "restart-gre", id), Keys: back}
	case "tp":
		return tgScreen{Text: tgRunAction(c, usr, "ping", id), Keys: back}
	case "tn":
		tgSetInput(usr.ID, "rename", func(u *tgBotUser, text string) tgScreen {
			text = strings.TrimSpace(text)
			if text == "" || len([]rune(text)) > 64 {
				return tgScreen{Text: tgT(c, "❌ نام باید ۱ تا ۶۴ نویسه باشد.", "❌ A name is 1 to 64 characters."), Keys: back}
			}
			if err := tgAPIJSON(u, http.MethodPatch, "/api/peers", map[string]any{"id": id, "name": text}, nil); err != nil {
				return tgScreen{Text: "❌ " + err.Error(), Keys: back}
			}
			return tgScreen{Text: "✅ " + tgT(c, "نام جدید: ", "New name: ") + text, Keys: back}
		})
		return tgScreen{Text: tgT(c, "✏️ نام تازه‌ی «", "✏️ Send the new name for \"") + name + tgT(c, "» را بفرستید (یا /cancel).", "\" (or /cancel).")}
	case "tx":
		return tgConfirm(c, usr, tgT(c, "تونل «", "Remove the tunnel \"")+name+tgT(c, "» حذف شود؟ سرویس‌ها و تنظیماتش پاک می‌شوند و کاربرانش قطع می‌شوند.", "\"? Its services and settings are deleted and its users are cut off."),
			tgT(c, "در حال حذف تونل…", "Removing the tunnel…"), func(u *tgBotUser) string { return tgRunAction(c, u, "remove-tunnel", id) })
	}
	return tgTunnel(c, usr, id)
}

// ---- watchdog and backups ----

type tgWDView struct {
	Enabled        bool         `json:"enabled"`
	Status         string       `json:"status"`
	CheckResult    string       `json:"check_result"`
	LastCheck      string       `json:"last_check"`
	AutoRestart    bool         `json:"auto_restart"`
	TGChatID       string       `json:"tg_chat_id"`
	WatchedByPanel bool         `json:"watched_by_panel"`
	Links          []wdLink     `json:"links"`
	Backups        []backupItem `json:"backups"`
	ScheduleHuman  string       `json:"schedule_human"`
}

func tgWatchdog(c tgBotConfig, usr *tgBotUser, arg string) tgScreen {
	post := func(body map[string]any) string {
		if err := tgAPIJSON(usr, http.MethodPost, "/api/watchdog", body, nil); err != nil {
			return "❌ " + err.Error()
		}
		return ""
	}
	note := ""
	switch arg {
	case "on", "off":
		note = post(map[string]any{"action": arg})
	case "ar1", "ar0":
		note = post(map[string]any{"action": "set-autorestart", "auto_restart": arg == "ar1"})
	case "test":
		if note = post(map[string]any{"action": "test"}); note == "" {
			note = "✅ " + tgT(c, "پیام آزمایشی فرستاده شد.", "Test message sent.")
		}
	case "bkn":
		if note = post(map[string]any{"action": "backup-now"}); note == "" {
			note = "✅ " + tgT(c, "نسخه پشتیبان گرفته شد.", "Backup made.")
		}
	case "rst":
		return tgConfirm(c, usr, tgT(c, "همه‌ی تونل‌ها الان ری‌استارت شوند؟ چند ثانیه همه‌ی کاربران قطع می‌شوند.", "Restart every tunnel now? All users are cut off for a few seconds."),
			tgT(c, "ری‌استارت تونل‌ها…", "Restarting the tunnels…"), func(u *tgBotUser) string {
				if err := tgAPIJSON(u, http.MethodPost, "/api/watchdog", map[string]any{"action": "restart-tunnel-now"}, nil); err != nil {
					return "❌ " + err.Error()
				}
				return "✅ " + tgT(c, "تونل‌ها ری‌استارت شدند.", "The tunnels were restarted.")
			})
	}
	var v tgWDView
	if err := tgAPIJSON(usr, http.MethodGet, "/api/watchdog", nil, &v); err != nil {
		return tgErrScreen(c, "m", err)
	}
	onoff := func(b bool) string {
		if b {
			return tgT(c, "روشن", "on")
		}
		return tgT(c, "خاموش", "off")
	}
	var b strings.Builder
	if note != "" {
		b.WriteString(note + "\n\n")
	}
	fmt.Fprintf(&b, tgT(c, "🐶 نگهبان: %s · ری‌استارت خودکار: %s\n", "🐶 Watchdog: %s · auto-restart: %s\n"), onoff(v.Enabled), onoff(v.AutoRestart))
	if v.TGChatID == "" {
		b.WriteString(tgT(c, "⚠️ چت هشدار تلگرام تنظیم نشده (تب نگهبان پنل).\n", "⚠️ No Telegram alert chat is set (the panel's Watchdog tab).\n"))
	}
	if v.CheckResult != "" {
		fmt.Fprintf(&b, tgT(c, "آخرین بررسی: %s %s\n", "Last check: %s %s\n"), v.LastCheck, tgCut(v.CheckResult, 300))
	}
	for _, l := range v.Links {
		icon := map[string]string{"up": "🟢", "down": "🔴"}[l.State]
		if icon == "" {
			icon = "⚪️"
		}
		fmt.Fprintf(&b, "%s %s", icon, l.Name)
		if l.Restarts > 0 {
			fmt.Fprintf(&b, tgT(c, " · %d ری‌استارت", " · %d restarts"), l.Restarts)
		}
		if l.Why != "" && l.State != "up" {
			fmt.Fprintf(&b, " · %s", tgCut(l.Why, 120))
		}
		b.WriteString("\n")
	}
	keys := [][]tgBtn{}
	if usr.admin() {
		tog := tgBtn{Text: tgT(c, "▶️ روشن کن", "▶️ Turn on"), Data: "wd:on"}
		if v.Enabled {
			tog = tgBtn{Text: tgT(c, "⏸ خاموش کن", "⏸ Turn off"), Data: "wd:off"}
		}
		ar := tgBtn{Text: tgT(c, "ری‌استارت خودکار: روشن", "Auto-restart: on"), Data: "wd:ar1"}
		if v.AutoRestart {
			ar = tgBtn{Text: tgT(c, "ری‌استارت خودکار: خاموش", "Auto-restart: off"), Data: "wd:ar0"}
		}
		keys = append(keys, []tgBtn{tog, ar},
			[]tgBtn{{Text: tgT(c, "📨 پیام آزمایشی", "📨 Test message"), Data: "wd:test"}, {Text: tgT(c, "🔁 ری‌استارت همه", "🔁 Restart all"), Data: "wd:rst"}},
			[]tgBtn{{Text: tgT(c, "💾 الان نسخه پشتیبان بگیر", "💾 Back up now"), Data: "wd:bkn"}, {Text: tgT(c, "📦 نسخه‌های پشتیبان", "📦 Backups"), Data: "bk"}})
	}
	keys = append(keys, []tgBtn{{Text: tgT(c, "🔄 تازه کن", "🔄 Refresh"), Data: "wd"}}, tgBack(c, "m"))
	return tgScreen{Text: b.String(), Keys: keys}
}

func tgBackups(c tgBotConfig, usr *tgBotUser, key string, idx int, arg string) tgScreen {
	var v tgWDView
	if err := tgAPIJSON(usr, http.MethodGet, "/api/watchdog", nil, &v); err != nil {
		return tgErrScreen(c, "m", err)
	}
	list := append([]backupItem(nil), v.Backups...)
	sort.Slice(list, func(i, j int) bool { return list[i].Name > list[j].Name })
	if len(list) > 10 {
		list = list[:10]
	}
	back := [][]tgBtn{tgBack(c, "bk")}
	if key != "bk" {
		if arg == "" || idx < 0 || idx >= len(list) {
			return tgScreen{Text: tgT(c, "این نسخه پشتیبان دیگر نیست.", "This backup is gone."), Keys: back}
		}
		f := list[idx].Name
		if key == "bks" {
			if !usr.admin() {
				return tgScreen{Text: tgT(c, "⛔ فقط ادمین.", "⛔ Admins only."), Keys: back}
			}
			code, data, err := tgAPI(usr, http.MethodGet, "/api/watchdog/backup-download?f="+url.QueryEscape(f), nil)
			if err == nil && code >= 300 {
				err = fmt.Errorf("%s", tgAPIErrText(code, data))
			}
			if err != nil {
				return tgErrScreen(c, "bk", err)
			}
			return tgScreen{Text: "💾 " + f + tgT(c, "\n(رمزنگاری‌شده؛ با رمز نسخه پشتیبان باز می‌شود)", "\n(encrypted: it opens with the backup password)"), Doc: data, DocName: f, Keys: back}
		}
		return tgConfirm(c, usr, tgT(c, "تنظیمات از نسخه پشتیبان «", "Restore the settings from \"")+f+tgT(c, "» برگردانده شود؟ تنظیمات فعلی با آن جایگزین می‌شوند.", "\"? The current settings are replaced with it."),
			tgT(c, "برگرداندن نسخه پشتیبان…", "Restoring…"), func(u *tgBotUser) string {
				var res struct {
					Detail string `json:"detail"`
				}
				if err := tgAPIJSON(u, http.MethodPost, "/api/watchdog", map[string]any{"action": "restore", "file": f}, &res); err != nil {
					return "❌ " + err.Error()
				}
				return "✅ " + tgT(c, "برگردانده شد.", "Restored.") + "\n\n" + tgCut(strings.TrimSpace(res.Detail), 3000)
			})
	}
	if len(list) == 0 {
		return tgScreen{Text: tgT(c, "هنوز نسخه پشتیبانی نیست.", "No backups yet."), Keys: [][]tgBtn{tgBack(c, "wd")}}
	}
	var b strings.Builder
	b.WriteString(tgT(c, "📦 نسخه‌های پشتیبان (جدیدترین اول):\n", "📦 Backups (newest first):\n"))
	keys := [][]tgBtn{}
	for i, it := range list {
		fmt.Fprintf(&b, "%d. %s · %s\n", i+1, it.Time, fmtBytesDec(uint64(max(it.Size, 0))))
		if usr.admin() {
			keys = append(keys, []tgBtn{{Text: fmt.Sprintf("⬇️ %d", i+1), Data: "bks:" + strconv.Itoa(i)}, {Text: fmt.Sprintf(tgT(c, "♻️ برگرداندن %d", "♻️ Restore %d"), i+1), Data: "bkr:" + strconv.Itoa(i)}})
		}
	}
	keys = append(keys, tgBack(c, "wd"))
	return tgScreen{Text: b.String(), Keys: keys}
}

// ---- Autopilot and alerts ----

func tgAutopilot(c tgBotConfig, usr *tgBotUser, arg string) tgScreen {
	note := ""
	if arg == "on" || arg == "off" {
		if err := tgAPIJSON(usr, http.MethodPost, "/api/autopilot", map[string]any{"enabled": arg == "on"}, nil); err != nil {
			note = "❌ " + err.Error() + "\n\n"
		}
	}
	var v struct {
		Config struct {
			Enabled bool `json:"enabled"`
		} `json:"config"`
		Licensed bool `json:"licensed"`
		Tunnels  []struct {
			Name    string `json:"name"`
			State   string `json:"state"`
			Skipped bool   `json:"skipped"`
			CanSwap bool   `json:"can_swap"`
			Carrier string `json:"carrier"`
			Running bool   `json:"running"`
			Step    string `json:"step"`
			Waiting string `json:"waiting"`
		} `json:"tunnels"`
		Events []struct {
			At     string `json:"at"`
			Kind   string `json:"kind"`
			Tunnel string `json:"tunnel"`
			Detail string `json:"detail"`
		} `json:"events"`
		Switched int `json:"switched_day"`
		Failed   int `json:"failed_day"`
	}
	if err := tgAPIJSON(usr, http.MethodGet, "/api/autopilot", nil, &v); err != nil {
		return tgErrScreen(c, "m", err)
	}
	var b strings.Builder
	b.WriteString(note)
	st := tgT(c, "خاموش", "off")
	if v.Config.Enabled {
		st = tgT(c, "روشن", "on")
	}
	fmt.Fprintf(&b, tgT(c, "🤖 Autopilot: %s · ۲۴ ساعت: %d جابه‌جایی، %d ناموفق\n", "🤖 Autopilot: %s · 24 h: %d switches, %d failed\n"), st, v.Switched, v.Failed)
	b.WriteString(tgT(c, "وقتی مسیر تونلی بسته شود، خودش حامل را عوض می‌کند.\n\n", "When a tunnel's path is blocked it swaps the carrier by itself.\n\n"))
	for _, t := range v.Tunnels {
		fmt.Fprintf(&b, "%s %s · %s", tgStateIcon(t.State), t.Name, t.Carrier)
		switch {
		case t.Running:
			fmt.Fprintf(&b, " · ⏳ %s", t.Step)
		case t.Skipped:
			b.WriteString(tgT(c, " · کنار گذاشته", " · skipped"))
		case !t.CanSwap:
			b.WriteString(tgT(c, " · قابل جابه‌جایی نیست", " · cannot swap"))
		case t.Waiting != "":
			fmt.Fprintf(&b, " · %s", tgCut(t.Waiting, 100))
		}
		b.WriteString("\n")
	}
	for i, e := range v.Events {
		if i == 0 {
			b.WriteString(tgT(c, "\nرویدادهای اخیر:\n", "\nRecent events:\n"))
		}
		if i >= 5 {
			break
		}
		fmt.Fprintf(&b, "• %s %s %s %s\n", tgShortTime(e.At), e.Kind, e.Tunnel, tgCut(e.Detail, 120))
	}
	keys := [][]tgBtn{}
	if usr.admin() {
		if v.Config.Enabled {
			keys = append(keys, []tgBtn{{Text: tgT(c, "⏸ خاموش کن", "⏸ Turn off"), Data: "ap:off"}})
		} else {
			keys = append(keys, []tgBtn{{Text: tgT(c, "▶️ روشن کن", "▶️ Turn on"), Data: "ap:on"}})
		}
	}
	keys = append(keys, []tgBtn{{Text: tgT(c, "🔄 تازه کن", "🔄 Refresh"), Data: "ap"}}, tgBack(c, "m"))
	return tgScreen{Text: b.String(), Keys: keys}
}

func tgShortTime(rfc string) string {
	if t, err := time.Parse(time.RFC3339, rfc); err == nil {
		return t.Local().Format("01-02 15:04")
	}
	return rfc
}

func tgAlerts(c tgBotConfig, usr *tgBotUser, arg string) tgScreen {
	note := ""
	set := func(body map[string]any) {
		if err := tgAPIJSON(usr, http.MethodPost, "/api/alerts", body, nil); err != nil {
			note = "❌ " + err.Error() + "\n\n"
		}
	}
	switch arg {
	case "on", "off":
		set(map[string]any{"enabled": arg == "on"})
	case "tg1", "tg0":
		set(map[string]any{"telegram": arg == "tg1"})
	case "dg1", "dg0":
		set(map[string]any{"notify_degraded": arg == "dg1"})
	case "test":
		set(map[string]any{"action": "test"})
		if note == "" {
			note = "✅ " + tgT(c, "هشدار آزمایشی فرستاده شد.", "Test alert sent.") + "\n\n"
		}
	}
	var v struct {
		Enabled    bool   `json:"enabled"`
		Telegram   bool   `json:"telegram"`
		Degraded   bool   `json:"notify_degraded"`
		Webhook    string `json:"webhook_url"`
		Configured bool   `json:"telegram_configured"`
	}
	if err := tgAPIJSON(usr, http.MethodGet, "/api/alerts", nil, &v); err != nil {
		return tgErrScreen(c, "m", err)
	}
	yes := func(b bool) string {
		if b {
			return "✅"
		}
		return "❌"
	}
	text := note + fmt.Sprintf(tgT(c, "🔔 هشدارها %s\nتلگرام %s · وضعیت ضعیف هم %s\nوب‌هوک: %s", "🔔 Alerts %s\nTelegram %s · also degraded %s\nWebhook: %s"),
		yes(v.Enabled), yes(v.Telegram), yes(v.Degraded), map[bool]string{true: v.Webhook, false: "—"}[v.Webhook != ""])
	if !v.Configured {
		text += tgT(c, "\n⚠️ برای هشدار تلگرام، چت آن را در تب نگهبان پنل بگذارید.", "\n⚠️ For Telegram alerts set their chat in the panel's Watchdog tab.")
	}
	keys := [][]tgBtn{}
	if usr.admin() {
		flip := func(on bool, label, data1, data0 string) tgBtn {
			if on {
				return tgBtn{Text: "❌ " + label, Data: data0}
			}
			return tgBtn{Text: "✅ " + label, Data: data1}
		}
		keys = append(keys,
			[]tgBtn{flip(v.Enabled, tgT(c, "هشدارها", "Alerts"), "al:on", "al:off"), flip(v.Telegram, tgT(c, "تلگرام", "Telegram"), "al:tg1", "al:tg0")},
			[]tgBtn{flip(v.Degraded, tgT(c, "وضعیت ضعیف", "Degraded"), "al:dg1", "al:dg0"), {Text: tgT(c, "📨 آزمایش", "📨 Test"), Data: "al:test"}})
	}
	keys = append(keys, tgBack(c, "m"))
	return tgScreen{Text: text, Keys: keys}
}

// ---- customers ----

type tgCustView struct {
	ID        int     `json:"id"`
	Name      string  `json:"name"`
	Note      string  `json:"note"`
	Cut       string  `json:"cut"`
	ExpiresAt int64   `json:"expires_at"`
	QuotaGB   float64 `json:"quota_gb"`
	RateMbit  float64 `json:"rate_mbit"`
	UsedRx    uint64  `json:"used_rx"`
	UsedTx    uint64  `json:"used_tx"`
	DaysLeft  *int    `json:"days_left"`
	Days      int     `json:"days"`
	Links     []struct {
		Name   string `json:"name"`
		Engine string `json:"engine"`
		Active bool   `json:"active"`
		Linked bool   `json:"linked"`
	} `json:"links"`
}

func tgLoadCustomers(usr *tgBotUser) ([]tgCustView, error) {
	var v struct {
		Customers []tgCustView `json:"customers"`
	}
	err := tgAPIJSON(usr, http.MethodGet, "/api/customers", nil, &v)
	return v.Customers, err
}

func tgCustIcon(cu tgCustView) string {
	if cu.Cut != "" {
		return "⏸"
	}
	for _, l := range cu.Links {
		if !l.Active {
			return "🟡"
		}
	}
	return "🟢"
}

func tgCustomers(c tgBotConfig, usr *tgBotUser) tgScreen {
	list, err := tgLoadCustomers(usr)
	if err != nil {
		return tgErrScreen(c, "m", err)
	}
	if len(list) == 0 {
		return tgScreen{Text: tgT(c, "👥 هنوز مشتری‌ای نیست. ساختن مشتری فقط از پنل.", "👥 No customers yet. Customers are created in the panel."), Keys: [][]tgBtn{tgBack(c, "m")}}
	}
	keys := [][]tgBtn{}
	for _, cu := range list {
		label := tgCustIcon(cu) + " " + tgCut(cu.Name, 40)
		if cu.DaysLeft != nil {
			label += fmt.Sprintf(tgT(c, " · %d روز", " · %dd"), *cu.DaysLeft)
		}
		keys = append(keys, []tgBtn{{Text: label, Data: "c:" + strconv.Itoa(cu.ID)}})
		if len(keys) >= 60 {
			break
		}
	}
	keys = append(keys, tgBack(c, "m"))
	return tgScreen{Text: fmt.Sprintf(tgT(c, "👥 مشتری‌ها (%d):", "👥 Customers (%d):"), len(list)), Keys: keys}
}

func tgCustomer(c tgBotConfig, usr *tgBotUser, key string, id int) tgScreen {
	back := [][]tgBtn{tgBack(c, "c:"+strconv.Itoa(id))}
	act := func(u *tgBotUser, body map[string]any, done string) string {
		body["id"] = id
		if err := tgAPIJSON(u, http.MethodPost, "/api/customers", body, nil); err != nil {
			return "❌ " + err.Error()
		}
		return "✅ " + done
	}
	list, err := tgLoadCustomers(usr)
	if err != nil {
		return tgErrScreen(c, "cu", err)
	}
	var cu *tgCustView
	for i := range list {
		if list[i].ID == id {
			cu = &list[i]
		}
	}
	if cu == nil {
		return tgScreen{Text: tgT(c, "این مشتری دیگر نیست.", "This customer is gone."), Keys: [][]tgBtn{tgBack(c, "cu")}}
	}
	if key != "c" && !usr.admin() {
		return tgScreen{Text: tgT(c, "⛔ فقط ادمین.", "⛔ Admins only."), Keys: back}
	}
	switch key {
	case "cc":
		return tgConfirm(c, usr, tgT(c, "مشتری «", "Pause \"")+cu.Name+tgT(c, "» متوقف شود؟ تونل‌هایش می‌ایستند و کاربرانش قطع می‌شوند.", "\"? Their tunnels stop and their users are cut off."),
			tgT(c, "توقف…", "Pausing…"), func(u *tgBotUser) string {
				return act(u, map[string]any{"action": "cut"}, tgT(c, "متوقف شد.", "Paused."))
			})
	case "cr":
		return tgScreen{Text: act(usr, map[string]any{"action": "resume"}, tgT(c, "دوباره فعال شد.", "Resumed.")), Keys: back}
	case "cz":
		return tgConfirm(c, usr, tgT(c, "حجم مصرفی «", "Reset the used volume of \"")+cu.Name+tgT(c, "» صفر شود؟", "\" to 0?"),
			tgT(c, "صفر کردن…", "Resetting…"), func(u *tgBotUser) string {
				return act(u, map[string]any{"action": "reset"}, tgT(c, "مصرف صفر شد.", "Usage reset."))
			})
	case "cx":
		return tgConfirm(c, usr, tgT(c, "مشتری «", "Remove the customer \"")+cu.Name+tgT(c, "» برای همیشه حذف شود؟ تونل‌هایش پاک و پورت‌هایش آزاد می‌شوند. برگشت ندارد.", "\" for good? Their tunnels are deleted and their ports freed. This cannot be undone."),
			tgT(c, "حذف…", "Removing…"), func(u *tgBotUser) string {
				return act(u, map[string]any{"action": "remove"}, tgT(c, "مشتری حذف شد.", "Customer removed."))
			})
	case "cw":
		tgSetInput(usr.ID, "renew", func(u *tgBotUser, text string) tgScreen {
			days, err := strconv.Atoi(strings.TrimSpace(tgDigits(text)))
			if err != nil || days < 1 || days > 3650 {
				return tgScreen{Text: tgT(c, "❌ تعداد روز را به عدد بفرستید (۱ تا ۳۶۵۰).", "❌ Send the number of days (1 to 3650)."), Keys: back}
			}
			var n1, n2 string
			run := func(reset bool) func(u *tgBotUser) string {
				return func(u *tgBotUser) string {
					tgTakePending(n1, u.ID) // the other choice dies with this one: one renewal
					tgTakePending(n2, u.ID)
					return act(u, map[string]any{"action": "renew", "days": days, "reset_usage": reset}, fmt.Sprintf(tgT(c, "%d روز تمدید شد.", "Renewed for %d days."), days))
				}
			}
			n1 = tgAddPending(u.ID, tgT(c, "تمدید…", "Renewing…"), run(true))
			n2 = tgAddPending(u.ID, tgT(c, "تمدید…", "Renewing…"), run(false))
			return tgScreen{Text: fmt.Sprintf(tgT(c, "«%s» %d روز تمدید شود. مصرف هم صفر شود؟", "Renew \"%s\" for %d days. Reset the used volume too?"), cu.Name, days),
				Keys: [][]tgBtn{{{Text: tgT(c, "✅ تمدید + صفر کردن مصرف", "✅ Renew + reset usage"), Data: "ok:" + n1}}, {{Text: tgT(c, "✅ فقط تمدید", "✅ Renew only"), Data: "ok:" + n2}}, back[0]}}
		})
		return tgScreen{Text: fmt.Sprintf(tgT(c, "🗓 «%s» چند روز تمدید شود؟ عدد را بفرستید (یا /cancel).", "🗓 Renew \"%s\" for how many days? Send a number (or /cancel)."), cu.Name)}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s (#%d)\n", tgCustIcon(*cu), cu.Name, cu.ID)
	if cu.Note != "" {
		fmt.Fprintf(&b, "%s\n", tgCut(cu.Note, 200))
	}
	if cu.Cut != "" {
		why := map[string]string{"expired": tgT(c, "تمام شدن مدت", "expired"), "quota": tgT(c, "تمام شدن حجم", "volume used up"), "manual": tgT(c, "دستی", "by hand")}[cu.Cut]
		if why == "" {
			why = cu.Cut
		}
		fmt.Fprintf(&b, tgT(c, "⏸ متوقف: %s\n", "⏸ Paused: %s\n"), why)
	}
	used := fmtBytesDec(cu.UsedRx + cu.UsedTx)
	if cu.QuotaGB > 0 {
		fmt.Fprintf(&b, tgT(c, "مصرف: %s از %g GB\n", "Used: %s of %g GB\n"), used, cu.QuotaGB)
	} else {
		fmt.Fprintf(&b, tgT(c, "مصرف: %s (بی‌حد)\n", "Used: %s (no cap)\n"), used)
	}
	if cu.ExpiresAt > 0 {
		left := ""
		if cu.DaysLeft != nil {
			left = fmt.Sprintf(tgT(c, " (%d روز مانده)", " (%d days left)"), *cu.DaysLeft)
		}
		fmt.Fprintf(&b, tgT(c, "پایان: %s%s\n", "Ends: %s%s\n"), time.Unix(cu.ExpiresAt, 0).Local().Format("2006-01-02"), left)
	} else {
		b.WriteString(tgT(c, "بدون تاریخ پایان\n", "No end date\n"))
	}
	if cu.RateMbit > 0 {
		fmt.Fprintf(&b, tgT(c, "سرعت: %g Mbit/s\n", "Speed: %g Mbit/s\n"), cu.RateMbit)
	}
	for _, l := range cu.Links {
		icon := "🟢"
		if !l.Active {
			icon = "🔴"
		}
		fmt.Fprintf(&b, "%s %s %s\n", icon, l.Engine, l.Name)
	}
	sid := strconv.Itoa(id)
	keys := [][]tgBtn{}
	if usr.admin() {
		pause := tgBtn{Text: tgT(c, "⏸ توقف", "⏸ Pause"), Data: "cc:" + sid}
		if cu.Cut != "" {
			pause = tgBtn{Text: tgT(c, "▶️ فعال کن", "▶️ Resume"), Data: "cr:" + sid}
		}
		keys = append(keys, []tgBtn{pause, {Text: tgT(c, "🗓 تمدید", "🗓 Renew"), Data: "cw:" + sid}},
			[]tgBtn{{Text: tgT(c, "♻️ صفر کردن مصرف", "♻️ Reset usage"), Data: "cz:" + sid}, {Text: tgT(c, "🗑 حذف", "🗑 Remove"), Data: "cx:" + sid}})
	}
	keys = append(keys, []tgBtn{{Text: tgT(c, "🔄 تازه کن", "🔄 Refresh"), Data: "c:" + sid}}, tgBack(c, "cu"))
	return tgScreen{Text: b.String(), Keys: keys}
}

// tgDigits turns Persian and Arabic digits into ASCII ones.
func tgDigits(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= '۰' && r <= '۹':
			return '0' + (r - '۰')
		case r >= '٠' && r <= '٩':
			return '0' + (r - '٠')
		}
		return r
	}, s)
}

// ---- doctor, tools, logs and errors ----

func tgDoctor(c tgBotConfig, usr *tgBotUser, arg string) tgScreen {
	if arg == "fix" {
		return tgConfirm(c, usr, tgT(c, "تعمیر سریع اجرا شود؟ مشکلاتی که خودکار درست می‌شوند اصلاح و سرویس‌ها ری‌استارت می‌شوند.", "Run Quick Repair? What it can fix is fixed and services restart."),
			tgT(c, "تعمیر…", "Repairing…"), func(u *tgBotUser) string {
				var v struct {
					Report doctorReport `json:"report"`
				}
				if err := tgAPIJSON(u, http.MethodPost, "/api/doctor", map[string]any{"action": "fix"}, &v); err != nil {
					return "❌ " + err.Error()
				}
				return "✅ " + tgT(c, "تعمیر شد.\n\n", "Repaired.\n\n") + tgDoctorText(c, &v.Report)
			})
	}
	var rep doctorReport
	method, body := http.MethodGet, any(nil)
	if arg == "run" {
		method, body = http.MethodPost, map[string]any{"action": "run"}
	}
	if err := tgAPIJSON(usr, method, "/api/doctor", body, &rep); err != nil {
		return tgErrScreen(c, "m", err)
	}
	keys := [][]tgBtn{}
	if usr.admin() {
		row := []tgBtn{{Text: tgT(c, "▶️ اجرای تازه", "▶️ Run again"), Data: "dr:run"}}
		if rep.FixAvailable {
			row = append(row, tgBtn{Text: tgT(c, "🛠 تعمیر سریع", "🛠 Quick Repair"), Data: "dr:fix"})
		}
		keys = append(keys, row)
	}
	keys = append(keys, tgBack(c, "m"))
	return tgScreen{Text: tgDoctorText(c, &rep), Keys: keys}
}

func tgDoctorText(c tgBotConfig, r *doctorReport) string {
	if r == nil || r.Timestamp == "" {
		return tgT(c, "🩺 هنوز گزارشی نیست: «اجرای تازه» را بزنید.", "🩺 No report yet: press Run again.")
	}
	var b strings.Builder
	fmt.Fprintf(&b, tgT(c, "🩺 عیب‌یابی · امتیاز %d (%s)\n%s\n\n", "🩺 Doctor · score %d (%s)\n%s\n\n"), r.Score, r.Rating, r.Timestamp)
	for _, t := range r.Tunnels {
		fmt.Fprintf(&b, "• %s · %s %s\n", t.Name, t.Verdict, tgCut(t.Reason, 160))
	}
	icon := map[string]string{"critical": "🔴", "warning": "🟡", "minor": "⚪️"}
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "%s %s\n", icon[f.Severity], f.Title)
		if f.Fix != "" {
			fmt.Fprintf(&b, "   ↳ %s\n", f.Fix)
		}
	}
	if len(r.Findings) == 0 {
		b.WriteString(tgT(c, "✅ مشکلی پیدا نشد.\n", "✅ No problems found.\n"))
	}
	return b.String()
}

func tgTools(c tgBotConfig, usr *tgBotUser, arg string) tgScreen {
	back := [][]tgBtn{tgBack(c, "to")}
	action := func(u *tgBotUser, a string) string {
		var out struct {
			Output string `json:"output"`
		}
		if err := tgAPIJSON(u, http.MethodPost, "/api/action", map[string]any{"action": a}, &out); err != nil {
			return "❌ " + err.Error()
		}
		return "✅ " + tgCut(strings.TrimSpace(out.Output), 3500)
	}
	switch arg {
	case "opt":
		return tgConfirm(c, usr, tgT(c, "بهینه‌سازی شبکه (BBR، بافرها، MTU) اجرا شود؟", "Optimize the network (BBR, buffers, MTU)?"), tgT(c, "بهینه‌سازی…", "Optimizing…"),
			func(u *tgBotUser) string { return action(u, "optimize") })
	case "rst":
		return tgConfirm(c, usr, tgT(c, "تنظیمات شبکه به حالت قبل از بهینه‌سازی برگردد؟", "Put the network settings back as before Optimize?"), tgT(c, "برگرداندن…", "Restoring…"),
			func(u *tgBotUser) string { return action(u, "restore") })
	case "tune":
		if !usr.admin() {
			return tgScreen{Text: tgT(c, "⛔ فقط ادمین.", "⛔ Admins only."), Keys: back}
		}
		return tgScreen{Text: action(usr, "tune-status"), Keys: back}
	case "health":
		if !usr.admin() {
			return tgScreen{Text: tgT(c, "⛔ فقط ادمین.", "⛔ Admins only."), Keys: back}
		}
		return tgGenericPost(c, usr, "🧪 Tunnel health", "/api/tunnel-health/run", map[string]any{}, "to")
	case "adv":
		return tgGeneric(c, usr, "💡 Carrier advice", "/api/carrier/advice")
	case "lim":
		return tgGeneric(c, usr, "🚦 Limits", "/api/limits")
	case "sp":
		return tgGeneric(c, usr, "🛰 Sentinel", "/api/sentinel")
	}
	keys := [][]tgBtn{}
	if usr.admin() {
		keys = append(keys,
			[]tgBtn{{Text: tgT(c, "🚀 بهینه‌سازی شبکه", "🚀 Optimize network"), Data: "to:opt"}, {Text: tgT(c, "↩️ برگرداندن", "↩️ Restore"), Data: "to:rst"}},
			[]tgBtn{{Text: tgT(c, "📈 وضعیت تنظیم شبکه", "📈 Tuning status"), Data: "to:tune"}, {Text: tgT(c, "🧪 تست سلامت تونل‌ها", "🧪 Tunnel health test"), Data: "to:health"}})
	}
	if usr.admin() {
		keys = append(keys,
			[]tgBtn{{Text: tgT(c, "💡 پیشنهاد حامل", "💡 Carrier advice"), Data: "to:adv"}, {Text: tgT(c, "🚦 محدودیت‌ها", "🚦 Limits"), Data: "to:lim"}},
			[]tgBtn{{Text: "🛰 Sentinel", Data: "to:sp"}})
	}
	keys = append(keys, tgBack(c, "m"))
	return tgScreen{Text: tgT(c, "🛠 ابزارها:\nبرای هر کار دیگری از /api استفاده کنید (راهنما: /help).", "🛠 Tools:\nFor anything else use /api (see /help)."), Keys: keys}
}

func tgLogs(c tgBotConfig, usr *tgBotUser) tgScreen {
	var v struct {
		Logs string `json:"logs"`
	}
	if err := tgAPIJSON(usr, http.MethodGet, "/api/logs?svc=stream&n=400", nil, &v); err != nil {
		return tgErrScreen(c, "m", err)
	}
	if strings.TrimSpace(v.Logs) == "" {
		return tgScreen{Text: tgT(c, "لاگی نیست.", "No logs."), Keys: [][]tgBtn{tgBack(c, "m")}}
	}
	name := "hashem-logs-" + time.Now().Local().Format("20060102-1504") + ".txt"
	return tgScreen{Text: tgT(c, "📜 ۴۰۰ خط آخر لاگ سرویس‌ها", "📜 The services' last 400 log lines"), Doc: []byte(v.Logs), DocName: name, Keys: [][]tgBtn{tgBack(c, "m")}}
}

func tgErrors(c tgBotConfig, usr *tgBotUser) tgScreen {
	var v struct {
		Errors []errEvent `json:"events"`
	}
	code, data, err := tgAPI(usr, http.MethodGet, "/api/errors?n=20", nil)
	if err == nil && code >= 300 {
		err = fmt.Errorf("%s", tgAPIErrText(code, data))
	}
	if err != nil {
		return tgErrScreen(c, "m", err)
	}
	_ = json.Unmarshal(data, &v)
	if len(v.Errors) == 0 {
		return tgScreen{Text: tgT(c, "✅ خطای اخیری نیست.", "✅ No recent errors."), Keys: [][]tgBtn{tgBack(c, "m")}}
	}
	var b strings.Builder
	b.WriteString(tgT(c, "❗️ خطاهای اخیر:\n", "❗️ Recent errors:\n"))
	start := 0
	if len(v.Errors) > 20 {
		start = len(v.Errors) - 20
	}
	for _, e := range v.Errors[start:] {
		fmt.Fprintf(&b, "• %s %s %s\n", e.Time, e.Code, tgCut(e.Detail, 200))
	}
	return tgScreen{Text: b.String(), Keys: [][]tgBtn{{{Text: tgT(c, "🔄 تازه کن", "🔄 Refresh"), Data: "er"}}, tgBack(c, "m")}}
}

// ---- update and license ----

func tgUpdateMenu(c tgBotConfig, usr *tgBotUser, chat int64, arg string) tgScreen {
	var v struct {
		Current   string `json:"current"`
		Latest    string `json:"latest"`
		Channel   string `json:"channel"`
		Available bool   `json:"update_available"`
		Error     string `json:"error"`
		Changes   any    `json:"changes"`
	}
	q := "/api/version"
	if arg == "chk" {
		q += "?refresh=1"
	}
	if arg == "go" {
		return tgConfirm(c, usr, tgT(c, "پنل به آخرین نسخه آپدیت شود؟ پنل چند ثانیه ری‌استارت می‌شود (تونل‌ها کار می‌کنند) و بعد خبر می‌دهم.", "Update the panel to the latest version? It restarts for a few seconds (the tunnels keep running), then I tell you."),
			tgT(c, "آپدیت…", "Updating…"), func(u *tgBotUser) string {
				_, _ = updateTGBotConfig(func(cc *tgBotConfig) error {
					cc.Notify = &tgNotify{Chat: chat, From: panelVersion, At: time.Now().Unix()}
					return nil
				})
				var res struct {
					Detail string `json:"detail"`
				}
				if err := tgAPIJSON(u, http.MethodPost, "/api/update", map[string]any{}, &res); err != nil {
					_, _ = updateTGBotConfig(func(cc *tgBotConfig) error { cc.Notify = nil; return nil })
					return "❌ " + err.Error()
				}
				if strings.HasPrefix(res.Detail, "already latest") {
					_, _ = updateTGBotConfig(func(cc *tgBotConfig) error { cc.Notify = nil; return nil })
				}
				return "✅ " + res.Detail
			})
	}
	if err := tgAPIJSON(usr, http.MethodGet, q, nil, &v); err != nil {
		return tgErrScreen(c, "m", err)
	}
	text := fmt.Sprintf(tgT(c, "⬆️ نسخه‌ی فعلی: %s\nآخرین (%s): %s\n", "⬆️ Running: %s\nLatest (%s): %s\n"), v.Current, v.Channel, v.Latest)
	if v.Error != "" {
		text += "⚠️ " + v.Error + "\n"
	}
	keys := [][]tgBtn{{{Text: tgT(c, "🔄 دوباره بررسی کن", "🔄 Check again"), Data: "up:chk"}}}
	if v.Available {
		text += tgT(c, "✨ نسخه‌ی تازه آماده است.\n", "✨ A new version is ready.\n")
		if v.Changes != nil {
			text += "\n" + tgCut(tgPretty(v.Changes), 2500)
		}
		if usr.admin() {
			keys = append(keys, []tgBtn{{Text: tgT(c, "⬆️ الان آپدیت کن", "⬆️ Update now"), Data: "up:go"}})
		}
	} else {
		text += tgT(c, "✅ به‌روز است.", "✅ Up to date.")
	}
	keys = append(keys, tgBack(c, "m"))
	return tgScreen{Text: text, Keys: keys}
}

func tgLicense(c tgBotConfig, usr *tgBotUser) tgScreen {
	var v struct {
		Valid     bool     `json:"is_valid"`
		Customer  string   `json:"customer"`
		ExpiresAt int64    `json:"expires_at"`
		Pro       []string `json:"pro_features"`
		Machine   string   `json:"machine_hash"`
	}
	if err := tgAPIJSON(usr, http.MethodGet, "/api/license", nil, &v); err != nil {
		return tgErrScreen(c, "m", err)
	}
	var b strings.Builder
	if v.Valid {
		fmt.Fprintf(&b, tgT(c, "🔑 لایسنس فعال · %s\n", "🔑 License active · %s\n"), v.Customer)
		if v.ExpiresAt > 0 {
			fmt.Fprintf(&b, tgT(c, "تا: %s\n", "Until: %s\n"), time.Unix(v.ExpiresAt, 0).Local().Format("2006-01-02"))
		} else {
			b.WriteString(tgT(c, "بدون تاریخ پایان\n", "No end date\n"))
		}
		fmt.Fprintf(&b, tgT(c, "قابلیت‌های Pro: %s\n", "Pro features: %s\n"), strings.Join(v.Pro, ", "))
	} else {
		b.WriteString(tgT(c, "🔑 لایسنسی فعال نیست.\n", "🔑 No active license.\n"))
	}
	fmt.Fprintf(&b, "Machine: %s\n", v.Machine)
	b.WriteString(tgT(c, "\nوارد کردن کلید لایسنس فقط از خود پنل (نه از تلگرام).", "\nA license key is entered in the panel itself, never in Telegram."))
	return tgScreen{Text: b.String(), Keys: [][]tgBtn{tgBack(c, "m")}}
}

// ---- generic views and /api ----

func tgPretty(v any) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")
	_ = enc.Encode(v)
	return strings.TrimSpace(buf.String())
}

func tgPrettyRaw(data []byte) string {
	var v any
	if json.Unmarshal(data, &v) != nil {
		return strings.TrimSpace(string(data))
	}
	return tgPretty(v)
}

func tgGeneric(c tgBotConfig, usr *tgBotUser, title, pathQuery string) tgScreen {
	if !usr.admin() { // the whole answer is shown: it may hold secrets
		return tgScreen{Text: tgT(c, "⛔ فقط ادمین.", "⛔ Admins only."), Keys: [][]tgBtn{tgBack(c, "m")}}
	}
	code, data, err := tgAPI(usr, http.MethodGet, pathQuery, nil)
	if err == nil && code >= 300 {
		err = fmt.Errorf("%s", tgAPIErrText(code, data))
	}
	if err != nil {
		return tgErrScreen(c, "m", err)
	}
	return tgScreen{Text: title + "\n\n" + tgPrettyRaw(data), Keys: [][]tgBtn{tgBack(c, "m")}}
}

func tgGenericPost(c tgBotConfig, usr *tgBotUser, title, path string, body any, back string) tgScreen {
	code, data, err := tgAPI(usr, http.MethodPost, path, body)
	if err == nil && code >= 300 {
		err = fmt.Errorf("%s", tgAPIErrText(code, data))
	}
	if err != nil {
		return tgErrScreen(c, back, err)
	}
	return tgScreen{Text: title + "\n\n" + tgPrettyRaw(data), Keys: [][]tgBtn{tgBack(c, back)}}
}

// tgRawAPI: /api METHOD /api/path [json]. A GET runs at once; anything else
// is asked again.
func tgRawAPI(c tgBotConfig, usr *tgBotUser, rest string) tgScreen {
	if !usr.admin() { // a GET can hold secrets too (tunnel tokens, kits, keys)
		return tgScreen{Text: tgT(c, "⛔ /api فقط برای ادمین است.", "⛔ /api is for admins only.")}
	}
	usage := tgT(c, "نمونه‌ها:\n/api GET /api/status\n/api GET /api/peers\n/api POST /api/action {\"action\":\"ping\",\"peer_id\":2}\n/api PATCH /api/peers {\"id\":2,\"ports\":\"443, 8443\"}\n\nفهرست کامل در docs/API.md است.",
		"Examples:\n/api GET /api/status\n/api GET /api/peers\n/api POST /api/action {\"action\":\"ping\",\"peer_id\":2}\n/api PATCH /api/peers {\"id\":2,\"ports\":\"443, 8443\"}\n\nThe full list is in docs/API.md.")
	parts := strings.SplitN(rest, " ", 3)
	if len(parts) < 2 {
		return tgScreen{Text: usage}
	}
	method, path := strings.ToUpper(parts[0]), strings.TrimSpace(parts[1])
	var body any
	if len(parts) == 3 && strings.TrimSpace(parts[2]) != "" {
		if err := json.Unmarshal([]byte(parts[2]), &body); err != nil {
			return tgScreen{Text: tgT(c, "❌ بدنه JSON درست نیست: ", "❌ The JSON body is not valid: ") + err.Error() + "\n\n" + usage}
		}
	}
	p, _, _ := strings.Cut(path, "?")
	if !tgBotAllowed(method, p) {
		return tgScreen{Text: "⛔ " + method + " " + p + tgT(c, " از ربات در دسترس نیست (ترمینال، ورود، رمز، 2FA، تنظیمات دسترسی، کلید لایسنس): از پنل انجام دهید.",
			" is not available from the bot (terminal, login, password, 2FA, access settings, license key): use the panel.")}
	}
	run := func(u *tgBotUser) string {
		code, data, err := tgAPI(u, method, path, body)
		if err != nil {
			return "❌ " + err.Error()
		}
		head := fmt.Sprintf("%s %s → %d\n\n", method, p, code)
		if code >= 300 {
			return "❌ " + head + tgAPIErrText(code, data)
		}
		return "✅ " + head + tgPrettyRaw(data)
	}
	if method == http.MethodGet {
		return tgScreen{Text: run(usr)}
	}
	shown := ""
	if body != nil {
		shown = "\n" + tgCut(tgPretty(body), 1500)
	}
	return tgConfirm(c, usr, tgT(c, "این درخواست اجرا شود؟\n", "Run this request?\n")+method+" "+path+shown, method+" "+p+"…", run)
}

func tgHelp(c tgBotConfig) tgScreen {
	return tgScreen{Text: tgT(c, `❓ ربات هاشم

با دکمه‌ها کار کنید، یا این دستورها:
/menu /status /tunnels /watchdog /autopilot /customers /doctor /errors /logs /update /cancel /id

/api برای هر کار دیگری که پنل دارد (درخواست مستقیم به API پنل)، مثلاً:
/api GET /api/peers
/api POST /api/action {"action":"ping","peer_id":2}
فقط ادمین؛ هر درخواستی جز GET یک بار دیگر تأیید می‌خواهد.

کارهایی که از ربات نمی‌شود:
• ترمینال سرور
• ورود، تغییر رمز، 2FA و تنظیمات دسترسی پنل
• وارد کردن کلید لایسنس و تبدیل پنل به node core
• ساختن تونل یا مشتری با ویزارد (فقط از پنل، یا /api برای کسی که بدنه را می‌داند)
• آپلود فایل (مثل گواهی TLS دلخواه)
• نمودارها: فقط متن
• مدیریت نودهای دیگر: ربات هر سرور جداست

نکته‌ها:
• هر سرور یک ربات (توکن) جدا لازم دارد.
• اگر تلگرام روی سرور بسته باشد، ربات از مسیر تلگرام نگهبان (تونل) وصل می‌شود؛ اگر آن تونل هم قطع باشد، ربات تا برگشتنش جواب نمی‌دهد.
• دکمه‌های تأیید ۲ دقیقه اعتبار دارند و یک بار مصرف‌اند.`, `❓ Hashem bot

Use the buttons, or these commands:
/menu /status /tunnels /watchdog /autopilot /customers /doctor /errors /logs /update /cancel /id

/api for anything else the panel does (a request straight to the panel's API), e.g.:
/api GET /api/peers
/api POST /api/action {"action":"ping","peer_id":2}
Admins only; anything but GET asks once more.

What the bot cannot do:
• the server terminal
• login, password, 2FA and the panel's access settings
• entering a license key, or turning the panel into a node core
• creating tunnels or customers with the wizard (panel only, or /api if you know the body)
• uploading files (such as a custom TLS certificate)
• charts: text only
• managing other nodes: each server's bot is its own

Notes:
• Each server needs a bot (token) of its own.
• If Telegram is blocked on the server the bot goes out over the watchdog's Telegram route (a tunnel); if that tunnel is down too, the bot is silent until it is back.
• Confirm buttons last 2 minutes and work once.`), Keys: [][]tgBtn{tgBack(c, "m")}}
}
