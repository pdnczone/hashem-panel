package main

// The Telegram bot's tunnels: everything the panel's own pages show.
//
// The bot listed the snapshot's hub links only (the first tunnel of an Iran
// server and peers.json). A foreign server has none of those, so there it
// said "No tunnels yet" next to a working tunnel; and Xray, Bagher and Spoof
// tunnels, and the extra Iran hubs a foreign server serves, were missing
// everywhere. tgAllTunnels is the whole list, each kind with a button of its
// own (their IDs overlap): t:N a hub link or this server's first tunnel,
// hb:N a joined Iran hub, xl:N an Xray link, bl:N a Bagher link, sp:1 Spoof.

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type tgTun struct {
	Data   string // the button that opens it
	Name   string
	State  string // stateHealthy | stateDegraded | stateDown | "" (not known)
	Engine string
	Lat    float64
	Rx, Tx *uint64
	Why    string
	Detail []string // the lines of its own screen
}

// spokeHealth is the health of a foreign server's own (first) tunnel: it has
// no hub link, so its state comes from its session, as on the dashboard. A
// live session is not pinged (snapshot.go), so ping_ok alone would call a
// working tunnel weak.
func spokeHealth(s *HubSnapshot) LinkHealth {
	st := s.Local
	return ComputeHealth(LinkSignals{
		ServiceActive: st.FrpUp, GreIfUp: st.Gre.Exists, Session: s.LocalSession, TCPRTTms: s.LocalRTT,
		ICMPOK: st.PingOK, ICMPms: parsePingMs(st.PingMs), ICMPFresh: st.PingOK || s.LocalSession,
	})
}

// tgSpoke is a foreign server's first tunnel in the shape of a hub link, nil
// when this server has none.
func tgSpoke(s *HubSnapshot) *peerLive {
	st := s.Local
	if s.Main != nil || !strings.HasPrefix(st.Role, "foreign") || !baseTunnelConfigured(st) {
		return nil
	}
	name := linkLabel("main")
	if name == "" {
		name = "Tunnel"
	}
	h := spokeHealth(s)
	l := &peerLive{peerRecord: peerRecord{ID: mainTunnelID, Name: name, RemotePub: st.RemotePub, Engine: st.Engine, Transport: st.Transport,
		FrpPort: st.BindPort, Ports: st.ProxyPorts, FrpsSvc: st.FrpSvc, NoGre: !st.Gre.Exists && !fileExists(systemdUnitDir+"/gre-tunnel.service")},
		GreUp: st.Gre.Exists, GreInner: st.Gre.Inner, FrpUp: st.FrpUp, Linked: s.LocalSession, PingOK: st.PingOK,
		Rx: s.LocalRx, Tx: s.LocalTx, HealthState: h.State, Reasons: h.Reasons}
	l.LatencyMs, l.LatencyKind = h.LatencyMs, h.LatencyKind
	return l
}

// tgLinks is the snapshot and the links t:N buttons work on: this server's
// hub links, and on a foreign server its first tunnel.
func tgLinks() (*HubSnapshot, []peerLive) {
	s := currentSnapshot()
	links := apLinks(s)
	if l := tgSpoke(s); l != nil {
		links = append([]peerLive{*l}, links...)
	}
	return s, links
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

// tgExtraHubs: the Iran hubs a foreign server serves besides its first.
func tgExtraHubs() []joinedHub {
	var out []joinedHub
	for _, h := range joinedHubsView() {
		if !h.First {
			out = append(out, h)
		}
	}
	return out
}

func tgPortList(ports []int) string {
	s := make([]string, 0, len(ports))
	for _, p := range ports {
		s = append(s, strconv.Itoa(p))
	}
	return tgCut(strings.Join(s, ", "), 300)
}

func tgAllTunnels(c tgBotConfig) (*HubSnapshot, []tgTun) {
	s, links := tgLinks()
	var out []tgTun
	for _, l := range links {
		out = append(out, tgTun{Data: "t:" + strconv.Itoa(l.ID), Name: tgLinkName(l), State: l.HealthState, Engine: l.Engine,
			Lat: l.LatencyMs, Rx: l.Rx, Tx: l.Tx, Why: strings.Join(l.Reasons, "; ")})
	}
	for _, h := range tgExtraHubs() {
		t := tgTun{Data: "hb:" + strconv.Itoa(h.ID), Name: xrayOr(h.Name, fmt.Sprintf("hub-%d", h.ID)), Engine: h.Engine, State: stateDown, Why: h.Svc + " is not running"}
		switch {
		case h.Active && h.Session:
			t.State, t.Why = stateHealthy, ""
		case h.Active:
			t.State, t.Why = stateDegraded, "no session with the Iran hub"
		}
		if h.IranPub != "" && !strings.Contains(t.Name, h.IranPub) {
			t.Name += " (" + h.IranPub + ")"
		}
		t.Detail = []string{tgT(c, "هاب ایران: ", "Iran hub: ") + h.IranPub, tgT(c, "سرویس: ", "Service: ") + h.Svc}
		if h.Port > 0 {
			t.Detail = append(t.Detail, fmt.Sprintf(tgT(c, "پورت کنترل: %d", "Control port: %d"), h.Port))
		}
		if len(h.Ports) > 0 {
			t.Detail = append(t.Detail, tgT(c, "پورت‌ها: ", "Ports: ")+tgPortList(h.Ports))
		}
		out = append(out, t)
	}
	for _, l := range loadXrayState().Links {
		h := xrayHealthWait(l, 0)
		t := tgTun{Data: "xl:" + strconv.Itoa(l.ID), Name: xrayOr(l.Name, fmt.Sprintf("xray-%d", l.ID)), Engine: "xray", Lat: h.PingMS}
		switch {
		case l.Disabled:
			t.Why = tgT(c, "متوقف است", "stopped")
		case h.Link == "up" || h.Link == "listening":
			t.State = stateHealthy
		case h.Link == "down":
			t.State, t.Why = stateDown, h.Error
		}
		if l.Remote != "" && !strings.Contains(t.Name, l.Remote) {
			t.Name += " (" + l.Remote + ")"
		}
		if tr, ok := s.CarrierTags[xrayTag(l.ID)]; ok {
			rx, tx := tr[0], tr[1]
			t.Rx, t.Tx = &rx, &tx
		}
		t.Detail = []string{"Xray · " + l.Mode + " · " + l.Profile.Transport + "/" + l.Profile.Security,
			fmt.Sprintf(tgT(c, "پورت تونل: %d", "Tunnel port: %d"), l.TunnelPort), tgT(c, "پورت‌ها: ", "Ports: ") + tgPortList(l.Ports)}
		out = append(out, t)
	}
	out = append(out, tgBagherTunnels(c, s.Bagher)...)
	if sp := loadSpoofState(); sp.Enabled {
		h := spoofRuntimeHealth(sp)
		t := tgTun{Data: "sp:1", Name: "Spoof (" + sp.PeerPublicIP + ")", Engine: "spoof", State: stateDown, Why: tgT(c, "سرویس‌هایش اجرا نیستند", "its services are not running")}
		switch {
		case h.PeerPing:
			t.State, t.Why = stateHealthy, ""
		case h.CoreActive && h.WGActive:
			t.State, t.Why = stateDegraded, tgT(c, "از طرف دیگر پاسخی نیست", "no answer from the other end")
		}
		if h.Handshake != "" {
			t.Detail = []string{"WireGuard: " + h.Handshake}
		}
		out = append(out, t)
	}
	return s, out
}

// tgBagherTunnels are Bagher's links in the snapshot's own reading.
func tgBagherTunnels(c tgBotConfig, b map[string]any) []tgTun {
	if on, _ := b["has_config"].(bool); !on {
		return nil
	}
	one := func(id int, m map[string]any) tgTun {
		str := func(k string) string { v, _ := m[k].(string); return v }
		active, _ := m["is_active"].(bool)
		conn, _ := m["connected"].(bool)
		lat, _ := m["latency_ms"].(float64)
		host := str("remote_host")
		t := tgTun{Data: "bl:" + strconv.Itoa(id), Name: xrayOr(str("name"), "Bagher"), Engine: "bagher", State: stateDown, Lat: lat, Why: str("last_error")}
		switch {
		case conn:
			t.State, t.Why = stateHealthy, ""
		case active:
			t.State = stateDegraded
			t.Why = xrayOr(t.Why, tgT(c, "هنوز وصل نشده", "not connected"))
		default:
			t.Why = xrayOr(t.Why, tgT(c, "سرویسش اجرا نیست", "its service is not running"))
		}
		if host != "" && !strings.Contains(t.Name, host) {
			t.Name += " (" + host + ")"
		}
		t.Detail = []string{"Bagher"}
		if host != "" {
			t.Detail = append(t.Detail, tgT(c, "سرور خارج: ", "Foreign server: ")+host)
		}
		if ports, _ := m["ports"].([]int); len(ports) > 0 {
			t.Detail = append(t.Detail, tgT(c, "پورت‌ها: ", "Ports: ")+tgPortList(ports))
		}
		return t
	}
	out := []tgTun{one(1, b)}
	links, _ := b["links"].([]map[string]any)
	for _, m := range links {
		id, _ := m["id"].(int)
		out = append(out, one(id, m))
	}
	return out
}

// tgCounts: how many are up, weak or not known, and down.
func tgCounts(list []tgTun) (up, weak, down int) {
	for _, t := range list {
		switch t.State {
		case stateHealthy:
			up++
		case stateDown:
			down++
		default:
			weak++
		}
	}
	return
}

// tgNoTunnels is what the bot says when the list is empty.
func tgNoTunnels(c tgBotConfig, s *HubSnapshot) string {
	if s.At.IsZero() {
		return tgT(c, "وضعیت سرور هنوز خوانده نشده؛ چند ثانیه‌ی دیگر دوباره بزنید.", "The server's state has not been read yet: try again in a few seconds.")
	}
	text := tgT(c, "روی این سرور تونلی نیست.", "No tunnels on this server.")
	if tgIsCentral() {
		text += tgT(c, " تونل‌های نودها: دکمه‌ی «نودها».", " The nodes' tunnels: the Nodes button.")
	}
	return text
}

// tgOtherTunnel is the screen of a tunnel that is not a hub link.
func tgOtherTunnel(c tgBotConfig, usr *tgBotUser, data string) tgScreen {
	_, list := tgAllTunnels(c)
	for _, t := range list {
		if t.Data != data {
			continue
		}
		var b strings.Builder
		fmt.Fprintf(&b, "%s %s\n%s\n", tgStateIcon(t.State), t.Name, strings.Join(t.Detail, "\n"))
		if t.Lat > 0 {
			fmt.Fprintf(&b, tgT(c, "تأخیر: %.0f ms\n", "Latency: %.0f ms\n"), t.Lat)
		}
		if t.Rx != nil && t.Tx != nil {
			fmt.Fprintf(&b, tgT(c, "ترافیک: ↓%s ↑%s\n", "Traffic: ↓%s ↑%s\n"), fmtBytesDec(*t.Rx), fmtBytesDec(*t.Tx))
		}
		if t.Why != "" {
			fmt.Fprintf(&b, "↳ %s\n", tgCut(t.Why, 600))
		}
		keys := [][]tgBtn{}
		if key, id, _ := strings.Cut(data, ":"); key == "xl" && usr.admin() {
			row := []tgBtn{{Text: tgT(c, "🔁 ری‌استارت", "🔁 Restart"), Data: "xs:" + id}}
			if t.State != "" || t.Why == "" { // not stopped already
				row = append(row, tgBtn{Text: tgT(c, "⏹ توقف", "⏹ Stop"), Data: "xp:" + id})
			}
			keys = append(keys, row)
		}
		return tgScreen{Text: b.String(), Keys: append(keys, []tgBtn{{Text: tgT(c, "🔄 تازه کن", "🔄 Refresh"), Data: data}}, tgBack(c, "tl"))}
	}
	return tgScreen{Text: tgT(c, "این تونل دیگر نیست.", "This tunnel is gone."), Keys: [][]tgBtn{tgBack(c, "tl")}}
}

// tgXrayAction starts (again) or stops an Xray link.
func tgXrayAction(c tgBotConfig, usr *tgBotUser, key string, id int) tgScreen {
	back := [][]tgBtn{tgBack(c, "xl:"+strconv.Itoa(id))}
	if !usr.admin() {
		return tgScreen{Text: tgT(c, "⛔ فقط ادمین.", "⛔ Admins only."), Keys: back}
	}
	run := func(u *tgBotUser, action string) string {
		var out struct {
			Status string `json:"status"`
			Error  string `json:"error"`
		}
		if err := tgAPIJSON(u, http.MethodPost, "/api/xray", map[string]any{"action": action, "id": id}, &out); err != nil {
			return "❌ " + err.Error()
		}
		if out.Status == "error" {
			return "❌ " + out.Error
		}
		return "✅ " + tgT(c, "انجام شد", "Done")
	}
	if key == "xp" {
		return tgConfirm(c, usr, tgT(c, "این لینک Xray متوقف شود؟ کاربرانش قطع می‌شوند.", "Stop this Xray link? Its users are cut off."),
			tgT(c, "در حال توقف…", "Stopping…"), func(u *tgBotUser) string { return run(u, "stop") })
	}
	return tgScreen{Text: run(usr, "start"), Keys: back}
}

// ---- nodes (a central) ----

func tgIsCentral() bool {
	self, err := nodeSelfLoad()
	return err == nil && self.Role == nodeRoleCentral
}

// tgNodes: the servers a central manages, read only.
func tgNodes(c tgBotConfig) tgScreen {
	keys := [][]tgBtn{{{Text: tgT(c, "🔄 تازه کن", "🔄 Refresh"), Data: "nd"}}, tgBack(c, "m")}
	if !tgIsCentral() {
		return tgScreen{Text: tgT(c, "این پنل مرکزی نیست و نودی ندارد.", "This panel is not a central: it has no nodes."), Keys: keys}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	v := nodeFleetOverview(ctx)
	var b strings.Builder
	fmt.Fprintf(&b, tgT(c, "🗂 نودها: %d سرور، %d آنلاین\n\n", "🗂 Nodes: %d servers, %d online\n\n"), len(v.Servers), v.Online)
	for _, n := range v.Servers {
		icon := "🔴"
		if n.Online && n.Error == "" {
			icon = map[string]string{stateHealthy: "🟢", stateDegraded: "🟡", stateDown: "🔴"}[n.Health]
			if icon == "" {
				icon = "⚪️"
			}
		}
		fmt.Fprintf(&b, "%s %s", icon, n.Name)
		if n.Public != "" {
			fmt.Fprintf(&b, " (%s)", n.Public)
		}
		fmt.Fprintf(&b, tgT(c, " · تونل: %d", " · tunnels: %d"), n.Tunnels)
		if n.Version != "" {
			fmt.Fprintf(&b, " · %s", displayVersion(n.Version))
		}
		b.WriteString("\n")
		if n.Error != "" {
			fmt.Fprintf(&b, "   ↳ %s\n", tgCut(n.Error, 200))
		}
	}
	return tgScreen{Text: b.String(), Keys: keys}
}
