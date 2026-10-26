package main

// More than one foreign server on one Iran server with Bagher. Link 1 is the
// foreign server of the original setup (SSHFwdConfig's own fields); links 2+
// are SSHFwdConfig.Links. Every link has its own carrier unit and SSH session
// to its foreign server, and all of them reach the same frps on Iran. Each
// foreign server's frpc registers its own ports there, so the ports of two
// links must not overlap (frp proxy names are p<port>/u<port>).

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// BagherLink is one foreign server after the first.
type BagherLink struct {
	ID            int    `json:"id"`
	RemoteHost    string `json:"remote_host"`
	RemoteUser    string `json:"remote_user,omitempty"`
	RemoteSSHPort int    `json:"remote_ssh_port,omitempty"`
	Ports         []int  `json:"ports"`
	UDP           bool   `json:"udp,omitempty"`
}

func findBagherLink(cfg SSHFwdConfig, id int) (BagherLink, bool) {
	for _, l := range cfg.Links {
		if l.ID == id {
			return l, true
		}
	}
	return BagherLink{}, false
}

// bagherLinkUnit is the carrier unit name of link id.
func bagherLinkUnit(id int) string {
	if id <= 1 {
		return "hashem-bagher"
	}
	return fmt.Sprintf("hashem-bagher-%d", id)
}

func bagherLinkUnitPath(id int) string {
	return filepath.Join("/etc/systemd/system", bagherLinkUnit(id)+".service")
}

// bagherLinkCfg is cfg as seen by link id: its host, SSH port, user, ports
// and UDP in the top-level fields, for the bundle and the setup commands.
func bagherLinkCfg(cfg SSHFwdConfig, l BagherLink) SSHFwdConfig {
	c := cfg
	c.RemoteHost, c.Ports, c.UDP = l.RemoteHost, l.Ports, l.UDP
	if l.RemoteSSHPort > 0 {
		c.RemoteSSHPort = l.RemoteSSHPort
	}
	if l.RemoteUser != "" {
		c.RemoteUser = l.RemoteUser
	}
	c.Links = nil
	return c
}

var bagherHostRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)

// validBagherHost accepts an IP address or a DNS name, nothing that could
// break out of a unit file or a command line.
func validBagherHost(h string) bool {
	return net.ParseIP(h) != nil || bagherHostRe.MatchString(h)
}

var bagherUserRe = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}$`)

// bagherPortOwner returns which link already forwards port p (0: none),
// skipping link skip.
func bagherPortOwner(cfg SSHFwdConfig, p, skip int) int {
	if skip != 1 {
		for _, q := range cfg.Ports {
			if q == p {
				return 1
			}
		}
	}
	for _, l := range cfg.Links {
		if l.ID == skip {
			continue
		}
		for _, q := range l.Ports {
			if q == p {
				return l.ID
			}
		}
	}
	return 0
}

// checkBagherLinkPorts refuses ports another link (or this server's
// internal FRP ports) already uses.
func checkBagherLinkPorts(cfg SSHFwdConfig, ports []int, self int) error {
	for _, p := range ports {
		if p >= cfg.FRPBindPort && p <= cfg.FRPBindPort+2 {
			return fmt.Errorf("port %d is Bagher's internal FRP port (%d-%d)", p, cfg.FRPBindPort, cfg.FRPBindPort+2)
		}
		if owner := bagherPortOwner(cfg, p, self); owner != 0 {
			return fmt.Errorf("port %d is already forwarded to foreign server %d (%s)", p, owner, bagherLinkHost(cfg, owner))
		}
	}
	return nil
}

func bagherLinkHost(cfg SSHFwdConfig, id int) string {
	if id == 1 {
		return cfg.RemoteHost
	}
	l, _ := findBagherLink(cfg, id)
	return l.RemoteHost
}

// addBagherLink validates and appends a foreign server; it returns the new link.
func addBagherLink(cfg *SSHFwdConfig, l BagherLink) (BagherLink, error) {
	l.RemoteHost = strings.TrimSpace(l.RemoteHost)
	if strings.TrimSpace(cfg.RemoteHost) == "" || len(cfg.Ports) == 0 {
		return l, fmt.Errorf("set up Bagher with the first foreign server before adding more")
	}
	if !validBagherHost(l.RemoteHost) {
		return l, fmt.Errorf("invalid foreign server address %q", l.RemoteHost)
	}
	if l.RemoteUser != "" && !bagherUserRe.MatchString(l.RemoteUser) {
		return l, fmt.Errorf("invalid SSH user %q", l.RemoteUser)
	}
	if l.RemoteSSHPort < 0 || l.RemoteSSHPort > 65535 {
		return l, fmt.Errorf("invalid SSH port %d", l.RemoteSSHPort)
	}
	if len(l.Ports) == 0 {
		return l, fmt.Errorf("at least one port must be specified")
	}
	// The foreign sshd listens on 127.0.0.1:FRP for each session, so one
	// foreign server can carry one link only.
	taken := l.RemoteHost == cfg.RemoteHost
	for _, x := range cfg.Links {
		taken = taken || x.RemoteHost == l.RemoteHost
	}
	if taken {
		return l, fmt.Errorf("%s is already a Bagher foreign server", l.RemoteHost)
	}
	if err := checkBagherLinkPorts(*cfg, l.Ports, 0); err != nil {
		return l, err
	}
	l.ID = 2
	for _, x := range cfg.Links {
		if x.ID >= l.ID {
			l.ID = x.ID + 1
		}
	}
	cfg.Links = append(cfg.Links, l)
	return l, nil
}

func removeBagherLink(cfg *SSHFwdConfig, id int) bool {
	for i, l := range cfg.Links {
		if l.ID == id {
			cfg.Links = append(cfg.Links[:i], cfg.Links[i+1:]...)
			return true
		}
	}
	return false
}

// installBagherLinkUnits writes the carrier unit of every extra link and
// starts the ones not running (with restart, restarts all: the settings
// they read changed); stale units of removed links are removed.
func installBagherLinkUnits(cfg SSHFwdConfig, restart bool) error {
	keep := map[string]bool{}
	for _, l := range cfg.Links {
		keep[bagherLinkUnit(l.ID)+".service"] = true
		if err := os.WriteFile(bagherLinkUnitPath(l.ID), []byte(buildBagherCarrierUnit(cfg, l.ID)), 0644); err != nil {
			return fmt.Errorf("failed writing unit: %w", err)
		}
	}
	for _, u := range staleBagherLinkUnits(keep) {
		_, _ = runCmd("systemctl", "disable", "--now", u)
		_ = os.Remove(filepath.Join("/etc/systemd/system", u))
	}
	if _, err := runCmd("systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("daemon-reload failed: %w", err)
	}
	for _, l := range cfg.Links {
		u := bagherLinkUnit(l.ID) + ".service"
		if out, err := runCmd("systemctl", "enable", "--now", u); err != nil {
			return fmt.Errorf("failed starting %s: %v %s", u, err, strings.TrimSpace(out))
		}
		if restart {
			_, _ = runCmd("systemctl", "restart", u)
		}
	}
	return nil
}

// staleBagherLinkUnits lists hashem-bagher-<n>.service files not in keep.
func staleBagherLinkUnits(keep map[string]bool) []string {
	matches, _ := filepath.Glob("/etc/systemd/system/hashem-bagher-*.service")
	var out []string
	for _, m := range matches {
		b := filepath.Base(m)
		var n int
		if _, err := fmt.Sscanf(b, "hashem-bagher-%d.service", &n); err == nil && n > 1 && !keep[b] {
			out = append(out, b)
		}
	}
	sort.Strings(out)
	return out
}

// stopBagherLinkUnits stops (and with remove, deletes) every extra link's carrier.
func stopBagherLinkUnits(cfg SSHFwdConfig, remove bool) {
	names := staleBagherLinkUnits(nil)
	for _, l := range cfg.Links {
		names = append(names, bagherLinkUnit(l.ID)+".service")
	}
	seen := map[string]bool{}
	for _, u := range names {
		if seen[u] {
			continue
		}
		seen[u] = true
		_, _ = runCmd("systemctl", "disable", "--now", u)
		if remove {
			_ = os.Remove(filepath.Join("/etc/systemd/system", u))
		}
	}
	for _, l := range cfg.Links {
		_ = os.Remove(bagherCarrierStatusPath(l.ID))
	}
}

// bagherProxiesOnline asks the Iran frps which proxies are online
// (name -> online); ok is false when its dashboard does not answer.
func bagherProxiesOnline(cfg SSHFwdConfig) (map[string]bool, bool) {
	out := map[string]bool{}
	client := &http.Client{Timeout: 400 * time.Millisecond}
	got := false
	for _, typ := range []string{"tcp", "udp"} {
		req, err := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/api/proxy/%s", cfg.FRPBindPort+1, typ), nil)
		if err != nil {
			continue
		}
		req.SetBasicAuth("admin", "bagher-dash-local")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		var body struct {
			Proxies []struct {
				Name   string `json:"name"`
				Status string `json:"status"`
			} `json:"proxies"`
		}
		if resp.StatusCode == 200 && json.NewDecoder(resp.Body).Decode(&body) == nil {
			got = true
			for _, p := range body.Proxies {
				out[p.Name] = p.Status == "online"
			}
		}
		_ = resp.Body.Close()
	}
	return out, got
}

// bagherLinkUp reports whether any of the link's ports is registered online.
func bagherLinkUp(online map[string]bool, ports []int) bool {
	for _, p := range ports {
		if online[fmt.Sprintf("p%d", p)] {
			return true
		}
	}
	return false
}

// bagherCarrierRTT is the carrier's last measured tunnel ping, if fresh.
func bagherCarrierRTT(cfg SSHFwdConfig, id int) (float64, bool) {
	alive := time.Duration(cfg.ServerAliveInterval) * time.Second
	if alive <= 0 {
		alive = 10 * time.Second
	}
	st, ok := readBagherCarrierStatus(id, 3*alive+5*time.Second)
	if !ok || !st.Connected || st.RTTMs <= 0 {
		return 0, false
	}
	return st.RTTMs, true
}

// bagherLinksStatus is the per-link view for the Tunnel tab; withBundle adds
// each link's bundle (the full status only: it looks up the public IP).
func bagherLinksStatus(cfg SSHFwdConfig, pubKey string, withBundle bool) []map[string]any {
	if len(cfg.Links) == 0 {
		return []map[string]any{}
	}
	online, gotProxies := bagherProxiesOnline(cfg)
	res := make([]map[string]any, 0, len(cfg.Links))
	for _, l := range cfg.Links {
		out, _ := runCmd("systemctl", "is-active", bagherLinkUnit(l.ID)+".service")
		active := strings.TrimSpace(out) == "active"
		rtt, _ := bagherCarrierRTT(cfg, l.ID)
		connected := active && gotProxies && bagherLinkUp(online, l.Ports)
		m := map[string]any{
			"id": l.ID, "remote_host": l.RemoteHost, "ports": l.Ports, "udp": l.UDP,
			"remote_ssh_port": l.RemoteSSHPort, "remote_user": l.RemoteUser,
			"is_active": active, "connected": connected, "latency_ms": rtt,
			"unit": bagherLinkUnit(l.ID), "name": linkLabel(fmt.Sprintf("bagher-%d", l.ID)),
		}
		if st, ok := readBagherCarrierStatus(l.ID, 24*time.Hour); ok && st.Error != "" && !st.Connected {
			m["last_error"] = st.Error
		}
		if withBundle && pubKey != "" {
			m["bundle"], _ = MakeBagherBundle(bagherLinkCfg(cfg, l), pubKey)
		}
		res = append(res, m)
	}
	return res
}

// migrateBagherCarrierUnit moves a Bagher unit written by an older panel
// (ssh -N -R, the high-ping carrier) to the panel's carrier, so an update
// alone fixes the ping. Only a unit for the configured foreign server is
// touched; a running one is restarted onto the new carrier.
func migrateBagherCarrierUnit(unitPath string) (bool, error) {
	data, err := os.ReadFile(unitPath)
	if err != nil {
		return false, nil // no Bagher here
	}
	unit := string(data)
	cfg := loadSSHFwdConfigLocked()
	if !strings.Contains(unit, "ExecStart=/usr/bin/ssh -N ") || !strings.Contains(unit, fmt.Sprintf(" -R 127.0.0.1:%d:", cfg.FRPBindPort)) ||
		cfg.RemoteHost == "" || !strings.HasSuffix(strings.TrimSpace(execStartOf(unit)), "@"+cfg.RemoteHost) {
		return false, nil
	}
	if _, err := os.Stat(cfg.KeyPath); err != nil {
		return false, nil
	}
	if err := os.WriteFile(unitPath, []byte(buildSSHFwdService(cfg)), 0644); err != nil {
		return false, err
	}
	_, _ = runCmd("systemctl", "daemon-reload")
	_, _ = runCmd("systemctl", "try-restart", filepath.Base(unitPath))
	return true, nil
}

// migrateBagherFRPCTLS adds bagherFRPCNoTLS to a Bagher frpc.toml written by
// an older panel or hashem.sh and restarts a running frpc, so an update alone
// drops the second encryption layer. A file that sets TLS itself is left alone.
func migrateBagherFRPCTLS(path string) (bool, error) {
	data, err := os.ReadFile(path)
	// a [transport] table would make the prepended dotted key a duplicate: leave such a file to its writer
	if err != nil || strings.Contains(string(data), "transport.tls.enable") || strings.Contains(string(data), "[transport") {
		return false, nil // no Bagher frpc here, or already decided
	}
	// first line: a top-level key must come before any [[proxies]] table
	if err := writeTokenFile(path, append([]byte(bagherFRPCNoTLS+"\n"), data...)); err != nil {
		return false, err
	}
	_, _ = runCmd("systemctl", "try-restart", "hashem-bagher-frpc.service")
	return true, nil
}

func execStartOf(unit string) string {
	for _, line := range strings.Split(unit, "\n") {
		if strings.HasPrefix(line, "ExecStart=") {
			return strings.TrimPrefix(line, "ExecStart=")
		}
	}
	return ""
}
