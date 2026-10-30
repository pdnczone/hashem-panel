package main

// Selling tunnels to customers (Hashem Pro, docs/PLAN_CUSTOMERS.md).
//
// A customer owns one or more foreign servers and buys this Iran server's
// end. Each of the customer's foreign servers is a link with its own relay:
//
//   - Unit hsell-<customer>-<link>.service runs a copy of frps
//     (custBinDir/frps, so hashem.sh's `pkill -f /usr/local/bin/frps` on
//     update never hits it) with customers/<customer>-<link>.toml: its own
//     control port and token, allowPorts = exactly the link's user ports.
//   - Volume: the HASHEM_CUST chain (iptables, jumped to from INPUT and
//     OUTPUT) counts each user port, --dport in and --sport out, with a
//     comment hsell-<customer>-in|out. Only users' traffic is billed: the
//     control port is not counted. The panel sums the counters per customer
//     in customers.json.
//   - Speed: tc clsact on the default-route interface, pref custTCPref, one
//     police action per customer and direction (index custPoliceIndex) that
//     every filter of every one of the customer's ports shares: the cap is
//     for the customer, not per port or per link.
//   - Cut (plan expired, volume used up, or by hand): the customer's rules
//     become DROP and the units are stopped and disabled. A unit is started
//     only once the chain is in place, so no traffic passes unbilled.
//
// Rules are enforced with or without a license (cut and remove always
// work); creating, renewing and resuming customers needs Pro. hashem.sh
// customers_teardown removes it all on uninstall.

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

const (
	custChain       = "HASHEM_CUST"
	custTCPref      = "4919"
	custTCPref6     = "4920" // reserved: users over IPv6 (customer relays bind IPv4 today)
	custPoliceBase  = 0x48530000
	proCustomersTxt = "Selling tunnels to customers"
	custMaxLinks    = 16
	custMaxPorts    = 64
	custMaxCount    = 2000
	custMaxID       = 32767 // custPoliceIndex stays within 0x4853xxxx
	custFRPVersion  = "0.71.0"
)

// Paths, swappable for tests.
var (
	custBinDir  = "/usr/local/lib/hashem-sell"
	custFrpsSrc = "/usr/local/bin/frps"
)

func custBin() string              { return filepath.Join(custBinDir, "frps") }
func custUnit(cid, lid int) string { return fmt.Sprintf("hsell-%d-%d", cid, lid) }
func custConfDir() string          { return filepath.Join(configDir, "customers") }
func custConfPath(cid, lid int) string {
	return filepath.Join(custConfDir(), fmt.Sprintf("%d-%d.toml", cid, lid))
}
func custUnitPath(cid, lid int) string {
	return filepath.Join(engineUnitDir, custUnit(cid, lid)+".service")
}
func customersPath() string { return filepath.Join(configDir, "customers.json") }

// custPoliceIndex is the tc police action of customer cid: out (to users)
// or in (from users).
func custPoliceIndex(cid int, out bool) int {
	if out {
		return custPoliceBase + cid*2
	}
	return custPoliceBase + cid*2 + 1
}

type customerLink struct {
	ID        int    `json:"id"`
	Name      string `json:"name,omitempty"` // the foreign server, for the seller
	Engine    string `json:"engine"`         // "frp"
	Transport string `json:"transport"`      // frp: tcp | kcp | quic | websocket
	CtrlPort  int    `json:"ctrl_port"`
	Ports     []int  `json:"ports"`
	UDP       bool   `json:"udp,omitempty"`
	Token     string `json:"token"`
}

type customer struct {
	ID      int    `json:"id"`
	Name    string `json:"name"`
	Note    string `json:"note,omitempty"`
	Token   string `json:"token"`             // the status page /_hs/<token>
	Address string `json:"address,omitempty"` // what the kit dials ("" = this server's public IP)
	Created int64  `json:"created"`
	// Plan. ExpiresAt 0 = never; QuotaGB and RateMbit 0 = unlimited.
	ExpiresAt int64   `json:"expires_at"`
	QuotaGB   float64 `json:"quota_gb"`
	RateMbit  float64 `json:"rate_mbit"`
	Days      int     `json:"days,omitempty"` // the plan's length, the default for a renewal
	// Usage in the current period, in bytes: rx from the users, tx to them.
	UsedRx      uint64 `json:"used_rx"`
	UsedTx      uint64 `json:"used_tx"`
	PeriodStart int64  `json:"period_start"`
	// Cut: "" (running) | "expired" | "quota" | "manual".
	Cut    string         `json:"cut,omitempty"`
	Warned bool           `json:"warned,omitempty"` // the 90% alert went out this period
	Links  []customerLink `json:"links"`
}

func (c customer) used() uint64 { return c.UsedRx + c.UsedTx }

func (c customer) quotaBytes() uint64 { return uint64(math.Round(c.QuotaGB * gb)) }

func (c *customer) link(id int) *customerLink {
	for i := range c.Links {
		if c.Links[i].ID == id {
			return &c.Links[i]
		}
	}
	return nil
}

type customersFile struct {
	Customers []customer `json:"customers"`
	NextID    int        `json:"next_id"`
	// Counters are the chain's byte counters (by comment) at the last tick,
	// saved with the usage they were added to: after a panel restart the
	// bytes counted while it was down are billed, none twice.
	Counters map[string]uint64 `json:"counters,omitempty"`
}

var custs = struct {
	sync.Mutex
	loaded  bool
	loadErr string // customers.json could not be read: nothing is changed
	f       customersFile
	speed   map[int][2]float64 // bytes/s by customer: [0] from, [1] to the users
	at      time.Time
	dirty   bool
	saved   time.Time
	err     string
}{}

// custTickMu serialises the ticks (the loop and a POST that applies at once).
var custTickMu sync.Mutex

// custApplied is what is loaded in the kernel and systemd; only the tick
// touches it.
var custApplied = struct {
	ipt, tc, tcIf string
	tcCheck       time.Time
	police        []int
	cleaned       bool
	running       map[string]bool // unit -> started by the tick
	swept         bool            // stray units and police actions removed once
	reserved      string          // the ports kept out of the ephemeral range
}{}

// Commands, swappable for tests.
var (
	custRun     = func(name string, args ...string) ([]byte, error) { return runCmdTimeout(10*time.Second, name, args...) }
	custSaveOut = func() ([]byte, error) { return runCmdTimeoutOut(5*time.Second, "iptables-save", "-c", "-t", "filter") }
	custIface   = primaryInterface
	custAlert   = sendCustomerAlert
	// custPortBusy says whether something outside Hashem holds a port.
	custPortBusy = func(proto string, port int) bool {
		if proto == "udp" {
			c, err := net.ListenPacket("udp4", ":"+strconv.Itoa(port))
			if err != nil {
				return true
			}
			_ = c.Close()
			return false
		}
		l, err := net.Listen("tcp4", ":"+strconv.Itoa(port))
		if err != nil {
			return true
		}
		_ = l.Close()
		return false
	}
)

func custLoadLocked() {
	if custs.loaded {
		return
	}
	custs.loaded = true
	custs.f = customersFile{}
	custs.loadErr = ""
	custs.speed = map[int][2]float64{}
	if data, err := os.ReadFile(customersPath()); err == nil {
		if err := json.Unmarshal(data, &custs.f); err != nil {
			// never treated as "no customers": that would drop the chain
			// while the units keep running, and reuse their IDs
			custs.f = customersFile{}
			custs.loadErr = "customers.json cannot be read (" + err.Error() + "): fix or restore it, then restart the panel; nothing is changed until then"
		}
	} else if !os.IsNotExist(err) {
		custs.loadErr = "customers.json: " + err.Error()
	}
	if custs.f.Counters == nil {
		custs.f.Counters = map[string]uint64{}
	}
	var ok []customer
	for _, c := range custs.f.Customers {
		if c.ID > 0 && c.ID <= custMaxID {
			ok = append(ok, c)
		}
	}
	custs.f.Customers = ok
	if custs.f.NextID < 1 {
		custs.f.NextID = 1
	}
}

// custNewIDLocked is the next customer ID: IDs grow and are not reused while
// they fit the police index range; past custMaxID the lowest free one.
func custNewIDLocked() int {
	used := map[int]bool{}
	for _, c := range custs.f.Customers {
		used[c.ID] = true
		if c.ID >= custs.f.NextID {
			custs.f.NextID = c.ID + 1
		}
	}
	if custs.f.NextID <= custMaxID {
		id := custs.f.NextID
		custs.f.NextID++
		return id
	}
	for id := 1; id <= custMaxID; id++ {
		if !used[id] {
			return id
		}
	}
	return 0
}

func custSaveLocked() error {
	if custs.f.Customers == nil {
		custs.f.Customers = []customer{}
	}
	data, err := json.MarshalIndent(custs.f, "", "  ")
	if err != nil {
		return err
	}
	if err := writeFileAtomic(customersPath(), data, 0o600); err != nil {
		return err
	}
	custs.dirty, custs.saved = false, time.Now()
	return nil
}

func custFindLocked(id int) *customer {
	for i := range custs.f.Customers {
		if custs.f.Customers[i].ID == id {
			return &custs.f.Customers[i]
		}
	}
	return nil
}

// customersFlush saves the usage counted since the last save (shutdown).
func customersFlush() {
	custs.Lock()
	defer custs.Unlock()
	if custs.loaded && custs.dirty {
		_ = custSaveLocked()
	}
}

// customerPortClaims are the ports sold tunnels take (ports_registry.go).
func customerPortClaims() []portClaim {
	custs.Lock()
	custLoadLocked()
	list := append([]customer(nil), custs.f.Customers...)
	custs.Unlock()
	var out []portClaim
	for _, c := range list {
		for _, l := range c.Links {
			owner := fmt.Sprintf("customer %s (link %d)", c.Name, l.ID)
			for _, p := range l.Ports {
				out = append(out, portClaim{"tcp", p, claimCustomer, c.ID, l.ID, owner})
				if l.UDP {
					out = append(out, portClaim{"udp", p, claimCustomer, c.ID, l.ID, owner})
				}
			}
			ctrl := "the control port of " + owner
			out = append(out, portClaim{"tcp", l.CtrlPort, claimCustomer, c.ID, l.ID, ctrl})
			if l.Transport == "kcp" || l.Transport == "quic" {
				out = append(out, portClaim{"udp", l.CtrlPort, claimCustomer, c.ID, l.ID, ctrl})
			}
		}
	}
	return out
}

// ---- configs and units ----

var custTransports = map[string]bool{"tcp": true, "kcp": true, "quic": true, "websocket": true}

// custFrpsConf is a link's frps config.
func custFrpsConf(l customerLink) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Hashem: sold tunnel. Written by the panel; edits are overwritten.\n")
	fmt.Fprintf(&b, "bindAddr = \"0.0.0.0\"\nbindPort = %d\n", l.CtrlPort)
	switch l.Transport {
	case "kcp":
		fmt.Fprintf(&b, "kcpBindPort = %d\n", l.CtrlPort)
	case "quic":
		fmt.Fprintf(&b, "quicBindPort = %d\n", l.CtrlPort)
	}
	fmt.Fprintf(&b, "proxyBindAddr = \"0.0.0.0\"\n")
	fmt.Fprintf(&b, "auth.method = \"token\"\nauth.token = %q\n", l.Token)
	fmt.Fprintf(&b, "transport.tcpMux = true\ntransport.maxPoolCount = 50\ntransport.heartbeatTimeout = 90\n")
	fmt.Fprintf(&b, "maxPortsPerClient = %d\n", len(l.Ports)*2)
	b.WriteString("log.to = \"console\"\nlog.level = \"warn\"\n")
	b.WriteString("allowPorts = [\n")
	for _, p := range l.Ports {
		fmt.Fprintf(&b, "  { single = %d },\n", p)
	}
	b.WriteString("]\n")
	// every proxy the customer's frpc registers is checked by the panel: only
	// tcp (and udp when sold) on the sold ports. stcp/sudp/xtcp would carry
	// traffic over the control port, which is neither billed nor capped.
	fmt.Fprintf(&b, "\n[[httpPlugins]]\nname = \"hashem\"\naddr = \"127.0.0.1:%d\"\npath = \"/_hsplugin/%s\"\nops = [\"NewProxy\"]\n\n", cfg.Port, custPluginKey(l.Token))
	return b.String()
}

// custFrpcConf is the foreign end of a link (the kit carries the same).
func custFrpcConf(c customer, l customerLink, addr string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Hashem: tunnel to %s (%s, link %d)\n", addr, custUnit(c.ID, l.ID), l.ID)
	fmt.Fprintf(&b, "serverAddr = %q\nserverPort = %d\n", addr, l.CtrlPort)
	fmt.Fprintf(&b, "auth.method = \"token\"\nauth.token = %q\n", l.Token)
	fmt.Fprintf(&b, "loginFailExit = false\n")
	fmt.Fprintf(&b, "transport.protocol = %q\ntransport.tcpMux = true\ntransport.poolCount = 10\n", l.Transport)
	fmt.Fprintf(&b, "transport.heartbeatInterval = 30\ntransport.heartbeatTimeout = 90\n")
	b.WriteString("log.to = \"console\"\nlog.level = \"warn\"\n")
	for _, p := range l.Ports {
		fmt.Fprintf(&b, "\n[[proxies]]\nname = \"tcp-%d\"\ntype = \"tcp\"\nlocalIP = \"127.0.0.1\"\nlocalPort = %d\nremotePort = %d\n", p, p, p)
		if l.UDP {
			fmt.Fprintf(&b, "\n[[proxies]]\nname = \"udp-%d\"\ntype = \"udp\"\nlocalIP = \"127.0.0.1\"\nlocalPort = %d\nremotePort = %d\n", p, p, p)
		}
	}
	return b.String()
}

// custUnitFile has no [Install]: only the panel starts it, after the chain
// that counts it is loaded (also after a reboot).
func custUnitFile(cid, lid int) string {
	return fmt.Sprintf(`[Unit]
Description=Hashem sold tunnel: customer %d, link %d
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s -c %s
Restart=always
RestartSec=3
LimitNOFILE=1048576
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictNamespaces=true
LockPersonality=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
`, cid, lid, custBin(), custConfPath(cid, lid))
}

// custWriteFile writes path when its content differs; it says whether it did.
func custWriteFile(path, content string, mode os.FileMode) (bool, error) {
	if old, err := os.ReadFile(path); err == nil && string(old) == content {
		return false, nil
	}
	return true, writeFileAtomic(path, []byte(content), mode)
}

// custEnsureBin keeps custBin a copy of the installed frps: a missing copy is
// made, one of another size (frps was updated) replaced. It says whether the
// copy changed (running units then restart).
func custEnsureBin() (bool, error) {
	src, err := os.Stat(custFrpsSrc)
	if err != nil {
		if _, err2 := os.Stat(custBin()); err2 == nil {
			return false, nil // the copy alone is enough
		}
		return false, fmt.Errorf("frps is not installed on this server (%s): install the FRP engine first (hashem menu, or set up any FRP tunnel)", custFrpsSrc)
	}
	if dst, err := os.Stat(custBin()); err == nil && dst.Size() == src.Size() && dst.Mode()&0o111 != 0 {
		return false, nil
	}
	data, err := os.ReadFile(custFrpsSrc)
	if err != nil {
		return false, err
	}
	if err := os.MkdirAll(custBinDir, 0o755); err != nil {
		return false, err
	}
	tmp := custBin() + ".new"
	if err := os.WriteFile(tmp, data, 0o755); err != nil {
		return false, err
	}
	return true, os.Rename(tmp, custBin())
}

// custRemoveLinkFiles stops a link's unit and deletes its unit and config.
// It holds custTickMu: a tick that read the list before the removal must not
// write the files back and start the unit again.
func custRemoveLinkFiles(cid, lid int) {
	custTickMu.Lock()
	defer custTickMu.Unlock()
	custRemoveUnitLocked(custUnit(cid, lid), custUnitPath(cid, lid), custConfPath(cid, lid))
}

func custRemoveUnitLocked(u, unitPath, confPath string) {
	_ = runSystemctl("disable", "--now", u+".service")
	_ = os.Remove(unitPath)
	_ = os.Remove(confPath)
	_ = runSystemctl("daemon-reload")
	delete(custApplied.running, u)
}

// custSweepUnits removes hsell units on disk that no customer has (a crash
// between saving customers.json and removing a unit, or a hand-made copy).
func custSweepUnits(list []customer) {
	known := map[string]bool{}
	for _, c := range list {
		for _, l := range c.Links {
			known[custUnit(c.ID, l.ID)] = true
		}
	}
	files, _ := filepath.Glob(filepath.Join(engineUnitDir, "hsell-*.service"))
	for _, f := range files {
		u := strings.TrimSuffix(filepath.Base(f), ".service")
		var cid, lid int
		if _, err := fmt.Sscanf(u, "hsell-%d-%d", &cid, &lid); err != nil || known[u] || custUnit(cid, lid) != u {
			continue
		}
		custRemoveUnitLocked(u, f, custConfPath(cid, lid))
	}
}

// ---- kernel rules ----

func custComment(cid int, out bool) string {
	if out {
		return fmt.Sprintf("hsell-%d-out", cid)
	}
	return fmt.Sprintf("hsell-%d-in", cid)
}

// custRules renders the chain as iptables-restore input.
func custRules(list []customer) string {
	var b strings.Builder
	fmt.Fprintf(&b, "*filter\n:%s - [0:0]\n-F %s\n", custChain, custChain)
	for _, c := range list {
		target := ""
		if c.Cut != "" {
			target = " -j DROP"
		}
		for _, l := range c.Links {
			protos := []string{"tcp"}
			if l.UDP {
				protos = append(protos, "udp")
			}
			for _, p := range l.Ports {
				for _, proto := range protos {
					fmt.Fprintf(&b, "-A %s -p %s -m %s --dport %d -m comment --comment %s%s\n", custChain, proto, proto, p, custComment(c.ID, false), target)
					fmt.Fprintf(&b, "-A %s -p %s -m %s --sport %d -m comment --comment %s%s\n", custChain, proto, proto, p, custComment(c.ID, true), target)
				}
			}
		}
	}
	b.WriteString("COMMIT\n")
	return b.String()
}

// custRuleKey normalises one chain rule ("-A HASHEM_CUST ...", without
// counters) to proto/direction/port/comment/target, so the kernel's rules
// compare with the wanted ones whatever order iptables-save prints.
func custRuleKey(rule string) string {
	f := strings.Fields(rule)
	var proto, dir, port, comment, target string
	for i := 0; i+1 < len(f); i++ {
		switch f[i] {
		case "-p":
			proto = f[i+1]
		case "--dport", "--sport":
			dir, port = f[i], f[i+1]
		case "--comment":
			comment = strings.Trim(f[i+1], `"`)
		case "-j":
			target = f[i+1]
		}
	}
	return strings.Join([]string{proto, dir, port, comment, target}, " ")
}

// custWantKeys are the rule keys of custRules' output, in order.
func custWantKeys(text string) []string {
	var out []string
	for _, l := range strings.Split(text, "\n") {
		if strings.HasPrefix(l, "-A "+custChain+" ") {
			out = append(out, custRuleKey(l))
		}
	}
	return out
}

// parseCustSave reads the byte counters of the chain's rules from
// `iptables-save -c` output, by comment, and whether the chain and its two
// jumps exist.
func parseCustSave(out string) (map[string]uint64, bool) {
	m, _, ok := parseCustSaveRules(out)
	return m, ok
}

// parseCustSaveRules is parseCustSave plus the chain's rule keys in order.
func parseCustSaveRules(out string) (map[string]uint64, []string, bool) {
	m := map[string]uint64{}
	var keys []string
	chain, hooks := false, 0
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, ":"+custChain+" ") {
			chain = true
			continue
		}
		if !strings.HasPrefix(line, "[") {
			continue
		}
		end := strings.Index(line, "]")
		if end < 0 {
			continue
		}
		rule := strings.TrimSpace(line[end+1:])
		switch rule {
		case "-A INPUT -j " + custChain, "-A OUTPUT -j " + custChain:
			hooks++
			continue
		}
		if !strings.HasPrefix(rule, "-A "+custChain+" ") {
			continue
		}
		keys = append(keys, custRuleKey(rule))
		_, bytesStr, _ := strings.Cut(line[1:end], ":")
		n, err := strconv.ParseUint(bytesStr, 10, 64)
		if err != nil {
			continue
		}
		f := strings.Fields(rule)
		for i := 0; i+1 < len(f); i++ {
			if f[i] == "--comment" {
				m[strings.Trim(f[i+1], `"`)] += n
				break
			}
		}
	}
	return m, keys, chain && hooks == 2
}

func custLoadChain(rules string) error {
	_ = os.MkdirAll(configDir, 0o700)
	f := filepath.Join(configDir, "customers.v4")
	if err := os.WriteFile(f, []byte(rules), 0o600); err != nil {
		return err
	}
	if out, err := custRun("iptables-restore", "-w", "5", "-n", f); err != nil {
		return fmt.Errorf("iptables-restore: %s", strings.TrimSpace(string(out)))
	}
	for _, h := range []string{"INPUT", "OUTPUT"} {
		if _, err := custRun("iptables", "-w", "5", "-C", h, "-j", custChain); err != nil {
			if out, err := custRun("iptables", "-w", "5", "-I", h, "1", "-j", custChain); err != nil {
				return fmt.Errorf("iptables -I %s: %s", h, strings.TrimSpace(string(out)))
			}
		}
	}
	return nil
}

func custDropChain() {
	for _, h := range []string{"INPUT", "OUTPUT"} {
		_, _ = custRun("iptables", "-w", "5", "-D", h, "-j", custChain)
	}
	_, _ = custRun("iptables", "-w", "5", "-F", custChain)
	_, _ = custRun("iptables", "-w", "5", "-X", custChain)
}

// custTCArgs are the tc commands for the speed caps (Mbit/s by customer):
// the two shared police actions per customer, then one filter per user port
// and direction pointing at them. The burst is 500 ms at the rate (at least
// 64 KB), as for the per-server limits.
func custTCArgs(ifname string, list []customer) [][]string {
	var cmds [][]string
	for _, c := range list {
		if c.RateMbit <= 0 || c.Cut != "" {
			continue
		}
		var ports []int
		for _, l := range c.Links {
			ports = append(ports, l.Ports...)
		}
		if len(ports) == 0 {
			continue
		}
		kbit := int64(math.Round(c.RateMbit * 1000))
		burst := kbit * 1000 / 8 / 2
		if burst < 65536 {
			burst = 65536
		}
		for _, out := range []bool{true, false} {
			cmds = append(cmds, []string{"actions", "replace", "action", "police", "rate", fmt.Sprintf("%dkbit", kbit), "burst", strconv.FormatInt(burst, 10),
				"mtu", "65535", "conform-exceed", "drop/pass", "index", strconv.Itoa(custPoliceIndex(c.ID, out))})
		}
		sort.Ints(ports)
		for _, p := range ports {
			for _, d := range []struct {
				hook, field string
				out         bool
			}{{"egress", "sport", true}, {"ingress", "dport", false}} {
				cmds = append(cmds, []string{"filter", "add", "dev", ifname, d.hook, "pref", custTCPref, "protocol", "ip", "u32",
					"match", "ip", d.field, strconv.Itoa(p), "0xffff", "action", "police", "index", strconv.Itoa(custPoliceIndex(c.ID, d.out))})
			}
		}
	}
	return cmds
}

// custTCPolice lists the police indexes custTCArgs creates.
func custTCPolice(cmds [][]string) []int {
	var out []int
	for _, c := range cmds {
		if c[0] == "actions" {
			n, _ := strconv.Atoi(c[len(c)-1])
			out = append(out, n)
		}
	}
	return out
}

func custTCClear(ifname string, police []int) {
	if ifname != "" {
		for _, dir := range []string{"egress", "ingress"} {
			for _, pref := range []string{custTCPref, custTCPref6} {
				_, _ = custRun("tc", "filter", "del", "dev", ifname, dir, "pref", pref)
			}
		}
	}
	for _, n := range police {
		_, _ = custRun("tc", "actions", "del", "action", "police", "index", strconv.Itoa(n))
	}
}

func custTCApply(ifname string, cmds [][]string) error {
	custTCClear(ifname, custApplied.police)
	custApplied.police = nil
	if len(cmds) == 0 {
		return nil
	}
	if out, err := custRun("tc", "qdisc", "show", "dev", ifname); err != nil || !strings.Contains(string(out), "clsact") {
		if out, err := custRun("tc", "qdisc", "add", "dev", ifname, "clsact"); err != nil {
			return fmt.Errorf("tc qdisc add clsact: %s", strings.TrimSpace(string(out)))
		}
	}
	custApplied.police = custTCPolice(cmds)
	for _, c := range cmds {
		if out, err := custRun("tc", c...); err != nil {
			custTCClear(ifname, custApplied.police)
			custApplied.police = nil
			return fmt.Errorf("tc %s: %s", strings.Join(c[:4], " "), strings.TrimSpace(string(out)))
		}
	}
	return nil
}

func custTCFilters(cmds [][]string) int {
	n := 0
	for _, c := range cmds {
		if c[0] == "filter" {
			n++
		}
	}
	return n
}

// ---- the tick ----

type custEvent struct {
	cid       int
	name, why string
	to        string
}

// customersTick counts usage, cuts customers whose plan ended or whose volume
// is used up, and keeps the kernel rules, the configs and the units in step.
// Runs every 10 s and after every change.
func customersTick(now time.Time) {
	custTickMu.Lock()
	defer custTickMu.Unlock()

	custs.Lock()
	custLoadLocked()
	n, loadErr := len(custs.f.Customers), custs.loadErr
	if loadErr != "" {
		custs.err = loadErr
	}
	custs.Unlock()
	if loadErr != "" {
		return // the rules and units stay as they are
	}
	if n == 0 {
		if custApplied.ipt != "" || !custApplied.cleaned {
			custDropChain()
			custTCClear(custApplied.tcIf, custApplied.police)
			if ifn := custIface(); ifn != custApplied.tcIf {
				custTCClear(ifn, nil)
			}
			custApplied.ipt, custApplied.tc, custApplied.tcIf, custApplied.police, custApplied.cleaned = "", "", "", nil, true
		}
		if !custApplied.swept {
			custApplied.swept = true
			custSweepUnits(nil)
			custSweepPolice()
		}
		custReservePorts()
		custs.Lock()
		custs.err = ""
		custs.Unlock()
		return
	}
	custApplied.cleaned = false

	out, saveErr := custSaveOut()
	counters, kernelKeys, ready := parseCustSaveRules(string(out))

	var events []custEvent
	custs.Lock()
	elapsed := now.Sub(custs.at).Seconds()
	first := custs.at.IsZero()
	custs.at = now
	last := custs.f.Counters
	for i := range custs.f.Customers {
		c := &custs.f.Customers[i]
		var d [2]uint64
		for j, out := range []bool{false, true} {
			k := custComment(c.ID, out)
			cur, ok := counters[k]
			prev := last[k]
			if ok {
				if cur >= prev {
					d[j] = cur - prev
				} else {
					d[j] = cur // the chain was rebuilt since
				}
				if last[k] != cur {
					last[k], custs.dirty = cur, true
				}
			}
		}
		// the saved counters make the first tick after a restart exact too
		if saveErr == nil && c.Cut == "" {
			c.UsedRx += d[0]
			c.UsedTx += d[1]
			if d[0]+d[1] > 0 {
				custs.dirty = true
			}
		}
		if elapsed > 0 && !first {
			custs.speed[c.ID] = [2]float64{float64(d[0]) / elapsed, float64(d[1]) / elapsed}
		}
		if c.Cut == "" && c.ExpiresAt > 0 && now.Unix() >= c.ExpiresAt {
			c.Cut, custs.dirty = "expired", true
			events = append(events, custEvent{c.ID, c.Name, "plan ended " + time.Unix(c.ExpiresAt, 0).Format("2006-01-02 15:04"), "cut"})
		}
		if q := c.quotaBytes(); q > 0 && c.Cut == "" {
			if c.used() >= q {
				c.Cut, custs.dirty = "quota", true
				events = append(events, custEvent{c.ID, c.Name, fmt.Sprintf("volume used up: %s of %s", fmtBytesDec(c.used()), fmtBytesDec(q)), "cut"})
			} else if !c.Warned && c.used() >= q/10*9 {
				c.Warned, custs.dirty = true, true
				events = append(events, custEvent{c.ID, c.Name, fmt.Sprintf("%s of %s", fmtBytesDec(c.used()), fmtBytesDec(q)), "90% used"})
			}
		}
	}
	list := cloneCustomersFile(custs.f).Customers
	custs.Unlock()
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })

	var errs []string
	if saveErr != nil {
		errs = append(errs, "iptables-save: "+saveErr.Error())
	}
	text := custRules(list)
	// the kernel's chain is checked rule by rule, not only that it exists:
	// a flushed chain would bill nothing and cut nobody
	chainOK := saveErr == nil && ready && strings.Join(kernelKeys, "\n") == strings.Join(custWantKeys(text), "\n")
	if saveErr == nil && !chainOK {
		if err := custLoadChain(text); err != nil {
			errs = append(errs, err.Error())
			custApplied.ipt = ""
		} else {
			custApplied.ipt, chainOK = text, true
			custs.Lock()
			for k := range custs.f.Counters {
				custs.f.Counters[k] = 0 // the rebuilt chain counts from zero
			}
			custs.dirty = true
			custs.Unlock()
		}
	} else if chainOK {
		custApplied.ipt = text
	}
	if !custApplied.swept {
		custApplied.swept = true
		custSweepUnits(list)
		custSweepPolice()
	}
	custReservePorts()

	ifname := custIface()
	if ifname == "" {
		for _, c := range list {
			if c.RateMbit > 0 && c.Cut == "" {
				errs = append(errs, "no default-route interface: speed caps not applied")
				break
			}
		}
	} else {
		cmds := custTCArgs(ifname, list)
		sig := fmt.Sprint(cmds)
		if ifname != custApplied.tcIf && custApplied.tcIf != "" {
			custTCClear(custApplied.tcIf, custApplied.police)
			custApplied.police, custApplied.tc = nil, ""
		}
		check := now.Sub(custApplied.tcCheck) > time.Minute
		if check {
			custApplied.tcCheck = now
		}
		if sig != custApplied.tc || ifname != custApplied.tcIf || (check && tcFiltersPresent(ifname, custTCPref, custTCPref6) != custTCFilters(cmds)) {
			if err := custTCApply(ifname, cmds); err != nil {
				errs = append(errs, err.Error())
				custApplied.tc = ""
			} else {
				custApplied.tc, custApplied.tcIf = sig, ifname
			}
		}
	}

	if err := custSyncUnits(list, chainOK); err != nil {
		errs = append(errs, err.Error())
	}

	custs.Lock()
	custs.err = strings.Join(errs, "; ")
	// saved every tick that counted something: the usage and the counters
	// it came from go to disk together
	if custs.dirty {
		if err := custSaveLocked(); err != nil {
			custs.err = strings.TrimPrefix(custs.err+"; save customers.json: "+err.Error(), "; ")
		}
	}
	custs.Unlock()
	for _, e := range events {
		custAlert(e)
	}
}

// custSweepPolice removes police actions in the customers' index range that
// no filter uses (a cap left by a panel that stopped mid-change).
func custSweepPolice() {
	out, err := custRun("tc", "actions", "ls", "action", "police")
	if err != nil {
		return
	}
	f := strings.Fields(string(out))
	for i := 0; i+1 < len(f); i++ {
		if f[i] != "index" {
			continue
		}
		n, err := strconv.Atoi(f[i+1])
		if err != nil || n < custPoliceBase || n > custPoliceBase+0xffff || hasInt(custApplied.police, n) {
			continue
		}
		_, _ = custRun("tc", "actions", "del", "action", "police", "index", strconv.Itoa(n))
	}
}

// custReservedPath lists the ports Hashem's configs take, for hashem.sh's
// reserve_service_ports (net.ipv4.ip_local_reserved_ports).
func custReservedPath() string { return filepath.Join(configDir, "ports.reserved") }

// custReserveSysctl is the kernel's reserved port list (swappable for tests).
var custReserveSysctl = "/proc/sys/net/ipv4/ip_local_reserved_ports"

// custReservePorts keeps every claimed port (sold ones included) out of the
// ephemeral range: the server's own outgoing connections never take a sold
// port as their source port, so they are never billed to a customer or cut
// with them. It adds to the kernel's list, never removes from it.
func custReservePorts() {
	seen := map[int]bool{}
	var ports []int
	for _, c := range hashemPortClaims() {
		if c.Port >= 1024 && !seen[c.Port] {
			seen[c.Port] = true
			ports = append(ports, c.Port)
		}
	}
	sort.Ints(ports)
	strs := make([]string, len(ports))
	for i, p := range ports {
		strs[i] = strconv.Itoa(p)
	}
	sig := strings.Join(strs, ",")
	if sig == custApplied.reserved {
		return
	}
	_ = writeFileAtomic(custReservedPath(), []byte(strings.Join(strs, "\n")+"\n"), 0o644)
	cur, err := os.ReadFile(custReserveSysctl)
	if err != nil {
		custApplied.reserved = sig
		return
	}
	merged := strings.TrimSpace(string(cur))
	have := map[int]bool{}
	for _, part := range strings.Split(merged, ",") {
		lo, hi, rng := strings.Cut(strings.TrimSpace(part), "-")
		a, err1 := strconv.Atoi(lo)
		b := a
		var err2 error
		if rng {
			b, err2 = strconv.Atoi(hi)
		}
		if err1 != nil || err2 != nil || b-a > 65535 {
			continue
		}
		for p := a; p <= b; p++ {
			have[p] = true
		}
	}
	var add []string
	for _, p := range ports {
		if !have[p] {
			add = append(add, strconv.Itoa(p))
		}
	}
	if len(add) > 0 {
		if merged != "" {
			merged += ","
		}
		if err := os.WriteFile(custReserveSysctl, []byte(merged+strings.Join(add, ",")), 0o644); err != nil {
			return // retried next tick
		}
	}
	custApplied.reserved = sig
}

// custSyncUnits writes each link's config and unit and starts the units of
// running customers (only while the chain counts them), stopping the rest.
func custSyncUnits(list []customer, chainOK bool) error {
	if custApplied.running == nil {
		custApplied.running = map[string]bool{}
	}
	var errs []string
	binChanged, binErr := false, error(nil)
	want := map[string]bool{}
	reload := false
	restart := map[string]bool{}
	for _, c := range list {
		for _, l := range c.Links {
			u := custUnit(c.ID, l.ID)
			// a new unit waits for the chain that counts it; one already
			// running keeps running through a failed reload (a cut stops it)
			want[u] = c.Cut == "" && (chainOK || custApplied.running[u])
			changed, err := custWriteFile(custConfPath(c.ID, l.ID), custFrpsConf(l), 0o600)
			if err != nil {
				errs = append(errs, u+": "+err.Error())
				want[u] = false
				continue
			}
			uc, err := custWriteFile(custUnitPath(c.ID, l.ID), custUnitFile(c.ID, l.ID), 0o644)
			if err != nil {
				errs = append(errs, u+": "+err.Error())
				want[u] = false
				continue
			}
			reload = reload || uc
			restart[u] = changed || uc
		}
	}
	anyWanted := false
	for _, w := range want {
		anyWanted = anyWanted || w
	}
	if anyWanted {
		binChanged, binErr = custEnsureBin()
		if binErr != nil {
			errs = append(errs, binErr.Error())
		}
	}
	if reload {
		_ = runSystemctl("daemon-reload")
	}
	units := make([]string, 0, len(want))
	for u := range want {
		units = append(units, u)
	}
	sort.Strings(units)
	for _, u := range units {
		w := want[u] && binErr == nil
		running, known := custApplied.running[u]
		switch {
		case w && (!known || !running):
			if err := runSystemctl("start", u+".service"); err != nil {
				errs = append(errs, "start "+u+": "+err.Error())
				continue
			}
			custApplied.running[u] = true
		case w && (restart[u] || binChanged):
			if err := runSystemctl("restart", u+".service"); err != nil {
				errs = append(errs, "restart "+u+": "+err.Error())
			}
		case !w && (!known || running):
			_ = runSystemctl("stop", u+".service")
			custApplied.running[u] = false
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

// sendCustomerAlert sends a cut or a warning through the panel's alerts.
func sendCustomerAlert(e custEvent) {
	cfg := loadAlertConfig()
	if !cfg.Enabled {
		return
	}
	go alertSend(cfg, []alertEvent{{Link: "customer " + e.name, From: "customer", To: e.to, Why: e.why, At: time.Now().UTC().Format(time.RFC3339)}})
}

func startCustomersLoop() {
	customersTick(time.Now())
	t := time.NewTicker(10 * time.Second)
	for now := range t.C {
		customersTick(now)
	}
}

// ---- validation ----

var custTokenRe = regexp.MustCompile(`^[A-Za-z0-9]{24,64}$`)

func custCleanText(s string, max int) (string, error) {
	s = strings.TrimSpace(s)
	if len([]rune(s)) > max {
		return "", fmt.Errorf("at most %d characters", max)
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return "", fmt.Errorf("no control characters")
		}
	}
	return s, nil
}

func custValidatePlan(quotaGB, rateMbit float64, days int) error {
	if rateMbit < 0 || rateMbit > 100000 || (rateMbit > 0 && rateMbit < 0.1) {
		return fmt.Errorf("speed: 0.1 to 100000 Mbit/s, or 0 for unlimited")
	}
	if quotaGB < 0 || quotaGB > 1e6 || (quotaGB > 0 && quotaGB < 0.01) {
		return fmt.Errorf("volume: 0.01 to 1000000 GB, or 0 for unlimited")
	}
	if days < 0 || days > 3660 {
		return fmt.Errorf("days: 1 to 3660, or 0 for no end date")
	}
	return nil
}

// custLinkInput is a link as the API takes it.
type custLinkInput struct {
	Name      string `json:"name"`
	Transport string `json:"transport"`
	CtrlPort  int    `json:"ctrl_port"`
	Ports     string `json:"ports"`
	UDP       bool   `json:"udp"`
}

// custBuildLink validates in and returns the link (cid, lid set); old is the
// link it replaces (nil for a new one). claims are every other claim.
func custBuildLink(in custLinkInput, cid, lid int, old *customerLink, claims []portClaim) (customerLink, error) {
	l := customerLink{ID: lid, Engine: "frp", Transport: strings.ToLower(strings.TrimSpace(in.Transport)), UDP: in.UDP}
	if l.Transport == "" {
		l.Transport = "tcp"
	}
	if !custTransports[l.Transport] {
		return l, fmt.Errorf("transport: tcp, kcp, quic or websocket")
	}
	var err error
	if l.Name, err = custCleanText(in.Name, 40); err != nil {
		return l, fmt.Errorf("server name: %v", err)
	}
	if strings.TrimSpace(in.Ports) == "" {
		return l, fmt.Errorf("at least one user port is required (e.g. 443, 2083)")
	}
	for _, f := range strings.FieldsFunc(in.Ports, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' }) {
		if _, ok := portNum(f); !ok {
			return l, fmt.Errorf("%q is not a port (1-65535)", f)
		}
	}
	l.Ports = parsePorts(in.Ports)
	if len(l.Ports) > custMaxPorts {
		return l, fmt.Errorf("at most %d ports per foreign server", custMaxPorts)
	}
	sort.Ints(l.Ports)
	if old != nil {
		l.Token = old.Token
	} else {
		l.Token = randomToken(32)
	}

	l.CtrlPort = in.CtrlPort
	if l.CtrlPort == 0 && old != nil {
		l.CtrlPort = old.CtrlPort
	}
	ctrlProto := "tcp"
	if l.Transport == "kcp" || l.Transport == "quic" {
		ctrlProto = "udp"
	}
	idx := indexClaims(claims)
	free := func(proto string, p int, mine []int) string {
		if owner := idx.owner(proto, p, nil); owner != "" {
			return "used by " + owner
		}
		if !hasInt(mine, p) && custPortBusy(proto, p) {
			return "held by another program on this server"
		}
		return ""
	}
	var oldPorts []int
	oldCtrl := 0
	if old != nil {
		oldPorts, oldCtrl = old.Ports, old.CtrlPort
	}
	if l.CtrlPort == 0 {
		for i := 0; i < 200 && l.CtrlPort == 0; i++ {
			p := 20000 + rand.IntN(40000)
			if hasInt(l.Ports, p) || free("tcp", p, nil) != "" || (ctrlProto == "udp" && free("udp", p, nil) != "") {
				continue
			}
			l.CtrlPort = p
		}
		if l.CtrlPort == 0 {
			return l, fmt.Errorf("no free control port found: give one")
		}
	} else {
		if _, ok := portNum(strconv.Itoa(l.CtrlPort)); !ok {
			return l, fmt.Errorf("control port: 1-65535")
		}
		if hasInt(l.Ports, l.CtrlPort) {
			return l, fmt.Errorf("control port %d is also a user port", l.CtrlPort)
		}
		for _, proto := range []string{"tcp", ctrlProto} {
			if why := free(proto, l.CtrlPort, []int{oldCtrl}); why != "" {
				return l, fmt.Errorf("control port %d is %s", l.CtrlPort, why)
			}
		}
	}
	for _, p := range l.Ports {
		protos := []string{"tcp"}
		if l.UDP {
			protos = append(protos, "udp")
		}
		for _, proto := range protos {
			if why := free(proto, p, oldPorts); why != "" {
				return l, fmt.Errorf("%s port %d is %s", strings.ToUpper(proto), p, why)
			}
		}
	}
	_ = cid
	return l, nil
}

// custClaimsExcept are every claim but one link's own (lid 0: none skipped).
func custClaimsExcept(cid, lid int) []portClaim {
	var out []portClaim
	for _, c := range hashemPortClaims() {
		if c.Kind == claimCustomer && c.Ref == cid && c.Sub == lid {
			continue
		}
		out = append(out, c)
	}
	return out
}

// ---- API ----

type custLinkView struct {
	customerLink
	Unit   string `json:"unit"`
	Active bool   `json:"active"`
	Linked bool   `json:"linked"` // the foreign server holds a session on the control port
}

type custView struct {
	customer
	Links    []custLinkView `json:"links"`
	SpeedRx  float64        `json:"speed_rx"`
	SpeedTx  float64        `json:"speed_tx"`
	DaysLeft *int           `json:"days_left"` // nil: no end date
	Status   string         `json:"status_path"`
}

// custUnitsActive asks systemd which of units are active.
var custUnitsActive = func(units []string) map[string]bool {
	m := map[string]bool{}
	if len(units) == 0 {
		return m
	}
	out, _ := runCmdTimeoutOut(5*time.Second, "systemctl", append([]string{"is-active"}, units...)...)
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for i, u := range units {
		m[u] = i < len(lines) && strings.TrimSpace(lines[i]) == "active"
	}
	return m
}

// custSS caches `ss` for 5 s: the public status page must not fork a process
// per request.
var custSS = struct {
	sync.Mutex
	at  time.Time
	out []byte
}{}

// custLinked lists the control ports that hold an established session.
var custLinked = func(ports []int) map[int]bool {
	m := map[int]bool{}
	if len(ports) == 0 {
		return m
	}
	custSS.Lock()
	if time.Since(custSS.at) > 5*time.Second {
		custSS.out, _ = runCmdTimeoutOut(5*time.Second, "ss", "-Htn", "state", "established")
		custSS.at = time.Now()
	}
	out := custSS.out
	custSS.Unlock()
	want := map[int]bool{}
	for _, p := range ports {
		want[p] = true
	}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		local := f[len(f)-2]
		if i := strings.LastIndex(local, ":"); i >= 0 {
			if p, err := strconv.Atoi(local[i+1:]); err == nil && want[p] {
				m[p] = true
			}
		}
	}
	return m
}

func daysLeft(expires int64, now time.Time) *int {
	if expires <= 0 {
		return nil
	}
	d := int(math.Ceil(float64(expires-now.Unix()) / 86400))
	if d < 0 {
		d = 0
	}
	return &d
}

func customersView() map[string]any {
	now := time.Now()
	custs.Lock()
	custLoadLocked()
	list := cloneCustomersFile(custs.f).Customers
	speed := map[int][2]float64{}
	for k, v := range custs.speed {
		speed[k] = v
	}
	errText := custs.err
	custs.Unlock()

	var units []string
	var ctrl []int
	for _, c := range list {
		for _, l := range c.Links {
			units = append(units, custUnit(c.ID, l.ID)+".service")
			ctrl = append(ctrl, l.CtrlPort)
		}
	}
	active := custUnitsActive(units)
	linked := custLinked(ctrl)
	views := make([]custView, 0, len(list))
	for _, c := range list {
		v := custView{customer: c, SpeedRx: speed[c.ID][0], SpeedTx: speed[c.ID][1], DaysLeft: daysLeft(c.ExpiresAt, now), Status: "/_hs/" + c.Token}
		v.Links = []custLinkView{}
		for _, l := range c.Links {
			lv := custLinkView{customerLink: l, Unit: custUnit(c.ID, l.ID)}
			lv.Token = ""
			lv.Active = active[lv.Unit+".service"]
			lv.Linked = lv.Active && linked[l.CtrlPort]
			v.Links = append(v.Links, lv)
		}
		v.customer.Links = nil
		views = append(views, v)
	}
	_, binErr := os.Stat(custFrpsSrc)
	_, copyErr := os.Stat(custBin())
	return map[string]any{
		"customers": views, "licensed": hasPro(proCustomers), "error": errText,
		"address": custDefaultAddress(), "frps_ok": binErr == nil || copyErr == nil,
	}
}

func custDefaultAddress() string { return detectPublicIPCached() }

func handleCustomersGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, customersView())
}

type custRequest struct {
	Action     string          `json:"action"`
	ID         int             `json:"id"`
	LinkID     int             `json:"link_id"`
	Name       string          `json:"name"`
	Note       string          `json:"note"`
	Address    string          `json:"address"`
	Days       int             `json:"days"`
	QuotaGB    float64         `json:"quota_gb"`
	RateMbit   float64         `json:"rate_mbit"`
	ResetUsage *bool           `json:"reset_usage"`
	Links      []custLinkInput `json:"links"`
	Link       *custLinkInput  `json:"link"`
}

// custFreeActions work without a license: they only take service away.
var custFreeActions = map[string]bool{"cut": true, "remove": true, "link-remove": true}

func handleCustomersPost(w http.ResponseWriter, r *http.Request) {
	var req custRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeAPIError(w, r, "E-CUST-01", "invalid json")
		return
	}
	if !custFreeActions[req.Action] && proRequired(w, r, proCustomers, proCustomersTxt) {
		return
	}
	custs.Lock()
	custLoadLocked()
	loadErr := custs.loadErr
	custs.Unlock()
	if loadErr != "" {
		writeAPIError(w, r, "E-CUST-06", loadErr)
		return
	}
	// bill what passed up to now before a cut, a reset or a removal
	customersTick(time.Now())
	code, err, removed, created := customersApply(req, time.Now())
	if err != nil {
		writeAPIError(w, r, code, err.Error())
		return
	}
	for _, x := range removed {
		custRemoveLinkFiles(x[0], x[1])
	}
	customersTick(time.Now())
	v := customersView()
	if req.Action == "create" {
		v["created"] = created
	}
	writeJSON(w, v)
}

// customersApply changes customers.json for one request. It returns the
// links whose units must go (customer, link).
func customersApply(req custRequest, now time.Time) (code string, err error, removed [][2]int, created int) {
	custAPIMu.Lock()
	defer custAPIMu.Unlock()
	custs.Lock()
	custLoadLocked()
	custs.Unlock()

	var c *customer
	find := func() error {
		custs.Lock()
		defer custs.Unlock()
		if custFindLocked(req.ID) == nil {
			return fmt.Errorf("no customer %d", req.ID)
		}
		return nil
	}
	if req.Action != "create" {
		if err := find(); err != nil {
			return "E-CUST-04", err, nil, 0
		}
	}

	// claims are built outside custs' lock: customerPortClaims takes it
	var claims []portClaim
	needClaims := req.Action == "create" || req.Action == "link-add" || req.Action == "link-update"
	if needClaims {
		skipCID, skipLID := 0, 0
		if req.Action == "link-update" {
			skipCID, skipLID = req.ID, req.LinkID
		}
		claims = custClaimsExcept(skipCID, skipLID)
	}

	custs.Lock()
	defer custs.Unlock()
	snapshot := cloneCustomersFile(custs.f)
	if req.Action != "create" {
		c = custFindLocked(req.ID)
		if c == nil {
			return "E-CUST-04", fmt.Errorf("no customer %d", req.ID), nil, 0
		}
	}
	fail := func(code string, e error) (string, error, [][2]int, int) {
		custs.f = snapshot
		return code, e, nil, 0
	}

	switch req.Action {
	case "create":
		if len(custs.f.Customers) >= custMaxCount {
			return fail("E-CUST-02", fmt.Errorf("at most %d customers", custMaxCount))
		}
		id := custNewIDLocked()
		if id == 0 {
			return fail("E-CUST-02", fmt.Errorf("no free customer ID"))
		}
		nc := customer{ID: id, Token: randomToken(32), Created: now.Unix(), PeriodStart: now.Unix()}
		if nc.Name, err = custCleanText(req.Name, 60); err != nil || nc.Name == "" {
			return fail("E-CUST-02", fmt.Errorf("name: 1 to 60 characters, no control characters"))
		}
		if nc.Note, err = custCleanText(req.Note, 500); err != nil {
			return fail("E-CUST-02", fmt.Errorf("note: %v", err))
		}
		if a := strings.TrimSpace(req.Address); a != "" && !custValidAddress(a) {
			return fail("E-CUST-02", fmt.Errorf("address: an IPv4 address or a domain"))
		} else {
			nc.Address = a
		}
		if err := custValidatePlan(req.QuotaGB, req.RateMbit, req.Days); err != nil {
			return fail("E-CUST-02", err)
		}
		nc.QuotaGB, nc.RateMbit, nc.Days = req.QuotaGB, req.RateMbit, req.Days
		if req.Days > 0 {
			nc.ExpiresAt = now.Add(time.Duration(req.Days) * 24 * time.Hour).Unix()
		}
		if len(req.Links) == 0 {
			return fail("E-CUST-02", fmt.Errorf("add at least one foreign server"))
		}
		if len(req.Links) > custMaxLinks {
			return fail("E-CUST-02", fmt.Errorf("at most %d foreign servers per customer", custMaxLinks))
		}
		for i, in := range req.Links {
			l, err := custBuildLink(in, nc.ID, i+1, nil, claims)
			if err != nil {
				return fail("E-CUST-03", fmt.Errorf("foreign server %d: %v", i+1, err))
			}
			claims = append(claims, custLinkClaims(nc, l)...)
			nc.Links = append(nc.Links, l)
		}
		custs.f.Customers = append(custs.f.Customers, nc)
		created = nc.ID

	case "update":
		name, err := custCleanText(req.Name, 60)
		if err != nil || name == "" {
			return fail("E-CUST-02", fmt.Errorf("name: 1 to 60 characters, no control characters"))
		}
		note, err := custCleanText(req.Note, 500)
		if err != nil {
			return fail("E-CUST-02", fmt.Errorf("note: %v", err))
		}
		a := strings.TrimSpace(req.Address)
		if a != "" && !custValidAddress(a) {
			return fail("E-CUST-02", fmt.Errorf("address: an IPv4 address or a domain"))
		}
		if err := custValidatePlan(req.QuotaGB, req.RateMbit, 0); err != nil {
			return fail("E-CUST-02", err)
		}
		c.Name, c.Note, c.Address, c.QuotaGB, c.RateMbit = name, note, a, req.QuotaGB, req.RateMbit
		// a higher volume (or none) reconnects a customer cut for volume
		if q := c.quotaBytes(); c.Cut == "quota" && (q == 0 || c.used() < q) {
			c.Cut = ""
		}
		if q := c.quotaBytes(); q == 0 || c.used() < q/10*9 {
			c.Warned = false
		}

	case "renew":
		days := req.Days
		if days == 0 {
			days = c.Days
		}
		if days < 1 || days > 3660 {
			return fail("E-CUST-02", fmt.Errorf("days: 1 to 3660"))
		}
		from := now
		if c.ExpiresAt > now.Unix() {
			from = time.Unix(c.ExpiresAt, 0)
		}
		c.ExpiresAt = from.Add(time.Duration(days) * 24 * time.Hour).Unix()
		c.Days = days
		if req.ResetUsage == nil || *req.ResetUsage {
			c.UsedRx, c.UsedTx, c.Warned, c.PeriodStart = 0, 0, false, now.Unix()
		}
		if c.Cut == "expired" || (c.Cut == "quota" && (c.quotaBytes() == 0 || c.used() < c.quotaBytes())) {
			c.Cut = ""
		}

	case "cut":
		c.Cut = "manual"

	case "resume":
		switch {
		case c.ExpiresAt > 0 && now.Unix() >= c.ExpiresAt:
			return fail("E-CUST-05", fmt.Errorf("the plan ended: renew it instead"))
		case c.quotaBytes() > 0 && c.used() >= c.quotaBytes():
			return fail("E-CUST-05", fmt.Errorf("the volume is used up: reset the usage, raise the volume or renew"))
		}
		c.Cut = ""

	case "reset":
		c.UsedRx, c.UsedTx, c.Warned, c.PeriodStart = 0, 0, false, now.Unix()
		if c.Cut == "quota" {
			c.Cut = ""
		}

	case "remove":
		for _, l := range c.Links {
			removed = append(removed, [2]int{c.ID, l.ID})
		}
		for i := range custs.f.Customers {
			if custs.f.Customers[i].ID == c.ID {
				custs.f.Customers = append(custs.f.Customers[:i], custs.f.Customers[i+1:]...)
				break
			}
		}

	case "link-add":
		if req.Link == nil {
			return fail("E-CUST-01", fmt.Errorf("link is required"))
		}
		if len(c.Links) >= custMaxLinks {
			return fail("E-CUST-02", fmt.Errorf("at most %d foreign servers per customer", custMaxLinks))
		}
		lid := 1
		for _, l := range c.Links {
			if l.ID >= lid {
				lid = l.ID + 1
			}
		}
		l, err := custBuildLink(*req.Link, c.ID, lid, nil, claims)
		if err != nil {
			return fail("E-CUST-03", err)
		}
		c.Links = append(c.Links, l)

	case "link-update":
		if req.Link == nil {
			return fail("E-CUST-01", fmt.Errorf("link is required"))
		}
		old := c.link(req.LinkID)
		if old == nil {
			return fail("E-CUST-04", fmt.Errorf("customer %d has no foreign server %d", c.ID, req.LinkID))
		}
		l, err := custBuildLink(*req.Link, c.ID, old.ID, old, claims)
		if err != nil {
			return fail("E-CUST-03", err)
		}
		*old = l

	case "link-remove":
		idx := -1
		for i, l := range c.Links {
			if l.ID == req.LinkID {
				idx = i
			}
		}
		if idx < 0 {
			return fail("E-CUST-04", fmt.Errorf("customer %d has no foreign server %d", c.ID, req.LinkID))
		}
		if len(c.Links) == 1 {
			return fail("E-CUST-02", fmt.Errorf("a customer keeps at least one foreign server: remove the customer instead"))
		}
		removed = append(removed, [2]int{c.ID, req.LinkID})
		c.Links = append(c.Links[:idx], c.Links[idx+1:]...)

	default:
		return fail("E-CUST-01", fmt.Errorf("unknown action %q", req.Action))
	}
	if err := custSaveLocked(); err != nil {
		return fail("E-CUST-06", err)
	}
	return "", nil, removed, created
}

// custValidAddress: an IPv4 address or a domain (the relays bind IPv4 only).
func custValidAddress(a string) bool {
	if ip := net.ParseIP(a); ip != nil {
		return ip.To4() != nil
	}
	return validBagherHost(a)
}

// custAPIMu serialises changes: the port checks run before custs is locked.
var custAPIMu sync.Mutex

func cloneCustomersFile(f customersFile) customersFile {
	out := customersFile{NextID: f.NextID, Customers: make([]customer, len(f.Customers)), Counters: map[string]uint64{}}
	for k, v := range f.Counters {
		out.Counters[k] = v
	}
	for i, c := range f.Customers {
		out.Customers[i] = c
		out.Customers[i].Links = make([]customerLink, len(c.Links))
		for j, l := range c.Links {
			out.Customers[i].Links[j] = l
			out.Customers[i].Links[j].Ports = append([]int(nil), l.Ports...)
		}
	}
	return out
}

func custLinkClaims(c customer, l customerLink) []portClaim {
	var out []portClaim
	owner := fmt.Sprintf("customer %s (link %d)", c.Name, l.ID)
	for _, p := range l.Ports {
		out = append(out, portClaim{"tcp", p, claimCustomer, c.ID, l.ID, owner})
		if l.UDP {
			out = append(out, portClaim{"udp", p, claimCustomer, c.ID, l.ID, owner})
		}
	}
	out = append(out, portClaim{"tcp", l.CtrlPort, claimCustomer, c.ID, l.ID, "the control port of " + owner})
	if l.Transport == "kcp" || l.Transport == "quic" {
		out = append(out, portClaim{"udp", l.CtrlPort, claimCustomer, c.ID, l.ID, "the control port of " + owner})
	}
	return out
}

// ---- the kit: what the customer runs on their foreign server ----

// custKit packs a link for tools/hashem-customer.sh: "hsk1." + base64url of
// key=value lines. The installer checks every value against a strict pattern.
func custKit(c customer, l customerLink, addr string) string {
	udp := "0"
	if l.UDP {
		udp = "1"
	}
	ports := make([]string, len(l.Ports))
	for i, p := range l.Ports {
		ports[i] = strconv.Itoa(p)
	}
	body := strings.Join([]string{
		"v=1",
		"name=" + custUnit(c.ID, l.ID),
		"server=" + addr,
		"port=" + strconv.Itoa(l.CtrlPort),
		"transport=" + l.Transport,
		"token=" + l.Token,
		"udp=" + udp,
		"ports=" + strings.Join(ports, ","),
	}, "\n") + "\n"
	return "hsk1." + base64.RawURLEncoding.EncodeToString([]byte(body))
}

// custInstallerURL is the installer of the release this panel is: every
// build's version is its release tag (vX.Y.Z, dev-rN or panel-rN), and each
// of those releases carries tools/hashem-customer.sh.
func custInstallerURL() string {
	return "https://github.com/pdnczone/hashem-panel/releases/download/" + panelVersion + "/hashem-customer.sh"
}

func handleCustomersKit(w http.ResponseWriter, r *http.Request) {
	cid, _ := strconv.Atoi(r.URL.Query().Get("id"))
	lid, _ := strconv.Atoi(r.URL.Query().Get("link"))
	custs.Lock()
	custLoadLocked()
	var c customer
	var l customerLink
	found := false
	if p := custFindLocked(cid); p != nil {
		if q := p.link(lid); q != nil {
			c, l, found = *p, *q, true
		}
	}
	custs.Unlock()
	if !found {
		writeAPIError(w, r, "E-CUST-04", fmt.Sprintf("no foreign server %d for customer %d", lid, cid))
		return
	}
	addr := c.Address
	if addr == "" {
		addr = custDefaultAddress()
	}
	if addr == "" {
		writeAPIError(w, r, "E-CUST-05", "this server's public address is unknown: set the customer's address (IP or domain)")
		return
	}
	kit := custKit(c, l, addr)
	url := custInstallerURL()
	writeJSON(w, map[string]any{
		"kit":       kit,
		"oneliner":  fmt.Sprintf("curl -fsSL %s -o hashem-customer.sh && sudo bash hashem-customer.sh install %s", url, kit),
		"installer": url,
		"frpc_toml": custFrpcConf(c, l, addr),
		"frp":       custFRPVersion,
		"unit":      custUnit(c.ID, l.ID),
		"address":   addr,
		"ports":     l.Ports,
		"ctrl_port": l.CtrlPort,
		"transport": l.Transport,
	})
}

// ---- the frps plugin: which proxies a customer's frpc may open ----

// custPluginKey is the path secret of a link's plugin calls (frps sends it
// from the config; the link token itself never appears in a URL).
func custPluginKey(token string) string {
	h := sha256.Sum256([]byte("hashem-sell-plugin\x00" + token))
	return hex.EncodeToString(h[:16])
}

// custPluginVerdict says why a NewProxy is refused, "" to allow it: tcp on a
// sold port, udp only where UDP is sold. stcp, sudp, xtcp, http, https and
// tcpmux are refused (they would bypass the billing and the speed cap).
func custPluginVerdict(l customerLink, typ string, port int) string {
	switch {
	case typ != "tcp" && typ != "udp":
		return "only tcp and udp proxies are allowed on this tunnel"
	case typ == "udp" && !l.UDP:
		return "UDP is not part of this tunnel"
	case !hasInt(l.Ports, port):
		return fmt.Sprintf("port %d is not part of this tunnel", port)
	}
	return ""
}

// handleCustomerPlugin answers frps's NewProxy calls (POST /_hsplugin/<key>,
// from this server only).
func handleCustomerPlugin(w http.ResponseWriter, r *http.Request) {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		http.NotFound(w, r)
		return
	}
	key := r.PathValue("key")
	var link *customerLink
	custs.Lock()
	custLoadLocked()
	for _, c := range custs.f.Customers {
		for _, l := range c.Links {
			if subtle.ConstantTimeCompare([]byte(custPluginKey(l.Token)), []byte(key)) == 1 {
				ll := l
				link = &ll
			}
		}
	}
	custs.Unlock()
	if link == nil {
		http.NotFound(w, r)
		return
	}
	var req struct {
		Op      string `json:"op"`
		Content struct {
			ProxyType  string `json:"proxy_type"`
			RemotePort int    `json:"remote_port"`
		} `json:"content"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeJSON(w, map[string]any{"reject": true, "reject_reason": "bad request"})
		return
	}
	if req.Op != "NewProxy" {
		writeJSON(w, map[string]any{"reject": false, "unchange": true})
		return
	}
	if why := custPluginVerdict(*link, req.Content.ProxyType, req.Content.RemotePort); why != "" {
		writeJSON(w, map[string]any{"reject": true, "reject_reason": why})
		return
	}
	writeJSON(w, map[string]any{"reject": false, "unchange": true})
}

// ---- the customer's status page data (/_hs/<token>.json) ----

type custPublic struct {
	Name      string   `json:"name"`
	ExpiresAt int64    `json:"expires_at"`
	DaysLeft  *int     `json:"days_left"`
	QuotaGB   float64  `json:"quota_gb"`
	RateMbit  float64  `json:"rate_mbit"`
	Used      uint64   `json:"used"`
	Cut       string   `json:"cut"`
	Links     []string `json:"links"` // "up" | "down" per foreign server
	SpeedRx   float64  `json:"speed_rx"`
	SpeedTx   float64  `json:"speed_tx"`
	At        int64    `json:"at"`
}

// custByToken finds a customer by status token in constant time per entry.
func custByToken(tok string) (customer, [2]float64, bool) {
	if !custTokenRe.MatchString(tok) {
		return customer{}, [2]float64{}, false
	}
	custs.Lock()
	defer custs.Unlock()
	custLoadLocked()
	for _, c := range custs.f.Customers {
		if subtle.ConstantTimeCompare([]byte(c.Token), []byte(tok)) == 1 {
			cc := c
			cc.Links = append([]customerLink(nil), c.Links...)
			return cc, custs.speed[c.ID], true
		}
	}
	return customer{}, [2]float64{}, false
}

func custPublicView(c customer, sp [2]float64, now time.Time) custPublic {
	p := custPublic{Name: c.Name, ExpiresAt: c.ExpiresAt, DaysLeft: daysLeft(c.ExpiresAt, now), QuotaGB: c.QuotaGB, RateMbit: c.RateMbit,
		Used: c.used(), Cut: c.Cut, SpeedRx: sp[0], SpeedTx: sp[1], At: now.Unix(), Links: []string{}}
	var ctrl []int
	for _, l := range c.Links {
		ctrl = append(ctrl, l.CtrlPort)
	}
	linked := custLinked(ctrl)
	for _, l := range c.Links {
		st := "down"
		if c.Cut == "" && linked[l.CtrlPort] {
			st = "up"
		}
		p.Links = append(p.Links, st)
	}
	return p
}

// custStatusPage is the status page; the server fills /*HS_DATA*/null.
//
//go:embed customer_status.html
var custStatusPage []byte

// custStatusLimiter keeps status-page lookups (and token guessing) cheap.
var custStatusLimiter = struct {
	sync.Mutex
	hits map[string][]time.Time
}{hits: map[string][]time.Time{}}

func custStatusAllowed(ip string, now time.Time) bool {
	custStatusLimiter.Lock()
	defer custStatusLimiter.Unlock()
	if _, known := custStatusLimiter.hits[ip]; !known && len(custStatusLimiter.hits) >= 10000 {
		// forget addresses that went quiet; a full table refuses new ones
		// instead of starting everyone's count again
		for k, ts := range custStatusLimiter.hits {
			if len(ts) == 0 || now.Sub(ts[len(ts)-1]) >= time.Minute {
				delete(custStatusLimiter.hits, k)
			}
		}
		if len(custStatusLimiter.hits) >= 10000 {
			return false
		}
	}
	keep := custStatusLimiter.hits[ip][:0]
	for _, t := range custStatusLimiter.hits[ip] {
		if now.Sub(t) < time.Minute {
			keep = append(keep, t)
		}
	}
	if len(keep) >= 60 {
		custStatusLimiter.hits[ip] = keep
		return false
	}
	custStatusLimiter.hits[ip] = append(keep, now)
	return true
}

// handleCustomerStatus serves /_hs/<token> (the page) and /_hs/<token>.json.
// A wrong token is a plain 404 that says nothing about customers.
func handleCustomerStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if !custStatusAllowed(ClientIP(r), time.Now()) {
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}
	tok := r.PathValue("token")
	asJSON := strings.HasSuffix(tok, ".json")
	tok = strings.TrimSuffix(tok, ".json")
	c, sp, ok := custByToken(tok)
	if !ok {
		http.NotFound(w, r)
		return
	}
	v := custPublicView(c, sp, time.Now())
	if asJSON {
		writeJSON(w, v)
		return
	}
	data, _ := json.Marshal(v)
	page := bytes.Replace(custStatusPage, []byte("/*HS_DATA*/null"), bytes.ReplaceAll(data, []byte("</"), []byte(`<\/`)), 1)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	_, _ = io.Copy(w, bytes.NewReader(page))
}
