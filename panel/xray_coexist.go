package main

// Living next to an Xray panel. 3x-ui, Marzban, Hiddify and the like run
// their own xray; the Xray tunnel must never take their ports, files or units.
// The tunnel has its own binary (xrayBinPath, never /usr/local/bin/xray, which
// the official installer uses), its own units (hashem-xray-N) and no API port.
// This file finds who listens where and which panels are installed, and
// refuses a link whose ports are taken.

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Paths are vars so tests point them at temp dirs.
var (
	xrayDir     = "/usr/local/lib/hashem/xray" // binary and its geo files
	xrayBinPath = "/usr/local/lib/hashem/xray/xray"
	xrayRoot    = "/" // where detectXrayPanels looks
)

// xrayListener is one listening socket and the program that holds it.
type xrayListener struct {
	Proto string // tcp | udp
	Port  int
	Proc  string // the process name ss shows (15 characters at most)
	PID   int
	Exe   string // the program's path, from /proc/<pid>/exe
}

var ssUsersRe = regexp.MustCompile(`\("([^"]*)",pid=(\d+)`)

// parseSSListeners reads `ss -Htulnp`:
//
//	tcp LISTEN 0 4096 0.0.0.0:443 0.0.0.0:* users:(("xray-linux-amd6",pid=812,fd=9))
//	udp UNCONN 0 0 [::]:2053 [::]:* users:(("xray",pid=9,fd=3))
func parseSSListeners(out string) []xrayListener {
	var ls []xrayListener
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 5 || (f[0] != "tcp" && f[0] != "udp") {
			continue
		}
		local := f[4]
		i := strings.LastIndexByte(local, ':')
		if i < 0 {
			continue
		}
		port, err := strconv.Atoi(local[i+1:])
		if err != nil || !xrayPortOK(port) {
			continue
		}
		l := xrayListener{Proto: f[0], Port: port}
		if m := ssUsersRe.FindStringSubmatch(line); m != nil {
			l.Proc = m[1]
			l.PID, _ = strconv.Atoi(m[2])
		}
		ls = append(ls, l)
	}
	return ls
}

// xrayListeners is every listening socket on this server; swappable for tests.
var xrayListeners = func() []xrayListener {
	out, err := runCmdTimeoutOut(5*time.Second, "ss", "-Htulnp")
	if err != nil {
		return nil
	}
	ls := parseSSListeners(string(out))
	for i := range ls {
		if ls[i].PID > 0 {
			if exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", ls[i].PID)); err == nil {
				ls[i].Exe = strings.TrimSuffix(exe, " (deleted)")
			}
		}
	}
	return ls
}

// xrayOwnPath reports whether a program is this panel's own Xray.
func xrayOwnPath(exe string) bool {
	return exe != "" && filepath.Clean(exe) == filepath.Clean(xrayBinPath)
}

// xrayOwnerLabel names the program that holds a port, for an error a user
// can act on ("port 443 is used by 3x-ui").
func xrayOwnerLabel(l xrayListener) string {
	s := strings.ToLower(l.Exe + " " + l.Proc)
	switch {
	case xrayOwnPath(l.Exe):
		return "the Hashem Xray tunnel"
	case strings.Contains(s, "x-ui") || strings.Contains(s, "xray-linux"):
		return "3x-ui (x-ui)"
	case strings.Contains(s, "marzneshin"):
		return "Marzneshin"
	case strings.Contains(s, "marzban"):
		return "Marzban"
	case strings.Contains(s, "pasarguard"):
		return "PasarGuard"
	case strings.Contains(s, "hiddify"):
		return "Hiddify"
	case strings.Contains(s, "s-ui"):
		return "S-UI"
	case strings.Contains(s, "remnanode") || strings.Contains(s, "remnawave"):
		return "Remnawave node"
	case strings.Contains(s, "sing-box"):
		return "sing-box"
	case strings.Contains(s, "docker-proxy"):
		return "a Docker container"
	case l.Proc != "":
		return l.Proc
	}
	return "another program"
}

// xrayPanel is an Xray panel (or a plain xray / sing-box) found on this server.
type xrayPanel struct {
	Name     string `json:"name"`
	Evidence string `json:"evidence"` // the path that shows it
}

// xrayPanelSigns are the paths each panel leaves; the first found is shown.
var xrayPanelSigns = []struct {
	name  string
	paths []string
}{
	{"3x-ui (x-ui)", []string{"usr/local/x-ui", "etc/systemd/system/x-ui.service"}},
	{"Marzban", []string{"opt/marzban", "var/lib/marzban"}},
	{"Marzneshin", []string{"etc/opt/marzneshin", "var/lib/marzneshin"}},
	{"PasarGuard", []string{"opt/pasarguard", "var/lib/pasarguard"}},
	{"Hiddify", []string{"opt/hiddify-manager"}},
	{"S-UI", []string{"usr/local/s-ui"}},
	{"Remnawave node", []string{"opt/remnanode"}},
	{"Xray (official install)", []string{"etc/systemd/system/xray.service", "usr/local/bin/xray"}},
	{"sing-box", []string{"etc/sing-box", "etc/systemd/system/sing-box.service"}},
}

// detectXrayPanels lists the Xray panels installed next to the tunnel.
func detectXrayPanels() []xrayPanel {
	var out []xrayPanel
	for _, s := range xrayPanelSigns {
		for _, p := range s.paths {
			if _, err := os.Stat(filepath.Join(xrayRoot, p)); err == nil {
				out = append(out, xrayPanel{Name: s.name, Evidence: "/" + p})
				break
			}
		}
	}
	return out
}

// xrayConflict is a port this link needs that something else holds.
type xrayConflict struct {
	Port  int    `json:"port"`
	Proto string `json:"proto"`
	Owner string `json:"owner"`
}

func (c xrayConflict) String() string {
	return fmt.Sprintf("%s port %d is used by %s", strings.ToUpper(c.Proto), c.Port, c.Owner)
}

// xrayPortConflicts lists the ports this end of l would bind that are taken:
// by another Xray tunnel link, by a running program (the tunnel's own Xray
// holding them for this same link is fine: that is a restart), or claimed
// by another tunnel's config (claimed: "tcp:443" -> owner).
func xrayPortConflicts(l XrayLink, others []XrayLink, ls []xrayListener, claimed map[string]string) []xrayConflict {
	var out []xrayConflict
	seen := map[string]bool{}
	add := func(c xrayConflict) {
		k := c.Proto + ":" + strconv.Itoa(c.Port)
		if !seen[k] {
			seen[k] = true
			out = append(out, c)
		}
	}
	tcp, udp := l.listens()
	check := func(proto string, ports []int) {
		for _, p := range ports {
			for _, o := range others {
				if o.ID == l.ID {
					continue
				}
				ot, ou := o.listens()
				if (proto == "tcp" && xrayHasPort(ot, p)) || (proto == "udp" && xrayHasPort(ou, p)) {
					add(xrayConflict{p, proto, fmt.Sprintf("Xray tunnel link %d", o.ID)})
				}
			}
			if owner := claimed[proto+":"+strconv.Itoa(p)]; owner != "" {
				add(xrayConflict{p, proto, owner})
			}
			for _, x := range ls {
				if x.Proto == proto && x.Port == p && !xrayOwnPath(x.Exe) {
					add(xrayConflict{p, proto, xrayOwnerLabel(x)})
				}
			}
		}
	}
	check("tcp", tcp)
	check("udp", udp)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		return out[i].Proto < out[j].Proto
	})
	return out
}

func xrayHasPort(list []int, p int) bool {
	for _, q := range list {
		if q == p {
			return true
		}
	}
	return false
}

// xrayPortCandidates are tunnel ports that look like HTTPS to a censor, best
// first: Xray warns that Reality on a port other than 443 is easier to block.
var xrayPortCandidates = []int{443, 8443, 2053, 2083, 2087, 2096, 9443, 10443, 4443, 6443}

// xraySuggestPort is the first candidate nothing holds for proto (avoid: ports
// already chosen elsewhere), 0 when all are taken.
func xraySuggestPort(proto string, ls []xrayListener, avoid []int) int {
	for _, p := range xrayPortCandidates {
		if xrayHasPort(avoid, p) {
			continue
		}
		free := true
		for _, x := range ls {
			if x.Proto == proto && x.Port == p && !xrayOwnPath(x.Exe) {
				free = false
				break
			}
		}
		if free {
			return p
		}
	}
	return 0
}
