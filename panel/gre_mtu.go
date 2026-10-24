package main

import (
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Path MTU. hashem.sh gives GRE interfaces MTU 1380 and clamps TCP MSS to
// 1340. When Diagnostics measures that 1380-byte packets do not cross the
// path, Quick Repair saves the largest size that does in <configDir>/gre_mtu.
// hashem.sh reads that file wherever it sets the MTU or the clamp (start,
// carrier switch, Optimize, Restore), and the panel re-checks it every minute
// so an older hashem.sh cannot put 1380 back.

const (
	pathMTUMin    = 1200 // the MTU probe's floor
	greMTUDefault = 1380
	greMSSDefault = 1340
)

func pathMTUFile() string { return filepath.Join(configDir, "gre_mtu") }

// savedPathMTU is the saved path MTU, 0 when there is none.
func savedPathMTU() int {
	b, err := os.ReadFile(pathMTUFile())
	if err != nil {
		return 0
	}
	v, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || v < pathMTUMin || v >= greMTUDefault {
		return 0
	}
	return v
}

func savePathMTU(v int) error {
	if v < pathMTUMin || v >= greMTUDefault {
		return os.Remove(pathMTUFile())
	}
	return os.WriteFile(pathMTUFile(), []byte(strconv.Itoa(v)+"\n"), 0644)
}

// pathMTURun runs ip / iptables; swappable so tests never touch the host.
var pathMTURun = func(name string, args ...string) ([]byte, error) {
	return runCmdTimeoutOut(5*time.Second, name, args...)
}

// greInterfaces lists this server's GRE tunnel interfaces (gre-tunnel, gre-tN).
func greInterfaces() []string {
	ents, err := os.ReadDir(sysClassNet)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), "gre-t") {
			out = append(out, e.Name())
		}
	}
	return out
}

// mssRewrite plans the mangle-table changes that bring every fixed TCPMSS
// clamp down to mss, from `iptables -t mangle -S` output. A larger clamp
// would win, so it is replaced; smaller ones and --clamp-mss-to-pmtu stay.
// With no TCPMSS rule in POSTROUTING at all, one is added.
func mssRewrite(rules string, mss int) (del, add [][]string) {
	have := map[string]bool{}
	post := false
	lines := strings.Split(rules, "\n")
	for _, l := range lines {
		have[strings.TrimSpace(l)] = true
	}
	want := strconv.Itoa(mss)
	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) < 2 || f[0] != "-A" || !strings.Contains(l, "TCPMSS") {
			continue
		}
		if f[1] == "POSTROUTING" {
			post = true
		}
		for i, w := range f {
			if w != "--set-mss" || i+1 >= len(f) {
				continue
			}
			if n, err := strconv.Atoi(f[i+1]); err != nil || n <= mss || (f[1] != "POSTROUTING" && f[1] != "FORWARD") {
				break
			}
			d := append([]string{"-t", "mangle", "-D"}, f[1:]...)
			del = append(del, d)
			nf := append([]string{}, f...)
			nf[i+1] = want
			if line := strings.Join(nf, " "); !have[line] {
				have[line] = true
				add = append(add, append([]string{"-t", "mangle"}, nf...))
			}
			break
		}
	}
	if !post {
		add = append(add, []string{"-t", "mangle", "-A", "POSTROUTING", "-p", "tcp",
			"--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--set-mss", want})
	}
	return del, add
}

// enforcePathMTU puts the GRE interfaces at the saved path MTU and the MSS
// clamp at the matching size. Without a saved MTU it only makes sure a clamp
// exists (1340, what hashem.sh adds). It returns what it changed.
func enforcePathMTU() []string {
	if runtime.GOOS == "windows" {
		return nil
	}
	var done []string
	mtu, mss := savedPathMTU(), greMSSDefault
	if mtu > 0 {
		mss = mtu - 40
		for _, name := range greInterfaces() {
			if cur := interfaceMTU(name); cur > mtu {
				if _, err := pathMTURun("ip", "link", "set", "dev", name, "mtu", strconv.Itoa(mtu)); err == nil {
					done = append(done, "Set "+name+" MTU "+strconv.Itoa(cur)+" -> "+strconv.Itoa(mtu))
				}
			}
		}
	}
	out, err := pathMTURun("iptables", "-t", "mangle", "-S")
	if err != nil {
		return done
	}
	del, add := mssRewrite(string(out), mss)
	for _, a := range add { // add first: never a moment without a clamp
		_, _ = pathMTURun("iptables", a...)
	}
	for _, d := range del {
		_, _ = pathMTURun("iptables", d...)
	}
	if len(del)+len(add) > 0 {
		done = append(done, "TCP MSS clamp set to "+strconv.Itoa(mss))
	}
	return done
}

// lastMeasuredMTU is the MTU result of the newest Diagnostics run.
func lastMeasuredMTU() mtuSummary {
	lastDoctorMu.RLock()
	defer lastDoctorMu.RUnlock()
	if lastDoctorReport == nil {
		return mtuSummary{}
	}
	return lastDoctorReport.MTUResult
}

// pathMTUFixes is the MTU step of Quick Repair: save what Diagnostics
// measured when 1380 did not fit, then apply it.
func pathMTUFixes() []string {
	var fixes []string
	if m := lastMeasuredMTU(); m.Tested && m.MaxPacket > 0 && m.MaxPacket < m.Interface {
		if err := savePathMTU(m.Optimal); err == nil {
			fixes = append(fixes, "GRE MTU "+strconv.Itoa(m.Optimal)+" saved: it is kept after restarts")
		}
	}
	return append(fixes, enforcePathMTU()...)
}

// pathMTUKeeper re-applies the saved path MTU after anything resets it:
// a reboot or carrier switch run by an hashem.sh that predates gre_mtu.
func pathMTUKeeper() {
	if runtime.GOOS == "windows" {
		return
	}
	time.Sleep(20 * time.Second)
	for {
		if savedPathMTU() > 0 {
			for _, line := range enforcePathMTU() {
				log.Printf("[path-mtu] %s", line)
			}
		}
		time.Sleep(time.Minute)
	}
}
