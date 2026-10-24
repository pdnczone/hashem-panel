package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const mangleWithClamp = `-P PREROUTING ACCEPT
-P POSTROUTING ACCEPT
-A FORWARD -o gre-tunnel -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1340
-A POSTROUTING -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1340
-A POSTROUTING -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1340
-A POSTROUTING -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1300`

func joinArgs(a [][]string) string {
	var s []string
	for _, x := range a {
		s = append(s, strings.Join(x, " "))
	}
	return strings.Join(s, "\n")
}

// Every clamp above the path MSS is replaced (once, even when duplicated);
// smaller ones stay, and nothing is added when a clamp already fits.
func TestMSSRewrite(t *testing.T) {
	del, add := mssRewrite(mangleWithClamp, 1334)
	if len(del) != 3 {
		t.Fatalf("want the three 1340 rules deleted:\n%s", joinArgs(del))
	}
	want := "-t mangle -A FORWARD -o gre-tunnel -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1334\n" +
		"-t mangle -A POSTROUTING -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1334"
	if got := joinArgs(add); got != want {
		t.Fatalf("adds:\n%s\nwant:\n%s", got, want)
	}
	if !strings.HasPrefix(joinArgs(del), "-t mangle -D FORWARD -o gre-tunnel") {
		t.Fatalf("deletes must mirror the rule: %s", joinArgs(del))
	}

	if del, add := mssRewrite(mangleWithClamp, 1340); len(del)+len(add) != 0 {
		t.Fatalf("clamps already at 1340: nothing to do, got -%v +%v", del, add)
	}
	_, add = mssRewrite("-P POSTROUTING ACCEPT\n-A POSTROUTING -p tcp -j TCPMSS --clamp-mss-to-pmtu", 1340)
	if len(add) != 0 {
		t.Fatal("a PMTU clamp counts as a clamp")
	}
	_, add = mssRewrite("-P POSTROUTING ACCEPT", 1340)
	if len(add) != 1 || !strings.HasSuffix(strings.Join(add[0], " "), "--set-mss 1340") {
		t.Fatalf("no clamp at all: one is added, got %v", add)
	}
}

func TestSavedPathMTUBounds(t *testing.T) {
	withTmpConfig(t)
	if savedPathMTU() != 0 {
		t.Fatal("no file: 0")
	}
	for v, want := range map[string]int{"1374\n": 1374, "1380": 0, "1100": 0, "x": 0} {
		_ = os.WriteFile(pathMTUFile(), []byte(v), 0644)
		if got := savedPathMTU(); got != want {
			t.Fatalf("%q: got %d want %d", v, got, want)
		}
	}
	_ = savePathMTU(1374)
	if savedPathMTU() != 1374 {
		t.Fatal("save/read round trip")
	}
	_ = savePathMTU(1380) // the default again: the file goes
	if fileExists(pathMTUFile()) {
		t.Fatal("saving the default must remove the file")
	}
}

// Quick Repair saves what Diagnostics measured and lowers the interface and
// the clamp; the MTU finding says Quick Repair handles it.
func TestQuickRepairAppliesMeasuredMTU(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("enforcePathMTU is a no-op on Windows")
	}
	withTmpConfig(t)
	net := t.TempDir()
	_ = os.MkdirAll(filepath.Join(net, "gre-tunnel"), 0755)
	_ = os.WriteFile(filepath.Join(net, "gre-tunnel", "mtu"), []byte("1380\n"), 0644)
	_ = os.MkdirAll(filepath.Join(net, "eth0"), 0755)
	oldNet, oldRun := sysClassNet, pathMTURun
	sysClassNet = net
	var ran []string
	pathMTURun = func(name string, args ...string) ([]byte, error) {
		ran = append(ran, name+" "+strings.Join(args, " "))
		if name == "iptables" && len(args) > 2 && args[2] == "-S" {
			return []byte(mangleWithClamp), nil
		}
		return nil, nil
	}
	lastDoctorMu.Lock()
	oldRep := lastDoctorReport
	lastDoctorReport = &doctorReport{MTUResult: mtuSummary{Tested: true, Interface: 1380, MaxPacket: 1374, Optimal: 1374, MSS: 1334}}
	lastDoctorMu.Unlock()
	t.Cleanup(func() {
		sysClassNet, pathMTURun = oldNet, oldRun
		lastDoctorMu.Lock()
		lastDoctorReport = oldRep
		lastDoctorMu.Unlock()
	})

	fixes := strings.Join(pathMTUFixes(), "\n")
	if savedPathMTU() != 1374 {
		t.Fatal("measured MTU not saved")
	}
	all := strings.Join(ran, "\n")
	if !strings.Contains(all, "ip link set dev gre-tunnel mtu 1374") || strings.Contains(all, "eth0") {
		t.Fatalf("only GRE interfaces are lowered:\n%s", all)
	}
	if !strings.Contains(all, "--set-mss 1334") || !strings.Contains(fixes, "TCP MSS clamp set to 1334") {
		t.Fatalf("clamp not lowered:\n%s\n%s", all, fixes)
	}

	in := greInputs()
	in.mtu = lastDoctorReport.MTUResult
	found := false
	for _, f := range evaluateDoctor(in).Findings {
		if f.Area == "mtu" {
			found = true
			if !f.Auto {
				t.Fatal("the MTU finding must offer Quick Repair")
			}
		}
	}
	if !found {
		t.Fatal("no MTU finding")
	}
}
