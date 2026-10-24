package main

// gre-panel settings ...: the Settings tab items that live in panel.json, for
// the terminal. The running panel reads most of them only at start, so the
// caller (hashem.sh) restarts gre-panel after a change; tunnels keep running.

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

func cliSettings(args []string) int {
	if !cliStart() {
		return 1
	}
	onOff := func(b bool) string {
		if b {
			return "on"
		}
		return "off"
	}
	usage := func() int {
		fmt.Fprintln(os.Stderr, "Usage: gre-panel settings [show | 2fa off | terminal on|off | terminal-allow [IP/CIDR ...] | idle MINUTES]")
		return 2
	}
	sub := "show"
	if len(args) > 0 {
		sub, args = args[0], args[1:]
	}
	switch sub {
	case "show":
		fmt.Printf("Username:        %s\n", cfg.Username)
		fmt.Printf("HTTP port:       %d\n", cfg.Port)
		fmt.Printf("Address path:    /%s/\n", cfg.BasePath)
		fmt.Printf("HTTPS port:      %d\n", effectiveTLSPort())
		fmt.Printf("Two-factor:      %s\n", onOff(cfg.TOTPEnabled))
		fmt.Printf("Web terminal:    %s\n", onOff(cfg.TerminalEnabled))
		if len(cfg.TerminalAllowIPs) > 0 {
			fmt.Printf("Terminal from:   %s\n", strings.Join(cfg.TerminalAllowIPs, ", "))
		}
		idle := "off"
		if cfg.IdleTimeoutMin > 0 {
			idle = strconv.Itoa(cfg.IdleTimeoutMin) + " min"
		}
		fmt.Printf("Idle sign-out:   %s\n", idle)
		fmt.Printf("Metrics:         %s\n", onOff(cfg.MetricsToken != ""))
		return 0
	case "2fa", "totp":
		if len(args) != 1 || args[0] != "off" {
			fmt.Fprintln(os.Stderr, "Usage: gre-panel settings 2fa off   (turn it on in the panel: it needs your authenticator app)")
			return 2
		}
		cfg.TOTPEnabled, cfg.TOTPSecret, cfg.RecoveryHashes = false, "", nil
		saveCfg()
		LogSecurityAudit("TOTP_DISABLED", "root", "terminal", "two-factor authentication turned off from the terminal")
		fmt.Println("Two-factor authentication is off. Sign in with the password only.")
		return 0
	case "terminal":
		if len(args) != 1 || (args[0] != "on" && args[0] != "off") {
			return usage()
		}
		cfg.TerminalEnabled = args[0] == "on"
		saveCfg()
		fmt.Printf("Web terminal tab: %s\n", args[0])
		return 0
	case "terminal-allow":
		var list []string
		for _, a := range args {
			for _, f := range strings.FieldsFunc(a, func(r rune) bool { return r == ',' || r == ' ' }) {
				list = append(list, f)
			}
		}
		if !validateAllowList(list) || len(list) > 32 {
			fmt.Fprintln(os.Stderr, "Give up to 32 IPs or CIDRs, e.g. 203.0.113.7 198.51.100.0/24 (none = any address).")
			return 1
		}
		clean := list
		cfg.TerminalAllowIPs = clean
		saveCfg()
		if len(clean) == 0 {
			fmt.Println("Web terminal: any address may open it (after sign-in).")
		} else {
			fmt.Printf("Web terminal only from: %s\n", strings.Join(clean, ", "))
		}
		return 0
	case "idle":
		if len(args) != 1 {
			return usage()
		}
		m, err := strconv.Atoi(args[0])
		if err != nil || (m != 0 && (m < 5 || m > 1440)) {
			fmt.Fprintln(os.Stderr, "Minutes must be 0 (off) or 5-1440.")
			return 2
		}
		cfg.IdleTimeoutMin = m
		saveCfg()
		if m == 0 {
			fmt.Println("Idle sign-out: off")
		} else {
			fmt.Printf("Idle sign-out: %d min\n", m)
		}
		return 0
	}
	return usage()
}
