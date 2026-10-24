package main

// gre-panel tls ...: the Settings tab's Domain & HTTPS card for the terminal.
// hashem.sh calls it, so both run the same checks and fixes (tls_acme.go).
// The running panel service is restarted by the caller to pick the files up;
// this process never opens the HTTPS port itself (cliMode).

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// cliMode: a one-shot command, not the panel service. No listeners.
var cliMode bool

// cliStart prepares a one-shot command on an installed panel: the service's
// log lines (command errors, audit echo) stay out of the terminal; the audit
// file still gets its entries. false: the panel is not installed here.
func cliStart() bool {
	if v := os.Getenv("GRE_PANEL_DIR"); v != "" {
		configDir = v
	}
	cliMode = true
	if _, err := os.Stat(cfgPath()); err != nil {
		fmt.Fprintln(os.Stderr, "The panel is not installed on this server ("+cfgPath()+" is missing). Install it first: hashem")
		return false
	}
	log.SetOutput(io.Discard)
	loadOrInit()
	return true
}

func cliTLS(args []string) int {
	if !cliStart() {
		return 1
	}
	sub := "status"
	if len(args) > 0 {
		sub, args = args[0], args[1:]
	}
	fail := func(err error) int {
		var f *tlsFail
		if errors.As(err, &f) {
			info := errCatalog[f.code]
			msg := f.msg
			if msg == "" {
				msg = info.Msg
			}
			fmt.Fprintf(os.Stderr, "[%s] %s\n", f.code, msg)
			if info.Hint != "" {
				fmt.Fprintf(os.Stderr, "Hint: %s\n", info.Hint)
			}
			return 1
		}
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	switch sub {
	case "status": // local facts only: the menu shows it, so no public-IP lookup
		host := routeSourceIP()
		if v := savedPublicIP(); host == "" || isPrivateIP(host) && v != "" {
			host = v
		}
		if host == "" {
			host = "<server-ip>"
		}
		httpURL := fmt.Sprintf("http://%s/%s/", hostPort(host, cfg.Port), cfg.BasePath)
		m := tlsMetaLoad()
		exp, _, err := tlsCertExpiry()
		if !tlsHasCert() || err != nil {
			fmt.Println("HTTPS:   off (no certificate)")
			fmt.Printf("HTTP:    %s\n", httpURL)
			return 0
		}
		name, src := host, ""
		if m != nil && m.Domain != "" {
			name, src = m.Domain, " ("+tlsSource(m)+")"
		}
		fmt.Printf("HTTPS:   on, https://%s:%d/%s/\n", name, effectiveTLSPort(), cfg.BasePath)
		fmt.Printf("Name:    %s%s\n", name, src)
		fmt.Printf("Expires: %s (%d days)\n", exp.Format("2006-01-02"), int(time.Until(exp).Hours()/24))
		fmt.Printf("HTTP:    %s\n", httpURL)
		if err := checkPortConflict(effectiveTLSPort()); err != nil {
			fmt.Printf("Warning: %v\n", err)
		}
		return 0
	case "issue":
		var domain, email string
		port, skipDNS := 0, false
		for i := 0; i < len(args); i++ {
			switch a := args[i]; {
			case a == "--skip-dns":
				skipDNS = true
			case a == "--port" && i+1 < len(args):
				i++
				port, _ = strconv.Atoi(args[i])
			case strings.HasPrefix(a, "--"):
				fmt.Fprintln(os.Stderr, "unknown flag: "+a)
				return 2
			case domain == "":
				domain = a
			default:
				email = a
			}
		}
		if domain == "" {
			fmt.Fprintln(os.Stderr, "Usage: gre-panel tls issue DOMAIN [EMAIL] [--port N] [--skip-dns]")
			return 2
		}
		if !tlsDomainRe.MatchString(strings.ToLower(CleanHost(domain))) {
			return fail(&tlsFail{"E-TLS-02", "invalid domain name: " + domain})
		}
		fmt.Println("Checking the domain, port 80 and certbot, then asking Let's Encrypt (up to 2 minutes)...")
		if err := tlsIssueLetsEncrypt(domain, email, port, skipDNS); err != nil {
			return fail(err)
		}
		fmt.Printf("Certificate installed. HTTPS: %s\n", tlsHTTPSURL())
		return 0
	case "renew":
		renewed, err := tlsRenewCurrent()
		if err != nil {
			return fail(err)
		}
		exp, _, _ := tlsCertExpiry()
		if renewed {
			fmt.Printf("Certificate renewed, expires %s\n", exp.Format("2006-01-02"))
		} else {
			fmt.Printf("Certificate is current (not due yet), expires %s\n", exp.Format("2006-01-02"))
		}
		return 0
	case "remove":
		tlsRemoveAll()
		fmt.Printf("HTTPS removed. The panel answers on HTTP: %s\n", tlsHTTPURL())
		return 0
	case "ip":
		ipStr := ""
		if len(args) > 0 {
			ipStr = args[0]
		} else {
			ipStr = detectPublicIP()
		}
		ip := net.ParseIP(CleanHost(ipStr))
		if ip == nil {
			fmt.Fprintln(os.Stderr, "Usage: gre-panel tls ip [IP] (the server IP could not be detected)")
			return 2
		}
		if _, msg := tlsIssueIPCert(ip); msg != "" {
			return fail(&tlsFail{"E-TLS-13", msg})
		}
		fmt.Printf("Self-signed IP certificate installed. HTTPS: %s\n", tlsHTTPSURL())
		fmt.Printf("Install the CA once in your browser or OS: %s\n", tlsCAFile())
		return 0
	case "custom":
		if len(args) != 2 {
			fmt.Fprintln(os.Stderr, "Usage: gre-panel tls custom CERT_FILE KEY_FILE")
			return 2
		}
		crt, err1 := os.ReadFile(args[0])
		key, err2 := os.ReadFile(args[1])
		if err := errors.Join(err1, err2); err != nil {
			return fail(&tlsFail{"E-TLS-12", err.Error()})
		}
		out, msg := tlsInstallCustom(&tlsCustomSource{cert: crt, key: key, label: args[0]})
		if msg != "" {
			return fail(&tlsFail{"E-TLS-12", msg})
		}
		fmt.Printf("Certificate installed, expires %v. HTTPS: %v\n", out["expiry"], out["https_url"])
		return 0
	}
	fmt.Fprintln(os.Stderr, "Usage: gre-panel tls [status | issue DOMAIN [EMAIL] [--port N] [--skip-dns] | renew | remove | ip [IP] | custom CERT KEY]")
	return 2
}
