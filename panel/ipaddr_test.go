package main

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestIPFamily(t *testing.T) {
	for in, want := range map[string]int{
		"1.2.3.4": 4, " 1.2.3.4 ": 4, "::ffff:1.2.3.4": 4,
		"2001:db8::1": 6, "::1": 6, "fd00::5": 6,
		"": 0, "example.com": 0, "[2001:db8::1]": 0, "1.2.3.4/32": 0, "1.2.3": 0,
	} {
		if got := ipFamily(in); got != want {
			t.Errorf("ipFamily(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestHostPortAndURLHost(t *testing.T) {
	for _, c := range []struct {
		host string
		port int
		hp   string
		uh   string
	}{
		{"1.2.3.4", 443, "1.2.3.4:443", "1.2.3.4"},
		{"2001:db8::1", 8443, "[2001:db8::1]:8443", "[2001:db8::1]"},
		{"[2001:db8::1]", 22, "[2001:db8::1]:22", "[2001:db8::1]"},
		{"example.com", 80, "example.com:80", "example.com"},
		{"0.0.0.0", 9000, "0.0.0.0:9000", "0.0.0.0"},
		{"::", 9000, "[::]:9000", "[::]"},
	} {
		if got := hostPort(c.host, c.port); got != c.hp {
			t.Errorf("hostPort(%q, %d) = %q, want %q", c.host, c.port, got, c.hp)
		}
		if got := urlHost(c.host); got != c.uh {
			t.Errorf("urlHost(%q) = %q, want %q", c.host, got, c.uh)
		}
	}
}

func TestValidPublicIP(t *testing.T) {
	for _, c := range []struct {
		ip   string
		fam  int
		want bool
	}{
		{"203.0.113.7", 4, true},
		{"203.0.113.7", 6, false},
		{"203.0.113.7", 0, true},
		{"10.0.0.1", 4, false},
		{"2001:db8::1", 6, true},
		{"2001:db8::1", 4, false},
		{"fd12:3456::1", 6, false}, // unique local
		{"fe80::1", 6, false},      // link local
		{"::1", 6, false},
		{"ff02::1", 6, false},
		{"::", 6, false},
		{"example.com", 0, false},
	} {
		if got := validPublicIP(c.ip, c.fam); got != c.want {
			t.Errorf("validPublicIP(%q, %d) = %v, want %v", c.ip, c.fam, got, c.want)
		}
	}
}

// TestNoBareHostPort keeps "%s:%d" host:port builders out of the panel: they
// break with IPv6 literals; hostPort / net.JoinHostPort bracket them.
func TestNoBareHostPort(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	bad := regexp.MustCompile(`Sprintf\("(?:[a-z]+://)?%s:%d`)
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(data), "\n") {
			if bad.MatchString(line) && !strings.Contains(line, "typ, ") {
				t.Errorf("%s:%d builds host:port without brackets: %s", f, i+1, strings.TrimSpace(line))
			}
		}
	}
}

func TestBundlesAndSetupIPv6(t *testing.T) {
	// Backhaul without GRE carries either family; the GRE bundles stay IPv4
	b, err := ParseBundle(MakeBackhaulBundle("2001:db8::1", 3080, "tcpmux", "tok", []string{"443"}))
	if err != nil || b.IranPub != "2001:db8::1" || b.FrpPort != 3080 {
		t.Fatalf("bh1 over IPv6: %+v %v", b, err)
	}
	if _, err := ParseBundle(MakeGreBackhaulBundle("2001:db8::1", 3080, "10.10.10.2", "10.10.10.1", "tcpmux", "tok", nil)); err == nil {
		t.Fatal("gh1 with an IPv6 Iran address accepted")
	}
	if _, err := ParseBundle(MakeBundle("2001:db8::1", 7000, "10.10.10.2", "10.10.10.1", "tok", nil)); err == nil {
		t.Fatal("hsh1 with an IPv6 Iran address accepted")
	}

	// setup: GRE needs IPv4 at both ends, with a clear message
	withPro(t)
	for _, engine := range []string{"frp", "gre-backhaul"} {
		rr := httptest.NewRecorder()
		handleSetupPost(rr, httptest.NewRequest("POST", "/api/setup", strings.NewReader(
			`{"role":"iran","engine":"`+engine+`","local_public":"2001:db8::1","remote_public":"2001:db8::2","local_gre":"10.10.10.2","peer_gre":"10.10.10.1","frp_port":7000}`)))
		if rr.Code != 400 || !strings.Contains(rr.Body.String(), "IPv4") {
			t.Errorf("%s over IPv6: %d %s", engine, rr.Code, rr.Body.String())
		}
	}
}

func TestPeerPatchIPv6(t *testing.T) {
	old := configDir
	configDir = t.TempDir()
	defer func() { configDir = old }()
	_ = os.WriteFile(peersFile(), []byte(`{"peers":[
	 {"id":1,"name":"gre","local_pub":"1.2.3.4","remote_pub":"198.51.100.1","frp_port":25000,"local_gre":"10.10.10.2","peer_gre":"10.10.10.1","ports":[80],"token":"t1","gre_if":"gre-t1","frps_svc":"frps"},
	 {"id":2,"name":"bh","engine":"backhaul","local_pub":"1.2.3.4","remote_pub":"198.51.100.2","frp_port":25001,"ports":[81],"token":"t2","gre_if":"none","frps_svc":"backhaul-server-2"}]}`), 0600)
	rr := httptest.NewRecorder()
	handlePeersPatch(rr, httptest.NewRequest("PATCH", "/api/peers", strings.NewReader(`{"id":1,"remote_pub":"2001:db8::9"}`)))
	if rr.Code != 400 || !strings.Contains(rr.Body.String(), "IPv4") {
		t.Errorf("GRE peer to IPv6: %d %s", rr.Code, rr.Body.String())
	}
	rr = httptest.NewRecorder()
	handlePeersPatch(rr, httptest.NewRequest("PATCH", "/api/peers", strings.NewReader(`{"id":2,"remote_pub":"2001:db8::9"}`)))
	if strings.Contains(rr.Body.String(), "E-PEER-07") {
		t.Errorf("Backhaul peer without GRE to IPv6 rejected: %d %s", rr.Code, rr.Body.String())
	}
}

func TestRescueIPv6(t *testing.T) {
	if ip, err := validRemoteIP(" 2001:DB8::5 "); err != nil || ip != "2001:db8::5" {
		t.Errorf("IPv6 rescue peer: %q %v", ip, err)
	}
	for _, bad := range []string{"fe80::1", "::1", "ff02::1", "::"} {
		if _, err := validRemoteIP(bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	if fw := rescueFwNft(7000, "2001:db8::5"); !strings.Contains(fw, "tcp dport 7000 ip6 saddr != 2001:db8::5 counter drop") {
		t.Errorf("IPv6 firewall rule:\n%s", fw)
	}
	if fw := rescueFwNft(7000, "203.0.113.5"); !strings.Contains(fw, "ip saddr != 203.0.113.5") {
		t.Errorf("IPv4 firewall rule:\n%s", fw)
	}
	if d := rescueDnatNft("2001:db8::5", []int{443}); !strings.Contains(d, "dnat ip6 to 2001:db8::5") || !strings.Contains(d, "ip6 daddr 2001:db8::5") {
		t.Errorf("IPv6 DNAT:\n%s", d)
	}
}
