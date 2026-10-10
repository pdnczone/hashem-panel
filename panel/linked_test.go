package main

import (
	"errors"
	"net"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestLinkedFromSS(t *testing.T) {
	ss := "0 0 10.10.10.1:7091 10.10.10.2:51000\n0 0 5.75.195.15:7093 1.2.3.4:40000\n0 0 [::ffff:77.1.1.1]:22 9.9.9.9:5\n"
	if !linkedFromSS(ss, []int{7091, 7093, 7089}, "5.75.195.15", "10.10.10.2") {
		t.Fatal("GRE-inner session must count")
	}
	if linkedFromSS(ss, []int{7091}, "8.8.8.8", "10.99.0.2") {
		t.Fatal("foreign remote must not match")
	}
	if !linkedFromSS(ss, []int{7093}) {
		t.Fatal("no remote filter must match any client")
	}
	if linkedFromSS("", []int{7091}) {
		t.Fatal("empty ss output is not linked")
	}
}

func TestFleetHealthFrpOnlyIsHealthy(t *testing.T) {
	l := mkLive(1, true, true, false, "")
	l.Linked = true
	if fleetHealth(l) != fleetOK {
		t.Fatal("linked FRP with dead GRE ping must be healthy")
	}
	l.Linked = false
	if fleetHealth(l) != fleetDeg {
		t.Fatal("unlinked FRP with dead ping stays degraded")
	}
}

func TestDashboardRollupMatchesFleet(t *testing.T) {
	ok := mkLive(1, true, true, false, "")
	ok.Linked = true
	bad := mkLive(2, true, true, false, "")
	if fleetHealth(ok) != fleetOK || fleetHealth(bad) != fleetDeg {
		t.Fatal("linked => healthy, unlinked+no ping => degraded")
	}
}

const ssSample = "0      0      10.10.10.1:7091   10.10.10.2:51000\n\t bbr wscale:9,9 rto:275 rtt:74.102/0.085 ato:40 mss:1328\n" +
	"0      0      5.75.195.15:7093   1.2.3.4:40000\n\t cubic rto:201 rtt:0.564/0.087 mss:1\n" +
	"0      0      5.75.195.15:22   9.9.9.9:5\n\t rtt:1/1\n" +
	"0      0      5.75.195.15:7091   10.10.10.2:51001\n"

func TestParseSSRTT(t *testing.T) {
	all := parseSS(ssSample)
	if len(all) != 4 {
		t.Fatalf("want 4 sessions, got %d", len(all))
	}
	if all[0].RTTms != 74.102 || all[1].RTTms != 0.564 || all[3].RTTms != -1 {
		t.Fatalf("rtt parse wrong: %+v", all)
	}
	got := sessionsOn(all, []int{7091}, "10.10.10.2")
	if len(got) != 2 || minRTT(got) != 74.102 {
		t.Fatalf("filter/min wrong: %+v", got)
	}
	if len(sessionsOn(all, []int{7091}, "8.8.8.8")) != 0 {
		t.Fatal("foreign remote must not match")
	}
	if minRTT(nil) != -1 {
		t.Fatal("empty -> -1")
	}
}

func TestPickLatency(t *testing.T) {
	if v, k := pickLatency(true, "12ms", 80); v != 12 || k != "icmp" {
		t.Fatalf("icmp must win: %v %v", v, k)
	}
	if v, k := pickLatency(false, "", 80.04); v != 80 || k != "tcp" {
		t.Fatalf("tcp fallback: %v %v", v, k)
	}
	if v, k := pickLatency(false, "", -1); v != -1 || k != "" {
		t.Fatalf("none: %v %v", v, k)
	}
}

func TestHubLatency(t *testing.T) {
	n := []fleetNode{
		{LatencyMs: 10, LatKind: "icmp"}, {LatencyMs: 90, LatKind: "tcp"},
		{LatencyMs: -1}, {LatencyMs: 20, LatKind: "icmp"},
	}
	h := hubLatency(n)
	if h.Count != 3 || h.Min != 10 || h.Max != 90 || h.Avg != 40 || h.ICMP != 2 || h.TCP != 1 {
		t.Fatalf("hub latency wrong: %+v", h)
	}
	if z := hubLatency(nil); z.Count != 0 || z.Avg != 0 {
		t.Fatalf("empty: %+v", z)
	}
}

// captured `ss -Htin state established` shapes (info line indented under the header)
const (
	ssNAT    = "0      0      5.9.9.9:7091   100.64.3.9:41000\n\t cubic wscale:7,7 rto:276 rtt:75.5/1.2 mss:1328\n"
	ssWSS    = "0      0      5.9.9.9:7093   198.51.100.7:50000\n\t cubic rto:240 rtt:40.25/3.1 mss:1388\n"
	ssDial   = "0      0      203.0.113.5:7091   198.51.100.7:52000\n\t cubic rto:230 rtt:12.5/0.5\n"
	ssMapped = "0      0      [::ffff:5.9.9.9]:7091   [::ffff:198.51.100.7]:53000\n\t cubic rto:230 rtt:21.125/0.5\n"
	ssTwo    = "0      0      10.10.10.1:7091   10.10.10.2:51000\n\t cubic rtt:74.1/0.1\n" +
		"0      0      10.20.20.1:7100   10.20.20.2:51001\n\t cubic rtt:30.2/0.1\n"
)

func TestControlSessionFixtures(t *testing.T) {
	resetSnapshotState()
	a := ctrlQuery{ID: 1, Port: 7091, RemotePub: "198.51.100.7", PeerGre: "10.10.10.2"}
	b := ctrlQuery{ID: 2, Port: 7100, RemotePub: "198.51.100.8", PeerGre: "10.20.20.2"}
	owners := portOwners([]int{7091, 7100})

	t.Run("NAT remote single owner is accepted and cached", func(t *testing.T) {
		r := controlSessionIn(parseSS(ssNAT), a, owners)
		if !r.Linked || r.RTTms != 75.5 || r.Remote != "100.64.3.9" {
			t.Fatalf("NAT'd client must link: %+v", r)
		}
		if cachedRemote(1) != "100.64.3.9" {
			t.Fatal("observed remote must be cached")
		}
	})
	t.Run("cached remote matches where owners are ambiguous", func(t *testing.T) {
		amb := portOwners([]int{7091, 7093}) // 7093 claimed by both peers
		c := ctrlQuery{ID: 9, Port: 7093, RemotePub: "198.51.100.99"}
		other := ctrlQuery{ID: 10, Port: 7091, RemotePub: "198.51.100.98"}
		sess := parseSS("0 0 5.9.9.9:7093 100.64.7.7:40000\n\t rtt:9.5/1\n")
		if controlSessionIn(sess, c, amb).Linked || controlSessionIn(sess, other, amb).Linked {
			t.Fatal("ambiguous port with unknown remote must not be attributed")
		}
		rememberRemote(9, "100.64.7.7")
		if !controlSessionIn(sess, c, amb).Linked {
			t.Fatal("cached remote must match")
		}
		if controlSessionIn(sess, other, amb).Linked {
			t.Fatal("cache is per peer")
		}
	})
	t.Run("WSS front port+2", func(t *testing.T) {
		r := controlSessionIn(parseSS(ssWSS), a, owners)
		if !r.Linked || r.RTTms != 40.25 {
			t.Fatalf("port+2 session from the peer must link: %+v", r)
		}
	})
	t.Run("dial route over public IP", func(t *testing.T) {
		r := controlSessionIn(parseSS(ssDial), a, owners)
		if !r.Linked || r.RTTms != 12.5 || r.Remote != "198.51.100.7" {
			t.Fatalf("public-IP session must link: %+v", r)
		}
	})
	t.Run("two peers on different ports", func(t *testing.T) {
		all := parseSS(ssTwo)
		ra, rb := controlSessionIn(all, a, owners), controlSessionIn(all, b, owners)
		if !ra.Linked || ra.RTTms != 74.1 || !rb.Linked || rb.RTTms != 30.2 {
			t.Fatalf("each peer owns its own session: %+v %+v", ra, rb)
		}
		only := parseSS("0 0 10.20.20.1:7100 10.20.20.2:51001\n")
		if controlSessionIn(only, a, owners).Linked {
			t.Fatal("peer B's session must not link peer A")
		}
	})
	t.Run("IPv6-mapped addresses", func(t *testing.T) {
		all := parseSS(ssMapped)
		if all[0].RHost != "198.51.100.7" || all[0].LPort != 7091 || all[0].RPort != 53000 {
			t.Fatalf("mapped remote must normalise to IPv4: %+v", all[0])
		}
		strict := portOwners([]int{7091, 7093}) // port claimed twice: only a remote match can link
		if r := controlSessionIn(all, ctrlQuery{ID: 20, Port: 7091, RemotePub: "198.51.100.7"}, strict); !r.Linked || r.RTTms != 21.125 {
			t.Fatalf("mapped remote must match RemotePub: %+v", r)
		}
	})
	t.Run("no session", func(t *testing.T) {
		if r := controlSessionIn(parseSS(""), a, owners); r.Linked || r.RTTms != -1 {
			t.Fatalf("empty ss: %+v", r)
		}
		if r := controlSessionIn(parseSS("0 0 1.1.1.1:22 2.2.2.2:5\n"), a, owners); r.Linked {
			t.Fatal("unrelated port must not link")
		}
	})
}

func TestNormHost(t *testing.T) {
	for in, want := range map[string]string{
		"[::ffff:1.2.3.4]": "1.2.3.4", "::ffff:1.2.3.4": "1.2.3.4", "1.2.3.4": "1.2.3.4",
		"[2001:db8::1]": "2001:db8::1", "fe80::1%eth0": "fe80::1", "": "", "host": "host",
	} {
		if got := normHost(in); got != want {
			t.Errorf("normHost(%q)=%q want %q", in, got, want)
		}
	}
}

func stubDial(t *testing.T, f func(addr string) (net.Conn, error)) *[]string {
	t.Helper()
	var calls []string
	prev := dialFn
	dialFn = func(network, addr string, timeout time.Duration) (net.Conn, error) {
		calls = append(calls, addr)
		if timeout != connectProbeTimeout {
			t.Errorf("probe timeout %v, want %v", timeout, connectProbeTimeout)
		}
		return f(addr)
	}
	t.Cleanup(func() { dialFn = prev })
	return &calls
}

func TestConnectProbe(t *testing.T) {
	refused := &net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
	q := ctrlQuery{ID: 1, Port: 7091, RemotePub: "198.51.100.7", PeerGre: "10.10.10.2"}

	calls := stubDial(t, func(addr string) (net.Conn, error) { return nil, refused })
	if r := connectProbe(q); !r.OK || r.Addr != "10.10.10.2:7091" || r.RTTms < 0 {
		t.Fatalf("refusal over the inner address proves reachability: %+v", r)
	}
	if len(*calls) != 1 {
		t.Fatalf("inner success must not try the public address: %v", *calls)
	}

	calls = stubDial(t, func(addr string) (net.Conn, error) {
		if addr == "198.51.100.7:7091" {
			return nil, refused
		}
		return nil, errors.New("i/o timeout")
	})
	if r := connectProbe(q); !r.OK || r.Addr != "198.51.100.7:7091" {
		t.Fatalf("falls back to the public address: %+v", r)
	}
	if len(*calls) != 2 || (*calls)[0] != "10.10.10.2:7091" {
		t.Fatalf("order must be inner then public: %v", *calls)
	}

	stubDial(t, func(addr string) (net.Conn, error) { return nil, errors.New("i/o timeout") })
	if r := connectProbe(q); r.OK || r.RTTms != -1 {
		t.Fatalf("both timing out is a failed probe: %+v", r)
	}
	if r := connectProbe(ctrlQuery{}); r.OK {
		t.Fatal("no target, no probe")
	}
}
