package main

// Inner addresses of the GRE tunnels. A tunnel's two ends are the two hosts of
// one /30, so a pair is free only when its whole /30 is: no address of another
// tunnel in it, and not inside a network this server is connected to (a
// provider's private network, a Docker bridge): the /30 route would take its
// hosts away. Two Iran hubs must not give the same pair to one foreign server
// either, so the pairs of the linked hubs count as used too.

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// greNet reads "10.11.0.2" (its /30) or "10.0.0.0/8"; nil for anything else.
func greNet(s string) *net.IPNet {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, "/") {
		ip := net.ParseIP(s).To4()
		if ip == nil {
			return nil
		}
		m := net.CIDRMask(30, 32)
		return &net.IPNet{IP: ip.Mask(m), Mask: m}
	}
	ip, n, err := net.ParseCIDR(s)
	if err != nil || ip.To4() == nil {
		return nil
	}
	if ones, _ := n.Mask.Size(); ones == 0 || ones == 32 {
		if ones == 0 {
			return nil
		}
		return greNet(ip.String())
	}
	return n
}

// greOverlap is the first of used (addresses and networks) that overlaps the
// /30 of a; "" when none does.
func greOverlap(a string, used []string) string {
	n := greNet(a)
	if n == nil {
		return ""
	}
	for _, u := range used {
		if x := greNet(u); x != nil && (x.Contains(n.IP) || n.Contains(x.IP)) {
			return u
		}
	}
	return ""
}

// grePairOK: the two addresses are the two hosts of one /30.
func grePairOK(a, b string) bool {
	x, y := net.ParseIP(a).To4(), net.ParseIP(b).To4()
	if x == nil || y == nil || gre30(a) != gre30(b) {
		return false
	}
	return (x[3]&3 == 1 && y[3]&3 == 2) || (x[3]&3 == 2 && y[3]&3 == 1)
}

// greFreePair is the first free pair (Iran's address, the foreign server's);
// empty when none is.
func greFreePair(used []string) (string, string) {
	pairs := [][2]string{{defaultIranGRE, defaultForeignGRE}}
	for k := 1; k <= 89; k++ {
		pairs = append(pairs, [2]string{fmt.Sprintf("10.1%d.0.2", k), fmt.Sprintf("10.1%d.0.1", k)})
	}
	// a server whose private network is all of 10.0.0.0/8
	for k := 1; k <= 60; k++ {
		pairs = append(pairs, [2]string{fmt.Sprintf("172.30.%d.2", k), fmt.Sprintf("172.30.%d.1", k)})
	}
	for k := 1; k <= 60; k++ {
		pairs = append(pairs, [2]string{fmt.Sprintf("192.168.%d.2", 190+k), fmt.Sprintf("192.168.%d.1", 190+k)})
	}
	for _, p := range pairs {
		if greOverlap(p[0], used) == "" {
			return p[0], p[1]
		}
	}
	return "", ""
}

// greConnected are the IPv4 networks of this server's interfaces and the
// private networks it has a route to.
func greConnected() []string {
	var out []string
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ip, n, err := net.ParseCIDR(a.String()); err == nil && ip.To4() != nil && !ip.IsLoopback() {
				out = append(out, ip.String())
				if ones, _ := n.Mask.Size(); ones > 0 && ones < 32 {
					out = append(out, n.String())
				}
			}
		}
	}
	data, _ := os.ReadFile(filepath.Join(procNetRoot, "route"))
	for i, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if i == 0 || len(f) < 8 || f[0] == "lo" {
			continue
		}
		d, err1 := strconv.ParseUint(f[1], 16, 32)
		m, err2 := strconv.ParseUint(f[7], 16, 32)
		if err1 != nil || err2 != nil || m == 0 {
			continue
		}
		ip, mask := make(net.IP, 4), make(net.IPMask, 4)
		binary.LittleEndian.PutUint32(ip, uint32(d))
		binary.LittleEndian.PutUint32(mask, uint32(m))
		if ones, _ := mask.Size(); ones < 8 || !ip.IsPrivate() {
			continue
		}
		out = append(out, (&net.IPNet{IP: ip, Mask: mask}).String())
	}
	return out
}

// greHubs are the pairs of the linked Iran hubs' tunnels, asked in the
// background at most once a minute (a hub that does not answer keeps what it
// said last).
var greHubs struct {
	sync.Mutex
	at   time.Time
	busy bool
	m    map[string][]string
}

// greHubsGo runs the refresh (tests run it in place).
var greHubsGo = func(f func()) { go f() }

// clusterGre lists them as known now. The heartbeat loop keeps them fresh.
func clusterGre() []string {
	c := loadClusterConfig()
	if c.Secret == "" || len(c.Hubs) == 0 {
		return nil
	}
	clusterGreRefresh(c)
	greHubs.Lock()
	defer greHubs.Unlock()
	var out []string
	for _, h := range c.Hubs {
		out = append(out, greHubs.m[h.ID]...)
	}
	return out
}

func clusterGreRefresh(c ClusterConfig) {
	greHubs.Lock()
	due := !greHubs.busy && time.Since(greHubs.at) > time.Minute
	if due {
		greHubs.busy = true
	}
	greHubs.Unlock()
	if !due {
		return
	}
	greHubsGo(func() {
		got := make([][]string, len(c.Hubs))
		var wg sync.WaitGroup
		for i, h := range c.Hubs {
			wg.Add(1)
			go func(i int, h HubPeer) {
				defer wg.Done()
				var l syncList
				if meshCall(h, c.Secret, "/tunnels", map[string]string{"id": c.NodeID}, &l, 4*time.Second) != nil {
					return
				}
				got[i] = []string{}
				for _, t := range l.Tunnels {
					if t.LocalGre != "" {
						got[i] = append(got[i], t.LocalGre, t.PeerGre)
					}
				}
			}(i, h)
		}
		wg.Wait()
		greHubs.Lock()
		defer greHubs.Unlock()
		if greHubs.m == nil {
			greHubs.m = map[string][]string{}
		}
		for i, h := range c.Hubs {
			if got[i] != nil {
				greHubs.m[h.ID] = got[i]
			}
		}
		greHubs.at, greHubs.busy = time.Now(), false
	})
}
