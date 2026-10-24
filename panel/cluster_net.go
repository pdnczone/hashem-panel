package main

// Host observations for the cluster's fast health loop. They run every second,
// so nothing here forks: sockets come from /proc/net and ICMP goes through one
// raw socket per round.

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Socket states as /proc/net/tcp prints them (hex).
const (
	sockEstablished = 0x01
	sockListen      = 0x0A
	sockUDPBound    = 0x07
)

type sockInfo struct {
	Proto  string // "tcp" | "udp"
	Local  netip.AddrPort
	Remote netip.AddrPort
	State  uint8
}

// procNetRoot is /proc/net; tests point it at a temp dir.
var procNetRoot = "/proc/net"

// readSockets returns every TCP and UDP socket of the host, IPv4 and IPv6.
// IPv4-mapped IPv6 addresses are unmapped so callers compare plain IPv4.
func readSockets() []sockInfo {
	var out []sockInfo
	for _, f := range []struct{ file, proto string }{{"tcp", "tcp"}, {"tcp6", "tcp"}, {"udp", "udp"}, {"udp6", "udp"}} {
		data, err := os.ReadFile(filepath.Join(procNetRoot, f.file))
		if err != nil {
			continue
		}
		out = append(out, parseProcNet(string(data), f.proto)...)
	}
	return out
}

// parseProcNet parses one /proc/net/{tcp,tcp6,udp,udp6} table.
func parseProcNet(data, proto string) []sockInfo {
	var out []sockInfo
	for i, line := range strings.Split(data, "\n") {
		if i == 0 {
			continue // header
		}
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		local, ok1 := parseProcAddr(f[1])
		remote, ok2 := parseProcAddr(f[2])
		st, err := hex.DecodeString(f[3])
		if !ok1 || !ok2 || err != nil || len(st) != 1 {
			continue
		}
		out = append(out, sockInfo{Proto: proto, Local: local, Remote: remote, State: st[0]})
	}
	return out
}

// parseProcAddr decodes "0100007F:1F90" (IPv4) or the 32-digit IPv6 form. The
// kernel prints each 32-bit word in host (little-endian) byte order.
func parseProcAddr(s string) (netip.AddrPort, bool) {
	host, port, ok := strings.Cut(s, ":")
	if !ok {
		return netip.AddrPort{}, false
	}
	pb, err := hex.DecodeString(port)
	if err != nil || len(pb) != 2 {
		return netip.AddrPort{}, false
	}
	hb, err := hex.DecodeString(host)
	if err != nil || (len(hb) != 4 && len(hb) != 16) {
		return netip.AddrPort{}, false
	}
	for w := 0; w+4 <= len(hb); w += 4 {
		hb[w], hb[w+1], hb[w+2], hb[w+3] = hb[w+3], hb[w+2], hb[w+1], hb[w]
	}
	a, ok := netip.AddrFromSlice(hb)
	if !ok {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(a.Unmap(), binary.BigEndian.Uint16(pb)), true
}

// ---- ICMP ----

// lbPinger sends one echo to every target and returns the round trip in ms
// (-1 = no answer). ok is false when ICMP cannot be used at all (no raw
// socket): callers then treat ICMP as unknown, not as failing.
var lbPinger = icmpPingAll

var icmpSeq struct {
	sync.Mutex
	n uint16
}

func icmpPingAll(targets []string, timeout time.Duration) (res map[string]float64, ok bool) {
	res = make(map[string]float64, len(targets))
	var v4 []netip.Addr
	for _, t := range targets {
		res[t] = -1
		if a, err := netip.ParseAddr(t); err == nil && a.Unmap().Is4() {
			v4 = append(v4, a.Unmap())
		}
	}
	if len(v4) == 0 {
		return res, true
	}
	c, err := net.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return res, false
	}
	defer c.Close()

	icmpSeq.Lock()
	icmpSeq.n++
	seq := icmpSeq.n
	icmpSeq.Unlock()
	const id = 0x4853 // "HS"
	sent := make(map[netip.Addr]time.Time, len(v4))
	for _, a := range v4 {
		msg := icmpEcho(id, seq)
		if _, err := c.WriteTo(msg, &net.IPAddr{IP: a.AsSlice()}); err == nil {
			sent[a] = time.Now()
		}
	}
	_ = c.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 1500)
	for left := len(sent); left > 0; {
		n, from, err := c.ReadFrom(buf)
		if err != nil {
			break
		}
		ip, _ := from.(*net.IPAddr)
		if ip == nil || n < 8 || buf[0] != 0 || binary.BigEndian.Uint16(buf[4:]) != id || binary.BigEndian.Uint16(buf[6:]) != seq {
			continue
		}
		a, _ := netip.AddrFromSlice(ip.IP)
		a = a.Unmap()
		if at, ok := sent[a]; ok && res[a.String()] < 0 {
			res[a.String()] = float64(time.Since(at).Microseconds()) / 1000
			left--
		}
	}
	return res, true
}

// icmpEcho builds an ICMP echo request with an 8-byte payload.
func icmpEcho(id, seq uint16) []byte {
	b := make([]byte, 16)
	b[0] = 8 // echo request
	binary.BigEndian.PutUint16(b[4:], id)
	binary.BigEndian.PutUint16(b[6:], seq)
	copy(b[8:], "hashemlb")
	binary.BigEndian.PutUint16(b[2:], icmpChecksum(b))
	return b
}

func icmpChecksum(b []byte) uint16 {
	var s uint32
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		s += uint32(b[len(b)-1]) << 8
	}
	for s>>16 != 0 {
		s = s&0xffff + s>>16
	}
	return ^uint16(s)
}

// lbProbeHold is how long the service check waits on an open connection: one
// that is still open (the service waits for the client, as TLS does) or that
// answered by then works.
const lbProbeHold = 1500 * time.Millisecond

// lbTCPProbe opens a connection through a member's relay (its private
// address) to the service on the foreign server. When the service is down,
// the foreign client cannot reach it and the relay closes the connection at
// once; that, a refusal or a reset fails the check.
func lbTCPProbe(addr string, port int, timeout time.Duration) (bool, string) {
	c, err := net.DialTimeout("tcp", net.JoinHostPort(addr, strconv.Itoa(port)), timeout)
	if err != nil {
		return false, "the relay did not take the connection"
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(lbProbeHold))
	n, err := c.Read(make([]byte, 1))
	var ne net.Error
	switch {
	case n > 0:
		return true, ""
	case errors.As(err, &ne) && ne.Timeout():
		return true, ""
	case errors.Is(err, io.EOF):
		return false, "the connection was closed at once: the service on the foreign server did not take it"
	}
	return false, "the connection was reset: the service on the foreign server did not take it"
}
