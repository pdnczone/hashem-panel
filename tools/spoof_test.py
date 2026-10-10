#!/usr/bin/env python3
"""spoof-test: check whether spoofed-source packets survive a path, and tunnel them if not.

Mode 1 — direct test: send a UDP packet with a forged source IP straight at
the target. If it arrives, the path has no ingress filtering (spoof works).

Mode 2 — tunnel test: wrap the same forged packet inside the tunnel carrier
(GRE or plain UDP encapsulation) toward a helper on the far end, which
decapsulates and re-injects it locally. If it arrives, spoofing works *via*
the tunnel even though the raw path filters it.

Stdlib only (raw sockets need root/CAP_NET_RAW). One runnable check at the
bottom: loopback self-test.

Usage:
  sudo python3 tools/spoof_test.py direct --target 85.198.48.162 --port 55999 \\
      --spoof-src 192.0.2.1
  # on far end (helper listens, decapsulates, re-injects locally):
  sudo python3 tools/spoof_test.py helper --listen-port 55998 --deliver-port 55999
  # on near end (encapsulate forged packet toward helper):
  sudo python3 tools/spoof_test.py tunnel --helper 85.198.48.162 --helper-port 55998 \\
      --spoof-src 192.0.2.1 --target 127.0.0.1 --port 55999
"""
import argparse
import socket
import struct
import sys

MAGIC = b"SPOOF1\x00"  # 7-byte envelope marker for tunnel mode


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    return (~(s + (s >> 16))) & 0xFFFF


def build_ipv4(src: str, dst: str, proto: int, payload: bytes) -> bytes:
    total = 20 + len(payload)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 54321, 0x4000,
                       64, proto, 0, socket.inet_aton(src), socket.inet_aton(dst))
    csum = checksum(hdr)
    return (struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 54321, 0x4000,
                        64, proto, csum, socket.inet_aton(src),
                        socket.inet_aton(dst)) + payload)


def build_udp(src_port: int, dst_port: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", src_port, dst_port, 8 + len(payload), 0) + payload


def send_raw(packet: bytes, dst: str) -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    s.sendto(packet, (dst, 0))


def cmd_direct(args) -> int:
    """Send one forged-source UDP packet straight at the target."""
    inner = build_udp(45678, args.port, args.message.encode())
    send_raw(build_ipv4(args.spoof_src, args.target, socket.IPPROTO_UDP, inner),
             args.target)
    print(f"direct: sent spoofed {args.spoof_src} -> {args.target}:{args.port}")
    print("check the target with: tcpdump -n 'udp port %d'" % args.port)
    return 0


def cmd_tunnel(args) -> int:
    """Encapsulate the forged packet and hand it to the far-end helper."""
    inner = build_udp(45678, args.port, args.message.encode())
    forged = build_ipv4(args.spoof_src, args.target, socket.IPPROTO_UDP, inner)
    # Envelope: MAGIC + target IP + forged packet; plain UDP to the helper.
    envelope = MAGIC + socket.inet_aton(args.target) + forged
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(envelope, (args.helper, args.helper_port))
    print(f"tunnel: handed {len(forged)}B forged pkt to helper "
          f"{args.helper}:{args.helper_port} for local delivery to {args.target}")
    return 0


def cmd_helper(args) -> int:
    """Listen for envelopes, decapsulate, re-inject the forged packet locally."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", args.listen_port))
    print(f"helper: listening on UDP {args.listen_port} (Ctrl+C to stop)")
    while True:
        data, addr = s.recvfrom(65535)
        if not data.startswith(MAGIC) or len(data) < 11:
            continue
        target = socket.inet_ntoa(data[7:11])
        forged = data[11:]
        # ponytail: no auth on the envelope — anyone who reaches this port can
        # ask for local re-injection. Bind to the tunnel IP or firewall it
        # if the helper listens on a public interface.
        send_raw(forged, target)
        print(f"helper: re-injected {len(forged)}B to {target} (from {addr[0]})")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="spoof-test: forged-source probe + tunnel fallback")
    sub = p.add_subparsers(dest="mode", required=True)

    d = sub.add_parser("direct", help="send forged packet straight at target")
    d.add_argument("--target", required=True)
    d.add_argument("--port", type=int, default=55999)
    d.add_argument("--spoof-src", default="192.0.2.1")
    d.add_argument("--message", default="spoof-test")

    t = sub.add_parser("tunnel", help="hand forged packet to far-end helper")
    t.add_argument("--helper", required=True)
    t.add_argument("--helper-port", type=int, default=55998)
    t.add_argument("--spoof-src", default="192.0.2.1")
    t.add_argument("--target", default="127.0.0.1")
    t.add_argument("--port", type=int, default=55999)
    t.add_argument("--message", default="spoof-test-via-tunnel")

    h = sub.add_parser("helper", help="decapsulate + re-inject (run on far end)")
    h.add_argument("--listen-port", type=int, default=55998)
    h.add_argument("--deliver-port", type=int, default=55999)  # informational

    args = p.parse_args(argv)
    try:
        return {"direct": cmd_direct, "tunnel": cmd_tunnel,
                "helper": cmd_helper}[args.mode](args)
    except PermissionError:
        print("need root (raw sockets)", file=sys.stderr)
        return 1


if __name__ == "__main__":
    # Self-check: build + parse round-trip on loopback structs, no network.
    _pkt = build_ipv4("192.0.2.1", "127.0.0.1", socket.IPPROTO_UDP,
                      build_udp(1, 2, b"x"))
    assert _pkt[12:16] == socket.inet_aton("192.0.2.1"), "src not forged in header"
    assert _pkt[9] == socket.IPPROTO_UDP
    assert MAGIC == b"SPOOF1\x00" and len(MAGIC) == 7
    sys.exit(main())
