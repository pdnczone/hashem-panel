#!/usr/bin/env bash
# tests/test_limits_lab.sh — speed and volume limits per foreign server with
# the real kernel.
#
# A hub (lm-hub) and a foreign server (lm-fo) in network namespaces, joined by
# a veth that is the hub's default route. A sink on the foreign server; the
# panel's limits code (panel/limits_lab_test.go) runs in the hub namespace
# with the real iptables and tc: a 20 Mbit/s policer both ways, a 30 MB
# volume counted against exact bytes and then cut (DROP), reset and remove.
#
# Needs root (netns), ip, iptables(-save/-restore), tc, python3 and Go or a
# prebuilt test binary (LIMITS_LAB_TEST_BIN). Skips cleanly otherwise.
# Touches nothing outside the two namespaces and a mktemp dir.
set -u
cd "$(dirname "$0")/.." || exit 1
ROOT=$PWD

for c in ip tc python3 iptables-save iptables-restore; do
    command -v "$c" >/dev/null 2>&1 || { echo "SKIP test_limits_lab ($c missing)"; exit 0; }
done
HUB=lm-hub; FO=lm-fo
HUB_IP=10.19.0.1; FO_IP=10.19.0.2
HUB_IP6=2001:db8:19::1; FO_IP6=2001:db8:19::2
TMP=$(mktemp -d /tmp/limits-lab.XXXXXX)
chmod 755 "$TMP"
cleanup() {
    for ns in $HUB $FO; do ip netns pids "$ns" 2>/dev/null | xargs -r kill -9 2>/dev/null; ip netns del "$ns" 2>/dev/null; done
    rm -rf "$TMP"
}
trap cleanup EXIT
for ns in $HUB $FO; do ip netns del "$ns" 2>/dev/null; done
ip netns add $HUB 2>/dev/null || { echo "SKIP test_limits_lab (no netns permission)"; exit 0; }
ip netns add $FO || { echo "SKIP test_limits_lab (netns)"; exit 0; }
ip link add lm-hub0 netns $HUB type veth peer name lm-fo0 netns $FO || { echo "SKIP test_limits_lab (veth unsupported)"; exit 0; }
ip -n $HUB addr add $HUB_IP/24 dev lm-hub0; ip -n $FO addr add $FO_IP/24 dev lm-fo0
for l in "$HUB lm-hub0" "$HUB lo" "$FO lm-fo0" "$FO lo"; do set -- $l; ip -n "$1" link set "$2" up; done
ip -n $HUB route add default via $FO_IP dev lm-hub0   # the panel polices on the default-route interface
V6=1
for a in "$HUB lm-hub0 $HUB_IP6" "$FO lm-fo0 $FO_IP6"; do
    set -- $a
    ip netns exec "$1" sysctl -qw net.ipv6.conf.all.disable_ipv6=0 2>/dev/null
    ip -n "$1" -6 addr add "$3/64" dev "$2" nodad 2>/dev/null || V6=
done

cat >"$TMP/sink.py" <<'PY'
import socket, struct, threading
CHUNK = b"\0" * 65536
def serve(c):
    try:
        hdr = b""
        while len(hdr) < 16:
            b = c.recv(16 - len(hdr))
            if not b: return
            hdr += b
        up, down = struct.unpack("!QQ", hdr)
        got = 0
        while got < up:
            b = c.recv(min(1 << 20, up - got))
            if not b: return
            got += len(b)
        if down == 0:
            c.sendall(b"k")
        while down > 0:
            n = min(down, len(CHUNK))
            c.sendall(CHUNK[:n])
            down -= n
    finally:
        c.close()
s = socket.socket(socket.AF_INET6); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)   # IPv4 and IPv6
s.bind(("::", 9000)); s.listen(16)
while True:
    c, _ = s.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
PY
ip netns exec $FO python3 "$TMP/sink.py" >/dev/null 2>&1 &
for _ in $(seq 50); do ip netns exec $HUB bash -c "exec 3<>/dev/tcp/$FO_IP/9000" 2>/dev/null && break; sleep 0.1; done

BIN=${LIMITS_LAB_TEST_BIN:-}
if [[ -z $BIN ]]; then
    command -v go >/dev/null 2>&1 || { echo "SKIP test_limits_lab (no go and no LIMITS_LAB_TEST_BIN)"; exit 0; }
    (cd "$ROOT/panel" && go test -c -o "$TMP/limitslab.test" .) || { echo "FAIL: build"; exit 1; }
    BIN=$TMP/limitslab.test
fi
(cd "$ROOT/panel" && ip netns exec $HUB env LIMITS_LAB_FOREIGN=$FO_IP \
    "$BIN" -test.run '^TestLimitsLab$' -test.v >"$TMP/lab.log" 2>&1)
rc=$?
# the same on IPv6: ip6tables, tc protocol ipv6 (pref 4918)
if [[ -n $V6 && $rc -eq 0 ]]; then
    echo "-- IPv6 round (foreign server $FO_IP6)" >>"$TMP/lab.log"
    (cd "$ROOT/panel" && ip netns exec $HUB env LIMITS_LAB_FOREIGN=$FO_IP6 \
        "$BIN" -test.run '^TestLimitsLab$' -test.v 2>&1 | sed 's/limits_lab_test.go:/limits_lab_test.go(IPv6):/' >>"$TMP/lab.log")
    grep -q "^--- FAIL" "$TMP/lab.log" && rc=1
fi
grep -E "limits_lab_test.go|^(--- |ok|FAIL|PASS|-- IPv6)" "$TMP/lab.log"
# the measured rates, as notices on the CI run
[[ -n ${GITHUB_ACTIONS:-} && $rc -eq 0 ]] && grep -E "limits_lab_test.go(\(IPv6\))?:[0-9]+:" "$TMP/lab.log" | sed 's/^ *//; s/^/::notice title=limits lab::/'
if [[ $rc -ne 0 ]]; then
    tail -40 "$TMP/lab.log"
    [[ -n ${GITHUB_ACTIONS:-} ]] && grep -E "limits_lab_test.go(\(IPv6\))?:[0-9]+:" "$TMP/lab.log" | sed 's/^ *//; s/^/::error title=limits lab::/'
    echo "FAIL: test_limits_lab"
    exit 1
fi
echo "PASS: test_limits_lab"
