#!/usr/bin/env bash
# tests/test_pathtest_lab.sh — the Benchmark tab's path test (gre-panel pathtest)
# between two namespaces joined by a veth (Iran 192.0.2.1, foreign 192.0.2.2),
# with the real frps/frpc and Backhaul v0.7.2 cores and no tunnel installed:
#
#  1. open path: every check works (plain TCP/UDP, GRE, SSH banner, FRP x 5,
#     Backhaul x 7), data crosses each transport and a speed is measured.
#  2. a filtered path: UDP and GRE dropped and Backhaul ws's port blocked on the
#     way to Iran -> exactly those checks are "fail", the rest still "ok".
#  3. next to a live tunnel (GRE + Backhaul tcpmux on port 41000, the test's
#     default first port): the test picks the next free ports by itself, all
#     checks work (its keyed GRE beside the tunnel's GRE to the same peer), and
#     the tunnel carries data every half second during the test without a miss.
#  4. nothing is left behind: no hpt0 interface, no core process, no temp dir.
#
# The path test is Hashem Pro: PT_LICENSE is a license for it, and PANEL_BIN is
# built to trust its signing key (see TestWriteLabLicense in panel/). Without a
# license the command must refuse.
#
# Needs: PANEL_BIN (linux gre-panel), PT_LICENSE, ip, iptables, ping, python3, the cores in
# FRP_DIR and BACKHAUL_BIN, CAP_NET_ADMIN. Skips cleanly otherwise.
set -u
cd "$(dirname "$0")/.." || exit 1

PANEL=${PANEL_BIN:-}
BIN=${BACKHAUL_BIN:-/tmp/backhaul-rel/backhaul}
FRP_DIR=${FRP_DIR:-/tmp/frp-rel}
[[ -n $PANEL && -x $PANEL ]] || { echo "SKIP test_pathtest_lab (PANEL_BIN not set)"; exit 0; }
LIC=${PT_LICENSE:-}
[[ -n $LIC && -f $LIC ]] || { echo "SKIP test_pathtest_lab (PT_LICENSE not set)"; exit 0; }
[[ -x $BIN && -x $FRP_DIR/frps && -x $FRP_DIR/frpc ]] || { echo "SKIP test_pathtest_lab (cores missing)"; exit 0; }
for c in ip iptables ping python3 timeout; do
    command -v "$c" >/dev/null 2>&1 || { echo "SKIP test_pathtest_lab ($c missing)"; exit 0; }
done

HUB=pt-iran
SPOKE=pt-foreign
TMP=$(mktemp -d /tmp/pt-lab.XXXXXX)
pids=()
set +m
cleanup() {
    local p
    for p in "${pids[@]:-}"; do [[ -n $p ]] && { kill -9 "$p"; wait "$p"; } 2>/dev/null; done
    ip netns pids "$HUB" 2>/dev/null | xargs -r kill -9 2>/dev/null
    ip netns pids "$SPOKE" 2>/dev/null | xargs -r kill -9 2>/dev/null
    ip netns del "$HUB" 2>/dev/null; ip netns del "$SPOKE" 2>/dev/null
    # the panel copies a valid key to /etc/hashem; take the lab's key back out
    cmp -s /etc/hashem/license.key "$LIC" 2>/dev/null && rm -f /etc/hashem/license.key
    rm -rf "$TMP"
}
trap cleanup EXIT
ip netns del "$HUB" 2>/dev/null; ip netns del "$SPOKE" 2>/dev/null
ip netns add "$HUB" 2>/dev/null || { echo "SKIP test_pathtest_lab (no netns permission)"; exit 0; }
ip netns add "$SPOKE"
H="ip netns exec $HUB"; S="ip netns exec $SPOKE"
ip link add pt-h type veth peer name pt-s
ip link set pt-h netns "$HUB"; ip link set pt-s netns "$SPOKE"
$H sh -c 'ip addr add 192.0.2.1/24 dev pt-h; ip link set pt-h up; ip link set lo up'
$S sh -c 'ip addr add 192.0.2.2/24 dev pt-s; ip link set pt-s up; ip link set lo up'

# the cores, where the panel looks for them
mkdir -p "$TMP/cores"
ln -s "$FRP_DIR/frps" "$TMP/cores/frps"; ln -s "$FRP_DIR/frpc" "$TMP/cores/frpc"; ln -s "$BIN" "$TMP/cores/backhaul"
export HASHEM_CORE_DIR="$TMP/cores" HASHEM_PT_GRACE=25s TMPDIR="$TMP"

# an SSH server stand-in on the foreign side (Bagher dials it from Iran)
$S python3 -c '
import socket
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("192.0.2.2", 2222)); s.listen(20)
while True:
    c, _ = s.accept(); c.sendall(b"SSH-2.0-OpenSSH_9.6\r\n"); c.close()
' & pids+=($!)

fail=0
fails=()
check() { if [[ "$2" != "$3" ]]; then echo "FAIL: $1 (want [$2] got [$3])"; fail=1; fails+=("$1 (want [$2] got [$3])"); else echo "ok:   $1"; fi; }

# run_test PORT -> Iran's JSON results in $TMP/hub.json, the foreign side's in $TMP/spoke.json
run_test() {
    : > "$TMP/hub.out"
    local port=(-port "$1"); [[ $1 == auto ]] && port=()
    $H env GRE_PANEL_DIR="$TMP/cfg-hub" "$PANEL" pathtest serve "${port[@]}" -ip 192.0.2.1 -foreign 192.0.2.2 -ssh 2222 -minutes 3 > "$TMP/hub.out" 2>&1 &
    local hp=$! i code=""
    for i in $(seq 1 50); do code=$(awk '/^CODE /{print $2}' "$TMP/hub.out"); [[ -n $code ]] && break; sleep 0.2; done
    [[ -n $code ]] || { echo "FAIL: no code from serve"; cat "$TMP/hub.out"; fail=1; kill $hp; return; }
    $S env GRE_PANEL_DIR="$TMP/cfg-spoke" "$PANEL" pathtest join "$code" > "$TMP/spoke.out" 2>&1 &
    local sp=$!
    for i in $(seq 1 150); do kill -0 $hp 2>/dev/null || break; sleep 1; done
    kill $hp 2>/dev/null; wait $hp 2>/dev/null
    for i in $(seq 1 30); do kill -0 $sp 2>/dev/null || break; sleep 1; done
    kill $sp 2>/dev/null; wait $sp 2>/dev/null
    sed -n 's/^JSON //p' "$TMP/hub.out" > "$TMP/hub.json"
    sed -n 's/^JSON //p' "$TMP/spoke.out" > "$TMP/spoke.json"
    grep -v '^JSON ' "$TMP/hub.out"
}
# status_of FILE ID -> status ; field FILE ID KEY -> value
status_of() { python3 -c 'import json,sys; d={c["id"]:c for c in json.load(open(sys.argv[1]))}; print(d.get(sys.argv[2],{}).get("status","missing"))' "$1" "$2" 2>/dev/null || echo none; }
has_num()   { python3 -c 'import json,sys; d={c["id"]:c for c in json.load(open(sys.argv[1]))}; print("yes" if d.get(sys.argv[2],{}).get(sys.argv[3],0)>0 else "no")' "$1" "$2" "$3" 2>/dev/null || echo none; }

# ---- 0. no license: the command refuses, before it opens anything ----
mkdir -p "$TMP/cfg-none" "$TMP/cfg-hub" "$TMP/cfg-spoke"
$H env GRE_PANEL_DIR="$TMP/cfg-none" "$PANEL" pathtest serve -ip 192.0.2.1 -minutes 1 > "$TMP/nolic.out" 2>&1; rc=$?
check "no license: serve refuses" 1 "$rc"
check "no license: says it is Hashem Pro" yes "$(grep -q 'Hashem Pro feature' "$TMP/nolic.out" && echo yes)"
check "no license: nothing listening" "" "$($H ss -Htln 'sport = :41000' 2>/dev/null)"
cp "$LIC" "$TMP/cfg-hub/license.key"; cp "$LIC" "$TMP/cfg-spoke/license.key"

ALL="tcp udp gre ssh frp-tcp frp-websocket frp-wss frp-kcp frp-quic bh-tcp bh-tcpmux bh-ws bh-wss bh-wsmux bh-wssmux bh-udp"

# ---- 1. open path ----
echo "== open path"
run_test 41000
for id in $ALL; do check "open: $id works" ok "$(status_of "$TMP/hub.json" "$id")"; done
for id in frp-tcp frp-kcp frp-wss bh-tcpmux bh-wssmux; do check "open: $id has a speed" yes "$(has_num "$TMP/hub.json" "$id" mbps)"; done
check "open: bh-udp has a latency" yes "$(has_num "$TMP/hub.json" bh-udp rtt_ms)"
check "open: the foreign side got Iran's results" ok "$(status_of "$TMP/spoke.json" bh-tcpmux)"

# ---- 2. filtered path: UDP, GRE and Backhaul ws's port dropped towards Iran ----
echo "== filtered path"
$S iptables -A OUTPUT -d 192.0.2.1 -p udp -j DROP
$S iptables -A OUTPUT -d 192.0.2.1 -p 47 -j DROP
$S iptables -A OUTPUT -d 192.0.2.1 -p tcp --dport 42006 -j DROP
run_test 42000
for id in udp gre frp-kcp frp-quic bh-udp bh-ws; do check "filtered: $id blocked" fail "$(status_of "$TMP/hub.json" "$id")"; done
for id in tcp ssh frp-tcp frp-websocket frp-wss bh-tcp bh-tcpmux bh-wss bh-wsmux bh-wssmux; do
    check "filtered: $id still works" ok "$(status_of "$TMP/hub.json" "$id")"
done
$S iptables -F OUTPUT

# ---- 3. next to a live tunnel ----
echo "== next to a live tunnel"
$H sh -c 'ip tunnel add gre-tunnel mode gre local 192.0.2.1 remote 192.0.2.2 ttl 255; ip addr add 10.10.10.1/30 dev gre-tunnel; ip link set gre-tunnel up mtu 1380'
$S sh -c 'ip tunnel add gre-tunnel mode gre local 192.0.2.2 remote 192.0.2.1 ttl 255; ip addr add 10.10.10.2/30 dev gre-tunnel; ip link set gre-tunnel up mtu 1380'
$S python3 -c '
import socket, threading
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("127.0.0.1", 19001)); s.listen(50)
def h(c):
    while True:
        d = c.recv(65536)
        if not d: break
        c.sendall(d)
    c.close()
while True:
    c, _ = s.accept(); threading.Thread(target=h, args=(c,), daemon=True).start()
' & pids+=($!)
cat > "$TMP/live-s.toml" <<'EOT'
[server]
bind_addr = "0.0.0.0:41000"
transport = "tcpmux"
token = "live"
nodelay = true
ports = ["127.0.0.1:29001=19001"]
EOT
cat > "$TMP/live-c.toml" <<'EOT'
[client]
remote_addr = "10.10.10.1:41000"
transport = "tcpmux"
token = "live"
connection_pool = 4
nodelay = true
retry_interval = 1
EOT
$H "$BIN" -c "$TMP/live-s.toml" > "$TMP/live-s.log" 2>&1 & pids+=($!)
sleep 1
$S "$BIN" -c "$TMP/live-c.toml" > "$TMP/live-c.log" 2>&1 & pids+=($!)
# the tunnel's user: 4 KiB through it and a ping over its GRE, every half second
cat > "$TMP/live.py" <<'PY'
import os, socket, subprocess, sys, time
log, stop, once = sys.argv[1], sys.argv[2], len(sys.argv) > 3
while True:
    r = "OK"
    try:
        m = os.urandom(4096); c = socket.create_connection(("127.0.0.1", 29001), timeout=3); c.sendall(m); g = b""
        while len(g) < len(m):
            d = c.recv(65536)
            if not d: break
            g += d
        c.close()
        if g != m: r = "FAIL data"
    except Exception as e:
        r = "FAIL " + type(e).__name__
    if r == "OK" and subprocess.call(["ping", "-c1", "-W1", "10.10.10.2"], stdout=subprocess.DEVNULL) != 0:
        r = "FAIL gre ping"
    if once:
        print(r); break
    open(log, "a").write(r + "\n")
    if os.path.exists(stop): break
    time.sleep(0.5)
PY
up=""; for i in $(seq 1 40); do up=$($H python3 "$TMP/live.py" x x once); [[ $up == OK ]] && break; sleep 0.5; done
check "live: the tunnel carries data before the test" OK "$up"
rm -f "$TMP/live.stop" "$TMP/live.log"
$H python3 "$TMP/live.py" "$TMP/live.log" "$TMP/live.stop" & lp=$!; pids+=($lp)
run_test auto
touch "$TMP/live.stop"; wait $lp 2>/dev/null
grep -q "NOTE ports from 41000 are in use on this server, so the test uses 41040-41050" "$TMP/hub.out" && moved=yes || moved=no
check "live: the test moved off the tunnel's port 41000 by itself" yes "$moved"
for id in $ALL; do check "live: $id works" ok "$(status_of "$TMP/hub.json" "$id")"; done
check "live: tunnel never missed during the test" 0 "$(grep -c FAIL "$TMP/live.log")"
(( $(grep -c OK "$TMP/live.log") >= 20 )) && n=enough || n="only $(grep -c OK "$TMP/live.log")"
check "live: tunnel checked all through the test" enough "$n"
check "live: tunnel still carries data after the test" OK "$($H python3 "$TMP/live.py" x x once)"
check "live: the tunnel's GRE is still there" yes "$($H ip link show gre-tunnel >/dev/null 2>&1 && echo yes)"

# ---- 4. nothing left behind ----
sleep 1
check "no hpt0 left (Iran)" "" "$($H ip -o link show hpt0 2>/dev/null)"
check "no hpt0 left (foreign)" "" "$($S ip -o link show hpt0 2>/dev/null)"
check "no core process left" "" "$(pgrep -f "$TMP/cores/" || true)"
check "no temp dir left" "" "$(ls -d "$TMP"/hashem-pathtest-* 2>/dev/null)"

if [[ -n ${GITHUB_ACTIONS:-} ]]; then
    for r in "${fails[@]:0:9}"; do echo "::error title=Path test lab::$r"; done
    if (( fail )) && [[ -s $TMP/hub.out ]]; then
        out=$(grep -v '^JSON ' "$TMP/hub.out" | tail -n 40 | sed -e 's/%/%25/g' | sed -e ':a;N;$!ba;s/\n/%0A/g')
        echo "::warning title=Path test lab, last Iran output::$out"
    fi
fi
(( fail )) && exit 1; echo "PASS test_pathtest_lab"
