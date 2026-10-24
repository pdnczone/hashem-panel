#!/usr/bin/env bash
# tests/test_gre_backhaul_lab.sh — GRE + Backhaul with the real v0.7.2 core.
# Two namespaces joined by a veth (the public path) and a GRE tunnel (inner
# 10.10.10.1 <-> 10.10.10.2, MTU 1380). Uses hashem.sh's own dial_pick, config
# writers and backhaul_wait_link, and proves: the foreign side dials the GRE
# address, 1 MiB crosses byte-exact, a wrong token and a tcp/tcpmux mismatch are
# reported, a silent Iran side is "no answer", and with GRE blocked the dial
# falls back to the public IP and still carries data.
#
# Needs: ip, iptables, ping, python3, the binary, CAP_NET_ADMIN. Skips cleanly
# otherwise. Everything lives in two namespaces + a mktemp dir, removed on exit.
set -u
cd "$(dirname "$0")/.." || exit 1
ROOT=$PWD

BIN=${BACKHAUL_BIN:-/tmp/backhaul-rel/backhaul}
[[ -x $BIN ]] || { echo "SKIP test_gre_backhaul_lab (binary $BIN missing)"; exit 0; }
for c in ip iptables ping python3; do
    command -v "$c" >/dev/null 2>&1 || { echo "SKIP test_gre_backhaul_lab ($c missing)"; exit 0; }
done
[[ $("$BIN" -v 2>&1) == v0.7.2* ]] || { echo "SKIP test_gre_backhaul_lab (unexpected version)"; exit 0; }

HUB=ghb-hub
SPOKE=ghb-spoke
TMP=$(mktemp -d /tmp/ghb-lab.XXXXXX)
pids=()
set +m
cleanup() {
    local p
    for p in "${pids[@]:-}"; do [[ -n $p ]] && { kill -9 "$p"; wait "$p"; } 2>/dev/null; done
    ip netns del "$HUB" 2>/dev/null; ip netns del "$SPOKE" 2>/dev/null
    rm -rf "$TMP"
}
trap cleanup EXIT
cleanup; TMP=$(mktemp -d /tmp/ghb-lab.XXXXXX)
ip netns add "$HUB" 2>/dev/null || { echo "SKIP test_gre_backhaul_lab (no netns permission)"; exit 0; }
ip netns add "$SPOKE"
H="ip netns exec $HUB"; S="ip netns exec $SPOKE"
ip link add ghb-h type veth peer name ghb-s
ip link set ghb-h netns "$HUB"; ip link set ghb-s netns "$SPOKE"
$H sh -c 'ip addr add 192.0.2.1/24 dev ghb-h; ip link set ghb-h up; ip link set lo up
  ip tunnel add gre-tunnel mode gre remote 192.0.2.2 local 192.0.2.1 ttl 255
  ip addr add 10.10.10.1/30 dev gre-tunnel; ip link set gre-tunnel up mtu 1380'
$S sh -c 'ip addr add 192.0.2.2/24 dev ghb-s; ip link set ghb-s up; ip link set lo up
  ip tunnel add gre-tunnel mode gre remote 192.0.2.1 local 192.0.2.2 ttl 255
  ip addr add 10.10.10.2/30 dev gre-tunnel; ip link set gre-tunnel up mtu 1380'

cat > "$TMP/echo.py" <<'PY'
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
PY
cat > "$TMP/probe.py" <<'PY'
import socket, os, sys
m = os.urandom(int(sys.argv[1]))
try:
    s = socket.create_connection(("127.0.0.1", 29001), timeout=10); s.sendall(m); g = b""
    while len(g) < len(m):
        d = s.recv(65536)
        if not d: break
        g += d
    print("OK" if g == m else "MISMATCH")
except Exception as e:
    print("FAIL", type(e).__name__)
PY
$S python3 "$TMP/echo.py" & pids+=($!)

# hashem.sh's own functions
INSTALL_DIR=$(dirname "$BIN"); BACKHAUL_CONFIG_DIR=$TMP; RED=""; GREEN=""; YELLOW=""; CYAN=""; NC=""
ext() { awk -v n="$1" '$0 ~ "^"n"\\(\\) \\{" {p=1} p {print} p && /^}/ {exit}' "$ROOT/hashem.sh"; }
eval "$(grep -E '^(BACKHAUL_TRANSPORTS|backhaul_transport_ok|backhaul_udp_wanted)' "$ROOT/hashem.sh")"
for f in hostonly backhaul_is_v2 backhaul_write_server_conf_v1 backhaul_write_client_conf_v1 backhaul_write_server_conf \
         backhaul_write_client_conf dial_gre_usable dial_pick backhaul_wait_link; do
    b="$(ext $f)"; [[ -n "$b" ]] || { echo "FAIL: $f missing from hashem.sh"; exit 1; }; eval "$b"
done
backhaul_ensure_tls() { :; }
journalctl() { cat "$TMP/client.log"; }   # backhaul_wait_link reads the client's log

fail=0
check() { if [[ "$2" != "$3" ]]; then echo "FAIL: $1 (want [$2] got [$3])"; fail=1; else echo "ok:   $1"; fi; }
SP=""; CP=""
start() { # server_transport server_token client_transport client_token
    backhaul_write_server_conf "$TMP/s.toml" "0.0.0.0:3080" "$1" "$2" "29001=19001"
    $H "$BIN" -c "$TMP/s.toml" > "$TMP/server.log" 2>&1 & SP=$!; pids+=($SP)
    sleep 1
    DIAL=$($S bash -c "$(declare -f dial_gre_usable dial_pick); dial_pick auto 10.10.10.1 192.0.2.1 3080")
    backhaul_write_client_conf "$TMP/c.toml" "${DIAL}:3080" "$3" "$4"
    $S "$BIN" -c "$TMP/c.toml" > "$TMP/client.log" 2>&1 & CP=$!; pids+=($CP)
}
stop() { kill -9 $SP $CP 2>/dev/null; wait $SP $CP 2>/dev/null; SP=""; CP=""; sleep 1; }
link() { backhaul_wait_link backhaul-client x 12; echo $?; }

start tcpmux tok tcpmux tok
check "dial picks the GRE address" 10.10.10.1 "$DIAL"
check "link up" 0 "$(link)"
check "16 B over GRE" OK "$($H python3 "$TMP/probe.py" 16)"
check "1 MiB over GRE (MTU 1380)" OK "$($H python3 "$TMP/probe.py" 1048576)"
stop

start tcpmux tok tcpmux wrong-token
check "wrong token reported" 1 "$(link)"
stop

start tcp tok tcpmux tok
check "tcp hub / tcpmux spoke reported" 1 "$(link)"
stop

DIAL=10.10.10.1; backhaul_write_client_conf "$TMP/c.toml" "10.10.10.1:3080" tcpmux tok
$S "$BIN" -c "$TMP/c.toml" > "$TMP/client.log" 2>&1 & CP=$!; pids+=($CP)
check "silent Iran side is no answer" 2 "$(link)"
stop

$S iptables -A INPUT -p 47 -j DROP
start tcpmux tok tcpmux tok
check "GRE blocked: dial falls back to public" 192.0.2.1 "$DIAL"
check "link up over the public IP" 0 "$(link)"
check "data over the public IP" OK "$($H python3 "$TMP/probe.py" 4096)"
stop

(( fail )) && exit 1; echo "PASS test_gre_backhaul_lab"
