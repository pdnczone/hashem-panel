#!/usr/bin/env bash
# tests/test_tunnel_combos_lab.sh — every tunnel combination Setup offers, with the
# real cores. Two namespaces joined by a veth (the public path, 192.0.2.1 <-> .2)
# and a GRE tunnel (inner 10.10.10.1 <-> 10.10.10.2, MTU 1380):
#
#  1. Backhaul with GRE and without GRE, on all 7 transports, plus UDP over tcp
#     (accept_udp): the link comes up and data crosses byte-exact. "Without GRE"
#     runs with GRE (protocol 47) dropped, so it cannot lean on GRE.
#  2. Route of the foreign side (Backhaul with GRE): GRE blocked at setup -> the
#     public IP; GRE back -> the watchdog moves the client to GRE after
#     DIAL_BACK_TICKS good ticks and data flows over GRE; GRE dies -> public again.
#  3. The same route switching for GRE + FRP with the real frps / frpc (skipped
#     when FRP_DIR has no binaries).
#
# Uses hashem.sh's own config writers, dial_pick and dial_watch_tick. Needs: ip,
# iptables, ping, python3, openssl, the Backhaul v0.7.2 binary, CAP_NET_ADMIN.
# Skips cleanly otherwise. Everything lives in two namespaces + a mktemp dir.
set -u
cd "$(dirname "$0")/.." || exit 1
ROOT=$PWD

BIN=${BACKHAUL_BIN:-/tmp/backhaul-rel/backhaul}
FRP_DIR=${FRP_DIR:-/tmp/frp-rel}
[[ -x $BIN ]] || { echo "SKIP test_tunnel_combos_lab (binary $BIN missing)"; exit 0; }
for c in ip iptables ping python3 openssl ss; do
    command -v "$c" >/dev/null 2>&1 || { echo "SKIP test_tunnel_combos_lab ($c missing)"; exit 0; }
done
[[ $("$BIN" -v 2>&1) == v0.7.2* ]] || { echo "SKIP test_tunnel_combos_lab (unexpected version)"; exit 0; }

HUB=tc-hub
SPOKE=tc-spoke
TMP=$(mktemp -d /tmp/tc-lab.XXXXXX)
pids=()
set +m
cleanup() {
    local p
    for p in "${pids[@]:-}"; do [[ -n $p ]] && { kill -9 "$p"; wait "$p"; } 2>/dev/null; done
    [[ -f $TMP/client.pid ]] && kill -9 "$(cat "$TMP/client.pid")" 2>/dev/null
    ip netns del "$HUB" 2>/dev/null; ip netns del "$SPOKE" 2>/dev/null
    rm -rf "$TMP"
}
trap cleanup EXIT
ip netns del "$HUB" 2>/dev/null; ip netns del "$SPOKE" 2>/dev/null
ip netns add "$HUB" 2>/dev/null || { echo "SKIP test_tunnel_combos_lab (no netns permission)"; exit 0; }
ip netns add "$SPOKE"
H="ip netns exec $HUB"; S="ip netns exec $SPOKE"
ip link add tc-h type veth peer name tc-s
ip link set tc-h netns "$HUB"; ip link set tc-s netns "$SPOKE"
$H sh -c 'ip addr add 192.0.2.1/24 dev tc-h; ip link set tc-h up; ip link set lo up
  ip tunnel add gre-tunnel mode gre remote 192.0.2.2 local 192.0.2.1 ttl 255
  ip addr add 10.10.10.1/30 dev gre-tunnel; ip link set gre-tunnel up mtu 1380'
$S sh -c 'ip addr add 192.0.2.2/24 dev tc-s; ip link set tc-s up; ip link set lo up
  ip tunnel add gre-tunnel mode gre remote 192.0.2.1 local 192.0.2.2 ttl 255
  ip addr add 10.10.10.2/30 dev gre-tunnel; ip link set gre-tunnel up mtu 1380'
gre_block()   { $S iptables -C INPUT -p 47 -j DROP 2>/dev/null || $S iptables -A INPUT -p 47 -j DROP; }
gre_unblock() { $S iptables -D INPUT -p 47 -j DROP 2>/dev/null; true; }

# services on the foreign side: a TCP echo on 19001 and a UDP echo on 19002
cat > "$TMP/echo.py" <<'PY'
import socket, threading
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("127.0.0.1", 19001)); s.listen(50)
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.bind(("127.0.0.1", 19002))
def udp():
    while True:
        d, a = u.recvfrom(65535); u.sendto(d, a)
threading.Thread(target=udp, daemon=True).start()
def h(c):
    while True:
        d = c.recv(65536)
        if not d: break
        c.sendall(d)
    c.close()
while True:
    c, _ = s.accept(); threading.Thread(target=h, args=(c,), daemon=True).start()
PY
# a user on the Iran side: TCP through 29001, UDP through 29002
cat > "$TMP/probe.py" <<'PY'
import socket, os, sys, time
kind, n = sys.argv[1], int(sys.argv[2])
m = os.urandom(n)
try:
    if kind == "tcp":
        s = socket.create_connection(("127.0.0.1", 29001), timeout=10); s.sendall(m); g = b""
        while len(g) < len(m):
            d = s.recv(65536)
            if not d: break
            g += d
        print("OK" if g == m else "MISMATCH")
    else:
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.settimeout(2)
        for _ in range(5):
            u.sendto(m, ("127.0.0.1", 29002))
            try:
                d, _ = u.recvfrom(65535)
                print("OK" if d == m else "MISMATCH"); break
            except socket.timeout:
                time.sleep(0.5)
        else:
            print("FAIL timeout")
except Exception as e:
    print("FAIL", type(e).__name__)
PY
$S python3 "$TMP/echo.py" & pids+=($!)

# hashem.sh's own functions, saved once so both namespaces can source them
ext() { awk -v n="$1" '$0 ~ "^"n"\\(\\) \\{" {p=1} p {print} p && /^}/ {exit}' "$ROOT/hashem.sh"; }
{
    echo "INSTALL_DIR='$(dirname "$BIN")' BACKHAUL_CONFIG_DIR='$TMP/bh' CONFIG_DIR='$TMP/frp'"
    echo "RED='' GREEN='' YELLOW='' CYAN='' NC='' TMP='$TMP' BIN='$BIN' FRPC='$FRP_DIR/frpc'"
    grep -E '^(BACKHAUL_TRANSPORTS|DIAL_BACK_TICKS|DIAL_BACK_WAIT|DIAL_HOLD_SECS)=' "$ROOT/hashem.sh"
    grep -E '^(backhaul_transport_ok|backhaul_udp_wanted)\(\)' "$ROOT/hashem.sh"
    for f in hostport hostonly backhaul_is_v2 backhaul_ensure_tls backhaul_write_server_conf_v1 backhaul_write_client_conf_v1 \
             backhaul_write_server_conf backhaul_write_client_conf backhaul_wait_link \
             dial_env_file dial_env_write dial_env_get dial_conf_file dial_service dial_current_addr \
             dial_current_port dial_gre_usable dial_pick dial_apply_addr dial_env_ensure dial_reselect \
             dial_connected dial_transport_udp dial_gre_back_ok dial_streak_file dial_hold_file \
             dial_hold_active dial_watch_tick; do
        b="$(ext $f)"; [[ -n "$b" ]] || { echo "echo 'FAIL: $f missing from hashem.sh'; exit 1"; continue; }
        echo "$b"
    done
    cat <<'EOS'
log_msg() { echo "$3" >> "$TMP/watch.log"; }
journalctl() { cat "$TMP/client.log"; }   # backhaul_wait_link reads the client's log
# systemd stand-in: "restart backhaul-client|frpc" restarts the foreign client
client_start() {
    if [[ "$1" == frpc ]]; then
        "$FRPC" -c "$CONFIG_DIR/frpc.toml" >> "$TMP/client.log" 2>&1 &
    else
        "$BIN" -c "$BACKHAUL_CONFIG_DIR/client.toml" >> "$TMP/client.log" 2>&1 &
    fi
    echo $! > "$TMP/client.pid"
}
client_stop() { [[ -f $TMP/client.pid ]] && kill -9 "$(cat "$TMP/client.pid")" 2>/dev/null; rm -f "$TMP/client.pid"; sleep 0.3; }
systemctl() { [[ "$1" == restart ]] || return 0; client_stop; : > "$TMP/client.log"; client_start "$2"; }
EOS
} > "$TMP/funcs.sh"
mkdir -p "$TMP/bh" "$TMP/frp"
source "$TMP/funcs.sh"
spoke() { $S bash -c "source '$TMP/funcs.sh'; $*"; }

fail=0
check() { if [[ "$2" != "$3" ]]; then echo "FAIL: $1 (want [$2] got [$3])"; fail=1; else echo "ok:   $1"; fi; }
SP=""
server_start() { # transport ports [udp]
    BH_ACCEPT_UDP=${3:-0} backhaul_write_server_conf "$TMP/bh/s.toml" "0.0.0.0:3080" "$1" tok "$2"
    $H "$BIN" -c "$TMP/bh/s.toml" > "$TMP/server.log" 2>&1 & SP=$!; pids+=($SP)
    sleep 1
}
server_stop() { kill -9 "$SP" 2>/dev/null; wait "$SP" 2>/dev/null; SP=""; }
link() { backhaul_wait_link backhaul-client x 15; echo $?; }
dialled() { $S ss -Htn state established 2>/dev/null | awk '$4 ~ /:(3080|7000)$/ {print $4}' | sort -u | head -n1; }

# ---- 1. Backhaul: every transport, with GRE and without GRE ----
for mode in gre nogre; do
    if [[ $mode == gre ]]; then gre_unblock; addr=10.10.10.1; else gre_block; addr=192.0.2.1; fi
    for t in tcp tcpmux ws wss wsmux wssmux udp tcp+udp; do
        tr=${t%+udp}; udp=0; [[ $t == tcp+udp ]] && udp=1
        if [[ $tr == udp ]]; then ports="29002=19002"; elif (( udp )); then ports="29001=19001,29002=19002"; else ports="29001=19001"; fi
        server_start "$tr" "$ports" "$udp"
        spoke "backhaul_write_client_conf '$TMP/bh/client.toml' '$addr:3080' '$tr' tok; : > '$TMP/client.log'; client_start backhaul-client"
        name="Backhaul $mode $t"
        check "$name: link up" 0 "$(link)"
        if [[ $tr == udp ]]; then
            check "$name: UDP data" OK "$($H python3 "$TMP/probe.py" udp 1200)"
        else
            check "$name: TCP data 256 KiB" OK "$($H python3 "$TMP/probe.py" tcp 262144)"
            check "$name: dials $addr" "$addr:3080" "$(dialled)"
            (( udp )) && check "$name: UDP data" OK "$($H python3 "$TMP/probe.py" udp 1200)"
        fi
        spoke client_stop; server_stop
    done
done
gre_unblock

# ---- 2. Backhaul with GRE: the foreign side's route follows GRE ----
server_start tcpmux "29001=19001"
gre_block
DIAL=$(spoke "dial_pick auto 10.10.10.1 192.0.2.1 3080")
check "route: GRE blocked at setup -> public IP" 192.0.2.1 "$DIAL"
spoke "dial_env_write auto backhaul 10.10.10.1 192.0.2.1; backhaul_write_client_conf '$TMP/bh/client.toml' '$DIAL:3080' tcpmux tok; : > '$TMP/client.log'; client_start backhaul-client"
check "route: link up over the public IP" 0 "$(link)"
check "route: data over the public IP" OK "$($H python3 "$TMP/probe.py" tcp 65536)"
for i in 1 2 3; do spoke dial_watch_tick; done
check "route: GRE still blocked -> stays public" 192.0.2.1 "$(spoke 'dial_current_addr backhaul')"
gre_unblock
for i in 1 2 3 4; do spoke dial_watch_tick; done
check "route: 4 good ticks -> not yet back" 192.0.2.1 "$(spoke 'dial_current_addr backhaul')"
spoke dial_watch_tick
check "route: 5th good tick -> back on GRE" 10.10.10.1 "$(spoke 'dial_current_addr backhaul')"
check "route: link up over GRE again" 0 "$(link)"
check "route: client connected to the GRE address" "10.10.10.1:3080" "$(dialled)"
check "route: data over GRE again" OK "$($H python3 "$TMP/probe.py" tcp 262144)"
grep -q "back on GRE" "$TMP/watch.log" 2>/dev/null || { echo "FAIL: route: no 'back on GRE' log"; fail=1; }
# GRE dies: the client loses its session (restarted here, the keepalive does it live)
gre_block; spoke "systemctl restart backhaul-client"; sleep 2
spoke dial_watch_tick
check "route: GRE dead -> public IP again" 192.0.2.1 "$(spoke 'dial_current_addr backhaul')"
check "route: link up over the public IP again" 0 "$(link)"
check "route: data over the public IP again" OK "$($H python3 "$TMP/probe.py" tcp 65536)"
gre_unblock; spoke client_stop; server_stop

# ---- 3. GRE + FRP: the same route switching with frps / frpc ----
if [[ -x $FRP_DIR/frps && -x $FRP_DIR/frpc ]]; then
    cat > "$TMP/frps.toml" <<'EOT'
bindAddr = "0.0.0.0"
bindPort = 7000
auth.method = "token"
auth.token = "tok"
EOT
    $H "$FRP_DIR/frps" -c "$TMP/frps.toml" > "$TMP/frps.log" 2>&1 & pids+=($!)
    sleep 1
    frpc_conf() {
        cat > "$TMP/frp/frpc.toml" <<EOT
serverAddr = "$1"
serverPort = 7000
loginFailExit = false
auth.method = "token"
auth.token = "tok"
transport.heartbeatInterval = 5
transport.heartbeatTimeout = 15

[[proxies]]
name = "echo"
type = "tcp"
localIP = "127.0.0.1"
localPort = 19001
remotePort = 29001
EOT
    }
    frp_up() { local i; for i in $(seq 1 20); do [[ "$($H python3 "$TMP/probe.py" tcp 4096)" == OK ]] && { echo OK; return; }; sleep 0.5; done; echo DOWN; }
    rm -f "$TMP/frp/dial.env" "$TMP/frp/dial.streak" "$TMP/frp/dial.hold"
    gre_block
    DIAL=$(spoke "dial_pick auto 10.10.10.1 192.0.2.1 7000")
    check "FRP: GRE blocked at setup -> public IP" 192.0.2.1 "$DIAL"
    frpc_conf "$DIAL"
    spoke "dial_env_write auto frp 10.10.10.1 192.0.2.1; : > '$TMP/client.log'; client_start frpc"
    check "FRP: data over the public IP" OK "$(frp_up)"
    gre_unblock
    for i in 1 2 3 4 5; do spoke dial_watch_tick; done
    check "FRP: back on GRE after 5 good ticks" 10.10.10.1 "$(spoke 'dial_current_addr frp')"
    check "FRP: frpc connected to the GRE address" "10.10.10.1:7000" "$(dialled)"
    check "FRP: data over GRE" OK "$(frp_up)"
    check "FRP: 256 KiB over GRE (MTU 1380)" OK "$($H python3 "$TMP/probe.py" tcp 262144)"
    gre_block; spoke "systemctl restart frpc"; sleep 2
    spoke dial_watch_tick
    check "FRP: GRE dead -> public IP again" 192.0.2.1 "$(spoke 'dial_current_addr frp')"
    check "FRP: data over the public IP again" OK "$(frp_up)"
    gre_unblock; spoke client_stop
else
    echo "skip: GRE + FRP route (no frps/frpc in $FRP_DIR)"
fi

(( fail )) && exit 1; echo "PASS test_tunnel_combos_lab"
