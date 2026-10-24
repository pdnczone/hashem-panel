#!/usr/bin/env bash
# tests/test_ipv6_lab.sh — IPv6 with the real cores and the real kernel.
#
# Two namespaces joined by a dual-stack veth (192.0.2.1 / 2001:db8:6::1 on the
# Iran hub, .2 / ::2 on the foreign spoke), a TCP and a UDP echo on the
# spoke's 127.0.0.1:19001 / :19002, and hashem.sh's own config writers:
#
#  1. Users over IPv6: the link runs over IPv4, a user reaches the Iran ports
#     29001 (TCP) and 29002 (UDP) over IPv6 and over IPv4, byte-exact.
#     Backhaul on every transport, and FRP.
#  2. The link over IPv6: IPv4 between the servers is dropped, the foreign
#     side dials the hub's IPv6 address. Backhaul on every transport, and FRP.
#  3. The GRE carriers with hashem.sh's carrier_apply: direct, then 6to4 with
#     IP protocol 47 dropped, then 4in6 with no IPv4 between the servers at
#     all, then direct again; Backhaul over the tunnel each time.
#
# Needs: ip, iptables, ip6tables, ping, python3, openssl, ss, the Backhaul
# v0.7.2 binary (BACKHAUL_BIN), frps/frpc (FRP_DIR, optional), CAP_NET_ADMIN.
# Skips cleanly otherwise. Everything lives in two namespaces + a mktemp dir.
set -u
cd "$(dirname "$0")/.." || exit 1
ROOT=$PWD

BIN=${BACKHAUL_BIN:-/tmp/backhaul-rel/backhaul}
FRP_DIR=${FRP_DIR:-/tmp/frp-rel}
[[ -x $BIN ]] || { echo "SKIP test_ipv6_lab (binary $BIN missing)"; exit 0; }
for c in ip iptables ip6tables ping python3 openssl ss; do
    command -v "$c" >/dev/null 2>&1 || { echo "SKIP test_ipv6_lab ($c missing)"; exit 0; }
done

HUB=v6-hub
SPOKE=v6-spoke
HUB4=192.0.2.1 SPOKE4=192.0.2.2
HUB6=2001:db8:6::1 SPOKE6=2001:db8:6::2
TMP=$(mktemp -d /tmp/v6-lab.XXXXXX)
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
ip netns add "$HUB" 2>/dev/null || { echo "SKIP test_ipv6_lab (no netns permission)"; exit 0; }
ip netns add "$SPOKE"
H="ip netns exec $HUB"; S="ip netns exec $SPOKE"
ip link add v6-h type veth peer name v6-s
ip link set v6-h netns "$HUB"; ip link set v6-s netns "$SPOKE"
for side in "$HUB v6-h $HUB4 $HUB6" "$SPOKE v6-s $SPOKE4 $SPOKE6"; do
    set -- $side
    ip netns exec "$1" sh -c "sysctl -qw net.ipv6.conf.all.disable_ipv6=0 net.ipv6.conf.default.disable_ipv6=0
      ip addr add $3/24 dev $2; ip -6 addr add $4/64 dev $2 nodad; ip link set $2 up; ip link set lo up"
done
for _ in $(seq 1 20); do $H ping -6 -c1 -W1 "$SPOKE6" >/dev/null 2>&1 && break; sleep 0.3; done
$H ping -6 -c1 -W2 "$SPOKE6" >/dev/null 2>&1 || { echo "SKIP test_ipv6_lab (no IPv6 between the namespaces)"; exit 0; }
v4_block()   { $H iptables -C INPUT -s "$SPOKE4" -j DROP 2>/dev/null || $H iptables -A INPUT -s "$SPOKE4" -j DROP; }
v4_unblock() { $H iptables -D INPUT -s "$SPOKE4" -j DROP 2>/dev/null; true; }

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
# a user: probe.py tcp|udp HOST N -> TCP via HOST:29001, UDP via HOST:29002
cat > "$TMP/probe.py" <<'PY'
import socket, os, sys, time
kind, host, n = sys.argv[1], sys.argv[2], int(sys.argv[3])
fam = socket.AF_INET6 if ":" in host else socket.AF_INET
m = os.urandom(n)
try:
    if kind == "tcp":
        s = socket.socket(fam, socket.SOCK_STREAM); s.settimeout(10); s.connect((host, 29001)); s.sendall(m); g = b""
        while len(g) < len(m):
            d = s.recv(65536)
            if not d: break
            g += d
        print("OK" if g == m else "MISMATCH")
    else:
        u = socket.socket(fam, socket.SOCK_DGRAM); u.settimeout(2)
        for _ in range(5):
            u.sendto(m, (host, 29002))
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
    grep -E '^(backhaul_transport_ok|backhaul_udp_wanted)\(\)' "$ROOT/hashem.sh"
    for f in hostport hostonly backhaul_is_v2 backhaul_ensure_tls backhaul_write_server_conf_v1 backhaul_write_client_conf_v1 \
             backhaul_write_server_conf backhaul_write_client_conf backhaul_wait_link; do
        b="$(ext $f)"; [[ -n "$b" ]] || { echo "echo 'FAIL: $f missing from hashem.sh'; exit 1"; continue; }
        echo "$b"
    done
    cat <<'EOS'
journalctl() { cat "$TMP/client.log"; }   # backhaul_wait_link reads the client's log
client_start() {
    if [[ "$1" == frpc ]]; then
        "$FRPC" -c "$CONFIG_DIR/frpc.toml" >> "$TMP/client.log" 2>&1 &
    else
        "$BIN" -c "$BACKHAUL_CONFIG_DIR/client.toml" >> "$TMP/client.log" 2>&1 &
    fi
    echo $! > "$TMP/client.pid"
}
client_stop() { [[ -f $TMP/client.pid ]] && kill -9 "$(cat "$TMP/client.pid")" 2>/dev/null; rm -f "$TMP/client.pid"; sleep 0.3; }
EOS
} > "$TMP/funcs.sh"
mkdir -p "$TMP/bh" "$TMP/frp"
source "$TMP/funcs.sh"
spoke() { $S bash -c "source '$TMP/funcs.sh'; $*"; }

fail=0
results=()
check() {
    if [[ "$2" != "$3" ]]; then echo "FAIL: $1 (want [$2] got [$3])"; fail=1; results+=("FAIL $1"); else echo "ok:   $1"; results+=("ok $1"); fi
}
SP=""
server_start() { # transport ports [udp]
    BH_ACCEPT_UDP=${3:-0} backhaul_write_server_conf "$TMP/bh/s.toml" "0.0.0.0:3080" "$1" tok "$2"
    $H "$BIN" -c "$TMP/bh/s.toml" > "$TMP/server.log" 2>&1 & SP=$!; pids+=($SP)
    sleep 1
}
server_stop() { kill -9 "$SP" 2>/dev/null; wait "$SP" 2>/dev/null; SP=""; }
link() { backhaul_wait_link backhaul-client x 15; echo $?; }
dialled() { $S ss -Htn state established 2>/dev/null | awk '$4 ~ /:(3080|7000)$/ {print $4}' | sort -u | head -n1; }
probe() { $H python3 "$TMP/probe.py" "$@"; }

backhaul_round() { # mode(v4link|v6link) transport
    local mode=$1 t=$2 tr udp=0 ports addr name
    tr=${t%+udp}; [[ $t == *+udp ]] && udp=1
    if [[ $tr == udp ]]; then ports="29002=19002"; elif (( udp )); then ports="29001=19001,29002=19002"; else ports="29001=19001"; fi
    if [[ $mode == v6link ]]; then addr=$HUB6; else addr=$HUB4; fi
    server_start "$tr" "$ports" "$udp"
    spoke "backhaul_write_client_conf '$TMP/bh/client.toml' '$(hostport "$addr" 3080)' '$tr' tok; : > '$TMP/client.log'; client_start backhaul-client"
    name="Backhaul $t, link over ${mode%link}"
    check "$name: link up" 0 "$(link)"
    if [[ $tr != udp ]]; then
        check "$name: user over IPv6, TCP 256 KiB" OK "$(probe tcp "$HUB6" 262144)"
        check "$name: user over IPv4, TCP 256 KiB" OK "$(probe tcp 127.0.0.1 262144)"
        check "$name: dials $(hostport "$addr" 3080)" "$(hostport "$addr" 3080)" "$(dialled)"
    fi
    if [[ $tr == udp ]] || (( udp )); then
        check "$name: user over IPv6, UDP" OK "$(probe udp "$HUB6" 1200)"
        check "$name: user over IPv4, UDP" OK "$(probe udp 127.0.0.1 1200)"
    fi
    spoke client_stop; server_stop
}

frp_round() { # mode(v4link|v6link)
    local mode=$1 addr i ok=DOWN
    if [[ $mode == v6link ]]; then addr=$HUB6; else addr=$HUB4; fi
    cat > "$TMP/frps.toml" <<'EOT'
bindAddr = "0.0.0.0"
bindPort = 7000
auth.method = "token"
auth.token = "tok"
EOT
    $H "$FRP_DIR/frps" -c "$TMP/frps.toml" > "$TMP/frps.log" 2>&1 & local FP=$!; pids+=($FP)
    sleep 1
    cat > "$TMP/frp/frpc.toml" <<EOT
serverAddr = "$addr"
serverPort = 7000
loginFailExit = false
auth.method = "token"
auth.token = "tok"

[[proxies]]
name = "echo"
type = "tcp"
localIP = "127.0.0.1"
localPort = 19001
remotePort = 29001

[[proxies]]
name = "echo-udp"
type = "udp"
localIP = "127.0.0.1"
localPort = 19002
remotePort = 29002
EOT
    spoke ": > '$TMP/client.log'; client_start frpc"
    for i in $(seq 1 30); do [[ "$(probe tcp 127.0.0.1 4096)" == OK ]] && { ok=OK; break; }; sleep 0.5; done
    local name="FRP, link over ${mode%link}"
    check "$name: link up" OK "$ok"
    check "$name: user over IPv6, TCP 256 KiB" OK "$(probe tcp "$HUB6" 262144)"
    check "$name: user over IPv4, TCP 256 KiB" OK "$(probe tcp 127.0.0.1 262144)"
    check "$name: user over IPv6, UDP" OK "$(probe udp "$HUB6" 1200)"
    check "$name: dials $(hostport "$addr" 7000)" "$(hostport "$addr" 7000)" "$(dialled)"
    spoke client_stop; kill -9 "$FP" 2>/dev/null; wait "$FP" 2>/dev/null
}

TRANSPORTS="tcp tcpmux ws wss wsmux wssmux udp tcp+udp"

# ---- 1. users over IPv6, the link over IPv4 ----
for t in $TRANSPORTS; do backhaul_round v4link "$t"; done
[[ -x $FRP_DIR/frps && -x $FRP_DIR/frpc ]] && frp_round v4link

# ---- 2. the link over IPv6, IPv4 between the servers dropped ----
v4_block
check "IPv4 between the servers is dropped" FAIL "$($S python3 -c "
import socket
try:
    socket.create_connection(('$HUB4', 22), timeout=2); print('OPEN')
except ConnectionRefusedError: print('OPEN')
except Exception: print('FAIL')")"
for t in $TRANSPORTS; do backhaul_round v6link "$t"; done
[[ -x $FRP_DIR/frps && -x $FRP_DIR/frpc ]] && frp_round v6link
v4_unblock

# ---- 3. the GRE carriers: direct -> 6to4 -> 4in6 -> direct ----
# hashem.sh's own carrier_apply switches gre-tunnel on both servers. The Iran
# end is 10.10.10.2, the foreign end 10.10.10.1, as the panel sets them up;
# Backhaul tcpmux runs over the inner addresses the whole time.
{
    echo "PANEL_CONFIG_DIR=\${PANEL_CONFIG_DIR:?}; CARRIER_FILE=\$PANEL_CONFIG_DIR/carrier.json; TUNNEL_NAME=gre-tunnel"
    echo "RED='' GREEN='' YELLOW='' CYAN='' NC=''"
    for f in is_valid_port is_valid_ip6 init_carrier_json carrier_get_active carrier_get_fou_ports carrier_init_kernel \
             gre_path_mtu gre_mtu_for gre_mss mss_clamp_set gre6_env_file gre6_get gre6_set gre6_sit_name \
             gre_dev_kind gre_dev_ends gre6_ula gre6_firewall gre6_rebuild carrier_apply; do
        b="$(ext $f)"; [[ -n "$b" ]] || { echo "echo 'FAIL: $f missing from hashem.sh'; exit 1"; continue; }
        echo "$b"
    done
} > "$TMP/carrier.sh"
mkdir -p "$TMP/cfg-hub" "$TMP/cfg-spoke"
hubc()   { $H env PANEL_CONFIG_DIR="$TMP/cfg-hub" bash -c "source '$TMP/carrier.sh'; $*"; }
spokec() { $S env PANEL_CONFIG_DIR="$TMP/cfg-spoke" bash -c "source '$TMP/carrier.sh'; $*"; }
$H sh -c "ip link add gre-tunnel type gre local $HUB4 remote $SPOKE4 ttl 255; ip link set gre-tunnel up mtu 1380
  ip addr add 10.10.10.2/30 dev gre-tunnel; ip route replace 10.10.10.1/32 dev gre-tunnel"
$S sh -c "ip link add gre-tunnel type gre local $SPOKE4 remote $HUB4 ttl 255; ip link set gre-tunnel up mtu 1380
  ip addr add 10.10.10.1/30 dev gre-tunnel; ip route replace 10.10.10.2/32 dev gre-tunnel"
inner_ping() { local i; for i in $(seq 1 20); do $S ping -c1 -W1 10.10.10.2 >/dev/null 2>&1 && { echo OK; return; }; sleep 0.5; done; echo DOWN; }
kind() { ip netns exec "$1" bash -c "source '$TMP/carrier.sh'; gre_dev_kind gre-tunnel"; }
over_gre() { # name: Backhaul tcpmux over the inner addresses, 256 KiB byte-exact
    server_start tcpmux "29001=19001"
    spoke "backhaul_write_client_conf '$TMP/bh/client.toml' '10.10.10.2:3080' tcpmux tok; : > '$TMP/client.log'; client_start backhaul-client"
    check "$1: Backhaul over the tunnel, link up" 0 "$(link)"
    check "$1: Backhaul over the tunnel, TCP 256 KiB" OK "$(probe tcp 127.0.0.1 262144)"
    check "$1: a user over IPv6 through it, TCP 256 KiB" OK "$(probe tcp "$HUB6" 262144)"
    spoke client_stop; server_stop
}
block47() { for ns in "$H" "$S"; do $ns iptables -A INPUT -p 47 -j DROP; done; }
block41() { for ns in "$H" "$S"; do $ns iptables -A INPUT -p 41 -j DROP; done; }
unblock_all() { for ns in "$H" "$S"; do $ns iptables -F INPUT; $ns ip6tables -F INPUT; done; }

check "carrier direct: the inner address answers" OK "$(inner_ping)"
# 6to4, with IP protocol 47 dropped on the IPv4 path: only protocol 41 passes
block47
check "carrier direct: down once protocol 47 is dropped" DOWN "$(inner_ping)"
hubc "carrier_apply 6to4 gre-tunnel" >/dev/null 2>&1; spokec "carrier_apply 6to4 gre-tunnel" >/dev/null 2>&1
check "carrier 6to4: gre-tunnel is ip6gre" "ip6gre ip6gre" "$(kind "$HUB") $(kind "$SPOKE")"
check "carrier 6to4: the sit underlay is up" sit "$($H bash -c "source '$TMP/carrier.sh'; gre_dev_kind hs6-gre-tunnel")"
check "carrier 6to4: inner IPv4 and its route kept" "10.10.10.1 dev gre-tunnel" "$($H ip -4 route show 10.10.10.1 | awk '{print $1, $2, $3}')"
check "carrier 6to4: the inner address answers with GRE (47) dropped" OK "$(inner_ping)"
over_gre "carrier 6to4"
# 4in6, with all IPv4 between the servers dropped
block41; v4_block; $S iptables -A INPUT -s "$HUB4" -j DROP
check "carrier 6to4: down once protocol 41 is dropped" DOWN "$(inner_ping)"
hubc "gre6_set gre-tunnel REMOTE6 $SPOKE6; gre6_set gre-tunnel LOCAL6 $HUB6; carrier_apply 4in6 gre-tunnel" >/dev/null 2>&1
spokec "gre6_set gre-tunnel REMOTE6 $HUB6; gre6_set gre-tunnel LOCAL6 $SPOKE6; carrier_apply 4in6 gre-tunnel" >/dev/null 2>&1
check "carrier 4in6: gre-tunnel is ip6gre, no sit left" "ip6gre ip6gre -" "$(kind "$HUB") $(kind "$SPOKE") $($H ip link show hs6-gre-tunnel >/dev/null 2>&1 && echo sit || echo -)"
check "carrier 4in6: the inner address answers with no IPv4 between the servers" OK "$(inner_ping)"
over_gre "carrier 4in6"
# back to plain GRE over IPv4
unblock_all
hubc "carrier_apply direct gre-tunnel" >/dev/null 2>&1; spokec "carrier_apply direct gre-tunnel" >/dev/null 2>&1
check "carrier direct again: gre-tunnel is gre" "gre gre" "$(kind "$HUB") $(kind "$SPOKE")"
check "carrier direct again: the IPv4 ends came back" "$SPOKE4 $HUB4" "$($H bash -c "source '$TMP/carrier.sh'; gre_dev_ends gre-tunnel")"
check "carrier direct again: the inner address answers" OK "$(inner_ping)"
over_gre "carrier direct again"
# 4in6 without the other server's IPv6: refused, and the tunnel keeps working
rm -f "$TMP/cfg-hub/gre6/gre-tunnel.env"
check "carrier 4in6 without an IPv6 address is refused" 1 "$(hubc "carrier_apply 4in6 gre-tunnel" >/dev/null 2>&1; echo $?)"
check "carrier 4in6 refused: gre-tunnel still gre and answering" "gre OK" "$(kind "$HUB") $(inner_ping)"

if [[ -n ${GITHUB_ACTIONS:-} ]]; then
    ok=0 bad=0
    for r in "${results[@]}"; do [[ $r == ok* ]] && ok=$((ok + 1)) || bad=$((bad + 1)); done
    echo "::notice title=IPv6 lab::$ok checks passed, $bad failed (Backhaul x 8 + FRP, users and the link over IPv6, GRE over 6to4 and 4in6)"
    for r in "${results[@]}"; do [[ $r == FAIL* ]] && echo "::error title=IPv6 lab::${r#FAIL }"; done
fi
(( fail )) && { echo "FAIL: test_ipv6_lab"; exit 1; }
echo "PASS: test_ipv6_lab"
