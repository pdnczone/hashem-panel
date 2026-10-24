#!/usr/bin/env bash
# tests/test_backhaul_udp_lab.sh — UDP over a TCP-only Backhaul transport, with
# the real v0.7.2 core in two namespaces.
#
# The tunnel runs tcpmux (TCP only: the core ignores accept_udp there). The UDP
# companion hashem.sh adds (backhaul_udp_conf: same config, udp transport, its
# own control port) must carry the UDP of the same ports, while TCP keeps working.
# Proves: TCP through tcpmux; no UDP without the companion; UDP with it, both
# small and near-MTU datagrams; recovery after kill -9 of the companion client.
#
# Needs: ip, python3, the binary (BACKHAUL_BIN), CAP_NET_ADMIN. Skips cleanly
# otherwise. Touches nothing outside two namespaces and a mktemp dir.
set -u
cd "$(dirname "$0")/.." || exit 1
ROOT=$PWD

BIN=${BACKHAUL_BIN:-/tmp/backhaul-rel/backhaul}
[[ -x $BIN ]] || { echo "SKIP test_backhaul_udp_lab (binary $BIN missing)"; exit 0; }
for c in ip python3; do
    command -v "$c" >/dev/null 2>&1 || { echo "SKIP test_backhaul_udp_lab ($c missing)"; exit 0; }
done
ver=$("$BIN" -v 2>&1)
[[ $ver == v0.7.2* ]] || { echo "SKIP test_backhaul_udp_lab (unexpected version: $ver)"; exit 0; }

HUB=bu-hub
SPOKE=bu-spoke
CTRL=18090   # tunnel control port (tcpmux)
FWD=18091    # forwarded port on the hub (TCP and UDP)
ECHO=18092   # echo target in the spoke (TCP and UDP)
UCTRL=18095  # the UDP companion's own control port (the udp transport holds it on TCP)
TMP=$(mktemp -d /tmp/bh-udp.XXXXXX)
pids=()
set +m
cleanup() {
    local p
    for p in "${pids[@]:-}"; do [[ -n $p ]] && { kill -9 "$p"; wait "$p"; } 2>/dev/null; done
    ip netns del "$HUB" 2>/dev/null; ip netns del "$SPOKE" 2>/dev/null
    [[ -n ${BH_UDP_LOGDIR:-} ]] && { mkdir -p "$BH_UDP_LOGDIR"; cp "$TMP"/*.log "$TMP"/*.toml "$BH_UDP_LOGDIR"/ 2>/dev/null; }
    rm -rf "$TMP"
}
trap cleanup EXIT
ip netns del "$HUB" 2>/dev/null; ip netns del "$SPOKE" 2>/dev/null
ip netns add "$HUB" 2>/dev/null || { echo "SKIP test_backhaul_udp_lab (no netns permission)"; exit 0; }
ip netns add "$SPOKE" || { echo "SKIP test_backhaul_udp_lab (no netns permission)"; exit 0; }
ip link add vbu-hub netns "$HUB" type veth peer name vbu-spoke netns "$SPOKE" \
    || { echo "SKIP test_backhaul_udp_lab (veth unsupported)"; exit 0; }
ip netns exec "$HUB" bash -c 'ip addr add 192.0.2.1/24 dev vbu-hub; ip link set vbu-hub up; ip link set lo up'
ip netns exec "$SPOKE" bash -c 'ip addr add 192.0.2.2/24 dev vbu-spoke; ip link set vbu-spoke up; ip link set lo up'

fail=0
check() {
    local line
    if [[ "$2" != "$3" ]]; then line="FAIL: $1 (want [$2] got [$3])"; fail=1; else line="ok:   $1"; fi
    echo "$line"; echo "$line" >> "$TMP/result.txt"
}
# annotate LEVEL TITLE FILE: the job log needs auth; annotations are public.
annotate() {
    [[ -n ${GITHUB_ACTIONS:-} ]] || return 0
    local msg
    msg=$(tail -c 6000 "$3" | sed -e 's/%/%25/g' | sed -e ':a;N;$!ba;s/\n/%0A/g' -e 's/\r/%0D/g')
    echo "::$1 title=$2::$msg"
}

# hashem.sh's own companion builder
for fn in backhaul_conf_transport backhaul_udp_conf; do
    awk -v f="$fn" '$0 ~ "^"f"\\(\\) \\{" {p=1} p {print} p && /^}/ {p=0}' "$ROOT/hashem.sh"
done > "$TMP/fn.sh"
# shellcheck disable=SC1091
source "$TMP/fn.sh"

TOKEN=lab-token-udp
cat >"$TMP/server.toml" <<EOF
[server]
bind_addr = "192.0.2.1:$CTRL"
transport = "tcpmux"
token = "$TOKEN"
heartbeat = 5
accept_udp = true
web_port = 0
log_level = "debug"
ports = ["$FWD=127.0.0.1:$ECHO"]
EOF
cat >"$TMP/client.toml" <<EOF
[client]
remote_addr = "192.0.2.1:$CTRL"
transport = "tcpmux"
token = "$TOKEN"
retry_interval = 1
dial_timeout = 5
log_level = "debug"
EOF
backhaul_udp_conf "$TMP/server.toml" "$TMP/server-udp.toml" "$UCTRL"; check "companion server config built" 0 $?
backhaul_udp_conf "$TMP/client.toml" "$TMP/client-udp.toml" "$UCTRL"; check "companion client config built" 0 $?
check "companion transport" udp "$(backhaul_conf_transport "$TMP/server-udp.toml")"

# echo responders (TCP and UDP) in the spoke: the tunnel target
ip netns exec "$SPOKE" python3 -I -c '
import socket, socketserver, threading
class T(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            d = self.request.recv(65536)
            if not d: break
            self.request.sendall(d)
class TS(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
threading.Thread(target=TS(("127.0.0.1", 18092), T).serve_forever, daemon=True).start()
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
u.bind(("127.0.0.1", 18092))
while True:
    d, a = u.recvfrom(65535)
    u.sendto(d, a)' >"$TMP/echo.log" 2>&1 &
pids+=($!)

tcp_probe() {
    ip netns exec "$HUB" python3 -I - <<'PY'
import os, socket, sys
data = os.urandom(4096)
try:
    s = socket.create_connection(("192.0.2.1", 18091), timeout=3)
    s.settimeout(3); s.sendall(data); got = b""
    while len(got) < len(data):
        c = s.recv(65536)
        if not c: break
        got += c
except Exception:
    sys.exit(2)
sys.exit(0 if got == data else 1)
PY
}
# udp_probe COUNT SIZE: datagrams to the hub's forwarded port; rc 0 when at
# least 90% come back byte-exact.
udp_probe() {
    ip netns exec "$HUB" python3 -I - "$1" "$2" <<'PY'
import os, socket, sys
n, size = int(sys.argv[1]), int(sys.argv[2])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(1.0)
s.connect(("192.0.2.1", 18091))
ok = 0
for _ in range(n):
    d = os.urandom(size)
    try:
        s.send(d)
        if s.recv(65535) == d: ok += 1
    except Exception:
        pass
sys.exit(0 if ok * 10 >= n * 9 else 1)
PY
}
wait_for() { local end=$((SECONDS + $1)); shift; while (( SECONDS < end )); do "$@" && return 0; sleep 0.5; done; return 1; }
start() { # ns config log
    ip netns exec "$1" "$BIN" -c "$2" >"$3" 2>&1 &
    pids+=($!); last=$!
}

# 1. tcpmux alone: TCP passes, UDP does not (accept_udp is ignored there)
start "$HUB" "$TMP/server.toml" "$TMP/server.log"
sleep 1
start "$SPOKE" "$TMP/client.toml" "$TMP/client.log"
wait_for 15 tcp_probe; check "1. TCP through tcpmux" 0 $?
udp_probe 5 64; check "1. no UDP through tcpmux alone" 1 $?

# 2. the companion carries UDP on the same port number
start "$HUB" "$TMP/server-udp.toml" "$TMP/server-udp.log"
sleep 1
start "$SPOKE" "$TMP/client-udp.toml" "$TMP/client-udp.log"
ucpid=$last
sleep 1
{ echo "== hub sockets"; ip netns exec "$HUB" ss -lntup 2>/dev/null | grep -E ":1809[0-5] "; echo "== spoke sockets"; ip netns exec "$SPOKE" ss -ntup 2>/dev/null | grep -E ":1809[0-5] " | head -8; } > "$TMP/sockets.txt"
wait_for 15 udp_probe 5 64; check "2. UDP through the companion" 0 $?
udp_probe 50 64;   check "2. 50 small datagrams (>=90% byte-exact)" 0 $?
udp_probe 20 1200; check "2. 20 datagrams of 1200 B (>=90% byte-exact)" 0 $?
tcp_probe;         check "2. TCP still through tcpmux" 0 $?

# 3. the companion client dies and comes back (systemd restarts it)
kill -9 "$ucpid" 2>/dev/null; wait "$ucpid" 2>/dev/null
start "$SPOKE" "$TMP/client-udp.toml" "$TMP/client-udp2.log"
t0=$SECONDS
wait_for 20 udp_probe 5 64; rc=$?
check "3. UDP back within 20 s of kill -9 (took $((SECONDS - t0))s)" 0 "$rc"

# 4. the dashboard's traffic counters (panel carrier_traffic.go): the panel's
# own code builds its iptables chains in the hub namespace from these configs,
# 2 MiB of TCP and 50 kB of UDP cross the tunnel, the counters must see them.
if [[ -x ${CARRIER_LAB_TEST_BIN:-} ]] && command -v iptables-save >/dev/null 2>&1; then
    mkdir -p "$TMP/bhconf/udp"
    cp "$TMP/server.toml" "$TMP/bhconf/server.toml"
    cp "$TMP/server-udp.toml" "$TMP/bhconf/udp/backhaul-udp-server.toml"
    cat >"$TMP/traffic.sh" <<'EOF'
python3 -I - <<'PY'
import os, socket, sys
data = os.urandom(2 << 20)
s = socket.create_connection(("192.0.2.1", 18091), timeout=10)
s.settimeout(10)
s.sendall(data)
got = 0
while got < len(data):
    c = s.recv(1 << 16)
    if not c: break
    got += len(c)
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
u.settimeout(1.0)
u.connect(("192.0.2.1", 18091))
for _ in range(50):
    u.send(os.urandom(1000))
    try: u.recv(65535)
    except Exception: pass
sys.exit(0 if got == len(data) else 1)
PY
EOF
    ip netns exec "$HUB" env CARRIER_LAB_DIR="$TMP/bhconf" CARRIER_LAB_TRAFFIC="$TMP/traffic.sh" \
        CARRIER_LAB_MIN=$((2 << 20)) "$CARRIER_LAB_TEST_BIN" -test.run '^TestCarrierLab$' -test.v >"$TMP/carrier.log" 2>&1
    rc=$?
    grep -o 'carrier counters after the traffic: .*' "$TMP/carrier.log" >> "$TMP/sockets.txt"
    (( rc )) && { echo "--- carrier.log"; grep -v CMD-ERROR "$TMP/carrier.log" | tail -n 30; } >> "$TMP/sockets.txt"
    check "4. dashboard counters see the tunnel's bytes (iptables, real core)" 0 "$rc"
else
    echo "skip 4: CARRIER_LAB_TEST_BIN or iptables-save missing"
fi

{ echo "core: $ver"; cat "$TMP/sockets.txt" 2>/dev/null
  if (( fail )); then
      for f in server-udp client-udp server client client-udp2; do echo "--- $f.log"; tail -n 6 "$TMP/$f.log" 2>/dev/null | cut -c1-200; done
      echo "--- server-udp.toml"; cat "$TMP/server-udp.toml"
  fi; echo "=== results"; cat "$TMP/result.txt"; } > "$TMP/report.txt"
if (( fail == 0 )); then
    annotate notice "Backhaul UDP lab" "$TMP/report.txt"
    echo "PASS test_backhaul_udp_lab"
else
    cat "$TMP/report.txt"
    annotate error "Backhaul UDP lab" "$TMP/report.txt"
    exit 1
fi
