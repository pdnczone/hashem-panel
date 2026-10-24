#!/usr/bin/env bash
# tests/test_backhaul_e2e.sh — real Backhaul v0.7.2 hub/spoke proof in netns.
# Runs the REAL binary (BACKHAUL_BIN, default /tmp/backhaul-rel/backhaul) as a
# tcpmux server in bh-hub and a client in bh-spoke over a veth pair, then
# proves: handshake, byte-exact data path, wrong-token rejection, and
# recovery after kill -9 of the client.
#
# Backhaul is a REVERSE tunnel: the server (hub) owns the public port and the
# client (spoke) dials the target. So the echo responder lives in bh-spoke and
# the probe connects to the hub's forwarded port.
#
# Needs: ip, python3, the binary, CAP_NET_ADMIN. Skips cleanly otherwise.
# Never touches host interfaces, routes, firewall, units or /etc: everything
# lives in two namespaces + a mktemp dir, all removed on exit.
set -u
cd "$(dirname "$0")/.." || exit 1

BIN=${BACKHAUL_BIN:-/tmp/backhaul-rel/backhaul}
[[ -x $BIN ]] || { echo "SKIP test_backhaul_e2e (binary $BIN missing)"; exit 0; }
for c in ip python3; do
    command -v "$c" >/dev/null 2>&1 || { echo "SKIP test_backhaul_e2e ($c missing)"; exit 0; }
done
ver=$("$BIN" -v 2>&1)
[[ $ver == v0.7.2* ]] || { echo "SKIP test_backhaul_e2e (unexpected version: $ver)"; exit 0; }

HUB=bh-hub
SPOKE=bh-spoke
CTRL=18080   # tunnel control port (hub)
FWD=18081    # forwarded port (hub, public side)
ECHO=18082   # echo target (spoke, loopback)
TMP=$(mktemp -d /tmp/bh-e2e.XXXXXX)
pids=()
set +m
cleanup() {
    local p
    for p in "${pids[@]:-}"; do [[ -n $p ]] && { kill -9 "$p"; wait "$p"; } 2>/dev/null; done
    ip netns del "$HUB" 2>/dev/null; ip netns del "$SPOKE" 2>/dev/null
    [[ -n ${BH_E2E_LOGDIR:-} ]] && { mkdir -p "$BH_E2E_LOGDIR"; cp "$TMP"/*.log "$TMP"/*.toml "$BH_E2E_LOGDIR"/ 2>/dev/null; }
    rm -rf "$TMP"
}
trap cleanup EXIT
ip netns del "$HUB" 2>/dev/null; ip netns del "$SPOKE" 2>/dev/null
ip netns add "$HUB" 2>/dev/null || { echo "SKIP test_backhaul_e2e (no netns permission)"; exit 0; }
ip netns add "$SPOKE" || { echo "SKIP test_backhaul_e2e (no netns permission)"; exit 0; }

# veth created directly inside the namespaces: never exists in the host ns.
ip link add vbh-hub netns "$HUB" type veth peer name vbh-spoke netns "$SPOKE" \
    || { echo "SKIP test_backhaul_e2e (veth unsupported)"; exit 0; }
ip netns exec "$HUB" bash -c 'ip addr add 192.0.2.1/24 dev vbh-hub; ip link set vbh-hub up; ip link set lo up'
ip netns exec "$SPOKE" bash -c 'ip addr add 192.0.2.2/24 dev vbh-spoke; ip link set vbh-spoke up; ip link set lo up'

fail=0
check() { if [[ "$2" != "$3" ]]; then echo "FAIL: $1 (want [$2] got [$3])"; fail=1; else echo "ok:   $1"; fi; }

TOKEN=lab-token-e2e
write_server() { cat >"$TMP/server.toml" <<EOF
[server]
bind_addr = "192.0.2.1:$CTRL"
transport = "tcpmux"
token = "$TOKEN"
heartbeat = 5
log_level = "debug"
ports = ["$FWD=127.0.0.1:$ECHO"]
EOF
}
write_client() { cat >"$TMP/client.toml" <<EOF
[client]
remote_addr = "192.0.2.1:$CTRL"
transport = "tcpmux"
token = "$1"
retry_interval = 1
dial_timeout = 5
log_level = "debug"
EOF
}

# probe: send a random payload to the hub's forwarded port, return rc 0 only on
# a byte-exact echo. Runs in the hub namespace (the public side).
probe() {
    ip netns exec "$HUB" python3 -I - "$1" <<'PY'
import os, socket, sys
n = int(sys.argv[1])
data = os.urandom(n)
try:
    s = socket.create_connection(("192.0.2.1", 18081), timeout=3)
    s.settimeout(3)
    s.sendall(data)
    got = b""
    while len(got) < n:
        c = s.recv(65536)
        if not c: break
        got += c
    s.close()
except Exception:
    sys.exit(2)
sys.exit(0 if got == data else 1)
PY
}
wait_probe() { # secs size
    local end=$((SECONDS + $1))
    while (( SECONDS < end )); do probe "$2" && return 0; sleep 0.5; done
    return 1
}
start_client() { # token log
    write_client "$1"
    ip netns exec "$SPOKE" "$BIN" -c "$TMP/client.toml" >"$2" 2>&1 &
    cpid=$!; pids+=("$cpid")
}

# echo responder in the spoke (the tunnel target).
ip netns exec "$SPOKE" python3 -I -c '
import socketserver
class H(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            d = self.request.recv(65536)
            if not d: break
            self.request.sendall(d)
class S(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
S(("127.0.0.1", 18082), H).serve_forever()' >"$TMP/echo.log" 2>&1 &
pids+=($!)

write_server
ip netns exec "$HUB" "$BIN" -c "$TMP/server.toml" >>"$TMP/server.log" 2>&1 &
pids+=($!)
sleep 1

# a. handshake
start_client "$TOKEN" "$TMP/client.log"
if wait_probe 15 16; then check "a. handshake: tunnel established" up up; else check "a. handshake: tunnel established" up down; fi
sleep 11   # >10 s: must not be in a reconnect loop
recon=$(grep -c -i -E 'invalid token|connection refused|reconnect' "$TMP/client.log")
check "a. no reconnect loop / invalid token in 10s+" 0 "$recon"

# b. data path, byte-compare (small + 1 MiB)
probe 16;      check "b. echo 16 B byte-exact" 0 $?
probe 1048576; check "b. echo 1 MiB byte-exact" 0 $?

# c. wrong token must be rejected
kill -9 "$cpid" 2>/dev/null; wait "$cpid" 2>/dev/null
sleep 1
: >"$TMP/server.log"
start_client "wrong-token" "$TMP/client_bad.log"
sleep 4
if probe 16; then check "c. wrong token rejected (data path must be down)" down up; else check "c. wrong token rejected (data path must be down)" down down; fi
rej=$(grep -c 'invalid security token received: wrong-token' "$TMP/server.log")
check "c. server logged the rejection" yes "$([[ $rej -gt 0 ]] && echo yes || echo no)"

# d. restart resilience: good client, kill -9, restart, recover < 15 s
kill -9 "$cpid" 2>/dev/null; wait "$cpid" 2>/dev/null
start_client "$TOKEN" "$TMP/client2.log"
wait_probe 15 16; check "d. good client reconnects" 0 $?
kill -9 "$cpid" 2>/dev/null; wait "$cpid" 2>/dev/null
start_client "$TOKEN" "$TMP/client3.log"
t0=$SECONDS
wait_probe 15 4096; rc=$?
check "d. data path back within 15 s of kill -9 (took $((SECONDS - t0))s)" 0 "$rc"

if (( fail == 0 )); then echo "PASS test_backhaul_e2e"; else
    for f in server client client_bad client2 client3; do echo "--- $f.log"; tail -n 15 "$TMP/$f.log" 2>/dev/null; done
    exit 1
fi
