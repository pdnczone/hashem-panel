#!/usr/bin/env bash
# tests/test_bagher_lab.sh — real Bagher stealth tunnel in network namespaces.
#
# Iran (bg-ir) keeps an SSH session to each foreign server (bg-fo, and bg-fo2,
# which Iran reaches over IPv6 only)
# with the panel's own carrier (gre-panel bagher-carrier: a reverse forward of
# 127.0.0.1:FRP). frps on Iran listens on loopback and publishes the user
# ports; the frpc on each foreign server reaches it through its SSH session
# and serves that server's services. A user (bg-us) only talks to Iran.
#
# Every config is the panel's own output (panel/bagher_lab_test.go), so this
# proves what the panel ships: data path for two foreign servers on one Iran
# server, nothing exposed, the restricted key allows only its one reverse
# forward, recovery after crashes and a network outage longer than the
# keepalive timeout, and the tunnel's ping: with 30 ms each way, a reply
# written in two parts arrives one round trip after the request (plain
# `ssh -N` is measured too, for comparison: its sshd holds the second part
# for the first one's ACK).
#
# Needs root (netns), ip, sshd, ssh, ssh-keygen, python3, curl, frps/frpc
# (FRP_DIR, default /tmp/frp-rel) and Go or a prebuilt test binary
# (BAGHER_LAB_TEST_BIN). tc with netem for the ping check (skipped without).
# Skips cleanly otherwise. Touches nothing outside the four namespaces and a
# mktemp dir (and creates /run/sshd if missing).
set -u
cd "$(dirname "$0")/.." || exit 1
ROOT=$PWD

FRP_DIR=${FRP_DIR:-/tmp/frp-rel}
for c in ip ssh ssh-keygen python3 curl; do
    command -v "$c" >/dev/null 2>&1 || { echo "SKIP test_bagher_lab ($c missing)"; exit 0; }
done
SSHD=$(command -v sshd || echo /usr/sbin/sshd)
[[ -x $SSHD ]] || { echo "SKIP test_bagher_lab (sshd missing)"; exit 0; }
[[ -x $FRP_DIR/frps && -x $FRP_DIR/frpc ]] || { echo "SKIP test_bagher_lab (frps/frpc missing in $FRP_DIR)"; exit 0; }

IR=bg-ir; FO=bg-fo; FO2=bg-fo2; US=bg-us
IR_FO=198.51.100.1;  FO_IP=198.51.100.2    # Iran <-> Foreign 1
IR_FO2=2001:db8:22::1; FO2_IP=2001:db8:22::2 # Iran <-> Foreign 2, over IPv6 only
IR_US=203.0.113.1;   US_IP=203.0.113.2     # user <-> Iran link
P1=18080; P2=18081; PL=18083               # Foreign 1: two web servers, the ping service
P3=18082                                   # Foreign 2: a web server
FRP=55400                                  # panel default
TMP=$(mktemp -d /tmp/bagher-lab.XXXXXX)
chmod 755 "$TMP"
pids=()
set +m
# the job log needs auth; annotations are public. Sent on every exit, an early
# one included, with the last lines the script printed to stderr.
report() {
    [[ -n ${GITHUB_ACTIONS:-} ]] || return 0
    local rc=$1 bad=0 r n_ok n_bad
    (( rc || ${fail:-1} )) && bad=1
    # plain ASCII, one line per annotation: a raw log byte must not cost the report
    gh() { LC_ALL=C tr -cd '\11\12\40-\176' | sed -e 's/%/%25/g' | sed -e ':a;N;$!ba;s/\n/%0A/g'; }
    n_ok=$(grep -c '^ok:' "$TMP/result.txt" 2>/dev/null); n_bad=$(grep -c '^FAIL:' "$TMP/result.txt" 2>/dev/null)
    echo "::notice title=Bagher lab::${n_ok:-0} checks passed, ${n_bad:-0} failed, exit $rc"
    grep '^FAIL:' "$TMP/result.txt" 2>/dev/null | head -n 8 | while IFS= read -r r; do echo "::error title=Bagher lab::$(printf '%s' "$r" | gh)"; done
    if (( bad )); then
        r=$({ echo "--- stderr"; tail -n 8 "$TMP/stderr.log"
              echo "--- carrier1.log"; tail -n 10 "$TMP/carrier1.log"; echo "--- carrier2.log"; tail -n 8 "$TMP/carrier2.log"
              echo "--- sshd2.log"; tail -n 6 "$TMP/sshd2.log"; echo "--- frpc2.log"; tail -n 6 "$TMP/frpc2.log"; } 2>/dev/null | tail -c 5000 | gh)
        echo "::warning title=Bagher lab logs::$r"
    fi
}
cleanup() {
    local rc=$? p
    report "$rc"
    for p in "${pids[@]:-}"; do [[ -n $p ]] && { pkill -9 -P "$p"; kill -9 "$p"; wait "$p"; } 2>/dev/null; done
    for ns in $IR $FO $FO2 $US; do ip netns pids "$ns" 2>/dev/null | xargs -r kill -9 2>/dev/null; ip netns del "$ns" 2>/dev/null; done
    [[ -n ${BAGHER_LAB_LOGDIR:-} ]] && { mkdir -p "$BAGHER_LAB_LOGDIR"; cp "$TMP"/*.log "$TMP"/*.toml "$TMP"/*.json "$TMP"/authorized_keys* "$BAGHER_LAB_LOGDIR"/ 2>/dev/null; }
    rm -rf "$TMP"
}
trap cleanup EXIT
exec 2> >(tee -a "$TMP/stderr.log" >&2)
for ns in $IR $FO $FO2 $US; do ip netns del "$ns" 2>/dev/null; done
ip netns add $IR 2>/dev/null || { echo "SKIP test_bagher_lab (no netns permission)"; exit 0; }
ip netns add $FO && ip netns add $FO2 && ip netns add $US || { echo "SKIP test_bagher_lab (netns)"; exit 0; }
ip link add vg-ir netns $IR type veth peer name vg-fo netns $FO || { echo "SKIP test_bagher_lab (veth unsupported)"; exit 0; }
ip link add vg-ir2 netns $IR type veth peer name vg-fo2 netns $FO2
ip link add vg-irus netns $IR type veth peer name vg-us netns $US
ip -n $IR addr add $IR_FO/24 dev vg-ir;    ip -n $IR -6 addr add $IR_FO2/64 dev vg-ir2 nodad;  ip -n $IR addr add $IR_US/24 dev vg-irus
ip -n $FO addr add $FO_IP/24 dev vg-fo;    ip -n $FO2 -6 addr add $FO2_IP/64 dev vg-fo2 nodad; ip -n $US addr add $US_IP/24 dev vg-us
for l in "$IR vg-ir" "$IR vg-ir2" "$IR vg-irus" "$IR lo" "$FO vg-fo" "$FO lo" "$FO2 vg-fo2" "$FO2 lo" "$US vg-us" "$US lo"; do
    set -- $l; ip -n "$1" link set "$2" up
done

fail=0
ok()   { echo "ok:   $1"; echo "ok:   $1" >> "$TMP/result.txt"; }
bad()  { echo "FAIL: $1"; echo "FAIL: $1" >> "$TMP/result.txt"; fail=1; }
note() { echo "note: $1"; echo "note: $1" >> "$TMP/result.txt"; }
check() { if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1 (want [$2] got [$3])"; fi; }
# wait_for SECS CMD...: true once CMD succeeds, polling every second.
wait_for() { local n=$1; shift; local i; for ((i = 0; i < n; i++)); do "$@" >/dev/null 2>&1 && return 0; sleep 1; done; return 1; }
in_ns() { local ns=$1; shift; ip netns exec "$ns" "$@"; }

# ---- the panel's own configs and its carrier -------------------------------
ssh-keygen -q -t ed25519 -N '' -f "$TMP/id" -C hashem-bagher-carrier
ssh-keygen -q -t ed25519 -N '' -f "$TMP/wrong" -C stranger
BIN=${BAGHER_LAB_TEST_BIN:-}
if [[ -z $BIN ]]; then
    command -v go >/dev/null 2>&1 || { echo "SKIP test_bagher_lab (no go and no BAGHER_LAB_TEST_BIN)"; exit 0; }
    (cd "$ROOT/panel" && go test -c -o "$TMP/bagherlab.test" .) || { bad "building the test binary"; exit 1; }
    BIN=$TMP/bagherlab.test
fi
(cd "$ROOT/panel" && env BAGHER_LAB_DIR="$TMP" BAGHER_LAB_KEY="$TMP/id" BAGHER_LAB_HOST="$FO_IP" BAGHER_LAB_PORTS="$P1,$P2,$PL" \
    BAGHER_LAB_FRP_PORT="$FRP" BAGHER_LAB_UDP=1 BAGHER_LAB_HOST2="$FO2_IP" BAGHER_LAB_PORTS2="$P3" \
    "$BIN" -test.run '^TestBagherLabConfigs$' >"$TMP/gen.log" 2>&1)
[[ -s $TMP/frps.toml && -s $TMP/frpc.toml && -s $TMP/frpc2.toml && -s $TMP/sshfwd.json && -s $TMP/authorized_keys && -s $TMP/authorized_keys2 ]] \
    || { cat "$TMP/gen.log"; bad "panel generated the Bagher configs"; exit 1; }
grep -q '^ExecStart=.* bagher-carrier -link 1$' "$TMP/unit.service" || { bad "the unit runs the panel's carrier"; cat "$TMP/unit.service"; }
ok "panel generated frps.toml, frpc.toml (x2), sshfwd.json with 2 foreign servers and authorized_keys (x2)"
RESTART=$(sed -n 's/^RestartSec=//p' "$TMP/unit.service"); RESTART=${RESTART:-15}

# ---- Foreign servers: sshd, the services, frpc ------------------------------
mkdir -p /run/sshd "$TMP/www1" "$TMP/www2" "$TMP/www3"
# start_sshd NS IP N AUTHORIZED_KEYS
start_sshd() {
    ssh-keygen -q -t ed25519 -N '' -f "$TMP/host_key$3"
    cat >"$TMP/sshd_config$3" <<EOF
ListenAddress $2
Port 22
HostKey $TMP/host_key$3
AuthorizedKeysFile $4
PidFile $TMP/sshd$3.pid
PermitRootLogin prohibit-password
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
StrictModes no
LogLevel VERBOSE
EOF
    in_ns "$1" "$SSHD" -D -e -f "$TMP/sshd_config$3" >"$TMP/sshd$3.log" 2>&1 & pids+=($!)
}
start_sshd $FO $FO_IP 1 "$TMP/authorized_keys"
start_sshd $FO2 $FO2_IP 2 "$TMP/authorized_keys2"
head -c 8388608 /dev/urandom >"$TMP/www1/blob"
head -c 1048576 /dev/urandom >"$TMP/www2/blob"
head -c 4194304 /dev/urandom >"$TMP/www3/blob"
in_ns $FO python3 -m http.server $P1 --bind 127.0.0.1 --directory "$TMP/www1" >"$TMP/www1.log" 2>&1 & pids+=($!)
in_ns $FO python3 -m http.server $P2 --bind 127.0.0.1 --directory "$TMP/www2" >"$TMP/www2.log" 2>&1 & pids+=($!)
in_ns $FO2 python3 -m http.server $P3 --bind 127.0.0.1 --directory "$TMP/www3" >"$TMP/www3.log" 2>&1 & pids+=($!)
# UDP echo on the first port (the panel's frpc carries it as a udp proxy)
in_ns $FO python3 -I -c '
import socket, sys
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
u.bind(("127.0.0.1", int(sys.argv[1])))
while True:
    d, a = u.recvfrom(65535)
    u.sendto(d, a)' $P1 >"$TMP/udpecho.log" 2>&1 & pids+=($!)
# The ping service: each request byte is answered in two writes 5 ms apart,
# like a TLS server flight or an HTTP header then body.
in_ns $FO python3 -I -c '
import socket, sys, threading, time
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1]))); s.listen(16)
def serve(c):
    c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    while c.recv(1):
        c.sendall(b"A"); time.sleep(0.005); c.sendall(b"B")
while True:
    c, _ = s.accept(); threading.Thread(target=serve, args=(c,), daemon=True).start()' $PL >"$TMP/pingsvc.log" 2>&1 & pids+=($!)
in_ns $FO "$FRP_DIR/frpc" -c "$TMP/frpc.toml" >"$TMP/frpc.log" 2>&1 & pids+=($!)
in_ns $FO2 "$FRP_DIR/frpc" -c "$TMP/frpc2.toml" >"$TMP/frpc2.log" 2>&1 & pids+=($!)

# ---- Iran: frps and one carrier per foreign server, each under a Restart=always loop
start_frps() { in_ns $IR "$FRP_DIR/frps" -c "$TMP/frps.toml" >>"$TMP/frps.log" 2>&1 & FRPS_PID=$!; pids+=($FRPS_PID); }
start_frps
# loop NAME CMD: CMD under a Restart=always loop with the unit's delay. The
# loop's and the current CMD's pids go to NAME.loop / NAME.pid (ip netns exec
# may or may not fork, so $! is not reliably either of them).
loop() {
    local name=$1; shift
    in_ns $IR bash -c "echo \$\$ >'$TMP/$name.loop'; while true; do $* >>'$TMP/$name.log' 2>&1 & echo \$! >'$TMP/$name.pid'; wait \$!; echo \"exit \$? \$(date +%T)\" >>'$TMP/$name.log'; sleep $RESTART; done" &
    pids+=($!)
    wait_for 5 test -s "$TMP/$name.pid"
}
# kill_cmd NAME: kill -9 the current CMD (the loop restarts it); stop_loop NAME: both, for good.
kill_cmd() { kill -9 "$(cat "$TMP/$1.pid")" 2>/dev/null; }
stop_loop() { kill -9 "$(cat "$TMP/$1.loop")" 2>/dev/null; kill_cmd "$1"; rm -f "$TMP/$1.pid" "$TMP/$1.loop"; }
# carrier_loop LINK: the unit's ExecStart (the carrier).
carrier_loop() {
    loop "carrier$1" "env GRE_PANEL_DIR='$TMP' BAGHER_LAB_CARRIER_LINK=$1 BAGHER_LAB_KNOWN='$TMP/known_hosts' '$BIN' -test.run '^TestBagherLabCarrier\$'"
}
carrier_loop 1
carrier_loop 2

fetch() { in_ns $US curl -fsS --max-time 20 "http://$IR_US:$1/blob" | sha256sum | cut -d' ' -f1; }
want1=$(sha256sum <"$TMP/www1/blob" | cut -d' ' -f1)
want2=$(sha256sum <"$TMP/www2/blob" | cut -d' ' -f1)
want3=$(sha256sum <"$TMP/www3/blob" | cut -d' ' -f1)
tunnel_up() { [[ $(fetch $P1) == "$want1" ]]; }
tunnel2_up() { [[ $(fetch $P3) == "$want3" ]]; }

# ---- 1. data path, two foreign servers ---------------------------------------
if wait_for 60 tunnel_up; then ok "user -> Iran:$P1 -> carrier -> Foreign 1 service (8 MiB, sha256 match)"; else
    bad "tunnel never carried data"; tail -n 20 "$TMP/carrier1.log" "$TMP/frpc.log" "$TMP/sshd1.log"; exit 1; fi
check "second port reaches its own service (1 MiB)" "$want2" "$(fetch $P2)"
if wait_for 60 tunnel2_up; then ok "user -> Iran:$P3 -> carrier 2 -> Foreign 2 service (4 MiB, sha256 match)"; else
    bad "second foreign server never carried data"; tail -n 20 "$TMP/carrier2.log" "$TMP/frpc2.log" "$TMP/sshd2.log"; fi
okc=0
par=()
for i in $(seq 16); do if (( i % 2 )); then (fetch $P2 >"$TMP/par.$i") & else (fetch $P3 >"$TMP/par.$i") & fi; par+=($!); done
wait "${par[@]}"   # only these: a bare wait would also wait for sshd and frp
for i in $(seq 16); do w=$want2; (( i % 2 )) || w=$want3; [[ $(cat "$TMP/par.$i") == "$w" ]] && okc=$((okc + 1)); done
check "16 parallel requests over both foreign servers all intact" 16 "$okc"

# What the panel reads: frps's per-proxy status (each foreign server's own
# ports) and each carrier's status file (connected, tunnel ping).
proxies=$(in_ns $IR curl -fsS -u admin:bagher-dash-local "http://127.0.0.1:$((FRP + 1))/api/proxy/tcp" 2>/dev/null)
online=$(python3 -c 'import json,sys; print(" ".join(sorted(p["name"] for p in json.load(sys.stdin)["proxies"] if p.get("status") == "online")))' <<<"$proxies" 2>/dev/null)
check "frps lists every foreign server's ports online" "p$P1 p$P2 p$P3 p$PL" "$online"
for n in 1 2; do
    st=$(python3 -c 'import json,sys; s=json.load(open(sys.argv[1])); print("up" if s.get("connected") and s.get("rtt_ms",0) > 0 else "down")' "$TMP/bagher-carrier-$n.json" 2>/dev/null)
    check "carrier $n reports connected with a ping" up "$st"
done
grep -q 'Starting session: forced-command' "$TMP/sshd1.log" && ok "carrier ran its one exec (sshd sets TCP_NODELAY), held to the forced command" \
    || note "sshd1.log has no forced-command session line (log format?)"

# ---- 1b. UDP on the same port, through the same carrier ---------------------
# udp_ok N SIZE: datagrams from the user to Iran:P1; true when >=90% come back intact.
udp_ok() {
    in_ns $US python3 -I - "$IR_US" "$P1" "$1" "$2" <<'PY'
import os, socket, sys
host, port, n, size = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(1.5)
s.connect((host, port))
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
if wait_for 30 udp_ok 5 64; then ok "UDP user -> Iran:$P1 -> carrier -> Foreign UDP service"; else bad "UDP never crossed the Bagher tunnel"; fi
udp_ok 30 1200 && ok "30 datagrams of 1200 B (>=90% intact)" || bad "UDP datagrams of 1200 B lost"

# ---- 1c. ping: 30 ms each way between Iran and Foreign 1 --------------------
# lat_ms: median ms from a request byte to both parts of its reply, on one connection.
lat_ms() {
    in_ns $US python3 -I - "$IR_US" "$PL" <<'PY'
import socket, sys, time
s = socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=5)
s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
v = []
for i in range(28):
    t = time.monotonic(); s.sendall(b"x"); got = b""
    while len(got) < 2: got += s.recv(2 - len(got))
    if i >= 3: v.append((time.monotonic() - t) * 1000)
    time.sleep(0.2)
v.sort(); print(int(v[len(v) // 2]))
PY
}
pl_up() { [[ -n $(lat_ms) ]]; }
if in_ns $IR tc qdisc add dev vg-ir root netem delay 30ms 2>/dev/null && in_ns $FO tc qdisc add dev vg-fo root netem delay 30ms 2>/dev/null; then
    wait_for 30 pl_up
    new=$(lat_ms)
    # The same link over plain ssh -N, the carrier before this version.
    cpid=$(cat "$TMP/carrier1.pid")
    stop_loop carrier1
    sleep 1
    kill -0 "$cpid" 2>/dev/null && bad "carrier 1 still running after stop (pid $cpid)"
    loop legacy "/usr/bin/ssh -N -i '$TMP/id' -o BatchMode=yes -o IdentitiesOnly=yes -o ExitOnForwardFailure=yes -o ConnectTimeout=8 -o ServerAliveInterval=15 -o ServerAliveCountMax=3 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -R 127.0.0.1:$FRP:127.0.0.1:$FRP -o Ciphers=aes128-gcm@openssh.com,chacha20-poly1305@openssh.com -o TCPKeepAlive=yes root@$FO_IP"
    old=""
    wait_for 90 pl_up && old=$(lat_ms)
    # proof that this was ssh -N: it is alive and holds the only session on Foreign 1
    lpid=$(cat "$TMP/legacy.pid" 2>/dev/null)
    sess=$(in_ns $FO ss -Htn state established "( sport = :22 )" | wc -l)
    kill -0 "$lpid" 2>/dev/null && [[ $sess == 1 ]] && ok "comparison ran over plain ssh -N (pid $lpid, $sess SSH session on Foreign 1)" \
        || bad "comparison was not over ssh -N alone (ssh pid ${lpid:-none}, $sess SSH sessions on Foreign 1)"
    stop_loop legacy
    carrier_loop 1
    in_ns $IR tc qdisc del dev vg-ir root 2>/dev/null; in_ns $FO tc qdisc del dev vg-fo root 2>/dev/null
    wait_for 90 tunnel_up || bad "carrier did not come back after the ping comparison"
    note "two-part reply over a 60 ms round trip: carrier ${new:-?} ms, plain ssh -N ${old:-?} ms ($(ssh -V 2>&1 | cut -d, -f1))"
    if [[ -n $new ]] && (( new < 100 )); then ok "carrier: the reply arrives one round trip after the request (${new} ms of 60)"
    else bad "carrier ping ${new:-none} ms over a 60 ms round trip (Nagle on the foreign sshd?)"; fi
else
    note "tc netem unavailable: ping comparison skipped"
fi

# ---- 2. nothing exposed -----------------------------------------------------
in_ns $US bash -c "exec 3<>/dev/tcp/$IR_US/$FRP" 2>/dev/null && bad "frps control port reachable from outside Iran" \
    || ok "frps control port is loopback-only on Iran"
in_ns $IR bash -c "exec 3<>/dev/tcp/$FO_IP/$FRP" 2>/dev/null && bad "reverse port reachable on Foreign's public address" \
    || ok "reverse port is loopback-only on Foreign"

# ---- 3. the key Iran holds can do nothing but its one reverse forward -------
SSHO=(-i "$TMP/id" -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=8)
out=$(in_ns $IR timeout 15 ssh "${SSHO[@]}" root@$FO_IP 'echo PWNED-$(id -u)' 2>&1)
[[ $out == *PWNED* ]] && bad "key runs commands on Foreign as root ($out)" || ok "key cannot run commands on Foreign"
# -L to a real service on Foreign's loopback (the 8 MiB web server).
in_ns $IR timeout 20 ssh "${SSHO[@]}" -N -L 127.0.0.1:19999:127.0.0.1:$P1 root@$FO_IP >"$TMP/lfwd.log" 2>&1 & lf=$!; pids+=($lf)
sleep 3
got=$(in_ns $IR curl -fsS --max-time 5 -o /dev/null -w '%{http_code}' http://127.0.0.1:19999/ 2>/dev/null)
kill "$lf" 2>/dev/null
[[ $got == 200 ]] && bad "key opens -L forwards into Foreign's loopback services" || ok "key cannot open -L forwards"
in_ns $IR timeout 15 ssh "${SSHO[@]}" -N -o ExitOnForwardFailure=yes -R 127.0.0.1:55499:127.0.0.1:1 root@$FO_IP >/dev/null 2>&1
rc=$?
[[ $rc -ne 124 ]] && ok "key cannot listen on any other port (ssh exit $rc)" || bad "key opened -R on another port"
out=$(in_ns $IR timeout 15 ssh -i "$TMP/wrong" -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@$FO_IP true 2>&1)
[[ $out == *"Permission denied"* ]] && ok "a different key is refused" || bad "unknown key accepted ($out)"

# ---- 4. recovery and independence ---------------------------------------------
t0=$(date +%s)
cpid=$(cat "$TMP/carrier1.pid")
kill_cmd carrier1   # the carrier, not its restart loop
sleep 1
kill -0 "$cpid" 2>/dev/null && bad "carrier survived kill -9"
if wait_for $((RESTART + 60)) tunnel_up; then ok "recovers after kill -9 of the carrier ($(( $(date +%s) - t0 ))s)"
else bad "no recovery after kill -9 of the carrier"; fi

t0=$(date +%s)
kill -9 "$FRPS_PID"; wait "$FRPS_PID" 2>/dev/null
sleep 10   # the frps unit's RestartSec
start_frps
if wait_for 90 tunnel_up; then ok "recovers after frps crash on Iran ($(( $(date +%s) - t0 ))s)"
else bad "no recovery after frps crash"; fi
wait_for 90 tunnel2_up && ok "Foreign 2 recovers after the frps crash too" || bad "Foreign 2 did not recover after the frps crash"

# Outage of Foreign 1 longer than the keepalive timeout (15s x 3): its carrier
# gives up while sshd may still hold the reverse port for the dead session.
# Foreign 2 must not notice.
ip -n $FO link set vg-fo down
sleep 20
tunnel2_up && ok "Foreign 2 keeps working while Foreign 1 is cut off" || bad "Foreign 2 failed while Foreign 1 was down"
sleep 40
ip -n $FO link set vg-fo up
t0=$(date +%s)
if wait_for 240 tunnel_up; then ok "recovers after a 60s Iran<->Foreign outage ($(( $(date +%s) - t0 ))s after the link returned)"
else bad "no recovery within 240s after a 60s outage"; echo "--- carrier1.log"; tail -n 15 "$TMP/carrier1.log"; echo "--- sshd1.log"; tail -n 15 "$TMP/sshd1.log"; fi

[[ $fail -eq 0 ]] && echo "PASS test_bagher_lab" || { echo "--- carrier1.log"; tail -n 10 "$TMP/carrier1.log"; echo "--- frpc.log"; tail -n 10 "$TMP/frpc.log"; exit 1; }
