#!/usr/bin/env bash
# tests/test_xray_lab.sh — the Xray tunnel with a real Xray-core.
#
# Three network namespaces: a user (xr-user), the Iran server (xr-iran) and the
# foreign server (xr-fo), with 30 ms between Iran and foreign. The foreign
# server runs the service the tunnel forwards to (127.0.0.1:2053, TCP and UDP),
# a TLS 1.3 site Reality borrows its handshake from (127.0.0.1:9443,
# lab.example: the namespaces have no internet) and a fake 3x-ui: another xray
# under /usr/local/x-ui that holds port 443.
#
# The configs come from the panel's own code (panel/xray_lab_test.go: the Iran
# link, its bundle, the foreign link imported from it). For every preset
# (Reality, XHTTP, gRPC, mKCP) in both modes it checks: the probe, 8 MiB each
# way with sha256, 16 parallel connections, UDP. Reverse mode runs with Iran's
# connections to the foreign server blocked. Also: the fake x-ui is named and
# left alone, a probe without the key gets the borrowed site's certificate, the
# foreign end refuses a port it does not forward, and a reverse link comes back
# after the foreign Xray restarts.
#
# Needs root (netns), ip, iptables, tc (netem), python3, openssl, an Xray-core
# (XRAY_BIN) and Go or a prebuilt test binary (XRAY_LAB_TEST_BIN). Skips
# cleanly otherwise. Touches nothing outside the namespaces and a mktemp dir.
set -u
cd "$(dirname "$0")/.." || exit 1
ROOT=$PWD

for c in ip python3 openssl iptables; do
    command -v "$c" >/dev/null 2>&1 || { echo "SKIP test_xray_lab ($c missing)"; exit 0; }
done
XRAY=${XRAY_BIN:-}
[[ -x $XRAY ]] || { echo "SKIP test_xray_lab (set XRAY_BIN to an Xray-core binary)"; exit 0; }
USR=xr-user; IR=xr-iran; FO=xr-fo
USR_IP=10.31.1.2; IR_U=10.31.1.1; IR_IP=10.31.2.1; FO_IP=10.31.2.2
PORT=2053; TUNNEL=8443; PROBE=10999; EVIL=2054; TAKEN=443
TMP=$(mktemp -d /tmp/xray-lab.XXXXXX)
chmod 755 "$TMP"
pids=()
set +m
cleanup() {
    local p
    for p in "${pids[@]:-}"; do [[ -n $p ]] && { kill -9 "$p"; wait "$p"; } 2>/dev/null; done
    for ns in $USR $IR $FO; do ip netns pids "$ns" 2>/dev/null | xargs -r kill -9 2>/dev/null; ip netns del "$ns" 2>/dev/null; done
    rm -rf "$TMP"
}
trap cleanup EXIT
for ns in $USR $IR $FO; do ip netns del "$ns" 2>/dev/null; done
ip netns add $USR 2>/dev/null || { echo "SKIP test_xray_lab (no netns permission)"; exit 0; }
ip netns add $IR && ip netns add $FO || { echo "SKIP test_xray_lab (netns)"; exit 0; }
ip link add xu0 netns $USR type veth peer name xu1 netns $IR || { echo "SKIP test_xray_lab (veth unsupported)"; exit 0; }
ip link add xf0 netns $IR type veth peer name xf1 netns $FO
ip -n $USR addr add $USR_IP/24 dev xu0; ip -n $IR addr add $IR_U/24 dev xu1
ip -n $IR addr add $IR_IP/24 dev xf0; ip -n $FO addr add $FO_IP/24 dev xf1
for l in "$USR xu0" "$USR lo" "$IR xu1" "$IR xf0" "$IR lo" "$FO xf1" "$FO lo"; do set -- $l; ip -n "$1" link set "$2" up; done
# IPv6 next to IPv4 on both links, for the IPv6 round at the end
USR_IP6=2001:db8:31:1::2; IR_U6=2001:db8:31:1::1; IR_IP6=2001:db8:31:2::1; FO_IP6=2001:db8:31:2::2
V6=1
for a in "$USR xu0 $USR_IP6" "$IR xu1 $IR_U6" "$IR xf0 $IR_IP6" "$FO xf1 $FO_IP6"; do
    set -- $a
    ip netns exec "$1" sysctl -qw net.ipv6.conf.all.disable_ipv6=0 2>/dev/null
    ip -n "$1" -6 addr add "$3/64" dev "$2" nodad 2>/dev/null || V6=
done
NETEM=""
if ip netns exec $IR tc qdisc add dev xf0 root netem delay 15ms 2>/dev/null && ip netns exec $FO tc qdisc add dev xf1 root netem delay 15ms 2>/dev/null; then
    NETEM="30 ms"
fi

fail=0
ok()   { echo "ok:   $1"; echo "ok:   $1" >> "$TMP/result.txt"; }
bad()  { echo "FAIL: $1"; echo "FAIL: $1" >> "$TMP/result.txt"; fail=1; }
note() { echo "note: $1"; echo "note: $1" >> "$TMP/result.txt"; }

# ---- the lab's tools: the service (sha256 both ways), a UDP echo, a banner
# that must never be reached through the tunnel, the borrowed TLS 1.3 site,
# and the clients.
cat >"$TMP/xr.py" <<'PY'
import hashlib, os, socket, ssl, struct, sys, threading, time

def recvn(c, n):
    b = bytearray()
    while len(b) < n:
        x = c.recv(min(1 << 20, n - len(b)))
        if not x:
            break
        b += x
    return bytes(b)

def serve(listen, handler):
    while True:
        c, _ = listen.accept()
        threading.Thread(target=handler, args=(c,), daemon=True).start()

def tcp_listen(host, port):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port)); s.listen(128)
    return s

def service(host, port):
    def h(c):
        with c:
            n = struct.unpack("!Q", recvn(c, 8))[0]
            if n >> 63:  # a download that runs until the client hangs up
                chunk = os.urandom(1 << 16)
                try:
                    while True:
                        c.sendall(chunk)
                except OSError:
                    return
            got = hashlib.sha256(recvn(c, n)).digest()
            data = os.urandom(n)
            c.sendall(got + hashlib.sha256(data).digest() + data)
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.bind((host, port))
    def echo():
        while True:
            d, a = u.recvfrom(65535); u.sendto(d, a)
    threading.Thread(target=echo, daemon=True).start()
    serve(tcp_listen(host, port), h)

def banner(host, port):
    def h(c):
        with c:
            c.sendall(b"SECRET\n"); time.sleep(1)
    serve(tcp_listen(host, port), h)

def tls_site(host, port, cert, key):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(cert, key)
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    def h(c):
        try:
            with ctx.wrap_socket(c, server_side=True) as t:
                t.settimeout(5); t.recv(4096)
                t.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        except Exception:
            c.close()
    serve(tcp_listen(host, port), h)

def one(host, port, n):
    c = socket.create_connection((host, port), timeout=60)
    data = os.urandom(n)
    c.sendall(struct.pack("!Q", n) + data)
    r = recvn(c, 64 + n)
    c.close()
    return len(r) == 64 + n and r[:32] == hashlib.sha256(data).digest() and r[32:64] == hashlib.sha256(r[64:]).digest()

def tcp(host, port, n):
    sys.exit(0 if one(host, port, n) else 1)

def par(host, port, k, n):
    res = []
    ts = [threading.Thread(target=lambda: res.append(one(host, port, n))) for _ in range(k)]
    [t.start() for t in ts]; [t.join() for t in ts]
    sys.exit(0 if len(res) == k and all(res) else 1)

def load(host, port, secs):
    c = socket.create_connection((host, port), timeout=10)
    c.sendall(struct.pack("!Q", 1 << 63))
    end = time.time() + secs
    while time.time() < end:
        if not c.recv(1 << 16):
            break
    c.close()

def udp(host, port, count, size):
    s = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(0.2)
    got = set()
    for i in range(count):
        s.sendto(struct.pack("!I", i) + os.urandom(size - 4), (host, port))
        time.sleep(0.01)
    end = time.time() + 3
    while time.time() < end and len(got) < count:
        try:
            d, _ = s.recvfrom(65535)
            if len(d) == size:
                got.add(struct.unpack("!I", d[:4])[0])
        except socket.timeout:
            pass
    print(len(got))
    sys.exit(0 if len(got) >= count * 0.9 else 1)

def probe(port):
    t = time.time()
    try:
        c = socket.create_connection(("127.0.0.1", port), timeout=3); c.settimeout(6)
        c.sendall(b"GET / HTTP/1.1\r\nHost: probe.hashem\r\n\r\n")
        line = c.recv(64)
    except Exception:
        sys.exit(1)
    print("%.1f" % ((time.time() - t) * 1000))
    sys.exit(0 if line.startswith(b"HTTP/1.1 403") else 1)

def reach(host, port):
    # prints what a connection reads in 3 s
    try:
        c = socket.create_connection((host, port), timeout=3); c.settimeout(3)
        c.sendall(b"hello\n")
        print(c.recv(64).decode(errors="replace").strip())
    except Exception as e:
        print("closed")

f = globals()[sys.argv[1]]
f(*[int(a) if a.isdigit() else a for a in sys.argv[2:]])
PY
py() { local ns=$1; shift; ip netns exec "$ns" python3 -I "$TMP/xr.py" "$@"; }
bg() { "$@" >/dev/null 2>&1 & pids+=($!); }

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj "/CN=lab.example" \
    -addext "subjectAltName=DNS:lab.example" -keyout "$TMP/site.key" -out "$TMP/site.crt" >/dev/null 2>&1 \
    || { bad "making the lab site's certificate"; exit 1; }
bg py $FO service 127.0.0.1 $PORT
bg py $FO banner 127.0.0.1 $EVIL
# the Reality server borrows it: the foreign server in direct mode, Iran in reverse mode
bg py $FO tls_site 127.0.0.1 9443 "$TMP/site.crt" "$TMP/site.key"
bg py $IR tls_site 127.0.0.1 9443 "$TMP/site.crt" "$TMP/site.key"

# ---- a fake 3x-ui on the foreign server: another xray, in x-ui's folder, on 443
mkdir -p "$TMP/root/usr/local/x-ui/bin"
cp "$XRAY" "$TMP/root/usr/local/x-ui/bin/xray-linux-amd64"
cat >"$TMP/xui.json" <<EOF
{"log":{"loglevel":"warning"},"inbounds":[{"listen":"0.0.0.0","port":$TAKEN,"protocol":"dokodemo-door","settings":{"address":"127.0.0.1","port":9,"network":"tcp"}}],"outbounds":[{"protocol":"freedom"}]}
EOF
ip netns exec $FO "$TMP/root/usr/local/x-ui/bin/xray-linux-amd64" run -c "$TMP/xui.json" >"$TMP/xui.log" 2>&1 & XUI=$!; pids+=($XUI)
sleep 1

BIN=${XRAY_LAB_TEST_BIN:-}
if [[ -z $BIN ]]; then
    command -v go >/dev/null 2>&1 || { echo "SKIP test_xray_lab (no go and no XRAY_LAB_TEST_BIN)"; exit 0; }
    (cd "$ROOT/panel" && go test -c -o "$TMP/xraylab.test" .) || { bad "building the test binary"; exit 1; }
    BIN=$TMP/xraylab.test
fi
mkdir -p "$TMP/cfg"
if (cd "$ROOT/panel" && env XRAY_LAB_DIR="$TMP/cfg" XRAY_LAB_IRAN=$IR_IP XRAY_LAB_FOREIGN=$FO_IP XRAY_LAB_TARGET=127.0.0.1:9443 \
        XRAY_LAB_PORT=$PORT XRAY_LAB_TUNNEL=$TUNNEL XRAY_LAB_PROBE=$PROBE XRAY_LAB_EVIL=$EVIL \
        "$BIN" -test.run '^TestXrayLabGen$' >"$TMP/gen.log" 2>&1); then
    ok "panel made the Iran and foreign configs of $(wc -l <"$TMP/cfg/combos") links (Iran link -> bundle -> foreign link)"
else
    bad "generating the configs"; cat "$TMP/gen.log"; exit 1
fi

# ---- next to the fake 3x-ui: the panel names it and offers another port
if (cd "$ROOT/panel" && ip netns exec $FO env XRAY_LAB_TAKEN=$TAKEN "$BIN" -test.run '^TestXrayLabPorts$' -test.v >"$TMP/ports.log" 2>&1); then
    ok "port $TAKEN of the fake 3x-ui is refused, named and a free port offered ($(grep -o 'Use tunnel port [0-9]*' "$TMP/ports.log" | head -1))"
else
    bad "the panel did not see the fake 3x-ui on $TAKEN"; grep -v CMD-ERROR "$TMP/ports.log" | tail -20
fi

# start_link NAME [IRAN_CONFIG [CONFIG_DIR]]: both ends of one link; sets IRX and FOX
start_link() {
    local ic=${2:-$TMP/cfg/iran-$1.json} dir=${3:-$TMP/cfg}
    ip netns exec $FO "$XRAY" run -c "$dir/fo-$1.json" >"$TMP/fo-$1.log" 2>&1 & FOX=$!; pids+=($FOX)
    ip netns exec $IR "$XRAY" run -c "$ic" >"$TMP/iran-$1.log" 2>&1 & IRX=$!; pids+=($IRX)
}
stop_link() { kill -9 "$IRX" "$FOX" 2>/dev/null; wait "$IRX" "$FOX" 2>/dev/null; sleep 0.3; }
# wait_probe SECONDS: until a request through the link comes back; prints its ms
wait_probe() {
    local i ms
    for ((i = 0; i < $1 * 2; i++)); do
        if ms=$(py $IR probe $PROBE 2>/dev/null); then echo "$ms"; return 0; fi
        sleep 0.5
    done
    return 1
}
block_iran_out() { ip netns exec $IR iptables -A OUTPUT -d $FO_IP -m conntrack --ctstate NEW -j DROP; }
unblock_iran_out() { ip netns exec $IR iptables -D OUTPUT -d $FO_IP -m conntrack --ctstate NEW -j DROP 2>/dev/null; }

probes=""
while read -r name; do
    [[ -n $name ]] || continue
    mode=${name##*-}
    unblock_iran_out
    [[ $mode == reverse ]] && block_iran_out
    start_link "$name"
    if ! ms=$(wait_probe 20); then
        bad "$name: the link never answered the probe"
        echo "--- Iran:"; tail -n 15 "$TMP/iran-$name.log"; echo "--- foreign:"; tail -n 15 "$TMP/fo-$name.log"
        stop_link; continue
    fi
    # again once the link is open: what a user's new connection costs
    sleep 1
    warm=$(py $IR probe $PROBE 2>/dev/null || echo "?")
    probes+="$name ${ms}/${warm} ms, "
    # Direct Reality keeps connections ready (pre-connect): a new connection
    # skips the TCP and Reality handshakes, about one round trip.
    if [[ $name == reality-direct && -n $NETEM && $warm != "?" ]]; then
        if awk -v w="$warm" 'BEGIN { exit !(w < 60) }'; then
            ok "pre-connect: a new connection through direct Reality takes $warm ms over a $NETEM round trip"
        else
            bad "pre-connect: a new connection through direct Reality took $warm ms over a $NETEM round trip (want under 60)"
        fi
    fi
    sent=ok
    py $USR tcp $IR_U $PORT $((8 << 20)) || { bad "$name: 8 MiB each way through the tunnel (sha256)"; sent=; }
    py $USR par $IR_U $PORT 16 $((256 << 10)) || { bad "$name: 16 parallel connections"; sent=; }
    n=$(py $USR udp $IR_U $PORT 30 1200) || { bad "$name: UDP, $n of 30 datagrams came back"; sent=; }
    [[ -n $sent ]] && ok "$name: probe, 8 MiB each way (sha256), 16 parallel connections, UDP $n/30$([[ $mode == reverse ]] && echo ', with Iran -> foreign blocked')"
    if [[ $name == reality-direct ]]; then
        cn=$(ip netns exec $IR sh -c "openssl s_client -connect $FO_IP:$TUNNEL -servername lab.example </dev/null 2>/dev/null | openssl x509 -noout -subject 2>/dev/null")
        [[ $cn == *lab.example* ]] && ok "camouflage: without the key the tunnel port shows the borrowed site's certificate ($cn)" \
            || bad "camouflage: the tunnel port showed [$cn], not lab.example's certificate"
    fi
    if [[ $name == xhttp-reverse ]]; then
        kill -9 "$FOX"; wait "$FOX" 2>/dev/null
        t0=$SECONDS
        ip netns exec $FO "$XRAY" run -c "$TMP/cfg/fo-$name.json" >>"$TMP/fo-$name.log" 2>&1 & FOX=$!; pids+=($FOX)
        if wait_probe 30 >/dev/null && py $USR tcp $IR_U $PORT $((1 << 20)); then
            ok "reverse: the link comes back after the foreign Xray is killed ($((SECONDS - t0))s)"
        else
            bad "reverse: no link after the foreign Xray restarted"
        fi
    fi
    stop_link
done <"$TMP/cfg/combos"
unblock_iran_out
note "a request through each link and back, first/once open${NETEM:+, over a $NETEM round trip}: ${probes%, }"

# ---- Ping under load and a dead connection. The reverse link carries every
# user as a stream on its connections, so a download used to fill the one
# connection's send queue in front of everyone else; and a connection the
# network dropped without a word stayed in use for minutes. "base" is the
# reverse link as v2.8.4 made it: one connection, no send queue cap, no fast
# dead-connection check.
median() { sort -n | awk '{a[NR] = $1} END {if (NR) print a[int((NR + 1) / 2)]; else print "?"}'; }
# loaded: the probe while one download fills foreign -> Iran at 30 Mbit/s; median of 5, ms
loaded() {
    local lp i
    ip netns exec $FO tc qdisc change dev xf1 root netem delay 15ms rate 30mbit limit 100 || return 1
    py $USR load $IR_U $PORT 20 >/dev/null 2>&1 & lp=$!
    sleep 4
    for i in 1 2 3 4 5; do py $IR probe $PROBE 2>/dev/null || echo 6000; sleep 0.5; done | median
    kill "$lp" 2>/dev/null; wait "$lp" 2>/dev/null
    ip netns exec $FO tc qdisc change dev xf1 root netem delay 15ms limit 1000
    sleep 1
}
# dead_flow NAME: drop the link's open connections both ways without a word
# (new ones still pass); seconds until a request gets through again, at most
# 120. The sockets of both ends go to the log at 20 and 45 s. Packets are
# dropped where they arrive, as a network loses them: one dropped by the
# sender's own OUTPUT chain counts as local congestion, and TCP then retries
# without ever giving up.
dead_flow() {
    local p ports t0=$SECONDS shown=
    ports=$(ip netns exec $FO ss -Htn state established "dport = :$TUNNEL" | awk '{n = split($(NF - 1), a, ":"); print a[n]}')
    [[ -n $ports ]] || { echo 99; return; }
    for p in $ports; do
        ip netns exec $IR iptables -A INPUT -p tcp --sport "$p" --dport $TUNNEL -j DROP
        ip netns exec $FO iptables -A INPUT -p tcp --sport $TUNNEL --dport "$p" -j DROP
    done
    while ((SECONDS - t0 < 120)); do
        py $IR probe $PROBE >/dev/null 2>&1 && break
        for p in 20 45; do
            if ((SECONDS - t0 >= p)) && [[ $shown != *" $p"* ]]; then
                shown+=" $p"
                {
                    echo "--- $1 at $((SECONDS - t0)) s, dropped ports: $(echo $ports)"
                    echo "Iran:"; ip netns exec $IR ss -tnoi state all "( sport = :$TUNNEL )"
                    echo "foreign:"; ip netns exec $FO ss -tnoi state all "( dport = :$TUNNEL )"
                } >&2
            fi
        done
        sleep 1
    done
    echo $((SECONDS - t0))
    for p in $ports; do
        ip netns exec $IR iptables -D INPUT -p tcp --sport "$p" --dport $TUNNEL -j DROP
        ip netns exec $FO iptables -D INPUT -p tcp --sport $TUNNEL --dport "$p" -j DROP
    done
}
if [[ -n $NETEM ]]; then
    declare -A L D
    for name in reality-direct reality-reverse-base reality-reverse; do
        unblock_iran_out
        [[ $name == *reverse* ]] && block_iran_out
        start_link "$name"
        if ! wait_probe 20 >/dev/null; then
            bad "$name: the link never answered the probe"; stop_link; continue
        fi
        sleep 1
        L[$name]=$(loaded)
        [[ $name == *reverse* ]] && D[$name]=$(dead_flow "$name")
        stop_link
    done
    unblock_iran_out
    note "a request through the link while a download fills it (foreign -> Iran at 30 Mbit/s, ${NETEM}), median of 5: direct ${L[reality-direct]:-?} ms, reverse as v2.8.4 ${L[reality-reverse-base]:-?} ms, reverse ${L[reality-reverse]:-?} ms"
    note "the reverse link's connections dropped without a word: requests get through again after ${D[reality-reverse-base]:-?} s as v2.8.4, ${D[reality-reverse]:-?} s now (120 = not yet)"
    if awk -v r="${L[reality-reverse]:-6000}" -v d="${L[reality-direct]:-0}" 'BEGIN { exit !(r <= 1.5 * d + 20) }'; then
        ok "reverse under load: ${L[reality-reverse]} ms, next to direct's ${L[reality-direct]} ms"
    else
        bad "reverse under load: ${L[reality-reverse]:-?} ms against direct's ${L[reality-direct]:-?} ms (want at most 1.5x + 20)"
    fi
fi

# ---- IPv6: the servers connect over IPv6 only (IPv4 between them dropped)
# and the user comes in over IPv6
if [[ -n $V6 ]]; then
    mkdir -p "$TMP/cfg6"
    if (cd "$ROOT/panel" && env XRAY_LAB_DIR="$TMP/cfg6" XRAY_LAB_IRAN=$IR_IP6 XRAY_LAB_FOREIGN=$FO_IP6 XRAY_LAB_TARGET=127.0.0.1:9443             XRAY_LAB_PORT=$PORT XRAY_LAB_TUNNEL=$TUNNEL XRAY_LAB_PROBE=$PROBE XRAY_LAB_EVIL=$EVIL XRAY_LAB_PRESETS="reality xhttp"             "$BIN" -test.run '^TestXrayLabGen$' >"$TMP/gen6.log" 2>&1); then
        ip netns exec $IR iptables -A OUTPUT -d $FO_IP -j DROP; ip netns exec $FO iptables -A OUTPUT -d $IR_IP -j DROP
        for name in reality-direct reality-reverse xhttp-direct xhttp-reverse; do
            start_link "$name" "$TMP/cfg6/iran-$name.json" "$TMP/cfg6"
            if ! wait_probe 20 >/dev/null; then
                bad "IPv6 $name: the link never answered the probe"
                echo "--- Iran:"; tail -n 15 "$TMP/iran-$name.log"; echo "--- foreign:"; tail -n 15 "$TMP/fo-$name.log"
                stop_link; continue
            fi
            sent=ok
            py $USR tcp $IR_U6 $PORT $((8 << 20)) || { bad "IPv6 $name: 8 MiB each way, user over IPv6 (sha256)"; sent=; }
            py $USR tcp $IR_U $PORT $((1 << 20)) || { bad "IPv6 $name: user over IPv4 next to IPv6"; sent=; }
            n=$(py $USR udp $IR_U6 $PORT 30 1200) || { bad "IPv6 $name: UDP over IPv6, $n of 30 came back"; sent=; }
            [[ -n $sent ]] && ok "IPv6 $name: servers over IPv6 only, a user over IPv6: 8 MiB each way (sha256), UDP $n/30, and IPv4 users too"
            stop_link
        done
        ip netns exec $IR iptables -D OUTPUT -d $FO_IP -j DROP; ip netns exec $FO iptables -D OUTPUT -d $IR_IP -j DROP
    else
        bad "generating the IPv6 configs"; cat "$TMP/gen6.log"
    fi
else
    note "IPv6 round skipped: no IPv6 in the namespaces"
fi

# ---- the foreign end reaches only what it forwards
start_link reality-direct "$TMP/cfg/iran-evil.json"
if wait_probe 20 >/dev/null; then
    direct=$(py $FO reach 127.0.0.1 $EVIL)
    through=$(py $IR reach 127.0.0.1 $((PROBE + 1)))
    if [[ $direct == SECRET && $through != *SECRET* ]]; then
        ok "the foreign end refuses a port it does not forward (127.0.0.1:$EVIL: [$through] through the tunnel)"
    else
        bad "port $EVIL on the foreign server: [$direct] there, [$through] through the tunnel"
    fi
else
    bad "the link for the refusal check never came up"
fi
stop_link

# ---- the fake 3x-ui was left alone
if kill -0 $XUI 2>/dev/null && ip netns exec $FO ss -Htlnp "sport = :$TAKEN" | grep -q "pid=$XUI"; then
    ok "the fake 3x-ui still runs with the same pid and still holds port $TAKEN"
else
    bad "the fake 3x-ui was stopped or lost port $TAKEN"
fi

if [[ -n ${GITHUB_ACTIONS:-} ]]; then
    msg=$(tail -c 6000 "$TMP/result.txt" | sed -e 's/%/%25/g' | sed -e ':a;N;$!ba;s/\n/%0A/g' -e 's/\r/%0D/g')
    echo "::$([[ $fail -eq 0 ]] && echo notice || echo error) title=Xray lab::$msg"
fi
cat "$TMP/result.txt"
[[ $fail -eq 0 ]] && echo "PASS test_xray_lab" || exit 1
