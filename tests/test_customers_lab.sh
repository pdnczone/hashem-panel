#!/usr/bin/env bash
# tests/test_customers_lab.sh: tunnels sold to customers, with the real
# kernel and the real engines: FRP v0.71.0, and when given Backhaul v0.7.2
# and Xray-core v26.3.27 (TestCustomersLabEngines).
#
#   cs-us (users) ── cs-hub (the seller's Iran server, the panel) ── cs-fo (the customer's foreign server)
#
# The hub's default route faces the users (that is where the speed cap
# polices). On the foreign server a sink answers on 127.0.0.1:9000-9004 (TCP:
# a 16-byte header with the bytes up and down; UDP: echo). The hub serves a
# TLS site on 127.0.0.1:9443 for Reality to borrow (no internet here). The panel code
# (panel/customers_lab_test.go) runs in the hub namespace: it sells the
# tunnel, the customer's frpc runs the config tools/hashem-customer.sh makes
# from the kit, and users move exact byte counts through it.
#
# Needs root (netns), ip, iptables(-save/-restore), tc, python3, Go or a
# prebuilt test binary (CUST_LAB_TEST_BIN) and FRP (CUST_LAB_FRP_DIR with
# frps and frpc v0.71.0); CUST_LAB_BACKHAUL and CUST_LAB_XRAY (the binaries)
# add the engines lab, which also needs openssl. Skips cleanly otherwise. Touches nothing outside
# its three namespaces and a mktemp dir.
set -u
cd "$(dirname "$0")/.." || exit 1
ROOT=$PWD

for c in ip tc python3 iptables-save iptables-restore; do
    command -v "$c" >/dev/null 2>&1 || { echo "SKIP test_customers_lab ($c missing)"; exit 0; }
done
FRP=${CUST_LAB_FRP_DIR:-}
[[ -x "$FRP/frps" && -x "$FRP/frpc" ]] || { echo "SKIP test_customers_lab (set CUST_LAB_FRP_DIR to FRP v0.71.0)"; exit 0; }
HUB=cs-hub; FO=cs-fo; US=cs-us
TMP=$(mktemp -d /tmp/customers-lab.XXXXXX)
chmod 755 "$TMP"
cleanup() {
    for ns in $HUB $FO $US; do ip netns pids "$ns" 2>/dev/null | xargs -r kill -9 2>/dev/null; ip netns del "$ns" 2>/dev/null; done
    rm -rf "$TMP"
}
trap cleanup EXIT
for ns in $HUB $FO $US; do ip netns del "$ns" 2>/dev/null; done
ip netns add $HUB 2>/dev/null || { echo "SKIP test_customers_lab (no netns permission)"; exit 0; }
ip netns add $FO && ip netns add $US || { echo "SKIP test_customers_lab (netns)"; exit 0; }
ip link add cs-hub-fo netns $HUB type veth peer name cs-fo0 netns $FO || { echo "SKIP test_customers_lab (veth unsupported)"; exit 0; }
ip link add cs-hub-us netns $HUB type veth peer name cs-us0 netns $US
ip -n $HUB addr add 10.23.0.1/24 dev cs-hub-fo; ip -n $FO addr add 10.23.0.2/24 dev cs-fo0
ip -n $HUB addr add 10.24.0.1/24 dev cs-hub-us; ip -n $US addr add 10.24.0.2/24 dev cs-us0
for l in "$HUB cs-hub-fo" "$HUB cs-hub-us" "$HUB lo" "$FO cs-fo0" "$FO lo" "$US cs-us0" "$US lo"; do set -- $l; ip -n "$1" link set "$2" up; done
ip -n $HUB route add default via 10.24.0.2 dev cs-hub-us   # the users' side: the cap polices here

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
def udp(port):
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.bind(("127.0.0.1", port))
    while True:
        d, a = u.recvfrom(65535)
        u.sendto(d, a)
def tcp(port):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port)); s.listen(16)
    while True:
        c, _ = s.accept()
        threading.Thread(target=serve, args=(c,), daemon=True).start()
for p in range(9000, 9005):
    threading.Thread(target=udp, args=(p,), daemon=True).start()
    threading.Thread(target=tcp, args=(p,), daemon=True).start()
threading.Event().wait()
PY
cat >"$TMP/site.py" <<'PY'
import socket, ssl, sys, threading
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.minimum_version = ssl.TLSVersion.TLSv1_3
ctx.load_cert_chain(sys.argv[1], sys.argv[2])
ctx.set_alpn_protocols(["h2", "http/1.1"])
def h(c):
    try:
        with ctx.wrap_socket(c, server_side=True) as t:
            t.settimeout(5); t.recv(4096)
            t.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
    except Exception:
        c.close()
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 9443)); s.listen(64)
while True:
    c, _ = s.accept()
    threading.Thread(target=h, args=(c,), daemon=True).start()
PY
cat >"$TMP/client.py" <<'PY'
# client.py HOST PORT tcp UP DOWN | client.py HOST PORT udp: prints the rates as JSON
import json, socket, struct, sys, time
host, port, mode = sys.argv[1], int(sys.argv[2]), sys.argv[3]
if mode == "udp":
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.settimeout(3)
    msg = b"u" * 1200
    for _ in range(5):
        u.sendto(msg, (host, port))
        try:
            d, _ = u.recvfrom(65535)
            if d == msg:
                print(json.dumps({"ok": 1})); sys.exit(0)
        except socket.timeout:
            pass
    sys.exit(1)
up, down = int(sys.argv[4]), int(sys.argv[5])
c = socket.create_connection((host, port), timeout=3)
c.settimeout(60)
c.sendall(struct.pack("!QQ", up, down))
t0 = time.time()
buf = b"\0" * 65536
left = up
while left > 0:
    n = min(left, len(buf)); c.sendall(buf[:n]); left -= n
want = down if down > 0 else 1
first = c.recv(1)
if not first: sys.exit(2)
t1 = time.time(); got = 1
while got < want:
    b = c.recv(1 << 20)
    if not b: sys.exit(3)
    got += len(b)
t2 = time.time()
r = {"up_mbit": up * 8 / 1e6 / max(t1 - t0, 1e-6) if up else 0, "down_mbit": down * 8 / 1e6 / max(t2 - t1, 1e-6) if down > 1 else 0}
print(json.dumps(r))
PY
ip netns exec $FO python3 "$TMP/sink.py" >/dev/null 2>&1 &
for _ in $(seq 50); do ip netns exec $FO bash -c "exec 3<>/dev/tcp/127.0.0.1/9004" 2>/dev/null && break; sleep 0.1; done
BH=${CUST_LAB_BACKHAUL:-} XR=${CUST_LAB_XRAY:-}
RUN='^TestCustomersLab$'
if [[ -x "$BH" && -x "$XR" ]] && command -v openssl >/dev/null 2>&1; then
    RUN='^TestCustomersLab(Engines)?$'
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj "/CN=lab.example" \
        -addext "subjectAltName=DNS:lab.example" -keyout "$TMP/site.key" -out "$TMP/site.crt" >/dev/null 2>&1
    ip netns exec $HUB python3 "$TMP/site.py" "$TMP/site.crt" "$TMP/site.key" >/dev/null 2>&1 &
else
    echo "NOTE: CUST_LAB_BACKHAUL and CUST_LAB_XRAY not set: the Backhaul and Xray part is skipped"
fi

BIN=${CUST_LAB_TEST_BIN:-}
if [[ -z $BIN ]]; then
    command -v go >/dev/null 2>&1 || { echo "SKIP test_customers_lab (no go and no CUST_LAB_TEST_BIN)"; exit 0; }
    (cd "$ROOT/panel" && go test -c -o "$TMP/customerslab.test" .) || { echo "FAIL: build"; exit 1; }
    BIN=$TMP/customerslab.test
fi
(cd "$ROOT/panel" && ip netns exec $HUB env CUST_LAB_FRP_DIR="$FRP" CUST_LAB_NO_TC="${CUST_LAB_NO_TC:-}" CUST_LAB_FO_NS=$FO CUST_LAB_US_NS=$US \
    CUST_LAB_BACKHAUL="$BH" CUST_LAB_XRAY="$XR" CUST_LAB_XRAY_TARGET=127.0.0.1:9443 \
    CUST_LAB_HUB_FO_IP=10.23.0.1 CUST_LAB_HUB_US_IP=10.24.0.1 \
    CUST_LAB_INSTALLER="$ROOT/tools/hashem-customer.sh" CUST_LAB_CLIENT="$TMP/client.py" \
    "$BIN" -test.run "$RUN" -test.v -test.timeout 20m >"$TMP/lab.log" 2>&1)
rc=$?
grep -E "customers_lab_test.go|^(--- |ok|FAIL|PASS)" "$TMP/lab.log"
[[ -n ${GITHUB_ACTIONS:-} && $rc -eq 0 ]] && grep -E "customers_lab_test.go:[0-9]+:" "$TMP/lab.log" | sed 's/^ *//; s/^/::notice title=customers lab::/'
if [[ $rc -ne 0 ]]; then
    tail -60 "$TMP/lab.log"
    # the tail of the log in one annotation (the job log may not be readable)
    [[ -n ${GITHUB_ACTIONS:-} ]] && echo "::error title=customers lab::$(grep -E '_test\.go:[0-9]+:|^ *--- |^(FAIL|ok|panic)|goroutine ' "$TMP/lab.log" | grep -v CMD-ERROR | tail -30 | cut -c1-200 | sed 's/%/%25/g' | awk '{printf "%s%%0A", $0}')"
    [[ -n ${GITHUB_ACTIONS:-} ]] && echo "::error title=customers lab (log tail)::$(grep -vE 'CMD-ERROR|^=== ' "$TMP/lab.log" | tail -25 | cut -c1-160 | sed 's/%/%25/g' | awk '{printf "%s%%0A", $0}')"
    echo "FAIL: test_customers_lab"
    exit 1
fi
echo "PASS: test_customers_lab"
