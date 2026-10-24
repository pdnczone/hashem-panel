#!/usr/bin/env bash
# tests/test_traffic_lab.sh — the panel's traffic numbers against real bytes.
#
# A hub (tr-hub) and a foreign server (tr-fo) in network namespaces, joined by
# a veth that is the hub's default route. Over it: a GRE main tunnel
# (gre-tunnel), a GRE peer (gre-p2, key 2), a Backhaul peer without GRE (TCP
# port 3090 on the veth, counted by the panel's iptables chains) and a Bagher
# link (the hub dials the foreign server's SSH port 2222) and an Xray link
# (the hub dials the foreign tunnel port 4433). The panel's own
# code (panel/traffic_lab_test.go: snapshot, /api/status, /api/dashboard,
# /api/traffic/usage) runs in the hub namespace while this script moves exact
# byte counts over each link, a paced 2 MB/s transfer, and traffic while the
# panel's traffic state is reset as by a restart.
#
# Needs root (netns), ip with GRE, iptables(-save/-restore), python3 and Go or
# a prebuilt test binary (TRAFFIC_LAB_TEST_BIN). Skips cleanly otherwise.
# Touches nothing outside the two namespaces and a mktemp dir.
set -u
cd "$(dirname "$0")/.." || exit 1
ROOT=$PWD

for c in ip python3 iptables-save iptables-restore; do
    command -v "$c" >/dev/null 2>&1 || { echo "SKIP test_traffic_lab ($c missing)"; exit 0; }
done
HUB=tr-hub; FO=tr-fo
HUB_IP=10.9.0.1; FO_IP=10.9.0.2
TMP=$(mktemp -d /tmp/traffic-lab.XXXXXX)
chmod 755 "$TMP"
pids=()
set +m
cleanup() {
    local p
    for p in "${pids[@]:-}"; do [[ -n $p ]] && { kill -9 "$p"; wait "$p"; } 2>/dev/null; done
    for ns in $HUB $FO; do ip netns pids "$ns" 2>/dev/null | xargs -r kill -9 2>/dev/null; ip netns del "$ns" 2>/dev/null; done
    rm -rf "$TMP"
}
trap cleanup EXIT
for ns in $HUB $FO; do ip netns del "$ns" 2>/dev/null; done
ip netns add $HUB 2>/dev/null || { echo "SKIP test_traffic_lab (no netns permission)"; exit 0; }
ip netns add $FO || { echo "SKIP test_traffic_lab (netns)"; exit 0; }
ip link add vt-hub netns $HUB type veth peer name vt-fo netns $FO || { echo "SKIP test_traffic_lab (veth unsupported)"; exit 0; }
ip -n $HUB addr add $HUB_IP/24 dev vt-hub; ip -n $FO addr add $FO_IP/24 dev vt-fo
for l in "$HUB vt-hub" "$HUB lo" "$FO vt-fo" "$FO lo"; do set -- $l; ip -n "$1" link set "$2" up; done
ip -n $HUB route add default via $FO_IP dev vt-hub   # the panel counts Backhaul/Bagher on the default-route interface
# gre_tun NAME KEY HUB_INNER FO_INNER
gre_tun() {
    local key=()
    [[ $2 != 0 ]] && key=(key "$2")
    ip -n $HUB link add "$1" type gre local $HUB_IP remote $FO_IP ttl 64 "${key[@]}" || return 1
    ip -n $FO link add "$1" type gre local $FO_IP remote $HUB_IP ttl 64 "${key[@]}" || return 1
    ip -n $HUB addr add "$3/30" dev "$1"; ip -n $FO addr add "$4/30" dev "$1"
    ip -n $HUB link set "$1" up; ip -n $FO link set "$1" up
}
gre_tun gre-tunnel 0 10.10.0.1 10.10.0.2 || { echo "SKIP test_traffic_lab (no GRE in this kernel)"; exit 0; }
gre_tun gre-p2 2 10.11.0.1 10.11.0.2

fail=0
ok()   { echo "ok:   $1"; echo "ok:   $1" >> "$TMP/result.txt"; }
bad()  { echo "FAIL: $1"; echo "FAIL: $1" >> "$TMP/result.txt"; fail=1; }

# ---- the transfer tool: a client sends a 16-byte header (bytes up, bytes
# down), then its bytes (paced when asked); the server reads them and sends
# the bytes down.
cat >"$TMP/xfer.py" <<'PY'
import os, socket, struct, sys, threading, time
CHUNK = b"\0" * 65536
def server(host, port):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port)); s.listen(16)
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
            while down > 0:
                n = c.send(CHUNK[:min(len(CHUNK), down)]); down -= n
        finally:
            c.close()
    while True:
        c, _ = s.accept(); threading.Thread(target=serve, args=(c,), daemon=True).start()
def client(host, port, up, down, rate=0):
    c = socket.create_connection((host, port), timeout=30)
    c.sendall(struct.pack("!QQ", up, down))
    sent, t0 = 0, time.monotonic()
    while sent < up:
        n = min(len(CHUNK) if not rate else 20000, up - sent)
        c.sendall(CHUNK[:n]); sent += n
        if rate:
            ahead = sent / rate - (time.monotonic() - t0)
            if ahead > 0: time.sleep(ahead)
    got = 0
    while True:
        b = c.recv(1 << 20)
        if not b: break
        got += len(b)
    sys.exit(0 if got == down else 1)
if sys.argv[1] == "server":
    server(sys.argv[2], int(sys.argv[3]))
else:
    client(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5]), float(sys.argv[6]) if len(sys.argv) > 6 else 0)
PY
ip netns exec $HUB python3 -I "$TMP/xfer.py" server 10.10.0.1 9000 >/dev/null 2>&1 & pids+=($!)
ip netns exec $HUB python3 -I "$TMP/xfer.py" server 10.11.0.1 9000 >/dev/null 2>&1 & pids+=($!)
ip netns exec $HUB python3 -I "$TMP/xfer.py" server 0.0.0.0 3090 >/dev/null 2>&1 & pids+=($!)
ip netns exec $FO python3 -I "$TMP/xfer.py" server $FO_IP 2222 >/dev/null 2>&1 & pids+=($!)
ip netns exec $FO python3 -I "$TMP/xfer.py" server $FO_IP 4433 >/dev/null 2>&1 & pids+=($!)
sleep 1

# Bytes at the hub (rx = received from the foreign server, tx = sent to it).
MAIN_RX=$((4 << 20)); MAIN_TX=$((3 << 20))
P2_RX=$((3 << 20));   P2_TX=$((2 << 20))
P3_RX=$((2 << 20));   P3_TX=$((1 << 20))
BG_RX=$((2 << 20));   BG_TX=$((1 << 20))
XR_RX=$((3 << 20));   XR_TX=$((1 << 20))
cat >"$TMP/traffic.sh" <<EOF
set -e
x() { ip netns exec "\$1" python3 -I "$TMP/xfer.py" client "\${@:2}"; }
case "\$1" in
  bulk)   # foreign -> hub sends rx up, hub sends tx down; Bagher: the hub dials out
          x $FO 10.10.0.1 9000 $MAIN_RX $MAIN_TX
          x $FO 10.11.0.1 9000 $P2_RX $P2_TX
          x $FO $HUB_IP 3090 $P3_RX $P3_TX
          x $HUB $FO_IP 2222 $BG_TX $BG_RX
          x $HUB $FO_IP 4433 $XR_TX $XR_RX ;;
  paced)  x $FO 10.10.0.1 9000 34000000 0 2000000 ;;   # 2 MB/s for 17 s
  main3)  x $FO 10.10.0.1 9000 $((3 << 20)) 0 ;;
esac
EOF

BIN=${TRAFFIC_LAB_TEST_BIN:-}
if [[ -z $BIN ]]; then
    command -v go >/dev/null 2>&1 || { echo "SKIP test_traffic_lab (no go and no TRAFFIC_LAB_TEST_BIN)"; exit 0; }
    (cd "$ROOT/panel" && go test -c -o "$TMP/trafficlab.test" .) || { bad "building the test binary"; exit 1; }
    BIN=$TMP/trafficlab.test
fi
(cd "$ROOT/panel" && ip netns exec $HUB env TRAFFIC_LAB_SCRIPT="$TMP/traffic.sh" TRAFFIC_LAB_FOREIGN=$FO_IP \
    TRAFFIC_LAB_EXPECT="main=$MAIN_RX:$MAIN_TX,p2=$P2_RX:$P2_TX,p3=$P3_RX:$P3_TX,bagher=$BG_RX:$BG_TX,xray=$XR_RX:$XR_TX" \
    "$BIN" -test.run '^TestTrafficLab$' -test.v >"$TMP/lab.log" 2>&1)
rc=$?
sed -n '/traffic lab:/,/^---/p' "$TMP/lab.log" | grep -v '^---' | sed 's/^ *//' >> "$TMP/result.txt"
grep -E '^\s+traffic_lab_test.go:[0-9]+: ' "$TMP/lab.log" | grep -v 'traffic lab:' >> "$TMP/result.txt"
if (( rc == 0 )); then ok "the panel's totals, per-link counters, speeds and ledger match the bytes sent"
else bad "traffic numbers differ from the bytes sent (exit $rc)"; grep -v CMD-ERROR "$TMP/lab.log" | tail -n 40; fi

if [[ -n ${GITHUB_ACTIONS:-} ]]; then
    msg=$(tail -c 6000 "$TMP/result.txt" | sed -e 's/%/%25/g' | sed -e ':a;N;$!ba;s/\n/%0A/g' -e 's/\r/%0D/g')
    echo "::$([[ $fail -eq 0 ]] && echo notice || echo error) title=Traffic lab::$msg"
fi
cat "$TMP/result.txt"
[[ $fail -eq 0 ]] && echo "PASS test_traffic_lab" || exit 1
