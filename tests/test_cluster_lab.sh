#!/usr/bin/env bash
# tests/test_cluster_lab.sh — the cluster on a real kernel and real relays, in a
# network namespace of its own (never touches the runner's interfaces or
# firewall):
#   - the kernel rules alone: balance, stickiness, failover to another port,
#     pass-through ports, an atomic swap, clearing (TestLBLab);
#   - a pool forwarded to another Iran hub through a DROP forward policy
#     (TestLBLabForward);
#   - end to end (TestLBLabE2E): real frps x2 and a Backhaul server on the hub,
#     their clients in front of a small service on three "foreign servers", a
#     user connecting to the hub. Balance, a dead service behind a live tunnel
#     (service check), a dead tunnel, a standby member, sticky users.
# Needs root, iproute2, iptables, FRP_DIR (frps, frpc) and optionally
# BACKHAUL_BIN; skips cleanly otherwise. CLUSTER_LAB_TEST_BIN: a prebuilt
# `go test -c` binary of panel/ (else it is built here).
set -u
cd "$(dirname "$0")/.." || exit 1
[[ $EUID -eq 0 ]] || { echo "SKIP test_cluster_lab (needs root)"; exit 0; }
FRP_DIR=${FRP_DIR:-/tmp/frp-rel}
BACKHAUL_BIN=${BACKHAUL_BIN:-/tmp/backhaul-rel/backhaul}
command -v iptables >/dev/null && command -v ip >/dev/null || { echo "SKIP test_cluster_lab (iptables/iproute2 missing)"; exit 0; }
[[ -x $FRP_DIR/frps && -x $FRP_DIR/frpc ]] || { echo "SKIP test_cluster_lab (frps/frpc missing in $FRP_DIR)"; exit 0; }
[[ -x $BACKHAUL_BIN ]] || { echo "note: no Backhaul binary, the end-to-end lab runs with FRP only"; BACKHAUL_BIN=""; }
BIN=${CLUSTER_LAB_TEST_BIN:-}
if [[ -z $BIN ]]; then
    BIN=$(mktemp)
    (cd panel && go test -c -o "$BIN" .) || { echo "FAIL: cannot build the test binary"; exit 1; }
fi

HUB=hlb-hub
cleanup() {
    for n in $HUB hlb-de hlb-nl hlb-bh hlb-user far client; do ip netns del "$n" 2>/dev/null; done
}
cleanup
trap cleanup EXIT
ip netns add $HUB
in_hub() { ip netns exec $HUB "$@"; }
in_hub ip link set lo up
# the hub's "public" address (TestLBLab connects to it)
in_hub ip link add hlb-pub type dummy
in_hub ip addr add 10.97.0.1/24 dev hlb-pub
in_hub ip link set hlb-pub up

rc=0
# In GitHub Actions the outcome also goes to an annotation, readable without
# the job log.
annotate() { # level title file
    [[ -n ${GITHUB_ACTIONS:-} ]] || return 0
    local msg
    msg=$(tail -c 6000 "$3" | sed -e 's/%/%25/g' | sed -e ':a;N;$!ba;s/\n/%0A/g' -e 's/\r/%0D/g')
    echo "::$1 title=$2::$msg"
}
run() { # name env...  (PATTERN: the tests)
    local name=$1; shift
    local out=/tmp/hlb-$name.out
    echo "=== $name"
    in_hub env "$@" "$BIN" -test.run "$PATTERN" -test.count=1 -test.v -test.timeout 300s >"$out" 2>&1
    grep -E '^(=== RUN|--- |\s+cluster_lab_test.go|ok|FAIL|PASS)' "$out"
    if grep -q '^--- FAIL' "$out" || ! grep -q '^PASS' "$out"; then
        echo "FAIL: $name"; rc=1
        annotate error "cluster lab: $name" "$out"
    elif grep -q -- '--- SKIP' "$out"; then
        echo "FAIL: $name skipped inside the lab"; rc=1
        annotate error "cluster lab: $name skipped" "$out"
    else
        echo "ok:   $name"
        grep -E '^\s+cluster_lab_test.go' "$out" > "$out.notes" && annotate notice "cluster lab: $name" "$out.notes"
    fi
}
PATTERN='^(TestLBLab|TestLBLabForward)$' run kernel-rules HASHEM_LB_LAB=1
PATTERN='^TestLBLabE2E$' run end-to-end HASHEM_LB_E2E=1 FRP_DIR="$FRP_DIR" BACKHAUL_BIN="$BACKHAUL_BIN"
(( rc )) && exit 1
echo "PASS test_cluster_lab"
