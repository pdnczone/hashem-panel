#!/usr/bin/env bash
# tests/test_nodes_lab.sh — the central/node channel over a real network.
#
# A central (nd-c) and a node (nd-n) in network namespaces, joined by a veth.
# panel/node_lab_test.go runs the central in nd-c and the node (the same test
# binary) in nd-n: join with a code, info over the pinned channel, a firewall
# that drops the path silently, the central restarting, and removal.
#
# Needs root (netns), ip, iptables and Go or a prebuilt test binary
# (NODES_LAB_TEST_BIN). Skips cleanly otherwise. Touches nothing outside the
# two namespaces.
set -u
cd "$(dirname "$0")/.." || exit 1
for c in ip iptables; do
    command -v "$c" >/dev/null 2>&1 || { echo "SKIP test_nodes_lab ($c missing)"; exit 0; }
done
C=nd-c; N=nd-n
cleanup() {
    for ns in $C $N; do ip netns pids "$ns" 2>/dev/null | xargs -r kill -9 2>/dev/null; ip netns del "$ns" 2>/dev/null; done
}
trap cleanup EXIT
cleanup
ip netns add $C 2>/dev/null || { echo "SKIP test_nodes_lab (no netns permission)"; exit 0; }
ip netns add $N || exit 1
ip link add nd-cv netns $C type veth peer name nd-nv netns $N || exit 1
ip -n $C addr add 10.78.0.1/24 dev nd-cv && ip -n $C link set nd-cv up && ip -n $C link set lo up
ip -n $N addr add 10.78.0.2/24 dev nd-nv && ip -n $N link set nd-nv up && ip -n $N link set lo up
if command -v ping >/dev/null 2>&1; then ip netns exec $N ping -c1 -W2 10.78.0.1 >/dev/null || { echo "FAIL: no path between the namespaces"; exit 1; }; fi

BIN=${NODES_LAB_TEST_BIN:-}
if [[ -z "$BIN" ]]; then
    command -v go >/dev/null 2>&1 || { echo "SKIP test_nodes_lab (no Go and no NODES_LAB_TEST_BIN)"; exit 0; }
    BIN=$(mktemp /tmp/nodeslab.XXXXXX)
    (cd panel && go test -c -o "$BIN" .) || exit 1
fi
ip netns exec $C env NODES_LAB_NODE_NS=$N NODES_LAB_ADDR=10.78.0.1 "$BIN" -test.run '^TestNodesLab$' -test.v -test.count=1
