#!/usr/bin/env bash
# The Watchdog must not call a GRE link dead only because ICMP is dropped inside
# it. TCP passes, a client holds a session or the interface receives packets:
# that is a working link. Fake commands and a throwaway tree: no live state.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin" "$T/frp" "$T/sys/gre-tunnel/statistics"
export CONFIG_DIR="$T/frp" HASHEM_SYS_NET="$T/sys" TUNNEL_NAME=gre-tunnel WATCHDOG_FILE="$T/none.json"
export GRE_HEALTH_WAIT=0

{
  echo 'RED= GREEN= CYAN= YELLOW= NC='
  for fn in watchdog_check gre_if_healthy autopool_live_toml_int backhaul_session_ok; do
    awk -v f="$fn" '$0 ~ "^"f"\\(\\) \\{" {p=1} p {print} p && /^}/ {p=0}' "$ROOT/hashem.sh"
  done
} > "$T/fn.sh"
# shellcheck disable=SC1091
source "$T/fn.sh"
init_watchdog_json() { :; }
watchdog_get_peer_gre() { echo 10.10.10.2; }
gre_if_peer() { :; }   # no ping inside gre_if_healthy: only the rx counters count

mk() { printf '#!/bin/sh\n%s\n' "$2" > "$T/bin/$1"; chmod +x "$T/bin/$1"; }
mk ping 'exit 1'
mk nc 'exit 1'
mk ip 'exit 0'
mk journalctl 'exit 0'
# frps is the only unit; ss answers the control port only when SS_EST=1
mk systemctl 'case "$*" in "is-active --quiet frps") exit 0;; "list-unit-files") echo "frps.service enabled";; *) exit 1;; esac'
mk ss 'case "$*" in *sport*) [ "${SS_EST:-0}" = 1 ] && echo "ESTAB 0 0 1.1.1.1:7000 2.2.2.2:5555";; esac; exit 0'
# the sleep between the two rx reads is where packets "arrive"
mk sleep '[ "${MOVE:-0}" = 1 ] && echo 200 > "$HASHEM_SYS_NET/gre-tunnel/statistics/rx_packets"; exit 0'
export PATH="$T/bin:$PATH"
printf 'bindPort = 7000\n' > "$T/frp/frps.toml"

fail=0
chk() { [[ "$2" == *"$3"* ]] || { echo "FAIL $1: got '$2' want '*$3*'"; fail=1; }; }
run() { echo 100 > "$T/sys/gre-tunnel/statistics/rx_packets"; watchdog_check; }

out=$(SS_EST=1 MOVE=0 run); chk "session on the control port, ping dead" "$out" "status=up"
chk "says why" "$out" "ping filtered"
out=$(SS_EST=0 MOVE=1 run); chk "GRE receives packets, ping dead" "$out" "status=up"
out=$(SS_EST=0 MOVE=0 run); chk "nothing at all is still down" "$out" "status=down"
chk "down names the ping" "$out" "GRE ping 10.10.10.2 failed"

[[ $fail -eq 0 ]] && echo "PASS test_watchdog_icmp" || exit 1
