#!/usr/bin/env bash
# Auto Pool: scale-up on pool-full errors, restart gating (active conns / severe / cooldown),
# scale-down hysteresis, bounds and maxPoolCount >= 1.5 * poolCount. Isolated dirs, no systemd.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin" "$T/frp" "$T/panel"
export PANEL_CONFIG_DIR="$T/panel" GRE_PANEL_DIR="$T/panel" CONFIG_DIR="$T/frp"
export PERF_FILE="$T/panel/perf.json" AUTO_POOL_STATE="$T/panel/auto_pool.json"
unset PERF_AUTO_POOL
export AUTOPOOL_RAM_MB=2048   # cap = min(500, 2048*8/5) = 500 -> pool ceiling min(200, 333) = 200

# constants + the functions under test, lifted from hashem.sh
grep -E '^AUTOPOOL_[A-Z_]+=' "$ROOT/hashem.sh" > "$T/fn.sh"
for fn in perf_get_auto_pool perf_get_int pool_clamp pool_ram_cap autopool_state_get autopool_state_set \
          pool_effective_values autopool_set_toml_key autopool_live_toml_int autopool_count_errors \
          autopool_conn_counts autopool_free_mb autopool_cpu_hot autopool_tick; do
    awk -v f="$fn" '$0 ~ "^"f"\\(\\) \\{" {p=1} p {print} p && /^}/ {p=0}' "$ROOT/hashem.sh"
done >> "$T/fn.sh"
# shellcheck disable=SC1091
source "$T/fn.sh"

fail=0
chk() { [[ "$2" == "$3" ]] || { echo "FAIL $1: got '$2' want '$3'"; fail=1; }; }
st() { autopool_state_get "$1" "${2:-}"; }

# fakes: systemctl records restarts, journalctl prints $T/errs.txt, ss/proc readings come from files
printf '#!/bin/sh\necho "$@" >> "%s/restarts"\n' "$T" > "$T/bin/systemctl"
printf '#!/bin/sh\ncat "%s/journal"\n' "$T" > "$T/bin/journalctl"
chmod +x "$T/bin/systemctl" "$T/bin/journalctl"
export PATH="$T/bin:$PATH"
autopool_conn_counts() { echo "$(cat "$T/tunnel") 500"; }   # established conns to the hub / total
autopool_free_mb() { cat "$T/free"; }
autopool_cpu_hot() { cat "$T/hot"; }
echo 4096 > "$T/free"; echo 0 > "$T/hot"

set_errs() { : > "$T/journal"; local i; for ((i=0;i<$1;i++)); do echo "frpc[1]: StartWorkConn contains error: work connection pool is full, discarding" >> "$T/journal"; done; }
# tunnel conns = control(1) + live pool + active user conns
set_active() { echo $(( $1 + 1 + $(autopool_live_toml_int "$CONFIG_DIR/frpc.toml" transport.poolCount) )) > "$T/tunnel"; }
restarts() { [[ -f "$T/restarts" ]] && wc -l < "$T/restarts" || echo 0; }
# pretend the previous restart happened $1 seconds ago
age_restart() { autopool_state_set last_restart=$(( $(date +%s) - $1 )) last_tick=$(( $(date +%s) - 60 )); }
reset() { rm -f "$AUTO_POOL_STATE" "$T/restarts"; printf 'serverAddr = "10.0.0.1"\nserverPort = 7000\ntransport.poolCount = 20\n\n[[proxies]]\nname = "a"\n' > "$CONFIG_DIR/frpc.toml"; set_errs 0; set_active 0; }

# ---- config defaults ----
chk "auto_pool missing => on" "$(perf_get_auto_pool)" "1"
echo '{"auto_pool": false}' > "$PERF_FILE"; chk "auto_pool false => off" "$(perf_get_auto_pool)" "0"
echo '{"auto_pool": true}' > "$PERF_FILE";  chk "auto_pool true => on" "$(perf_get_auto_pool)" "1"
rm -f "$PERF_FILE"

# ---- effective values + bounds ----
reset
read -r p m <<< "$(pool_effective_values)"; chk "default pool" "$p" "20"; (( m >= 30 )) || { echo "FAIL default maxPool $m"; fail=1; }
autopool_state_set pool=999; read -r p m <<< "$(pool_effective_values)"; chk "pool ceiling" "$p" "200"; chk "max >= 1.5x at ceiling" "$m" "500"
autopool_state_set pool=3;   read -r p m <<< "$(pool_effective_values)"; chk "pool floor" "$p" "20"
AUTOPOOL_RAM_MB=128 read -r p m <<< "$(AUTOPOOL_RAM_MB=128 pool_effective_values)"; (( m >= 60 )) || { echo "FAIL low-RAM maxPool $m"; fail=1; }
read -r p m <<< "$(AUTOPOOL_RAM_MB=128 pool_effective_values)"; (( m * 2 >= p * 3 )) || { echo "FAIL low-RAM max<1.5*pool: $p $m"; fail=1; }
echo '{"auto_pool": false, "frp_pool_count": 90, "frp_max_pool": 100}' > "$PERF_FILE"
read -r p m <<< "$(pool_effective_values)"; chk "manual pool" "$p" "90"; chk "manual max lifted to 1.5x" "$m" "135"
echo '{"auto_pool": false, "frp_pool_count": 40, "frp_max_pool": 300}' > "$PERF_FILE"
read -r p m <<< "$(pool_effective_values)"; chk "manual pool as typed" "$p" "40"; chk "manual max as typed" "$m" "300"
rm -f "$PERF_FILE"

# ---- manual mode: tick does nothing ----
echo '{"auto_pool": false}' > "$PERF_FILE"; reset; set_errs 50
autopool_tick; chk "manual: no state written" "$([[ -f $AUTO_POOL_STATE ]] && echo y || echo n)" "n"; chk "manual: no restart" "$(restarts)" "0"
rm -f "$PERF_FILE"

# ---- scale up on errors, few users => immediate frpc restart, only frpc ----
reset; set_errs 3; set_active 5
autopool_tick
chk "up: pool x1.5" "$(st pool)" "30"
chk "up: toml rewritten" "$(autopool_live_toml_int "$CONFIG_DIR/frpc.toml" transport.poolCount)" "30"
chk "up: one restart" "$(restarts)" "1"
chk "up: restarts frpc" "$(cat "$T/restarts")" "restart frpc"
chk "up: decision" "$(st last_decision)" "scale_up"
chk "up: errors recorded" "$(st errors_last_tick)" "3"
chk "up: proxies untouched" "$(grep -c '^\[\[proxies\]\]' "$CONFIG_DIR/frpc.toml")" "1"
read -r p m <<< "$(pool_effective_values)"; (( m * 2 >= p * 3 )) || { echo "FAIL max<1.5*pool after up: $p $m"; fail=1; }

# ---- cooldown: more errors right away => pool grows in state, restart deferred ----
set_errs 3; set_active 5
autopool_tick
chk "cooldown: pool still grows" "$(st pool)" "45"
chk "cooldown: toml unchanged" "$(autopool_live_toml_int "$CONFIG_DIR/frpc.toml" transport.poolCount)" "30"
chk "cooldown: no second restart" "$(restarts)" "1"
chk "cooldown: deferred" "$(st last_decision)" "deferred"
# severe errors do NOT bypass the cooldown
set_errs 100; autopool_tick; chk "cooldown beats severe" "$(restarts)" "1"
# once the cooldown passed the pending pool is applied
age_restart 400; set_errs 0; set_active 5
autopool_tick
chk "after cooldown: applied" "$(autopool_live_toml_int "$CONFIG_DIR/frpc.toml" transport.poolCount)" "$(st pool)"
chk "after cooldown: restart" "$(restarts)" "2"

# ---- many users: scale up recorded but no restart unless severe ----
reset; set_errs 3; set_active 200
autopool_tick
chk "busy: pool raised in state" "$(st pool)" "30"
chk "busy: toml untouched" "$(autopool_live_toml_int "$CONFIG_DIR/frpc.toml" transport.poolCount)" "20"
chk "busy: no restart" "$(restarts)" "0"
chk "busy: deferred" "$(st last_decision)" "deferred"
set_errs 25; set_active 200; age_restart 400
autopool_tick
chk "severe: restart despite many users" "$(restarts)" "1"
chk "severe: applied" "$(autopool_live_toml_int "$CONFIG_DIR/frpc.toml" transport.poolCount)" "$(st pool)"

# ---- ceiling ----
reset; autopool_state_set pool=190 applied_pool=190; autopool_set_toml_key "$CONFIG_DIR/frpc.toml" transport.poolCount 190
set_errs 5; set_active 0; autopool_tick
chk "ceiling: capped at 200" "$(st pool)" "200"
age_restart 400; set_errs 5; autopool_tick
chk "ceiling: stays 200" "$(st pool)" "200"

# ---- scale down needs AUTOPOOL_DOWN_QUIET quiet ticks; errors reset the counter ----
reset; autopool_state_set pool=100 applied_pool=100; autopool_set_toml_key "$CONFIG_DIR/frpc.toml" transport.poolCount 100
set_errs 0; set_active 10
for i in $(seq 1 $((AUTOPOOL_DOWN_QUIET - 1))); do autopool_tick; done
chk "down: holds before N quiet ticks" "$(st pool)" "100"
chk "down: quiet counter" "$(st quiet_ticks)" "$((AUTOPOOL_DOWN_QUIET - 1))"
set_errs 1; autopool_tick; chk "down: error resets quiet" "$(st quiet_ticks)" "0"
reset; autopool_state_set pool=100 applied_pool=100 quiet_ticks=$((AUTOPOOL_DOWN_QUIET - 1)) last_restart=0; autopool_set_toml_key "$CONFIG_DIR/frpc.toml" transport.poolCount 100
set_errs 0; set_active 10; autopool_tick
chk "down: x0.8 after N quiet ticks" "$(st pool)" "80"
chk "down: decision" "$(st last_decision)" "scale_down"
chk "down: applied (few users, no cooldown)" "$(autopool_live_toml_int "$CONFIG_DIR/frpc.toml" transport.poolCount)" "80"
# floor
reset; autopool_state_set pool=22 applied_pool=22 quiet_ticks=$((AUTOPOOL_DOWN_QUIET - 1)); autopool_set_toml_key "$CONFIG_DIR/frpc.toml" transport.poolCount 22
set_active 0; autopool_tick; chk "down: floor 20" "$(st pool)" "20"
autopool_state_set quiet_ticks=$((AUTOPOOL_DOWN_QUIET - 1)); autopool_tick; chk "down: never below 20" "$(st pool)" "20"

# ---- low free RAM blocks scale-up ----
reset; echo 50 > "$T/free"; set_errs 10; set_active 0; autopool_tick
chk "ram low: pool unchanged" "$(st pool)" "20"; chk "ram low: no restart" "$(restarts)" "0"
echo 4096 > "$T/free"

# ---- hub (frps only): never restarts, raises maxPoolCount in toml and flags it ----
reset; rm -f "$CONFIG_DIR/frpc.toml"; printf 'bindPort = 7000\ntransport.maxPoolCount = 60\n' > "$CONFIG_DIR/frps.toml"
autopool_tick
chk "hub: no restart" "$(restarts)" "0"
chk "hub: maxPoolCount raised" "$(autopool_live_toml_int "$CONFIG_DIR/frps.toml" transport.maxPoolCount)" "500"
chk "hub: restart flagged" "$(st frps_restart_needed)" "true"

[[ $fail -eq 0 ]] && echo "PASS test_autopool" || exit 1
