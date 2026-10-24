#!/usr/bin/env bash
# tests/test_pro_gate.sh — Backhaul setups in hashem.sh need Hashem Pro, asked
# through the panel binary (`gre-panel license check backhaul`, the same key and
# rules as the panel); running tunnels are never gated. Hermetic: a fake binary.
set -u
cd "$(dirname "$0")/.." || exit 1
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
fail=0
check() { if [[ "$2" != "$3" ]]; then echo "FAIL: $1 (want [$2] got [$3])"; fail=1; else echo "ok:   $1"; fi; }

ext() { awk -v n="$1" '$0 ~ "^"n"\\(\\) \\{" {p=1} p {print} p && /^}/ {exit}' hashem.sh; }
RED='' NC=''
eval "$(ext pro_ok)"

# fake panel binary: "license check F" succeeds only for the features in $T/unlocked
cat > "$T/gre-panel" <<EOF
#!/bin/bash
[[ "\$1 \$2" == "license check" ]] && grep -qx "\$3" "$T/unlocked" 2>/dev/null
EOF
chmod +x "$T/gre-panel"
export PANEL_BIN="$T/gre-panel"

: > "$T/unlocked"
check "no license: Backhaul refused" 1 "$(pro_ok backhaul Backhaul >/dev/null; echo $?)"
check "no license: says why" yes "$(pro_ok backhaul Backhaul | grep -q 'Hashem Pro feature' && echo yes)"
echo backhaul > "$T/unlocked"
check "Pro license: Backhaul allowed" 0 "$(pro_ok backhaul Backhaul >/dev/null; echo $?)"
PANEL_BIN="$T/missing" check "no panel binary: refused" 1 "$(PANEL_BIN="$T/missing" pro_ok backhaul Backhaul >/dev/null; echo $?)"

# every entry that creates a Backhaul tunnel asks first ...
for f in setup_backhaul_iran_server_noninteractive setup_backhaul_foreign_server_noninteractive \
         setup_gre_backhaul_iran_server_noninteractive setup_gre_backhaul_foreign_server_noninteractive \
         cli_add_backhaul_peer setup_backhaul_iran_interactive; do
    first=$(ext "$f" | sed -n '2,3p' | grep -c 'pro_ok backhaul')
    check "$f asks for Pro before doing anything" 1 "$first"
done
# ... and nothing that keeps a running tunnel alive does
for f in cli_backhaul_migrate backhaul_status backhaul_show_bundle watchdog_tick dial_watch_tick dial_reselect; do
    check "$f never asks for a license" 0 "$(ext "$f" | grep -c 'pro_ok')"
done

# Performance, Watchdog, Diagnostics and making backups are Pro in the
# terminal too; what keeps applied settings running is not.
for fn in cli_perf cli_watchdog cli_doctor cli_backup; do eval "$(ext "$fn")"; done
perf_apply() { echo APPLIED; }
autopool_tick() { echo TICKED; }
pool_effective_values() { echo "20 60"; }
watchdog_on() { echo ON; }
watchdog_tick() { echo TICK; }
watchdog_check() { echo CHECK; }
watchdog_timer_ensure() { echo TIMER; }
doctor_health_check() { echo DOCTOR; }
doctor_stop_server() { echo STOPPED; }
backup_now() { echo BACKED; }
backup_restore() { echo RESTORED; }
: > "$T/unlocked"
check "no license: hashem perf enc refused" 1 "$(cli_perf enc on >/dev/null 2>&1; echo $?)"
check "no license: tcpMux fix and apply still run" APPLIED "$(cli_perf apply)"
check "no license: hashem watchdog on refused" "" "$(cli_watchdog on 2>/dev/null | grep -x ON)"
check "no license: hashem doctor refused" "" "$(cli_doctor 2>/dev/null | grep DOCTOR)"
check "no license: hashem backup now refused" "" "$(cli_backup now 2>/dev/null | grep BACKED)"
check "no license: refusal says where to buy" yes "$(cli_perf status | grep -q 'pdnczone.com' && echo yes)"
check "no license: Auto Pool tick still runs" TICKED "$(cli_perf autopool tick)"
check "no license: watchdog timer tick still runs" TICK "$(cli_watchdog tick)"
check "no license: watchdog check still runs" CHECK "$(cli_watchdog check)"
check "no license: watchdog timer still starts" TIMER "$(cli_watchdog timer)"
check "no license: doctor stop-server still runs" STOPPED "$(cli_doctor stop-server)"
check "no license: backup restore still runs" RESTORED "$(cli_backup restore /x)"
printf 'performance\nwatchdog\ndiagnostics\n' > "$T/unlocked"
check "Pro license: hashem perf apply runs" APPLIED "$(cli_perf apply)"
check "Pro license: hashem watchdog on runs" ON "$(cli_watchdog on)"
check "Pro license: hashem doctor runs" DOCTOR "$(cli_doctor)"
check "Pro license: hashem backup now runs" BACKED "$(cli_backup now)"
# the update re-applies perf.json without asking
check "update_all never asks for a license" 0 "$(ext update_all | grep -c 'pro_ok\|cli_perf')"

(( fail )) && exit 1; echo "PASS test_pro_gate"
