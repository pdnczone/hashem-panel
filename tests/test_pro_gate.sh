#!/usr/bin/env bash
# Community edition: all former premium operations are available by default.
set -euo pipefail
cd "$(dirname "$0")/.."
func() { sed -n "/^$1() {/,/^}/p" hashem.sh; }
eval "$(func pro_ok)"
eval "$(func ui_pro)"
pro_ok backhaul Backhaul
pro_ok watchdog Watchdog
pro_ok xray Xray
pro_ok cluster Cluster
ui_pro backhaul Backhaul
ui_pro benchmark Benchmark
grep -q 'roboapi2/hashem-panel' install.sh
grep -q 'roboapi2/hashem-panel' hashem.sh
echo "Community edition shell access: OK"
