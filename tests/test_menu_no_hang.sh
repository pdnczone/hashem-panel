#!/usr/bin/env bash
# The menu header must be drawn even when systemctl or the panel binary hang.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin"
printf '#!/bin/sh\nsleep 600\n' > "$T/bin/systemctl"; chmod +x "$T/bin/systemctl"
printf '#!/bin/sh\nsleep 600\n' > "$T/gre-panel"; chmod +x "$T/gre-panel"
export PATH="$T/bin:$PATH"
for f in ui_status_refresh tunnel_present panel_address; do
    awk "/^$f\\(\\) \\{/,/^}/" "$ROOT/hashem.sh" >> "$T/fn.sh"
done
# shellcheck disable=SC1091
source "$T/fn.sh"
CONFIG_DIR="$T/frp"; mkdir -p "$CONFIG_DIR"; : > "$CONFIG_DIR/frps.toml"
PANEL_CONFIG_DIR="$T/gp"; PANEL_BIN="$T/gre-panel"; TUNNEL_NAME=gre-tunnel UI_STATUS_AT=0
GREEN= RED= NC= DIM=
start=$(date +%s)
ui_status_refresh
took=$(( $(date +%s) - start ))
fail=0
(( took < 45 )) || { echo "FAIL header took ${took}s"; fail=1; }
[[ "$UI_LIC" == "Free" ]] || { echo "FAIL a hung license check must read as Free"; fail=1; }
(( fail )) && exit 1; echo "PASS test_menu_no_hang (${took}s)"
