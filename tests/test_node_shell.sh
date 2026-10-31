#!/usr/bin/env bash
# tests/test_node_shell.sh — hashem node-join / hashem node: the panel is
# installed when missing, updated when too old for nodes, and the code and
# name reach `gre-panel node join`. An old panel binary is never run with
# `node` (it does not know the word and would start a second panel). Hermetic.
set -u
cd "$(dirname "$0")/.." || exit 1
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
fail=0
check() { if [[ "$2" != "$3" ]]; then echo "FAIL: $1 (want [$2] got [$3])"; fail=1; else echo "ok:   $1"; fi; }
ext() { awk -v n="$1" '$0 ~ "^"n"\\(\\) \\{" {p=1} p {print} p && /^}/ {exit}' hashem.sh; }
RED='' NC='' GREEN='' YELLOW='' CYAN='' BOLD=''
for fn in panel_supports cli_node cli_node_join; do eval "$(ext "$fn")"; done
PANEL_BIN="$T/gre-panel"
LOG="$T/log"
fake_panel() { # $1 = new|old
    cat > "$PANEL_BIN" <<FAKE
#!/usr/bin/env bash
if [[ "\$1" == "--help" ]]; then
  [[ "$1" == new ]] && echo "Usage: gre-panel [license [status] | node [status|join CODE|leave]]" || echo "Usage: gre-panel [license [status]]"
  exit 0
fi
echo "panel \$*" >> "$LOG"
FAKE
    chmod +x "$PANEL_BIN"
}
install_panel_smart() { echo "install_panel_smart" >> "$LOG"; fake_panel new; }
install_panel() { echo "install_panel" >> "$LOG"; fake_panel new; }

: > "$LOG"
check "a code that is not hn1. is refused" 1 "$(cli_node_join hsh1_x >/dev/null; echo $?)"
check "nothing was run for it" "" "$(cat "$LOG")"

: > "$LOG"; rm -f "$PANEL_BIN"
cli_node_join hn1.abc --name "DE 1" >/dev/null
check "no panel: install, then join" "install_panel_smart|panel node join hn1.abc --name DE 1" "$(paste -sd'|' "$LOG")"

: > "$LOG"; fake_panel old
cli_node_join hn1.abc >/dev/null
check "an old panel: update, then join" "install_panel|panel node join hn1.abc" "$(paste -sd'|' "$LOG")"

: > "$LOG"; fake_panel new
cli_node_join hn1.abc >/dev/null
check "a new panel: join only" "panel node join hn1.abc" "$(paste -sd'|' "$LOG")"

: > "$LOG"; fake_panel old
install_panel() { echo "install_panel" >> "$LOG"; }  # the update brings no node support
check "still no node support: refused" 1 "$(cli_node_join hn1.abc >/dev/null; echo $?)"
check "the old binary never got 'node'" "install_panel" "$(paste -sd'|' "$LOG")"
: > "$LOG"
check "hashem node on an old panel: refused" 1 "$(cli_node status >/dev/null; echo $?)"
check "and not run" "" "$(cat "$LOG")"
fake_panel new
cli_node status >/dev/null
check "hashem node status passes through" "panel node status" "$(cat "$LOG")"
check "usage lists node-join" 1 "$(grep -c '^  hashem node-join' hashem.sh)"
check "dispatch has node-join" 1 "$(grep -c '^        node-join) shift; cli_node_join' hashem.sh)"
exit $fail
