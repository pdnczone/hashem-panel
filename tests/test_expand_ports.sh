#!/usr/bin/env bash
# expand_ports turns the ports an admin types ("443, 1051-1060") into the
# list FRP forwards: every port of a range on its own. Before, a range was
# dropped by the prompt and the CLI, and reached the bundle as two ports.
# Hermetic: only the functions are sourced.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
for f in is_valid_port expand_ports; do
    awk -v f="$f" '$0 ~ "^"f"\\(\\) \\{" {p=1} p {print} p && /^}/ {exit}' "$ROOT/hashem.sh"
done > "$T/fn.sh"
# shellcheck disable=SC1091
source "$T/fn.sh"
declare -F expand_ports >/dev/null || { echo "FAIL: expand_ports not found in hashem.sh"; exit 1; }
fail=0
check() { if [[ "$2" != "$3" ]]; then echo "FAIL: $1 (want [$2] got [$3])"; fail=1; else echo "ok:   $1"; fi; }

check "single ports, commas and spaces" "443 2083 8443" "$(expand_ports "443, 2083 8443")"
check "a range is every port of it" "1051 1052 1053 1054 1055" "$(expand_ports "1051-1055")"
check "the user's two ranges" \
    "1051 1052 1053 1054 1055 1056 1057 1058 1059 1060 1092 1093 1094 1095 1096 1097 1098 1099" \
    "$(expand_ports "1051-1060, 1092-1099")"
check "repeats once, order kept" "443 1051 1052 2083" "$(expand_ports "443,1051-1052, 1051 443 2083")"
check "leading zeros read as decimal" "443 1051 1052" "$(expand_ports "0443 01051-01052")"
check "mappings, IP:, backwards and out-of-range entries are dropped" "443" \
    "$(expand_ports "2083=8443 127.0.0.1:55973 1060-1051 0 70000 x 443")"
check "a glob character is not expanded" "443" "$(cd "$T" && touch a b && expand_ports "* 443")"
check "empty input" "" "$(expand_ports "")"
out=$(expand_ports "1-2000" 2>"$T/err")
check "stops at 1000 ports" 1000 "$(wc -w <<< "$out")"
check "and says so" 1 "$(grep -c "More than 1000 ports" "$T/err")"
check "the last port kept" 1000 "${out##* }"

exit $fail
