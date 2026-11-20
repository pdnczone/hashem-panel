#!/usr/bin/env bash
# display_tz_env: hashem.sh shows times in Tehran's zone without changing the
# server's own zone. Hermetic: a fake zoneinfo tree; nothing on the host moves.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
awk '$0 ~ "^display_tz_env\\(\\) \\{" {p=1} p {print} p && /^}/ {exit}' "$ROOT/hashem.sh" > "$T/fn.sh"
# shellcheck disable=SC1091
source "$T/fn.sh"
declare -F display_tz_env >/dev/null || { echo "FAIL: display_tz_env not found in hashem.sh"; exit 1; }
export HASHEM_ZONEINFO="$T/zoneinfo"
mkdir -p "$T/zoneinfo/Asia" "$T/zoneinfo/Europe"; touch "$T/zoneinfo/Asia/Tehran" "$T/zoneinfo/Europe/Berlin"
fail=0
check() { if [[ "$2" != "$3" ]]; then echo "FAIL: $1 (want [$2] got [$3])"; fail=1; else echo "ok:   $1"; fi; }
tz() { (unset TZ; [[ -n "${2+x}" ]] && export TZ="$2"; HASHEM_DISPLAY_TZ="$1"; [[ -z "$1" ]] && unset HASHEM_DISPLAY_TZ; display_tz_env; echo "${TZ:-}"); }

check "default is Tehran" "Asia/Tehran" "$(tz "")"
check "another zone" "Europe/Berlin" "$(tz Europe/Berlin)"
check "server keeps the server's zone" "" "$(tz server)"
check "a TZ already set (by the panel) is kept" "UTC" "$(tz "" UTC)"
check "unknown zone: server's zone" "" "$(tz Mars/Olympus)"
check "a path is not a zone" "" "$(tz '../../etc/passwd')"
rm "$T/zoneinfo/Asia/Tehran"
check "no tzdata: Tehran's fixed offset" "<+0330>-03:30" "$(tz "")"
check "that offset reads 3:30 ahead" "03:30" "$(TZ='<+0330>-03:30' date -d @0 +%H:%M)"

# the server's zone is never changed by hashem.sh
if grep -nE 'timedatectl set-timezone|ln -sf?[^#]*/etc/localtime|> */etc/timezone' "$ROOT/hashem.sh"; then
    echo "FAIL: hashem.sh changes the server's time zone"; fail=1
else
    echo "ok:   hashem.sh leaves the server's time zone alone"
fi
grep -q '^display_tz_env$' "$ROOT/hashem.sh"; check "hashem.sh applies it at start" 0 $?

[[ $fail -eq 0 ]] && echo "PASS test_display_tz" || { echo "FAIL test_display_tz"; exit 1; }
