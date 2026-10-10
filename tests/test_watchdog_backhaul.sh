#!/usr/bin/env bash
# Watchdog must judge Backhaul by its control-channel session, not unit state.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin"
awk '/^backhaul_session_ok\(\) \{/ {p=1} p {print} p && /^}/ {p=0}' "$ROOT/hashem.sh" > "$T/fn.sh"
[[ -s "$T/fn.sh" ]] || { echo "FAIL backhaul_session_ok not found"; exit 1; }
# shellcheck disable=SC1091
source "$T/fn.sh"
export PATH="$T/bin:$PATH"
fail=0
jc() { printf '#!/bin/sh\n' > "$T/bin/journalctl"; for l in "$@"; do printf 'echo "%s"\n' "$l" >> "$T/bin/journalctl"; done; chmod +x "$T/bin/journalctl"; }
chk() { [[ "$2" == "$3" ]] || { echo "FAIL $1: got $2 want $3"; fail=1; }; }

jc "[INFO] control channel established successfully"
backhaul_session_ok backhaul-client; chk "healthy" $? 0
jc "[INFO] control channel established successfully" "[ERROR] failed to read from control channel. EOF" "[INFO] restarting client..."
backhaul_session_ok backhaul-client; chk "dropped after success" $? 1
jc "[WARNING] invalid security token received: ***" "[INFO] control channel established successfully"
backhaul_session_ok backhaul-server; chk "recovered" $? 0
jc "[WARNING] invalid security token received: ***"
backhaul_session_ok backhaul-server; chk "token rejected" $? 1
jc "[INFO] something unrelated"
backhaul_session_ok backhaul-server; chk "no signal -> no false alarm" $? 0
grep -q 'backhaul_session_ok "\$BH_UNIT"' "$ROOT/hashem.sh" || { echo "FAIL watchdog_check does not use it"; fail=1; }
[[ $fail -eq 0 ]] && echo "PASS test_watchdog_backhaul" || exit 1
