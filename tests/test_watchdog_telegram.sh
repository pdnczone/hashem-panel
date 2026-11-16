#!/usr/bin/env bash
# The Watchdog's Telegram send must tell the user what Telegram said: a bad
# token and a bad chat id are different problems. Fake curl, throwaway tree.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin"
export WATCHDOG_FILE="$T/watchdog.json"
{
  echo 'RED= GREEN= CYAN= YELLOW= NC='
  for fn in watchdog_send watchdog_test; do
    awk -v f="$fn" '$0 ~ "^"f"\\(\\) \\{" {p=1} p {print} p && /^}/ {p=0}' "$ROOT/hashem.sh"
  done
} > "$T/fn.sh"
# shellcheck disable=SC1091
source "$T/fn.sh"
init_watchdog_json() { :; }
printf '{"tg_bot_token":"123456:SECRETSECRET","tg_chat_id":"42","tg_route":"direct","tg_tunnel_port":0}' > "$WATCHDOG_FILE"
export PATH="$T/bin:$PATH"
fake() { printf '#!/bin/sh\nprintf "%%s" '"'%s'"'\nexit %s\n' "$1" "${2:-0}" > "$T/bin/curl"; chmod +x "$T/bin/curl"; }

fail=0
chk() { [[ "$2" == *"$3"* ]] || { echo "FAIL $1: got '$2' want '*$3*'"; fail=1; }; }

fake '{"ok":true,"result":{}}'
out=$(watchdog_send "hi" 2>&1); rc=$?; [[ $rc -eq 0 ]] || { echo "FAIL good send rc=$rc: $out"; fail=1; }

fake '{"ok":false,"error_code":401,"description":"Unauthorized"}'
out=$(watchdog_send "hi" 2>&1); rc=$?
[[ $rc -ne 0 ]] || { echo "FAIL a 401 must fail"; fail=1; }
chk "bad token" "$out" "Telegram said: Unauthorized"

fake '{"ok":false,"error_code":400,"description":"Bad Request: chat not found"}'
out=$(watchdog_send "hi" 2>&1); chk "bad chat id" "$out" "chat not found"

fake 'curl: (7) Failed to connect to 123456:SECRETSECRET' 7
out=$(watchdog_send "hi" 2>&1); rc=$?
[[ $rc -ne 0 ]] || { echo "FAIL a network failure must fail"; fail=1; }
chk "network failure" "$out" "Telegram send failed"
[[ "$out" != *SECRETSECRET* ]] || { echo "FAIL the token leaked: $out"; fail=1; }
[[ "$out" != *"Telegram said"* ]] || { echo "FAIL a network failure is not Telegram's answer"; fail=1; }

[[ $fail -eq 0 ]] && echo "PASS test_watchdog_telegram" || exit 1
