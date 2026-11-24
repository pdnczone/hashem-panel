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
  for fn in watchdog_send watchdog_test tg_tunnel_host tg_bridge_ports; do
    awk -v f="$fn" '$0 ~ "^"f"\\(\\) \\{" {p=1} p {print} p && /^}/ {p=0}' "$ROOT/hashem.sh"
  done
} > "$T/fn.sh"
# shellcheck disable=SC1091
source "$T/fn.sh"
init_watchdog_json() { :; }
PRO=1
pro_ok() { [[ "$PRO" == 1 ]]; }
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

# One bot: every paired account that did not mute alerts, and the extra chat.
# A fake curl that logs its arguments; FAIL_DIRECT=1: Telegram is blocked here.
cat > "$T/bin/curl" <<'EOF'
#!/bin/sh
echo "$*" >> "$CURL_LOG"
case "$*" in *--socks5-hostname*) ;; *) [ -n "$FAIL_DIRECT" ] && { echo 'curl: (28) timeout'; exit 28; } ;; esac
echo '{"ok":true,"result":{}}'
EOF
chmod +x "$T/bin/curl"
export CURL_LOG="$T/curl.log" FAIL_DIRECT=""
printf '{"enabled":true,"token":"","users":[{"id":42,"role":"admin"},{"id":77,"role":"viewer"},{"id":78,"mute":true}]}' > "$T/telegram_bot.json"
: > "$CURL_LOG"
watchdog_send "hi" || { echo "FAIL paired send"; fail=1; }
ids=$(grep -o 'chat_id=[0-9-]*' "$CURL_LOG" | tr '\n' ' ')
[[ "$ids" == "chat_id=42 chat_id=77 " ]] || { echo "FAIL receivers: $ids"; fail=1; }
PRO=0; : > "$CURL_LOG"; watchdog_send "hi"
ids=$(grep -o 'chat_id=[0-9-]*' "$CURL_LOG" | tr '\n' ' ')
[[ "$ids" == "chat_id=42 " ]] || { echo "FAIL without a license: $ids"; fail=1; }
PRO=1

# The automatic route: direct, then the panel's loopback bridges; the way that
# answered carries the other chats too.
cat > "$T/bin/ss" <<'EOF'
#!/bin/sh
cat <<'L'
LISTEN 0 4096 127.0.0.1:17082 0.0.0.0:*
LISTEN 0 4096 127.0.0.1:17079 0.0.0.0:*
LISTEN 0 4096 0.0.0.0:17090 0.0.0.0:*
LISTEN 0 4096 127.0.0.1:17281 0.0.0.0:*
L
EOF
chmod +x "$T/bin/ss"
[[ "$(tg_bridge_ports | tr '\n' ' ')" == "17082 " ]] || { echo "FAIL bridges: $(tg_bridge_ports)"; fail=1; }
printf '{"tg_bot_token":"123456:SECRETSECRET","tg_chat_id":"","tg_route":"auto"}' > "$WATCHDOG_FILE"
export FAIL_DIRECT=1; : > "$CURL_LOG"
watchdog_send "hi" || { echo "FAIL auto send"; fail=1; }
[[ $(grep -c socks5 "$CURL_LOG") == 2 && $(grep -vc socks5 "$CURL_LOG") == 1 ]] || { echo "FAIL auto: $(cat "$CURL_LOG")"; fail=1; }
printf '{"tg_bot_token":"123456:SECRETSECRET","tg_chat_id":"42","tg_route":"direct"}' > "$WATCHDOG_FILE"
out=$(watchdog_send "hi" 2>&1) && { echo "FAIL direct only must not use a tunnel"; fail=1; }

[[ $fail -eq 0 ]] && echo "PASS test_watchdog_telegram" || exit 1
