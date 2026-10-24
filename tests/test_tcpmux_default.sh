#!/usr/bin/env bash
# FRP tcpMux must be OFF by default (speed-first); the EOF hint is read-only.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin" "$T/frp"
export PERF_FILE="$T/perf.json" CONFIG_DIR="$T/frp"
unset PERF_TCPMUX
for fn in perf_get_tcpmux perf_tcpmux_new perf_tcpmux_lines tcpmux_eof_hint; do
    awk -v f="$fn" '$0 ~ "^"f"\\(\\) \\{" {p=1} p {print} p && /^}/ {p=0}' "$ROOT/hashem.sh"
done > "$T/fn.sh"
# shellcheck disable=SC1091
source "$T/fn.sh"
fail=0
chk() { [[ "$2" == "$3" ]] || { echo "FAIL $1: got '$2' want '$3'"; fail=1; }; }

chk "unset -> off" "$(perf_tcpmux_lines)" "transport.tcpMux = false"
echo '{"tcp_mux": false}' > "$PERF_FILE"
chk "false -> off" "$(perf_tcpmux_lines)" "transport.tcpMux = false"
echo '{"tcp_mux": true}' > "$PERF_FILE"
chk "true -> on" "$(perf_tcpmux_lines)" $'transport.tcpMux = true\ntransport.tcpMuxKeepaliveInterval = 30'
echo '{}' > "$PERF_FILE"
chk "off carries no keepalive" "$(perf_tcpmux_lines | grep -c Keepalive)" "0"

printf '#!/bin/sh\necho "frpc: connect to server error: EOF"\n' > "$T/bin/journalctl"; chmod +x "$T/bin/journalctl"
export PATH="$T/bin:$PATH"
tcpmux_eof_hint >/dev/null && { echo "FAIL hint without frpc.toml"; fail=1; }
: > "$T/frp/frpc.toml"
tcpmux_eof_hint | grep -q 'tcpMux mismatch' || { echo "FAIL no hint on EOF"; fail=1; }
[[ ! -s "$T/frp/frpc.toml" ]] || { echo "FAIL hint modified config"; fail=1; }

# recovered tunnel: EOF followed by a successful login must NOT hint
printf '#!/bin/sh\necho "frpc: connect to server error: EOF"\necho "frpc: login to server success, get run id [x]"\n' > "$T/bin/journalctl"
tcpmux_eof_hint >/dev/null && { echo "FAIL hint after recovered login"; fail=1; }

[[ $fail -eq 0 ]] && echo "PASS test_tcpmux_default" || exit 1
