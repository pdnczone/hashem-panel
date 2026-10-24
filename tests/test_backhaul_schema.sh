#!/usr/bin/env bash
# B-03: backhaul config schema must match the installed core (v0.x flat [server]/[client] vs Modified v2.x [listener]/[dialer]).
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin"
BACKHAUL_CONFIG_DIR="$T/etc"; INSTALL_DIR="$T/bin"
fail=0
ext() { awk -v n="$1" '$0 ~ "^"n"\\(\\) \\{" {p=1} p {print} p && /^}/ {exit}' "$ROOT/hashem.sh"; }
eval "$(grep -E '^backhaul_udp_wanted' "$ROOT/hashem.sh")"
for f in hostonly pool_clamp perf_get_int backhaul_pool_size backhaul_is_v2 backhaul_write_server_conf_v1 backhaul_write_client_conf_v1 backhaul_write_server_conf_v2 backhaul_write_client_conf_v2 backhaul_write_server_conf backhaul_write_client_conf; do
  b="$(ext $f)"; [[ -n "$b" ]] || { echo "FAIL: $f missing"; exit 1; }; eval "$b"
done
backhaul_ensure_tls() { mkdir -p "$BACKHAUL_CONFIG_DIR"; : > "$BACKHAUL_CONFIG_DIR/server.crt"; : > "$BACKHAUL_CONFIG_DIR/server.key"; }
fake() { printf '#!/bin/sh\necho %s\n' "$1" > "$INSTALL_DIR/backhaul"; chmod +x "$INSTALL_DIR/backhaul"; }

fake v2.0.0-hotfix8
backhaul_is_v2 || { echo "FAIL v2 not detected"; fail=1; }
backhaul_write_server_conf "$T/s.toml" "0.0.0.0:7100" wssmux tok "9001, 9002"
grep -q '^\[listener\]' "$T/s.toml" && grep -q '^\[ports\]' "$T/s.toml" && grep -q '"9002",' "$T/s.toml" && grep -q '^\[mux\]' "$T/s.toml" && grep -q '^\[tls\]' "$T/s.toml" \
  || { echo "FAIL v2 server schema"; cat "$T/s.toml"; fail=1; }
grep -q '^\[server\]' "$T/s.toml" && { echo "FAIL v2 server must not use [server]"; fail=1; }
backhaul_write_client_conf "$T/c.toml" "1.2.3.4:7100" tcp tok
grep -q '^\[dialer\]' "$T/c.toml" && grep -q 'remote_addr = "1.2.3.4:7100"' "$T/c.toml" || { echo "FAIL v2 client schema"; fail=1; }

fake v0.7.2
backhaul_is_v2 && { echo "FAIL v0.7.2 detected as v2"; fail=1; }
backhaul_write_server_conf "$T/s1.toml" "0.0.0.0:7100" tcp tok "9001"
grep -q '^\[server\]' "$T/s1.toml" || { echo "FAIL v1 server schema regressed"; fail=1; }
backhaul_write_client_conf "$T/c1.toml" "1.2.3.4:7100" tcp tok
grep -q '^\[client\]' "$T/c1.toml" || { echo "FAIL v1 client schema regressed"; fail=1; }

# connection_pool follows perf.json backhaul_pool (Performance tab), 8 when unset
PERF_FILE="$T/perf.json"
backhaul_write_client_conf "$T/p0.toml" "1.2.3.4:7100" tcp tok
grep -q '^connection_pool = 8$' "$T/p0.toml" || { echo "FAIL pool default is not 8"; fail=1; }
echo '{"backhaul_pool": 24}' > "$PERF_FILE"
backhaul_write_client_conf "$T/p1.toml" "1.2.3.4:7100" tcp tok
grep -q '^connection_pool = 24$' "$T/p1.toml" || { echo "FAIL v1 pool not from perf.json"; fail=1; }
fake v2.0.0-hotfix8
backhaul_write_client_conf "$T/p2.toml" "1.2.3.4:7100" tcpmux tok
grep -q '^connection_pool = 24$' "$T/p2.toml" || { echo "FAIL v2 pool not from perf.json"; fail=1; }
echo '{"backhaul_pool": 900}' > "$PERF_FILE"
backhaul_write_client_conf "$T/p3.toml" "1.2.3.4:7100" tcpmux tok
grep -q '^connection_pool = 64$' "$T/p3.toml" || { echo "FAIL pool not clamped to 64"; fail=1; }

(( fail )) && exit 1; echo "PASS test_backhaul_schema"
