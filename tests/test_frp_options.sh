#!/usr/bin/env bash
# FRP proxy options from the Performance tab (PROXY protocol, bandwidth limit,
# health check) reach every [[proxies]] block of frpc.toml through perf apply,
# and a PROXY protocol chosen at setup is never dropped by an update.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin" "$T/frp"
export PERF_FILE="$T/perf.json" CONFIG_DIR="$T/frp" PATH="$T/bin:$PATH"
unset PERF_TCPMUX PERF_ENC PERF_COMP
for fn in perf_get_str perf_get_int perf_frpc_extra_lines perf_get_tcpmux perf_get_enc perf_get_comp perf_apply; do
    awk -v f="$fn" '$0 ~ "^"f"\\(\\) \\{" {p=1} p {print} p && /^}/ {p=0}' "$ROOT/hashem.sh"
done > "$T/fn.sh"
# shellcheck disable=SC1091
source "$T/fn.sh"
init_perf_json() { [[ -f "$PERF_FILE" ]] || echo '{}' > "$PERF_FILE"; }
pool_effective_values() { echo "20 60"; }
autopool_state_set() { :; }
printf '#!/bin/sh\nexit 0\n' > "$T/bin/systemctl"; chmod +x "$T/bin/systemctl"
RED='' GREEN='' YELLOW='' CYAN='' NC=''
fail=0
chk() { [[ "$2" == "$3" ]] || { echo "FAIL $1: got [$2] want [$3]"; fail=1; }; }
cnt() { grep -c -- "$1" "$T/frp/frpc.toml"; }

frpc() {
    cat > "$T/frp/frpc.toml" <<'EOF'
serverAddr = "10.0.0.1"
serverPort = 7000
transport.poolCount = 20

[[proxies]]
name = "tcp_443"
type = "tcp"
localIP = "127.0.0.1"
localPort = 443
remotePort = 443
transport.proxyProtocolVersion = "v2"

[[proxies]]
name = "udp_443"
type = "udp"
localIP = "127.0.0.1"
localPort = 443
remotePort = 443
EOF
}

# 1. never set in the Performance tab: the setup's PROXY protocol stays (updates run perf apply)
frpc; echo '{}' > "$PERF_FILE"
perf_apply >/dev/null
chk "unset keeps setup v2" "$(cnt 'proxyProtocolVersion = "v2"')" 1
chk "no bandwidth by default" "$(cnt bandwidthLimit)" 0
chk "no health check by default" "$(cnt healthCheck)" 0

# 2. turned off in the Performance tab
echo '{"proxy_protocol": "off"}' > "$PERF_FILE"
perf_apply >/dev/null
chk "off removes it" "$(cnt proxyProtocolVersion)" 0

# 3. v1 + bandwidth + health check
echo '{"proxy_protocol": "v1", "bandwidth_limit_mb": 50, "health_check": true}' > "$PERF_FILE"
perf_apply >/dev/null
chk "v1 on tcp only" "$(cnt 'proxyProtocolVersion = "v1"')" 1
chk "bandwidth on tcp and udp" "$(cnt 'transport.bandwidthLimit = "50MB"')" 2
chk "bandwidth mode" "$(cnt 'bandwidthLimitMode = "client"')" 2
chk "health check on tcp only" "$(cnt 'healthCheck.type = "tcp"')" 1
awk '/name = "udp_443"/ {u=1} u && /healthCheck|proxyProtocol/ {bad=1} END {exit bad}' "$T/frp/frpc.toml" || { echo "FAIL udp block got tcp-only options"; fail=1; }

# 4. applying twice changes nothing (no duplicate lines)
cp "$T/frp/frpc.toml" "$T/before"
perf_apply >/dev/null
cmp -s "$T/before" "$T/frp/frpc.toml" || { echo "FAIL second apply changed frpc.toml"; diff "$T/before" "$T/frp/frpc.toml"; fail=1; }

# 5. options off again: every line goes
echo '{"proxy_protocol": "off"}' > "$PERF_FILE"
perf_apply >/dev/null
chk "all removed" "$(grep -cE 'bandwidthLimit|healthCheck|proxyProtocol' "$T/frp/frpc.toml")" 0

# 6. a new setup writes the same lines
echo '{"bandwidth_limit_mb": 10, "health_check": true}' > "$PERF_FILE"
chk "setup tcp lines" "$(perf_frpc_extra_lines tcp | grep -c .)" 6
chk "setup udp lines" "$(perf_frpc_extra_lines udp | grep -c .)" 2
echo '{"bandwidth_limit_mb": 99999}' > "$PERF_FILE"
chk "out of range bandwidth ignored" "$(perf_frpc_extra_lines udp | grep -c .)" 0

[[ $fail -eq 0 ]] && echo "PASS test_frp_options" || exit 1
