#!/usr/bin/env bash
# With ufw active, the Iran side opens everything frps listens on: the control
# port (tcp, and udp for kcp), quic on the next port and the users' ports.
# With ufw inactive or missing it touches nothing. Hermetic: ufw is a stub.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin"
cat > "$T/bin/ufw" <<EOF
#!/bin/sh
[ "\$1" = status ] && { cat "$T/state"; exit 0; }
echo "\$*" >> "$T/calls.log"
EOF
chmod +x "$T/bin/ufw"
export PATH="$T/bin:$PATH"
for f in is_valid_port frps_ufw_open; do
    awk -v f="$f" '$0 ~ "^"f"\\(\\) \\{" {p=1} p {print} p && /^}/ {exit}' "$ROOT/hashem.sh"
done > "$T/fn.sh"
# shellcheck disable=SC1091
source "$T/fn.sh"
declare -F frps_ufw_open >/dev/null || { echo "FAIL: frps_ufw_open not found in hashem.sh"; exit 1; }
fail=0
check() { if [[ "$2" != "$3" ]]; then echo "FAIL: $1 (want [$2] got [$3])"; fail=1; else echo "ok:   $1"; fi; }
calls() { tr '\n' ' ' < "$T/calls.log" 2>/dev/null | sed 's/ $//'; }

echo "Status: active" > "$T/state"
: > "$T/calls.log"; frps_ufw_open 7000 "443, 2083,bad,0"
check "control tcp+udp, quic, users' ports" "allow 7000/tcp allow 7000/udp allow 7001/udp allow 443/tcp allow 443/udp allow 2083/tcp allow 2083/udp" "$(calls)"
: > "$T/calls.log"; frps_ufw_open 65535
check "quic below the control port at 65535" "allow 65535/tcp allow 65535/udp allow 65534/udp" "$(calls)"

echo "Status: inactive" > "$T/state"
: > "$T/calls.log"; frps_ufw_open 7000 "443"
check "ufw inactive: nothing" "" "$(calls)"

# every Iran FRP path goes through it
check "Iran setup opens its ports" 1 "$(grep -c 'frps_ufw_open "\$BIND_PORT" "\$PORTS_CLEANED"' "$ROOT/hashem.sh")"
check "add-peer opens its ports" 1 "$(grep -c 'frps_ufw_open "\$FRP_PORT" "\$CLEANED"' "$ROOT/hashem.sh")"
check "no frps path opens tcp alone" 0 "$(grep -c 'ufw allow "\${BIND_PORT}/tcp" >/dev/null 2>&1$' "$ROOT/hashem.sh")"

(( fail )) && exit 1; echo "PASS test_frps_ufw"
