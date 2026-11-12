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
# a rule the admin already had is skipped, as the real ufw says
[ "\$1" = allow ] && grep -qx "\$2" "$T/admin" 2>/dev/null && echo "Skipping adding existing rule"
exit 0
EOF
chmod +x "$T/bin/ufw"
export PATH="$T/bin:$PATH"
for f in is_valid_port hashem_ufw_allow hashem_ports_needed hashem_ufw_release frps_ufw_open; do
    awk -v f="$f" '$0 ~ "^"f"\\(\\) \\{" {p=1} p {print} p && /^}/ {exit}' "$ROOT/hashem.sh"
done > "$T/fn.sh"
# shellcheck disable=SC1091
source "$T/fn.sh"
mkdir -p "$T/panel" "$T/frp" "$T/bh" "$T/sd"
PANEL_CONFIG_DIR="$T/panel" CONFIG_DIR="$T/frp" BACKHAUL_CONFIG_DIR="$T/bh" PEERS_FILE="$T/panel/peers.json"
export HASHEM_SYSTEMD_DIR="$T/sd"
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

# removing a tunnel closes the rules Hashem added for it, and only those
echo "Status: active" > "$T/state"
rm -f "$T/panel/ufw.opened"; echo "443/tcp" > "$T/admin"
frps_ufw_open 7000 "443 2083"; frps_ufw_open 7100 "2083 8443"
check "the admin's own rule is not recorded" 0 "$(grep -c '^443/tcp$' "$T/panel/ufw.opened")"
# tunnel 1 (7000: 443, 2083) is gone; tunnel 2 (7100: 2083, 8443) stays
cat > "$PEERS_FILE" <<'JSON'
{"peers": [{"id": 2, "frp_port": 7100, "ports": [2083, 8443], "raw_ports": ["9000-9002=443"]}]}
JSON
printf 'bindPort = 7100\nkcpBindPort = 7100\nquicBindPort = 7101\n' > "$T/frp/frps-2.toml"
echo "9001/tcp" >> "$T/panel/ufw.opened"
: > "$T/calls.log"; hashem_ufw_release
check "only the removed tunnel's own rules are deleted" "delete allow 7000/tcp delete allow 7000/udp delete allow 7001/udp delete allow 443/udp" "$(calls)"
check "the kept rules stay recorded" "2083/tcp 2083/udp 7100/tcp 7100/udp 7101/udp 8443/tcp 8443/udp 9001/tcp" "$(tr '\n' ' ' < "$T/panel/ufw.opened" | sed 's/ $//')"
rm -f "$PEERS_FILE" "$T/frp/frps-2.toml"
: > "$T/calls.log"; hashem_ufw_release
check "the last tunnel removed: every recorded rule goes" 8 "$(grep -c '^delete allow' "$T/calls.log")"
check "and the record with them" no "$([[ -e "$T/panel/ufw.opened" ]] && echo yes || echo no)"

# every Iran FRP path goes through it
check "Iran setup opens its ports" 1 "$(grep -c 'frps_ufw_open "\$BIND_PORT" "\$PORTS_CLEANED"' "$ROOT/hashem.sh")"
check "add-peer opens its ports" 1 "$(grep -c 'frps_ufw_open "\$FRP_PORT" "\$CLEANED"' "$ROOT/hashem.sh")"
check "no frps path opens tcp alone" 0 "$(grep -c 'ufw allow "\${BIND_PORT}/tcp" >/dev/null 2>&1$' "$ROOT/hashem.sh")"

(( fail )) && exit 1; echo "PASS test_frps_ufw"
