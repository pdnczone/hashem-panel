#!/usr/bin/env bash
# Removing the first tunnel next to other tunnels removes it alone: the other
# tunnels' units, GRE interfaces, configs and registry records stay. With no
# other tunnel left it is the full removal.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin" "$T/sd" "$T/frp" "$T/bh" "$T/panel"
for c in systemctl ip; do
    printf '#!/bin/sh\necho "%s $*" >> %s/calls.log\n' "$c" "$T" > "$T/bin/$c"; chmod +x "$T/bin/$c"
done
export PATH="$T/bin:$PATH" HASHEM_SYSTEMD_DIR="$T/sd"
for f in cli_remove_peer peer_init peer_require_py peer_get remove_base_tunnel peers_other_than \
         frps_wss_front_remove backhaul_udp_remove backhaul_udp_unit gre6_sit_name; do
    awk -v f="$f" '$0 ~ "^"f"\\(\\) \\{" {p=1} p {print} p && /^}/ {exit}' "$ROOT/hashem.sh"
done > "$T/fn.sh"
# shellcheck disable=SC1091
source "$T/fn.sh"
for f in cli_remove_peer remove_base_tunnel peers_other_than; do
    declare -F "$f" >/dev/null || { echo "FAIL: $f not found in hashem.sh"; exit 1; }
done
remove_tunnel_force() { echo FORCE >> "$T/calls.log"; rm -f "$PEERS_FILE"; }
RED= GREEN= YELLOW= CYAN= NC=
TUNNEL_NAME=gre-tunnel CONFIG_DIR="$T/frp" BACKHAUL_CONFIG_DIR="$T/bh" PANEL_CONFIG_DIR="$T/panel"
PEERS_FILE="$T/panel/peers.json"
fail=0
check() { "$@" || { echo "FAIL: $*"; fail=1; }; }
none() { ! grep -qE "$1" "$T/calls.log"; }

seed() {
    : > "$T/calls.log"
    touch "$T/sd/frps.service" "$T/sd/gre-tunnel.service" "$T/sd/frps-2.service" "$T/sd/gre-t2.service" \
          "$T/frp/frps.toml" "$T/frp/frps-2.toml"
    cat > "$PEERS_FILE" <<'EOF'
{"peers": [
 {"id": 1, "name": "first", "gre_if": "gre-tunnel", "frps_svc": "frps", "legacy": true},
 {"id": 2, "name": "second", "gre_if": "gre-t2", "frps_svc": "frps-2", "carrier_id": 1}
]}
EOF
}

# 1. The first tunnel as legacy peer 1, next to peer 2
seed
cli_remove_peer --id 1 --force >/dev/null
check none FORCE
check grep -q 'disable --now frps.service' "$T/calls.log"
check grep -q 'link del gre-tunnel' "$T/calls.log"
check none 'frps-2|gre-t2'
check [ ! -e "$T/sd/frps.service" ]
check [ ! -e "$T/frp/frps.toml" ]
check [ -e "$T/sd/frps-2.service" ]
check [ -e "$T/sd/gre-t2.service" ]
check [ -e "$T/frp/frps-2.toml" ]
check [ "$(grep -o '"id": *[0-9]*' "$PEERS_FILE" | tr -d ' ')" = '"id":2' ]

# 2. The first tunnel from Setup (not in the registry), next to peer 2
seed
python3 -c 'import json,sys; f=sys.argv[1]; d=json.load(open(f)); d["peers"]=d["peers"][1:]; json.dump(d,open(f,"w"))' "$PEERS_FILE"
remove_base_tunnel >/dev/null
check none FORCE
check none 'frps-2|gre-t2'
check [ -e "$T/sd/frps-2.service" ]
check grep -q '"id": 2' "$PEERS_FILE"

# 3. No other tunnel: the full removal
seed
echo '{"peers": [{"id": 1, "name": "first", "gre_if": "gre-tunnel", "frps_svc": "frps", "legacy": true}]}' > "$PEERS_FILE"
check [ "$(peers_other_than 1)" = 0 ]
cli_remove_peer --id 1 --force >/dev/null
check grep -q FORCE "$T/calls.log"
rm -f "$PEERS_FILE"
check [ "$(peers_other_than 0)" = 0 ]

(( fail )) && exit 1; echo "PASS test_remove_base_tunnel"
