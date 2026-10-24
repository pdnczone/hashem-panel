#!/usr/bin/env bash
# tests/test_cluster.sh — the script side of the cluster: relays of pool members
# keep their private address (the same rule as the panel), a pooled port may be
# claimed by another peer, the cluster commands go through the panel binary and
# need Hashem Pro, and join-hub records extra Iran hubs. Hermetic.
set -u
cd "$(dirname "$0")/.." || exit 1
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
fail=0
check() { if [[ "$2" != "$3" ]]; then echo "FAIL: $1 (want [$2] got [$3])"; fail=1; else echo "ok:   $1"; fi; }

ext() { awk -v n="$1" '$0 ~ "^"n"\\(\\) \\{" {p=1} p {print} p && /^}/ {exit}' hashem.sh; }
RED='' NC='' GREEN='' YELLOW='' CYAN='' BOLD=''
for fn in lb_addr_for_svc lb_port_pooled lb_bound_addr lb_frps_bind lb_prefix_ports pro_ok cli_cluster hubs_init hub_next_id cli_leave_hub; do
    eval "$(ext "$fn")"
done
PANEL_CONFIG_DIR="$T"
LB_BINDS_FILE="$T/lb-binds"
LB_PORTS_FILE="$T/lb-ports"
HUBS_FILE="$T/hubs.json"

# the panel's rule (cluster_lb.go lbAddrFor)
check "frps -> .1" 169.254.77.1 "$(lb_addr_for_svc frps)"
check "backhaul-server -> .1" 169.254.77.1 "$(lb_addr_for_svc backhaul-server)"
check "frps-3 -> .4" 169.254.77.4 "$(lb_addr_for_svc frps-3)"
check "backhaul-server-10 -> .11" 169.254.77.11 "$(lb_addr_for_svc backhaul-server-10)"
check "frpc has none" "" "$(lb_addr_for_svc frpc)"
check "frps-x has none" "" "$(lb_addr_for_svc frps-x)"
check "panel and script agree" 1 "$(grep -c '"169.254.77.%d", n+1' panel/cluster_lb.go)"

# pooled ports
printf '443/tcp\n443/udp\n' > "$LB_PORTS_FILE"
check "443 is pooled" 0 "$(lb_port_pooled 443; echo $?)"
check "0443 is pooled" 0 "$(lb_port_pooled 0443; echo $?)"
check "4430 is not" 1 "$(lb_port_pooled 4430; echo $?)"
rm -f "$LB_PORTS_FILE"
check "no pools: nothing pooled" 1 "$(lb_port_pooled 443; echo $?)"

# a bound relay keeps proxyBindAddr when the script rewrites it
cat > "$T/frps-2.toml" <<'EOF'
bindAddr = "0.0.0.0"
bindPort = 7002
kcpBindPort = 7002
auth.token = "x"
EOF
cp "$T/frps-2.toml" "$T/orig.toml"
lb_frps_bind "$T/frps-2.toml" frps-2
check "not bound: file unchanged" "" "$(diff "$T/orig.toml" "$T/frps-2.toml")"
echo "frps-2 169.254.77.3" > "$LB_BINDS_FILE"
lb_frps_bind "$T/frps-2.toml" frps-2
check "bound: right after bindPort" 'proxyBindAddr = "169.254.77.3"' "$(sed -n 3p "$T/frps-2.toml")"
lb_frps_bind "$T/frps-2.toml" frps-2
check "bound twice: one line" 1 "$(grep -c proxyBindAddr "$T/frps-2.toml")"
rm -f "$LB_BINDS_FILE"
LB_BIND_ADDR=169.254.77.9 lb_frps_bind "$T/orig.toml" frps-8
check "a new pool member is bound at once" 1 "$(grep -c 'proxyBindAddr = "169.254.77.9"' "$T/orig.toml")"

check "backhaul entries move to the address" "169.254.77.2:443,169.254.77.2:2083=8443,169.254.77.2:10000-10010,1.2.3.4:80=80" \
    "$(lb_prefix_ports 169.254.77.2 "443, 2083=8443,10000-10010, 1.2.3.4:80=80")"
check "no address: entries as given" "443, 2083" "$(lb_prefix_ports "" "443, 2083")"

# the script writers call the hooks
check "peer_write_frps keeps the bind" 1 "$(ext peer_write_frps | grep -c 'lb_frps_bind')"
check "setup-iran keeps the bind" 1 "$(grep -c 'lb_frps_bind "${CONFIG_DIR}/frps.toml" frps' hashem.sh)"
check "backhaul server conf keeps the bind" 1 "$(ext backhaul_write_server_conf | grep -c 'lb_prefix_ports')"
check "add-peer lets a pooled port be claimed" 1 "$(ext cli_add_peer | grep -c 'lb_port_pooled "$p" && { POOLED=1; continue; }')"
check "add-backhaul-peer binds a pool member" 1 "$(ext cli_add_backhaul_peer | grep -c 'lb_port_pooled')"

# cluster commands: the panel binary, Pro for changes, not for reading
cat > "$T/gre-panel" <<EOF
#!/bin/bash
if [[ "\$1 \$2" == "license check" ]]; then grep -qx "\$3" "$T/unlocked" 2>/dev/null; exit; fi
echo "PANEL \$*"
EOF
chmod +x "$T/gre-panel"
export PANEL_BIN="$T/gre-panel"
: > "$T/unlocked"
check "status without a license" "PANEL cluster status" "$(cli_cluster status)"
check "events without a license" "PANEL cluster events" "$(cli_cluster events)"
check "pool add needs Pro" 1 "$(cli_cluster pool add 443 >/dev/null; echo $?)"
check "add-hub needs Pro" "" "$(cli_cluster add-hub hc1_x | grep PANEL)"
echo cluster > "$T/unlocked"
check "pool add with Pro" "PANEL cluster pool add 443 --mode sticky" "$(cli_cluster pool add 443 --mode sticky)"
PANEL_BIN="$T/none" check "no panel: refused" 1 "$(PANEL_BIN="$T/none" cli_cluster status >/dev/null; echo $?)"

# extra hubs on a foreign server
check "join-hub asks for Pro first" 1 "$(ext cli_join_hub | grep -c 'pro_ok cluster')"
check "join-hub refuses the first hub's IP" 1 "$(ext cli_join_hub | grep -c 'already serves the Iran hub')"
check "join-hub never reuses a GRE address" 1 "$(ext cli_join_hub | grep -c 'is already used here')"
hubs_init
check "hubs.json created" '{"hubs": []}' "$(cat "$HUBS_FILE")"
check "first extra hub is 2" 2 "$(hub_next_id)"
echo '{"hubs": [{"id": 2, "name": "a", "svc": "frpc-h2", "conf": "/x", "gre_if": "none"}, {"id": 3, "name": "b", "svc": "frpc-h3", "conf": "/y", "gre_if": "none"}]}' > "$HUBS_FILE"
check "next free id" 4 "$(hub_next_id)"
# leave-hub drops the record (systemctl/ip are stubbed)
systemctl() { :; }; ip() { :; }; peer_require_py() { :; }
cli_leave_hub --id 2 >/dev/null
check "leave-hub removes it" '[3]' "$(python3 -c 'import json,sys; print([h["id"] for h in json.load(open(sys.argv[1]))["hubs"]])' "$HUBS_FILE")"
check "leave-hub unknown id" 1 "$(cli_leave_hub --id 7 >/dev/null; echo $?)"

# the terminal menu offers every pool feature the panel has
check "menu: least connections mode" 1 "$(ext cluster_pick_mode | grep -c "printf -v \"\$1\" '%s' least")"
check "menu: service check" 1 "$(ext menu_cluster | grep -c 'pool set "$a" --check tcp --check-every')"
check "menu: fail back now" 1 "$(ext menu_cluster | grep -c 'pool failback "$a"')"
check "menu: standby member" 1 "$(ext menu_cluster | grep -c 'member set "$a" "$b" --backup yes')"
check "menu: connection limit" 1 "$(ext menu_cluster | grep -c 'member set "$a" "$b" --max-conn')"
check "menu: several ports at once" 1 "$(ext menu_cluster | grep -c 'Several ports at once')"

# CLI wiring and uninstall
check "join-hub dispatched" 1 "$(grep -c 'join-hub) shift; cli_join_hub' hashem.sh)"
check "uninstall removes the cluster rules" 2 "$(grep -c 'cluster reset >/dev/null' hashem.sh)"
check "extra-hub GRE interfaces are ours" 1 "$(grep -c "grep -E '^gre-\[th\]\[0-9\]+\$'" hashem.sh)"

(( fail )) && exit 1; echo "PASS test_cluster"
