#!/usr/bin/env bash
# A tunnel whose service does not start leaves nothing behind (its config used
# to stay without a peers.json record: the panel counted its control port as
# taken for good), and what older releases left that way is swept. Hermetic:
# systemctl, ip, journalctl and ufw are stubs.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin" "$T/sd" "$T/frp" "$T/bh/udp" "$T/panel"
cat > "$T/bin/systemctl" <<EOF
#!/bin/sh
echo "systemctl \$*" >> "$T/calls.log"
# only the units listed in "active" are running
[ "\$1" = is-active ] && { for a in "\$@"; do grep -qx "\$a" "$T/active" 2>/dev/null && exit 0; done; exit 3; }
exit 0
EOF
for c in ip journalctl ufw; do
    printf '#!/bin/sh\necho "%s $*" >> %s/calls.log\n' "$c" "$T" > "$T/bin/$c"
done
chmod +x "$T/bin"/*
export PATH="$T/bin:$PATH" HASHEM_SYSTEMD_DIR="$T/sd"
for f in peer_add_rollback peer_sweep_orphans frps_wss_front_remove backhaul_udp_remove backhaul_udp_unit gre6_sit_name; do
    awk -v f="$f" '$0 ~ "^"f"\\(\\) \\{" {p=1} p {print} p && /^}/ {exit}' "$ROOT/hashem.sh"
done > "$T/fn.sh"
# shellcheck disable=SC1091
source "$T/fn.sh"
for f in peer_add_rollback peer_sweep_orphans; do
    declare -F "$f" >/dev/null || { echo "FAIL: $f not found in hashem.sh"; exit 1; }
done
hashem_ufw_release() { echo UFW_RELEASE >> "$T/calls.log"; }
reserve_service_ports() { echo RESERVE >> "$T/calls.log"; }
RED= GREEN= YELLOW= CYAN= NC=
CONFIG_DIR="$T/frp" BACKHAUL_CONFIG_DIR="$T/bh" PANEL_CONFIG_DIR="$T/panel" PEERS_FILE="$T/panel/peers.json"
fail=0
ok() { if "${@:2}"; then echo "ok:   $1"; else echo "FAIL: $1"; fail=1; fi; }
gone() { local p; for p in "$@"; do [[ ! -e "$p" ]] || return 1; done; }
there() { local p; for p in "$@"; do [[ -e "$p" ]] || return 1; done; }
called() { grep -qE "$1" "$T/calls.log"; }

# --- a failed FRP add: unit, config, GRE unit and interface go
: > "$T/calls.log"; : > "$T/active"
touch "$T/sd/frps-3.service" "$T/sd/gre-t3.service" "$T/frp/frps-3.toml" "$T/sd/frps-wss-3.service" \
      "$T/sd/frps-2.service" "$T/frp/frps-2.toml"
peer_add_rollback frps-3 gre-t3 "$T/frp/frps-3.toml" >/dev/null
ok "failed FRP add: its files are gone" gone "$T/sd/frps-3.service" "$T/sd/gre-t3.service" "$T/frp/frps-3.toml" "$T/sd/frps-wss-3.service"
ok "another tunnel's files stay" there "$T/sd/frps-2.service" "$T/frp/frps-2.toml"
ok "its service is stopped and disabled" called '^systemctl disable --now frps-3$'
ok "its GRE interface is deleted" called '^ip link del gre-t3$'
ok "the firewall and the reserved list are released" called '^UFW_RELEASE$'
ok "reserved ports rebuilt" called '^RESERVE$'

# --- a failed Backhaul add without GRE: no interface is touched
: > "$T/calls.log"
touch "$T/sd/backhaul-server-4.service" "$T/bh/server-4.toml"
peer_add_rollback backhaul-server-4 none "$T/bh/server-4.toml" >/dev/null
ok "failed Backhaul add: its files are gone" gone "$T/sd/backhaul-server-4.service" "$T/bh/server-4.toml"
ok "no interface is deleted without GRE" bash -c "! grep -q '^ip ' '$T/calls.log'"

# --- the sweep: only a numbered config without a record and without a running unit
cat > "$PEERS_FILE" <<'JSON'
{"peers": [{"id": 2, "name": "kept", "frps_svc": "frps-2"}]}
JSON
touch "$T/frp/frps.toml" "$T/frp/frps-5.toml" "$T/sd/frps-5.service" \
      "$T/bh/server-6.toml" "$T/sd/backhaul-server-6.service" \
      "$T/frp/frps-7.toml" "$T/sd/frps-7.service" "$T/bh/config.toml" "$T/bh/server.toml"
echo "frps-7" > "$T/active"
: > "$T/calls.log"
peer_sweep_orphans >/dev/null
ok "left-over configs are removed" gone "$T/frp/frps-5.toml" "$T/sd/frps-5.service" "$T/bh/server-6.toml" "$T/sd/backhaul-server-6.service"
ok "a recorded tunnel stays" there "$T/frp/frps-2.toml" "$T/sd/frps-2.service"
ok "a running unit without a record stays" there "$T/frp/frps-7.toml" "$T/sd/frps-7.service"
ok "the first tunnel's configs stay" there "$T/frp/frps.toml" "$T/bh/config.toml" "$T/bh/server.toml"
ok "the sweep releases the ports" called '^UFW_RELEASE$'

# --- peers.json that cannot be read: nothing is swept
touch "$T/frp/frps-8.toml"
echo '{broken' > "$PEERS_FILE"
peer_sweep_orphans >/dev/null
ok "an unreadable peers.json sweeps nothing" there "$T/frp/frps-8.toml" "$T/frp/frps-2.toml"
rm -f "$PEERS_FILE"
peer_sweep_orphans >/dev/null
ok "no peers.json sweeps nothing" there "$T/frp/frps-8.toml"

# --- both add paths and the update call them
n() { grep -c "$1" "$ROOT/hashem.sh"; }
ok "FRP add rolls back" test "$(n 'peer_add_rollback "\$FRPS_SVC" "\$GRE_IF"')" = 1
ok "Backhaul add rolls back" test "$(n 'peer_add_rollback "\$SVC_NAME" "\$GRE_IF" "\$CONF_FILE"')" = 1
ok "add, remove and update sweep" test "$(n '^ *peer_sweep_orphans')" -ge 4

(( fail )) && exit 1; echo "PASS test_peer_add_rollback"
