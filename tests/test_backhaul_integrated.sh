#!/usr/bin/env bash
# Backhaul inside Hashem: port entries the core accepts, multi-port configs,
# UDP forwarding, transport check, and moving tunnels made by the old separate
# Modified Backhaul script (backhaul-iranN / backhaul-kharejN) into Hashem.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin" "$T/systemd" "$T/legacy"
BACKHAUL_CONFIG_DIR="$T/etc"; INSTALL_DIR="$T/bin"; HASHEM_SYSTEMD_DIR="$T/systemd"
BACKHAUL_LEGACY_DIR="$T/legacy"; RED=""; GREEN=""; YELLOW=""; CYAN=""; NC=""
fail=0
ext() { awk -v n="$1" '$0 ~ "^"n"\\(\\) \\{" {p=1} p {print} p && /^}/ {exit}' "$ROOT/hashem.sh"; }
eval "$(grep -E '^(BACKHAUL_TRANSPORTS|backhaul_transport_ok|backhaul_udp_wanted)' "$ROOT/hashem.sh")"
for f in hostonly is_valid_port backhaul_is_v2 backhaul_ports_normalize backhaul_setup_guard backhaul_write_server_conf_v1 \
         backhaul_write_client_conf_v1 backhaul_write_server_conf_v2 backhaul_write_server_conf backhaul_write_client_conf \
         backhaul_legacy_units bh_legacy_get bh_legacy_ports cli_backhaul_migrate; do
  b="$(ext $f)"; [[ -n "$b" ]] || { echo "FAIL: $f missing"; exit 1; }; eval "$b"
done
backhaul_ensure_tls() { :; }
log_msg() { :; }
install_backhaul_binaries() { :; }
systemctl() { echo "systemctl $*" >> "$T/calls"; }
setup_backhaul_server_systemd() { echo "server-unit $1 $2" >> "$T/calls"; }
setup_backhaul_client_systemd() { echo "client-unit $1 $2" >> "$T/calls"; }
printf '#!/bin/sh\necho v0.7.2\n' > "$INSTALL_DIR/backhaul"; chmod +x "$INSTALL_DIR/backhaul"
check() { if [[ "$2" == "$3" ]]; then :; else echo "FAIL $1: got '$2' want '$3'"; fail=1; fi; }

# 1. port entries
check "spaces" "$(backhaul_ports_normalize '443 2083')" "443,2083"
check "range colon" "$(backhaul_ports_normalize '10000-10050:443, 80')" "10000-10050=443,80"
check "ip forms" "$(backhaul_ports_normalize '127.0.0.2:443=1.1.1.1:5201')" "127.0.0.2:443=1.1.1.1:5201"
for bad in "abc" "443-" "=80" "443=" "1.2.3:443"; do
  backhaul_ports_normalize "$bad" >/dev/null 2>&1 && { echo "FAIL '$bad' accepted"; fail=1; }
done

# 2. guard: transports the core has, normalized ports
backhaul_setup_guard anytls "443" >/dev/null && { echo "FAIL anytls accepted"; fail=1; }
backhaul_setup_guard xtcpmux >/dev/null && { echo "FAIL xtcpmux accepted"; fail=1; }
backhaul_setup_guard udp "53 5353" >/dev/null || { echo "FAIL udp refused"; fail=1; }
check "guard ports" "$BH_PORTS_NORM" "53,5353"
backhaul_setup_guard tcpmux "443 bad" >/dev/null 2>&1 && { echo "FAIL bad port accepted"; fail=1; }

# 3. writer: one entry per port even with spaces (the core FATALs on "443 2083")
backhaul_write_server_conf "$T/s.toml" "0.0.0.0:7100" tcpmux tok "443 2083"
grep -q '"443"' "$T/s.toml" && grep -q '"2083"' "$T/s.toml" && ! grep -q '443 2083' "$T/s.toml" \
  || { echo "FAIL multi-port"; cat "$T/s.toml"; fail=1; }

# 4. UDP only on tcp
BH_ACCEPT_UDP=1 backhaul_write_server_conf "$T/u.toml" "0.0.0.0:7100" tcp tok "443"
grep -q '^accept_udp = true' "$T/u.toml" || { echo "FAIL accept_udp missing on tcp"; fail=1; }
BH_ACCEPT_UDP=1 backhaul_write_server_conf "$T/m.toml" "0.0.0.0:7100" tcpmux tok "443"
grep -q 'accept_udp' "$T/m.toml" && { echo "FAIL accept_udp on tcpmux"; fail=1; }
backhaul_write_server_conf "$T/n.toml" "0.0.0.0:7100" tcp tok "443"
grep -q 'accept_udp' "$T/n.toml" && { echo "FAIL accept_udp without --udp"; fail=1; }

# 5. migrate old-script tunnels: a tcpmux Iran tunnel moves in, an anytls one is retired
printf '#!/bin/sh\necho v0.7.2\n' > "$T/legacy/backhaul_premium"; chmod +x "$T/legacy/backhaul_premium"
cat > "$T/legacy/iran2020.toml" <<'EOF'
[listener]
bind_addr = ":2020"

[transport]
type = "tcpmux"
nodelay = true

[security]
token = "legacy-tok"

[ports]
forwarder = "backhaul"
mapping = [
    "443",
    "10000-10050:443",
]
EOF
printf '[dialer]\nremote_addr = "203.0.113.5:3030"\n[transport]\ntype = "anytls"\n[security]\ntoken = "x"\n' > "$T/legacy/kharej3030.toml"
for n in iran2020 kharej3030; do
  printf '[Service]\nExecStart=%s/backhaul_premium -c %s/%s.toml\n' "$T/legacy" "$T/legacy" "$n" > "$T/systemd/backhaul-$n.service"
done
check "legacy get" "$(bh_legacy_get "$T/legacy/iran2020.toml" security token)" "legacy-tok"
check "legacy ports" "$(bh_legacy_ports "$T/legacy/iran2020.toml")" "443,10000-10050:443"
out=$(cli_backhaul_migrate 2>&1)
[[ -f "$T/systemd/backhaul-iran2020.service" || -f "$T/systemd/backhaul-kharej3030.service" ]] && { echo "FAIL legacy units left"; fail=1; }
grep -q '^\[server\]' "$T/etc/config.toml" && grep -q 'bind_addr = "0.0.0.0:2020"' "$T/etc/config.toml" \
  && grep -q 'transport = "tcpmux"' "$T/etc/config.toml" && grep -q 'token = "legacy-tok"' "$T/etc/config.toml" \
  && grep -q '"10000-10050=443"' "$T/etc/config.toml" || { echo "FAIL migrated server config"; cat "$T/etc/config.toml"; fail=1; }
grep -q "server-unit backhaul-server" "$T/calls" || { echo "FAIL backhaul-server unit not made"; fail=1; }
grep -q "client-unit" "$T/calls" && { echo "FAIL anytls tunnel was converted"; fail=1; }
echo "$out" | grep -q "anytls" || { echo "FAIL no notice for anytls"; echo "$out"; fail=1; }
[[ -f "$T/etc/legacy/kharej3030.toml" ]] || { echo "FAIL old config not kept"; fail=1; }
[[ -d "$T/legacy" ]] && { echo "FAIL old dir left in place"; fail=1; }

# 6. a tunnel whose core really is v2.x is left alone
mkdir -p "$T/legacy"; : > "$T/calls"
printf '#!/bin/sh\necho v2.0.0\n' > "$T/legacy/backhaul_premium"; chmod +x "$T/legacy/backhaul_premium"
printf '[listener]\nbind_addr = ":4040"\n' > "$T/legacy/iran4040.toml"
printf '[Service]\nExecStart=%s/backhaul_premium -c %s/iran4040.toml\n' "$T/legacy" "$T/legacy" > "$T/systemd/backhaul-iran4040.service"
cli_backhaul_migrate >/dev/null 2>&1
[[ -f "$T/systemd/backhaul-iran4040.service" && -f "$T/legacy/iran4040.toml" ]] || { echo "FAIL v2 tunnel touched"; fail=1; }

# 7. a setup replaces the main tunnel: the other engine's units and configs go
for f in engine_retire_others backhaul_wait_link backhaul_udp_remove backhaul_udp_unit; do
  b="$(ext $f)"; [[ -n "$b" ]] || { echo "FAIL: $f missing"; exit 1; }; eval "$b"
done
CONFIG_DIR="$T/frp"; PANEL_CONFIG_DIR="$T/panel"; TUNNEL_NAME="gre-tunnel"; mkdir -p "$CONFIG_DIR" "$PANEL_CONFIG_DIR" "$BACKHAUL_CONFIG_DIR"
frps_wss_front_remove() { echo "wss-front-removed" >> "$T/calls"; }
ip() { echo "ip $*" >> "$T/calls"; }
reset_host() {
  : > "$T/calls"; rm -f "$T/systemd"/*.service
  for u in frps frpc backhaul-server backhaul-client frps-2 backhaul-server-3 gre-tunnel gre-t2 backhaul-udp-server backhaul-udp-server-3; do : > "$T/systemd/$u.service"; done
  : > "$CONFIG_DIR/frps.toml"; : > "$CONFIG_DIR/frpc.toml"; : > "$CONFIG_DIR/frps-2.toml"
  : > "$BACKHAUL_CONFIG_DIR/config.toml"; : > "$BACKHAUL_CONFIG_DIR/client.toml"; : > "$PANEL_CONFIG_DIR/gre_mtu"
}
reset_host
engine_retire_others backhaul-client >/dev/null
for u in frps frpc backhaul-server backhaul-udp-server; do [[ -f "$T/systemd/$u.service" ]] && { echo "FAIL $u unit left"; fail=1; }; done
[[ -f "$T/systemd/backhaul-udp-server-3.service" ]] || { echo "FAIL a peer UDP companion removed"; fail=1; }
[[ -f "$T/systemd/backhaul-client.service" && -f "$BACKHAUL_CONFIG_DIR/client.toml" ]] || { echo "FAIL kept engine touched"; fail=1; }
[[ -f "$CONFIG_DIR/frps.toml" || -f "$CONFIG_DIR/frpc.toml" || -f "$BACKHAUL_CONFIG_DIR/config.toml" ]] && { echo "FAIL old configs left"; fail=1; }
[[ -f "$T/systemd/frps-2.service" && -f "$CONFIG_DIR/frps-2.toml" && -f "$T/systemd/backhaul-server-3.service" ]] || { echo "FAIL extra peers touched"; fail=1; }
[[ -f "$T/systemd/gre-tunnel.service" && -f "$PANEL_CONFIG_DIR/gre_mtu" ]] || { echo "FAIL GRE removed for GRE+Backhaul"; fail=1; }
grep -q "disable --now frps.service" "$T/calls" && grep -q "wss-front-removed" "$T/calls" || { echo "FAIL frps not stopped"; cat "$T/calls"; fail=1; }
reset_host
engine_retire_others backhaul-server nogre >/dev/null
[[ -f "$T/systemd/gre-tunnel.service" || -f "$PANEL_CONFIG_DIR/gre_mtu" ]] && { echo "FAIL main GRE left for Backhaul without GRE"; fail=1; }
grep -q "ip link del gre-tunnel" "$T/calls" || { echo "FAIL gre-tunnel interface not deleted"; fail=1; }
[[ -f "$T/systemd/gre-t2.service" ]] || { echo "FAIL peer GRE removed"; fail=1; }
reset_host
engine_retire_others frps >/dev/null
[[ -f "$T/systemd/frps.service" && -f "$CONFIG_DIR/frps.toml" ]] || { echo "FAIL FRP setup removed frps"; fail=1; }
[[ -f "$T/systemd/backhaul-server.service" || -f "$T/systemd/backhaul-client.service" ]] && { echo "FAIL FRP setup left Backhaul running"; fail=1; }

# 8. backhaul_wait_link reads the core's own log lines (from a GRE lab with v0.7.2)
sleep() { :; }
journalctl() { cat "$T/jlog"; }
wl() { printf '%s\n' "$@" > "$T/jlog"; backhaul_wait_link backhaul-client "x" 3; echo $?; }
check "link up" "$(wl '[INFO] attempting to establish a new tcpmux control channel connection...' '[INFO] control channel established successfully')" "0"
check "wrong token" "$(wl '[ERROR] failed to receive control channel response: EOF' '[ERROR] failed to receive control channel response: EOF' '[ERROR] failed to receive control channel response: EOF')" "1"
check "mismatch beats up" "$(wl '[ERROR] unexpected response from channel: 6.' '[INFO] restarting client...' '[INFO] control channel established successfully')" "1"
check "rejected config" "$(wl '[FATAL] neither server nor client configuration is properly set.')" "1"
check "no answer" "$(wl '[INFO] client with remote address 10.10.10.1:3080 started successfully')" "2"
unset -f sleep journalctl ip

(( fail )) && exit 1; echo "PASS test_backhaul_integrated"
