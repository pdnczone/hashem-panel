#!/usr/bin/env bash
# Full uninstall must remove every Hashem unit, its drop-ins and .wants links,
# and leave other software's units alone.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin" "$T/sd/multi-user.target.wants" "$T/sd/timers.target.wants"
printf '#!/bin/sh\necho "$@" >> %s/systemctl.log\n' "$T" > "$T/bin/systemctl"; chmod +x "$T/bin/systemctl"
export PATH="$T/bin:$PATH" HASHEM_SYSTEMD_DIR="$T/sd"
awk '/^purge_hashem_units\(\) \{/,/^}/' "$ROOT/hashem.sh" > "$T/fn.sh"
[[ -s "$T/fn.sh" ]] || { echo "FAIL: purge_hashem_units not found"; exit 1; }
# shellcheck disable=SC1091
source "$T/fn.sh"
fail=0
mk() { printf '[Service]\nExecStart=%s\n' "$2" > "$T/sd/$1"; ln -sf "$T/sd/$1" "$T/sd/multi-user.target.wants/$1"; }
ours=(gre-panel.service gre-tunnel.service gre-x.service frps.service frps-2.service frps-wss.service frpc.service
      backhaul-server.service backhaul-udp-server-3.service hashem-rescue-fw.service hashem-rescue-frps.service
      hashem-rescue-frpc.service hashem-rescue-dnat.service hashem-frp-ssh-tunnel.service hashem-bagher-2.service
      hashem-watchdog.service hsell-1-2.service spoof-core.service hashem-xray-1.service)
for u in "${ours[@]}"; do mk "$u" "/usr/local/bin/frps -c /etc/frp/x.toml"; done
mk my-tunnel.service "/usr/local/bin/frpc -c /etc/frp/custom.toml"     # ours by path
mk hashem-watchdog.timer ""; ln -sf "$T/sd/hashem-watchdog.timer" "$T/sd/timers.target.wants/hashem-watchdog.timer"
mkdir -p "$T/sd/gre-panel.service.d"; echo '[Service]' > "$T/sd/gre-panel.service.d/override.conf"
ln -sf "$T/sd/frps-9.service" "$T/sd/multi-user.target.wants/frps-9.service"   # dangling, ours
mk nginx.service "/usr/sbin/nginx"
mk sentinel.service "/opt/sentinel/sentinel"
mk x-ui.service "/usr/local/x-ui/x-ui"
ln -sf /nonexistent "$T/sd/multi-user.target.wants/other.service"            # dangling, not ours
purge_hashem_units
for u in "${ours[@]}" my-tunnel.service hashem-watchdog.timer; do
    [[ ! -e "$T/sd/$u" ]] || { echo "FAIL kept $u"; fail=1; }
    [[ ! -L "$T/sd/multi-user.target.wants/$u" ]] || { echo "FAIL kept link $u"; fail=1; }
done
[[ ! -e "$T/sd/gre-panel.service.d" ]] || { echo "FAIL kept drop-in"; fail=1; }
[[ ! -L "$T/sd/timers.target.wants/hashem-watchdog.timer" ]] || { echo "FAIL kept timer link"; fail=1; }
[[ ! -L "$T/sd/multi-user.target.wants/frps-9.service" ]] || { echo "FAIL kept dangling link"; fail=1; }
for u in nginx.service sentinel.service x-ui.service; do
    [[ -e "$T/sd/$u" && -L "$T/sd/multi-user.target.wants/$u" ]] || { echo "FAIL removed $u"; fail=1; }
done
[[ -L "$T/sd/multi-user.target.wants/other.service" ]] || { echo "FAIL removed foreign link"; fail=1; }
grep -q '^stop hashem-watchdog.timer' "$T/systemctl.log" || { echo "FAIL timer not stopped"; fail=1; }
[[ "$(grep -m1 '^stop' "$T/systemctl.log")" == "stop hashem-watchdog.timer" ]] || { echo "FAIL timer not stopped first"; fail=1; }
grep -q 'daemon-reload' "$T/systemctl.log" || { echo "FAIL no daemon-reload"; fail=1; }
purge_hashem_units || { echo "FAIL not idempotent"; fail=1; }
(( fail )) && exit 1; echo "PASS test_uninstall_units"
