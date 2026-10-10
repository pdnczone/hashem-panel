#!/usr/bin/env bash
# Backup must cover every config the panel writes; restore must refuse
# archives that escape the allowed directories.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
for fn in backup_file_list backup_listing_safe; do
    awk -v f="$fn" '$0 ~ "^"f"\\(\\) \\{" {p=1} p {print} p && /^}/ {p=0}' "$ROOT/hashem.sh"
done > "$T/fn.sh"
[[ -s "$T/fn.sh" ]] || { echo "FAIL functions not found"; exit 1; }
# shellcheck disable=SC1091
source "$T/fn.sh"
fail=0
chk() { [[ "$2" == "$3" ]] || { echo "FAIL $1: got '$2' want '$3'"; fail=1; }; }

export BK_ROOT="$T/root"
mkdir -p "$BK_ROOT"/etc/{frp,backhaul,gre-panel/tls,systemd/system}
for f in etc/frp/frps.toml etc/backhaul/config.toml etc/gre-panel/panel.json etc/gre-panel/alerts.json \
         etc/gre-panel/carrier.json etc/gre-panel/wss_carrier.json etc/gre-panel/auto_pool.json \
         etc/gre-panel/peer_link.json etc/gre-panel/setup.json etc/gre-panel/tls/server.crt \
         etc/systemd/system/gre-tunnel.service etc/systemd/system/backhaul-client.service; do
    : > "$BK_ROOT/$f"
done
: > "$BK_ROOT/etc/gre-panel/sessions.json"      # must NOT be backed up (volatile)
: > "$BK_ROOT/etc/gre-panel/security-audit.log" # must NOT be backed up
list=$(backup_file_list | sed "s#^$BK_ROOT/##")
for want in etc/frp/frps.toml etc/backhaul/config.toml etc/gre-panel/alerts.json etc/gre-panel/carrier.json \
            etc/gre-panel/wss_carrier.json etc/gre-panel/auto_pool.json etc/gre-panel/peer_link.json \
            etc/gre-panel/setup.json etc/gre-panel/tls/server.crt etc/systemd/system/backhaul-client.service; do
    grep -qx "$want" <<< "$list" || { echo "FAIL not backed up: $want"; fail=1; }
done
grep -q sessions.json <<< "$list" && { echo "FAIL sessions.json must not be backed up"; fail=1; }
grep -q security-audit <<< "$list" && { echo "FAIL audit log must not be backed up"; fail=1; }

printf 'etc/frp/frps.toml\netc/gre-panel/panel.json\netc/systemd/system/gre-tunnel.service\netc/backhaul/client.toml\n' > "$T/ok.txt"
backup_listing_safe "$T/ok.txt"; chk "normal listing safe" $? 0
for bad in '/etc/passwd' 'etc/frp/../../root/.ssh/authorized_keys' 'root/.bashrc' 'usr/local/bin/hashem' 'etc/cron.d/x' '../etc/frp/a'; do
    printf 'etc/frp/frps.toml\n%s\n' "$bad" > "$T/bad.txt"
    backup_listing_safe "$T/bad.txt"; chk "unsafe entry '$bad' refused" $? 1
done
[[ $fail -eq 0 ]] && echo "PASS test_backup_files" || exit 1
