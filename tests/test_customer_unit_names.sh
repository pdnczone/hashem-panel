#!/usr/bin/env bash
# Sold customer tunnels (panel/customers.go) run as hsell-<id>-<link>.service
# with their own frps copy in /usr/local/lib/hashem-sell. hashem.sh's own
# "stop/remove every tunnel" paths (remove tunnel, update, the per-engine
# cleanups) must never match them: a seller who rebuilds their own tunnel
# must not cut paying customers off. Only uninstall_all_force removes them,
# through customers_teardown. This test collects every unit glob and every
# pkill -f pattern in hashem.sh and checks none matches a customer unit.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SH="$ROOT/hashem.sh"
INSTALL_DIR=/usr/local/bin
TUNNEL_NAME=gre-tunnel
fail=0

units=(hsell-1-1 hsell-12-3 hsell-250-9)
cmdlines=("/usr/local/lib/hashem-sell/frps -c /etc/gre-panel/customers/12-3.toml"
    "/usr/local/lib/hashem-sell/backhaul -c /etc/gre-panel/customers/12-4.toml"
    "/usr/local/lib/hashem-sell/xray run -c /etc/gre-panel/customers/12-5.json")

# the uninstall-everything path (and customers_teardown itself) may match
body="$(awk '/^uninstall_all_force\(\) \{/,/^}/ {next} /^customers_teardown\(\) \{/,/^}/ {next} {print}' "$SH")"

# 1. unit globs: systemctl stop/disable/... '<glob>' and /etc/systemd/system/<glob>.service
globs=$(printf '%s\n' "$body" | grep -oE "systemctl [a-z-]+ [^;|&#]*" | grep -oE "'[^']+'" | tr -d "'")
globs+=$'\n'$(printf '%s\n' "$body" | grep -oE '/etc/systemd/system/[][A-Za-z0-9_*.?{}$-]+\.service' | sed -e 's#^/etc/systemd/system/##' -e 's#\.service$##')
globs+=$'\n'$(printf '%s\n' "$body" | grep -oE 'list-units[^|]*' | grep -oE "'[^']+'" | tr -d "'")
globs+=$'\n'$(printf '%s\n' "$body" | grep -oE '\$\{HASHEM_SYSTEMD_DIR:-/etc/systemd/system\}"?/[][A-Za-z0-9_*.?{}-]+\.service' | sed -e 's#^.*}"\{0,1\}/##' -e 's#\.service$##')
n=0
while IFS= read -r g; do
    [[ -z "$g" ]] && continue
    g="${g//\$\{TUNNEL_NAME\}/$TUNNEL_NAME}"
    g="${g//\$\{HASHEM_SYSTEMD_DIR:-\/etc\/systemd\/system\}\//}"
    n=$((n + 1))
    for u in "${units[@]}"; do
        # shellcheck disable=SC2053
        if [[ "$u" == $g || "$u.service" == $g ]]; then
            echo "FAIL: hashem.sh unit pattern '$g' matches customer unit $u"
            fail=1
        fi
    done
done <<< "$globs"
(( n > 5 )) || { echo "FAIL: found only $n unit patterns in hashem.sh: the parser is broken"; fail=1; }

# 2. pkill -f patterns, with INSTALL_DIR expanded (pkill -f is a regex on the command line)
m=0
while IFS= read -r p; do
    [[ -z "$p" ]] && continue
    p="${p//\$\{INSTALL_DIR\}/$INSTALL_DIR}"
    m=$((m + 1))
    for cmdline in "${cmdlines[@]}"; do
        if printf '%s\n' "$cmdline" | grep -qE -- "$p"; then
            echo "FAIL: hashem.sh 'pkill -f $p' would kill a customer relay ($cmdline)"
            fail=1
        fi
    done
done < <(printf '%s\n' "$body" | grep -oE 'pkill (-9 )?-f "[^"]+"' | sed -E 's/^pkill (-9 )?-f "(.*)"$/\2/' | sort -u)
(( m > 3 )) || { echo "FAIL: found only $m pkill patterns: the parser is broken"; fail=1; }

# 3. pkill/killall by process name: the customer binaries are frps, backhaul and xray
while IFS= read -r p; do
    [[ -z "$p" ]] && continue
    for name in frps backhaul xray; do
        if [[ "$name" =~ ^($p)$ ]]; then
            echo "FAIL: hashem.sh 'pkill/killall $p' (by name) would kill customer $name processes"
            fail=1
        fi
    done
done < <(printf '%s\n' "$body" | grep -oE '(pkill|killall)( -[0-9A-Za-z]+)* [A-Za-z0-9_.*^$-]+' | grep -vE ' -f$' | awk '{print $NF}' | grep -v '^-' | sort -u)

# 4. release_frps_port kills a stray frps holding a control port: never a customer's
awk '/^release_frps_port\(\) \{/,/^}/' "$SH" | grep -q '/usr/local/lib/hashem-sell/' \
    || { echo "FAIL: release_frps_port does not spare customer frps (/usr/local/lib/hashem-sell)"; fail=1; }

# 5. the customer names themselves stay what panel/customers.go writes
if [[ -f "$ROOT/panel/customers.go" ]]; then
    grep -q '"hsell-%d-%d"' "$ROOT/panel/customers.go" || { echo "FAIL: customers.go unit name is not hsell-%d-%d"; fail=1; }
    grep -q '/usr/local/lib/hashem-sell' "$ROOT/panel/customers.go" || { echo "FAIL: customers.go engine copies are not in /usr/local/lib/hashem-sell"; fail=1; }
fi

(( fail )) && exit 1
echo "PASS test_customer_unit_names ($n unit patterns, $m pkill patterns)"
