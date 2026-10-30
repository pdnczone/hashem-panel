#!/usr/bin/env bash
# The shell side of sold customer tunnels, with stubbed system commands:
#   - tools/hashem-customer.sh: kits are decoded strictly (a kit that tries
#     to inject into the config or the unit is refused), the frpc config,
#     install / status / remove with the units it writes.
#   - hashem.sh customers_teardown (full uninstall): units, chain, tc caps.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
fail=0
F() { echo "FAIL: $*"; fail=1; }

mkdir -p "$T/bin" "$T/sd" "$T/conf" "$T/lib"
for c in systemctl journalctl pkill iptables tc; do
    printf '#!/bin/sh\necho "%s $*" >> %s/calls.log\n' "$c" "$T" > "$T/bin/$c"
    chmod +x "$T/bin/$c"
done
printf '#!/bin/sh\necho 0\n' > "$T/bin/id"; chmod +x "$T/bin/id"
# journalctl: the tunnel logs in
printf '#!/bin/sh\necho "login to server success"\n' > "$T/bin/journalctl"; chmod +x "$T/bin/journalctl"
# tc actions ls: one Hashem customer cap and one foreign action
cat > "$T/bin/tc" <<EOF
#!/bin/sh
echo "tc \$*" >> $T/calls.log
if [ "\$1 \$2" = "actions ls" ]; then
  printf 'total acts 2\n\n\taction order 0:  police 0x2 rate 1Mbit burst 64Kb mtu 64Kb action drop/pass\n\tref 1 bind 0\n\tindex 1213399042 ref 1 bind 0\n\n\taction order 1:  police 0x5 rate 1Mbit\n\tindex 5 ref 1 bind 1\n'
fi
EOF
chmod +x "$T/bin/tc"
# a frpc that is already the pinned version (no download in this test)
mkdir -p "$T/lib/hc"
printf '#!/bin/sh\n[ "$1" = "-v" ] && echo 0.71.0\n' > "$T/lib/hc/frpc"; chmod +x "$T/lib/hc/frpc"
export PATH="$T/bin:$PATH" HASHEM_SYSTEMD_DIR="$T/sd" HASHEM_CUSTOMER_CONF_DIR="$T/conf" HASHEM_CUSTOMER_BIN_DIR="$T/lib/hc"

SH="$ROOT/tools/hashem-customer.sh"
mkkit() { printf 'hsk1.%s' "$(printf '%s' "$1" | base64 -w0 | tr '+/' '-_' | tr -d '=')"; }
GOOD=$'v=1\nname=hsell-3-1\nserver=203.0.113.7\nport=31000\ntransport=tcp\ntoken=AbCdEfGhIjKlMnOpQrStUvWxYz012345\nudp=1\nports=443,2083\n'
KIT=$(mkkit "$GOOD")

# config: the frpc config the kit makes
out=$(bash "$SH" config "$KIT" 2>&1) || F "config: $out"
for want in 'serverAddr = "203.0.113.7"' 'serverPort = 31000' 'auth.token = "AbCdEfGhIjKlMnOpQrStUvWxYz012345"' \
            'name = "udp-2083"' 'remotePort = 443' 'transport.protocol = "tcp"'; do
    grep -qF "$want" <<< "$out" || F "config lacks: $want"
done

# hostile or broken kits are refused before anything is written
bad() {
    local name=$1 body=$2
    if out=$(bash "$SH" config "$(mkkit "$body")" 2>&1); then F "kit with $name accepted: $out"; fi
}
bad "a quote in the server" "${GOOD/server=203.0.113.7/server=1.2.3.4\"\\nx=\"}"
bad "a command in the token" "${GOOD/token=AbCdEfGhIjKlMnOpQrStUvWxYz012345/token=\$(reboot)AAAAAAAAAAAAAAAAAA}"
bad "a newline-joined unit line" "${GOOD/name=hsell-3-1/name=hsell-3-1 ExecStart=/bin/sh}"
bad "port 0" "${GOOD/port=31000/port=0}"
bad "port 70000 in the list" "${GOOD/ports=443,2083/ports=443,70000}"
bad "an unknown transport" "${GOOD/transport=tcp/transport=wss}"
bad "version 2" "${GOOD/v=1/v=2}"
if bash "$SH" config "not-a-kit" >/dev/null 2>&1; then F "a non-kit was accepted"; fi
if bash "$SH" config "hsk1.%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%" >/dev/null 2>&1; then F "a damaged kit was accepted"; fi

# install: config (0600), unit, started; installing again updates the same unit
out=$(bash "$SH" install "$KIT" 2>&1) || F "install: $out"
U=hcust-203-0-113-7-3-1
[[ -f "$T/sd/$U.service" ]] || F "no unit $U ($(ls "$T/sd"))"
[[ -f "$T/conf/$U.toml" ]] || F "no config"
[[ "$(stat -c %a "$T/conf/$U.toml" 2>/dev/null)" == 600 ]] || F "config is not 0600"
grep -q "ExecStart=$T/lib/hc/frpc -c $T/conf/$U.toml" "$T/sd/$U.service" || F "unit ExecStart: $(cat "$T/sd/$U.service")"
grep -q "systemctl restart $U.service" "$T/calls.log" || F "not started"
grep -q "Connected" <<< "$out" || F "no success message: $out"
bash "$SH" install "$KIT" >/dev/null 2>&1 || F "install again"
[[ $(ls "$T/sd" | wc -l) -eq 1 ]] || F "a second install made another unit: $(ls "$T/sd")"
bash "$SH" status | grep -q "^$U" || F "status does not list $U"
grep -q "publishes TCP and UDP port(s) 443, 2083" <<< "$out" || F "install does not say which ports it publishes: $out"
grep -q '^\[Install\]' "$T/sd/$U.service" || F "the customer unit does not start at boot"
# a new kit for the same link (the seller moved the control port) replaces the tunnel
KIT2=$(mkkit "${GOOD/port=31000/port=31555}")
bash "$SH" install "$KIT2" >/dev/null 2>&1 || F "install the moved kit"
[[ $(ls "$T/sd" | wc -l) -eq 1 ]] || F "the moved kit left the old tunnel: $(ls "$T/sd")"
grep -q "serverPort = 31555" "$T/conf/$U.toml" || F "the moved kit did not update the config"
# a damaged download is refused and nothing is left behind
rm -f "$T/lib/hc/frpc"
printf 'not frp' > "$T/fake.tgz"
if out=$(HASHEM_FRP_TARBALL="$T/fake.tgz" bash "$SH" install "$KIT" 2>&1); then F "a bad FRP archive was accepted"; fi
grep -q "does not match its checksum" <<< "$out" || F "bad archive message: $out"
printf '#!/bin/sh\n[ "$1" = "-v" ] && echo 0.71.0\n' > "$T/lib/hc/frpc"; chmod +x "$T/lib/hc/frpc"

# remove: by name, unknown names refused, the frpc copy goes with the last tunnel
if bash "$SH" remove 'hcust-x;rm -rf /' >/dev/null 2>&1; then F "a hostile remove name was accepted"; fi
if bash "$SH" remove hcust-nope >/dev/null 2>&1; then F "removing an unknown tunnel succeeded"; fi
bash "$SH" remove "$U" >/dev/null 2>&1 || F "remove"
[[ ! -e "$T/sd/$U.service" && ! -e "$T/conf/$U.toml" ]] || F "remove left files"
[[ ! -e "$T/lib/hc" ]] || F "the frpc copy survived the last tunnel"

# hashem.sh customers_teardown
: > "$T/calls.log"
mkdir -p "$T/sd2"
touch "$T/sd2/hsell-1-1.service" "$T/sd2/hsell-12-3.service" "$T/sd2/frps-2.service"
awk '/^customers_teardown\(\) \{/,/^}/' "$ROOT/hashem.sh" > "$T/fn.sh"
[[ -s "$T/fn.sh" ]] || F "customers_teardown not found in hashem.sh"
(
    export HASHEM_SYSTEMD_DIR="$T/sd2" PANEL_CONFIG_DIR="$T/panel"
    # shellcheck disable=SC1091
    source "$T/fn.sh"
    # never the real /usr/local/lib in a test
    rm() { echo "rm $*" >> "$T/calls.log"; }
    customers_teardown
)
grep -q "systemctl disable --now hsell-1-1.service" "$T/calls.log" || F "teardown: unit 1-1 not stopped"
grep -q "systemctl disable --now hsell-12-3.service" "$T/calls.log" || F "teardown: unit 12-3 not stopped"
grep -q "frps-2" "$T/calls.log" && F "teardown touched the seller's own frps-2"
grep -q "iptables -w 5 -D INPUT -j HASHEM_CUST" "$T/calls.log" || F "teardown: chain hook not removed"
grep -q "iptables -w 5 -X HASHEM_CUST" "$T/calls.log" || F "teardown: chain not deleted"
grep -q "tc filter del dev lo egress pref 4919" "$T/calls.log" || F "teardown: tc filters not removed"
grep -q "tc actions del action police index 1213399042" "$T/calls.log" || F "teardown: the customer cap not removed"
grep -q "index 5\$" "$T/calls.log" && grep -q "actions del action police index 5$" "$T/calls.log" && F "teardown removed someone else's police action"
grep -q "rm -rf /usr/local/lib/hashem-sell $T/panel/customers" "$T/calls.log" || F "teardown: binary copy and configs not removed"

(( fail )) && exit 1
echo "PASS test_customers_shell"
