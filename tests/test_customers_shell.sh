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
for c in systemctl journalctl pkill iptables ip6tables tc; do
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
h6() { printf '%s' "$1" | sha256sum | cut -c1-6; }
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
U=hcust-203-0-113-7-$(h6 203.0.113.7)-3-1
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
# the seller switched the address to a domain: the old tunnel goes too
KIT3=$(mkkit "${GOOD/server=203.0.113.7/server=iran.example.com}")
bash "$SH" install "$KIT3" >/dev/null 2>&1 || F "install the kit with a domain"
U=hcust-iran-example-com-$(h6 iran.example.com)-3-1
[[ "$(ls "$T/sd")" == "$U.service" ]] || F "a new address left the old tunnel: $(ls "$T/sd")"
# a damaged download is refused and nothing is left behind
rm -f "$T/lib/hc/frpc"
printf 'not frp' > "$T/fake.tgz"
if out=$(HASHEM_FRP_TARBALL="$T/fake.tgz" bash "$SH" install "$KIT" 2>&1); then F "a bad FRP archive was accepted"; fi
grep -q "does not match its checksum" <<< "$out" || F "bad archive message: $out"
printf '#!/bin/sh\n[ "$1" = "-v" ] && echo 0.71.0\n' > "$T/lib/hc/frpc"; chmod +x "$T/lib/hc/frpc"

# remove: by name, unknown names refused, the frpc copy goes with the last tunnel
if bash "$SH" remove 'hcust-x;rm -rf /' >/dev/null 2>&1; then F "a hostile remove name was accepted"; fi
if bash "$SH" remove hcust-nope >/dev/null 2>&1; then F "removing an unknown tunnel succeeded"; fi
out=$(bash "$SH" remove "$U" 2>&1) || F "remove: $out ($(ls "$T/sd"))"
[[ ! -e "$T/sd/$U.service" && ! -e "$T/conf/$U.toml" ]] || F "remove left files"
[[ ! -e "$T/lib/hc" ]] || F "the frpc copy survived the last tunnel"

# Backhaul and Xray kits (version 2: the kit names the engine)
cat > "$T/bin/iptables" <<EOF
#!/bin/sh
echo "iptables \$*" >> $T/calls.log
case "\$*" in
  *"-m cgroup -h"*) echo "cgroup match options: --path path" ;;
  *"-S OUTPUT"*) [ -f $T/hook ] && cat $T/hook ;;
esac
exit 0
EOF
chmod +x "$T/bin/iptables"
sed 's/iptables/ip6tables/' "$T/bin/iptables" > "$T/bin/ip6tables"; chmod +x "$T/bin/ip6tables"
printf '#!/bin/sh\necho "203.0.113.7     STREAM 203.0.113.7"\n' > "$T/bin/getent"; chmod +x "$T/bin/getent"
printf 'nameserver 127.0.0.53\nnameserver 2001:db8::53\n' > "$T/resolv.conf"
export HASHEM_CUSTOMER_CGROUP=/system.slice/test.service HASHEM_RESOLV_CONF="$T/resolv.conf"
printf '#!/bin/sh\necho "ESTAB 0 0 10.0.0.2:40000 203.0.113.7:31000"\n' > "$T/bin/ss"; chmod +x "$T/bin/ss"
mkdir -p "$T/lib/hc"
for b in backhaul xray; do printf '#!/bin/sh\n' > "$T/lib/hc/$b"; chmod +x "$T/lib/hc/$b"; done
echo v0.7.2 > "$T/lib/hc/backhaul.version"; echo v26.3.27 > "$T/lib/hc/xray.version"
printf '#!/bin/sh\n[ "$1" = "-v" ] && echo 0.71.0\n' > "$T/lib/hc/frpc"; chmod +x "$T/lib/hc/frpc"
BH=$'v=2\nengine=backhaul\nname=hsell-4-2\nserver=203.0.113.7\nport=31000\ntransport=wssmux\ntoken=AbCdEfGhIjKlMnOpQrStUvWxYz012345\nudp=0\nports=443,2083\n'
out=$(bash "$SH" config "$(mkkit "$BH")" 2>&1) || F "backhaul config: $out"
for want in '[client]' 'remote_addr = "203.0.113.7:31000"' 'transport = "wssmux"' 'token = "AbCdEfGhIjKlMnOpQrStUvWxYz012345"' 'connection_pool = 8'; do
    grep -qF "$want" <<< "$out" || F "backhaul config lacks: $want"
done
XR=$'v=2\nengine=xray\nname=hsell-4-3\nserver=203.0.113.7\nport=31001\ntransport=xhttp\ntoken=ZbCdEfGhIjKlMnOpQrStUvWxYz012345\nudp=1\nports=443,2083\nuuid=2ea594b3-1ea8-407e-9417-dc885e0187ad\npbk=hXXHnZ9xJsb1gn564RV3n7Q9LF8mXCSdmBDC0ijQmDE\nsid=2a574b13\nsni=www.digikala.com\npath=/ee7cabe38bed\n'
out=$(bash "$SH" config "$(mkkit "$XR")" 2>&1) || F "xray config: $out"
python3 -c 'import json,sys; c=json.load(sys.stdin); assert c["routing"]["rules"][1]["port"]=="443,2083", c' <<< "$out" || F "xray config is not the expected JSON: $out"
bad "a v1 kit naming backhaul as its transport" "${BH/v=2/v=1}"
bad "an unknown engine" "${BH/engine=backhaul/engine=spoof}"
bad "Backhaul UDP on tcpmux" "${BH/udp=0/udp=1}"
bad "a quote in the SNI" "${XR/sni=www.digikala.com/sni=a\"b.com}"
bad "a JSON break in the path" "${XR/path=\/ee7cabe38bed/path=\/a\",\"x}"
bad "a bad uuid" "${XR/uuid=2ea594b3/uuid=zzz594b3}"
bad "a bad Reality key" "${XR/pbk=hXXH/pbk=h\"XH}"
bad "a user port that is the control port" "${XR/ports=443,2083/ports=443,31001}"
XK=$'v=2\nengine=xray\nname=hsell-4-4\nserver=203.0.113.7\nport=31002\ntransport=kcp\ntoken=YbCdEfGhIjKlMnOpQrStUvWxYz012345\nudp=0\nports=443\nuuid=2ea594b3-1ea8-407e-9417-dc885e0187ad\nkcppw=d6bccc0cce627f41a3995745\n'
out=$(bash "$SH" config "$(mkkit "$XK")" 2>&1) || F "xray kcp config: $out"
grep -qF '"password": "d6bccc0cce627f41a3995745"' <<< "$out" || F "xray kcp: no mKCP password"
bad "a bad mKCP password" "${XK/kcppw=d6bc/kcppw=\"d6bc}"
# Xray direct: Reality hands strangers' handshakes to the SNI, so it must be
# public and is pinned to the address it had at install
XD="${XR/engine=xray/engine=xray-direct}pk=sDhQDB0cMDj4z6R2nKcGFFdqPEw8yW2mZsS9n7h1aEc"$'\n'
out=$(bash "$SH" config "$(mkkit "$XD")" 2>&1) || F "xray-direct config: $out"
grep -qF '"target": "203.0.113.7:443", "xver": 0, "serverNames": ["www.digikala.com"]' <<< "$out" || F "xray-direct target not pinned: $out"
bad "an IP as the SNI" "${XD/sni=www.digikala.com/sni=127.0.0.1}"
bad "a LAN name as the SNI" "${XD/sni=www.digikala.com/sni=router.lan}"
bad "a single-label SNI" "${XD/sni=www.digikala.com/sni=intranet}"
for a in 127.0.0.1 10.1.2.3 192.168.1.1 172.20.0.1 169.254.169.254 100.64.0.1 0.0.0.0 ::1 fd00::1 fe80::1 fec0::1 ::ffff:127.0.0.1 ::127.0.0.1 2002:7f00:1::1; do
    printf '#!/bin/sh\necho "203.0.113.8     STREAM x"\necho "%s     STREAM x"\n' "$a" > "$T/bin/getent"
    bad "an SNI resolving to $a" "$XD"
done
printf '#!/bin/sh\nexit 2\n' > "$T/bin/getent"
bad "an SNI that does not resolve" "$XD"
# retarget: the pinned address follows the site, never to a private one
mkdir -p "$T/conf"
U=hcust-xd
printf '{"target": "203.0.113.7:443", "xver": 0, "serverNames": ["www.digikala.com"], "x": 1}\n' > "$T/conf/$U.json"
printf '#!/bin/sh\necho "203.0.113.9     STREAM x"\necho "203.0.113.7     STREAM x"\n' > "$T/bin/getent"
bash "$SH" retarget "$U" 2>&1 || F "retarget failed"
grep -qF '"target": "203.0.113.7:443"' "$T/conf/$U.json" || F "retarget moved a target still in the answers: $(cat "$T/conf/$U.json")"
printf '#!/bin/sh\necho "10.0.0.5     STREAM x"\n' > "$T/bin/getent"
bash "$SH" retarget "$U" 2>/dev/null || F "retarget failed on a private answer"
grep -qF '"target": "203.0.113.7:443"' "$T/conf/$U.json" || F "retarget followed the SNI to a private address"
printf '#!/bin/sh\necho "203.0.113.9     STREAM x"\n' > "$T/bin/getent"
bash "$SH" retarget "$U" 2>&1 || F "retarget failed"
grep -qF '"target": "203.0.113.9:443", "xver": 0, "serverNames": ["www.digikala.com"], "x": 1' "$T/conf/$U.json" || F "retarget did not follow the site: $(cat "$T/conf/$U.json")"
rm -f "$T/conf/$U.json"
printf '#!/bin/sh\necho "203.0.113.7     STREAM 203.0.113.7"\n' > "$T/bin/getent"
# install a Backhaul tunnel, then the same link sold as Xray: one tunnel, its new engine
: > "$T/calls.log"
out=$(bash "$SH" install "$(mkkit "$BH")" 2>&1) || F "backhaul install: $out"
U=hcust-203-0-113-7-$(h6 203.0.113.7)-4-2
grep -q "ExecStart=$T/lib/hc/backhaul -c $T/conf/$U.toml" "$T/sd/$U.service" || F "backhaul unit: $(cat "$T/sd/$U.service")"
grep -q "Connected" <<< "$out" || F "backhaul: no success message: $out"
grep -qx "token=AbCdEfGhIjKlMnOpQrStUvWxYz012345" "$T/conf/$U.id" || F "backhaul: no link id file"
grep -q "^ExecStartPre=+/bin/bash $T/lib/hc/hashem-customer.sh guard $U$" "$T/sd/$U.service" || F "backhaul unit: no fence: $(cat "$T/sd/$U.service")"
grep -q "^ExecStopPost=+/bin/bash $T/lib/hc/hashem-customer.sh unguard $U$" "$T/sd/$U.service" || F "backhaul unit: the fence is not removed on stop"
[[ -x "$T/lib/hc/hashem-customer.sh" ]] || F "the installer was not kept for the fence"
grep -q "skip_optz = true" "$T/conf/$U.toml" || F "backhaul client tunes the server's sysctls"
# the fence: the seller's control port, 127.0.0.1 on the sold ports, the resolvers; the rest rejected
: > "$T/calls.log"
bash "$SH" guard "$U" >/dev/null 2>&1 || F "guard failed: $(cat "$T/calls.log")"
C="HC$(printf '%s' "$U" | sha256sum | cut -c1-10)"
for want in "iptables -w 5 -N $C" "iptables -w 5 -A $C -o lo -d 127.0.0.1 -p tcp --dport 443 -j RETURN" \
    "iptables -w 5 -A $C -o lo -d 127.0.0.1 -p tcp --dport 2083 -j RETURN" "iptables -w 5 -A $C -d 203.0.113.7 -p tcp --dport 31000 -j RETURN" \
    "iptables -w 5 -A $C -d 127.0.0.53 -p udp --dport 53 -j RETURN" "iptables -w 5 -A $C -j REJECT" \
    "iptables -w 5 -I OUTPUT 1 -m cgroup --path /system.slice/test.service -j $C"; do
    grep -qxF -- "$want" "$T/calls.log" || F "guard lacks: $want"
done
grep -q -- "-p udp --dport 443" "$T/calls.log" && F "guard let UDP through on a TCP-only tunnel"
grep -q "^iptables .*2001:db8::53" "$T/calls.log" && F "an IPv6 resolver went into iptables"
grep -qxF "ip6tables -w 5 -A $C -d 2001:db8::53 -p udp --dport 53 -j RETURN" "$T/calls.log" || F "guard: no IPv6 resolver rule"
grep -qxF "ip6tables -w 5 -A $C -j REJECT" "$T/calls.log" || F "guard: IPv6 is not fenced"
grep -q "^ip6tables .*-o lo" "$T/calls.log" && F "guard: IPv6 loopback allowed"
echo "-A OUTPUT -m cgroup --path /system.slice/test.service -j $C" > "$T/hook"
: > "$T/calls.log"
bash "$SH" unguard "$U" >/dev/null 2>&1 || F "unguard failed"
for want in "iptables -w 5 -D OUTPUT -m cgroup --path /system.slice/test.service -j $C" "iptables -w 5 -F $C" "iptables -w 5 -X $C"; do
    grep -qxF -- "$want" "$T/calls.log" || F "unguard lacks: $want ($(cat "$T/calls.log"))"
done
rm -f "$T/hook"
if bash "$SH" guard 'hcust-x;reboot' >/dev/null 2>&1; then F "guard took a hostile unit name"; fi
# no cgroup match: a Backhaul kit is refused before anything changes
mv "$T/bin/iptables" "$T/bin/iptables.ok"
printf '#!/bin/sh\nexit 0\n' > "$T/bin/iptables"; chmod +x "$T/bin/iptables"
BH2=${BH/name=hsell-4-2/name=hsell-4-9}
BH2=${BH2/token=AbCd/token=QbCd}
if out=$(bash "$SH" install "$(mkkit "$BH2")" 2>&1); then F "a Backhaul kit installed without the fence: $out"; fi
grep -q "cannot fence" <<< "$out" || F "no fence message: $out"
ls "$T/sd" | grep -q -- "-4-9.service" && F "a refused Backhaul install left a unit"
mv -f "$T/bin/iptables.ok" "$T/bin/iptables"
XS=${XR/name=hsell-4-3/name=hsell-4-2}
XS=${XS/token=ZbCd/token=AbCd}
bash "$SH" install "$(mkkit "$XS")" >/dev/null 2>&1 || F "the same link as xray"
[[ ! -e "$T/conf/$U.toml" && -f "$T/conf/$U.json" ]] || F "the engine change left the old config: $(ls "$T/conf")"
grep -q "ExecStart=$T/lib/hc/xray run -c $T/conf/$U.json" "$T/sd/$U.service" || F "xray unit: $(cat "$T/sd/$U.service")"
grep -q "Environment=GODEBUG=multipathtcp=0" "$T/sd/$U.service" || F "xray unit lacks GODEBUG"
bash "$SH" remove "$U" >/dev/null 2>&1 || F "remove the xray tunnel"
[[ ! -e "$T/conf/$U.json" && ! -e "$T/conf/$U.id" ]] || F "remove left files: $(ls "$T/conf")"
# a damaged Backhaul download is refused
rm -rf "$T/lib/hc"
if out=$(HASHEM_BACKHAUL_TARBALL="$T/fake.tgz" bash "$SH" install "$(mkkit "$BH")" 2>&1); then F "a bad Backhaul archive was accepted"; fi
grep -q "does not match its checksum" <<< "$out" || F "bad backhaul archive message: $out"
[[ ! -e "$T/sd/$U.service" ]] || F "a failed Backhaul install left a unit"

# Bagher: a locked-down user, its key line, a reply code; remove takes the line away
mkdir -p "$T/lib/hc" "$T/home/hcust" "$T/sshd"
printf '#!/bin/sh\nexit 0\n' > "$T/bin/ss"  # nothing listens
printf '#!/bin/sh\n[ "$1" = "-v" ] && echo 0.71.0\n' > "$T/lib/hc/frpc"; chmod +x "$T/lib/hc/frpc"
cat > "$T/bin/getent" <<EOF
#!/bin/sh
case "\$1" in
  passwd) [ "\$2" = hcust ] && grep -q "^useradd" "$T/calls.log" && echo "hcust:x:998:998::\${GETENT_HOME:-/var/lib/hashem-customer/hcust}:\${GETENT_SHELL:-/usr/sbin/nologin}" ;;
  *) echo "203.0.113.7     STREAM 203.0.113.7" ;;
esac
EOF
chmod +x "$T/bin/getent"
for c in useradd usermod chown; do printf '#!/bin/sh\necho "%s $*" >> %s/calls.log\n' "$c" "$T" > "$T/bin/$c"; chmod +x "$T/bin/$c"; done
cat > "$T/bin/sshd" <<EOF
#!/bin/sh
echo "sshd \$*" >> "$T/calls.log"
[ "\$1" = -t ] && exit \${SSHD_T_FAIL:-0}
[ "\$1" = -T ] || exit 0
echo "port 2222"
if [ "\$2" = -C ] && [ -s "$T/sshd.d/hashem-customer.conf" ] && [ -z "\$SSHD_NO_INCLUDE" ]; then
    printf 'allowtcpforwarding remote\nallowstreamlocalforwarding no\nauthorizedkeysfile %s\n' "\$HASHEM_CUSTOMER_AUTH_KEYS"
else
    printf 'allowtcpforwarding yes\nallowstreamlocalforwarding yes\nauthorizedkeysfile .ssh/authorized_keys\n'
fi
EOF
chmod +x "$T/bin/sshd"
mkdir -p "$T/sshd.d"
export HASHEM_SSHD_DROPIN="$T/sshd.d/hashem-customer.conf" HASHEM_CUSTOMER_AUTH_KEYS="$T/hcust.keys"
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl root@fo" > "$T/sshd/ssh_host_ed25519_key.pub"
export HASHEM_SSH_DIR="$T/sshd"
BG=$'v=2\nengine=bagher\nname=hsell-5-1\nserver=203.0.113.7\nport=31500\ntransport=ssh\ntoken=BbCdEfGhIjKlMnOpQrStUvWxYz012345\nudp=1\nports=443\nsshpub=AAAAC3NzaC1lZDI1NTE5AAAAIEu8Pp9xvOHGCZnNqY2UtFzrW1PZ3Zp6YyUq9o3gJmJk\n'
out=$(bash "$SH" config "$(mkkit "$BG")" 2>&1) || F "bagher config: $out"
grep -qF 'serverAddr = "127.0.0.1"' <<< "$out" && grep -qF 'serverPort = 31500' <<< "$out" && grep -qF 'transport.protocol = "tcp"' <<< "$out" \
    || F "bagher frpc config: $out"
bad "a Bagher key that is not ed25519" "${BG/sshpub=AAAAC3NzaC1lZDI1NTE5/sshpub=AAAAB3NzaC1yc2EAAAADAQAB}"
bad "a quote in the Bagher key" "${BG/sshpub=AAAAC3/sshpub=\"AAAC3}"
: > "$T/calls.log"
out=$(bash "$SH" install "$(mkkit "$BG")" 2>&1) || F "bagher install: $out"
U=hcust-203-0-113-7-$(h6 203.0.113.7)-5-1
AK="$T/hcust.keys"
[[ "$(cat "$AK" 2>/dev/null)" == "command=\"/bin/false\",restrict,port-forwarding,permitlisten=\"127.0.0.1:31500\",permitopen=\"127.0.0.1:31500\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEu8Pp9xvOHGCZnNqY2UtFzrW1PZ3Zp6YyUq9o3gJmJk $U" ]] \
    || F "bagher authorized_keys: $(cat "$AK" 2>&1)"
[[ "$(stat -c %a "$AK" 2>/dev/null)" == 644 ]] || F "the keys file is not 0644 (root's)"
grep -q "useradd --system --create-home --home-dir /var/lib/hashem-customer/hcust" "$T/calls.log" || F "bagher user: $(cat "$T/calls.log")"
for want in "Match User hcust" "AuthorizedKeysFile $AK" "AllowTcpForwarding remote" "AllowStreamLocalForwarding no" "PermitOpen none" "ForceCommand /bin/false"; do
    grep -qF -- "$want" "$HASHEM_SSHD_DROPIN" || F "sshd rules lack $want: $(cat "$HASHEM_SSHD_DROPIN" 2>&1)"
done
grep -q "usermod -p \* hcust" "$T/calls.log" || F "the user is left locked (sshd refuses it without PAM)"
code=$(grep -oE 'hsr1\.[A-Za-z0-9_-]+' <<< "$out")
[[ -n "$code" ]] || F "no reply code: $out"
dec=$(printf '%s' "${code#hsr1.}" | tr '_-' '/+'); while (( ${#dec} % 4 )); do dec="$dec="; done
dec=$(printf '%s' "$dec" | base64 -d)
for want in "v=1" "name=hsell-5-1" "port=2222" "user=hcust" "key=ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"; do
    grep -qx -- "$want" <<< "$dec" || F "reply code lacks $want: $dec"
done
grep -q "ExecStart=$T/lib/hc/frpc -c $T/conf/$U.toml" "$T/sd/$U.service" || F "bagher unit: $(cat "$T/sd/$U.service")"
# another seller's line stays; remove takes only this one
echo "ssh-ed25519 AAAAOTHER other-seller ${U}0" >> "$AK"
bash "$SH" remove "$U" >/dev/null 2>&1 || F "remove the bagher tunnel"
[[ "$(cat "$AK")" == "ssh-ed25519 AAAAOTHER other-seller ${U}0" ]] || F "remove: authorized_keys is now: $(cat "$AK")"
# sshd that does not read the drop-in, or refuses it: no tunnel, no rules left behind
rm -f "$HASHEM_SSHD_DROPIN" "$AK"; : > "$T/calls.log"
out=$(SSHD_NO_INCLUDE=1 bash "$SH" install "$(mkkit "$BG")" 2>&1) && F "installed with sshd not applying the rules"
grep -q "Include" <<< "$out" || F "no Include hint: $out"
[[ ! -e "$HASHEM_SSHD_DROPIN" && ! -s "$AK" ]] || F "rules or key left after sshd ignored them"
out=$(SSHD_T_FAIL=1 bash "$SH" install "$(mkkit "$BG")" 2>&1) && F "installed with sshd -t failing"
[[ ! -e "$HASHEM_SSHD_DROPIN" ]] || F "a drop-in sshd -t refused was left"
# a user of that name that is not the tunnels' is never taken over
out=$(GETENT_SHELL=/bin/bash bash "$SH" install "$(mkkit "$BG")" 2>&1) && F "took over an existing login user"
grep -q "not the tunnels'" <<< "$out" || F "existing user: $out"
# the control port is another service's: the key could open it
printf '#!/bin/sh\necho "LISTEN 0 511 127.0.0.1:31500 0.0.0.0:* users:((\\"redis-server\\",pid=9,fd=6))"\n' > "$T/bin/ss"; chmod +x "$T/bin/ss"
out=$(bash "$SH" install "$(mkkit "$BG")" 2>&1) && F "installed on a port another service holds"
grep -q "already in use" <<< "$out" || F "busy port: $out"
printf '#!/bin/sh\necho "LISTEN 0 128 127.0.0.1:31500 0.0.0.0:* users:((\\"sshd\\",pid=9,fd=6))"\n' > "$T/bin/ss"
bash "$SH" install "$(mkkit "$BG")" >/dev/null 2>&1 || F "a reinstall refused the tunnel's own sshd listener"
rm -f "$T/bin/ss"
bash "$SH" remove all >/dev/null 2>&1 || true
unset HASHEM_SSH_DIR

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
