#!/usr/bin/env bash
# hashem-customer.sh: the foreign end of a tunnel bought from a Hashem seller.
#
# The seller's panel (Customers tab) gives a kit, "hsk1.<...>", for each of
# your foreign servers. On that server run:
#
#   sudo bash hashem-customer.sh install hsk1.XXXX   # set up or update the tunnel
#                                          (--yes: no question, for scripts)
#   sudo bash hashem-customer.sh status              # every tunnel and its state
#   sudo bash hashem-customer.sh remove NAME|all     # take tunnels away
#   bash hashem-customer.sh config hsk1.XXXX         # print the tunnel's config only
#
# The kit says which engine the seller sold: FRP (frpc v0.71.0), Backhaul
# (v0.7.2), Xray (Xray-core v26.3.27, reverse or direct) or Bagher (SSH:
# the seller's server logs in to this one's sshd as a locked-down user and
# frpc v0.71.0 runs through it; install prints a reply code for the
# seller, `reply hsk1.XXXX` prints it again). The installer
# downloads that engine from its official release (sha256 checked) to
# /usr/local/lib/hashem-customer, writes its config to /etc/hashem-customer
# and runs one systemd unit per tunnel. The kit is data: every value is
# checked and the config is written here, never taken from the kit. Your
# services keep running on this server; users reach them on the same ports
# on the seller's Iran server. No Hashem panel and no license are needed.
set -euo pipefail

FRP_VERSION="0.71.0"
FRP_SHA256_amd64="84f27e39f11169f7adcef8e8b70c9329de17747b1f14dad9fb95eef5682ea716"
FRP_SHA256_arm64="f33c293c275d8fc68c654b6fba8f10b2551d6463d09a9fc9cffb7227eae82266"
BACKHAUL_VERSION="v0.7.2"
BACKHAUL_SHA256_amd64="57bf95c2eabeddb1152d2e94ac42f4310883ce0fb909ee2a57bd53503b2dabbc"
BACKHAUL_SHA256_arm64="9a424c97ff16fc3f682e8314c418790d2b5bf3136e008edbb6cd402ea00999f6"
XRAY_VERSION="v26.3.27"
XRAY_SHA256_amd64="23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae"
XRAY_SHA256_arm64="4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c"
BIN_DIR="${HASHEM_CUSTOMER_BIN_DIR:-/usr/local/lib/hashem-customer}"
CONF_DIR="${HASHEM_CUSTOMER_CONF_DIR:-/etc/hashem-customer}"
UNIT_DIR="${HASHEM_SYSTEMD_DIR:-/etc/systemd/system}"

die() { echo "[!] $*" >&2; exit 1; }
say() { echo "[*] $*"; }

# kit_decode KIT: sets K_ENGINE K_NAME K_SERVER K_PORT K_TRANSPORT K_TOKEN
# K_UDP K_PORTS (and for Xray K_UUID K_PBK K_SID K_SNI K_PATH K_KCPPW), each
# checked against a strict pattern (the kit is pasted, never trusted).
kit_decode() {
    local kit=$1 body line key val
    [[ "$kit" =~ ^hsk1\.[A-Za-z0-9_-]{20,4000}$ ]] || die "not a Hashem kit (it starts with hsk1.): copy it again from the seller"
    body=${kit#hsk1.}
    body=$(printf '%s' "$body" | tr '_-' '/+')
    while (( ${#body} % 4 )); do body="${body}="; done
    body=$(printf '%s' "$body" | base64 -d 2>/dev/null) || die "the kit is damaged: copy it again"
    K_V="" K_NAME="" K_SERVER="" K_PORT="" K_TRANSPORT="" K_TOKEN="" K_UDP="" K_PORTS="" K_ENGINE=""
    K_UUID="" K_PBK="" K_SID="" K_SNI="" K_PATH="" K_KCPPW="" K_PK="" K_SSHPUB=""
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        key=${line%%=*}
        val=${line#*=}
        case "$key" in
            v) K_V=$val ;;
            name) K_NAME=$val ;;
            server) K_SERVER=$val ;;
            port) K_PORT=$val ;;
            transport) K_TRANSPORT=$val ;;
            token) K_TOKEN=$val ;;
            udp) K_UDP=$val ;;
            ports) K_PORTS=$val ;;
            engine) K_ENGINE=$val ;;
            uuid) K_UUID=$val ;;
            pbk) K_PBK=$val ;;
            sid) K_SID=$val ;;
            sni) K_SNI=$val ;;
            path) K_PATH=$val ;;
            kcppw) K_KCPPW=$val ;;
            pk) K_PK=$val ;;
            sshpub) K_SSHPUB=$val ;;
        esac
    done <<< "$body"
    case "$K_V" in
        1) K_ENGINE=frp ;;  # kits from before Backhaul and Xray
        2) ;;
        *) die "this kit needs a newer hashem-customer.sh (kit version ${K_V:-?})" ;;
    esac
    [[ "$K_ENGINE" =~ ^(frp|backhaul|xray|xray-direct|bagher)$ ]] || die "kit: bad engine"
    [[ "$K_NAME" =~ ^hsell-[0-9]{1,6}-[0-9]{1,4}$ ]] || die "kit: bad name"
    [[ "$K_SERVER" =~ ^[A-Za-z0-9]([A-Za-z0-9.:-]{0,251}[A-Za-z0-9])?$ ]] || die "kit: bad server address"
    valid_port "$K_PORT" || die "kit: bad control port"
    case "$K_ENGINE" in
        frp) [[ "$K_TRANSPORT" =~ ^(tcp|kcp|quic|websocket)$ ]] || die "kit: bad transport" ;;
        backhaul) [[ "$K_TRANSPORT" =~ ^(tcp|tcpmux|ws|wsmux|wss|wssmux)$ ]] || die "kit: bad transport" ;;
        bagher) [[ "$K_TRANSPORT" == ssh ]] || die "kit: bad transport"
            [[ "$K_SSHPUB" =~ ^AAAAC3NzaC1lZDI1NTE5AAAAI[A-Za-z0-9+/]{43}$ ]] || die "kit: bad SSH key" ;;
        xray|xray-direct) [[ "$K_TRANSPORT" =~ ^(reality|xhttp|grpc|kcp)$ ]] || die "kit: bad transport"
            [[ "$K_UUID" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || die "kit: bad uuid"
            if [[ "$K_TRANSPORT" == kcp ]]; then
                [[ "$K_KCPPW" =~ ^[0-9a-f]{8,64}$ ]] || die "kit: bad mKCP password"
            else
                [[ "$K_PBK" =~ ^[A-Za-z0-9_-]{43}$ ]] || die "kit: bad Reality key"
                [[ "$K_SID" =~ ^[0-9a-f]{0,16}$ ]] || die "kit: bad Reality short id"
                [[ "$K_SNI" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$ ]] || die "kit: bad SNI"
                [[ "$K_ENGINE" != xray-direct || "$K_PK" =~ ^[A-Za-z0-9_-]{43}$ ]] || die "kit: bad Reality private key"
            fi
            case "$K_TRANSPORT" in
                xhttp) [[ "$K_PATH" =~ ^/[A-Za-z0-9]{1,32}$ ]] || die "kit: bad path" ;;
                grpc) [[ "$K_PATH" =~ ^[A-Za-z0-9]{1,32}$ ]] || die "kit: bad service name" ;;
            esac ;;
    esac
    [[ "$K_TOKEN" =~ ^[A-Za-z0-9]{16,64}$ ]] || die "kit: bad token"
    [[ "$K_UDP" =~ ^[01]$ ]] || die "kit: bad udp flag"
    [[ "$K_PORTS" =~ ^[0-9]{1,5}(,[0-9]{1,5}){0,63}$ ]] || die "kit: bad port list"
    local p
    for p in ${K_PORTS//,/ }; do
        valid_port "$p" || die "kit: bad port $p"
        [[ "$p" != "$K_PORT" ]] || die "kit: port $p is also the control port"
    done
    [[ "$K_ENGINE" != backhaul || "$K_UDP" == 0 || "$K_TRANSPORT" == tcp ]] || die "kit: Backhaul carries UDP on tcp only"
    if [[ "$K_ENGINE" == xray-direct && "$K_TRANSPORT" != kcp ]]; then
        public_name "$K_SNI" || die "kit: the SNI must be a public domain name"
        resolve_sni
    fi
}

# public_name NAME: a dotted public domain (as the panel's custPublicName).
public_name() {
    local n=${1,,} tld
    [[ "$n" == *.* && ! "$n" =~ ^[0-9.]+$ ]] || return 1
    tld=${n##*.}
    [[ "$tld" =~ ^[a-z]{2,}$ ]] || return 1
    case "$tld" in localhost|local|internal|lan|home|corp|intranet|arpa|test|invalid|example) return 1 ;; esac
    [[ "${n%%.*}" != localhost ]]
}

# public_addr ADDR: not loopback, private, link-local, CGNAT, multicast or
# another special range.
public_addr() {
    local a=${1,,} o1 o2 o3 o4
    if [[ "$a" == *:* ]]; then
        [[ "$a" =~ ^::ffff:([0-9.]+)$ ]] && { public_addr "${BASH_REMATCH[1]}"; return; }
        [[ ! "$a" =~ ^(::1?$|f[cd]|fe[89ab]|ff|2001:db8:|64:ff9b:|::ffff:) ]]
        return
    fi
    [[ "$a" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
    IFS=. read -r o1 o2 o3 o4 <<< "$a"
    : "$o4"
    (( o1 == 0 || o1 == 10 || o1 == 127 || o1 >= 224 )) && return 1
    (( o1 == 169 && o2 == 254 )) && return 1
    (( o1 == 172 && o2 >= 16 && o2 <= 31 )) && return 1
    (( o1 == 192 && o2 == 168 )) && return 1
    (( o1 == 100 && o2 >= 64 && o2 <= 127 )) && return 1
    (( o1 == 192 && o2 == 0 && o3 == 0 )) && return 1
    (( o1 == 198 && (o2 == 18 || o2 == 19) )) && return 1
    return 0
}

# resolve_sni: SNI_TARGET, where Reality hands the handshakes it does not
# recognise (anyone's who connects to the tunnel's port). The kit names the
# SNI, so it must not lead to this server or its network: every answer must
# be public, and the address is pinned (a later DNS answer cannot move it).
SNI_TARGET=""
resolve_sni() {
    local a ips v4="" any=""
    ips=$(getent ahosts "$K_SNI" 2>/dev/null | awk '!seen[$1]++ { print $1 }') || true
    [[ -n "$ips" ]] || die "the SNI ${K_SNI} does not resolve on this server: check its DNS, or ask the seller for another SNI"
    for a in $ips; do
        public_addr "$a" || die "the SNI ${K_SNI} points at ${a}, an address of this server or its network: anyone could reach it through the tunnel's port. Ask the seller for another SNI."
        [[ -n "$v4" || "$a" == *:* ]] || v4=$a
        [[ -n "$any" ]] || any=$a
    done
    if [[ -n "$v4" ]]; then SNI_TARGET="$v4:443"; else SNI_TARGET="[$any]:443"; fi
}

valid_port() { [[ "$1" =~ ^[0-9]{1,5}$ ]] && (( 10#$1 >= 1 && 10#$1 <= 65535 )); }

# unit_name: one per seller server and sold link (the kit's name), so
# tunnels bought from two sellers never share a name (the hash of the exact
# address keeps a.b.c and a-b-c, or two long names, apart), and a new kit
# for the same link (another control port) replaces the old tunnel.
unit_name() {
    local s h
    s=$(printf '%s' "$K_SERVER" | tr -c 'A-Za-z0-9' '-' | tr -s '-' | cut -c1-40)
    s=${s%-}
    h=$(printf '%s' "$K_SERVER" | sha256sum | cut -c1-6)
    echo "hcust-${s#-}-${h}-${K_NAME#hsell-}"
}

# confirm: the kit decides which local ports become public on the seller's
# server. Say which, warn about services bound to this server only, and ask.
confirm() {
    local p ans local_only=""
    local protos=TCP
    [[ "$K_UDP" == 1 ]] && protos="TCP and UDP"
    say "This tunnel publishes ${protos} port(s) ${K_PORTS//,/, } of this server on ${K_SERVER}."
    [[ "$K_ENGINE" != xray-direct ]] || say "The seller's server connects to port ${K_PORT} of this server: let it through your firewall."
    [[ "$K_ENGINE" != bagher ]] || say "The seller's server logs in to this server's sshd as the user ${SSH_USER} (made for it: no password, no shell), which may only listen on the tunnel's port ${K_PORT} on 127.0.0.1 (sshd's rules for it are in ${SSHD_DROPIN})."
    [[ "$K_ENGINE" != backhaul ]] || say "Backhaul lets the seller's server choose what this server connects to: a firewall fence keeps the tunnel to ${K_SERVER}:${K_PORT} and 127.0.0.1 on these ports."
    if command -v ss >/dev/null 2>&1; then
        for p in ${K_PORTS//,/ }; do
            if ss -Hltn "sport = :$p" 2>/dev/null | awk '{print $4}' | grep -qE '^(127\.|\[::1\]|::1)'; then
                if ! ss -Hltn "sport = :$p" 2>/dev/null | awk '{print $4}' | grep -qvE '^(127\.|\[::1\]|::1)'; then
                    local_only="$local_only $p"
                fi
            fi
        done
    fi
    [[ -z "$local_only" ]] || echo "[!] Port(s)${local_only} are open on this server only (127.0.0.1): the tunnel makes them reachable from the internet." >&2
    [[ "$ASSUME_YES" == 1 ]] && return 0
    if [[ -r /dev/tty ]] && { : < /dev/tty; } 2>/dev/null; then
        read -r -p "Continue? (y/N): " ans < /dev/tty || ans=""
        [[ "$ans" =~ ^[Yy]$ ]] || die "aborted: nothing was changed"
    fi
}

frpc_config() {
    local p addr=$K_SERVER proto=$K_TRANSPORT
    # Bagher: frps is on the seller's server, reached through 127.0.0.1 here
    [[ "$K_ENGINE" == bagher ]] && addr=127.0.0.1 proto=tcp
    echo "# Hashem: tunnel to ${K_SERVER} (${K_NAME}). Written by hashem-customer.sh."
    printf 'serverAddr = "%s"\nserverPort = %s\n' "$addr" "$K_PORT"
    printf 'auth.method = "token"\nauth.token = "%s"\n' "$K_TOKEN"
    printf 'loginFailExit = false\n'
    printf 'transport.protocol = "%s"\ntransport.tcpMux = true\ntransport.poolCount = 10\n' "$proto"
    printf 'transport.heartbeatInterval = 30\ntransport.heartbeatTimeout = 90\n'
    printf 'log.to = "console"\nlog.level = "info"\n'
    for p in ${K_PORTS//,/ }; do
        printf '\n[[proxies]]\nname = "tcp-%s"\ntype = "tcp"\nlocalIP = "127.0.0.1"\nlocalPort = %s\nremotePort = %s\n' "$p" "$p" "$p"
        if [[ "$K_UDP" == 1 ]]; then
            printf '\n[[proxies]]\nname = "udp-%s"\ntype = "udp"\nlocalIP = "127.0.0.1"\nlocalPort = %s\nremotePort = %s\n' "$p" "$p" "$p"
        fi
    done
}

backhaul_config() {
    echo "# Hashem: tunnel to ${K_SERVER} (${K_NAME}). Written by hashem-customer.sh."
    echo "[client]"
    if [[ "$K_SERVER" == *:* ]]; then
        printf 'remote_addr = "[%s]:%s"\n' "$K_SERVER" "$K_PORT"
    else
        printf 'remote_addr = "%s:%s"\n' "$K_SERVER" "$K_PORT"
    fi
    printf 'transport = "%s"\ntoken = "%s"\n' "$K_TRANSPORT" "$K_TOKEN"
    printf 'connection_pool = 8\nnodelay = true\nretry_interval = 3\nkeepalive_period = 75\n'
    printf 'sniffer = false\nweb_port = 0\nsniffer_log = ""\nlog_level = "info"\nskip_optz = true\n'
}

# xray_stream: the link's streamSettings on this (dialing) end, as the
# seller's panel builds them (panel/xray_config.go, xrayStream).
xray_stream() {
    local sock='"sockopt": {"customSockopt": [{"level": "6", "network": "tcp", "opt": "25", "system": "linux", "type": "int", "value": "16384"}], "tcpKeepAliveIdle": 10, "tcpKeepAliveInterval": 5, "tcpUserTimeout": 25000}'
    local reality
    reality=$(printf '"security": "reality", "realitySettings": {"fingerprint": "chrome", "password": "%s", "serverName": "%s", "shortId": "%s"}' "$K_PBK" "$K_SNI" "$K_SID")
    case "$K_TRANSPORT" in
        reality) printf '{"network": "raw", %s, %s}' "$reality" "$sock" ;;
        xhttp) printf '{"network": "xhttp", %s, "xhttpSettings": {"mode": "auto", "path": "%s"}, %s}' "$reality" "$K_PATH" "$sock" ;;
        grpc) printf '{"network": "grpc", %s, "grpcSettings": {"serviceName": "%s"}, %s}' "$reality" "$K_PATH" "$sock" ;;
        kcp) printf '{"network": "kcp", "security": "none", "kcpSettings": {"congestion": true, "downlinkCapacity": 100, "mtu": 1350, "tti": 20, "uplinkCapacity": 20}, "finalmask": {"udp": [{"type": "mkcp-aes128gcm", "settings": {"password": "%s"}}]}}' "$K_KCPPW" ;;
    esac
}

# xray_config: the foreign end of a reverse link. It dials the seller's
# server and hands the connections that come back only to this server's own
# 127.0.0.1 on the sold ports; everything else goes to the blackhole.
xray_config() {
    local stream flow="" vnext tag i net=tcp
    stream=$(xray_stream)
    [[ "$K_TRANSPORT" == reality ]] && flow=', "flow": "xtls-rprx-vision"'
    [[ "$K_UDP" == 1 ]] && net="tcp,udp"
    vnext=$(printf '{"address": "%s", "port": %s, "id": "%s", "encryption": "none"%s, "reverse": {"tag": "from-iran"}}' "$K_SERVER" "$K_PORT" "$K_UUID" "$flow")
    printf '{\n  "log": {"access": "none", "loglevel": "warning"},\n  "inbounds": null,\n  "outbounds": [\n'
    printf '    {"protocol": "blackhole", "tag": "block"},\n'
    for i in 1 2 3 4; do
        tag=tunnel
        (( i > 1 )) && tag="tunnel-$i"
        printf '    {"tag": "%s", "protocol": "vless", "settings": %s, "streamSettings": %s},\n' "$tag" "$vnext" "$stream"
    done
    printf '    {"protocol": "freedom", "tag": "direct"},\n'
    printf '    {"protocol": "blackhole", "tag": "probe", "settings": {"response": {"type": "http"}}}\n  ],\n'
    printf '  "routing": {"domainStrategy": "AsIs", "rules": [\n'
    printf '    {"inboundTag": ["from-iran"], "domain": ["full:probe.hashem"], "outboundTag": "probe"},\n'
    printf '    {"inboundTag": ["from-iran"], "ip": ["127.0.0.1"], "port": "%s", "network": "%s", "outboundTag": "direct"},\n' "$K_PORTS" "$net"
    printf '    {"inboundTag": ["from-iran"], "outboundTag": "block"}\n  ]}\n}\n'
}

# xray_direct_stream: the server end's streamSettings (xrayStream, server).
xray_direct_stream() {
    local mux='"sockopt": {"customSockopt": [{"level": "6", "network": "tcp", "opt": "25", "system": "linux", "type": "int", "value": "16384"}]}'
    local reality
    reality=$(printf '"security": "reality", "realitySettings": {"target": "%s", "xver": 0, "serverNames": ["%s"], "privateKey": "%s", "shortIds": ["%s"]}' "$SNI_TARGET" "$K_SNI" "$K_PK" "$K_SID")
    case "$K_TRANSPORT" in
        reality) printf '{"network": "raw", %s}' "$reality" ;;
        xhttp) printf '{"network": "xhttp", %s, "xhttpSettings": {"mode": "auto", "path": "%s"}, %s}' "$reality" "$K_PATH" "$mux" ;;
        grpc) printf '{"network": "grpc", %s, "grpcSettings": {"serviceName": "%s"}, %s}' "$reality" "$K_PATH" "$mux" ;;
        kcp) printf '{"network": "kcp", "security": "none", "kcpSettings": {"congestion": true, "downlinkCapacity": 100, "mtu": 1350, "tti": 20, "uplinkCapacity": 20}, "finalmask": {"udp": [{"type": "mkcp-aes128gcm", "settings": {"password": "%s"}}]}}' "$K_KCPPW" ;;
    esac
}

# xray_direct_config: the foreign end of a direct link. The seller's server
# dials this VLESS inbound; connections go only to this server's own
# 127.0.0.1 on the sold ports, everything else to the blackhole.
xray_direct_config() {
    local flow="" net=tcp policy=""
    [[ "$K_TRANSPORT" == reality ]] && flow=', "flow": "xtls-rprx-vision"'
    [[ "$K_UDP" == 1 ]] && net="tcp,udp"
    [[ "$K_TRANSPORT" != kcp ]] && policy=',
  "policy": {"levels": {"0": {"handshake": 150}}}'
    printf '{\n  "log": {"access": "none", "loglevel": "warning"},\n'
    printf '  "inbounds": [{"tag": "tunnel", "listen": "0.0.0.0", "port": %s, "protocol": "vless", "settings": {"clients": [{"id": "%s", "email": "hashem@link"%s}], "decryption": "none"}, "streamSettings": %s}],\n' \
        "$K_PORT" "$K_UUID" "$flow" "$(xray_direct_stream)"
    printf '  "outbounds": [\n    {"protocol": "blackhole", "tag": "block"},\n    {"protocol": "freedom", "tag": "direct"},\n'
    printf '    {"protocol": "blackhole", "tag": "probe", "settings": {"response": {"type": "http"}}}\n  ],\n'
    printf '  "routing": {"domainStrategy": "AsIs", "rules": [\n'
    printf '    {"inboundTag": ["tunnel"], "domain": ["full:probe.hashem"], "outboundTag": "probe"},\n'
    printf '    {"inboundTag": ["tunnel"], "ip": ["127.0.0.1"], "port": "%s", "network": "%s", "outboundTag": "direct"},\n' "$K_PORTS" "$net"
    printf '    {"inboundTag": ["tunnel"], "outboundTag": "block"}\n  ]}%s\n}\n' "$policy"
}

# engine_config: this tunnel's config for its engine.
engine_config() {
    case "$K_ENGINE" in
        backhaul) backhaul_config ;;
        xray) xray_config ;;
        xray-direct) xray_direct_config ;;
        *) frpc_config ;;
    esac
}

conf_ext() { if [[ "$K_ENGINE" == xray || "$K_ENGINE" == xray-direct ]]; then echo json; else echo toml; fi; }

# ---- Bagher: the seller's server logs in to this sshd ----
# A system user of its own (no password, no shell). sshd's own rules for it
# (a Match block) allow nothing but listening (-R): no local forwarding, no
# Unix sockets, no command, agent, X11 or tunnel. The key line further limits
# it to 127.0.0.1 at the tunnel's port. The keys file is root's, outside the
# user's home: the user cannot change it.
SSH_USER="${HASHEM_CUSTOMER_SSH_USER:-hcust}"
SSH_HOME="/var/lib/hashem-customer/$SSH_USER"
KEYS_FILE="${HASHEM_CUSTOMER_AUTH_KEYS:-/etc/ssh/hashem-$SSH_USER.keys}"
SSHD_DROPIN="${HASHEM_SSHD_DROPIN:-/etc/ssh/sshd_config.d/hashem-customer.conf}"

# bagher_auth_line UNIT: the authorized_keys line (the unit name is its comment).
bagher_auth_line() {
    printf 'command="/bin/false",restrict,port-forwarding,permitlisten="127.0.0.1:%s",permitopen="127.0.0.1:%s" ssh-ed25519 %s %s\n' "$K_PORT" "$K_PORT" "$K_SSHPUB" "$1"
}

# sshd_rules: sshd's Match block for the user.
sshd_rules() {
    cat <<EOF
# Hashem: the seller's servers log in as ${SSH_USER} for Bagher tunnels. Written by hashem-customer.sh.
Match User ${SSH_USER}
    AuthorizedKeysFile ${KEYS_FILE}
    AllowTcpForwarding remote
    AllowStreamLocalForwarding no
    AllowAgentForwarding no
    X11Forwarding no
    PermitTTY no
    PermitTunnel no
    PermitOpen none
    GatewayPorts no
    ForceCommand /bin/false
EOF
}

sshd_reload() { systemctl try-reload-or-restart ssh.service sshd.service >/dev/null 2>&1 || true; }

# bagher_sshd: the Match block in place, and sshd seen applying it.
bagher_sshd() {
    local d cur out
    d=$(dirname "$SSHD_DROPIN")
    [[ -d "$d" ]] || die "sshd has no $d (OpenSSH older than 8.2?): a Bagher tunnel needs it. Nothing was changed for sshd."
    cur=$(cat "$SSHD_DROPIN" 2>/dev/null || true)
    if [[ "$cur" != "$(sshd_rules)" ]]; then
        sshd_rules > "$SSHD_DROPIN.new"
        chmod 644 "$SSHD_DROPIN.new"
        mv -f "$SSHD_DROPIN.new" "$SSHD_DROPIN"
        if ! sshd -t >/dev/null 2>&1; then
            if [[ -n "$cur" ]]; then printf '%s\n' "$cur" > "$SSHD_DROPIN"; else rm -f "$SSHD_DROPIN"; fi
            die "sshd refuses its config with the Hashem rules (sshd -t): nothing was changed for sshd"
        fi
        sshd_reload
    fi
    out=$(sshd -T -C "user=$SSH_USER,host=hashem.invalid,addr=192.0.2.1" 2>/dev/null || true)
    if ! grep -qix "allowtcpforwarding remote" <<< "$out" || ! grep -qix "allowstreamlocalforwarding no" <<< "$out" \
        || ! grep -qixF "authorizedkeysfile $KEYS_FILE" <<< "$out"; then
        rm -f "$SSHD_DROPIN"
        sshd_reload
        die "sshd does not apply ${SSHD_DROPIN} (its /etc/ssh/sshd_config needs 'Include ${d}/*.conf' near the top, before any Match): nothing was changed for sshd"
    fi
}

# bagher_user: the user, made once; '*' (no password) rather than a locked
# account, which sshd refuses even for keys when PAM is off. A user of that
# name that this script did not make is left alone.
bagher_user() {
    local ent nologin
    ent=$(getent passwd "$SSH_USER" || true)
    if [[ -z "$ent" ]]; then
        nologin=$(command -v nologin || echo /usr/sbin/nologin)
        mkdir -p "$(dirname "$SSH_HOME")"
        useradd --system --create-home --home-dir "$SSH_HOME" --shell "$nologin" "$SSH_USER" \
            || die "cannot create the user $SSH_USER"
        usermod -p '*' "$SSH_USER" >/dev/null 2>&1 || true
    else
        local home shell
        home=$(cut -d: -f6 <<< "$ent")
        shell=$(cut -d: -f7 <<< "$ent")
        [[ "$home" == "$SSH_HOME" && "$shell" =~ (nologin|/false)$ ]] \
            || die "this server already has a user $SSH_USER that is not the tunnels' (home $home, shell $shell): nothing was changed"
    fi
    if sshd -T 2>/dev/null | grep -qiE '^(allowusers|allowgroups) '; then
        echo "[!] sshd has AllowUsers/AllowGroups: add $SSH_USER there, or the seller's server cannot log in." >&2
    fi
}

# bagher_authorize UNIT: its line in the keys file (replacing an older one).
bagher_authorize() {
    touch "$KEYS_FILE"
    bagher_unauthorize "$1"
    bagher_auth_line "$1" >> "$KEYS_FILE"
    chmod 644 "$KEYS_FILE"
}

# bagher_unauthorize UNIT: its line goes.
bagher_unauthorize() {
    local tmp
    [[ -f "$KEYS_FILE" ]] || return 0
    tmp=$(mktemp "$KEYS_FILE.XXXXXX")
    awk -v u="$1" '$NF != u' "$KEYS_FILE" > "$tmp"  # the line whose comment is exactly UNIT
    cat "$tmp" > "$KEYS_FILE"
    rm -f "$tmp"
}

# bagher_port_free: nothing but sshd (an earlier session of this tunnel)
# listens on the tunnel's port here: the key may open that port, so it must
# not be another service's.
bagher_port_free() {
    command -v ss >/dev/null 2>&1 || return 0
    ! ss -Hltnp "sport = :$K_PORT" 2>/dev/null | grep -v 'users:(("sshd' | grep -q .
}

# reply_code UNIT: what the seller pastes back: sshd's port, the user and
# this server's host keys, so the seller's server trusts exactly them.
reply_code() {
    local port body f
    port=${HASHEM_SSH_PORT:-}
    [[ -n "$port" ]] || port=$(sshd -T 2>/dev/null | awk '$1 == "port" { print $2; exit }' || true)
    valid_port "${port:-}" || port=22
    body=$(printf 'v=1\nname=%s\nport=%s\nuser=%s\n' "$K_NAME" "$port" "$SSH_USER")
    for f in "${HASHEM_SSH_DIR:-/etc/ssh}"/ssh_host_*_key.pub; do
        [[ -f "$f" ]] || continue
        body+=$'\n'"key=$(awk '{ print $1, $2; exit }' "$f")"
    done
    [[ "$body" == *key=* ]] || die "no SSH host keys in ${HASHEM_SSH_DIR:-/etc/ssh}: is sshd installed?"
    printf 'hsr1.%s\n' "$(printf '%s\n' "$body" | base64 -w0 | tr '+/' '-_' | tr -d '=')"
}

frp_arch() {
    case "$(uname -m)" in
        x86_64|amd64) echo amd64 ;;
        aarch64|arm64) echo arm64 ;;
        *) die "this server's CPU ($(uname -m)) is not supported: use amd64 or arm64" ;;
    esac
}

# install_frpc: the pinned frpc, downloaded once (HASHEM_FRP_TARBALL: a local
# copy of the same release archive, still sha256 checked).
install_frpc() {
    local arch want tmp tgz got
    if [[ -x "$BIN_DIR/frpc" ]] && "$BIN_DIR/frpc" -v 2>/dev/null | grep -qx "$FRP_VERSION"; then
        return 0
    fi
    arch=$(frp_arch)
    eval "want=\${FRP_SHA256_${arch}}"
    tmp=$(mktemp -d)
    tgz="$tmp/frp.tgz"
    if [[ -n "${HASHEM_FRP_TARBALL:-}" ]]; then
        cp "$HASHEM_FRP_TARBALL" "$tgz"
    else
        say "Downloading FRP v${FRP_VERSION} (${arch})..."
        command -v curl >/dev/null 2>&1 || die "curl is needed: apt-get install -y curl"
        curl -fsSL --retry 3 --connect-timeout 15 -o "$tgz" \
            "https://github.com/fatedier/frp/releases/download/v${FRP_VERSION}/frp_${FRP_VERSION}_linux_${arch}.tar.gz" \
            || die "cannot download FRP from GitHub: check this server's internet access"
    fi
    got=$(sha256sum "$tgz" | awk '{print $1}')
    [[ "$got" == "$want" ]] || { rm -rf "$tmp"; die "the FRP download does not match its checksum (got $got): not installed"; }
    tar -xzf "$tgz" -C "$tmp" --strip-components=1 "frp_${FRP_VERSION}_linux_${arch}/frpc" || { rm -rf "$tmp"; die "cannot unpack FRP"; }
    mkdir -p "$BIN_DIR"
    install -m 0755 "$tmp/frpc" "$BIN_DIR/frpc.new"
    mv -f "$BIN_DIR/frpc.new" "$BIN_DIR/frpc"
    rm -rf "$tmp"
}

# fetch_pinned URL WANT_SHA OUT [LOCAL]: download URL to OUT (or copy LOCAL,
# a local copy of the same release file) and check its sha256.
fetch_pinned() {
    local url=$1 want=$2 out=$3 local_copy=${4:-} got
    if [[ -n "$local_copy" ]]; then
        cp "$local_copy" "$out" || die "cannot read $local_copy"
    else
        command -v curl >/dev/null 2>&1 || die "curl is needed: apt-get install -y curl"
        curl -fsSL --retry 3 --connect-timeout 15 -o "$out" "$url" \
            || die "cannot download $url: check this server's internet access"
    fi
    got=$(sha256sum "$out" | awk '{print $1}')
    [[ "$got" == "$want" ]] || { rm -f "$out"; die "the download does not match its checksum (got $got): not installed"; }
}

# install_backhaul: the pinned Backhaul (HASHEM_BACKHAUL_TARBALL: a local
# copy of the release archive, still sha256 checked). A stamp file says which
# release the copy is.
install_backhaul() {
    local arch want tmp
    [[ -x "$BIN_DIR/backhaul" && "$(cat "$BIN_DIR/backhaul.version" 2>/dev/null)" == "$BACKHAUL_VERSION" ]] && return 0
    arch=$(frp_arch)
    eval "want=\${BACKHAUL_SHA256_${arch}}"
    tmp=$(mktemp -d)
    say "Downloading Backhaul ${BACKHAUL_VERSION} (${arch})..."
    ( fetch_pinned "https://github.com/Musixal/Backhaul/releases/download/${BACKHAUL_VERSION}/backhaul_linux_${arch}.tar.gz" \
        "$want" "$tmp/bh.tgz" "${HASHEM_BACKHAUL_TARBALL:-}" ) || { rm -rf "$tmp"; exit 1; }
    tar -xzf "$tmp/bh.tgz" -C "$tmp" backhaul || { rm -rf "$tmp"; die "cannot unpack Backhaul"; }
    mkdir -p "$BIN_DIR"
    install -m 0755 "$tmp/backhaul" "$BIN_DIR/backhaul.new"
    mv -f "$BIN_DIR/backhaul.new" "$BIN_DIR/backhaul"
    echo "$BACKHAUL_VERSION" > "$BIN_DIR/backhaul.version"
    rm -rf "$tmp"
}

# xray_unzip ZIP DIR: unzip, else python3, else install unzip and retry.
xray_unzip() {
    unzip -oq "$1" xray -d "$2" 2>/dev/null && [[ -f "$2/xray" ]] && return 0
    python3 -c 'import sys, zipfile; zipfile.ZipFile(sys.argv[1]).extract("xray", sys.argv[2])' "$1" "$2" 2>/dev/null \
        && [[ -f "$2/xray" ]] && return 0
    if command -v apt-get >/dev/null 2>&1; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq unzip >/dev/null 2>&1 || true
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y -q unzip >/dev/null 2>&1 || true
    fi
    unzip -oq "$1" xray -d "$2" 2>/dev/null && [[ -f "$2/xray" ]]
}

# install_xray: the pinned Xray-core (HASHEM_XRAY_ZIP: a local copy of the
# release archive, still sha256 checked).
install_xray() {
    local arch zarch want tmp
    [[ -x "$BIN_DIR/xray" && "$(cat "$BIN_DIR/xray.version" 2>/dev/null)" == "$XRAY_VERSION" ]] && return 0
    arch=$(frp_arch)
    zarch=64
    [[ "$arch" == arm64 ]] && zarch=arm64-v8a
    eval "want=\${XRAY_SHA256_${arch}}"
    tmp=$(mktemp -d)
    say "Downloading Xray-core ${XRAY_VERSION} (${arch})..."
    ( fetch_pinned "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/Xray-linux-${zarch}.zip" \
        "$want" "$tmp/xray.zip" "${HASHEM_XRAY_ZIP:-}" ) || { rm -rf "$tmp"; exit 1; }
    mkdir -p "$tmp/x"
    xray_unzip "$tmp/xray.zip" "$tmp/x" || { rm -rf "$tmp"; die "cannot unpack Xray-core (install unzip or python3)"; }
    mkdir -p "$BIN_DIR"
    install -m 0755 "$tmp/x/xray" "$BIN_DIR/xray.new"
    mv -f "$BIN_DIR/xray.new" "$BIN_DIR/xray"
    echo "$XRAY_VERSION" > "$BIN_DIR/xray.version"
    rm -rf "$tmp"
}

install_engine() {
    case "$K_ENGINE" in
        backhaul) install_backhaul ;;
        xray|xray-direct) install_xray ;;
        *) install_frpc ;;
    esac
}

# unit_exec: the ExecStart of a tunnel (and the environment it needs).
unit_exec() {
    local conf=$1
    case "$K_ENGINE" in
        backhaul) echo "ExecStart=${BIN_DIR}/backhaul -c ${conf}" ;;
        xray|xray-direct) printf 'Environment=GODEBUG=multipathtcp=0\nExecStart=%s/xray run -c %s\n' "$BIN_DIR" "$conf" ;;
        *) echo "ExecStart=${BIN_DIR}/frpc -c ${conf}" ;;
    esac
}

# unit_guard UNIT: the Backhaul fence's ExecStartPre/ExecStopPost ("+": as
# root outside the sandbox, still in the unit's cgroup).
unit_guard() {
    [[ "$K_ENGINE" == backhaul ]] || return 0
    printf 'ExecStartPre=+/bin/bash %s/hashem-customer.sh guard %s\nExecStopPost=+/bin/bash %s/hashem-customer.sh unguard %s\n' "$BIN_DIR" "$1" "$BIN_DIR" "$1"
}

# connected UNIT: the tunnel reached the seller's server.
connected() {
    case "$K_ENGINE" in
        frp|bagher) journalctl -u "$1.service" --since "-30s" --no-pager -q 2>/dev/null | grep -q "login to server success" ;;
        xray-direct) [[ "$K_TRANSPORT" == kcp ]] && return 0
           ss -Htn state established "( sport = :${K_PORT} )" 2>/dev/null | grep -q . ;;
        *) [[ "$K_TRANSPORT" == kcp ]] && return 0  # mKCP: UDP, no session to see
           ss -Htn state established "( dport = :${K_PORT} )" 2>/dev/null | grep -q . ;;
    esac
}

# ---- the Backhaul fence ----
# A Backhaul server sends its client the address to connect to for each
# user ("443=10.0.0.5:22" would reach this server's network). FRP and Xray
# decide that on this end; for Backhaul a firewall chain on the tunnel's
# cgroup allows only the seller's control port, 127.0.0.1 on the sold ports
# and the system's DNS servers, and rejects the rest. The unit adds it
# before each start (guard) and removes it after each stop (unguard).

# id_file: what the token dedupe and the fence read later (<unit>.id).
id_file() {
    printf 'token=%s\nengine=%s\nserver=%s\nport=%s\nports=%s\nudp=%s\n' "$K_TOKEN" "$K_ENGINE" "$K_SERVER" "$K_PORT" "$K_PORTS" "$K_UDP"
}

guard_chain() { printf 'HC%s' "$(printf '%s' "$1" | sha256sum | cut -c1-10)"; }

guard_unit_ok() { [[ "$1" =~ ^hcust-[A-Za-z0-9-]{1,90}$ ]] || die "bad tunnel name: $1"; }

# guard_read UNIT: K_SERVER K_PORT K_PORTS K_UDP from <unit>.id, checked again.
guard_read() {
    local line key val
    K_SERVER="" K_PORT="" K_PORTS="" K_UDP=""
    [[ -f "$CONF_DIR/$1.id" ]] || die "no $CONF_DIR/$1.id: install the tunnel again"
    while IFS= read -r line; do
        key=${line%%=*} val=${line#*=}
        case "$key" in
            server) K_SERVER=$val ;; port) K_PORT=$val ;; ports) K_PORTS=$val ;; udp) K_UDP=$val ;;
        esac
    done < "$CONF_DIR/$1.id"
    [[ "$K_SERVER" =~ ^[A-Za-z0-9]([A-Za-z0-9.:-]{0,251}[A-Za-z0-9])?$ ]] || die "$1.id: bad server"
    valid_port "$K_PORT" || die "$1.id: bad port"
    [[ "$K_PORTS" =~ ^[0-9]{1,5}(,[0-9]{1,5}){0,63}$ ]] || die "$1.id: bad ports"
    [[ "$K_UDP" =~ ^[01]$ ]] || die "$1.id: bad udp"
}

guard_supported() {
    command -v iptables >/dev/null 2>&1 || return 1
    iptables -m cgroup -h 2>/dev/null | grep -q -- '--path' || return 1
    if command -v ip6tables >/dev/null 2>&1; then
        ip6tables -m cgroup -h 2>/dev/null | grep -q -- '--path' || return 1
    fi
    [[ -n "$(guard_cgroup)" ]]
}

# guard_cgroup: this process's cgroup v2 path (the unit's, in ExecStartPre).
guard_cgroup() {
    if [[ -n "${HASHEM_CUSTOMER_CGROUP:-}" ]]; then echo "$HASHEM_CUSTOMER_CGROUP"; return; fi
    awk -F: '$1 == "0" && $3 != "/" { print $3; exit }' /proc/self/cgroup 2>/dev/null
}

cmd_unguard() {
    local unit=$1 chain ipt rule args
    guard_unit_ok "$unit"
    chain=$(guard_chain "$unit")
    for ipt in iptables ip6tables; do
        command -v "$ipt" >/dev/null 2>&1 || continue
        while IFS= read -r rule; do
            [[ -n "$rule" ]] || continue
            read -ra args <<< "${rule/-A OUTPUT/-D OUTPUT}"  # the hook's own words, as -S prints them
            "$ipt" -w 5 "${args[@]}" >/dev/null 2>&1 || true
        done < <("$ipt" -w 5 -S OUTPUT 2>/dev/null | grep -E -- "^-A OUTPUT .* -j ${chain}\$" || true)
        "$ipt" -w 5 -F "$chain" >/dev/null 2>&1 || true
        "$ipt" -w 5 -X "$chain" >/dev/null 2>&1 || true
    done
}

cmd_guard() {
    local unit=$1 chain cg ipt ip p ns fam ips v4="" v6=""
    guard_unit_ok "$unit"
    guard_read "$unit"
    chain=$(guard_chain "$unit")
    cg=$(guard_cgroup)
    [[ -n "$cg" ]] || die "no cgroup v2 path for the Backhaul fence: not started"
    command -v iptables >/dev/null 2>&1 || die "iptables is needed for the Backhaul fence: not started"
    ips=$(getent ahosts "$K_SERVER" 2>/dev/null | awk '{print $1}' | sort -u)
    [[ -n "$ips" ]] || die "cannot resolve ${K_SERVER}: not started (it is retried)"
    for ip in $ips; do
        if [[ "$ip" == *:* ]]; then v6="$v6 $ip"; else v4="$v4 $ip"; fi
    done
    cmd_unguard "$unit"
    for ipt in iptables ip6tables; do
        if ! command -v "$ipt" >/dev/null 2>&1; then
            [[ "$ipt" == ip6tables ]] && continue
            die "$ipt is missing"
        fi
        fam=$v4
        [[ "$ipt" == ip6tables ]] && fam=$v6
        "$ipt" -w 5 -N "$chain" || die "$ipt: cannot make the fence chain"
        if [[ "$ipt" == iptables ]]; then
            for p in ${K_PORTS//,/ }; do
                "$ipt" -w 5 -A "$chain" -o lo -d 127.0.0.1 -p tcp --dport "$p" -j RETURN
                [[ "$K_UDP" == 1 ]] && "$ipt" -w 5 -A "$chain" -o lo -d 127.0.0.1 -p udp --dport "$p" -j RETURN
            done
        fi
        for ip in $fam; do
            "$ipt" -w 5 -A "$chain" -d "$ip" -p tcp --dport "$K_PORT" -j RETURN
        done
        # the resolvers in resolv.conf, for a seller's address that is a name
        # shellcheck disable=SC2013  # one address per line, no spaces
        for ns in $(awk '$1 == "nameserver" { print $2 }' "${HASHEM_RESOLV_CONF:-/etc/resolv.conf}" 2>/dev/null); do
            if [[ ( "$ns" == *:* && "$ipt" == ip6tables ) || ( "$ns" != *:* && "$ipt" == iptables ) ]] && [[ "$ns" =~ ^[0-9A-Fa-f.:]+$ ]]; then
                "$ipt" -w 5 -A "$chain" -d "$ns" -p udp --dport 53 -j RETURN
                "$ipt" -w 5 -A "$chain" -d "$ns" -p tcp --dport 53 -j RETURN
            fi
        done
        "$ipt" -w 5 -A "$chain" -j REJECT
        "$ipt" -w 5 -I OUTPUT 1 -m cgroup --path "$cg" -j "$chain" || die "$ipt: cannot hook the fence (cgroup match): not started"
    done
}

need_root() { [[ $(id -u) -eq 0 ]] || die "run it as root (sudo bash $0 $*)"; }

cmd_install() {
    need_root install
    command -v systemctl >/dev/null 2>&1 || die "systemd is needed"
    kit_decode "$1"
    local unit conf p f u missing=""
    unit=$(unit_name)
    if [[ "$K_ENGINE" == bagher ]] && ! command -v sshd >/dev/null 2>&1 && [[ ! -x /usr/sbin/sshd ]]; then
        die "a Bagher tunnel needs sshd (apt-get install -y openssh-server): nothing was changed"
    fi
    if [[ "$K_ENGINE" == bagher ]] && ! bagher_port_free; then
        die "port ${K_PORT} is already in use on this server: ask the seller for another control port. Nothing was changed."
    fi
    if [[ "$K_ENGINE" == backhaul ]] && ! guard_supported; then
        die "this server cannot fence a Backhaul tunnel (it needs iptables with the cgroup match and cgroup v2): nothing was changed. Ask the seller for an FRP or Xray link instead."
    fi
    [[ -f "$0" ]] || die "run the downloaded file (bash hashem-customer.sh ...), not a pipe"
    confirm
    if [[ "$K_ENGINE" == bagher ]]; then
        bagher_user
        bagher_sshd
    fi
    conf="$CONF_DIR/${unit}.$(conf_ext)"
    install_engine
    install -m 0755 "$0" "$BIN_DIR/hashem-customer.sh.new" && mv -f "$BIN_DIR/hashem-customer.sh.new" "$BIN_DIR/hashem-customer.sh"
    # an older tunnel for this same link goes: the seller moved its control
    # port or address, or changed the engine. Same link = same token (never
    # shared between links): in <unit>.id, or in an FRP config from before.
    for f in "$UNIT_DIR"/hcust-*.service; do
        [[ -e "$f" ]] || continue
        u=$(basename "${f%.service}")
        if ! grep -qxF "token=${K_TOKEN}" "$CONF_DIR/$u.id" 2>/dev/null \
            && ! grep -qF "auth.token = \"${K_TOKEN}\"" "$CONF_DIR/$u.toml" 2>/dev/null; then
            continue
        fi
        if [[ "$u" == "$unit" ]]; then
            rm -f "$CONF_DIR/$u".{toml,json}  # the same tunnel: only its old config (the engine may change)
            continue
        fi
        systemctl disable --now "${f##*/}" >/dev/null 2>&1 || true
        bagher_unauthorize "$u"
        rm -f "$f" "$CONF_DIR/$u".{toml,json,id}
    done
    mkdir -p "$CONF_DIR"
    chmod 700 "$CONF_DIR"
    (umask 077 && engine_config > "$conf.new" && id_file > "$CONF_DIR/${unit}.id")
    mv -f "$conf.new" "$conf"
    if [[ "$K_ENGINE" == bagher ]]; then
        bagher_authorize "$unit"
    else
        bagher_unauthorize "$unit"  # the same link, moved off Bagher
    fi
    cat > "$UNIT_DIR/${unit}.service" <<EOF
[Unit]
Description=Hashem tunnel to ${K_SERVER} (${K_NAME})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
$(unit_guard "$unit")
$(unit_exec "$conf")
Restart=always
RestartSec=3
LimitNOFILE=1048576
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictNamespaces=true
LockPersonality=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable "${unit}.service" >/dev/null 2>&1
    systemctl restart "${unit}.service"
    if [[ "$K_ENGINE" == bagher ]]; then
        say "Tunnel ${unit} is ready. Send the seller this reply code; the tunnel connects once they paste it:"
        echo
        reply_code
        echo
        return 0
    fi
    say "Tunnel ${unit}: connecting to ${K_SERVER}:${K_PORT} (${K_ENGINE}, ${K_TRANSPORT})..."
    local ok=""
    for _ in $(seq 20); do
        if connected "$unit"; then
            ok=1
            break
        fi
        sleep 1
    done
    if [[ -n "$ok" ]]; then
        say "Connected. Users reach ports ${K_PORTS//,/, } on ${K_SERVER}."
    else
        echo "[!] Not connected yet: the seller's server may not be reachable on port ${K_PORT}. Check with: journalctl -u ${unit} -n 30" >&2
    fi
    if command -v ss >/dev/null 2>&1; then
        for p in ${K_PORTS//,/ }; do
            ss -Hltn "sport = :$p" 2>/dev/null | grep -q . || missing="$missing $p"
        done
        [[ -z "$missing" ]] || echo "[!] Nothing listens on TCP port(s)${missing} on this server yet: start your service there." >&2
    fi
}

cmd_remove() {
    need_root remove
    local what=${1:-} f u n=0
    [[ -n "$what" ]] || die "remove what? a tunnel name from 'status', or all"
    [[ "$what" == all || "$what" =~ ^hcust-[A-Za-z0-9-]{1,60}$ ]] || die "bad tunnel name: $what"
    for f in "$UNIT_DIR"/hcust-*.service; do
        [[ -e "$f" ]] || continue
        u=${f##*/}
        u=${u%.service}
        [[ "$what" == all || "$what" == "$u" ]] || continue
        systemctl disable --now "${u}.service" >/dev/null 2>&1 || true
        cmd_unguard "$u" 2>/dev/null || true
        bagher_unauthorize "$u"
        rm -f "$f" "$CONF_DIR/${u}".{toml,json,id}
        say "Removed $u"
        n=$((n + 1))
    done
    systemctl daemon-reload >/dev/null 2>&1 || true
    (( n > 0 )) || die "no tunnel named $what"
    if ! compgen -G "$UNIT_DIR/hcust-*.service" >/dev/null; then
        rm -rf "$BIN_DIR"
        rmdir "$CONF_DIR" 2>/dev/null || true
    fi
}

cmd_status() {
    local f u any=""
    for f in "$UNIT_DIR"/hcust-*.service; do
        [[ -e "$f" ]] || continue
        any=1
        u=${f##*/}
        u=${u%.service}
        printf '%-48s %s\n' "$u" "$(systemctl is-active "${u}.service" 2>/dev/null || true)"
    done
    [[ -n "$any" ]] || echo "No Hashem tunnels on this server."
}

ASSUME_YES=0
args=()
for a in "$@"; do
    if [[ "$a" == "--yes" || "$a" == "-y" ]]; then ASSUME_YES=1; else args+=("$a"); fi
done
set -- "${args[@]+"${args[@]}"}"
case "${1:-}" in
    install) [[ $# -eq 2 ]] || die "usage: $0 install hsk1.XXXX [--yes]"; cmd_install "$2" ;;
    config) [[ $# -eq 2 ]] || die "usage: $0 config hsk1.XXXX"; kit_decode "$2"; engine_config ;;
    remove) cmd_remove "${2:-}" ;;
    status) cmd_status ;;
    guard) [[ $# -eq 2 ]] || die "usage: $0 guard UNIT"; need_root guard; cmd_guard "$2" ;;
    unguard) [[ $# -eq 2 ]] || die "usage: $0 unguard UNIT"; need_root unguard; cmd_unguard "$2" ;;
    idfile) [[ $# -eq 2 ]] || die "usage: $0 idfile hsk1.XXXX"; kit_decode "$2"; id_file ;;
    reply) [[ $# -eq 2 ]] || die "usage: $0 reply hsk1.XXXX"; kit_decode "$2"; [[ "$K_ENGINE" == bagher ]] || die "only a Bagher kit has a reply code"; reply_code ;;
    sshdrules) sshd_rules ;;
    authline) [[ $# -eq 2 ]] || die "usage: $0 authline hsk1.XXXX"; kit_decode "$2"; [[ "$K_ENGINE" == bagher ]] || die "not a Bagher kit"; bagher_auth_line "$(unit_name)" ;;
    *) sed -n '2,23p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
