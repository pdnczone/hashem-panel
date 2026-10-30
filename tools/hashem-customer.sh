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
# (v0.7.2) or Xray (Xray-core v26.3.27, a reverse link). The installer
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
    K_UUID="" K_PBK="" K_SID="" K_SNI="" K_PATH="" K_KCPPW=""
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
        esac
    done <<< "$body"
    case "$K_V" in
        1) K_ENGINE=frp ;;  # kits from before Backhaul and Xray
        2) ;;
        *) die "this kit needs a newer hashem-customer.sh (kit version ${K_V:-?})" ;;
    esac
    [[ "$K_ENGINE" =~ ^(frp|backhaul|xray)$ ]] || die "kit: bad engine"
    [[ "$K_NAME" =~ ^hsell-[0-9]{1,6}-[0-9]{1,4}$ ]] || die "kit: bad name"
    [[ "$K_SERVER" =~ ^[A-Za-z0-9]([A-Za-z0-9.:-]{0,251}[A-Za-z0-9])?$ ]] || die "kit: bad server address"
    valid_port "$K_PORT" || die "kit: bad control port"
    case "$K_ENGINE" in
        frp) [[ "$K_TRANSPORT" =~ ^(tcp|kcp|quic|websocket)$ ]] || die "kit: bad transport" ;;
        backhaul) [[ "$K_TRANSPORT" =~ ^(tcp|tcpmux|ws|wsmux|wss|wssmux)$ ]] || die "kit: bad transport" ;;
        xray) [[ "$K_TRANSPORT" =~ ^(reality|xhttp|grpc|kcp)$ ]] || die "kit: bad transport"
            [[ "$K_UUID" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || die "kit: bad uuid"
            if [[ "$K_TRANSPORT" == kcp ]]; then
                [[ "$K_KCPPW" =~ ^[0-9a-f]{8,64}$ ]] || die "kit: bad mKCP password"
            else
                [[ "$K_PBK" =~ ^[A-Za-z0-9_-]{43}$ ]] || die "kit: bad Reality key"
                [[ "$K_SID" =~ ^[0-9a-f]{0,16}$ ]] || die "kit: bad Reality short id"
                [[ "$K_SNI" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$ ]] || die "kit: bad SNI"
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
}

valid_port() { [[ "$1" =~ ^[0-9]{1,5}$ ]] && (( 10#$1 >= 1 && 10#$1 <= 65535 )); }

# unit_name: one per seller server and sold link (the kit's name), so
# tunnels bought from two sellers never share a name, and a new kit for the
# same link (another control port) replaces the old tunnel.
unit_name() {
    local s
    s=$(printf '%s' "$K_SERVER" | tr -c 'A-Za-z0-9' '-' | tr -s '-' | cut -c1-40)
    s=${s%-}
    echo "hcust-${s#-}-${K_NAME#hsell-}"
}

# confirm: the kit decides which local ports become public on the seller's
# server. Say which, warn about services bound to this server only, and ask.
confirm() {
    local p ans local_only=""
    local protos=TCP
    [[ "$K_UDP" == 1 ]] && protos="TCP and UDP"
    say "This tunnel publishes ${protos} port(s) ${K_PORTS//,/, } of this server on ${K_SERVER}."
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
    local p
    echo "# Hashem: tunnel to ${K_SERVER} (${K_NAME}). Written by hashem-customer.sh."
    printf 'serverAddr = "%s"\nserverPort = %s\n' "$K_SERVER" "$K_PORT"
    printf 'auth.method = "token"\nauth.token = "%s"\n' "$K_TOKEN"
    printf 'loginFailExit = false\n'
    printf 'transport.protocol = "%s"\ntransport.tcpMux = true\ntransport.poolCount = 10\n' "$K_TRANSPORT"
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
    printf 'sniffer = false\nweb_port = 0\nsniffer_log = ""\nlog_level = "info"\n'
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

# engine_config: this tunnel's config for its engine.
engine_config() {
    case "$K_ENGINE" in
        backhaul) backhaul_config ;;
        xray) xray_config ;;
        *) frpc_config ;;
    esac
}

conf_ext() { if [[ "$K_ENGINE" == xray ]]; then echo json; else echo toml; fi; }

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
        cp "$local_copy" "$out"
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
        xray) install_xray ;;
        *) install_frpc ;;
    esac
}

# unit_exec: the ExecStart of a tunnel (and the environment it needs).
unit_exec() {
    local conf=$1
    case "$K_ENGINE" in
        backhaul) echo "ExecStart=${BIN_DIR}/backhaul -c ${conf}" ;;
        xray) printf 'Environment=GODEBUG=multipathtcp=0\nExecStart=%s/xray run -c %s\n' "$BIN_DIR" "$conf" ;;
        *) echo "ExecStart=${BIN_DIR}/frpc -c ${conf}" ;;
    esac
}

# connected UNIT: the tunnel reached the seller's server.
connected() {
    case "$K_ENGINE" in
        frp) journalctl -u "$1.service" --since "-30s" --no-pager -q 2>/dev/null | grep -q "login to server success" ;;
        *) [[ "$K_TRANSPORT" == kcp ]] && return 0  # mKCP: UDP, no session to see
           ss -Htn state established "( dport = :${K_PORT} )" 2>/dev/null | grep -q . ;;
    esac
}

need_root() { [[ $(id -u) -eq 0 ]] || die "run it as root (sudo bash $0 $*)"; }

cmd_install() {
    need_root install
    command -v systemctl >/dev/null 2>&1 || die "systemd is needed"
    kit_decode "$1"
    local unit conf p f u missing=""
    unit=$(unit_name)
    confirm
    conf="$CONF_DIR/${unit}.$(conf_ext)"
    install_engine
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
        rm -f "$f" "$CONF_DIR/$u".{toml,json,id}
    done
    mkdir -p "$CONF_DIR"
    chmod 700 "$CONF_DIR"
    (umask 077 && engine_config > "$conf.new" && echo "token=${K_TOKEN}" > "$CONF_DIR/${unit}.id")
    mv -f "$conf.new" "$conf"
    cat > "$UNIT_DIR/${unit}.service" <<EOF
[Unit]
Description=Hashem tunnel to ${K_SERVER} (${K_NAME})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
$(unit_exec "$conf")
Restart=always
RestartSec=3
LimitNOFILE=1048576
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable "${unit}.service" >/dev/null 2>&1
    systemctl restart "${unit}.service"
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
    *) sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
