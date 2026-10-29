#!/usr/bin/env bash
# hashem-customer.sh: the foreign end of a tunnel bought from a Hashem seller.
#
# The seller's panel (Customers tab) gives a kit, "hsk1.<...>", for each of
# your foreign servers. On that server run:
#
#   sudo bash hashem-customer.sh install hsk1.XXXX   # set up or update the tunnel
#   sudo bash hashem-customer.sh status              # every tunnel and its state
#   sudo bash hashem-customer.sh remove NAME|all     # take tunnels away
#   bash hashem-customer.sh config hsk1.XXXX         # print the frpc config only
#
# It installs frpc v0.71.0 from the official FRP release (sha256 checked) to
# /usr/local/lib/hashem-customer, writes /etc/hashem-customer/<name>.toml
# and runs one systemd unit per tunnel. Your services keep running on this
# server; users reach them on the same ports on the seller's Iran server.
# No Hashem panel and no license are needed here.
set -euo pipefail

FRP_VERSION="0.71.0"
FRP_SHA256_amd64="84f27e39f11169f7adcef8e8b70c9329de17747b1f14dad9fb95eef5682ea716"
FRP_SHA256_arm64="f33c293c275d8fc68c654b6fba8f10b2551d6463d09a9fc9cffb7227eae82266"
BIN_DIR="${HASHEM_CUSTOMER_BIN_DIR:-/usr/local/lib/hashem-customer}"
CONF_DIR="${HASHEM_CUSTOMER_CONF_DIR:-/etc/hashem-customer}"
UNIT_DIR="${HASHEM_SYSTEMD_DIR:-/etc/systemd/system}"

die() { echo "[!] $*" >&2; exit 1; }
say() { echo "[*] $*"; }

# kit_decode KIT: sets K_NAME K_SERVER K_PORT K_TRANSPORT K_TOKEN K_UDP K_PORTS,
# each checked against a strict pattern (the kit is pasted, never trusted).
kit_decode() {
    local kit=$1 body line key val
    [[ "$kit" =~ ^hsk1\.[A-Za-z0-9_-]{20,4000}$ ]] || die "not a Hashem kit (it starts with hsk1.): copy it again from the seller"
    body=${kit#hsk1.}
    body=$(printf '%s' "$body" | tr '_-' '/+')
    while (( ${#body} % 4 )); do body="${body}="; done
    body=$(printf '%s' "$body" | base64 -d 2>/dev/null) || die "the kit is damaged: copy it again"
    K_V="" K_NAME="" K_SERVER="" K_PORT="" K_TRANSPORT="" K_TOKEN="" K_UDP="" K_PORTS=""
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
        esac
    done <<< "$body"
    [[ "$K_V" == 1 ]] || die "this kit needs a newer hashem-customer.sh (kit version ${K_V:-?})"
    [[ "$K_NAME" =~ ^hsell-[0-9]{1,6}-[0-9]{1,4}$ ]] || die "kit: bad name"
    [[ "$K_SERVER" =~ ^[A-Za-z0-9]([A-Za-z0-9.:-]{0,251}[A-Za-z0-9])?$ ]] || die "kit: bad server address"
    valid_port "$K_PORT" || die "kit: bad control port"
    [[ "$K_TRANSPORT" =~ ^(tcp|kcp|quic|websocket)$ ]] || die "kit: bad transport"
    [[ "$K_TOKEN" =~ ^[A-Za-z0-9]{16,64}$ ]] || die "kit: bad token"
    [[ "$K_UDP" =~ ^[01]$ ]] || die "kit: bad udp flag"
    [[ "$K_PORTS" =~ ^[0-9]{1,5}(,[0-9]{1,5}){0,63}$ ]] || die "kit: bad port list"
    local p
    for p in ${K_PORTS//,/ }; do valid_port "$p" || die "kit: bad port $p"; done
}

valid_port() { [[ "$1" =~ ^[0-9]{1,5}$ ]] && (( 10#$1 >= 1 && 10#$1 <= 65535 )); }

# unit_name: one per seller server and control port, so tunnels bought from
# two sellers never share a name; installing the same kit again updates it.
unit_name() {
    local s
    s=$(printf '%s' "$K_SERVER" | tr -c 'A-Za-z0-9' '-' | tr -s '-' | cut -c1-40)
    s=${s%-}
    echo "hcust-${s#-}-${K_PORT}"
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
    trap 'rm -rf "$tmp"' RETURN
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
    [[ "$got" == "$want" ]] || die "the FRP download does not match its checksum (got $got): not installed"
    tar -xzf "$tgz" -C "$tmp" --strip-components=1 "frp_${FRP_VERSION}_linux_${arch}/frpc" || die "cannot unpack FRP"
    mkdir -p "$BIN_DIR"
    install -m 0755 "$tmp/frpc" "$BIN_DIR/frpc.new"
    mv -f "$BIN_DIR/frpc.new" "$BIN_DIR/frpc"
}

need_root() { [[ $(id -u) -eq 0 ]] || die "run it as root (sudo bash $0 $*)"; }

cmd_install() {
    need_root install
    command -v systemctl >/dev/null 2>&1 || die "systemd is needed"
    kit_decode "$1"
    local unit conf p missing=""
    unit=$(unit_name)
    conf="$CONF_DIR/${unit}.toml"
    install_frpc
    mkdir -p "$CONF_DIR"
    chmod 700 "$CONF_DIR"
    (umask 077 && frpc_config > "$conf.new")
    mv -f "$conf.new" "$conf"
    cat > "$UNIT_DIR/${unit}.service" <<EOF
[Unit]
Description=Hashem tunnel to ${K_SERVER} (${K_NAME})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${BIN_DIR}/frpc -c ${conf}
Restart=always
RestartSec=3
LimitNOFILE=1048576
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable "${unit}.service" >/dev/null 2>&1
    systemctl restart "${unit}.service"
    say "Tunnel ${unit}: connecting to ${K_SERVER}:${K_PORT} (${K_TRANSPORT})..."
    local ok=""
    for _ in $(seq 20); do
        if journalctl -u "${unit}.service" --since "-30s" --no-pager -q 2>/dev/null | grep -q "login to server success"; then
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
        rm -f "$f" "$CONF_DIR/${u}.toml"
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

case "${1:-}" in
    install) [[ $# -eq 2 ]] || die "usage: $0 install hsk1.XXXX"; cmd_install "$2" ;;
    config) [[ $# -eq 2 ]] || die "usage: $0 config hsk1.XXXX"; kit_decode "$2"; frpc_config ;;
    remove) cmd_remove "${2:-}" ;;
    status) cmd_status ;;
    *) sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
