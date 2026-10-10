#!/bin/bash

# ==============================================================================
#   Hashem — GRE + FRP Reverse Tunnel Automated Setup Script (hashem.sh)
#   Architecture: GRE Layer 3 Tunnel + FRP Reverse TLS Tunnel
#   Features: Auto Arch Detect, Systemd Auto-start on boot, MTU Clamping, TCP/UDP
#   One file: interactive menu (`bash hashem.sh`) + non-interactive CLI
#   (`hashem setup-iran ...`) — the old gre.sh name still works as symlink.
# ==============================================================================
# ---- installed names (single source of truth for this script) ----
HASHEM_BIN="/usr/local/bin/hashem"       # this script, after install
HASHEM_SCRIPT="/usr/local/bin/hashem.sh" # versioned copy (gre.sh = legacy alias)
HASHEM_URL_BASE="https://raw.githubusercontent.com/pdnczone/hashem-panel/main"

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/frp"
DEFAULT_FRP_VERSION="0.71.0"

# Default GRE internal IPs (/30 subnet)
IRAN_GRE_IP="10.10.10.2"
FOREIGN_GRE_IP="10.10.10.1"
TUNNEL_NAME="gre-tunnel"
PANEL_CONFIG_DIR="${GRE_PANEL_DIR:-/etc/gre-panel}"
WATCHDOG_FILE="${PANEL_CONFIG_DIR}/watchdog.json"
PERF_FILE="${PANEL_CONFIG_DIR}/perf.json"
CARRIER_FILE="${PANEL_CONFIG_DIR}/carrier.json"
AUTO_POOL_STATE="${PANEL_CONFIG_DIR}/auto_pool.json"
# Auto Pool tuning (env-overridable): frpc poolCount 20..200, frps maxPoolCount 60..500 (also RAM-capped)
AUTOPOOL_MIN="${AUTOPOOL_MIN:-20}"
AUTOPOOL_MAX="${AUTOPOOL_MAX:-200}"
AUTOPOOL_MAXPOOL_MIN="${AUTOPOOL_MAXPOOL_MIN:-60}"
AUTOPOOL_MAXPOOL_MAX="${AUTOPOOL_MAXPOOL_MAX:-500}"
AUTOPOOL_LOW_CONNS="${AUTOPOOL_LOW_CONNS:-30}"       # restart frpc only below this many active user conns
AUTOPOOL_COOLDOWN="${AUTOPOOL_COOLDOWN:-300}"        # min seconds between automatic frpc restarts
AUTOPOOL_SEVERE_ERRS="${AUTOPOOL_SEVERE_ERRS:-20}"   # pool-full lines per tick that justify a restart under load
AUTOPOOL_DOWN_QUIET="${AUTOPOOL_DOWN_QUIET:-15}"     # consecutive quiet ticks before scaling down
AUTOPOOL_MIN_FREE_MB="${AUTOPOOL_MIN_FREE_MB:-150}"  # below this free RAM, never scale up
BACKUP_DIR="/var/backups/hashem"

ensure_hashem_bin() {
    [[ ${EUID:-$(id -u 2>/dev/null || echo 1)} -eq 0 ]] || return 0
    mkdir -p /usr/local/bin
    if [[ -f "$0" && "$0" != "$HASHEM_BIN" ]]; then
        cp "$0" "$HASHEM_BIN" 2>/dev/null && chmod +x "$HASHEM_BIN" 2>/dev/null || true
        cp "$0" "$HASHEM_SCRIPT" 2>/dev/null && chmod +x "$HASHEM_SCRIPT" 2>/dev/null || true
        ln -sf "$HASHEM_SCRIPT" /usr/local/bin/gre.sh 2>/dev/null || true
    elif [[ ! -x "$HASHEM_BIN" ]]; then
        local cand
        for cand in "$0" ./hashem.sh /tmp/hashem.sh "$HASHEM_SCRIPT"; do
            if [[ -f "$cand" ]]; then
                cp "$cand" "$HASHEM_BIN" 2>/dev/null && chmod +x "$HASHEM_BIN" 2>/dev/null || true
                break
            fi
        done
    fi
}
ensure_hashem_bin

LOG_DIR="/var/log/hashem"

# Mask tokens and sensitive credentials in log strings
mask_sensitive() {
    local text="$1"
    echo "$text" | sed -E \
        -e 's/(hsh1_[^_]+_[0-9]+_[^_]+_[^_]+_)[A-Za-z0-9_-]{8,128}/\1[MASKED_TOKEN]/g' \
        -e 's/(auth\.token[[:space:]]*=[[:space:]]*")[^"]+/\1[MASKED_TOKEN]/g' \
        -e 's/(token[[:space:]]*=[[:space:]]*")[^"]+/\1[MASKED_TOKEN]/g' \
        -e 's/(--token[[:space:]]+)[A-Za-z0-9_-]{16,128}/\1[MASKED_TOKEN]/g' \
        -e 's/(Token:[[:space:]]*)[A-Za-z0-9_-]{16,128}/\1[MASKED_TOKEN]/g'
}

log_msg() {
    local category="${1:-installer}"
    local level="${2:-INFO}"
    local msg="$3"
    [[ ${EUID:-$(id -u 2>/dev/null || echo 1)} -eq 0 ]] || return 0
    mkdir -p "$LOG_DIR" 2>/dev/null || return 0
    local logfile="${LOG_DIR}/${category}.log"
    local masked
    masked=$(mask_sensitive "$msg")
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [${level}] ${masked}" >> "$logfile" 2>/dev/null || true
}

backup_configs() {
    local label="${1:-manual}"
    local ts
    ts=$(date '+%Y%m%d_%H%M%S')
    local bdir="${BACKUP_DIR}/${ts}_${label}"
    mkdir -p "$bdir" 2>/dev/null || return 1
    
    # Backup configuration folders
    [[ -d /etc/hashem ]] && cp -rp /etc/hashem "$bdir/" 2>/dev/null || true
    [[ -d /etc/gre-panel ]] && cp -rp /etc/gre-panel "$bdir/" 2>/dev/null || true
    [[ -d /etc/frp ]] && cp -rp /etc/frp "$bdir/" 2>/dev/null || true
    
    # Backup relevant systemd units
    mkdir -p "$bdir/systemd" 2>/dev/null || true
    for u in /etc/systemd/system/gre-*.service /etc/systemd/system/frps*.service /etc/systemd/system/frpc*.service /etc/systemd/system/gre-panel.service; do
        [[ -f "$u" ]] && cp -p "$u" "$bdir/systemd/" 2>/dev/null || true
    done
    
    echo "$bdir" > "${BACKUP_DIR}/latest" 2>/dev/null || true
    log_msg "installer" "INFO" "Created config backup at $bdir"
    echo "$bdir"
}

# Component States: NOT_INSTALLED, INSTALLED, RUNNING, STOPPED, BROKEN, UNKNOWN
get_component_status() {
    local comp="$1"
    case "$comp" in
        panel)
            local bin="/usr/local/bin/gre-panel"
            local svc="gre-panel"
            if [[ ! -f "$bin" && ! -f "/etc/systemd/system/${svc}.service" ]]; then
                echo "NOT_INSTALLED"; return 0
            fi
            if systemctl is-active --quiet "$svc" 2>/dev/null; then
                echo "RUNNING"; return 0
            elif systemctl is-failed --quiet "$svc" 2>/dev/null; then
                echo "BROKEN"; return 0
            elif [[ -f "$bin" ]]; then
                echo "STOPPED"; return 0
            else
                echo "BROKEN"; return 0
            fi
            ;;
        frps)
            local bin="/usr/local/bin/frps"
            local svc="frps"
            if [[ ! -f "$bin" && ! -f "/etc/systemd/system/${svc}.service" && ! -f "/etc/frp/frps.toml" ]]; then
                echo "NOT_INSTALLED"; return 0
            fi
            if systemctl is-active --quiet "$svc" 2>/dev/null; then
                echo "RUNNING"; return 0
            elif systemctl is-failed --quiet "$svc" 2>/dev/null; then
                echo "BROKEN"; return 0
            elif [[ -f "$bin" ]]; then
                echo "STOPPED"; return 0
            else
                echo "BROKEN"; return 0
            fi
            ;;
        frpc)
            local bin="/usr/local/bin/frpc"
            local svc="frpc"
            if [[ ! -f "$bin" && ! -f "/etc/systemd/system/${svc}.service" && ! -f "/etc/frp/frpc.toml" ]]; then
                echo "NOT_INSTALLED"; return 0
            fi
            if systemctl is-active --quiet "$svc" 2>/dev/null; then
                echo "RUNNING"; return 0
            elif systemctl is-failed --quiet "$svc" 2>/dev/null; then
                echo "BROKEN"; return 0
            elif [[ -f "$bin" ]]; then
                echo "STOPPED"; return 0
            else
                echo "BROKEN"; return 0
            fi
            ;;
        gre)
            local ifname="${2:-$TUNNEL_NAME}"
            local svc="${ifname}.service"
            local link_exists=0
            local addr_exists=0
            if ip link show "$ifname" >/dev/null 2>&1; then
                link_exists=1
            fi
            if ip -4 addr show dev "$ifname" 2>/dev/null | grep -q "inet "; then
                addr_exists=1
            fi
            if [[ "$link_exists" -eq 1 && "$addr_exists" -eq 1 ]]; then
                echo "RUNNING"; return 0
            fi
            if systemctl is-failed --quiet "$svc" 2>/dev/null; then
                echo "BROKEN"; return 0
            elif [[ -f "/etc/systemd/system/${svc}" || "$link_exists" -eq 1 ]]; then
                echo "BROKEN"; return 0
            else
                echo "NOT_INSTALLED"; return 0
            fi
            ;;
        deps)
            local missing=()
            for cmd in ip curl tar iptables systemctl python3 ping; do
                command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
            done
            if [[ ${#missing[@]} -eq 0 ]]; then
                echo "INSTALLED"; return 0
            else
                echo "BROKEN"; return 0
            fi
            ;;
        *)
            echo "UNKNOWN"; return 0
            ;;
    esac
}

ensure_dependencies_smart() {
    local DEPS_MARKER="/etc/gre-panel/.deps_installed"
    if [[ -f "$DEPS_MARKER" ]] && command -v ip >/dev/null 2>&1 && command -v curl >/dev/null 2>&1 && \
       command -v tar >/dev/null 2>&1 && command -v iptables >/dev/null 2>&1 && \
       command -v systemctl >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1; then
        return 0
    fi

    local missing_pkgs=()
    command -v ip >/dev/null 2>&1 || missing_pkgs+=("iproute2")
    command -v curl >/dev/null 2>&1 || missing_pkgs+=("curl")
    command -v tar >/dev/null 2>&1 || missing_pkgs+=("tar")
    command -v iptables >/dev/null 2>&1 || missing_pkgs+=("iptables")
    command -v systemctl >/dev/null 2>&1 || missing_pkgs+=("systemd")
    command -v python3 >/dev/null 2>&1 || missing_pkgs+=("python3")
    command -v ping >/dev/null 2>&1 || missing_pkgs+=("iputils-ping")
    command -v ss >/dev/null 2>&1 || missing_pkgs+=("iproute2")
    
    if [[ ${#missing_pkgs[@]} -eq 0 ]]; then
        mkdir -p /etc/gre-panel
        touch "$DEPS_MARKER" 2>/dev/null || true
        echo -e "${GREEN}[✔️] All system dependencies are satisfied.${NC}"
        return 0
    fi
    
    local uniq_pkgs
    uniq_pkgs=$(printf "%s\n" "${missing_pkgs[@]}" | sort -u | tr '\n' ' ')
    echo -e "${CYAN}[*] Installing missing dependencies: ${uniq_pkgs}...${NC}"
    log_msg "installer" "INFO" "Installing missing dependencies: ${uniq_pkgs}"
    
    if command -v apt-get >/dev/null 2>&1; then
        export DEBIAN_FRONTEND=noninteractive
        (timeout 25 apt-get update -qq || true)
        apt-get install -y -qq --no-install-recommends $uniq_pkgs 2>/dev/null || {
            echo -e "${YELLOW}[!] Warning: apt-get encountered issues installing: ${uniq_pkgs}. Continuing setup.${NC}"
        }
    elif command -v yum >/dev/null 2>&1; then
        yum install -y -q $uniq_pkgs || true
    fi
    mkdir -p /etc/gre-panel
    touch "$DEPS_MARKER" 2>/dev/null || true
    echo -e "${GREEN}[✔️] System dependencies installed and cached.${NC}"
}

is_port_in_use() {
    local port=$1
    if command -v ss >/dev/null 2>&1; then
        ss -tulpn "sport = :$port" 2>/dev/null | grep -q ":$port " && return 0
    elif command -v netstat >/dev/null 2>&1; then
        netstat -tulpn 2>/dev/null | grep -q ":$port " && return 0
    elif command -v lsof >/dev/null 2>&1; then
        lsof -i :"$port" >/dev/null 2>&1 && return 0
    fi
    return 1
}

diagnose_port_process() {
    local port=$1
    echo -e "${CYAN}=== Diagnosing Process Holding Port :$port ===${NC}"
    if command -v ss >/dev/null 2>&1; then
        ss -tulpn "sport = :$port" 2>/dev/null
    fi
    if command -v lsof >/dev/null 2>&1; then
        lsof -i :"$port" 2>/dev/null
    elif command -v fuser >/dev/null 2>&1; then
        fuser "$port/tcp" 2>/dev/null
    fi
    echo -e "${CYAN}=============================================${NC}"
}

ensure_port_available() {
    local port=$1
    local purpose=${2:-"Required port"}
    local is_bundle=${3:-0}
    # $4: if set to "warn-only", non-interactive mode will warn but not fail.
    # Proxy ports on Foreign are declared in frpc config as localPort —
    # frpc never binds them itself (Marzban/X-UI owns them), so a conflict
    # is informational, not a hard blocker.
    local warn_only=${4:-""}
    
    while is_port_in_use "$port"; do
        echo -e "${YELLOW}[!] WARNING: ${purpose} ${port} is already in use by another process.${NC}"
        log_msg "tunnel" "WARN" "${purpose} ${port} is in use"
        if [[ ! -t 0 ]]; then
            # Non-interactive (panel / piped): just warn and continue.
            # If this is the FRP control port, it's an actual conflict;
            # for proxy ports it is expected (Marzban/X-UI is there).
            echo -e "${CYAN}[*] Non-interactive mode: continuing despite port conflict (frpc will try to start anyway).${NC}"
            echo "$port"
            return 0
        fi
        echo "Options:"
        echo "  1) Retry (after stopping conflicting process)"
        echo "  2) Diagnose process"
        echo "  3) Cancel"
        if [[ "$is_bundle" -ne 1 ]]; then
            echo "  4) Choose another port"
        else
            echo "  4) Explicitly choose another port (override bundle)"
        fi
        read -p "Select option [1-4]: " P_OPT
        case "$P_OPT" in
            1)
                continue
                ;;
            2)
                diagnose_port_process "$port"
                echo ""
                ;;
            3)
                return 1
                ;;
            4)
                prompt_port NEW_PORT "Enter new ${purpose}" "$(gen_random_port)"
                port=$NEW_PORT
                ;;
            *)
                echo -e "${RED}[!] Invalid option.${NC}"
                ;;
        esac
    done
    echo "$port"
    return 0
}

cli_bundle_inspect() {
    local BUNDLE="" SHOW_TOKEN=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --show-token|-s) SHOW_TOKEN=1; shift ;;
            hsh1_*) BUNDLE="$1"; shift ;;
            *) BUNDLE="$1"; shift ;;
        esac
    done
    if [[ -z "$BUNDLE" ]]; then
        read -p "Enter setup bundle (hsh1_...): " BUNDLE
    fi
    if ! bundle_parse "$BUNDLE"; then
        echo -e "${RED}[!] Invalid bundle format. Expected: hsh1_<IRAN_PUB>_<FRP_PORT>_<IRAN_GRE>_<FOREIGN_GRE>_<TOKEN>[_<PORTS>][_fou<P1>-<P2>]${NC}"
        return 1
    fi
    
    local DISP_TOKEN="******************************** (Masked, pass --show-token to reveal)"
    if [[ "$SHOW_TOKEN" -eq 1 ]]; then
        DISP_TOKEN="$B_TOKEN"
    fi
    
    echo -e "\n${CYAN}=============================================================="
    echo "                 HASHEM TUNNEL BUNDLE INSPECT"
    echo -e "==============================================================${NC}"
    echo -e "Bundle Version:        ${GREEN}hsh1${NC}"
    echo -e "Iran Public IP:        ${CYAN}${B_IRAN_PUB}${NC}"
    echo -e "FRP Server Port:       ${CYAN}${B_FRP_PORT}${NC} (serverPort / bindPort)"
    echo -e "Iran GRE Internal IP:  ${CYAN}${B_IRAN_GRE}${NC}"
    echo -e "Foreign GRE IP:        ${CYAN}${B_FOREIGN_GRE}${NC}"
    echo -e "Reverse Proxy Ports:   ${CYAN}${B_PORTS:-None (Manual configuration)}${NC}"
    echo -e "FOU UDP Ports:         ${CYAN}${B_FOU_P1}, ${B_FOU_P2}${NC}"
    echo -e "Auth Token:            ${YELLOW}${DISP_TOKEN}${NC}"
    echo -e "Source of Truth:       ${GREEN}Enforced on Foreign Server${NC}"
    echo -e "${CYAN}==============================================================${NC}\n"
    return 0
}


# ---- Performance Configuration (/etc/gre-panel/perf.json) ----
init_perf_json() {
    mkdir -p /etc/gre-panel
    if [[ ! -f "$PERF_FILE" ]]; then
        cat << 'EOF' > "$PERF_FILE"
{
  "proxy_encryption": false,
  "proxy_compression": false,
  "tcp_mux": false,
  "auto_pool": true
}
EOF
        chmod 600 "$PERF_FILE" 2>/dev/null || true
    fi
}

# tcp_mux: prints 1 / 0 when explicitly configured (env PERF_TCPMUX or perf.json "tcp_mux"),
# prints an EMPTY string when unset so perf_apply leaves the live toml untouched.
# FRP multiplexes every user stream over ONE TCP connection when tcpMux is on; measured over the
# GRE path that caps a tunnel at roughly half of what per-connection work conns reach.
perf_get_tcpmux() {
    if [[ -n "${PERF_TCPMUX:-}" ]]; then
        [[ "$PERF_TCPMUX" == "1" || "$PERF_TCPMUX" == "true" ]] && echo 1 || echo 0
        return 0
    fi
    if [[ -f "$PERF_FILE" ]] && command -v python3 >/dev/null 2>&1; then
        python3 -c '
import json
try:
    with open("'"$PERF_FILE"'") as f:
        d = json.load(f)
    print(("1" if d["tcp_mux"] else "0") if "tcp_mux" in d else "")
except Exception:
    print("")
' 2>/dev/null && return 0
    fi
    echo ""
}

# value written into NEW frps/frpc tomls: speed-first default is OFF unless explicitly enabled
perf_tcpmux_new() {
    [[ "$(perf_get_tcpmux)" == "1" ]] && echo true || echo false
}

# toml lines for a new config (keepalive only has meaning with mux on)
perf_tcpmux_lines() {
    if [[ "$(perf_tcpmux_new)" == "true" ]]; then
        printf 'transport.tcpMux = true\ntransport.tcpMuxKeepaliveInterval = 30'
    else
        printf 'transport.tcpMux = false'
    fi
}

# read-only: frpc logging "connect to server error: EOF" is the signature of a tcpMux mismatch
# (hub tcpMux=true, spoke false or vice versa). Prints the hint, never changes config.
tcpmux_eof_hint() {
    [[ -f "${CONFIG_DIR}/frpc.toml" ]] || return 1
    command -v journalctl >/dev/null 2>&1 || return 1
    # only the NEWEST login outcome counts: an old EOF followed by "login to server success" is a recovered tunnel
    journalctl -u frpc -n 200 --no-pager 2>/dev/null \
        | grep -E 'connect to server error: EOF|login to server success' | tail -n 1 \
        | grep -q 'connect to server error: EOF' || return 1
    echo "tcpMux mismatch: hub is likely tcpMux=true, run \`hashem perf tcpmux on|off\` (must match on hub and spoke)"
}

perf_get_enc() {
    if [[ -n "${PERF_ENC:-}" ]]; then
        [[ "$PERF_ENC" == "1" || "$PERF_ENC" == "true" ]] && echo 1 || echo 0
        return 0
    fi
    if [[ -f "$PERF_FILE" ]] && command -v python3 >/dev/null 2>&1; then
        python3 -c '
import json
try:
    with open("'"$PERF_FILE"'") as f:
        print(1 if json.load(f).get("proxy_encryption", False) else 0)
except Exception:
    print(0)
' 2>/dev/null && return 0
    elif [[ -f "$PERF_FILE" ]]; then
        grep -q '"proxy_encryption"[[:space:]]*:[[:space:]]*true' "$PERF_FILE" && echo 1 || echo 0
        return 0
    fi
    echo 0
}

perf_get_comp() {
    if [[ -n "${PERF_COMP:-}" ]]; then
        [[ "$PERF_COMP" == "1" || "$PERF_COMP" == "true" ]] && echo 1 || echo 0
        return 0
    fi
    if [[ -f "$PERF_FILE" ]] && command -v python3 >/dev/null 2>&1; then
        python3 -c '
import json
try:
    with open("'"$PERF_FILE"'") as f:
        print(1 if json.load(f).get("proxy_compression", False) else 0)
except Exception:
    print(0)
' 2>/dev/null && return 0
    elif [[ -f "$PERF_FILE" ]]; then
        grep -q '"proxy_compression"[[:space:]]*:[[:space:]]*true' "$PERF_FILE" && echo 1 || echo 0
        return 0
    fi
    echo 0
}

perf_set_val() {
    local key="$1" val="$2" is_raw="${3:-0}"
    init_perf_json
    if command -v python3 >/dev/null 2>&1; then
        python3 -c '
import json
path = "'"$PERF_FILE"'"
key = "'"$key"'"
raw = '"$is_raw"'
val_str = """'"$val"'"""
try:
    with open(path, "r") as f:
        d = json.load(f)
except Exception:
    d = {}
if raw:
    if val_str in ("true", "True", "1"):
        d[key] = True
    elif val_str in ("false", "False", "0"):
        d[key] = False
    else:
        try:
            d[key] = int(val_str)
        except Exception:
            d[key] = val_str
else:
    d[key] = val_str
for k in ("force_tls", "chaff_profile", "dpi_enabled", "dpi_rate", "dpi_burst", "auto_tune", "tuning_profile"):
    d.pop(k, None)
with open(path, "w") as f:
    json.dump(d, f, indent=2)
'
        chmod 600 "$PERF_FILE" 2>/dev/null || true
    fi
}

# drop keys of removed features from an existing perf.json (idempotent)
perf_prune_legacy_keys() {
    [[ -f "$PERF_FILE" ]] && command -v python3 >/dev/null 2>&1 || return 0
    python3 -c '
import json
path = "'"$PERF_FILE"'"
try:
    with open(path) as f:
        d = json.load(f)
    n = len(d)
    for k in ("force_tls", "chaff_profile", "dpi_enabled", "dpi_rate", "dpi_burst", "auto_tune", "tuning_profile"):
        d.pop(k, None)
    if len(d) != n:
        with open(path, "w") as f:
            json.dump(d, f, indent=2)
except Exception:
    pass
' 2>/dev/null || true
}

# ---- Auto Pool: one place decides poolCount (frpc) / maxPoolCount (frps) ----
# auto_pool in perf.json (missing = on). On: poolCount follows $AUTO_POOL_STATE written by autopool_tick;
# off: frp_pool_count / frp_max_pool from perf.json apply as typed.
perf_get_auto_pool() {
    if [[ -n "${PERF_AUTO_POOL:-}" ]]; then
        [[ "$PERF_AUTO_POOL" == "0" || "$PERF_AUTO_POOL" == "false" ]] && echo 0 || echo 1
        return 0
    fi
    if [[ -f "$PERF_FILE" ]] && command -v python3 >/dev/null 2>&1; then
        python3 -c '
import json
try:
    with open("'"$PERF_FILE"'") as f:
        print(1 if json.load(f).get("auto_pool", True) else 0)
except Exception:
    print(1)
' 2>/dev/null && return 0
    fi
    echo 1
}

# integer value from perf.json, $2 when missing/invalid
perf_get_int() {
    local key="$1" def="$2"
    [[ -f "$PERF_FILE" ]] && command -v python3 >/dev/null 2>&1 || { echo "$def"; return 0; }
    python3 -c '
import json
try:
    with open("'"$PERF_FILE"'") as f:
        print(int(json.load(f).get("'"$key"'", '"$def"')))
except Exception:
    print('"$def"')
' 2>/dev/null || echo "$def"
}

# pool_clamp VALUE MIN MAX
pool_clamp() {
    local v="$1" lo="$2" hi="$3"
    [[ "$v" =~ ^[0-9]+$ ]] || v="$lo"
    (( v < lo )) && v="$lo"
    (( v > hi )) && v="$hi"
    echo "$v"
}

# RAM ceiling for maxPoolCount: budget 10% of RAM at ~64KB per pooled work conn
# => cap = RAM_MB * 1024 * 0.10 / 64 = RAM_MB * 8 / 5, clamped to [AUTOPOOL_MAXPOOL_MIN, AUTOPOOL_MAXPOOL_MAX].
pool_ram_cap() {
    local ram="${AUTOPOOL_RAM_MB:-}"
    [[ "$ram" =~ ^[0-9]+$ ]] || ram=$(awk '/^MemTotal:/ {printf "%d", $2 / 1024}' /proc/meminfo 2>/dev/null)
    [[ "$ram" =~ ^[0-9]+$ && "$ram" -gt 0 ]] || ram=1024
    pool_clamp $(( ram * 8 / 5 )) "$AUTOPOOL_MAXPOOL_MIN" "$AUTOPOOL_MAXPOOL_MAX"
}

# state file accessors (auto_pool.json)
autopool_state_get() { # $1=key $2=default
    local def="${2:-}"
    [[ -f "$AUTO_POOL_STATE" ]] && command -v python3 >/dev/null 2>&1 || { echo "$def"; return 0; }
    python3 - "$AUTO_POOL_STATE" "$1" "$def" <<'PY' 2>/dev/null || echo "$def"
import json, sys
path, key, default = sys.argv[1:4]
try:
    with open(path) as f:
        v = json.load(f).get(key, default)
    print(str(v).lower() if isinstance(v, bool) else v)
except Exception:
    print(default)
PY
}

autopool_state_set() { # key=value ...  (ints / true / false stay typed)
    command -v python3 >/dev/null 2>&1 || return 0
    mkdir -p "$(dirname "$AUTO_POOL_STATE")" 2>/dev/null || true
    python3 - "$AUTO_POOL_STATE" "$@" <<'PY' 2>/dev/null || true
import json, os, sys
path = sys.argv[1]
try:
    with open(path) as f:
        d = json.load(f)
except Exception:
    d = {}
for kv in sys.argv[2:]:
    k, _, v = kv.partition("=")
    if v in ("true", "false"):
        d[k] = (v == "true")
    else:
        try:
            d[k] = int(v)
        except ValueError:
            d[k] = v
with open(path + ".tmp", "w") as f:
    json.dump(d, f, indent=2)
os.chmod(path + ".tmp", 0o600)
os.replace(path + ".tmp", path)
PY
}

# THE helper every frps/frpc writer uses. Prints "<poolCount> <maxPoolCount>".
# maxPoolCount is always >= 1.5 * poolCount; auto mode keeps poolCount <= 2/3 of the RAM cap so that holds.
pool_effective_values() {
    local cap pool maxp
    cap=$(pool_ram_cap)
    if [[ "$(perf_get_auto_pool)" == "1" ]]; then
        local hi=$(( cap * 2 / 3 ))
        (( hi > AUTOPOOL_MAX )) && hi="$AUTOPOOL_MAX"
        (( hi < AUTOPOOL_MIN )) && hi="$AUTOPOOL_MIN"
        pool=$(pool_clamp "$(autopool_state_get pool "$AUTOPOOL_MIN")" "$AUTOPOOL_MIN" "$hi")
        maxp="$cap"
    else
        pool=$(pool_clamp "$(perf_get_int frp_pool_count "$AUTOPOOL_MIN")" 2 1000)
        maxp=$(perf_get_int frp_max_pool 0)
        (( maxp >= 10 )) || maxp="$cap"
    fi
    local need=$(( (pool * 3 + 1) / 2 ))
    (( maxp < need )) && maxp="$need"
    echo "$pool $maxp"
}

# rewrite "<key> = N" in a toml header (before the first [[proxies]]); appends when missing
autopool_set_toml_key() { # $1=file $2=key $3=value
    local f="$1" key="$2" val="$3"
    [[ -f "$f" ]] || return 1
    if grep -Eq "^[[:space:]]*${key}[[:space:]]*=" "$f"; then
        sed -i -E "s|^([[:space:]]*${key}[[:space:]]*=[[:space:]]*).*|\1${val}|" "$f"
    else
        local hdr_end
        hdr_end=$(grep -n -m1 -E '^\[\[' "$f" | cut -d: -f1)
        if [[ -n "$hdr_end" ]]; then
            sed -i "$((hdr_end - 1))a ${key} = ${val}" "$f"
        else
            printf '%s = %s\n' "$key" "$val" >> "$f"
        fi
    fi
}

autopool_live_toml_int() { # $1=file $2=key
    grep -E "^[[:space:]]*$2[[:space:]]*=" "$1" 2>/dev/null | head -1 | sed -E 's/.*=[[:space:]]*([0-9]+).*/\1/'
}

# "work connection pool is full" lines logged by frpc since epoch $1
autopool_count_errors() {
    local since="$1" n=0
    if command -v journalctl >/dev/null 2>&1; then
        n=$(journalctl -u frpc --since "$(date -d "@${since}" '+%Y-%m-%d %H:%M:%S' 2>/dev/null)" --no-pager -q 2>/dev/null \
            | grep -c 'work connection pool is full')
    elif [[ -f "${AUTOPOOL_LOG_FILE:-/var/log/frpc.log}" ]]; then
        n=$(tail -n 2000 "${AUTOPOOL_LOG_FILE:-/var/log/frpc.log}" 2>/dev/null | grep -c 'work connection pool is full')
    fi
    [[ "$n" =~ ^[0-9]+$ ]] || n=0
    echo "$n"
}

# Established TCP conns to the hub (control + idle pool + in-flight work conns). "tunnel total"
autopool_conn_counts() { # $1=hub port
    local total tunnel=0
    total=$(ss -Htn state established 2>/dev/null | wc -l)
    [[ -n "$1" ]] && tunnel=$(ss -Htn state established "( dport = :$1 )" 2>/dev/null | wc -l)
    echo "$tunnel $total"
}

autopool_free_mb() {
    awk '/^MemAvailable:/ {printf "%d", $2 / 1024}' /proc/meminfo 2>/dev/null || echo 1024
}

# 1 when 1-min load exceeds 2x CPU count
autopool_cpu_hot() {
    local l ncpu
    l=$(awk '{printf "%d", $1 * 100}' /proc/loadavg 2>/dev/null)
    ncpu=$(nproc 2>/dev/null || echo 1)
    [[ "$l" =~ ^[0-9]+$ ]] || l=0
    (( l > ncpu * 200 )) && echo 1 || echo 0
}

# Called once a minute from watchdog_tick. Spoke: size frpc poolCount from pool-full errors, user
# conns and CPU/RAM; scale up x1.5 at once, scale down x0.8 only after AUTOPOOL_DOWN_QUIET quiet ticks.
# A change reaches frpc via a restart (never frps) only when <AUTOPOOL_LOW_CONNS user conns are active
# or errors are severe, and never within AUTOPOOL_COOLDOWN of the previous restart.
# Hub: never restarts frps; it only raises maxPoolCount in the toml and flags frps_restart_needed.
autopool_tick() {
    [[ "$(perf_get_auto_pool)" == "1" ]] || return 0
    local now cap
    now=$(date +%s)
    cap=$(pool_ram_cap)

    if [[ ! -f "${CONFIG_DIR}/frpc.toml" ]]; then
        local f live want need=0 f_ok=0
        read -r _ want <<< "$(pool_effective_values)"
        for f in "${CONFIG_DIR}"/frps*.toml; do
            [[ -f "$f" ]] || continue
            f_ok=1
            live=$(autopool_live_toml_int "$f" transport.maxPoolCount)
            if [[ -z "$live" ]] || (( live < want )); then
                autopool_set_toml_key "$f" transport.maxPoolCount "$want"
                need=1
            fi
        done
        [[ "$f_ok" -eq 1 ]] || return 0
        if [[ "$need" -eq 1 ]]; then
            autopool_state_set max_pool="$want" frps_restart_needed=true last_tick="$now" \
                last_decision=hub_raise_max "last_reason=maxPoolCount raised to ${want} in frps toml; restart frps when idle to apply"
        else
            autopool_state_set max_pool="$want" last_tick="$now"
        fi
        return 0
    fi

    local pool applied last_tick last_restart quiet hi
    hi=$(( cap * 2 / 3 ))
    (( hi > AUTOPOOL_MAX )) && hi="$AUTOPOOL_MAX"
    (( hi < AUTOPOOL_MIN )) && hi="$AUTOPOOL_MIN"
    applied=$(autopool_live_toml_int "${CONFIG_DIR}/frpc.toml" transport.poolCount)
    [[ "$applied" =~ ^[0-9]+$ ]] || applied="$AUTOPOOL_MIN"
    pool=$(pool_clamp "$(autopool_state_get pool "$applied")" "$AUTOPOOL_MIN" "$hi")
    last_tick=$(autopool_state_get last_tick $(( now - 60 )))
    last_restart=$(autopool_state_get last_restart 0)
    quiet=$(autopool_state_get quiet_ticks 0)
    [[ "$last_tick" =~ ^[0-9]+$ ]] || last_tick=$(( now - 60 ))
    [[ "$last_restart" =~ ^[0-9]+$ ]] || last_restart=0
    [[ "$quiet" =~ ^[0-9]+$ ]] || quiet=0

    local hub_port errs counts tunnel total active free_mb hot
    hub_port=$(autopool_live_toml_int "${CONFIG_DIR}/frpc.toml" serverPort)
    errs=$(autopool_count_errors "$last_tick")
    counts=$(autopool_conn_counts "$hub_port")
    read -r tunnel total <<< "$counts"
    active=$(( tunnel - 1 - applied ))
    (( active < 0 )) && active=0
    free_mb=$(autopool_free_mb)
    hot=$(autopool_cpu_hot)

    local decision="hold" reason="steady" new="$pool"
    if (( free_mb < AUTOPOOL_MIN_FREE_MB )) && (( errs > 0 || active > pool )); then
        reason="free RAM ${free_mb}MB below ${AUTOPOOL_MIN_FREE_MB}MB, not scaling up"
        quiet=0
    elif (( errs > 0 )) || { (( active > pool )) && [[ "$hot" -eq 0 ]]; }; then
        quiet=0
        new=$(( (pool * 3 + 1) / 2 ))
        (( new <= pool )) && new=$(( pool + 1 ))
        new=$(pool_clamp "$new" "$AUTOPOOL_MIN" "$hi")
        if (( new > pool )); then
            decision="scale_up"
            (( errs > 0 )) && reason="${errs} pool-full errors since last tick" || reason="${active} active conns exceed pool ${pool}"
        else
            reason="at ceiling ${hi} (errors=${errs})"
        fi
    elif (( errs == 0 )) && [[ "$hot" -eq 0 ]] && (( active < pool )); then
        quiet=$(( quiet + 1 ))
        if (( quiet >= AUTOPOOL_DOWN_QUIET )) && (( pool > AUTOPOOL_MIN )); then
            new=$(( pool * 4 / 5 ))
            (( new < active )) && new="$active"
            new=$(pool_clamp "$new" "$AUTOPOOL_MIN" "$hi")
            if (( new < pool )); then
                decision="scale_down"
                reason="${quiet} quiet ticks"
                quiet=0
            else
                new="$pool"
            fi
        else
            reason="quiet ${quiet}/${AUTOPOOL_DOWN_QUIET}"
        fi
    else
        quiet=0
        reason="busy (active=${active} load_hot=${hot})"
    fi
    pool="$new"

    local last_change; last_change=$(autopool_state_get last_change 0)
    [[ "$decision" == "scale_up" || "$decision" == "scale_down" ]] && last_change="$now"
    local max_pool="$cap" need_max=$(( (pool * 3 + 1) / 2 ))
    (( max_pool < need_max )) && max_pool="$need_max"

    # a pending change (state pool != live poolCount) reaches frpc only through the restart gate
    if (( pool != applied )); then
        local since=$(( now - last_restart ))
        if (( since < AUTOPOOL_COOLDOWN )); then
            decision="deferred"; reason="${reason}; cooldown $(( AUTOPOOL_COOLDOWN - since ))s left"
        elif (( active < AUTOPOOL_LOW_CONNS )) || (( errs >= AUTOPOOL_SEVERE_ERRS )); then
            autopool_set_toml_key "${CONFIG_DIR}/frpc.toml" transport.poolCount "$pool"
            systemctl restart frpc >/dev/null 2>&1 || true
            applied="$pool"; last_restart="$now"
            [[ "$decision" == "deferred" || "$decision" == "hold" ]] && decision="applied"
            reason="${reason}; frpc restarted"
        else
            decision="deferred"; reason="${reason}; ${active} active conns, waiting for <${AUTOPOOL_LOW_CONNS}"
        fi
    fi

    autopool_state_set pool="$pool" max_pool="$max_pool" applied_pool="$applied" quiet_ticks="$quiet" \
        last_tick="$now" last_restart="$last_restart" last_change="$last_change" last_decision="$decision" \
        "last_reason=${reason}" errors_last_tick="$errs" active_conns="$active" tunnel_conns="$tunnel" \
        total_conns="$total" free_mb="$free_mb" cpu_hot="$hot" role=foreign
}

# ---- input validation (same rules as the web panel: IPv4, port 1-65535) ----
is_valid_ip() {
    [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    local IFS=. a b c d o
    read -r a b c d <<<"$1"
    for o in "$a" "$b" "$c" "$d"; do
        ((10#$o <= 255)) || return 1
    done
}

is_valid_port() {
    [[ "$1" =~ ^[0-9]+$ ]] && ((10#$1 >= 1 && 10#$1 <= 65535))
}

panel_tls_issue() { # $1=domain [$2=email] — certbot standalone on :80 + install to /etc/gre-panel/tls
    local DOMAIN=${1:-} EMAIL=${2:-}
    [[ -z "$DOMAIN" ]] && read -p "Panel domain (e.g. panel.example.com, must point to this server): " DOMAIN
    [[ -z "$DOMAIN" ]] && { echo -e "${RED}[!] Domain is required.${NC}"; return 1; }
    # Clean domain from scheme or port
    DOMAIN=$(echo "$DOMAIN" | sed -e 's|^[^/]*//||' -e 's|/.*$||' -e 's|:.*$||' | tr '[:upper:]' '[:lower:]')
    read -p "Email for expiry notices [Enter to skip]: " EMAIL_IN
    EMAIL=${EMAIL:-$EMAIL_IN}

    # Pre-flight 1: Port 80 check
    if ss -tulpn 2>/dev/null | grep -q ":80 " || lsof -i :80 >/dev/null 2>&1; then
        echo -e "${YELLOW}[!] Warning: Port 80 is currently occupied. If using Nginx/Caddy, consider reverse proxying to panel port.${NC}"
    fi

    # Pre-flight 2: DNS check
    if command -v getent >/dev/null 2>&1; then
        local RESOLVED_IP
        RESOLVED_IP=$(getent ahosts "$DOMAIN" 2>/dev/null | awk '{print $1}' | head -n1)
        if [[ -z "$RESOLVED_IP" ]]; then
            echo -e "${RED}[!] DNS resolution failed for ${DOMAIN}. Please verify DNS records before proceeding.${NC}"
            return 1
        fi
    fi

    if ! command -v certbot >/dev/null 2>&1; then
        echo -e "${CYAN}[*] Installing certbot...${NC}"
        apt-get update -qq && apt-get install -y -qq certbot || { echo -e "${RED}[!] certbot install failed.${NC}"; return 1; }
    fi

    # Atomic backup of previous certs
    mkdir -p /etc/gre-panel/tls
    [[ -f /etc/gre-panel/tls/server.crt ]] && cp -f /etc/gre-panel/tls/server.crt /etc/gre-panel/tls/server.crt.bak
    [[ -f /etc/gre-panel/tls/server.key ]] && cp -f /etc/gre-panel/tls/server.key /etc/gre-panel/tls/server.key.bak
    [[ -f /etc/gre-panel/tls/meta.json ]] && cp -f /etc/gre-panel/tls/meta.json /etc/gre-panel/tls/meta.json.bak

    echo -e "${CYAN}[*] Issuing Let's Encrypt certificate for ${DOMAIN}...${NC}"
    local ARGS=(certonly --standalone --non-interactive --agree-tos --preferred-challenges http --http-01-port 80 -d "$DOMAIN")
    if [[ -n "$EMAIL" ]]; then ARGS+=(-m "$EMAIL"); else ARGS+=(--register-unsafely-without-email); fi
    if ! certbot "${ARGS[@]}"; then
        echo -e "${RED}[!] certbot failed — check DNS and port 80 accessibility.${NC}"
        # Rollback
        [[ -f /etc/gre-panel/tls/server.crt.bak ]] && mv -f /etc/gre-panel/tls/server.crt.bak /etc/gre-panel/tls/server.crt
        [[ -f /etc/gre-panel/tls/server.key.bak ]] && mv -f /etc/gre-panel/tls/server.key.bak /etc/gre-panel/tls/server.key
        [[ -f /etc/gre-panel/tls/meta.json.bak ]] && mv -f /etc/gre-panel/tls/meta.json.bak /etc/gre-panel/tls/meta.json
        echo -e "${YELLOW}[*] Previous panel configuration kept intact. Tunnels unaffected.${NC}"
        return 1
    fi

    cp "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" /etc/gre-panel/tls/server.crt
    cp "/etc/letsencrypt/live/${DOMAIN}/privkey.pem" /etc/gre-panel/tls/server.key
    chmod 600 /etc/gre-panel/tls/server.key
    echo "{\"domain\":\"$DOMAIN\",\"issued_at\":\"$(date '+%F %T')\"}" > /etc/gre-panel/tls/meta.json
    rm -f /etc/gre-panel/tls/*.bak

    # Reload only gre-panel (NEVER touch tunnel services)
    systemctl restart gre-panel 2>/dev/null || true
    sleep 2
    local PORT BASE TPORT
    PORT=$(grep -o '"port": *[0-9]*' /etc/gre-panel/panel.json 2>/dev/null | grep -o '[0-9]*'); PORT=${PORT:-7777}
    BASE=$(grep -o '"base_path": *"[^"]*"' /etc/gre-panel/panel.json 2>/dev/null | cut -d'"' -f4)
    TPORT=$(grep -o '"tls_port": *[0-9]*' /etc/gre-panel/panel.json 2>/dev/null | grep -o '[0-9]*'); TPORT=${TPORT:-7443}
    echo -e "${GREEN}[✔️] HTTPS ready: ${CYAN}https://${DOMAIN}:${TPORT}/${BASE}${NC}"
    echo -e "${GREEN}    HTTP still works: ${CYAN}http://<this-server-ip>:${PORT}/${BASE}${NC}"
    echo -e "${GREEN}    Tunnel infrastructure continues running without interruption.${NC}"
}

panel_tls_remove() {
    echo -e "${CYAN}[*] Removing custom domain and HTTPS certificates...${NC}"
    rm -f /etc/gre-panel/tls/server.crt /etc/gre-panel/tls/server.key /etc/gre-panel/tls/meta.json /etc/gre-panel/tls/*.bak
    systemctl restart gre-panel 2>/dev/null || true
    local PORT BASE
    PORT=$(grep -o '"port": *[0-9]*' /etc/gre-panel/panel.json 2>/dev/null | grep -o '[0-9]*'); PORT=${PORT:-7777}
    BASE=$(grep -o '"base_path": *"[^"]*"' /etc/gre-panel/panel.json 2>/dev/null | cut -d'"' -f4)
    echo -e "${GREEN}[✔️] Domain removed. Panel reverted to HTTP: ${CYAN}http://<this-server-ip>:${PORT}/${BASE}${NC}"
    echo -e "${GREEN}    Active tunnels remain fully operational.${NC}"
}

gen_token32() { # 32-char alphanumeric secret (FRP auth token)
    tr -dc A-Za-z0-9 </dev/urandom | head -c 32 2>/dev/null || openssl rand -hex 16
}

gen_random_port() { # random port 20000-60000 for FRP
    if command -v shuf >/dev/null 2>&1; then
        shuf -i 20000-60000 -n 1
    elif command -v python3 >/dev/null 2>&1; then
        python3 -c 'import random; print(random.randint(20000, 60000))'
    else
        awk 'BEGIN{srand(); print int(20000 + rand() * 40001)}'
    fi
}

# ---- Carrier & Multi-Protocol Failover (Direct GRE <-> FOU UDP) ----
init_carrier_json() {
    mkdir -p "$PANEL_CONFIG_DIR"
    if [[ ! -f "$CARRIER_FILE" ]]; then
        cat << 'EOF' > "$CARRIER_FILE"
{
  "mode": "direct",
  "active_carrier": "direct",
  "fou_port1": 443,
  "fou_port2": 55555,
  "wss_port": 8443,
  "candidates": [
    "direct",
    "wss:8443"
  ],
  "last_switch": "",
  "switch_count": 0
}
EOF
        chmod 600 "$CARRIER_FILE" 2>/dev/null || true
    fi
}

carrier_get_mode() {
    init_carrier_json
    python3 -c '
import json
try:
    with open("'"$CARRIER_FILE"'") as f:
        d = json.load(f)
        m = d.get("mode", "direct")
        if m == "auto":
            d["mode"] = "direct"
            with open("'"$CARRIER_FILE"'.tmp", "w") as ftmp:
                json.dump(d, ftmp, indent=2)
            import os
            os.replace("'"$CARRIER_FILE"'.tmp", "'"$CARRIER_FILE"'")
            print("direct")
        else:
            print(m)
except Exception:
    print("direct")
' 2>/dev/null || echo "direct"
}

carrier_get_active() {
    init_carrier_json
    python3 -c '
import json
try:
    with open("'"$CARRIER_FILE"'") as f:
        print(json.load(f).get("active_carrier", "direct"))
except Exception:
    print("direct")
' 2>/dev/null || echo "direct"
}

carrier_get_fou_ports() {
    init_carrier_json
    python3 -c '
import json
try:
    with open("'"$CARRIER_FILE"'") as f:
        d = json.load(f)
        p1 = d.get("fou_port1", 443)
        p2 = d.get("fou_port2", 55555)
        print(f"{p1} {p2}")
except Exception:
    print("443 55555")
' 2>/dev/null || echo "443 55555"
}

carrier_set_mode() {
    local M="$1"
    [[ "$M" == "auto" ]] && M="direct"
    [[ "$M" == "direct" || "$M" == fou:* || "$M" == wss* ]] || return 1
    init_carrier_json
    python3 -c '
import json, sys
p = "'"$CARRIER_FILE"'"
try:
    with open(p) as f:
        d = json.load(f)
except Exception:
    d = {}
d["mode"] = sys.argv[1]
with open(p + ".tmp", "w") as f:
    json.dump(d, f, indent=2)
import os
os.replace(p + ".tmp", p)
os.chmod(p, 0o600)
' "$M" 2>/dev/null || true
}

carrier_set_fou_ports() {
    local P1=$1 P2=$2
    is_valid_port "$P1" || return 1
    is_valid_port "$P2" || return 1
    init_carrier_json
    python3 -c '
import json, sys
p = "'"$CARRIER_FILE"'"
p1 = int(sys.argv[1])
p2 = int(sys.argv[2])
try:
    with open(p) as f:
        d = json.load(f)
except Exception:
    d = {}
wp = d.get("wss_port", 8443)
d["fou_port1"] = p1
d["fou_port2"] = p2
d["candidates"] = ["direct", f"wss:{wp}"]
with open(p + ".tmp", "w") as f:
    json.dump(d, f, indent=2)
import os
os.replace(p + ".tmp", p)
os.chmod(p, 0o600)
' "$P1" "$P2" 2>/dev/null || true
}

carrier_init_kernel() {
    modprobe fou >/dev/null 2>&1 || true
    modprobe ip_gre >/dev/null 2>&1 || true
    local P1 P2
    read -r P1 P2 <<< "$(carrier_get_fou_ports)"
    if is_valid_port "$P1"; then
        ip fou add port "$P1" ipproto 47 >/dev/null 2>&1 || true
        iptables -C INPUT -p udp --dport "$P1" -j ACCEPT >/dev/null 2>&1 || \
            iptables -I INPUT 1 -p udp --dport "$P1" -j ACCEPT >/dev/null 2>&1 || true
        if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
            ufw allow "$P1"/udp >/dev/null 2>&1 || true
        fi
    fi
    if is_valid_port "$P2" && [[ "$P2" != "$P1" ]]; then
        ip fou add port "$P2" ipproto 47 >/dev/null 2>&1 || true
        iptables -C INPUT -p udp --dport "$P2" -j ACCEPT >/dev/null 2>&1 || \
            iptables -I INPUT 1 -p udp --dport "$P2" -j ACCEPT >/dev/null 2>&1 || true
        if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
            ufw allow "$P2"/udp >/dev/null 2>&1 || true
        fi
    fi
    local WP=8443
    if [[ -f "$CARRIER_FILE" ]] && command -v python3 >/dev/null 2>&1; then
        WP=$(python3 -c "import json; print(json.load(open('$CARRIER_FILE')).get('wss_port', 8443))" 2>/dev/null || echo 8443)
    fi
    iptables -C INPUT -p tcp --dport "$WP" -j ACCEPT >/dev/null 2>&1 || \
        iptables -I INPUT 1 -p tcp --dport "$WP" -j ACCEPT >/dev/null 2>&1 || true
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
        ufw allow "$WP"/tcp >/dev/null 2>&1 || true
    fi
    ip fou add port 19998 ipproto 47 >/dev/null 2>&1 || true
}

carrier_apply() {
    local TARGET="$1"
    local SPECIFIC_IF="${2:-}"
    [[ -z "$TARGET" ]] && TARGET="direct"
    carrier_init_kernel

    local IFS_TO_APPLY=()
    if [[ -n "$SPECIFIC_IF" ]]; then
        IFS_TO_APPLY+=("$SPECIFIC_IF")
    else
        local dev
        for dev in $(ip -o link show type gre 2>/dev/null | awk -F': ' '{print $2}' | cut -d'@' -f1); do
            [[ "$dev" == "gre0" || "$dev" == "gretap0" ]] && continue
            IFS_TO_APPLY+=("$dev")
        done
        if [[ ${#IFS_TO_APPLY[@]} -eq 0 ]]; then
            IFS_TO_APPLY+=("$TUNNEL_NAME")
        fi
    fi

    local ANY_APPLIED=0
    for dev in "${IFS_TO_APPLY[@]}"; do
        if ip link show "$dev" >/dev/null 2>&1; then
            # Record current IPv4 address so it can NEVER be lost when toggling state
            local DEV_IP=""
            DEV_IP=$(ip -o -4 addr show dev "$dev" 2>/dev/null | awk '{print $4}' | head -1)
            if [[ -z "$DEV_IP" ]]; then
                if [[ "$dev" == "$TUNNEL_NAME" ]]; then
                    if [[ -f "/etc/frp/frps.toml" ]]; then
                        DEV_IP="10.10.10.2/30"
                    elif [[ -f "/etc/frp/frpc.toml" ]]; then
                        DEV_IP="10.10.10.1/30"
                    fi
                fi
            fi

            local TARGET_MTU=1380
            [[ "$TARGET" == wss* ]] && TARGET_MTU=1360

            local CHANGED=0
            if [[ "$TARGET" == "direct" ]]; then
                iptables -t nat -D OUTPUT -p udp --dport 19999 -j DNAT --to-destination 127.0.0.1:19999 >/dev/null 2>&1 || true
                if ip link set dev "$dev" type gre encap none >/dev/null 2>&1; then
                    CHANGED=1
                else
                    ip link set dev "$dev" down >/dev/null 2>&1 || true
                    if ip link set dev "$dev" type gre encap none >/dev/null 2>&1; then
                        CHANGED=1
                    fi
                fi
                ANY_APPLIED=1
            elif [[ "$TARGET" == fou:* ]]; then
                iptables -t nat -D OUTPUT -p udp --dport 19999 -j DNAT --to-destination 127.0.0.1:19999 >/dev/null 2>&1 || true
                local DPORT="${TARGET#fou:}"
                if is_valid_port "$DPORT"; then
                    ip fou add port "$DPORT" ipproto 47 >/dev/null 2>&1 || true
                    if ip link set dev "$dev" type gre encap fou encap-sport auto encap-dport "$DPORT" >/dev/null 2>&1; then
                        CHANGED=1
                    else
                        ip link set dev "$dev" down >/dev/null 2>&1 || true
                        if ip link set dev "$dev" type gre encap fou encap-sport auto encap-dport "$DPORT" >/dev/null 2>&1; then
                            CHANGED=1
                        fi
                    fi
                    ANY_APPLIED=1
                fi
            elif [[ "$TARGET" == wss* ]]; then
                local WPORT="8443"
                [[ "$TARGET" == wss:* ]] && WPORT="${TARGET#wss:}"
                iptables -C INPUT -p tcp --dport "$WPORT" -j ACCEPT >/dev/null 2>&1 || \
                    iptables -I INPUT 1 -p tcp --dport "$WPORT" -j ACCEPT >/dev/null 2>&1 || true
                if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
                    ufw allow "$WPORT"/tcp >/dev/null 2>&1 || true
                fi
                ip fou add port 19998 ipproto 47 >/dev/null 2>&1 || true
                iptables -t nat -C OUTPUT -p udp --dport 19999 -j DNAT --to-destination 127.0.0.1:19999 >/dev/null 2>&1 || \
                    iptables -t nat -A OUTPUT -p udp --dport 19999 -j DNAT --to-destination 127.0.0.1:19999 >/dev/null 2>&1 || true
                if ip link set dev "$dev" type gre encap fou encap-sport auto encap-dport 19999 >/dev/null 2>&1; then
                    CHANGED=1
                else
                    ip link set dev "$dev" down >/dev/null 2>&1 || true
                    if ip link set dev "$dev" type gre encap fou encap-sport auto encap-dport 19999 >/dev/null 2>&1; then
                        CHANGED=1
                    fi
                fi
                ANY_APPLIED=1
            fi

            # If dynamic changelink is unsupported by this kernel, re-instantiate cleanly in-place
            if [[ "$CHANGED" -eq 0 ]]; then
                local REMOTE_PUB LOCAL_PUB
                REMOTE_PUB=$(ip tunnel show "$dev" 2>/dev/null | awk '/remote/ {for(i=1;i<=NF;i++) if($i=="remote") print $(i+1)}' | head -1)
                LOCAL_PUB=$(ip tunnel show "$dev" 2>/dev/null | awk '/local/ {for(i=1;i<=NF;i++) if($i=="local") print $(i+1)}' | head -1)
                if [[ -n "$REMOTE_PUB" ]]; then
                    ip tunnel del "$dev" >/dev/null 2>&1 || ip link del "$dev" >/dev/null 2>&1 || true
                    local LOCAL_OPTS=""
                    [[ -n "$LOCAL_PUB" && "$LOCAL_PUB" != "any" ]] && LOCAL_OPTS="local $LOCAL_PUB"
                    if [[ "$TARGET" == "direct" ]]; then
                        ip link add name "$dev" type gre $LOCAL_OPTS remote "$REMOTE_PUB" ttl 255 >/dev/null 2>&1 || true
                    elif [[ "$TARGET" == fou:* ]]; then
                        local DPORT="${TARGET#fou:}"
                        ip link add name "$dev" type gre $LOCAL_OPTS remote "$REMOTE_PUB" ttl 255 encap fou encap-sport auto encap-dport "$DPORT" >/dev/null 2>&1 || true
                    elif [[ "$TARGET" == wss* ]]; then
                        ip link add name "$dev" type gre $LOCAL_OPTS remote "$REMOTE_PUB" ttl 255 encap fou encap-sport auto encap-dport 19999 >/dev/null 2>&1 || true
                    fi
                    # Fallback safeguard: if encap creation failed, re-create as direct GRE so tunnel is never left broken
                    if ! ip link show "$dev" >/dev/null 2>&1; then
                        ip link add name "$dev" type gre $LOCAL_OPTS remote "$REMOTE_PUB" ttl 255 >/dev/null 2>&1 || \
                        ip tunnel add "$dev" mode gre $LOCAL_OPTS remote "$REMOTE_PUB" ttl 255 >/dev/null 2>&1 || true
                    fi
                    ANY_APPLIED=1
                fi
            fi

            # Always bring interface up with proper MTU and restore inner IPv4 address
            ip link set dev "$dev" up mtu "$TARGET_MTU" >/dev/null 2>&1 || true
            if [[ -n "$DEV_IP" ]]; then
                if ! ip -o -4 addr show dev "$dev" 2>/dev/null | grep -q "${DEV_IP%/*}"; then
                    ip addr add "$DEV_IP" dev "$dev" >/dev/null 2>&1 || true
                fi
            fi
            iptables -t mangle -C POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1340 >/dev/null 2>&1 || \
                iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1340 >/dev/null 2>&1 || true
        fi
    done

    python3 -c '
import json, time, sys
p = "'"$CARRIER_FILE"'"
try:
    with open(p) as f:
        d = json.load(f)
except Exception:
    d = {}
d["active_carrier"] = sys.argv[1]
d["last_switch"] = time.strftime("%Y-%m-%d %H:%M:%S")
d["switch_count"] = int(d.get("switch_count", 0)) + 1
with open(p + ".tmp", "w") as f:
    json.dump(d, f, indent=2)
import os
os.replace(p + ".tmp", p)
os.chmod(p, 0o600)
' "$TARGET" 2>/dev/null || true

    if [[ $ANY_APPLIED -eq 1 ]]; then
        return 0
    fi
    # Don't call systemctl restart recursively if invoked from a systemd service hook
    if [[ -z "${SYSTEMD_EXEC_PID:-}" && -z "${INVOCATION_ID:-}" && -n "${IFS_TO_APPLY[0]:-}" ]]; then
        systemctl restart "${IFS_TO_APPLY[0]}.service" >/dev/null 2>&1 || true
    fi
    return 0
}

carrier_apply_active() {
    local IFNAME="${1:-}"
    local ACT=""
    if [[ -n "$IFNAME" && -f "$PEERS_FILE" ]]; then
        ACT=$(python3 -c '
import json, sys
ifname = sys.argv[1]
try:
    with open("'"$PEERS_FILE"'") as f:
        d = json.load(f)
    for p in d.get("peers", []):
        if p.get("gre_if") == ifname and p.get("carrier"):
            print(p["carrier"])
            sys.exit(0)
except Exception:
    pass
' "$IFNAME" 2>/dev/null || true)
    fi
    if [[ -z "$ACT" ]]; then
        ACT=$(carrier_get_active)
    fi
    carrier_apply "$ACT" "$IFNAME"
}

carrier_cycle_next() {
    init_carrier_json
    local NEXT
    NEXT=$(python3 -c '
import json
path = "'"$CARRIER_FILE"'"
try:
    with open(path) as f:
        d = json.load(f)
    cur = d.get("active_carrier", "direct")
    p1 = d.get("fou_port1", 443)
    p2 = d.get("fou_port2", 55555)
    wp = d.get("wss_port", 8443)
    cands = d.get("candidates", ["direct", f"fou:{p1}", f"fou:{p2}", f"wss:{wp}"])
    if cur in cands:
        idx = (cands.index(cur) + 1) % len(cands)
        next_cand = cands[idx]
    else:
        next_cand = cands[0] if cands else "direct"
    print(next_cand)
except Exception:
    print("direct")
' 2>/dev/null || echo "direct")

    carrier_apply "$NEXT" >/dev/null 2>&1
    echo "$NEXT"
}

# ---- setup bundle: one readable string with everything foreign needs ----
# Format: hsh1_<IRAN_PUB>_<FRP_PORT>_<IRAN_GRE>_<FOREIGN_GRE>_<TOKEN>[_<PORTS>][_fou<P1>-<P2>]
# Format: bh1_<IRAN_PUB>_<BH_PORT>_<TRANSPORT>_<TOKEN>[_<PORTS>]
# Format: gh1_<IRAN_PUB>_<BH_PORT>_<IRAN_GRE>_<FOREIGN_GRE>_<TRANSPORT>_<TOKEN>[_<PORTS>]
BUNDLE_PREFIX="hsh1_"
BUNDLE_PREFIX_BACKHAUL="bh1_"
BUNDLE_PREFIX_GRE_BACKHAUL="gh1_"

bundle_make() { # $1=iran_pub $2=frp_port $3=iran_gre $4=foreign_gre $5=token [$6="p1 p2"] [$7="p1-p2"] [$8=transport]
    local IRAN_PUB=$1 FRP_PORT=$2 IRAN_GRE=$3 FOREIGN_GRE=$4 TOKEN=$5 PORTS_SP=${6:-} FOU_ARG=${7:-} FRP_TRANS=${8:-}
    local PORTS_DASH=""
    if [[ -n "$PORTS_SP" ]]; then
        PORTS_DASH=$(echo "$PORTS_SP" | xargs | tr ' ' '-')
    fi
    if [[ -z "$FOU_ARG" ]]; then
        local P1 P2
        read -r P1 P2 <<< "$(carrier_get_fou_ports 2>/dev/null || echo '443 55555')"
        FOU_ARG="${P1}-${P2}"
    fi
    local TR_SUFFIX=""
    if [[ -n "$FRP_TRANS" && "$FRP_TRANS" != "tcp" ]]; then
        TR_SUFFIX="_tr-${FRP_TRANS}"
    fi
    if [[ -n "$PORTS_DASH" ]]; then
        echo "${BUNDLE_PREFIX}${IRAN_PUB}_${FRP_PORT}_${IRAN_GRE}_${FOREIGN_GRE}_${TOKEN}_${PORTS_DASH}_fou${FOU_ARG}${TR_SUFFIX}"
    else
        echo "${BUNDLE_PREFIX}${IRAN_PUB}_${FRP_PORT}_${IRAN_GRE}_${FOREIGN_GRE}_${TOKEN}__fou${FOU_ARG}${TR_SUFFIX}"
    fi
}

bundle_make_backhaul() { # $1=iran_pub $2=bh_port $3=transport $4=token [$5="ports"]
    local IRAN_PUB=$1 BH_PORT=$2 TRANSPORT=${3:-tcpmux} TOKEN=$4 PORTS=${5:-}
    local P_STR=""
    if [[ -n "$PORTS" ]]; then
        P_STR=$(echo "$PORTS" | tr ' ' ',' | tr -s ',')
    fi
    if [[ -n "$P_STR" ]]; then
        echo "${BUNDLE_PREFIX_BACKHAUL}${IRAN_PUB}_${BH_PORT}_${TRANSPORT}_${TOKEN}_${P_STR}"
    else
        echo "${BUNDLE_PREFIX_BACKHAUL}${IRAN_PUB}_${BH_PORT}_${TRANSPORT}_${TOKEN}"
    fi
}

bundle_make_gre_backhaul() { # $1=iran_pub $2=bh_port $3=iran_gre $4=foreign_gre $5=transport $6=token [$7="ports"]
    local IRAN_PUB=$1 BH_PORT=$2 IRAN_GRE=$3 FOREIGN_GRE=$4 TRANSPORT=${5:-tcpmux} TOKEN=$6 PORTS=${7:-}
    local P_STR=""
    if [[ -n "$PORTS" ]]; then
        P_STR=$(echo "$PORTS" | tr ' ' ',' | tr -s ',')
    fi
    if [[ -n "$P_STR" ]]; then
        echo "${BUNDLE_PREFIX_GRE_BACKHAUL}${IRAN_PUB}_${BH_PORT}_${IRAN_GRE}_${FOREIGN_GRE}_${TRANSPORT}_${TOKEN}_${P_STR}"
    else
        echo "${BUNDLE_PREFIX_GRE_BACKHAUL}${IRAN_PUB}_${BH_PORT}_${IRAN_GRE}_${FOREIGN_GRE}_${TRANSPORT}_${TOKEN}"
    fi
}

bundle_parse() {
    local IN=$1
    if [[ "$IN" == ${BUNDLE_PREFIX_BACKHAUL}* ]]; then
        B_ENGINE="backhaul"; B_IRAN_PUB=""; B_FRP_PORT=""; B_TRANSPORT="tcpmux"; B_TOKEN=""; B_PORTS=""
        local rest=${IN#${BUNDLE_PREFIX_BACKHAUL}}
        local a b c d e
        IFS=_ read -r a b c d e <<<"$rest"
        [[ -n "$a" && -n "$b" && -n "$c" && -n "$d" ]] || return 1
        is_valid_ip "$a" || return 1
        is_valid_port "$b" || return 1
        [[ ${#d} -ge 1 && ${#d} -le 128 ]] || return 1
        B_IRAN_PUB="$a"
        B_FRP_PORT="$((10#$b))"
        B_TRANSPORT="$c"
        B_TOKEN="$d"
        B_PORTS="${e:-}"
        return 0
    elif [[ "$IN" == ${BUNDLE_PREFIX_GRE_BACKHAUL}* ]]; then
        B_ENGINE="gre-backhaul"; B_IRAN_PUB=""; B_FRP_PORT=""; B_IRAN_GRE=""; B_FOREIGN_GRE=""; B_TRANSPORT="tcpmux"; B_TOKEN=""; B_PORTS=""
        local rest=${IN#${BUNDLE_PREFIX_GRE_BACKHAUL}}
        local a b c d e f g
        IFS=_ read -r a b c d e f g <<<"$rest"
        [[ -n "$a" && -n "$b" && -n "$c" && -n "$d" && -n "$e" && -n "$f" ]] || return 1
        is_valid_ip "$a" || return 1
        is_valid_port "$b" || return 1
        is_valid_ip "$c" || return 1
        is_valid_ip "$d" || return 1
        [[ ${#f} -ge 1 && ${#f} -le 128 ]] || return 1
        B_IRAN_PUB="$a"
        B_FRP_PORT="$((10#$b))"
        B_IRAN_GRE="$c"
        B_FOREIGN_GRE="$d"
        B_TRANSPORT="$e"
        B_TOKEN="$f"
        B_PORTS="${g:-}"
        return 0
    fi
    B_ENGINE="frp"; B_IRAN_PUB=""; B_FRP_PORT=""; B_IRAN_GRE=""; B_FOREIGN_GRE=""; B_TOKEN=""; B_PORTS=""; B_TRANSPORT="tcp"; B_FOU_P1=443; B_FOU_P2=55555
    local rest a b c d e f g h
    [[ "$IN" == ${BUNDLE_PREFIX}* ]] || return 1
    rest=${IN#${BUNDLE_PREFIX}}
    IFS=_ read -r a b c d e f g h <<<"$rest"
    [[ -n "$a" && -n "$b" && -n "$c" && -n "$d" && -n "$e" ]] || return 1
    is_valid_ip "$a" || return 1
    is_valid_port "$b" || return 1
    is_valid_ip "$c" || return 1
    is_valid_ip "$d" || return 1
    [[ ${#e} -ge 1 && ${#e} -le 128 ]] || return 1
    local CLEANED="" p
    if [[ -n "${f:-}" && "$f" != fou* && "$f" != tr-* ]]; then
        for p in $(echo "$f" | tr -- '-,' '  '); do
            is_valid_port "$p" && CLEANED="$CLEANED $((10#$p))"
        done
        CLEANED=$(echo "$CLEANED" | xargs)
        [[ -n "$CLEANED" ]] || return 1
    fi
    local FOU_RAW=""
    for seg in "$f" "$g" "$h"; do
        if [[ "$seg" == tr-* ]]; then
            B_TRANSPORT="${seg#tr-}"
        elif [[ "$seg" == fou* ]]; then
            FOU_RAW="$seg"
        fi
    done
    if [[ -n "$FOU_RAW" ]]; then
        local FP1 FP2
        IFS=- read -r FP1 FP2 <<< "${FOU_RAW#fou}"
        is_valid_port "$FP1" && B_FOU_P1=$((10#$FP1))
        is_valid_port "$FP2" && B_FOU_P2=$((10#$FP2))
    fi
    B_IRAN_PUB=$a; B_FRP_PORT=$((10#$b)); B_IRAN_GRE=$c; B_FOREIGN_GRE=$d; B_TOKEN=$e; B_PORTS=$CLEANED
    return 0
}
prompt_ip() { # $1=varname $2=label $3=default (empty = required)
    local __var=$1 __label=$2 __def=$3 __in
    while true; do
        if [[ -n "$__def" ]]; then
            read -p "$__label [Default: $__def]: " __in
            __in=${__in:-$__def}
        else
            read -p "$__label: " __in
        fi
        if is_valid_ip "$__in"; then printf -v "$__var" '%s' "$__in"; return 0; fi
        echo -e "${RED}[!] Invalid IPv4 address: '${__in}'. Example: 203.0.113.10${NC}"
    done
}

prompt_port() { # $1=varname $2=label $3=default
    local __var=$1 __label=$2 __def=$3 __in
    while true; do
        read -p "$__label [Default: $__def]: " __in
        __in=${__in:-$__def}
        if is_valid_port "$__in"; then printf -v "$__var" '%s' "$((10#$__in))"; return 0; fi
        echo -e "${RED}[!] Invalid port: '${__in}'. Must be 1-65535.${NC}"
    done
}

prompt_required() { # $1=varname $2=label — must be non-empty
    local __var=$1 __label=$2 __in
    while true; do
        read -p "$__label: " __in
        if [[ -n "$__in" ]]; then printf -v "$__var" '%s' "$__in"; return 0; fi
        echo -e "${RED}[!] This field is required and cannot be empty.${NC}"
    done
}

prompt_token() { # $1=varname $2=label $3=default (empty accepts default)
    local __var=$1 __label=$2 __def=$3 __in
    while true; do
        read -p "$__label [Press Enter for: $__def]: " __in
        __in="${__in:-$__def}"
        if [[ "$__in" == *"_"* ]]; then
            echo -e "${RED}[!] Token cannot contain underscores ('_') as it breaks the bundle format.${NC}"
        else
            printf -v "$__var" '%s' "$__in"
            return 0
        fi
    done
}

prompt_ports() { # $1=varname $2=label — at least one valid port
    local __var=$1 __label=$2 __in __ok p
    while true; do
        read -p "$__label (e.g. 443, 2083, 8080): " __in
        __ok=""
        for p in $(echo "$__in" | tr ',' ' '); do
            is_valid_port "$p" && __ok="$__ok $((10#$p))"
        done
        __ok=$(echo "$__ok" | xargs)
        if [[ -n "$__ok" ]]; then printf -v "$__var" '%s' "$__ok"; return 0; fi
        echo -e "${RED}[!] Enter at least one valid port (1-65535).${NC}"
    done
}

# validate_setup_common checks non-interactive args with the same rules as
# the prompts above. Prints a clear error per bad field, returns non-zero.
validate_setup_common() { # $1=local_pub $2=remote_pub $3=frp_port $4=local_gre
    local ok=1
    is_valid_ip "$1" || { echo -e "${RED}[!] Invalid local public IP: '$1'${NC}"; ok=0; }
    is_valid_ip "$2" || { echo -e "${RED}[!] Invalid remote public IP: '$2'${NC}"; ok=0; }
    is_valid_port "$3" || { echo -e "${RED}[!] Invalid FRP port: '$3' (must be 1-65535)${NC}"; ok=0; }
    is_valid_ip "$4" || { echo -e "${RED}[!] Invalid local GRE IP: '$4'${NC}"; ok=0; }
    return $((1 - ok))
}

tunnel_present() {
    ip link show "$TUNNEL_NAME" >/dev/null 2>&1 && return 0
    ip tunnel show 2>/dev/null | grep -q "$TUNNEL_NAME" && return 0
    [[ -f "${CONFIG_DIR}/frps.toml" || -f "${CONFIG_DIR}/frpc.toml" ]] && return 0
    return 1
}

# ---- Dial route (foreign side): how frpc / backhaul-client reaches the Iran hub ----
# The control connection can go over the GRE inner address (default) or straight
# to the hub's public IP (the hub listens on 0.0.0.0). When GRE is blocked on one
# path (ICMP/protocol 47 dropped) the public route keeps FRP alive.
# dial.env keeps: DIAL_MODE=auto|gre|public  DIAL_KIND=frp|backhaul  DIAL_GRE  DIAL_PUBLIC
dial_env_file() { echo "${CONFIG_DIR}/dial.env"; }

dial_env_write() { # $1=mode $2=kind $3=gre_ip $4=public_ip
    mkdir -p "$CONFIG_DIR"
    printf 'DIAL_MODE=%s\nDIAL_KIND=%s\nDIAL_GRE=%s\nDIAL_PUBLIC=%s\n' "$1" "$2" "$3" "$4" > "$(dial_env_file)"
    chmod 600 "$(dial_env_file)" 2>/dev/null || true
}

dial_env_get() { # $1=KEY
    local f; f="$(dial_env_file)"
    [[ -f "$f" ]] || return 1
    sed -n "s/^$1=//p" "$f" | head -n1
}

dial_conf_file() { # $1=kind
    if [[ "$1" == "backhaul" ]]; then echo "${BACKHAUL_CONFIG_DIR:-/etc/backhaul}/client.toml"; else echo "${CONFIG_DIR}/frpc.toml"; fi
}

dial_service() { [[ "$1" == "backhaul" ]] && echo backhaul-client || echo frpc; }

dial_current_addr() { # $1=kind -> host currently dialled
    local f; f="$(dial_conf_file "$1")"
    [[ -f "$f" ]] || return 1
    if [[ "$1" == "backhaul" ]]; then
        sed -n 's/^remote_addr[[:space:]]*=[[:space:]]*"\([^":]*\):[0-9]*".*/\1/p' "$f" | head -n1
    else
        sed -n 's/^serverAddr[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$f" | head -n1
    fi
}

dial_current_port() { # $1=kind
    local f; f="$(dial_conf_file "$1")"
    [[ -f "$f" ]] || return 1
    if [[ "$1" == "backhaul" ]]; then
        sed -n 's/^remote_addr[[:space:]]*=[[:space:]]*"[^":]*:\([0-9]*\)".*/\1/p' "$f" | head -n1
    else
        sed -n 's/^serverPort[[:space:]]*=[[:space:]]*\([0-9]*\).*/\1/p' "$f" | head -n1
    fi
}

# GRE is "usable" when its inner address answers ping or accepts the control port.
dial_gre_usable() { # $1=gre_ip $2=port
    ping -c 2 -W 2 "$1" >/dev/null 2>&1 && return 0
    timeout 3 bash -c "exec 3<>/dev/tcp/$1/$2" >/dev/null 2>&1 && return 0
    return 1
}

dial_pick() { # $1=mode $2=gre_ip $3=public_ip $4=port -> chosen address
    case "$1" in
        gre)    echo "$2" ;;
        public) echo "$3" ;;
        *)      if dial_gre_usable "$2" "$4"; then echo "$2"; else echo "$3"; fi ;;
    esac
}

dial_apply_addr() { # $1=kind $2=addr $3=port
    local f; f="$(dial_conf_file "$1")"
    [[ -f "$f" ]] || return 1
    if [[ "$1" == "backhaul" ]]; then
        sed -i -E "s|^remote_addr[[:space:]]*=.*|remote_addr = \"$2:$3\"|" "$f"
    else
        sed -i -E "s|^serverAddr[[:space:]]*=.*|serverAddr = \"$2\"|" "$f"
    fi
}

# Older installs have no dial.env: rebuild it from the live GRE interface + client config.
dial_env_ensure() {
    [[ -f "$(dial_env_file)" ]] && return 0
    local kind="" cur pub inner gre a b c d
    if [[ -f "${CONFIG_DIR}/frpc.toml" ]]; then kind=frp
    elif [[ -f "${BACKHAUL_CONFIG_DIR:-/etc/backhaul}/client.toml" ]]; then kind=backhaul
    else return 1; fi
    cur=$(dial_current_addr "$kind"); [[ -n "$cur" ]] || return 1
    pub=$(ip tunnel show "$TUNNEL_NAME" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="remote") print $(i+1)}' | head -n1)
    inner=$(ip -4 addr show dev "$TUNNEL_NAME" 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1)
    gre=""
    if [[ "$cur" =~ ^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.) ]]; then
        gre="$cur"
    elif [[ -n "$inner" ]]; then
        IFS=. read -r a b c d <<< "$inner"
        if (( d % 2 == 0 )); then gre="$a.$b.$c.$((d - 1))"; else gre="$a.$b.$c.$((d + 1))"; fi
    fi
    [[ -z "$pub" && "$cur" != "$gre" ]] && pub="$cur"
    [[ -n "$gre" && -n "$pub" ]] || return 1
    dial_env_write auto "$kind" "$gre" "$pub"
}

# dial_reselect [mode]: re-evaluate the route and rewrite the client config.
# Prints "changed:<addr>" / "same:<addr>". Does NOT restart the service.
dial_reselect() {
    dial_env_ensure || return 1
    local mode kind gre pub port cur want
    kind=$(dial_env_get DIAL_KIND); gre=$(dial_env_get DIAL_GRE); pub=$(dial_env_get DIAL_PUBLIC)
    mode="${1:-$(dial_env_get DIAL_MODE)}"; mode="${mode:-auto}"
    port=$(dial_current_port "$kind"); cur=$(dial_current_addr "$kind")
    [[ -n "$kind" && -n "$port" && -n "$cur" ]] || return 1
    want=$(dial_pick "$mode" "$gre" "$pub" "$port")
    [[ -n "$want" ]] || return 1
    if [[ "$want" == "$cur" ]]; then
        echo "same:$cur"
    else
        dial_apply_addr "$kind" "$want" "$port" || return 1
        echo "changed:$want"
    fi
}

# True when the client already holds an established TCP session to its server.
dial_connected() { # $1=addr $2=port
    ss -Htn state established 2>/dev/null | awk -v a="$1:$2" '$4==a {f=1} END {exit !f}'
}

# Watchdog hook (auto mode only): GRE died and the client is not connected -> go public.
dial_watch_tick() {
    [[ -f "$(dial_env_file)" ]] || return 0
    [[ "$(dial_env_get DIAL_MODE)" == "auto" ]] || return 0
    local kind gre pub port cur svc
    kind=$(dial_env_get DIAL_KIND); gre=$(dial_env_get DIAL_GRE); pub=$(dial_env_get DIAL_PUBLIC)
    port=$(dial_current_port "$kind"); cur=$(dial_current_addr "$kind")
    [[ -n "$port" && "$cur" == "$gre" ]] || return 0
    dial_connected "$cur" "$port" && return 0
    dial_gre_usable "$gre" "$port" && return 0
    dial_apply_addr "$kind" "$pub" "$port" || return 0
    svc=$(dial_service "$kind")
    systemctl restart "$svc" >/dev/null 2>&1 || true
    log_msg "tunnel" "WARN" "GRE path to ${gre} dead; ${svc} now dials Iran public ${pub}:${port}" 2>/dev/null || true
}

cli_dial() {
    local sub="${1:-status}"
    case "$sub" in
        status)
            if ! dial_env_ensure; then echo "available=0"; return 0; fi
            local kind cur port mode gre pub active
            kind=$(dial_env_get DIAL_KIND); gre=$(dial_env_get DIAL_GRE); pub=$(dial_env_get DIAL_PUBLIC)
            mode=$(dial_env_get DIAL_MODE); cur=$(dial_current_addr "$kind"); port=$(dial_current_port "$kind")
            active="other"; [[ "$cur" == "$gre" ]] && active=gre; [[ "$cur" == "$pub" ]] && active=public
            echo "available=1"; echo "mode=${mode:-auto}"; echo "active=$active"; echo "addr=$cur"
            echo "port=$port"; echo "gre=$gre"; echo "public=$pub"; echo "kind=$kind"
            ;;
        auto|gre|public)
            dial_env_ensure || { echo -e "${RED}[!] No foreign client config found (frpc / backhaul client).${NC}"; return 1; }
            sed -i -E "s/^DIAL_MODE=.*/DIAL_MODE=${sub}/" "$(dial_env_file)"
            local r; r=$(dial_reselect "$sub") || { echo -e "${RED}[!] Could not apply dial route.${NC}"; return 1; }
            if [[ "$r" == changed:* ]]; then
                systemctl restart "$(dial_service "$(dial_env_get DIAL_KIND)")" >/dev/null 2>&1 || true
            fi
            echo -e "${GREEN}[✔️] Dial route: ${sub} (${r#*:})${NC}"
            ;;
        *) echo "Usage: hashem dial [status|auto|gre|public]"; return 1 ;;
    esac
}

check_root() {
    [[ "${HASHEM_NO_ROOT_CHECK:-0}" == "1" ]] && return 0
    if [[ ${EUID:-$(id -u 2>/dev/null || echo 1)} -ne 0 ]]; then
        echo -e "${RED}[!] This script must be run as root (sudo).${NC}"
        exit 1
    fi
}

detect_arch() {
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)
            FRP_ARCH="amd64"
            ;;
        aarch64|arm64)
            FRP_ARCH="arm64"
            ;;
        armv7l|armhf)
            FRP_ARCH="arm"
            ;;
        *)
            echo -e "${RED}[!] Unsupported architecture: $ARCH${NC}"
            exit 1
            ;;
    esac
}

get_latest_frp_version() {
    if [[ -n "${FRP_VERSION:-}" && "$FRP_VERSION" != "$DEFAULT_FRP_VERSION" ]]; then
        return 0
    fi
    LATEST_VER=$(curl -sSL --connect-timeout 3 --max-time 6 "https://api.github.com/repos/fatedier/frp/releases/latest" 2>/dev/null | grep '"tag_name":' | sed -E 's/.*"v([^"]+)".*/\1/')
    if [[ -z "$LATEST_VER" ]]; then
        FRP_VERSION="$DEFAULT_FRP_VERSION"
    else
        FRP_VERSION="$LATEST_VER"
    fi
}

download_with_fallback() {
    local DEST="$1"
    local URL="$2"
    local TIMEOUT="${3:-45}"

    # If destination already exists and is non-empty, reuse it
    if [[ -s "$DEST" ]]; then
        return 0
    fi

    # Try direct URL first (use fast 5s connect-timeout for GitHub since it is often blocked in Iran)
    local DIRECT_CONNECT_TO=10
    local DIRECT_MAX_TO="$TIMEOUT"
    if [[ "$URL" == https://github.com/* || "$URL" == https://raw.githubusercontent.com/* ]]; then
        DIRECT_CONNECT_TO=5
        DIRECT_MAX_TO=8
    fi

    if curl -fsSL --connect-timeout "$DIRECT_CONNECT_TO" --max-time "$DIRECT_MAX_TO" -o "$DEST" "$URL" 2>/dev/null && [[ -s "$DEST" ]]; then
        return 0
    fi

    # Iran-friendly GitHub proxy mirrors if it is a GitHub URL
    if [[ "$URL" == https://github.com/* || "$URL" == https://raw.githubusercontent.com/* ]]; then
        echo -e "${YELLOW}[*] Direct download timed out / blocked — trying Iran proxy mirror...${NC}"
        local MIRRORS=(
            "https://ghproxy.net/${URL}"
            "https://gh-proxy.com/${URL}"
            "https://gh.ddlc.top/${URL}"
            "https://ghproxy.cn/${URL}"
        )
        for M in "${MIRRORS[@]}"; do
            if curl -fsSL --connect-timeout 6 --max-time 20 -o "$DEST" "$M" 2>/dev/null && [[ -s "$DEST" ]]; then
                echo -e "${GREEN}[✔️] Download succeeded via mirror: ${M%/*}${NC}"
                return 0
            fi
        done
    fi
    return 1
}

install_frp_binaries() {
    local ROLE="${1:-all}"
    if [[ "$ROLE" == "server" && -x "${INSTALL_DIR}/frps" ]]; then
        return 0
    fi
    if [[ "$ROLE" == "client" && -x "${INSTALL_DIR}/frpc" ]]; then
        return 0
    fi
    if [[ -x "${INSTALL_DIR}/frps" && -x "${INSTALL_DIR}/frpc" ]]; then
        return 0
    fi
    detect_arch
    get_latest_frp_version
    echo -e "${CYAN}[*] Downloading FRP v${FRP_VERSION} (${FRP_ARCH})...${NC}"

    mkdir -p "$CONFIG_DIR"
    TMP_DIR=$(mktemp -d)
    TAR_FILE="frp_${FRP_VERSION}_linux_${FRP_ARCH}.tar.gz"

    local DOWNLOAD_URL="https://github.com/pdnczone/hashem-panel/releases/download/v${FRP_VERSION}/${TAR_FILE}"
    if ! download_with_fallback "${TMP_DIR}/${TAR_FILE}" "$DOWNLOAD_URL" 30; then
        DOWNLOAD_URL="https://github.com/fatedier/frp/releases/download/v${FRP_VERSION}/${TAR_FILE}"
        if ! download_with_fallback "${TMP_DIR}/${TAR_FILE}" "$DOWNLOAD_URL" 60; then
            echo -e "${RED}[!] Failed to download FRP from GitHub or mirrors.${NC}"
            rm -rf "$TMP_DIR"
            return 1
        fi
    fi

    tar -xzf "${TMP_DIR}/${TAR_FILE}" -C "$TMP_DIR"
    local FOUND_FRPS FOUND_FRPC
    FOUND_FRPS=$(find "$TMP_DIR" -type f -name "frps" 2>/dev/null | head -1)
    FOUND_FRPC=$(find "$TMP_DIR" -type f -name "frpc" 2>/dev/null | head -1)
    if [[ -n "$FOUND_FRPS" ]]; then cp -f "$FOUND_FRPS" "$INSTALL_DIR/" 2>/dev/null; fi
    if [[ -n "$FOUND_FRPC" ]]; then cp -f "$FOUND_FRPC" "$INSTALL_DIR/" 2>/dev/null; fi
    chmod +x "${INSTALL_DIR}/frps" "${INSTALL_DIR}/frpc" 2>/dev/null || true

    rm -rf "$TMP_DIR"
    if [[ "$ROLE" == "server" && ! -x "${INSTALL_DIR}/frps" ]]; then
        echo -e "${RED}[!] frps binary not found or not executable after installation.${NC}"
        return 1
    elif [[ "$ROLE" == "client" && ! -x "${INSTALL_DIR}/frpc" ]]; then
        echo -e "${RED}[!] frpc binary not found or not executable after installation.${NC}"
        return 1
    elif [[ "$ROLE" == "all" && ! -x "${INSTALL_DIR}/frps" && ! -x "${INSTALL_DIR}/frpc" ]]; then
        echo -e "${RED}[!] FRP binaries not found or not executable after installation.${NC}"
        return 1
    fi
    echo -e "${GREEN}[✔️] FRP installed to ${INSTALL_DIR}.${NC}"
}

BACKHAUL_CONFIG_DIR="/etc/backhaul"
DEFAULT_BACKHAUL_VERSION="v0.7.2"

install_backhaul_binaries() {
    if [[ -x "${INSTALL_DIR}/backhaul" ]]; then
        return 0
    fi
    detect_arch
    local BH_ARCH="$FRP_ARCH"
    local BH_VER="$DEFAULT_BACKHAUL_VERSION"
    echo -e "${CYAN}[*] Downloading Backhaul ${BH_VER} (${BH_ARCH})...${NC}"

    mkdir -p "$BACKHAUL_CONFIG_DIR"
    local TMP_DIR
    TMP_DIR=$(mktemp -d)
    local TAR_FILE="backhaul_linux_${BH_ARCH}.tar.gz"

    local DOWNLOAD_URL="https://github.com/pdnczone/hashem-panel/releases/download/${BH_VER}/${TAR_FILE}"
    if ! download_with_fallback "${TMP_DIR}/${TAR_FILE}" "$DOWNLOAD_URL" 30; then
        DOWNLOAD_URL="https://github.com/Musixal/Backhaul/releases/download/${BH_VER}/${TAR_FILE}"
        if ! download_with_fallback "${TMP_DIR}/${TAR_FILE}" "$DOWNLOAD_URL" 60; then
            echo -e "${RED}[!] Failed to download Backhaul from GitHub or mirrors.${NC}"
            rm -rf "$TMP_DIR"
            return 1
        fi
    fi

    tar -xzf "${TMP_DIR}/${TAR_FILE}" -C "$TMP_DIR"
    if [[ -f "${TMP_DIR}/backhaul" ]]; then
        cp "${TMP_DIR}/backhaul" "$INSTALL_DIR/" 2>/dev/null
    else
        local FOUND
        FOUND=$(find "$TMP_DIR" -type f -name "backhaul" 2>/dev/null | head -n 1)
        if [[ -n "$FOUND" ]]; then
            cp "$FOUND" "$INSTALL_DIR/" 2>/dev/null
        fi
    fi
    chmod +x "${INSTALL_DIR}/backhaul" 2>/dev/null

    rm -rf "$TMP_DIR"
    if [[ -x "${INSTALL_DIR}/backhaul" ]]; then
        mkdir -p "/root/backhaul-core" 2>/dev/null || true
        cp -f "${INSTALL_DIR}/backhaul" "/root/backhaul-core/backhaul_premium" 2>/dev/null || ln -sf "${INSTALL_DIR}/backhaul" "/root/backhaul-core/backhaul_premium"
        chmod +x "/root/backhaul-core/backhaul_premium" 2>/dev/null || true
        echo -e "${GREEN}[✔️] Backhaul (Modified v2.0.0-hotfix8) installed to ${INSTALL_DIR}/backhaul.${NC}"
        return 0
    else
        echo -e "${RED}[!] Backhaul binary extraction failed.${NC}"
        return 1
    fi
}

backhaul_ensure_tls() {
    mkdir -p "$BACKHAUL_CONFIG_DIR"
    if [[ ! -f "${BACKHAUL_CONFIG_DIR}/server.crt" || ! -f "${BACKHAUL_CONFIG_DIR}/server.key" ]]; then
        echo -e "${CYAN}[*] Generating self-signed TLS certificate for Backhaul WSS...${NC}"
        openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
            -keyout "${BACKHAUL_CONFIG_DIR}/server.key" \
            -out "${BACKHAUL_CONFIG_DIR}/server.crt" \
            -subj "/CN=backhaul" >/dev/null 2>&1 || true
        chmod 600 "${BACKHAUL_CONFIG_DIR}/server.key" 2>/dev/null || true
    fi
}

backhaul_write_server_conf_v1() {
    local CONF_FILE="$1"
    local BIND_ADDR="$2"
    local TRANSPORT="${3:-tcpmux}"
    local TOKEN="$4"
    local PORTS_LIST="$5"

    mkdir -p "$(dirname "$CONF_FILE")"
    if [[ "$TRANSPORT" == "wss" || "$TRANSPORT" == "wssmux" ]]; then
        backhaul_ensure_tls
    fi

    cat <<EOF > "$CONF_FILE"
[server]
bind_addr = "${BIND_ADDR}"
transport = "${TRANSPORT}"
token = "${TOKEN}"
keepalive_period = 75
nodelay = true
heartbeat = 40
channel_size = 2048
sniffer = false
web_port = 0
sniffer_log = ""
log_level = "info"
EOF

    if [[ "$TRANSPORT" == "wss" || "$TRANSPORT" == "wssmux" ]]; then
        cat <<EOF >> "$CONF_FILE"
tls_cert = "${BACKHAUL_CONFIG_DIR}/server.crt"
tls_key = "${BACKHAUL_CONFIG_DIR}/server.key"
EOF
    fi

    echo "ports = [" >> "$CONF_FILE"
    local FIRST=1
    IFS=',' read -ra ADDR <<< "$PORTS_LIST"
    for p in "${ADDR[@]}"; do
        p=$(echo "$p" | xargs)
        [[ -z "$p" ]] && continue
        if [[ $FIRST -eq 1 ]]; then
            echo "  \"$p\"" >> "$CONF_FILE"
            FIRST=0
        else
            echo "  ,\"$p\"" >> "$CONF_FILE"
        fi
    done
    echo "]" >> "$CONF_FILE"
}

backhaul_write_client_conf_v1() {
    local CONF_FILE="$1"
    local REMOTE_ADDR="$2"
    local TRANSPORT="${3:-tcpmux}"
    local TOKEN="$4"

    mkdir -p "$(dirname "$CONF_FILE")"
    cat <<EOF > "$CONF_FILE"
[client]
remote_addr = "${REMOTE_ADDR}"
transport = "${TRANSPORT}"
token = "${TOKEN}"
connection_pool = 8
nodelay = true
retry_interval = 3
keepalive_period = 75
sniffer = false
web_port = 0
sniffer_log = ""
log_level = "info"
EOF
}

# B-03: the Backhaul core shipped by hashem is the "Modified v2.x" build, whose
# TOML schema differs from upstream v0.x ([listener]/[dialer]/[transport]/
# [security]/[ports] instead of flat [server]/[client]). Writing the v0.x
# schema for a v2 core makes it exit with "neither server nor client
# configuration is properly set". Pick the schema from the installed core.
backhaul_is_v2() {
    local bin="${INSTALL_DIR:-/usr/local/bin}/backhaul" v
    [[ -x "$bin" ]] || bin="$(command -v backhaul 2>/dev/null)"
    [[ -n "$bin" ]] || return 1
    v="$("$bin" -v 2>/dev/null | head -n1)"
    [[ "$v" =~ ^v?2\. ]]
}

backhaul_write_server_conf_v2() {
    local CONF_FILE="$1" BIND_ADDR="$2" TRANSPORT="$3" TOKEN="$4" PORTS_LIST="$5"
    mkdir -p "$(dirname "$CONF_FILE")"
    if [[ "$TRANSPORT" == "wss" || "$TRANSPORT" == "wssmux" ]]; then
        backhaul_ensure_tls
    fi
    {
        printf '[listener]\nbind_addr = "%s"\n\n' "$BIND_ADDR"
        printf '[transport]\ntype = "%s"\nnodelay = true\nkeepalive_period = 75\n\n' "$TRANSPORT"
        printf '[security]\ntoken = "%s"\n\n' "$TOKEN"
        if [[ "$TRANSPORT" == *mux ]]; then
            printf '[mux]\nmux_version = 1\n\n'
        fi
        if [[ "$TRANSPORT" == "wss" || "$TRANSPORT" == "wssmux" ]]; then
            printf '[tls]\ntls_cert = "%s/server.crt"\ntls_key = "%s/server.key"\n\n' "$BACKHAUL_CONFIG_DIR" "$BACKHAUL_CONFIG_DIR"
        fi
        printf '[logging]\nlog_level = "info"\n\n[ports]\nmapping = [\n'
        local p
        IFS=',' read -ra _ADDR <<< "$PORTS_LIST"
        for p in "${_ADDR[@]}"; do
            p="$(echo "$p" | xargs)"
            [[ -z "$p" ]] && continue
            printf '    "%s",\n' "$p"
        done
        printf ']\n'
    } > "$CONF_FILE"
}

backhaul_write_client_conf_v2() {
    local CONF_FILE="$1" REMOTE_ADDR="$2" TRANSPORT="${3:-tcpmux}" TOKEN="$4"
    mkdir -p "$(dirname "$CONF_FILE")"
    {
        printf '[dialer]\nremote_addr = "%s"\ndial_timeout = 10\nretry_interval = 3\n\n' "$REMOTE_ADDR"
        printf '[transport]\ntype = "%s"\nconnection_pool = 8\nnodelay = true\nkeepalive_period = 75\n\n' "$TRANSPORT"
        printf '[security]\ntoken = "%s"\n\n' "$TOKEN"
        if [[ "$TRANSPORT" == *mux ]]; then
            printf '[mux]\nmux_version = 1\n\n'
        fi
        if [[ "$TRANSPORT" == "wss" || "$TRANSPORT" == "wssmux" ]]; then
            printf '[tls]\nsni = "%s"\n\n' "${REMOTE_ADDR%%:*}"
        fi
        printf '[logging]\nlog_level = "info"\n'
    } > "$CONF_FILE"
}

backhaul_write_server_conf() {
    if backhaul_is_v2; then backhaul_write_server_conf_v2 "$@"; else backhaul_write_server_conf_v1 "$@"; fi
}

backhaul_write_client_conf() {
    if backhaul_is_v2; then backhaul_write_client_conf_v2 "$@"; else backhaul_write_client_conf_v1 "$@"; fi
}

setup_backhaul_server_systemd() {
    local SVC_NAME="${1:-backhaul-server}"
    local CONF_FILE="${2:-${BACKHAUL_CONFIG_DIR}/config.toml}"

    cat <<EOF > "/etc/systemd/system/${SVC_NAME}.service"
[Unit]
Description=Backhaul Server Tunnel (${SVC_NAME})
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=${INSTALL_DIR}/backhaul -c ${CONF_FILE}
Restart=always
RestartSec=3s
LimitNOFILE=1048576
CPUWeight=100

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable "${SVC_NAME}.service" >/dev/null 2>&1 || true
    systemctl restart "${SVC_NAME}.service"
}

setup_backhaul_client_systemd() {
    local SVC_NAME="${1:-backhaul-client}"
    local CONF_FILE="${2:-${BACKHAUL_CONFIG_DIR}/client.toml}"

    cat <<EOF > "/etc/systemd/system/${SVC_NAME}.service"
[Unit]
Description=Backhaul Client Tunnel (${SVC_NAME})
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=${INSTALL_DIR}/backhaul -c ${CONF_FILE}
Restart=always
RestartSec=3s
LimitNOFILE=1048576
CPUWeight=100

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable "${SVC_NAME}.service" >/dev/null 2>&1 || true
    systemctl restart "${SVC_NAME}.service"
}

setup_gre_systemd() {
    setup_gre_iface "$TUNNEL_NAME" "$1" "$2" "$3" "$4"
}

# Generalized GRE interface setup: $1=ifname $2=local_pub $3=remote_pub $4=inner_ip.
# setup_gre_systemd() above is the legacy single-tunnel wrapper; peers call this
# directly with gre-tN names so every tunnel is the same GRE, just N of them.
setup_gre_iface() {
    local IFNAME=$1
    local LOCAL_IP=$2
    local REMOTE_IP=$3
    local GRE_INTERNAL_IP=$4
    local CLEAN_GRE_IP="${GRE_INTERNAL_IP%/*}"
    local PEER_INNER=$5

    echo -e "${CYAN}[*] Configuring persistent GRE tunnel service (${IFNAME})...${NC}"

    ensure_hashem_bin

    local IP_BIN
    IP_BIN=$(command -v ip || echo "/sbin/ip")
    modprobe ip_gre >/dev/null 2>&1 || true
    modprobe fou >/dev/null 2>&1 || true

    # Tear down existing if present
    "$IP_BIN" link del "$IFNAME" >/dev/null 2>&1 || "$IP_BIN" tunnel del "$IFNAME" >/dev/null 2>&1 || true

    # Intelligent NAT / local IP handling:
    # If LOCAL_IP is not bound directly to a local interface (common on cloud/NAT VPS in Iran),
    # binding explicitly causes Linux kernel EADDRNOTAVAIL (Cannot assign requested address).
    # In that case, use the interface IP that routes to REMOTE_IP, or wildcard (omit local).
    local LOCAL_ARG=""
    if [[ -n "$LOCAL_IP" ]] && "$IP_BIN" -o addr show 2>/dev/null | grep -qw "$LOCAL_IP"; then
        LOCAL_ARG="local ${LOCAL_IP}"
    else
        local NIC_IP
        NIC_IP=$("$IP_BIN" route get "$REMOTE_IP" 2>/dev/null | awk '/src/ {for (i=1; i<=NF; i++) if ($i=="src") {print $(i+1); exit}}')
        if [[ -n "$NIC_IP" ]] && "$IP_BIN" -o addr show 2>/dev/null | grep -qw "$NIC_IP"; then
            LOCAL_ARG="local ${NIC_IP}"
        else
            LOCAL_ARG=""
        fi
    fi

    if [[ -z "$PEER_INNER" ]]; then
        if [[ "$CLEAN_GRE_IP" =~ \.2$ ]]; then
            PEER_INNER="${CLEAN_GRE_IP%.*}.1"
        else
            PEER_INNER="${CLEAN_GRE_IP%.*}.2"
        fi
    fi

    # Create systemd service for GRE
    # Robust architecture:
    # 1. Multi-fallback: try netlink `ip link add` (modern), then `ip tunnel add` (ioctl),
    #    and if local address binding failed due to NAT/routing, retry without local arg.
    # 2. Fixed TTL (255) without incompatible nopmtudisc (fixing root cause: ttl != 0 and nopmtudisc are incompatible).
    # 3. Wrap hooks in /bin/sh -c with [ -x ... ] checks so systemd never exits with status 203/EXEC.
    # 4. Use addr replace / add to avoid failure when address is already assigned.
    # 5. Add direct point-to-point /32 route to the peer inner GRE IP.
    cat <<EOF > /etc/systemd/system/${IFNAME}.service
[Unit]
Description=GRE Tunnel Interface
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=-/bin/sh -c "modprobe ip_gre 2>/dev/null; modprobe fou 2>/dev/null; if [ -x /usr/local/bin/hashem ]; then /usr/local/bin/hashem carrier-kernel-init 2>/dev/null; fi; true"
ExecStartPre=-/bin/sh -c "${IP_BIN} link del ${IFNAME} 2>/dev/null || ${IP_BIN} tunnel del ${IFNAME} 2>/dev/null; true"
ExecStart=/bin/sh -c '(\
    ${IP_BIN} link add ${IFNAME} type gre ${LOCAL_ARG} remote ${REMOTE_IP} ttl 255 2>/dev/null || \
    ${IP_BIN} tunnel add ${IFNAME} mode gre ${LOCAL_ARG} remote ${REMOTE_IP} ttl 255 2>/dev/null || \
    ${IP_BIN} link add ${IFNAME} type gre remote ${REMOTE_IP} ttl 255 2>/dev/null || \
    ${IP_BIN} tunnel add ${IFNAME} mode gre remote ${REMOTE_IP} ttl 255 2>/dev/null || true); \
    ${IP_BIN} link set dev ${IFNAME} up mtu 1380 && \
    (${IP_BIN} addr replace ${CLEAN_GRE_IP}/30 dev ${IFNAME} 2>/dev/null || ${IP_BIN} addr add ${CLEAN_GRE_IP}/30 dev ${IFNAME} 2>/dev/null || true) && \
    (${IP_BIN} route replace ${PEER_INNER}/32 dev ${IFNAME} 2>/dev/null || true)'
ExecStartPost=-/bin/sh -c "if [ -x /usr/local/bin/hashem ]; then /usr/local/bin/hashem carrier-apply-active ${IFNAME} 2>/dev/null; fi; true"
ExecStop=-/bin/sh -c "${IP_BIN} link del ${IFNAME} 2>/dev/null || ${IP_BIN} tunnel del ${IFNAME} 2>/dev/null; true"

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl reset-failed "${IFNAME}.service" >/dev/null 2>&1 || true
    systemctl enable "${IFNAME}.service" >/dev/null 2>&1
    local GRE_STARTED=0
    if systemctl restart "${IFNAME}.service" >/dev/null 2>&1; then
        if "$IP_BIN" link show "$IFNAME" >/dev/null 2>&1 && "$IP_BIN" -4 addr show dev "$IFNAME" 2>/dev/null | grep -q "${CLEAN_GRE_IP}"; then
            GRE_STARTED=1
        fi
    fi

    if [[ "$GRE_STARTED" -ne 1 ]]; then
        # Direct fallback in bash if systemctl restart did not bring up interface
        "$IP_BIN" link del "$IFNAME" >/dev/null 2>&1 || "$IP_BIN" tunnel del "$IFNAME" >/dev/null 2>&1 || true
        ( "$IP_BIN" link add "$IFNAME" type gre ${LOCAL_ARG} remote "$REMOTE_IP" ttl 255 2>/dev/null || \
          "$IP_BIN" tunnel add "$IFNAME" mode gre ${LOCAL_ARG} remote "$REMOTE_IP" ttl 255 2>/dev/null || \
          "$IP_BIN" link add "$IFNAME" type gre remote "$REMOTE_IP" ttl 255 2>/dev/null || \
          "$IP_BIN" tunnel add "$IFNAME" mode gre remote "$REMOTE_IP" ttl 255 2>/dev/null || true )
        "$IP_BIN" link set dev "$IFNAME" up mtu 1380 >/dev/null 2>&1 || true
        ( "$IP_BIN" addr replace "${CLEAN_GRE_IP}/30" dev "$IFNAME" 2>/dev/null || "$IP_BIN" addr add "${CLEAN_GRE_IP}/30" dev "$IFNAME" 2>/dev/null || true )
        ( "$IP_BIN" route replace "${PEER_INNER}/32" dev "$IFNAME" 2>/dev/null || true )

        if "$IP_BIN" link show "$IFNAME" >/dev/null 2>&1 && "$IP_BIN" -4 addr show dev "$IFNAME" 2>/dev/null | grep -q "${CLEAN_GRE_IP}"; then
            GRE_STARTED=1
        fi
    fi

    if [[ "$GRE_STARTED" -ne 1 ]]; then
        echo -e "${RED}[!] GRE interface ${IFNAME} failed to start — check: ip tunnel show; journalctl -u ${IFNAME}.service${NC}"
        journalctl -u "${IFNAME}.service" -n 5 --no-pager 2>/dev/null || true
        return 1
    fi

    carrier_apply_active "${IFNAME}" >/dev/null 2>&1 || true

    # Safeguard: ensure GRE interface remains UP and has IP assigned after carrier apply
    if ! "$IP_BIN" link show "$IFNAME" >/dev/null 2>&1 || ! "$IP_BIN" -4 addr show dev "$IFNAME" 2>/dev/null | grep -q "${CLEAN_GRE_IP}"; then
        ( "$IP_BIN" link add "$IFNAME" type gre ${LOCAL_ARG} remote "$REMOTE_IP" ttl 255 2>/dev/null || \
          "$IP_BIN" tunnel add "$IFNAME" mode gre ${LOCAL_ARG} remote "$REMOTE_IP" ttl 255 2>/dev/null || \
          "$IP_BIN" link add "$IFNAME" type gre remote "$REMOTE_IP" ttl 255 2>/dev/null || \
          "$IP_BIN" tunnel add "$IFNAME" mode gre remote "$REMOTE_IP" ttl 255 2>/dev/null || true )
        "$IP_BIN" link set dev "$IFNAME" up mtu 1380 >/dev/null 2>&1 || true
        ( "$IP_BIN" addr replace "${CLEAN_GRE_IP}/30" dev "$IFNAME" 2>/dev/null || "$IP_BIN" addr add "${CLEAN_GRE_IP}/30" dev "$IFNAME" 2>/dev/null || true )
        ( "$IP_BIN" route replace "${PEER_INNER}/32" dev "$IFNAME" 2>/dev/null || true )
    fi

    # Enable packet forwarding & MSS clamping to avoid fragmentation
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1
    iptables -t mangle -D POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu >/dev/null 2>&1 || true
    iptables -t mangle -C POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1340 >/dev/null 2>&1 || \
        iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1340

    echo -e "${GREEN}[✔️] GRE Tunnel service active with IP ${CLEAN_GRE_IP} (MTU 1380, MSS 1340).${NC}"
}

# Retire features removed from this release (chaff pinger, DPI shield). Older installs may still
# have their units, script and iptables chain; stop and delete them so nothing keeps running orphaned.
purge_legacy_obfuscation() {
    local u
    for u in /etc/systemd/system/gre-chaff*.service /etc/systemd/system/hashem-chaff*.service /etc/systemd/system/hashem-dpi.service; do
        [[ -f "$u" ]] || continue
        systemctl disable --now "$(basename "$u")" >/dev/null 2>&1 || true
        rm -f "$u"
    done
    pkill -f "hashem-chaff.sh" >/dev/null 2>&1 || true
    rm -f /usr/local/bin/hashem-chaff.sh /usr/local/bin/gre-chaff.sh
    if command -v iptables >/dev/null 2>&1; then
        iptables -D INPUT -j HASHEM-DPI 2>/dev/null || true
        iptables -F HASHEM-DPI 2>/dev/null || true
        iptables -X HASHEM-DPI 2>/dev/null || true
    fi
}

# ---- Performance & Obfuscation Controls (CLI + Menu 22) ----

perf_apply() {
    init_perf_json
    local EFF_ENC=$(perf_get_enc)
    local EFF_COMP=$(perf_get_comp)
    local EFF_MUX=$(perf_get_tcpmux)
    local EFF_POOL EFF_MAXPOOL
    read -r EFF_POOL EFF_MAXPOOL <<< "$(pool_effective_values)"

    local IS_FOREIGN=0
    local IS_IRAN=0
    [[ -f "${CONFIG_DIR}/frpc.toml" ]] && IS_FOREIGN=1
    [[ -f "${CONFIG_DIR}/frps.toml" ]] && IS_IRAN=1
    for f in "${CONFIG_DIR}"/frps*.toml; do
        [[ -f "$f" ]] && IS_IRAN=1
    done

    if [[ "$IS_FOREIGN" -eq 0 && "$IS_IRAN" -eq 0 ]]; then
        echo -e "${YELLOW}[!] No frps.toml or frpc.toml found in ${CONFIG_DIR}.${NC}"
        echo -e "${YELLOW}[*] Set up a tunnel first before applying performance settings.${NC}"
        return 1
    fi

    echo -e "${CYAN}[*] Applying performance settings (enc=${EFF_ENC} comp=${EFF_COMP} tcpmux=${EFF_MUX:-unchanged} pool=${EFF_POOL}/${EFF_MAXPOOL})...${NC}"

    if [[ "$IS_FOREIGN" -eq 1 ]]; then
        local TOML_FILE="${CONFIG_DIR}/frpc.toml"
        if command -v python3 >/dev/null 2>&1; then
            python3 -c '
path = "'"$TOML_FILE"'"
enc = ("'"$EFF_ENC"'".strip() in ("1", "true", "True"))
comp = ("'"$EFF_COMP"'".strip() in ("1", "true", "True"))
mux_raw = "'"$EFF_MUX"'".strip()
pool_cnt = "'"$EFF_POOL"'".strip()

with open(path, "r") as f:
    lines = f.read().splitlines()

sections = []
current = []
for line in lines:
    if line.strip().startswith("[[proxies]]"):
        if current:
            sections.append(current)
        current = [line]
    else:
        current.append(line)
if current:
    sections.append(current)

out_sections = []
for i, sec in enumerate(sections):
    if i == 0 and not sec[0].strip().startswith("[[proxies]]"):
        final_hdr = []
        for l in sec:
            s = l.strip()
            if s.startswith("transport.tls.disableCustomTLSFirstByte") or s.startswith("transport.poolCount"):
                continue
            if mux_raw in ("0", "1") and (s.startswith("transport.tcpMux ") or s.startswith("transport.tcpMux=") or s.startswith("transport.tcpMuxKeepaliveInterval")):
                continue
            final_hdr.append(l)
        if mux_raw in ("0", "1"):
            final_hdr.append("transport.tcpMux = true" if mux_raw == "1" else "transport.tcpMux = false")
            if mux_raw == "1":
                final_hdr.append("transport.tcpMuxKeepaliveInterval = 30")
        final_hdr.append("transport.poolCount = " + pool_cnt)
        out_sections.append(final_hdr)
    else:
        new_sec = []
        is_tcp = any("type = \"tcp\"" in l or "type=\"tcp\"" in l for l in sec)
        for l in sec:
            s = l.strip()
            if s.startswith("transport.useEncryption") or s.startswith("transport.useCompression"):
                continue
            new_sec.append(l)
        while new_sec and new_sec[-1].strip() == "":
            new_sec.pop()
        if enc and is_tcp:
            new_sec.append("transport.useEncryption = true")
        if comp and is_tcp:
            new_sec.append("transport.useCompression = true")
        new_sec.append("")
        out_sections.append(new_sec)

result = "\n".join("\n".join(s) for s in out_sections).strip() + "\n"
with open(path, "w") as f:
    f.write(result)
'
        fi
        systemctl daemon-reload >/dev/null 2>&1 || true
        systemctl restart frpc
        autopool_state_set applied_pool="$EFF_POOL" last_restart="$(date +%s)"
        echo -e "${GREEN}[✔️] frpc.toml updated & frpc service restarted.${NC}"
    fi

    if [[ "$IS_IRAN" -eq 1 ]]; then
        for TOML_FILE in "${CONFIG_DIR}"/frps*.toml; do
            [[ -f "$TOML_FILE" ]] || continue
            if command -v python3 >/dev/null 2>&1; then
                python3 -c '
path = "'"$TOML_FILE"'"
mux_raw = "'"$EFF_MUX"'".strip()
max_pool = "'"$EFF_MAXPOOL"'".strip()

with open(path, "r") as f:
    lines = f.read().splitlines()

new_lines = []
for l in lines:
    s = l.strip()
    if s.startswith("transport.tls.force"):
        continue
    if mux_raw in ("0", "1") and (s.startswith("transport.tcpMux ") or s.startswith("transport.tcpMux=") or s.startswith("transport.tcpMuxKeepaliveInterval")):
        continue
    new_lines.append(l)

final_lines = new_lines

if mux_raw in ("0", "1"):
    mux_lines = ["transport.tcpMux = true" if mux_raw == "1" else "transport.tcpMux = false"]
    if mux_raw == "1":
        mux_lines.append("transport.tcpMuxKeepaliveInterval = 30")
    final_lines = final_lines + mux_lines

# Update maxPoolCount
out_lines = []
has_pool = False
for l in final_lines:
    if l.strip().startswith("transport.maxPoolCount"):
        out_lines.append("transport.maxPoolCount = " + max_pool)
        has_pool = True
    else:
        out_lines.append(l)
if not has_pool:
    out_lines.append("transport.maxPoolCount = " + max_pool)

result = "\n".join(out_lines).strip() + "\n"
with open(path, "w") as f:
    f.write(result)
'
            fi
        done
        systemctl daemon-reload >/dev/null 2>&1 || true
        systemctl restart frps >/dev/null 2>&1 || true
        for s in /etc/systemd/system/frps-*.service; do
            [[ -f "$s" ]] || continue
            local sname=$(basename "$s")
            systemctl restart "$sname" >/dev/null 2>&1 || true
        done
        autopool_state_set frps_restart_needed=false
        echo -e "${GREEN}[✔️] frps toml(s) updated & frps service(s) restarted.${NC}"
    fi

    echo -e "${GREEN}[✔️] Performance settings successfully applied.${NC}"
    return 0
}

cli_perf() {
    local SUB="${1:-status}"
    case "$SUB" in
        status)
            init_perf_json
            local ENC=$(perf_get_enc)
            local COMP=$(perf_get_comp)

            echo -e "\n${CYAN}==========================================================${NC}"
            echo -e "${CYAN}                 Performance Status                       ${NC}"
            echo -e "${CYAN}==========================================================${NC}"
            echo -e "Settings (/etc/gre-panel/perf.json):"
            echo -e "  Proxy Encryption:  $([[ "$ENC" == "1" ]] && echo -e "${GREEN}on${NC}" || echo -e "${YELLOW}off${NC}")"
            echo -e "  Proxy Compression: $([[ "$COMP" == "1" ]] && echo -e "${GREEN}on${NC}" || echo -e "${YELLOW}off${NC}")"
            local MUX_CFG=$(perf_get_tcpmux)
            echo -e "  TCP Multiplexing:  $([[ "$MUX_CFG" == "1" ]] && echo -e "${YELLOW}on (slower over GRE)${NC}" || { [[ "$MUX_CFG" == "0" ]] && echo -e "${GREEN}off (speed-first)${NC}" || echo -e "${CYAN}not set (live toml unchanged)${NC}"; })"
            local EP EM
            read -r EP EM <<< "$(pool_effective_values)"
            echo -e "  Auto Pool:         $([[ "$(perf_get_auto_pool)" == "1" ]] && echo -e "${GREEN}on${NC}" || echo -e "${YELLOW}off (manual)${NC}") — poolCount ${EP}, maxPoolCount ${EM}"

            if [[ -n "${PERF_ENC:-}" || -n "${PERF_COMP:-}" ]]; then
                echo -e "${YELLOW}[!] Env overrides active: PERF_ENC=${PERF_ENC:-unset} PERF_COMP=${PERF_COMP:-unset}${NC}"
            fi

            echo ""
            echo -e "Live Tunnel Configuration:"
            local MATCH=1

            if [[ -f "${CONFIG_DIR}/frpc.toml" ]]; then
                local LIVE_ENC=0 LIVE_COMP=0
                grep -E -q '^[[:space:]]*transport\.useEncryption[[:space:]]*=[[:space:]]*true' "${CONFIG_DIR}/frpc.toml" && LIVE_ENC=1
                grep -E -q '^[[:space:]]*transport\.useCompression[[:space:]]*=[[:space:]]*true' "${CONFIG_DIR}/frpc.toml" && LIVE_COMP=1

                if [[ "$MUX_CFG" == "0" || "$MUX_CFG" == "1" ]]; then
                    local LIVE_MUX=1
                    grep -E -q '^[[:space:]]*transport\.tcpMux[[:space:]]*=[[:space:]]*false' "${CONFIG_DIR}/frpc.toml" && LIVE_MUX=0
                    echo -e "  Live TCP Multiplexing:  $([[ "$LIVE_MUX" == "1" ]] && echo "on" || echo "off") $([[ "$LIVE_MUX" == "$MUX_CFG" ]] && echo -e "${GREEN}[MATCH]${NC}" || echo -e "${RED}[MISMATCH]${NC}")"
                else
                    # unset: still show the live value (a missing tcpMux line means FRP's own default = on); must equal the hub's
                    grep -E -q '^[[:space:]]*transport\.tcpMux[[:space:]]*=[[:space:]]*false' "${CONFIG_DIR}/frpc.toml" \
                        && echo -e "  Live TCP Multiplexing:  off (must match the hub)" \
                        || echo -e "  Live TCP Multiplexing:  ${YELLOW}on${NC} (must match the hub; run: hashem perf tcpmux off on BOTH ends for max speed)"
                fi
                echo -e "  Role: Foreign client (frpc)"
                echo -e "  Live Proxy Encryption:  $([[ "$LIVE_ENC" == "1" ]] && echo "on" || echo "off") $([[ "$LIVE_ENC" == "$ENC" ]] && echo -e "${GREEN}[MATCH]${NC}" || echo -e "${RED}[MISMATCH]${NC}")"
                echo -e "  Live Proxy Compression: $([[ "$LIVE_COMP" == "1" ]] && echo "on" || echo "off") $([[ "$LIVE_COMP" == "$COMP" ]] && echo -e "${GREEN}[MATCH]${NC}" || echo -e "${RED}[MISMATCH]${NC}")"
                local LIVE_POOL; LIVE_POOL=$(autopool_live_toml_int "${CONFIG_DIR}/frpc.toml" transport.poolCount)
                echo -e "  Live poolCount:         ${LIVE_POOL:-unset}"
                # MATCH=0 inside $(...) is lost (subshell) - evaluate mismatches here instead
                [[ "$LIVE_ENC" == "$ENC" && "$LIVE_COMP" == "$COMP" ]] || MATCH=0
                [[ "$MUX_CFG" != "0" && "$MUX_CFG" != "1" ]] || [[ "$LIVE_MUX" == "$MUX_CFG" ]] || MATCH=0
            elif [[ -f "${CONFIG_DIR}/frps.toml" ]] || ls "${CONFIG_DIR}"/frps*.toml >/dev/null 2>&1; then
                local F
                if [[ "$MUX_CFG" == "0" || "$MUX_CFG" == "1" ]]; then
                    local LIVE_MUX=1
                    for F in "${CONFIG_DIR}"/frps*.toml; do
                        [[ -f "$F" ]] || continue
                        grep -E -q '^[[:space:]]*transport\.tcpMux[[:space:]]*=[[:space:]]*false' "$F" && LIVE_MUX=0
                    done
                    echo -e "  Live TCP Multiplexing:  $([[ "$LIVE_MUX" == "1" ]] && echo "on" || echo "off") $([[ "$LIVE_MUX" == "$MUX_CFG" ]] && echo -e "${GREEN}[MATCH]${NC}" || echo -e "${RED}[MISMATCH]${NC}")"
                else
                    local UNSET_MUX="off" F
                    for F in "${CONFIG_DIR}"/frps*.toml; do
                        [[ -f "$F" ]] || continue
                        grep -E -q '^[[:space:]]*transport\.tcpMux[[:space:]]*=[[:space:]]*false' "$F" || UNSET_MUX="on"
                    done
                    echo -e "  Live TCP Multiplexing:  ${UNSET_MUX} (must match every spoke; a missing line means FRP's default = on)"
                fi
                echo -e "  Role: Iran server (frps)"
                [[ "$MUX_CFG" != "0" && "$MUX_CFG" != "1" ]] || [[ "$LIVE_MUX" == "$MUX_CFG" ]] || MATCH=0
                echo -e "  (Proxy encryption & compression are client-side settings on Foreign VPS)"
            else
                echo -e "  No live tunnel configs found."
            fi

            echo ""
            if [[ "$MATCH" -eq 1 ]]; then
                echo -e "${GREEN}[✔️] Live configuration matches effective settings.${NC}"
            else
                echo -e "${RED}[!] Live configuration does NOT match settings. Run 'hashem perf apply' to sync.${NC}"
            fi
            ;;
        enc)
            local VAL="${2:-}"
            case "$VAL" in
                on)  perf_set_val "proxy_encryption" "true" 1; echo -e "${GREEN}[✔️] Proxy encryption set to 'on'. Run 'hashem perf apply' to apply and restart tunnels.${NC}" ;;
                off) perf_set_val "proxy_encryption" "false" 1; echo -e "${GREEN}[✔️] Proxy encryption set to 'off'. Run 'hashem perf apply' to apply and restart tunnels.${NC}" ;;
                *)   echo -e "${RED}[!] Usage: hashem perf enc on|off${NC}"; return 1 ;;
            esac
            ;;
        comp)
            local VAL="${2:-}"
            case "$VAL" in
                on)  perf_set_val "proxy_compression" "true" 1; echo -e "${GREEN}[✔️] Proxy compression set to 'on'. Run 'hashem perf apply' to apply and restart tunnels.${NC}" ;;
                off) perf_set_val "proxy_compression" "false" 1; echo -e "${GREEN}[✔️] Proxy compression set to 'off'. Run 'hashem perf apply' to apply and restart tunnels.${NC}" ;;
                *)   echo -e "${RED}[!] Usage: hashem perf comp on|off${NC}"; return 1 ;;
            esac
            ;;
        tcpmux|mux)
            local VAL="${2:-}"
            case "$VAL" in
                on)  perf_set_val "tcp_mux" "true" 1; echo -e "${GREEN}[✔️] TCP multiplexing set to 'on'. It MUST match on the Iran hub and every foreign spoke. Run 'hashem perf apply' on each server.${NC}" ;;
                off) perf_set_val "tcp_mux" "false" 1; echo -e "${GREEN}[✔️] TCP multiplexing set to 'off' (speed-first). It MUST match on the Iran hub and every foreign spoke. Run 'hashem perf apply' on each server.${NC}" ;;
                *)   echo -e "${RED}[!] Usage: hashem perf tcpmux on|off${NC}"; return 1 ;;
            esac
            ;;
        autopool|auto-pool)
            local VAL="${2:-status}"
            case "$VAL" in
                on)  perf_set_val "auto_pool" "true" 1; echo -e "${GREEN}[✔️] Auto Pool set to 'on'. The 1-min timer (watchdog) resizes frpc poolCount; no restart now.${NC}" ;;
                off) perf_set_val "auto_pool" "false" 1; echo -e "${GREEN}[✔️] Auto Pool set to 'off' (manual frp_pool_count / frp_max_pool). Run 'hashem perf apply' to apply.${NC}" ;;
                tick) autopool_tick ;;
                status)
                    local EP EM
                    read -r EP EM <<< "$(pool_effective_values)"
                    echo "auto_pool=$(perf_get_auto_pool) poolCount=${EP} maxPoolCount=${EM}"
                    echo "last_decision=$(autopool_state_get last_decision none) reason=$(autopool_state_get last_reason -)"
                    echo "quiet_ticks=$(autopool_state_get quiet_ticks 0) last_restart=$(autopool_state_get last_restart 0) frps_restart_needed=$(autopool_state_get frps_restart_needed false)"
                    ;;
                *)   echo -e "${RED}[!] Usage: hashem perf autopool on|off|status|tick${NC}"; return 1 ;;
            esac
            ;;
        pool)
            pool_effective_values
            ;;
        apply)
            perf_apply
            ;;
        reset)
            init_perf_json
            perf_set_val "proxy_encryption" "false" 1
            perf_set_val "proxy_compression" "false" 1
            perf_set_val "tcp_mux" "false" 1
            perf_set_val "auto_pool" "true" 1
            perf_apply
            echo -e "${GREEN}[✔️] Performance RESET to safe defaults (encryption: off, compression: off, tcpMux: off, Auto Pool: on).${NC}"
            ;;
        -h|--help|help)
            echo "Usage: hashem perf status|enc on|off|comp on|off|tcpmux on|off|autopool on|off|status|tick|pool|apply|reset"
            ;;
        *)
            echo -e "${RED}[!] Unknown subcommand: $SUB${NC}"
            echo "Usage: hashem perf status|enc on|off|comp on|off|tcpmux on|off|autopool on|off|status|tick|pool|apply|reset"
            return 1
            ;;
    esac
}

menu_perf() {
    while true; do
        cli_perf status
        echo ""
        echo "  1) Toggle Proxy Encryption (enc on/off)"
        echo "  2) Toggle Proxy Compression (comp on/off)"
        echo "  3) Toggle Auto Pool (autopool on/off)"
        echo "  4) Apply settings & restart tunnels"
        echo "  5) Toggle TCP Multiplexing (tcpmux on/off - must match on hub AND spokes)"
        echo "  0) Back to main menu"
        echo ""
        read -p "Select an option [0-5]: " P_OPT
        case "$P_OPT" in
            1)
                local cur=$(perf_get_enc)
                if [[ "$cur" == "1" ]]; then cli_perf enc off; else cli_perf enc on; fi
                ;;
            2)
                local cur=$(perf_get_comp)
                if [[ "$cur" == "1" ]]; then cli_perf comp off; else cli_perf comp on; fi
                ;;
            3)
                local cur=$(perf_get_auto_pool)
                if [[ "$cur" == "1" ]]; then cli_perf autopool off; else cli_perf autopool on; fi
                ;;
            4)
                cli_perf apply
                ;;
            5)
                local cur=$(perf_get_tcpmux)
                if [[ "$cur" == "1" ]]; then cli_perf tcpmux off; else cli_perf tcpmux on; fi
                ;;
            0)
                return 0
                ;;
            *)
                echo -e "${RED}[!] Invalid option.${NC}"
                ;;
        esac
    done
}


# ---- SINGLE SOURCE OF TRUTH for install logic ----
# setup_iran_server_noninteractive / setup_foreign_server_noninteractive do the
# real work. The interactive menu functions below only prompt + validate, then
# delegate here. The web panel calls the same functions via the CLI flags at
# the bottom of this file (setup-iran / setup-foreign), so all three paths
# (menu, CLI, panel) execute identical steps.
# Args: $1=local_pub $2=remote_pub $3=frp_port $4=token [$5=local_gre [$6=peer_gre [$7="cleaned ports"]]]
# wss_front_port <control_port>: FRP "wss" needs a TLS terminator in front of
# frps (frpc speaks WebSocket-over-TLS, frps only cleartext WebSocket). The
# front listens on control_port+2 (quic uses +1); wraps below 65535.
wss_front_port() {
    local p=$(( $1 + 2 ))
    (( p > 65535 )) && p=$(( $1 - 2 ))
    echo "$p"
}

# frps_wss_front_ensure <suffix> <control_port>: (re)create + start the
# TLS front unit frps-wss<suffix>.service (idempotent).
frps_wss_front_ensure() {
    local SUF="$1" CPORT="$2"
    local FPORT SVC="frps-wss${1}" PBIN="${PANEL_BIN:-/usr/local/bin/gre-panel}"
    FPORT=$(wss_front_port "$CPORT")
    if [[ ! -x "$PBIN" ]]; then
        echo -e "${YELLOW}[!] ${PBIN} not found — cannot start the WSS TLS front on :${FPORT}.${NC}"
        return 1
    fi
    cat > "${HASHEM_SYSTEMD_DIR:-/etc/systemd/system}/${SVC}.service" <<UNIT
[Unit]
Description=Hashem FRP WSS TLS front (:${FPORT} -> 127.0.0.1:${CPORT})
After=network.target frps${SUF}.service

[Service]
Type=simple
User=root
Restart=always
RestartSec=3s
LimitNOFILE=1048576
CPUWeight=100
ExecStart=${PBIN} tls-proxy -listen 0.0.0.0:${FPORT} -target 127.0.0.1:${CPORT}

[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl enable "$SVC" >/dev/null 2>&1 || true
    systemctl restart "$SVC" >/dev/null 2>&1 || true
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
        ufw allow "${FPORT}/tcp" >/dev/null 2>&1 || true
    fi
    echo -e "${GREEN}[✔️] WSS TLS front listening on :${FPORT} (-> frps :${CPORT})${NC}"
}

# frps_wss_front_remove <suffix>
frps_wss_front_remove() {
    local SVC="frps-wss${1}"
    systemctl stop "$SVC" >/dev/null 2>&1 || true
    systemctl disable "$SVC" >/dev/null 2>&1 || true
    rm -f "${HASHEM_SYSTEMD_DIR:-/etc/systemd/system}/${SVC}.service"
}

setup_iran_server_noninteractive() {
    local IP_IRAN=$1 IP_FOREIGN=$2 BIND_PORT=$3 TOKEN=$4
    local LOCAL_GRE=${5:-$IRAN_GRE_IP} PEER_GRE=${6:-$FOREIGN_GRE_IP}
    local PORTS_CLEANED="${7:-}"
    local FRP_TRANSPORT="${8:-tcp}"
    
    log_msg "tunnel" "INFO" "Starting IRAN server setup: GRE ${IP_IRAN} <-> ${IP_FOREIGN}, FRP port: ${BIND_PORT}"
    backup_configs "pre_setup_iran"
    ensure_dependencies_smart

    local STATUS_GRE="OK"
    local STATUS_FRP="OK"
    local STATUS_PANEL="OK"
    local GRE_ERR="" FRP_ERR="" PANEL_ERR=""

    # 1. Setup GRE interface
    if ! setup_gre_systemd "$IP_IRAN" "$IP_FOREIGN" "$LOCAL_GRE" "$PEER_GRE"; then
        STATUS_GRE="FAILED"
        GRE_ERR="GRE interface failed to start or configure IP"
        log_msg "tunnel" "ERROR" "GRE setup failed on IRAN server"
    fi

    # 2. Setup FRP Server
    if ! install_frp_binaries; then
        STATUS_FRP="FAILED"
        FRP_ERR="FRP installation failed (binary download or extraction error)"
        log_msg "tunnel" "ERROR" "FRP binaries failed to install"
    fi
    local _POOL MAX_POOL
    read -r _POOL MAX_POOL <<< "$(pool_effective_values)"
    local QUIC_PORT=$((BIND_PORT + 1))
    if [[ "$QUIC_PORT" -gt 65535 ]]; then QUIC_PORT=$((BIND_PORT - 1)); fi
    mkdir -p "${CONFIG_DIR}"
    cat <<EOF > "${CONFIG_DIR}/frps.toml"
bindAddr = "0.0.0.0"
bindPort = ${BIND_PORT}
kcpBindPort = ${BIND_PORT}
quicBindPort = ${QUIC_PORT}
auth.method = "token"
auth.token = "${TOKEN}"
$(perf_tcpmux_lines)
transport.tcpKeepalive = 30
transport.heartbeatTimeout = 90
transport.maxPoolCount = ${MAX_POOL}
EOF
    cat <<EOF > /etc/systemd/system/frps.service
[Unit]
Description=FRP Server Service
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Restart=always
RestartSec=3s
StartLimitIntervalSec=0
LimitNOFILE=1048576
LimitNPROC=512000
TasksMax=infinity
CPUWeight=100
ExecStart=${INSTALL_DIR}/frps -c ${CONFIG_DIR}/frps.toml

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl reset-failed frps >/dev/null 2>&1 || true
    systemctl enable frps >/dev/null 2>&1
    if command -v fuser >/dev/null 2>&1; then
        fuser -k "${BIND_PORT}/tcp" >/dev/null 2>&1 || true
    fi
    systemctl restart frps

    local _frps_ok=0
    for _i in {1..5}; do
        sleep 2
        if systemctl is-active --quiet frps 2>/dev/null; then
            _frps_ok=1
            break
        fi
    done

    if [[ "$_frps_ok" -ne 1 ]]; then
        STATUS_FRP="FAILED"
        local FRPS_LOG=""
        FRPS_LOG=$(journalctl -u frps -n 5 --no-pager 2>/dev/null | tr '\n' ' ' | head -c 200)
        FRP_ERR="frps service failed to start${FRPS_LOG:+: $FRPS_LOG}"
        log_msg "tunnel" "ERROR" "frps service failed to start"
    fi

    if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
        ufw allow "${BIND_PORT}/tcp" >/dev/null 2>&1
    fi

    tune_apply >/dev/null 2>&1 || true
    install_watchdog_units >/dev/null 2>&1 || true
    init_watchdog_json >/dev/null 2>&1 || true

    # 3. Web Panel
    if [[ "${GRE_SKIP_PANEL:-0}" == "1" ]]; then
        echo -e "${CYAN}[*] Skipping panel install (called from panel or flag).${NC}"
    else
        if ! install_panel_smart; then
            STATUS_PANEL="FAILED"
            PANEL_ERR="Panel installation or start failed"
        fi
    fi

    # 3b. WSS transport needs a TLS front for frps (needs the panel binary installed above)
    if [[ "$FRP_TRANSPORT" == "wss" ]]; then
        frps_wss_front_ensure "" "$BIND_PORT" || { STATUS_FRP="FAILED"; FRP_ERR="WSS TLS front failed to start"; }
    else
        frps_wss_front_remove ""
    fi

    # 4. Summary & Verification
    echo -e "\n=============================================================="
    echo "                   INSTALLATION SUMMARY"
    echo "=============================================================="
    if [[ "$STATUS_GRE" == "OK" ]]; then
        echo -e "[${GREEN}OK${NC}]     GRE Tunnel Interface (${TUNNEL_NAME}: ${IP_IRAN} <-> ${IP_FOREIGN}, IP: ${LOCAL_GRE})"
    else
        echo -e "[${RED}FAILED${NC}] GRE Tunnel Interface (${GRE_ERR})"
    fi

    if [[ "$STATUS_FRP" == "OK" ]]; then
        echo -e "[${GREEN}OK${NC}]     FRP Server Service (frps listening on port :${BIND_PORT})"
    else
        echo -e "[${RED}FAILED${NC}] FRP Server Service (${FRP_ERR})"
    fi

    if [[ "${GRE_SKIP_PANEL:-0}" != "1" ]]; then
        if [[ "$STATUS_PANEL" == "OK" ]]; then
            echo -e "[${GREEN}OK${NC}]     Web Panel (healthy and accessible)"
        else
            echo -e "[${RED}FAILED${NC}] Web Panel (${PANEL_ERR})"
        fi
    fi
    echo "=============================================================="

    local BUNDLE_OUT
    BUNDLE_OUT=$(bundle_make "$IP_IRAN" "$BIND_PORT" "$LOCAL_GRE" "$PEER_GRE" "$TOKEN" "$PORTS_CLEANED" "" "$FRP_TRANSPORT")
    echo -e "Setup Bundle:         ${CYAN}${BUNDLE_OUT}${NC}"
    echo -e "BUNDLE:${BUNDLE_OUT}"

    if [[ "$STATUS_GRE" == "OK" && "$STATUS_FRP" == "OK" ]]; then
        echo -e "Overall Installation Status: ${GREEN}SUCCESS${NC}\n"
        echo -e "GRE Public Link:      ${CYAN}${IP_IRAN} <--> ${IP_FOREIGN}${NC}"
        echo -e "IRAN GRE Internal IP: ${CYAN}${LOCAL_GRE}${NC}"
        echo -e "FRP Bind Port:        ${CYAN}${BIND_PORT}${NC}"
        echo -e "Secret Token:         ${CYAN}${TOKEN}${NC}"
        log_msg "tunnel" "INFO" "IRAN server setup completed successfully"
        return 0
    else
        echo -e "Overall Installation Status: ${RED}PARTIALLY FAILED${NC}"
        echo -e "${YELLOW}[!] Review component failure(s) above. Do NOT assume tunnel is ready.${NC}\n"
        log_msg "tunnel" "ERROR" "IRAN server setup partially failed: GRE=${STATUS_GRE}, FRP=${STATUS_FRP}"
        return 1
    fi
}

setup_foreign_server_noninteractive() {
    local IP_FOREIGN=$1 IP_IRAN=$2 SERVER_PORT=$3 TOKEN=$4
    local LOCAL_GRE=${5:-$FOREIGN_GRE_IP} PEER_GRE=${6:-$IRAN_GRE_IP}
    local PORTS_CLEANED=${7:-}
    local RELAY_IP=${8:-}
    local PROXY_PROTOCOL=${9:-off}
    local FRP_TRANSPORT=${10:-tcp}
    local FRP_ENCRYPTION=${11:-off}
    local FRP_COMPRESSION=${12:-off}
    _setup_foreign_full "$IP_FOREIGN" "$IP_IRAN" "$SERVER_PORT" "$TOKEN" "$LOCAL_GRE" "$PEER_GRE" "$PORTS_CLEANED" "$RELAY_IP" "$PROXY_PROTOCOL" "$FRP_TRANSPORT" "$FRP_ENCRYPTION" "$FRP_COMPRESSION"
}

# shared full foreign path: GRE + ping feedback + frpc binaries/config/service + panel.
# Called by the interactive menu, the CLI, and (via CLI) the web panel.
_setup_foreign_full() {
    local IP_FOREIGN=$1 IP_IRAN=$2 SERVER_PORT=$3 TOKEN=$4
    local LOCAL_GRE=$5 PEER_GRE=$6 PORTS_CLEANED=$7
    local RELAY_IP=${8:-}
    local PROXY_PROTOCOL=${9:-off}
    local FRP_TRANSPORT=${10:-tcp}
    local FRP_ENCRYPTION=${11:-off}
    local FRP_COMPRESSION=${12:-off}
    
    log_msg "tunnel" "INFO" "Starting FOREIGN server setup: GRE ${IP_FOREIGN} <-> ${IP_IRAN}, serverPort: ${SERVER_PORT}, reverse ports: ${PORTS_CLEANED}"
    backup_configs "pre_setup_foreign"
    ensure_dependencies_smart

    local STATUS_GRE="OK"
    local STATUS_PING="OK"
    local STATUS_FRP="OK"
    local STATUS_PANEL="OK"
    local GRE_ERR="" PING_ERR="" FRP_ERR="" PANEL_ERR=""

    carrier_init_kernel 2>/dev/null || true
    if ! setup_gre_systemd "$IP_FOREIGN" "$IP_IRAN" "$LOCAL_GRE" "$PEER_GRE"; then
        STATUS_GRE="FAILED"
        GRE_ERR="GRE interface failed to configure or initialize"
        log_msg "tunnel" "ERROR" "GRE setup failed on FOREIGN server"
    fi
    carrier_apply_active "$TUNNEL_NAME" >/dev/null 2>&1 || true

    echo -e "${CYAN}[*] Testing GRE internal ping to Iran (${PEER_GRE})...${NC}"
    if ping -c 3 -W 2 "$PEER_GRE" >/dev/null 2>&1; then
        echo -e "${GREEN}[✔️] GRE Tunnel link is UP and reachable!${NC}"
    else
        STATUS_PING="WARN"
        PING_ERR="Ping to peer GRE IP ${PEER_GRE} timed out (may need Iran side up)"
        echo -e "${YELLOW}[!] Warning: Ping to ${PEER_GRE} did not respond yet.${NC}"
    fi

    install_frp_binaries
    local EFF_ENC=$(perf_get_enc)
    local EFF_COMP=$(perf_get_comp)
    local EFF_POOL _MAXPOOL
    read -r EFF_POOL _MAXPOOL <<< "$(pool_effective_values)"
    local EFF_SERVER_PORT="${SERVER_PORT}"
    if [[ "$FRP_TRANSPORT" == "quic" ]]; then
        EFF_SERVER_PORT=$((SERVER_PORT + 1))
        if [[ "$EFF_SERVER_PORT" -gt 65535 ]]; then EFF_SERVER_PORT=$((SERVER_PORT - 1)); fi
    elif [[ "$FRP_TRANSPORT" == "wss" ]]; then
        EFF_SERVER_PORT=$(wss_front_port "$SERVER_PORT")
    fi
    # Dial route: GRE inner address when it works, else the hub's public IP (hub listens on 0.0.0.0)
    local DIAL_ADDR
    DIAL_ADDR=$(dial_pick "${FRP_DIAL:-auto}" "$PEER_GRE" "$IP_IRAN" "$EFF_SERVER_PORT")
    if [[ "$DIAL_ADDR" != "$PEER_GRE" ]]; then
        echo -e "${YELLOW}[!] GRE path to ${PEER_GRE} is not usable — frpc will dial the Iran public IP ${IP_IRAN} directly.${NC}"
    fi
    dial_env_write "${FRP_DIAL:-auto}" frp "$PEER_GRE" "$IP_IRAN"
    mkdir -p "${CONFIG_DIR}"
    cat <<EOF > "${CONFIG_DIR}/frpc.toml"
serverAddr = "${DIAL_ADDR}"
serverPort = ${EFF_SERVER_PORT}
auth.method = "token"
auth.token = "${TOKEN}"
loginFailExit = false
transport.protocol = "${FRP_TRANSPORT}"
$(perf_tcpmux_lines)
transport.heartbeatInterval = 30
transport.heartbeatTimeout = 90
transport.dialServerTimeout = 15
transport.dialServerKeepalive = 30
transport.poolCount = ${EFF_POOL}

EOF
    local PROXY_TARGET_IP="${RELAY_IP:-127.0.0.1}"
    local PP_LINE=""
    if [[ "$PROXY_PROTOCOL" == "v2" || "$PROXY_PROTOCOL" == "v1" ]]; then
        PP_LINE="transport.proxyProtocolVersion = \"${PROXY_PROTOCOL}\""
    fi
    local ENC_LINE=""
    if [[ "$FRP_ENCRYPTION" == "on" || "$FRP_ENCRYPTION" == "1" || "$FRP_ENCRYPTION" == "true" ]]; then
        ENC_LINE="transport.useEncryption = true"
    fi
    local COMP_LINE=""
    if [[ "$FRP_COMPRESSION" == "on" || "$FRP_COMPRESSION" == "1" || "$FRP_COMPRESSION" == "true" ]]; then
        COMP_LINE="transport.useCompression = true"
    fi
    local PORT
    for PORT in $PORTS_CLEANED; do
        cat <<EOF >> "${CONFIG_DIR}/frpc.toml"
[[proxies]]
name = "tcp_${PORT}"
type = "tcp"
localIP = "${PROXY_TARGET_IP}"
localPort = ${PORT}
remotePort = ${PORT}
${PP_LINE:+$PP_LINE
}${ENC_LINE:+$ENC_LINE
}${COMP_LINE:+$COMP_LINE
}
[[proxies]]
name = "udp_${PORT}"
type = "udp"
localIP = "${PROXY_TARGET_IP}"
localPort = ${PORT}
remotePort = ${PORT}

EOF
    done

    cat <<EOF > /etc/systemd/system/frpc.service
[Unit]
Description=FRP Client Reverse Service
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Restart=always
RestartSec=3s
StartLimitIntervalSec=0
LimitNOFILE=1048576
LimitNPROC=512000
TasksMax=infinity
CPUWeight=100
ExecStartPre=-/bin/sh -c "if [ -x /usr/local/bin/hashem ]; then timeout 30 /usr/local/bin/hashem dial-select >/dev/null 2>&1; fi; true"
ExecStart=${INSTALL_DIR}/frpc -c ${CONFIG_DIR}/frpc.toml

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl reset-failed frpc >/dev/null 2>&1 || true
    systemctl enable frpc >/dev/null 2>&1
    systemctl restart frpc

    local _frpc_ok=0
    for _i in {1..5}; do
        sleep 2
        if systemctl is-active --quiet frpc 2>/dev/null; then
            _frpc_ok=1
            break
        fi
    done

    if [[ "$_frpc_ok" -ne 1 ]]; then
        STATUS_FRP="FAILED"
        FRP_ERR="frpc service failed to start — check: journalctl -u frpc"
        log_msg "tunnel" "ERROR" "frpc service failed to start"
    fi

    tune_apply >/dev/null 2>&1 || true
    install_watchdog_units >/dev/null 2>&1 || true
    init_watchdog_json >/dev/null 2>&1 || true

    if [[ "${GRE_SKIP_PANEL:-0}" == "1" ]]; then
        echo -e "${CYAN}[*] Skipping panel install (called from panel or flag).${NC}"
    else
        if ! install_panel_smart; then
            STATUS_PANEL="FAILED"
            PANEL_ERR="Panel installation or start failed"
        fi
    fi

    echo -e "\n=============================================================="
    echo "                   INSTALLATION SUMMARY"
    echo "=============================================================="
    if [[ "$STATUS_GRE" == "OK" ]]; then
        echo -e "[${GREEN}OK${NC}]     GRE Tunnel Interface (${TUNNEL_NAME}: ${IP_FOREIGN} <-> ${IP_IRAN}, IP: ${LOCAL_GRE})"
    else
        echo -e "[${RED}FAILED${NC}] GRE Tunnel Interface (${GRE_ERR})"
    fi

    if [[ "$STATUS_PING" == "OK" ]]; then
        echo -e "[${GREEN}OK${NC}]     GRE Ping Connectivity (Peer ${PEER_GRE} reachable)"
    else
        echo -e "[${YELLOW}WARN${NC}]   GRE Ping Connectivity (${PING_ERR})"
    fi

    if [[ "$STATUS_FRP" == "OK" ]]; then
        echo -e "[${GREEN}OK${NC}]     FRP Client Service (frpc active, connecting to ${DIAL_ADDR}:${EFF_SERVER_PORT})"
        echo -e "         Reverse ports: ${PORTS_CLEANED} (TCP & UDP, TLS)"
    else
        echo -e "[${RED}FAILED${NC}] FRP Client Service (${FRP_ERR})"
    fi

    if [[ "${GRE_SKIP_PANEL:-0}" != "1" ]]; then
        if [[ "$STATUS_PANEL" == "OK" ]]; then
            echo -e "[${GREEN}OK${NC}]     Web Panel (healthy and accessible)"
        else
            echo -e "[${RED}FAILED${NC}] Web Panel (${PANEL_ERR})"
        fi
    fi
    echo "=============================================================="

    # Success: GRE interface up + frpc connected = tunnel functional.
    # PING=WARN is acceptable: ICMP is often filtered by the ISP on GRE tunnels
    # in Iran while TCP (used by frpc) works fine. Only treat ping as blocking
    # failure if frpc itself also failed.
    local _ping_blocking=0
    if [[ "$STATUS_PING" != "OK" && "$STATUS_FRP" != "OK" ]]; then
        _ping_blocking=1
    fi

    if [[ "$STATUS_GRE" == "OK" && "$STATUS_FRP" == "OK" && "$_ping_blocking" -eq 0 ]]; then
        if [[ "$STATUS_PING" != "OK" ]]; then
            echo -e "Overall Installation Status: ${GREEN}SUCCESS${NC} ${YELLOW}(ICMP ping filtered — tunnel TCP is working)${NC}\n"
        else
            echo -e "Overall Installation Status: ${GREEN}SUCCESS${NC}\n"
        fi
        log_msg "tunnel" "INFO" "FOREIGN server setup completed successfully (PING=${STATUS_PING})"
        return 0
    else
        echo -e "Overall Installation Status: ${RED}PARTIALLY FAILED${NC}"
        echo -e "${YELLOW}[!] Review component failure(s) above. Do NOT assume tunnel is ready.${NC}\n"
        log_msg "tunnel" "ERROR" "FOREIGN server setup partially failed: GRE=${STATUS_GRE}, FRP=${STATUS_FRP}, PING=${STATUS_PING}"
        return 1
    fi
}

setup_backhaul_iran_server_noninteractive() {
    local IP_IRAN=$1 IP_FOREIGN=$2 BIND_PORT=$3 TOKEN=$4 TRANSPORT=${5:-tcpmux} PORTS=${6:-}
    
    log_msg "tunnel" "INFO" "Starting Standalone Backhaul IRAN server setup: port ${BIND_PORT}, transport ${TRANSPORT}"
    backup_configs "pre_setup_backhaul_iran"
    ensure_dependencies_smart

    local STATUS_BH="OK"
    local STATUS_PANEL="OK"
    local BH_ERR="" PANEL_ERR=""

    install_backhaul_binaries || { STATUS_BH="FAILED"; BH_ERR="Failed to download/install backhaul binary"; }
    backhaul_ensure_tls "$TRANSPORT"

    if [[ "$STATUS_BH" == "OK" ]]; then
        mkdir -p "${BACKHAUL_CONFIG_DIR}"
        backhaul_write_server_conf "${BACKHAUL_CONFIG_DIR}/config.toml" "0.0.0.0:${BIND_PORT}" "$TRANSPORT" "$TOKEN" "$PORTS"
        setup_backhaul_server_systemd "backhaul-server" "${BACKHAUL_CONFIG_DIR}/config.toml"

        local _bh_ok=0
        for _i in {1..5}; do
            sleep 2
            if systemctl is-active --quiet backhaul-server 2>/dev/null; then
                _bh_ok=1
                break
            fi
        done

        if [[ "$_bh_ok" -ne 1 ]]; then
            STATUS_BH="FAILED"
            BH_ERR="backhaul-server service failed to start — check: journalctl -u backhaul-server"
            log_msg "tunnel" "ERROR" "backhaul-server service failed to start"
        fi
    fi

    if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
        ufw allow "${BIND_PORT}/tcp" >/dev/null 2>&1 || true
    fi

    tune_apply >/dev/null 2>&1 || true
    install_watchdog_units >/dev/null 2>&1 || true
    init_watchdog_json >/dev/null 2>&1 || true

    if [[ "${GRE_SKIP_PANEL:-0}" == "1" ]]; then
        echo -e "${CYAN}[*] Skipping panel install (called from panel or flag).${NC}"
    else
        if ! install_panel_smart; then
            STATUS_PANEL="FAILED"
            PANEL_ERR="Panel installation or start failed"
        fi
    fi

    echo -e "\n=============================================================="
    echo "                   INSTALLATION SUMMARY"
    echo "=============================================================="
    if [[ "$STATUS_BH" == "OK" ]]; then
        echo -e "[${GREEN}OK${NC}]     Backhaul Server Service (listening on :${BIND_PORT}, transport: ${TRANSPORT})"
    else
        echo -e "[${RED}FAILED${NC}] Backhaul Server Service (${BH_ERR})"
    fi

    if [[ "${GRE_SKIP_PANEL:-0}" != "1" ]]; then
        if [[ "$STATUS_PANEL" == "OK" ]]; then
            echo -e "[${GREEN}OK${NC}]     Web Panel (healthy and accessible)"
        else
            echo -e "[${RED}FAILED${NC}] Web Panel (${PANEL_ERR})"
        fi
    fi
    echo "=============================================================="

    if [[ "$STATUS_BH" == "OK" ]]; then
        echo -e "Overall Installation Status: ${GREEN}SUCCESS${NC}\n"
        echo -e "Iran Public IP:       ${CYAN}${IP_IRAN}${NC}"
        echo -e "Backhaul Port:        ${CYAN}${BIND_PORT}${NC}"
        echo -e "Transport Protocol:   ${CYAN}${TRANSPORT}${NC}"
        echo -e "Secret Token:         ${CYAN}${TOKEN}${NC}"
        local BUNDLE_STR
        BUNDLE_STR=$(bundle_make_backhaul "$IP_IRAN" "$BIND_PORT" "$TRANSPORT" "$TOKEN" "$PORTS")
        echo -e "Setup Bundle:         ${CYAN}${BUNDLE_STR}${NC}"
        echo -e "BUNDLE:${BUNDLE_STR}"
        log_msg "tunnel" "INFO" "IRAN Backhaul server setup completed successfully"
        return 0
    else
        echo -e "Overall Installation Status: ${RED}PARTIALLY FAILED${NC}"
        log_msg "tunnel" "ERROR" "IRAN Backhaul server setup failed"
        return 1
    fi
}

setup_backhaul_foreign_server_noninteractive() {
    local IP_FOREIGN=$1 IP_IRAN=$2 SERVER_PORT=$3 TOKEN=$4 TRANSPORT=${5:-tcpmux}
    
    log_msg "tunnel" "INFO" "Starting Standalone Backhaul FOREIGN setup: remote ${IP_IRAN}:${SERVER_PORT}, transport ${TRANSPORT}"
    backup_configs "pre_setup_backhaul_foreign"
    ensure_dependencies_smart

    local STATUS_BH="OK"
    local STATUS_PANEL="OK"
    local BH_ERR="" PANEL_ERR=""

    install_backhaul_binaries || { STATUS_BH="FAILED"; BH_ERR="Failed to install backhaul binary"; }
    backhaul_ensure_tls "$TRANSPORT"

    if [[ "$STATUS_BH" == "OK" ]]; then
        mkdir -p "${BACKHAUL_CONFIG_DIR}"
        backhaul_write_client_conf "${BACKHAUL_CONFIG_DIR}/client.toml" "${IP_IRAN}:${SERVER_PORT}" "$TRANSPORT" "$TOKEN"
        setup_backhaul_client_systemd "backhaul-client" "${BACKHAUL_CONFIG_DIR}/client.toml"

        local _bh_ok=0
        for _i in {1..5}; do
            sleep 2
            if systemctl is-active --quiet backhaul-client 2>/dev/null; then
                _bh_ok=1
                break
            fi
        done

        if [[ "$_bh_ok" -ne 1 ]]; then
            STATUS_BH="FAILED"
            BH_ERR="backhaul-client service failed to start — check: journalctl -u backhaul-client"
            log_msg "tunnel" "ERROR" "backhaul-client service failed to start"
        fi
    fi

    tune_apply >/dev/null 2>&1 || true
    install_watchdog_units >/dev/null 2>&1 || true
    init_watchdog_json >/dev/null 2>&1 || true

    if [[ "${GRE_SKIP_PANEL:-0}" == "1" ]]; then
        echo -e "${CYAN}[*] Skipping panel install (called from panel or flag).${NC}"
    else
        if ! install_panel_smart; then
            STATUS_PANEL="FAILED"
            PANEL_ERR="Panel installation or start failed"
        fi
    fi

    echo -e "\n=============================================================="
    echo "                   INSTALLATION SUMMARY"
    echo "=============================================================="
    if [[ "$STATUS_BH" == "OK" ]]; then
        echo -e "[${GREEN}OK${NC}]     Backhaul Client Service (connected to ${IP_IRAN}:${SERVER_PORT}, transport: ${TRANSPORT})"
    else
        echo -e "[${RED}FAILED${NC}] Backhaul Client Service (${BH_ERR})"
    fi

    if [[ "${GRE_SKIP_PANEL:-0}" != "1" ]]; then
        if [[ "$STATUS_PANEL" == "OK" ]]; then
            echo -e "[${GREEN}OK${NC}]     Web Panel (healthy and accessible)"
        else
            echo -e "[${RED}FAILED${NC}] Web Panel (${PANEL_ERR})"
        fi
    fi
    echo "=============================================================="

    if [[ "$STATUS_BH" == "OK" ]]; then
        echo -e "Overall Installation Status: ${GREEN}SUCCESS${NC}\n"
        log_msg "tunnel" "INFO" "FOREIGN Backhaul client setup completed successfully"
        return 0
    else
        echo -e "Overall Installation Status: ${RED}FAILED${NC}"
        log_msg "tunnel" "ERROR" "FOREIGN Backhaul client setup failed"
        return 1
    fi
}

setup_gre_backhaul_iran_server_noninteractive() {
    local IP_IRAN=$1 IP_FOREIGN=$2 BIND_PORT=$3 TOKEN=$4
    local LOCAL_GRE=${5:-$IRAN_GRE_IP} PEER_GRE=${6:-$FOREIGN_GRE_IP}
    local TRANSPORT=${7:-tcpmux} PORTS=${8:-}
    
    log_msg "tunnel" "INFO" "Starting GRE+Backhaul IRAN setup: GRE ${IP_IRAN} <-> ${IP_FOREIGN}, port: ${BIND_PORT}, transport: ${TRANSPORT}"
    backup_configs "pre_setup_gre_backhaul_iran"
    ensure_dependencies_smart

    local STATUS_GRE="OK"
    local STATUS_BH="OK"
    local STATUS_PANEL="OK"
    local GRE_ERR="" BH_ERR="" PANEL_ERR=""

    # 1. Setup GRE interface
    if ! setup_gre_systemd "$IP_IRAN" "$IP_FOREIGN" "$LOCAL_GRE" "$PEER_GRE"; then
        STATUS_GRE="FAILED"
        GRE_ERR="GRE interface failed to start or configure IP"
        log_msg "tunnel" "ERROR" "GRE setup failed on IRAN server"
    fi

    # 2. Setup Backhaul Server
    install_backhaul_binaries || { STATUS_BH="FAILED"; BH_ERR="Failed to install backhaul binary"; }
    backhaul_ensure_tls "$TRANSPORT"

    if [[ "$STATUS_BH" == "OK" ]]; then
        mkdir -p "${BACKHAUL_CONFIG_DIR}"
        backhaul_write_server_conf "${BACKHAUL_CONFIG_DIR}/config.toml" "0.0.0.0:${BIND_PORT}" "$TRANSPORT" "$TOKEN" "$PORTS"
        setup_backhaul_server_systemd "backhaul-server" "${BACKHAUL_CONFIG_DIR}/config.toml"
        sed -i "s/After=network.target/After=network.target ${TUNNEL_NAME}.service/" /etc/systemd/system/backhaul-server.service 2>/dev/null || true
        systemctl daemon-reload
        systemctl restart backhaul-server

        local _bh_ok=0
        for _i in {1..5}; do
            sleep 2
            if systemctl is-active --quiet backhaul-server 2>/dev/null; then
                _bh_ok=1
                break
            fi
        done

        if [[ "$_bh_ok" -ne 1 ]]; then
            STATUS_BH="FAILED"
            BH_ERR="backhaul-server service failed to start — check: journalctl -u backhaul-server"
            log_msg "tunnel" "ERROR" "backhaul-server service failed to start"
        fi
    fi

    if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
        ufw allow "${BIND_PORT}/tcp" >/dev/null 2>&1 || true
    fi

    tune_apply >/dev/null 2>&1 || true
    install_watchdog_units >/dev/null 2>&1 || true
    init_watchdog_json >/dev/null 2>&1 || true

    # 3. Web Panel
    if [[ "${GRE_SKIP_PANEL:-0}" == "1" ]]; then
        echo -e "${CYAN}[*] Skipping panel install (called from panel or flag).${NC}"
    else
        if ! install_panel_smart; then
            STATUS_PANEL="FAILED"
            PANEL_ERR="Panel installation or start failed"
        fi
    fi

    # 4. Summary & Verification
    echo -e "\n=============================================================="
    echo "                   INSTALLATION SUMMARY"
    echo "=============================================================="
    if [[ "$STATUS_GRE" == "OK" ]]; then
        echo -e "[${GREEN}OK${NC}]     GRE Tunnel Interface (${TUNNEL_NAME}: ${IP_IRAN} <-> ${IP_FOREIGN}, IP: ${LOCAL_GRE})"
    else
        echo -e "[${RED}FAILED${NC}] GRE Tunnel Interface (${GRE_ERR})"
    fi

    if [[ "$STATUS_BH" == "OK" ]]; then
        echo -e "[${GREEN}OK${NC}]     Backhaul Server Service (listening on :${BIND_PORT}, transport: ${TRANSPORT})"
    else
        echo -e "[${RED}FAILED${NC}] Backhaul Server Service (${BH_ERR})"
    fi

    if [[ "${GRE_SKIP_PANEL:-0}" != "1" ]]; then
        if [[ "$STATUS_PANEL" == "OK" ]]; then
            echo -e "[${GREEN}OK${NC}]     Web Panel (healthy and accessible)"
        else
            echo -e "[${RED}FAILED${NC}] Web Panel (${PANEL_ERR})"
        fi
    fi
    echo "=============================================================="

    if [[ "$STATUS_GRE" == "OK" && "$STATUS_BH" == "OK" ]]; then
        echo -e "Overall Installation Status: ${GREEN}SUCCESS${NC}\n"
        echo -e "GRE Public Link:      ${CYAN}${IP_IRAN} <--> ${IP_FOREIGN}${NC}"
        echo -e "IRAN GRE Internal IP: ${CYAN}${LOCAL_GRE}${NC}"
        echo -e "Backhaul Port:        ${CYAN}${BIND_PORT}${NC}"
        echo -e "Transport Protocol:   ${CYAN}${TRANSPORT}${NC}"
        echo -e "Secret Token:         ${CYAN}${TOKEN}${NC}"
        local BUNDLE_STR
        BUNDLE_STR=$(bundle_make_gre_backhaul "$IP_IRAN" "$BIND_PORT" "$LOCAL_GRE" "$PEER_GRE" "$TRANSPORT" "$TOKEN" "$PORTS")
        echo -e "Setup Bundle:         ${CYAN}${BUNDLE_STR}${NC}"
        echo -e "BUNDLE:${BUNDLE_STR}"
        log_msg "tunnel" "INFO" "IRAN GRE+Backhaul setup completed successfully"
        return 0
    else
        echo -e "Overall Installation Status: ${RED}PARTIALLY FAILED${NC}"
        log_msg "tunnel" "ERROR" "IRAN GRE+Backhaul setup partially failed: GRE=${STATUS_GRE}, BH=${STATUS_BH}"
        return 1
    fi
}

setup_gre_backhaul_foreign_server_noninteractive() {
    local IP_FOREIGN=$1 IP_IRAN=$2 SERVER_PORT=$3 TOKEN=$4
    local LOCAL_GRE=${5:-$FOREIGN_GRE_IP} PEER_GRE=${6:-$IRAN_GRE_IP}
    local TRANSPORT=${7:-tcpmux}
    
    log_msg "tunnel" "INFO" "Starting GRE+Backhaul FOREIGN setup: GRE ${IP_FOREIGN} <-> ${IP_IRAN}, port: ${SERVER_PORT}, transport: ${TRANSPORT}"
    backup_configs "pre_setup_gre_backhaul_foreign"
    ensure_dependencies_smart

    local STATUS_GRE="OK"
    local STATUS_PING="OK"
    local STATUS_BH="OK"
    local STATUS_PANEL="OK"
    local GRE_ERR="" PING_ERR="" BH_ERR="" PANEL_ERR=""

    carrier_init_kernel 2>/dev/null || true
    if ! setup_gre_systemd "$IP_FOREIGN" "$IP_IRAN" "$LOCAL_GRE" "$PEER_GRE"; then
        STATUS_GRE="FAILED"
        GRE_ERR="GRE interface failed to configure or initialize"
        log_msg "tunnel" "ERROR" "GRE setup failed on FOREIGN server"
    fi
    carrier_apply_active "$TUNNEL_NAME" >/dev/null 2>&1 || true

    echo -e "${CYAN}[*] Testing GRE internal ping to Iran (${PEER_GRE})...${NC}"
    if ping -c 3 -W 2 "$PEER_GRE" >/dev/null 2>&1; then
        echo -e "${GREEN}[✔️] GRE Tunnel link is UP and reachable!${NC}"
    else
        STATUS_PING="WARN"
        PING_ERR="Ping to peer GRE IP ${PEER_GRE} timed out (may need Iran side up)"
        echo -e "${YELLOW}[!] Warning: Ping to ${PEER_GRE} did not respond yet.${NC}"
    fi

    install_backhaul_binaries || { STATUS_BH="FAILED"; BH_ERR="Failed to install backhaul binary"; }
    backhaul_ensure_tls "$TRANSPORT"

    if [[ "$STATUS_BH" == "OK" ]]; then
        mkdir -p "${BACKHAUL_CONFIG_DIR}"
        # In GRE+Backhaul, foreign client dials Iran via the GRE internal IP (PEER_GRE)
        local BH_DIAL
        BH_DIAL=$(dial_pick "${FRP_DIAL:-auto}" "$PEER_GRE" "$IP_IRAN" "$SERVER_PORT")
        dial_env_write "${FRP_DIAL:-auto}" backhaul "$PEER_GRE" "$IP_IRAN"
        backhaul_write_client_conf "${BACKHAUL_CONFIG_DIR}/client.toml" "${BH_DIAL}:${SERVER_PORT}" "$TRANSPORT" "$TOKEN"
        setup_backhaul_client_systemd "backhaul-client" "${BACKHAUL_CONFIG_DIR}/client.toml"
        sed -i "s/After=network.target/After=network.target ${TUNNEL_NAME}.service/" /etc/systemd/system/backhaul-client.service 2>/dev/null || true
        systemctl daemon-reload
        systemctl restart backhaul-client

        local _bh_ok=0
        for _i in {1..5}; do
            sleep 2
            if systemctl is-active --quiet backhaul-client 2>/dev/null; then
                _bh_ok=1
                break
            fi
        done

        if [[ "$_bh_ok" -ne 1 ]]; then
            STATUS_BH="FAILED"
            BH_ERR="backhaul-client service failed to start — check: journalctl -u backhaul-client"
            log_msg "tunnel" "ERROR" "backhaul-client service failed to start"
        fi
    fi

    tune_apply >/dev/null 2>&1 || true
    install_watchdog_units >/dev/null 2>&1 || true
    init_watchdog_json >/dev/null 2>&1 || true

    if [[ "${GRE_SKIP_PANEL:-0}" == "1" ]]; then
        echo -e "${CYAN}[*] Skipping panel install (called from panel or flag).${NC}"
    else
        if ! install_panel_smart; then
            STATUS_PANEL="FAILED"
            PANEL_ERR="Panel installation or start failed"
        fi
    fi

    echo -e "\n=============================================================="
    echo "                   INSTALLATION SUMMARY"
    echo "=============================================================="
    if [[ "$STATUS_GRE" == "OK" ]]; then
        echo -e "[${GREEN}OK${NC}]     GRE Tunnel Interface (${TUNNEL_NAME}: ${IP_FOREIGN} <-> ${IP_IRAN}, IP: ${LOCAL_GRE})"
    else
        echo -e "[${RED}FAILED${NC}] GRE Tunnel Interface (${GRE_ERR})"
    fi

    if [[ "$STATUS_PING" == "OK" ]]; then
        echo -e "[${GREEN}OK${NC}]     GRE Ping Connectivity (Peer ${PEER_GRE} reachable)"
    else
        echo -e "[${YELLOW}WARN${NC}]   GRE Ping Connectivity (${PING_ERR})"
    fi

    if [[ "$STATUS_BH" == "OK" ]]; then
        echo -e "[${GREEN}OK${NC}]     Backhaul Client Service (connected to ${PEER_GRE}:${SERVER_PORT}, transport: ${TRANSPORT})"
    else
        echo -e "[${RED}FAILED${NC}] Backhaul Client Service (${BH_ERR})"
    fi

    if [[ "${GRE_SKIP_PANEL:-0}" != "1" ]]; then
        if [[ "$STATUS_PANEL" == "OK" ]]; then
            echo -e "[${GREEN}OK${NC}]     Web Panel (healthy and accessible)"
        else
            echo -e "[${RED}FAILED${NC}] Web Panel (${PANEL_ERR})"
        fi
    fi
    echo "=============================================================="

    local _ping_blocking=0
    if [[ "$STATUS_PING" != "OK" && "$STATUS_BH" != "OK" ]]; then
        _ping_blocking=1
    fi

    if [[ "$STATUS_GRE" == "OK" && "$STATUS_BH" == "OK" && "$_ping_blocking" -eq 0 ]]; then
        echo -e "Overall Installation Status: ${GREEN}SUCCESS${NC}\n"
        log_msg "tunnel" "INFO" "FOREIGN GRE+Backhaul setup completed successfully"
        return 0
    else
        echo -e "Overall Installation Status: ${RED}PARTIALLY FAILED${NC}"
        log_msg "tunnel" "ERROR" "FOREIGN GRE+Backhaul setup partially failed: GRE=${STATUS_GRE}, BH=${STATUS_BH}"
        return 1
    fi
}

# ---- Multi-peer tunnels: up to MAX_PEERS foreign servers on one Iran ----
# Peer 1 reuses the legacy names (gre-tunnel, frps.toml, frps.service) so
# existing installs keep working. Peers 2..5 get gre-tN + frps-N.toml +
# frps-N.service, each with its own token and control port (one frps
# understands only one token). Registry: /etc/gre-panel/peers.json.
PEERS_FILE="${PANEL_CONFIG_DIR}/peers.json"
MAX_PEERS=5

peer_init() {
    mkdir -p "$(dirname "$PEERS_FILE")" "$CONFIG_DIR"
    [[ -f "$PEERS_FILE" ]] || echo '{"peers":[]}' > "$PEERS_FILE"
}

peer_require_py() {
    command -v python3 >/dev/null 2>&1 || { echo -e "${RED}[!] python3 is required for peer management.${NC}"; return 1; }
}

# print registry as-is (JSON)
peer_list() { peer_init; cat "$PEERS_FILE"; }

# smallest free peer id (1..MAX_PEERS), or 0 when full
peer_next_id() {
    peer_require_py || return 1
    PEERS_F="$PEERS_FILE" MAX_PEERS="$MAX_PEERS" python3 -c \
'import json,os; d=json.load(open(os.environ["PEERS_F"])); used={p["id"] for p in d.get("peers",[])}; ids=[i for i in range(1,int(os.environ["MAX_PEERS"])+1) if i not in used]; print(ids[0] if ids else 0)'
}

# space-separated "port:peername" of all claimed reverse ports
peer_ports_used() {
    peer_init; peer_require_py || return 1
    PEERS_F="$PEERS_FILE" python3 -c \
'import json,os; d=json.load(open(os.environ["PEERS_F"])); print(" ".join(str(p) + ":" + str(r.get("name","")) for r in d.get("peers",[]) for p in r.get("ports",[])))'
}

# $1=id -> compact JSON record or empty
peer_get() {
    PEERS_F="$PEERS_FILE" PEER_ID="$1" python3 -c \
'import json,os; d=json.load(open(os.environ["PEERS_F"])); m=[p for p in d.get("peers",[]) if p["id"]==int(os.environ["PEER_ID"])]; print(json.dumps(m[0]) if m else "")'
}

peer_token() {
    peer_init; peer_require_py || return 1
    local ID=$1 rec
    rec=$(peer_get "$ID")
    [[ -n "$rec" ]] || { echo -e "${RED}[!] No peer with id $ID.${NC}"; return 1; }
    echo "$rec" | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])'
    # second line: full foreign-setup bundle (token + addresses + ports).
    # First-line token output stays unchanged for scripts.
    local B_TOK LIP RIP FP LGRE PGRE PTS
    B_TOK=$(echo "$rec" | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')
    LIP=$(echo "$rec" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("local_pub",""))')
    RIP=$(echo "$rec" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("remote_pub",""))')
    FP=$(echo "$rec" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("frp_port",""))')
    LGRE=$(echo "$rec" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("local_gre",""))')
    PGRE=$(echo "$rec" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("peer_gre",""))')
    PTS=$(echo "$rec" | python3 -c 'import json,sys; print(" ".join(str(x) for x in json.load(sys.stdin).get("ports",[])))')
    if is_valid_ip "$LIP" && is_valid_port "$FP" && is_valid_ip "$LGRE" && is_valid_ip "$PGRE"; then
        echo "BUNDLE:$(bundle_make "$LIP" "$FP" "$LGRE" "$PGRE" "$B_TOK" "$PTS")"
    fi
}

# write one frps instance: $1=suffix("" for legacy, "-N" for peers) $2=bind_port $3=token
peer_write_frps() {
    local SUF=$1 BIND_PORT=$2 TOKEN=$3
    local _POOL MAX_POOL
    read -r _POOL MAX_POOL <<< "$(pool_effective_values)"
    cat <<EOF > "${CONFIG_DIR}/frps${SUF}.toml"
bindAddr = "0.0.0.0"
bindPort = ${BIND_PORT}
auth.method = "token"
auth.token = "${TOKEN}"
$(perf_tcpmux_lines)
transport.tcpKeepalive = 30
transport.heartbeatTimeout = 90
transport.maxPoolCount = ${MAX_POOL}
EOF
    local SVC="frps${SUF}"
    cat <<EOF > /etc/systemd/system/${SVC}.service
[Unit]
Description=FRP Server Service${SUF:+ (peer${SUF#-})}
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Restart=always
RestartSec=3s
StartLimitIntervalSec=0
LimitNOFILE=1048576
LimitNPROC=512000
TasksMax=infinity
CPUWeight=100
ExecStart=${INSTALL_DIR}/frps -c ${CONFIG_DIR}/frps${SUF}.toml

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable "$SVC" >/dev/null 2>&1
    if command -v fuser >/dev/null 2>&1; then
        fuser -k "${BIND_PORT}/tcp" >/dev/null 2>&1 || true
    fi
    systemctl restart "$SVC"
    if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
        ufw allow "${BIND_PORT}/tcp" >/dev/null 2>&1
    fi
}

# add a peer tunnel on the Iran side.
# Flags: --name --local-pub --remote-pub --frp-port --token --local-gre --peer-gre --ports "443, 2083" [--bundle hsh1_...] [--force]
# --bundle pastes a foreign-setup string: empty flags are filled from it,
# explicit flags always win.
cli_add_peer() {
    local NAME="" LOCAL_PUB="" REMOTE_PUB="" FRP_PORT="" TOKEN="" LOCAL_GRE="" PEER_GRE="" PORTS="" FORCE=0 BUNDLE=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --name) NAME="$2"; shift 2 ;;
            --local-pub) LOCAL_PUB="$2"; shift 2 ;;
            --remote-pub) REMOTE_PUB="$2"; shift 2 ;;
            --frp-port) FRP_PORT="$2"; shift 2 ;;
            --token) TOKEN="$2"; shift 2 ;;
            --local-gre) LOCAL_GRE="$2"; shift 2 ;;
            --peer-gre) PEER_GRE="$2"; shift 2 ;;
            --ports) PORTS="$2"; shift 2 ;;
            --bundle) BUNDLE="$2"; shift 2 ;;
            --force) FORCE=1; shift ;;
            -h|--help) echo 'Usage: hashem.sh add-peer --local-pub IP --remote-pub IP [--frp-port N] --token T --local-gre IP --peer-gre IP --ports "443, 2083" [--name LABEL] [--bundle hsh1_...] [--force]'; return 0 ;;
            *) echo -e "${RED}[!] Unknown flag: $1${NC}"; return 1 ;;
        esac
    done
    case "${FRP_DIAL:-auto}" in auto|gre|public) ;; *) echo -e "${YELLOW}[!] Unknown --dial '${FRP_DIAL}', using auto.${NC}"; FRP_DIAL=auto ;; esac
    if [[ -n "$BUNDLE" ]]; then
        bundle_parse "$BUNDLE" || { echo -e "${RED}[!] Bad --bundle (want hsh1_<IRAN_PUB>_<PORT>_<IRAN_GRE>_<FOREIGN_GRE>_<TOKEN>[_<PORTS>]).${NC}"; return 1; }
        # add-peer runs on Iran: bundle Iran pub/GRE are OURS, foreign GRE is THEIRS
        [[ -z "$LOCAL_PUB" ]] && LOCAL_PUB=$B_IRAN_PUB
        [[ -z "$FRP_PORT" ]] && FRP_PORT=$B_FRP_PORT
        [[ -z "$LOCAL_GRE" ]] && LOCAL_GRE=$B_IRAN_GRE
        [[ -z "$PEER_GRE" ]] && PEER_GRE=$B_FOREIGN_GRE
        [[ -z "$TOKEN" ]] && TOKEN=$B_TOKEN
        [[ -z "$PORTS" ]] && PORTS=$B_PORTS
        PEER_FRP_TRANSPORT="${B_TRANSPORT:-tcp}"
    fi
    FRP_PORT=${FRP_PORT:-$(gen_random_port)}
    validate_setup_common "$LOCAL_PUB" "$REMOTE_PUB" "$FRP_PORT" "$LOCAL_GRE" || return 1
    is_valid_ip "$PEER_GRE" || { echo -e "${RED}[!] Invalid peer GRE IP: '$PEER_GRE'${NC}"; return 1; }
    [[ "$LOCAL_GRE" != "$PEER_GRE" ]] || { echo -e "${RED}[!] Local and peer GRE IPs must differ.${NC}"; return 1; }
    if grep -q "\"remote_pub\": *\"${REMOTE_PUB}\"" "$PEERS_FILE" 2>/dev/null; then
        echo -e "${RED}[!] Foreign IP ${REMOTE_PUB} is already used by another tunnel. You cannot add multiple tunnels to the exact same server.${NC}"; return 1
    fi
    [[ -n "$TOKEN" ]] || { echo -e "${RED}[!] --token is required (generate one per peer).${NC}"; return 1; }
    local CLEANED="" p
    for p in $(echo "$PORTS" | tr ',' ' '); do
        is_valid_port "$p" && CLEANED="$CLEANED $((10#$p))"
    done
    CLEANED=$(echo "$CLEANED" | xargs)
    [[ -n "$CLEANED" ]] || { echo -e "${RED}[!] --ports needs at least one valid port.${NC}"; return 1; }
    peer_init; peer_require_py || return 1
    local ID
    ID=$(peer_next_id)
    [[ "$ID" -ge 1 ]] || { echo -e "${RED}[!] Peer table full (max ${MAX_PEERS} foreign servers). Remove one first.${NC}"; return 1; }
    # port conflict: a remotePort can be served by only one frpc
    local USED entry CONFLICT=""
    USED=$(peer_ports_used)
    for p in $CLEANED; do
        for entry in $USED; do
            if [[ "${entry%%:*}" == "$p" ]]; then CONFLICT="$CONFLICT $p (used by peer '${entry#*:}')"; fi
        done
    done
    if [[ -n "$CONFLICT" ]]; then
        echo -e "${RED}[!] Port conflict — already claimed by another tunnel:${CONFLICT}${NC}"
        echo -e "${YELLOW}    Pick a different port for this peer (e.g. 8443 instead of 443).${NC}"
        return 1
    fi
    # control port must be free on this machine
    if ss -tln 2>/dev/null | grep -q ":${FRP_PORT} "; then
        echo -e "${RED}[!] Control port ${FRP_PORT} is already in use on this server — use another one.${NC}"
        return 1
    fi
    # GRE inner IPs must be unique across peers
    if grep -q "\"local_gre\": *\"${LOCAL_GRE}\"" "$PEERS_FILE" || grep -q "\"peer_gre\": *\"${LOCAL_GRE}\"" "$PEERS_FILE"; then
        echo -e "${RED}[!] GRE IP ${LOCAL_GRE} is already used by another peer.${NC}"; return 1
    fi
    [[ -z "$NAME" ]] && NAME="peer-${ID}"
    install_frp_binaries || return 1
    if [[ "$ID" -eq 1 ]] && ! tunnel_present; then
        # first tunnel keeps legacy names (gre-tunnel, frps) — old setups untouched
        setup_gre_systemd "$LOCAL_PUB" "$REMOTE_PUB" "$LOCAL_GRE" "$PEER_GRE"
        peer_write_frps "" "$FRP_PORT" "$TOKEN"
        GRE_IF="$TUNNEL_NAME"; FRPS_SVC="frps"; LEGACY=true
        else
        GRE_IF="gre-t${ID}"; FRPS_SVC="frps-${ID}"; LEGACY=false
        setup_gre_iface "$GRE_IF" "$LOCAL_PUB" "$REMOTE_PUB" "$LOCAL_GRE" "$PEER_GRE"
        peer_write_frps "-${ID}" "$FRP_PORT" "$TOKEN"
        # point the new unit at the right interface
        sed -i "s/After=network.target/After=network.target ${GRE_IF}.service/" /etc/systemd/system/${FRPS_SVC}.service
        systemctl daemon-reload; systemctl restart "$FRPS_SVC"
        fi
    sleep 1
    if ! systemctl is-active --quiet "$FRPS_SVC"; then
        echo -e "${RED}[!] Error: ${FRPS_SVC} failed to start. Generated configuration might be invalid.${NC}"
        return 1
    fi
    if [[ "${PEER_FRP_TRANSPORT:-tcp}" == "wss" ]]; then
        local _fsuf=""; [[ "$LEGACY" == "true" ]] || _fsuf="-${ID}"
        frps_wss_front_ensure "$_fsuf" "$FRP_PORT" || echo -e "${YELLOW}[!] WSS TLS front could not be started for this peer.${NC}"
    fi
    # registry record (ports as JSON array)
    local PORTS_JSON
    PORTS_JSON=$(echo "$CLEANED" | python3 -c 'import json,sys; print(json.dumps([int(x) for x in sys.stdin.read().split()]))')
    PEERS_F="$PEERS_FILE" python3 - "$ID" "$NAME" "$LOCAL_PUB" "$REMOTE_PUB" "$FRP_PORT" "$TOKEN" "$LOCAL_GRE" "$PEER_GRE" "$PORTS_JSON" "$GRE_IF" "$FRPS_SVC" "$LEGACY" <<'PYEOF'
import json, os, sys
f = os.environ["PEERS_F"]
iid, name, lip, rip, fport, tok, lgre, pgre, pjson, gif, svc, leg = sys.argv[1:]
d = json.load(open(f))
d.setdefault("peers", []).append({"id": int(iid), "name": name, "local_pub": lip,
  "remote_pub": rip, "frp_port": int(fport), "token": tok, "local_gre": lgre,
  "peer_gre": pgre, "ports": json.loads(pjson), "gre_if": gif, "frps_svc": svc,
  "legacy": leg == "true"})
json.dump(d, open(f, "w"), indent=2)
PYEOF
    echo -e "${GREEN}[✔️] Peer '${NAME}' (id ${ID}) added: GRE ${LOCAL_PUB} <-> ${REMOTE_PUB} (${LOCAL_GRE} peer ${PEER_GRE} on ${GRE_IF}), ${FRPS_SVC} :${FRP_PORT}${NC}"
    echo -e "${YELLOW}Token for '${NAME}': ${TOKEN} (enter it on the FOREIGN side with ports: ${CLEANED})${NC}"
    echo -e "BUNDLE:$(bundle_make "$LOCAL_PUB" "$FRP_PORT" "$LOCAL_GRE" "$PEER_GRE" "$TOKEN" "$CLEANED")"
    echo -e "${CYAN}Foreign side: frpc server ${LOCAL_GRE}:${FRP_PORT}${NC}"
}

# remove one peer ($1=id). Legacy peer 1 also drops the old single tunnel.
cli_remove_peer() {
    local ID="" FORCE=0
    while [[ $# -gt 0 ]]; do
        case "$1" in --id) ID="$2"; shift 2 ;; --force) FORCE=1; shift ;;
            -h|--help) echo 'Usage: hashem.sh remove-peer --id N [--force]'; return 0 ;;
            *) echo -e "${RED}[!] Unknown flag: $1${NC}"; return 1 ;; esac
    done
    [[ "$ID" =~ ^[0-9]+$ ]] || { echo -e "${RED}[!] --id N is required.${NC}"; return 1; }
    peer_init; peer_require_py || return 1
    local rec
    rec=$(peer_get "$ID")
    [[ -n "$rec" ]] || { echo -e "${RED}[!] No peer with id $ID.${NC}"; return 1; }
    local NAME GIF SVC LEG
    NAME=$(echo "$rec" | python3 -c 'import json,sys; print(json.load(sys.stdin)["name"])')
    GIF=$(echo "$rec" | python3 -c 'import json,sys; print(json.load(sys.stdin)["gre_if"])')
    SVC=$(echo "$rec" | python3 -c 'import json,sys; print(json.load(sys.stdin)["frps_svc"])')
    LEG=$(echo "$rec" | python3 -c 'import json,sys; print("1" if json.load(sys.stdin).get("legacy") else "0")')
    if [[ "$FORCE" -ne 1 ]]; then
        read -p "Remove peer '${NAME}' (id ${ID})? GRE + its frps go away. (y/N): " CONFIRM
        [[ "$CONFIRM" =~ ^[Yy]$ ]] || { echo -e "${YELLOW}[*] Aborted.${NC}"; return 0; }
    fi
    if [[ "$LEG" == "1" ]]; then
        remove_tunnel_force
    else
        frps_wss_front_remove "-${ID}"
        systemctl stop "$SVC" "${GIF}.service" >/dev/null 2>&1
        systemctl disable "$SVC" "${GIF}.service" >/dev/null 2>&1
        rm -f "/etc/systemd/system/${SVC}.service" "/etc/systemd/system/${GIF}.service" "/etc/frp/frps-${ID}.toml" "/etc/backhaul/server-${ID}.toml"
        systemctl daemon-reload; systemctl reset-failed >/dev/null 2>&1 || true
        if [[ "$GIF" != "none" && -n "$GIF" ]]; then
            ip tunnel del "$GIF" >/dev/null 2>&1 || true
        fi
    fi
    PEERS_F="$PEERS_FILE" PEER_ID="$ID" python3 -c \
'import json,os; f=os.environ["PEERS_F"]; d=json.load(open(f)); d["peers"]=[p for p in d.get("peers",[]) if p["id"]!=int(os.environ["PEER_ID"])]; json.dump(d,open(f,"w"),indent=2)' \
        || echo -e "${YELLOW}[!] peers registry already gone — nothing left to clean.${NC}"
    echo -e "${GREEN}[✔️] Peer '${NAME}' (id ${ID}) removed.${NC}"
}

cli_add_backhaul_peer() {
    local NAME="" LOCAL_PUB="" REMOTE_PUB="" PORT="" TOKEN="" LOCAL_GRE="" PEER_GRE="" PORTS="" TRANSPORT="tcpmux" NO_GRE=0 FORCE=0 BUNDLE=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --name) NAME="$2"; shift 2 ;;
            --local-pub) LOCAL_PUB="$2"; shift 2 ;;
            --remote-pub) REMOTE_PUB="$2"; shift 2 ;;
            --port) PORT="$2"; shift 2 ;;
            --token) TOKEN="$2"; shift 2 ;;
            --local-gre) LOCAL_GRE="$2"; shift 2 ;;
            --peer-gre) PEER_GRE="$2"; shift 2 ;;
            --transport) TRANSPORT="$2"; shift 2 ;;
            --ports) PORTS="$2"; shift 2 ;;
            --no-gre) NO_GRE=1; shift ;;
            --bundle) BUNDLE="$2"; shift 2 ;;
            --force) FORCE=1; shift ;;
            -h|--help) echo 'Usage: hashem.sh add-backhaul-peer --remote-pub IP --port P --transport T --token K --ports "443, 10000-10050" [--no-gre]'; return 0 ;;
            *) echo -e "${RED}[!] Unknown flag: $1${NC}"; return 1 ;;
        esac
    done
    if [[ -n "$BUNDLE" ]]; then
        bundle_parse "$BUNDLE" || { echo -e "${RED}[!] Bad bundle: $BUNDLE${NC}"; return 1; }
        [[ -z "$LOCAL_PUB" ]] && LOCAL_PUB=$B_IRAN_PUB
        [[ -z "$PORT" ]] && PORT=$B_FRP_PORT
        [[ -z "$TRANSPORT" ]] && TRANSPORT=$B_TRANSPORT
        [[ -z "$TOKEN" ]] && TOKEN=$B_TOKEN
        [[ -z "$PORTS" ]] && PORTS=$B_PORTS
        if [[ "$B_ENGINE" == "backhaul" ]]; then
            NO_GRE=1
        else
            [[ -z "$LOCAL_GRE" ]] && LOCAL_GRE=$B_IRAN_GRE
            [[ -z "$PEER_GRE" ]] && PEER_GRE=$B_FOREIGN_GRE
        fi
    fi
    LOCAL_PUB=${LOCAL_PUB:-$(ip route get 1.1.1.1 2>/dev/null | awk '/src/ {for (i=1; i<=NF; i++) if ($i=="src") {print $(i+1); exit}}')}
    [[ -z "$LOCAL_PUB" ]] && LOCAL_PUB=$(curl -sSL --max-time 5 https://api.ipify.org 2>/dev/null)
    PORT=${PORT:-$(gen_random_port)}
    is_valid_ip "$LOCAL_PUB" || { echo -e "${RED}[!] Invalid local IP: '$LOCAL_PUB'${NC}"; return 1; }
    is_valid_port "$PORT" || { echo -e "${RED}[!] Invalid control port: '$PORT'${NC}"; return 1; }
    if grep -q "\"remote_pub\": *\"${REMOTE_PUB}\"" "$PEERS_FILE" 2>/dev/null; then
        echo -e "${RED}[!] Foreign IP ${REMOTE_PUB} is already used by another tunnel.${NC}"; return 1
    fi
    [[ -n "$TOKEN" ]] || { echo -e "${RED}[!] --token is required.${NC}"; return 1; }
    peer_init; peer_require_py || return 1
    local ID
    ID=$(peer_next_id)
    [[ "$ID" -ge 1 ]] || { echo -e "${RED}[!] Peer table full (max ${MAX_PEERS}).${NC}"; return 1; }

    # Control port check
    if ss -tln 2>/dev/null | grep -q ":${PORT} "; then
        echo -e "${RED}[!] Control port ${PORT} is already in use.${NC}"; return 1
    fi

    [[ -z "$NAME" ]] && NAME="peer-${ID}"
    install_backhaul_binaries || return 1
    backhaul_ensure_tls "$TRANSPORT"

    local GRE_IF="none" SVC_NAME="backhaul-server-${ID}" CONF_FILE="/etc/backhaul/server-${ID}.toml"
    local ENGINE="backhaul"
    if [[ "$NO_GRE" -eq 1 ]]; then
        ENGINE="backhaul"
        GRE_IF="none"
        backhaul_write_server_conf "$CONF_FILE" "0.0.0.0:${PORT}" "$TRANSPORT" "$TOKEN" "$PORTS"
        setup_backhaul_server_systemd "$SVC_NAME" "$CONF_FILE"
    else
        ENGINE="gre-backhaul"
        is_valid_ip "$LOCAL_GRE" || { echo -e "${RED}[!] Invalid local GRE IP: '$LOCAL_GRE'${NC}"; return 1; }
        is_valid_ip "$PEER_GRE" || { echo -e "${RED}[!] Invalid peer GRE IP: '$PEER_GRE'${NC}"; return 1; }
        if [[ "$ID" -eq 1 ]] && ! tunnel_present; then
            GRE_IF="$TUNNEL_NAME"
            setup_gre_systemd "$LOCAL_PUB" "$REMOTE_PUB" "$LOCAL_GRE" "$PEER_GRE"
        else
            GRE_IF="gre-t${ID}"
            setup_gre_iface "$GRE_IF" "$LOCAL_PUB" "$REMOTE_PUB" "$LOCAL_GRE" "$PEER_GRE"
        fi
        backhaul_write_server_conf "$CONF_FILE" "0.0.0.0:${PORT}" "$TRANSPORT" "$TOKEN" "$PORTS"
        setup_backhaul_server_systemd "$SVC_NAME" "$CONF_FILE"
        sed -i "s/After=network.target/After=network.target ${GRE_IF}.service/" "/etc/systemd/system/${SVC_NAME}.service" 2>/dev/null || true
        systemctl daemon-reload; systemctl restart "$SVC_NAME"
    fi

    sleep 1
    if ! systemctl is-active --quiet "$SVC_NAME"; then
        echo -e "${RED}[!] Error: ${SVC_NAME} failed to start. Review config in ${CONF_FILE}.${NC}"
        return 1
    fi

    # Record peer into peers.json
    local NUM_PORTS_JSON
    NUM_PORTS_JSON=$(python3 -c '
import sys, json, re
raw = sys.argv[1]
nums = []
for tok in re.split(r"[, ]+", raw):
    tok = tok.strip()
    if not tok: continue
    if "=" in tok: tok = tok.split("=")[0]
    if "-" in tok:
        parts = tok.split("-")
        try:
            start, end = int(parts[0]), int(parts[1])
            nums.extend(range(start, min(end + 1, start + 100)))
        except: pass
    else:
        try: nums.append(int(tok))
        except: pass
print(json.dumps(nums))
' "$PORTS")

    PEERS_F="$PEERS_FILE" python3 - "$ID" "$NAME" "$LOCAL_PUB" "$REMOTE_PUB" "$PORT" "$TOKEN" "${LOCAL_GRE:-}" "${PEER_GRE:-}" "$NUM_PORTS_JSON" "$GRE_IF" "$SVC_NAME" "$ENGINE" "$TRANSPORT" "$NO_GRE" "$PORTS" <<'PYEOF'
import json, os, sys
f = os.environ["PEERS_F"]
iid, name, lip, rip, fport, tok, lgre, pgre, pjson, gif, svc, eng, trans, nogre, raw_p = sys.argv[1:]
d = json.load(open(f))
d.setdefault("peers", []).append({
  "id": int(iid), "name": name, "local_pub": lip, "remote_pub": rip,
  "frp_port": int(fport), "token": tok, "local_gre": lgre, "peer_gre": pgre,
  "ports": json.loads(pjson), "gre_if": gif, "frps_svc": svc, "legacy": False,
  "engine": eng, "transport": trans, "no_gre": nogre == "1", "raw_ports": raw_p
})
json.dump(d, open(f, "w"), indent=2)
PYEOF

    echo -e "${GREEN}[✔️] Backhaul Peer '${NAME}' (id ${ID}) added [Engine: ${ENGINE}, Transport: ${TRANSPORT}]!${NC}"
    if [[ "$NO_GRE" -eq 1 ]]; then
        echo -e "BUNDLE:$(bundle_make_backhaul "$LOCAL_PUB" "$PORT" "$TRANSPORT" "$TOKEN" "$PORTS")"
    else
        echo -e "BUNDLE:$(bundle_make_gre_backhaul "$LOCAL_PUB" "$PORT" "$LOCAL_GRE" "$PEER_GRE" "$TRANSPORT" "$TOKEN" "$PORTS")"
    fi
}

# edit full configuration of one peer ($1=id, [--name], [--remote-pub], [--carrier], [--ports])
cli_edit_peer() {
    local ID="" NAME="" REMOTE_PUB="" CARRIER="" PORTS="" PROXY_PROTOCOL=""
    local FRP_TRANSPORT="" FRP_ENCRYPTION="" FRP_COMPRESSION=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --id) ID="$2"; shift 2 ;;
            --name) NAME="$2"; shift 2 ;;
            --remote-pub) REMOTE_PUB="$2"; shift 2 ;;
            --carrier) CARRIER="$2"; shift 2 ;;
            --ports) PORTS="$2"; shift 2 ;;
            --proxy-protocol) PROXY_PROTOCOL="$2"; shift 2 ;;
            --frp-transport) FRP_TRANSPORT="$2"; shift 2 ;;
            --encrypt) FRP_ENCRYPTION="on"; shift ;;
            --compress) FRP_COMPRESSION="on"; shift ;;
            --frp-encryption) FRP_ENCRYPTION="$2"; shift 2 ;;
            --frp-compression) FRP_COMPRESSION="$2"; shift 2 ;;
            -h|--help) echo 'Usage: hashem.sh edit-peer --id N [--name LABEL] [--remote-pub IP] [--carrier direct|wss:P] [--ports "443, 2083"] [--proxy-protocol off|v1|v2] [--frp-transport tcp|kcp|quic|websocket|wss] [--encrypt] [--compress]'; return 0 ;;
            *) echo -e "${RED}[!] Unknown flag: $1${NC}"; return 1 ;;
        esac
    done
    [[ "$ID" =~ ^[0-9]+$ ]] || { echo -e "${RED}[!] --id N is required.${NC}"; return 1; }
    if [[ -z "$NAME" && -z "$REMOTE_PUB" && -z "$CARRIER" && -z "$PORTS" && -z "$PROXY_PROTOCOL" && -z "$FRP_TRANSPORT" && -z "$FRP_ENCRYPTION" && -z "$FRP_COMPRESSION" ]]; then
        echo -e "${RED}[!] Nothing to edit — specify at least one parameter.${NC}"
        return 1
    fi

    peer_init; peer_require_py || return 1
    local rec
    rec=$(peer_get "$ID")
    [[ -n "$rec" ]] || { echo -e "${RED}[!] No peer with id $ID.${NC}"; return 1; }

    local CUR_NAME CUR_REMOTE CUR_CARRIER CUR_GIF CUR_SVC
    CUR_NAME=$(echo "$rec" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("name",""))')
    CUR_REMOTE=$(echo "$rec" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("remote_pub",""))')
    CUR_CARRIER=$(echo "$rec" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("carrier","direct"))')
    CUR_GIF=$(echo "$rec" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("gre_if",""))')
    CUR_SVC=$(echo "$rec" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("frps_svc","frps"))')

    # Validate remote public IP if provided
    if [[ -n "$REMOTE_PUB" ]]; then
        is_valid_ip "$REMOTE_PUB" || { echo -e "${RED}[!] Invalid remote public IP: ${REMOTE_PUB}${NC}"; return 1; }
        PEERS_F="$PEERS_FILE" PEER_ID="$ID" NEW_IP="$REMOTE_PUB" python3 <<'PYEOF'
import json, os, sys
f = os.environ["PEERS_F"]
pid = int(os.environ["PEER_ID"])
new_ip = os.environ["NEW_IP"]
d = json.load(open(f))
for p in d.get("peers", []):
    if p.get("id") != pid and p.get("remote_pub") == new_ip:
        print(f"[!] IP conflict: {new_ip} already used by peer '{p.get('name')}'", file=sys.stderr)
        sys.exit(1)
PYEOF
        if [[ $? -ne 0 ]]; then
            return 1
        fi
    fi

    # Validate carrier if provided
    if [[ -n "$CARRIER" ]]; then
        if [[ "$CARRIER" != "direct" && "$CARRIER" != fou:* && "$CARRIER" != wss:* && "$CARRIER" != "fou" && "$CARRIER" != "wss" ]]; then
            echo -e "${RED}[!] Invalid carrier mode: ${CARRIER} (must be direct, fou:PORT, or wss:PORT)${NC}"
            return 1
        fi
    fi

    # Validate ports if provided
    local CLEANED=""
    if [[ -n "$PORTS" ]]; then
        local p
        for p in $(echo "$PORTS" | tr ',' ' '); do
            is_valid_port "$p" && CLEANED="$CLEANED $((10#$p))"
        done
        CLEANED=$(echo "$CLEANED" | xargs)
        [[ -n "$CLEANED" ]] || { echo -e "${RED}[!] --ports needs at least one valid port (1-65535).${NC}"; return 1; }

        local USED entry CONFLICT=""
        USED=$(peer_ports_used)
        for p in $CLEANED; do
            for entry in $USED; do
                local port_owner="${entry#*:}" port_num="${entry%%:*}"
                if [[ "$port_num" == "$p" ]] && [[ "$port_owner" != "$CUR_NAME" ]]; then
                    CONFLICT="$CONFLICT $p (used by peer '${port_owner}')"
                fi
            done
        done
        if [[ -n "$CONFLICT" ]]; then
            echo -e "${RED}[!] Port conflict — already claimed by another tunnel:${CONFLICT}${NC}"
            return 1
        fi
    fi

    # 1. Apply Remote IP update if changed
    if [[ -n "$REMOTE_PUB" && "$REMOTE_PUB" != "$CUR_REMOTE" ]]; then
        echo -e "${CYAN}[*] Updating GRE remote endpoint: ${CUR_REMOTE} -> ${REMOTE_PUB}...${NC}"
        if ip link show "$CUR_GIF" >/dev/null 2>&1; then
            ip tunnel change "$CUR_GIF" remote "$REMOTE_PUB" >/dev/null 2>&1 || {
                ip link set dev "$CUR_GIF" down >/dev/null 2>&1 || true
                ip tunnel change "$CUR_GIF" remote "$REMOTE_PUB" >/dev/null 2>&1 || true
                ip link set dev "$CUR_GIF" up >/dev/null 2>&1 || true
            }
        fi
        local SVC_FILE="/etc/systemd/system/${CUR_GIF}.service"
        if [[ -f "$SVC_FILE" ]]; then
            sed -i -E "s/remote [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/remote ${REMOTE_PUB}/g" "$SVC_FILE"
            systemctl daemon-reload >/dev/null 2>&1 || true
            systemctl restart "${CUR_GIF}.service" >/dev/null 2>&1 || true
        fi
        if ! ping -c 1 -W 2 "$REMOTE_PUB" >/dev/null 2>&1; then
            echo -e "${YELLOW}[WARN] New remote IP ${REMOTE_PUB} did not reply to ping (peer may be offline or firewalling ICMP).${NC}"
        fi
    fi

    # 2. Apply Carrier update if changed
    if [[ -n "$CARRIER" && "$CARRIER" != "$CUR_CARRIER" ]]; then
        echo -e "${CYAN}[*] Applying carrier mode ${CARRIER} to interface ${CUR_GIF}...${NC}"
        carrier_apply "$CARRIER" "$CUR_GIF"
    fi

    # 3. Apply Ports update if changed
    if [[ -n "$CLEANED" ]]; then
        echo -e "${CYAN}[*] Updating forwarded ports for ${CUR_SVC}...${NC}"
        local TOML_FILE="/etc/frp/frps-${ID}.toml"
        [[ ! -f "$TOML_FILE" && "$ID" -eq 1 ]] && TOML_FILE="/etc/frp/frps.toml"
        if [[ -f "$TOML_FILE" ]]; then
            PEERS_F="$PEERS_FILE" TOML_F="$TOML_FILE" PORTS_CLEAN="$CLEANED" python3 <<'PYEOF'
import os
tf = os.environ["TOML_F"]
ports = [int(x) for x in os.environ["PORTS_CLEAN"].split()]
lines = open(tf).readlines()
header = []
in_proxy = False
for line in lines:
    t = line.strip()
    if t.startswith("[[proxies]]"):
        in_proxy = True
        continue
    if t.startswith("[") and not t.startswith("[[proxies]]"):
        in_proxy = False
    if not in_proxy:
        header.append(line)
out = "".join(header).rstrip() + "\n"
for p in ports:
    out += f"\n[[proxies]]\nname = \"tcp_{p}\"\ntype = \"tcp\"\nlocalIP = \"127.0.0.1\"\nlocalPort = {p}\nremotePort = {p}\n"
    out += f"\n[[proxies]]\nname = \"udp_{p}\"\ntype = \"udp\"\nlocalIP = \"127.0.0.1\"\nlocalPort = {p}\nremotePort = {p}\n"
open(tf, "w").write(out)
PYEOF
            systemctl reload-or-restart "$CUR_SVC" >/dev/null 2>&1 || true
        fi
        if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
            for p in $CLEANED; do
                ufw allow "$p"/tcp >/dev/null 2>&1 || true
                ufw allow "$p"/udp >/dev/null 2>&1 || true
            done
        fi
    fi

    # 4. Update peers.json
    PEERS_F="$PEERS_FILE" PEER_ID="$ID" NEW_NAME="$NAME" NEW_REMOTE="$REMOTE_PUB" NEW_CARRIER="$CARRIER" NEW_PORTS="$CLEANED" NEW_PP="$PROXY_PROTOCOL" NEW_TRANS="$FRP_TRANSPORT" NEW_ENC="$FRP_ENCRYPTION" NEW_COMP="$FRP_COMPRESSION" python3 <<'PYEOF'
import json, os
f = os.environ["PEERS_F"]
pid = int(os.environ["PEER_ID"])
name = os.environ.get("NEW_NAME")
rip = os.environ.get("NEW_REMOTE")
car = os.environ.get("NEW_CARRIER")
pstr = os.environ.get("NEW_PORTS")
pp = os.environ.get("NEW_PP")
ft = os.environ.get("NEW_TRANS")
enc = os.environ.get("NEW_ENC")
comp = os.environ.get("NEW_COMP")
d = json.load(open(f))
for p in d.get("peers", []):
    if p.get("id") == pid:
        if name:
            p["name"] = name
        if rip:
            p["remote_pub"] = rip
        if car:
            p["carrier"] = car
        if pstr:
            p["ports"] = [int(x) for x in pstr.split()]
        if pp:
            p["proxy_protocol"] = pp
        if ft:
            p["frp_transport"] = ft
        if enc in ("on", "true", "1"):
            p["use_encryption"] = True
        elif enc in ("off", "false", "0"):
            p["use_encryption"] = False
        if comp in ("on", "true", "1"):
            p["use_compression"] = True
        elif comp in ("off", "false", "0"):
            p["use_compression"] = False
json.dump(d, open(f, "w"), indent=2)
PYEOF

    local FINAL_NAME="${NAME:-$CUR_NAME}"
    echo -e "${GREEN}[✔️] Peer '${FINAL_NAME}' (id ${ID}) updated successfully.${NC}"
}

# edit forwarded ports of one peer ($1=id, --ports "443, 2083")
cli_edit_peer_ports() {
    local ID="" PORTS=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --id) ID="$2"; shift 2 ;;
            --ports) PORTS="$2"; shift 2 ;;
            -h|--help) echo 'Usage: hashem.sh edit-peer-ports --id N --ports "443, 2083"'; return 0 ;;
            *) echo -e "${RED}[!] Unknown flag: $1${NC}"; return 1 ;;
        esac
    done
    cli_edit_peer --id "$ID" --ports "$PORTS"
}


# readable peer table for the menu
peer_list_pretty() {
    peer_init; peer_require_py || return 1
    PEERS_F="$PEERS_FILE" python3 <<'PYEOF'
import json, os, subprocess
try:
    peers = json.load(open(os.environ["PEERS_F"])).get("peers", [])
except Exception as e:
    print(f"[!] cannot read peers registry: {e}"); raise SystemExit(1)
if not peers:
    print("[*] No peer tunnels yet. Use 'Add peer tunnel' to connect a foreign server.")
    raise SystemExit(0)
tun = subprocess.run(["ip", "tunnel", "show"], capture_output=True, text=True).stdout
for p in sorted(peers, key=lambda x: x["id"]):
    gre = "up" if p.get("gre_if", "") in tun else "down"
    try:
        frp = subprocess.run(["systemctl", "is-active", p.get("frps_svc", "")],
                             capture_output=True, text=True).stdout.strip()
    except Exception:
        frp = "?"
    print(f"#{p['id']} {p['name']}: {p['remote_pub']} (GRE {p['local_gre']} peer {p['peer_gre']}, {p['gre_if']} {gre}) "
          f"| {p['frps_svc']} :{p['frp_port']} {frp} | ports: {','.join(map(str, p.get('ports', [])))}")
PYEOF
}

setup_iran_server() {
    echo -e "\n${YELLOW}====================================================${NC}"
    echo -e "${YELLOW}       STEP 1: CONFIGURING IRAN SERVER (GRE + FRPS)  ${NC}"
    echo -e "${YELLOW}====================================================${NC}"

    MY_PUBLIC_IP=$(ip route get 1.1.1.1 2>/dev/null | awk '/src/ {for (i=1; i<=NF; i++) if ($i=="src") {print $(i+1); exit}}')
    [[ -z "$MY_PUBLIC_IP" ]] && MY_PUBLIC_IP=$(curl -sSL --max-time 5 https://api.ipify.org 2>/dev/null)
    prompt_ip IP_IRAN "Enter IRAN Server Public IP" "$MY_PUBLIC_IP"
    prompt_ip IP_FOREIGN "Enter FOREIGN Server Public IP" ""

    prompt_port BIND_PORT "Enter FRP Bind Port" "$(gen_random_port)"
    BIND_PORT=$(ensure_port_available "$BIND_PORT" "FRP Bind Port" 0) || return 1

    AUTO_TOKEN=$(gen_token32)
    prompt_token TOKEN "Enter Secret Auth Token" "$AUTO_TOKEN"

    # single source of truth: GRE + frps + panel all happen inside
    setup_iran_server_noninteractive "$IP_IRAN" "$IP_FOREIGN" "$BIND_PORT" "$TOKEN" "$IRAN_GRE_IP" "$FOREIGN_GRE_IP"
}

# interactive wrapper for cli_add_peer: prompts for one more foreign server.
menu_add_peer() {
    echo -e "\n${YELLOW}=== Add Peer Tunnel (connect ANOTHER foreign server to this Iran) ===${NC}"
    peer_init
    USED=$(peer_ports_used 2>/dev/null)
    [[ -n "$USED" ]] && echo -e "${CYAN}Already claimed reverse ports: ${USED}${NC}"
    local MYIP
    MYIP=$(ip route get 1.1.1.1 2>/dev/null | awk '/src/ {for (i=1; i<=NF; i++) if ($i=="src") {print $(i+1); exit}}')
    local NAME IP_FOREIGN PORT CPORT TOKEN LGRE PGRE PPORTS
    read -p "Peer name (e.g. germany-1) [Enter for auto]: " NAME
    prompt_ip LOCAL_IRAN "Enter IRAN Server Public IP" "$MYIP"
    prompt_ip IP_FOREIGN "Enter FOREIGN Server Public IP" ""
    # suggest next free control port + GRE pair
    local NEXT_ID SU_FP SU_LG SU_PG
    NEXT_ID=$(peer_next_id 2>/dev/null || echo 2)
    SU_FP=$(gen_random_port)
    SU_LG="10.1${NEXT_ID}.0.2"; SU_PG="10.1${NEXT_ID}.0.1"
    prompt_port CPORT "Enter FRP Control Port (unique per peer)" "$SU_FP"
    AUTO_TOKEN=$(gen_token32)
    prompt_token TOKEN "Peer token (each peer gets its own)" "$AUTO_TOKEN"
    prompt_ip LGRE "Local GRE IP (unique per peer)" "$SU_LG"
    prompt_ip PGRE "Peer GRE IP" "$SU_PG"
    prompt_ports PPORTS "Ports to Reverse-Tunnel"
    cli_add_peer --name "$NAME" --local-pub "$LOCAL_IRAN" --remote-pub "$IP_FOREIGN" \
        --frp-port "$CPORT" --token "$TOKEN" --local-gre "$LGRE" --peer-gre "$PGRE" --ports "$PPORTS"
    echo -e "\n${GREEN}=== On the FOREIGN server, run this script option 2 with: ===${NC}"
    echo -e "IRAN Public IP: ${CYAN}${LOCAL_IRAN}${NC} | Port: ${CYAN}${CPORT}${NC} | Token: ${CYAN}${TOKEN}${NC}"
    echo -e "GRE: local ${CYAN}${PGRE}${NC} peer ${CYAN}${LGRE}${NC} | Ports: ${CYAN}${PPORTS}${NC}"
}

menu_remove_peer() {
    echo -e "\n${YELLOW}=== Remove Peer Tunnel ===${NC}"
    peer_list_pretty || return 1
    local ID
    read -p "Peer id to remove: " ID
    cli_remove_peer --id "$ID"
}

menu_edit_peer() {
    echo -e "\n${YELLOW}=== Edit Peer Tunnel Configuration ===${NC}"
    peer_list_pretty || return 1
    local ID
    read -p "Peer id to edit: " ID
    [[ "$ID" =~ ^[0-9]+$ ]] || { echo -e "${RED}[!] Invalid Peer ID.${NC}"; return 1; }

    peer_init; peer_require_py || return 1
    local rec
    rec=$(peer_get "$ID")
    [[ -n "$rec" ]] || { echo -e "${RED}[!] No peer with id $ID.${NC}"; return 1; }

    local CUR_NAME CUR_REMOTE CUR_CARRIER CUR_PORTS
    CUR_NAME=$(echo "$rec" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("name",""))')
    CUR_REMOTE=$(echo "$rec" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("remote_pub",""))')
    CUR_CARRIER=$(echo "$rec" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("carrier","direct"))')
    CUR_PORTS=$(echo "$rec" | python3 -c 'import json,sys; print(", ".join(str(x) for x in json.load(sys.stdin).get("ports",[])))')

    echo -e "\n${CYAN}Editing Peer #${ID} (${CUR_NAME}):${NC}"
    echo -e "Press Enter on any field to keep its current value."

    local NEW_NAME NEW_REMOTE CAR_OPT NEW_CARRIER="" NEW_PORTS
    read -p "Name [${CUR_NAME}]: " NEW_NAME
    read -p "Remote Public IP [${CUR_REMOTE}]: " NEW_REMOTE
    echo -e "Carrier mode options: 1) Direct GRE  2) FOU:443  3) FOU:55555  4) WSS:8443  (Enter to keep '${CUR_CARRIER}')"
    read -p "Select carrier [1-4]: " CAR_OPT
    case "$CAR_OPT" in
        1) NEW_CARRIER="direct" ;;
        2) NEW_CARRIER="fou:443" ;;
        3) NEW_CARRIER="fou:55555" ;;
        4) NEW_CARRIER="wss:8443" ;;
        *) NEW_CARRIER="" ;;
    esac
    read -p "Forwarded ports (comma-separated) [${CUR_PORTS}]: " NEW_PORTS

    local ARGS=(--id "$ID")
    [[ -n "$NEW_NAME" ]] && ARGS+=(--name "$NEW_NAME")
    [[ -n "$NEW_REMOTE" ]] && ARGS+=(--remote-pub "$NEW_REMOTE")
    [[ -n "$NEW_CARRIER" ]] && ARGS+=(--carrier "$NEW_CARRIER")
    [[ -n "$NEW_PORTS" ]] && ARGS+=(--ports "$NEW_PORTS")

    cli_edit_peer "${ARGS[@]}"
}

setup_foreign_server() {
    echo -e "\n${YELLOW}====================================================${NC}"
    echo -e "${YELLOW}   STEP 2: CONFIGURING FOREIGN SERVER (GRE + FRPC)  ${NC}"
    echo -e "${YELLOW}====================================================${NC}"
    MY_PUBLIC_IP=$(ip route get 1.1.1.1 2>/dev/null | awk '/src/ {for (i=1; i<=NF; i++) if ($i=="src") {print $(i+1); exit}}')
    [[ -z "$MY_PUBLIC_IP" ]] && MY_PUBLIC_IP=$(curl -sSL --max-time 5 https://api.ipify.org 2>/dev/null)

    echo -e "Do you have a Setup Bundle from the Iran server? (${CYAN}hsh1_...${NC})"
    read -p "Enter Setup Bundle [Press Enter to configure manually]: " BUNDLE_IN
    local SERVER_PORT TOKEN INPUT_PORTS BUNDLE_USED=0 LOCAL_GRE_SET="$FOREIGN_GRE_IP" PEER_GRE_SET="$IRAN_GRE_IP"
    local IP_FOREIGN="" IP_IRAN=""
    
    if [[ -n "$BUNDLE_IN" ]]; then
        if bundle_parse "$BUNDLE_IN"; then
            echo ""
            cli_bundle_inspect "$BUNDLE_IN"
            read -p "Apply this bundle configuration? [Y/n]: " CONFIRM_APPLY
            if [[ "$CONFIRM_APPLY" =~ ^[Nn]$ ]]; then
                echo -e "${YELLOW}[*] Bundle application cancelled by user. Returning to menu.${NC}"
                return 0
            fi
            BUNDLE_USED=1
            prompt_ip IP_FOREIGN "Enter FOREIGN Server Public IP" "$MY_PUBLIC_IP"
            if [[ "$B_ENGINE" == "backhaul" ]]; then
                setup_backhaul_foreign_server_noninteractive "$IP_FOREIGN" "$B_IRAN_PUB" "$B_FRP_PORT" "$B_TOKEN" "$B_TRANSPORT"
                return $?
            elif [[ "$B_ENGINE" == "gre-backhaul" ]]; then
                setup_gre_backhaul_foreign_server_noninteractive "$IP_FOREIGN" "$B_IRAN_PUB" "$B_FRP_PORT" "$B_TOKEN" "$B_FOREIGN_GRE" "$B_IRAN_GRE" "$B_TRANSPORT"
                return $?
            fi
            IP_IRAN=$B_IRAN_PUB
            SERVER_PORT=$B_FRP_PORT
            TOKEN=$B_TOKEN
            LOCAL_GRE_SET=$B_FOREIGN_GRE
            PEER_GRE_SET=$B_IRAN_GRE
            INPUT_PORTS=$(echo "$B_PORTS" | tr ' ' ',')
            carrier_set_fou_ports "$B_FOU_P1" "$B_FOU_P2" 2>/dev/null || true
            carrier_init_kernel 2>/dev/null || true
            if [[ -z "$INPUT_PORTS" ]]; then
                prompt_ports INPUT_PORTS "Enter Ports to Reverse-Tunnel"
            fi
        else
            echo -e "${RED}[!] Invalid bundle format. Falling back to manual input.${NC}"
        fi
    fi

    if [[ "$BUNDLE_USED" -ne 1 ]]; then
        prompt_ip IP_FOREIGN "Enter FOREIGN Server Public IP" "$MY_PUBLIC_IP"
        prompt_ip IP_IRAN "Enter IRAN Server Public IP" ""
        prompt_port SERVER_PORT "Enter FRP Server Port (from Iran server)" "$(gen_random_port)"
        prompt_required TOKEN "Enter Secret Auth Token"
        prompt_ports INPUT_PORTS "Enter Ports to Reverse-Tunnel"
    fi

    PORTS_CLEANED=$(echo "$INPUT_PORTS" | tr ',' ' ')

    # single source of truth: GRE + ping + frpc + panel all happen inside
    _setup_foreign_full "$IP_FOREIGN" "$IP_IRAN" "$SERVER_PORT" "$TOKEN" "$LOCAL_GRE_SET" "$PEER_GRE_SET" "$PORTS_CLEANED"
}

check_status() {
    echo -e "\n${YELLOW}=== Checking GRE & FRP / Backhaul Status ===${NC}"

    # 1. GRE Status
    echo -e "\n${CYAN}[1] GRE Tunnel Interface:${NC}"
    if ip link show "$TUNNEL_NAME" >/dev/null 2>&1; then
        ip addr show dev "$TUNNEL_NAME"
        echo -e "${GREEN}[✔️] Interface ${TUNNEL_NAME} exists and is UP.${NC}"
    else
        echo -e "${YELLOW}[*] Interface ${TUNNEL_NAME} not found (may be running in No-GRE Backhaul mode).${NC}"
    fi

    # 2. Ping Test
    if ip link show "$TUNNEL_NAME" >/dev/null 2>&1; then
        echo -e "\n${CYAN}[2] GRE Ping Test:${NC}"
        if ip addr show dev "$TUNNEL_NAME" 2>/dev/null | grep -q "$IRAN_GRE_IP"; then
            TARGET_PING="$FOREIGN_GRE_IP"
            echo "Testing ping to Foreign GRE IP ($TARGET_PING)..."
        else
            TARGET_PING="$IRAN_GRE_IP"
            echo "Testing ping to Iran GRE IP ($TARGET_PING)..."
        fi
        ping -c 3 -W 2 "$TARGET_PING" && echo -e "${GREEN}[✔️] Ping OK.${NC}" || echo -e "${YELLOW}[!] Remote peer did not answer ping.${NC}"
    fi

    # 3. Service Status
    echo -e "\n${CYAN}[3] Reverse Tunnel Service Status:${NC}"
    if systemctl is-active --quiet frps; then
        echo -e "${GREEN}[✔️] frps (FRP Server on IRAN) is ACTIVE and RUNNING.${NC}"
        systemctl status frps --no-pager -l
    elif systemctl is-active --quiet backhaul-server; then
        echo -e "${GREEN}[✔️] backhaul-server (Backhaul Server on IRAN) is ACTIVE and RUNNING.${NC}"
        systemctl status backhaul-server --no-pager -l
    elif systemctl is-active --quiet frpc; then
        echo -e "${GREEN}[✔️] frpc (FRP Client on FOREIGN) is ACTIVE and RUNNING.${NC}"
        systemctl status frpc --no-pager -l
        local MUX_HINT
        MUX_HINT=$(tcpmux_eof_hint) && echo -e "${YELLOW}[!] ${MUX_HINT}${NC}"
    elif systemctl is-active --quiet backhaul-client; then
        echo -e "${GREEN}[✔️] backhaul-client (Backhaul Client on FOREIGN) is ACTIVE and RUNNING.${NC}"
        systemctl status backhaul-client --no-pager -l
    else
        echo -e "${RED}[!] Neither FRP nor Backhaul service is active.${NC}"
    fi
}

show_logs() {
    echo -e "\n${YELLOW}=== Live Service Logs (Ctrl+C to exit) ===${NC}"
    if systemctl list-unit-files | grep -q "backhaul-server.service"; then
        journalctl -u backhaul-server -n 50 -f
    elif systemctl list-unit-files | grep -q "backhaul-client.service"; then
        journalctl -u backhaul-client -n 50 -f
    elif systemctl list-unit-files | grep -q "frps.service"; then
        journalctl -u frps -n 50 -f
    elif systemctl list-unit-files | grep -q "frpc.service"; then
        journalctl -u frpc -n 50 -f
    else
        echo -e "${RED}[!] No tunnel service found.${NC}"
    fi
}

restart_all() {
    echo -e "\n${CYAN}[*] Restarting GRE and FRP/Backhaul services (all tunnels)...${NC}"
    local u
    for u in /etc/systemd/system/gre-t*.service /etc/systemd/system/gre-tunnel.service /etc/systemd/system/frps*.service /etc/systemd/system/frpc.service /etc/systemd/system/backhaul*.service; do
        [[ -f "$u" ]] || continue
        systemctl restart "$(basename "$u")" >/dev/null 2>&1 && echo -e "${GREEN}[✔️] $(basename "$u") restarted.${NC}"
    done
    echo -e "${GREEN}[✔️] All services restarted.${NC}"
}

ensure_doctor_tools() {
    local NEED_INSTALL=0
    for cmd in iperf3 ping curl; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            NEED_INSTALL=1
            break
        fi
    done
    if [[ "$NEED_INSTALL" -eq 1 ]]; then
        echo -e "${CYAN}[*] Installing diagnostic tools (iperf3, iputils-ping, curl)...${NC}"
        apt-get update -qq && apt-get install -y -qq iperf3 iputils-ping curl || echo -e "${YELLOW}[!] Warning: failed to install some diagnostic tools.${NC}"
    fi
}

doctor_diagnostics() {
    ensure_doctor_tools

    echo -e "\n${CYAN}==========================================================${NC}"
    echo -e "${CYAN}      Hashem Diagnostics & Speed Test (Doctor Suite)      ${NC}"
    echo -e "${CYAN}==========================================================${NC}\n"

    # 1. Determine Peer IP
    local ROLE="unknown"
    local TARGET_IP=""
    local LOCAL_IP=""

    if ip addr show dev "$TUNNEL_NAME" 2>/dev/null | grep -q "$IRAN_GRE_IP"; then
        ROLE="Iran (Server)"
        LOCAL_IP="$IRAN_GRE_IP"
        TARGET_IP="$FOREIGN_GRE_IP"
    elif ip addr show dev "$TUNNEL_NAME" 2>/dev/null | grep -q "$FOREIGN_GRE_IP"; then
        ROLE="Foreign (Client)"
        LOCAL_IP="$FOREIGN_GRE_IP"
        TARGET_IP="$IRAN_GRE_IP"
    else
        local IFACE
        IFACE=$(ip -o link show type gre 2>/dev/null | awk -F': ' '{print $2}' | cut -d'@' -f1 | head -n1)
        if [[ -n "$IFACE" ]]; then
            LOCAL_IP=$(ip -o -4 addr show dev "$IFACE" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1)
            if [[ "$LOCAL_IP" =~ \.1$ ]]; then
                TARGET_IP="${LOCAL_IP%.*}.2"
                ROLE="Foreign"
            elif [[ "$LOCAL_IP" =~ \.2$ ]]; then
                TARGET_IP="${LOCAL_IP%.*}.1"
                ROLE="Iran"
            fi
        fi
    fi

    echo -e "  ${YELLOW}Role:${NC}        ${ROLE}"
    echo -e "  ${YELLOW}Tunnel:${NC}      ${TUNNEL_NAME:-gre-tunnel}"
    echo -e "  ${YELLOW}Local IP:${NC}    ${LOCAL_IP:-N/A}"
    echo -e "  ${YELLOW}Peer IP:${NC}     ${TARGET_IP:-N/A}\n"

    if [[ -z "$TARGET_IP" ]]; then
        echo -e "${RED}[!] Tunnel interface is not active or peer IP cannot be determined.${NC}"
        return 1
    fi

    # 2. Ping & Jitter Test (10 packets)
    echo -e "${CYAN}[1/4] Measuring Latency, Packet Loss & Jitter (10 packets)...${NC}"
    local PING_OUT
    PING_OUT=$(ping -c 10 -W 2 "$TARGET_IP" 2>&1)
    local LOSS
    LOSS=$(echo "$PING_OUT" | awk -F',' '/packet loss/ {for(i=1;i<=NF;i++) if($i~/packet loss/) print $(i-0)}' | tr -dc '0-9.')
    local RTT_LINE
    RTT_LINE=$(echo "$PING_OUT" | grep -E '(rtt|round-trip) min/avg/max')

    local MIN_RTT="0" AVG_RTT="0" MAX_RTT="0" JITTER="0"
    if [[ -n "$RTT_LINE" ]]; then
        local STATS
        STATS=$(echo "$RTT_LINE" | awk -F'=' '{print $2}' | tr -d ' ' | cut -d'/' -f1-4)
        MIN_RTT=$(echo "$STATS" | cut -d'/' -f1)
        AVG_RTT=$(echo "$STATS" | cut -d'/' -f2)
        MAX_RTT=$(echo "$STATS" | cut -d'/' -f3)
        JITTER=$(echo "$STATS" | cut -d'/' -f4)
    fi

    local LOSS_INT="${LOSS%%.*}"
    LOSS_INT="${LOSS_INT:-0}"

    echo -e "  • Packet Loss:  ${LOSS:-0}%"
    echo -e "  • Min RTT:      ${MIN_RTT} ms"
    echo -e "  • Avg RTT:      ${AVG_RTT} ms"
    echo -e "  • Max RTT:      ${MAX_RTT} ms"
    echo -e "  • Jitter (mdev):${JITTER} ms"

    if [[ "$LOSS_INT" -eq 0 ]]; then
        echo -e "  ${GREEN}[✔️] Ping test passed with zero packet loss.${NC}\n"
    elif [[ "$LOSS_INT" -le 10 ]]; then
        echo -e "  ${YELLOW}[⚠️] Mild packet loss (${LOSS}%).${NC}\n"
    else
        echo -e "  ${RED}[!] High packet loss detected (${LOSS}%).${NC}\n"
    fi

    # 3. Path MTU Discovery
    echo -e "${CYAN}[2/4] Testing Path MTU & Fragmentation...${NC}"
    local OPTIMAL_MTU=0
    # 1420
    if ping -c 2 -W 2 -M do -s 1392 "$TARGET_IP" >/dev/null 2>&1; then
        echo -e "  • MTU 1420: ${GREEN}PASS (Unfragmented)${NC}"
        OPTIMAL_MTU=1420
    else
        echo -e "  • MTU 1420: ${YELLOW}FRAGMENTED${NC}"
    fi

    # 1400
    if ping -c 2 -W 2 -M do -s 1372 "$TARGET_IP" >/dev/null 2>&1; then
        echo -e "  • MTU 1400: ${GREEN}PASS (Unfragmented)${NC}"
        [[ "$OPTIMAL_MTU" -eq 0 ]] && OPTIMAL_MTU=1400
    else
        echo -e "  • MTU 1400: ${YELLOW}FRAGMENTED${NC}"
    fi

    # 1360
    if ping -c 2 -W 2 -M do -s 1332 "$TARGET_IP" >/dev/null 2>&1; then
        echo -e "  • MTU 1360: ${GREEN}PASS (Unfragmented)${NC}"
        [[ "$OPTIMAL_MTU" -eq 0 ]] && OPTIMAL_MTU=1360
    else
        echo -e "  • MTU 1360: ${RED}FAILED${NC}"
    fi

    echo -e "  ${GREEN}[✔️] Optimal Recommended MTU: ${OPTIMAL_MTU:-1400} bytes.${NC}\n"

    # 4. Kernel TCP Stack Audit
    echo -e "${CYAN}[3/4] Auditing Kernel TCP Stack & Forwarding...${NC}"
    local CC
    CC=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "unknown")
    local FWD
    FWD=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo "0")
    local MSS_COUNT
    MSS_COUNT=$(iptables -t mangle -L -v -n 2>/dev/null | grep -c "TCPMSS" || echo "0")

    if [[ "$CC" == "bbr" ]]; then
        echo -e "  • TCP Congestion Control: ${GREEN}BBR (Active)${NC}"
    else
        echo -e "  • TCP Congestion Control: ${YELLOW}${CC} (BBR not enabled)${NC}"
    fi

    if [[ "$FWD" == "1" ]]; then
        echo -e "  • IPv4 Forwarding:        ${GREEN}Enabled${NC}"
    else
        echo -e "  • IPv4 Forwarding:        ${RED}Disabled${NC}"
    fi

    if [[ "$MSS_COUNT" -gt 0 ]]; then
        echo -e "  • TCP MSS Clamping:       ${GREEN}Active (${MSS_COUNT} rules)${NC}\n"
    else
        echo -e "  • TCP MSS Clamping:       ${YELLOW}Not configured${NC}\n"
    fi

    # 5. Throughput / iPerf3 Test
    echo -e "${CYAN}[4/4] Bandwidth & Throughput Speed Test...${NC}"
    if command -v iperf3 >/dev/null 2>&1; then
        echo -e "  Attempting 3-second throughput benchmark to ${TARGET_IP}:5201..."
        local IPERF_OUT
        IPERF_OUT=$(iperf3 -c "$TARGET_IP" -t 3 -J 2>/dev/null)
        if [[ -n "$IPERF_OUT" ]] && echo "$IPERF_OUT" | grep -q '"bits_per_second"'; then
            local BPS
            BPS=$(echo "$IPERF_OUT" | awk -F'"bits_per_second":' '/"bits_per_second"/ {print $2}' | tr -dc '0-9.' | head -n1)
            local MBPS
            MBPS=$(awk -v b="$BPS" 'BEGIN { if (b > 0) printf "%.2f", b / 1000000; else print "0" }')
            echo -e "  ${GREEN}[✔️] Throughput Speed: ${MBPS} Mbps${NC}\n"
        else
            echo -e "  ${YELLOW}[i] Remote iperf3 server not running on ${TARGET_IP}:5201.${NC}"
            echo -e "      (Run 'hashem doctor server' on the remote server to enable direct speed tests).\n"
        fi
    fi

    # 6. Overall Rating & Recommendations
    local SCORE=100
    if [[ "$LOSS_INT" -gt 0 ]]; then
        SCORE=$((SCORE - LOSS_INT * 2))
    fi
    if [[ "$AVG_RTT" != "0" ]] && awk -v r="$AVG_RTT" 'BEGIN { exit (r > 100 ? 0 : 1) }'; then
        SCORE=$((SCORE - 15))
    fi
    if [[ "$CC" != "bbr" ]]; then
        SCORE=$((SCORE - 15))
    fi
    if [[ "$FWD" != "1" ]]; then
        SCORE=$((SCORE - 20))
    fi
    if [[ "$MSS_COUNT" -eq 0 ]]; then
        SCORE=$((SCORE - 10))
    fi
    if [[ "$OPTIMAL_MTU" -lt 1400 && "$OPTIMAL_MTU" -gt 0 ]]; then
        SCORE=$((SCORE - 10))
    fi
    [[ "$SCORE" -lt 0 ]] && SCORE=0

    echo -e "${CYAN}==========================================================${NC}"
    echo -e "  ${YELLOW}Overall Health Score:${NC} ${SCORE}/100"
    if [[ "$SCORE" -ge 85 ]]; then
        echo -e "  ${GREEN}Status: EXCELLENT — Tunnel is fully optimized.${NC}"
    elif [[ "$SCORE" -ge 70 ]]; then
        echo -e "  ${CYAN}Status: GOOD — Minor optimizations recommended.${NC}"
    elif [[ "$SCORE" -ge 50 ]]; then
        echo -e "  ${YELLOW}Status: WARNING — Packet loss or kernel bottlenecks present.${NC}"
    else
        echo -e "  ${RED}Status: CRITICAL — Major network or routing issues detected.${NC}"
    fi
    echo -e "${CYAN}==========================================================${NC}\n"

    if [[ "$SCORE" -lt 85 ]]; then
        read -p "Would you like to automatically apply recommended fixes (BBR, MSS, MTU)? [y/N]: " DO_FIX
        if [[ "$DO_FIX" =~ ^[Yy]$ ]]; then
            doctor_apply_fixes
        fi
    fi
}

doctor_apply_fixes() {
    echo -e "\n${CYAN}[*] Applying automated optimizations...${NC}"
    tune_apply
    echo -e "${GREEN}[✔️] Optimizations applied successfully.${NC}\n"
}

doctor_start_server() {
    ensure_doctor_tools
    if pgrep -x iperf3 >/dev/null 2>&1; then
        echo -e "${YELLOW}[i] iperf3 server is already running.${NC}"
    else
        iperf3 -s -D
        echo -e "${GREEN}[✔️] iperf3 server started in background on port 5201.${NC}"
    fi
}

doctor_stop_server() {
    pkill -f "iperf3 -s" >/dev/null 2>&1 || true
    echo -e "${GREEN}[✔️] iperf3 server stopped.${NC}"
}

doctor_health_check() {
    echo -e "\n${CYAN}=============================================================="
    echo "             HASHEM SYSTEM & TUNNEL HEALTH CHECK"
    echo -e "==============================================================${NC}"
    
    local PASS_COUNT=0 WARN_COUNT=0 FAIL_COUNT=0
    
    report_item() {
        local name="$1" status="$2" details="$3"
        local badge
        case "$status" in
            PASS) badge="${GREEN}[PASS]${NC}"; ((PASS_COUNT++)) ;;
            WARN) badge="${YELLOW}[WARN]${NC}"; ((WARN_COUNT++)) ;;
            FAIL) badge="${RED}[FAIL]${NC}"; ((FAIL_COUNT++)) ;;
        esac
        printf "%-8b %-30s %s\n" "$badge" "$name" "$details"
    }
    
    local MUX_HINT
    if MUX_HINT=$(tcpmux_eof_hint); then
        report_item "FRP tcpMux match" "WARN" "$MUX_HINT"
    fi

    # 1. OS & Architecture
    local OS_INFO
    OS_INFO=$(uname -s -m 2>/dev/null || echo "Linux")
    report_item "Operating System & Arch" "PASS" "$OS_INFO"
    
    # 2. Linux Kernel Version
    local KERNEL_VER
    KERNEL_VER=$(uname -r 2>/dev/null || echo "Unknown")
    report_item "Linux Kernel Version" "PASS" "$KERNEL_VER"
    
    # 3. IP Forwarding
    local IP_FWD
    IP_FWD=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)
    if [[ "$IP_FWD" == "1" ]]; then
        report_item "IP Forwarding (ip_forward)" "PASS" "Enabled (1)"
    else
        report_item "IP Forwarding (ip_forward)" "WARN" "Disabled (0) — enable via sysctl"
    fi
    
    # 4. GRE Kernel Modules
    if lsmod 2>/dev/null | grep -q "ip_gre" || modprobe ip_gre 2>/dev/null; then
        report_item "Kernel Module (ip_gre)" "PASS" "Loaded"
    else
        report_item "Kernel Module (ip_gre)" "FAIL" "Missing / Cannot load ip_gre module"
    fi
    
    # 5. FOU Kernel Module
    if lsmod 2>/dev/null | grep -q "fou" || modprobe fou 2>/dev/null; then
        report_item "Kernel Module (fou)" "PASS" "Loaded"
    else
        report_item "Kernel Module (fou)" "WARN" "FOU module not available (fallback to direct GRE)"
    fi
    
    # 6. GRE Interface Status
    if ip link show "$TUNNEL_NAME" >/dev/null 2>&1; then
        local INNER_IP
        INNER_IP=$(ip -4 addr show dev "$TUNNEL_NAME" 2>/dev/null | awk '/inet / {print $2}')
        if [[ -n "$INNER_IP" ]]; then
            report_item "GRE Interface (${TUNNEL_NAME})" "PASS" "UP with IP: $INNER_IP"
        else
            report_item "GRE Interface (${TUNNEL_NAME})" "WARN" "Interface exists but no IPv4 assigned"
        fi
    else
        report_item "GRE Interface (${TUNNEL_NAME})" "WARN" "Interface not found"
    fi
    
    # 7. GRE Peer Ping Connectivity
    local PEER_PING_TARGET=""
    if [[ -f /etc/frp/frpc.toml ]]; then
        PEER_PING_TARGET=$(awk -F'=' '/serverAddr/{gsub(/[ "]/,"",$2); print $2}' /etc/frp/frpc.toml 2>/dev/null)
    elif [[ -f /etc/frp/frps.toml ]]; then
        PEER_PING_TARGET="$FOREIGN_GRE_IP"
    fi
    if [[ -n "$PEER_PING_TARGET" ]]; then
        local P_OUT
        if P_OUT=$(ping -c 2 -W 2 "$PEER_PING_TARGET" 2>/dev/null); then
            local RTT
            RTT=$(echo "$P_OUT" | awk -F'/' '/rtt/ {print $5}')
            report_item "GRE Peer Connectivity" "PASS" "Reachable (${RTT:-<50} ms)"
        else
            # ICMP may be filtered by the ISP (common in Iran with GRE tunnels).
            # If frpc is active, TCP through GRE is working — downgrade to WARN.
            if systemctl is-active --quiet frpc 2>/dev/null; then
                report_item "GRE Peer Connectivity" "WARN" "ICMP filtered (ISP) but frpc TCP tunnel is active — tunnel functional"
            else
                report_item "GRE Peer Connectivity" "FAIL" "Cannot ping peer ${PEER_PING_TARGET}"
            fi
        fi
    else
        report_item "GRE Peer Connectivity" "WARN" "No peer IP configured yet"
    fi
    
    # 8. FRPS Service
    if [[ -f /etc/systemd/system/frps.service ]]; then
        if systemctl is-active --quiet frps 2>/dev/null; then
            local F_PORT
            F_PORT=$(awk -F'=' '/bindPort/{gsub(/[ "]/,"",$2); print $2}' /etc/frp/frps.toml 2>/dev/null)
            report_item "FRP Server (frps)" "PASS" "Active and listening on port :${F_PORT:-unknown}"
        else
            report_item "FRP Server (frps)" "FAIL" "Service installed but NOT running"
        fi
    fi
    
    # 9. FRPC Service
    if [[ -f /etc/systemd/system/frpc.service ]]; then
        if systemctl is-active --quiet frpc 2>/dev/null; then
            report_item "FRP Client (frpc)" "PASS" "Active (Reverse Tunnel Established)"
        else
            report_item "FRP Client (frpc)" "FAIL" "Service installed but NOT running"
        fi
    fi
    
    # 10. Web Panel Service
    if [[ -f /etc/systemd/system/gre-panel.service ]]; then
        if systemctl is-active --quiet gre-panel 2>/dev/null; then
            local P_PORT
            P_PORT=$(grep -o '"port": *[0-9]*' /etc/gre-panel/panel.json 2>/dev/null | grep -o '[0-9]*' || echo 7777)
            report_item "Web Panel (gre-panel)" "PASS" "Active on port ${P_PORT}"
        else
            report_item "Web Panel (gre-panel)" "FAIL" "Service installed but NOT running"
        fi
    else
        report_item "Web Panel (gre-panel)" "WARN" "Not installed on this host"
    fi
    
    # 11. Firewall / Ports
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
        report_item "Firewall (UFW)" "PASS" "Active (ports configured)"
    else
        report_item "Firewall (UFW)" "PASS" "Permissive / inactive"
    fi
    
    echo -e "${CYAN}==============================================================${NC}"
    if [[ "$FAIL_COUNT" -eq 0 && "$WARN_COUNT" -eq 0 ]]; then
        echo -e "OVERALL HEALTH RESULT: ${GREEN}PASS${NC} (All checks passed successfully)"
    elif [[ "$FAIL_COUNT" -eq 0 ]]; then
        echo -e "OVERALL HEALTH RESULT: ${YELLOW}WARN${NC} (${WARN_COUNT} warning(s) detected, system functional)"
    else
        echo -e "OVERALL HEALTH RESULT: ${RED}FAIL${NC} (${FAIL_COUNT} critical failure(s) detected)"
    fi
    echo -e "${CYAN}==============================================================${NC}\n"
}

cli_doctor() {
    case "${1:-}" in
        server) doctor_start_server ;;
        stop-server) doctor_stop_server ;;
        fix) doctor_apply_fixes ;;
        diag|speed) doctor_diagnostics ;;
        stress|stress-test|load) shift; cli_stress_test "$@" ;;
        check|*) doctor_health_check ;;
    esac
}

cli_stress_test() {
    local TARGET_HOST="${1:-127.0.0.1}"
    local TARGET_PORT="${2:-}"
    local CONNS="${3:-200}"

    if [[ -z "$TARGET_PORT" ]]; then
        TARGET_PORT=$(awk -F'=' '/bindPort/{gsub(/[ "]/,"",$2); print $2}' /etc/frp/frps.toml 2>/dev/null)
        [[ -z "$TARGET_PORT" ]] && TARGET_PORT=$(awk -F'=' '/serverPort/{gsub(/[ "]/,"",$2); print $2}' /etc/frp/frpc.toml 2>/dev/null)
        [[ -z "$TARGET_PORT" ]] && TARGET_PORT=7000
    fi

    echo -e "\n${CYAN}==============================================================${NC}"
    echo -e "${CYAN}      HASHEM TUNNEL CONCURRENCY STRESS TEST${NC}"
    echo -e "${CYAN}==============================================================${NC}"
    echo -e "Target: ${GREEN}${TARGET_HOST}:${TARGET_PORT}${NC}"
    echo -e "Concurrent Connections: ${YELLOW}${CONNS}${NC}\n"

    echo -e "${CYAN}[*] Verifying High-Concurrency System Limits...${NC}"
    local NOFILE_VAL
    NOFILE_VAL=$(ulimit -n 2>/dev/null || echo 1024)
    local SOMAXCONN_VAL
    SOMAXCONN_VAL=$(sysctl -n net.core.somaxconn 2>/dev/null || echo 128)
    local CONNTRACK_VAL
    CONNTRACK_VAL=$(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null || sysctl -n net.nf_conntrack_max 2>/dev/null || echo 65536)

    echo -e "  - ulimit -n: ${GREEN}${NOFILE_VAL}${NC} (target: >=65536)"
    echo -e "  - somaxconn: ${GREEN}${SOMAXCONN_VAL}${NC} (target: >=65535)"
    tune_scale_values "$(tune_mem_mb)"
    local CT_TARGET="$TUNE_CT_MAX"
    echo -e "  - nf_conntrack_max: ${GREEN}${CONNTRACK_VAL}${NC} (target: >=${CT_TARGET} for ${TUNE_MEM_MB}MB RAM)"

    for svc in frps frpc backhaul-server backhaul-client; do
        if systemctl list-unit-files "${svc}.service" >/dev/null 2>&1; then
            local SV_NOFILE
            SV_NOFILE=$(systemctl show -p LimitNOFILE "$svc" 2>/dev/null | cut -d= -f2)
            echo -e "  - ${svc} LimitNOFILE: ${GREEN}${SV_NOFILE:-1048576}${NC}"
        fi
    done

    echo -e "\n${CYAN}[*] Launching ${CONNS} concurrent probe connections...${NC}"
    if ! command -v python3 >/dev/null 2>&1; then
        echo -e "${YELLOW}[!] python3 not found, falling back to sequential netcat probe.${NC}"
        local SUCCESS=0
        for ((i=1; i<=CONNS; i++)); do
            if nc -z -w 2 "$TARGET_HOST" "$TARGET_PORT" >/dev/null 2>&1; then
                ((SUCCESS++))
            fi
        done
        echo -e "Completed: ${SUCCESS}/${CONNS} connections established."
        return 0
    fi

    python3 -c "
import socket, sys, time, concurrent.futures

target_host = sys.argv[1]
target_port = int(sys.argv[2])
conns = int(sys.argv[3])

def probe(cid):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4.0)
        s.connect((target_host, target_port))
        time.sleep(0.05)
        s.close()
        return True, None
    except Exception as e:
        return False, str(e)

success = 0
dropped = 0
with concurrent.futures.ThreadPoolExecutor(max_workers=min(conns, 200)) as executor:
    futures = [executor.submit(probe, i) for i in range(conns)]
    for f in concurrent.futures.as_completed(futures):
        ok, err = f.result()
        if ok:
            success += 1
        else:
            dropped += 1

print(f'RESULT: Total={conns} Success={success} Dropped={dropped}')
if dropped > 0:
    sys.exit(1)
" "$TARGET_HOST" "$TARGET_PORT" "$CONNS"

    local RET=$?
    echo -e "${CYAN}==============================================================${NC}"
    if [[ $RET -eq 0 ]]; then
        echo -e "${GREEN}[✔️] PASS: Zero connection drops detected under high concurrency!${NC}"
        echo -e "${GREEN}High Concurrent Connections -> No Unexpected Drops -> Stable FRP -> Stable Tunnel${NC}"
    else
        echo -e "${RED}[!] FAIL: Some connections dropped under load. Check /var/log/hashem/errors.log${NC}"
    fi
    echo -e "${CYAN}==============================================================${NC}\n"
    return $RET
}

uninstall_all() {
    echo -e "\n${RED}=== Uninstalling EVERYTHING (tunnel + panel + hashem command) ===${NC}"
    read -p "Are you sure? This removes GRE & FRP, the web panel AND the 'hashem' command. (y/N): " CONFIRM
    if [[ "$CONFIRM" =~ ^[Yy]$ ]]; then
        uninstall_all_force
    else
        echo -e "${YELLOW}[*] Aborted.${NC}"
    fi
}

# Non-interactive core: full wipe. Called by uninstall_all() after confirm
# and by `hashem uninstall --force`. Must also delete the menu entrypoints
# (/usr/local/bin/hashem + /usr/local/bin/hashem.sh + legacy gre.sh) so
# `hashem` stops working.
uninstall_all_force() {
        echo -e "${CYAN}[*] Performing complete uninstallation of Hashem...${NC}"
        # 1. Stop & disable all services & timers
        systemctl stop 'frps-wss*' >/dev/null 2>&1 || true
        systemctl stop frps frpc "${TUNNEL_NAME}.service" gre-panel hashem-watchdog.timer hashem-watchdog.service backhaul-server backhaul-client backhaul >/dev/null 2>&1 || true
        systemctl stop 'frps*' 'frpc*' 'backhaul*' 'gre-t*' >/dev/null 2>&1 || true
        systemctl disable frps frpc "${TUNNEL_NAME}.service" gre-panel hashem-watchdog.timer hashem-watchdog.service backhaul-server backhaul-client backhaul >/dev/null 2>&1 || true
        systemctl disable 'frps*' 'frpc*' 'backhaul*' 'gre-t*' >/dev/null 2>&1 || true
        purge_legacy_obfuscation

        # 2. Terminate any leftover processes
        pkill -9 -f "${INSTALL_DIR}/frps" >/dev/null 2>&1 || true
        pkill -9 -f "${INSTALL_DIR}/frpc" >/dev/null 2>&1 || true
        pkill -9 -f "${INSTALL_DIR}/backhaul" >/dev/null 2>&1 || true
        pkill -9 -f "${INSTALL_DIR}/gre-panel" >/dev/null 2>&1 || true

        # 3. Remove all systemd files
        rm -f /etc/systemd/system/frps*.service /etc/systemd/system/frpc*.service \
              /etc/systemd/system/backhaul*.service /etc/systemd/system/${TUNNEL_NAME}.service \
              /etc/systemd/system/gre-t*.service /etc/systemd/system/gre-panel.service \
              /etc/systemd/system/hashem-watchdog.*
        rm -f /var/lock/hashem-watchdog.lock
        remove_legacy_units
        systemctl daemon-reload
        systemctl reset-failed >/dev/null 2>&1 || true

        # 4. Remove all GRE and FOU interfaces
        local gif
        for gif in "$TUNNEL_NAME" $(ip tunnel show 2>/dev/null | awk -F: '{print $1}') $(ip -d link show type gre 2>/dev/null | awk -F: '/^[0-9]+: / {print $2}' | tr -d ' '); do
            [[ -n "$gif" ]] && { ip link del "$gif" >/dev/null 2>&1 || ip tunnel del "$gif" >/dev/null 2>&1 || true; }
        done
        if command -v ip >/dev/null 2>&1; then
            ip fou show 2>/dev/null | awk '{print $3}' | while read -r fp; do
                [[ -n "$fp" ]] && ip fou del port "$fp" 2>/dev/null || true
            done
            ip fou del port 19998 >/dev/null 2>&1 || true
        fi

        # 5. Clean iptables / firewall rules
        if command -v iptables >/dev/null 2>&1; then
            iptables -t mangle -D POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
            iptables -t mangle -D POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1340 2>/dev/null || true
            iptables -t nat -D OUTPUT -p udp --dport 19999 -j DNAT --to-destination 127.0.0.1:19999 2>/dev/null || true
            iptables -D INPUT -p tcp --dport 8443 -j ACCEPT 2>/dev/null || true
        fi

        # 6. Revert network tuning
        tune_restore >/dev/null 2>&1 || true
        rm -f /etc/sysctl.d/99-hashem.conf /etc/sysctl.d/99-gre-panel.conf
        command -v sysctl >/dev/null 2>&1 && sysctl --system >/dev/null 2>&1 || true

        # 7. Remove all binaries
        rm -f "${INSTALL_DIR}/frps" "${INSTALL_DIR}/frpc" "${INSTALL_DIR}/backhaul"
        rm -f /usr/local/bin/gre-panel /usr/local/bin/grepanel

        # 8. Remove configs, data, registries, logs, cron
        rm -rf "$CONFIG_DIR" "$BACKHAUL_CONFIG_DIR"
        rm -rf /etc/gre-panel /usr/local/gre-panel
        rm -rf /var/log/hashem* /var/log/gre-panel* /var/lock/hashem* /tmp/hashem*
        rm -f /etc/cron.d/hashem* /etc/cron.daily/hashem*
        crontab -l 2>/dev/null | grep -v 'hashem' | crontab - 2>/dev/null || true

        # 9. Remove entrypoints last
        rm -f /usr/local/bin/hashem /usr/local/bin/hashem.sh /usr/local/bin/gre.sh

        echo -e "${GREEN}[✔️] Complete uninstallation finished: all tunnels, services, panel, and files removed.${NC}"
}

remove_tunnel() {
    echo -e "\n${RED}=== Removing GRE + FRP Tunnel (panel stays) ===${NC}"
    read -p "Remove the tunnel from THIS server? Panel stays installed. (y/N): " CONFIRM
    if [[ "$CONFIRM" =~ ^[Yy]$ ]]; then
        remove_tunnel_force
    else
        echo -e "${YELLOW}[*] Aborted.${NC}"
    fi
}

# Non-interactive core: stop/disable units, drop interface, remove FRP files.
# Panel files/services are never touched here.
remove_tunnel_force() {
        echo -e "${CYAN}[*] Removing all tunnel components...${NC}"
        # Stop & disable services
        frps_wss_front_remove ""
        systemctl stop frps frpc "${TUNNEL_NAME}.service" backhaul-server backhaul-client backhaul >/dev/null 2>&1 || true
        systemctl stop 'frps*' 'frpc*' 'backhaul*' 'gre-t*' >/dev/null 2>&1 || true
        systemctl disable frps frpc "${TUNNEL_NAME}.service" backhaul-server backhaul-client backhaul >/dev/null 2>&1 || true
        systemctl disable 'frps*' 'frpc*' 'backhaul*' 'gre-t*' >/dev/null 2>&1 || true
        purge_legacy_obfuscation

        # Kill stray tunnel processes
        pkill -9 -f "${INSTALL_DIR}/frps" >/dev/null 2>&1 || true
        pkill -9 -f "${INSTALL_DIR}/frpc" >/dev/null 2>&1 || true
        pkill -9 -f "${INSTALL_DIR}/backhaul" >/dev/null 2>&1 || true

        # Remove systemd files
        rm -f /etc/systemd/system/frps*.service /etc/systemd/system/frpc.service \
              /etc/systemd/system/backhaul*.service /etc/systemd/system/${TUNNEL_NAME}.service \
              /etc/systemd/system/gre-t*.service
        systemctl daemon-reload
        systemctl reset-failed >/dev/null 2>&1 || true

        # Remove GRE interfaces
        local gif
        for gif in "$TUNNEL_NAME" $(ip tunnel show 2>/dev/null | awk -F: '{print $1}') $(ip -d link show type gre 2>/dev/null | awk -F: '/^[0-9]+: / {print $2}' | tr -d ' '); do
            [[ -n "$gif" ]] && { ip link del "$gif" >/dev/null 2>&1 || ip tunnel del "$gif" >/dev/null 2>&1 || true; }
        done
        if command -v ip >/dev/null 2>&1; then
            ip fou show 2>/dev/null | awk '{print $3}' | while read -r fp; do
                [[ -n "$fp" ]] && ip fou del port "$fp" 2>/dev/null || true
            done
            ip fou del port 19998 >/dev/null 2>&1 || true
        fi

        # Clean firewall rules
        if command -v iptables >/dev/null 2>&1; then
            iptables -t mangle -D POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
            iptables -t mangle -D POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1340 2>/dev/null || true
            iptables -t nat -D OUTPUT -p udp --dport 19999 -j DNAT --to-destination 127.0.0.1:19999 2>/dev/null || true
            iptables -D INPUT -p tcp --dport 8443 -j ACCEPT 2>/dev/null || true
        fi

        # Remove configs
        rm -rf "$CONFIG_DIR" "$BACKHAUL_CONFIG_DIR"
        rm -f "$PEERS_FILE"

        echo -e "${GREEN}[✔️] Tunnel removed — GRE interface, FRP/Backhaul services, binaries and configs gone. Panel still running.${NC}"
}

PANEL_DIR="/usr/local/gre-panel"
PANEL_BIN="/usr/local/bin/gre-panel"

# ---- Network optimization for tunnel throughput ----
# Same on both roles (auto-detects nothing: these are role-independent).
# Backup lives in /etc/gre-panel/tune.bak (key=value snapshot), restored by
# tune_restore(). Idempotent — safe to run twice.
TUNE_BACKUP="/etc/gre-panel/tune.bak"

tune_backup_once() {
    if [[ -f "$TUNE_BACKUP" ]]; then return 0; fi
    mkdir -p "$(dirname "$TUNE_BACKUP")"
    : > "$TUNE_BACKUP"
    local k v
    for k in net.ipv4.ip_forward net.core.rmem_max net.core.wmem_max \
             net.core.rmem_default net.core.wmem_default net.ipv4.tcp_rmem net.ipv4.tcp_wmem \
             net.core.netdev_max_backlog net.core.somaxconn net.ipv4.tcp_max_syn_backlog \
             net.ipv4.tcp_slow_start_after_idle net.ipv4.tcp_window_scaling net.ipv4.tcp_mtu_probing \
             net.ipv4.tcp_keepalive_time net.ipv4.tcp_keepalive_intvl net.ipv4.tcp_keepalive_probes \
             net.core.default_qdisc net.ipv4.tcp_congestion_control \
             net.ipv4.tcp_fastopen net.ipv4.ip_local_port_range \
             net.ipv4.tcp_max_tw_buckets net.ipv4.tcp_max_orphans \
             net.netfilter.nf_conntrack_max net.netfilter.nf_conntrack_tcp_timeout_established; do
        v=$(sysctl -n "$k" 2>/dev/null) || v=""
        echo "$k=$v" >> "$TUNE_BACKUP"
    done
    if lsmod 2>/dev/null | grep -q "^tcp_bbr"; then echo "tcp_bbr=loaded" >> "$TUNE_BACKUP";
    else echo "tcp_bbr=absent" >> "$TUNE_BACKUP"; fi
    echo "gre_mtu=$(ip link show "$TUNNEL_NAME" 2>/dev/null | grep -o 'mtu [0-9]*' | awk '{print $2}')" >> "$TUNE_BACKUP"
    if iptables -t mangle -C POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1340 >/dev/null 2>&1 || \
       iptables -t mangle -C POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu >/dev/null 2>&1; then
        echo "mss_clamp=present" >> "$TUNE_BACKUP"
    else
        echo "mss_clamp=absent" >> "$TUNE_BACKUP"
    fi
    echo -e "${CYAN}[*] Current settings backed up to ${TUNE_BACKUP}.${NC}"
}

# tune_scale_values <mem_mb>: RAM-scaled kernel targets (sets TUNE_* globals).
# Fixed 1MB per-socket defaults / 1M conntrack made 30k sockets exhaust a 1-2GB box.
tune_scale_values() {
    local mem_mb="${1:-0}"
    [[ "$mem_mb" =~ ^[0-9]+$ ]] && (( mem_mb > 0 )) || mem_mb=1024
    TUNE_MEM_MB="$mem_mb"
    TUNE_RMEM_DEFAULT=262144
    TUNE_TCP_RMEM="4096 131072 16777216"
    TUNE_TCP_WMEM="4096 131072 16777216"
    TUNE_CT_MAX=$(( mem_mb * 128 ))
    (( TUNE_CT_MAX < 65536 )) && TUNE_CT_MAX=65536
    (( TUNE_CT_MAX > 1048576 )) && TUNE_CT_MAX=1048576
    TUNE_CT_BUCKETS=$(( TUNE_CT_MAX / 4 ))
    TUNE_CT_EST_TIMEOUT=3600
    TUNE_TW_BUCKETS=$(( mem_mb * 256 ))
    (( TUNE_TW_BUCKETS < 65536 )) && TUNE_TW_BUCKETS=65536
    (( TUNE_TW_BUCKETS > 2000000 )) && TUNE_TW_BUCKETS=2000000
    TUNE_MAX_ORPHANS=$(( mem_mb * 32 ))
    (( TUNE_MAX_ORPHANS < 8192 )) && TUNE_MAX_ORPHANS=8192
    (( TUNE_MAX_ORPHANS > 262144 )) && TUNE_MAX_ORPHANS=262144
}

tune_mem_mb() {
    local kb
    kb=$(awk '/^MemTotal:/{print $2; exit}' /proc/meminfo 2>/dev/null)
    [[ "$kb" =~ ^[0-9]+$ ]] && echo $(( kb / 1024 )) || echo 1024
}

tune_apply() {
    tune_scale_values "$(tune_mem_mb)"
    tune_backup_once
    echo -e "${CYAN}[*] Optimizing network stack for tunnel throughput & stability...${NC}"

    # 1. BBR congestion control + fq queuing (best for high-latency / lossy links)
    modprobe tcp_bbr >/dev/null 2>&1 || true
    sysctl -w net.core.default_qdisc=fq >/dev/null 2>&1 || true
    if sysctl -w net.ipv4.tcp_congestion_control=bbr >/dev/null 2>&1; then
        echo -e "${GREEN}[✔️] TCP congestion control → bbr + fq${NC}"
    else
        echo -e "${YELLOW}[!] bbr unavailable — keeping current CC.${NC}"
    fi

    # 2. Bigger socket buffers (16MB) and full TCP window scaling
    sysctl -w net.core.rmem_max=16777216 >/dev/null 2>&1
    sysctl -w net.core.wmem_max=16777216 >/dev/null 2>&1
    sysctl -w net.core.rmem_default="$TUNE_RMEM_DEFAULT" >/dev/null 2>&1
    sysctl -w net.core.wmem_default="$TUNE_RMEM_DEFAULT" >/dev/null 2>&1
    sysctl -w net.ipv4.tcp_rmem="$TUNE_TCP_RMEM" >/dev/null 2>&1
    sysctl -w net.ipv4.tcp_wmem="$TUNE_TCP_WMEM" >/dev/null 2>&1
    sysctl -w net.ipv4.tcp_window_scaling=1 >/dev/null 2>&1
    echo -e "${GREEN}[✔️] Socket buffers → max 16MB, default ${TUNE_RMEM_DEFAULT}/tcp 131072 (RAM ${TUNE_MEM_MB}MB)${NC}"

    # 3. Deeper NIC queue and high connection backlog
    sysctl -w net.core.netdev_max_backlog=65535 >/dev/null 2>&1
    sysctl -w net.core.somaxconn=65535 >/dev/null 2>&1
    sysctl -w net.ipv4.tcp_max_syn_backlog=65535 >/dev/null 2>&1
    echo -e "${GREEN}[✔️] Network backlog → 65535 / 65535${NC}"

    # 4. Anti-stall, keepalive, TIME_WAIT reuse, and fast connection tuning
    sysctl -w net.ipv4.tcp_slow_start_after_idle=0 >/dev/null 2>&1
    sysctl -w net.ipv4.tcp_mtu_probing=1 >/dev/null 2>&1
    sysctl -w net.ipv4.tcp_keepalive_time=30 >/dev/null 2>&1
    sysctl -w net.ipv4.tcp_keepalive_intvl=10 >/dev/null 2>&1
    sysctl -w net.ipv4.tcp_keepalive_probes=5 >/dev/null 2>&1
    sysctl -w net.ipv4.tcp_tw_reuse=1 >/dev/null 2>&1 || true
    sysctl -w net.ipv4.tcp_fin_timeout=15 >/dev/null 2>&1 || true
    sysctl -w net.ipv4.tcp_max_tw_buckets="$TUNE_TW_BUCKETS" >/dev/null 2>&1 || true
    sysctl -w net.ipv4.tcp_max_orphans="$TUNE_MAX_ORPHANS" >/dev/null 2>&1 || true
    sysctl -w fs.file-max=2097152 >/dev/null 2>&1 || true
    sysctl -w fs.nr_open=2097152 >/dev/null 2>&1 || true
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1
    # TCP Fast Open: eliminate 1 RTT on new connections (client+server)
    sysctl -w net.ipv4.tcp_fastopen=3 >/dev/null 2>&1 || true
    # Wider ephemeral port range: default 32768-60999 → 1024-65535
    # Prevents port exhaustion under high connection load
    sysctl -w net.ipv4.ip_local_port_range="1024 65535" >/dev/null 2>&1 || true

    # Conntrack table size & timeout optimization for high concurrent conns
    modprobe nf_conntrack >/dev/null 2>&1 || true
    sysctl -w net.netfilter.nf_conntrack_max="$TUNE_CT_MAX" >/dev/null 2>&1 || sysctl -w net.nf_conntrack_max="$TUNE_CT_MAX" >/dev/null 2>&1 || true
    # buckets: runtime-settable only via module param (ignore failure)
    if [[ -w /sys/module/nf_conntrack/parameters/hashsize ]] && \
       [[ "$(cat /sys/module/nf_conntrack/parameters/hashsize 2>/dev/null || echo 0)" -lt "$TUNE_CT_BUCKETS" ]]; then
        echo "$TUNE_CT_BUCKETS" > /sys/module/nf_conntrack/parameters/hashsize 2>/dev/null || true
    fi
    sysctl -w net.netfilter.nf_conntrack_tcp_timeout_established="$TUNE_CT_EST_TIMEOUT" >/dev/null 2>&1 || true
    sysctl -w net.netfilter.nf_conntrack_tcp_timeout_close_wait=60 >/dev/null 2>&1 || true
    sysctl -w net.netfilter.nf_conntrack_tcp_timeout_fin_wait=60 >/dev/null 2>&1 || true
    sysctl -w net.netfilter.nf_conntrack_tcp_timeout_time_wait=60 >/dev/null 2>&1 || true
    echo -e "${GREEN}[✔️] TCP keepalive (30s) + Fast Open + TW reuse + Conntrack (${TUNE_CT_MAX}) + port range 1024-65535${NC}"

    # OS limits configuration for high concurrency
    mkdir -p /etc/security/limits.d
    cat > /etc/security/limits.d/99-hashem.conf <<'EOF'
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
* soft nproc 512000
* hard nproc 512000
EOF

    # 5. GRE MTU 1380 for tunnel interface and any peer interfaces
    local iface
    for iface in $(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d'@' -f1 | grep -E '^gre-t'); do
        ip link set dev "$iface" mtu 1380 >/dev/null 2>&1 || true
    done
    if ip link show "$TUNNEL_NAME" >/dev/null 2>&1; then
        ip link set dev "$TUNNEL_NAME" mtu 1380 >/dev/null 2>&1 && echo -e "${GREEN}[✔️] ${TUNNEL_NAME} MTU → 1380${NC}" || echo -e "${YELLOW}[!] Could not set GRE MTU.${NC}"
    else
        echo -e "${YELLOW}[*] No ${TUNNEL_NAME} interface yet — MTU will apply on next setup.${NC}"
    fi

    # 6. MSS clamp: POSTROUTING (general) + per GRE interface (precise)
    # --clamp-mss-to-pmtu is less predictable than a fixed value for tunnel links
    iptables -t mangle -D POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu >/dev/null 2>&1 || true
    iptables -t mangle -C POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1340 >/dev/null 2>&1 || \
        iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1340
    # Per-interface MSS clamp on all GRE ifaces (covers FORWARD path too)
    local gre_iface
    for gre_iface in $(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d'@' -f1 | grep -E '^(gre-t|gre-tunnel)'); do
        iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -o "$gre_iface" -j TCPMSS --set-mss 1340 >/dev/null 2>&1 || \
            iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -o "$gre_iface" -j TCPMSS --set-mss 1340 >/dev/null 2>&1 || true
    done
    echo -e "${GREEN}[✔️] TCP MSS clamp → 1340 (POSTROUTING + FORWARD per GRE iface)${NC}"

    # 7. Persist across reboots
    mkdir -p /etc/sysctl.d
    cat > /etc/sysctl.d/99-gre-tune.conf <<EOF
# Hashem tunnel optimization (applied by Optimize button / tune command)
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = ${TUNE_RMEM_DEFAULT}
net.core.wmem_default = ${TUNE_RMEM_DEFAULT}
net.ipv4.tcp_rmem = ${TUNE_TCP_RMEM}
net.ipv4.tcp_wmem = ${TUNE_TCP_WMEM}
net.core.netdev_max_backlog = 65535
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_keepalive_time = 30
net.ipv4.tcp_keepalive_intvl = 10
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_max_tw_buckets = ${TUNE_TW_BUCKETS}
net.ipv4.tcp_max_orphans = ${TUNE_MAX_ORPHANS}
fs.file-max = 2097152
fs.nr_open = 2097152
net.ipv4.ip_forward = 1
net.ipv4.tcp_fastopen = 3
net.ipv4.ip_local_port_range = 1024 65535
net.netfilter.nf_conntrack_max = ${TUNE_CT_MAX}
net.netfilter.nf_conntrack_tcp_timeout_established = ${TUNE_CT_EST_TIMEOUT}
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 60
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 60
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 60
EOF
    echo -e "${GREEN}[✔️] Settings persisted in /etc/sysctl.d/99-gre-tune.conf${NC}"
    echo -e "${GREEN}[✔️] Optimization done — run Restore if anything feels worse.${NC}"
}

tune_restore() {
    if [[ ! -f "$TUNE_BACKUP" ]]; then
        echo -e "${YELLOW}[!] No backup found at ${TUNE_BACKUP} — nothing to restore.${NC}"
        return 1
    fi
    echo -e "${CYAN}[*] Restoring pre-optimization settings...${NC}"
    local k v
    while IFS='=' read -r k v; do
        case "$k" in
            net.*) [[ -n "$v" ]] && sysctl -w "$k=$v" >/dev/null 2>&1 && echo -e "${GREEN}[✔️] $k → $v${NC}" ;;
            gre_mtu)
                if [[ -n "$v" ]] && ip link show "$TUNNEL_NAME" >/dev/null 2>&1; then
                    ip link set dev "$TUNNEL_NAME" mtu "$v" >/dev/null 2>&1 && echo -e "${GREEN}[✔️] ${TUNNEL_NAME} MTU → $v${NC}"
                fi ;;
            mss_clamp)
                if [[ "$v" == "absent" ]]; then
                    iptables -t mangle -D POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1340 >/dev/null 2>&1 || true
                    iptables -t mangle -D POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu >/dev/null 2>&1 || true
                    # Also remove per-GRE-iface FORWARD clamp rules added by tune_apply
                    local gri
                    for gri in $(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d'@' -f1 | grep -E '^(gre-t|gre-tunnel)'); do
                        iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -o "$gri" -j TCPMSS --set-mss 1340 >/dev/null 2>&1 || true
                    done
                    echo -e "${GREEN}[✔️] MSS clamp removed (POSTROUTING + FORWARD)${NC}"
                fi ;;
        esac
    done < "$TUNE_BACKUP"
    rm -f /etc/sysctl.d/99-gre-tune.conf
    echo -e "${GREEN}[✔️] Restored — backup kept at ${TUNE_BACKUP} (deleted on next optimize run).${NC}"
    rm -f "$TUNE_BACKUP"
}

tune_status() {
    echo -e "${CYAN}=== Tunnel Optimization Status ===${NC}"
    echo "CC:        $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo ?) ($(sysctl -n net.core.default_qdisc 2>/dev/null || echo ?))"
    echo "rmem_max:  $(sysctl -n net.core.rmem_max 2>/dev/null || echo ?)"
    echo "wmem_max:  $(sysctl -n net.core.wmem_max 2>/dev/null || echo ?)"
    tune_scale_values "$(tune_mem_mb)"
    echo "RAM:       ${TUNE_MEM_MB}MB -> targets: tcp_rmem/wmem=[${TUNE_TCP_RMEM}] conntrack_max=${TUNE_CT_MAX} tw_buckets=${TUNE_TW_BUCKETS} orphans=${TUNE_MAX_ORPHANS}"
    echo "tcp_rmem:  $(sysctl -n net.ipv4.tcp_rmem 2>/dev/null || echo ?)"
    echo "conntrack: $(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null || echo ?)"
    echo "backlog:   $(sysctl -n net.core.netdev_max_backlog 2>/dev/null || echo ?)"
    echo "forward:   $(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo ?)"
    echo "GRE MTU:   $(ip link show "$TUNNEL_NAME" 2>/dev/null | grep -o 'mtu [0-9]*' | awk '{print $2}' || echo 'no interface')"
    if iptables -t mangle -C POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1340 >/dev/null 2>&1 || \
       iptables -t mangle -C POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu >/dev/null 2>&1; then
        echo "MSS clamp: on (1340)"
    else
        echo "MSS clamp: off"
    fi
    if [[ -f "$TUNE_BACKUP" ]]; then echo "Backup:    $TUNE_BACKUP (restore available)"; else echo "Backup:    none"; fi
    [[ -f /etc/sysctl.d/99-gre-tune.conf ]] && echo "Persisted: yes (/etc/sysctl.d/99-gre-tune.conf)" || echo "Persisted: no"
}

# free_ram: drop page caches + compact memory + journald cap + ensure 1G swap.
# Safe on any Ubuntu host: no service is touched, kernel reclaims only
# discardable cache; swap is created once and reused afterwards.
free_ram() {
    echo -e "${CYAN}[*] Freeing RAM (safe: caches only, no service touched)...${NC}"
    local before
    before=$(free -m | awk '/^Mem:/{print $7}')
    # 1. journald cap (the #1 silent RAM eater on Ubuntu: 100M+ in RAM)
    if [[ -f /etc/systemd/journald.conf ]]; then
        sed -i 's/^#*SystemMaxUse=.*/SystemMaxUse=32M/' /etc/systemd/journald.conf
        sed -i 's/^#*RuntimeMaxUse=.*/RuntimeMaxUse=16M/' /etc/systemd/journald.conf
        grep -q '^SystemMaxUse=32M' /etc/systemd/journald.conf || echo 'SystemMaxUse=32M' >> /etc/systemd/journald.conf
        grep -q '^RuntimeMaxUse=16M' /etc/systemd/journald.conf || echo 'RuntimeMaxUse=16M' >> /etc/systemd/journald.conf
        journalctl --vacuum-size=16M >/dev/null 2>&1
        systemctl restart systemd-journald >/dev/null 2>&1
        echo -e "${GREEN}[✔️] journald capped at 16M (was the main RAM eater)${NC}"
    fi
    # 2. drop page caches + compact
    sync
    echo 3 > /proc/sys/vm/drop_caches 2>/dev/null
    echo 1 > /proc/sys/vm/compact_memory 2>/dev/null
    echo -e "${GREEN}[✔️] page cache dropped + memory compacted${NC}"
    # 3. ensure 1G swap (safety net for 1GB VPS)
    if ! swapon --show 2>/dev/null | grep -q '/swapfile'; then
        echo -e "${CYAN}[*] Creating 1G swapfile...${NC}"
        if fallocate -l 1G /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count=1024 2>/dev/null; then
            chmod 600 /swapfile
            mkswap /swapfile >/dev/null 2>&1
            swapon /swapfile >/dev/null 2>&1
            grep -q '/swapfile' /etc/fstab 2>/dev/null || echo '/swapfile none swap sw 0 0' >> /etc/fstab
            echo -e "${GREEN}[✔️] 1G swap created${NC}"
        else
            echo -e "${YELLOW}[!] Could not create swapfile (disk full?)${NC}"
        fi
    else
        echo -e "${GREEN}[✔️] swap already active${NC}"
    fi
    sysctl -w vm.swappiness=15 >/dev/null 2>&1
    echo 'vm.swappiness=15' > /etc/sysctl.d/99-swappiness.conf 2>/dev/null
    local after
    after=$(free -m | awk '/^Mem:/{print $7}')
    echo -e "${GREEN}[✔️] Available RAM: ${before}M → ${after}M${NC}"
    free -m | head -2
}

install_panel_smart() {
    local status
    status=$(get_component_status panel)
    case "$status" in
        RUNNING)
            echo -e "${GREEN}[✔️] Web Panel is already installed and running.${NC}"
            echo -e "${CYAN}[*] Skipping redundant reinstallation to preserve system state.${NC}"
            show_panel_url
            return 0
            ;;
        STOPPED)
            echo -e "${YELLOW}[!] Web Panel is installed but currently STOPPED.${NC}"
            if [[ -t 0 ]]; then
                read -p "Start Web Panel service now? [Y/n]: " START_OPT
                if [[ ! "$START_OPT" =~ ^[Nn]$ ]]; then
                    if [[ ! -f /etc/systemd/system/gre-panel.service ]]; then
                        backup_configs "panel_unit_repair"
                        install_panel
                        return $?
                    fi
                    systemctl start gre-panel
                    sleep 2
                    if systemctl is-active --quiet gre-panel; then
                        echo -e "${GREEN}[✔️] Web Panel started successfully.${NC}"
                        show_panel_url
                        return 0
                    else
                        echo -e "${RED}[!] Failed to start Web Panel.${NC}"
                    fi
                fi
            else
                # B-02: binary present but unit missing (e.g. copied in by an
                # updater, or unit removed) => `systemctl start` can never work.
                if [[ ! -f /etc/systemd/system/gre-panel.service ]]; then
                    backup_configs "panel_unit_repair"
                    install_panel
                    return $?
                fi
                systemctl start gre-panel
                sleep 2
                systemctl is-active --quiet gre-panel && return 0
            fi
            ;;
        BROKEN)
            echo -e "${RED}[!] Web Panel is installed but UNHEALTHY / BROKEN.${NC}"
            if [[ -t 0 ]]; then
                echo "Options:"
                echo "  1) Repair (reset-failed & restart service)"
                echo "  2) Reinstall (clean download & install)"
                echo "  3) Skip"
                echo "  4) Back"
                read -p "Select option [1-4]: " BROKEN_OPT
                case "$BROKEN_OPT" in
                    1)
                        echo -e "${CYAN}[*] Attempting repair...${NC}"
                        systemctl reset-failed gre-panel >/dev/null 2>&1 || true
                        systemctl restart gre-panel >/dev/null 2>&1 || true
                        sleep 2
                        if systemctl is-active --quiet gre-panel; then
                            echo -e "${GREEN}[✔️] Web Panel repaired and running!${NC}"
                            show_panel_url
                            return 0
                        else
                            echo -e "${RED}[!] Repair failed. Falling back to clean install...${NC}"
                            backup_configs "panel_broken"
                            install_panel
                            return $?
                        fi
                        ;;
                    2)
                        backup_configs "panel_reinstall"
                        install_panel
                        return $?
                        ;;
                    3|4)
                        return 0
                        ;;
                    *)
                        echo -e "${YELLOW}[*] Action skipped.${NC}"
                        return 0
                        ;;
                esac
            else
                backup_configs "panel_reinstall"
                install_panel
                return $?
            fi
            ;;
        NOT_INSTALLED|*)
            ensure_dependencies_smart
            backup_configs "panel_install"
            install_panel
            return $?
            ;;
    esac
}

UPDATE_FILE="${PANEL_CONFIG_DIR}/update.json"
UPDATE_API="https://api.github.com/repos/pdnczone/hashem-panel"

# Update channel: stable (default) or dev. Same file the web panel reads.
update_get_channel() {
    local C
    C=$(python3 -c "import json; c=json.load(open('$UPDATE_FILE')).get('channel'); print(c if c in ('stable','dev') else 'stable')" 2>/dev/null) || C=""
    [[ "$C" == "dev" ]] && echo dev || echo stable
}

update_set_channel() {
    [[ "$1" == "stable" || "$1" == "dev" ]] || return 1
    mkdir -p "$PANEL_CONFIG_DIR" 2>/dev/null || true
    ( umask 077; printf '{"channel": "%s"}\n' "$1" > "${UPDATE_FILE}.tmp" ) && mv -f "${UPDATE_FILE}.tmp" "$UPDATE_FILE"
}

# Prints the release tag to install for the active channel (empty = unknown).
# stable: newest vX.Y.Z that is not a prerelease/draft, else GitHub's "Latest".
# dev:    newest dev-rN prerelease. Never falls back across channels.
# A release tag may only look like vX.Y.Z, dev-rN or panel-rN before it is used in a URL.
update_tag_ok() { [[ "${1:-}" =~ ^(v[0-9]+\.[0-9]+\.[0-9]+|dev-r[0-9]+|panel-r[0-9]+)$ ]]; }

# update_verify_asset <file> <tag> <asset>: sha256 against that release's checksums.txt.
# 0 = verified, 1 = MISMATCH (never fall back after this), 2 = no manifest/entry (legacy release).
update_verify_asset() {
    local F="$1" TAG="$2" ASSET="$3" SUMS WANT GOT
    SUMS=$(curl -fsSL --connect-timeout 5 --max-time 15 "https://github.com/pdnczone/hashem-panel/releases/download/${TAG}/checksums.txt" 2>/dev/null) || return 2
    WANT=$(printf '%s\n' "$SUMS" | awk -v a="$ASSET" '$2==a {print $1; exit}')
    [[ -n "$WANT" ]] || return 2
    GOT=$(sha256sum "$F" 2>/dev/null | awk '{print $1}')
    [[ -n "$GOT" && "$GOT" == "$WANT" ]] && return 0
    return 1
}

update_pick_tag() {
    local CH JSON="" U ROWS TAG=""
    CH=$(update_get_channel)
    for U in "${UPDATE_API}/releases?per_page=30" "https://mirror.ghproxy.com/${UPDATE_API}/releases?per_page=30"; do
        JSON=$(curl -fsSL --connect-timeout 4 --max-time 10 "$U" 2>/dev/null) || JSON=""
        [[ -n "$JSON" ]] && break
    done
    # one "tag draft prerelease" row per release
    ROWS=$(printf '%s' "$JSON" | tr -d ' \n\r\t' | tr ',{}' '\n\n\n' \
        | awk -F'"' '/^"tag_name":/{t=$4} /^"draft":/{d=$3} /^"prerelease":/{if (t != "") print t, d, $3; t=""}')
    if [[ "$CH" == "dev" ]]; then
        TAG=$(printf '%s\n' "$ROWS" | awk '$2==":false" && $3==":true" && $1 ~ /^dev-r[0-9]+$/ {sub(/^dev-r/,"",$1); print $1}' | sort -n | tail -1)
        [[ -n "$TAG" ]] && TAG="dev-r${TAG}"
    else
        TAG=$(printf '%s\n' "$ROWS" | awk '$2==":false" && $3==":false" && $1 ~ /^v[0-9]+\.[0-9]+\.[0-9]+$/ {print $1}' | sort -V | tail -1)
        if [[ -z "$TAG" ]]; then
            TAG=$(curl -fsSL --connect-timeout 4 --max-time 10 "${UPDATE_API}/releases/latest" 2>/dev/null | grep -m1 '"tag_name":' | cut -d'"' -f4)
        fi
    fi
    update_tag_ok "$TAG" || TAG=""
    echo "$TAG"
}

cli_update_channel() {
    local CH="${1:-}"
    if [[ -z "$CH" ]]; then
        update_get_channel
        return 0
    fi
    if ! update_set_channel "$CH"; then
        echo -e "${RED}[!] Channel must be 'stable' or 'dev'.${NC}"
        return 1
    fi
    echo -e "${GREEN}[✔️] Update channel set to ${CH}.${NC}"
    [[ "$CH" == "dev" ]] && echo -e "${YELLOW}[!] Dev builds are test builds and may break.${NC}"
    return 0
}

# RAM-scaled limits for the gre-panel unit (C2.6). Pure: MEM_MB in, directives out.
# The panel serves the UI, not traffic: it must stay responsive but never eat
# a small hub. Thresholds from the load lab (panel RSS well under 150MB at
# N=20; caps leave headroom for spikes + Go runtime + page cache pressure).
panel_limits_for_ram() { # $1 = total RAM in MB (defaults: autodetect, floor 512)
    local mem="${1:-}"
    [[ "$mem" =~ ^[0-9]+$ && "$mem" -gt 0 ]] || mem=$(awk '/^MemTotal:/ {printf "%d", $2 / 1024}' /proc/meminfo 2>/dev/null)
    [[ "$mem" =~ ^[0-9]+$ && "$mem" -gt 0 ]] || mem=1024
    if (( mem <= 1250 )); then
        echo "280M 350M"
    elif (( mem <= 2560 )); then
        echo "450M 550M"
    elif (( mem <= 4200 )); then
        echo "700M 850M"
    else
        echo "1G 1.2G"
    fi
}

# Idempotent: ensure one "Key=Value" directive under [Service] in a unit file
# (replace if a different value exists, add if missing, keep user extras).
unit_set_directive() { # $1=file $2=key $3=value
    local f="$1" k="$2" v="$3"
    [[ -f "$f" ]] || return 1
    if grep -qE "^${k}=" "$f"; then
        sed -i -E "s|^${k}=.*|${k}=${v}|" "$f"
    else
        sed -i "0,/^\\[Service\\]/s//[Service]\n${k}=${v}/" "$f"
    fi
}

# Apply panel isolation limits to a unit file (no daemon-reload, no restart:
# callers do that once). $2 = "HIGH MAX" from panel_limits_for_ram.
apply_panel_unit_limits() { # $1=unit file [$2="HIGH MAX"]
    local f="$1" lim="${2:-$(panel_limits_for_ram)}" high max
    high="${lim%% *}"; max="${lim##* }"
    [[ -f "$f" ]] || return 1
    for kv in "OOMScoreAdjust=-900" "Nice=-5" "CPUWeight=200" "Restart=always" \
              "RestartSec=3" "LimitNOFILE=1048576" "LimitNPROC=512000" \
              "TasksMax=4096" "MemoryHigh=${high}" "MemoryMax=${max}" \
              "WatchdogSec=30" "NotifyAccess=main" "StartLimitIntervalSec=0"; do
        unit_set_directive "$f" "${kv%%=*}" "${kv#*=}"
    done
}

# FRP units get a LOWER CPUWeight than the panel (C2.6): tunnels keep full
# throughput but the UI stays responsive when the box is saturated.
apply_frp_unit_weight() { # $1=unit file
    unit_set_directive "$1" "CPUWeight" "100"
}

cli_panel_limits() { # [--apply] [--mem MB]: print (default) or apply panel limits
    local apply=0 mem=""
    while [[ $# -gt 0 ]]; do case "$1" in
        --apply) apply=1; shift ;;
        --mem) mem="$2"; shift 2 ;;
        *) shift ;;
    esac; done
    if (( apply == 1 )); then
        # --apply always uses the live host value: a synthetic --mem must never
        # be written to a real unit file.
        mem=$(awk '/^MemTotal:/ {printf "%d", $2 / 1024}' /proc/meminfo 2>/dev/null)
    fi
    [[ -n "$mem" ]] || mem=$(awk '/^MemTotal:/ {printf "%d", $2 / 1024}' /proc/meminfo 2>/dev/null)
    local lim high max
    lim=$(panel_limits_for_ram "$mem"); high="${lim%% *}"; max="${lim##* }"
    local unit=/etc/systemd/system/gre-panel.service
    if (( apply == 0 )); then
        echo "Host RAM: ${mem:-unknown} MB -> MemoryHigh=${high} MemoryMax=${max}"
        echo "Unit: ${unit}"
        if [[ -f "$unit" ]]; then
            for k in OOMScoreAdjust Nice CPUWeight MemoryHigh MemoryMax WatchdogSec LimitNOFILE; do
                v=$(grep -E "^${k}=" "$unit" 2>/dev/null | cut -d= -f2-)
                echo "  ${k}=${v:-(missing)}"
            done
        else
            echo "  (unit file not present)"
        fi
        return 0
    fi
    [[ -f "$unit" ]] || { echo -e "${RED}[!] ${unit} not found — install the panel first.${NC}"; return 1; }
    apply_panel_unit_limits "$unit" "$lim"
    systemctl daemon-reload 2>/dev/null || true
    systemctl restart gre-panel 2>/dev/null || true
    echo -e "${GREEN}[✔️] Panel limits applied (RAM ${mem}MB -> ${high}/${max}).${NC}"
}

install_panel() {
    echo -e "${CYAN}[*] Installing Hashem web panel...${NC}"
    ensure_doctor_tools

    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)  PANEL_ASSET="gre-panel-linux-amd64" ;;
        aarch64|arm64) PANEL_ASSET="gre-panel-linux-arm64" ;;
        *) echo -e "${RED}[!] Unsupported arch for panel: $ARCH${NC}"; return 1 ;;
    esac

    TMP_PANEL="$(mktemp -d)"
    DL_OK=0
    # pick the release of the active update channel (prebuilt, no Go needed)
    UPD_TAG="${UPD_TAG:-$(update_pick_tag)}"
    if [[ -z "$UPD_TAG" && "$(update_get_channel)" == "dev" ]]; then
        echo -e "${RED}[!] No dev build found on the dev channel — nothing changed.${NC}"
        rm -rf "$TMP_PANEL"
        return 1
    fi
    LATEST_JSON=""
    if [[ -z "$UPD_TAG" ]]; then
        LATEST_JSON=$(curl -fsSL --connect-timeout 4 --max-time 10 "https://api.github.com/repos/pdnczone/hashem-panel/releases/latest" 2>/dev/null) || true
        if [[ -z "$LATEST_JSON" ]]; then
            LATEST_JSON=$(curl -fsSL --connect-timeout 4 --max-time 10 "https://mirror.ghproxy.com/https://api.github.com/repos/pdnczone/hashem-panel/releases/latest" 2>/dev/null) || true
        fi
    fi
    DL_URL=""
    GREPANEL_URL=""
    HASHEMSH_URL=""
    HASHEM_URL=""
    if [[ -n "$UPD_TAG" ]]; then
        local REL_BASE="https://github.com/pdnczone/hashem-panel/releases/download/${UPD_TAG}"
        DL_URL="${REL_BASE}/${PANEL_ASSET}"
        GREPANEL_URL="${REL_BASE}/grepanel"
        HASHEMSH_URL="${REL_BASE}/hashem.sh"
        HASHEM_URL="${REL_BASE}/hashem"
    elif [[ -n "$LATEST_JSON" ]]; then
        DL_URL=$(echo "$LATEST_JSON" | grep -o "\"browser_download_url\": *\"[^\"]*${PANEL_ASSET}\"" | head -1 | cut -d'"' -f4)
        GREPANEL_URL=$(echo "$LATEST_JSON" | grep -o "\"browser_download_url\": *\"[^\"]*grepanel\"" | head -1 | cut -d'"' -f4)
        HASHEMSH_URL=$(echo "$LATEST_JSON" | grep -o "\"browser_download_url\": *\"[^\"]*hashem\\.sh\"" | head -1 | cut -d'"' -f4)
        HASHEM_URL=$(echo "$LATEST_JSON" | grep -o "\"browser_download_url\": *\"[^\"]*/hashem\"" | head -1 | cut -d'"' -f4)
    fi
    # Fallback to direct release asset URLs if API was blocked/empty
    [[ -z "$DL_URL" ]] && DL_URL="https://github.com/pdnczone/hashem-panel/releases/latest/download/${PANEL_ASSET}"
    [[ -z "$GREPANEL_URL" ]] && GREPANEL_URL="https://github.com/pdnczone/hashem-panel/releases/latest/download/grepanel"
    [[ -z "$HASHEMSH_URL" ]] && HASHEMSH_URL="https://github.com/pdnczone/hashem-panel/releases/latest/download/hashem.sh"
    [[ -z "$HASHEM_URL" ]] && HASHEM_URL="https://github.com/pdnczone/hashem-panel/releases/latest/download/hashem"

    if download_with_fallback "$TMP_PANEL/gre-panel" "$DL_URL" 60 && [[ -s "$TMP_PANEL/gre-panel" ]]; then
        if head -c 4 "$TMP_PANEL/gre-panel" 2>/dev/null | grep -q "ELF"; then
            DL_OK=1
            echo -e "${GREEN}[✔️] Downloaded prebuilt panel ($(du -h "$TMP_PANEL/gre-panel" | cut -f1)).${NC}"
        else
            echo -e "${YELLOW}[!] Downloaded file is not a binary — falling back to source build.${NC}"
        fi
    fi

    if download_with_fallback "/usr/local/bin/grepanel" "$GREPANEL_URL" 30; then
        chmod +x /usr/local/bin/grepanel 2>/dev/null || true
    fi

    if download_with_fallback "$HASHEM_SCRIPT" "$HASHEMSH_URL" 30; then
        chmod +x "$HASHEM_SCRIPT" 2>/dev/null || true
        cp "$HASHEM_SCRIPT" "$HASHEM_BIN" 2>/dev/null && chmod +x "$HASHEM_BIN" || true
        ln -sf "$HASHEM_SCRIPT" /usr/local/bin/gre.sh 2>/dev/null || true
    fi

    if download_with_fallback "/usr/local/bin/hashem" "$HASHEM_URL" 30; then
        chmod +x /usr/local/bin/hashem 2>/dev/null || true
    fi

    if [[ "$DL_OK" -ne 1 ]]; then
        # fallback: build from source (needs Go)
        echo -e "${YELLOW}[*] No prebuilt panel found — building from source...${NC}"
        local FREE_RAM
        FREE_RAM=$(free -m 2>/dev/null | awk '/Mem:/ {print $7}')
        local TMP_SWAP=""
        if [[ -n "$FREE_RAM" && "$FREE_RAM" -lt 800 ]]; then
            echo -e "${YELLOW}[*] Low RAM (${FREE_RAM}MB) detected — enabling temporary build swapfile...${NC}"
            TMP_SWAP="/tmp/.hashem_build_swap"
            fallocate -l 1G "$TMP_SWAP" 2>/dev/null || dd if=/dev/zero of="$TMP_SWAP" bs=1M count=1024 2>/dev/null || true
            chmod 600 "$TMP_SWAP" 2>/dev/null || true
            mkswap "$TMP_SWAP" 2>/dev/null && swapon "$TMP_SWAP" 2>/dev/null || true
        fi

        if ! command -v go >/dev/null 2>&1; then
            echo -e "${CYAN}[*] Installing Go to build the panel...${NC}"
            apt-get update -qq || true
            apt-get install -y -qq golang-go || true
        fi
        if ! download_with_fallback "$TMP_PANEL/panel.tgz" "https://github.com/pdnczone/hashem-panel/archive/refs/heads/main.tar.gz" 60; then
            echo -e "${RED}[!] Failed to download panel sources.${NC}"
            [[ -n "$TMP_SWAP" && -f "$TMP_SWAP" ]] && { swapoff "$TMP_SWAP" 2>/dev/null || true; rm -f "$TMP_SWAP" 2>/dev/null || true; }
            rm -rf "$TMP_PANEL"
            return 1
        fi
        tar -xzf "$TMP_PANEL/panel.tgz" -C "$TMP_PANEL"
        SRC="$(dirname "$(find "$TMP_PANEL" -name main.go -path '*panel*' | head -1)")"
        if [[ -z "$SRC" || ! -f "$SRC/main.go" ]]; then
            echo -e "${RED}[!] Panel sources not found in archive.${NC}"
            [[ -n "$TMP_SWAP" && -f "$TMP_SWAP" ]] && { swapoff "$TMP_SWAP" 2>/dev/null || true; rm -f "$TMP_SWAP" 2>/dev/null || true; }
            rm -rf "$TMP_PANEL"
            return 1
        fi
        (cd "$SRC" && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o "$TMP_PANEL/gre-panel" .)
        if [[ -f "$SRC/grepanel" ]]; then
            cp "$SRC/grepanel" /usr/local/bin/grepanel
            chmod +x /usr/local/bin/grepanel
        fi
        [[ -n "$TMP_SWAP" && -f "$TMP_SWAP" ]] && { swapoff "$TMP_SWAP" 2>/dev/null || true; rm -f "$TMP_SWAP" 2>/dev/null || true; }
    fi

    # stop the running panel BEFORE overwriting its binary: cp over a live
    # executable fails with ETXTBSY ("Text file busy") and leaves the old
    # version in place. The restart at the end of this function brings it back.
    if systemctl is-active --quiet gre-panel 2>/dev/null; then
        systemctl stop gre-panel 2>/dev/null || true
    fi
    if ! cp "$TMP_PANEL/gre-panel" "$PANEL_BIN"; then
        echo -e "${RED}[!] Failed to install panel binary — keeping the running version.${NC}"
        rm -rf "$TMP_PANEL"
        return 1
    fi
    chmod +x "$PANEL_BIN"
    rm -rf "$TMP_PANEL"
    # /usr/local/bin/hashem IS this script now (no shortcut file anymore):
    # install a copy plus a legacy gre.sh symlink so old muscle memory works.
    cp "$0" "$HASHEM_BIN" 2>/dev/null || cp ./hashem.sh "$HASHEM_BIN" 2>/dev/null || cp "$SRC/hashem.sh" "$HASHEM_BIN" 2>/dev/null || true
    chmod +x "$HASHEM_BIN" 2>/dev/null || true
    ln -sf "$HASHEM_SCRIPT" /usr/local/bin/gre.sh 2>/dev/null || true

    cat > /etc/systemd/system/gre-panel.service <<EOF
[Unit]
Description=Hashem Web Panel
After=network.target

[Service]
Type=simple
User=root
Restart=always
RestartSec=5s
ExecStart=${PANEL_BIN}

[Install]
WantedBy=multi-user.target
EOF
    apply_panel_unit_limits /etc/systemd/system/gre-panel.service

    ensure_panel_pass
    systemctl daemon-reload
    systemctl enable gre-panel >/dev/null 2>&1
    systemctl restart gre-panel
    sleep 2

    if systemctl is-active --quiet gre-panel; then
        if [[ -z "$PANEL_PASS" ]]; then
            NEWPASS=$(journalctl -u gre-panel -n 30 --no-pager 2>/dev/null | grep -o 'INITIAL PANEL PASSWORD: [^ ]*' | tail -1 | awk '{print $4}')
            [[ -n "$NEWPASS" ]] && PANEL_PASS="$NEWPASS"
        fi
        echo -e "${GREEN}[✔️] Panel installed and running.${NC}"
        # full credentials right here — no need to open another menu
        echo ""
        echo -e "${CYAN}=== Panel credentials ===${NC}"
        show_panel_url
        # auto port: if 7777 was busy the binary picked the next free one
        _APORT=$(grep -o '"port": *[0-9]*' /etc/gre-panel/panel.json 2>/dev/null | grep -o '[0-9]*')
        if [[ -n "$_APORT" && "$_APORT" != "7777" ]]; then
            echo -e "${YELLOW}[!] Port 7777 was busy — panel auto-switched to ${_APORT} (saved, survives restarts).${NC}"
        fi
    else
        echo -e "${RED}[!] Panel failed to start — see: journalctl -u gre-panel${NC}"
        return 1
    fi
}

show_panel_url() {
    if [[ ! -f /etc/gre-panel/panel.json ]]; then
        echo -e "${YELLOW}Panel is not installed on this server (no /etc/gre-panel/panel.json). Run Setup first.${NC}"
        return 1
    fi
    local port base user
    port=$(grep -o '"port": *[0-9]*' /etc/gre-panel/panel.json 2>/dev/null | grep -o '[0-9]*')
    base=$(grep -o '"base_path": *"[^"]*"' /etc/gre-panel/panel.json 2>/dev/null | cut -d'"' -f4)
    user=$(grep -o '"username": *"[^"]*"' /etc/gre-panel/panel.json 2>/dev/null | cut -d'"' -f4)
    port=${port:-7777}
    user=${user:-admin}
    ensure_panel_pass
    MYIP=$(ip route get 1.1.1.1 2>/dev/null | awk '/src/ {for (i=1; i<=NF; i++) if ($i=="src") {print $(i+1); exit}}')
    echo -e "${GREEN}Panel URL:  ${CYAN}http://${MYIP:-<this-server-ip>}:${port}/${base}${NC}"
    echo -e "${GREEN}Username:   ${CYAN}${user}${NC}"
    if [[ -n "$PANEL_PASS" ]]; then
        echo -e "${GREEN}Password:   ${CYAN}${PANEL_PASS}${NC} ${YELLOW}(Please record this password now!)${NC}"
    else
        echo -e "${GREEN}Password:   ${YELLOW}(hashed in panel.json — reset anytime via: ${CYAN}hashem reset-password${YELLOW})${NC}"
    fi
}

# reset_panel_password: change web panel password interactively or with auto-generation
reset_panel_password() {
    check_root
    echo -e "\n${CYAN}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}             RESET HASHEM WEB PANEL PASSWORD                  ${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${YELLOW}Enter new password for user 'admin' (minimum 12 chars).${NC}"
    echo -e "${YELLOW}Or press Enter to auto-generate a secure random password.${NC}"
    echo ""
    read -p "New Password: " USER_NEW_PASS
    if [[ -z "$USER_NEW_PASS" ]]; then
        USER_NEW_PASS=$(tr -dc 'A-Za-z0-9!@#$%' </dev/urandom | head -c 16)
    else
        if [[ ${#USER_NEW_PASS} -lt 12 ]]; then
            echo -e "${RED}[!] Password must be at least 12 characters long (NIST 800-63B).${NC}"
            return 1
        fi
    fi

    cli_set_panel_password "$USER_NEW_PASS"
}

cli_set_panel_password() {
    local PASS="$1"
    if [[ ${#PASS} -lt 12 ]]; then
        echo -e "${RED}[!] Password must be at least 12 characters long (NIST 800-63B).${NC}"
        return 1
    fi

    local HASH
    HASH=$(echo -n "$PASS" | sha256sum | awk '{print $1}')
    if [[ -z "$HASH" ]] || ! command -v python3 >/dev/null 2>&1; then
        echo -e "${RED}[!] Cannot hash password (requires python3 + sha256sum).${NC}"
        return 1
    fi

    mkdir -p /etc/gre-panel
    python3 - "$HASH" <<'PYEOF'
import json, sys
p = '/etc/gre-panel/panel.json'
try:
    with open(p) as f:
        d = json.load(f)
except Exception:
    d = {"username": "admin", "port": 7777, "base_path": "panel"}
d['pass_hash'] = sys.argv[1]
with open(p + ".tmp", "w") as f:
    json.dump(d, f, indent=2)
import os
os.replace(p + ".tmp", p)
os.chmod(p, 0o600)
PYEOF

    chmod 600 /etc/gre-panel/panel.json 2>/dev/null || true
    systemctl restart gre-panel 2>/dev/null || true
    PANEL_PASS="$PASS"
    echo ""
    echo -e "${GREEN}[✔️] Web panel password successfully updated!${NC}"
    echo -e "${GREEN}Username:     ${CYAN}admin${NC}"
    echo -e "${GREEN}New Password: ${CYAN}${PASS}${NC}"
    echo -e "${YELLOW}Please save this password securely.${NC}"
    echo ""
}

# Dedicated backup key for encrypted backups (CWE-256: decouples backup key from login password)
ensure_backup_key() {
    mkdir -p /etc/gre-panel
    if [[ ! -f /etc/gre-panel/backup.key ]]; then
        if [[ -f /etc/gre-panel/panel.pass ]]; then
            mv /etc/gre-panel/panel.pass /etc/gre-panel/backup.key
            chmod 600 /etc/gre-panel/backup.key
        else
            tr -dc 'a-zA-Z0-9' </dev/urandom | head -c 32 > /etc/gre-panel/backup.key
            chmod 600 /etc/gre-panel/backup.key
        fi
    fi
    # Security Migration (CWE-256): Delete legacy plaintext panel.pass
    rm -f /etc/gre-panel/panel.pass
}

# make sure panel config exists. Passwords are never stored as plaintext on disk (CWE-256).
ensure_panel_pass() {
    ensure_backup_key
    if [[ -f /etc/gre-panel/panel.json ]]; then
        return 0
    fi
    echo -e "${YELLOW}[*] No panel config found — generating initial credentials...${NC}"
    local NEWPASS HASH
    NEWPASS=$(tr -dc 'A-Za-z0-9!@#$%' </dev/urandom | head -c 16)
    HASH=$(echo -n "$NEWPASS" | sha256sum | awk '{print $1}')
    if [[ -z "$HASH" ]] || ! command -v python3 >/dev/null 2>&1; then
        echo -e "${RED}[!] Cannot initialize panel config (need sha256sum + python3).${NC}"
        return 1
    fi
    python3 - "$HASH" <<'PYEOF'
import json, sys
p = '/etc/gre-panel/panel.json'
try:
    d = json.load(open(p))
except Exception:
    d = {"username": "admin", "port": 7777, "base_path": "panel"}
d['pass_hash'] = sys.argv[1]
json.dump(d, open(p, 'w'), indent=2)
PYEOF
    chmod 600 /etc/gre-panel/panel.json
    systemctl restart gre-panel 2>/dev/null || true
    PANEL_PASS="$NEWPASS"
    echo -e "${GREEN}[✔️] Initial password generated: ${CYAN}${NEWPASS}${NC}"
    echo -e "${YELLOW}[!] NOTE: Passwords are not saved in plaintext on disk (CWE-256). Record it now!${NC}"
    return 0
}

# save_panel_pass: deprecated for CWE-256 compliance
save_panel_pass() {
    ensure_backup_key
}

# ---- Watchdog & Scheduled Encrypted Backup ----
init_watchdog_json() {
    mkdir -p "$PANEL_CONFIG_DIR"
    if [[ ! -f "$WATCHDOG_FILE" ]]; then
        cat << 'EOF' > "$WATCHDOG_FILE"
{
  "enabled": false,
  "interval_sec": 60,
  "fail_threshold": 2,
  "auto_restart": false,
  "restart_every_hours": 0,
  "last_restart": 0,
  "last_restart_date": "",
  "tg_bot_token": "",
  "tg_chat_id": "",
  "tg_route": "direct",
  "tg_tunnel_port": 0,
  "backup_every_hours": 0,
  "backup_daily_at": "",
  "last_check": "",
  "consec_fails": 0,
  "last_alert": ""
}
EOF
        chmod 600 "$WATCHDOG_FILE" 2>/dev/null || true
    fi
}

watchdog_get_peer_gre() {
    local PEER=""
    if ip link show "$TUNNEL_NAME" >/dev/null 2>&1; then
        local INNER
        INNER=$(ip -4 addr show dev "$TUNNEL_NAME" 2>/dev/null | awk '/inet / {print $2}' | cut -d/ -f1 | head -n1)
        if [[ -n "$INNER" ]]; then
            if [[ "$INNER" == "$IRAN_GRE_IP" ]]; then
                PEER="$FOREIGN_GRE_IP"
            elif [[ "$INNER" == "$FOREIGN_GRE_IP" ]]; then
                PEER="$IRAN_GRE_IP"
            else
                IFS=. read -r a b c d <<< "$INNER"
                if (( d % 2 == 0 )); then
                    PEER="$a.$b.$c.$((d - 1))"
                else
                    PEER="$a.$b.$c.$((d + 1))"
                fi
            fi
        fi
    fi
    if [[ -z "$PEER" && -f "$PEERS_FILE" ]] && command -v python3 >/dev/null 2>&1; then
        PEER=$(python3 -c '
import json
try:
    with open("'"$PEERS_FILE"'") as f:
        d = json.load(f)
        peers = d.get("peers", [])
        if peers and "peer_gre" in peers[0]:
            print(peers[0]["peer_gre"])
except Exception:
    pass
' 2>/dev/null)
    fi
    echo "$PEER"
}

watchdog_check() {
    init_watchdog_json
    local PEER_GRE
    PEER_GRE=$(watchdog_get_peer_gre)
    local GRE_OK=0
    if [[ -n "$PEER_GRE" ]]; then
        if ping -c 1 -W 2 "$PEER_GRE" >/dev/null 2>&1; then
            GRE_OK=1
        elif ss -tn state established 2>/dev/null | grep -q "$PEER_GRE"; then
            GRE_OK=1
        elif nc -z -w 2 "$PEER_GRE" 22 >/dev/null 2>&1 || nc -z -w 2 "$PEER_GRE" 7777 >/dev/null 2>&1 || nc -z -w 2 "$PEER_GRE" 5201 >/dev/null 2>&1; then
            GRE_OK=1
        elif timeout 2 bash -c "</dev/tcp/$PEER_GRE/22" >/dev/null 2>&1 || timeout 2 bash -c "</dev/tcp/$PEER_GRE/7777" >/dev/null 2>&1; then
            GRE_OK=1
        fi
    fi

    local FRP_NAME=""
    local FRP_OK=0
    if [[ -f /etc/frp/frpc.toml ]] || systemctl list-unit-files 2>/dev/null | grep -q "^frpc\.service"; then
        FRP_NAME="frpc"
        systemctl is-active --quiet frpc 2>/dev/null && FRP_OK=1
    elif [[ -f /etc/frp/frps.toml ]] || systemctl list-unit-files 2>/dev/null | grep -q "^frps\.service"; then
        FRP_NAME="frps"
        systemctl is-active --quiet frps 2>/dev/null && FRP_OK=1
    else
        if systemctl list-units --type=service 2>/dev/null | grep -q 'frps'; then
            FRP_NAME="frps"
            FRP_OK=1
        fi
    fi

    # Foreign spoke resilience: if GRE ICMP ping fails (datacenter firewall/filtering or relay),
    # but frpc is active AND holds established TCP sockets to the FRP control/reverse port,
    # the transport is alive and passing traffic — do NOT trigger false-down restart loops.
    if [[ $GRE_OK -eq 0 && "$FRP_NAME" == "frpc" && $FRP_OK -eq 1 ]]; then
        if ss -tn state established 2>/dev/null | grep -qE ':(4773[0-9]|7000)'; then
            GRE_OK=1
        fi
    fi

    if [[ $GRE_OK -eq 0 && "$FRP_NAME" == "frpc" && $FRP_OK -eq 1 ]]; then
        local _da _dp
        _da=$(dial_current_addr frp 2>/dev/null); _dp=$(dial_current_port frp 2>/dev/null)
        if [[ -n "$_da" && -n "$_dp" ]] && dial_connected "$_da" "$_dp"; then
            GRE_OK=1
        fi
    fi

    local FAILS=0
    if [[ -f "$WATCHDOG_FILE" ]] && command -v python3 >/dev/null 2>&1; then
        FAILS=$(python3 -c '
import json
try:
    with open("'"$WATCHDOG_FILE"'") as f:
        print(int(json.load(f).get("consec_fails", 0)))
except Exception:
    print(0)
' 2>/dev/null || echo 0)
    fi

    local STATUS="down"
    local DETAIL=""
    if [[ $GRE_OK -eq 1 && $FRP_OK -eq 1 ]]; then
        STATUS="up"
        DETAIL="GRE ping OK ($PEER_GRE), FRP $FRP_NAME active"
    else
        local ERR_PARTS=()
        if [[ $GRE_OK -ne 1 ]]; then
            if [[ -z "$PEER_GRE" ]]; then
                ERR_PARTS+=("GRE interface missing/down")
            else
                ERR_PARTS+=("GRE ping $PEER_GRE failed")
            fi
        fi
        if [[ $FRP_OK -ne 1 ]]; then
            ERR_PARTS+=("FRP ${FRP_NAME:-service} inactive")
        fi
        DETAIL=$(IFS="; "; echo "${ERR_PARTS[*]}")
    fi

    echo "WATCHDOG status=$STATUS fails=$FAILS detail=$DETAIL"
    return 0
}

watchdog_send() {
    local TEXT="$1"
    [[ -z "$TEXT" ]] && return 1
    init_watchdog_json

    local CFG
    CFG=$(python3 -c '
import json
try:
    with open("'"$WATCHDOG_FILE"'") as f:
        d = json.load(f)
        tok = d.get("tg_bot_token", "").strip()
        cid = str(d.get("tg_chat_id", "")).strip()
        route = d.get("tg_route", "direct").strip()
        port = str(d.get("tg_tunnel_port", 0)).strip()
        print(f"{tok}\t{cid}\t{route}\t{port}")
except Exception:
    pass
' 2>/dev/null)

    local TG_TOKEN TG_CHAT_ID TG_ROUTE TG_PORT
    IFS=$'\t' read -r TG_TOKEN TG_CHAT_ID TG_ROUTE TG_PORT <<< "$CFG"

    if [[ -z "$TG_TOKEN" || -z "$TG_CHAT_ID" ]]; then
        echo -e "${YELLOW}[!] Telegram bot token or chat ID not configured in ${WATCHDOG_FILE}.${NC}" >&2
        return 1
    fi

    local HOST
    HOST="$(hostname 2>/dev/null || echo 'server')"
    local FULL_MSG="[Hashem ${HOST}] ${TEXT}"

    local CURL_ARGS=(-sS -f)
    if [[ "$TG_ROUTE" == "tunnel" ]]; then
        if [[ -z "$TG_PORT" || "$TG_PORT" -le 0 ]]; then
            echo -e "${RED}[!] Telegram route is set to tunnel but tunnel port is not configured.${NC}" >&2
            return 1
        fi
        CURL_ARGS+=(--max-time 20 --socks5-hostname "127.0.0.1:${TG_PORT}")
    else
        CURL_ARGS+=(--max-time 15)
    fi

    local CURL_OUT
    CURL_OUT=$(curl "${CURL_ARGS[@]}" -d "chat_id=${TG_CHAT_ID}" --data-urlencode "text=${FULL_MSG}" "https://api.telegram.org/bot${TG_TOKEN}/sendMessage" 2>&1)
    local RET=$?

    if [[ $RET -ne 0 ]]; then
        local REDACTED_ERR
        REDACTED_ERR=$(echo "$CURL_OUT" | sed "s/${TG_TOKEN}/[REDACTED]/g")
        echo -e "${RED}[!] Telegram send failed: ${REDACTED_ERR}${NC}" >&2
        return 1
    fi
    return 0
}

watchdog_test() {
    echo -e "${CYAN}[*] Testing Telegram alerts...${NC}"
    if watchdog_send "✅ Hashem watchdog test OK"; then
        echo -e "${GREEN}[✔️] Telegram test message sent successfully.${NC}"
        return 0
    else
        echo -e "${RED}[!] Telegram test message failed. Check token, chat ID, and route.${NC}"
        return 1
    fi
}

restart_all_lite() {
    local u
    # On Iran Hub (frps services exist and frpc does not):
    # NEVER blindly restart listening frps server daemons! Listening frps instances
    # do not recover broken client routes by restarting; restarting frps severs all
    # active client/user sessions across ALL other healthy connected spokes simultaneously.
    # Only restart GRE tunnel interfaces on the hub.
    if [[ -f /etc/frp/frps.toml ]] || systemctl list-unit-files 2>/dev/null | grep -q "^frps\.service"; then
        for u in /etc/systemd/system/gre-t*.service /etc/systemd/system/gre-tunnel.service; do
            [[ -f "$u" ]] || continue
            systemctl restart "$(basename "$u")" >/dev/null 2>&1
        done
        return 0
    fi

    # On foreign node (frpc client):
    local list=()
    for u in /etc/systemd/system/gre-tunnel.service /etc/systemd/system/frpc.service; do
        [[ -f "$u" ]] || continue
        list+=("$(basename "$u")")
    done
    local unique_units=($(echo "${list[@]}" | tr " " "\n" | sort -u))
    for u in "${unique_units[@]}"; do
        systemctl restart "$u" >/dev/null 2>&1
    done
}


watchdog_tick() {
    local LOCKFILE="/var/lock/hashem-watchdog.lock"
    mkdir -p /var/lock 2>/dev/null || true
    exec 200>"$LOCKFILE" 2>/dev/null || exec 200>/tmp/hashem-watchdog.lock
    if ! flock -n 200; then
        echo "watchdog_tick: another instance running, exiting"
        return 0
    fi

    init_watchdog_json
    dial_watch_tick 2>/dev/null || true
    autopool_tick 2>/dev/null || true

    local TICK_ACTION
    TICK_ACTION=$(python3 -c '
import json, time
try:
    with open("'"$WATCHDOG_FILE"'") as f:
        d = json.load(f)
    enabled = d.get("enabled", False)
    backup_every = int(d.get("backup_every_hours", 0))
    backup_daily = d.get("backup_daily_at", "").strip()
    last_backup = int(d.get("last_backup", 0))
    last_bdate = d.get("last_backup_date", "")
    restart_every = int(d.get("restart_every_hours", 0))
    last_restart = int(d.get("last_restart", 0))
    now = int(time.time())
    do_backup = False
    if backup_every > 0:
        if (now - last_backup) >= (backup_every * 3600):
            do_backup = True
    elif backup_daily:
        cur_hm = time.strftime("%H:%M")
        cur_date = time.strftime("%Y-%m-%d")
        if cur_hm == backup_daily and last_bdate != cur_date:
            do_backup = True
    do_restart = False
    if restart_every > 0:
        if (now - last_restart) >= (restart_every * 3600):
            do_restart = True
    print(f"{enabled} {do_backup} {do_restart}")
except Exception as e:
    print("False False False")
' 2>/dev/null)

    local IS_ENABLED="False"
    local DO_BACKUP="False"
    local DO_RESTART_SCHED="False"
    read -r IS_ENABLED DO_BACKUP DO_RESTART_SCHED <<< "$TICK_ACTION"

    if [[ "$IS_ENABLED" == "True" || "$IS_ENABLED" == "true" ]]; then
        local CHECK_OUT
        CHECK_OUT=$(watchdog_check)
        local STATUS DETAIL
        STATUS=$(echo "$CHECK_OUT" | sed -n 's/.*status=\([^ ]*\).*/\1/p')
        DETAIL=$(echo "$CHECK_OUT" | sed -n 's/.*detail=\(.*\)/\1/p')

        local DECISION
        DECISION=$(CHECK_STATUS="$STATUS" CHECK_DETAIL="$DETAIL" python3 -c '
import json, os, time

path = "'"$WATCHDOG_FILE"'"
st = os.environ.get("CHECK_STATUS", "down")
detail = os.environ.get("CHECK_DETAIL", "")
now = int(time.time())
now_str = time.strftime("%Y-%m-%d %H:%M:%S")

try:
    with open(path) as f:
        d = json.load(f)
except Exception:
    d = {"enabled": True, "fail_threshold": 2, "consec_fails": 0, "last_alert": ""}

threshold = int(d.get("fail_threshold", 2))
consec = int(d.get("consec_fails", 0))
last_alert = d.get("last_alert", "")
down_since = int(d.get("down_since", 0))

action = "NONE"

if st == "up":
    if last_alert == "down":
        down_min = max(1, int((now - down_since + 59) / 60))
        action = f"RECOVERED {down_min}"
        d["last_alert"] = "up"
        d["down_since"] = 0
    d["consec_fails"] = 0
else:
    consec += 1
    d["consec_fails"] = consec
    if consec >= threshold:
        if last_alert != "down":
            action = "DOWN"
            d["last_alert"] = "down"
            d["down_since"] = now
        elif consec % 2 == 0:
            action = "DOWN_RETRY"

d["last_check"] = now_str

tmp = path + ".tmp"
with open(tmp, "w") as f:
    json.dump(d, f, indent=2)
os.replace(tmp, path)
os.chmod(path, 0o600)
print(action)
' 2>/dev/null)

        local DO_RESTART
        DO_RESTART=$(python3 -c "import json; print(json.load(open('$WATCHDOG_FILE')).get('auto_restart', False))" 2>/dev/null || echo "False")
        if [[ "$DECISION" == DOWN* ]]; then
            if [[ "$DECISION" == "DOWN" ]]; then
                if [[ "$DO_RESTART" == "True" || "$DO_RESTART" == "true" ]]; then
                    watchdog_send "🔴 Tunnel DOWN: ${DETAIL} (attempting tunnel restart)" || true
                else
                    watchdog_send "🔴 Tunnel DOWN: ${DETAIL} (alert only, auto-restart disabled)" || true
                fi
            fi
            if [[ "$DO_RESTART" == "True" || "$DO_RESTART" == "true" ]]; then
                restart_all_lite
            fi
        elif [[ "$DECISION" == RECOVERED* ]]; then
            local DMIN
            DMIN=$(echo "$DECISION" | awk '{print $2}')
            watchdog_send "🟢 Tunnel RECOVERED (was down ${DMIN}m)" || true
        fi
    fi

    if [[ "$DO_BACKUP" == "True" || "$DO_BACKUP" == "true" ]]; then
        backup_now >/dev/null 2>&1 || true
        python3 -c '
import json, time
path = "'"$WATCHDOG_FILE"'"
try:
    with open(path) as f:
        d = json.load(f)
    d["last_backup"] = int(time.time())
    d["last_backup_date"] = time.strftime("%Y-%m-%d")
    with open(path + ".tmp", "w") as f:
        json.dump(d, f, indent=2)
    import os
    os.replace(path + ".tmp", path)
    os.chmod(path, 0o600)
except Exception:
    pass
' 2>/dev/null || true
    fi

    if [[ "$DO_RESTART_SCHED" == "True" || "$DO_RESTART_SCHED" == "true" ]]; then
        restart_all_lite >/dev/null 2>&1 || true
        python3 -c '
import json, time
path = "'"$WATCHDOG_FILE"'"
try:
    with open(path) as f:
        d = json.load(f)
    d["last_restart"] = int(time.time())
    d["last_restart_date"] = time.strftime("%Y-%m-%d %H:%M:%S")
    with open(path + ".tmp", "w") as f:
        json.dump(d, f, indent=2)
    import os
    os.replace(path + ".tmp", path)
    os.chmod(path, 0o600)
except Exception:
    pass
' 2>/dev/null || true
    fi

    return 0
}

backup_now() {
    local OUTDIR="$BACKUP_DIR"
    local KEEP=7
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --keep) KEEP="$2"; shift 2 ;;
            *)
                if [[ "$1" != --* ]]; then
                    OUTDIR="$1"
                fi
                shift
                ;;
        esac
    done

    mkdir -p "$OUTDIR"
    chmod 700 "$OUTDIR" 2>/dev/null || true

    ensure_backup_key
    if [[ ! -f /etc/gre-panel/backup.key ]]; then
        echo -e "${RED}[!] /etc/gre-panel/backup.key not found — cannot encrypt backup.${NC}" >&2
        return 1
    fi

    local DATE_STR
    DATE_STR=$(date +%Y%m%d-%H%M%S)
    local OUT_FILE="${OUTDIR}/hashem-backup-${DATE_STR}.enc"

    local FILES=()
    local f
    for f in /etc/frp/*.toml /etc/gre-panel/panel.json /etc/gre-panel/peers.json /etc/gre-panel/watchdog.json \
             /etc/gre-panel/perf.json /etc/gre-panel/backup.key \
             /etc/systemd/system/gre-*.service /etc/systemd/system/frps*.service \
             /etc/systemd/system/frpc*.service; do
        [[ -f "$f" ]] && FILES+=("$f")
    done

    if [[ ${#FILES[@]} -eq 0 ]]; then
        echo -e "${RED}[!] No configuration or unit files found to back up.${NC}" >&2
        return 1
    fi

    if ! tar -czf - "${FILES[@]}" 2>/dev/null | openssl enc -aes-256-cbc -pbkdf2 -pass file:/etc/gre-panel/backup.key -out "$OUT_FILE"; then
        echo -e "${RED}[!] Failed to create encrypted backup.${NC}" >&2
        rm -f "$OUT_FILE"
        return 1
    fi

    chmod 600 "$OUT_FILE" 2>/dev/null || true
    local SIZE
    SIZE=$(stat -c%s "$OUT_FILE" 2>/dev/null || echo 0)
    local HSIZE
    HSIZE=$(du -h "$OUT_FILE" 2>/dev/null | cut -f1)

    echo "BACKUP path=${OUT_FILE} size=${SIZE}"
    echo -e "${GREEN}[✔️] Backup created: ${OUT_FILE} (${HSIZE})${NC}"

    if [[ "$KEEP" -gt 0 ]]; then
        local OLD_FILES
        OLD_FILES=$(ls -1t "$OUTDIR"/hashem-backup-*.enc 2>/dev/null | tail -n +$((KEEP + 1)))
        if [[ -n "$OLD_FILES" ]]; then
            echo "$OLD_FILES" | xargs -r rm -f
            echo -e "${CYAN}[*] Pruned old backups (kept latest ${KEEP}).${NC}"
        fi
    fi
    return 0
}

backup_restore() {
    local FILE=""
    local DRY_RUN=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --dry-run) DRY_RUN=1; shift ;;
            *) FILE="$1"; shift ;;
        esac
    done

    if [[ -z "$FILE" || ! -f "$FILE" ]]; then
        echo -e "${RED}[!] Backup file not found: '${FILE}'${NC}" >&2
        return 1
    fi
    ensure_backup_key
    local KEY_FILE="/etc/gre-panel/backup.key"
    if [[ ! -f "$KEY_FILE" && -f "/etc/gre-panel/panel.pass" ]]; then
        KEY_FILE="/etc/gre-panel/panel.pass"
    fi
    if [[ ! -f "$KEY_FILE" ]]; then
        echo -e "${RED}[!] Backup encryption key not found — cannot decrypt backup.${NC}" >&2
        return 1
    fi

    local TMP_D
    TMP_D=$(mktemp -d)
    trap 'rm -rf "$TMP_D"' RETURN

    echo -e "${CYAN}[*] Decrypting backup archive...${NC}"
    if ! openssl enc -d -aes-256-cbc -pbkdf2 -pass file:"$KEY_FILE" -in "$FILE" -out "$TMP_D/backup.tar.gz" 2>/dev/null; then
        echo -e "${RED}[!] Decryption failed: invalid encryption key or file corrupted.${NC}" >&2
        return 1
    fi

    echo -e "${CYAN}[*] Verifying archive contents...${NC}"
    if ! tar -ztf "$TMP_D/backup.tar.gz" >"$TMP_D/list.txt" 2>/dev/null; then
        echo -e "${RED}[!] Archive verification failed: invalid tar archive.${NC}" >&2
        return 1
    fi

    if [[ "$DRY_RUN" -eq 1 ]]; then
        echo -e "${GREEN}[✔️] Archive verified OK. Files inside:${NC}"
        cat "$TMP_D/list.txt"
        return 0
    fi

    echo -e "${CYAN}[*] Restoring configuration files and systemd units...${NC}"
    tar -xzf "$TMP_D/backup.tar.gz" -C /
    chmod 600 /etc/gre-panel/*.json 2>/dev/null || true
    chmod 600 /etc/gre-panel/*.pass 2>/dev/null || true
    echo -e "${GREEN}[✔️] Files restored:${NC}"
    cat "$TMP_D/list.txt"

    echo -e "${CYAN}[*] Reloading systemd daemon...${NC}"
    systemctl daemon-reload

    echo -e "${CYAN}[*] Restarting tunnel services...${NC}"
    restart_all

    echo -e "${GREEN}[✔️] Restore completed successfully.${NC}"
    return 0
}

install_watchdog_units() {
    [[ -x "$HASHEM_BIN" ]] || { cp "$0" "$HASHEM_BIN" 2>/dev/null && chmod +x "$HASHEM_BIN"; } || true
    cat << 'EOF' > /etc/systemd/system/hashem-watchdog.service
[Unit]
Description=Hashem Watchdog and Scheduled Backup Tick
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/hashem watchdog tick
EOF

    cat << 'EOF' > /etc/systemd/system/hashem-watchdog.timer
[Unit]
Description=Run Hashem Watchdog every minute
After=network.target

[Timer]
OnBootSec=1min
OnUnitActiveSec=1min
Persistent=true

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
}

watchdog_on() {
    init_watchdog_json
    install_watchdog_units
    systemctl enable --now hashem-watchdog.timer >/dev/null 2>&1
    python3 -c '
import json
path = "'"$WATCHDOG_FILE"'"
try:
    with open(path) as f:
        d = json.load(f)
    d["enabled"] = True
    with open(path + ".tmp", "w") as f:
        json.dump(d, f, indent=2)
    import os
    os.replace(path + ".tmp", path)
    os.chmod(path, 0o600)
except Exception:
    pass
' 2>/dev/null || true
    echo -e "${GREEN}[✔️] Watchdog enabled (systemd timer active, checks every 1 min).${NC}"
}

watchdog_off() {
    init_watchdog_json
    systemctl stop hashem-watchdog.timer hashem-watchdog.service >/dev/null 2>&1 || true
    systemctl disable hashem-watchdog.timer >/dev/null 2>&1 || true
    python3 -c '
import json
path = "'"$WATCHDOG_FILE"'"
try:
    with open(path) as f:
        d = json.load(f)
    d["enabled"] = False
    with open(path + ".tmp", "w") as f:
        json.dump(d, f, indent=2)
    import os
    os.replace(path + ".tmp", path)
    os.chmod(path, 0o600)
except Exception:
    pass
' 2>/dev/null || true
    echo -e "${YELLOW}[*] Watchdog disabled (systemd timer stopped).${NC}"
}

watchdog_status_full() {
    init_watchdog_json
    echo -e "${CYAN}==========================================================${NC}"
    echo -e "${CYAN}                 Hashem Watchdog Status                   ${NC}"
    echo -e "${CYAN}==========================================================${NC}"

    local INFO
    INFO=$(python3 -c '
import json
path = "'"$WATCHDOG_FILE"'"
try:
    with open(path) as f:
        d = json.load(f)
    en = "Enabled" if d.get("enabled", False) else "Disabled"
    tok = d.get("tg_bot_token", "").strip()
    if tok:
        masked = tok[:6] + "..." + tok[-4:] if len(tok) > 10 else "******"
    else:
        masked = "(not configured)"
    cid = str(d.get("tg_chat_id", "")) or "(not configured)"
    route = d.get("tg_route", "direct")
    port = str(d.get("tg_tunnel_port", 0))
    fails = str(d.get("consec_fails", 0))
    thresh = str(d.get("fail_threshold", 2))
    last_c = d.get("last_check", "") or "(none yet)"
    last_a = d.get("last_alert", "") or "(none)"
    be = int(d.get("backup_every_hours", 0))
    bd = d.get("backup_daily_at", "")
    if be > 0:
        sched = f"Every {be} hours"
    elif bd:
        sched = f"Daily at {bd}"
    else:
        sched = "Disabled"
    print(f"{en}\t{masked}\t{cid}\t{route}\t{port}\t{fails}\t{thresh}\t{last_c}\t{last_a}\t{sched}")
except Exception as e:
    print(f"Error\t-\t-\t-\t-\t0\t2\t-\t-\tDisabled")
' 2>/dev/null)

    local EN TOK CID ROUTE PORT FAILS THRESH LAST_C LAST_A SCHED
    IFS=$'\t' read -r EN TOK CID ROUTE PORT FAILS THRESH LAST_C LAST_A SCHED <<< "$INFO"

    local TIMER_ACTIVE="inactive"
    if systemctl is-active --quiet hashem-watchdog.timer 2>/dev/null; then
        TIMER_ACTIVE="active (every 1 min)"
    fi

    echo -e "Watchdog State:     ${CYAN}${EN}${NC} (systemd timer: ${TIMER_ACTIVE})"
    echo -e "Consecutive Fails:  ${FAILS} / ${THRESH}"
    echo -e "Last Check:         ${LAST_C}"
    echo -e "Last Alert:         ${LAST_A}"
    echo ""
    echo -e "${YELLOW}── Telegram Alerts ──${NC}"
    echo -e "Bot Token:          ${TOK}"
    echo -e "Chat ID:            ${CID}"
    if [[ "$ROUTE" == "tunnel" ]]; then
        echo -e "Route:              tunnel (SOCKS5 127.0.0.1:${PORT})"
    else
        echo -e "Route:              direct"
    fi
    echo ""
    echo -e "${YELLOW}── Backup Schedule & Files ──${NC}"
    echo -e "Schedule:           ${SCHED}"
    local BC=0
    if [[ -d "$BACKUP_DIR" ]]; then
        BC=$(ls -1 "$BACKUP_DIR"/hashem-backup-*.enc 2>/dev/null | wc -l)
    fi
    echo -e "Stored Backups:     ${BC} in ${BACKUP_DIR}"
    if [[ "$BC" -gt 0 ]]; then
        ls -lh "$BACKUP_DIR"/hashem-backup-*.enc 2>/dev/null | awk '{print "  " $9 " (" $5 ", " $6 " " $7 " " $8 ")"}' | tail -n 5
    fi
    echo ""
    echo -e "${YELLOW}── Live Health Check ──${NC}"
    watchdog_check
    echo -e "${CYAN}==========================================================${NC}"
}

find_live_proxy_ports() {
    local PORTS=()
    if [[ -f /etc/frp/frpc.toml ]]; then
        while read -r p; do
            [[ -n "$p" ]] && PORTS+=("$p")
        done < <(grep -E '^(remotePort|localPort)\s*=' /etc/frp/frpc.toml 2>/dev/null | awk -F= '{print $2}' | tr -d ' "')
    fi
    local f
    for f in /etc/frp/frps*.toml; do
        [[ -f "$f" ]] || continue
        while read -r p; do
            [[ -n "$p" ]] && PORTS+=("$p")
        done < <(grep -E '^(remotePort|localPort)\s*=' "$f" 2>/dev/null | awk -F= '{print $2}' | tr -d ' "')
    done
    if [[ -f "$PEERS_FILE" ]] && command -v python3 >/dev/null 2>&1; then
        while read -r p; do
            [[ -n "$p" ]] && PORTS+=("$p")
        done < <(python3 -c '
import json
try:
    with open("'"$PEERS_FILE"'") as f:
        d = json.load(f)
        for peer in d.get("peers", []):
            for port in peer.get("ports", []):
                print(port)
except Exception:
    pass
' 2>/dev/null)
    fi
    if [[ ${#PORTS[@]} -gt 0 ]]; then
        printf "%s\n" "${PORTS[@]}" | sort -n -u
    fi
}

menu_watchdog() {
    while true; do
        clear
        echo -e "${CYAN}==========================================================${NC}"
        echo -e "${CYAN}              Watchdog & Encrypted Backup                 ${NC}"
        echo -e "${CYAN}==========================================================${NC}"
        echo ""
        init_watchdog_json
        local W_EN
        W_EN=$(python3 -c '
import json
try:
    with open("'"$WATCHDOG_FILE"'") as f:
        print("ENABLED" if json.load(f).get("enabled", False) else "DISABLED")
except Exception:
    print("DISABLED")
' 2>/dev/null)
        if [[ "$W_EN" == "ENABLED" ]]; then
            echo -e "Watchdog Status: ${GREEN}● ENABLED${NC} (checks every 1 min)"
        else
            echo -e "Watchdog Status: ${RED}○ DISABLED${NC}"
        fi
        echo ""
        echo "  1) Enable / Disable Watchdog"
        echo "  2) Set Telegram (Bot Token & Chat ID)"
        echo "  3) Test Telegram Alert"
        echo "  4) Route Direct vs Tunnel (+pick tunnel socks port)"
        echo "  5) Backup Now (OpenSSL AES-256-CBC Encrypted)"
        echo "  6) Schedule Backup (Every-N-Hours OR Daily at HH:MM)"
        echo "  7) Restore from Encrypted Backup"
        echo "  8) View Full Status & Stored Backups"
        echo "  0) Back to Main Menu"
        echo ""
        read -p "Select an option [0-8]: " SUBOPT
        case "$SUBOPT" in
            1)
                if [[ "$W_EN" == "ENABLED" ]]; then
                    watchdog_off
                else
                    watchdog_on
                fi
                read -p "Press Enter to continue..." _
                ;;
            2)
                echo -e "\n${CYAN}── Configure Telegram Alerts ──${NC}"
                read -p "Enter Telegram Bot Token: " INPUT_TOKEN
                read -p "Enter Telegram Chat ID: " INPUT_CID
                if [[ -n "$INPUT_TOKEN" || -n "$INPUT_CID" ]]; then
                    python3 -c '
import json
path = "'"$WATCHDOG_FILE"'"
tok = "'"$INPUT_TOKEN"'".strip()
cid = "'"$INPUT_CID"'".strip()
try:
    with open(path) as f:
        d = json.load(f)
    if tok:
        d["tg_bot_token"] = tok
    if cid:
        d["tg_chat_id"] = cid
    with open(path + ".tmp", "w") as f:
        json.dump(d, f, indent=2)
    import os
    os.replace(path + ".tmp", path)
    os.chmod(path, 0o600)
except Exception as e:
    print(e)
' 2>/dev/null
                    echo -e "${GREEN}[✔️] Telegram settings saved.${NC}"
                else
                    echo -e "${YELLOW}[*] No changes made.${NC}"
                fi
                read -p "Press Enter to continue..." _
                ;;
            3)
                watchdog_test
                read -p "Press Enter to continue..." _
                ;;
            4)
                echo -e "\n${CYAN}── Telegram Delivery Route ──${NC}"
                echo "  1) Direct (curl direct to Telegram API)"
                echo "  2) Via Tunnel (SOCKS5 through tunnel port)"
                read -p "Choose route [1-2]: " ROUTE_CHOICE
                if [[ "$ROUTE_CHOICE" == "1" ]]; then
                    python3 -c '
import json
path = "'"$WATCHDOG_FILE"'"
try:
    with open(path) as f:
        d = json.load(f)
    d["tg_route"] = "direct"
    with open(path + ".tmp", "w") as f:
        json.dump(d, f, indent=2)
    import os
    os.replace(path + ".tmp", path)
    os.chmod(path, 0o600)
except Exception:
    pass
' 2>/dev/null
                    echo -e "${GREEN}[✔️] Route set to Direct.${NC}"
                elif [[ "$ROUTE_CHOICE" == "2" ]]; then
                    local PORTS=()
                    mapfile -t PORTS < <(find_live_proxy_ports)
                    local CHOSEN_PORT=0
                    if [[ ${#PORTS[@]} -gt 0 ]]; then
                        echo -e "\nDetected live tunnel ports:"
                        local idx=1
                        for p in "${PORTS[@]}"; do
                            echo "  $idx) Port $p"
                            ((idx++))
                        done
                        echo "  $idx) Enter custom port manually"
                        read -p "Select port [1-$idx]: " PIDX
                        if [[ "$PIDX" =~ ^[0-9]+$ ]] && (( PIDX >= 1 && PIDX < idx )); then
                            CHOSEN_PORT="${PORTS[$((PIDX-1))]}"
                        else
                            read -p "Enter SOCKS5 tunnel port (1-65535): " CHOSEN_PORT
                        fi
                    else
                        read -p "Enter SOCKS5 tunnel port (1-65535): " CHOSEN_PORT
                    fi
                    if is_valid_port "$CHOSEN_PORT"; then
                        python3 -c '
import json
path = "'"$WATCHDOG_FILE"'"
try:
    with open(path) as f:
        d = json.load(f)
    d["tg_route"] = "tunnel"
    d["tg_tunnel_port"] = int("'"$CHOSEN_PORT"'")
    with open(path + ".tmp", "w") as f:
        json.dump(d, f, indent=2)
    import os
    os.replace(path + ".tmp", path)
    os.chmod(path, 0o600)
except Exception:
    pass
' 2>/dev/null
                        echo -e "${GREEN}[✔️] Route set to Tunnel (127.0.0.1:${CHOSEN_PORT}).${NC}"
                    else
                        echo -e "${RED}[!] Invalid port number.${NC}"
                    fi
                fi
                read -p "Press Enter to continue..." _
                ;;
            5)
                echo -e "\n${CYAN}── Creating Encrypted Backup ──${NC}"
                backup_now
                read -p "Press Enter to continue..." _
                ;;
            6)
                echo -e "\n${CYAN}── Schedule Encrypted Backup ──${NC}"
                echo "  1) Every N hours"
                echo "  2) Daily at fixed time (HH:MM)"
                echo "  3) Disable scheduled backups"
                read -p "Select schedule mode [1-3]: " S_CHOICE
                case "$S_CHOICE" in
                    1)
                        read -p "Enter interval in hours (e.g. 6): " N_HOURS
                        if [[ "$N_HOURS" =~ ^[0-9]+$ ]] && (( N_HOURS >= 1 && N_HOURS <= 168 )); then
                            python3 -c '
import json
path = "'"$WATCHDOG_FILE"'"
try:
    with open(path) as f:
        d = json.load(f)
    d["backup_every_hours"] = int("'"$N_HOURS"'")
    d["backup_daily_at"] = ""
    with open(path + ".tmp", "w") as f:
        json.dump(d, f, indent=2)
    import os
    os.replace(path + ".tmp", path)
    os.chmod(path, 0o600)
except Exception:
    pass
' 2>/dev/null
                            echo -e "${GREEN}[✔️] Backup scheduled every ${N_HOURS} hours.${NC}"
                        else
                            echo -e "${RED}[!] Invalid hours (must be 1-168).${NC}"
                        fi
                        ;;
                    2)
                        read -p "Enter daily time in 24h format HH:MM (e.g. 03:00): " DAILY_T
                        if [[ "$DAILY_T" =~ ^([01][0-9]|2[0-3]):[0-5][0-9]$ ]]; then
                            python3 -c '
import json
path = "'"$WATCHDOG_FILE"'"
try:
    with open(path) as f:
        d = json.load(f)
    d["backup_every_hours"] = 0
    d["backup_daily_at"] = "'"$DAILY_T"'"
    with open(path + ".tmp", "w") as f:
        json.dump(d, f, indent=2)
    import os
    os.replace(path + ".tmp", path)
    os.chmod(path, 0o600)
except Exception:
    pass
' 2>/dev/null
                            echo -e "${GREEN}[✔️] Backup scheduled daily at ${DAILY_T}.${NC}"
                        else
                            echo -e "${RED}[!] Invalid time format (use HH:MM e.g. 03:00).${NC}"
                        fi
                        ;;
                    3)
                        python3 -c '
import json
path = "'"$WATCHDOG_FILE"'"
try:
    with open(path) as f:
        d = json.load(f)
    d["backup_every_hours"] = 0
    d["backup_daily_at"] = ""
    with open(path + ".tmp", "w") as f:
        json.dump(d, f, indent=2)
    import os
    os.replace(path + ".tmp", path)
    os.chmod(path, 0o600)
except Exception:
    pass
' 2>/dev/null
                        echo -e "${GREEN}[✔️] Scheduled backups disabled.${NC}"
                        ;;
                    *)
                        echo -e "${RED}[!] Invalid option.${NC}"
                        ;;
                esac
                read -p "Press Enter to continue..." _
                ;;
            7)
                echo -e "\n${CYAN}── Restore Backup ──${NC}"
                local BAKS=()
                if [[ -d "$BACKUP_DIR" ]]; then
                    mapfile -t BAKS < <(ls -1t "$BACKUP_DIR"/hashem-backup-*.enc 2>/dev/null)
                fi
                if [[ ${#BAKS[@]} -eq 0 ]]; then
                    echo -e "${YELLOW}[!] No backups found in ${BACKUP_DIR}.${NC}"
                    read -p "Enter full path to backup file manually (or Enter to cancel): " MAN_FILE
                    if [[ -n "$MAN_FILE" ]]; then
                        backup_restore "$MAN_FILE"
                    fi
                else
                    echo "Available backups:"
                    local bidx=1
                    for b in "${BAKS[@]}"; do
                        local bsz
                        bsz=$(du -h "$b" 2>/dev/null | cut -f1)
                        echo "  $bidx) $(basename "$b") ($bsz)"
                        ((bidx++))
                    done
                    read -p "Select backup to restore [1-$((bidx-1))]: " PICK_B
                    if [[ "$PICK_B" =~ ^[0-9]+$ ]] && (( PICK_B >= 1 && PICK_B < bidx )); then
                        local SELECTED="${BAKS[$((PICK_B-1))]}"
                        read -p "Restore $(basename "$SELECTED")? Current configs will be overwritten and services restarted. (y/N): " CONFIRM_R
                        if [[ "$CONFIRM_R" =~ ^[Yy]$ ]]; then
                            backup_restore "$SELECTED"
                        else
                            echo -e "${YELLOW}[*] Restore cancelled.${NC}"
                        fi
                    else
                        echo -e "${RED}[!] Invalid choice.${NC}"
                    fi
                fi
                read -p "Press Enter to continue..." _
                ;;
            8)
                watchdog_status_full
                read -p "Press Enter to continue..." _
                ;;
            0)
                return 0
                ;;
            *)
                echo -e "${RED}[!] Invalid option.${NC}"
                sleep 1
                ;;
        esac
    done
}

cli_watchdog() {
    local SUB="$1"
    shift || true
    case "$SUB" in
        on) watchdog_on ;;
        off) watchdog_off ;;
        status) watchdog_status_full ;;
        test) watchdog_test ;;
        tick) watchdog_tick ;;
        check) watchdog_check ;;
        *) echo -e "${RED}[!] Unknown watchdog command: '$SUB' (want on|off|status|test|tick)${NC}"; return 1 ;;
    esac
}

cli_backup() {
    local SUB="$1"
    shift || true
    case "$SUB" in
        now) backup_now "$@" ;;
        restore) backup_restore "$@" ;;
        status)
            echo -e "${CYAN}=== Hashem Backups (${BACKUP_DIR}) ===${NC}"
            if [[ -d "$BACKUP_DIR" ]]; then
                ls -lh "$BACKUP_DIR"/hashem-backup-*.enc 2>/dev/null || echo "(no backups found)"
            else
                echo "(no backup directory)"
            fi
            ;;
        schedule)
            local MODE="" HOURS=0 DAILY=""
            while [[ $# -gt 0 ]]; do
                case "$1" in
                    --every|every) HOURS="$2"; MODE="interval"; shift 2 ;;
                    --daily|daily) DAILY="$2"; MODE="daily"; shift 2 ;;
                    --off|off) MODE="off"; shift ;;
                    *) shift ;;
                esac
            done
            init_watchdog_json
            if [[ "$MODE" == "interval" ]]; then
                if [[ "$HOURS" =~ ^[0-9]+$ ]] && (( HOURS >= 1 && HOURS <= 168 )); then
                    python3 -c '
import json
path = "'"$WATCHDOG_FILE"'"
try:
    with open(path) as f:
        d = json.load(f)
    d["backup_every_hours"] = int("'"$HOURS"'")
    d["backup_daily_at"] = ""
    with open(path + ".tmp", "w") as f:
        json.dump(d, f, indent=2)
    import os
    os.replace(path + ".tmp", path)
    os.chmod(path, 0o600)
except Exception:
    pass
' 2>/dev/null
                    echo -e "${GREEN}[✔️] Backup scheduled every ${HOURS} hours.${NC}"
                else
                    echo -e "${RED}[!] Invalid interval hours: '$HOURS' (1-168)${NC}"; return 1
                fi
            elif [[ "$MODE" == "daily" ]]; then
                if [[ "$DAILY" =~ ^([01][0-9]|2[0-3]):[0-5][0-9]$ ]]; then
                    python3 -c '
import json
path = "'"$WATCHDOG_FILE"'"
try:
    with open(path) as f:
        d = json.load(f)
    d["backup_every_hours"] = 0
    d["backup_daily_at"] = "'"$DAILY"'"
    with open(path + ".tmp", "w") as f:
        json.dump(d, f, indent=2)
    import os
    os.replace(path + ".tmp", path)
    os.chmod(path, 0o600)
except Exception:
    pass
' 2>/dev/null
                    echo -e "${GREEN}[✔️] Backup scheduled daily at ${DAILY}.${NC}"
                else
                    echo -e "${RED}[!] Invalid daily time format: '$DAILY' (HH:MM e.g. 03:00)${NC}"; return 1
                fi
            elif [[ "$MODE" == "off" ]]; then
                python3 -c '
import json
path = "'"$WATCHDOG_FILE"'"
try:
    with open(path) as f:
        d = json.load(f)
    d["backup_every_hours"] = 0
    d["backup_daily_at"] = ""
    with open(path + ".tmp", "w") as f:
        json.dump(d, f, indent=2)
    import os
    os.replace(path + ".tmp", path)
    os.chmod(path, 0o600)
except Exception:
    pass
' 2>/dev/null
                echo -e "${GREEN}[✔️] Scheduled backups disabled.${NC}"
            else
                echo -e "${RED}[!] Usage: hashem backup schedule [--every N | --daily HH:MM | --off]${NC}"; return 1
            fi
            ;;
        *)
            echo -e "${RED}[!] Unknown backup command: '$SUB' (want now|restore|schedule|status)${NC}"
            return 1
            ;;
    esac
}

# remove_legacy_units: older releases installed hashem-monitor.service and
# hashem-webui.service (ExecStart=hashem --monitor / --webui). Those verbs no
# longer exist, so the units crash-looped forever (Restart=always) and flooded
# journald. Remove them (idempotent; only when ExecStart really is the dead verb).
# HASHEM_SYSTEMD_DIR is overridable for tests.
remove_legacy_units() {
    local dir="${HASHEM_SYSTEMD_DIR:-/etc/systemd/system}" name unit removed=0
    for name in hashem-monitor hashem-webui; do
        unit="${dir}/${name}.service"
        [[ -f "$unit" ]] || continue
        grep -Eq '^ExecStart=.*/hashem(\.sh)? +--(monitor|webui)([[:space:]]|$)' "$unit" || continue
        systemctl stop "${name}.service" >/dev/null 2>&1 || true
        systemctl disable "${name}.service" >/dev/null 2>&1 || true
        rm -f "$unit" "${dir}/multi-user.target.wants/${name}.service"
        systemctl reset-failed "${name}.service" >/dev/null 2>&1 || true
        echo -e "${GREEN}[✔️] Removed obsolete unit ${name}.service${NC}"
        removed=1
    done
    (( removed )) && { systemctl daemon-reload >/dev/null 2>&1 || true; }
    return 0
}

update_all() {
    echo -e "${CYAN}[*] Updating Hashem (script + panel binary)...${NC}"
    TMP_U="$(mktemp -d)"
    trap 'rm -rf "$TMP_U"' RETURN
    # 1. fresh script from the channel's release (main only if the tag has no asset)
    UPD_TAG=$(update_pick_tag)
    echo -e "${CYAN}[*] Channel: $(update_get_channel)${UPD_TAG:+ (release ${UPD_TAG})}${NC}"
    if [[ -n "$UPD_TAG" ]]; then
        download_with_fallback "$TMP_U/hashem.sh" "https://github.com/pdnczone/hashem-panel/releases/download/${UPD_TAG}/hashem.sh" 30 || rm -f "$TMP_U/hashem.sh"
        if [[ -s "$TMP_U/hashem.sh" ]]; then
            update_verify_asset "$TMP_U/hashem.sh" "$UPD_TAG" hashem.sh; _VR=$?
            if [[ $_VR -eq 1 ]]; then
                echo -e "${RED}[!] hashem.sh does not match ${UPD_TAG}/checksums.txt — refusing, nothing changed.${NC}"
                return 1
            fi
        fi
    fi
    if [[ ! -s "$TMP_U/hashem.sh" ]] && [[ "$(update_get_channel)" == "dev" ]]; then
        echo -e "${RED}[!] No dev release script available — nothing changed.${NC}"
        return 1
    fi
    if ! download_with_fallback "$TMP_U/hashem.sh" "${HASHEM_URL_BASE}/hashem.sh" 30; then
        echo -e "${RED}[!] Failed to download latest hashem.sh — nothing changed.${NC}"
        return 1
    fi
    bash -n "$TMP_U/hashem.sh" || { echo -e "${RED}[!] Downloaded script failed syntax check — nothing changed.${NC}"; return 1; }
    if cmp -s "$TMP_U/hashem.sh" "$0" 2>/dev/null || cmp -s "$TMP_U/hashem.sh" ./hashem.sh 2>/dev/null; then
        echo -e "${GREEN}[✔️] hashem.sh is already the latest version.${NC}"
    else
        echo -e "${GREEN}[✔️] New hashem.sh downloaded and syntax-checked.${NC}"
    fi
    remove_legacy_units
    # 2. reinstall panel binary from latest release (downloads prebuilt, restarts service)
    echo -e "${CYAN}[*] Updating panel binary...${NC}"
    # backup panel config so a failed update can be rolled back
    PANEL_BAK=""
    if [[ -f /etc/gre-panel/panel.json ]]; then
        PANEL_BAK="$(mktemp -d)"
        cp -a /etc/gre-panel/panel.json "$PANEL_BAK/" 2>/dev/null || true
    fi
    if ! install_panel; then
        echo -e "${RED}[!] Panel update failed — restoring previous config.${NC}"
        [[ -n "$PANEL_BAK" ]] && cp -a "$PANEL_BAK/panel.json" /etc/gre-panel/ 2>/dev/null || true
        systemctl restart gre-panel 2>/dev/null || true
        return 1
    fi
    [[ -n "$PANEL_BAK" ]] && rm -rf "$PANEL_BAK"
    # 3. replace running script only after everything succeeded
    cp "$TMP_U/hashem.sh" "$0" 2>/dev/null || cp "$TMP_U/hashem.sh" ./hashem.sh
    chmod +x "$0" 2>/dev/null || true
    # 4. sync copies next to the panel binary + the hashem command + legacy
    # gre.sh symlink, so the web panel + grepanel always shell out to the
    # latest tune/setup logic (single source of truth)
    cp "$TMP_U/hashem.sh" "$HASHEM_SCRIPT" 2>/dev/null && chmod +x "$HASHEM_SCRIPT" || true
    cp "$TMP_U/hashem.sh" "$HASHEM_BIN" 2>/dev/null && chmod +x "$HASHEM_BIN" || true
    ln -sf "$HASHEM_SCRIPT" /usr/local/bin/gre.sh 2>/dev/null || true
    # 5. Retire removed features (chaff service, DPI shield, force_tls/auto_tune keys) left by older releases
    purge_legacy_obfuscation
    perf_prune_legacy_keys

    # 6. Legacy hub tomls with no transport.tcpMux line run FRP's default (ON) while new spokes
    # write false => EOF. Warn only: changing it automatically would flip a live pair.
    if [[ -z "$(perf_get_tcpmux)" ]]; then
        local _frps_f
        for _frps_f in "$CONFIG_DIR"/frps*.toml; do
            [[ -f "$_frps_f" ]] || continue
            grep -Eq '^[[:space:]]*transport\.tcpMux[[:space:]]*=' "$_frps_f" 2>/dev/null && continue
            echo -e "${YELLOW}[!] $(basename "$_frps_f") has no transport.tcpMux line (FRP default = ON); set explicitly with: hashem perf tcpmux on|off on hub AND spokes${NC}"
        done
    fi
    perf_apply >/dev/null 2>&1 || true
    if [[ -f "$WATCHDOG_FILE" ]] && command -v python3 >/dev/null 2>&1; then
        local WD_EN
        WD_EN=$(python3 -c '
import json
try:
    with open("'"$WATCHDOG_FILE"'") as f:
        print(json.load(f).get("enabled", False))
except Exception:
    print(False)
' 2>/dev/null)
        if [[ "$WD_EN" == "True" || "$WD_EN" == "true" ]]; then
            install_watchdog_units
            systemctl enable --now hashem-watchdog.timer >/dev/null 2>&1 || true
        fi
    fi
    PANEL_VER=$("$PANEL_BIN" --version 2>/dev/null || echo "unknown")
    echo -e "${GREEN}[✔️] Update complete — script + panel are latest (panel: ${PANEL_VER}). Re-run the script to use the new menu.${NC}"
}

cli_carrier() {
    init_carrier_json
    local SUB="${1:-status}"
    case "$SUB" in
        status)
            local MODE ACT P1 P2
            MODE=$(carrier_get_mode)
            ACT=$(carrier_get_active)
            read -r P1 P2 <<< "$(carrier_get_fou_ports)"
            local PGRE PING_OUT="no peer"
            PGRE=$(watchdog_get_peer_gre 2>/dev/null)
            if [[ -n "$PGRE" ]]; then
                if ping -c 1 -W 2 "$PGRE" >/dev/null 2>&1; then
                    local RTT
                    RTT=$(ping -c 1 -W 2 "$PGRE" 2>/dev/null | sed -n 's/.*time=\([0-9.]*\) *ms.*/\1/p' | head -n1)
                    PING_OUT="${GREEN}OK (${RTT}ms to ${PGRE})${NC}"
                else
                    PING_OUT="${RED}FAIL (no reply from ${PGRE})${NC}"
                fi
            fi

            echo -e "\n${CYAN}==========================================================${NC}"
            echo -e "${CYAN}         Tunnel Carrier & Multi-Protocol Failover         ${NC}"
            echo -e "${CYAN}==========================================================${NC}"
            echo -e "Failover Mode:    ${YELLOW}${MODE}${NC} (auto / direct / manual)"
            echo -e "Active Carrier:   ${GREEN}${ACT}${NC}"
            echo -e "FOU Listeners:    UDP ${P1} / UDP ${P2} (Kernel FOU / ipproto 47)"
            echo -e "Tunnel Health:    ${PING_OUT}"
            python3 -c '
import json
try:
    with open("'"$CARRIER_FILE"'") as f:
        d = json.load(f)
    cands = ", ".join(d.get("candidates", []))
    print(f"Candidates:       {cands}")
    print(f"Total Switches:   {d.get(\"switch_count\", 0)}")
    last = d.get("last_switch", "") or "never"
    print(f"Last Switch:      {last}")
except Exception:
    pass
' 2>/dev/null
            echo -e "${CYAN}==========================================================${NC}\n"
            ;;
        mode|set-mode)
            local TARGET="${2:-direct}"
            [[ "$TARGET" == "auto" ]] && TARGET="direct"
            carrier_set_mode "$TARGET"
            echo -e "${GREEN}[✔️] Carrier mode set to: ${TARGET}${NC}"
            carrier_apply "$TARGET"
            echo -e "${GREEN}[✔️] Active carrier applied: ${TARGET}${NC}"
            ;;
        set|set-active|apply)
            local TARGET="${2:-direct}"
            carrier_apply "$TARGET"
            echo -e "${GREEN}[✔️] Switched active carrier to: ${TARGET}${NC}"
            ;;
        next|cycle)
            local NEW_C
            NEW_C=$(carrier_cycle_next)
            echo -e "${GREEN}[✔️] Cycled carrier to: ${NEW_C}${NC}"
            ;;
        set-ports)
            local P1="${2:-443}" P2="${3:-55555}"
            carrier_set_fou_ports "$P1" "$P2"
            carrier_init_kernel
            echo -e "${GREEN}[✔️] FOU ports updated: ${P1} and ${P2}${NC}"
            ;;
        kernel-init)
            carrier_init_kernel
            ;;
        *)
            echo "Usage: hashem carrier [status|mode <direct|fou:PORT>|set <direct|fou:PORT>|next|cycle|set-ports <P1> <P2>]"
            return 1
            ;;
    esac
}

menu_carrier() {
    cli_carrier status
    echo -e "${YELLOW}Select an action:${NC}"
    echo "  1) Force Direct GRE (Raw Protocol 47)"
    echo "  2) Force WSS Obfuscated Carrier (WebSocket over TLS / Port 8443)"
    echo "  3) Cycle to Next Candidate Now"
    echo "  0) Back to Main Menu"
    echo ""
    read -p "Select an option [0-3]: " C_OPT
    case "$C_OPT" in
        1) cli_carrier set direct ;;
        2) cli_carrier set wss:8443 ;;
        3) cli_carrier next ;;
        0) return 0 ;;
        *) echo -e "${RED}[!] Invalid option.${NC}" ;;
    esac
    read -p "Press Enter to return to menu..."
}

pause_prompt() {
    echo ""
    read -p "Press Enter to return to menu..." _dummy
}

setup_backhaul_iran_interactive() {
    echo -e "\n${YELLOW}=== Setup Backhaul Iran Server (No-GRE) ===${NC}"
    local MYIP REMOTE_PUB PORT TOKEN TRANSPORT PORTS
    MYIP=$(ip route get 1.1.1.1 2>/dev/null | awk '/src/ {for (i=1; i<=NF; i++) if ($i=="src") {print $(i+1); exit}}')
    [[ -z "$MYIP" ]] && MYIP=$(curl -sSL --max-time 5 https://api.ipify.org 2>/dev/null)
    prompt_ip LOCAL_PUB "Enter IRAN Server Public IP" "$MYIP"
    prompt_ip REMOTE_PUB "Enter FOREIGN Server Public IP" ""
    prompt_port PORT "Enter Backhaul Server Port" "$(gen_random_port)"
    PORT=$(ensure_port_available "$PORT" "Backhaul Server Port" 0) || return 1
    AUTO_TOKEN=$(gen_token32)
    prompt_token TOKEN "Enter Secret Auth Token" "$AUTO_TOKEN"
    read -p "Transport [tcpmux/ws/wss] (default tcpmux): " TRANSPORT
    TRANSPORT=${TRANSPORT:-tcpmux}
    prompt_ports PORTS "Enter Ports to Reverse-Tunnel (e.g. 443, 2083)"
    setup_backhaul_iran_server_noninteractive "$LOCAL_PUB" "$REMOTE_PUB" "$PORT" "$TOKEN" "$TRANSPORT" "$PORTS"
}

setup_gre_backhaul_iran_interactive() {
    echo -e "\n${YELLOW}=== Setup GRE + Backhaul Iran Server ===${NC}"
    local MYIP REMOTE_PUB PORT TOKEN TRANSPORT PORTS
    MYIP=$(ip route get 1.1.1.1 2>/dev/null | awk '/src/ {for (i=1; i<=NF; i++) if ($i=="src") {print $(i+1); exit}}')
    [[ -z "$MYIP" ]] && MYIP=$(curl -sSL --max-time 5 https://api.ipify.org 2>/dev/null)
    prompt_ip LOCAL_PUB "Enter IRAN Server Public IP" "$MYIP"
    prompt_ip REMOTE_PUB "Enter FOREIGN Server Public IP" ""
    prompt_port PORT "Enter Backhaul Server Port" "$(gen_random_port)"
    PORT=$(ensure_port_available "$PORT" "Backhaul Server Port" 0) || return 1
    AUTO_TOKEN=$(gen_token32)
    prompt_token TOKEN "Enter Secret Auth Token" "$AUTO_TOKEN"
    read -p "Transport [tcpmux/ws/wss] (default tcpmux): " TRANSPORT
    TRANSPORT=${TRANSPORT:-tcpmux}
    prompt_ports PORTS "Enter Ports to Reverse-Tunnel (e.g. 443, 2083)"
    setup_gre_backhaul_iran_server_noninteractive "$LOCAL_PUB" "$REMOTE_PUB" "$PORT" "$TOKEN" "$IRAN_GRE_IP" "$FOREIGN_GRE_IP" "$TRANSPORT" "$PORTS"
}

show_banner() {
    echo -e "${CYAN}"
    cat << 'EOF'
  _    _           _____ _    _ ______ __  __ 
 | |  | |   /\    / ____| |  | |  ____|  \/  |
 | |__| |  /  \  | (___ | |__| | |__  | \  / |
 |  __  | / /\ \  \___ \|  __  |  __| | |\/| |
 | |  | |/ ____ \ ____) | |  | | |____| |  | |
 |_|  |_/_/    \_|_____/|_|  |_|______|_|  |_|
EOF
    echo -e "${NC}"
    echo -e "${CYAN}==============================================================${NC}"
    echo -e "${GREEN}${BOLD}     HASHEM REVERSE TUNNEL & WEB PANEL MANAGER (Iran <-> Int)${NC}"
    echo -e "${CYAN}     Layer 3 GRE / FRP / Backhaul Reverse Relay & Web Panel${NC}"
    echo -e "${CYAN}==============================================================${NC}"
}

menu_tunnel() {
    while true; do
        clear
        show_banner
        echo -e "${CYAN}--- [1] TUNNEL MANAGEMENT ---${NC}"
        echo "  1) Setup IRAN Tunnel (GRE + FRPS / Backhaul Server)"
        echo "  2) Setup FOREIGN Tunnel (via Bundle string or Manual)"
        echo "  3) Add Peer Tunnel (Multi-foreign servers on Iran)"
        echo "  4) List Peers & Show Setup Bundle"
        echo "  5) Edit Peer Tunnel Configuration (Ports, IP, Carrier, Name)"
        echo "  6) Remove a Specific Peer Tunnel"
        echo "  7) Tunnel Health Status & GRE Ping Test"
        echo "  8) Restart All Tunnel Services"
        echo "  9) Teardown All Tunnels (Panel remains active)"
        echo "  0) Back to Main Menu"
        echo ""
        read -p "Select an option [0-9]: " T_OPT
        case "$T_OPT" in
            1)
                echo "Select tunnel protocol for Iran:"
                echo "  1) GRE + FRP Server (Recommended standard)"
                echo "  2) Backhaul Server (No-GRE / TCPMux)"
                echo "  3) GRE + Backhaul Server"
                echo "  4) Modified Backhaul (IPX / ICMP / anytls / xtcpmux / TUN)"
                echo "  0) Cancel"
                read -p "Select [0-4]: " IR_PROTO
                case "$IR_PROTO" in
                    1) setup_iran_server ;;
                    2) setup_backhaul_iran_interactive ;;
                    3) setup_gre_backhaul_iran_interactive ;;
                    4) menu_modified_backhaul ;;
                    *) ;;
                esac
                pause_prompt
                ;;
            2)
                echo "Select setup method for Foreign:"
                echo "  1) Fast Setup via Bundle String (Recommended)"
                echo "  2) Guided Setup (Bundle or Manual GRE/FRP/Backhaul)"
                echo "  0) Cancel"
                read -p "Select [0-2]: " FO_PROTO
                case "$FO_PROTO" in
                    1)
                        read -p "Paste Bundle string (hsh1_... / bh1_... / gh1_...): " BUNDLE_IN
                        if [[ -n "$BUNDLE_IN" ]]; then
                            cli_setup_foreign --bundle "$BUNDLE_IN"
                        fi
                        ;;
                    2) setup_foreign_server ;;
                    *) ;;
                esac
                pause_prompt
                ;;
            3) menu_add_peer; pause_prompt ;;
            4)
                peer_list_pretty
                local IP_IRAN BIND_PORT TOKEN
                IP_IRAN=$(grep -o '"local_public": *"[^"]*"' /etc/gre-panel/panel.json 2>/dev/null | cut -d'"' -f4)
                [[ -z "$IP_IRAN" ]] && IP_IRAN=$(ip route get 1.1.1.1 2>/dev/null | awk '/src/ {for (i=1; i<=NF; i++) if ($i=="src") {print $(i+1); exit}}')
                BIND_PORT=$(awk -F'=' '/bindPort/{gsub(/[ "]/,"",$2); print $2}' /etc/frp/frps.toml 2>/dev/null)
                TOKEN=$(awk -F'=' '/auth\.token/{gsub(/[ "]/,"",$2); print $2}' /etc/frp/frps.toml 2>/dev/null)
                if [[ -n "$IP_IRAN" && -n "$BIND_PORT" && -n "$TOKEN" ]]; then
                    echo -e "\n${GREEN}=== Iran Server Setup Bundle ===${NC}"
                    echo -e "BUNDLE: ${CYAN}$(bundle_make "$IP_IRAN" "$BIND_PORT" "$IRAN_GRE_IP" "$FOREIGN_GRE_IP" "$TOKEN")${NC}\n"
                fi
                pause_prompt
                ;;
            5) menu_edit_peer; pause_prompt ;;
            6) menu_remove_peer; pause_prompt ;;
            7) check_status; pause_prompt ;;
            8) restart_all; pause_prompt ;;
            9) remove_tunnel; pause_prompt ;;
            0) return 0 ;;
            *) echo -e "${RED}[!] Invalid option.${NC}"; sleep 1 ;;
        esac
    done
}

menu_panel() {
    while true; do
        clear
        show_banner
        echo -e "${CYAN}--- [2] WEB PANEL & DOMAIN ---${NC}"
        echo "  1) Show Web Panel URL & Credentials"
        echo "  2) Reset / Change Web Panel Password"
        echo "  3) Setup Domain & Free SSL Certificate (Let's Encrypt)"
        echo "  4) Remove Domain & Reset to Direct IP Access"
        echo "  5) Restart Web Panel Service"
        echo "  6) Reinstall / Repair Web Panel"
        echo "  0) Back to Main Menu"
        echo ""
        read -p "Select an option [0-6]: " P_OPT
        case "$P_OPT" in
            1) show_panel_url; pause_prompt ;;
            2) reset_panel_password; pause_prompt ;;
            3) panel_tls_issue; pause_prompt ;;
            4) panel_tls_remove; pause_prompt ;;
            5)
                echo -e "${CYAN}[*] Restarting Web Panel...${NC}"
                systemctl restart gre-panel 2>/dev/null || true
                show_panel_url
                pause_prompt
                ;;
            6) install_panel_smart; pause_prompt ;;
            0) return 0 ;;
            *) echo -e "${RED}[!] Invalid option.${NC}"; sleep 1 ;;
        esac
    done
}

menu_optimization() {
    while true; do
        clear
        show_banner
        echo -e "${CYAN}--- [3] PERFORMANCE & SECURITY ---${NC}"
        echo "  1) Network Optimization (BBR + sysctl TCP buffers + MTU clamp)"
        echo "  2) Tunnel Carrier Switch (Direct GRE <-> FOU UDP <-> WSS Obfuscated)"
        echo "  3) Tunnel Watchdog & Auto Failover / Telegram Alerts"
        echo "  4) Performance & Encryption Toggles (Proxy crypto/comp, Auto Pool)"
        echo "  5) Free RAM & Cache (Cap journald 16MB + drop cache + 1GB swapfile)"
        echo "  6) Restore Network Tuning (Revert to default sysctl)"
        echo "  0) Back to Main Menu"
        echo ""
        read -p "Select an option [0-6]: " O_OPT
        case "$O_OPT" in
            1) tune_apply; pause_prompt ;;
            2) menu_carrier ;;
            3) menu_watchdog ;;
            4) menu_perf ;;
            5) free_ram; pause_prompt ;;
            6) tune_restore; pause_prompt ;;
            0) return 0 ;;
            *) echo -e "${RED}[!] Invalid option.${NC}"; sleep 1 ;;
        esac
    done
}

menu_diagnostics_backup() {
    while true; do
        clear
        show_banner
        echo -e "${CYAN}--- [4] DIAGNOSTICS & BACKUP ---${NC}"
        echo "  1) Full System & Tunnel Health Check (Doctor audit)"
        echo "  2) Check Listening Ports & Routing Table"
        echo "  3) View Live Logs (journalctl for FRP, Panel & Watchdog)"
        echo "  4) High-Concurrency Connection Stress Test"
        echo "  5) Backup Configurations Now (Encrypted/Dated snapshot)"
        echo "  6) Restore Backup from File"
        echo "  7) Schedule Automated Backup (Interval or Daily)"
        echo "  0) Back to Main Menu"
        echo ""
        read -p "Select an option [0-7]: " D_OPT
        case "$D_OPT" in
            1) doctor_health_check; pause_prompt ;;
            2)
                echo -e "\n${CYAN}=== Listening Ports (FRP, Backhaul & Panel) ===${NC}"
                if command -v ss >/dev/null 2>&1; then
                    ss -tulpn | grep -E "frps|frpc|backhaul|gre-panel|7777" || ss -tulpn | head -15
                else
                    netstat -tulpn 2>/dev/null | grep -E "frps|frpc|backhaul|gre-panel|7777" || true
                fi
                echo -e "\n${CYAN}=== Routing Table & IP Forwarding ===${NC}"
                ip route show
                echo -e "${CYAN}IP Forwarding:${NC} $(sysctl -n net.ipv4.ip_forward 2>/dev/null || cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)"
                pause_prompt
                ;;
            3) show_logs ;;
            4)
                read -p "Target IP/Host [127.0.0.1]: " S_HOST
                S_HOST=${S_HOST:-127.0.0.1}
                read -p "Target Port [7777]: " S_PORT
                S_PORT=${S_PORT:-7777}
                read -p "Concurrent Connections [50]: " S_CONNS
                S_CONNS=${S_CONNS:-50}
                cli_stress_test "$S_HOST" "$S_PORT" "$S_CONNS"
                pause_prompt
                ;;
            5) backup_now; pause_prompt ;;
            6)
                echo -e "\n${CYAN}=== Available Backups ===${NC}"
                cli_backup status
                echo ""
                read -p "Enter full path to backup file to restore: " R_FILE
                if [[ -n "$R_FILE" && -f "$R_FILE" ]]; then
                    backup_restore "$R_FILE"
                else
                    echo -e "${RED}[!] File not found: '$R_FILE'${NC}"
                fi
                pause_prompt
                ;;
            7)
                echo "Schedule backup:"
                echo "  1) Every N hours (e.g. 6)"
                echo "  2) Daily at specific time (e.g. 03:00)"
                echo "  3) Disable automated backup"
                echo "  0) Cancel"
                read -p "Select [0-3]: " B_SCHED
                case "$B_SCHED" in
                    1) read -p "Interval hours [1-168]: " B_H; cli_backup schedule --every "$B_H" ;;
                    2) read -p "Daily time HH:MM (e.g. 03:00): " B_D; cli_backup schedule --daily "$B_D" ;;
                    3) cli_backup schedule --off ;;
                    *) ;;
                esac
                pause_prompt
                ;;
            0) return 0 ;;
            *) echo -e "${RED}[!] Invalid option.${NC}"; sleep 1 ;;
        esac
    done
}

menu_maintenance() {
    while true; do
        clear
        show_banner
        echo -e "${CYAN}--- [5] MAINTENANCE & UPDATE ---${NC}"
        echo "  1) Update All (Latest hashem.sh + latest Web Panel binary; channel: $(update_get_channel), change: hashem update-channel stable|dev)"
        echo "  2) Pre-cache / Verify Core Binaries (FRP, Backhaul, Go Panel)"
        echo "  3) Install / Refresh System Dependencies"
        echo "  4) Check & Load Kernel Modules (GRE & FOU)"
        echo "  5) Show System Version & Tuning Status"
        echo "  0) Back to Main Menu"
        echo ""
        read -p "Select an option [0-5]: " M_OPT
        case "$M_OPT" in
            1)
                backup_configs "pre_update"
                update_all
                doctor_health_check
                pause_prompt
                ;;
            2)
                echo -e "${CYAN}[*] Downloading and pre-caching core binaries...${NC}"
                install_frp_binaries "both" || true
                install_backhaul_binaries "both" || true
                echo -e "${GREEN}[✔️] Core binaries verified and ready in cache.${NC}"
                pause_prompt
                ;;
            3)
                rm -f "$DEPS_MARKER" 2>/dev/null
                ensure_dependencies_smart
                echo -e "${GREEN}[✔️] System dependencies refreshed.${NC}"
                pause_prompt
                ;;
            4)
                echo -e "${CYAN}[*] Ensuring GRE and FOU kernel modules are active...${NC}"
                modprobe ip_gre 2>/dev/null && modprobe fou 2>/dev/null && echo -e "${GREEN}[✔️] Modules ip_gre and fou loaded successfully.${NC}" || echo -e "${YELLOW}[!] Note: Could not load via modprobe (may be built-in).${NC}"
                pause_prompt
                ;;
            5)
                echo -e "\n${CYAN}=== System & Version Info ===${NC}"
                echo "Hashem Script Version: $HASHEM_VERSION"
                echo "Panel Version: $($PANEL_BIN --version 2>/dev/null || echo 'Not installed')"
                tune_status
                pause_prompt
                ;;
            0) return 0 ;;
            *) echo -e "${RED}[!] Invalid option.${NC}"; sleep 1 ;;
        esac
    done
}

menu_uninstall() {
    while true; do
        clear
        show_banner
        echo -e "${RED}--- [6] UNINSTALLATION ---${NC}"
        echo "  1) Uninstall Web Panel Only (Leaves all tunnels active)"
        echo "  2) Remove Tunnel Components Only (Leaves Web Panel active)"
        echo "  3) Full Clean System Wipe (Erases all tunnels, panel, firewall & CLI)"
        echo "  0) Back to Main Menu"
        echo ""
        read -p "Select an option [0-3]: " UN_OPT
        case "$UN_OPT" in
            1)
                read -p "Are you sure you want to uninstall Web Panel? [y/N]: " C_P
                if [[ "$C_P" =~ ^[Yy]$ ]]; then
                    systemctl stop gre-panel 2>/dev/null || true
                    systemctl disable gre-panel 2>/dev/null || true
                    pkill -9 -f "${INSTALL_DIR}/gre-panel" >/dev/null 2>&1 || true
                    rm -f /etc/systemd/system/gre-panel.service /usr/local/bin/gre-panel /usr/local/bin/grepanel
                    rm -rf /etc/gre-panel/tls /var/log/gre-panel*
                    systemctl daemon-reload
                    systemctl reset-failed >/dev/null 2>&1 || true
                    echo -e "${GREEN}[✔️] Web Panel uninstalled successfully.${NC}"
                fi
                pause_prompt
                ;;
            2)
                read -p "Are you sure you want to remove all tunnel components? [y/N]: " C_T
                if [[ "$C_T" =~ ^[Yy]$ ]]; then
                    remove_tunnel_force
                    echo -e "${GREEN}[✔️] All tunnel components removed.${NC}"
                fi
                pause_prompt
                ;;
            3)
                read -p "ARE YOU SURE you want to WIPE EVERYTHING? All configs and services will be deleted! [y/N]: " C_ALL
                if [[ "$C_ALL" =~ ^[Yy]$ ]]; then
                    uninstall_all_force
                    echo -e "${GREEN}[✔️] Complete uninstallation finished.${NC}"
                    exit 0
                fi
                pause_prompt
                ;;
            0) return 0 ;;
            *) echo -e "${RED}[!] Invalid option.${NC}"; sleep 1 ;;
        esac
    done
}

ensure_modified_backhaul_core() {
    mkdir -p "/root/backhaul-core" 2>/dev/null || true
    install_backhaul_binaries
    if [[ -x "${INSTALL_DIR}/backhaul" ]]; then
        cp -f "${INSTALL_DIR}/backhaul" "/root/backhaul-core/backhaul_premium" 2>/dev/null || ln -sf "${INSTALL_DIR}/backhaul" "/root/backhaul-core/backhaul_premium"
        chmod +x "/root/backhaul-core/backhaul_premium" 2>/dev/null || true
    fi
}

menu_modified_backhaul() {
    ensure_modified_backhaul_core
    local SCRIPT_TARGET="/usr/local/bin/hashem-backhaul.sh"
    if [[ ! -f "$SCRIPT_TARGET" ]]; then
        local SCRIPT_DIR
        SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
        if [[ -f "${SCRIPT_DIR}/hashem-backhaul.sh" ]]; then
            cp -f "${SCRIPT_DIR}/hashem-backhaul.sh" "$SCRIPT_TARGET"
        else
            local DL_URL="https://raw.githubusercontent.com/pdnczone/hashem-panel/main/hashem-backhaul.sh"
            download_with_fallback "$SCRIPT_TARGET" "$DL_URL" 30 || true
        fi
        chmod +x "$SCRIPT_TARGET" 2>/dev/null || true
    fi

    if [[ -x "$SCRIPT_TARGET" ]]; then
        bash "$SCRIPT_TARGET" "$@"
    else
        echo -e "${RED}[!] Could not locate or download hashem-backhaul.sh.${NC}"
        pause_prompt
    fi
}

menu_loop() {
    trap 'echo -e "\n\n${CYAN}[*] Exiting Hashem Manager. Goodbye!${NC}"; exit 0' INT
    while true; do
        clear
        show_banner
        echo ""
        echo "MAIN MENU"
        echo "  1) Tunnel Management (GRE + FRP / Multi-Peer)"
        echo "  2) Modified Backhaul (IPX, ICMP, anytls, xtcpmux, TUN)"
        echo "  3) Web Panel & Domain"
        echo "  4) Performance & Security"
        echo "  5) Diagnostics & Backup"
        echo "  6) Maintenance & Update"
        echo "  7) Uninstallation"
        echo "  0) Exit"
        echo ""
        read -p "Select an option [0-7]: " MAIN_OPT
        case "$MAIN_OPT" in
            1) menu_tunnel ;;
            2) menu_modified_backhaul ;;
            3) menu_panel ;;
            4) menu_optimization ;;
            5) menu_diagnostics_backup ;;
            6) menu_maintenance ;;
            7) menu_uninstall ;;
            0|8|exit|q)
                echo -e "${CYAN}Exiting Hashem Manager. Goodbye!${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}[!] Invalid option.${NC}"
                sleep 1
                ;;
        esac
    done
}

main_menu() {
    menu_loop
}

# Non-interactive CLI: hashem.sh setup-iran|setup-foreign with flags.
# The setup_*_noninteractive + _setup_foreign_full functions above are the
# SINGLE source of truth — menu, CLI, and web panel all run the same steps.
usage_cli() {
    cat <<EOF
Usage:
  hashem                                    # first run: auto-install (deps + FRP + panel) & show credentials
                                            # after install: show panel credentials & exit
  hashem menu                               # interactive management menu (all options)
  hashem setup-iran    --local-pub IP --remote-pub IP [--frp-port N] [--local-gre IP] [--peer-gre IP] [--token T] [--force]
  hashem setup-foreign --local-pub IP --remote-pub IP [--frp-port N] --token T --ports "443, 2083" [--local-gre IP] [--peer-gre IP] [--force]
                       # ... or: hashem setup-foreign --bundle hsh1_... / bh1_... / gh1_...
  hashem setup-backhaul-iran    --remote-pub IP --port P [--transport tcpmux] [--token K] [--ports "..."]
  hashem setup-backhaul-foreign --bundle bh1_... | --remote-pub IP --port P --token K [--transport tcpmux]
  hashem setup-gre-backhaul-iran    --remote-pub IP --port P [--transport tcpmux] [--local-gre IP] [--peer-gre IP] [--ports "..."]
  hashem setup-gre-backhaul-foreign --bundle gh1_... | --remote-pub IP --port P --token K [--transport tcpmux]
  hashem add-backhaul-peer      --remote-pub IP --port P --transport T --token K --ports "..." [--no-gre]
  hashem status | remove-tunnel [--force] | show-panel-url | reset-password [new_pass]
  hashem uninstall [--force]                   # full wipe: tunnel + panel + 'hashem' itself
  hashem add-peer --local-pub IP --remote-pub IP [--frp-port N] --token T --local-gre IP --peer-gre IP --ports "443, 2083" [--name LABEL] [--bundle hsh1_...]
  hashem remove-peer --id N [--force] | edit-peer --id N [--name L] [--remote-pub IP] [--carrier C] [--ports "..."] | edit-peer-ports --id N --ports "443, 2083" | peer-list | peer-token --id N
  hashem logs | restart | panel-tls [domain] [email]   # (also: bash hashem.sh ...)
  hashem optimize | restore | tune-status
  hashem carrier [status|mode auto|direct|fou:P|wss:P|set direct|fou:P|wss:P|next] # multi-carrier failover
  hashem dial [status|auto|gre|public]         # foreign side: reach the Iran hub over GRE, its public IP, or auto (GRE if it works)
  hashem perf status|enc on|off|comp on|off|tcpmux on|off|autopool on|off|status|tick|pool|apply
  hashem watchdog on|off|status|test|tick      # tunnel watchdog monitoring & alerts
  hashem backup now [--keep N] | restore <f> | schedule ... | status
  hashem tgsend "msg"                          # send Telegram alert manually
  hashem doctor [server|stop-server|fix]       # full latency, jitter, MTU & speed diagnostics
  hashem stress-test [host] [port] [conns]     # high-concurrency connection stress test (verify zero drops)
  hashem update | update-all                   # update script + panel to the latest release of the update channel
  hashem update-channel [stable|dev]           # show / set update channel (default stable; dev = test builds)
  hashem download-cores                        # download & pre-cache FRP and Backhaul core binaries
  hashem modified-backhaul                     # interactive Modified Backhaul manager (IPX, ICMP, TUN, anytls)
  hashem free-ram                              # cap journald + drop cache + 1GB swap

Setup bundles:
  FRP:              hsh1_<IRAN_PUB>_<FRP_PORT>_<IRAN_GRE>_<FOREIGN_GRE>_<TOKEN>[_<PORTS>]
  Backhaul No-GRE:  bh1_<IRAN_PUB>_<BH_PORT>_<TRANSPORT>_<TOKEN>[_<PORTS>]
  GRE + Backhaul:   gh1_<IRAN_PUB>_<BH_PORT>_<IRAN_GRE>_<FOREIGN_GRE>_<TRANSPORT>_<TOKEN>[_<PORTS>]
  Printed as BUNDLE:... by setup / add-peer; paste it into --bundle (CLI) or panel Foreign token field.
EOF
}


cli_setup_iran() {
    local LOCAL_PUB="" REMOTE_PUB="" FRP_PORT="" LOCAL_GRE="$IRAN_GRE_IP" PEER_GRE="$FOREIGN_GRE_IP" TOKEN="" FORCE=0 PORTS="" FRP_TRANSPORT="tcp"
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --local-pub) LOCAL_PUB="$2"; shift 2 ;;
            --remote-pub) REMOTE_PUB="$2"; shift 2 ;;
            --frp-port) FRP_PORT="$2"; shift 2 ;;
            --local-gre) LOCAL_GRE="$2"; shift 2 ;;
            --peer-gre) PEER_GRE="$2"; shift 2 ;;
            --token) TOKEN="$2"; shift 2 ;;
            --ports) PORTS="$2"; shift 2 ;;
            --frp-transport) FRP_TRANSPORT="$2"; shift 2 ;;
            --force) FORCE=1; shift ;;
            -h|--help) usage_cli; return 0 ;;
            *) echo -e "${RED}[!] Unknown flag: $1${NC}"; usage_cli; return 1 ;;
        esac
    done
    LOCAL_PUB=${LOCAL_PUB:-$(ip route get 1.1.1.1 2>/dev/null | awk '/src/ {for (i=1; i<=NF; i++) if ($i=="src") {print $(i+1); exit}}')}
    [[ -z "$LOCAL_PUB" ]] && LOCAL_PUB=$(curl -sSL --max-time 5 https://api.ipify.org 2>/dev/null)
    FRP_PORT=${FRP_PORT:-$(gen_random_port)}
    validate_setup_common "$LOCAL_PUB" "$REMOTE_PUB" "$FRP_PORT" "$LOCAL_GRE" || return 1
    is_valid_ip "$PEER_GRE" || { echo -e "${RED}[!] Invalid peer GRE IP: '$PEER_GRE'${NC}"; return 1; }
    if [[ -z "$TOKEN" ]]; then
        TOKEN=$(gen_token32)
        echo -e "${CYAN}[*] Generated token: ${TOKEN}${NC}"
    fi
    if tunnel_present && [[ "$FORCE" -ne 1 ]]; then
        echo -e "${RED}[!] Tunnel already exists — pass --force to overwrite.${NC}"
        return 1
    fi
    setup_iran_server_noninteractive "$LOCAL_PUB" "$REMOTE_PUB" "$FRP_PORT" "$TOKEN" "$LOCAL_GRE" "$PEER_GRE" "$PORTS" "$FRP_TRANSPORT"
}

cli_setup_foreign() {
    local LOCAL_PUB="" REMOTE_PUB="" FRP_PORT="" LOCAL_GRE="" PEER_GRE="" TOKEN="" PORTS="" FORCE=0 BUNDLE=""
    local FOREIGN_GRE_DEF="$FOREIGN_GRE_IP" IRAN_GRE_DEF="$IRAN_GRE_IP"
    local RELAY_IP="" PROXY_PROTOCOL="off"
    local FRP_TRANSPORT="tcp" FRP_ENCRYPTION="off" FRP_COMPRESSION="off"
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --local-pub) LOCAL_PUB="$2"; shift 2 ;;
            --remote-pub) REMOTE_PUB="$2"; shift 2 ;;
            --frp-port) FRP_PORT="$2"; shift 2 ;;
            --local-gre) LOCAL_GRE="$2"; shift 2 ;;
            --peer-gre) PEER_GRE="$2"; shift 2 ;;
            --token) TOKEN="$2"; shift 2 ;;
            --ports) PORTS="$2"; shift 2 ;;
            --bundle) BUNDLE="$2"; shift 2 ;;
            --relay-ip) RELAY_IP="$2"; shift 2 ;;
            --proxy-protocol) PROXY_PROTOCOL="$2"; shift 2 ;;
            --frp-transport) FRP_TRANSPORT="$2"; shift 2 ;;
            --encrypt) FRP_ENCRYPTION="on"; shift ;;
            --compress) FRP_COMPRESSION="on"; shift ;;
            --frp-encryption) FRP_ENCRYPTION="$2"; shift 2 ;;
            --frp-compression) FRP_COMPRESSION="$2"; shift 2 ;;
            --dial) FRP_DIAL="$2"; shift 2 ;;
            --force) FORCE=1; shift ;;
            -h|--help) usage_cli; return 0 ;;
            *) echo -e "${RED}[!] Unknown flag: $1${NC}"; usage_cli; return 1 ;;
        esac
    done
    if [[ -n "$BUNDLE" ]]; then
        bundle_parse "$BUNDLE" || { echo -e "${RED}[!] Bad --bundle (want hsh1_<IRAN_PUB>_<PORT>_<IRAN_GRE>_<FOREIGN_GRE>_<TOKEN>[_<PORTS>]).${NC}"; return 1; }
        if [[ "$B_ENGINE" == "backhaul" ]]; then
            cli_setup_backhaul_foreign "$@"
            return $?
        elif [[ "$B_ENGINE" == "gre-backhaul" ]]; then
            cli_setup_gre_backhaul_foreign "$@"
            return $?
        fi
        TOKEN=$B_TOKEN
        REMOTE_PUB=$B_IRAN_PUB
        # Bundle FRP server port is the absolute source of truth
        FRP_PORT=$B_FRP_PORT
        LOCAL_GRE=$B_FOREIGN_GRE
        PEER_GRE=$B_IRAN_GRE
        # B_PORTS may be empty if bundle had no ports segment (e.g. hsh1_...token__fouXXX)
        # Only override PORTS from bundle if not already provided via --ports and bundle has ports
        [[ -z "$PORTS" && -n "$B_PORTS" ]] && PORTS=$B_PORTS
        carrier_set_fou_ports "$B_FOU_P1" "$B_FOU_P2" 2>/dev/null || true
        carrier_init_kernel 2>/dev/null || true
        if [[ -n "$B_TRANSPORT" && "$FRP_TRANSPORT" == "tcp" ]]; then
            FRP_TRANSPORT="$B_TRANSPORT"
        fi
        echo -e "${CYAN}[*] Bundle applied: Source of Truth enforced (Iran ${REMOTE_PUB}, FRP port ${FRP_PORT}, transport ${FRP_TRANSPORT}).${NC}"
    fi
    # --bundle replaces --token as the required secret
    [[ -z "$TOKEN" && -n "$BUNDLE" ]] && TOKEN=$B_TOKEN
    LOCAL_PUB=${LOCAL_PUB:-$(ip route get 1.1.1.1 2>/dev/null | awk '/src/ {for (i=1; i<=NF; i++) if ($i=="src") {print $(i+1); exit}}')}
    [[ -z "$LOCAL_PUB" ]] && LOCAL_PUB=$(curl -sSL --max-time 5 https://api.ipify.org 2>/dev/null)
    FRP_PORT=${FRP_PORT:-$(gen_random_port)}
    LOCAL_GRE=${LOCAL_GRE:-$FOREIGN_GRE_DEF}
    PEER_GRE=${PEER_GRE:-$IRAN_GRE_DEF}
    validate_setup_common "$LOCAL_PUB" "$REMOTE_PUB" "$FRP_PORT" "$LOCAL_GRE" || return 1
    is_valid_ip "$PEER_GRE" || { echo -e "${RED}[!] Invalid peer GRE IP: '$PEER_GRE'${NC}"; return 1; }
    [[ -n "$TOKEN" ]] || { echo -e "${RED}[!] --token is required (copy it from the Iran side).${NC}"; return 1; }
    local CLEANED="" p
    for p in $(echo "$PORTS" | tr ',' ' '); do
        is_valid_port "$p" && CLEANED="$CLEANED $((10#$p))"
    done
    CLEANED=$(echo "$CLEANED" | xargs)
    if [[ -z "$CLEANED" ]]; then
        # Bundle had empty ports segment — non-interactive path cannot prompt;
        # the panel must always pass --ports explicitly when bundle has none.
        echo -e "${RED}[!] --ports needs at least one valid port (e.g. \"443, 2083\"). The bundle did not include ports — pass --ports explicitly.${NC}"
        return 1
    fi

    # Port availability check.
    FRP_PORT=$(ensure_port_available "$FRP_PORT" "FRP Control Port" ${BUNDLE:+1}) || return 1

    case "$FRP_TRANSPORT" in
        tcp|kcp|quic|websocket|wss) ;;
        *) echo -e "${YELLOW}[!] Unknown FRP transport '${FRP_TRANSPORT}', defaulting to tcp.${NC}"; FRP_TRANSPORT="tcp" ;;
    esac

    if tunnel_present && [[ "$FORCE" -ne 1 ]]; then
        echo -e "${RED}[!] Tunnel already exists — pass --force to overwrite.${NC}"
        return 1
    fi
    setup_foreign_server_noninteractive "$LOCAL_PUB" "$REMOTE_PUB" "$FRP_PORT" "$TOKEN" "$LOCAL_GRE" "$PEER_GRE" "$CLEANED" "$RELAY_IP" "$PROXY_PROTOCOL" "$FRP_TRANSPORT" "$FRP_ENCRYPTION" "$FRP_COMPRESSION"
}

cli_setup_backhaul_iran() {
    local LOCAL_PUB="" REMOTE_PUB="" PORT="" TRANSPORT="tcpmux" TOKEN="" PORTS="" FORCE=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --local-pub) LOCAL_PUB="$2"; shift 2 ;;
            --remote-pub) REMOTE_PUB="$2"; shift 2 ;;
            --port) PORT="$2"; shift 2 ;;
            --transport) TRANSPORT="$2"; shift 2 ;;
            --token) TOKEN="$2"; shift 2 ;;
            --ports) PORTS="$2"; shift 2 ;;
            --force) FORCE=1; shift ;;
            -h|--help) echo 'Usage: hashem setup-backhaul-iran [--local-pub IP] [--remote-pub IP] --port P [--transport T] [--token K] [--ports "..."]'; return 0 ;;
            *) echo -e "${RED}[!] Unknown flag: $1${NC}"; return 1 ;;
        esac
    done
    LOCAL_PUB=${LOCAL_PUB:-$(ip route get 1.1.1.1 2>/dev/null | awk '/src/ {for (i=1; i<=NF; i++) if ($i=="src") {print $(i+1); exit}}')}
    [[ -z "$LOCAL_PUB" ]] && LOCAL_PUB=$(curl -sSL --max-time 5 https://api.ipify.org 2>/dev/null)
    PORT=${PORT:-$(gen_random_port)}
    is_valid_ip "$LOCAL_PUB" || { echo -e "${RED}[!] Invalid local IP: '$LOCAL_PUB'${NC}"; return 1; }
    is_valid_port "$PORT" || { echo -e "${RED}[!] Invalid port: '$PORT'${NC}"; return 1; }
    if [[ -z "$TOKEN" ]]; then
        TOKEN=$(gen_token32)
        echo -e "${CYAN}[*] Generated token: ${TOKEN}${NC}"
    fi
    if [[ "$FORCE" -ne 1 ]] && systemctl is-active --quiet backhaul-server 2>/dev/null; then
        echo -e "${RED}[!] Backhaul server already active — pass --force to overwrite.${NC}"
        return 1
    fi
    setup_backhaul_iran_server_noninteractive "$LOCAL_PUB" "$REMOTE_PUB" "$PORT" "$TOKEN" "$TRANSPORT" "$PORTS"
}

cli_setup_backhaul_foreign() {
    local LOCAL_PUB="" REMOTE_PUB="" PORT="" TRANSPORT="tcpmux" TOKEN="" BUNDLE="" FORCE=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --local-pub) LOCAL_PUB="$2"; shift 2 ;;
            --remote-pub) REMOTE_PUB="$2"; shift 2 ;;
            --port) PORT="$2"; shift 2 ;;
            --transport) TRANSPORT="$2"; shift 2 ;;
            --token) TOKEN="$2"; shift 2 ;;
            --bundle) BUNDLE="$2"; shift 2 ;;
            --force) FORCE=1; shift ;;
            -h|--help) echo 'Usage: hashem setup-backhaul-foreign --remote-pub IP --port P --token K [--transport T] | --bundle bh1_...'; return 0 ;;
            *) echo -e "${RED}[!] Unknown flag: $1${NC}"; return 1 ;;
        esac
    done
    if [[ -n "$BUNDLE" ]]; then
        bundle_parse "$BUNDLE" || { echo -e "${RED}[!] Bad bundle: $BUNDLE${NC}"; return 1; }
        REMOTE_PUB=$B_IRAN_PUB
        PORT=$B_FRP_PORT
        TRANSPORT=$B_TRANSPORT
        TOKEN=$B_TOKEN
    fi
    [[ -z "$TOKEN" && -n "$BUNDLE" ]] && TOKEN=$B_TOKEN
    LOCAL_PUB=${LOCAL_PUB:-$(ip route get 1.1.1.1 2>/dev/null | awk '/src/ {for (i=1; i<=NF; i++) if ($i=="src") {print $(i+1); exit}}')}
    [[ -z "$LOCAL_PUB" ]] && LOCAL_PUB=$(curl -sSL --max-time 5 https://api.ipify.org 2>/dev/null)
    is_valid_ip "$REMOTE_PUB" || { echo -e "${RED}[!] Invalid remote public IP: '$REMOTE_PUB'${NC}"; return 1; }
    is_valid_port "$PORT" || { echo -e "${RED}[!] Invalid port: '$PORT'${NC}"; return 1; }
    [[ -n "$TOKEN" ]] || { echo -e "${RED}[!] --token or --bundle is required.${NC}"; return 1; }
    if [[ "$FORCE" -ne 1 ]] && systemctl is-active --quiet backhaul-client 2>/dev/null; then
        echo -e "${RED}[!] Backhaul client already active — pass --force to overwrite.${NC}"
        return 1
    fi
    setup_backhaul_foreign_server_noninteractive "$LOCAL_PUB" "$REMOTE_PUB" "$PORT" "$TOKEN" "$TRANSPORT"
}

cli_setup_gre_backhaul_iran() {
    local LOCAL_PUB="" REMOTE_PUB="" PORT="" LOCAL_GRE="$IRAN_GRE_IP" PEER_GRE="$FOREIGN_GRE_IP" TRANSPORT="tcpmux" TOKEN="" PORTS="" FORCE=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --local-pub) LOCAL_PUB="$2"; shift 2 ;;
            --remote-pub) REMOTE_PUB="$2"; shift 2 ;;
            --port) PORT="$2"; shift 2 ;;
            --local-gre) LOCAL_GRE="$2"; shift 2 ;;
            --peer-gre) PEER_GRE="$2"; shift 2 ;;
            --transport) TRANSPORT="$2"; shift 2 ;;
            --token) TOKEN="$2"; shift 2 ;;
            --ports) PORTS="$2"; shift 2 ;;
            --force) FORCE=1; shift ;;
            -h|--help) echo 'Usage: hashem setup-gre-backhaul-iran --remote-pub IP [--port P] [--transport T] [--local-gre IP] [--peer-gre IP]'; return 0 ;;
            *) echo -e "${RED}[!] Unknown flag: $1${NC}"; return 1 ;;
        esac
    done
    LOCAL_PUB=${LOCAL_PUB:-$(ip route get 1.1.1.1 2>/dev/null | awk '/src/ {for (i=1; i<=NF; i++) if ($i=="src") {print $(i+1); exit}}')}
    [[ -z "$LOCAL_PUB" ]] && LOCAL_PUB=$(curl -sSL --max-time 5 https://api.ipify.org 2>/dev/null)
    PORT=${PORT:-$(gen_random_port)}
    validate_setup_common "$LOCAL_PUB" "$REMOTE_PUB" "$PORT" "$LOCAL_GRE" || return 1
    is_valid_ip "$PEER_GRE" || { echo -e "${RED}[!] Invalid peer GRE IP: '$PEER_GRE'${NC}"; return 1; }
    if [[ -z "$TOKEN" ]]; then
        TOKEN=$(gen_token32)
        echo -e "${CYAN}[*] Generated token: ${TOKEN}${NC}"
    fi
    if tunnel_present && [[ "$FORCE" -ne 1 ]]; then
        echo -e "${RED}[!] Tunnel already exists — pass --force to overwrite.${NC}"
        return 1
    fi
    setup_gre_backhaul_iran_server_noninteractive "$LOCAL_PUB" "$REMOTE_PUB" "$PORT" "$TOKEN" "$LOCAL_GRE" "$PEER_GRE" "$TRANSPORT" "$PORTS"
}

cli_setup_gre_backhaul_foreign() {
    local LOCAL_PUB="" REMOTE_PUB="" PORT="" LOCAL_GRE="" PEER_GRE="" TRANSPORT="tcpmux" TOKEN="" BUNDLE="" FORCE=0
    local FOREIGN_GRE_DEF="$FOREIGN_GRE_IP" IRAN_GRE_DEF="$IRAN_GRE_IP"
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --local-pub) LOCAL_PUB="$2"; shift 2 ;;
            --remote-pub) REMOTE_PUB="$2"; shift 2 ;;
            --port) PORT="$2"; shift 2 ;;
            --local-gre) LOCAL_GRE="$2"; shift 2 ;;
            --peer-gre) PEER_GRE="$2"; shift 2 ;;
            --transport) TRANSPORT="$2"; shift 2 ;;
            --token) TOKEN="$2"; shift 2 ;;
            --bundle) BUNDLE="$2"; shift 2 ;;
            --dial) FRP_DIAL="$2"; shift 2 ;;
            --force) FORCE=1; shift ;;
            -h|--help) echo 'Usage: hashem setup-gre-backhaul-foreign --bundle gh1_... | --remote-pub IP --port P --token K'; return 0 ;;
            *) echo -e "${RED}[!] Unknown flag: $1${NC}"; return 1 ;;
        esac
    done
    if [[ -n "$BUNDLE" ]]; then
        bundle_parse "$BUNDLE" || { echo -e "${RED}[!] Bad bundle: $BUNDLE${NC}"; return 1; }
        TOKEN=$B_TOKEN
        REMOTE_PUB=$B_IRAN_PUB
        PORT=$B_FRP_PORT
        LOCAL_GRE=$B_FOREIGN_GRE
        PEER_GRE=$B_IRAN_GRE
        TRANSPORT=$B_TRANSPORT
    fi
    [[ -z "$TOKEN" && -n "$BUNDLE" ]] && TOKEN=$B_TOKEN
    LOCAL_PUB=${LOCAL_PUB:-$(ip route get 1.1.1.1 2>/dev/null | awk '/src/ {for (i=1; i<=NF; i++) if ($i=="src") {print $(i+1); exit}}')}
    [[ -z "$LOCAL_PUB" ]] && LOCAL_PUB=$(curl -sSL --max-time 5 https://api.ipify.org 2>/dev/null)
    LOCAL_GRE=${LOCAL_GRE:-$FOREIGN_GRE_DEF}
    PEER_GRE=${PEER_GRE:-$IRAN_GRE_DEF}
    validate_setup_common "$LOCAL_PUB" "$REMOTE_PUB" "$PORT" "$LOCAL_GRE" || return 1
    is_valid_ip "$PEER_GRE" || { echo -e "${RED}[!] Invalid peer GRE IP: '$PEER_GRE'${NC}"; return 1; }
    [[ -n "$TOKEN" ]] || { echo -e "${RED}[!] --token or --bundle is required.${NC}"; return 1; }
    if tunnel_present && [[ "$FORCE" -ne 1 ]]; then
        echo -e "${RED}[!] Tunnel already exists — pass --force to overwrite.${NC}"
        return 1
    fi
    setup_gre_backhaul_foreign_server_noninteractive "$LOCAL_PUB" "$REMOTE_PUB" "$PORT" "$TOKEN" "$LOCAL_GRE" "$PEER_GRE" "$TRANSPORT"
}

# ---- Auto-install: first-run installs everything, shows credentials, exits ----
auto_install_and_show() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                                                              ║${NC}"
    echo -e "${CYAN}║${NC}   ${GREEN}██╗  ██╗ █████╗ ███████╗██╗  ██╗███████╗███╗   ███╗${NC}       ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   ${GREEN}██║  ██║██╔══██╗██╔════╝██║  ██║██╔════╝████╗ ████║${NC}       ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   ${GREEN}███████║███████║███████╗███████║█████╗  ██╔████╔██║${NC}       ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   ${GREEN}██╔══██║██╔══██║╚════██║██╔══██║██╔══╝  ██║╚██╔╝██║${NC}       ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   ${GREEN}██║  ██║██║  ██║███████║██║  ██║███████╗██║ ╚═╝ ██║${NC}       ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   ${GREEN}╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝${NC}       ${CYAN}║${NC}"
    echo -e "${CYAN}║                                                              ║${NC}"
    echo -e "${CYAN}║${NC}        ${YELLOW}GRE + FRP Reverse Tunnel — Auto Installer${NC}             ${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    echo -e "${CYAN}[1/3]${NC} ${GREEN}Installing system dependencies...${NC}"
    ensure_dependencies_smart

    echo ""
    echo -e "${CYAN}[2/3]${NC} ${GREEN}Installing FRP binaries (frps + frpc)...${NC}"
    install_frp_binaries

    echo ""
    echo -e "${CYAN}[3/3]${NC} ${GREEN}Installing Hashem Web Panel...${NC}"
    install_panel

    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║              ${GREEN}✔  INSTALLATION COMPLETE${NC}                       ${CYAN}║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════════════╣${NC}"
    show_panel_url
    echo -e "${CYAN}╠══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC}  ${YELLOW}Next steps:${NC}                                                ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  • Open the panel URL above in your browser                ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  • Login and setup your tunnel from the web panel           ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  • Run ${GREEN}hashem${NC} for the interactive management menu          ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  • Run ${GREEN}hashem --help${NC} for CLI commands                      ${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${GREEN}${BOLD}DNC MADE THIS${NC}"
    echo ""
}

# ---- show_credentials_and_exit: pretty credentials banner for already-installed panel ----
show_credentials_and_exit() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║              ${GREEN}✔  HASHEM PANEL IS RUNNING${NC}                      ${CYAN}║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════════════╣${NC}"
    show_panel_url
    echo -e "${CYAN}╠══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC}  • Run ${GREEN}hashem${NC} for the interactive management menu          ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  • Run ${GREEN}hashem --help${NC} for CLI commands                      ${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${GREEN}${BOLD}DNC MADE THIS${NC}"
    echo ""
}

cli_carrier() {
    local SUB="${1:-status}"
    case "$SUB" in
        set|apply)
            shift
            if [[ -n "${1:-}" ]]; then
                carrier_apply "$1"
            else
                echo -e "${RED}[!] Usage: hashem carrier set <mode>${NC}"
                return 1
            fi
            ;;
        cycle)
            carrier_cycle_next
            ;;
        set-ports)
            shift
            carrier_set_fou_ports "${1:-443}" "${2:-55555}"
            ;;
        init)
            carrier_init_kernel
            ;;
        status|*)
            echo "Active Carrier: $(carrier_get_active)"
            echo "Mode: $(carrier_get_mode)"
            ;;
    esac
}

if [[ $# -gt 0 ]]; then
    case "$1" in
        -h|--help|help) usage_cli; exit 0 ;;
        bundle)
            shift
            case "${1:-}" in
                inspect) shift; cli_bundle_inspect "$@" ;;
                *) echo "Usage: hashem bundle inspect <bundle> [--show-token]"; exit 1 ;;
            esac
            exit $?
            ;;
    esac

    check_root
    case "$1" in
        menu) main_menu ;;
        setup-iran) shift; cli_setup_iran "$@" ;;
        setup-foreign) shift; cli_setup_foreign "$@" ;;
        setup-backhaul-iran) shift; cli_setup_backhaul_iran "$@" ;;
        setup-backhaul-foreign) shift; cli_setup_backhaul_foreign "$@" ;;
        setup-gre-backhaul-iran) shift; cli_setup_gre_backhaul_iran "$@" ;;
        setup-gre-backhaul-foreign) shift; cli_setup_gre_backhaul_foreign "$@" ;;
        add-peer) shift; cli_add_peer "$@" ;;
        add-backhaul-peer) shift; cli_add_backhaul_peer "$@" ;;
        remove-peer) shift; cli_remove_peer "$@" ;;
        edit-peer) shift; cli_edit_peer "$@" ;;
        edit-peer-ports) shift; cli_edit_peer_ports "$@" ;;
        peer-list) peer_list ;;
        logs) show_logs ;;
        restart) restart_all ;;
        restart-lite|tunnel-restart-lite) restart_all_lite; echo -e "${GREEN}[✔️] Tunnel services restarted successfully.${NC}" ;;
        perf) shift; cli_perf "$@" ;;
        watchdog) shift; cli_watchdog "$@" ;;
        backup) shift; cli_backup "$@" ;;
        tgsend) shift; watchdog_send "$1" ;;
        update|update-all) update_all ;;
        update-channel) shift; cli_update_channel "$@" ;;
        cleanup-legacy) remove_legacy_units ;;
        peer-token)
            shift; ID=""
            while [[ $# -gt 0 ]]; do case "$1" in --id) ID="$2"; shift 2 ;; *) shift ;; esac; done
            peer_token "$ID" ;;
        status) check_status ;;
        panel-limits) shift; cli_panel_limits "$@" ;;
        doctor|test|diagnose) shift; cli_doctor "$@" ;;
        stress-test|test-load|stress) shift; cli_stress_test "$@" ;;
        panel-tls) shift; panel_tls_issue "$@" ;;
        panel-remove-domain|panel-tls-remove) panel_tls_remove ;;
        carrier) shift; cli_carrier "$@" ;;
        carrier-kernel-init) carrier_init_kernel ;;
        dial) shift; cli_dial "$@" ;;
        dial-select) dial_reselect >/dev/null 2>&1; exit 0 ;;
        carrier-apply-active) shift; carrier_apply_active "$1" ;;
        optimize) tune_apply ;;
        restore) tune_restore ;;
        tune-status) tune_status ;;
        free-ram|optimize-ram) free_ram ;;
        download-cores|cores)
            echo -e "${CYAN}[*] Downloading and verifying core binaries from pdnczone repository...${NC}"
            install_frp_binaries "all" || { echo -e "${RED}[!] Failed to install FRP binaries.${NC}"; exit 1; }
            install_backhaul_binaries || { echo -e "${RED}[!] Failed to install Backhaul binary.${NC}"; exit 1; }
            echo -e "${GREEN}[✔️] All core binaries (frps, frpc, backhaul) are cached in ${INSTALL_DIR}.${NC}"
            ;;
        modified-backhaul|backhaul-premium|mbh)
            shift
            menu_modified_backhaul "$@"
            ;;
        remove-tunnel)
            if [[ "${2:-}" == "--force" ]]; then remove_tunnel_force; else remove_tunnel; fi ;;
        uninstall)
            if [[ "${2:-}" == "--force" ]]; then uninstall_all_force; else uninstall_all; fi ;;
        show-panel-url) show_panel_url ;;
        password|reset-password|reset-pass)
            shift
            if [[ -n "${1:-}" ]]; then
                cli_set_panel_password "$1"
            else
                reset_panel_password
            fi
            ;;
        *) echo -e "${RED}[!] Unknown command: $1${NC}"; usage_cli; exit 1 ;;
    esac
    exit $?
fi

# ---- No arguments: first-run auto-install OR interactive menu ----
check_root

PANEL_STATUS=$(get_component_status panel)
case "$PANEL_STATUS" in
    NOT_INSTALLED)
        # First run: auto-install everything and show credentials
        auto_install_and_show
        exit 0
        ;;
    RUNNING)
        # Already installed and healthy — show credentials and exit
        show_credentials_and_exit
        exit 0
        ;;
    STOPPED)
        # Installed but stopped — start it, show credentials, exit
        echo -e "${YELLOW}[*] Panel is installed but stopped. Starting...${NC}"
        systemctl start gre-panel 2>/dev/null || true
        sleep 2
        if systemctl is-active --quiet gre-panel 2>/dev/null; then
            show_credentials_and_exit
            exit 0
        else
            echo -e "${RED}[!] Failed to start panel — entering interactive menu for troubleshooting.${NC}"
            main_menu
        fi
        ;;
    BROKEN)
        # Broken panel — let user repair interactively
        echo -e "${RED}[!] Panel is installed but BROKEN / UNHEALTHY.${NC}"
        echo "Options:"
        echo "  1) Repair (reset-failed & restart service)"
        echo "  2) Reinstall (clean download & install)"
        echo "  3) Enter interactive menu"
        read -p "Select option [1-3]: " BROKEN_OPT
        case "$BROKEN_OPT" in
            1)
                echo -e "${CYAN}[*] Attempting repair...${NC}"
                systemctl reset-failed gre-panel >/dev/null 2>&1 || true
                systemctl restart gre-panel >/dev/null 2>&1 || true
                sleep 2
                if systemctl is-active --quiet gre-panel; then
                    echo -e "${GREEN}[✔️] Panel repaired and running!${NC}"
                    show_credentials_and_exit
                    exit 0
                else
                    echo -e "${RED}[!] Repair failed. Reinstalling...${NC}"
                    backup_configs "panel_broken"
                    auto_install_and_show
                    exit 0
                fi
                ;;
            2)
                backup_configs "panel_reinstall"
                auto_install_and_show
                exit 0
                ;;
            3|*)
                main_menu
                ;;
        esac
        ;;
    *)
        # Unknown state — fall back to interactive menu
        main_menu
        ;;
esac

