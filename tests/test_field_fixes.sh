#!/usr/bin/env bash
# Fixes for what a busy hub (one Iran server, four foreign servers, 20k+
# connections) showed in the field: the frp log level, the journal cap,
# StartLimit in [Unit], the Go memory limit of frps/frpc, RAM-scaled socket
# buffers and RPS, one TCPMSS rule, a Watchdog restart that leaves working
# GRE interfaces alone, the Auto Pool ceiling and the cleanup after a peer
# is removed. Isolated dirs and fake commands: no live state is touched.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin" "$T/frp" "$T/panel" "$T/units" "$T/sys"
export PANEL_CONFIG_DIR="$T/panel" CONFIG_DIR="$T/frp" PERF_FILE="$T/panel/perf.json"
export AUTO_POOL_STATE="$T/panel/auto_pool.json" HASHEM_SYSTEMD_DIR="$T/units" HASHEM_SYS_NET="$T/sys"
export HASHEM_JOURNALD_DIR="$T/journald.conf.d" TUNNEL_NAME=gre-tunnel HASHEM_BIN=/usr/local/bin/hashem
unset PERF_AUTO_POOL

{
  echo 'RED= GREEN= CYAN= YELLOW= NC='
  grep -E '^AUTOPOOL_[A-Z_]+=' "$ROOT/hashem.sh"
  for fn in perf_get_str perf_get_int perf_get_auto_pool frp_log_level frp_log_lines frp_log_level_apply \
            pool_clamp pool_ram_cap pool_max_cap autopool_state_get pool_effective_values \
            unit_start_limit_fix unit_env_default frp_go_mem_for_ram frp_unit_env_lines frp_units_refresh \
            journald_cap_apply tune_scale_values net_default_iface rps_cpu_mask net_queues_apply \
            net_queues_persist net_queues_remove gre_path_mtu gre_mss mss_clamp_set \
            gre_if_peer gre_if_healthy restart_all_lite tunnel_link_forget; do
    awk -v f="$fn" '$0 ~ "^"f"\\(\\) \\{" {p=1} p {print} p && /^}/ {p=0}' "$ROOT/hashem.sh"
  done
} > "$T/fn.sh"
# shellcheck disable=SC1091
source "$T/fn.sh"

fail=0
chk() { [[ "$2" == "$3" ]] || { echo "FAIL $1: got '$2' want '$3'"; fail=1; }; }
has() { grep -qF -- "$2" "$1" || { echo "FAIL $3: '$2' not in $1"; fail=1; }; }
section() { awk -v s="[$2]" '$0 == s {p=1; next} /^\[/ {p=0} p' "$1"; }

# ---- fakes ----
cat > "$T/bin/systemctl" <<EOF
#!/usr/bin/env bash
echo "\$*" >> "$T/systemctl.log"
case "\$1" in
  is-failed) grep -qxF "\${@: -1}" "$T/failed" 2>/dev/null ;;
  list-unit-files) exit 0 ;;
esac
EOF
cat > "$T/bin/ip" <<EOF
#!/usr/bin/env bash
echo "\$*" >> "$T/ip.log"
case "\$*" in
  "-4 route show default") cat "$T/route" 2>/dev/null ;;
  "-4 -o addr show dev "*) cat "$T/addr.\${@: -1}" 2>/dev/null ;;
  "link show "*) [[ -e "$T/sys/\${@: -1}" ]] ;;
esac
EOF
cat > "$T/bin/ping" <<EOF
#!/usr/bin/env bash
grep -qxF "\${@: -1}" "$T/pingok" 2>/dev/null
EOF
printf '#!/bin/sh\ncat "%s/nproc"\n' "$T" > "$T/bin/nproc"
# iptables: the mangle table kept as \`iptables -S\` lines in $T/rules
cat > "$T/bin/iptables" <<EOF
#!/usr/bin/env bash
R="$T/rules"; touch "\$R"
[[ "\$1" == "-t" ]] && shift 2
op="\$1"; chain="\$2"; shift 2
if [[ "\$op" == "-S" ]]; then grep -E "^-A \$chain " "\$R"; exit 0; fi
out=""; mss=""
while [[ \$# -gt 0 ]]; do
  case "\$1" in
    -o) out=" -o \$2"; shift 2 ;;
    --set-mss) mss="\$2"; shift 2 ;;
    *) shift ;;
  esac
done
line="-A \$chain\$out -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss \$mss"
case "\$op" in
  -C) grep -qxF -- "\$line" "\$R" ;;
  -A) echo "\$line" >> "\$R" ;;
  -D) grep -qxF -- "\$line" "\$R" || exit 1
      awk -v l="\$line" '\$0 == l && !d {d = 1; next} {print}' "\$R" > "\$R.tmp" && mv "\$R.tmp" "\$R" ;;
esac
EOF
chmod +x "$T/bin"/*
export PATH="$T/bin:$PATH"

# ============ 1. frp log level ============
chk "log level default" "$(frp_log_level)" "warn"
chk "log lines" "$(frp_log_lines)" $'log.to = "console"\nlog.level = "warn"'
echo '{"frp_log_level": "info"}' > "$PERF_FILE"; chk "log level explicit" "$(frp_log_level)" "info"
echo '{"frp_log_level": "shout"}' > "$PERF_FILE"; chk "log level invalid" "$(frp_log_level)" "warn"
rm -f "$PERF_FILE"

printf 'bindPort = 7000\nauth.token = "x"\n' > "$T/frp/frps.toml"
printf 'bindPort = 7001\nlog.level = "debug"\n' > "$T/frp/frps-2.toml"
printf 'serverPort = 7000\n\n[[proxies]]\nname = "a"\nremotePort = 443\n' > "$T/frp/frpc.toml"
chk "log level apply count" "$(frp_log_level_apply)" "2"
has "$T/frp/frps.toml" 'log.level = "warn"' "frps.toml gets warn"
has "$T/frp/frps-2.toml" 'log.level = "debug"' "explicit level kept"
chk "explicit level not doubled" "$(grep -c 'log.level' "$T/frp/frps-2.toml")" "1"
chk "frpc: level is above the first proxy" "$(awk '/log.level/ {l=NR} /^\[\[proxies\]\]/ {p=NR} END {print (l > 0 && l < p)}' "$T/frp/frpc.toml")" "1"
chk "frpc: proxy block intact" "$(tail -n 3 "$T/frp/frpc.toml" | tr '\n' '|')" '[[proxies]]|name = "a"|remotePort = 443|'
chk "log level apply twice" "$(frp_log_level_apply)" "0"
rm -f "$T/frp"/*.toml

# every frps/frpc config hashem.sh writes carries the log lines
chk "frp heredocs with a log level" "$(grep -c '^\$(frp_log_lines)$' "$ROOT/hashem.sh")" "3"

# ============ 2. units: StartLimit in [Unit], Go memory limit ============
U="$T/units/frps.service"
mkunit() { cat > "$1" <<'EOF'
[Unit]
Description=FRP Server Service
After=network.target

[Service]
Type=simple
Restart=always
RestartSec=10s
StartLimitIntervalSec=60s
StartLimitBurst=5
ExecStart=/usr/local/bin/frps -c /etc/frp/frps.toml

[Install]
WantedBy=multi-user.target
EOF
}
mkunit "$U"
unit_start_limit_fix "$U"
chk "no StartLimit in [Service]" "$(section "$U" Service | grep -c StartLimit)" "0"
chk "StartLimitIntervalSec=0 in [Unit]" "$(section "$U" Unit | grep -c '^StartLimitIntervalSec=0$')" "1"
unit_start_limit_fix "$U"
chk "start limit fix is idempotent" "$(grep -c StartLimit "$U")" "1"
has "$U" "ExecStart=/usr/local/bin/frps -c /etc/frp/frps.toml" "unit body kept"

unit_env_default "$U" GOMEMLIMIT 900MiB; unit_env_default "$U" GOMEMLIMIT 2500MiB
chk "env default once, first value kept" "$(grep '^Environment=GOMEMLIMIT=' "$U")" "Environment=GOMEMLIMIT=900MiB"
chk "env is under [Service]" "$(section "$U" Service | grep -c '^Environment=GOMEMLIMIT=900MiB$')" "1"

chk "mem 1GB"  "$(frp_go_mem_for_ram 1024)"  "300MiB 40"
chk "mem 2GB"  "$(frp_go_mem_for_ram 2048)"  "500MiB 40"
chk "mem 4GB"  "$(frp_go_mem_for_ram 3900)"  "900MiB 40"
chk "mem 6GB"  "$(frp_go_mem_for_ram 5900)"  "1400MiB 45"
chk "mem 8GB"  "$(frp_go_mem_for_ram 7900)"  "1800MiB 50"
chk "mem 16GB" "$(frp_go_mem_for_ram 15900)" "2500MiB 50"
chk "mem 32GB" "$(frp_go_mem_for_ram 32000)" "4000MiB 50"
[[ "$(frp_unit_env_lines)" =~ ^Environment=GOMEMLIMIT=[0-9]+MiB$'\n'Environment=GOGC=(40|45|50)$ ]] || { echo "FAIL env lines shape: $(frp_unit_env_lines)"; fail=1; }

rm -f "$T/units"/*; : > "$T/systemctl.log"
for n in frps frps-2 frpc gre-tunnel; do mkunit "$T/units/$n.service"; done
frp_units_refresh
for n in frps frps-2 frpc; do
  chk "$n: StartLimit moved" "$(section "$T/units/$n.service" Service | grep -c StartLimit)$(section "$T/units/$n.service" Unit | grep -c '^StartLimitIntervalSec=0$')" "01"
  chk "$n: GOMEMLIMIT set" "$(grep -c '^Environment=GOMEMLIMIT=[0-9]*MiB$' "$T/units/$n.service")" "1"
  chk "$n: GOGC set" "$(grep -cE '^Environment=GOGC=(40|45|50)$' "$T/units/$n.service")" "1"
done
chk "other units untouched" "$(grep -c 'StartLimitIntervalSec=60s' "$T/units/gre-tunnel.service")" "1"
chk "refresh reloads systemd, restarts nothing" "$(sort -u "$T/systemctl.log")" "daemon-reload"
rm -f "$T/units"/*

# in hashem.sh itself no StartLimit line sits under [Service] any more
chk "hashem.sh: StartLimit only in [Unit]" "$(awk '/^\[(Unit|Service|Install)\]/ {s=$0} /^StartLimit(IntervalSec|Burst)=/ && s != "[Unit]" {n++} END {print n+0}' "$ROOT/hashem.sh")" "0"
chk "hashem.sh: the three frp units get the Go memory lines" "$(grep -c '^\$(frp_unit_env_lines)$' "$ROOT/hashem.sh")" "3"

# ============ 3. journal cap ============
: > "$T/systemctl.log"
journald_cap_apply
J="$HASHEM_JOURNALD_DIR/99-hashem.conf"
has "$J" "[Journal]" "journald section"; has "$J" "SystemMaxUse=500M" "journald disk cap"; has "$J" "RuntimeMaxUse=200M" "journald runtime cap"
journald_cap_apply
chk "journald restarted once" "$(grep -c 'restart systemd-journald' "$T/systemctl.log")" "1"
journald_cap_apply 32M 16M      # hashem free-ram
has "$J" "SystemMaxUse=32M" "free-ram cap written"
journald_cap_apply              # the default never puts the larger cap back
has "$J" "SystemMaxUse=32M" "free-ram cap kept"

# ============ 4. sysctl by RAM, RPS/RFS, txqueuelen ============
tune_scale_values 4096;  chk "4GB buffers"  "$TUNE_BUF_MAX" "16777216"; chk "4GB tcp_rmem" "$TUNE_TCP_RMEM" "4096 131072 16777216"
tune_scale_values 6144;  chk "6GB buffers"  "$TUNE_BUF_MAX" "33554432"
tune_scale_values 8192;  chk "8GB buffers"  "$TUNE_BUF_MAX" "33554432"
tune_scale_values 16384; chk "16GB buffers" "$TUNE_BUF_MAX" "67108864"; chk "16GB tcp_wmem" "$TUNE_TCP_WMEM" "4096 131072 67108864"
tune_scale_values 4096
read -r lo pr hi <<< "$TUNE_TCP_MEM"
(( lo < pr && pr < hi )) || { echo "FAIL tcp_mem order: $TUNE_TCP_MEM"; fail=1; }
chk "4GB tcp_mem hard limit is 20% of RAM (pages)" "$hi" "$(( 4096 * 256 / 5 ))"
(( TUNE_CT_MAX >= 262144 )) || { echo "FAIL 4GB conntrack_max too small: $TUNE_CT_MAX"; fail=1; }

# the file name sorts after any other 99-*.conf, so its values win at boot
NAME=$(grep -E '^TUNE_SYSCTL=' "$ROOT/hashem.sh" | cut -d'"' -f2 | xargs basename)
chk "sysctl file name" "$NAME" "99-zz-hashem-perf.conf"
chk "sorts last" "$(printf '%s\n' "$NAME" 99-securebox-bbr-network.conf 99-sysctl.conf 99-gre-tune.conf | LC_ALL=C sort | tail -n 1)" "$NAME"
for k in net.core.somaxconn net.core.netdev_max_backlog net.ipv4.tcp_max_syn_backlog net.ipv4.tcp_keepalive_time \
         net.netfilter.nf_conntrack_max net.core.rps_sock_flow_entries net.core.netdev_budget net.core.netdev_budget_usecs net.ipv4.tcp_mem; do
  awk '/cat > "\$TUNE_SYSCTL" <<EOF/ {p=1; next} p && /^EOF$/ {p=0} p' "$ROOT/hashem.sh" | grep -q "^${k} = " || { echo "FAIL persisted sysctl file lacks $k"; fail=1; }
done
has "$ROOT/hashem.sh" 'net.core.rmem_max = ${TUNE_BUF_MAX}' "rmem_max follows RAM"
has "$ROOT/hashem.sh" 'net.core.rps_sock_flow_entries = 65536' "rps_sock_flow_entries"
has "$ROOT/hashem.sh" 'net.core.netdev_budget = 600' "netdev_budget"
has "$ROOT/hashem.sh" 'net.core.netdev_budget_usecs = 8000' "netdev_budget_usecs"

chk "mask 1 cpu"   "$(rps_cpu_mask 1)"  "1"
chk "mask 2 cpus"  "$(rps_cpu_mask 2)"  "3"
chk "mask 4 cpus"  "$(rps_cpu_mask 4)"  "f"
chk "mask 8 cpus"  "$(rps_cpu_mask 8)"  "ff"
chk "mask 32 cpus" "$(rps_cpu_mask 32)" "ffffffff"
chk "mask 36 cpus" "$(rps_cpu_mask 36)" "f,ffffffff"
chk "mask 64 cpus" "$(rps_cpu_mask 64)" "ffffffff,ffffffff"

echo "default via 192.0.2.1 dev ens3 proto static" > "$T/route"
mkdir -p "$T/sys/ens3/queues/rx-0" "$T/sys/ens3/queues/rx-1"
for q in rx-0 rx-1; do echo 0 > "$T/sys/ens3/queues/$q/rps_cpus"; echo 0 > "$T/sys/ens3/queues/$q/rps_flow_cnt"; done
chk "default interface" "$(net_default_iface)" "ens3"
echo 4 > "$T/nproc"; : > "$T/ip.log"
net_queues_apply || { echo "FAIL net_queues_apply"; fail=1; }
chk "rps_cpus rx-0" "$(cat "$T/sys/ens3/queues/rx-0/rps_cpus")" "f"
chk "rps_cpus rx-1" "$(cat "$T/sys/ens3/queues/rx-1/rps_cpus")" "f"
chk "rps_flow_cnt"  "$(cat "$T/sys/ens3/queues/rx-1/rps_flow_cnt")" "4096"
has "$T/ip.log" "link set dev ens3 txqueuelen 10000" "txqueuelen"
echo 0 > "$T/sys/ens3/queues/rx-0/rps_cpus"; echo 1 > "$T/nproc"
net_queues_apply
chk "one CPU: RPS left off" "$(cat "$T/sys/ens3/queues/rx-0/rps_cpus")" "0"
: > "$T/route"; net_queues_apply && { echo "FAIL no default route must not apply"; fail=1; }
echo "default via 192.0.2.1 dev ens3" > "$T/route"

: > "$T/systemctl.log"
net_queues_persist
NQ="$T/units/hashem-netq.service"
has "$NQ" "Type=oneshot" "netq oneshot"; has "$NQ" "ExecStart=/usr/local/bin/hashem net-queues" "netq ExecStart"
has "$NQ" "WantedBy=multi-user.target" "netq install"; has "$T/systemctl.log" "enable hashem-netq.service" "netq enabled"
grep -q 'net-queues) net_queues_apply' "$ROOT/hashem.sh" || { echo "FAIL the net-queues command the unit runs is missing"; fail=1; }
echo 4 > "$T/nproc"; net_queues_apply; net_queues_remove
chk "restore: unit gone" "$([[ -f "$NQ" ]] && echo yes || echo no)" "no"
chk "restore: RPS off" "$(cat "$T/sys/ens3/queues/rx-0/rps_cpus")" "0"

# ============ 6. one TCPMSS rule ============
P="-A POSTROUTING -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1340"
F="-A FORWARD -o gre-t2 -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1340"
: > "$T/rules"; mss_clamp_set POSTROUTING
chk "clamp added when missing" "$(grep -cxF -- "$P" "$T/rules")" "1"
mss_clamp_set POSTROUTING; mss_clamp_set POSTROUTING
chk "clamp not added twice" "$(grep -cxF -- "$P" "$T/rules")" "1"
printf '%s\n' "$P" "$P" "$P" "$F" "$F" > "$T/rules"
mss_clamp_set POSTROUTING
chk "three copies -> one" "$(grep -cxF -- "$P" "$T/rules")" "1"
chk "FORWARD untouched by a POSTROUTING call" "$(grep -cxF -- "$F" "$T/rules")" "2"
mss_clamp_set FORWARD -o gre-t2
chk "FORWARD copies -> one" "$(grep -cxF -- "$F" "$T/rules")" "1"
chk "POSTROUTING still one" "$(grep -cxF -- "$P" "$T/rules")" "1"
# a saved path MTU: the 1340 rule goes, one smaller clamp stays
echo 1300 > "$T/panel/gre_mtu"; printf '%s\n' "$P" "$P" > "$T/rules"
mss_clamp_set POSTROUTING
chk "path MTU: old clamps gone" "$(grep -c -- '--set-mss 1340' "$T/rules")" "0"
chk "path MTU: one 1260 clamp" "$(grep -c -- '--set-mss 1260$' "$T/rules")" "1"
rm -f "$T/panel/gre_mtu"

# ============ 3b. Watchdog restart: working GRE interfaces stay ============
sleep() { local i; for i in $(cat "$T/busy" 2>/dev/null); do echo $(( $(cat "$T/sys/$i/statistics/rx_packets") + 50 )) > "$T/sys/$i/statistics/rx_packets"; done; }
for i in gre-tunnel gre-t2 gre-t3; do mkdir -p "$T/sys/$i/statistics"; echo 1000 > "$T/sys/$i/statistics/rx_packets"; : > "$T/units/$i.service"; done
echo "2: gre-tunnel    inet 10.10.10.1/30 scope global gre-tunnel" > "$T/addr.gre-tunnel"
echo "3: gre-t2    inet 10.10.20.1 peer 10.10.20.2/30 scope global gre-t2" > "$T/addr.gre-t2"
echo "4: gre-t3    inet 10.10.30.2/30 scope global gre-t3" > "$T/addr.gre-t3"
chk "peer of .1/30" "$(gre_if_peer gre-tunnel)" "10.10.10.2"
chk "peer from the peer field" "$(gre_if_peer gre-t2)" "10.10.20.2"
chk "peer of .2/30" "$(gre_if_peer gre-t3)" "10.10.30.1"

# Iran hub: frps.toml exists
: > "$T/frp/frps.toml"; : > "$T/units/frps.service"; : > "$T/units/frps-2.service"
echo "10.10.10.2" > "$T/pingok"     # gre-tunnel answers a ping
echo "gre-t2" > "$T/busy"            # gre-t2: ICMP filtered, but packets arrive
echo "frps-2.service" > "$T/failed"  # one engine unit has failed
: > "$T/systemctl.log"
restart_all_lite --broken-only > "$T/out"
R=$(grep '^restart ' "$T/systemctl.log" | sort | tr '\n' ' ')
chk "hub, broken only: the dead interface and the failed engine" "$R" "restart frps-2.service restart gre-t3.service "
has "$T/out" "gre-tunnel is carrying traffic" "says why gre-tunnel was skipped"
has "$T/out" "gre-t2 is carrying traffic" "says why gre-t2 was skipped"

: > "$T/systemctl.log"; : > "$T/failed"
restart_all_lite > /dev/null       # the Restart Tunnel Now button: every interface, never frps
R=$(grep '^restart ' "$T/systemctl.log" | sort | tr '\n' ' ')
chk "hub, manual restart" "$R" "restart gre-t2.service restart gre-t3.service restart gre-tunnel.service "

# foreign server: frpc, no frps
rm -f "$T/frp/frps.toml" "$T/units"/frps*.service "$T/units"/gre-t[23].service
: > "$T/units/frpc.service"; : > "$T/systemctl.log"
restart_all_lite --broken-only > /dev/null
chk "foreign, broken only: the engine, not a working GRE" "$(grep '^restart ' "$T/systemctl.log" | tr '\n' ' ')" "restart frpc.service "
: > "$T/pingok"; : > "$T/busy"; : > "$T/systemctl.log"
restart_all_lite --broken-only > /dev/null
chk "foreign, GRE dead: both" "$(grep '^restart ' "$T/systemctl.log" | sort | tr '\n' ' ')" "restart frpc.service restart gre-tunnel.service "
unset -f sleep
# the Watchdog never asks for the full restart
chk "watchdog_tick uses --broken-only" "$(awk '/^watchdog_tick\(\) \{/,/^}/' "$ROOT/hashem.sh" | grep 'restart_all_lite' | grep -vc -- '--broken-only')" "0"

# ============ 8. Auto Pool ceiling follows perf.json ============
export AUTOPOOL_RAM_MB=2048
rm -f "$PERF_FILE"; chk "cap without perf.json" "$(pool_max_cap)" "500"
echo '{"auto_pool": true, "frp_max_pool": 60}' > "$PERF_FILE";   chk "default frp_max_pool never lowers" "$(pool_max_cap)" "500"
echo '{"auto_pool": true, "frp_max_pool": 1200}' > "$PERF_FILE"; chk "frp_max_pool 1200" "$(pool_max_cap)" "1200"
chk "writers get the raised ceiling" "$(pool_effective_values)" "20 1200"
echo '{"auto_pool": true, "frp_max_pool": 9000}' > "$PERF_FILE"; chk "bounded at 2000" "$(pool_max_cap)" "2000"
chk "autopool_tick reads the same ceiling" "$(awk '/^autopool_tick\(\) \{/,/^}/' "$ROOT/hashem.sh" | grep -c 'cap=\$(pool_max_cap)')" "1"
rm -f "$PERF_FILE"

# ============ 7. a removed peer's record ============
L="$T/panel/tunnel_links.json"
echo '{"2": {"public_ip": "5.6.7.8", "tls_pin": "aa"}, "3": {"public_ip": "9.9.9.9"}}' > "$L"
tunnel_link_forget 2
chk "peer 2 forgotten, peer 3 kept" "$(python3 -c 'import json,sys; print(sorted(json.load(open(sys.argv[1]))))' "$L")" "['3']"
tunnel_link_forget 3
chk "last record: file removed" "$([[ -f "$L" ]] && echo yes || echo no)" "no"
echo '{"4": {}}' > "$L"; tunnel_link_forget all
chk "all tunnels removed: file removed" "$([[ -f "$L" ]] && echo yes || echo no)" "no"
tunnel_link_forget 9   # nothing there: no error

[[ $fail -eq 0 ]] && echo "OK: field fixes" || exit 1
