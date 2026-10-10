#!/usr/bin/env bash
# tests/test_panel_limits.sh — RAM-scaled panel unit limits (C2.6).
# Sources only the pure functions from hashem.sh; touches no live state.
set -u
cd "$(dirname "$0")/.." || exit 1
SRC=$(mktemp -d); trap 'rm -rf "$SRC"' EXIT

# Extract just the functions we test (no top-level side effects).
{
  echo 'RED= GREEN= CYAN= YELLOW='
  awk '/^panel_limits_for_ram\(\)/,/^}/' hashem.sh
  awk '/^unit_set_directive\(\)/,/^}/' hashem.sh
  awk '/^apply_panel_unit_limits\(\)/,/^}/' hashem.sh
  awk '/^apply_frp_unit_weight\(\)/,/^}/' hashem.sh
} > "$SRC/funcs.sh"
# shellcheck disable=SC1091
source "$SRC/funcs.sh"

fail=0
check() { # name expected actual
  if [[ "$2" != "$3" ]]; then echo "FAIL: $1 (want [$2] got [$3])"; fail=1; fi
}

# RAM tiers -> HIGH MAX
check "1GB tier"   "280M 350M" "$(panel_limits_for_ram 1024)"
check "tier edge"  "280M 350M" "$(panel_limits_for_ram 1250)"
check "2GB tier"   "450M 550M" "$(panel_limits_for_ram 2048)"
check "4GB tier"   "700M 850M" "$(panel_limits_for_ram 4096)"
check "big tier"   "1G 1.2G"   "$(panel_limits_for_ram 8192)"
check "autodetect" ""          ""  # placeholder replaced below
auto=$(panel_limits_for_ram)
[[ "$auto" =~ ^[0-9]+[MG]\ [0-9]+(\.[0-9]+)?[MG]$ ]] || { echo "FAIL: autodetect shape [$auto]"; fail=1; }

# apply to a synthetic unit: idempotent, keeps user extras
U="$SRC/gre-panel.service"
cat > "$U" <<'EOF'
[Unit]
Description=Hashem Web Panel

[Service]
Type=simple
ExecStart=/usr/local/bin/gre-panel
Environment=FOO=bar

[Install]
WantedBy=multi-user.target
EOF
apply_panel_unit_limits "$U" "450M 550M"
for kv in "OOMScoreAdjust=-900" "Nice=-5" "CPUWeight=200" "MemoryHigh=450M" \
          "MemoryMax=550M" "WatchdogSec=30" "NotifyAccess=main" "LimitNOFILE=1048576" \
          "TasksMax=4096" "StartLimitIntervalSec=0"; do
  n=$(grep -cE "^${kv%%=*}=" "$U")
  [[ "$n" == "1" ]] || { echo "FAIL: $kv appears $n times"; fail=1; }
  grep -qE "^${kv}$" "$U" || { echo "FAIL: missing/wrong $kv"; fail=1; }
done
grep -q "Environment=FOO=bar" "$U" || { echo "FAIL: user extra lost"; fail=1; }
before=$(md5sum < "$U")
apply_panel_unit_limits "$U" "450M 550M"
check "idempotent" "$before" "$(md5sum < "$U")"
# re-tier replaces, does not duplicate
apply_panel_unit_limits "$U" "280M 350M"
check "re-tier high" "1" "$(grep -cE '^MemoryHigh=280M$' "$U")"
check "re-tier max"  "1" "$(grep -cE '^MemoryMax=350M$' "$U")"

# FRP weight
F="$SRC/frps.service"
printf '[Service]\nExecStart=/x\n' > "$F"
apply_frp_unit_weight "$F"
check "frp weight" "1" "$(grep -cE '^CPUWeight=100$' "$F")"

if (( fail == 0 )); then echo "PASS test_panel_limits"; else exit 1; fi
