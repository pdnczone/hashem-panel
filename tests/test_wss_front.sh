#!/usr/bin/env bash
# Regression tests:
#  B-01  FRP transport "wss" must get a TLS front (frps cannot terminate TLS WebSocket itself)
#  B-02  panel binary present but gre-panel.service missing must be repaired, not "start"ed forever
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin" "$T/sd"
printf '#!/bin/sh\necho "$@" >> %s/systemctl.log\nexit 0\n' "$T" > "$T/bin/systemctl"; chmod +x "$T/bin/systemctl"
export PATH="$T/bin:$PATH" HASHEM_SYSTEMD_DIR="$T/sd" GREEN= YELLOW= NC=
fail=0
ext() { awk -v n="$1" '$0 ~ "^"n"\\(\\) \\{" {p=1} p {print} p && /^}/ {exit}' "$ROOT/hashem.sh"; }
for f in wss_front_port frps_wss_front_ensure frps_wss_front_remove; do
  body="$(ext $f)"
  [[ -n "$body" ]] || { echo "FAIL: $f not defined in hashem.sh"; exit 1; }
  eval "$body"
done

# --- B-01
[[ "$(wss_front_port 7000)" == 7002 ]] || { echo "FAIL port 7000 -> $(wss_front_port 7000)"; fail=1; }
[[ "$(wss_front_port 65535)" == 65533 ]] || { echo "FAIL wrap"; fail=1; }
PANEL_BIN="$T/fakepanel"; printf '#!/bin/sh\n' > "$PANEL_BIN"; chmod +x "$PANEL_BIN"
frps_wss_front_ensure "" 7000 >/dev/null
u="$T/sd/frps-wss.service"
[[ -f "$u" ]] || { echo "FAIL unit not created"; fail=1; }
grep -q "tls-proxy -listen 0.0.0.0:7002 -target 127.0.0.1:7000" "$u" || { echo "FAIL ExecStart wrong"; fail=1; }
frps_wss_front_ensure "-3" 8000 >/dev/null
[[ -f "$T/sd/frps-wss-3.service" ]] || { echo "FAIL peer unit"; fail=1; }
frps_wss_front_remove ""
[[ ! -f "$u" ]] || { echo "FAIL unit not removed"; fail=1; }
PANEL_BIN="$T/missing"; frps_wss_front_ensure "" 7000 >/dev/null 2>&1 && { echo "FAIL should fail without binary"; fail=1; }

# frpc side must dial the front port for wss
grep -q 'elif \[\[ "\$FRP_TRANSPORT" == "wss" \]\]; then' "$ROOT/hashem.sh" || { echo "FAIL frpc wss port branch missing"; fail=1; }

# --- B-02
sec="$(awk '/^install_panel_smart\(\) \{/,/^}/' "$ROOT/hashem.sh")"
grep -q 'gre-panel.service \]\]; then' <<<"$sec" || { echo "FAIL install_panel_smart lacks missing-unit repair"; fail=1; }

(( fail )) && exit 1; echo "PASS test_wss_front"
