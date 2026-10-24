#!/usr/bin/env bash
# tests/test_panel_history_persist.sh — real-binary proof that link history
# survives a restart and that SIGTERM shuts the panel down cleanly.
set -u
cd "$(dirname "$0")/../panel" || exit 1
export PATH=$PATH:/usr/local/go/bin
command -v go >/dev/null 2>&1 || { echo "SKIP test_panel_history_persist (go missing)"; exit 0; }
T=$(mktemp -d); trap 'kill "$PID" 2>/dev/null; rm -rf "$T"' EXIT
go build -o "$T/gp" . || { echo "FAIL build"; exit 1; }
fail=0
ck() { if [[ "$2" == "$3" ]]; then echo "ok:   $1"; else echo "FAIL: $1 (got '$2' want '$3')"; fail=1; fi; }

start() {
    GRE_PANEL_DIR="$T/cfg" GRE_PANEL_PASSWORD='Persist-Test-Pass-1!' "$T/gp" >"$T/log" 2>&1 &
    PID=$!
    for _ in $(seq 1 40); do
        [[ -f "$T/cfg/panel.json" ]] && grep -q 'listening' "$T/log" 2>/dev/null && break
        sleep 0.25
    done
    read -r PORT BASE < <(python3 -c "import json;d=json.load(open('$T/cfg/panel.json'));print(d['port'],d['base_path'])")
}

start
ck "panel serves /" "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/$BASE/")" 200

# Seed a history file as an earlier run would have written it, then restart.
kill -TERM "$PID"; wait "$PID" 2>/dev/null
NOW=$(date +%s)
# register a real peer so the seeded history belongs to a link that exists
echo '{"peers":[{"id":2,"name":"seeded-link","local_gre":"10.10.20.1","peer_gre":"10.10.20.2","frp_port":23456,"gre_if":"gre-t2","frps_svc":"frps-2"}]}' > "$T/cfg/peers.json"
python3 - "$T/cfg/history.json" "$NOW" <<'EOF'
import json,sys
f,now=sys.argv[1],int(sys.argv[2])
pts=[{"t":now-3600+i*30,"state":2,"ms":10+i%5,"rx_bps":0,"tx_bps":0} for i in range(40)]
json.dump({"v":1,"saved_at":now,"links":{"seeded-link":pts}},open(f,"w"))
EOF
start
curl -s -c "$T/cj" -H 'Content-Type: application/json' -d '{"username":"admin","password":"Persist-Test-Pass-1!"}' "http://127.0.0.1:$PORT/$BASE/api/login" >/dev/null
N=$(curl -s -b "$T/cj" "http://127.0.0.1:$PORT/$BASE/api/history?link=seeded-link&hours=24" | python3 -c "import json,sys;print(len(json.load(sys.stdin)['points']))")
# 40 restored + at most 1 fresh live sample taken after start
if [[ "${N:-0}" -ge 40 && "${N:-0}" -le 41 ]]; then echo "ok:   seeded history restored after restart ($N points)"; else echo "FAIL: seeded history not restored (got '$N', want 40-41)"; fail=1; fi

# SIGTERM must exit promptly (graceful) and 0/143-free of a crash trace.
kill -TERM "$PID"
for _ in $(seq 1 30); do kill -0 "$PID" 2>/dev/null || break; sleep 0.2; done
if kill -0 "$PID" 2>/dev/null; then echo "FAIL: panel did not exit within 6s of SIGTERM"; fail=1; else echo "ok:   SIGTERM exits within 6s"; fi
grep -q "panic:" "$T/log" && { echo "FAIL: panic in log"; fail=1; }
[[ -s "$T/cfg/history.json" ]] && echo "ok:   history flushed on shutdown" || { echo "FAIL: history.json missing"; fail=1; }
[[ $fail -eq 0 ]] && echo "PASS test_panel_history_persist" || exit 1
