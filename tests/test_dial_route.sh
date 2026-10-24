#!/usr/bin/env bash
# Regression: foreign client must be able to reach the Iran hub over its PUBLIC IP
# when the GRE inner address is dead (Spain peer: GRE no ping, FRP must still connect).
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin"
export PATH="$T/bin:$PATH" GREEN= YELLOW= RED= NC=
CONFIG_DIR="$T/etc"; BACKHAUL_CONFIG_DIR="$T/bh"; mkdir -p "$CONFIG_DIR" "$BACKHAUL_CONFIG_DIR"
fail=0
ext() { awk -v n="$1" '$0 ~ "^"n"\\(\\) \\{" {p=1} p {print} p && /^}/ {exit}' "$ROOT/hashem.sh"; }
for f in hostport hostonly dial_env_file dial_env_write dial_env_get dial_conf_file dial_service dial_current_addr dial_current_port \
         dial_pick dial_apply_addr dial_reselect dial_env_ensure dial_gre_usable dial_hold_file dial_hold_active; do
  body="$(ext $f)"; [[ -n "$body" ]] || { echo "FAIL: $f missing"; exit 1; }; eval "$body"
done
eval "$(grep -E '^DIAL_(BACK_TICKS|BACK_WAIT|HOLD_SECS)=' "$ROOT/hashem.sh")"
# ping + /dev/tcp both fail => GRE dead
printf '#!/bin/sh\nexit 1\n' > "$T/bin/ping"; chmod +x "$T/bin/ping"

cat > "$CONFIG_DIR/frpc.toml" <<EOT
serverAddr = "10.14.0.1"
serverPort = 7091
EOT
dial_env_write auto frp 10.14.0.1 203.0.113.217

# auto + dead GRE => public
[[ "$(dial_pick auto 10.14.0.1 203.0.113.217 7091)" == 203.0.113.217 ]] || { echo "FAIL auto dead GRE must pick public"; fail=1; }
[[ "$(dial_pick gre 10.14.0.1 203.0.113.217 7091)" == 10.14.0.1 ]] || { echo "FAIL gre mode"; fail=1; }
[[ "$(dial_pick public 10.14.0.1 203.0.113.217 7091)" == 203.0.113.217 ]] || { echo "FAIL public mode"; fail=1; }

r="$(dial_reselect)"; [[ "$r" == "changed:203.0.113.217" ]] || { echo "FAIL reselect: $r"; fail=1; }
grep -q 'serverAddr = "203.0.113.217"' "$CONFIG_DIR/frpc.toml" || { echo "FAIL frpc.toml not rewritten"; fail=1; }
grep -q 'serverPort = 7091' "$CONFIG_DIR/frpc.toml" || { echo "FAIL port changed"; fail=1; }
r="$(dial_reselect)"; [[ "$r" == "same:203.0.113.217" ]] || { echo "FAIL idempotent: $r"; fail=1; }

# forced gre flips it back
r="$(dial_reselect gre)"; [[ "$r" == "changed:10.14.0.1" ]] || { echo "FAIL force gre: $r"; fail=1; }

# backhaul client.toml
cat > "$BACKHAUL_CONFIG_DIR/client.toml" <<EOT
[client]
remote_addr = "10.14.0.1:8443"
transport = "wssmux"
EOT
rm -f "$CONFIG_DIR/frpc.toml"; dial_env_write auto backhaul 10.14.0.1 203.0.113.217
r="$(dial_reselect)"; [[ "$r" == "changed:203.0.113.217" ]] || { echo "FAIL backhaul reselect: $r"; fail=1; }
grep -q 'remote_addr = "203.0.113.217:8443"' "$BACKHAUL_CONFIG_DIR/client.toml" || { echo "FAIL backhaul toml"; fail=1; }

# GRE alive => stays on GRE
printf '#!/bin/sh\nexit 0\n' > "$T/bin/ping"
[[ "$(dial_pick auto 10.14.0.1 203.0.113.217 8443)" == 10.14.0.1 ]] || { echo "FAIL live GRE must stay on GRE"; fail=1; }

# ---- watchdog: back to GRE once it answers again ----
for f in dial_connected dial_transport_udp dial_gre_back_ok dial_streak_file dial_watch_tick; do
  body="$(ext $f)"; [[ -n "$body" ]] || { echo "FAIL: $f missing"; exit 1; }; eval "$body"
done
eval "$(grep -E '^DIAL_(BACK_TICKS|BACK_WAIT|HOLD_SECS)=' "$ROOT/hashem.sh")"
DIAL_BACK_WAIT=1
# stubs: GRE TCP answers when $T/tcp_ok exists; the client is connected to the address in $T/conn
printf '#!/bin/sh\n[ -f "%s/tcp_ok" ]\n' "$T" > "$T/bin/timeout"; chmod +x "$T/bin/timeout"
printf '#!/bin/sh\ncase "$*" in *-Htn*) [ -f "%s/conn" ] && printf "0 0 192.0.2.9:40000 %%s\n" "$(cat %s/conn)";; esac; exit 0\n' "$T" "$T" > "$T/bin/ss"; chmod +x "$T/bin/ss"
systemctl() { echo "$*" >> "$T/systemctl.log"; }
log_msg() { echo "$3" >> "$T/msg.log"; }
sleep() { :; }
want() { [[ "$2" == "$3" ]] || { echo "FAIL $1: want [$2] got [$3]"; fail=1; }; }

cat > "$BACKHAUL_CONFIG_DIR/client.toml" <<EOT
[client]
remote_addr = "203.0.113.217:8443"
transport = "tcpmux"
EOT
dial_env_write auto backhaul 10.14.0.1 203.0.113.217
rm -f "$T/tcp_ok" "$T/conn" "$T/systemctl.log"
dial_watch_tick
want "GRE silent: streak stays 0" 0 "$(cat "$CONFIG_DIR/dial.streak")"
touch "$T/tcp_ok"
for i in 1 2 3 4; do dial_watch_tick; done
want "4 good ticks: still public" 203.0.113.217 "$(dial_current_addr backhaul)"
want "4 good ticks: streak 4" 4 "$(cat "$CONFIG_DIR/dial.streak")"
rm -f "$T/tcp_ok"; dial_watch_tick
want "a miss resets the streak" 0 "$(cat "$CONFIG_DIR/dial.streak")"
touch "$T/tcp_ok"; echo "10.14.0.1:8443" > "$T/conn"
for i in 1 2 3 4 5; do dial_watch_tick; done
want "5 good ticks: back on GRE" 10.14.0.1 "$(dial_current_addr backhaul)"
want "restarted once" "restart backhaul-client" "$(cat "$T/systemctl.log")"
grep -q "back on GRE" "$T/msg.log" || { echo "FAIL no back-on-GRE log"; fail=1; }
[[ ! -f "$CONFIG_DIR/dial.streak" ]] || { echo "FAIL streak left behind"; fail=1; }
want "port kept" 8443 "$(dial_current_port backhaul)"

# GRE answers but the client cannot connect over it: back to public, then hold
dial_apply_addr backhaul 203.0.113.217 8443; rm -f "$T/conn" "$T/systemctl.log" "$T/msg.log"
for i in 1 2 3 4 5; do dial_watch_tick; done
want "failed return: public again" 203.0.113.217 "$(dial_current_addr backhaul)"
grep -q "could not connect over it" "$T/msg.log" || { echo "FAIL no failed-return log"; fail=1; }
want "two restarts" 2 "$(wc -l < "$T/systemctl.log")"
for i in 1 2 3 4 5 6 7; do dial_watch_tick; done
want "hold: no new attempt" 2 "$(wc -l < "$T/systemctl.log")"
r="$(dial_reselect)"; want "hold: service restart keeps public" "same:203.0.113.217" "$r"
echo $(( $(date +%s) - 4000 )) > "$CONFIG_DIR/dial.hold"
r="$(dial_reselect)"; want "hold over: restart may pick GRE" "changed:10.14.0.1" "$r"
dial_apply_addr backhaul 203.0.113.217 8443
date +%s > "$CONFIG_DIR/dial.hold"
r="$(dial_reselect auto)"; want "explicit auto clears the hold" "changed:10.14.0.1" "$r"
[[ ! -f "$CONFIG_DIR/dial.hold" ]] || { echo "FAIL explicit choice must clear hold"; fail=1; }

# mode gre / public: the watchdog leaves the route alone
dial_apply_addr backhaul 203.0.113.217 8443; rm -f "$T/systemctl.log"
sed -i 's/^DIAL_MODE=.*/DIAL_MODE=public/' "$CONFIG_DIR/dial.env"
for i in 1 2 3 4 5 6; do dial_watch_tick; done
want "public mode: untouched" 203.0.113.217 "$(dial_current_addr backhaul)"
[[ ! -f "$T/systemctl.log" ]] || { echo "FAIL public mode restarted"; fail=1; }

# udp transport: GRE is judged by ping, not a TCP connect
sed -i 's/^DIAL_MODE=.*/DIAL_MODE=auto/; s/^transport = .*/transport = "udp"/' "$CONFIG_DIR/dial.env" "$BACKHAUL_CONFIG_DIR/client.toml"
rm -f "$T/tcp_ok"; dial_transport_udp backhaul || { echo "FAIL udp transport not seen"; fail=1; }
dial_gre_back_ok backhaul 10.14.0.1 8443 || { echo "FAIL udp: ping should decide"; fail=1; }

[[ $fail -eq 0 ]] && echo "dial route: all OK"
exit $fail
