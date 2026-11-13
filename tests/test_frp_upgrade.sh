#!/usr/bin/env bash
# An update must move an FRP from an older release to DEFAULT_FRP_VERSION:
# configs checked first, services restarted, and the old binary put back when
# a service does not come up. Fake frps/frpc/systemctl, no network.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
fail=0
ext() { awk -v n="$1" '$0 ~ "^"n"\\(\\) \\{" {p=1} p {print} p && /^}/ {exit}' "$ROOT/hashem.sh"; }
eval "$(grep -E '^DEFAULT_FRP_VERSION=' "$ROOT/hashem.sh")"
eval "$(grep -E '^ver_lt\(\)' "$ROOT/hashem.sh")"
for f in frp_installed_version frp_units frp_upgrade; do
  b="$(ext $f)"; [[ -n "$b" ]] || { echo "FAIL: $f missing"; exit 1; }; eval "$b"
done
RED= GREEN= YELLOW= CYAN= NC=
FRP_ARCH=amd64
detect_arch() { :; }
flock() { return 0; }
sleep() { :; }

# fakebin DIR NAME VERSION [verify-exit]
fakebin() {
  printf '#!/bin/sh\n[ "$1" = "--version" ] && { echo %s; exit 0; }\n[ "$1" = "verify" ] && { echo "config check"; exit %s; }\nexit 0\n' "$3" "${4:-0}" > "$1/$2"
  chmod +x "$1/$2"
}
# The "download": a tarball with frps/frpc of version $NEW_VER.
download_with_fallback() {
  [[ "${DL_FAIL:-0}" == 1 ]] && return 1
  local d; d=$(mktemp -d "$T/dl.XXXX"); mkdir -p "$d/frp_x"
  fakebin "$d/frp_x" frps "$NEW_VER" "${VERIFY_EXIT:-0}"; fakebin "$d/frp_x" frpc "$NEW_VER" "${VERIFY_EXIT:-0}"
  tar -czf "$1" -C "$d" frp_x
}
# systemctl: units in $T/active are running; units in $T/dies stop on restart.
systemctl() {
  case "$1" in
    is-active) shift; [[ "$1" == --quiet ]] && shift; grep -qx "$1" "$T/active"; return ;;
    restart) if grep -qx "$2" "$T/dies" 2>/dev/null && [[ "$(cat "$INSTALL_DIR/frps")" == *"$NEW_VER"* ]]; then
               grep -vx "$2" "$T/active" > "$T/a2"; mv "$T/a2" "$T/active"
             else grep -qx "$2" "$T/active" || echo "$2" >> "$T/active"; echo "$2" >> "$T/restarted"; fi ;;
  esac
  return 0
}

setup() {
  rm -rf "$T/bin" "$T/units" "$T/etc"; mkdir -p "$T/bin" "$T/units" "$T/etc"
  INSTALL_DIR="$T/bin"; HASHEM_SYSTEMD_DIR="$T/units"
  fakebin "$INSTALL_DIR" frps "$1"; fakebin "$INSTALL_DIR" frpc "$1"
  printf '[Service]\nExecStart=%s/frps -c %s/frps.toml\n' "$INSTALL_DIR" "$T/etc" > "$T/units/frps.service"
  printf '[Service]\nExecStart=%s/frpc -c %s/bagher.toml\n' "$INSTALL_DIR" "$T/etc" > "$T/units/hashem-bagher-frpc.service"
  printf '[Service]\nExecStart=/usr/bin/ssh -N host\n' > "$T/units/other.service"
  : > "$T/etc/frps.toml"; : > "$T/etc/bagher.toml"
  printf 'frps\nhashem-bagher-frpc\n' > "$T/active"; : > "$T/dies"; : > "$T/restarted"
  NEW_VER="$DEFAULT_FRP_VERSION"; DL_FAIL=0; VERIFY_EXIT=0
}
ver() { "$INSTALL_DIR/frps" --version; }

# frp_units finds the FRP units and their configs, not the others
setup 0.61.1
u="$(frp_units | sort)"
[[ "$u" == "frps frps $T/etc/frps.toml"$'\n'"hashem-bagher-frpc frpc $T/etc/bagher.toml" ]] || { echo "FAIL frp_units: $u"; fail=1; }

# older FRP: upgraded, both services restarted
setup 0.61.1
frp_upgrade >/dev/null || { echo "FAIL upgrade returned an error"; fail=1; }
[[ "$(ver)" == "$DEFAULT_FRP_VERSION" ]] || { echo "FAIL frps not upgraded ($(ver))"; fail=1; }
[[ "$("$INSTALL_DIR/frpc" --version)" == "$DEFAULT_FRP_VERSION" ]] || { echo "FAIL frpc not upgraded"; fail=1; }
[[ "$(sort "$T/restarted" | tr '\n' ' ')" == "frps hashem-bagher-frpc " ]] || { echo "FAIL restarted: $(cat "$T/restarted")"; fail=1; }
[[ "$("$INSTALL_DIR/frps.bak" --version)" == 0.61.1 ]] || { echo "FAIL no .bak of the old frps"; fail=1; }

# already pinned, or newer: nothing downloaded or restarted
for v in "$DEFAULT_FRP_VERSION" 9.0.0; do
  setup "$v"; DL_FAIL=1
  frp_upgrade >/dev/null || { echo "FAIL $v returned an error"; fail=1; }
  [[ "$(ver)" == "$v" && ! -s "$T/restarted" ]] || { echo "FAIL $v was touched"; fail=1; }
done

# a config the new FRP refuses: nothing changes
setup 0.61.1; VERIFY_EXIT=1
out="$(frp_upgrade)" && { echo "FAIL refused config returned success"; fail=1; }
[[ "$(ver)" == 0.61.1 && ! -s "$T/restarted" ]] || { echo "FAIL refused config still swapped"; fail=1; }
[[ "$out" == *"frps.toml does not pass"* ]] || { echo "FAIL no config message: $out"; fail=1; }

# download blocked: nothing changes
setup 0.61.1; DL_FAIL=1
frp_upgrade >/dev/null && { echo "FAIL blocked download returned success"; fail=1; }
[[ "$(ver)" == 0.61.1 ]] || { echo "FAIL blocked download changed frps"; fail=1; }

# a download that is not the pinned version is not installed
setup 0.61.1; NEW_VER=0.65.0
frp_upgrade >/dev/null && { echo "FAIL wrong version returned success"; fail=1; }
[[ "$(ver)" == 0.61.1 ]] || { echo "FAIL wrong version installed"; fail=1; }

# a service that does not come up on the new FRP: the old one is put back
setup 0.61.1; echo frps > "$T/dies"
frp_upgrade >/dev/null && { echo "FAIL dead service returned success"; fail=1; }
[[ "$(ver)" == 0.61.1 ]] || { echo "FAIL not rolled back ($(ver))"; fail=1; }

# no FRP installed: nothing to do
setup 0.61.1; rm -f "$INSTALL_DIR/frps" "$INSTALL_DIR/frpc"; DL_FAIL=1
frp_upgrade >/dev/null || { echo "FAIL no FRP returned an error"; fail=1; }

grep -q 'cores-upgrade) frp_upgrade' "$ROOT/hashem.sh" || { echo "FAIL no cores-upgrade command"; fail=1; }
grep -q '"$HASHEM_BIN" cores-upgrade' "$ROOT/hashem.sh" || { echo "FAIL update_all does not upgrade FRP"; fail=1; }

(( fail )) && exit 1; echo "PASS test_frp_upgrade"
