#!/usr/bin/env bash
# tests/test_xray_core.sh — the Xray tunnel's own Xray-core in hashem.sh:
# installed only into its own directory (never /usr/local/bin/xray or an Xray
# panel's), sha256 checked, replaced by rename; removal only touches the
# hashem-xray-N units; installing needs Pro, running links never ask; nothing
# in hashem.sh kills an xray by name. Hermetic: fake download, fake systemctl.
set -u
cd "$(dirname "$0")/.." || exit 1
command -v python3 >/dev/null 2>&1 || { echo "SKIP test_xray_core (python3 missing)"; exit 0; }
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
fail=0
check() { if [[ "$2" != "$3" ]]; then echo "FAIL: $1 (want [$2] got [$3])"; fail=1; else echo "ok:   $1"; fi; }

ext() { awk -v n="$1" '$0 ~ "^"n"\\(\\) \\{" {p=1} p {print} p && /^}/ {exit}' hashem.sh; }
RED='' GREEN='' YELLOW='' CYAN='' NC=''
for f in xray_unzip install_xray_core xray_link_units xray_enabled_units xray_remove_all cli_xray pro_ok; do eval "$(ext "$f")"; done
eval "$(grep -E '^(DEFAULT_XRAY_VERSION|XRAY_SHA256_amd64)=' hashem.sh)"
check "pinned version" v26.3.27 "$DEFAULT_XRAY_VERSION"
check "pinned sha256 is 64 hex digits" yes "$([[ $XRAY_SHA256_amd64 =~ ^[0-9a-f]{64}$ ]] && echo yes)"

# a release archive with a fake xray that reports the pinned version
mkdir -p "$T/rel"
cat > "$T/rel/xray" <<'EOF'
#!/bin/bash
[[ "$1" == version ]] && echo "Xray 26.3.27 (Xray, Penetrates Everything.) Custom (go1.26.1 linux/amd64)"
EOF
echo geo > "$T/rel/geoip.dat"; echo geo > "$T/rel/geosite.dat"
python3 -I -c 'import sys, zipfile, os
z = zipfile.ZipFile(sys.argv[1], "w")
for n in ("xray", "geoip.dat", "geosite.dat"):
    i = zipfile.ZipInfo(n); i.external_attr = 0o755 << 16
    z.writestr(i, open(os.path.join(sys.argv[2], n), "rb").read())
z.close()' "$T/release.zip" "$T/rel"
detect_arch() { FRP_ARCH=amd64; }
download_with_fallback() { echo "$2" > "$T/url"; cp "$T/release.zip" "$1"; }
XRAY_SHA256_amd64=$(sha256sum "$T/release.zip" | awk '{print $1}')
XRAY_DIR="$T/lib/hashem/xray"

install_xray_core >/dev/null 2>&1
check "installs into its own directory" yes "$([[ -x $XRAY_DIR/xray && -f $XRAY_DIR/geoip.dat ]] && echo yes)"
check "downloads the official pinned release" \
    "https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-linux-64.zip" "$(cat "$T/url")"
check "no temporary file left next to it" 0 "$(ls "$XRAY_DIR" | grep -c '\.new$')"
rm -f "$T/url"
install_xray_core >/dev/null 2>&1
check "the pinned version is not downloaded again" no "$([[ -f $T/url ]] && echo yes || echo no)"

XRAY_SHA256_amd64=$(printf '0%.0s' {1..64})
check "a wrong checksum is refused" 1 "$(install_xray_core --force >/dev/null 2>&1; echo $?)"
check "...and the installed core is kept" yes "$("$XRAY_DIR/xray" version | grep -q 26.3.27 && echo yes)"

# the defaults never point at another Xray's files
check "default directory is the panel's own" /usr/local/lib/hashem/xray \
    "$(grep -E '^XRAY_DIR=' hashem.sh | sed -E 's/^XRAY_DIR="\$\{XRAY_DIR:-(.*)\}"$/\1/')"
check "panel's Go side uses the same path" 1 "$(grep -c 'xrayBinPath = "/usr/local/lib/hashem/xray/xray"' panel/xray_coexist.go)"
check "nothing kills an xray by name" 0 "$(grep -nE '(pkill|killall)[^#]*xray' hashem.sh | wc -l)"

# removal: only hashem-xray-N units are stopped
# xargs runs systemctl as a program, so the fake one is a file on PATH
mkdir -p "$T/bin"
cat > "$T/bin/systemctl" <<EOF
#!/bin/bash
# link 3 was stopped in the panel: disabled
[[ "\$1" == is-enabled && "\$3" == hashem-xray-3.service ]] && exit 1
[[ "\$1" == is-enabled ]] && exit 0
echo "\$*" >> "$T/systemctl.log"
EOF
chmod +x "$T/bin/systemctl"
PATH="$T/bin:$PATH"
xray_link_units() { printf 'hashem-xray-1.service\nhashem-xray-3.service\n'; }
: > "$T/systemctl.log"
xray_remove_all
check "remove stops only the tunnel's units" "disable --now hashem-xray-1.service hashem-xray-3.service" \
    "$(grep disable "$T/systemctl.log")"
check "remove deletes the tunnel's core" no "$([[ -e $XRAY_DIR ]] && echo yes || echo no)"
check "remove never names another unit" 0 "$(grep -cE 'x-ui|xray\.service|marzban' "$T/systemctl.log")"

# Pro: installing asks, running links never do
cat > "$T/gre-panel" <<EOF
#!/bin/bash
[[ "\$1 \$2" == "license check" ]] && grep -qx "\$3" "$T/unlocked" 2>/dev/null
EOF
chmod +x "$T/gre-panel"
export PANEL_BIN="$T/gre-panel"
: > "$T/unlocked"
install_xray_core() { echo INSTALLED; }
check "no license: hashem xray install refused" "" "$(cli_xray install 2>/dev/null | grep INSTALLED)"
check "no license: refusal names the feature" yes "$(cli_xray install | grep -q 'Xray Tunnel is a Hashem Pro feature' && echo yes)"
: > "$T/systemctl.log"
cli_xray restart >/dev/null
check "no license: restart still runs; a link stopped in the panel stays stopped" 1 "$(grep -cx 'restart hashem-xray-1.service' "$T/systemctl.log")"
for f in start stop restart logs status uninstall; do
    check "hashem xray $f never asks for a license" 0 "$(ext cli_xray | awk -v s="        $f" 'index($0, s) == 1 {p=1} p && /;;/ {print; exit} p {print}' | grep -c pro_ok)"
done
echo xray > "$T/unlocked"
check "Pro license: hashem xray install runs" INSTALLED "$(cli_xray install)"
check "dispatcher routes hashem xray" 1 "$(grep -c 'xray|xray-tunnel) shift; cli_xray' hashem.sh)"
check "uninstall removes the Xray tunnel" 1 "$(ext uninstall_all_force | grep -c xray_remove_all)"

(( fail )) && exit 1; echo "PASS test_xray_core"
