#!/usr/bin/env bash
# The panel address in the terminal: http://IP:port without a certificate,
# https://DOMAIN:tls_port once a domain certificate is set (plus the HTTP line).
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
export HASHEM_NO_ROOT_CHECK=1 GRE_PANEL_DIR="$T/panel"
fail=0
has() { grep -qF -- "$2" <<< "$1" || { echo "FAIL $3: no \"$2\" in:"; echo "$1"; fail=1; }; }
hasnt() { ! grep -qF -- "$2" <<< "$1" || { echo "FAIL $3: unexpected \"$2\""; fail=1; }; }
url() { bash "$ROOT/hashem.sh" show-panel-url 2>&1 | sed 's/\x1b\[[0-9;]*m//g'; }

mkdir -p "$T/panel/tls"
echo '{"username":"admin","port":7777,"base_path":"abc","tls_port":8443}' > "$T/panel/panel.json"

out=$(url)
has "$out" "Panel URL:  http://" "no certificate"
has "$out" ":7777/abc/" "no certificate port"
hasnt "$out" "https://" "no certificate"

echo crt > "$T/panel/tls/server.crt"; echo key > "$T/panel/tls/server.key"
echo '{"domain":"panel.example.com","issued_at":"x"}' > "$T/panel/tls/meta.json"
out=$(url)
has "$out" "Panel URL:  https://panel.example.com:8443/abc/" "domain"
has "$out" "HTTP:       http://" "domain keeps the HTTP line"

# A certificate made for the IP has the IP as its name; an IPv6 one is bracketed.
echo '{"domain":"2001:db8::1","issued_at":"x"}' > "$T/panel/tls/meta.json"
has "$(url)" "https://[2001:db8::1]:8443/abc/" "IPv6 name"

[[ $fail -eq 0 ]] && echo "PASS test_panel_address"
exit $fail
