#!/usr/bin/env bash
# Inner GRE addresses: the free pair, what clashes, and the pair a first tunnel
# gets. Hermetic: ip is a stub that prints $T/addrs.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin"
cat > "$T/bin/ip" <<EOF
#!/bin/sh
case "\$*" in
    "-o -4 addr show") cat "$T/addrs" ;;
    "link show gre-tunnel") grep -q gre-tunnel "$T/addrs" ;;
esac
EOF
chmod +x "$T/bin/ip"
export PATH="$T/bin:$PATH"
for f in gre_py gre_pair_ok gre_other_end gre_default_pair; do
    # gre_py holds a python heredoc, whose lines never are a lone "}"
    awk -v f="$f" '$0 ~ "^"f"\\(\\) \\{" {p=1} p {print} p && /^}/ {exit}' "$ROOT/hashem.sh"
done > "$T/fn.sh"
# shellcheck disable=SC1091
source "$T/fn.sh"
RED='' GREEN='' YELLOW='' NC=''
TUNNEL_NAME=gre-tunnel IRAN_GRE_IP=10.10.10.2 FOREIGN_GRE_IP=10.10.10.1
PEERS_FILE="$T/peers.json" HUBS_FILE="$T/hubs.json"
fail=0
eq() { if [[ "$2" == "$3" ]]; then echo "ok:   $1"; else echo "FAIL: $1: got '$2', want '$3'"; fail=1; fi; }
has() { if [[ "$2" == *"$3"* ]]; then echo "ok:   $1"; else echo "FAIL: $1: '$2' has no '$3'"; fail=1; fi; }
: > "$T/addrs"
eq "nothing used" "$(gre_py free)" "10.10.10.2 10.10.10.1"
eq "nothing clashes" "$(gre_py clash 10.10.10.2 10.10.10.1)" ""
printf '1: lo inet 127.0.0.1/8 x\n2: eth0 inet 203.0.113.5/24 x\n9: gre-tunnel inet 10.10.10.2/30 x\n' | sed 's/^[0-9]*: //;s/^/1: /' > "$T/addrs"
eq "the first tunnel's pair is used" "$(gre_py free)" "10.11.0.2 10.11.0.1"
has "its /30, either end" "$(gre_py clash 10.10.10.1 10.10.10.2)" "gre-tunnel"
eq "not for itself" "$(gre_py clash 10.10.10.2 10.10.10.1 gre-tunnel)" ""
eq "the next /30 is free" "$(gre_py clash 10.10.10.6 10.10.10.5)" ""
has "two /30s" "$(gre_py clash 10.11.0.2 10.12.0.1)" "not the two ends"
has "a network address" "$(gre_py clash 10.11.0.4 10.11.0.5)" "not the two ends"
echo '{"peers":[{"id":1,"name":"base","gre_if":"gre-tunnel","local_gre":"10.10.10.2","peer_gre":"10.10.10.1"},{"id":2,"name":"de","gre_if":"gre-t2","local_gre":"10.11.0.2","peer_gre":"10.11.0.1"},{"id":3,"name":"bh","gre_if":"none","local_gre":"","peer_gre":""}]}' > "$PEERS_FILE"
eq "a tunnel whose interface is down counts too" "$(gre_py free)" "10.12.0.2 10.12.0.1"
has "by its name" "$(gre_py clash 10.11.0.2 10.11.0.1)" "de"
eq "the base record is the interface skipped" "$(gre_py clash 10.10.10.2 10.10.10.1 gre-tunnel)" ""
echo '{"hubs":[{"id":2,"name":"hub-2","gre_if":"gre-h2","iran_gre":"10.12.0.2","foreign_gre":"10.12.0.1"},{"id":3,"gre_if":"none","iran_gre":"10.13.0.2"}]}' > "$HUBS_FILE"
eq "a joined hub's pair is used, one without GRE is not" "$(gre_py free)" "10.13.0.2 10.13.0.1"
echo '1: eth1 inet 10.13.5.9/16 x' >> "$T/addrs"
eq "not inside this server's networks" "$(gre_py free)" "10.14.0.2 10.14.0.1"
has "that is a warning" "$(gre_py clash 10.13.0.2 10.13.0.1)" "warn:"
if gre_pair_ok 10.13.0.2 10.13.0.1 >/dev/null; then echo "ok:   allowed with a warning"; else echo "FAIL: refused"; fail=1; fi
has "the address itself is taken" "$(gre_py clash 10.13.5.9 10.13.5.10)" "already used by eth1"
out=$(gre_pair_ok 10.11.0.2 10.11.0.1); rc=$?
eq "another tunnel's is refused" "$rc" 1
has "with a free one" "$out" "--local-gre 10.14.0.2 --peer-gre 10.14.0.1"
eq "a first tunnel there is keeps its pair" "$(gre_default_pair)" "10.10.10.2 10.10.10.1"
sed -i 's#10.10.10.2/30#10.77.0.5/30#' "$T/addrs"
eq "also another one than the default" "$(gre_default_pair)" "10.77.0.6 10.77.0.5"
sed -i '/gre-tunnel/d' "$T/addrs"
eq "a new first one gets a free pair" "$(gre_default_pair)" "10.14.0.2 10.14.0.1"
eq "the other end" "$(gre_other_end 10.11.0.6) $(gre_other_end 10.11.0.1/30)" "10.11.0.5 10.11.0.2"
(( fail )) && exit 1; echo "PASS test_gre_pair"
