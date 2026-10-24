#!/usr/bin/env bash
# install.sh must not trust a lone mirror: canonical copy, 2-mirror quorum,
# or a pinned HASHEM_SHA256; anything else fails closed.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
TMP="$T/tmp"; mkdir -p "$TMP"
good=$'#!/bin/bash\necho good\n'; evil=$'#!/bin/bash\necho evil\n'
mkdir -p "$T/a" "$T/b" "$T/c" "$T/d"
printf '%s' "$good" > "$T/a/hashem.sh"; printf '%s' "$good" > "$T/b/hashem.sh"
printf '%s' "$evil" > "$T/c/hashem.sh"; printf '%s' "$evil" > "$T/d/hashem.sh"
printf '%s' "$good" | sha256sum | awk '{print $1}' > "$T/good.sha"
GOOD=$(cat "$T/good.sha")
# pull in the functions only
{ echo 'url_host() { local h="${1#*://}"; echo "${h%%/*}"; }'
  awk '/^fetch_verified\(\) \{/ {p=1} p {print} p && /^}/ {p=0}' "$ROOT/install.sh"; } > "$T/fn.sh"
[[ -s "$T/fn.sh" ]] || { echo "FAIL fetch_verified not found"; exit 1; }
# shellcheck disable=SC1091
source "$T/fn.sh"
fail=0
run() { URLS=("$@"); PRIMARY="${URLS[0]}"; rm -f "$T/out" "$TMP"/cand.*; fetch_verified "$T/out" >/dev/null 2>&1; }
chk() { [[ "$2" == "$3" ]] || { echo "FAIL $1: got $2 want $3"; fail=1; }; }
unset HASHEM_SHA256 HASHEM_ALLOW_UNVERIFIED
# file:// URLs share one "host" (empty), so use distinct fake hosts via query-less paths:
# host = text before the first '/', after '://'. Build pseudo-hosts with file://hostN/... is not
# fetchable, so override url_host to key on the directory.
url_host() { basename "$(dirname "${1#file://}")"; }

run "file://$T/a/hashem.sh" "file://$T/c/hashem.sh"; chk "canonical copy trusted" $? 0
chk "canonical content" "$(cat "$T/out")" "${good%$'\n'}"
run "file://$T/missing/hashem.sh" "file://$T/c/hashem.sh"; chk "lone mirror refused" $? 1
run "file://$T/missing/hashem.sh" "file://$T/c/hashem.sh" "file://$T/d/hashem.sh"; chk "two agreeing mirrors accepted" $? 0
run "file://$T/missing/hashem.sh" "file://$T/a/hashem.sh" "file://$T/c/hashem.sh"; chk "disagreeing mirrors refused" $? 1
export HASHEM_SHA256="$GOOD"
run "file://$T/c/hashem.sh" "file://$T/b/hashem.sh"; chk "pinned hash skips evil, takes match" $? 0
chk "pinned content" "$(cat "$T/out")" "${good%$'\n'}"
export HASHEM_SHA256="deadbeef"
run "file://$T/a/hashem.sh"; chk "wrong pin refuses even canonical" $? 1
unset HASHEM_SHA256
export HASHEM_ALLOW_UNVERIFIED=1
run "file://$T/missing/hashem.sh" "file://$T/c/hashem.sh"; chk "explicit opt-out accepts lone mirror" $? 0
unset HASHEM_ALLOW_UNVERIFIED
printf '#!/bin/bash\nif then\n' > "$T/a/hashem.sh"
run "file://$T/a/hashem.sh"; chk "syntax-broken script refused" $? 1
[[ $fail -eq 0 ]] && echo "PASS test_install_verify" || exit 1
