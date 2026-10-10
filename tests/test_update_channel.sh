#!/usr/bin/env bash
# Regression: update channel pick (stable = newest vX.Y.Z non-prerelease, dev = newest dev-rN prerelease).
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin"
export PATH="$T/bin:$PATH" GREEN= YELLOW= RED= NC=
PANEL_CONFIG_DIR="$T/etc"; mkdir -p "$PANEL_CONFIG_DIR"
fail=0
ext() { awk -v n="$1" '$0 ~ "^"n"\\(\\) \\{" {p=1} p {print} p && /^}/ {exit}' "$ROOT/hashem.sh"; }
UPDATE_FILE="$PANEL_CONFIG_DIR/update.json"
UPDATE_API="https://api.github.com/repos/pdnczone/hashem-panel"
for f in update_get_channel update_set_channel update_tag_ok update_verify_asset update_pick_tag cli_update_channel; do
  body="$(ext $f)"; [[ -n "$body" ]] || { echo "FAIL: $f missing"; exit 1; }; eval "$body"
done

# fake curl: serves $T/list.json for the releases list, $T/latest.json for /releases/latest
cat > "$T/bin/curl" <<'EOT'
#!/bin/sh
for a; do u="$a"; done
case "$u" in
  *releases/latest) [ -f "$FAKE_DIR/latest.json" ] && cat "$FAKE_DIR/latest.json" || exit 22 ;;
  *releases\?per_page=30) [ -f "$FAKE_DIR/list.json" ] && cat "$FAKE_DIR/list.json" || exit 22 ;;
  *) exit 22 ;;
esac
EOT
chmod +x "$T/bin/curl"; export FAKE_DIR="$T"

rel() { printf '  {"tag_name": "%s", "name": "x", "draft": %s, "prerelease": %s, "assets": [{"name": "a", "prerelease": false}]},\n' "$1" "$2" "$3"; }
{
  echo '['
  rel dev-r30 false true
  rel dev-r9 false true
  rel v1.0.1 false true      # prerelease semver: must be ignored on stable
  rel v1.0.0 false false
  rel v1.0.10 true false     # draft: ignored
  rel v.0.1.1 false false    # odd tag
  rel v1.0.2-rc1 false false # odd tag
  rel v0.9.0 false false
  rel panel-r148 false false
  rel panel-r200 false false
  echo '  {"tag_name": "dev-r2", "draft": false, "prerelease": true}'
  echo ']'
} > "$T/list.json"
# minified variant must work too
tr -d '\n' < "$T/list.json" > "$T/list.min.json"

chk() { [[ "$2" == "$3" ]] || { echo "FAIL $1: got '$2' want '$3'"; fail=1; }; }

chk "default channel" "$(update_get_channel)" stable
chk "stable pick" "$(update_pick_tag)" v1.0.0
cp "$T/list.min.json" "$T/list.json.bak"; mv "$T/list.json" "$T/list.pretty"; cp "$T/list.min.json" "$T/list.json"
chk "stable pick (minified)" "$(update_pick_tag)" v1.0.0
mv "$T/list.pretty" "$T/list.json"

update_set_channel dev || { echo "FAIL set dev"; fail=1; }
chk "channel dev" "$(update_get_channel)" dev
chk "dev pick numeric max" "$(update_pick_tag)" dev-r30
chk "update.json mode" "$(stat -c %a "$UPDATE_FILE")" 600
update_set_channel beta 2>/dev/null && { echo "FAIL beta accepted"; fail=1; }
chk "channel unchanged after bad set" "$(update_get_channel)" dev
echo '{"channel": "../x"}' > "$UPDATE_FILE"
chk "invalid channel => stable" "$(update_get_channel)" stable
echo 'not json' > "$UPDATE_FILE"
chk "corrupt file => stable" "$(update_get_channel)" stable
rm -f "$UPDATE_FILE"

# fallback: no semver stable => GitHub's releases/latest
{ echo '['; rel dev-r3 false true; rel panel-r148 false false; echo '  {"tag_name": "panel-r149", "draft": false, "prerelease": false}'; echo ']'; } > "$T/list.json"
echo '{"tag_name": "panel-r149", "name": "x"}' > "$T/latest.json"
chk "stable fallback to latest" "$(update_pick_tag)" panel-r149
# list unreachable => latest
rm -f "$T/list.json"
chk "stable list down => latest" "$(update_pick_tag)" panel-r149

# dev never falls back to stable
update_set_channel dev
chk "dev list down => empty" "$(update_pick_tag)" ""
{ echo '['; rel v1.0.0 false false; echo '  {"tag_name": "panel-r1", "draft": false, "prerelease": false}'; echo ']'; } > "$T/list.json"
chk "dev with no dev release => empty" "$(update_pick_tag)" ""

# CLI verb
update_set_channel stable
chk "cli prints current" "$(cli_update_channel)" stable
cli_update_channel dev >/dev/null; chk "cli sets dev" "$(update_get_channel)" dev
cli_update_channel nope >/dev/null 2>&1 && { echo "FAIL cli accepted nope"; fail=1; }


# tag validation: nothing but vX.Y.Z / dev-rN / panel-rN may reach a URL
for bad in "" "../x" "v1.0.0/../o" "v1.0.0?x" "v1.0.0 y" "x/y" "latest" "v1.0"; do
  update_tag_ok "$bad" && { echo "FAIL update_tag_ok accepted '$bad'"; fail=1; }
done
for ok in v1.0.0 v12.3.45 dev-r7 panel-r148; do
  update_tag_ok "$ok" || { echo "FAIL update_tag_ok rejected '$ok'"; fail=1; }
done

# hostile fallback tag from /releases/latest must be dropped (stable, empty list)
printf '{"tag_name": "x/../../../other/repo/releases/download/t"}' > "$T/latest.json"; rm -f "$T/list.json"
printf '{"channel": "stable"}' > "$PANEL_CONFIG_DIR/update.json"
[[ -z "$(update_pick_tag)" ]] || { echo "FAIL hostile latest tag accepted: $(update_pick_tag)"; fail=1; }

# checksum verification: match=0, mismatch=1, no manifest=2
printf 'hello' > "$T/f"; good=$(sha256sum "$T/f" | awk '{print $1}')
cat > "$T/bin/curl" <<'EOT'
#!/bin/sh
for a; do u="$a"; done
case "$u" in *checksums.txt) [ -f "$FAKE_DIR/sums" ] && cat "$FAKE_DIR/sums" || exit 22 ;; *) exit 22 ;; esac
EOT
printf '%s  hashem.sh\n' "$good" > "$T/sums"; update_verify_asset "$T/f" v1.0.0 hashem.sh; [[ $? -eq 0 ]] || { echo "FAIL verify match"; fail=1; }
printf '%s  hashem.sh\n' "0000" > "$T/sums"; update_verify_asset "$T/f" v1.0.0 hashem.sh; [[ $? -eq 1 ]] || { echo "FAIL verify mismatch"; fail=1; }
rm -f "$T/sums"; update_verify_asset "$T/f" v1.0.0 hashem.sh; [[ $? -eq 2 ]] || { echo "FAIL verify no manifest"; fail=1; }

[[ $fail -eq 0 ]] && echo "PASS: update channel pick"
exit $fail
