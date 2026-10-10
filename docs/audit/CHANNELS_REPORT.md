# Update channels (stable / dev) — implementation report

Branch `dev`, nothing committed or pushed. No server, SSH, systemd or Backhaul was touched.

## Files
| File | Change |
|---|---|
| `.github/workflows/build-panel.yml` | `dev` branch trigger; `dev-r<run>` build (`-X main.panelVersion=dev-r<run>`); new **Create release (Dev)** step (`prerelease: true`, `make_latest: "false"`, full asset list incl. `checksums.txt`); tag step gets `prerelease: false`, `make_latest: "true"`; legacy main step kept, now guarded by `github.ref == 'refs/heads/main'` (so dev pushes can't hit it) and commented `# legacy: remove after v1.0.0 is published` |
| `.github/workflows/security.yml` | CI also on `dev` (push + PR) |
| `panel/update_channel.go` (new) | channel config, `compareVersions`, `displayVersion`, `updateAvailable`, channel-aware `latestReleaseTag`, `handleVersion`, `/api/update/channel`, `/api/releases`, per-tag script fetch |
| `panel/update.go` | removed old `handleVersion`/`latestReleaseTag`; display-normalised messages; `syncPanelScriptFrom(tag)` / `syncChaffScript(tag)` use `fetchScript` |
| `panel/main.go` | 3 routes |
| `panel/errors.go` | `E-UPDATE-08` (400, invalid channel) — `E-SYS-01` has status 0 in the catalog, so it can't be reused |
| `panel/index.html` | Update tab: channel select, DEV badge, dev warning, i18n (en + fa) |
| `hashem.sh` | `update_get_channel`, `update_set_channel`, `update_pick_tag`, `cli_update_channel`; `install_panel` and `update_all` use the channel's tag; `hashem update-channel [stable|dev]`; usage + menu hint |
| `tests/test_update_channel.sh`, `panel/update_channel_test.go` (new) | see Tests |

## Behaviour
- Channel lives in `<configDir>/update.json` `{"channel":"stable"|"dev"}`. Anything else reads as `stable`. POST validates strictly and writes 0600 via tmp+rename.
- **stable** = highest `^vX.Y.Z$` that is not prerelease or draft (semver compare, so v1.0.10 > v1.0.9). If no semver stable exists, the newest non-prerelease. If that is empty or the list fetch fails, `releases/latest`.
- **dev** = highest `dev-rN` prerelease by number. It never falls back to stable.
- `/api/version` → `{current, latest, channel, update_available}`. `current` = `v1.0.0` for `panel-rN`, N ≤ 148 (`legacyPanelRBase`, `legacyDisplay`). Otherwise it is `panelVersion` as is. `latest` also goes through `displayVersion`.
- `compareVersions` ranks: semver > `dev-rN` > `panel-rN` > unknown. `panel-r148 < v1.0.0 < v1.0.1 < v1.1.0`, `dev-r5 < dev-r12`.
- `updateAvailable` is strict "newer". One deliberate extra: on channel `dev`, a host that is not running a `dev-r` build is offered the newest dev build, since otherwise switching to dev would never offer anything.
- `handleUpdate` refuses if `latest == panelVersion`. The download URL is the channel's tag, and only falls back to `releases/latest/download` when the tag couldn't be determined. Checksum fail-closed, ELF check, `.bak` rollback and restart are unchanged.
- **Script sync**: `hashem.sh` and `hashem-chaff.sh` come from `releases/download/<tag>/…`, verified against that tag's `checksums.txt` (fail-closed, same `bash -n` and header checks). Only a missing tag asset falls back to the old `main` raw URL. A checksum mismatch never falls back. `ensureFreshScript` (setup.go) uses the running binary's own tag when it is `vX.Y.Z` or `dev-rN`, else `main`.
- `GET /api/releases?channel=` (auth): up to 20 non-draft releases of the channel (tag, name, date, prerelease), sorted by version. Stable also lists legacy `panel-rN` releases. `?channel=beta` gives 400.
- CLI: `hashem update-channel` prints the current channel. `hashem update-channel dev|stable` sets it, anything else fails. `hashem update` picks the tag via `update_pick_tag` and downloads the panel binary, `grepanel` and `hashem.sh` from that tag. The `main` raw URL is only a fallback for stable. Dev with no dev release aborts without changes.

## Tests
- Go (`update_channel_test.go`), run with `safe_gotest.sh`:
  - compareVersions table
  - displayVersion (r148/r10 → v1.0.0, r149 stays)
  - stable pick ignores prerelease, draft, `panel-r*`, `dev-r*` and odd tags like `v.0.1.1` and `v1.0.2-rc1`
  - dev picks by number (dev-r30 > dev-r9)
  - fallbacks: pre-v1 stable, `releases/latest`, list down, everything down
  - dev never crosses channels
  - updateAvailable matrix
  - `/api/version` has no `panel-r` for a r148 host
  - channel endpoint rejects `beta`, `../x`, empty, `{}`, garbage and `Dev`, writes nothing on rejection, and writes 0600 on success
  - `/api/releases` filtering
  - `fetchScript` URL choice: tag URL, checksum mismatch → error with no main fallback, missing asset → main, empty tag → main
- Shell: `tests/test_update_channel.sh` (fake `curl`; stable, dev, minified JSON, prerelease semver ignored, fallbacks, CLI verb, 0600, corrupt/invalid config).
- Results are in the final message of the run (all green except the item below).
- **Not run**: `node --check` on the inline JS. Executing node needs approval in this environment. The JS change is about 12 lines (the `loadVersion` additions and the `updChannel` onchange handler). Please run it once.

## Publishing v1.0.0 (owner)
1. Merge `dev` → `main`. (Until the legacy rule is removed, this also creates one more `panel-r<N>` Latest. Harmless: old hosts will upgrade to it, then to v1.0.0.) To avoid that, tag from `dev` without merging.
2. `git tag -a v1.0.0 -m "…" && git push origin v1.0.0`. The tag step publishes a non-prerelease with `make_latest: true` and the assets `gre-panel-linux-amd64`, `gre-panel-linux-arm64`, `grepanel`, `hashem.sh`, `hashem-chaff.sh`, `hashem-backhaul.sh`, `checksums.txt`, plus the `hashem-v1.0.0-linux-*` copies. This matches the r148 asset names.
3. Verify `releases/latest` returns `v1.0.0`. Then delete the legacy `main` → `panel-r<run>` step so main pushes stop becoming Latest.

**How r148 hosts see it:** the old updater reads `/releases/latest` → `v1.0.0`, sees `v1.0.0 != panel-r148`, downloads `…/download/v1.0.0/gre-panel-linux-<arch>` and verifies against `checksums.txt`. It then syncs scripts from `main` (old behaviour). After the update the host runs the new binary: it shows `v1.0.0` and follows the channel logic. Dev prereleases are never "Latest", so old hosts can't be pulled onto dev.

## Open risks
- `panel-rN` with N > 148 (builds from the legacy `main` rule after r148) is shown as-is, so `panel-r*` can still appear in the UI for those. It also ranks below any semver, so such a host is offered v1.0.0 — that is a lateral hop, not a downgrade of code. Fix by flipping the legacy rule (step 3).
- r148 and older hosts still sync scripts from `main` on update (their code can't change). A script on `main` newer than v1.0.0's binary can leak to them once.
- If the owner cuts v1.0.0 from the commit of r148's build but `main` has moved on, `hashem.sh` fetched by r148 hosts from `main` ≠ v1.0.0's. Keep `main` and the tag in step at release time.
- `hashem.sh` JSON parsing of the release list is `tr`/`awk` text parsing. It only trusts rows with `tag_name`, `draft` and `prerelease` in GitHub's field order. Verified against pretty and minified JSON. A release body containing literal `"prerelease":` unescaped can't occur (JSON escapes quotes).
- `hashem.sh` itself has no checksum verification of downloaded assets (unchanged, out of scope).
- Mirror API URLs (`mirror.ghproxy.com`, `ghproxy.net`) are trusted for the release list. A hostile mirror could only steer the tag choice. Binaries are still checksum-verified, but the manifest comes from the same mirror path (pre-existing).
- `install.sh` untouched, as asked.
