# CLAUDE.md

## What this repo is
Hashem Panel: a hub-and-spoke tunnel manager. An Iran hub runs `frps` / Backhaul server and owns the public ports. Foreign spokes run `frpc` / Backhaul client and dial the hub. GRE (L3) is the carrier underneath. It has two parts:
- Installer/CLI: `hashem.sh` (installed as `hashem`), plus `hashem-backhaul.sh` and `hashem-chaff.sh`. All are bash, and systemd manages the services.
- Panel: a Go backend (`gre-panel`) with a single-page web UI.

## Layout
- `hashem.sh` — interactive menu and non-interactive CLI (`hashem setup-iran ...`). Owns setup, tuning, perf, watchdog and carrier logic.
- `install.sh` — one-line installer that fetches release binaries.
- `panel/` — Go module, flat `package main`. Each feature has its own file (`setup.go`, `perf.go`, `watchdog.go`, `carrier.go`, `fleet.go`, `peer.go`, `tlsproxy.go`, `update.go`, `dashboard.go`, ...) with a matching `*_test.go`. The UI is `index.html` plus `*.css` and the vendored xterm and fonts.
- `tests/` — bash regression scripts (`test_*.sh`): backhaul schema, dial route, legacy units, WSS front.
- `docs/` — deployment and FRP guides. Also `README.md`, `SECURITY.md`, `AUDIT_*.md`.
- Runtime config lives in `/etc/gre-panel` (`watchdog.json`, `perf.json`, `carrier.json`, ...) and `/etc/frp`. Both are overridable with `GRE_PANEL_DIR`.

## Build / verify
```
bash -n hashem.sh                      # syntax check (also hashem-backhaul.sh, hashem-chaff.sh, install.sh)
cd panel && /usr/local/go/bin/go vet ./... && /usr/local/go/bin/go build
cd panel && /usr/local/go/bin/go test ./...
for t in tests/test_*.sh; do bash "$t"; done
```
Run all of these before saying work is done. Report failures verbatim.

## Rules
- `hashem.sh` is the single source of truth for tuning and setup logic. The Go panel shells out to it. Do not reimplement that logic in Go.
- Every Go exec of a script must use `context.WithTimeout` and set env `TERM=dumb GRE_SKIP_PANEL=1`.
- Never hardcode `/etc/gre-panel` in Go. Use `configDir`.
- Never touch production servers or use SSH unless the user explicitly asks.
- Never `git commit` or `git push`. The supervisor does that.
- The carrier stays manual GRE unless the user switches it.
- Watchdog `auto_restart` defaults to `false`.
- Match the surrounding style, comment density and naming. Keep changes minimal.
