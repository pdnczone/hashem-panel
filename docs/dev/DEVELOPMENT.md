# Development guide

## What this repo is
Hashem Panel: a hub-and-spoke tunnel manager. An Iran hub runs `frps` / Backhaul server and owns the public ports. Foreign spokes run `frpc` / Backhaul client and dial the hub. GRE (L3) is the carrier underneath. It has two parts:
- Installer/CLI: `hashem.sh` (installed as `hashem`), plus `install.sh`. Both are bash, and systemd manages the services.
- Panel: a Go backend (`gre-panel`) with a single-page web UI.

## Layout
- `hashem.sh` — interactive menu and non-interactive CLI (`hashem setup-iran ...`). Owns setup, tuning, perf, watchdog and carrier logic.
- `install.sh` — one-line installer that fetches release binaries.
- `panel/` — Go module, flat `package main`. Each feature has its own file (`setup.go`, `perf.go`, `watchdog.go`, `carrier.go`, `fleet.go`, `peer.go`, `tlsproxy.go`, `update.go`, `dashboard.go`, ...) with a matching `*_test.go`. The UI is `index.html` plus `*.css` and the vendored xterm and fonts.
- `tests/` — bash regression scripts (`test_*.sh`): backhaul schema, dial route, legacy units, WSS front, watchdog/backup/install checks. `test_backhaul_e2e.sh` and `test_revpath_lab.sh` need netns/real binaries and are lab-only (CI skips them).
- `panel/app.js` — the whole UI script (embedded and served with `index.html`); keep new UI code there, not inline.
- `docs/` — deployment, FRP and engine guides, generated API and error-code references (`tools/gen_docs.py`), audit reports in `docs/audit/`. Root keeps `README.md`, `SECURITY.md`, `CHANGELOG.md`, `CONTRIBUTING.md`.
- Runtime config lives in `/etc/gre-panel` (`watchdog.json`, `perf.json`, `carrier.json`, ...) and `/etc/frp`. Both are overridable with `GRE_PANEL_DIR`.

## Build / verify
```
bash -n hashem.sh                      # syntax check (also install.sh)
cd panel && /usr/local/go/bin/go vet ./... && /usr/local/go/bin/go build
cd panel && /usr/local/go/bin/go test ./...
for t in tests/test_*.sh; do bash "$t"; done
cd panel && /usr/local/go/bin/go test -race ./...   # CI also runs this
```
Run all of these before opening a pull request.

## Rules
- `hashem.sh` is the single source of truth for tuning and setup logic. The Go panel shells out to it. Do not reimplement that logic in Go.
- Every Go exec of a script must use `context.WithTimeout` and set env `TERM=dumb GRE_SKIP_PANEL=1`.
- Never hardcode `/etc/gre-panel` in Go. Use `configDir`.
- Never touch production servers or use SSH unless the user explicitly asks.
- Commit to `dev`; `main` only changes through a reviewed `dev → main` pull request.
- After changing routes in `panel/main.go` or codes in `panel/errors.go`, run `python3 tools/gen_docs.py` and commit `docs/API.md` and `docs/ERROR_CODES.md`.
- The carrier stays manual GRE unless the user switches it.
- Watchdog `auto_restart` defaults to `false`.
- Match the surrounding style, comment density and naming. Keep changes minimal.
