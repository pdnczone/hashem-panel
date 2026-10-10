# Shell-layer audit report

Scope: hashem.sh, hashem-chaff.sh, install.sh, tests/*.sh, docs/*.md, README.md. panel/ and Backhaul were not edited. No commit, no push, no server access, nothing under /etc touched.

## FIXED

- `hashem.sh:~400-410` (new `tcpmux_eof_hint`): read-only check. When `frpc.toml` exists and the last 200 lines of the frpc journal contain `connect to server error: EOF`, it prints "tcpMux mismatch: hub is likely tcpMux=true, run `hashem perf tcpmux on|off`". It never changes config.
  - Wired into `check_status` (`hashem status`), in the frpc-active branch.
  - Wired into `doctor_health_check` (`hashem doctor`) as a WARN item "FRP tcpMux match".
- `hashem.sh` `cli_perf status`: when `tcp_mux` is unset, it now still prints the live tcpMux value on both the frpc and frps roles. It notes that a missing line means FRP's own default (on) and that the value must match the other end. Before, the live value was hidden whenever the setting was unset, which is exactly when a legacy-toml mismatch happens.
- `hashem.sh` (perf_apply frpc/frps python blocks, `setup_iran` and `peer_write_frps` MAX_POOL read, `autotune_tick`, the `update_all` perf.json migration): hardcoded `/etc/gre-panel/perf.json` replaced with `$PERF_FILE`. `PERF_FILE` honours `GRE_PANEL_DIR`. Before this, running with `GRE_PANEL_DIR` set still read and rewrote the real `/etc` file. This was the CLAUDE.md rule "never hardcode /etc/gre-panel".
- `README.md` (Performance section) and `docs/FRP_TUNNELS_GUIDE.md` (Persian note under TCP): default is OFF, must match on hub and every spoke, `connect to server error: EOF` is the symptom, and `status`/`doctor` print a hint.
- `tests/test_tcpmux_default.sh` (new): checks that unset, `false` and `{}` all write `transport.tcpMux = false` with no keepalive, that `true` writes the keepalive line, and that the hint appears only with `frpc.toml` plus an EOF in the journal and never modifies the config.

## REPORTED-NOT-FIXED

- **MEDIUM — legacy toml out of sync with a new spoke.** An old hub `frps.toml` with no `transport.tcpMux` line runs with FRP's default (true). If `perf.json` has no `tcp_mux` key, `perf_apply` leaves it untouched, but a NEW spoke (`setup-foreign`) is written with `false`. Result: EOF on login. I did not auto-fix it, because flipping a live hub restarts every spoke. The new status line and the doctor hint now surface it. Proposed fix, for the owner to decide: `update_all` or a one-time migration writes explicit `tcp_mux:false` and applies it to both ends.
- **MEDIUM — the same split can happen via `add-peer`.** `add-peer` writes `frps-N.toml` using the current `tcp_mux`, so a hub can hold peers with different values. This is correct per pair, but `cli_perf status` ORs files together: LIVE_MUX is off if ANY frps file is false.
- **MEDIUM — `perf tcpmux on|off` applies to the local host only.** The operator must run it on both ends. There is no remote check.
- `install.sh:31-36` (MEDIUM, supply chain): the installer fetches and runs `hashem.sh` with no checksum or signature, and falls back to third-party proxies (`mirror.ghproxy.com`, `ghproxy.net`). A malicious mirror gets root code execution. A fix needs a pinned hash or release-signature design.
- `README.md:158,152,...` (LOW): links point to `docs/en/panel/*.md`, but `docs/en` is not in the repo, so they are 404s. Fixing means writing those docs or relinking.
- `hashem.sh:~3290` (LOW, informational): frpc.toml carries `transport.heartbeatTimeout`. It is valid for frpc in v0.50+, so I left it. frps correctly has only `heartbeatTimeout`, and frpc has `heartbeatInterval`.
- `hashem.sh` (LOW): widespread `local X=$(cmd)` masks exit codes, for example in `cli_perf status` and `autotune_tick`. The script does not use `set -e`, so there is no behavioural bug today, but the `|| echo` fallbacks hide failures.
- Issue #5 (tunnel layout) lives in `panel/index.html` and the CSS. I did not investigate it, because panel/ is out of scope.
- panel/ (not audited; owned by another agent): `rescue.go` and `perf.go` already use `tcpMuxTomlLines()` (OFF unless enabled). `perf.go:544` pins false on "safe defaults".

## TCPMUX AUDIT

| Path | Result |
|---|---|
| `setup_iran` (frps.toml, hashem.sh:~3069) | `$(perf_tcpmux_lines)`: false unless `tcp_mux` is true. No keepalive when false. OK |
| `setup_foreign` (frpc.toml, ~3279) | Same. OK |
| `peer_write_frps` (add-peer, frps-N.toml, ~3926) | Same. OK |
| Dial / public-IP fallback (`dial_pick`, `dial_env_write`, sed at ~1341) | Only rewrites `serverAddr`. Does not touch tcpMux. OK |
| `perf_apply` frpc and frps (python) | Strips old `tcpMux`/`tcpMuxKeepaliveInterval`, writes the explicit value only when `tcp_mux` is 0 or 1. With false it carries no keepalive. When unset it leaves tomls untouched (see below). OK |
| `perf_get_tcpmux` returning empty when unset | Correct. New configs are false via `perf_tcpmux_new`. Existing files are never silently flipped. The trade-off is the legacy-toml split above, now visible in status and the doctor. |
| update_all / restore | Do not write tcpMux. They call `perf_apply`, which is a no-op for tcpMux when unset. The perf.json migration there resets force_tls, chaff and auto_tune, but not `tcp_mux`. OK |
| Watchdog restart paths | `systemctl restart` only, no toml writes. OK |
| Backhaul writers | Not touched, per instructions. |
| Go writers (`rescue.go` via `tcpMuxTomlLines`) | Read only. Default false. |
| Docs/README | Updated. UI text (`panel/index.html` `perf_mux_hint`) already says to keep it OFF and that it must match. The UI was not edited and its fa/en i18n was not checked. |
| One side true and the other false | Possible via (a) a legacy hub toml with no line, (b) `perf tcpmux` run on only one host, (c) a spoke added after the operator turned mux on. All three now show up in the status lines and the EOF hint. |

## TESTS RUN

- `bash -n` on hashem.sh, hashem-backhaul.sh, hashem-chaff.sh, install.sh: all OK (no output).
- `bash tests/test_backhaul_schema.sh`: PASS test_backhaul_schema
- `bash tests/test_dial_route.sh`: dial route: all OK
- `bash tests/test_legacy_units.sh`: PASS test_legacy_units
- `bash tests/test_wss_front.sh`: PASS test_wss_front
- `bash tests/test_tcpmux_default.sh` (new): PASS test_tcpmux_default
- **Not run:** `go vet ./...`, `go build -o /tmp/hp-test-bin`, `go test ./...`. The sandbox blocked every go command with "This command requires approval", so I did not run them. I made no Go changes, so a Go regression from my edits is not possible, but the repo-level Go result is unverified. Run them before merging.
- No tests failed. I did not check which tests failed before my changes.
