# Audit fix report

No commits, no pushes, no SSH, no real systemctl. Go tests were run only through `safe_gotest.sh`. Backhaul logic is untouched. Its paths now use `backhaulDir`, which has the same default.

## Fix A — Go code testable without touching /etc/frp
- **Files:** `panel/main.go`, `carrier.go`, `perf.go`, `rescue.go`, `setup.go`, `tunnel.go`, `test_main_test.go`, `live_switch_test.go`.
- **What:**
  - `main.go` declares `frpDir = "/etc/frp"` and `backhaulDir = "/etc/backhaul"` next to `configDir`. The env overrides are `GRE_FRP_DIR` and `GRE_BACKHAUL_DIR`, set beside the existing `GRE_PANEL_DIR` handling.
  - Every `/etc/frp/...` and `/etc/backhaul/...` path literal in non-test code now uses `filepath.Join(frpDir|backhaulDir, ...)`. Defaults are identical, so production behavior is unchanged.
  - `rescueFrpConfigs` is now nil by default. The new `rescueFrpConfigList()` builds the defaults from `frpDir` at call time. Existing tests that assign the var still work.
  - New `var runSystemctl = func(args ...string) error` in `main.go`. It is used by `switchTunnelEngine` and `ensureFRPServiceUnits` in `tunnel.go`, and by all systemctl calls in `setup.go` (port rewrite, remote-IP change, legacy main-tunnel ports).
  - `TestMain` sets `frpDir` and `backhaulDir` to subdirs of the temp `configDir` and stubs `runSystemctl` to a no-op.
  - `live_switch_test.go` had `MkdirAll` and `RemoveAll("/etc/backhaul")` with a literal path. That would have deleted the real directory, so it now uses `backhaulDir`.
- **Left as is:**
  - `setup.go:1956-1957` writes `tls_cert = "/etc/backhaul/server.crt"` into a generated Backhaul config. That is file content, not a path the panel reads, and it is Backhaul code.
  - Other `exec.Command("systemctl", ...)` calls (restart in `tunnel.go`, `dashboard.go`, `doctor.go`, `update.go`, etc.) are outside the requested scope.
- **Tests added:** none for this fix. It is infrastructure, and the whole suite now runs against temp dirs.

## Fix B — rescue code carries tcpMux
- **Files:** `panel/rescue.go`, `panel/perf.go`, new `panel/rescue_mux_test.go`.
- **What:**
  - `rescueCode` gets `M *bool` (`json:"m,omitempty"`). `rescueEncode` sets it from the origin's `tcpMuxEnabled()`.
  - `rescueEnableEntry` uses `*c.M` when present, otherwise the local `tcpMuxEnabled()`. Old codes without `M` therefore behave as before.
  - New `rescueEntryFrpcTomlMux(..., mux bool)`. The old `rescueEntryFrpcToml` calls it with `tcpMuxEnabled()`.
  - New `tcpMuxTomlLinesFor(mux)`. `tcpMuxTomlLines()` now calls it.
- **Tests added** (4):
  - `TestRescueCodeCarriesOriginMux` covers M=true and M=false round trips.
  - `TestRescueCodeWithoutMuxDecodesNil` covers a code with M absent: it is omitted from the JSON and decodes as nil.
  - `TestRescueEntryTomlMux` checks `tcpMux = true` plus keepalive for mux=true, and `= false` with no keepalive for mux=false.
  - `TestRescueEntryTomlLegacyUsesLocalMux` checks the old signature follows the local setting.
- **Result:** all 4 pass. The full suite passes.

## Fix C — README broken links
- **File:** `README.md`.
- **What:**
  - All 10 `docs/en/panel/*.md` links are removed. No existing doc fits those panel tabs, so I added no new text.
  - The arrow lines, the "Details:" lines and the "Other tabs" link targets are gone. The tab descriptions are kept.
  - The Documentation map keeps the Guides line (DEPLOYMENT.md, FRP_TUNNELS_GUIDE.md) and the Policy line.
  - `gre-frp.md` now points to `docs/FRP_TUNNELS_GUIDE.md`.
  - Screenshots are unchanged.
- **Beyond the 10 listed:** I also removed the other dead links to `docs/en/index.md`, `docs/fa/index.md`, `docs/en/tunnels/{gre-backhaul,backhaul-standalone,carriers}.md` and `docs/en/development/branches-and-releases.md`. The same bug applied to them.
- **Result:** no `docs/en` or `docs/fa` references remain in `README.md`.

## Fix D — legacy-hub tcpMux warning
- **File:** `hashem.sh`, in `update_all` as new step 7 before `perf_apply`.
- **What:** if `perf_get_tcpmux` is empty (`tcp_mux` unset), the step checks each `$CONFIG_DIR/frps*.toml` (`CONFIG_DIR=/etc/frp`). A file with no `transport.tcpMux` line gets this one-line warning:
  `frps<N>.toml has no transport.tcpMux line (FRP default = ON); set explicitly with: hashem perf tcpmux on|off on hub AND spokes`
- **Nothing is written.** It is read-only, so it is idempotent and cannot flip a live pair.
- **Tests added:** none. I did not run the warning path because `update_all` downloads and replaces the installed script. `bash -n` passes.

## Verification (verbatim)
- `bash -n hashem.sh`: `SYNTAX_OK`.
- Bash tests, each run alone (a `for` loop was blocked by the sandbox):
  - `PASS test_backhaul_schema`
  - `dial route: all OK`
  - `PASS test_legacy_units`
  - `PASS test_tcpmux_default`
  - `PASS test_wss_front`
- `go vet ./... && go build -o /tmp/hp-fix-bin`: `VET_BUILD_OK`, no output from vet.
- `safe_gotest.sh ./...`: `ok  	github.com/pdnczone/hashem-panel/panel	20.484s`
- `grep '"/etc/frp' panel/*.go | grep -v _test`: only `main.go:34:	frpDir      = "/etc/frp"`. No rescue default remains, because it is built from `frpDir`.
