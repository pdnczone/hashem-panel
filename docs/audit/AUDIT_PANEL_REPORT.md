# Hashem Panel audit (Go + UI scope)

Scope: `panel/*.go`, `panel/index.html`, `panel/*.css`. I did not edit `hashem.sh`, `tests/`, `install.sh`, docs or README, and did not touch Backhaul. Nothing is committed.

## FIXED
- `panel/errors.go` (new `E-FRP-10`, plus a case at the top of `matchLogCode`): `connect to server error: EOF` in a log line is now classified. The hint reads "tcpMux mismatch: hub is likely tcpMux=true, run `hashem perf tcpmux on|off`". It shows up in the log findings header. Hint only, nothing is changed automatically. Test: `TestFrpcLoginEOFHint` in `perf_tcpmux_test.go`.
- `panel/doctor.go` (`frpcLoginEOF`, called as step 1b in `runFullDiagnostics`): on a spoke (`FrpSvc == "frpc"`) the doctor reads the last 50 frpc journal lines (read-only, 5 s `context.WithTimeout`). If it sees the EOF pattern it adds the issue and the same hint. It deliberately does not subtract from the score.
- `panel/wss_carrier.go:106` and `:293`: `localStatus().Role` is `"foreign (client)"` or `"iran (server)"`, never `"foreign"` or `"iran"`. The `==` checks could never match. The default WSS role was always "server", and `auto` always resolved to "client", even on the Iran hub. Both now use `strings.HasPrefix`.
- `panel/index.html:~83` (**issue #5**, Tunnel tab layout): `.tunnel-card{display:flex}` overrides the `hidden` attribute. `#dialCard` ("Route to the Iran hub") has `hidden` but no `[hidden]` rule, so it always rendered as an empty card with a "—" badge, even on hubs where `dialRender()` sets `card.hidden = true`. I added `.tunnel-card[hidden], .qs[hidden] { display:none; }`. I could not read the issue text (no network or remote access here), so I don't know whether this is the whole of what was reported. It is the one concrete layout defect I found in the tab's markup and CSS.
- `panel/index.html` (`perf_mux_hint` in the HTML default, the en dictionary and the fa dictionary): the text said "Keep OFF"; it now says "Default is OFF (max speed)" and still says both ends must match. The fa text was changed to match.

## REPORTED-NOT-FIXED
- **Rescue code does not carry tcpMux** (`rescue.go:210-227`, `rescueCode` at ~`:330`). `rescueFrpsToml` runs on the blocked side and `rescueEntryFrpcToml` on the reachable side. Each reads its own node's `perf.json`. If the two nodes differ (one has `tcp_mux=true`), rescue login fails with EOF. Severity: medium. Fix: add an optional `m` bool (`omitempty`) to `rescueCode` and have the entry side use it. That changes the rescue wire format and the `rescueEntryFrpcToml` signature (used by tests), so I left it.
- **`tunnel.go:942-946` reads `tls_enabled`**, but perf.json only has `force_tls`. The key never exists, so engine switch → FRP never writes `transport.tls.force = true` on the hub, whatever `Force TLS` says. Severity: medium. Switching the key would start forcing TLS on the hub, and the foreign side doesn't write the matching frpc line in this path (only `shell setup` does), which could break login. That needs a decision from the owner.
- **tcpMux unset (nil) never touches live tomls.** This is correct for existing pairs, because it can't desync them. New configs get `false` via `tcpMuxTomlLines()`. The risk is a pair created before the default flipped: the hub may be `true` and a fresh spoke `false`. The new doctor/log hint detects this on the spoke. `checkLiveTomlSync` only compares when `tcp_mux` is set, so the UI says "not set" with no mismatch warning. Severity: low.
- `liveTCPMux()` returns "on" for a toml missing the key. That matches frp, where a missing key means true. It is correct, but it makes legacy files show as "slower path active".
- **Hardcoded `/etc/frp`** in Go (`perf.go`, `tunnel.go`, `setup.go`, `rescue.go`, `carrier.go`). CLAUDE.md says `configDir` for `/etc/gre-panel` only, and there is no frp-dir override variable. Tests can't isolate these paths. Severity: low.
- Several `exec.Command` calls without a context timeout: `tunnel.go` (`systemctl`, `journalctl`, `ip`), `perf.go` (`iptables`, `systemctl`). CLAUDE.md requires timeouts only for script execs, so these are not violations. A hung `systemctl` could still block a handler. Severity: low.
- `tunnel.go:62,94`: `svc` is passed to `journalctl -u` from a whitelist plus the prefixes `frps-`, `gre-t` and `backhaul-`. Arbitrary suffixes are allowed. This is read-only and `exec.Command` has no shell, so it is not injectable, but a suffix starting with `-` can't occur because of the prefixes. Informational.

## TCPMUX AUDIT (Go side)
| Path | Result |
|---|---|
| `tunnel.go:954-961` frps writer (`switchTunnelEngine`) | `tcpMuxTomlLines()` → `false` by default, no keepalive line. OK |
| `tunnel.go:1015-1026` frpc writer (same function) | `tcpMuxTomlLines()`. OK. Writes `heartbeatInterval` and `heartbeatTimeout` on frpc and `heartbeatTimeout` on frps, which matches v0.50+. OK |
| `rescue.go:210` rescue frps | `tcpMuxTomlLines()`. OK, but see the rescue mismatch above |
| `rescue.go:214,225` rescue frpc (origin and entry) | `tcpMuxTomlLines()`. Same note |
| `setup.go:1695-1706` toml port rewrite | Rewrites proxy lines only and leaves transport lines untouched. OK |
| setup-iran, setup-foreign, add-peer, update_all, restore, perf_apply, dial fallback, watchdog | All shell out to `hashem.sh`, so they are out of my scope and unaudited here |
| `perf.go` defaults | `defaultPerfConfig().TCPMux == nil`. `tcpMuxEnabled()` is false when nil. `reset` pins `false`. Verified by `TestTCPMuxDefaultIsOff` |
| Other Go code that writes a `transport.tcpMux` line | None |
| UI Performance tab | Now says default OFF and must match on both ends (en and fa) |
| Status/doctor surface | New `E-FRP-10` and doctor hint, hint only |

README and docs are for the other agent. `hashem status` (shell) is not covered.

## TESTS RUN
- `cd panel && go vet ./...` → OK, no output.
- `cd panel && go build -o /tmp/hp-test-bin` → OK.
- `cd panel && GRE_PANEL_DIR=/tmp/hp-test-dir go test ./...` → `ok github.com/pdnczone/hashem-panel/panel 75.715s`.
- `bash -n` on `hashem.sh`, `hashem-backhaul.sh`, `hashem-chaff.sh`, `install.sh` → **NOT RUN**: the sandbox required approval for `bash` and I didn't get it. I did not edit these files.
- `for t in tests/test_*.sh` → **NOT RUN**, same reason.
- No panel process was started.
