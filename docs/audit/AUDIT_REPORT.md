# Hashem Panel — Audit Report (in progress)

Baseline: `main` @ 52b41ad (+ uncommitted: `hashem.sh` tune_scale_values change by the owner, untracked `panel/peer_leak_test.go`). Remote: `pdnczone/hashem-panel`. These are treated as the owner's work and are NOT overwritten.

## Phase 1 — Inventory (verified)
- Go panel (`panel/`, 45 files, ~17k LOC, deps: gorilla/websocket, creack/pty), bash CLI `hashem.sh` (8004 lines), `hashem-backhaul.sh`, `hashem-chaff.sh`, `install.sh`. CI: `build-panel.yml`, `security.yml`.
- Local host = Iran-hub-style dev box: `gre-panel.service` active on :7777 (health 200). No GRE tunnel/frps/frpc active here (`gre-tunnel`, `frpc`, `frps` inactive; only `gre0/gretap0` kernel stubs). → live tunnel tests on this host are **Blocked**; fleet nodes need explicit approval.

## Phase 4 baseline results (real output)
| Check | Result |
|---|---|
| `go build ./...` | OK |
| `go vet ./...` | OK, no findings |
| `go test -count=1 ./...` | PASS (149s), coverage 43.0% |
| `go test -race` (Peer/Auth/Security/Rescue/Watchdog) | PASS |
| `bash -n` on 4 shell scripts | OK |
| shellcheck / staticcheck / govulncheck / gosec | **Blocked**: install command awaiting approval, not run |
| File perms `/etc/gre-panel/*` | 600 root (OK); binary 755 |

## Findings

### H-01 — Two orphaned systemd units crash-loop forever (High, VERIFIED)
- Units: `/etc/systemd/system/hashem-monitor.service` (`ExecStart=/usr/local/bin/hashem --monitor`), `hashem-webui.service` (`--webui`). Dated 2026-09-22.
- Evidence: `hashem --monitor` → `[!] Unknown command: --monitor` + usage, exit 1. `NRestarts=29005` (monitor), `46770` (webui). ~45k journal lines/hour from webui alone; `journalctl --disk-usage` = 4.0 GB; `Nice=-5` + `Restart=always` spawns bash every 3–5s.
- Root cause: units were created by an older release; current `hashem.sh` has no `--monitor/--webui` handlers and nothing in the repo (`grep -r`) references or removes these unit names; uninstall (hashem.sh ~L4853–4871) and update paths don't clean them either.
- Impact: CPU/fork churn, journald bloat (4 GB, can evict useful logs), noise hides real errors. Does not currently break the panel.
- Fix: (a) update/install migration removes legacy units (stop+disable+rm+daemon-reload) and adds them to uninstall list; (b) test with a fake systemd root dir. Live cleanup of the two units on this host + journal vacuum needs your approval.
- Test: shell test that migration function removes legacy unit files and is idempotent.

### M-01 — Update checksum verification is optional/fail-open (Medium, VERIFIED by code read)
- `panel/update.go` L120–131: `manifest, _ := fetchChecksumManifest(latest)`; if the manifest is missing/unreachable, the binary is installed after only `verifyELF`. `build-panel.yml` does not publish `checksums.txt` at all (grep count 0), so verification is effectively never performed.
- Impact: a compromised release/MITM-able mirror yields root code execution via panel update.
- Fix: CI publishes `checksums.txt`; updater fails closed when manifest absent (with explicit documented override for old releases).
- Test: unit test with httptest server serving asset without manifest → update rejected.

### M-02 — WSS carrier server accepts any WebSocket Origin (Medium, Unverified exploitability)
- `panel/wss_carrier.go` L360 `CheckOrigin: return true`. Auth for this endpoint needs review (token/TLS pinning) before rating; browsers are not the expected client.
- Action: read `runServer` auth path; if token-gated, downgrade to Low/Info.

### M-03 — Session cookie value is a static derivable MAC (Medium, VERIFIED by code read)
- `auth.go` L156/204: legacy cookie = sha256(nonce‖PassHash); not rotated per login, no per-session expiry for this form (nonce regenerates on restart only). Server-side sessions (`validSession`) exist in parallel. Password hash is unsalted SHA-256 (`main.go` L146/159, `auth.go` L266).
- Impact: offline brute force of `panel.json` is cheap if the file leaks; stolen legacy cookie is valid until restart/password change.
- Fix: migrate to argon2id/bcrypt with transparent upgrade on login (keep verifying old hashes); drop legacy cookie path or bound it by expiry. Backward compat required.

### L-01 — Journald 4 GB, no size cap on host (Low) — see H-01; `hashem free-ram` already caps journald but was not applied here.
### L-02 — Test coverage 43% (Low/tech debt): no tests for `terminal.go`, `tls.go`, `update.go` happy path, shell scripts.
### L-03 — Installed `/usr/local/bin/hashem` differs from repo working tree (Info): expected given owner's uncommitted `hashem.sh` edits.

## Not yet audited (next)
Rescue/peer/carrier logic for races & leaks (peer leak already regression-tested), `setup.go` input validation for ports/IPs, `tls.go`/ACME flow, `tunnel.go` iptables argument handling, watchdog, backup/restore round-trip in sandbox, clean-install and uninstall in an isolated container, `hashem-backhaul.sh`, frontend `index.html` (444 KB) console/API contract.

## Blocked
- Live tunnel/GRE/FRP/MTU/failover tests (no tunnel active on this host; fleet nodes need explicit permission).
- Static analyzers (install awaiting approval).
- Reboot test (would disrupt other services on this box: x-ui, nexora, dnc panels).
