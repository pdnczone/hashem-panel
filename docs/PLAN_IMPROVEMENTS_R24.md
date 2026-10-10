# Improvement plan r24 (branch: dev)

Baseline: `go vet` clean, `go test ./...` green at 8aaab59. Every step: test first, then code,
then `go vet` + `go test ./...` + `bash -n` on scripts, then commit and push to `dev`.
Small commits, one concern each. No production servers are touched.

## Phase 1 - Correctness (Backhaul gap list, docs/audit/BACKHAUL_E2E_REPORT.md)
- [x] 1.1 Redact secrets (token, `invalid security token received: X`) in log endpoints (gap 10)
- [x] 1.2 `switchTunnelEngine` stops swallowing errors; reports real failure (gaps 6, 7)
- [x] 1.3 Real TOML parsing for backhaul config instead of line scanner (gap 2)
- [x] 1.4 Per-peer backhaul units recognised in role detection (gap 4)
- [x] 1.5 Doctor knows Backhaul: token mismatch / control-channel EOF / transport mismatch hints (gap 9)
- [x] 1.6 Watchdog judges Backhaul by control-channel session (hashem.sh backhaul_session_ok + tests/test_watchdog_backhaul.sh); Go snapshot already uses ss sessions + probes

## Phase 2 - CI and quality
- [x] 2.1 ci.yml: vet, build, test -race, gofmt on changed files, bash -n, hermetic tests/*.sh (race in wss test fixed)
- [x] 2.2 Move `spoof_test.py` to `tools/`, fix references

## Phase 3 - Security
- [x] 3.1 Login lockout escalates per repeat offender (15m x2 up to 24h, decays after 24h), Retry-After header (5-failure lockout already existed)
- [x] 3.2 Audit log: every mutating API call (method, path, status; never body), size rotation, GET /api/audit (newest first, filter, redacted)
- [x] 3.3 Optional TOTP 2FA (RFC 6238 vectors tested, replay guard, 8 single-use recovery codes, two-step enrol, disable needs password+code, login + Settings UI)
- [x] 3.4 Idle session timeout (off by default; user-activity header so polling never keeps a session alive; Settings card)
- [x] 3.5 Terminal hardening: IP allowlist (IP/CIDR, refuses self-lockout), password(+2FA) re-auth gives a single-use 60s ticket bound to session+IP, required by the WS
- [x] 3.6 install.sh: canonical copy or 2-host mirror quorum or HASHEM_SHA256 pin, else fail closed (panel updater already verified checksums.txt fail-closed); tests/test_install_verify.sh

## Phase 4 - Operations
- [x] 4.1 Alerts: webhook + Telegram on health STATE CHANGE only (baseline tick, per-link min gap, degraded opt-in, secrets masked in GET/errors), Settings card, test button
- [x] 4.2 24h in-memory link history (30s, ring, derived rx/tx rates, 64-link cap) + /api/history + Settings graph; Prometheus /metrics behind bearer token (404 until enabled)
- [x] 4.3 Backup covers backhaul/alerts/carrier/wss/autopool/peer_link/setup/tls + units; restore refuses archives escaping allowed dirs and saves a pre-restore safety backup (backup/restore CLI, schedule and panel UI already existed)

## Phase 5 - Anti-censorship
- [ ] 5.1 Carrier advisor: from tunnel-health probes, recommend/rotate carrier (advisory by default,
      never auto-switch; carrier stays manual per project rule)
- [ ] 5.2 Port/SNI suggestion helper (pure function + tests)

## Phase 6 - Maintainability
- [ ] 6.1 Extract inline JS from index.html into `app.js` served statically (no behavior change)
- [ ] 6.2 Docs: README/CLAUDE.md/CHANGELOG updates

Order is fixed; if a step turns out risky it is skipped and recorded under "Deferred".

## Deferred / notes
(filled during execution)
