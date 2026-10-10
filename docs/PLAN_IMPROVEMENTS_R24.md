# Improvement plan r24 (branch: dev)

Baseline: `go vet` clean, `go test ./...` green at 8aaab59. Every step: test first, then code,
then `go vet` + `go test ./...` + `bash -n` on scripts, then commit and push to `dev`.
Small commits, one concern each. No production servers are touched.

## Phase 1 - Correctness (Backhaul gap list, docs/audit/BACKHAUL_E2E_REPORT.md)
- [x] 1.1 Redact secrets (token, `invalid security token received: X`) in log endpoints (gap 10)
- [ ] 1.2 `switchTunnelEngine` stops swallowing errors; reports real failure (gaps 6, 7)
- [ ] 1.3 Real TOML parsing for backhaul config instead of line scanner (gap 2)
- [ ] 1.4 Per-peer backhaul units recognised in role detection (gap 4)
- [ ] 1.5 Doctor knows Backhaul: token mismatch / control-channel EOF / transport mismatch hints (gap 9)
- [ ] 1.6 Watchdog/health use session state, not unit state, for Backhaul (gap 12)

## Phase 2 - CI and quality
- [ ] 2.1 GitHub Actions `ci.yml`: go vet, gofmt check, go test -race, bash -n, tests/*.sh (hermetic ones)
- [ ] 2.2 Move `spoof_test.py` to `tools/`, fix references

## Phase 3 - Security
- [ ] 3.1 Login rate-limit + lockout with backoff per IP
- [ ] 3.2 Audit log of mutating API calls (append-only JSONL, rotated, redacted) + API endpoint
- [ ] 3.3 TOTP 2FA (RFC 6238, optional, off by default)
- [ ] 3.4 Session idle timeout setting
- [ ] 3.5 Terminal hardening: IP allowlist + password re-confirm before WS open
- [ ] 3.6 Update integrity: verify sha256 of downloaded binary (extend existing checksum logic) in install.sh

## Phase 4 - Operations
- [ ] 4.1 Alerts: webhook + Telegram on state change only (debounced), config via panel
- [ ] 4.2 Metrics history ring buffer (latency/loss/throughput) + API; Prometheus coverage review
- [ ] 4.3 Config backup/restore (tar of /etc/gre-panel, secrets masked in listing), CLI + API

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
