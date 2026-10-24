# Initial Audit Report - Hashem Panel

## Executive Summary

This report summarizes the findings of a read-only, evidence-based audit of the Hashem Panel repository (`github.com/pdnczone/hashem-panel`) conducted on the `dev` branch at commit `4ef9f30`. The audit focused on architecture, code quality, frontend/backend functionality, security, performance, and test coverage without modifying any files or production state.

**Overall Status:** The panel demonstrates a solid foundation with comprehensive test coverage, clear separation of concerns, and active maintenance. No confirmed critical defects were identified in production code during this audit. Several low-risk improvements and suspected risks are noted for future hardening.

**Key Observations:**
- The codebase is written in Go (v1.23 module, built with go1.27.1) with embedded frontend assets.
- All tests pass (`go test -race ./...` ok).
- The panel uses a cookie-based session mechanism with brute-force IP lockout and session rotation.
- External command execution is wrapped via a seam (`runCmdTimeout`) allowing testability.
- Configuration is loaded from `/etc/gre-panel` (overridable via env).
- The panel provides a rich web UI with internationalization (English placeholder) and a terminal script (`hashem.sh`) for tunnel management.

## Confirmed Defects

| ID | Title | Category | Severity | Confidence | Evidence |
|----|-------|----------|----------|------------|----------|
| None | No confirmed defects found in production code during read-only audit. | — | — | — | All critical paths (auth, API, tunnel config generation) inspected; no actual failures observed. Test suite passes completely. |

## Suspected Risks & Potential Improvements

| ID | Title | Category | Severity | Confidence | Evidence |
|----|-------|----------|----------|------------|----------|
| AUD-001 | HTTP client calls without timeout in test helpers | Test Code | Low | Strong Evidence | `panel/hardening_test.go`: lines 47, 53, 111, 128, 142, 166 use `http.Get` without configuring a timeout or using `http.Client{Timeout: ...}`. While these are in test code, they could cause hanging tests under network issues. |
| AUD-002 | Hardcoded default paths in globals | Configuration | Medium | Strong Evidence | `panel/main.go`: lines 32-39 define `configDir`, `frpDir`, `backhaulDir` as hardcoded strings. Although overridable via environment variables (`GRE_PANEL_DIR`, etc.), the defaults assume a specific Linux layout (`/etc/gre-panel`, `/etc/frp`, `/etc/backhaul`). This may cause confusion in non-standard deployments. |
| AUD-003 | Potential information leakage via debug endpoints | Security | Low | Suspected | `panel/main.go`: function `mountDebug` (line ~626) conditionally mounts debug endpoints (e.g., `/api/dial`) based on environment. No evidence of exposure in default configuration, but review recommended. |
| AUD-004 | Inconsistent error handling for `exec.Command` in some files | Reliability | Medium | Suspected | Several files (e.g., `panel/dial.go`, `panel/carrier.go`) use `exec.CommandContext` but do not consistently check error return values before using output. However, many calls are wrapped in `runCmdTimeout` which records errors. No observed failures. |
| AUD-005 | Lack of input sanitization on shell script arguments | Security | Low | Suspected | Scripts like `hashem.sh` invoke external commands with user‑provided arguments (e.g., interface names, IPs). While the script does validation, a thorough review of all argument passes is advised. |
| AUD-006 | Missing rate‑limiting on authentication endpoints | Security | Medium | Suspected | The `/api/login` endpoint relies on IP‑based lockout (`loginMaxFails=5`, `loginFailWindow=15m`) but does not implement per‑username rate limiting or HTTP‑level throttling. This could allow distributed credential stuffing from many IPs. |
| AUD-007 | Session token entropy source | Security | Low | Strong Evidence | Session token uses `sha256(nonce + pass_hash)` where `nonce` is generated once at startup via `rand.Read`. If `rand.Read` fails, the service logs fatal and exits. The nonce is regenerated only on password change (via `handlePassword`). This is acceptable but could be improved by regenerating nonce periodically. |

## Feature Inventory & Regression Baseline

| Feature | Description | Components | Test Coverage | Known Limitations |
|---------|-------------|------------|---------------|-------------------|
| Authentication | Cookie‑based session, brute‑force lockout, 2FA (TOTP), password strength validation (argon2id) | `auth.go`, `password.go`, `totp.go`, middleware in `main.go` | ✅ All `*_test.go` pass | Lockout escalation may lock legitimate users after many failed attempts from shared IP (e.g., NAT). |
| Dashboard | Real‑time traffic charts, KPI cards, peer list, tunnel status | `dashboard.go`, `app.js`, `index.html` | ✅ Dashboard-related tests pass | Charts rely on client‑side JS; no server‑side rendering fallback. |
| Tunnel Management | Create, modify, delete GRE/FRP/Bagher tunnels; carrier switching; port forwarding | `tunnel.go`, `setup.go`, `peers_edit.go`, `carrier.go`, `app.js` | ✅ Peer/tunnel tests pass | Depends on external `hashem.sh` for system‑level changes; assumes `systemd` and `iptables`/`nft` availability. |
| Backup & Encryption | Encrypted backups of configs, peers, tunnels, systemd units (AES‑256‑CBC) | `watchdog.go`, `hashem.sh` (backup functions) | ✅ Watchdog/backup tests pass | Backup password derived from panel password; loss of panel password makes backups unrecoverable. |
| Cluster / Mesh | Multi‑Iran‑server gossip, failover, load balancing (WRR, latency) | `cluster.go`, `hashem.sh` (cluster functions) | ✅ Cluster tests pass | Requires UDP port openness for gossip; firewall rules must allow inter‑node communication. |
| Diagnostics | MTU probe, ping, TCP/USB connectivity tests, auto‑fix suggestions | `doctor.go`, `app.js` | ✅ Doctor tests pass | Some diagnostics require privileged raw sockets; may fail in restricted containers. |
| Performance Tuning | Auto‑pool adjustment based on workload, carrier benchmark, TCP BBR tuning | `perf.go`, `benchmark.go`, `app.js` | ✅ Perf/benchmark tests pass | Auto‑pool adjustments restart only `frpc`; may not take effect if `frps` is misconfigured. |
| Update Mechanism | Check for new versions, download and verify binaries, apply updates | `update.go`, `hashem.sh` (update functions) | ✅ Update tests pass | Relies on GitHub API; rate limits may affect update checks in high‑frequency scenarios. |
| Terminal (Web PTY) | In‑browser root‑like terminal (protected by re‑authentication) | `terminal.go`, `app.js` | ✅ Terminal tests pass | Limited to 24‑hour session; output may be truncated for very long runs. |
| Audit Logging | Tamper‑evident security‑relevant event logging (login, logout, config changes, etc.) | `security.go`, `main.go` (audit hooks) | ✅ Audit tests pass | Log rotation keeps only recent entries; no remote forwarding by default. |

All tests in the `panel/` directory pass (`go test -race ./...` ok). No flaky tests observed in this run.

## Severity‑Ranked Findings Table

| ID | Title | Severity | Confidence | Recommended Action |
|----|-------|----------|------------|--------------------|
| AUD-002 | Hardcoded default paths | Medium | Strong | Make defaults configurable via a single base directory or improve documentation. |
| AUD-006 | Missing rate‑limiting on auth endpoint | Medium | Suspected | Add per‑username or HTTP‑level rate limiting as defense‑in‑depth. |
| AUD-004 | Inconsistent exec.Command error handling | Medium | Suspected | Audit all external command call sites; ensure errors are logged and acted upon. |
| AUD-001 | HTTP client calls without timeout in tests | Low | Strong | Add timeouts to `http.Get` in test helpers to avoid hanging CI. |
| AUD-003 | Potential debug endpoint exposure | Low | Suspected | Review `mountDebug` logic; ensure debug endpoints are disabled in production builds. |
| AUD-005 | Shell script argument sanitization | Low | Suspected | Review `hashem.sh` and related Go wrappers for proper quoting/escaping. |
| AUD-007 | Session token nonce rotation | Low | Strong | Consider rotating nonce periodically (e.g., on config reload) to limit exposure window. |

## Multi‑Phase Remediation Roadmap

**Phase 1 — Critical Security and Data‑Loss Risks**  
*(Address any confirmed critical findings; none present at this time.)*

**Phase 2 — Core Functionality and High‑Impact Bugs**  
*(Address high‑confidence, medium‑severity suspects that could affect reliability or security.)*  
- AUD-002: Make default paths more flexible or document override mechanism clearly.  
- AUD-006: Add per‑username rate limiting to `/api/login` (e.g., using a simple counter with expiry).  
- AUD-004: Review and standardize error handling for all `exec.Command` invocations.

**Phase 3 — Reliability and Regression Prevention**  
- AUD-001: Add timeouts to test HTTP calls to improve CI stability.  
- AUD-003: Ensure debug endpoints are only exposed when explicitly enabled via a secure flag.  
- AUD-005: Validate all user‑derived arguments passed to shell scripts (use `shlex.Quote`‑equivalent or allow‑list).  
- AUD-007: Implement periodic nonce rotation (e.g., every 12 h) to reduce session‑token predictability.

**Phase 4 — Performance and Scalability**  
*(No measured bottlenecks observed; defer unless profiling reveals issues.)*

**Phase 5 — Maintainability and Technical Debt**  
- Improve documentation for environment overrides (`GRE_*_DIR`).  
- Add more integration tests for backup/restore and cluster failover.  
- Consider extracting the `runCmdTimeout` seam into a reusable package for easier testing.

**Phase 6 — Final Verification and Release Readiness**  
- Run full test suite after each phase.  
- Perform manual sanity checks of core workflows (login, tunnel create/update/delete, backup, cluster).  
- Verify that no existing functionality is broken by running the panel in a staging environment.

## Proposed First Phase (Upon Approval)

**Scope:** Address the medium‑confidence, medium‑severity items from Phase 2:  
- AUD-002 (hardcoded paths)  
- AUD-006 (auth rate limiting)  
- AUD-004 (exec.Command error handling)

**Prerequisites:**  
- Current Git status clean (verified).  
- No uncommitted changes.  
- Test suite passing baseline.

**Files Likely to Change:**  
- `panel/main.go` (paths, possibly audit logging for exec errors)  
- `panel/auth.go` (add rate‑limiting map)  
- `panel/runcmd.go` (enhance error reporting)  
- Possibly `panel/setup.go`, `panel/tunnel.go`, `panel/carrier.go`, etc. (audit exec error handling)

**Risk Level:** Low to Medium. Changes are confined to adding validation and configurability; no removal of existing features.

**Estimated Effort:** 2–3 hours (including testing).

**Acceptance Criteria:**  
- All existing tests continue to pass.  
- New rate‑limiting logic correctly blocks excessive login attempts per username while preserving existing IP‑based lockout.  
- Default paths remain functional but can be overridden via environment variables without breaking existing deployments.  
- External command errors are logged at appropriate level (error) and do not cause silent failures.

**Required Tests:**  
- Run `go test -race ./...` (unit).  
- Manual test of login with failed attempts (both IP and username based).  
- Manual test of overriding `GRE_PANEL_DIR`, `GRE_FRP_DIR`, `GRE_BACKHAUL_DIR`.  
- Manual test of a few external command pathways (e.g., `hashem.sh version`, `gre-panel info`) to ensure error handling works.

**Rollback Method:**  
- Since changes are additive and non‑destructive, rollback is simply reverting the commit(s).  
- Create a temporary branch before starting; if issues arise, reset to original state.

**Dependencies:** None on other tasks.

**Required Human Approval:** Yes – proceed only after explicit approval to modify code.

## Information Needed Before Safe Remediation

- Confirmation that the panel is not currently serving live production traffic where a brief restart during testing could disrupt users (though the changes are backward‑compatible and require a restart only to take effect).  
- Any specific constraints on path overrides (e.g., SELinux contexts, AppArmor profiles) that the team wishes to consider.

Please review the findings above. If approved, we will proceed with Phase 2 tasks as outlined. Otherwise, provide feedback or request additional investigation.

---  
*End of Report*  