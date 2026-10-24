# Remediation Plan - Hashem Panel

This plan outlines the prioritized, multi-phase roadmap for addressing the findings documented in `INITIAL_AUDIT.md`.

## Phase 1: Critical Security & Data-Loss Risks
*None identified during initial audit.*  
Status: **COMPLETED / SKIPPED** (no critical defects confirmed).

---

## Phase 2: Core Functionality & High-Impact Bugs
Status: **COMPLETED** (commit `2fb1e09`)

### Task 2.1: Add Per-Username Rate Limiting on Login (AUD-006)
- **Status:** **COMPLETED**
- **Changes:** Added sliding-window per-username failure counter in `panel/auth.go` (`loginUserMaxFails = 10`, `loginUserLockoutDur = 15m`). Integrated into `handleLogin` with `Retry-After` header. Added unit test in `panel/auth_lockout_test.go`.

### Task 2.2: Standardize External Command Error Propagation (AUD-004)
- **Status:** **COMPLETED**
- **Changes:** Standardized exit code extraction and structured `[CMD-ERROR]` logging in `panel/runcmd.go`.

### Task 2.3: Configurable Base Directories Validation (AUD-002)
- **Status:** **COMPLETED**
- **Changes:** Added `validateConfigDirs()` on startup in `panel/main.go` to ensure directory existence and log warnings cleanly.

---

## Phase 3: Reliability & Regression Prevention
Status: **COMPLETED** (commits `31c5f19`, `b1b43b6`)

### Task 3.1: Enforce HTTP Client Timeouts in Tests (AUD-001)
- **Status:** **COMPLETED**
- **Changes:** Replaced all bare `http.Get` in `panel/hardening_test.go` with explicit 5-second timeout clients to prevent CI hangs.

### Task 3.2: Secure Audit of Debug Endpoints (AUD-003)
- **Status:** **COMPLETED**
- **Changes:** Verified that diagnostic endpoints are gated behind `debugEnabled()` and wrapped with `requireAuth` in `panel/main.go` and `panel/metrics.go`.

### Task 3.3: Periodic Session Nonce Rotation (AUD-007)
- **Status:** **COMPLETED**
- **Changes:** Added `rotateNonce()` in `panel/auth.go` called via a 12-hour background ticker in `panel/main.go`. Added unit test `TestRotateNonce` in `panel/password_test.go`.

### Task 3.4: Shell Argument & IP Address Sanitization (AUD-005)
- **Status:** **COMPLETED**
- **Changes:** Added `net.ParseIP` verification to `testPing` in `panel/peers_edit.go` to prevent any argument manipulation or invalid input from reaching external ping commands.

---

## Phase 4: Performance & Scalability
- Profile goroutine counts and memory consumption during high-concurrency carrier benchmark runs.
- Add metrics for FRP work connection saturation.
- Status: **DEFERRED** pending production telemetry.

---

## Phase 5: Maintainability & Developer Tooling
Status: **COMPLETED**

- Documented environment variables (`GRE_PANEL_DIR`, `GRE_FRP_DIR`, `GRE_BACKHAUL_DIR`, `GRE_SYSCTL_CONF`, `HASHEM_PPROF`, `HASHEM_MIRROR_REPO`) in `docs/DEPLOYMENT.md`.

---

## Phase 6: Final Verification & Release Readiness
Status: **COMPLETED**

- Full regression suite execution: `go test -race ./...` (Passed with zero race conditions or errors).
- Clean tree state verified on branch `dev`.
