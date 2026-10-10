# Security Policy

## Overview

Security and operator safety are critical priorities for `hashem-panel`. This document describes the project's vulnerability reporting procedure, supported releases, and security hardening architecture.

---

## Supported Versions

Only the latest release receives active security patches.

| Version | Supported |
| ------- | --------- |
| Latest release (`main` branch) | :white_check_mark: |
| < Latest | :x: |

---

## Reporting a Vulnerability

If you discover a security vulnerability in `hashem-panel`, please report it responsibly:

1. **Do not create a public GitHub issue.**
2. Send an email to the security maintainers with a detailed description, reproduction steps, and proof-of-concept (PoC) at:
   - `security@pdnc.zone` or open a private [GitHub Security Advisory](https://github.com/pdnczone/hashem-panel/security/advisories/new).
3. You will receive an acknowledgment within 48 hours.
4. Security patches will be issued within 7 days of confirmation.

---

## Security Architecture & CWE Mitigations

### 1. Plaintext Password Storage (CWE-256)
- **Mitigation**: Plaintext passwords are **never** stored on disk. Passwords are only stored as cryptographic SHA-256 hashes inside `/etc/gre-panel/panel.json`.
- Legacy `panel.pass` files are automatically removed during startup migration.
- Disaster recovery of admin credentials is provided exclusively via the ephemeral environment variable `GRE_PANEL_PASSWORD`.
- Backup archives use an independent, cryptographically generated 32-byte key (`/etc/gre-panel/backup.key`, mode 0600) rather than user passwords.

### 2. Update Integrity & Mirror Hardening (CWE-494)
- **Mitigation**: Prebuilt panel updates and script updates are strictly pinned to official GitHub domains (`github.com`, `raw.githubusercontent.com`, `api.github.com`).
- Untrusted third-party mirrors (such as `ghfast.top`) have been completely removed.
- Binary downloads verify SHA-256 checksums from official release manifests (`checksums.txt` / `SHA256SUMS`) before installation.
- ELF header verification rejects HTML error redirects or corrupt files.
- Automatic rollback is executed if new binary installation encounters an error.

### 3. IP Spoofing & Rate Limiting Protection (CWE-348)
- **Mitigation**: Client IP evaluation defaults strictly to `RemoteAddr`.
- Headers such as `X-Forwarded-For` and `X-Real-IP` are **only** evaluated when the immediate socket connection originates from a verified reverse proxy configured via the `TRUSTED_PROXY_IPS` environment variable.
- Brute-force rate limiting and lockout mechanisms cannot be bypassed by forging forwarding headers.

### 4. Cross-Site Request Forgery & Secure Cookies (CWE-352)
- **Mitigation**: State-changing endpoints (`POST`, `PUT`, `PATCH`, `DELETE`) require a cryptographically valid `X-CSRF-Token` header.
- CSRF tokens are derived using HMAC-SHA256 bound to the authenticated session.
- Session cookies (`gre_session`) are issued with `HttpOnly`, `SameSite=Lax`, and `Secure` flags when running over HTTPS or trusted TLS reverse proxies.

### 5. Password Verification & Account Takeover Prevention (CWE-640)
- **Mitigation**: Changing the panel password requires verification of the `current_password` via constant-time comparison.
- Password change automatically invalidates all existing sessions (`dropAllSessions`), preventing hijacked sessions from persisting.

### 6. Script Download & Dynamic Execution Hardening (CWE-95)
- **Mitigation**: Installer scripts (`hashem.sh`) downloaded from the repository must pass:
  1. Size and shebang integrity validation (`#!/bin/bash` or `#!/usr/bin/env bash`).
  2. Non-execution syntax verification (`bash -n`).
  3. Domain origin verification.
- Failed script synchronization does not disrupt running daemon operations.

### 7. Interactive Terminal Access Control & Auditing (CWE-269)
- **Mitigation**: Interactive terminal access is **disabled by default** and requires explicit administrator enablement (`TerminalEnabled: false`).
- Single concurrent session enforcement with 10-minute idle disconnect and 30-minute absolute lifetime caps.
- WebSocket upgrades enforce same-origin checks.
- Connect, disconnect, and redacted command execution events are logged to tamper-evident security audit logs (`/etc/gre-panel/security-audit.log`).
- Connecting terminals present an immediate security notice banner informing the operator that sessions are audited.

### 8. NIST 800-63B Password Complexity (CWE-521)
- **Mitigation**: Passwords must be at least 12 characters long and must contain at least:
  - 1 uppercase letter (`A-Z`)
  - 1 lowercase letter (`a-z`)
  - 1 number (`0-9`)
  - 1 symbol (`!@#$%^&*()-_=+[]{}|;:,.<>?/~`'\"`)
- Common and easily guessable passwords are systematically rejected by dictionary filtering.
- Client-side interface includes real-time password strength validation.
