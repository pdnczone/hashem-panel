# Plan: Bagher Stealth Tunnel — Beginner-Friendly UX & Strict License Gating

## Objective
1. Strict License Gating & Inactive Hiding:
   - When unlicensed, clicking Bagher anywhere (sidebar, buttons, modals) immediately presents the license activation modal and never exposes the configuration UI or half-rendered cards.
   - When inactive / unconfigured / unlicensed, Bagher cards MUST NOT appear in the Dashboard or the Tunnels tab (`tunnelBagherCard`).
   - The sidebar item shows a clear `PRO` / lock badge.
2. Beginner-Friendly 2-Step Architecture:
   - Role selector (Iran vs Foreign) with clear, bilingual visual cards.
   - Iran setup: 2 essential inputs only (Foreign Public IP, Forwarded Ports with quick presets like `443, 8443`). All low-level plumbing (internal port 55400, pool size 25, ssh user root, ssh port 22) hidden in a collapsed "Advanced Settings" section.
   - Foreign setup: 1 single input (paste the `BAGHER:...` bundle) and 1 click "Connect to Iran & Start Foreign Tunnel".
   - Telemetry consolidation: Merge duplicate metric boxes into one clean, responsive status bar.
   - Informative status cues: Clarify when Iran is waiting for Foreign peer vs actively connected.
3. Backend & Engine Hardening:
   - Empty `Ports` in `defaultSSHFwdConfig()` so clean installations do not trigger `has_config` / `hasBagherConfigOrActive`.
   - Public IP resolution helper in `MakeBagherBundle` that avoids packing internal/private RFC1918 IPs when public IP is discoverable.
   - Elimination of JavaScript runtime risk (`ReferenceError: state is not defined`).

## Files to Modify
- `panel/sshfwd.go`
- `panel/sshfwd_test.go`
- `panel/index.html`
- `panel/app.js`

## Tests to Run
- `go test -v -run "TestSSHFwd" ./panel/...`
- `go test -v ./panel/...`
- `go vet ./panel/...`
- `staticcheck ./panel/...`
- `node --check panel/app.js`
- DOM validation script (checking IDs between index.html and app.js)

## Rollback Strategy
`git checkout .` to revert to `d5301ac` if any regression is detected.
