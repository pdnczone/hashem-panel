# Plan: Redesign Benchmark Tab (Premium UI & Pre-Connection Multi-Protocol Probing)

## Context & Objectives
- **Goal**: Redesign the Benchmark tab in Hashem panel to a clean, premium, beginner-friendly experience.
- **Pre-Connection Probing**: Ability to benchmark all protocols supported in Hashem (GRE Direct, FRP-TCP, FRP-KCP, FRP-QUIC, FRP-WSS, Backhaul, Bagher SSH) even before the two servers are connected.
- **Workflow**:
  - Detect or ask for Server Role (Iran Hub vs Foreign Worker).
  - If Foreign: Display the server's public IP with copy button and instructions.
  - If Iran: Input field for Foreign Server IP/Domain (pre-filled if known), with optional custom port overrides.
  - Hybrid testing: probes ICMP Ping, TCP connects (FRP/Backhaul/SSH), UDP streams (KCP/QUIC), and TLS Handshake (WSS). If foreign web panel is reachable, conducts two-way telemetry.
  - After benchmark: Highlight and announce the best/fastest carrier with quality score and metrics; do NOT auto-switch without explicit user confirmation.
  - Premium, simplified UI without confusing clutter.
- **Free & Unrestricted**: Accessible to all users without license barriers.

## Architecture & Components
1. **Backend (`panel/benchmark.go` & `panel/main.go`)**:
   - Update `handleBenchmarkRun` to accept optional JSON request `BenchmarkRunRequest { TargetHost, TargetRole, Ports: { FrpPort, WssPort, SshPort, BackhaulPort } }`.
   - Update `runCarrierBenchmark(opt ...BenchmarkRunRequest)`:
     - If `TargetHost` is provided, use it as the probe destination instead of localhost fallback.
     - Include all 7 active Hashem protocols: GRE, FRP-TCP, FRP-KCP, FRP-QUIC, WSS TLS, Backhaul, and Bagher SSH.
     - Probe Bagher/SSH (port 22 or configured) and Backhaul.
     - Calculate composite score and assign `IsRecommended = true` to the best candidate.
   - Maintain backward compatibility with GET `/api/benchmark` and existing `/api/benchmark/apply`.

2. **Frontend Template (`panel/index.html`)**:
   - Completely redesign `#tab-benchmark`:
     - Clean Hero Header with status and "⚡ شروع بنچمارک هوشمند".
     - Role Selector & Target Card:
       - Role toggle (🇮🇷 سرور ایران / 🌍 سرور خارج).
       - Iran view: Target IP input, auto-filled from current peer if available, collapsible advanced port settings.
       - Foreign view: Informational card with server public IP, copy button, and guide.
     - Progress animation bar during probe execution.
     - Recommendation Banner (Golden Winner card with Crown, badge, latency, loss, and explanation).
     - 7-Protocol Comparison Leaderboard Table: Rank, Protocol & Route, Layer Type pill, Port, Latency RTT, Packet Loss, Jitter, Quality Score bar, Status, Manual Switch Action.
     - Clean, streamlined Automatic Failover / Auto-Pilot card (OFF by default).

3. **Frontend Logic (`panel/app.js`)**:
   - `loadBenchmark()` and `runBenchmarkClick()`:
     - Read target host and role from inputs.
     - Send POST `/api/benchmark/run` with `{ target_host, target_role, ports }`.
     - Render the new recommendation card, score bars, and metrics.
     - Provide clear toasts and messages for beginners.
     - Ensure non-blocking modal (`entConfirm`) is used if user clicks "Switch".

4. **Testing (TDD)**:
   - Create `panel/benchmark_test.go`:
     - Test benchmark request with custom target IP.
     - Test candidate generation for all 7 protocols.
     - Test composite score ranking and recommendation logic.
     - Test API handler POST `/api/benchmark/run`.
   - Run all Go tests: `go test -v ./...`.
   - Verify JS syntax with `node --check panel/app.js`.
   - Verify DOM IDs with Python script.

## Risks & Mitigations
- **Risk**: Testing foreign IP before tunnel exists might timeout if firewall blocks ICMP or certain ports.
  - **Mitigation**: Probes use short timeouts (1.5s per probe, concurrency limited) so the whole benchmark completes within 3-5 seconds, clearly marking blocked ports as "Filtered / Closed" without crashing or hanging.
- **Risk**: Overwriting existing benchmark data or affecting current active tunnel.
  - **Mitigation**: Benchmark is read-only probing; per user clarification, carrier is never automatically switched.
