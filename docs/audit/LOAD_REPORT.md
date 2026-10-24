# Hub load lab report (Phases 1-3)

Source: `panel/loadlab_test.go`.
Phase 1 ("Before"): run 2026-10-10, direct per-request collection, serial pings.
Phase 2+3 ("After"): run 2026-10-10, same lab harness driving the shared 5 s
snapshot (snapshotEvery compressed 20x, ICMP cadence 60 s compressed 20x).
Same host (2-core / 3.8 GB Linux VM), same stub, same 20 000-socket table.
Raw data: `docs/audit/load_lab_results.csv` (after),
`docs/audit/load_lab_results_phase1.csv` (before).

## Method (unchanged from Phase 1)

- Fully in-process. The `runner` seam (`panel/runcmd.go`) is replaced by a stub
  host, so no `ip`, `ping`, `ss` or `systemctl` binary is ever started. `PATH`
  points at an empty directory during the run, so any direct `exec.Command`
  that bypasses the seam fails instantly instead of touching the machine.
  Config, peers and sessions live in the test temp dir. The process runs at
  nice 19, `GOMAXPROCS=1` and a 768 MB soft memory limit.
- The stub emulates, for N fake spokes: `ip tunnel show`, `ip -o -4 addr show`
  (batched, one call), `systemctl is-active <all units>` (one batched call),
  `ss -Htin state established` (N control sessions with rtt, plus the extra
  sockets), and `ping` (instant OK, or blocking 2 s then failing, which models
  ICMP dropped). Hub socket table: 20,000 extra established connections
  (`ss lines` column). The hub also has a legacy main tunnel (`gre-tunnel`,
  `frps` active).
- Drivers: C clients, each running one sequential poll loop per route
  (`/api/dashboard`, `/api/fleet`, `/api/peers`) with a 50 ms pause between
  requests (the UI polls every 5 s, so cadence is compressed about 100x).
  In the After run a goroutine runs `snapshotTick` every 250 ms (5 s
  compressed, like the fleet sampler was before) plus the fleet sampler body
  reading the snapshot. Requests pass through the real auth,
  `securityMiddleware`, `inflightLimiter` and `metricsMiddleware`.
- Window: 8 s per cell (Before dropped-ICMP cells got
  `min(20 s, (N+3) x 2 s)` so small N had a chance to finish; the After cells
  all use 8 s because requests finish). Latencies come from the panel's own
  route ring (`/api/selfstats` data).
- Assertions are leak invariants only: after the clients stop, goroutines and
  FDs return to baseline (+5) and nothing stays in flight. All 32 cells passed
  in both runs. No performance threshold is asserted.
- Reproduce: `HASHEM_LOADLAB=1 go test -count=1 -timeout 30m -run LoadLab -v ./...`
  from `panel/` (about 7 minutes). To keep the CSV, set
  `HASHEM_LOADLAB_OUT=<path>`.

## Before vs After (dashboard; the request that hung)

| N | C | ICMP | Before: dash p50 / p95 ms (n served) | After: dash p50 / p95 ms (n served) |
|---|---|---|---|---|
| 1 | 1 | ok | 16 / 31 (104) | 0 / 1 (152) |
| 1 | 1 | dropped | none finished (0) | 0 / 1 (152) |
| 1 | 3 | ok | 17 / 59 (205) | 0 / 1 (376) |
| 3 | 3 | ok | 157 / 238 (68) | 0 / 5 (309) |
| 3 | 10 | ok | 441 / 651 (79) | 0 / 1 (1252) |
| 3 | 10 | dropped | none finished | 0 / 0 (1419) |
| 6 | 1 | ok | 204 / 258 (24) | 0 / 1 (147) |
| 6 | 1 | dropped | none finished (0) | 0 / 1 (278) |
| 6 | 3 | ok | 405 / 528 (38) | 0 / 1 (426) |
| 6 | 3 | dropped | none finished (0) | 0 / 1 (933) |
| 6 | 10 | ok | 1285 / 1791 (38) | 0 / 1 (1175) |
| 6 | 10 | dropped | none finished (0) | 0 / 0 (2926) |
| 10 | 10 | ok | 2460 / 2959 (21) | 0 / 1 (1210) |
| 10 | 10 | dropped | none finished (0) | 0 / 0 (3218) |
| 20 | 10 | ok | 5424 / 5694 (10) | 0 / 1 (1325) |
| 20 | 10 | dropped | none finished (0) | 0 / 1 (3013) |

Full table: every one of the 32 cells now serves dashboard p95 <= 5 ms
(max 19 ms at N=10 C=3 ICMP-ok; fleet p95 <= 4 ms, peers p95 <= 2 ms).
Before, zero dashboard requests finished in ANY dropped-ICMP cell.

## Host-command cost

- Before: one `/api/dashboard` hit started about 5N+13 commands (43 at N=6,
  113 at N=20); `ping` ran N+3 times per hit (~5000/min at N=6 in the lab).
- After: the collector runs exactly 4 host commands per tick
  (`ss -Htin`, `ip tunnel show`, `ip -o -4 addr show`, `systemctl is-active`,
  asserted by `TestSnapshotTickCommandsIndependentOfPeerCount`),
  independent of N and of request volume (asserted by
  `TestHandlersNeverForkAndTickCostIsConstant`: 200 concurrent handler calls
  with the collector paused issue zero commands). Ping now runs at most once
  per 60 s per target, is skipped while the peer's control session is live,
  and off the request path (lab: ping 17-90/min depending on cell, vs
  thousands before; the residual is the background cadence, not requests).
- `ss -tun` per hit is gone: `activeConns` streams `/proc/net/{tcp,udp}[6]`
  and counts ESTABLISHED rows without buffering.

## Tick duration with dropped ICMP (the N x 2 s is gone)

- Before: `livePeers()` took N x 2 s (12.1 s at N=6); dashboard (N+3) x 2 s.
- After: snapshot build avg 19-84 ms, max 30-465 ms across all cells
  (transient max when background ICMP probes overlap a tick; ticks never
  pile up — a still-running tick is skipped and counted in
  `/api/selfstats`).

## Resource deltas

Unchanged in kind: goroutines/FDs return to baseline in every cell
(peak 130-137 goroutines at C=10 is the client drivers, same as before).
Heap peaks are lower (18-81 MB after vs up to 214 MB before at N=10+ C=10).

## What the lab still does not model

- Real `fork/exec` cost (the stub returns instantly).
- RAM pressure and the OOM killer on a 1-2 GB hub, CPU contention with `frps`
  and kernel GRE forwarding under real traffic.
- Browsers whose `setInterval` overlaps slow requests (lab clients wait).
- Lossy or slow client links (the 30 s / 60 s timeouts and the 64-wide
  in-flight limiter are asserted by unit tests, not by the lab).
- Process death was never reproduced in the lab, before or after; cgroup
  tuning (plan C2.6) still needs a real loaded hub via `/api/selfstats`.
