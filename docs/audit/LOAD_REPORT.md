# Hub load lab report (Phase 1: measurement only)

Source: `panel/loadlab_test.go`, run on 2026-10-10 on a 2-core / 3.8 GB Linux VM.
Raw data: `docs/audit/load_lab_results.csv`. Nothing here changes panel behaviour.

## Method

- Fully in-process. The `runner` seam (`panel/runcmd.go`) is replaced by a stub
  host, so no `ip`, `ping`, `ss` or `systemctl` binary is ever started. `PATH`
  points at an empty directory during the run, so any direct `exec.Command`
  that bypasses the seam fails instantly instead of touching the machine.
  Config, peers and sessions live in the test temp dir. The process runs at
  nice 19, `GOMAXPROCS=1` and a 768 MB soft memory limit.
- The stub emulates, for N fake spokes: `ip tunnel show`, `ip -4 addr show dev
  gre-tN`, `systemctl is-active frps-N`, `ss -Htin state established` (N control
  sessions with rtt, plus the extra sockets), `ss -tun state established`, and
  `ping` (instant OK, or blocking 2 s then failing, which models ICMP dropped).
  Hub socket table: 20,000 extra established connections (`ss lines` column).
  The hub also has a legacy main tunnel (`gre-tunnel`, `frps` active).
- Drivers: C clients, each running one sequential poll loop per route
  (`/api/dashboard`, `/api/fleet`, `/api/peers`) with a 50 ms pause between
  requests (the UI polls every 5 s, so cadence is compressed about 100x). A
  goroutine runs the same body as `startFleetSampler`'s tick every 150 ms
  (15 s compressed). Requests pass through the real auth, `securityMiddleware`
  and `metricsMiddleware`.
- Window: 8 s per cell. Dropped-ICMP cells get `min(20 s, (N+3) x 2 s)` so
  small N has a chance to finish. Latencies come from the panel's own route
  ring (`/api/selfstats` data), snapshotted before the stub is aborted so
  cancelled work is not counted as fast. "none finished" means no request of
  that kind completed inside the window.
- Assertions are leak invariants only: after the clients stop, goroutines and
  FDs return to baseline (+5) and nothing stays in flight. All 32 cells passed.
  No performance threshold is asserted.
- Reproduce: `HASHEM_LOADLAB=1 go test -count=1 -timeout 30m -run LoadLab -v ./...`
  from `panel/` (about 7 minutes).

## Results

| N | clients | ICMP | ss lines | window s | /api/dashboard p50 / p95 / p99 ms (n) | /api/peers p50 / p95 ms (n) | /api/fleet p95 ms | livePeers avg / max ms | goroutines peak | heap peak MB | FDs peak | in flight at end (oldest ms) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 1 | ok | 20000 | 8 | 16 / 31 / 48 (104) | 14 / 38 (106) | 0 | 17 / 136 | 19 | 28 | 14 | 2 (20) |
| 1 | 1 | dropped | 20000 | 8 | none finished | 2015 / 2020 (3) | 0 | 2017 / 2019 | 20 | 20 | 13 | 2 (8001) |
| 1 | 3 | ok | 20000 | 8 | 17 / 59 / 90 (205) | 14 / 52 (212) | 0 | 20 / 91 | 44 | 28 | 26 | 4 (16) |
| 1 | 3 | dropped | 20000 | 8 | none finished | 2015 / 2063 (9) | 0 | 2019 / 2062 | 48 | 16 | 25 | 6 (8001) |
| 1 | 10 | ok | 20000 | 8 | 20 / 210 / 277 (214) | 13 / 157 (234) | 0 | 53 / 295 | 138 | 66 | 77 | 25 (342) |
| 1 | 10 | dropped | 20000 | 8 | none finished | 2021 / 2129 (30) | 0 | 2038 / 2160 | 137 | 51 | 67 | 20 (8001) |
| 3 | 1 | ok | 20000 | 8 | 65 / 97 / 105 (53) | 68 / 97 (54) | 1 | 64 / 124 | 19 | 43 | 14 | 3 (52) |
| 3 | 1 | dropped | 20000 | 12 | none finished | 6218 / 6218 (1) | 3 | 6201 / 6235 | 20 | 32 | 13 | 2 (12001) |
| 3 | 3 | ok | 20000 | 8 | 157 / 238 / 269 (68) | 153 / 251 (70) | 1 | 150 / 287 | 48 | 72 | 28 | 9 (283) |
| 3 | 3 | dropped | 20000 | 12 | none finished | 6191 / 6203 (3) | 1 | 6163 / 6203 | 48 | 52 | 25 | 6 (12001) |
| 3 | 10 | ok | 20000 | 8 | 441 / 651 / 797 (79) | 414 / 739 (80) | 1 | 439 / 891 | 153 | 161 | 88 | 25 (788) |
| 3 | 10 | dropped | 20000 | 12 | none finished | 6193 / 6446 (10) | 1 | 6245 / 6509 | 145 | 71 | 67 | 24 (12000) |
| 6 | 1 | ok | 20000 | 8 | 204 / 258 / 518 (24) | 205 / 266 (24) | 1 | 193 / 547 | 19 | 50 | 13 | 1 (42) |
| 6 | 1 | dropped | 20000 | 18 | none finished | 12190 / 12190 (1) | 2 | 12189 / 12219 | 20 | 46 | 13 | 2 (18000) |
| 6 | 3 | ok | 20000 | 8 | 405 / 528 / 590 (38) | 390 / 526 (39) | 1 | 395 / 651 | 52 | 85 | 29 | 9 (615) |
| 6 | 3 | dropped | 20000 | 18 | none finished | 12182 / 12183 (3) | 1 | 12125 / 12183 | 48 | 44 | 25 | 6 (18000) |
| 6 | 10 | ok | 20000 | 8 | 1285 / 1791 / 1935 (38) | 1285 / 1575 (41) | 1 | 1232 / 1932 | 157 | 185 | 81 | 29 (1625) |
| 6 | 10 | dropped | 20000 | 18 | none finished | 13605 / 13808 (10) | 1 | 13452 / 13808 | 148 | 154 | 69 | 20 (18001) |
| 10 | 1 | ok | 20000 | 8 | 352 / 379 / 407 (17) | 361 / 404 (17) | 1 | 330 / 426 | 19 | 63 | 14 | 2 (103) |
| 10 | 1 | dropped | 20000 | 20 | none finished | none finished | 1 | none finished | 20 | 36 | 13 | 2 (20001) |
| 10 | 3 | ok | 20000 | 8 | 770 / 947 / 1004 (24) | 719 / 911 (24) | 1 | 749 / 1003 | 50 | 96 | 27 | 9 (951) |
| 10 | 3 | dropped | 20000 | 20 | none finished | none finished | 1 | none finished | 48 | 60 | 25 | 6 (20001) |
| 10 | 10 | ok | 20000 | 8 | 2460 / 2959 / 2995 (21) | 2481 / 2932 (20) | 2 | 2439 / 2992 | 163 | 213 | 80 | 30 (3111) |
| 10 | 10 | dropped | 20000 | 20 | none finished | none finished | 1 | none finished | 147 | 120 | 67 | 20 (20001) |
| 20 | 1 | ok | 20000 | 8 | 737 / 934 / 934 (9) | 778 / 850 (9) | 2 | 743 / 931 | 19 | 75 | 14 | 3 (153) |
| 20 | 1 | dropped | 20000 | 20 | none finished | none finished | 3 | none finished | 20 | 43 | 13 | 2 (20000) |
| 20 | 3 | ok | 20000 | 8 | 1687 / 1965 / 2087 (12) | 1678 / 1937 (12) | 2 | 1705 / 2085 | 47 | 103 | 26 | 8 (325) |
| 20 | 3 | dropped | 20000 | 20 | none finished | none finished | 1 | none finished | 48 | 52 | 25 | 6 (20001) |
| 20 | 10 | ok | 20000 | 8 | 5424 / 5694 / 5694 (10) | 5436 / 5893 (10) | 2 | 5271 / 5892 | 160 | 214 | 82 | 30 (2922) |
| 20 | 10 | dropped | 20000 | 20 | none finished | none finished | 2 | none finished | 152 | 111 | 71 | 20 (20001) |
| 6 | 3 | ok | 0 | 8 | 1 / 1 / 2 (447) | 0 / 1 (448) | 1 | 0 / 1 | 36 | 35 | 21 | 0 (0) |
| 6 | 3 | dropped | 0 | 18 | none finished | 12004 / 12005 (3) | 1 | 12004 / 12005 | 48 | 36 | 25 | 6 (18000) |

The last two rows repeat N=6, C=3 with an empty socket table (`ss lines` = 0).

## Costs per request (measured by counting stub calls for one request)

| Request | Commands started per hit, N spokes |
|---|---|
| `/api/dashboard` | `ip tunnel show` N+3, `ip addr show` N+3, `systemctl is-active` N+3, `ping` N+3, `ss -Htin` N, `ss -tun` 1 (about 5N+13 forks: 43 at N=6, 113 at N=20) |
| `/api/peers` | the same four commands N times each plus `ss -Htin` N (5N: 30 at N=6) |
| `/api/fleet` | none (reads the sampler's cache) |

The `+3` is `localStatus()` running three times inside one dashboard hit: once
directly, once through `mainTunnelLive`, and once through
`loadPeerConfig` -> `defaultPeerConfig` when `peer_link.json` does not exist (the lab has
no such file; a hub that has one pays two, not three). Each `localStatus()`
includes a blocking `ping -W 2`.

## What the data shows

1. **Serial blocking pings are the dominant hang, and it is deterministic.**
   With ICMP dropped, `livePeers()` takes N x 2 s (measured: 2.0 s at N=1,
   6.2 s at N=3, 12.1 s at N=6). A dashboard hit needs (N+3) x 2 s (18 s at
   N=6, 46 s at N=20). No dashboard request finished inside its window in any
   dropped cell, and at N>=10 not even `/api/peers` finished (oldest request
   still in flight at 20 s, the cap). At N=10 the fleet sampler's own tick
   (20 s) is longer than its 15 s interval.
2. **`ss -Htin` is dumped and parsed once per peer per request.** It returns the
   whole hub socket table, not only control sessions. With ICMP ok at N=6, C=3,
   dashboard p50 is 405 ms with 20,000 sockets and 1 ms with none. The ss
   parsing is therefore more than 99% of in-process time in that cell, and
   it grows with both N and the socket count.
3. **Concurrency multiplies it.** At N=6 with 20,000 sockets, dashboard p50
   goes 203 ms (C=1) -> 405 ms (C=3) -> 1285 ms (C=10). Peaks at C=10: about
   157 goroutines, 81 FDs, 185 MB heap. There is no result sharing between
   concurrent identical requests.
4. **No leak.** In all 32 cells goroutines, FDs and in-flight count returned
   to baseline.

## Did the lab reproduce the overload at N=6?

**Partly.**

- Reproduced: UI-level hang. With ICMP dropped, an N=6 hub cannot answer
  `/api/dashboard` in under 18 s and `/api/peers` in under 12 s, and every
  poll holds a goroutine and connection for that long. A browser timeout or a
  `setInterval` that overlaps slow requests would see "panel down" at N=6, and
  the pile-up grows with each open browser. CPU saturation is also
  reproduced when the hub has a large socket table, even with ICMP ok.
- Not reproduced: the panel process dying or being killed. Nothing crashed,
  leaked or hit the memory limit.
- Not modelled, so the lab understates the real cost:
  - Real `fork/exec` cost (the stub returns instantly). Estimate, not
    measured: about 43 forks per dashboard hit at N=6.
  - RAM pressure and the OOM killer on a 1-2 GB hub, and CPU contention with
    `frps` and kernel GRE forwarding under real traffic.
  - Real `ss` output cost in the kernel for 20,000 sockets.
  - Browsers whose `setInterval` overlaps slow requests (the lab clients wait
    for each response).
  - Lossy or slow client links, which hold connections open longer.
  - Slow-client handling: the server has no read or write timeout, and the lab
    does not exercise it.
  - Background loops other than the fleet sampler (traffic recorder, peer
    sync, autopilot, rescue monitor, benchmark).

## Implication for Phase 3

- The gate in the plan was "reproduce the hang before changing anything". The
  hang is reproduced, but only the latency/pile-up half. Process death is
  unconfirmed and should be confirmed on a real hub before cgroup limits
  (C2.6) are tuned. The Phase 1 tooling is built for that: enable
  `HASHEM_PPROF=1`, then read `/api/selfstats` (RSS, FDs, exec counts, sampler
  durations, route p95) while a real hub is under load.
- The data supports C2 items 1-3 first: a single shared collector so requests
  never fork; one `ss` dump per tick instead of N per request; pings moved off
  the request path and run concurrently with a bound, or skipped while a
  control session is live. Together they remove the N x 2 s and the
  N x full-table cost.
- C2.4 (HTTP timeouts and an in-flight limiter) is justified by the pile-up
  analysis but its effect was not measured here.
- C2.5 (`activeConns` summary) is a small win: one `ss -tun` per hit, versus N
  `ss -Htin` dumps.
