# PLAN — Reverse-path ping, honest fleet health, and hub scalability

Status: **PROPOSED — awaiting approval. No code changed.**
Scope: `panel/` (Go), `hashem.sh`, `tests/`, `docs/`.
Constraints from owner: no access to a real affected pair → everything below is
derived from the code plus synthetic tests; Problem 3 is **measure first, fix
what the data shows**.

---------------------------------------------------------------------------
## 0. Problems and decisions

| # | Symptom | Decision (owner) |
|---|---------|------------------|
| P1 | On some servers Iran→abroad ping works, abroad→Iran does not | **Reverse Path Doctor**: auto-diagnose + auto-fix + report |
| P2 | Link works, but Performance / Fleet Health shows "no ping" / errors | **Multi-signal health**: FRP control session + TCP RTT primary, ICMP secondary; never show "no ping" while the session is live |
| P3 | 5–6 spokes on one Iran hub → web panel goes down | **Profile first** (6 simulated spokes), then fix what data shows |
| — | Deliverable | This document; implement after approval |

---------------------------------------------------------------------------
## 1. What the code does today (root-cause evidence)

### 1.1 Probes are ICMP-over-GRE, one direction only
- `tunnel.go:livePeers()` and `tunnel.go:localStatus()` run
  `ping -c 1 -W 2 <peer inner GRE>` **from the hub**. They only ever test
  hub→spoke. Nothing tests spoke→hub, so asymmetry is invisible and nothing
  explains *why* it happens.
- `doctor.go:applyDoctorFixes()` step 5: `!st.PingOK && st.Gre.PeerIP != ""` →
  `systemctl restart gre-tunnel`. On an asymmetric-ICMP server this
  **restarts a healthy tunnel every time** the fixer runs (drops live FRP
  sessions) and does not fix anything.
- `doctor.go:executeKernelAudit()` checks BBR / ip_forward / MSS / somaxconn /
  conntrack / tw_reuse / NOFILE. It does **not** check the things that cause
  one-way GRE ping (below).

### 1.2 Likely causes of "Iran→abroad OK, abroad→Iran fails" (hypotheses to test)
Ranked by how often they produce exactly this one-way pattern on GRE (proto 47):

1. **rp_filter strict (=1) on the receiving side / wrong interface** — reply
   or request arrives on `gre-tunnel` but the best route back is the physical
   NIC → dropped as martian. Fix: `rp_filter=2` (loose) on `all`, `default`,
   and the GRE iface.
2. **Missing/wrong return route or source-address selection** — ping from the
   spoke picks the public IP as source (not the GRE inner IP), so replies go
   out the public path and are dropped by Iranian ISP. Fix: `ping -I <inner>`
   semantic check; add `ip route ... src <inner>` on the GRE route.
3. **ISP drops ICMP (and sometimes proto 47) in one direction only** (Iran
   egress filtering). Not fixable locally → must be *classified* and routed
   around (FRP over public path / WSS carrier), and **reported honestly**.
4. **MTU / DF black hole** — GRE iface MTU 1380 but outer path smaller in one
   direction; small ICMP passes, bigger fails. `executeMTUTest` exists but is
   one-directional.
5. **iptables / conntrack** — `INPUT`/`FORWARD` default DROP on one side with
   no `-i gre-tunnel` accept; conntrack marks asymmetric GRE replies INVALID.
6. **GRE keepalive / key / TTL mismatch** — `ttl 255` + `nopmtudisc` combo,
   or `key` mismatch only on the one that was re-created.
7. **Local firewall (ufw/nftables/cloud SG) blocks proto 47 or ICMP inbound**
   on the spoke (cloud provider security groups are the #1 real-world cause on
   abroad VPS).

### 1.3 Health is computed from the wrong primary signal
- `fleet.go:fleetHealth()` already treats `FrpUp && Linked` as OK — good — but
  these still leak raw `PingOK=false` to the UI:
  - `/api/dashboard` returns `ping_ok` / `ping` from `localStatus()` (ICMP only).
  - `fleetNode.PingOK` / `PingMs` are populated from ICMP; the UI renders "no
    ping" from that field.
  - `dashboard.go:handleDashboard` single-tunnel branch:
    `Gre.Exists && FrpUp && PingOK` → HEALTHY else DEGRADED. A working FRP-only
    link shows **DEGRADED**.
  - `peerLive.Linked` depends on `controlSession()` matching `RemotePub` or
    `PeerGre` against the `ss` remote host. Behind NAT/CGNAT, via the WSS
    carrier (port+2) or dial-route over public IP, the remote can differ →
    `Linked=false` although traffic flows → "no ping / down" while working.
  - `FrpUp` = `systemctl is-active frps-N` — says nothing about a session.

---

## 2. Plan A — Reverse Path Doctor (P1)

New file `panel/revpath.go` (+ `panel/revpath_test.go`), new tests dir script
`tests/test_revpath.sh`.

### A1. Probe matrix (both directions, three layers)
For each peer the hub can run locally; for the spoke direction the spoke runs
the same probe through its own panel/agent (existing Peer Link
`/api/peer/*` channel with `PeerSecret`; fall back to a tiny signed
`/api/revpath/probe` the spoke panel exposes).

Layers per direction (hub→spoke, spoke→hub):
1. **L3 ICMP over GRE inner** (`ping -I <inner_src> <inner_dst>`), sizes 64
   and 1300 with DF.
2. **L3 ICMP over public path** (outer IPs) — separates "ISP drops ICMP" from
   "GRE broken".
3. **L4 TCP connect** to the FRP control port (inner IP, then public IP) and
   to the WSS port 8443 — this is the signal that actually matters for service.
4. **Proto-47 delivery**: counters on `gre-tunnel` rx/tx deltas while probing
   (did the packet get *in*? did the reply get *out*?) via `/proc/net/dev` +
   `ip -s link`.

### A2. Classifier (pure function → unit-testable)
Input: probe matrix + local config snapshot. Output: one verdict + evidence:

| Verdict code | Meaning | Auto-fix |
|---|---|---|
| `RP_FILTER` | rp_filter=1 on iface/all, rx counter increments, no reply | set `rp_filter=2` (sysctl + `/etc/sysctl.d/99-hashem-revpath.conf`) |
| `SRC_SELECT` | reply leaves with public src | add `src <inner>` to GRE route; set `ping`/probe source |
| `NO_RETURN_ROUTE` | no route to peer inner back via GRE | `ip route replace` + persist in gre unit |
| `FW_INPUT` | iptables/nft INPUT/FORWARD drops proto 47 or ICMP on gre iface | insert accept rules (`-p 47`, `-i gre-tunnel`, `icmp`) **only our own chain** `HASHEM-REVPATH` |
| `MTU_BLACKHOLE` | 64B ok, 1300B DF fails in one direction | lower GRE MTU stepwise (1380→1360→1340→1300) + MSS clamp re-check |
| `CONNTRACK_INVALID` | asymmetric GRE flagged INVALID | `NOTRACK` raw rule for proto 47 / gre iface |
| `ISP_ICMP_ONE_WAY` | ICMP over GRE and over public path fails one way, TCP ok | **no local fix**; mark ICMP as "unreliable on this link", rely on TCP signal (Plan B), show clear explanation |
| `ISP_GRE_BLOCK` | proto 47 not delivered one way, TCP over public ok | recommend / auto-switch carrier to WSS (:8443) via existing carrier manager (behind confirm if `auto_failover` off) |
| `CLOUD_SG` | local rules fine, rx counter 0 on the spoke | cannot fix; print exact SG rule to add (proto 47 + ICMP from hub IP) |
| `HEALTHY` | symmetric | none |

### A3. Safe auto-fix engine
- Every fix: **dry-run → snapshot → apply → re-probe → rollback if worse**.
  Snapshot = `sysctl -a` subset + `iptables-save` of our chain + route dump,
  stored in `configDir/revpath/<ts>.json`.
- Our rules live in a dedicated chain/table (`HASHEM-REVPATH`); never edit
  user rules. Idempotent (`-C` before `-A`).
- Rate limit: max 1 auto-fix per peer per 10 min, max 3 per hour, then alert
  only. Fixes never restart `gre-tunnel`/`frps`/`frpc` (that was the
  Doctor's bug in §1.1); only sysctl / route / our chain.
- **Remove** the `!PingOK → restart gre-tunnel` branch in
  `applyDoctorFixes()`; replace by "run Reverse Path Doctor for this peer".

### A4. Surfaces
- API: `GET /api/revpath` (last result per peer), `POST /api/revpath/run`
  `{peer_id, apply:bool}`; included in `/api/doctor` report as a new section.
- UI (Doctor tab): per-peer card — two arrows (hub→spoke, spoke→hub) × three
  layers with ✓/✗, verdict, evidence lines, "Apply fix" / "Auto" toggle,
  history of applied fixes + rollback.
- CLI: `hashem.sh revpath [--peer N] [--apply]` for spokes without the panel.
- Background: run on link-state change (ICMP flips) and every 30 min per peer,
  debounced; results cached (no per-request probing).

### A5. Tests (no real servers needed)
- Table tests for the classifier with synthetic probe matrices for every
  verdict (incl. ambiguous → `UNKNOWN`, never a wrong fix).
- Fake `exec` layer (interface `cmdRunner`) → assert exact commands,
  idempotency, and rollback ordering.
- `tests/test_revpath.sh`: network-namespace lab (`ip netns`, veth + `ip
  tunnel add mode gre`) reproducing rp_filter=1 and FW_INPUT one-way ping on
  CI/this host; verify detect → fix → symmetric ping. This is our
  substitute for a real affected server.

**Risks:** wrong auto-fix on prod → mitigated by snapshot/rollback + own chain
+ rate limit + `apply:false` default for the first release (owner can flip
to auto after seeing reports). ISP-level causes can't be fixed, only
classified — report says so explicitly.

---

## 3. Plan B — Honest multi-signal health (P2)

Principle: **service reachability is decided by the FRP session + TCP, ICMP is
metadata.** Never display "no ping" while the session is live.

### B1. One health model, one place
New `panel/health.go`:

```go
type LinkSignals struct {
    ServiceActive bool    // systemctl is-active (cached 5s)
    Session       bool    // ESTABLISHED to control/WSS port (see B2)
    TCPRTTms      float64 // kernel RTT of session, else active connect probe
    ConnectRTTms  float64 // active TCP connect to ctrl port (fallback)
    ICMPOK        bool
    ICMPms        float64
    GreIfUp       bool
    Rx, Tx        *uint64 // deltas -> "traffic flowing"
    ReverseICMP   *bool   // from Plan A, nil = unknown
}
func ComputeHealth(s LinkSignals) (state, latencyKind string, ms float64, reasons []string)
```
States: `healthy` (session live) · `healthy-frp-only` (session live, ICMP
dead — shown as green with a small "ICMP filtered" tag, not an error) ·
`degraded` (service up, no session / GRE up only / flapping) · `down`.
Latency source order: **tcp-session RTT → active TCP connect RTT → ICMP**.
`reasons[]` is shown in the tooltip so "degraded" always says why.

### B2. Fix `Linked` false negatives
`controlSession()` currently requires the `ss` remote == `RemotePub` or
`PeerGre`. Change to:
1. Match by **local control port set** (port, port+2 WSS, port-2) **and**
   remote ∈ {RemotePub, PeerGre, any address from `ip route get` of the peer,
   last-seen remote cached per peer}.
2. If still no match but exactly one peer owns that control port (ports are
   per-peer), accept any remote (NAT/CGNAT/roaming IP) and **cache the
   observed remote** for next time.
3. If no `ss` session: **active TCP connect** to `inner:port` / `pub:port`
   with 1.5s timeout (cheap) before declaring `Session=false`.
4. Add frps-side truth when available: frps dashboard/admin API
   (`/api/serverinfo`, `/api/proxy/tcp`) → client count + proxy `status`.
   Optional, behind detection; falls back to 1–3.

### B3. Stop leaking raw ICMP as the headline
- `fleetNode.PingOK/PingMs` → keep for compat, add `icmp_ok`, `icmp_ms`,
  `signals{}`, `reasons[]`, `health_state`. UI shows `latency_ms` +
  `latency_kind` (tcp/icmp) and an "ICMP filtered" chip; never "no ping".
- `handleDashboard` single-tunnel branch: replace
  `Gre.Exists && FrpUp && PingOK` with `ComputeHealth(...)`.
- Performance tab / Doctor "ping" rows: show "ICMP: filtered (TCP 38 ms ✓)".
- `fleetRecord`: sample uses the same latency → sparkline continuous instead
  of gaps (a gap currently equals "loss" in `fleetCompute`, so working links
  show phantom loss%). Separate `icmp_loss` from `service_loss`.
- Add flap damping: state changes only after 2 consecutive samples (30s) to
  stop healthy↔degraded blinking.

### B4. Tests
- Table tests for `ComputeHealth` (every combination of signals).
- `controlSession` tests with captured `ss -Htin` fixtures: NAT'd remote, WSS
  port+2, dial-route via public IP, two peers, IPv6-mapped (`[::ffff:x]`).
- Regression: link with `Session=true, ICMPOK=false` ⇒ never `down`/`degraded`
  and `latency_kind=="tcp"`.

**Risks:** over-reporting healthy when only the control TCP is up but
proxies are dead → mitigate by adding "proxy count with status=online" when
frps API is available and `traffic flowing` check; state `healthy` requires
session AND (no proxies configured OR ≥1 proxy online).

---

## 4. Plan C — Hub scalability (P3): measure first

### C0. Reading of the code (hypotheses, **not** conclusions)
All of these are cheap to confirm with profiling; none is fixed until C1 data
supports it.

1. `livePeers()` is **serial** and heavy per peer: `ip tunnel show` (once per
   peer, same output every time), `systemctl is-active`, **`ss -Htin state
   established` full dump per peer** (inside `controlSession`), then a
   blocking `ping -W 2` (up to 2 s when ICMP is dropped → 6 ICMP-dead peers =
   12 s per tick).
2. `livePeers()` is called from **three** places concurrently: the fleet
   sampler (every 15 s), `handleDashboard` (on **every** UI poll, and again
   inside `mainTunnelLive → localStatus` which also pings), and the autopilot
   / peer loops. No cache, no singleflight → N browsers × M peers × fork/exec
   storm. Each `exec.Command` forks a process from a Go process that may hold
   a large RSS → fork cost + spikes on small Iranian VPS.
3. `activeConns()` runs `ss -tun` and **counts every line** — on a hub with
   tens of thousands of proxied connections this is a large output buffered in
   memory on every dashboard hit.
4. `http.Server` has only `ReadHeaderTimeout` and `IdleTimeout`: **no
   `ReadTimeout`/`WriteTimeout`/`MaxHeaderBytes`**, no concurrency limit →
   slow clients on lossy Iran links pile up goroutines/FDs.
5. Possible OOM / CPU starvation by `frps` + GRE under load, killing or
   starving the panel (no `MemoryMax`/`OOMScoreAdjust`/`Nice`/`CPUWeight` set
   on the panel unit; panel and frps share one box).
6. Background loops multiply per peer: traffic recorder 5 s, fleet 15 s,
   peerSync 10 s, rescue monitor, autopilot, benchmark 60 s — each may shell
   out independently.

### C1. Measurement harness (Phase 1, ships first, read-only)
- `panel/pprof` endpoints behind the existing auth + `debug_enabled` flag:
  `/debug/pprof/{goroutine,heap,profile}`.
- `panel/metrics.go`: self-metrics at `/api/selfstats` — goroutines, heap,
  RSS, open FDs (`/proc/self/fd`), GC pause, per-sampler `last_duration_ms`,
  `exec` calls/min by command name, in-flight HTTP requests, request
  latency p50/p95/p99 per route, `livePeers()` duration histogram.
- Wrap `exec.Command` usage in `runCmd(name, args…)` (timeout via context,
  counter, duration) — also a prerequisite for C2 timeouts.
- **Load lab** `tests/loadlab/`: a Go program that spawns **N fake spokes**
  (N=1,3,6,10,20) in network namespaces *or* as loopback listeners:
  fake frps control sockets (ESTABLISHED sessions), dummy GRE ifaces
  (`ip link add type dummy`), registered in `peers.json`; optional ICMP-drop
  with `iptables`/`tc netem` (delay/loss) to mimic the Iran link; plus M
  simulated browser clients polling `/api/dashboard`, `/api/fleet`,
  `/api/peers` at the real UI cadence (`supTick` 5 s etc.).
- Scenario matrix: N∈{1,3,6,10,20} × clients∈{1,3,10} × ICMP{ok, dropped}
  × RAM{1 GB, 2 GB cgroup}. Output: CSV + flamegraph (`go tool pprof`) +
  a one-page `docs/audit/LOAD_REPORT.md`. **Success criteria baseline:**
  the harness must reproduce "panel dies/hangs at ~6 spokes"; if it doesn't,
  we widen the matrix (ICMP-dropped, slow clients, low RAM) before changing
  anything. Reproducing it is the gate to Phase 2.

### C2. Expected fixes (applied only if C1 confirms; ordered by likely payoff)
Each is independent, flag-guarded, and has a before/after number from the lab.

1. **Single shared collector + cache + singleflight.** One goroutine produces
   a `HubSnapshot` every 5 s (configurable); `/api/dashboard`, `/api/fleet`,
   `/api/peers`, autopilot, rescue **only read the snapshot** (RWMutex /
   atomic.Pointer). HTTP handlers never fork. Biggest win: per-request cost
   becomes O(1) regardless of spokes and browsers.
2. **Batch the per-peer work:** one `ss -Htin` per tick (parse once, index by
   local port); one `ip -o addr`/`ip -s link` per tick; one `systemctl
   is-active a b c …` (accepts many units) per tick; replace `ping` forks with
   an in-process ICMP socket (`golang.org/x/net/icmp`, unprivileged datagram
   or raw since we're root) or skip ICMP entirely when `Session=true` (Plan B)
   — ICMP becomes optional, low-frequency (every 60 s, jittered).
3. **Bounded concurrency + timeouts:** worker pool (`min(NumCPU, 4)`) for any
   remaining per-peer probes; every external command via
   `exec.CommandContext` (≤2 s); per-peer jitter to avoid thundering herd;
   skip a tick if the previous one is still running (no pile-up).
4. **HTTP server hardening:** `ReadTimeout 15s`, `WriteTimeout 30s`,
   `MaxHeaderBytes 1MB`, global in-flight limiter (e.g. 64) returning 503 with
   `Retry-After`, per-IP rate limit on heavy endpoints, gzip + `ETag`/
   `If-None-Match` on JSON (304s for unchanged snapshot), WebSocket/terminal
   unaffected.
5. **`activeConns()`:** read `/proc/net/sockstat` + `ss -s` (summary, O(1))
   or stream-count `/proc/net/tcp{,6}` instead of buffering full `ss -tun`.
6. **Process isolation:** panel systemd unit gets `OOMScoreAdjust=-900`,
   `MemoryHigh/MemoryMax` (sane for box RAM), `CPUWeight=200`, `Nice=-5`,
   `Restart=always`, `LimitNOFILE=1048576`, `TasksMax=` ; frps/frpc get
   *lower* `CPUWeight` than the panel so UI stays responsive under load but
   tunnels aren't starved (`CPUWeight` of panel modest; frps higher in
   absolute terms — decided from C1 data). Optional `GOMEMLIMIT`/`GOGC`
   tuning from lab results.
7. **Frontend:** UI polling backoff (hidden tab ⇒ stop; error ⇒ exponential
   backoff), single `/api/summary` call instead of 4–5, diff-render of fleet
   rows, cap sparkline points sent (downsample server-side to ≤120).
8. **Persistence cost:** `fleetSaveLocked` every 60 s writes JSON of
   N×720 samples; switch to append-only ring file / write only on change, and
   fsync-less atomic rename. `trafficRecorder` same.
9. **Watchdog on the watchdog:** panel self-heartbeat to systemd
   (`sd_notify WATCHDOG=1` with `WatchdogSec=30`) so a hung (not crashed)
   panel is restarted automatically; on restart, state is reloaded from disk
   — "forced to go up" becomes a seamless 2–3 s blip instead of a stuck UI.

### C3. Acceptance targets (to be confirmed/adjusted by C1 numbers)
- Panel RSS < 150 MB and CPU < 5 % of one core at N=20 spokes, 10 UI clients.
- `/api/dashboard` p95 < 50 ms regardless of N (served from snapshot).
- Zero fork/exec from HTTP handlers (asserted by a test that stubs the runner).
- Fleet tick duration < 1 s at N=20 even when all ICMP is dropped.
- No goroutine/FD growth over a 2 h soak (leak test in load lab).

---

## 5. Phasing and order

| Phase | Content | Why this order | Gate |
|---|---|---|---|
| **1** (1–2 d) | C1 measurement + load lab, `runCmd` wrapper, self-stats, pprof. A: classifier + fake-exec tests (read-only probes, no fixes). | Zero behaviour risk; gives numbers + proof for P3 and visibility for P1 | Lab reproduces the hang; classifier tests green |
| **2** (1–2 d) | B1–B3 (health model, `Linked` fixes, UI chips) + remove `restart gre-tunnel` on `!PingOK` | Fixes the visible "no ping while working" and the harmful Doctor restart; low risk | Regression tests; no `down` while session live |
| **3** (2–3 d) | C2 items 1–4 (+5,6 if data says so): shared snapshot, batching, timeouts, HTTP hardening | Data-backed fixes for hub overload | Acceptance targets §C3 on the lab |
| **4** (2 d) | A3/A4: auto-fix engine behind `revpath_auto` flag (default **off**), UI cards, CLI, netns lab test | Highest-risk (changes sysctl/iptables) → last, with rollback | netns tests detect→fix→symmetric |
| **5** | C2 7–9, flip defaults after 1 week of reports, docs (`docs/REVERSE_PATH.md`, FRP guide update), release tag | Polish | Owner sign-off |

Each phase: Claude Code implements (`claude -p` in `/root/gre-frp`), I review
and fix its output, run `go vet ./... && go test ./...` + the shell tests,
commit, and `git push origin main` in the same turn.

---

## 6. Files to touch (estimate)

- New: `panel/revpath.go`, `panel/revpath_test.go`, `panel/health.go`,
  `panel/health_test.go`, `panel/metrics.go`, `panel/runcmd.go`,
  `panel/snapshot.go`, `tests/test_revpath.sh`, `tests/loadlab/*`,
  `docs/REVERSE_PATH.md`, `docs/audit/LOAD_REPORT.md`.
- Changed: `panel/tunnel.go` (`livePeers`, `localStatus`), `panel/linked.go`
  (`controlSession`), `panel/fleet.go` (`fleetHealth`, `fleetRecord`,
  `fleetNode`), `panel/dashboard.go` (`handleDashboard`, `activeConns`,
  health rollup), `panel/doctor.go` (`applyDoctorFixes` step 5, audit
  additions: rp_filter, proto-47 rules, GRE counters), `panel/main.go`
  (server timeouts, limiter, snapshot start), `panel/index.html` (health
  chips, Doctor revpath cards, polling backoff), `hashem.sh` (`revpath`
  subcommand, panel unit limits, persistent sysctl for rp_filter).

---

## 7. Open questions (need owner decision before Phase 4)

1. Default for `revpath_auto`: report-only first release (recommended) vs
   auto-apply immediately?
2. Spoke agent: extend the existing Peer Link channel for spoke-side probes
   (recommended, no new port) vs a separate tiny agent?
3. OK to add dependency `golang.org/x/net/icmp` (in-process ICMP)? Else keep
   `ping` but only ≤1/min per peer and only when no live session.
4. Memory/CPU budget of target hub boxes (RAM size) so cgroup limits in C2.6
   are set from real numbers.

---------------------------------------------------------------------------
## Phase 1 status (measurement + read-only diagnosis)

Phase 1 changes no tunnel, health verdict or system state. Every new probe is a
read, and every new endpoint sits behind the normal session auth.

### Shipped
- `panel/runcmd.go`: `runner` seam (`cmdRunner`) plus `runCmdTimeout` /
  `runCmdTimeoutOut`, with a context timeout and per-command counters (calls,
  avg/max, timeouts, errors, calls in the last 60 s). The plan called this
  `runCmd`, but `rescue.go` already owns that name (a swappable var its tests
  assign), so the new helper is `runCmdTimeout`. Converted call sites only:
  `livePeers`, `localStatus`, `ifaceInner`, `svcActive`, `ssEstablished`,
  `activeConns`. Timeouts are 5 s; ping uses 4 s on top of its own `-W 2`.
- `panel/metrics.go`: `GET /api/selfstats` (goroutines, heap, GC, RSS, open
  FDs, uptime, exec stats, per-sampler stats, per-route p50/p95/p99 over the
  last 512 requests, in-flight gauge). Samplers timed: `livePeers`,
  `fleetSampler`, `trafficRecorder`, `peerSync`. Routes are labelled
  `/{base}/...`; paths outside the base collapse to `other`.
  `metricsMiddleware` wraps both the HTTP and HTTPS handler chains.
- Optional pprof at `/{base}/debug/pprof/*`, mounted only when
  `HASHEM_PPROF=1` or `debug_enabled` is true in `panel.json` (default off),
  behind `requireAuth`.
- `panel/loadlab_test.go`: in-process load lab (see
  `docs/audit/LOAD_REPORT.md`). Skipped unless `HASHEM_LOADLAB=1`.
- `panel/revpath.go`: probe matrix types, the pure `classifyRevPath`
  (verdict codes from A2, ambiguous input gives `UNKNOWN` with no fix),
  read-only collectors (rp_filter, ip_forward, GRE MTU, `ip route get`,
  `/proc/net/dev` counters, `iptables-save` parsing, conntrack invalid),
  `GET /api/revpath` (60 s cache, one collection at a time) and
  `POST /api/revpath/run {peer_id}`. The doctor report gains an additive
  `revpath` field filled from the cache only (it never probes).
- Tests: runcmd, metrics, revpath (a stub-runner test fails if any write
  command is issued) and the load lab.

### Deferred
- Spoke-side half of the matrix. Only hub to spoke is probed; spoke to hub
  ICMP layers stay `unprobed`. The only spoke to hub data is passive: TCP
  layers seen from live ESTABLISHED sessions. With the spoke side missing the
  classifier caps confidence and asks for spoke data.
- All fixes (A3), `applyDoctorFixes()` step 5 removal, `revpath_auto`, the UI
  cards, the CLI subcommand and the netns lab.
- Plan B (health model, `Linked` fixes, UI chips), Plan C2 (shared snapshot,
  batching, server timeouts, cgroup limits). Phase 3 is gated on the lab
  findings in `docs/audit/LOAD_REPORT.md`.
- GRE counter deltas include live tunnel traffic, so they are only used as
  zero versus non-zero.

## Phase 2+3 status (multi-signal health + hub scalability) — 2026-10-10

Owner decisions locked in: (D1) system `ping` only, background, <=1/min per
peer, skipped while the session is live; (D2) 5 s shared snapshot with age in
the API; (D3) session-live + ICMP-dead = healthy with `icmp_filtered` chip,
TCP RTT as latency; (D4) moderate HTTP hardening
(Read 30 s / Write 60 s / 1 MB headers / 64 in-flight -> 503+Retry-After,
WebSocket/terminal/streaming/selfstats exempt); (D5) 2-sample debounce.

Shipped (see `docs/audit/LOAD_REPORT.md` + `load_lab_results.csv` for numbers):
- `panel/health.go`: `LinkSignals`/`ComputeHealth` (session -> healthy; latency
  order tcp-session RTT -> connect RTT -> ICMP; reasons always populated);
  2-consecutive-snapshot debounce; `fleetHealth` is a thin wrapper over it.
- `linked.go`: remote matching by port set + known/cached remotes (NAT/CGNAT/
  WSS port+2/dial-route/IPv6-mapped), single-owner fallback, 1.5 s active TCP
  connect probe (injectable `dialFn`, collector-only).
- Snapshot (`panel/snapshot.go`): 5 s collector, one `ss` dump + one
  `ip tunnel show` + one `ip -o -4 addr` + one batched `systemctl is-active`
  per tick (4 commands, asserted), bounded worker pool, skip-if-running,
  background ICMP per D1, `/proc/net/*` streaming conn count, atomic fleet
  save. Consumers (dashboard/fleet/peers/status/fleet sampler, plus
  setup/peer/rescue/watchdog readers) read it; handlers never fork
  (asserted); `X-Snapshot-Age-Ms` header; `snapshot` block in selfstats.
- `panel/hardening.go`: server limits on both listeners, in-flight limiter,
  long-running/stream exemptions, E-SYS-02 503 shape.
- UI (surgical): TCP latency + "ICMP filtered" chip instead of "no ping" on
  healthy links, reasons tooltips, snapshot age, health-aware nav badge.
- `applyDoctorFixes` step 5: no more `restart gre-tunnel` on silent ICMP;
  `interfaceFixes` is factored and tested.

Deviations from the spec worth knowing:
- `signalsOf`/`fleetHealth` wrapper infers `ICMPFresh` from `ICMKnown` on the
  record rather than an explicit flag (fewer fields to plumb, same meaning).
- ICMP is skipped while the *control session* is live (D1 said "FRP session";
  same thing, implemented as `FrpUp && Linked`).
- `activeConns` counts /proc/net/{tcp,udp}[6] state-01 rows (equivalent to
  the old `ss -tun state established` count, incl. connected UDP).
- Pre-existing `gofmt` drift (15 files) left untouched, incl. doctor.go.
- `detectPublicIP`: still `ip route get` inside the collector (cached
  10 min, 1 min negative); tests pre-seed the cache.

Deferred: C2.6 (systemd limits, cgroup, watchdog), C2.7 (frontend polling
backoff), Plan A fixes/UI/CLI/netns lab, spoke-side probes, x/net/icmp.

## C2.6+C2.7 status (process isolation + frontend polling) — 2026-10-10

C2.7 was ~90% done before this run: `makePoller` already pauses hidden tabs,
backs off exponentially (cap 60 s), skips overlapping requests and resumes on
`visibilitychange`. Added the one missing guard: `supTick` (support popup)
now returns early on `document.hidden`. Log-follow keeps its own interval
(user-toggled, bounded, already hidden-gated). A string guard
(`TestIndexPollingPolicy`) pins the policy in place.

C2.6 shipped:
- `panel_limits_for_ram` (hashem.sh): RAM tiers -> MemoryHigh/MemoryMax:

  | host RAM | MemoryHigh | MemoryMax |
  |---|---|---|
  | <=1250 MB | 280M | 350M |
  | <=2560 MB | 450M | 550M |
  | <=4200 MB | 700M | 850M |
  | above | 1G | 1.2G |

  Autodetects from /proc/meminfo, falls back to 1024 MB.
- `apply_panel_unit_limits`: idempotent per-directive setter
  (`unit_set_directive`, keeps user extras): OOMScoreAdjust=-900, Nice=-5,
  CPUWeight=200, Restart=always/RestartSec=3, LimitNOFILE=1048576,
  LimitNPROC=512000, TasksMax=4096, WatchdogSec=30, NotifyAccess=main,
  StartLimitIntervalSec=0 + the RAM-scaled memory caps. Wired into
  `install_panel`; FRP templates (frps/frpc/peer frps/backhaul x2/WSS front)
  gained CPUWeight=100, and the Go `ensureFRPServiceUnits` patcher adds it to
  existing units without touching ExecStart.
- `hashem panel-limits [--apply] [--mem MB]`: print (default) or apply.
  `--apply` always uses the live host value; `--mem` is print-path only so a
  synthetic tier can never be written to a real unit.
- sd_notify watchdog (`panel/sdnotify.go`): READY=1 once + WATCHDOG=1 every
  10 s (WatchdogSec=30), silent no-op without NOTIFY_SOCKET or with
  HASHEM_NO_SDNOTIFY=1; tested against a temp unixgram socket.
- `tests/test_panel_limits.sh`: tiers, idempotency, extras preserved,
  re-tier replaces, FRP weight.

Deferred: GOMEMLIMIT/GOGC (needs real-hub data), /api/summary merge,
cgroup tuning from a loaded hub via /api/selfstats.

## Phase 4 status (auto-fix engine + spoke probes) — 2026-10-10

Report-only by default; auto behind `revpath_auto` (panel.json) or
HASHEM_REVPATH_AUTO=1. Spoke half rides the existing Peer Link channel
(same secret, no new port).

Shipped:
- Spoke probes: `POST /api/peer/revpath-probe` (peer auth) runs the
  spoke->hub half on the spoke (ICMP over GRE both sizes, public ICMP, TCP
  to control/WSS ports, GRE counters) against hub addresses the hub sends.
  The hub merges it in `revPathRefresh` and reclassifies with both
  directions genuinely probed; unreachable spokes keep the hub-only result
  with lowered confidence. Seam `spokeFetcher` (nil in tests by default).
- Auto-fix (`panel/revfix.go`): dry-run plan via `POST /api/revpath/fix`
  (default); `apply:true` runs snapshot -> apply -> re-probe -> rollback if
  worse. Fixable: RP_FILTER (3 sysctl keys + persist), SRC_SELECT (route
  src pin), NO_RETURN_ROUTE, FW_INPUT (own HASHEM-REVPATH chain only),
  MTU_BLACKHOLE (stepwise down), CONNTRACK_INVALID (raw NOTRACK). Never
  restarts services. Rate limits: 1/peer/10min, 3/hour; explicit clicks
  bypass the auto flag but not the limits. History at
  `GET /api/revpath/fixes`.
- UI: Reverse Path card in the Doctor tab (verdict, confidence, evidence,
  suggested fix, Show plan / Apply fix per peer, step log).
- CLI: `hashem revpath [--peer ID] [--apply] [--auto]` (login via
  HASHEM_PANEL_PASS or prompt; read-only unless --apply).
- `tests/test_revpath_lab.sh`: netns GRE pair proving the one-way pattern
  (rp_filter strict, INPUT DROP proto 47) detect -> fix -> symmetric;
  self-cleaning, skips without privileges.
- Tests: plan shapes per verdict, exact-command apply, rollback order,
  rate limits, merge, handler dry-run/auto-off, probe read-only gate
  (via `forbiddenCmd`).

Deferred: auto on by default (needs a week of reports), GOMEMLIMIT,
/api/summary merge, real-hub cgroup tuning.
