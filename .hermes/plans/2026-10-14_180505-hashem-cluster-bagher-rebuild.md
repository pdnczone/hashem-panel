# Plan: Hashem Panel — Cluster Multi-Iran/Multi-Foreign Rebuild & Bagher Engine Stabilization

**Goal:** Stabilize and fix all DOM and SSH-handshake bugs in Bagher (SSH forward carrier) and re-architect the Cluster subsystem into a resilient Multi-Iran to Multi-Foreign mesh with synthetic health probing, clean iptables chain isolation, and synchronized failover.

---

## Current Context / Assumptions
- **Repository:** `/root/gre-frp` on branch `dev` (HEAD commit `3c866b7acb831145d8a6667e78ef99e8cdb1ff3c`).
- **Runtime Environment:** Linux (amd64), Go 1.24+ at `/usr/local/go/bin/go`, Staticcheck at `/root/go/bin/staticcheck`.
- **Panel Stack:** Go HTTP backend (`panel/*.go`), vanilla JavaScript (`panel/app.js`), single-page HTML (`panel/index.html`), and CLI operations script (`hashem.sh`).
- **Core Diagnostics Findings:**
  1. **Bagher (Bugger):**
     - Broken DOM IDs: `sshfwdToggleBtn`, `sshfwdApplyBtn`, `sshfwdSyncPeerBtn`, `bagherApplyBundleBtn` are bound in `app.js` but missing in `index.html`.
     - Missing element `sshfwdMode` causes null-dereferences in role switching.
     - License banner ID mismatch: `sshfwdLicBanner` in JS vs `bagherLockedBanner` in HTML.
     - Dual-event firing: Inline `onclick="..."` in HTML combined with `on(id, 'click', ...)` in JS triggers duplicate concurrent API calls.
     - Fail2ban lockout: Iran starts `hashem-bagher.service` immediately upon bundle creation; SSH loops every 3 seconds with `Permission denied` before the Foreign server receives the key, causing IP bans.
     - Speedometer bug: `bagherLiveSpeed` displays total transferred bytes (`d.rx_formatted`) instead of transmission rate (bytes/sec).
  2. **Cluster:**
     - Missing Multi-Foreign topology: Existing `cluster.go` only supports 1:1 Iran pings; no concept of managing multiple Foreign exit nodes or switching between them.
     - Dead auto-failover: `getLocalTunnelStatus()` defaults to `"UP", 0, 1.0` if peer sync is not configured, meaning local tunnel failure is never detected.
     - Concurrency race: Map mutations in `startClusterMonitor()` occur across concurrent Goroutines without deep copying.
     - Dirty iptables accumulation: Failover rules are appended (`-A`) directly to `PREROUTING`/`POSTROUTING`; repeated triggers accumulate duplicate rules, and `-D` deletes only the first rule.
  3. **Panel Hygiene:**
     - Dead references to removed FOU carrier (`carrierPortsInput`, stale tooltips).

---

## Architecture / Proposed Approach
1. **Bagher Engine:** Reconcile DOM IDs, eliminate duplicate `onclick` attributes, calculate rate-of-change for live speed, and configure SSH reconnection with backoff (`RestartSec=15`) so Iran does not spam Foreign before bundle installation.
2. **Cluster Subsystem:** Expand `ClusterConfig` into a two-tier mesh:
   - `IranNodes`: Peer Iran servers communicating via authenticated heartbeat (`X-Cluster-Secret`).
   - `ForeignNodes`: Pool of foreign exit servers with synthetic TCP health probes.
   - Dedicated iptables custom chains (`HASHEM-CLUSTER-PREROUTING`, `HASHEM-CLUSTER-POSTROUTING`) flushed cleanly with `-F` to prevent rule pollution.
3. **Frontend Integration:** Provide a dual-table UI in `tab-cluster` for Iran Mesh Peers and Foreign Nodes Pool, with manual and automated failover toggles.

---

## Phase 1: Bagher DOM, Event Listeners, and Telemetry Fixes

### Task 1.1: Reconcile Bagher DOM IDs between `panel/index.html` and `panel/app.js`
- **Files:** `panel/app.js`, `panel/index.html`
- **Actions:**
  - In `panel/index.html`: Ensure hidden input `<input type="hidden" id="sshfwdMode" value="bagher" />` exists inside `tab-sshfwd`.
  - In `panel/app.js`: In `loadSSHFwd` and `renderSSHFwd`, replace references to `sshfwdLicBanner` with `bagherLockedBanner`.
  - In `panel/app.js`: Remove dead listener registrations: `sshfwdToggleBtn`, `sshfwdApplyBtn`, `sshfwdSyncPeerBtn`, and `bagherApplyBundleBtn`.
- **Verification:**
  ```bash
  python3 -c '
  import re
  with open("/root/gre-frp/panel/index.html") as f: html = f.read()
  with open("/root/gre-frp/panel/app.js") as f: js = f.read()
  for dead in ["sshfwdToggleBtn", "sshfwdApplyBtn", "sshfwdSyncPeerBtn", "bagherApplyBundleBtn"]:
      assert dead not in js, f"Dead ID still in JS: {dead}"
  assert "bagherLockedBanner" in js, "bagherLockedBanner missing in JS"
  print("DOM ID reconciliation verified")
  '
  ```

### Task 1.2: Remove Duplicate Inline `onclick` Attributes from Bagher Controls
- **Files:** `panel/index.html`
- **Actions:**
  - Strip inline `onclick` from:
    - `bagherIranApplyBtn` (`onclick="bagherIranApplyClick()"`)
    - `bagherIranStopBtn` (`onclick="bagherIranStopClick()"`)
    - `bagherIranCleanBtn` (`onclick="cleanBagherTunnelClick()"`)
    - `bagherForeignConnectBtn` (`onclick="bagherForeignConnectClick()"`)
    - `bagherForeignStopBtn` (`onclick="bagherForeignStopClick()"`)
    - `bagherForeignCleanBtn` (`onclick="cleanBagherTunnelClick()"`)
  - Ensure all clicks are bound exclusively once via `on(...)` inside `initSSHFwdEvents()` in `panel/app.js`.
- **Verification:**
  ```bash
  grep -E 'id="bagher(Iran|Foreign)[a-zA-Z]+" onclick=' /root/gre-frp/panel/index.html
  # Expected: No output (zero matches)
  ```

### Task 1.3: Fix Live Speed Calculation in `panel/app.js`
- **Files:** `panel/app.js`
- **Actions:**
  - Track previous telemetry sample: `let lastBagherBytesRx = 0, lastBagherBytesTx = 0, lastBagherTime = 0;`.
  - In `renderSSHFwd(d)`:
    Calculate `deltaSec = (now - lastBagherTime) / 1000`.
    Calculate `rxSpeed = (d.bytes_rx - lastBagherBytesRx) / deltaSec`.
    Format as `formatSpeed(rxSpeed)` and display: `↓ 240 KB/s  ↑ 45 KB/s`.
- **Verification:**
  ```bash
  node --check /root/gre-frp/panel/app.js
  # Expected: Exit code 0
  ```

---

## Phase 2: Bagher Backend Resilience & Handshake Safety

### Task 2.1: Add Unit Tests for Bagher Backoff & Service Templates
- **Files:** `panel/sshfwd_test.go`
- **Actions:**
  - Add test `TestSSHFwdServiceBackoff` verifying `RestartSec=15` and `StartLimitIntervalSec=120` are present in `buildSSHFwdService(cfg)`.
  - Add test `TestSSHFwdPermitListenWildcard` verifying OpenSSH `permitlisten` accepts both `127.0.0.1:port` and `port`.
- **Verification:**
  ```bash
  export PATH=/usr/local/go/bin:$PATH
  cd /root/gre-frp/panel && go test -v -run "TestSSHFwdServiceBackoff|TestSSHFwdPermitListenWildcard" ./...
  # Expected: Tests run (failing initially before implementation)
  ```

### Task 2.2: Implement Safe SSH Retry and Connection Resilience in `panel/sshfwd.go`
- **Files:** `panel/sshfwd.go`
- **Actions:**
  - Update `buildSSHFwdService(cfg)`:
    - Set `RestartSec=15` (prevents fast fail2ban ban).
    - Set `StartLimitIntervalSec=120` and `StartLimitBurst=5`.
    - Add SSH options: `-o StrictHostKeyChecking=accept-new -o ConnectTimeout=8 -o ServerAliveInterval=15 -o ServerAliveCountMax=3`.
  - In `handleSSHFwdPost`:
    - Reconcile the default error response message to include all supported actions: `enable, disable, gen_key, sync_peer, clear_dnat, apply_bundle, get_bundle, clean`.
- **Verification:**
  ```bash
  export PATH=/usr/local/go/bin:$PATH
  cd /root/gre-frp/panel && go test -v -run "TestSSHFwd.*" ./...
  # Expected: All tests PASS
  ```

---

## Phase 3: Multi-Iran to Multi-Foreign Cluster Architecture

### Task 3.1: Define Failing Unit Tests for Multi-Iran to Multi-Foreign Topology
- **Files:** `panel/cluster_test.go`
- **Actions:**
  - Add test `TestClusterMultiForeignConfig` verifying persistence of `ForeignNodes` in `ClusterConfig`.
  - Add test `TestClusterSyntheticHealthProbe` verifying that active TCP probe detects down state when peer port is closed.
  - Add test `TestClusterIPTablesChainIsolation` verifying rule generation targets `HASHEM-CLUSTER-PREROUTING`.
- **Verification:**
  ```bash
  export PATH=/usr/local/go/bin:$PATH
  cd /root/gre-frp/panel && go test -v -run "TestClusterMultiForeignConfig|TestClusterSyntheticHealthProbe|TestClusterIPTablesChainIsolation" ./...
  # Expected: Fails to compile or fails assertion
  ```

### Task 3.2: Re-architect Data Models in `panel/cluster.go`
- **Files:** `panel/cluster.go`
- **Actions:**
  - Define `ForeignNode` struct:
    ```go
    type ForeignNode struct {
        ID         string    `json:"id"`
        Name       string    `json:"name"`
        PublicIP   string    `json:"public_ip"`
        TunnelPort int       `json:"tunnel_port"`
        Protocol   string    `json:"protocol"` // "gre" or "wss"
        IsActive   bool      `json:"is_active"`
        IsHealthy  bool      `json:"is_healthy"`
        LatencyMs  float64   `json:"latency_ms"`
        LastProbe  time.Time `json:"last_probe"`
    }
    ```
  - Update `ClusterConfig`:
    ```go
    type ClusterConfig struct {
        Enabled        bool                   `json:"enabled"`
        NodeID         string                 `json:"node_id"`
        ClusterSecret  string                 `json:"cluster_secret"`
        PublicIP       string                 `json:"public_ip"`
        ServicePorts   []int                  `json:"service_ports"`
        Nodes          map[string]ClusterNode `json:"nodes"`         // Peer Iran Hubs
        ForeignNodes   map[string]ForeignNode `json:"foreign_nodes"` // Foreign Exit Nodes Pool
        ActiveForeign  string                 `json:"active_foreign,omitempty"`
        AutoFailover   bool                   `json:"auto_failover"`
        ActiveFailover string                 `json:"active_failover,omitempty"`
        FailoverTarget string                 `json:"failover_target,omitempty"`
        Updated        string                 `json:"updated,omitempty"`
    }
    ```
  - Ensure `loadClusterConfig()` performs deep copying of maps under `clusterMu.RLock()` to eliminate data races.

### Task 3.3: Implement Active Synthetic Health Probing in `panel/cluster.go`
- **Files:** `panel/cluster.go`
- **Actions:**
  - Replace dummy `getLocalTunnelStatus()` with `probeForeignNodeHealth(node ForeignNode) (status string, latency float64, err error)`:
    - Performs direct TCP dial to `node.PublicIP:node.TunnelPort` with a 2-second timeout.
    - If dial succeeds: `status = "UP"`, `latency = roundTripTime`.
    - If dial fails: `status = "DOWN"`, `latency = 0`.
  - Update cluster heartbeat to exchange status of both Iran hub health and Foreign pool availability.

### Task 3.4: Implement Dedicated IPTables Chains in `panel/cluster.go` and `hashem.sh`
- **Files:** `panel/cluster.go`, `hashem.sh`
- **Actions:**
  - In `panel/cluster.go`:
    - Ensure custom chain setup:
      `iptables -t nat -N HASHEM-CLUSTER-PREROUTING 2>/dev/null || true`
      `iptables -t nat -C PREROUTING -j HASHEM-CLUSTER-PREROUTING 2>/dev/null || iptables -t nat -I PREROUTING 1 -j HASHEM-CLUSTER-PREROUTING`
    - In `applyClusterFailover`: Flush `HASHEM-CLUSTER-PREROUTING` before adding new DNAT rules.
    - In `clearClusterFailover`: Flush `HASHEM-CLUSTER-PREROUTING` cleanly (`iptables -t nat -F HASHEM-CLUSTER-PREROUTING`).
  - In `hashem.sh`:
    - Update `cli_cluster` status and revert routines to inspect and flush `HASHEM-CLUSTER-PREROUTING`.
- **Verification:**
  ```bash
  export PATH=/usr/local/go/bin:$PATH
  cd /root/gre-frp/panel && go test -v -run "TestCluster.*" ./...
  # Expected: All cluster tests pass
  ```

### Task 3.5: Update Cluster Frontend UI & JavaScript in `panel/index.html` and `panel/app.js`
- **Files:** `panel/index.html`, `panel/app.js`
- **Actions:**
  - In `panel/index.html` under `tab-cluster`:
    - Add section 1: **Iran Hubs Mesh** (Table of peer Iran nodes, sync status, latency, failover relay status).
    - Add section 2: **Foreign Exit Nodes Pool** (Table of Foreign nodes, IP, protocol, active badge, switch button).
    - Add modal for Adding/Editing Foreign Nodes.
  - In `panel/app.js`:
    - Implement `renderClusterForeignNodes(foreignNodes, activeId)`.
    - Implement `clusterSwitchForeignClick(targetId)`.
    - Implement `clusterAddForeignNodeClick()`.
- **Verification:**
  ```bash
  node --check /root/gre-frp/panel/app.js
  # Expected: Exit code 0
  ```

---

## Phase 4: Panel Hygiene, FOU Removal, and Final Verification

### Task 4.1: Purge Residual FOU Carrier References
- **Files:** `panel/index.html`, `panel/app.js`
- **Actions:**
  - Remove `carrierPortsInput` dead check from `panel/app.js`.
  - Fix tooltip in `tunnelCarrierCycleBtn` in `panel/index.html` to reflect `(Direct GRE / WSS)` instead of FOU.
- **Verification:**
  ```bash
  grep -rni "carrierPortsInput" /root/gre-frp/panel/
  # Expected: No output
  ```

### Task 4.2: Full Static Analysis & Test Suite Run
- **Actions:**
  - Run `go vet ./...`
  - Run `staticcheck ./...`
  - Run `go test -v ./...`
- **Commands:**
  ```bash
  export PATH=/usr/local/go/bin:/root/go/bin:$PATH
  cd /root/gre-frp/panel
  go vet ./...
  staticcheck ./...
  go test -v ./...
  ```
- **Expected:** All packages clean, zero warnings, 100% test pass.

---

## Risks, Tradeoffs, and Open Questions
1. **Risk:** Failover iptables redirection requires kernel IP forwarding (`net.ipv4.ip_forward = 1`).
   - *Mitigation:* Ensure `applyClusterFailover` explicitly verifies or enables `sysctl -w net.ipv4.ip_forward=1`.
2. **Tradeoff:** Synthetic TCP probing every 5 seconds adds negligible network traffic (~64 bytes per probe) but drastically increases failover detection accuracy from zero to <10 seconds.
3. **Open Question:** Should Foreign exit nodes in the pool be switchable dynamically without restarting local client tunnels, or via seamless iptables reroute?
   - *Resolution:* Support iptables rerouting instantly for existing connections while updating tunnel endpoints for long-term stability.
