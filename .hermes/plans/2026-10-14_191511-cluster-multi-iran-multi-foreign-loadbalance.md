# Multi-Iran Hubs to Multi-Foreign Exit Nodes Load Balancing Plan

## 1. Goal
Support multi-Iran to multi-Foreign clusters with identical or custom target ports using Linux kernel `iptables` statistic mode (Weighted Round-Robin) combined with Go active health probes and decentralized P2P mesh status exchange between Iran hubs.

## 2. Key Architecture Decisions (User Approved)
1. **Load Balancing Strategy**: Weighted Round-Robin (WRR) with active background health checks (`iptables -m statistic --mode random --probability ...`).
2. **Balancing Mechanism**: High-performance kernel iptables DNAT in isolated `HASHEM-CLUSTER-PREROUTING` and `HASHEM-CLUSTER-POSTROUTING` chains.
3. **Iran Hubs Coordination**: Decentralized P2P mesh. Each Iran hub manages its own foreign node pool and exchanges live health/telemetry via authenticated heartbeats (`/api/cluster/heartbeat`).
4. **Port Mapping**: Support identical service ports by default (e.g. 443 -> 443) with optional custom target ports per foreign node (e.g. 443 -> 8443).

## 3. Implementation Steps (TDD)
- **Phase 1: Backend Data Model & Unit Tests**
  - Update `ForeignNode` struct with `Weight` (default: 1) and `TargetPorts map[int]int`.
  - Update `ClusterConfig` with `BalancingMode` (default: "wrr").
  - Add TDD tests in `cluster_test.go` for:
    - WRR probability calculation and rule generation.
    - Custom port mapping vs identical port mapping.
    - Foreign node pool multi-balancing and auto-pruning unhealthy nodes.
- **Phase 2: Kernel iptables Load Balancer Engine**
  - Implement `applyClusterLoadBalancing(cfg *ClusterConfig)` using `iptables -m statistic --mode random --probability ...` across all healthy foreign nodes.
  - Implement graceful fallback: if only 1 node is healthy, 100% traffic goes to it without statistic overhead.
  - Periodic monitor loop updates iptables rules automatically when foreign node health status changes.
- **Phase 3: Endpoints & P2P Gossip**
  - Extend `/api/cluster/foreign/add` to accept `weight` and `target_ports`.
  - Extend `/api/cluster/config` to configure `balancing_mode`.
  - P2P heartbeat sends mesh health metrics.
- **Phase 4: Frontend UI (Cluster Tab)**
  - Add Load Balancing Strategy selector (Weighted Round-Robin / Active-Passive Failover).
  - Add Weight input and Port Mapping inputs to `#clusterForeignModal`.
  - Display live traffic distribution percentage and health state per Foreign node in `clusterForeignList`.
- **Phase 5: Regression & Verification**
  - Run all Go unit tests (`go test ./...`).
  - Run `go vet` and `staticcheck`.
  - Verify zero impact on single-node setups and GRE/FRP carriers.
