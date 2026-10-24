# IPv6 in Hashem

[فارسی](IPV6.fa.md)

Hashem uses IPv6 in three places:

1. **Users → Iran server.** Users can connect to the forwarded ports over IPv6 as well as IPv4.
2. **Iran server ↔ foreign server.** Some engines can connect the two servers over IPv6.
3. **The GRE wrap.** The main GRE tunnel can travel over IPv6 (4in6), or over a private IPv6 inside IPv4 (6to4).

## 1. Users over IPv6

Nothing to set up. Backhaul, FRP, Bagher and Xray listen on every address of both families. If the Iran server has a public IPv6 address and its firewall lets the ports in (UFW does for IPv6 when `/etc/default/ufw` has `IPV6=yes`, the default), users can connect to `[IPv6]:port`.

## 2. The two servers over IPv6

| Engine | Over IPv6 | How |
| --- | --- | --- |
| Backhaul without GRE | yes | Setup → Backhaul → Without GRE → **Connect the two servers over: IPv6**. The bundle (`bh1_…`) carries the Iran server's IPv6. |
| Bagher (SSH) | yes | Type the foreign server's IPv6 as its address. |
| Xray | yes | Type the other server's IPv6 as its address (or as this server's public IP in reverse mode). |
| WSS wrap | yes | Tunnel tab → GRE wrap → WSS settings → **Address of the other server**: its IPv6. |
| GRE + FRP, GRE + Backhaul | through the GRE wrap | GRE itself needs IPv4 addresses on both servers; use the 4in6 wrap to carry it over IPv6. |
| Spoof | no | It spoofs IPv4 source addresses by design. |

## 3. GRE over IPv6: the 6to4 and 4in6 wraps

Tunnel tab → **GRE wrap**:

| Wrap | What crosses the network | Needs |
| --- | --- | --- |
| Direct GRE | IP protocol 47 between the IPv4 addresses | protocol 47 passes |
| WSS | GRE inside TLS on a TCP port | the TCP port passes |
| **6to4** | IP protocol 41 between the IPv4 addresses, carrying a private IPv6 /64 with GRE on it | protocol 41 passes (often when 47 does not) |
| **4in6** | GRE (protocol 47) between the servers' public IPv6 addresses | both servers have public IPv6 |

The tunnel interface (`gre-tunnel`, `gre-tN`) keeps its name, its inner IPv4 address (`10.10.10.x/30`) and its routes, so everything on top of it (FRP, Backhaul, the MTU settings, the traffic counters) keeps working unchanged. Under 6to4 there is one extra interface, `hs6-<name>`.

**Switching changes both servers.** **Switch Wrap** changes this server, then the other one over the Peer Link. For 4in6 the panel uses this server's public IPv6 and asks the other server for its own; you can also type it. It then waits up to 45 seconds for the other server's inner address to answer. If it does not, both servers go back to the wrap they had. Without a Peer Link only this server changes, and you switch the other one yourself.

If a 6to4 or 4in6 interface cannot be built (no IPv6 in the kernel, or the other server's IPv6 is unknown), the tunnel goes back to plain GRE instead of being left without an interface.

### From the command line

```bash
hashem carrier set 6to4
hashem carrier set 4in6 --local6 2001:db8::1 --remote6 2001:db8::2
hashem carrier set direct
hashem edit-peer --id 2 --carrier 4in6 --remote6 2001:db8::9
```

`--if gre-tN` applies the wrap to one tunnel only. The ends of each tunnel are kept in `/etc/gre-panel/gre6/<interface>.env`.

### Firewall

- 6to4: the panel lets IP protocol 41 in from the other server's IPv4 (`iptables`).
- 4in6: the panel lets IP protocol 47 in from the other server's IPv6 (`ip6tables`).
- A cloud firewall (security group) in front of the server has to allow the same.

### MTU

The tunnel stays at MTU 1380. That fits 6to4 (64 bytes of headers over a 1500 path) and 4in6 (44 bytes).

## Limits and traffic counters

A foreign server can be limited by its IPv6 address. When a GRE tunnel runs on 4in6, the foreign server's IPv6 counts towards the same speed and volume as its IPv4. The volume is counted with `ip6tables` and the speed is policed with `tc ... protocol ipv6`. The dashboard's per-tunnel counters count links over IPv6 too.

## Before you build: the path test

Benchmark tab → **Path test** also tries the IPv6 paths between the two servers: **6to4** (protocol 41), **TCP over IPv6** and **4in6**. A row that works tells you that wrap will get through. Without a public IPv6 on the Iran server, the last two are not tested.

## Cluster

DNS failover writes `AAAA` records for the working hubs that have a public IPv6 and no pools. A hub with pools gets no `AAAA`: the load balancer is IPv4 NAT, so users over IPv6 would not reach its pooled ports. See [CLUSTER.md](CLUSTER.md#9-dns-failover).

## Doctor

When the server has a public IPv6 but UFW is set to `IPV6=no`, the doctor says so: users and servers cannot reach the tunnel ports over IPv6 until it is `IPV6=yes`.

## Not over IPv6

- The cluster's load balancer (IPv4 NAT).
- The Spoof tunnel (IPv4 by design).
