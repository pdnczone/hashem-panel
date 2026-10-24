# Hashem Cluster Guide

**English** · [فارسی](CLUSTER.fa.md)

The cluster keeps your users connected when a server dies. It joins several servers together so that one failure, whether an Iran server, a foreign server, a tunnel or the service behind it, does not take users down. It is a **Hashem Pro** feature: any Pro key includes it, or a key with the `cluster` feature.

- [The cluster map](#the-cluster-map)
- [1. What it can do](#1-what-it-can-do)
- [2. Words used here](#2-words-used-here)
- [3. Before you start](#3-before-you-start)
- [4. Scenarios, step by step](#4-scenarios-step-by-step)
- [5. Pool modes](#5-pool-modes)
- [6. Health checks and timing](#6-health-checks-and-timing)
- [7. Settings reference](#7-settings-reference)
- [8. Linked Iran hubs](#8-linked-iran-hubs)
- [9. DNS failover](#9-dns-failover)
- [10. Monitoring and alerts](#10-monitoring-and-alerts)
- [11. Terminal commands](#11-terminal-commands)
- [12. HTTP API](#12-http-api)
- [13. How it works inside](#13-how-it-works-inside)
- [14. Troubleshooting](#14-troubleshooting)
- [15. Limits](#15-limits)

![Cluster map: one Iran hub, six foreign servers, three pools, two linked Iran hubs and DNS failover](img/cluster-map.png)

### The cluster map

The Cluster tab opens on a map of the cluster. Every part of it can be clicked, and an inspector next to it (under it on narrow screens) shows that part and lets you change everything about it:

| Click | You see and can change |
|---|---|
| **This Iran hub** (middle) | hub name and public IP, the health check (interval, Fall, Rise), hub forwarding; New Pool, Show Join Code, Link a Hub, the kernel rules |
| **A pool** (port inside the hub) | its state and members with share and connections; mode (one click), port, protocol, name, service check and interval, manual failback; Fail Back Now, Enable/Disable, Delete, add a foreign server |
| **A line** from a pool to a foreign server | that server's settings in that pool: weight (slider), priority, port, connection limit, standby, drain; Remove From Pool |
| **A foreign server** (right) | its health and why, latency, session, ports, private address; the pools it is in (click one to edit it), Add to a pool |
| **A linked Iran hub** (left) | its state, latency, version and pools; Unlink |
| **DNS Failover** (left) | provider (Cloudflare or webhook), record, TTL, token or secret, on/off; Test, Save |
| **+ New Pool / + Link a Hub / + Add a foreign server** | the matching dialog (a foreign server is added in Setup) |

Line thickness is the share of new connections the server gets; moving dashes show traffic. Green carries traffic, grey is healthy but idle (for example the backup in failover mode), blue dashes are standby members, DNS and linked hubs, red dots are down, grey dots are drained or not serving. The map refreshes every 3 seconds without touching what you are typing in the inspector. **List** shows the same data as tables. On a foreign server, the map shows the Iran hubs it serves; click one to leave it, or **+ Join Another Iran Hub**.

---

## 1. What it can do

| Shape | What happens when something dies | Built from |
|---|---|---|
| **One Iran server → several foreign servers** | A foreign server, its tunnel or its service dies: its users move to the others within seconds. | a **pool** |
| **Several Iran servers → one foreign server** | An Iran server dies: users who connect through the other Iran servers keep working. | `join-hub` on the foreign server |
| **Iran servers backing each other up** | Every foreign server of a pool is down on one Iran server: its port is forwarded to another Iran server where the pool works. | **linked hubs** |
| **A domain that follows the working Iran servers** | An Iran server dies: the domain stops pointing at it. | **DNS failover** (Cloudflare or a webhook) |
| **Full mesh (N Iran × M foreign)** | Any single server can die. | all of the above together |

What a pool gives you:

- **Six ways to split traffic.** Failover, balance by weight, sticky per user, lowest latency and least connections, plus standby (backup) members for any mode.
- **Health checks on three levels.** The tunnel session, ping on the path the tunnel really uses, and an optional **service check** that connects through the tunnel to the service behind it (for example xray). A live tunnel in front of a dead service is still taken out.
- **Connection limits** per foreign server, with overflow to the others or to standby members.
- **Maintenance without cuts.** Drain a server so it takes no new connections while open ones finish.
- **Manual failback.** It stops traffic from bouncing back to a flapping primary server.
- **Kernel speed, nothing in between.** Users' packets are redirected by the Linux kernel (DNAT). The real client IP reaches the tunnel, so PROXY protocol keeps working, and restarting or updating the panel drops nothing.
- **Mixed engines.** FRP (any transport) and Backhaul tunnels can serve the same pool.

---

## 2. Words used here

- **Iran hub (hub):** the Iran server. Users connect to it.
- **Foreign server:** the server abroad that the hub tunnels to. Hashem calls it a *peer* on the hub. Tunnel id `0` is the main tunnel made in Setup; `N` is peer N (`hashem peer-list`).
- **Link / tunnel:** one hub ↔ foreign server tunnel (an `frps` or `backhaul-server` unit on the hub).
- **Pool:** one public port on the hub (TCP, UDP or both) served by several links.
- **Member:** a link in a pool.
- **Linked hubs:** other Iran hubs this hub trusts. They exchange signed heartbeats.

---

## 3. Before you start

- **License:** Hashem Pro on every server that runs a pool, links hubs or joins extra hubs. Pools that already run keep running if a license expires, but nothing can be changed until it is renewed.
- **Same version** of Hashem on every server of the cluster.
- **Foreign servers added on the hub** in Setup (or with `hashem add-peer` / `hashem add-backhaul-peer`), with the port the pool will serve (for example 443) in their port list. **Order matters:** add the first foreign server, make the pool on its port, then add the others with the same port. A port without a pool belongs to one tunnel, so a second tunnel on it is refused until the pool exists.
- **For linked hubs:** each hub's panel port (the plain HTTP one, also when HTTPS is on: the heartbeat is signed, not secret) must be reachable from the other hub, and both clocks must be right (within 90 seconds). Enable NTP: `timedatectl set-ntp true`. A panel reachable only through a reverse proxy cannot be linked.
- **For DNS failover:** a Cloudflare API token with *Zone → DNS → Edit*, and a DNS-only (grey cloud) record; or your own webhook.
- **For the service check:** a TCP service behind the tunnel (xray, sing-box, SSH, a web server…).

> The first time a link joins a pool, its relay (`frps` / `backhaul-server`) restarts once to move behind the pool. That takes a few seconds, for that tunnel only. Plan it outside peak hours.

---

## 4. Scenarios, step by step

Every step can be done in the panel (**Cluster** tab), in the terminal menu (`hashem`, then **Cluster**), or with commands (`hashem cluster …`). The examples use port 443.

### 4.1 Active/standby: one Iran server, two foreign servers, failover

Goal: everything goes through foreign server A. If A dies, B takes over within seconds.

1. On the hub, add A as a foreign server in **Setup** with port 443 (or use the main tunnel).
2. **Cluster → New Pool** → port `443`, protocol TCP (or TCP and UDP), mode **Failover**. A is already ticked because it carries port 443. Save: A's relay restarts once to move behind the pool.
3. Add B in **Setup**, also with port 443. A port without a pool belongs to one tunnel only, so B is accepted only now that the pool covers 443. B joins the pool by itself, already behind it.
4. Give A priority `0` and B priority `1` (click B's line on the map, or Edit). The pool shows **Healthy**, with 100% on A.

```bash
hashem cluster pool add 443 --mode failover        # picks every tunnel that has port 443
hashem cluster member set 443 2 --priority 1       # peer 2 is the backup
```

When A comes back, traffic returns to A after it passes 3 checks in a row. To stop that (see 4.7), set **Failback: Manual**.

### 4.2 Load balancing over several foreign servers

Goal: spread users over three foreign servers, more on the bigger one.

- **Balance:** each new connection goes to a member chosen at random by weight. Give the big server weight `2`, the others `1`.
- **Least connections:** new connections go to the members with the fewest open connections per unit of weight. This is the better choice for long-lived connections (VLESS, VMess, Trojan, SSH), where a server that just came back would otherwise stay empty.

```bash
hashem cluster pool add 443 --mode least
hashem cluster member set 443 1 --weight 2
```

### 4.3 A stable exit IP per user (sticky)

Some sites (banks, Instagram, Google) dislike an IP that keeps changing. In **Sticky per user** mode, each user (source IP) always goes to the same foreign server. Users are spread by weight. When a server leaves, only its own users move; everybody else stays put.

```bash
hashem cluster pool mode 443 sticky
```

### 4.4 Always the fastest server

**Lowest latency** sends all traffic to the healthy member with the lowest ping. It moves only when another member has been clearly faster (20% and at least 10 ms) for 10 checks in a row, so it does not flap between two close servers.

### 4.5 Standby servers and overflow

Mark a member **Standby** (backup). It gets no traffic while any normal member is healthy and has room, in every mode.

Combined with a **connection limit**, this gives tiers:

- Members A and B have `max connections 500`, and C is standby.
- A and B share the load. When one reaches 500 open connections, it takes no new ones until it drops below 450 (90%).
- When both are full or down, new connections overflow to C.
- When everyone is full, the pool still serves rather than refusing users.

```bash
hashem cluster member set 443 1 --max-conn 500
hashem cluster member set 443 2 --max-conn 500
hashem cluster member set 443 3 --backup yes
```

### 4.6 Detecting a dead service behind a live tunnel (service check)

The tunnel can be fine while xray on the foreign server has crashed. Users would connect and get nothing. Turn on **Service check: TCP** in the pool. Every *N* seconds (default 3), the hub opens a connection through each member's tunnel to the real service:

- **Passes:** the service answers, or keeps the connection open (TLS servers wait for the client).
- **Fails:** the connection is refused, reset, or closed at once. When the service is down, the foreign client cannot reach it and the tunnel drops the connection immediately.

After 3 failures in a row (the **Fall** setting) the member is out; after 3 passes (**Rise**) it is back.

```bash
hashem cluster pool set 443 --check tcp --check-every 3
```

> The service sees one short connection per member every few seconds; xray may log it as a rejected or empty connection. Use 5–10 seconds if that bothers you. The check is for TCP pools; UDP pools rely on the tunnel health.

### 4.7 No flapping: manual failback

In failover mode with **Failback: Manual**, once traffic has moved to a backup it stays there while the backup works, even when the first server comes back. Press **Fail Back Now** on the pool when you are ready. New connections then go to the first server; open ones stay where they are.

```bash
hashem cluster pool set 443 --no-failback yes
hashem cluster pool failback 443
```

### 4.8 Maintenance without cutting anyone

**Drain** a member: it takes no new connections and the open ones finish. Do the maintenance, then **Resume**.

```bash
hashem cluster member drain 443 2
hashem cluster member resume 443 2
```

To stop a pool without restarting anything, **Disable** it. The port then goes to one tunnel (the lowest id); **Enable** brings the pool back.

### 4.9 Many ports

- To create several pools at once, enter `443, 8443` or a range `2000-2005` in the **Public port** field (at most 50 ports), or run `hashem cluster pool add 443,8443,2000-2005`.
- Ports of a pooled tunnel that are **not** in any pool still work: they pass straight through to that tunnel. If two pooled tunnels both serve such a port, the lower id gets it and the Cluster tab warns you. Make a pool for that port to use both.
- A member can serve the pool from **another port** on its side. Set the member's **Port** (for example pool 443 → member port 8443).

### 4.10 Several Iran servers, one foreign server (`join-hub`)

Goal: two Iran servers (Tehran and Mashhad) both use the same foreign server, so either one keeps working alone.

1. The foreign server is already set up with its first Iran hub (Tehran).
2. On the second Iran server (Mashhad), go to **Setup** and add the foreign server as a peer with the same ports. Copy the bundle it prints (`hsh1_…`, `bh1_…` or `gh1_…`).
3. On the foreign server, paste it into **Cluster → Join Another Iran Hub**, or run:

```bash
hashem join-hub --bundle hsh1_... --name mashhad
hashem hubs                 # lists the Iran hubs this server serves
hashem leave-hub --id 2     # stop serving one
```

The foreign server runs a second client (`frpc-h2` or `backhaul-client-h2`) with its own GRE interface `gre-h2`. If the bundle's GRE addresses are already used on this server, it dials the hub's public IP instead. Options:

- `--dial auto|gre|public` chooses how it dials the hub.
- `--relay-ip` sets the local service address, 127.0.0.1 by default.

A foreign server can serve up to 9 Iran hubs.

### 4.11 Two Iran hubs backing each other up (linked hubs)

Goal: if every foreign server of pool 443 is down on Tehran, Tehran forwards port 443 to Mashhad, where the pool works.

1. Both hubs have a pool on port **443** (the other hub must have a pool on the same port, even with one member).
2. On Tehran: **Cluster → Show Join Code**, then copy it. On Mashhad: **Cluster → Link a Hub**, then paste it. One side is enough: the other learns about the link from the first signed heartbeat.
3. Keep **Forward a pool to another hub when no foreign server here can serve it** on (the default).

```bash
hashem cluster join-code            # on Tehran
hashem cluster add-hub hc1_...      # on Mashhad
```

The forwarded traffic leaves Tehran with Tehran's own address (MASQUERADE). Users notice nothing except a little extra latency.

### 4.12 A domain that always works (DNS failover)

Users connect to `vpn.example.com` instead of an IP. The domain always holds the public IPs of the Iran hubs that work.

1. Link the hubs (4.11).
2. On each hub, go to **Cluster → DNS Failover**:
   - **Cloudflare:** set the record name `vpn.example.com`, an API token (*Zone → DNS → Edit*) and TTL `60`. Press **Test**, tick **Keep the record pointed at the working hubs**, then **Save**. The record must be **DNS only** (grey cloud); a proxied record is refused because Cloudflare's proxy does not carry tunnels.
   - **Webhook:** use this for any other DNS provider (ArvanCloud, your own API…). See [9.2](#92-webhook).

### 4.13 Full mesh

Use everything together: every Iran hub has a pool over every foreign server, every foreign server joins every hub (`join-hub`), the hubs are linked, and DNS failover is on. Any one server can die, and the clients that use the domain keep working.

### 4.14 Mixed engines and UDP

- **Mixed engines:** FRP (tcp, kcp, quic, websocket, wss) and Backhaul tunnels can be members of the same pool. For KCP / QUIC / UDP transports, which hold no TCP session, the tunnel's own health from the dashboard is used.
- **UDP pools** (Hysteria, TUIC, WireGuard over the tunnel…): choose protocol UDP or TCP and UDP. Every member must forward UDP: FRP always does; a Backhaul or Bagher member needs **Also forward UDP** in its setup. Balance and sticky work per flow. When a member leaves, its UDP flows are flushed from conntrack so they move at once; this needs the `conntrack` tool. The service check and least connections need TCP.

---

## 5. Pool modes

| Mode | Where new connections go | Uses | Best for |
|---|---|---|---|
| **Failover** | All to the first healthy member by **priority** (lower first) | priority, failback | one main server, others as backup |
| **Balance** | Random member, in proportion to **weight** | weight | many short connections, equal servers |
| **Sticky per user** | Each source IP always to the same member (weighted rendezvous hash over 64 buckets) | weight | a stable exit IP per user |
| **Lowest latency** | All to the member with the lowest ping, with hysteresis | — | users far apart, uneven paths |
| **Least connections** | Members with the fewest open connections per unit of weight (re-weighted every 5 checks) | weight, live counts | long connections (VLESS, VMess, SSH) |

In every mode, **standby** members are used only when no normal member is healthy and below its connection limit, and **drained** members get nothing new. Open connections always stay where they are: a change applies to new connections only.

---

## 6. Health checks and timing

A member counts as **up** when all of these hold:

1. **Tunnel session:** the foreign client holds its control session to the relay (a TCP session on the control port, ±2 for the WSS front). For KCP/QUIC/UDP transports, the dashboard's health of the tunnel is used instead.
2. **Ping on the real path:** the hub pings the address the session comes from. Ping only counts for a link that has answered ping in the last 10 minutes, so a network that filters ICMP never takes a working link out.
3. **The relay listens** on the pool's port. If frpc's own health check (Performance tab) removed the proxy, the member is out too.
4. **Service check** (if on): see [4.6](#46-detecting-a-dead-service-behind-a-live-tunnel-service-check).

Timing, with the defaults (Cluster → **Health Check**):

| Event | Detected after | Default |
|---|---|---|
| Tunnel or foreign server down | **Fall** × interval | 3 × 1 s ≈ **3 s** |
| Back up | **Rise** × interval | 3 × 1 s ≈ 3 s |
| Service behind the tunnel down | Fall × service check interval | 3 × 3 s ≈ **9 s** |
| Relay stops listening (frpc gone, proxy removed) | next check | ≈ 1 s |
| Another Iran hub down | 3 missed heartbeats (every 3 s) | ≈ **9–12 s** |
| DNS moves to the working hubs | change detected + record TTL | ≈ 10 s + TTL (60 s) |

The interval can be 0.5–10 s, Fall 1–30 and Rise 1–60. Lower is faster, but too low can take a server out on a short hiccup.

**Fail-open:** if *no* member passes the checks but some relays still listen, the pool sends traffic to every listening member rather than refusing everyone, since health can be wrong. Then, if a linked hub has the pool working, the port is forwarded there instead.

**Pool states:**

| State | Meaning |
|---|---|
| Healthy | every member is up |
| Degraded | some members are out; traffic is on the rest |
| No Healthy Server | fail-open, as above |
| Forwarded to Another Hub | the port is sent to a linked hub |
| Down | nothing can serve it |
| Disabled | turned off by you |

---

## 7. Settings reference

### Pool

| Setting | Values | Notes |
|---|---|---|
| Public port | 1–65535 | When creating a pool, a list or range creates one pool each. It cannot be the panel's port or a tunnel's control port. |
| Protocol | TCP, UDP, TCP and UDP | |
| Name | text, up to 40 characters | shown in events and alerts |
| Mode | failover, balance, sticky, latency, least | [section 5](#5-pool-modes) |
| Service check | off, tcp | TCP pools |
| Check every | 1–60 s (default 3) | |
| Failback | automatic, manual | failover mode |
| Disabled | on, off | the port goes to one tunnel; nothing restarts |

### Member

| Setting | Values | Notes |
|---|---|---|
| Weight | 1–100 | balance, sticky, least connections |
| Priority | 0–1000 | failover; lower first |
| Port | 1–65535 | the member's own port, if not the pool port |
| Max connections | 0 (no limit) – 1,000,000 | no new connections at the limit; back below 90% |
| Standby | yes, no | used only when no other member can take it |
| Drain | on, off | no new connections; open ones finish |

A tunnel whose ports include a pool's port **joins the pool by itself**. A member you remove by hand stays out (it is listed in the pool's `excluded`) until you add it again.

### Hub

| Setting | Default |
|---|---|
| Health check: interval / Fall / Rise | 1000 ms / 3 / 3 |
| Forward a pool to another hub | on |
| Hub name, public IP | the hostname; detected automatically |

---

## 8. Linked Iran hubs

- **Join code** (`hc1_…`) carries the hub's id, name, address, panel port and the **cluster secret**. Share it only with your own servers. Pasting it on one hub is enough: the hub that made the code learns about the new one from its first signed hello, and a hub that joins a group of linked hubs is introduced to all of them.
- Hubs exchange a heartbeat every 3 seconds on the panel's port (`/_hc/beat`). Each heartbeat is signed with HMAC-SHA256 over timestamp, nonce and body. Clocks must agree within 90 seconds, and a replayed nonce is refused. A request that is not correctly signed gets a plain 404, so the routes do not show from outside.
- A hub is **healthy** when one of its pools is Healthy or Degraded, or, with no pools, when one of its tunnels is up.
- **Forwarding** picks a linked hub that is up and reports the same pool (same port and protocol) as Healthy or Degraded, the lowest latency first. A hub that is forwarding a pool itself is never a target, so traffic cannot loop.
- **Unlink:** **Cluster → Hubs → Remove**, or `hashem cluster remove-hub <id>`. The other hub is told.

---

## 9. DNS failover

Every hub with DNS failover on reports the record name in its heartbeat. Among the reachable hubs with the same name, **the one with the lowest id writes** the record, so two hubs never fight over it. Writes happen when the set of working hubs changes, and every 30 seconds.

### 9.1 Cloudflare

- The record is `A` records, one per working hub.
- Only records whose IP belongs to a hub of the cluster are added or removed. Other records under the same name are never touched.
- The last record is never removed: if every hub looks down, the record stays as it was.
- A proxied (orange cloud) record is refused.

### 9.2 Webhook

For any DNS provider. The leading hub POSTs JSON to your URL:

```json
{"name": "vpn.example.com", "ips": ["5.5.5.5", "6.6.6.6"], "ttl": 60, "hub": "hub-1a2b3c4d", "at": "2026-10-19T14:00:00Z"}
```

- Headers: `Content-Type: application/json` and, when you set a secret, `Authorization: Bearer <secret>`.
- Your endpoint sets the record to exactly `ips`. Any `2xx` answer counts as done; anything else is shown as an error and retried.
- **Test** sends the same body with `"test": true`.

A minimal receiver, to adapt to your provider's API:

```python
# dns_hook.py — run on any server you control: python3 dns_hook.py
import json, os
from http.server import BaseHTTPRequestHandler, HTTPServer

SECRET = os.environ.get("HOOK_SECRET", "")

class Hook(BaseHTTPRequestHandler):
    def do_POST(self):
        if SECRET and self.headers.get("Authorization") != "Bearer " + SECRET:
            self.send_response(403); self.end_headers(); return
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if not body.get("test"):
            # call your DNS provider here: make body["name"] resolve to body["ips"]
            print("set", body["name"], "->", body["ips"])
        self.send_response(204); self.end_headers()

HTTPServer(("0.0.0.0", 8787), Hook).serve_forever()
```

---

## 10. Monitoring and alerts

- **The Cluster tab** refreshes every 3 seconds and shows:
  - for each pool: its state, a bar of where new connections go, and per member the health with the reason, open connections against the limit, latency, share, and the Standby and Full badges;
  - the tunnels with their one-second health;
  - the linked hubs, DNS failover and the health settings;
  - the kernel rules (**Show Kernel Rules**) and an **event log** of the last 200 events.
- **Alerts:** pool state changes go to the alert channels in **Settings → Alerts** (webhook, Telegram), worded like link alerts.
- **Prometheus:** `GET /metrics` (enabled in Settings with a token) also reports:

| Metric | Labels | Meaning |
|---|---|---|
| `hashem_cluster_pool_state` | pool | 2 healthy, 1 degraded or forwarded, 0 down or fail-open |
| `hashem_cluster_member_up` | pool, link | 1 when the member passes every check |
| `hashem_cluster_member_connections` | pool, link | open TCP connections |
| `hashem_cluster_member_share` | pool, link | fraction of new connections it gets now |
| `hashem_cluster_hub_up` | hub | 1 when the linked hub answers |

---

## 11. Terminal commands

`hashem cluster …` and `gre-panel cluster …` are the same. Reading (`status`, `events`, `rules`) needs no license; changes need Hashem Pro. Changes made in the terminal are picked up by the running panel within a second.

```text
hashem cluster status
hashem cluster events
hashem cluster rules

hashem cluster pool add PORTS [--proto tcp|udp|both] [--mode failover|balance|sticky|latency|least]
                              [--links 0,2,3] [--name N] [--check tcp|off] [--check-every SEC] [--no-failback yes|no]
                              # PORTS: 443, or 443,8443, or 2000-2005 (one pool each)
hashem cluster pool set PORT [--mode M] [--name N] [--check tcp|off] [--check-every SEC] [--no-failback yes|no]
hashem cluster pool mode PORT MODE
hashem cluster pool rm|enable|disable|failback PORT [--proto P]

hashem cluster member add|rm|drain|resume|set PORT LINK [--weight N] [--priority N] [--port N]
                              [--backup yes|no] [--max-conn N] [--proto P]
                              # LINK: 0 = main tunnel, N = peer N

hashem cluster join-code
hashem cluster add-hub hc1_...
hashem cluster remove-hub ID
hashem cluster reset          # remove the rules and private addresses (the panel puts them back while pools exist)

# on a foreign server
hashem join-hub --bundle hsh1_...|bh1_...|gh1_... [--name LABEL] [--dial auto|gre|public] [--relay-ip IP]
hashem hubs
hashem leave-hub --id N
```

The terminal app (`hashem` → **Cluster**) has the same functions in menus. On a foreign server it shows the Iran hubs that server serves.

---

## 12. HTTP API

All routes are under the panel's secret path. Changes need a session and the CSRF header, like every panel API. The full list is in [API.md](API.md).

| Method | Route | Body / result |
|---|---|---|
| GET | `/api/cluster/status` | pools with live state, links, hubs, DNS, events |
| GET | `/api/cluster/rules` | the kernel rules (text) |
| POST | `/api/cluster/pool` | a pool: `{port, proto, name, mode, members:[{link, weight, priority, port, max_conn, backup, drain}], excluded, check, check_every, no_failback, disabled}`; `orig_port`/`orig_proto` to change an existing pool's port |
| POST | `/api/cluster/pool/delete` | `{port, proto}` |
| POST | `/api/cluster/pool/failback` | `{port, proto}` |
| POST | `/api/cluster/member` | `{port, proto, link, action: add|remove|drain|resume|set, weight, priority, link_port, backup, max_conn}` |
| POST | `/api/cluster/settings` | `{health:{interval_ms, fall, rise}, hub_forward, name, public_ip}` |
| POST | `/api/cluster/join-code` | `{code}` |
| POST | `/api/cluster/hubs/add` · `/hubs/delete` | `{code}` · `{id}` |
| POST | `/api/cluster/dns` | `{enabled, provider: cloudflare|webhook, token, url, name, ttl, test}` |
| POST | `/api/cluster/join-hub` · `/leave-hub` | foreign side: `{bundle, name}` · `{id}` |

---

## 13. How it works inside

```text
 user ──► hub public IP:443
            │  iptables nat PREROUTING ─► HASHEM-LB-ENTRY ─► HASHEM-LB ─► HLB-T443
            │                                  (DNAT by mode: statistic / u32 buckets / single target)
            ├──► 169.254.77.2:443  frps-1            ──tunnel──► foreign A ──► xray
            ├──► 169.254.77.3:443  frps-2            ──tunnel──► foreign B ──► xray
            └──► 169.254.77.4:443  backhaul-server-3 ──tunnel──► foreign C ──► xray
```

- **Private addresses.** Each pooled relay listens on its own private address instead of `0.0.0.0`:
  - the main tunnel (`frps` / `backhaul-server`) gets `169.254.77.1`;
  - peer N (`frps-N` / `backhaul-server-N`) gets `169.254.77.(N+1)`.

  The addresses live on the dummy interface `hashem-lb`, which `hashem-lb-net.service` recreates at boot. FRP gets `proxyBindAddr`; Backhaul port entries become `169.254.77.N:port`. The script and the panel agree on the same addresses (`lb-binds`, `lb-ports` in `/etc/gre-panel`), so rewriting a peer keeps the binding.
- **Rules.** The panel builds the rules and applies them atomically with `iptables-restore --noflush`, only in its own chains: `HASHEM-LB*` and `HLB-T<port>` / `HLB-U<port>` in nat, `HASHEM-LB-FILTER` / `HASHEM-LB-FWD` in filter. Direct connections to the private addresses from outside are dropped. The rules are rewritten only when something changes, and the hooks are re-checked every 30 seconds.
- **No user-space proxy.** The kernel does the work: DNAT keeps the client's real address, an existing connection stays on its member (conntrack), and the panel can restart without any connection dropping.
- **The check loop** runs every second without forking: it reads sockets from `/proc/net/{tcp,tcp6,udp,udp6}` and pings through one raw ICMP socket. With no pool it idles.
- **Files** in `/etc/gre-panel`:

| File | What it holds |
|---|---|
| `cluster.json` | pools, hubs, secret, DNS (mode 0600) |
| `cluster-events.json` | the event log |
| `cluster-rules.v4` | the last applied rules |
| `lb-binds` | relays bound to private addresses |
| `lb-ports` | pooled ports |

  On a foreign server, `hubs.json` lists the extra hubs.
- **Uninstall** removes the rules, the `hashem-lb` interface and units, and the extra-hub units (`frpc-hN`, `backhaul-client-hN`, `gre-hN`).

---

## 14. Troubleshooting

| You see | Cause and fix |
|---|---|
| Member **Not serving this port** | The tunnel does not carry the pool port. Add the port to the peer (Setup), or set the member's **Port**. If the relay was just bound, wait a few seconds for its restart. |
| Member **Down: no control session** | The foreign client is not connected. On the foreign server: `systemctl status frpc` (or `frpc-hN`, `backhaul-client`), and check the control port in the firewall. |
| Member **Down: stopped answering ping** | The path is broken although the session has not timed out yet. It comes back by itself after Rise good checks. |
| Member **Service down** | The tunnel works but the service behind it refuses the connection. Restart xray / the service on that foreign server. Check `ss -ltnp` there for the local port. |
| Pool **No Healthy Server** (fail-open) | Every member fails its checks while relays still listen. Look at the reasons per member, and at the Events. |
| **The kernel rules could not be applied** | Usually iptables is missing or conflicts with a firewall manager. Run `hashem cluster rules` and `iptables -t nat -S | grep HASHEM`. If you use `nftables` only, install `iptables-nft`. |
| Linked hub **unreachable** | The panel port is closed between the hubs, the clocks differ by more than 90 s, or the hubs have different secrets (re-link with a fresh join code). Run `timedatectl`. |
| Hub forwarding does nothing | The other hub has no pool on the same port and protocol, or its pool is not Healthy/Degraded. |
| DNS: *record is proxied* | Turn the record grey (DNS only) in Cloudflare. |
| DNS: *Another hub writes the record* | Normal: only the lowest id writes. |
| A pooled port answers from the wrong server after removing a pool | Removing a pool unbinds the relays (each restarts once). Wait 5–10 s. |

Useful commands on the hub:

```bash
hashem cluster status
hashem cluster events
iptables -t nat -S | grep -E 'HASHEM|HLB'
ip -4 addr show dev hashem-lb
ss -ltn | grep 169.254.77
conntrack -L -d 169.254.77.0/24 | head
```

---

## 15. Limits

- IPv4 only, for pools, hub links and DNS records.
- Up to 250 pooled tunnels per hub, and up to 9 Iran hubs per foreign server.
- Sticky mode spreads users by the low 6 bits of their IPv4 address (64 buckets): many users behind one NAT address count as one user.
- Least connections and the service check need TCP. UDP members are balanced by weight.
- A pool changes where **new** connections go; open connections stay on their member until they close, except UDP flows of a member that left, which are flushed.
