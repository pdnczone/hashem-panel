<div align="center">

# Hashem Panel 🇮🇷 ↔ 🌍

**A hub-and-spoke tunnel manager: GRE Layer-3 + FRP / Backhaul reverse relay, with a web dashboard, health model, watchdog and safe updates.**

*Keep the real servers hidden — expose foreign-server ports through the public IP of your Iran server.*

🇬🇧 English | [🇮🇷 فارسی](README.fa.md)

[![Latest Release](https://img.shields.io/github/release/pdnczone/hashem-panel?display_name=tag)](https://github.com/pdnczone/hashem-panel/releases/latest)
[![CI](https://github.com/pdnczone/hashem-panel/actions/workflows/ci.yml/badge.svg)](https://github.com/pdnczone/hashem-panel/actions/workflows/ci.yml)
[![Build Panel](https://github.com/pdnczone/hashem-panel/actions/workflows/build-panel.yml/badge.svg)](https://github.com/pdnczone/hashem-panel/actions/workflows/build-panel.yml)
[![Security CI](https://github.com/pdnczone/hashem-panel/actions/workflows/security.yml/badge.svg)](https://github.com/pdnczone/hashem-panel/actions/workflows/security.yml)
[![Go version](https://img.shields.io/github/go-mod/go-version/pdnczone/hashem-panel?filename=panel%2Fgo.mod)](panel/go.mod)
[![Downloads](https://img.shields.io/github/downloads/pdnczone/hashem-panel/total)](https://github.com/pdnczone/hashem-panel/releases)
[![Last commit](https://img.shields.io/github/last-commit/pdnczone/hashem-panel)](https://github.com/pdnczone/hashem-panel/commits/main)
[![Platform](https://img.shields.io/badge/platform-linux%20amd64%20%7C%20arm64-blue)](#requirements)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

[🌐 Website](https://pdnczone.ir) · [✈️ Telegram](https://t.me/pdnczone) · [▶️ YouTube](https://youtube.com/@pdnczone) · *DNC MADE THIS*

</div>

---

## Table of contents

- [What's new in v2.7.0](#whats-new-in-v270)
- [What's new in v2.6.0](#whats-new-in-v260)
- [What's new in v2.5.0](#whats-new-in-v250)
- [What is Hashem?](#what-is-hashem)
- [Why Hashem?](#why-hashem)
- [Features](#features)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Quick install](#quick-install)
- [Choosing an engine](#choosing-an-engine)
- [Panel tour](#panel-tour)
- [Tunnel types](#tunnel-types)
- [Cluster](#cluster)
- [Health model](#health-model)
- [Automation](#automation)
- [Updates, downgrade and channels](#updates-downgrade-and-channels)
- [`hashem` CLI](#hashem-cli)
- [Troubleshooting](#troubleshooting)
- [Uninstall and your data](#uninstall-and-your-data)
- [Known limitations](#known-limitations)
- [Documentation map](#documentation-map)
- [Security notes](#security-notes)
- [Contributing](#contributing)
- [License](#license)

---

## What's new in v2.7.0

- 🌐 **IPv6 in every tunnel.** Users reach the Iran ports over IPv6 and IPv4 at once (Backhaul, FRP, Bagher, Xray), and Backhaul without GRE, Bagher, Xray and WSS can connect the two servers over IPv6. Limits, traffic counters, rescue, the path test and cluster DNS (AAAA) cover IPv6 too. [Guide](docs/IPV6.md).
- 🧅 **Two new GRE wraps: 6to4 and 4in6.** 6to4 runs GRE on a private IPv6 between the IPv4 addresses (protocol 41), for networks that drop 47 but pass 41; 4in6 runs GRE over the servers' real IPv6. FRP and Backhaul over GRE keep working unchanged, both servers switch together, and a wrap that stays silent for 45 s is undone on both.
- 🛰️ **Xray tunnel [PRO].** Reality, XHTTP, gRPC or mKCP, direct or reverse, through Cloudflare if you like, with a three-step wizard, a live picture of the link and an SNI tester. Its own Xray-core: it never touches 3x-ui, Marzban or Hiddify. [Guide](docs/XRAY_TUNNEL.md).
- 🚦 **Speed and volume limits per foreign server [PRO]**, with a monthly reset, a cut when the volume is used up and alerts at 90%.
- ⚡ **Bagher: lower ping and several foreign servers** on one Iran server, each with its own SSH carrier, ports and bundle.
- 📊 **Traffic you can trust:** no more jumps in the total, live speeds that were up to 5× too high, and Bagher and Backhaul without GRE counted per link.
- 🔀 **Change the carrier from the foreign server too:** the Iran server runs the change on both servers.

Full list: [CHANGELOG](CHANGELOG.md).

## What's new in v2.6.0

- 🎭 **Spoof Tunnel (new) [PRO].** For whitelist-based Layer-3 firewalls (the kind seen during Iran's blackouts): both servers forge their source IP and know the other's real one, from [ParsaKSH/spoof-tunnel](https://github.com/ParsaKSH/spoof-tunnel). The panel wraps the raw pipe with WireGuard for a real encrypted link, generates the keys for both sides, and hands the foreign server one bundle. Its own **Spoof** tab, with a built-in **spoof-IP tester** that finds which source IPs get through.
- 🔀 **Swap the carrier of any tunnel.** Move the main tunnel or any foreign server between GRE + FRP, Backhaul over GRE and Backhaul without GRE from its card. Both servers switch, and a carrier that does not connect within 45 s is undone on both.
- 📡 **UDP in every tunnel.** One tick (Also forward UDP) and Backhaul forwards UDP on any transport, tcpmux and wss included (a UDP companion on the next free port, managed with the tunnel), and Bagher forwards it through the SSH tunnel. FRP always did. For Hysteria, TUIC, WireGuard, QUIC and games.
- 🗺️ **A map of every tunnel** on the dashboard and a link diagram on every tunnel card, with live speeds both ways; the traffic chart now counts Backhaul and Bagher too.

Full list: [CHANGELOG](CHANGELOG.md).

## What's new in v2.5.0

- 🕸️ **Cluster: no single point of failure.** One Iran port served by several foreign servers (failover, balance, sticky per user, lowest latency, least connections), a one-second health check plus a **service check through the tunnel** (catches a dead xray behind a live tunnel), standby servers and connection limits, drain for maintenance, manual failback. Several Iran servers can share the same foreign servers, Iran hubs back each other up, and DNS failover (Cloudflare or any provider by webhook) keeps a domain on the working hubs. Everything runs in the kernel: no speed loss, the real client IP is kept, and a panel restart drops nothing.
- 🗺️ **Cluster map.** A live picture of the whole cluster. Line thickness is each server's share of traffic and color is its health. Click any server, pool, line, hub or DNS to change it in place.
- 🧪 **Path test before any tunnel.** Benchmark tab: every transport between your two servers (TCP/UDP, GRE, SSH, FRP x 5, Backhaul x 7) with latency and speed, so you know what gets through before you build anything.
- 🧩 **Every tunnel in Setup.** GRE + FRP, Backhaul (with or without GRE, now one engine) and Bagher, all from the same Setup and Tunnel tabs. Old "Modified Backhaul" tunnels move in by themselves.
- 🔁 **Back to GRE by itself.** A foreign server that fell back to the hub's public IP returns to GRE once GRE carries the tunnel again.
- 💻 **`hashem` is a terminal app** with arrow-key menus that follow the panel tabs; everything the panel does works from SSH too (TLS, settings, cluster, performance).
- ⚙️ **FRP options where they apply:** PROXY protocol (v1/v2), bandwidth limit per port, health check, TCP multiplexing; Backhaul connection pool. Let's Encrypt in Settings fixed.
- 🔐 **Hashem Pro** now covers Cluster, Path Test, Backhaul setup, Diagnostics, Performance, Watchdog and Benchmark. Every existing Pro key opens all of them, and running tunnels are never taken away.

Full list: [CHANGELOG](CHANGELOG.md). Cluster: [guide](docs/CLUSTER.md) · [how it works and tutorial](docs/CLUSTER_TUTORIAL.md).

---

## What is Hashem?

Hashem is a tunnel manager made of two parts:

- **The installer / CLI** — `hashem.sh` (installed as `hashem`). It sets up GRE, FRP and Backhaul services with systemd.
- **The panel** — a Go backend with a single-page web UI (`gre-panel`). It runs on every server and shows the tunnel, peers, health, latency, logs, diagnostics and updates.

The model is a **hub and spokes**:

- The **Iran hub** is the server in Iran. It runs `frps` / the Backhaul server and the panel, and it owns the public ports that users connect to.
- Each **foreign server** is a spoke. It runs `frpc` / the Backhaul client and dials the hub. Traffic that arrives on the hub is relayed to the foreign server.
- Several foreign servers can be attached to one hub. The peer limit defaults to 10 and is read from the `GRE_MAX_PEERS` environment variable.

---

## Why Hashem?

Plain `frp` or Backhaul give you a relay and a config file. Hashem wraps them with the parts you would otherwise build by hand:

- **A Layer-3 link under the relay** (GRE, direct or over WSS), so the relay runs over a private inner address and can fall back to the public IP when GRE is blocked.
- **Setup bundles** — one pasted string configures the foreign side. No hand-copied tokens, ports or IPs.
- **One health model** — the same rule drives the dashboard banner, fleet cards and topology graph, and shows which leg is down.
- **Operations built in** — watchdog, webhook/Telegram alerts only on state change, 24 h history, encrypted backups, `hashem doctor`.
- **Updates you can undo** — stable/dev channels, SHA-256 verified downloads, config backup before every swap, automatic rollback after repeated crashes.
- **A hardened panel** — argon2id passwords, CSRF, optional TOTP 2FA, audit log, terminal off by default.

If you need one relay on one server pair and are happy editing TOML, plain frp or Backhaul is simpler. Hashem is for several links you want to watch and keep alive.

---

## Features

- 🚀 **One-line install** — prebuilt standalone Go binary from official GitHub releases.
- 🧩 **Three tunnel engines** — `GRE + FRP`, `Backhaul` (with or without GRE, TCP and UDP) and `Bagher` (SSH pool + FRP), all from the Setup tab. See [Choosing an engine](#choosing-an-engine).
- 🕸️ **Cluster** [PRO] — pools of foreign servers behind one Iran port (failover, balance, sticky, latency, least connections), service check through the tunnel, standby servers, connection limits, several Iran hubs, hub-to-hub forwarding and DNS failover, on an interactive map. See [Cluster](#cluster).
- 🧪 **Path test** [PRO] — which transports get through between two servers, before any tunnel exists.
- 🛰️ **Four GRE carriers** — Direct GRE (IP protocol 47), WSS (TLS WebSocket, port `8443` by default), 6to4 (GRE on a private IPv6 inside IP protocol 41) and 4in6 (GRE over the servers' IPv6). A switch changes both servers and is undone if the tunnel does not answer within 45 s.
- 🌐 **IPv6** — users reach the ports over IPv6; Backhaul without GRE, Bagher, Xray and WSS connect the two servers over IPv6; the path test checks 6to4, TCP over IPv6 and 4in6; cluster DNS failover writes AAAA records. See [docs/IPV6.md](docs/IPV6.md).
- 🔌 **FRP transports** — `tcp`, `kcp`, `quic`, `websocket`, `wss`, with payload encryption, compression and PROXY Protocol v2. See the [FRP Transports Guide](docs/FRP_TUNNELS_GUIDE.md).
- 📦 **Setup bundles** — one string carries keys, IPs, transport and ports: `hsh1_…` (FRP), `bh1_…` (Backhaul), `gh1_…` (GRE+Backhaul). Paste it on the foreign server and the form fills itself.
- 🔀 **Port management** — single ports (`443`), lists (`80,443`), ranges (`1000-1010`) and mappings (`8080=80`).
- 🩺 **One health model everywhere** — the Dashboard banner, fleet cards and topology graph use the same rules.
- ⏱️ **Latency per link and hub average** — ICMP first, kernel TCP RTT as fallback.
- 🔁 **Dial route** — foreign servers can dial the hub over the GRE inner IP or its public IP, with automatic fallback.
- 🐕 **Watchdog** — runs every minute from a systemd timer; optional Telegram alerts.
- 🔄 **Safe updates** — stable / dev channels, install any of the last 20 releases (upgrade or downgrade), SHA-256 verification, config backup, automatic rollback.
- 🎯 **Carrier benchmark** and **diagnostics** (`hashem doctor`).
- 🖥️ **Terminal app** — `hashem` opens arrow-key menus that mirror the panel tabs.
- 💻 **In-browser terminal** — disabled by default, audited.
- ⚙️ **Auto Pool** — frpc `poolCount` / frps `maxPoolCount` sized automatically from pool-full errors, load and RAM (on by default).
- 🔔 **External alerts** — webhook and/or Telegram message only when a tunnel changes state (with a per-link minimum gap), plus host alerts for disk, RAM and panel TLS-certificate expiry. Set up in Settings.
- 📈 **History and metrics** — 24 h per-link latency/state/throughput graph, and an optional Prometheus `/metrics` endpoint behind a bearer token (off by default).
- 🧭 **Carrier advisor** — tells you when the active carrier keeps failing and which one to try; advice only, it never switches by itself. Also suggests free ports and SNI names.
- 🔒 **Hardened panel** — argon2id password hashes, NIST 800-63B password policy, CSRF tokens, trusted-proxy handling, audit log. See [Security notes](#security-notes).
- 📚 **Documented API** — every route and every error code is listed in [docs/API.md](docs/API.md) and [docs/ERROR_CODES.md](docs/ERROR_CODES.md), generated from the source.

---

## Architecture

```mermaid
flowchart LR
    U["Users"] --> HUB

    subgraph IR["Iran"]
        HUB["Iran hub<br/>frps / backhaul-server<br/>public ports"]
        PANEL["Hashem panel<br/>:7777"]
        HUB --- PANEL
    end

    subgraph F1["Foreign server A"]
        C1["frpc<br/>GRE + FRP"]
    end
    subgraph F2["Foreign server B"]
        C2["backhaul-client<br/>GRE + Backhaul"]
    end
    subgraph F3["Foreign server C"]
        C3["backhaul-client<br/>Backhaul standalone"]
    end

    HUB <== "GRE direct (proto 47)" ==> C1
    HUB <== "GRE over WSS (:8443)" ==> C2
    HUB <-- "Backhaul, no GRE" --> C3
```

Inside a GRE link, the relay (FRP or Backhaul) normally runs over the GRE inner addresses. If the GRE path is dead, the foreign side can dial the hub's public IP instead (see [Health model](#health-model) and [Automation](#automation)).

How one public connection travels:

```mermaid
sequenceDiagram
    participant User
    participant Hub as Iran hub
    participant Link as GRE / WSS / Backhaul link
    participant Srv as Foreign server
    Srv->>Hub: relay client dials the control port
    User->>Hub: connects to a public port
    Hub->>Link: forwards through the relay
    Link->>Srv: delivers to the local service
    Srv-->>User: reply travels back the same way
```

An interactive version with the layers, data path, join flow, automation and defaults is in [`docs/hashem-architecture.html`](docs/hashem-architecture.html). GitHub shows HTML as source, so [open it rendered](https://htmlpreview.github.io/?https://github.com/pdnczone/hashem-panel/blob/main/docs/hashem-architecture.html) or download the file.

---

## Requirements

- **OS:** Linux with **systemd**, `amd64` or `arm64`. Developed and tested on Ubuntu. The installer adds missing packages with `apt-get` (Debian/Ubuntu), with a `yum` fallback.
- **Access:** root (`sudo`) on both servers.
- **Tools:** `curl`, `tar`, `python3`, `iproute2` (`ip`, `ss`), `iptables`, `ping`. The installer adds any that are missing.
- **Kernel:** the `ip_gre` module for the GRE engines (`modprobe ip_gre`). Backhaul standalone needs no GRE.
- **Network** — open these between the two servers (and to users on the hub):

  | Purpose | Port / protocol |
  | --- | --- |
  | Direct GRE carrier | IP protocol **47** (not TCP/UDP) |
  | WSS carrier | TCP `8443` (default) |
  | 6to4 carrier | IP protocol **41** (not TCP/UDP) |
  | 4in6 carrier | IP protocol **47** over IPv6 |
  | FRP / Backhaul control | the control port you choose; the `wss` front uses `control_port+2` |
  | KCP / QUIC transports | UDP, on the ports shown in the panel |
  | Panel | TCP `7777` (moves to the next free port if busy); HTTPS `7443` once a certificate is issued |
  | Your services | the public ports you forward on the hub |

- **GitHub reachability** from the servers (releases and `raw.githubusercontent.com`) for install and updates. From inside Iran this may need a working route; the installer tries mirrors for the script itself.

---

## Quick install

Run the same one-liner on **both** servers. It is `install.sh` from this repository: it downloads `hashem.sh`, installs it as `/usr/local/bin/hashem`, and starts it.

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/pdnczone/hashem-panel/main/install.sh)
```

1. **On the Iran server** — run the command and choose option `1`. Choose the engine, carrier and ports. The installer prints a **setup bundle** (for example `hsh1_…`). Copy it.
2. **On the foreign server** — run the command and choose option `2`. Paste the bundle; the tunnel and services are configured automatically.
3. **Open the panel** — the end of the install prints the secure panel URL (`http://<server-ip>:7777/<secret>`) and the first admin credentials. The password is not stored in plaintext; save it. Reset it any time with `hashem reset-password`, or CLI menu option `3 -> 2`. Print the URL again with `hashem show-panel-url`.

Adding more foreign servers: use the **Setup** tab in the panel or `hashem add-peer` / `hashem add-backhaul-peer` on the hub, then paste the new bundle on the new foreign server.

**Read it first, or pin it.** To inspect the installer before running it:

```bash
curl -fsSL https://raw.githubusercontent.com/pdnczone/hashem-panel/main/install.sh -o install.sh
less install.sh && bash install.sh
```

`install.sh` accepts `hashem.sh` only from GitHub itself, from two agreeing mirrors, or when it matches a hash you pin. Every release publishes a `checksums.txt`; pin the script like this:

```bash
HASHEM_SHA256=<sha256 of hashem.sh from the release checksums.txt> \
  bash <(curl -fsSL https://raw.githubusercontent.com/pdnczone/hashem-panel/main/install.sh)
```

The panel binary comes from the active [update channel](#updates-downgrade-and-channels). To run an exact panel version, install first, then pick the tag in the **Update** tab (or `POST /api/update {"tag":"v1.1.0"}`).

> ⚠️ **The panel speaks plain HTTP by default**, on a long random path. Before you expose it to the internet, put it behind TLS: `hashem panel-tls <domain> <email>` (needs port 80 reachable and the domain pointing at the server), or a reverse proxy — see [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

---

## Choosing an engine

| | GRE + FRP | Backhaul with GRE | Backhaul without GRE |
| --- | --- | --- | --- |
| Setup bundle | `hsh1_` | `gh1_` | `bh1_` |
| GRE interface | yes | yes | **no** |
| Relay | frp | Backhaul | Backhaul |
| Transports | tcp, kcp, quic, websocket, wss | Backhaul transports | Backhaul transports |
| Dials the hub's public IP while GRE is dead, back to GRE when it returns | yes | yes | n/a |
| Pick it when | you want the most features and tuning (Auto Pool, encryption, compression, PROXY v2) | you want Backhaul and GRE when the path allows it | GRE (protocol 47) is blocked for good between your servers |

Backhaul is one engine in Setup and in `hashem backhaul`; "with GRE" or "without GRE" is a question inside it. **Bagher** [PRO] (an SSH connection pool carrying FRP) is set up from the same Setup tab and runs from the Tunnel tab like the other tunnels.

Start with **GRE + FRP** and the **Direct GRE** carrier. If IP protocol 47 is dropped between your servers, try the **WSS** carrier, then Backhaul without GRE. Not sure what gets through? The Benchmark tab's **Path Test** checks every transport between your two servers before any tunnel exists. More detail: [docs/ENGINES.md](docs/ENGINES.md) and the [FRP transports guide](docs/FRP_TUNNELS_GUIDE.md).

---

## Panel tour

The panel is one page with these tabs:

- **Dashboard** — a banner with one big word (Healthy / Degraded / Down) and one line per tunnel; KPIs; the Fleet Health card with hub latency, the topology graph and per-server cards.
- **Tunnel** — every tunnel on this server: the main tunnel, the foreign-server peer cards and the Bagher card (start, stop, copy bundle, quick edit, remove); per-tunnel PASS/FAIL checks, the dial-route card, and the GRE carrier (Direct GRE or WSS, its port and SNI).
- **Performance** [PRO] — the settings of the engine this server runs: for FRP, Auto Pool, encryption, compression, TCP multiplexing, PROXY protocol (real client IP for Xray), a bandwidth limit per port and a health check; for Backhaul, the connection pool. Plus the kernel network stack (Optimize Network / Restore).
- **Diagnostics** [PRO] — latency, jitter, MTU and speed tests; the same engine as `hashem doctor`.
- **Setup** — create any tunnel: GRE + FRP, Backhaul (with or without GRE) or Bagher; bundles and peers.
- **Watchdog** [PRO] — monitoring, backups and alerts.
- **Cluster** [PRO] — opens on a live map of the cluster; click anything to change it. Pools (one Iran port served by several foreign servers: failover, balance, sticky per user, lowest latency or least connections; one-second health check, service check, standby servers, connection limits, drain, manual failback), linked Iran hubs that take over each other's ports, DNS failover (Cloudflare or webhook), and on a foreign server, serving several Iran hubs. See [Cluster](#cluster).
- **Benchmark** [PRO] — the Path Test (which transports get through between the two servers, before any tunnel: plain TCP/UDP, GRE, SSH, FRP x 5, Backhaul x 7, with latency and speed), carrier probing and the optional auto-pilot.
- **Update** — channels, install any tag, rollback state.
- **Logs, Settings, Terminal** — redacted logs with error codes; password, 2FA, idle timeout, alerts, TLS, metrics token; the audited shell (off by default).

**FRP TCP Multiplexing (`transport.tcpMux`) is OFF by default** (speed-first: tcpMux roughly halves throughput over GRE). New `frps`/`frpc` configs are written with `transport.tcpMux = false`. Turn it on only deliberately with `hashem perf tcpmux on` (or the Performance tab). The setting **must be identical on the Iran hub and every foreign spoke**; a mismatch makes `frpc` fail to log in with `connect to server error: EOF`, and `hashem status` / `hashem doctor` print a hint when they see it. Backhaul is unaffected.

---

## Tunnel types

- **GRE+FRP** (`frp`) — a GRE Layer-3 link between the two servers with FRP running over it. FRP transports: `tcp`, `kcp`, `quic`, `websocket`, `wss`. `wss` needs a TLS front: a `frps-wss*.service` unit running `gre-panel tls-proxy` on `control_port+2`. Guide: [FRP transports guide](docs/FRP_TUNNELS_GUIDE.md).
- **Backhaul with GRE** (`gre-backhaul`) [PRO] — the same GRE link, with Backhaul as the relay. Bundle prefix `gh1_`.
- **Backhaul without GRE** (`backhaul`) [PRO] — Backhaul only, no GRE interface at all. Bundle prefix `bh1_`.
- **Bagher** [PRO] — an SSH connection pool from Iran to the foreign server carrying FRP. Bundle prefix `BAGHER:`.
- **Spoof** [PRO] — an IP-spoofing UDP pipe ([ParsaKSH/spoof-tunnel](https://github.com/ParsaKSH/spoof-tunnel)) with WireGuard on top (`wg-spoof`, 10.20.0.1 ↔ 10.20.0.2), for whitelist firewalls. Set up in its own Spoof tab; bundle prefix `spf1_`. Core: `hashem spoof install` (sha256-pinned).
- **Xray** [PRO] — a port forward over Xray-core (VLESS): **direct** (Iran dials) or **reverse** (the foreign server dials Iran), with Reality, XHTTP, gRPC, mKCP or a CDN (Cloudflare). Its own Xray-core (`/usr/local/lib/hashem/xray`) and units (`hashem-xray-N`), so it runs next to 3x-ui or Marzban without touching them. Set up in the Xray tab; bundle prefix `xr1_`. Guide: [Xray tunnel](docs/XRAY_TUNNEL.md).

**Speed and volume limits** [PRO] — in the Tunnel tab, each foreign server (by its IPv4, so every tunnel to it) gets one speed for both directions and/or a volume, or stays unlimited. The speed is a tc policer on the default-route interface (the root qdisc and BBR are not touched); the volume is counted by the `HASHEM_LIMIT` iptables chain and kept in `limits.json`. When a server's volume is used up its links are cut (DROP) until the reset, monthly on a chosen day or by hand; the other servers keep working, and an alert goes out when alerts are on. Limits keep working without a license and can always be removed. IPv4 only; links through a CDN cannot be limited by address.

**Hashem Pro** features: Bagher, the Spoof tunnel, the Xray tunnel, the speed and volume limits, setting up Backhaul (with or without GRE), the Path Test, Diagnostics, Performance, Watchdog, Benchmark and Cluster. A lock next to a tab in the sidebar marks the ones that need a license (Sentinel is a separate add-on). Every Pro license unlocks all of them, including features that became Pro after the key was issued, so an update never asks for a new key. Pro is checked on both servers. A Backhaul tunnel that already runs keeps running, restarting and being repaired without a license; only setting up a new one needs it. GRE + FRP stays free.
- **Carriers for the GRE layer** — **Direct GRE** (IP protocol 47), **WSS** (TLS WebSocket, default `:8443`), **6to4** (protocol 41) and **4in6** (over IPv6). The FOU carrier was removed.

---

## Cluster

Three ways to keep users up when a server dies; they combine.

- **One Iran server, several foreign servers (pool).** Add the first foreign server in Setup, make a pool on its port, then add the other foreign servers in Setup with the same port: they join the pool by themselves. Each new connection goes to a foreign server that works, chosen by the pool's mode. A failed server is out within about three seconds.
- **Several Iran servers, one foreign server.** On the second Iran server add the foreign server as a peer; on the foreign server run `hashem join-hub --bundle <its bundle>` (or Cluster in its panel). The foreign server then serves both, so either Iran server works on its own.
- **Iran servers backing each other up.** Link the hubs with a join code. A pool with no working foreign server is forwarded to a hub where it works; with DNS failover, a domain points only at hubs that work.

The relays of pool members listen on `169.254.77.N` (interface `hashem-lb`); kernel DNAT in the `HASHEM-LB` chains picks the member, so the real client IP is kept and nothing stops when the panel restarts. `hashem cluster rules` prints the rules.

Pool modes: failover, balance, sticky per user, lowest latency and least connections, with standby members, connection limits, a service check through the tunnel, drain and manual failback. The Cluster tab shows it all on a live map where every part can be clicked and changed.

![Cluster map](docs/img/cluster-map.png)

- **[How it works, and a hands-on tutorial](docs/CLUSTER_TUTORIAL.md)** ([فارسی](docs/CLUSTER_TUTORIAL.fa.md)): build a cluster lesson by lesson, break it on purpose and watch it recover.
- **[Cluster guide](docs/CLUSTER.md)** ([فارسی](docs/CLUSTER.fa.md)): every scenario, setting, command, the API and troubleshooting.

---

## Health model

The same rule is used by the Dashboard banner, the fleet cards and the topology graph (`fleetHealth` in `panel/fleet.go`). Per tunnel:

- **Healthy** — (GRE up **and** FRP up **and** ICMP ping ok) **or** (FRP service up **and** the foreign client holds an ESTABLISHED TCP session on the control port — called *linked*).
- **Degraded** — exactly one leg up (GRE or FRP) and no linked session; or both up but no ping and not linked.
- **Down** — nothing up.
- **"FRP only" badge** — linked, but the GRE inner address does not answer ICMP: traffic still flows over FRP while the GRE path is blocked.

*Linked* is detected with `ss -Htn state established` on the control port (also `port+2` for the wss front and `port-2`).

The dashboard's overall status uses the same function. The main tunnel counts as one more spoke of the hub (synthetic id `0`, named `Tunnel · <ip>`).

**Latency** per link is taken in this order: (1) ICMP ping of the GRE inner address → kind `icmp`; (2) if ICMP fails, the kernel TCP RTT of the live session on the control port (from `ss -tin`) → kind `tcp`; (3) otherwise `—`. The hub summary (`/api/fleet` → `latency`) gives avg, min, max over links that have a value, the count, and how many are `icmp` vs `tcp`. History, sparkline, average, loss and uptime use the same value.

---

## Automation

- **Watchdog** — a systemd timer (`hashem-watchdog.timer`) runs `hashem watchdog tick` every minute. Control it with `hashem watchdog on|off|status|test|tick`. Telegram alerts are configured in the watchdog settings; `hashem tgsend "msg"` sends a manual message. `auto_restart` defaults to **off** (alert only).
- **Dial route** — on foreign servers, `hashem dial [status|auto|gre|public]` chooses whether `frpc` / `backhaul-client` dials the hub over the GRE inner IP or the hub public IP. `auto` uses GRE if it answers (ping or TCP to the control port), otherwise public. The watchdog switches to public automatically when GRE is dead and the client is not connected, and back to GRE once GRE has carried the control port for 5 checks in a row (5 minutes). If the client cannot connect over GRE after that move, it goes back to the public IP and waits 30 minutes before trying again. The foreign side of Setup asks for the route when the bundle uses GRE. Foreign servers show a "Route to the Iran hub" card.
- **Carrier failover** — `hashem carrier` manages and cycles carriers. Switching is manual; the advisor only suggests.
- **Backups** — `hashem backup now|restore|schedule|status` (encrypted archives in `/var/backups/hashem`).
- **Adaptive capacity** — multiplexing capacity adjusts to load and available RAM.

---

## Updates, downgrade and channels

The **Update** tab (and `hashem update` for the script + panel) uses two channels:

- **`stable`** — GitHub releases that are *not* prerelease (tags `panel-rN` and `vX.Y.Z`).
- **`dev`** — prereleases tagged `dev-rN`, built from the `dev` branch.

The channel is stored in `<configDir>/update.json` (`GET/POST /api/update/channel`). `GET /api/releases?channel=stable|dev` lists the last 20 releases of a channel. You can install **any listed tag**, newer or older — that is how you downgrade (`POST /api/update {"tag":"panel-r140"}`; without a tag, the newest of the selected channel).

Install steps: validate tag → download the panel binary and `hashem.sh` of that tag → verify SHA-256 from that tag's `checksums.txt` (fail-closed) → verify ELF / `bash -n` → back up the config dir to `<configDir>/backups/pre-<from>-<timestamp>.tar.gz` (last 5 kept; `exe.bak` and `hashem.sh.bak` kept) → swap → write `<configDir>/pending_update.json` → restart.

**Auto-rollback:** the new process counts its starts in `pending_update.json`. If it crashes 3 times before it is confirmed healthy (self health check 45 s after start), the old binary and `hashem.sh` are restored and the panel restarts.

**Branches:** `main` is stable (a push that changes `panel/**` or `hashem*.sh` builds release `panel-r<run>`); `dev` is for testing (each push builds prerelease `dev-r<run>`, never offered on stable). Promote by a manual Pull Request `dev → main`. Hotfix: branch from `main`, PR to `main`, then merge `main` back into `dev`. Release history: [CHANGELOG.md](CHANGELOG.md).

---

## `hashem` CLI

Everything works from SSH too (commands as in `hashem help`):

```bash
hashem                # first run: auto-install; afterwards the terminal app (arrows, Enter, Esc)
hashem menu           # the terminal app
hashem status         # tunnel health, peers, service status
hashem show-panel-url # print the panel URL again
hashem reset-password # reset / auto-generate the admin password
hashem password <p>   # set the panel password non-interactively
hashem tls issue <domain> [email]   # HTTPS for the panel (Let's Encrypt; also: status, renew, remove, ip, custom)
hashem settings show  # panel settings; also: 2fa off, terminal on|off, idle N
hashem license activate <key>
hashem cluster status | events | rules              # the cluster (Pro to change it)
hashem cluster pool add 443,8443 --mode least --check tcp
hashem cluster pool set 443 --no-failback yes | pool failback 443
hashem cluster member set 443 2 --weight 2 --max-conn 500 --backup no | member drain 443 2
hashem cluster join-code | add-hub <code>          # link two Iran hubs
hashem join-hub --bundle <bundle>   # foreign side: also serve another Iran hub (hubs, leave-hub --id N)
hashem logs           # relay logs
hashem optimize       # BBR / MTU / sysctl tuning
hashem doctor         # latency, jitter, MTU and speed diagnostics
hashem doctor fix     # Quick Repair (same as the Diagnostics tab), then diagnose again
hashem spoof install  # Spoof tunnel core + WireGuard tools (also: status, up, down)
hashem xray install   # Xray tunnel core (also: status, start, stop, restart, logs, uninstall)
hashem carrier        # carrier management / failover
hashem dial status    # foreign side: route to the Iran hub
hashem watchdog status
hashem backup now     # encrypted backup (/var/backups/hashem)
hashem perf autopool status  # Auto Pool: on|off|status|tick
hashem perf tcpmux on|off    # must match on hub and spokes
hashem perf proxy-protocol off|v1|v2 | bandwidth MB | health-check on|off | backhaul-pool N
hashem free-ram       # free RAM
hashem update         # update script and panel to the latest release
hashem update-channel [stable|dev]
hashem uninstall      # full wipe (see "Uninstall and your data")
```

`hashem help` prints the full list, including the non-interactive `setup-*` and `*-peer` commands.

---

## Troubleshooting

Every failure in the panel carries a stable code (`E-FRP-10`, `E-GRE-02`, …). Look the code up in [docs/ERROR_CODES.md](docs/ERROR_CODES.md), or run `hashem doctor`. The most common cases:

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `frpc` logs `connect to server error: EOF` (`E-FRP-10`) | `tcpMux` differs between hub and spoke | `hashem perf tcpmux on` or `off` on **every** server so they match (default is off) |
| `E-FRP-02` / `E-BH-01` authentication failed | token differs | re-copy the token from the Iran peer card or the bundle |
| `E-FRP-04` cannot reach server | wrong IP/port, firewall, or `frps` down | check the control port is open on the hub; run `hashem dial status` on the spoke |
| `E-GRE-02` GRE ping fails but traffic flows (**FRP only** badge) | ICMP or proto 47 filtered | expected when GRE is blocked; the dial route falls back to the public IP. Try the WSS carrier to get GRE back |
| GRE never comes up | the provider drops IP protocol 47 | open proto 47 both ways, switch the carrier to WSS, or use Backhaul standalone |
| Panel URL not reachable | port busy (the panel moves to the next free port) or a firewall | `hashem show-panel-url`; open that port |
| Lost the admin password | — | `hashem reset-password` |
| Locked out after failed logins (`E-AUTH-02`) | 5 failures → 15 min lock, doubling for repeat offenders up to 24 h | wait, or `systemctl restart gre-panel` (lockouts are kept in memory) |
| `E-UPDATE-01` / `E-UPDATE-02` | GitHub not reachable from the server | retry later or fix the route; nothing was changed |
| An update was rolled back | the new binary crashed 3 times | check `journalctl -u gre-panel`; the old version was restored automatically |
| HTTPS certificate fails (`E-TLS-05`) | port 80 closed or the domain does not point here | open port 80, fix DNS, retry |

More cases, with commands: [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md).

---

## Uninstall and your data

```bash
hashem backup now      # optional: encrypted archive in /var/backups/hashem
hashem uninstall       # asks to confirm; "--force" skips the question
```

Uninstall is a **full wipe**. It removes:

- all tunnel, relay, panel and watchdog systemd units, and the GRE interfaces;
- the binaries `frps`, `frpc`, `backhaul`, `gre-panel`, `grepanel`, and the `hashem` command itself;
- `/etc/frp`, `/etc/backhaul`, `/etc/gre-panel` (panel config, history and the **backup key**) and `/usr/local/gre-panel`;
- Hashem logs, locks, cron entries, its iptables rules and its sysctl tuning.

It does **not** remove `/var/backups/hashem`. But those archives are encrypted with `/etc/gre-panel/backup.key`, which the wipe deletes. **Copy `backup.key` somewhere safe before uninstalling** if you want to restore later.

---

## Known limitations

- **GRE can be blocked.** Some providers drop IP protocol 47. The WSS carrier and Backhaul standalone exist for that case, but no carrier is guaranteed to pass every network.
- **The panel is HTTP by default.** Use `hashem panel-tls` or a reverse proxy for anything public.
- **One admin account** per panel; there are no roles.
- **Linux + systemd only**, `amd64` and `arm64` builds.
- **Peer limit** of 10 per hub by default (`GRE_MAX_PEERS`).
- **Automatic actions are conservative on purpose:** watchdog `auto_restart` is off and the carrier is never switched automatically.
- **Docs language:** the README, the Cluster guide and the FRP guide exist in Persian; the other guides are English.

Ideas and bug reports are welcome — see [Contributing](#contributing).

---

## Documentation map

- **Start here** — [Quick install](#quick-install) · [Choosing an engine](docs/ENGINES.md) · [Troubleshooting](docs/TROUBLESHOOTING.md)
- **Guides** — [Cluster: how it works and tutorial](docs/CLUSTER_TUTORIAL.md) ([فارسی](docs/CLUSTER_TUTORIAL.fa.md)) · [Cluster guide](docs/CLUSTER.md) ([فارسی](docs/CLUSTER.fa.md)) · [FRP transports guide](docs/FRP_TUNNELS_GUIDE.md) (Persian + English) · [IPv6](docs/IPV6.md) ([فارسی](docs/IPV6.fa.md)) · [Secure deployment](docs/DEPLOYMENT.md)
- **Reference** — [HTTP API](docs/API.md) · [Error codes](docs/ERROR_CODES.md) · [CHANGELOG](CHANGELOG.md) · [Architecture (interactive)](docs/hashem-architecture.html)
- **Project** — [CONTRIBUTING](CONTRIBUTING.md) · [Development guide](docs/dev/DEVELOPMENT.md) · [Code of conduct](CODE_OF_CONDUCT.md) · [SECURITY](SECURITY.md)
- **Audits and plans** — [docs/audit/](docs/audit/) · [r24 improvement plan](docs/PLAN_IMPROVEMENTS_R24.md)

---

## Security notes

- **Policy and disclosure:** [SECURITY.md](SECURITY.md).
- **Production deployment** (Nginx / Caddy, TLS, firewall, `TRUSTED_PROXY_IPS`): [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).
- Passwords are stored only as salted **argon2id** hashes in `/etc/gre-panel/panel.json` (older unsalted SHA-256 hashes are upgraded on the next login). The policy requires 12+ characters with upper, lower, number and symbol.
- State-changing requests need a session-bound HMAC-SHA256 `X-CSRF-Token`; `X-Forwarded-For` is trusted only from `TRUSTED_PROXY_IPS`.
- Updates are pinned to official GitHub domains and verified with SHA-256 from `checksums.txt`; the installer script is checked with `bash -n`.
- The in-browser terminal is **disabled by default** and audited (10-minute idle and 30-minute absolute limits).
- Security events and **every state-changing API call** (method, path, status; never the body) are written to `/etc/gre-panel/security-audit.log` (rotated at 2 MiB, newest entries via `GET /api/audit`).
- Login lockout escalates for repeat offenders (15 min, doubling up to 24 h).
- Optional **TOTP two-factor login** (Settings → Two-factor authentication) with 8 single-use recovery codes; off by default. Recovery if you lose the device: set `GRE_PANEL_PASSWORD` and remove `totp_enabled` from `panel.json`.
- Optional **idle session timeout** (Settings), driven by real clicks/keys, not background refresh.
- The terminal asks for your password (and 2FA code) every time it opens, uses a single-use 60 s ticket bound to your session and IP, and can be limited to an **IP allowlist**.
- `install.sh` only accepts `hashem.sh` from GitHub itself, from two agreeing mirrors, or matching a pinned `HASHEM_SHA256`; otherwise it stops.
- Logs shown in the panel mask tokens and passwords (Backhaul prints rejected tokens verbatim).
- Backups include every panel config and Backhaul unit; restore refuses archives that reach outside the config directories and first saves a safety copy of the current state.

---

## Contributing

Issues and Pull Requests are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) first: branch from `dev`, run the tests, regenerate the API docs, open a PR. Use the issue forms for bugs and ideas; report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## License

Licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)**. If you modify this software and run it as a network service, you must make your modifications available under the same license. See [LICENSE](LICENSE).

## Community

- 🌐 [pdnczone.ir](https://pdnczone.ir) · ✈️ [@pdnczone](https://t.me/pdnczone) · ▶️ [@pdnczone](https://youtube.com/@pdnczone)
