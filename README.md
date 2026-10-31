<div align="center">

# Hashem Panel

**Tunnels between an Iran server and foreign servers, managed from one web panel.**

Users connect to the Iran server's public IP; their traffic reaches services on your foreign servers through GRE, FRP, Backhaul, Xray, SSH or a spoofed pipe, with health checks, failover and safe updates built in.

[![Downloads](https://img.shields.io/github/downloads/pdnczone/hashem-panel/total?label=downloads&color=brightgreen)](https://github.com/pdnczone/hashem-panel/releases)
[![CI](https://github.com/pdnczone/hashem-panel/actions/workflows/ci.yml/badge.svg)](https://github.com/pdnczone/hashem-panel/actions/workflows/ci.yml)
[![Platform](https://img.shields.io/badge/linux-amd64%20%7C%20arm64-blue)](#requirements)
[![License: AGPL v3](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)

English · [فارسی](README.fa.md) · [Website](https://pdnczone.ir) · [Telegram](https://t.me/pdnczone) · [YouTube](https://youtube.com/@pdnczone)

<img src="docs/img/dashboard.png" alt="Hashem dashboard: one Iran server, four foreign servers, live traffic" width="900">

</div>

## How it works

```mermaid
flowchart LR
    U([Users]) --> HUB
    subgraph IR["Iran server"]
        HUB["Public ports<br/>frps · Backhaul · Xray"]
        P["Panel :7777"]
    end
    HUB <== "GRE · 6to4 · 4in6 · WSS" ==> A["Foreign server A<br/>FRP over GRE"]
    HUB <-- "Backhaul, no GRE" --> B["Foreign server B"]
    HUB <-- "Xray / SSH" --> C["Foreign server C"]
```

The **Iran server** owns the public ports users connect to. Each **foreign server** runs your services (for example an Xray panel) and is linked to the Iran server by a tunnel. The same panel runs on both sides: you set up the Iran server, copy one **setup bundle**, and paste it on the foreign server.

## Tunnels

| Tunnel | How it travels | Pick it when |
| --- | --- | --- |
| **GRE + FRP** | FRP over a GRE link (tcp, kcp, quic, websocket, wss) | the default: most options, free |
| **Backhaul** | with or without GRE (tcpmux, ws, wss, udp, …) | GRE is blocked, or you want Backhaul's transports |
| **Xray** | VLESS with Reality, XHTTP, gRPC, mKCP or a CDN | the path needs to look like normal HTTPS |
| **Bagher** | FRP inside a pool of SSH connections | only SSH gets through |
| **Spoof** | spoofed-source pipe with WireGuard on top | the firewall whitelists source IPs |

The GRE link itself can be wrapped four ways: **Direct** (protocol 47), **WSS** (TLS on a web port), **6to4** (protocol 41) and **4in6** (over IPv6). Not sure what gets through? **Path test** (Benchmark tab) checks every transport between your two servers before you build anything. Details: [docs/ENGINES.md](docs/ENGINES.md).

## Features

- **One health model** for the dashboard, the map and every card, with latency per link and alerts by webhook or Telegram when a tunnel changes state.
- **Swap a tunnel's carrier** from either server; both switch, and both go back if the new one does not connect within 45 seconds.
- **Cluster:** several foreign servers behind one Iran port (failover, balance, sticky, least connections), Iran servers backing each other up, and DNS failover. [Guide](docs/CLUSTER.md)
- **Nodes:** manage all your servers from one panel: add them with one line or SSH, open any server's pages from the central, make a tunnel between two of them from one page, update and back them up, and get their alerts in one place. [Guide](docs/NODES.md)
- **Customers (Pro):** sell tunnels: each customer brings foreign servers, you set the plan (days, volume, speed), and their tunnels stop when it ends. [Guide](docs/CUSTOMERS.md)
- **Watchdog, encrypted backups and diagnostics** (`hashem doctor`), with Quick Repair.
- **Updates you can undo:** stable and dev channels, SHA-256 verified, automatic rollback after a bad start.
- **Hardened panel:** argon2id passwords, CSRF, optional 2FA, audit log; the web terminal is off by default.
- **Everything from SSH too:** `hashem` opens a terminal app with the same menus as the panel.

## Quick install

Run on **both** servers:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/pdnczone/hashem-panel/main/install.sh)
```

1. **Iran server:** choose `1`, pick the tunnel and ports, and copy the bundle it prints (`hsh1_…`).
2. **Foreign server:** choose `2` and paste the bundle.
3. **Open the panel** at the URL printed at the end (`http://<server-ip>:7777/<secret>`). Lost it? `hashem show-panel-url`; new password: `hashem reset-password`.

More foreign servers are added from the panel's **Setup** tab. To read the installer first, or pin it to a release's `checksums.txt`, see [Installing safely](docs/OPERATIONS.md#installing-safely).

> [!IMPORTANT]
> The panel uses plain HTTP on a long random path by default. Before exposing it, add TLS with `hashem tls issue <domain>` or a reverse proxy ([docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)).

## Requirements

- Linux with systemd, `amd64` or `arm64` (developed on Ubuntu), and root on both servers. The installer adds missing packages.
- The GitHub releases reachable from both servers, for install and updates.
- Between the servers, whatever your tunnel uses:

| Tunnel or wrap | Open |
| --- | --- |
| Direct GRE · 4in6 | IP protocol 47 (over IPv4 · over IPv6) |
| 6to4 | IP protocol 41 |
| WSS wrap | TCP `8443` (default) |
| FRP · Backhaul · Xray | the control port you choose (UDP too for kcp, quic, udp) |
| Panel | TCP `7777`, or `7443` once HTTPS is on |

## Hashem Pro

GRE + FRP, the panel and updates are free. A **Pro license** unlocks Backhaul setup, Xray, Bagher, Spoof, limits, the cluster, the path test, diagnostics, performance tuning, the watchdog and the benchmark. Every Pro key opens every Pro feature, including ones added later, and tunnels and settings that already run keep running without one. [pdnczone.ir](https://pdnczone.ir)

## Documentation

| | |
| --- | --- |
| **Start** | [Choosing a tunnel](docs/ENGINES.md) · [Troubleshooting](docs/TROUBLESHOOTING.md) · [Secure deployment](docs/DEPLOYMENT.md) |
| **Guides** | [IPv6](docs/IPV6.md) · [Xray tunnel](docs/XRAY_TUNNEL.md) · [Cluster](docs/CLUSTER.md) · [Cluster tutorial](docs/CLUSTER_TUTORIAL.md) · [Nodes](docs/NODES.md) · [Customers](docs/CUSTOMERS.md) · [FRP transports](docs/FRP_TUNNELS_GUIDE.md) |
| **Reference** | [Operations: health model, updates, CLI, uninstall](docs/OPERATIONS.md) · [HTTP API](docs/API.md) · [Error codes](docs/ERROR_CODES.md) · [Changelog](CHANGELOG.md) |
| **Project** | [Contributing](CONTRIBUTING.md) · [Development](docs/dev/DEVELOPMENT.md) · [Security policy](SECURITY.md) · [Code of conduct](CODE_OF_CONDUCT.md) |

Persian versions exist for the README and the IPv6, Xray, cluster and FRP guides.

## Contributing and license

Issues and pull requests are welcome; read [CONTRIBUTING.md](CONTRIBUTING.md) and branch from `dev`. Report vulnerabilities privately ([SECURITY.md](SECURITY.md)).

Licensed under the [GNU AGPL-3.0](LICENSE): if you run a modified version as a network service, publish your changes under the same license. The Pro features need a license from the author.
