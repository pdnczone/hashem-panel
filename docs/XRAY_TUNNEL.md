# Xray tunnel

[فارسی](XRAY_TUNNEL.fa.md)

A **Hashem Pro** tunnel that forwards ports from the Iran server to a foreign server over Xray-core (VLESS). Users connect to a port on the Iran server. Xray carries each connection to `127.0.0.1` on the same port on the foreign server, where your service listens, usually a 3x-ui inbound.

```
users ──> Iran :2053 ══ Xray (Reality, XHTTP, gRPC, mKCP or CDN) ══> foreign 127.0.0.1:2053 (3x-ui)
```

## Direct or reverse

| | Who connects | Use it when |
|---|---|---|
| **Direct** | The Iran server connects to the foreign server. | Usually. |
| **Reverse** | The foreign server connects to the Iran server (Xray's VLESS reverse proxy). | The Iran server cannot reach the foreign one, or its outgoing connections get cut. |

In reverse mode the Iran server listens on the tunnel port, and its key may only open reverse links: a leaked key gives no proxy. One Iran server can have several links, each to its own foreign server.

## Presets

| Preset | On the wire | For |
|---|---|---|
| **Reality** | RAW + Reality + Vision | The fastest. It looks like a visit to a normal HTTPS site (the SNI). |
| **XHTTP** | XHTTP + Reality | Ordinary HTTP requests: for when plain Reality gets cut. The default in reverse mode. |
| **gRPC** | gRPC + Reality | Many streams over one connection. |
| **mKCP** | mKCP over UDP, encrypted | For when TCP is throttled. |
| **CDN** | XHTTP + TLS through Cloudflare | A censor sees only Cloudflare, and a blocked server IP stays reachable. |

**Advanced settings** cover the transport (also WebSocket and HTTPUpgrade), Reality (fingerprint, target, SpiderX, PROXY protocol), TLS (your own certificate files), mux, TCP Fast Open, congestion control, MPTCP, socket mark, fragment (anti-DPI, on the dialing end), mKCP tuning, and an **expert JSON**. The expert JSON is merged over the generated config: objects merge key by key, inbounds and outbounds by `tag`. Xray checks the result before it is used.

## Setting up a link

1. On the **Iran server**, open the **Xray** tab and choose **Create a tunnel**. Install Xray-core first if the tab asks.
2. **Direction:** direct or reverse.
3. **Settings:** pick a preset. Enter the foreign server's IP, the ports to forward, and the tunnel port. **Find a working site** tests the disguise sites from this server (TLS 1.3 with h2) and picks the fastest. A port that something else holds is named with its owner, and a free one is offered.
4. **Review**, then **Create the tunnel**. The link comes up step by step: Xray-core, ports free, config accepted by Xray, service running, link works.
5. Copy the **bundle** (`xr1_…`). On the **foreign server**, open the Xray tab, choose **Paste a bundle**, and import it.

Changing a link later restarts it. If the foreign server needs the change too, the panel shows a new bundle to paste there. Pasting a bundle again updates the link in place.

## CDN (Cloudflare)

1. A domain or subdomain whose DNS is on Cloudflare.
2. **DNS:** an `A` record for the domain to the server that listens (the foreign server in direct mode, the Iran server in reverse mode), with the proxy on (orange cloud).
3. **SSL/TLS mode: Full**, not Full strict. The link uses a certificate the panel makes for the domain and carries inside the config.
4. The tunnel port must be one Cloudflare passes: 443, 2053, 2083, 2087, 2096 or 8443.
5. Optionally, a clean Cloudflare IP for the dialing server to connect to. Empty means the domain itself.
6. For WebSocket or gRPC in the advanced settings, turn that on under Cloudflare's **Network**.

**TLS without a CDN** (advanced settings): the dialing end trusts exactly the panel's certificate (pinned), so no certificate authority is needed. Your own certificate files can be used instead.

## Next to 3x-ui, Marzban and others

- **Its own Xray-core**, the official release pinned by sha256, in `/usr/local/lib/hashem/xray`. That is never `/usr/local/bin/xray` (the official installer's) or a panel's folder.
- **Its own services**, `hashem-xray-N`, and **no Xray API port**. Nothing is ever stopped by process name.
- **Before a link starts**, the panel reads who listens where. A port held by another program is refused with its name, for example `TCP port 443 is used by 3x-ui (x-ui)`, and a free port is suggested. Xray panels found on the server are listed in the tab.
- **The foreign end reaches only** `127.0.0.1` on the forwarded ports. Your 3x-ui inbounds stay as they are. If an inbound expects the PROXY protocol, set it in the advanced settings.

## Health and traffic

The Iran end checks a link by sending a request through it that the other end's Xray answers itself, so no extra port opens anywhere. The ping on the card is a real round trip:
- In direct mode it is the TCP round trip to the foreign server.
- In reverse mode it is one request down the link the foreign server keeps open.

Each link's traffic is counted on its own (`xray-N`) by the panel's counters. The links show on the dashboard map and on the Tunnel tab, with the same live picture as the Xray tab.

## Terminal

```bash
hashem xray install     # the pinned Xray-core (Pro)
hashem xray status      # core version and each link's service
hashem xray restart     # also: start, stop
hashem xray logs 200    # the links' log
hashem xray uninstall   # removes the services and the core; the links stay in the panel
```

## Tested

The CI lab runs a real Xray-core between Iran and foreign network namespaces. It covers every preset, plus TLS on XHTTP, WebSocket, HTTPUpgrade and gRPC (the path a CDN takes to the server), in both modes. Each combination carries:
- 8 MiB each way, checked by sha256,
- 16 parallel connections,
- UDP.

Reverse mode runs with the Iran server's outgoing connections blocked. The lab also checks that:
- a fake 3x-ui on port 443 is named and left running,
- the tunnel port without the key shows the borrowed site's certificate,
- the foreign end refuses a port it does not forward,
- a reverse link comes back after the foreign Xray is killed.
