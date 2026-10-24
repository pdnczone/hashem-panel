# Choosing an engine and a carrier

Hashem has two independent choices:

1. the **engine** — what relays your traffic (FRP or Backhaul) and whether a GRE link sits underneath;
2. the **carrier** — how the GRE packets cross the internet (only for engines that use GRE).

## Engines

| | GRE + FRP (`frp`) | Backhaul with GRE (`gre-backhaul`) | Backhaul without GRE (`backhaul`) |
| --- | --- | --- | --- |
| Setup bundle | `hsh1_…` | `gh1_…` | `bh1_…` |
| GRE interface (`gre-tunnel`) | yes | yes | no |
| Relay binary | `frps` / `frpc` | `backhaul` | `backhaul` |
| Relay runs over | GRE inner IPs (10.10.10.x by default) | GRE inner IPs | the public IP |
| Fallback to the hub's public IP while GRE is dead, back to GRE when it returns | yes (`hashem dial`) | yes | not needed |
| Transports | `tcp`, `kcp`, `quic`, `websocket`, `wss` | Backhaul transports | Backhaul transports |
| Tuning in the panel | Auto Pool, encryption, compression, PROXY Protocol v2, tcpMux | Backhaul settings | Backhaul settings |

**GRE + FRP** is the default and the most complete: every Performance-tab option applies to it, and the FRP transports cover the common Iranian network conditions (see the matrix in [FRP_TUNNELS_GUIDE.md](FRP_TUNNELS_GUIDE.md)).

Backhaul is **one engine** in the panel's Setup tab and in `hashem backhaul`: "with GRE" or "without GRE" is a question inside it, not a separate engine.

**Backhaul with GRE** keeps the private L3 link and uses Backhaul as the relay. The foreign side dials the GRE inner address while GRE works and the hub's public IP while it does not (see *Route to the Iran hub* below), so it also works on paths that block GRE some of the time.

**Backhaul without GRE** makes no GRE interface at all. Use it when IP protocol 47 is blocked for good between your two servers: no GRE unit, no GRE warnings in the panel, no watchdog repairs of a GRE that cannot work. Its setup bundles are the `bh1_` strings.

**Bagher** [PRO] is an SSH connection pool from Iran to the foreign server that carries FRP. It is set up from the same Setup tab (Engine: Bagher; the foreign side pastes the `BAGHER:` bundle into the same bundle box) and runs from the Tunnel tab's Bagher card (start, stop, copy bundle, quick edit, remove). It runs next to the main tunnel, so the Setup lock does not apply to it.

### Route to the Iran hub (foreign side)

With GRE underneath (GRE + FRP, Backhaul with GRE) the foreign client can reach the hub over the GRE inner address or the hub's public IP (the hub listens on every address). `hashem dial auto|gre|public`, the Tunnel tab's route card and the foreign side of Setup choose it:

- **auto** (default): GRE when it answers, the public IP otherwise. The watchdog (every minute) moves the client to the public IP when GRE is dead and the client is not connected, and back to GRE after GRE has carried the control port for 5 checks in a row. If the client cannot connect over GRE after the move, it returns to the public IP and does not try again for 30 minutes.
- **gre** / **public**: fixed; the watchdog leaves the route alone.

### Backhaul transports and ports

Hashem installs upstream Backhaul v0.7.2. Its transports are `tcpmux` (default), `tcp`, `ws`, `wss`, `wsmux`, `wssmux` and `udp`. All of them carry TCP except `udp`, which carries UDP only. To forward TCP **and** UDP on the same ports, use `tcp` with "Also forward UDP" (`--udp`, the core's `accept_udp`); the core ignores that option on the other transports.

Port entries: `443`, `10000-10050`, `2083=8443`, `10000-10050=443`, with an optional `IP:` on either side. The `10000-10050:443` form from Backhaul's README is rejected by the core, so Hashem rewrites it to `10000-10050=443`.

Everything Backhaul lives in Hashem: `hashem backhaul` (menu), the panel's Setup tab, `/etc/backhaul`, and the `backhaul-server[-N]` / `backhaul-client` units. Tunnels made by the old separate Modified Backhaul script (`backhaul-iranN` / `backhaul-kharejN`) are moved into Hashem by `hashem backhaul-migrate`, which the panel also runs once when it starts. Their IPX, ICMP, TUN, anytls and xtcpmux transports need the paid Backhaul Premium core, which Hashem does not ship; those tunnels never started on the installed core and have to be set up again with a transport from the list above.

You can switch the engine of an existing tunnel from the panel; the switch checks that the binary and unit exist before it stops anything, and reports the real error if a step fails.

## Carriers (GRE layer)

| Carrier | What crosses the network | Port | Use when |
| --- | --- | --- | --- |
| **Direct GRE** (default) | IP protocol 47 packets | none (protocol 47) | the path between the servers passes protocol 47 |
| **WSS** | GRE inside a TLS WebSocket | TCP `8443` (default) | protocol 47 is dropped, but outbound TCP/443-style traffic passes |
| **6to4** | GRE (as ip6gre) on a private IPv6 /64, inside IP protocol 41 between the IPv4 addresses | none (protocol 41) | protocol 47 is dropped but 41 passes |
| **4in6** | GRE (as ip6gre) between the servers' public IPv6 addresses | none (protocol 47 over IPv6) | both servers have IPv6 and the IPv4 path is blocked or slow |

With 6to4 and 4in6 the tunnel interface keeps its name, its inner IPv4 /30 and its routes, so FRP and Backhaul over GRE work unchanged. Switching from the panel's GRE wrap card changes both servers over the Peer Link and waits up to 45 seconds for the inner address to answer; otherwise both go back to the previous carrier. See [IPV6.md](IPV6.md).

The FOU carrier was removed. The carrier is **never switched automatically**: the *carrier advisor* in the panel can tell you the active carrier keeps failing and suggest another, and `hashem carrier` changes it when you decide to.

The GRE interface MTU is set to 1380 (1360 for WSS) so tunnelled TCP does not fragment. 1380 also fits 6to4 (64 bytes of headers) and 4in6 (44 bytes).

## A simple decision path

1. Try **GRE + FRP** with **Direct GRE**. Check the Dashboard: *Healthy* means done.
2. If the badge says **FRP only** or GRE never comes up, protocol 47 is probably filtered. Switch the carrier to **WSS** or **6to4** (`hashem carrier`), or to **4in6** when both servers have IPv6.
3. If GRE is still unusable, or you do not need it, use **Backhaul without GRE**.
4. Run the **Benchmark** tab to compare carriers on your real path before you commit.

## Transports for FRP

Pick per network condition; the full explanation and the operator matrix are in [FRP_TUNNELS_GUIDE.md](FRP_TUNNELS_GUIDE.md).

| Transport | Good for | Costs |
| --- | --- | --- |
| `tcp` | stable fixed lines, lowest CPU | slows under heavy packet loss |
| `kcp` | high packet loss (mobile at peak) | 10–20 % more bandwidth, needs UDP |
| `quic` | modern, many parallel streams | needs UDP |
| `websocket` | firewalls that only let web ports through | small overhead |
| `wss` | strict DPI | extra CPU for TLS; needs the TLS front (`control_port+2`) |

## One rule that bites: tcpMux

FRP `transport.tcpMux` is **off** by default and must be **identical on the hub and on every spoke**. A mismatch shows up as `connect to server error: EOF` (`E-FRP-10`). Change it everywhere with `hashem perf tcpmux on|off`.
