# Changelog

Format: newest first. Versions are git tags; every tag has a GitHub release with `checksums.txt`.
Builds before `v0.1.0` were numbered `panel-rN` (see the releases page).

## v2.7.2 — 2026-10-25

A fix for the Spoof Tunnel. Run `hashem update` on the Iran server; update the foreign server too for the clearer messages.

**Fixes**
- **Up** on the Iran server no longer stops with `E-ENGINE-01` "the peer WireGuard key is missing" when the bundle has not been shown yet. The Iran server owns both WireGuard keypairs and now makes any that are missing when it brings the tunnel up; showing the bundle later gives the same keys.
- Spoof settings that are still incomplete (no bundle imported on the foreign server, no spoof IP, no peer IP) now return the new `E-ENGINE-02` (400) with a hint that fits, instead of `E-ENGINE-01` (500) with a journalctl hint. The missing peer key message now tells the foreign server to import the bundle from the Iran server.

## v2.7.1 — 2026-10-24

A fix for servers with more than one foreign server. Run `hashem update` on the Iran server; nothing else to do.

**Fixes**
- A second, third or later foreign server no longer disappears from the Tunnels tab and the dashboard while its tunnel is connected. `hashem.sh` wrote a Backhaul tunnel's forwarded ports to `peers.json` as one string, the panel could not read that file, and it then showed no extra tunnel at all. The panel now reads both forms, `hashem.sh` writes a list, and Edit Peer opens for these tunnels again.

## v2.7.0 — 2026-10-24

IPv6 in every tunnel, with two new GRE wraps (**6to4** when protocol 47 is blocked but 41 is not, **4in6** over the servers' real IPv6); a new **Xray** tunnel (Reality, XHTTP, gRPC, mKCP, CDN, direct or reverse); **speed and volume limits** per foreign server; Bagher with lower ping and several foreign servers; traffic counters you can trust; and the carrier can be changed from the foreign server too. Update both servers of a tunnel: 6to4/4in6 and a swap from the foreign side need this version on each.

**Upgrade notes**
- Nothing to migrate: tunnels, pools and settings from v2.6.0 keep working as they are. A running Bagher tunnel moves to the panel's own SSH carrier by itself after `hashem update` on the Iran server (the foreign server needs no update).
- The Xray tunnel and the limits are Hashem Pro; every existing Pro key opens them. Limits already set keep working without a license and can always be removed.
- 6to4 needs protocol 41 between the servers, 4in6 a public IPv6 on both. Test first: Benchmark → Path test now has these rows.
- Totals that the old traffic bugs inflated stay as they are; from this version on, only real bytes are added.

### New: IPv6 in every tunnel, and the 6to4 / 4in6 carriers

- **Users over IPv6.** Users can reach the Iran server's forwarded ports over IPv6 as well as IPv4, on Backhaul, FRP, Bagher and Xray. Bagher's direct mode now listens on every address of both families.
- **The two servers over IPv6.** Backhaul without GRE, Bagher and Xray can connect the Iran and foreign servers over IPv6. In Setup, Backhaul without GRE has **Connect the two servers over IPv4 / IPv6**, which fills in this server's public IPv6. `bh1_` bundles may carry an IPv6 address. GRE setups still need IPv4 on both ends, and say so instead of failing later.
- **Two new GRE wraps: 6to4 and 4in6.** 6to4 builds a private IPv6 between the servers' IPv4 addresses (IP protocol 41) and runs GRE on it, for networks that drop protocol 47 but pass 41. 4in6 runs GRE between the servers' public IPv6 addresses. The tunnel interface keeps its name, inner address and routes, so FRP and Backhaul over GRE keep working unchanged. If a new wrap cannot be built, the tunnel goes back to plain GRE instead of being left without an interface.
- **A switch changes both servers and is undone if the tunnel goes quiet.** The GRE wrap card switches this server, then the other one over the Peer Link (for 4in6 the other server's IPv6 is asked for you), and waits up to 45 seconds for the tunnel to answer; if it does not, both servers go back to the wrap they had.
- `hashem carrier set 6to4|4in6 [--if IF] [--local6 IP --remote6 IP]`; `hashem edit-peer --carrier 6to4|4in6 [--remote6 IP]` for one foreign server.
- **Limits and traffic counters cover IPv6.** A foreign server can be limited by its IPv6 address, and a GRE tunnel on 4in6 counts the server's IPv6 towards the same speed and volume (ip6tables, and tc with `protocol ipv6`). The dashboard's per-tunnel counters count links over IPv6 too.
- Rescue mode accepts an IPv6 peer; then every port goes through frp, since kernel DNAT cannot hand IPv4 users to an IPv6 origin.
- **WSS over IPv6.** The WSS settings take the other server's address (IPv4, IPv6 or a host name), and the WSS port is opened for IPv6 too.
- **The path test (Benchmark) checks the IPv6 paths:** 6to4 (protocol 41 between the IPv4 addresses), TCP over IPv6, and 4in6 (GRE between the IPv6 addresses), so you can pick a wrap before building a tunnel. `gre-panel pathtest serve -ip6 ADDR` sets this server's IPv6 (`-` skips these rows).
- **Cluster DNS failover writes AAAA records** for the working hubs that have a public IPv6 and no pools (each hub sends its IPv6 in the heartbeat). The webhook gets them as `ips6`; `ips` stays IPv4 only, so existing receivers keep working.
- The carrier advisor suggests 6to4 when the active carrier keeps failing, and 4in6 on a server with IPv6. The doctor warns when the server has IPv6 but UFW is set to `IPV6=no`.
- The menus of `hashem.sh` offer 6to4 and 4in6 (carrier menu and Edit peer), instead of the old FOU entries.
- **Change the carrier from the foreign server too.** The **Swap carrier** button and the Carriers card now work on the foreign server, and so does the GRE wrap card (Direct, WSS, 6to4, 4in6). The foreign server asks the Iran server over the Peer Link (or its own tunnel token), and the Iran server runs the change exactly as if it was started there: the foreign server is told first, both switch, and both go back if the tunnel does not answer within 45 seconds. The dialog shows the Iran server's view and the steps live. An older Iran panel, or one this server cannot reach, is named instead of a silent one-sided switch (the GRE wrap then switches this server alone, as before, and says so). `GET/POST /api/peer/swap-request` and `/api/peer/wrap-request` on the Iran side.
- Fixed: the carrier menu's **Next candidate** and **Automatic** only printed the status (`cli_carrier` was defined twice). There is one definition now, with every subcommand.
- Fixed: changing one foreign server's GRE wrap switched every GRE interface on the server, and its WSS branch used the wrong port.
- Fixed: on a server with both IPv4 and IPv6, the "what is my IP" lookups in `hashem.sh` could get the IPv6 address and reject it. They now ask over IPv4.
- **Tested in CI** with the real kernel: Backhaul on all 8 transport setups and FRP, users over IPv6 and IPv4 at once, and the two servers over IPv6 only, all byte-exact over TCP and UDP. The carrier lab drives `hashem.sh`'s own carrier code from direct GRE to 6to4 with protocol 47 dropped, then to 4in6 with no IPv4 between the servers, then back to direct, with Backhaul running over the tunnel each time. The Bagher lab reaches its second foreign server over IPv6 only, the Xray lab runs Reality and XHTTP in both modes over IPv6, the limits lab runs again against an IPv6 server, and the path test lab finds 6to4, TCP over IPv6 and 4in6 open, then blocked.
- Guide: [docs/IPV6.md](docs/IPV6.md) ([فارسی](docs/IPV6.fa.md)). Not over IPv6: the Spoof tunnel (it spoofs IPv4 by design) and the cluster's load balancer (IPv4 NAT).

### New: Xray tunnel (Hashem Pro, first part)

- **A new Xray tab.** It forwards ports from the Iran server to a foreign server over Xray-core (VLESS), so users connect to the Iran server and reach your 3x-ui inbounds on the foreign server. **Direct**: the Iran server connects to the foreign server. **Reverse**: the foreign server connects to the Iran server (Xray's VLESS reverse proxy), for when the Iran server cannot reach the foreign one. One Iran server can have several links, each to its own foreign server.
- **Presets.** Reality (RAW + Vision, the fastest), XHTTP + Reality, gRPC + Reality and mKCP over UDP. Each one shows its speed, stealth and stability. **Advanced settings** cover the transport, Reality (fingerprint, target, SpiderX, PROXY protocol), mux, TCP options, fragment, mKCP tuning, and an expert JSON that is merged over the generated config and checked by Xray before it is used.
- **Simple to set up.** A three-step wizard (direction, settings, review) on the Iran server makes the link and a bundle (`xr1_…`). Pasting the bundle in the foreign server's Xray tab completes the link. Bringing a link up shows each step live: Xray-core, ports free, config accepted by Xray, service running, link works. When a step fails, the exact reason is shown.
- **A live picture of the link.** Users → Iran → tunnel → foreign → service. Packets move at the link's real speed, an arrow shows which server connects to which, and a tag shows what a censor sees on the wire ("looks like www.speedtest.net"). The ping and the up and down speeds are shown too. The ping is a real round trip through the link: the panel asks the other end's Xray for a name only it answers.
- **No conflict with an Xray panel.** The tunnel uses its own Xray-core (the official v26.3.27, sha256-checked) in `/usr/local/lib/hashem/xray`, its own services (`hashem-xray-N`) and no API port. It never touches the files, services or ports of 3x-ui, Marzban, Hiddify or an official Xray install, and it never kills a process by name. A port another program holds is refused with the owner's name (for example "TCP port 443 is used by 3x-ui (x-ui)"), and a free port is offered. Xray panels found on the server are listed.
- **Safe by default.** The foreign end reaches only `127.0.0.1` on the forwarded ports, so a leaked key is no open proxy. In reverse mode the Iran server's key may only open reverse links.
- **SNI tester.** Tests the disguise sites from the server (TLS 1.3 with h2) and picks the fastest that works.
- Each link's traffic is counted on its own (`xray-N`) with the panel's counters.
- CLI: `hashem xray install|status|start|stop|restart|logs|uninstall`. `hashem uninstall` removes the tunnel's units and core.
- **Tested in CI** with the real Xray-core: every preset, and TLS on XHTTP, WebSocket, HTTPUpgrade and gRPC (the path a CDN takes to the server), in both modes, carries 8 MiB each way (sha256), 16 parallel connections and UDP. Reverse mode is tested with the Iran server's outgoing connections blocked. The lab also checks that a fake 3x-ui on port 443 is named and left running, that the tunnel port without the key shows the borrowed site's certificate, that the foreign end refuses a port it does not forward, and that a reverse link comes back after the foreign Xray is killed.
- **CDN mode (Cloudflare).** A CDN preset sends the link through Cloudflare: a censor sees only a Cloudflare site, and a blocked server IP stays reachable. You give a domain whose DNS is on Cloudflare and, if you like, a clean Cloudflare IP. The wizard lists the Cloudflare steps: an A record with the proxy on, and SSL/TLS mode Full. The tunnel port is limited to the ports Cloudflare passes (443, 2053, 2083, 2087, 2096, 8443). The panel makes the certificate for the domain, carried inside the config, so no file has to be set up. The link's picture shows the cloud on the way. XHTTP is the default; WebSocket, HTTPUpgrade and gRPC are in the advanced settings.
- **Noise for mKCP** (advanced settings): before its first real packet to the other server, the dialing end sends a few junk packets, random bytes or a packet you give (text, hex or base64), to throw off DPI. The other end drops them. The CI lab runs mKCP with noise in both modes.
- **TLS without a CDN** (advanced settings): the panel's certificate, pinned on the dialing end, so it is checked with no certificate authority. Your own certificate files can be used instead.
- The Xray tab sits in the Tunnel group, right after Setup.
- **On the dashboard and the Tunnel tab.** Each Xray link is a node on the dashboard map, with its state, ping and live speed; clicking it opens its card in the Xray tab. The links bar shows `Xray n/m`. A server whose only tunnel is Xray shows as healthy when its links are. The Tunnel tab shows each link with the same live picture.
- Guide: [docs/XRAY_TUNNEL.md](docs/XRAY_TUNNEL.md) ([فارسی](docs/XRAY_TUNNEL.fa.md)). The traffic lab now also checks an Xray link's counters against the exact bytes sent.

### New: speed and volume limits per foreign server (Hashem Pro)

- **A Limits card in the Tunnel tab.** Each foreign server gets one speed for both directions (Mbit/s) and a volume (GB, download and upload together), or stays unlimited. A server is its address, so a limit covers every tunnel to it: GRE, FRP, Backhaul, Bagher and Xray.
- **When the volume is used up, that server's links are cut** until the next reset; the other servers keep working. The reset is monthly on a day you pick (1 to 28), or only by hand (**Reset usage**). Raising the volume or removing the limit brings a cut server back at once. With alerts on (Watchdog tab), a webhook or Telegram message goes out at 90%, at the cut and at the reset.
- **Live view.** Each server shows its speed against its limit and its used volume against its quota, with the date of the next reset.
- **How it works.** The speed is a tc policer on the default-route interface (clsact, egress to the server and ingress from it); the root qdisc and BBR are not touched. The volume is counted by the `HASHEM_LIMIT` iptables chain (from INPUT, OUTPUT and FORWARD), added up every 10 seconds and saved in `limits.json`, so it survives restarts, updates and reboots. A cut is a DROP for that address. `hashem uninstall` removes the chain and the policers.
- Limits keep working without a license and can always be removed; setting them needs Hashem Pro. Links through a CDN cannot be limited by address.
- **Tested in CI** with the real kernel: a 20 Mbit/s limit holds both ways, 20 MB is counted within a few percent, the cut stops new connections, and reset and remove bring the server back and leave nothing behind.

### Bagher: lower ping, and several foreign servers on one Iran server

- **Lower ping.** Bagher's SSH leg was `ssh -N -R`. An SSH connection that opens no session never gets `TCP_NODELAY` from the foreign server's sshd (OpenSSH up to 10.0, so Ubuntu 22.04 and 24.04 and Debian 12). Every small packet from the foreign server, such as a TLS reply or an HTTP header followed by its body, then waited for the ACK of the previous one. That added up to one Iran↔foreign round trip to each reply. The SSH leg is now the panel's own carrier (`gre-panel bagher-carrier`). It runs one exec request after connecting: the key's forced `/bin/false`, which makes sshd set `TCP_NODELAY`. The connection stays up after that request ends. In the lab, with 30 ms each way, a two-part reply now arrives one round trip after the request. The same key and the same foreign-side setup are used, and nothing changes on the foreign server.
- **Real tunnel ping.** The Bagher card and the dashboard show the carrier's keepalive round trip, which waits behind the tunnel's own data. Before, they showed a TCP connect to the foreign SSH port.
- **Several foreign servers.** On the Tunnel tab, the Bagher card has **Add Foreign Server**. Each foreign server gets its own SSH carrier (`hashem-bagher-N.service`), its own ports and its own bundle. All of them use the one frps on the Iran server. A port can belong to only one foreign server, and one foreign server can be added only once. Each one shows its own status and ping on the card and on the dashboard map, and the CLI's `hashem bagher start|stop|restart|status` covers all of them.
- **Upgrade.** After `hashem update` on the Iran server, a running Bagher tunnel moves to the new carrier by itself. The foreign server needs no update.
- Quick Edit no longer resets a custom foreign SSH port to 22 and user to root.
- `hashem uninstall` now removes the Bagher units.

### Traffic and speed you can trust

- **Total traffic jumped up for no reason.** Two parts of the panel read the same counters: the 5-second snapshot, with a `/proc/net/dev` read taken seconds earlier, and the history recorder, with a fresh read. When the older reading was processed after the newer one, every counter looked lower, was taken for a reset, and each tunnel interface's whole counter (often gigabytes) was added to the total again. Now the snapshot is the only reader, and a reading older than the last one is ignored.
- **Live speeds were up to 5× too high on the Tunnel tab and the dashboard map.** The browser measured the time between its own polls, but each poll returns the snapshot taken up to 5 s earlier: two polls 0.2 s apart could carry readings 5 s apart. Speeds now use the time the server read the counters (`counters_at` in `/api/status` and `/api/dashboard`). The dashboard's live speed also uses the reading time, not the time it was processed.
- **Bagher traffic was never counted.** The counting code expected the role "client", which Bagher never has. Now each Bagher link counts its own SSH connection: on the Iran server per foreign server, and on the foreign server only the Iran server's traffic to its sshd, so admin logins are not counted.
- **The main tunnel had no speed on a hub with more foreign servers.** Its counters were never filled in. Now they come from the `gre-tunnel` interface, or from its Backhaul unit's port counters.
- **Backhaul without GRE now shows a speed per foreign server.** Its traffic used to appear only in the total. The iptables counters are now split per Backhaul unit (the UDP companion counts with its unit) and per Bagher link.
- **No more counting the whole server.** With no tunnel interface, and while a GRE interface was being recreated, the panel counted the main network interface, meaning every byte the server moved, as tunnel traffic. That fallback is gone. The Spoof tunnel's WireGuard interface is now counted.
- **Traffic during a restart or update is kept.** Each interface's last counters are saved, so bytes moved while the panel was stopped count after it starts.
- **Usage ledger.** The "This server" series had the same reset bug as the total: when an interface went away, the remaining interfaces' whole counters were added again, and a new interface's existing counter was booked as traffic. It is now counted per interface and includes Backhaul and Bagher.
- **New CI lab (`tests/test_traffic_lab.sh`).** It sends exact byte counts over a GRE main tunnel, a GRE peer, a Backhaul peer without GRE and a Bagher link. It then checks every number the panel shows (per-link counters, dashboard totals, usage ledger), a paced 2 MB/s transfer's live speed, and traffic sent while the traffic state is reset as a restart would.

Totals that the old bugs inflated stay as they are; from this version on, only real bytes are added.

### Smaller changes

- **The first foreign server can have a name.** Before, only the servers added later could be named. The setup forms (Iran setup, Bagher setup, the foreign server's join) now have an optional name field, and the main tunnel's card, the Bagher card and each Bagher link have a **Rename** button. The name shows on the dashboard map, the Tunnel tab and the edit window. It is kept in `link_names.json`; renaming does not restart the tunnel.
- The Live Activity stream no longer shows `command "systemctl" failed (exit 4) | output: inactive` every few seconds. `systemctl is-active` exits non-zero for a stopped or uninstalled unit, which is the answer the status pollers ask for, not an error; these calls are no longer logged or counted as errors. A failed command's multi-line output is now logged on one line.

## v2.6.0 — 2026-10-22

A new tunnel type, **Spoof**, that crosses whitelist firewalls by forging its source IP on both servers, with a built-in tester that finds the source IPs that get through; every tunnel can **swap its carrier** from the panel; **UDP in every tunnel**; a map of every tunnel on the dashboard. Update both servers of a tunnel: the carrier swap and the Spoof tunnel need this version on each side.

**Upgrade notes**
- The Spoof tunnel is Hashem Pro; every existing Pro key opens it. Its core is not installed by default: `hashem spoof install` on both servers.
- Nothing to migrate: tunnels, pools and settings from v2.5.0 keep working as they are.

### UDP in every tunnel
- **Backhaul forwards UDP on every transport.** UDP rode only the `tcp` transport (`accept_udp`); the core ignores it on tcpmux and the ws/wss family, so the default tunnel carried TCP alone. With **Also forward UDP** (Setup, `--udp`, the terminal menu), a TCP-only transport gets a UDP companion on both servers: a second Backhaul with the `udp` transport, same token, same ports, on its own control port (the first free one after the tunnel's port: the core holds the udp transport's control channel on TCP, so it cannot share the port) (`backhaul-udp-<unit>`). It starts, stops and restarts with its tunnel (systemd `PartOf`), rebuilds its config from the tunnel's config at each start, and goes away with the tunnel (replace, remove peer, leave hub, uninstall). The bundle carries the choice and the port (`tcpmux+udp3081`), so the foreign side follows by itself; older bundles are unchanged. Peers, extra hubs and pool members work the same way. On a firewall outside the server, open the companion's port for TCP and UDP (`hashem backhaul status` shows it).
- **Bagher forwards UDP** when asked (Setup and the Tunnel card's edit): a udp proxy per port next to the tcp one, through the same SSH tunnel; the bundle carries it to the foreign server. Direct SSH mode stays TCP only (SSH cannot carry UDP). `hashem bagher apply-bundle` now uses the bundle's ports instead of a fixed list.
- **FRP** already forwarded TCP and UDP on every port; Setup now says so.
- `hashem bundle inspect` shows whether a bundle forwards UDP; `hashem backhaul status` lists the UDP companions. The add-peer form has the same choice, and the foreign Setup says when a bundle forwards UDP.
- **A new build is always loaded by the browser.** The panel's JS and CSS were cached for a day under the version number, so a rebuilt or dev build of the same version showed the old page; their URL now carries a hash of their content.
- **The traffic chart works with Backhaul and Bagher.** Tunnel Traffic Throughput, the Live traffic speeds and the traffic ledger counted tunnel interfaces only; Backhaul (without GRE) and Bagher have none, so the chart sat at zero or showed the whole network card. The panel now counts their ports with two iptables chains (`HASHEM_ACCT_IN`/`HASHEM_ACCT_OUT`; rules without a target, they count and never drop), built from the Backhaul configs (main, peers, hubs, UDP companions) and the Bagher config, on the default-route interface so a Backhaul inside GRE is not counted twice. They are rebuilt after a reboot or firewall reload and removed with the tunnels (and on uninstall). IPv4.
- **The dashboard draws every tunnel.** With two, three or more tunnels the hero only said "3 foreign servers". It is now a map: this server on one side, a wire to every link (the main tunnel, each foreign server, Bagher), each with packets moving both ways at its own speed, a violet tube where it runs inside GRE and a red dashed wire when it is down; every server is a card with its state, IP, engine, latency and live speed, and a click opens its card in the Tunnel tab. Up to six are drawn (then "+N more"); one tunnel is a single wire in the same style. Same colors as the chart and the Tunnel tab: violet out, blue in.
- **A link diagram on every tunnel card** (Tunnel tab: the main tunnel, each foreign server, Bagher): this server and the other one joined by a pipe where packets move in both directions, faster with more traffic and still when idle; live download/upload speed and latency under it; the engine, transport and GRE (drawn as a tube around the pipe) above it; a broken red pipe when the link is down; the forwarded ports as chips. A peer whose service runs without its session now reads "down" in its header instead of "active". `/api/status` gives the base tunnel's byte counters (`rx`/`tx`) for the live speed.
- **A smoother chart.** New samples glide in from the right and the scale eases to its new ceiling instead of jumping at each refresh; the curve is monotone (it no longer dips below zero beside a burst); the lines glow and fade in from the left; hovering shows a guide line and a ring on both lines; finer ceilings (12 and 16 between 10 and 20).
- **Tested with the real cores in CI:** tcpmux carries TCP and no UDP alone, the companion carries UDP (small and 1200-byte datagrams) on its own control port while TCP keeps working, and recovers after kill -9; Bagher carries UDP through ssh -R + frp; the dashboard counters see the bytes of a real Backhaul tunnel.

### Spoof Tunnel (new)
- **A new tunnel type that forges its source IP on both servers** to cross whitelist-based Layer-3 firewalls (the kind seen during Iran's blackouts), from [ParsaKSH/spoof-tunnel](https://github.com/ParsaKSH/spoof-tunnel). The Iran server and the foreign server each spoof their source address and know the other's real one, so a stateful firewall sees flows that match no connection it tracks. The raw pipe carries UDP only, so the panel wraps it with **WireGuard** for a real encrypted tunnel (10.20.0.1 ↔ 10.20.0.2); WireGuard keys for both sides are generated on the Iran server and travel in one bundle, so there is nothing to copy back.
- **A built-in spoof-IP tester.** Infrastructure firewalls often whitelist a few source IPs; the tester finds which ones get through. Run the **receiver** on one server and the **sender** on the other over ICMP or TCP, give it IPs, ranges or CIDRs, and it reports each source's packet loss. Passing IPs become that server's spoof list with one click, then swap the roles to find the other direction.
- **A dedicated Spoof tab**: pick the role (Iran or foreign), set the peer's public IP, ports and the send/receive transports (TCP, UDP, ICMP, ICMPv6), run the tester, bring the tunnel up or down, and watch the pipe, WireGuard and peer reachability live. The foreign server fills everything by pasting the Iran server's bundle.
- Pro feature, on both servers. The core is installed and pinned by `hashem spoof install` (sha256-verified `v3.0.2`), which also pulls in WireGuard tools; `hashem spoof {status,up,down}` from the terminal. `GET/POST /api/spoof`, `GET/POST /api/spoof/tester`.
- The bundle is checked field by field before anything is written (addresses, ports, transports and keys only), and showing it again on the Iran server gives the same keys, so a running tunnel keeps working. A stopped tester run says so instead of "no IPs passed", and the sender side points to the receiver for results. `hashem uninstall` removes the Spoof core, its service, `wg-spoof` and `/etc/spoof`.

### Swap the carrier of any tunnel
- **Every tunnel can move to another carrier from the panel**: the main tunnel and each foreign server, between GRE + FRP (TCP, KCP, QUIC, WebSocket), Backhaul over GRE and Backhaul without GRE (tcpmux, wssmux, tcp, ws, wsmux, wss, udp). **Swap carrier** is on every tunnel card, in the edit dialog and in the new **Carriers** card, which lists each tunnel with the carrier it runs on. The dialog shows the two servers with the carrier between them, every carrier as a tile (what it is good for, TCP/UDP/TLS/MUX, which need GRE or Pro, which are not installed), and the swap live, step by step.
- **Both servers switch, and a carrier that does not connect is undone.** The foreign server is told first over the peer API (the main tunnel's Peer Link, or each foreign server's own tunnel token), answers at once and switches a moment later; then this server switches with the engine switch's rollback; then the panel waits up to 45 s for the tunnel's control session (and, for FRP, for frps to open a forwarded port). If it does not come, both servers go back to the old carrier on their own. When the foreign panel cannot be reached, nothing changes unless you choose to swap this side only, and then you get the new bundle for the foreign Setup.
- Peer tunnels really switch now: their engine, transport and FRP protocol in the edit dialog only rewrote `peers.json`. Those fields are gone from the dialog; the old engine's unit and config are removed after a swap (with its UDP companion), the new ones are written, and `peers.json` follows.
- A foreign server introduces itself to its hub with its tunnel token, so the hub learns where its panel answers even on a port other than 7777 (`tunnel_links.json`). That token opens the handshake and ping only.
- `POST /api/tunnel/swap`, `GET /api/tunnel/swap?id=N`; on the foreign side `POST /api/peer/swap-carrier` and `GET /api/peer/swap-status`. `/api/status` gives the base tunnel's `carrier_id`.

### A cleaner Tunnel tab
- **Traffic usage** has the total, received and sent as tiles, a stacked chart per day (or per few minutes for 1 h to 24 h) and one row per server with its share; the old table ran its columns together. **The hub total is never below what the tunnel interfaces carried**: a tunnel whose own counter reads nothing (an FRP-only foreign server) made it 0 B next to hundreds of GB.
- **GRE wrap** (the old "Carrier" card, renamed so it is not confused with the tunnel carriers) picks Direct GRE or WSS from two tiles, with the WSS port and SNI in their own panel.
- **Fleet health** draws the same map as the dashboard.
- A tunnel card's forwarded ports read "9 ports" instead of a list that ran out of the card (the chips above list them), and the one-line tunnel strip follows the tunnel's health instead of its GRE ping (an FRP-only tunnel no longer reads "down"); with a single tunnel it is not shown.

### For AI assistants
- `AGENTS.md`, `CLAUDE.md` and `.github/copilot-instructions.md`, plus notes in the license code: the Pro features need a license from the author, so assistants must not remove or bypass the license checks, change the trusted keys, or create license keys.

### Smaller changes
- **A linked hub on another version is flagged** in the Cluster tab (hub table and inspector), with the Update tab's "Different" / "Older version" badge: the cluster needs the same version on every hub.
- **`hashem doctor fix` is the Diagnostics tab's Quick Repair.** It only ran the sysctl tuning; it now diagnoses, repairs what the tab's button repairs (tuning, the measured path MTU, forwarding, FRP limits, a missing GRE interface, a stopped engine) and diagnoses again, through the new `gre-panel doctor [check|fix]`. An older panel binary keeps the old tuning-only repair.
- The measured speed is never negative: a fast run inside one tick of the clock (Windows) read 0 seconds and the speed overflowed to about -9×10¹⁷ Mbit/s.

## v2.5.0 — 2026-10-19

The cluster (several foreign servers behind one Iran port, several Iran hubs, DNS failover) with a live, clickable map; a path test before any tunnel; every tunnel engine in Setup; `hashem` as a terminal app. Update every server: the cluster needs the same version on all of them.

**Upgrade notes**
- `cluster.json` from the first cluster is upgraded by itself: the hub id and linked hubs stay, the old foreign-server list goes (it sent users outside the tunnel). Make pools instead: add the first foreign server, New Pool on its port, then add the others with the same port.
- Tunnels from the old `hashem-backhaul.sh` ("Modified Backhaul") move into Hashem by themselves at the first panel start.
- Performance, Watchdog, Benchmark, the Path Test, Backhaul setup and Diagnostics are Hashem Pro. Every existing Pro key opens them; settings and tunnels that already run keep running without a license.
- Bagher has no tab of its own any more: it is an engine in Setup and a card in Tunnel.

### Cluster: any scenario, and the guide
- **A second foreign server on a pooled port can be added from Setup.** The panel's port check refused it (only the script knew about pools), so the main way to grow a pool failed in the panel.
- **[How it works, and a hands-on tutorial](docs/CLUSTER_TUTORIAL.md)** ([فارسی](docs/CLUSTER_TUTORIAL.fa.md)): what happens to a connection and to a failure, then ten lessons from the first pool to DNS failover, breaking things on purpose.
- **Cluster map.** The Cluster tab opens on a live picture of the cluster: users, DNS and the linked Iran hubs, this hub with its pools, the foreign servers. Lines are as thick as the share of new connections they carry and colored by health (moving dashes show traffic). Click any box or line: an inspector edits it in place (pool mode with one click, port, protocol, service check, failback, enable, delete; a member's weight slider, priority, port, connection limit, standby, drain, remove; hub settings and health check; DNS; unlink a hub; join or leave a hub on a foreign server). Polls never wipe what is being typed; List keeps the tables. Phones get a pannable map centered on the hub, with the inspector below.
- **Service check.** A pool can connect through each foreign server to the service behind it (xray, sing-box, SSH…) every 1-60 seconds. A server whose tunnel is up but whose service refuses or drops the connection is taken out (Fall/Rise apply), with the reason in the tab and an event.
- **Standby members and connection limits.** A standby member gets traffic only when no other member is healthy and has room, in every mode. A member at its connection limit takes no new connections until it drops below 90% of it; the overflow goes to the others, then to standby members, and when every member is full the pool still serves.
- **Least connections mode.** New connections go to the members with the fewest open connections per unit of weight, counted from the kernel's socket table, re-weighted every 5 checks so the rules do not change every second. Best for long VLESS / VMess / SSH connections.
- **Manual failback.** In failover mode, traffic can stay on the backup after the first server comes back, until you press Fail Back Now (`hashem cluster pool failback PORT`).
- **Open connections per member** in the Cluster tab, in `/metrics` (with pool state, member health and share, linked hubs), and as the input of least connections.
- **Several ports at once:** `443, 8443` or `2000-2005` in New Pool, or `hashem cluster pool add 443,8443`.
- **DNS failover by webhook**, for any DNS provider: the leading hub POSTs the working hubs' IPs (with an optional bearer secret) whenever they change.
- **Disabling a pool no longer restarts its relays**, which then fought over the same public port: the port goes to one tunnel (the lowest id) until the pool is enabled again.
- **Terminal:** `hashem cluster pool set` (mode, service check, failback), `pool failback`, `member set --backup --max-conn`, and the same in the Cluster menu.
- **Cluster lab in CI:** two real frps and a real Backhaul server in a network namespace, with their clients in front of a service in three more: balance, a dead service behind a live tunnel (FRP and Backhaul), a dead tunnel, a standby member and sticky users, with the measured failover times in the job.
- **[Cluster guide](docs/CLUSTER.md)** ([فارسی](docs/CLUSTER.fa.md)): every scenario step by step (active/standby, balance, sticky, latency, standby and overflow, service check, maintenance, several Iran hubs, linked hubs, DNS failover, full mesh), the settings, the timing, the commands, the API and troubleshooting.

### Cluster, rebuilt: pools, linked Iran hubs, DNS failover
The first cluster sent users' traffic straight to the foreign servers' public IPs, outside the tunnel, and its peer hubs only exchanged an unsigned status. It is replaced; `cluster.json` is upgraded by itself (the hub id and linked hubs stay, the old foreign-server list goes, with a note in the cluster's event log).
- **Pools: one Iran port, several foreign servers.** Add the foreign servers in Setup as usual with the same port (two peers may now share a port when it is in a pool), then New Pool. The relays of the pool's tunnels (frps / backhaul-server) listen on a private address (`169.254.77.N` on the `hashem-lb` interface) and kernel DNAT sends each new connection to a working one: no process in the data path, the client's real IP still reaches the relay (PROXY protocol keeps working), and a panel restart or update drops nothing. Modes: **Failover** (priority order), **Balance** (by weight, per connection), **Sticky per user** (each source IP always on the same foreign server, so its exit IP does not change; weighted rendezvous hashing, so only the users of a server that leaves move) and **Lowest latency** (moves only when another server is clearly faster for 10 s). A member can be drained for maintenance. Tunnels whose ports include a pool port join it by themselves; a removed one stays out.
- **One-second health check per foreign server.** A link is out when its control session is gone, or when it stops answering ping on the path the relay really uses (only for links that answer ping; filtered ICMP never takes a working link out). Three failed checks take it out, three good ones put it back (Settings in the tab). frpc's health check (Performance) also takes a single service out. When no member passes, the pool tries every relay that still listens rather than refusing everyone. UDP flows of a server that left are dropped from conntrack so they move at once.
- **Linked Iran hubs.** Show Join Code on one hub, Link a Hub on the other: the hubs exchange a heartbeat every 3 s, signed with the cluster secret (HMAC-SHA256, timestamp and nonce; a replay or another secret gets a plain 404). When every member of a pool is down on one hub, its port is forwarded (DNAT + MASQUERADE, Iran to Iran) to a hub where the same pool works; a hub that forwards itself is never a target, so it cannot loop.
- **DNS failover (Cloudflare).** A record that always lists the Iran hubs that work, so users who connect by name move to a working hub. Only the reachable hub with the lowest id writes it; records that are not a hub's IP are never touched, and a proxied (orange cloud) record is refused.
- **A foreign server can serve several Iran hubs** (`hashem join-hub --bundle ...`, or Cluster on the foreign server's panel): a second frpc / backhaul-client with its own GRE interface, or dialing the hub's public IP when the bundle's GRE addresses are already used. `hashem hubs`, `hashem leave-hub --id N`.
- **New Cluster tab**: pools with where traffic goes now, per-server health, latency and share; the tunnels with their one-second health; linked hubs; DNS failover; health check; the kernel rules; an event log. Pool state changes go to the alert channels (webhook / Telegram). Terminal: the Cluster menu in `hashem`, and `hashem cluster status | pool | member | join-code | add-hub | events | rules`.
- **Tested on a real kernel** (privileged container, iptables nft and legacy): balance, stickiness, failover to another port, pass-through ports, an atomic rules swap and forwarding through a DROP forward policy. Uninstall removes the rules, the interface and the extra-hub units.

### Terminal app, HTTPS certificates, Buy License
- **`hashem` is a terminal app.** Arrow keys (or j/k) move, Enter opens, a number jumps (two digits for 10 and up), Esc, q or Left goes back. Every screen has the same header: role, tunnel up or down, panel running or stopped, license, and the panel address. Each menu remembers its row. The menus follow the panel tabs: Status, Setup, Tunnel, Bagher, Cluster, Performance, Watchdog, Diagnostics, Logs, Backup, Update, Settings, Uninstall. Without a terminal (a pipe, `TERM=dumb`, `HASHEM_PLAIN=1`) the same menus are numbered prompts, and end of input leaves cleanly. Everything is English; the status marks are plain `[OK]` and `[!]` instead of emoji, which broke the alignment in many SSH clients.
- **The terminal asks for Hashem Pro where the panel does.** `hashem perf`, `hashem watchdog`, `hashem doctor` and `hashem backup now|schedule` need the license (the same check as the panel: `gre-panel license check`), and the app's Performance, Watchdog and Diagnostics menus open a page with Activate a license key and Buy a license instead. What keeps applied settings running stays free: the watchdog timer and its tick, `watchdog check`, the Auto Pool tick, `perf apply` and the update's re-apply, `doctor stop-server`, and backup restore, status and key (nobody is locked out of their own data). `hashem perf tcpmux` stays free too: a tcpMux mismatch stops a free FRP tunnel from logging in, and the error tells you to run it. The refusal names https://pdnczone.com.
- **Everything the panel does, from the terminal.** New: `hashem tls status|issue|renew|remove|ip|custom` (the Settings tab's HTTPS card), `hashem settings show|2fa off|terminal on|off|terminal-allow|idle N` (two-factor can be turned off when the phone is lost), `hashem perf proxy-protocol|bandwidth|health-check|backhaul-pool`, and menus for the cluster, backup, update channel and logs. They run the panel's own code through `gre-panel tls` and `gre-panel settings`, then restart only the panel.
- **Fixed in the terminal:** Ctrl+C in a live log quit Hashem instead of going back; the header showed `http://127.0.0.1:7777path/` (a function that did not exist, and no slash); the Performance menu printed its status over and over without clearing; `hashem panel-tls DOMAIN EMAIL` still asked for the email; `hashem license activate` stored any text as the key (it is now checked first, and a bad key never replaces a good one); the license status needed jq; "Refresh system packages" did not refresh them; the script version line was empty.
- **Let's Encrypt in Settings fixed.** certbot is installed when it is missing (apt, dnf, yum or snap) instead of an error; ports 80 and the HTTPS port are opened in ufw or firewalld; a busy port 80 names the program that holds it; the error shows certbot's reason (for example "Timeout during connect (likely firewall problem)") instead of its whole log; the certificate is named after the domain (`--cert-name`), so a second issue no longer lands in `domain-0001` while the panel reads the old one; certbot has a time limit. When DNS does not point here (a CDN, NAT) the panel asks whether to try anyway instead of stopping.
- **Renew and auto-renew follow how the certificate was made.** Renew Now regenerates an IP certificate and runs certbot for Let's Encrypt; a custom certificate cannot be renewed here (the button hides, and the API answers `E-TLS-14`). The hourly auto-renew no longer copies certbot's certificate over a custom one for the same name, nor calls certbot for IP certificates. "Renewed" now says when Let's Encrypt found it not due yet. The card names the kind of certificate.
- **The web Terminal tab stays English and left to right** in the Persian panel.
- **Donate is now Buy License.** The popup and the Settings card sell Hashem Pro and link to the site; the popup never shows once a Pro license is active. The command palette item is "Buy a Hashem Pro license", and the installer's last line points to the license.

### FRP options, PROXY protocol, Watchdog, Benchmark
- **PROXY protocol fixed.** The Edit Peer window on the Iran server had PROXY Protocol, Encryption and Compression switches that only wrote peers.json: these options live in the foreign server's frpc, so nothing changed. They are now set where they apply, in the foreign server's Performance tab (FRP Transport), and Edit Peer says so. The Join form still sets PROXY protocol at setup, and the choice is kept in perf.json, so updates (which re-apply perf.json) never drop it. A PROXY protocol chosen before this release stays as it is until it is changed here. The hints say to turn on acceptProxyProtocol in the Xray inbound first: without it every connection fails.
- **Every FRP proxy option in one place.** FRP Transport on the foreign server: encryption, compression (shown again), TCP multiplexing, PROXY protocol (off, v1, v2), a bandwidth limit per port (`transport.bandwidthLimit`, MB/s, 0 = none) and a health check (frpc closes a port on the Iran server while the local service is down). `perf apply` writes them into every `[[proxies]]` block (PROXY protocol and health check on tcp only), a new setup or an engine switch to FRP writes them too, and applying twice changes nothing. The defaults stay off: on VLESS, Reality and Trojan the first three only cost speed, and PROXY protocol breaks a service that does not expect it.
- **Watchdog: Backhaul without GRE was always "down"** on the Iran server: the check pinged a GRE peer that does not exist, which meant false Telegram alerts and, with auto-restart on, a restart loop. A healthy Backhaul session now counts on both sides, hubs whose tunnels are all added peers (`backhaul-server-N`) are checked, and the detail line says "Backhaul session up" instead of an empty GRE ping.
- **Watchdog and Benchmark are Hashem Pro** (`watchdog`, `benchmark`; every Bagher / Pro key opens them). Locked: the tabs, `/api/watchdog` (with backup download) and `/api/benchmark`. A watchdog that already runs keeps its alerts, backups, schedules, Auto Pool and dial watch without a license. Both tabs show the lock in the sidebar.
- **Buy License** in the license window and in Settings opens the Hashem site.

### Performance tab
- **Performance is Hashem Pro** (`performance`; every Bagher / Pro key opens it, no new key). Locked: the tab and `/api/perf`. Settings already applied keep working without a license: Auto Pool keeps sizing the pool from the watchdog, and an update still re-applies perf.json.
- **A lock marks every tab that needs a license** in the sidebar and the phone menu: Performance, Diagnostics and Cluster (Hashem Pro), and Sentinel (its own add-on). It hides once the key opens the tab. The license is now read right after sign-in, so the locks are right from the first page.
- **Backhaul connection pool.** A Backhaul server had nothing to tune here. The new card sets `connection_pool` on the foreign server (1 to 64, default 8): the panel rewrites that one line in the running client config and restarts `backhaul-client` only when it changed. The value is kept in perf.json (`backhaul_pool`), so a Backhaul tunnel set up later, from the panel or `hashem.sh`, is written with it. On the Iran server the card says to set it on the foreign server.
- **Only the cards of this server's engine show**: FRP Transport and Auto Pool on FRP servers, the Backhaul pool on Backhaul servers, neither before a tunnel exists. The overview follows the engine too.
- **Carrier moved to the Tunnel tab.** Direct GRE or WSS is how the tunnel gets through, not a speed setting, so it stays free and sits with the tunnel.
- **Removed:** the Proxy Compression switch (encrypted traffic such as VLESS, Reality and Trojan does not compress, so it only cost CPU; it still shows while it is on, so it can be turned off) and the Save Without Restart button (Apply & Restart Tunnels does the job; the change waits marked Unsaved until then).

### Hashem Pro
- **The Path Test, Backhaul and Diagnostics are Hashem Pro**, next to Bagher. Locked: starting or joining a path test (panel and `gre-panel pathtest`), setting up a Backhaul tunnel with or without GRE (Setup, switching the engine to Backhaul, and `hashem backhaul` / `setup-backhaul-*` / `setup-gre-backhaul-*` / `add-backhaul-peer` from the shell, which ask the panel binary: `gre-panel license check backhaul`), and the Diagnostics tab and `/api/doctor`. Each shows PRO and opens the license window naming the feature. GRE + FRP stays free.
- **No new key for existing customers.** Every license that unlocks Bagher (`bagher`, `frp_ssh`, `*`, `all`, or no feature list) unlocks every Pro feature, including ones added after it was issued; a key may also name `pathtest`, `backhaul` or `diagnostics` alone. Sentinel and Cluster keys stay separate add-ons. `/api/license` lists what the key opens (`pro_features`), and Settings shows it.
- **Running tunnels are never taken away.** A Backhaul tunnel that already runs keeps running, restarting, being repaired by the watchdog and moving between GRE and the public IP without a license; only a new setup needs it.
- **The license survives updates.** An update replaces only the binary; the key stays in `/etc/gre-panel/license.key`, `/etc/hashem/license.key` and `panel.json`, and the new binary loads it at start. A new test activates a Bagher-only key, then starts the panel again the way an update does (also with `license.key` deleted and the key only in `panel.json`): every Pro feature is open each time with nothing entered again.

### Path test before any tunnel
- **Which transports get through, before you build a tunnel.** New card at the top of the Benchmark tab. On the Iran server press Start Test: for a few minutes (10 by default) it runs throwaway servers for every transport and shows a code. Paste the code on the foreign server's Benchmark tab: it dials all of them with the real cores, the same way a tunnel would. Both panels then show one table, each row Works / Blocked with latency and speed: plain TCP and UDP, GRE (protocol 47), SSH from Iran to the foreign server (Bagher), FRP `tcp`, `websocket`, `wss`, `kcp`, `quic` and Backhaul `tcp`, `tcpmux`, `ws`, `wss`, `wsmux`, `wssmux`, `udp`. A row only says Works when data pushed from Iran came back byte-exact through that transport; a port that merely accepts is not enough. Nothing stays behind: the processes run under `timeout`, the test GRE interface (`hpt0`, keyed, so it does not touch a real GRE tunnel) and any ufw openings are removed at the end. Missing cores are downloaded once (`hashem download-cores`).
- **Safe next to a running tunnel.** Left empty, the first port is the first free block from 41000, so a tunnel already on those ports is never touched (a port you enter that is taken is refused with the reason). The test's GRE interface `hpt0` is keyed, so it lives beside the tunnel's GRE to the same server; the carrier switch and the diagnostics' GRE lookup in `hashem.sh` skip it. A ufw rule that existed before the test is kept when the test ends. The Iran side fills in the foreign IP from the running tunnel.
- Ports: the first port and the next 10, TCP and UDP, on the Iran server. Enter your real tunnel's port to test that one.
- Also from the shell: `gre-panel pathtest serve` on Iran, `gre-panel pathtest join CODE` on the foreign server; both print the table when every check has an answer.
- Checked in a new lab that runs in CI (`tests/test_pathtest_lab.sh`, real FRP v0.71.0 and Backhaul v0.7.2 in two network namespaces): with an open path all 16 checks work and every TCP transport gets a speed; with UDP, GRE and one port dropped towards Iran exactly those checks say Blocked and the rest still work; next to a live GRE + Backhaul tunnel on port 41000 the test moves to 41040 by itself, all 16 checks work and the tunnel carries data every half second all through the test without one miss; nothing is left running afterwards.

### All tunnels in one place
- **Bagher moved into Setup and Tunnel.** It had its own tab with its own role buttons, forms and status boxes. Now it is the third engine in Setup (GRE + FRP, Backhaul, Bagher): the Iran side fills in the foreign IP and ports (SSH port, user, pool and internal FRP port under a fold) and gets the bundle in the same box as the other engines; the foreign side pastes the `BAGHER:` bundle into the same bundle field as `hsh1_`/`bh1_`/`gh1_`. The Tunnel tab's Bagher card runs it: start, stop, copy bundle, quick edit, clear DNAT conflicts, remove. Old links to the Bagher tab and the Benchmark's Bagher carrier open Setup with Bagher picked. Without a license the engine shows PRO and a note with an Activate button; the license window opens on Apply, and closing it no longer sends you to the Dashboard.
- **Backhaul is one engine.** "GRE + Backhaul" and "Backhaul (No-GRE)" were two engines that only differ by the GRE underneath. Setup now has one Backhaul with "Run Backhaul over GRE? With GRE / Without GRE", and the script's Backhaul menu has one Iran setup that asks the same question. The same names everywhere: GRE + FRP, Backhaul (with GRE), Backhaul (no GRE), Bagher.
- The foreign side of Setup asks for the route to Iran (Auto, GRE only, public IP only) when the bundle uses GRE, and `hashem backhaul` has a route item.
- Switching the engine in Setup starts from that engine's own transport (Backhaul came up on `tcp` after FRP instead of `tcpmux`).

### Route to the Iran hub
- **Back to GRE by itself.** In auto mode the watchdog moved a foreign client to the hub's public IP when GRE died, but never back: the client stayed on the public IP until someone ran `hashem dial auto`. Now, after GRE carries the control port for 5 checks in a row (one a minute; ping alone is not enough, some paths pass ICMP and drop TCP), the client moves back to GRE. If it cannot connect over GRE, it returns to the public IP and waits 30 minutes before trying again, so a half-working GRE does not make the tunnel flap. UDP transports (Backhaul `udp`, FRP `kcp`/`quic`) are judged by ping.
- A Backhaul setup without GRE removes the route state an earlier GRE setup left, so the watchdog does not chase a GRE address that no longer exists.
- Checked in a new lab that runs in CI (`tests/test_tunnel_combos_lab.sh`, real Backhaul v0.7.2 and FRP v0.71.0 in two network namespaces with GRE): all 7 Backhaul transports and UDP over `tcp`, with GRE and without GRE (GRE dropped), link and data; GRE blocked at setup goes to the public IP, GRE back returns to GRE after the 5th check with data over GRE, GRE dead goes public again; the same for GRE + FRP.

### Backhaul
- **One Backhaul, inside Hashem.** The separate `hashem-backhaul.sh` ("Modified Backhaul v2.0.0-hotfix8") is gone. It wrote the sectioned v2 config, but Hashem installs upstream Backhaul v0.7.2, which stops with `neither server nor client configuration is properly set`; none of its tunnels could start. Its IPX, ICMP, TUN, anytls and xtcpmux transports need the paid Backhaul Premium core, which Hashem never shipped. `hashem backhaul` (also from the Tunnel and Quick Setup menus, and the old `hashem modified-backhaul`) now opens Hashem's own Backhaul menu: set up Iran with or without GRE, join a foreign server from a bundle, status with the real link state, logs (tokens hidden), restart, and the bundle for the foreign server.
- **Old tunnels move in by themselves.** `hashem backhaul-migrate`, which the panel also runs once at start, turns each `backhaul-iranN` / `backhaul-kharejN` from the old script into Hashem's `backhaul-server` / `backhaul-client` with the same port, transport, token and ports, so the panel, watchdog, backup and uninstall see it. A tunnel on a transport the core lacks is retired with a notice; its config is kept in `/etc/backhaul/legacy`. A tunnel whose core really is v2.x is left alone.
- **More than one port from the menu works.** The menu wrote `"443 2083"` as one entry, and the core refused to start. Ports may now be separated by commas or spaces everywhere.
- **The port forms the core accepts:** `443`, `10000-10050`, `2083=8443`, `10000-10050=443`, with an optional `IP:` on either side, in the menu, CLI and panel. `10000-10050:443` (from Backhaul's README, rejected by the core) is rewritten to `10000-10050=443`.
- **UDP.** New `udp` transport (UDP only), and "Also forward UDP on these ports" (`--udp`) for the `tcp` transport in the menu, CLI and Setup tab. Checked on the real core: `accept_udp` works only with `tcp`.
- An unknown transport is refused before anything changes (it used to produce a server that never started), the menu offers a numbered list instead of free text, and `add-backhaul-peer --bundle` uses the bundle's transport instead of always `tcpmux`.

### GRE + Backhaul setup
- **Replacing a tunnel stops the old engine.** No setup stopped the other engine's services: after setting up GRE + Backhaul over GRE + FRP (or the other way round), `frps`/`frpc` kept running next to Backhaul on the same ports, the panel went on showing FRP, and Optimize restarted FRP from its old config. Every setup now stops and removes the other main relay (its config was already backed up). Extra peers stay. Backhaul without GRE also removes the old main GRE interface, which made the panel report GRE + Backhaul.
- **The foreign summary says what really happened.** It reported "connected" as soon as the service started, and always named the GRE address. It now waits up to 15 s for the control channel and shows the address it dialled (GRE, or the public IP when GRE does not answer). A wrong token or transport now fails the setup with the reason, and an Iran side that does not answer yet is a warning. Same for Backhaul without GRE.
- **New `E-BH-04`: transport mismatch.** With `tcp` on one side and `tcpmux` on the other (or `ws`/`wsmux`), the control channel comes up but no connection works. Diagnostics, the log view and the watchdog now recognise the core's lines for it instead of calling the link healthy.
- Checked in a GRE lab that now runs in CI (`tests/test_gre_backhaul_lab.sh`: two network namespaces, real GRE with MTU 1380, Backhaul v0.7.2): the foreign side picks the GRE address, 1 MiB arrives byte-exact, it falls back to the public IP when GRE is blocked, and the failures above are reported as described.

## v2.3.6 — 2026-10-18

Audit fixes, a Persian UI, a redesigned dashboard, and working Bagher, Diagnostics and engine switch. Update both servers.

The release was rebuilt the same day with the Dashboard, Performance, Setup, Update and Diagnostics changes below; a server that installed the first v2.3.6 build gets them with `hashem update` on the server (the Update tab sees the same version number and offers nothing).

### Diagnostics
- **Quick Repair fixes the MTU it finds.** Diagnostics reported "Packets of 1380 bytes do not cross the tunnel" but left the fix to the user, and even a manual fix did not last: `hashem.sh` set MTU 1380 and MSS 1340 again on every tunnel restart, carrier switch and Optimize. Quick Repair now saves the measured size in `/etc/gre-panel/gre_mtu`, lowers the GRE interfaces to it and replaces the larger MSS clamps with MTU − 40. `hashem.sh` honours that file wherever it sets the MTU or the clamp, the panel re-checks it every minute (for an older `hashem.sh`), and the Network Stack card shows the held value. Removing the tunnel clears it.

### Update tab
- **Automatic rollback that actually happens.** The old binary was kept as `.bak`, but nothing put it back if the new version did not start, so the panel stayed down (the confirm dialog promised a rollback). Now a short-lived systemd unit outside the panel's own service waits 60 s after an update; if the new binary has not started listening by then, it restores the previous one and restarts the panel. The tab then says which version failed and that it went back, and the error log records it (`E-UPDATE-09`).
- **Check Now works.** On an up-to-date panel the Check button was disabled, so it could never be pressed. It now asks GitHub again instead of answering from the 10-minute cache (at most every 30 s), and a failed check no longer retries every 5 s forever.
- **The page waits for the new version.** It reloaded as soon as `/api/health` answered, which the old panel often did before restarting, so the page came back on the old version. It now waits until the version changes and shows the steps: download and verify, restart, reload.
- **What's New:** release notes for every version between the installed and the latest one.
- **Other server:** shows the linked server's panel version and says when the two differ (peers now report their version).
- Installed and available versions side by side, last-checked time, release dates in the version list, the installed version cannot be "reinstalled" from it, and older versions moved under "Install a specific version". Fully translated to Persian.

### Setup tab
- **A foreign server could not join an Iran server set up with KCP, QUIC, WebSocket or WSS.** That bundle has eight parts (`…_fou443-55555_tr-kcp`) and the Setup form refused anything over seven. It now reads the transport too, shows it, and locks the FRP transport list to it (the server applied the bundle's transport anyway, whatever the list said).
- **Add Another Server Instead** (shown when the form is locked) did nothing; it now jumps to the add-server form.
- Joining from a foreign server that already has a tunnel asks before replacing it (it replaced it silently).
- Encryption and compression chosen while joining are saved to the performance settings too. Before, the Performance tab showed them as not applied and the next update removed them from frpc.
- The public IP lookup asks over IPv4 only: on a dual-stack server behind NAT it could fill in the IPv6 address, which GRE and the bundles cannot use.
- A new server's suggested control port and GRE pair skip the ones already in use (it suggested 7000 next to a tunnel on 7000), and the form clears after adding so the next suggestion is fresh. The added server's bundle has a Copy button.
- After an Iran setup the form locks right away instead of offering Apply again. The bundle info no longer turns later error messages blue, options a Backhaul bundle does not use are hidden, the diagram follows the chosen engine, the panel no longer calls `/api/setup` on every 15-second refresh, and plain TCP is no longer labelled "Multiplexed".

### Performance tab
- **Says what applies here.** On a server with no tunnel or with Backhaul, the FRP settings are greyed out with a note instead of offering an Apply that fails. On the Iran server, encryption and compression are greyed out: frps ignores them, they are set on the foreign servers. A hub with only numbered `frps-N.toml` files is now recognised as the Iran server.
- **New Network Stack card:** live congestion control and queue, socket buffers, connection-tracking use (warns at 70 % full), GRE MTU, MSS clamp and whether the settings survive a reboot, with Optimize Network and Restore right there.
- **FRP transport:** an "Unsaved changes" marker, Save is disabled until something changes, the top Apply button only shows when the running config differs, and the multiplexing line reads "In the running config: On / Off / mixed".
- **Auto Pool:** decisions in words (Scaled up, Waiting, …), last check time, and manual pool sizes are checked as you type. The API now refuses out-of-range values (pool 2–1000, max 10–2000) instead of ignoring them silently.
- **Carrier card:** the leftover FOU wording and fake "Manual / Auto Failover OFF" box are gone. It shows the active carrier, the ping to the other server ("No tunnel" instead of "Packet Loss / Link Down" when there is no GRE interface) and the WSS state. Switch Carrier asks first and is disabled until you pick a different carrier.
- **WSS settings:** a new port now moves the active carrier and Cycle to that port (they kept the old one), an empty SNI clears it, the saved SNI is shown, the port is validated, and the response no longer includes the WSS auth token.
- Fully translated to Persian; numbers and ports keep their order in RTL.

### Dashboard

- **Status hero:** one card answers "is the tunnel up": Healthy / Degraded / Down / Not set up, the first reason when it is not healthy, this server ⇄ the other server with their IPs and the engine chips (GRE, FRP, Backhaul, Bagher; GRE is not shown as a fault on engines that do not use it), and latency rated Good / Fair / High instead of always "Optimal".
- **Live traffic:** download and upload rates are the numbers; the lifetime total is a footnote. A separate Connections card shows the current count and the peak over the chart range.
- **Charts:** colors come from the theme tokens and match the legend (the connections legend was violet on a green line). A stopped tunnel greys the history instead of drawing it red. The axis uses round values in one unit (20 / 15 / 10 MB/s, not 18.6 GB/s and 512 KB/s), and rescales at once after a spike. The connections chart says what it counts: established TCP/UDP connections on the server.
- **Details:** no green "Stable / Zero Drops" and red "Down" before anything is set up; GRE and engine cards appear only when they exist; Role shows Iran/Foreign server (it never matched before); failover reads Automatic / Manual; times are local.
- **System:** CPU, RAM and disk as ring gauges colored by load, with uptime.
- **Tunnels table** for multi-peer hubs: status, foreign IP, engine, ports, ping and traffic per peer; a row opens its card in the Tunnel tab.
- Layout follows the space the dashboard has (container queries), so the activity side panel no longer squeezes it; works at 375px and in RTL.
- **Donate popup** now appears on the first visit after install ("Thanks for installing Hashem"), not only after a tunnel has been healthy, then every 7 days while the tunnel is healthy (30 days after "Don't remind me", 90 after Donate). It and the Settings/palette links point to pdnczone.com; the installer's final screen prints the link too.

### Upgrade notes (this release)
- **Bagher:** after updating, re-apply the bundle from the Bagher tab on the foreign server once. Its frpc config is only rewritten then (the old one made frpc exit at start). The Iran key line in `authorized_keys` is tightened automatically when the panel starts; other keys are not touched.
- **iPerf3** (Diagnostics) now listens on the GRE address only, not on every address.
- **Switch Engine** from the Iran server switches the linked foreign server too and says whether it did.

### Bagher, Diagnostics and Tunnel tab
- Bagher carried no data: the generated frpc config had an frps-only field, so frpc exited on start. Tested end to end in a three-namespace lab (`tests/test_bagher_lab.sh`, now in CI).
- Security: the Iran key could run commands as root on the foreign server and open forwards to any local service there. It is now limited to its one reverse forward.
- Live engine switch always failed with `invalid engine ""` (request field name mismatch). The foreign side is now told and waited for (40 s), and the result is shown.
- Diagnostics: no more false "MTU fragmented" on every GRE server (it probed 1420/1400 on a 1380 interface); ping now runs inside the tunnel and, separately, to the peer's public IP; Backhaul and Bagher servers are judged by their own engine instead of scoring 20/100; issues and their fixes no longer drift apart; Quick Repair adds the installer's MSS rule and restarts a stopped engine.
- Tunnel tab: Restart on Backhaul servers restarted a non-existent frps; Copy Bundle never showed; GRE cards on GRE-less servers; Bagher shown as active when only enabled; carrier and engine switches now ask first; Restore shows whenever a backup exists.
- Dashboard: throughput chart spikes when the traffic source changed; Details values overflowing their cards; Diagnostics showing login errors as tunnel errors. Live Activity Stream is a structured event feed. Browser tab icon and a premium tier mark.

### Design review (Apple HIG) and Persian UI

Review of the panel UI against Apple's Human Interface Guidelines, then fixes in seven phases.

#### Upgrade notes
- **FA mode is now Persian.** It used to switch the layout to right-to-left but keep English text. Switching language reloads the page.
- **Theme follows the system** until you pick one with the theme button.
- Before a tunnel is set up the dashboard and Diagnostics show a neutral "Not set up" state instead of red errors.

#### Fixed
- Contrast: white text on the default blue was 3.6:1, light-theme status colors 2.3–3.7:1, several badges and the login button below 4.5:1. Every tab now passes 4.5:1 in both themes.
- A Bagher button referenced a function that did not exist; the error stopped `app.js` during load, so Sentinel, Cluster, license and later handlers never initialised. Two more missing handlers defined.
- Six dialogs ignored Escape and did not keep keyboard focus; all nine now do.
- Performance, Settings and Benchmark scrolled sideways on phones; the light-theme chart tooltip was unreadable; the login page stayed dark in the light theme; undefined CSS variables rendered square corners and missing borders; the Diagnostics repair button could not be hidden.
- Benchmark recommended a carrier that never answered (0/100, 100% loss); it now says no carrier answered and what to check.

#### Changed
- Design tokens for every color (about 500 hard-coded colors replaced), 12px text floor, tabular figures, quieter depth (no glows or hover lifts), one primary button per card, Title Case buttons.
- Emoji replaced by an SVG icon set; 470 inline styles moved to utility classes; 26 fields gained accessible labels.
- Topbar link strip: this server ⇄ the other side · engine · latency, with one live dot.

### Audit fixes (docs/audit/BUG_REPORT_2026-10-17.md)

Fixes for the 61 findings of the 2026-10-17 code audit, plus the Sentinel addon. IDs (C1, H4, …) refer to the report.

#### Upgrade notes (behaviour changes)
- **Reverse proxy on the same server (nginx/Caddy):** loopback is no longer trusted for `X-Forwarded-For` by default. Add `Environment=TRUSTED_PROXY_IPS=127.0.0.1` to `gre-panel` (`systemctl edit gre-panel`), or every visitor is seen as 127.0.0.1. The generated proxy configs say so.
- **Peer Link** works best with both servers updated: the peer API is now also served at the fixed prefix `/_hp` (peer secret only; bare 404 otherwise). An old peer is still reached when its full panel URL (with its base path) is entered as Peer URL.
- **Updates and installs fail closed** when `checksums.txt` cannot be fetched from github.com itself; set `GRE_PANEL_ALLOW_UNVERIFIED_UPDATE=1` to accept the risk.
- **Connectivity Rescue** no longer activates on its own; it shows the banner, and auto-activation is a separate opt-in toggle.
- **`hashem watchdog off`** turns off alerts only; the `hashem-watchdog` timer keeps running scheduled backups, scheduled restarts and Auto-Pool.
- Editing an FRP peer's ports on the Iran server no longer touches `frps-N.toml`; apply the ports on the foreign server too.
- The benchmark reports KCP/QUIC as "Not measured" and never recommends them; Apply refuses Backhaul/Bagher (use Switch Engine / the Bagher page).
- The peer limit is 10 everywhere (`GRE_MAX_PEERS` overrides it in the panel and in `hashem.sh`).

#### Security
- 2FA, terminal and TLS settings were wiped from `panel.json` on every restart of a licensed panel (C1).
- The stored password hash was accepted as the password (C2).
- Peer-supplied SSH keys could add an unrestricted root key or delete all root keys (C4, L18).
- License deactivation did not stick (H10); `X-Forwarded-For` via loopback bypassed the login lockout and terminal allowlist (H11).
- Downloads: checksum manifest only from GitHub, verified install in `hashem.sh`, no mirrors for unverifiable files (H12).
- WSS carrier refuses to run without a token (M12); revpath firewall fix limited to the peer IP (M10); token files are 0600 (M15); inline handlers can no longer be broken out of (L10, L11).
- Backup encryption key can be exported (`hashem backup key`, panel with password re-check) (M6).

#### Fixed
- Panel crash `concurrent map iteration and map write` in the cluster code (C3).
- Peer Link reported "Connected" while every call landed on the login page (H1); status writes no longer clobber settings (M13).
- frpc restarted every minute by two competing Auto-Pool controllers (H2); editing Iran peer ports broke frps (H3).
- Switch Engine: real ports only, GRE inner address, kcp/quic listeners, Backhaul v2 schema, health check and rollback (H4).
- Web terminal closed after 30 s without output (H5); installer killed after 60 s (H7); `add-peer --frp-transport` rejected (H8).
- Benchmark faked UDP/loopback results and Apply could leave the two ends on different carriers (H9, L13, L14).
- Let's Encrypt certificate is renewed and reloaded without dropping the HTTPS connection (M7).
- `hashem cluster revert`, `panel-port|user|path`, `setup-foreign --bundle bh1_/gh1_`, `install_panel` stop/overwrite order, update restarting every tunnel, `fuser -k`, removal of unrelated tunnels, ephemeral port clashes, foreign control-port check (M1–M5, M18–M21).
- Private/CGNAT address reported as the public IP (M8); 5-second snapshot running ssh-keygen and IP lookups (M9); Doctor on GRE-less servers (M11); per-proxy options lost on port edits (M14); cluster UI fields (M16); bundles with default GRE IPs (M22).
- Plus L1–L9, L12, L15–L17, L19–L23 (error codes, telegram settings, backup dir, alerts after re-enable, LimitNOFILE source, fleet history, release-list caching, …).
- **Sentinel addon:** install/start/stop/uninstall errors are reported, the chosen port is honoured, concurrent installs are refused, credentials and URL are correct.

## v1.3.3 — downgrade list covers every release

### Changed
- The **Install a specific version (downgrade)** picker (`GET /api/releases`) now lists every published release of the channel, not just the newest 20. The panel pages the GitHub API (100 per page, up to 1000 releases).

## v1.3.2 — downgrade to any of the last 20 releases

### Added
- **Install a specific version from the Update tab** (`Install a specific version (downgrade)` picker, backed by `GET /api/releases`): choose any of the last 20 releases of the active channel and install it, newer or older. Downgrades keep the same safety as updates (SHA256 `checksums.txt` verification, `panel.json` preserved, automatic rollback on failure).
- `POST /api/update {"tag":"v1.1.0"}` now installs that exact release even if it is older than the running build; without a tag the behaviour is unchanged (newest of the channel).
- CLI `hashem update [tag]` (e.g. `hashem update v1.1.0`, `hashem update panel-r140`): validates the tag, then runs the normal update flow pinned to it. Plain `hashem update` still follows the channel's newest.

## v1.3.1 — rescue card always visible

### Fixed
- **Connectivity Rescue card now always shown** on the Tunnel tab. It was hidden until a one-way block was detected, so the Iran hub (the reachable/entry side) had no way to open **Join with code** and paste an `hrc1_…` rescue code.

## v1.3.0 — panel access control

### Added
- **Panel access settings** (Settings card + `GET/POST /api/access` + CLI `hashem panel-port|panel-user|panel-path`): change the HTTP port (1-65535, tunnel/reserved-port conflict checks), login username, and URL base path. Current password required; response carries the new URL and the UI redirects after `gre-panel` restarts. Tunnels untouched.
- **Custom SSL certificate install** (Settings + `POST /api/tls/custom` + `hashem panel-tls-custom <cert> <key>`): paste PEM, upload both files (multipart), or point at server paths. Pair validated with `tls.X509KeyPair` before anything is written; atomic backup/rollback; HTTPS reloads in-process.
- **Self-signed HTTPS on the server IP** (Settings + `POST /api/tls/ip` + `hashem panel-tls-ip [IP]`): persistent local CA (10 years) signs an 825-day server cert with the IP as SAN. `GET /api/tls/ip/ca` downloads the CA to install once in browser/OS. Regenerate rotates only the server cert so trust survives.

## v1.2.0 — traffic that stays

### Added
- **Per-server traffic ledger kept 7 days on disk** (`traffic_peers.json`): one point per minute for the hub total, the main tunnel and every foreign-server peer, plus per-day totals. It survives panel restarts, updates, crashes and reboots.
- `GET /api/traffic/usage?range=1h|6h|24h|7d` (admin session) and a **Traffic usage** card on the Tunnel tab: hub total, a 7-day bar chart and a per-server received/sent table.

### Fixed
- Traffic no longer disappears when the kernel counters restart. `/proc/net/dev` counters go back to zero when a GRE interface is recreated, a tunnel is removed and re-added, or the host reboots; the ledger stores per-interval deltas, treats a lower reading as a counter reset, and keeps its baseline across a gap so a returning interface does not produce a spike.
- Peers are keyed by id, so renaming a peer keeps its history.
- systemd log spam `Got notification message from PID n, but reception only permitted for main PID`: child processes (ping, ip, ss, systemctl) inherited `NOTIFY_SOCKET`. It is now removed from the panel's environment at start.

### Documentation
- Added `README.fa.md` (the language link in the README was broken), a Requirements section, an engine comparison, Troubleshooting, an Uninstall-and-your-data section and Known limitations.
- New guides: `docs/ENGINES.md`, `docs/TROUBLESHOOTING.md`; generated references `docs/API.md` (every route, its auth) and `docs/ERROR_CODES.md` (every `E-…` code), produced by `tools/gen_docs.py`; CI fails if they drift from the code.
- Added `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, issue forms and a pull request template.
- README: removed the dashboard screenshots, kept the architecture diagrams; documented installing with a pinned `HASHEM_SHA256`; password storage now described correctly as argon2id (README and SECURITY.md said SHA-256).
- Moved `AUDIT_REPORT.md` and `AUDIT_CHECKLIST.md` to `docs/audit/` and `CLAUDE.md` to `docs/dev/DEVELOPMENT.md`; the repository root now holds only the project files.

## v1.1.0 (2026-10-11) — plan r24 (docs/PLAN_IMPROVEMENTS_R24.md)

### Correctness
- Engine switch checks the binary and systemd unit **before** stopping anything, reports write/restart errors instead of "configured and started", and writes configs 0600.
- Backhaul config is read with a real TOML scanner (IPv6, comments, quoted `=`/`#`, multi-line arrays, sectioned dialect).
- Per-peer `backhaul-server-N` units are recognised.
- Doctor understands Backhaul failures (`E-BH-01..03`); the watchdog judges Backhaul by its control-channel session, not unit state.
- Panel logs mask tokens and passwords.

### Security
- Escalating login lockout, audit of every mutating API call, `GET /api/audit`, log rotation.
- Optional TOTP 2FA with recovery codes; optional idle session timeout.
- Terminal: password/2FA re-auth with a single-use ticket, IP allowlist.
- `install.sh` verifies the script (canonical source, mirror quorum, or pinned sha256).

### Operations
- Webhook/Telegram alerts on state change only; 24 h link history + graph; optional Prometheus `/metrics`.
- Backups cover all configs; safer restore with pre-restore safety copy.
- Carrier advisor (advice only), free-port and SNI suggestions.

### Added after the first r24 pass
- Host alerts for disk, RAM and panel TLS-certificate expiry, through the same state-change alert path (baseline tick, hysteresis, per-link gap).
- Link history now survives a panel restart (`history.json`, flushed on SIGTERM; a link must be missing 10 min before its history is dropped).
- Graceful shutdown on SIGTERM/SIGINT.

### Fixed
- **systemd watchdog kill loop**: units carried `WatchdogSec=30` while the installed panel binary predated the heartbeat, so systemd killed it every 30 s. `hashem.sh` now enables the watchdog only for a binary that implements sd_notify, and removes it otherwise.
- `setup.go` split into `setup.go`, `setup_bundle.go`, `setup_ports.go`, `setup_conf.go`, `peers_edit.go` (no code changes; all 51 declarations verified identical).
- Whole tree is gofmt-clean and CI enforces it; Backhaul e2e and GRE reverse-path labs run in CI on every push and weekly.

### Maintenance
- New `ci.yml` (vet, build, `go test -race`, gofmt on changed files, shell tests); fixed two data races found by `-race`.
- UI script moved from `index.html` to `app.js`; `spoof_test.py` moved to `tools/`.

## v1.0.0 (2026-10-10) — first stable-channel release

### Added
- FRP transports `tcp`, `kcp`, `quic`, `websocket`, `wss` with payload encryption, compression and PROXY Protocol v2; Persian UI with RTL layout; Fleet health and topology map.
- Update channels `stable` / `dev`: pick, upgrade or downgrade to any of the last 20 releases; `hashem update-channel`.
- Auto Pool: frpc `poolCount` / frps `maxPoolCount` sized from pool-full errors, load and RAM (on by default).
- Reverse-path auto-fix engine (dry-run by default, snapshot / apply / re-probe / rollback), per-tunnel health checks (PASS / FAIL / UNREACHABLE), multi-signal link health (session > TCP > ICMP) with debounce.
- Dial over the Iran hub's public IP when GRE is dead (`hashem dial`); hub-and-spoke topology view with the main tunnel as a plain spoke.
- TCP multiplexing toggle in the Performance tab and `hashem perf tcpmux` (off by default); `/api/selfstats`, in-process load lab, RAM-scaled unit limits and sd_notify watchdog.
- Connectivity Rescue: detect one-way TCP blocks and reverse the dial direction.

### Security
- Fail-closed SHA-256 verification of updates; CI publishes `checksums.txt` (M-01).
- WSS carrier rejects browser origins, constant-time token compare (M-02).
- argon2id password hashing with transparent upgrade of legacy hashes; random session ids (M-03).
- Security headers, server timeouts, request body limit, peer TLS pinning (TOFU).

### Fixed
- Removed obsolete `hashem-monitor` / `hashem-webui` units that crash-looped on old installs (H-01).

### Removed
- Chaff, DPI Shield and the FOU carrier.

## v0.71.0 and v0.7.2 (2026-10-07)

- Release builds bundling FRP `0.71.0` and Backhaul `0.7.2` respectively; the only change between them is the release signature text.
- Backhaul integration, live engine switcher, carrier switching made strictly manual, watchdog `auto_restart` default off.

## v0.1.3 (2026-09-30)

- Fixed the traffic chart reset; added a live speed KPI.

## v0.1.2 (2026-09-30)

- Fixed GRE routing instability when foreign servers share an IP; fixed bundle token parsing; peer limit raised to 10.

## v0.1.1 (2026-09-29)

- Performance overhaul: ping reduced from about 200 ms to 100 ms.

## v0.1.0 (2026-09-29)

- Simplified the installation flow; credentials are shown at the end of install.
