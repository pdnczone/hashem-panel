# Selling tunnels to customers

The **Customers** tab (Hashem Pro) lets the owner of an Iran server sell the
Iran end of a tunnel. A customer brings one or more foreign servers; you set
a plan; their users connect to your server and reach the customer's
services.

## How it works

- Each foreign server of a customer gets its own relay on your server
  (`hsell-<customer>-<server>`) with its own control port and secret, on
  the engine you choose for it:
  - **FRP** (TCP, WebSocket, KCP, QUIC). Its frpc may open only the ports
    you sold, and only as TCP (and UDP when you sold UDP); other FRP proxy
    types are refused.
  - **Backhaul** (TCP, TCP mux, WS, WS mux, WSS, WSS mux). Your server
    lists the ports; the customer's client cannot add any. UDP rides the TCP
    transport only.
  - **Xray reverse** (Reality, XHTTP + Reality, gRPC + Reality, mKCP). The
    customer's server dials yours; the link's user may only open the reverse
    link, never use your server as a proxy.
  - **Xray direct** (the same presets). Your server dials the customer's
    server, for when it can reach it and not the other way round. The
    customer's server serves only its own 127.0.0.1 on the sold ports.
  - **Bagher (SSH)**. Your server logs in to the customer's sshd with a key
    of the link's own and runs FRP through that SSH connection. On the
    customer's server the installer makes a user for it (`hcust`: no
    password, no shell). sshd's own rules for it
    (`/etc/ssh/sshd_config.d/hashem-customer.conf`) allow nothing but
    listening on 127.0.0.1 at the tunnel's port: no command, no other
    forwarding, no Unix sockets; its keys file is root's
    (`/etc/ssh/hashem-hcust.keys`). sshd must read `sshd_config.d`
    (Debian and Ubuntu do), or the installer stops. The
    installer then prints a **reply code** (sshd's port, the user and the
    server's host keys); paste it on the link (**Reply code**). Your server
    trusts exactly those host keys; until then the link waits.
- One customer can mix engines: each foreign server has its own. For Xray
  direct and Bagher give the foreign server's address.
- **Volume:** only users' traffic is counted (the ports users connect to),
  in both directions, summed over all of the customer's foreign servers.
- **Speed:** one cap for the whole customer, shared by all of its servers
  and ports, in each direction.
- **Cut:** when the plan ends, the volume is used up, or you press Pause,
  the customer's tunnels stop and their ports are blocked. Renew, a bigger
  volume, Reset usage or Resume brings them back.
- Customers need no Hashem license and no panel. Without your license the
  existing customers keep running and can still be paused or removed;
  creating, renewing and resuming need it.
- Removing or rebuilding your own tunnels never touches customers. A full
  `hashem uninstall` removes them too.

## Selling a tunnel

1. **Customers → New customer.** Name, plan (days, volume in GB, speed in
   Mbit/s; empty means unlimited).
2. **Foreign servers:** one entry per server the customer owns: the users'
   ports (e.g. `443, 2083`), UDP if needed, the engine and its transport
   (for Xray Reality, the SNI if you want another site than the default)
   and, if you want, the control port (picked automatically otherwise).
   Each port can be sold once on your server.
3. **Create.** The kit opens. Send it to the customer.

## What the customer does

On each foreign server, as root:

```
curl -fsSL https://github.com/pdnczone/hashem-panel/releases/download/<version>/hashem-customer.sh -o hashem-customer.sh
sudo bash hashem-customer.sh install hsk1.XXXX
```

The kit modal shows this exact command. The installer downloads the
link's engine from its official release (FRP v0.71.0, Backhaul v0.7.2 or
Xray-core v26.3.27, checksum checked), says which ports it publishes, warns
about services that listen on 127.0.0.1 only, and starts the tunnel. The
kit is data only: the installer checks each value and writes the config
itself. Running it again with a new kit updates the tunnel (also when you
moved the link to another engine). `status` lists the tunnels and
`remove NAME|all` takes them away. The kit modal also shows the plain
config (`frpc.toml`, Backhaul's `client.toml` or Xray's `config.json`) for
a manual setup.

The customer's service must listen on the same ports on the foreign server.

## Inside GRE

An FRP or Backhaul link can run inside a plain GRE tunnel: tick **Inside a
GRE tunnel** and give the foreign server's public IPv4 address (or a domain
that points to it; it is resolved and pinned when you save). The panel
makes the GRE interface on your server (`hcg<customer>x<link>`, a /30 from
10.231.0.0/16, MTU 1380) and the kit (version 3) tells the installer to make
the other end; the customer's tunnel then dials your inner address. The
control port still answers on your public address too.

- Over GRE your server takes only the link's control port from the
  customer's inner address to yours (and ICMP between the two): not the
  panel, SSH, your public address or another customer's port. The fence is
  in the raw table (`HASHEM_CUST_GRE`, first in PREROUTING, checked every
  10 s), so no ACCEPT rule added later can open it; if it cannot be put in
  place the GRE goes down. IPv6 is off on the interface, reverse-path
  filtering is strict and nothing is forwarded from or to it. The installer
  fences the customer's end the same way (only the tunnel's replies from
  your inner address, and after conntrack only flows the customer's
  server opened: your ping over GRE gets no answer), checks it every minute, and refuses a /30
  that overlaps the customer's own networks.
- One GRE link per foreign server, and none to a server your own Hashem
  tunnels already use GRE with: a second plain GRE between the same two
  addresses gets no packets.
- Set the customer's address to your server's IP (not a domain) when that
  IP is on one of its interfaces: the GRE then leaves from it.
- Billing and the speed cap work as for any link. Ports 2048 and 34525
  cannot be sold (the cap's filters would read GRE packets as those
  ports). Hashem's carrier switch (FOU, WSS, 6to4, 4in6) leaves the
  customers' GRE alone.
- A customer who runs Hashem on the foreign server uses the installer too:
  its units sit next to the customer's own Hashem tunnel without touching
  it. (A Hashem setup bundle would replace that tunnel, and Hashem's frpc
  runs with `tcpMux` off by default, which a sold link does not accept.)

## Day to day

- **Reminders.** With alerts on (Settings, Alerts: Telegram and the rest),
  the panel tells you when a customer has used 90 % of the volume, and 3
  days and 1 day before a plan ends, each once a period (a renewal starts a
  new one). Nothing goes to the customer: forward it if you want.
- **History.** Each customer's card has a History button: when it was
  created, plan changes, renewals, cuts (and why), resumes, usage resets,
  reminders and foreign servers added or removed (the last 100), and the
  usage of the periods that ended (the last 24). Name, note and address
  changes are not recorded. A plan that starts inside a reminder's window
  (a 2-day plan) does not get that reminder; after an upgrade, customers
  already within 3 days of their end get one reminder at once.
- **Plan templates.** Save the plans you sell often (name, days, volume,
  speed) and pick one in the new-customer wizard or when renewing.
- **Renew several.** Tick customers (those ending within 7 days or ended
  are ticked already) and renew them all by N days at once; if one cannot
  be renewed, none is.
- **Export CSV.** Every customer in one file (plan, status, days left,
  usage, foreign servers and ports, dates in UTC), for a spreadsheet. Cells that would
  start a formula get a leading `'`.

## The status page

Every customer has a private page, `http://<your server>:<panel port>/_hs/<token>`,
in Persian and English: days left, volume used, speed cap and the state of
each server. It needs no login; anyone with the link can see it. Copy it
from **Status page** on the customer's card or from the kit.

## Notes

- The relays bind IPv4. The kit's address is your server's public IPv4 by
  default; set a domain under "Address in the kit" if you prefer.
- Sold ports are kept out of the server's ephemeral port range, so the
  server's own connections are never counted against a customer.
- The engine must be installed on your server: set up one tunnel of that
  engine once (FRP or Backhaul), or install Xray-core from the Xray menu.
  The panel runs its own copy in `/usr/local/lib/hashem-sell`, so updating
  or rebuilding your own tunnels never stops customers.
- A Backhaul server tells its client where to connect for each user. On
  the customer's server the installer fences the Backhaul client with a
  firewall chain on its own cgroup: only your control port, 127.0.0.1 on
  the sold ports and the system's DNS servers; everything else is
  rejected. This needs iptables with the cgroup match (any current
  distribution); without it a Backhaul kit is refused and FRP or Xray is
  the way.
- Backhaul's token crosses the network as is on tcp, tcpmux, ws and wsmux,
  and wss/wssmux use a self-signed certificate the client does not check.
  On a path you do not trust, sell FRP or Xray (Reality checks your
  server's key).
- The Reality SNI must be a public domain: Reality hands every handshake
  it does not recognise to that site. For Xray direct the customer's
  installer also refuses an SNI that resolves to a loopback, private or
  link-local address there (or one of that server's own), and pins the
  address it resolved; an hourly timer (`hashem-customer-retarget`) moves
  it when the site moves, never to such an address.
- Every relay sees only its own config of the panel's directory.
- For Xray direct and Bagher the download cap matches the data that comes
  from the foreign server's address and port. A domain is resolved to its
  IPv4 address when the link is saved, and the relay dials that address:
  if the customer's server moves, save the link again.
- Errors are `E-CUST-01` to `E-CUST-06` (see [ERROR_CODES.md](ERROR_CODES.md)).
