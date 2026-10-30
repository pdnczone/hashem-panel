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
- One customer can mix engines: each foreign server has its own.
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
- With Backhaul your server decides what the customer's client connects
  to (127.0.0.1 on the sold ports); the customer trusts the seller with
  that, as with any Backhaul tunnel.
- Errors are `E-CUST-01` to `E-CUST-06` (see [ERROR_CODES.md](ERROR_CODES.md)).
