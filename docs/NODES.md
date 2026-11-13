# Nodes: one panel for all your servers

One panel is the **central**; your other servers join it as **nodes**.
A node does not need a panel of its own: a new one gets the **node core**,
the same program without the web page, and the central manages all of it.
The design is in [PLAN_NODES.md](PLAN_NODES.md).

The short way to a first tunnel, also the first card on the **Setup** page:

1. install Hashem on one server (usually the Iran one) and open its panel;
2. **Add a server** there and run the line on the other server;
3. **New tunnel**: pick the Iran server, the foreign server and the ports.

No token or bundle is copied by hand. The manual setup (a role and a token
on each server) is still on the Setup page below that card.

## Add a server

On the central, open **Nodes** and choose one of:

- **Add a server**: the panel gives two lines. Run one as root on the new
  server: `hashem node-join ...` if Hashem is installed there, or the
  `bash <(curl ...) node-join ...` line if it is not (it installs Hashem, then
  joins). The code works once, for 30 minutes.
- **Add with SSH**: give the server's IP, SSH port, user and password (or a
  private key). The panel shows the server's SSH host key for you to confirm,
  then logs in once, installs or updates Hashem and joins it. The password
  or key is not saved.

The first server you add makes this panel the central. Tunnels that are
already running are not touched on either side.

A server without Hashem gets the node core. Tick **Install the web panel on
it too** before you make the code (or in the SSH form) if you want its own
panel as well. A server that already has the panel keeps it.

On a server, `hashem node status` shows its role and `hashem node leave`
makes it standalone again.

## Core or panel

Each node's row says **Core only** or **With panel**.

| | Core only | With panel |
|---|---|---|
| Web page, login, terminal on the server | no | yes |
| Managed from the central | everything | everything |
| Tunnels, engines, Autopilot, Watchdog, license check | the same | the same |
| What its port answers | only the other servers of its tunnels (Peer Link, cluster, a sold tunnel's status page); anything else is a 404 | the panel |

- **Install its panel** / **Make it a core** on the row changes a node. It
  downloads the other build of the release the node runs, checks it against
  the release's checksums like an update, and restarts the service. Tunnels
  are not touched and nothing in `/etc/gre-panel` changes.
- On the server: `hashem panel status`, `hashem panel install`,
  `hashem panel remove`. `remove` works only on a node: without a panel and
  without a central nothing could manage the server.
- A core that leaves its central (or is removed there) has no page: run
  `hashem panel install` on it, or join it to a central again.
- The `hashem` menu and every `hashem ...` command work on a core as on a
  panel.

## How it works

- The node dials the central's panel port (the address in the code: by
  default the central's public IP and panel port). Nothing new is opened on
  the node.
- Inside that connection the two run TLS 1.3 with each other's key pinned:
  the code carries the central's key, and the central records the node's key
  when it joins. No certificate or domain is needed, and plain HTTP panels
  are protected the same way.
- The central only asks; a node never takes commands from anything but its
  pinned central. There is no shell or file access on the channel.
- If the central or the path is down, every tunnel keeps running. The node
  dials again by itself (every few seconds up to once a minute).
- A node with a panel keeps its full local panel. A core has none, and its
  tunnels do not need the central either.

## Moving an existing install

After the update, an Iran panel that has foreign servers asks once:
**Manage all your servers from this panel?** (on the dashboard and the Nodes
page; `hashem update` prints the same hint once).

- **Yes, move to nodes**: this panel becomes the central. Each foreign
  server joins by itself once it runs this version (`hashem update` on it).
  It proves who it is with the tunnel token the two servers already share,
  and joins only a central at the address it reaches its Iran panel on.
  The Nodes page lists every foreign server as waiting or joined; **Stop**
  ends the move. The move also closes by itself after 7 days, or when every
  foreign server has joined, and a server that joined once is not offered
  again.
- A server that joined by the move is marked on the Nodes page: check that
  it is yours (address, machine ID) and press **Approve**. This panel's
  license is copied to it only after that.
- The Peer Link that carries the offer sends the tunnel token without
  encryption, as it always has. Someone on the network path who learns it
  could try to join while the move is open; that is why the move is short,
  and why a joined server waits for your approval. If you want no window at
  all, add the servers with **Add a server** instead.
- A foreign server looks for its Iran panel's offer only for 14 days after
  it first runs this version, whether or not you start the move. If you
  start the move later, run `hashem node move` on it. The same token risk
  applies in this direction: while it is looking, someone on the path who
  knows the token could offer it a fake central at its Iran panel's
  address. To avoid that window, update the foreign servers only after you
  start the move, or add them with **Add a server**.
- If a server shows as joined but is not yours, or never connects, remove
  it and add the real one with **Add a server**: the move does not offer a
  server twice. A foreign server that belongs to someone else (a shared
  tunnel) should not be moved: whoever runs the central can manage it.
- **Not now** asks again in 7 days; **Don't ask again** never asks (the
  Nodes page keeps a **Move them** button).
- Running tunnels are not touched, and every server keeps its own panel. A
  foreign server joins by itself only once: if it leaves later, it stays
  standalone.

## Manage a node from the central

Pick the node in the server picker at the top of the page (or **Open** on its
row). Every page then shows that server: dashboard, tunnels, setup,
customers, cluster, logs, diagnostics, updates and its license. The central
sends each call over the node's channel and the node runs it with its own
checks, so it is exactly as if you used the node's panel. Its audit log
records each change as `via_central`.

Not relayed (they stay on the panel you are logged in to): the terminal, the
login, password, 2FA, HTTPS and access settings, and the node list. For a
node's own, open its panel. A core has no login to set; its certificate, if
you want one on its port, is `hashem tls ...` over SSH.

The node's pages open in a frame of their own (a browser sandbox with no
access to the central's page, cookies or API). It reaches only that node,
with a token tied to your login on the central, so even a node that was
broken into cannot act as the central. What a node sends is never shown as a
web page of the central: files it sends are downloads.

## All servers

On the central, the Nodes page shows **All servers**: each server's health,
tunnels, speeds, CPU, RAM and disk, read live from it, and the totals.
A tunnel between two of your servers is counted once, at its Iran server,
so the totals are not doubled.

- **Update nodes**: pick the nodes; they are updated one at a time, each
  waited for until it is back on its new version. The first failure stops
  the rest. The central itself is updated on its own Update page.
- **Backups**: the central keeps a copy of each node's newest backup for
  14 days (checked every 6 hours, or **now** per node). The node's
  Watchdog makes the backup and encrypts it with that node's own key, so
  the copy is only readable with that key. Save each node's key
  (its Watchdog page: export the backup key) somewhere safe: without it a
  lost node's copies cannot be opened. A node without Watchdog (Pro) has no
  backups to copy. A removed node's copies stay their 14 days.
- **Customers**: the customers of every server in one list; **Open** goes
  to that server's Customers page.
- **Alerts**: when Telegram or a webhook alert is set up on the central,
  the nodes' tunnel and resource alerts are sent with it too, named by the
  node. Each node keeps its own alerts as well. A node that joined by a
  move sends none until you approve it.

## Tunnels between servers

On the Nodes page, **New tunnel** makes a tunnel between two of your servers
(this panel counts as one of them). Pick the Iran server (users connect to
it), the foreign server, the engine and the ports, then **Check**: the
central asks both servers for a free control port and a free pair of GRE
addresses, and says what it will do. **Make the tunnel** then:

1. sets up the Iran end (its first tunnel, or one more) and takes the bundle
   it makes, as in Setup today;
2. sets up the foreign end with that bundle. A foreign server that already
   has a tunnel joins as one more Iran hub (Cluster, Pro on that server).

If the foreign end fails, the Iran end is removed again. If that fails too,
the Iran end is listed as **left over**, with a button to remove it. The
list shows every tunnel whose two ends are your servers; **Remove both
ends** removes the foreign end first, then the Iran end.

Each tunnel in the list shows what its Iran server says about it now (up
or down, its carrier, whether Autopilot watches it) and has:

- **Swap carrier** and **Ports and settings**: open that dialog on the Iran
  server's own pages, in its view. The Iran server tells the foreign one.
- **Test the path**: opens the Iran server's path test.
- **Restart both ends**: restarts the tunnel's engine on the Iran server,
  then on the foreign one. A foreign server that joined as one more hub is
  left alone: its client reconnects by itself.
- **Remove both ends**.

The two servers of a tunnel talk to each other on the Peer Link (carrier
swap, path test, Autopilot). When both belong to one central, that goes over
the channels they already hold with the central, so the foreign server's
panel port does not have to be open to the Iran server. It falls back to the
direct call when the channel cannot carry it (the central is down, or one
server runs a version from before this).

## Autopilot on every server

[Autopilot](AUTOPILOT.md) runs on each tunnel's Iran server, as before. On a
central, the **Autopilot** tab starts with **Autopilot on every server**:
every Iran server with its tunnels, its newest events and a switch for the
server or for one tunnel. The central reads and sets this with that server's
own API, so turning it on needs that server's license. **Rules and history**
opens that server's own Autopilot tab for the limits and the allowed
carriers.

## Licenses on nodes

A Pro key active on the central is copied to each node that has no key of
its own, and activated there by the node's own license check:

- a key that is not locked to one machine goes to every node, and to each
  new node when it joins;
- a key locked to a machine goes only to that machine. Each node's machine
  ID is on its row, and you can activate a node's own key from its License
  page through the picker;
- a node that has its own key keeps it; a renewal on the central replaces
  only the copy the central gave; removing the key on the central removes
  only that copy.

Adding a server as a node gives it the central's key when that key is not
locked to a machine (the node needs it to check it). Add only your own
servers.

## Remove or leave

- **Remove** on the central: the node is told, and becomes a standalone
  server again. Its tunnels keep running. A core then has no page: see
  [Core or panel](#core-or-panel).
- **Leave the central** on a node (or `hashem node leave`): the central drops
  it from its list.
- A central with no nodes can **stop being a central**.

## Files

| File | On | What |
|---|---|---|
| `/etc/gre-panel/node.key` | every panel and core | this server's key (0600) |
| `/etc/gre-panel/node.json` | central and nodes | the role; on a node, its central's address and key |
| `/etc/gre-panel/nodes.json` | central | the nodes and the open join codes (only their hashes) |
