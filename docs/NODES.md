# Nodes: one panel for all your servers

One panel is the **central**; your other servers join it as **nodes**.
The design is in [PLAN_NODES.md](PLAN_NODES.md).

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

On a server, `hashem node status` shows its role and `hashem node leave`
makes it standalone again.

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
- Every node keeps its full local panel.

## Moving an existing install

After the update, an Iran panel that has foreign servers asks once:
**Manage all your servers from this panel?** (on the dashboard and the Nodes
page; `hashem update` prints the same hint once).

- **Yes, move to nodes**: this panel becomes the central. Each foreign
  server joins by itself once it runs this version (`hashem update` on it).
  It proves who it is with the tunnel token the two servers already share:
  the token never crosses the network, and someone who only sees the
  traffic cannot join or pose as the central. The Nodes page lists every
  foreign server as waiting or joined; **Stop** ends the move.
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
node's own, open its panel.

The node's pages open in a frame of their own (a browser sandbox with no
access to the central's page, cookies or API). It reaches only that node,
with a token tied to your login on the central, so even a node that was
broken into cannot act as the central. What a node sends is never shown as a
web page of the central: files it sends are downloads.

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

To change a tunnel's engine or carrier, open the Iran server (the picker)
and use its Tunnel page: it tells the foreign server, as it does today.

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

- **Remove** on the central: the node is told, and becomes a standalone panel
  again. Its tunnels keep running.
- **Leave the central** on a node (or `hashem node leave`): the central drops
  it from its list.
- A central with no nodes can **stop being a central**.

## Files

| File | On | What |
|---|---|---|
| `/etc/gre-panel/node.key` | every panel | this panel's key (0600) |
| `/etc/gre-panel/node.json` | central and nodes | the role; on a node, its central's address and key |
| `/etc/gre-panel/nodes.json` | central | the nodes and the open join codes (only their hashes) |
