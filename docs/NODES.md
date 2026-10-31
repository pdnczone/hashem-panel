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
