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
