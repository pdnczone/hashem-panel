# Plan: central panel and nodes

Status: draft, waiting for the owner's approval. Built in phases on `dev`;
each phase is gated before the next starts (see "Gate").

## What it is

Today every server runs its own panel and every tunnel is set up by hand on
both ends (the `hsh1_...` bundle is copied from the Iran panel to the
foreign one). With nodes, one panel is the **central**. The other servers
are **nodes**: they keep running Hashem as today, and the central drives
them over one secure channel. A tunnel between two nodes is made from one
page; servers are added from the panel with SSH or with a one-line command.

## Decisions (owner)

- The central is usually the Iran server, but either side can be the
  central: the protocol has no direction (Iran central with foreign nodes,
  foreign central with Iran nodes, or a mix).
- Every node keeps its full local panel. When something cannot be done
  through the central (the channel is down, a rare case the central does
  not cover), the user does it by hand on the node, as today. The central
  always reads a node's state from the node, so a local change never
  conflicts with the central.
- Licenses: a key activated on the central is copied to every node whose
  own license check accepts it (see "Licenses").
- After the update, the panel offers to move the user to the node system.
  If the user accepts, it is done automatically; if not, nothing changes
  and the offer can be taken later from Settings (see "Migration").
- Existing tunnels are not touched by the update, nor by the migration.

## Principles

1. **The node is the source of truth for its own state.** The central has
   no database of tunnels; it holds the list of nodes, their keys and its
   own settings. Every view is read live from the node (with a short cache
   for the overview). This removes the two-masters problem and keeps the
   local panel fully usable.
2. **Control plane apart from data plane.** If the central dies or the
   channel is cut, every tunnel keeps running with its last config; only
   remote control is lost until the channel comes back.
3. **Reuse the node's own API.** Each panel already has the whole API. The
   central relays a request to `/api/...` on the node through the channel,
   with the node's own handlers, validation, Pro gates and audit. Almost
   every page works on a node with a node picker and no rewrite.
4. **SSH only to bootstrap.** SSH credentials are used once to install and
   enroll a node, never stored.
5. **Least power on the channel.** The channel carries API calls only, from
   an allowlist; no shell, no file access, no terminal (the web terminal
   stays local to each panel).

## Building blocks

### N0: this document, then the protocol note

Wire format, versioning and the threat model written next to the code
(`panel/node*.go` header comments) and in `docs/NODES.md` / `NODES.fa.md`.

### N1: node mode, enrollment, node list

- **Roles** in `/etc/gre-panel/node.json` (0600): `standalone` (today's
  default), `central`, or `node`. A central keeps `nodes.json` (0600):
  id, name, public IP, role hint (Iran/foreign), the node's public key,
  last seen, version, and `machine_hash` (for licenses).
- **Keys:** each node and the central make an Ed25519 key pair on
  enrollment (stored 0600). The channel is TLS with both sides pinned to
  each other's key (no CA, no domain needed). Removing a node on the
  central revokes its key at once.
- **Direction:** the node dials the central (works behind NAT, fits reverse
  tunnels where the foreign server already dials Iran, and the node opens
  no new port). One long-lived connection (HTTP/2 or WebSocket over TLS on
  the central's panel port, at a fixed path that does not reveal the
  panel, like the cluster heartbeats), with reconnect and backoff. When
  the two servers share a GRE tunnel, the node may dial the central's
  inner GRE address instead (preferred when the public path is filtered).
- **Enroll with a command:** the central shows
  `bash <(curl ...) node-join <central>:<port> <one-time code>`. The code
  is valid 30 minutes and once, and carries the central's key fingerprint
  so the node pins the right central from the first byte.
- **Enroll with SSH:** the user gives host, port, user and password or key.
  The central connects (`x/crypto/ssh`, host key shown to the user and
  confirmed), installs or updates Hashem, runs the same `node-join`, and
  drops the credentials from memory. Nothing SSH-related is saved.
- **Node list page:** state (online / offline / last seen), version,
  role, tunnels count, CPU / RAM / disk, license state. Remove node,
  rename, "open the local panel" link.
- `hashem node status|leave` on the node; `leave` drops the central's key
  and goes back to `standalone` (tunnels untouched).

### N2: relay and node picker

- `/api/node/<id>/<path>` on the central relays to `/api/<path>` on the
  node, after the central's own login, CSRF and audit. The node runs it as
  a request from the central (its audit log records "via central, user X").
- Allowlist of relayed paths: tunnels, carriers, engines, customers,
  cluster, alerts, health, logs, doctor, backups, license (see below).
  Refused: terminal, access/login settings, panel password, node.json.
- UI: a node picker in the header (central plus every node); every page
  then calls the relayed API for the chosen node. Offline node = the page
  says so and offers the local panel link.
- Streams (logs, live traffic) relayed with a size and time cap.

### N3: tunnels between two nodes from one page

- Wizard: choose the Iran node and the foreign node, the engine and the
  ports. The central asks both nodes for free ports (P0 registry on each),
  then makes the tunnel in two steps: the server end first (it returns the
  bundle it already makes today), then the client end with that bundle.
- Failure on the second step rolls the first back; if the rollback also
  fails, the tunnel is listed as "incomplete" with a remove button on both
  sides. Every step is idempotent (retry is safe).
- Same for change engine / carrier and remove: both ends in order.
- `join-hub` (one foreign, several Iran hubs) and cluster pools get the
  same two-node flow.

### N4: central overview and fleet actions

- Overview: every node's health, tunnels and traffic on one page; alerts
  from every node in one Telegram bot (each node keeps its own alerts too).
- Update nodes from the central (one or all, with the release channel),
  one node at a time, stopping on the first failure.
- Backup of every node's config to the central (encrypted, kept N days).
- Customers (sold tunnels) of every node in one list, with the actions
  relayed to the node that holds the customer.

### N5: migration of existing installs

See "Migration".

## Licenses

The license check is not changed: `panel/license.go`, `pro_ok`,
`isProLicensed` and the trusted public keys stay exactly as they are.

- A key activated on the central is offered to every node. The central
  sends the key string, and the node activates it through its own existing
  path (`POST /api/license`, `verifyLicenseKey`). The node's own check
  decides; the central only copies.
- Keys that are not locked to a machine (the check already accepts them
  on any server) are activated on every node automatically, and on each
  new node when it enrolls.
- A key locked to a machine is valid only on that machine: the central
  activates it only on the node whose `machine_hash` it names (the central
  itself or one node). The central shows each node's `machine_hash` so the
  owner can get keys for several servers at once and paste them all on the
  central, which then puts each on its node.
- Renewal and removal go out the same way. A node that refuses a key shows
  the node's error on the central.
- The central does not grant features: a node without a valid key of its
  own has no Pro features, even when the central has them.

## Migration

### What the update does to running tunnels

Nothing. The update replaces the panel binary and restarts `gre-panel`
only, as today; frps / frpc / Backhaul / GRE / Xray / Bagher units are not
restarted. Node mode is off until the user turns it on.

### The offer

- After the update, the Iran panel (any panel that has foreign peers in
  `peers.json`) shows a card once: "Manage all your servers from this
  panel?", with the list of its foreign servers and what will happen.
  Buttons: **Yes, move to nodes** / **Not now** / **Don't ask again**.
  "Not now" asks again after 7 days; "Don't ask again" never asks again.
  Settings > Nodes keeps the same button for later.
- The terminal menu shows the same offer once after `hashem update`.
- A foreign panel never offers to become the central by itself (it would
  steal the Iran panel's role); it shows "waiting for your Iran panel" if
  the Iran side has started the move.

### When the user accepts

1. The panel becomes `central` (keys made, `node.json` written).
2. For each foreign peer it already knows (`peers.json`: public IP, engine,
   token, inner GRE addresses) it publishes a short-lived enrollment offer.
3. Trust comes from the tunnel token the two servers already share and
   nobody else has: the foreign panel (once updated) proves it holds the
   token (HMAC over the central's key fingerprint, a nonce and a time) and
   the central proves the same back. Then they swap keys and the token is
   no longer used for the channel. Engines without a shared token (Xray,
   Bagher) fall back to the one-time code or SSH.
4. The channel goes over the existing path: the foreign server dials the
   Iran public IP as its tunnel does, or the inner GRE address.
5. Foreign servers still on an old version are listed as "update needed",
   with two buttons: copy the one-line command, or update over SSH.
6. The central shows the found nodes; one click accepts all (or the user
   ticks "accept automatically" in the offer). Nothing is changed in any
   tunnel, and every node keeps its local panel.
7. A foreign server that has joined several Iran hubs (`hubs.json`) joins
   the first that asks; the others see it as "managed by another central"
   and its local panel can move it.
8. Undo: "Leave the node system" on the central (all nodes back to
   `standalone`) or on one node; tunnels untouched.

### Never enrolled

- Customers' servers (`tools/hashem-customer.sh`): they belong to someone
  else, have no panel and are never offered or enrolled.
- A foreign panel whose Iran peer is not this panel.

## Security

- The central is now a high-value target: login 2FA is recommended on the
  enrollment page; every relayed call is in both audit logs; node removal
  revokes at once; enrollment codes are one-time and short-lived;
  the channel allowlist has no shell or file access.
- Replay: every channel message has a time and a nonce; stale or reused
  ones are refused (as in the cluster heartbeats).
- A stolen node key gives no power over the central or other nodes (the
  node only answers, it cannot send commands).
- Version skew: the channel has a protocol version; the central refuses
  relaying a path the node's version does not know, and shows "update this
  node".

## Gate (every phase)

As in PLAN_CUSTOMERS.md: go vet, gofmt, `go test -race`, hermetic shell
tests, a lab test in CI (two network namespaces: central + node, including
enrollment, relay, the two-node tunnel and the channel cut), two
independent reviews (correctness, and security with proof that the license
checks and trusted keys are unchanged), findings fixed, CI green. Push to
`dev` only; no merge to main and no release tag without the owner.

## Order

N1 → N2 → N3 → N5 (migration needs N1–N3 to be worth taking) → N4.
