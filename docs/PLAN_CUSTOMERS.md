# Plan: selling tunnels to customers

Status: approved by the owner. Built in phases on `dev`; each phase is gated
before the next starts (see "Gate").

## What it is

A seller runs Hashem (Pro) on an Iran server. A customer owns one or more
foreign servers and buys the Iran end: the seller's panel runs a separate
tunnel for each of the customer's foreign servers, counts the customer's
users' traffic, caps the speed, and cuts the customer off at the end of the
plan or when the volume is used up. The customer needs no Hashem license and
no Hashem panel: a one-line installer sets up the foreign end.

## Decisions (owner)

- Engines: every engine Hashem has except Spoof (FRP first, then Backhaul,
  Xray reverse and direct, Bagher, GRE wraps).
- Several foreign servers per customer, one plan: the volume is the sum over
  all of them, and one speed cap is shared by all of them.
- Only the users' traffic is billed (the ports users connect to on the Iran
  server), not the tunnel's own control traffic.
- Cut-off (expiry, volume used up, or by hand) = the customer's tunnels are
  stopped and disabled and their user ports are blocked (DROP).
- The seller needs Pro (`customers` feature, unlocked by every key that
  unlocks Bagher, like the other Pro features). Customers need no license.
  The license checks themselves (`license.go` checks, `pro_ok`,
  `isProLicensed`, trusted keys) are never changed.
- Each customer gets a status page on the panel port at a hidden path,
  `/_hs/<token>`, in Persian and English, in Hashem's design: plan, days
  left, volume used, speed, link state. No login; the token is the secret.

## Building blocks

### P0: one list of ports

`panel/ports_registry.go`: every port Hashem's own configs take on this
server (panel, FRP/Backhaul relay control ports, peers' user ports, Bagher,
Xray, cluster pools, and from P1a customers). Every "is this port free"
check uses it: `peerPortClash`, `checkBagherLinkPorts` (its callers hold
`sshFwdMu`, so it takes the Bagher config as an argument: `portClaimsWith`),
`xrayClaimedPorts` and `validatePool`. Also: the `customers` Pro feature
constant, `node --check panel/app.js` in CI, and a test that customer unit
names never match the patterns hashem.sh kills or removes.

### P1a: FRP backend

- `customers.json` in the panel config dir (0600): customers, each with
  plan (expiry, volume GB, speed Mbit/s), a status token, and links (one
  per foreign server: engine, control port, user ports, frp token).
- One unit per link: `hsell-<id>-<link>.service`, running its own copy of
  frps (`/usr/local/lib/hashem-sell/frps`, so hashem.sh's
  `pkill -f /usr/local/bin/frps` on update never hits it) with
  `/etc/gre-panel/customers/<id>-<link>.toml` (control port, token,
  `allowPorts` = exactly the customer's user ports, `proxyBindAddr`
  0.0.0.0).
- Counting: the `HASHEM_CUST` chain (jumped to from INPUT and OUTPUT): per
  user port, `--dport` in and `--sport` out, tcp and udp. Usage is summed
  per customer into customers.json. Cut = the customer's rules become
  DROP, units stopped and disabled. Units are started only after the chain
  is in place, so no unbilled traffic passes.
- Speed: tc clsact on the main interface, pref 4919 (IPv4; 4920 reserved
  for IPv6), one police action per customer and direction shared by all of
  the customer's ports (`index`), so the cap is for the customer as a
  whole, not per port.
- API: `GET/POST /api/customers`, `POST /api/customers/{action}` (renew,
  cut, resume, reset, remove, link add/remove), `GET /api/customers/kit`.
  Errors `E-CUST-01..`.
- Customer installer `tools/hashem-customer.sh`, attached to every release
  and fetched from the release that matches the panel's version: installs
  frpc v0.71.0 (sha256 pinned), writes `/etc/hashem-customer/frpc-<n>.toml`
  from the kit, one unit per Iran link. The kit modal also shows the plain
  frpc.toml for a manual install.
- hashem.sh: uninstall removes the hsell units, the chain, the tc filters
  and the binary copy.
- Lab: `tests/test_customers_lab.sh`, real frps/frpc 0.71.0 in network
  namespaces: bytes counted exactly, cap enforced, cut and resume, expiry.

### P1b: UI

Customers tab: list with usage bars and days left, a map of each
customer's links, a wizard (plan, foreign servers, ports), the kit modal
(one-liner, QR-free plain text, manual config), and the `/_hs/<token>`
status page (FA/EN, light/dark, Hashem design tokens).

### P2: Backhaul and Xray reverse links for customers

- `customerLink.Engine`: `frp`, `backhaul` or `xray`, per foreign server;
  one customer can mix them. Billing, the shared cap (user ports and
  control port ingress), cut and the port registry are the same for all.
- Backhaul (v0.7.2 schema, transports tcp, tcpmux, ws, wsmux, wss, wssmux):
  the server lists the ports (`p=127.0.0.1:p`), so the client cannot add
  any; UDP only with tcp (`accept_udp`). wss links get their own
  self-signed certificate. Unit runs `/usr/local/lib/hashem-sell/backhaul`.
- Xray reverse (Xray-core v26.3.27, presets reality, xhttp, grpc, kcp):
  the Iran end is a VLESS portal whose user carries `reverse` (Xray refuses
  it a forward proxy) and everything unmatched goes to the blackhole; built
  with `buildXrayConfig`. Keys stay across edits that keep engine and
  transport, so an installed kit stays valid.
- Kits: FRP stays version 1 (older installers), Backhaul and Xray are
  version 2 with `engine=`. The installer builds every config from checked
  values (Xray's foreign end equals `buildXrayConfig`'s, tested), pins the
  sha256 of each release, and replaces a link's old tunnel by its token
  (`<unit>.id`), also across an engine change.
- Review fixes: Backhaul listens on 0.0.0.0 only (IPv6 users would be
  unbilled), `skip_optz`; the customer's Backhaul client is fenced
  (iptables chain on its cgroup: the seller's control port, 127.0.0.1 on
  the sold ports, DNS; the rest rejected), since a Backhaul server picks
  the client's targets; unit names carry a hash of the seller's address;
  the Reality SNI must be a public domain; relay units see only their own
  files of the panel's config dir; UDP-control links show "running".
- Lab: one customer with Backhaul tcp+UDP, Backhaul wssmux, Xray Reality
  (+UDP) and Xray mKCP links on the real binaries: reach, one cap shared by
  two links at once, billed volume, the Xray user is no proxy into the
  seller's server, cut/resume, clean remove.

### P3: Xray direct and Bagher (Bagher needs the customer to run a command
that prints a reply code the seller pastes back).

### P4: GRE wraps and Hashem-bundle scenarios (customer runs Hashem too).

### P5: reminders (Telegram, days left / 90 % used), history, CSV export,
plan templates, bulk renew.

### P6: selling the foreign side: separate design, not in this plan.

## Gate (every phase)

1. `go vet`, `gofmt`, `go test -race ./...`, hermetic shell tests.
2. The phase's lab in CI (netns labs run in CI only).
3. Two independent reviews: correctness (including cluster/peer
   regressions) and security (including proof that the license checks are
   unchanged: `git diff` of `license.go` touches only the feature list).
4. Findings fixed, CI green on `dev`. Only then the next phase. No push to
   `main` and no release tag without the owner.
