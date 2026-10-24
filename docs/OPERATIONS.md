# Operations reference

How Hashem behaves day to day: the panel tabs, the health model, what runs by itself, updates, the `hashem` command, uninstalling and the security details. For a first install see the [README](../README.md); for problems see [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

- [Installing safely](#installing-safely)
- [Panel tour](#panel-tour)
- [Health model](#health-model)
- [Automation](#automation)
- [Updates, downgrade and channels](#updates-downgrade-and-channels)
- [`hashem` CLI](#hashem-cli)
- [Uninstall and your data](#uninstall-and-your-data)
- [Security notes](#security-notes)

## Installing safely

To read the installer before running it:

```bash
curl -fsSL https://raw.githubusercontent.com/pdnczone/hashem-panel/main/install.sh -o install.sh
less install.sh && bash install.sh
```

`install.sh` accepts `hashem.sh` only from GitHub itself, from two agreeing mirrors, or when it matches a hash you pin. Every release publishes a `checksums.txt`; pin the script like this:

```bash
HASHEM_SHA256=<sha256 of hashem.sh from the release checksums.txt>   bash <(curl -fsSL https://raw.githubusercontent.com/pdnczone/hashem-panel/main/install.sh)
```

The panel binary comes from the active [update channel](#updates-downgrade-and-channels). To run an exact panel version, install first, then pick the tag in the **Update** tab (or `POST /api/update {"tag":"v2.7.0"}`).

## Panel tour

The panel is one page with these tabs:

- **Dashboard** — a banner with one big word (Healthy / Degraded / Down) and one line per tunnel; KPIs; the Fleet Health card with hub latency, the topology graph and per-server cards.
- **Tunnel** — every tunnel on this server: the main tunnel, the foreign-server peer cards and the Bagher card (start, stop, copy bundle, quick edit, remove); per-tunnel PASS/FAIL checks, the dial-route card, and the GRE carrier (Direct GRE or WSS, its port and SNI).
- **Performance** [PRO] — the settings of the engine this server runs: for FRP, Auto Pool, encryption, compression, TCP multiplexing, PROXY protocol (real client IP for Xray), a bandwidth limit per port and a health check; for Backhaul, the connection pool. Plus the kernel network stack (Optimize Network / Restore).
- **Diagnostics** [PRO] — latency, jitter, MTU and speed tests; the same engine as `hashem doctor`.
- **Setup** — create any tunnel: GRE + FRP, Backhaul (with or without GRE) or Bagher; bundles and peers.
- **Watchdog** [PRO] — monitoring, backups and alerts.
- **Cluster** [PRO] — opens on a live map of the cluster; click anything to change it. Pools (one Iran port served by several foreign servers: failover, balance, sticky per user, lowest latency or least connections; one-second health check, service check, standby servers, connection limits, drain, manual failback), linked Iran hubs that take over each other's ports, DNS failover (Cloudflare or webhook), and on a foreign server, serving several Iran hubs. See [Cluster](CLUSTER.md).
- **Benchmark** [PRO] — the Path Test (which transports get through between the two servers, before any tunnel: plain TCP/UDP, GRE, SSH, FRP x 5, Backhaul x 7, with latency and speed), carrier probing and the optional auto-pilot.
- **Update** — channels, install any tag, rollback state.
- **Logs, Settings, Terminal** — redacted logs with error codes; password, 2FA, idle timeout, alerts, TLS, metrics token; the audited shell (off by default).

**FRP TCP Multiplexing (`transport.tcpMux`) is OFF by default** (speed-first: tcpMux roughly halves throughput over GRE). New `frps`/`frpc` configs are written with `transport.tcpMux = false`. Turn it on only deliberately with `hashem perf tcpmux on` (or the Performance tab). The setting **must be identical on the Iran hub and every foreign spoke**; a mismatch makes `frpc` fail to log in with `connect to server error: EOF`, and `hashem status` / `hashem doctor` print a hint when they see it. Backhaul is unaffected.

## Health model

The same rule is used by the Dashboard banner, the fleet cards and the topology graph (`fleetHealth` in `panel/fleet.go`). Per tunnel:

- **Healthy** — (GRE up **and** FRP up **and** ICMP ping ok) **or** (FRP service up **and** the foreign client holds an ESTABLISHED TCP session on the control port — called *linked*).
- **Degraded** — exactly one leg up (GRE or FRP) and no linked session; or both up but no ping and not linked.
- **Down** — nothing up.
- **"FRP only" badge** — linked, but the GRE inner address does not answer ICMP: traffic still flows over FRP while the GRE path is blocked.

*Linked* is detected with `ss -Htn state established` on the control port (also `port+2` for the wss front and `port-2`).

The dashboard's overall status uses the same function. The main tunnel counts as one more spoke of the hub (synthetic id `0`, named `Tunnel · <ip>`).

**Latency** per link is taken in this order: (1) ICMP ping of the GRE inner address → kind `icmp`; (2) if ICMP fails, the kernel TCP RTT of the live session on the control port (from `ss -tin`) → kind `tcp`; (3) otherwise `—`. The hub summary (`/api/fleet` → `latency`) gives avg, min, max over links that have a value, the count, and how many are `icmp` vs `tcp`. History, sparkline, average, loss and uptime use the same value.

## Automation

- **Watchdog** — a systemd timer (`hashem-watchdog.timer`) runs `hashem watchdog tick` every minute. Control it with `hashem watchdog on|off|status|test|tick`. Telegram alerts are configured in the watchdog settings; `hashem tgsend "msg"` sends a manual message. `auto_restart` defaults to **off** (alert only).
- **Dial route** — on foreign servers, `hashem dial [status|auto|gre|public]` chooses whether `frpc` / `backhaul-client` dials the hub over the GRE inner IP or the hub public IP. `auto` uses GRE if it answers (ping or TCP to the control port), otherwise public. The watchdog switches to public automatically when GRE is dead and the client is not connected, and back to GRE once GRE has carried the control port for 5 checks in a row (5 minutes). If the client cannot connect over GRE after that move, it goes back to the public IP and waits 30 minutes before trying again. The foreign side of Setup asks for the route when the bundle uses GRE. Foreign servers show a "Route to the Iran hub" card.
- **Carrier failover** — `hashem carrier` manages and cycles carriers. Switching is manual; the advisor only suggests.
- **Backups** — `hashem backup now|restore|schedule|status` (encrypted archives in `/var/backups/hashem`).
- **Adaptive capacity** — multiplexing capacity adjusts to load and available RAM.

## Updates, downgrade and channels

The **Update** tab (and `hashem update` for the script + panel) uses two channels:

- **`stable`** — GitHub releases that are *not* prerelease (tags `panel-rN` and `vX.Y.Z`).
- **`dev`** — prereleases tagged `dev-rN`, built from the `dev` branch.

The channel is stored in `<configDir>/update.json` (`GET/POST /api/update/channel`). `GET /api/releases?channel=stable|dev` lists the last 20 releases of a channel. You can install **any listed tag**, newer or older — that is how you downgrade (`POST /api/update {"tag":"panel-r140"}`; without a tag, the newest of the selected channel).

Install steps: validate tag → download the panel binary and `hashem.sh` of that tag → verify SHA-256 from that tag's `checksums.txt` (fail-closed) → verify ELF / `bash -n` → back up the config dir to `<configDir>/backups/pre-<from>-<timestamp>.tar.gz` (last 5 kept; `exe.bak` and `hashem.sh.bak` kept) → swap → write `<configDir>/pending_update.json` → restart.

**Auto-rollback:** the new process counts its starts in `pending_update.json`. If it crashes 3 times before it is confirmed healthy (self health check 45 s after start), the old binary and `hashem.sh` are restored and the panel restarts.

**Branches:** `main` is stable (a push that changes `panel/**` or `hashem*.sh` builds release `panel-r<run>`); `dev` is for testing (each push builds prerelease `dev-r<run>`, never offered on stable). Promote by a manual Pull Request `dev → main`. Hotfix: branch from `main`, PR to `main`, then merge `main` back into `dev`. Release history: [CHANGELOG.md](../CHANGELOG.md).

## `hashem` CLI

Everything works from SSH too (commands as in `hashem help`):

```bash
hashem                # first run: auto-install; afterwards the terminal app (arrows, Enter, Esc)
hashem menu           # the terminal app
hashem status         # tunnel health, peers, service status
hashem show-panel-url # print the panel URL again
hashem reset-password # reset / auto-generate the admin password
hashem password <p>   # set the panel password non-interactively
hashem tls issue <domain> [email]   # HTTPS for the panel (Let's Encrypt; also: status, renew, remove, ip, custom)
hashem settings show  # panel settings; also: 2fa off, terminal on|off, idle N
hashem license activate <key>
hashem cluster status | events | rules              # the cluster (Pro to change it)
hashem cluster pool add 443,8443 --mode least --check tcp
hashem cluster pool set 443 --no-failback yes | pool failback 443
hashem cluster member set 443 2 --weight 2 --max-conn 500 --backup no | member drain 443 2
hashem cluster join-code | add-hub <code>          # link two Iran hubs
hashem join-hub --bundle <bundle>   # foreign side: also serve another Iran hub (hubs, leave-hub --id N)
hashem logs           # relay logs
hashem optimize       # BBR / MTU / sysctl tuning
hashem doctor         # latency, jitter, MTU and speed diagnostics
hashem doctor fix     # Quick Repair (same as the Diagnostics tab), then diagnose again
hashem spoof install  # Spoof tunnel core + WireGuard tools (also: status, up, down)
hashem xray install   # Xray tunnel core (also: status, start, stop, restart, logs, uninstall)
hashem carrier        # carrier management / failover
hashem dial status    # foreign side: route to the Iran hub
hashem watchdog status
hashem backup now     # encrypted backup (/var/backups/hashem)
hashem perf autopool status  # Auto Pool: on|off|status|tick
hashem perf tcpmux on|off    # must match on hub and spokes
hashem perf proxy-protocol off|v1|v2 | bandwidth MB | health-check on|off | backhaul-pool N
hashem free-ram       # free RAM
hashem update         # update script and panel to the latest release
hashem update-channel [stable|dev]
hashem uninstall      # full wipe (see "Uninstall and your data")
```

`hashem help` prints the full list, including the non-interactive `setup-*` and `*-peer` commands.

## Uninstall and your data

```bash
hashem backup now      # optional: encrypted archive in /var/backups/hashem
hashem uninstall       # asks to confirm; "--force" skips the question
```

Uninstall is a **full wipe**. It removes:

- all tunnel, relay, panel and watchdog systemd units, and the GRE interfaces;
- the binaries `frps`, `frpc`, `backhaul`, `gre-panel`, `grepanel`, and the `hashem` command itself;
- `/etc/frp`, `/etc/backhaul`, `/etc/gre-panel` (panel config, history and the **backup key**) and `/usr/local/gre-panel`;
- Hashem logs, locks, cron entries, its iptables rules and its sysctl tuning.

It does **not** remove `/var/backups/hashem`. But those archives are encrypted with `/etc/gre-panel/backup.key`, which the wipe deletes. **Copy `backup.key` somewhere safe before uninstalling** if you want to restore later.

## Security notes

- **Policy and disclosure:** [SECURITY.md](../SECURITY.md).
- **Production deployment** (Nginx / Caddy, TLS, firewall, `TRUSTED_PROXY_IPS`): [docs/DEPLOYMENT.md](DEPLOYMENT.md).
- Passwords are stored only as salted **argon2id** hashes in `/etc/gre-panel/panel.json` (older unsalted SHA-256 hashes are upgraded on the next login). The policy requires 12+ characters with upper, lower, number and symbol.
- State-changing requests need a session-bound HMAC-SHA256 `X-CSRF-Token`; `X-Forwarded-For` is trusted only from `TRUSTED_PROXY_IPS`.
- Updates are pinned to official GitHub domains and verified with SHA-256 from `checksums.txt`; the installer script is checked with `bash -n`.
- The in-browser terminal is **disabled by default** and audited (10-minute idle and 30-minute absolute limits).
- Security events and **every state-changing API call** (method, path, status; never the body) are written to `/etc/gre-panel/security-audit.log` (rotated at 2 MiB, newest entries via `GET /api/audit`).
- Login lockout escalates for repeat offenders (15 min, doubling up to 24 h).
- Optional **TOTP two-factor login** (Settings → Two-factor authentication) with 8 single-use recovery codes; off by default. Recovery if you lose the device: set `GRE_PANEL_PASSWORD` and remove `totp_enabled` from `panel.json`.
- Optional **idle session timeout** (Settings), driven by real clicks/keys, not background refresh.
- The terminal asks for your password (and 2FA code) every time it opens, uses a single-use 60 s ticket bound to your session and IP, and can be limited to an **IP allowlist**.
- `install.sh` only accepts `hashem.sh` from GitHub itself, from two agreeing mirrors, or matching a pinned `HASHEM_SHA256`; otherwise it stops.
- Logs shown in the panel mask tokens and passwords (Backhaul prints rejected tokens verbatim).
- Backups include every panel config and Backhaul unit; restore refuses archives that reach outside the config directories and first saves a safety copy of the current state.
