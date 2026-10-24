# Troubleshooting

Start with the tools, then look up the code.

```bash
hashem status          # tunnel health, peers, service status (and a tcpMux hint if it sees a mismatch)
hashem doctor          # latency, jitter, MTU, speed; names the failing leg
hashem doctor fix      # Quick Repair from the Diagnostics tab, then a new diagnosis
hashem logs            # relay logs
hashem dial status     # foreign side: how it reaches the hub (GRE inner IP or public IP)
journalctl -u gre-panel -n 100 --no-pager
```

Every failure shown in the panel has a code such as `E-FRP-10`. Meaning and fix for each code: [ERROR_CODES.md](ERROR_CODES.md). The same codes annotate raw log lines in the **Logs** tab.

## The service names

| What | systemd unit |
| --- | --- |
| Iran hub relay | `frps` (per-peer: `frps-*`, `frps-wss*` for the TLS front) |
| Foreign relay (FRP) | `frpc` |
| Backhaul | `backhaul-server`, `backhaul-client` (per-peer: `backhaul-server-N`) |
| GRE link | `gre-tunnel.service` |
| Panel | `gre-panel` |
| Watchdog | `hashem-watchdog.timer` / `.service` |

Configs: `/etc/frp`, `/etc/backhaul`, `/etc/gre-panel`. Encrypted backups: `/var/backups/hashem`.

## Tunnel is down or degraded

**1. Which leg is down?** The Dashboard and `hashem status` use one rule: Healthy = (GRE up and relay up and ping ok) or (relay up and the spoke holds an established session — *linked*). Degraded = one leg only. Down = none.

**2. `FRP only` badge.** The relay session is up but the GRE inner address does not answer ICMP. Traffic flows; GRE is blocked or ICMP is filtered. Not an outage. To get GRE back: open IP protocol 47 between the two public IPs in both directions, or switch the carrier to WSS (`hashem carrier`).

**3. GRE never comes up.**
- `ip tunnel show` / `ip -d link show type gre` — is the `gre-tunnel` interface there? (`E-GRE-01`)
- `modprobe ip_gre` — the kernel module must load (some minimal or container hosts cannot).
- Check both firewalls (provider panel and host) allow **protocol 47** — not TCP, not UDP.
- On many hosts the public IP differs from the interface IP (NAT). Use the address the other side actually sees.

**4. Relay cannot connect.**

| Code | Cause | Fix |
| --- | --- | --- |
| `E-FRP-04` | refused / timeout | wrong hub IP or control port, the port is closed on the hub firewall, or `frps` is not running |
| `E-FRP-02`, `E-BH-01` | token mismatch | copy the token again from the Iran peer card or regenerate the bundle |
| `E-FRP-10` | `connect to server error: EOF` — tcpMux mismatch | `hashem perf tcpmux on` or `off` on every server so they agree |
| `E-BH-02` | Backhaul control channel EOF | usually a wrong token or a different transport on the two ends — set the same transport and token |
| `E-BH-03` | Backhaul rejected the config | the binary does not understand the config dialect — rerun the Backhaul setup in `hashem` |
| `E-FRP-03` | bind conflict | another tunnel uses that port; change the frp port or the reverse port |

**5. Drops under load.**

| Code | Meaning | Fix |
| --- | --- | --- |
| `E-FRP-05` | too many open files | `LimitNOFILE=1048576` in the unit and a high `fs.file-max`; `hashem optimize` |
| `E-FRP-06` | heartbeat timeout | jitter or saturation delayed heartbeats; check `hashem doctor`; heartbeat is already relaxed to 90 s |
| `E-FRP-07` | connection reset / broken pipe | the network or the peer reset the stream |
| `E-FRP-08` | conntrack table full | `hashem optimize` raises `nf_conntrack_max` |
| `E-FRP-09` | yamux stream capacity | raise `poolCount` or leave **Auto Pool** on (default) |

For MTU trouble (large transfers stall, small ones work): `hashem doctor` tests MTU. The GRE interface uses 1380 (1360 on WSS); `hashem optimize` adds MSS clamping.

## Panel problems

- **Cannot open the panel.** `hashem show-panel-url` prints the real URL and port. If port 7777 was busy the panel moved to the next free one. Open that port in the firewall.
- **Forgot the password.** `hashem reset-password`.
- **Locked out (`E-AUTH-02`).** 5 failed logins lock the IP for 15 minutes; repeat offenders double up to 24 hours. Wait, or `systemctl restart gre-panel` (lockouts are held in memory).
- **Lost the 2FA device.** Use a recovery code. If you have none: set `GRE_PANEL_PASSWORD` for the service, remove `totp_enabled` from `/etc/gre-panel/panel.json`, restart `gre-panel`.
- **Terminal says it is disabled (`E-TERM-11`)** or not allowed (`E-TERM-12`). The terminal is off by default; enable it in Settings, and add your IP to the allowlist if one is set.
- **Behind a reverse proxy, every client shows the proxy IP.** Set `TRUSTED_PROXY_IPS`; see [DEPLOYMENT.md](DEPLOYMENT.md).
- **HTTPS certificate fails (`E-TLS-05`).** Port 80 must be reachable and the domain must resolve to this server. `E-TLS-04`: install `certbot`.

## Updates

- **`E-UPDATE-01` / `-02`.** GitHub is not reachable from the server. Nothing was changed; retry.
- **`E-UPDATE-07` checksum failed.** The download did not match the release's `checksums.txt`. The update is refused; retry. Only if you understand the risk, `GRE_PANEL_ALLOW_UNVERIFIED_UPDATE=1` skips the check.
- **The panel went back to the old version.** The new build crashed three times before it confirmed it was healthy, so the old binary and `hashem.sh` were restored. Read `journalctl -u gre-panel` for the crash, then report it.
- **Hub and spoke on different versions.** Both sides can run different panel versions; update each with `hashem update`, or install the same tag from the **Update** tab.

## Watchdog and alerts

- **It alerts but does not restart.** That is the default: `auto_restart` is off. Enable it in the Watchdog tab if you want restarts.
- **No Telegram messages.** Test with `hashem watchdog test` or `hashem tgsend "test"`. The server must reach `api.telegram.org`, which Iranian servers often cannot — use the webhook alert instead, or send from the foreign side.

## When you ask for help

Open an issue with: the panel/`hashem` version, the engine and carrier, the **error code**, and the last relevant lines of `hashem logs`. Remove tokens and bundles (`hsh1_…`, `bh1_…`, `gh1_…` contain the token) first. Panel logs already mask tokens, but your shell history does not.
