# Backhaul v0.7.2 end-to-end proof (netns lab)

Date: 2026-10-10. Lab: `tests/test_backhaul_e2e.sh` (hermetic, two namespaces `bh-hub` / `bh-spoke`, veth 192.0.2.1 <-> 192.0.2.2, control 18080, forward 18081, echo target 18082).

## 1. Sanity (binary)

```
$ sha256sum /tmp/backhaul-rel/backhaul
7f1b1439d7fe1d15ae0b376e15614fe13d8a12f6e07a90263e310ea2a9d601fb  /tmp/backhaul-rel/backhaul
$ backhaul --help
Usage of /tmp/backhaul-rel/backhaul:
  -c string
    	path to the configuration file (TOML format)
  -v	print the version and exit
$ backhaul -v
v0.7.2
```

- No subcommands: only `-c <toml>` and `-v`.
- License mechanism: `strings backhaul | grep -i licen` returned only `runtime.panicunsafeslicenilptr` and `runtime.panicunsafeslicenilptr1` (Go runtime symbols). No license check, key or server.
- **Correction to the brief:** the `LICENSE` file shipped next to the binary is **GNU AGPL v3** ("GNU AFFERO GENERAL PUBLIC LICENSE Version 3, 19 November 2007"), not MIT. Worth knowing before redistributing it from the hashem-panel release page (AGPL source-offer obligations).
- The sha256 was recorded but not compared to an upstream value (no network check done).

## 2. Lab results (`bash tests/test_backhaul_e2e.sh`)

```
ok:   a. handshake: tunnel established
ok:   a. no reconnect loop / invalid token in 10s+
ok:   b. echo 16 B byte-exact
ok:   b. echo 1 MiB byte-exact
ok:   c. wrong token rejected (data path must be down)
ok:   c. server logged the rejection
ok:   d. good client reconnects
ok:   d. data path back within 15 s of kill -9 (took 4s)
PASS test_backhaul_e2e
```

Configs used (server / client, transport `tcpmux`):

```toml
[server]  bind_addr="192.0.2.1:18080" transport="tcpmux" token="lab-token-e2e" heartbeat=5 log_level="debug" ports=["18081=127.0.0.1:18082"]
[client]  remote_addr="192.0.2.1:18080" transport="tcpmux" token="lab-token-e2e" retry_interval=1 dial_timeout=5 log_level="debug"
```

**Direction note (differs from the brief's wording).** Backhaul is a reverse tunnel: the server (hub) owns the public port and the client (spoke) dials the target. So the echo responder runs in `bh-spoke` (127.0.0.1:18082) and the probe connects to the hub's forwarded port 192.0.2.1:18081 from `bh-hub`. The literal "echo in hub, probe from spoke" direction cannot be expressed in Backhaul.

Evidence:

- **Handshake:** client log `attempting to establish a new tcpmux control channel connection...` then `control channel established successfully`; server log `control channel successfully established.` and `listener started successfully, listening on address: [::]:18081`. Zero `invalid`/`refused`/`reconnect` lines over the following 11 s.
- **Data path:** `os.urandom` payloads of 16 B and 1 MiB sent to 192.0.2.1:18081 are read back and compared byte-for-byte; mismatch fails the test. Also verified by hand with the panel-generated config (`echo: b'hello-panel-cfg'`).
- **Wrong token (negative control):** data path stays down, and the server logs `[WARNING] invalid security token received: wrong-token` once per client retry (1/s).
- **Restart:** `kill -9` on the client, restart; data path byte-exact again after 4 s (limit 15 s). The first kill/restart cycle recovered inside the 15 s wait too.

## 3. Failure catalog

No failures hit while building the lab: the script passed on the first run. Not invented. What follows are behaviours observed during the negative and restart steps (not failures of the lab):

| Situation | Exact log |
|---|---|
| Wrong token, server side | `[WARNING] invalid security token received: wrong-token` (token echoed in clear text) |
| Wrong token, client side (no explicit message) | `[ERROR] failed to receive control channel response: failed to read message length from net.Conn: EOF` (repeats every `retry_interval`) |
| Client killed, server side | `[ERROR] failed to read from channel connection. failed to read message from net.Conn: EOF` then `[INFO] restarting server...` (server re-listens ~2 s later) |
| Client sees control channel drop | `[ERROR] failed to read from control channel. failed to read message from net.Conn: EOF` then `[INFO] restarting client...` |
| v0.7.2 given the sectioned dialect that `hashem-backhaul.sh` writes (`[listener]`, `[transport] type=`, `[ports] mapping=`) | `[FATAL] neither server nor client configuration is properly set.` |

Not hit: bind conflict, transport mismatch, MTU issue (veth MTU 1500, no GRE in this lab).

Side effects checked: the binary logs `Successfully set rmem_max to 268435456` and also writes `net.core.wmem_max`, `rmem_default`, `wmem_default`, `somaxconn`, `tcp_fin_timeout`, `tcp_window_scaling` at startup. Inside a namespace these stayed namespace-local: host `/proc/sys/net/core/rmem_max` is still 16777216 with an unchanged mtime. On a real host (no netns) the process will change those sysctls globally.

## 4. Panel readiness gap list (read-only analysis, no panel code changed)

Also proven: the configs the panel itself writes (`writeBackhaulServerConfig` / `writeBackhaulClientConfig`, `panel/setup.go:1935,1975`) are accepted by the real v0.7.2 and carry traffic. The extra keys `web_port = 0` and `sniffer_log = ""` are ignored.

### (a) What would mis-detect or mis-manage a real pair like the lab's

1. **Two incompatible config dialects.** `hashem-backhaul.sh` (≈ lines 500–600) generates a sectioned "premium" schema (`[listener]`/`[dialer]`, `[transport] type`, `[mux] mux_concurrency`, `[ports] mapping`, `[tuning]`, `[accept_udp]`). The real v0.7.2 rejects it (`[FATAL] neither server nor client configuration is properly set.`). Anything installed via the "modified-backhaul" path, or any config in that dialect, will not run on the OSS binary, while the panel's TOML parsing assumes the flat one.
2. **TOML parsing is a line scanner.** `localStatusFrom` (`panel/tunnel.go:~689–730`) reads `transport`, `remote_addr`, `bind_addr`, and uses `strings.Split(line, ":")` for `bind_addr`; it would misread IPv6 `bind_addr`, sectioned `type =`, and a `transport` string inside a comment. `ports` are not parsed by this block for the sectioned dialect.
3. **Binary identity.** `engineBinaryPresent` / `backhaulExtraBins` (`panel/tunnel.go:566–600`) accept `/root/backhaul-core/backhaul_premium`, which `install_backhaul_binaries` (`hashem.sh:1827`) fills with a copy of whichever `backhaul` is installed; `hashem-backhaul.sh` units run `backhaul_premium`, while `setup_backhaul_*_systemd` (`hashem.sh:2001,2029`) run `${INSTALL_DIR}/backhaul`. Two different binary paths and version strings (`v2.0.0-hotfix8` fallback in `hashem-backhaul.sh:712`) mean the panel cannot tell which core/dialect a running unit uses. This host already has a `backhaul_premium` pair running under `/tmp/bhtest` from another session; the panel only keys off unit names, not binary or version.
4. **Unit-name-only role detection.** `localStatusFrom` (`panel/tunnel.go:~655–665`) maps `backhaul-server` / `backhaul-client` to roles. Per-peer units (`backhaul-server-<id>`, referenced in `panel/setup.go:~1333–1346`) are not in the main detection list; `snapshot.go:59` `baseUnits` lists only the two base names.
5. **Session detection depends on `ss` to `RHost:BindPort`.** `localSessionFrom` (`panel/snapshot.go:443`) works for the spoke (client holds a connection to hub:18080). With `connection_pool`/mux the client holds several ESTABLISHED sockets to the control port (observed 8 `initiating new tunnel connection` lines in the lab), which is fine, but the hub side has no equivalent; the hub learns "linked" only through peer records.
6. **Error handling hides failures.** `switchTunnelEngine` (`panel/tunnel.go:1088–1118`) discards every `writeBackhaul*Config` and `runSystemctl` error (`_ =`) and then prints "configured and started". A missing unit file or binary reports success.
7. **No unit creation in the panel path.** `ensureFRPServiceUnits` (`panel/tunnel.go:1136`) only handles frps/frpc. The `backhaul` / `gre-backhaul` cases `systemctl restart backhaul-server` assuming `hashem.sh` already wrote the unit. If the unit does not exist the restart fails silently (see 6).
8. **Engine logic duplicated in Go.** `switchTunnelEngine` writes `/etc/backhaul/config.toml` itself (`writeBackhaulServerConfig`, hard-coded `0.0.0.0:port`, `heartbeat = 40`, `log_level = "info"`), contradicting the CLAUDE.md rule that `hashem.sh` is the single source of setup logic, and diverging from what `hashem.sh` writes (different defaults, `/etc/backhaul/server.crt` hard-coded for wss at `panel/setup.go:1955`).
9. **Doctor has no backhaul awareness.** `panel/doctor.go` has `frpcLoginEOF()` (line 660) and restarts `frps`/`frpc` units (line 630–631) only. A real backhaul failure (`invalid security token received`, `failed to receive control channel response ... EOF`, token mismatch, transport mismatch) produces no issue and no hint.
10. **Log viewer can leak the token.** The real server logs the rejected client's token verbatim (`invalid security token received: wrong-token`). If a client mistypes its token, a near-miss of the real secret is visible in whatever panel log endpoint (`handleLogs`, `panel/tunnel.go:61`) tails `backhaul-server`; it should be redacted.
11. **Global sysctl side effects.** On a real host the binary raises `net.core.rmem_max/wmem_max` and others at start (proved harmless only inside netns). The panel's perf/tuning (`panel/perf.go`, `hashem.sh` tuning) is not aware of this and may fight or be overwritten by it.
12. **Restart semantics.** Backhaul restarts itself internally on control loss (`restarting server...` / `restarting client...`, ~2 s) instead of exiting. A process-level "unit active" check stays true across a dead session, so `FrpUp` can be true while no session exists. The probe fallback (`probeQueries`, `panel/snapshot.go`) covers part of this, but the watchdog `auto_restart` logic keyed to unit state would not fire.

### (b) Functions/files that need to change to install, monitor and switch to backhaul for real

| Need | File: function |
|---|---|
| One dialect, one binary path | `hashem-backhaul.sh` config writer (≈500–600) vs `hashem.sh:install_backhaul_binaries`, `setup_backhaul_server_systemd`, `setup_backhaul_client_systemd`; decide v0.7.2 flat vs premium and pin version |
| Binary detection / version | `panel/tunnel.go: engineBinaryPresent, backhaulExtraBins` (add `-v` check and a recorded version) |
| Robust config parsing | `panel/tunnel.go: localStatusFrom` (replace line scanner with a TOML parse or a `hashem.sh` status call), `panel/setup.go: rewriteBackhaulTomlPorts` |
| Install/switch through the script | `panel/tunnel.go: switchTunnelEngine` (backhaul and gre-backhaul cases): call `hashem.sh` instead of `writeBackhaul*Config`; stop dropping errors |
| Unit creation | `panel/tunnel.go: ensureFRPServiceUnits` (add a backhaul equivalent, or delegate to `hashem.sh`), `panel/doctor.go: ~630` |
| Health / session | `panel/snapshot.go: localSessionFrom, probeQueries, baseUnits`, `panel/health.go` (treat "unit active but control channel lost" as down for backhaul) |
| Doctor checks | `panel/doctor.go`: add backhaul log signatures (`invalid security token`, `failed to receive control channel response`, `neither server nor client configuration is properly set`) next to `frpcLoginEOF` |
| Log redaction | `panel/tunnel.go: handleLogs` |
| Tests | add a Go-side test that runs panel-written configs against the real binary (currently only `tests/test_backhaul_e2e.sh` does, with hand-written configs) |

## 5. Not proven

- WS/WSS/wsmux and UDP (`accept_udp`) transports: only `tcpmux` was exercised.
- Backhaul over GRE (`gre-backhaul`) and MTU behaviour: lab uses a plain veth, no GRE.
- Behaviour under load, many ports, or multi-peer (`server-<id>.toml`).
- Install via `hashem.sh` / systemd units: deliberately not run (no host changes allowed). The unit files were only read.
- The binary's sha256 against an upstream checksum.
- Whether the panel's status page actually renders this pair: the panel was not run against the lab.
