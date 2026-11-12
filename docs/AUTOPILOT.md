# Autopilot

**Autopilot** (Hashem Pro) moves a tunnel that stays down to a carrier that
gets through, on both servers, without you. It has its own **Autopilot** tab
on the Iran server, and is off until you turn it on.

## What it does

1. The panel's health model reports a tunnel as down. Autopilot waits until it
   has been down for the minutes you set (5 by default).
2. It asks the foreign panel whether it answers. If it does not, nothing is
   changed.
3. It runs the [path test](ENGINES.md) between the two servers: this server
   starts the test and tells the foreign server to join it. Every transport is
   measured as the network is at that moment.
4. It moves the tunnel to the fastest carrier that got through, with the same
   carrier swap as the **Swap carrier** button. The swap puts both servers back
   on the old carrier when the tunnel does not connect within 45 seconds, and
   Autopilot then tries the next carrier, three at most in one run.
5. It writes what it did to its history and sends it to your webhook and
   Telegram.

A carrier is an engine and a transport: `frp:kcp`, `backhaul:wssmux`,
`gre-backhaul:tcpmux`. A tunnel that is down on a GRE carrier is first moved
off GRE (protocol 47 being blocked is the usual reason), and a tunnel without
GRE addresses is never moved onto GRE.

## What it needs

- **The Iran server.** The Iran side swaps a tunnel; the foreign side follows.
- **A foreign panel that answers on its public address.** With the tunnel down
  there is no other way to tell the foreign server. If its panel port is closed
  to the Iran server, Autopilot records "the foreign panel does not answer" and
  changes nothing.
- **The same release on both servers** for the path test. With an older foreign
  panel Autopilot skips the test and tries the carriers in order.
- **A license on both servers.** The path test and Backhaul are Pro on the
  foreign server too.
- **The engine's binary** on both servers for the carrier it moves to (`frps`
  and `frpc`, or `backhaul`).

## What it leaves alone

- A tunnel it has not seen up since it was turned on: a tunnel you are still
  setting up is not switched.
- A tunnel whose service is stopped on this server: that is not a blocked path
  (the watchdog restarts services).
- Xray, Bagher and Spoof tunnels: they have no carrier to swap.
- A tunnel you switched off in the list.
- A tunnel that came back while the path was being tested.

## The limits

| Setting | Default | Meaning |
| --- | --- | --- |
| Minutes down | 5 | how long a tunnel must be down first (2–720) |
| Minutes between two runs | 30 | per tunnel (10–1440) |
| Runs in 24 hours | 6 | per tunnel (1–24) |
| Test the path first | on | off: the carriers are tried in order |
| Quiet hours | none | no switching between these hours, server time |
| Allowed carriers | all | only these are ever chosen |

A carrier that did not connect is tried last for the next 6 hours. One tunnel
is handled at a time, the one down longest first. A run during which the
foreign panel did not answer does not count toward the daily limit.

## From SSH

```
hashem autopilot status
hashem autopilot on -down 5 -cooldown 30 -per-day 6
hashem autopilot on -no-path-test
hashem autopilot off
```

`status` and `off` never ask for a license.

## Files

| File | Holds |
| --- | --- |
| `/etc/gre-panel/autopilot.json` | the settings |
| `/etc/gre-panel/autopilot_state.json` | the last 100 events, and per tunnel the runs and the carriers that failed |

Every run is also in the audit log (`autopilot_switched`, `autopilot_failed`,
`autopilot_skipped`, `autopilot_recovered`).

## When it does not switch

Open the **Autopilot** tab. Next to each down tunnel is the reason Autopilot
is waiting ("down for 2 of 5 minutes", "next run in 12 minutes", "quiet
hours"), and the history says what the last run found.

| History says | Do this |
| --- | --- |
| the foreign panel does not answer | open the foreign panel's port to the Iran server's IP |
| the foreign panel is older than Autopilot | run `hashem update` on the foreign server |
| no other allowed carrier got through the path test | the path between the two servers is blocked for every transport tested: try another foreign server or IP, or the Xray, Bagher or Spoof tunnel |
| tried …: did not connect | the carriers were tried and both servers are back on the old one; the next run tries others |
