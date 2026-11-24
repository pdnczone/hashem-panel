# Telegram bot (Hashem Pro)

Run the panel from a Telegram chat: tunnel status, restarts, the watchdog,
Autopilot, alerts, customers, the doctor, backups, logs, updates, and any
other panel API request.

[فارسی](TELEGRAM_BOT.fa.md)

## Set it up

1. In Telegram, talk to **@BotFather**, send `/newbot` and copy the token it
   gives you. Make **one bot per server**: two servers polling the same token
   steal each other's messages (the panel then shows "another program reads
   this bot's messages").
2. In the panel: **Settings → Alerts & monitoring → Telegram bot**. Paste the
   token, pick the bot's language (Persian or English), tick **Enable the
   bot** and press **Save**.
3. Pick **Admin** or **Viewer** and press **Get a Pairing Code**. Open the
   link it shows in Telegram (or send `/start CODE` to your bot). The code
   works once, for 10 minutes. Pair each account you want to use the bot.

The badge on the card says whether the bot is running, and its last error.
**Send Test** checks the token and sends a message to everyone who gets alerts.

### One bot for everything

The same bot carries the menu and every alert: the watchdog's, Autopilot's and
the external alerts. They go to every paired account, and to the **alert chat**
on the card when one is set (a group or channel; add the bot to it). An account
mutes its own alerts in the bot (🔔 Alerts) or on the card.

Older versions had a second token in the Watchdog tab. At the update the bot
that is on and has paired accounts stays, else the watchdog's; the other token
is kept in `telegram_bot.json`, unused.

### When Telegram is blocked on the server

Nothing to set: on the **Automatic** route the bot goes straight out from this
server, and when that fails, through this server's tunnels (healthy ones
first). The card says which way it is connected. **Direct only** and one chosen
tunnel (then direct) are the other choices.

The tunnel's foreign panel makes the connection, over the Peer Link the panels
already share, and only to Telegram and Cloudflare. So it needs an FRP,
Backhaul or GRE tunnel whose foreign server runs this panel. Xray, Bagher and
Spoof tunnels have no such relay.

## What it can do

| Menu | What you get |
|---|---|
| 📊 Status | every tunnel's state, latency, traffic, and why it is not healthy |
| 🔗 Tunnels | every tunnel of this server (hub links, a foreign server's own tunnel and its other Iran hubs, Xray, Bagher, Spoof): details; restart relay, restart GRE, ping, rename, remove; restart or stop an Xray link |
| 🗂 Nodes | on a central: its nodes, their state and number of tunnels (read only) |
| 🐶 Watchdog | on/off, auto-restart, test message, restart every tunnel, back up now, each tunnel's watchdog state |
| 💾 Backups | the last 10 backups: download (the encrypted file), restore |
| 🤖 Autopilot | on/off, each tunnel's carrier and state, recent switches |
| 🔔 Alerts | on/off, Telegram copy, degraded alerts, test; mute the alerts to this account |
| 👥 Customers | each customer's usage, end date and links; pause/resume, renew, reset usage, remove |
| 🩺 Doctor | the last report, run again, Quick Repair |
| 🛠 Tools | optimize / restore the network tuning, tuning status, tunnel health test, carrier advice, limits, Sentinel |
| 📜 Logs | the services' last 400 log lines, as a file |
| ❗️ Errors | the last 20 panel errors |
| ⬆️ Update | running and latest version, update now (the bot says when the panel is back); **Other servers**: the linked Iran hubs and foreign servers with their versions, update every one on another version |
| 🌐 Cluster | the cluster's status |
| 🔑 License | the license's state and Pro features (read only) |

Everything else the panel does is reachable with **`/api`**, a request straight
to the panel's API ([API.md](API.md)):

```
/api GET /api/peers
/api POST /api/action {"action":"ping","peer_id":2}
/api PATCH /api/peers {"id":2,"ports":"443, 8443"}
```

Anything but `GET` asks once more before it runs.

Commands: `/menu /status /tunnels /watchdog /autopilot /customers /doctor
/errors /logs /update /api /cancel /help /id`.

## Who can use it

- Only accounts paired from the panel, and only in a **private chat** with the
  bot. Groups and channels are ignored, so nobody in a group can send it
  commands. An unpaired account gets one short answer with its Telegram ID.
- **Admin** may do everything above; **Viewer** may only look at the menus (not `/api`, the cluster, limits, Sentinel or carrier advice, whose full answers can hold tunnel tokens and keys).
- Every button carries a tag of its server: when two servers share one bot token, a button from one server's message does nothing on the other.
- A new pairing is announced to the other admins. Remove an account, or change
  its role, on the card.
- Five wrong pairing codes in ten minutes and that account is not heard for a
  while.

## Safety

- Every action goes through the panel's own API handlers, in process: the same
  checks, Pro gates and audit log as the page (audit lines say
  `via_telegram`).
- Removing a tunnel or a customer, restoring a backup, updating, Quick Repair,
  network tuning, restarting every tunnel and every `/api` change ask again
  with a **one-time button that lasts 2 minutes**, which only the account it
  was shown to can press.
- Messages sent to the bot while the panel was down are dropped when it starts,
  so an old command never runs after a restart.
- The token never appears in logs or errors.

## What it cannot do

- **The server's terminal.**
- **Login, password, 2FA and the panel's access settings** (port, user, path).
- **Entering a license key** (only in the panel), or turning the panel into a
  node core.
- **Creating a tunnel or a customer with the wizard.** Create them in the
  panel (or with `/api` if you know the request body).
- **Uploading files**, such as a custom TLS certificate or a backup to restore
  from your computer. Restoring a backup the server already has works.
- **Charts**: text only.
- **Managing other nodes**: each server's bot manages that server only (a
  central's bot shows its nodes).
- **When the server cannot reach Telegram** (blocked, and every tunnel is down
  too) the bot is silent until it can, and so are the alerts.
- Long jobs (an update, a doctor run) answer when they finish; Telegram shows
  "⏳" until then.
