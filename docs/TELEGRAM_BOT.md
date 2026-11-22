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
   token, or leave it empty to use the Watchdog tab's bot. Pick the bot's
   language (Persian or English), tick **Enable the bot** and press **Save**.
3. Pick **Admin** or **Viewer** and press **Get a Pairing Code**. Open the
   link it shows in Telegram (or send `/start CODE` to your bot). The code
   works once, for 10 minutes. Pair each account you want to use the bot.

The badge on the card says whether the bot is running, and its last error.
**Send Test** checks the token and sends a message to every paired account.

### When Telegram is blocked on the server

The bot uses the **watchdog's Telegram route**. In the Watchdog tab, set the
route to "through a tunnel" and pick a tunnel: the bot then reaches Telegram
through the foreign server, and falls back to a direct connection when that
fails.

## What it can do

| Menu | What you get |
|---|---|
| 📊 Status | every tunnel's state, latency, traffic, and why it is not healthy |
| 🔗 Tunnels | per tunnel: details, restart relay, restart GRE, ping, rename, remove |
| 🐶 Watchdog | on/off, auto-restart, test message, restart every tunnel, back up now, each tunnel's watchdog state |
| 💾 Backups | the last 10 backups: download (the encrypted file), restore |
| 🤖 Autopilot | on/off, each tunnel's carrier and state, recent switches |
| 🔔 Alerts | on/off, Telegram copy, degraded alerts, test |
| 👥 Customers | each customer's usage, end date and links; pause/resume, renew, reset usage, remove |
| 🩺 Doctor | the last report, run again, Quick Repair |
| 🛠 Tools | optimize / restore the network tuning, tuning status, tunnel health test, carrier advice, limits, Sentinel |
| 📜 Logs | the services' last 400 log lines, as a file |
| ❗️ Errors | the last 20 panel errors |
| ⬆️ Update | running and latest version, update now (the bot says when the panel is back) |
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
- **Other nodes**: each server's bot manages that server only.
- **When the server cannot reach Telegram** (blocked, and the routing tunnel is
  down too) the bot is silent until it can. The watchdog's alerts use the same
  route and fall back to direct.
- Long jobs (an update, a doctor run) answer when they finish; Telegram shows
  "⏳" until then.
