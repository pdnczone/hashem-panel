# Hashem Panel

Web control panel for the GRE+FRP tunnel stack (login inspired by Hashem panel).
Single Go binary, no dependencies. Install on **both** servers — each panel
configures only its own side, and shows the other side via Peer link.

## Features

- **Setup tunnel from web** — pick a role per server:
  - 🇮🇷 Iran: GRE + frps (token auto-generated, shown for copy)
  - 🌍 Foreign: GRE + frpc (token entered manually, ports like `443, 2083`)
- Auto-detected local public IP (editable), editable GRE inner IPs
  (default `10.10.10.2` / `10.10.10.1`), editable FRP port (default 7000)
- frps/frpc auto-download if missing, TLS on, TCP+UDP per port
- Auto ping test after setup + step-by-step log
- Overwrite guard: warns if a tunnel already exists, needs explicit confirm
- Tunnel status (GRE/FRP/ping), restart actions, live logs, peer view

## One-line install (recommended)

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/pdnczone/hashem-panel/main/install.sh)
```

Then pick **7) Install Web Panel** — it builds the Go binary, installs the
`gre-panel` systemd service and prints the panel URL + password.
Option **8) Show Panel URL** reprints the URL anytime.

After install, control it from SSH with:

```bash
grepanel status     # panel + tunnel state
grepanel url        # print panel URL
grepanel logs       # panel logs
grepanel restart    # restart panel
grepanel password   # reset password (prints new one)
grepanel uninstall  # remove panel (keeps /etc/gre-panel config)
```

## Manual build & run

```bash
cd panel
go build -o gre-panel .
sudo ./gre-panel            # listens on :7777 under a secret path
sudo GRE_PANEL_DIR=/etc/gre-panel ./gre-panel
```

First start prints an 8-digit password (`admin` user). Change it from Settings.
For tests/dev: `GRE_PANEL_PASSWORD=... ./gre-panel` sets a fixed password.

Get the URL: `sudo cat /etc/gre-panel/panel.json` → open
`http://<server-ip>:7777/<base_path>`.

## Tunnel setup walkthrough

1. Install the panel on **both** servers, open each URL, log in.
2. On the **Iran** panel → Setup: role Iran, check local public IP,
   enter Foreign public IP, Apply → **copy the shown token**.
3. On the **Foreign** panel → Setup: role Foreign, check local public IP,
   enter Iran public IP, paste token, enter reverse ports (e.g. `443, 2083`),
   Apply → wait for GRE ping OK in the step log.
4. Optional → Peer card: link the panels (use GRE inner IPs,
   e.g. `http://10.10.10.1:7777/<secret>`) to see both sides in one place.
