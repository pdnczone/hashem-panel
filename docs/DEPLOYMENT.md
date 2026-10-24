# Secure Deployment Guide for Hashem Panel

This guide explains how to deploy `hashem-panel` securely in production environments.

---

## 1. Network Topology & Ports

By default:
- **HTTP Panel**: Port `7777` (or configured port)
- **HTTPS Panel**: Port `7443` (when TLS certificate is issued)
- **GRE Ingress**: IP protocol 47 (point-to-point tunnel)
- **FRP Reverse Bridge**: Ports `20000-60000` (customizable)

---

## 2. Reverse Proxy & HTTPS Configuration

Deploying behind a reverse proxy (e.g. Nginx or Caddy) provides TLS termination, DDoS filtering, and centralized access logging.

### Nginx Configuration

```nginx
# /etc/nginx/sites-available/hashem-panel
server {
    listen 443 ssl http2;
    server_name panel.example.com;

    ssl_certificate /etc/letsencrypt/live/panel.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/panel.example.com/privkey.pem;

    # Security Headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    location / {
        proxy_pass http://127.0.0.1:7777;
        proxy_http_version 1.1;

        # WebSocket support (for xterm.js terminal)
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";

        # Proxy headers
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }
}
```

### Caddy Configuration

```caddyfile
panel.example.com {
    reverse_proxy 127.0.0.1:7777 {
        header_up Host {host}
        header_up X-Real-IP {remote_host}
    }
}
```

---

## 3. Trusted Reverse Proxies (`TRUSTED_PROXY_IPS`)

To prevent IP spoofing attacks in rate-limiting and audit logging (CWE-348), configure `TRUSTED_PROXY_IPS`:

Set this variable in your systemd service or environment:

```bash
# /etc/systemd/system/gre-panel.service.d/override.conf
[Service]
Environment="TRUSTED_PROXY_IPS=127.0.0.1,::1,10.0.0.0/8"
```

Then reload systemd:
```bash
systemctl daemon-reload
systemctl restart gre-panel
```

When configured, the panel only extracts `X-Forwarded-For` or `X-Real-IP` if the incoming connection is from one of the specified trusted IPs/subnets. Direct connections from external clients will always be logged using their direct socket IP.

---

## 4. Firewall Hardening (UFW)

If using a reverse proxy on the same server, bind the panel to localhost or restrict external access to the panel port:

```bash
# Allow SSH
ufw allow 22/tcp

# Allow Web Traffic to reverse proxy
ufw allow 80/tcp
ufw allow 443/tcp

# Block direct access to panel port from external networks (if using local proxy)
ufw deny 7777/tcp

# Enable firewall
ufw enable
```

---

## 5. Environment Variables Reference

| Variable | Description | Default |
| -------- | ----------- | ------- |
| `GRE_PANEL_PASSWORD` | Ephemeral recovery password override applied on restart | *(none)* |
| `GRE_PANEL_PORT` | Custom listening port override | `7777` |
| `GRE_PANEL_DIR` | Panel configuration directory | `/etc/gre-panel` |
| `GRE_FRP_DIR` | FRP configuration directory | `/etc/frp` |
| `GRE_BACKHAUL_DIR` | Backhaul configuration directory | `/etc/backhaul` |
| `GRE_SYSCTL_CONF` | Path to sysctl configuration file for reverse path filtering | `/etc/sysctl.d/99-hashem-revpath.conf` |
| `TRUSTED_PROXY_IPS` | Comma-separated trusted reverse proxy IPs and CIDRs | *(empty)* |
| `GRE_SCRIPT` / `HASHEM_SCRIPT` | Path to installer script | `/usr/local/bin/hashem.sh` |
| `HASHEM_PPROF` | Enable pprof diagnostic endpoints (`/debug/pprof/`) behind auth | `0` (disabled) |
| `HASHEM_MIRROR_REPO` | GitHub mirror repository for FRP/Backhaul binary releases | `pdnczone/hashem-frp` |

---

## 6. Audit Logs & Monitoring

Security events, failed login attempts, terminal sessions, and updates are journaled in:
```bash
/etc/gre-panel/security-audit.log
```

Each log line includes UTC timestamp, event type, user, IP, and details:
```text
[2026-10-06T08:25:47Z] EVENT=login_success user="admin" ip=192.0.2.1 authenticated successfully
[2026-10-06T08:26:01Z] EVENT=terminal_connect user="admin" ip=192.0.2.1 session=a3f89b1c
```

Review this log regularly to monitor unauthorized access attempts.
