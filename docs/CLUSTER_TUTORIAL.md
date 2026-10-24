# Hashem Cluster: How It Works, and a Hands-On Tutorial

**English** · [فارسی](CLUSTER_TUTORIAL.fa.md)

This page explains what the cluster does under the hood, in plain words, and then walks you through building one, lesson by lesson, breaking it on purpose and watching it recover. For every setting and command, see the [Cluster guide](CLUSTER.md).

- [Part 1: How it works](#part-1-how-it-works)
- [Part 2: Tutorial](#part-2-tutorial)
- [Checklist before production](#checklist-before-production)

---

## Part 1: How it works

### The problem

A normal Hashem setup is one Iran server and one foreign server. Users connect to the Iran server's IP, and the tunnel carries them to the foreign server, where xray (or any service) runs. If the foreign server, its tunnel or xray dies, every user is cut off until someone fixes it by hand.

```text
users ──► Iran server ══tunnel══► foreign server ──► xray
                         one of each: any failure = everyone down
```

### The idea

The cluster puts several foreign servers behind the same port, and if you like, several Iran servers in front of them. Something then has to decide, for every new connection, which server takes it, and notice within seconds when one stops working.

```text
                         ┌══tunnel══► foreign A ──► xray
users ──► Iran :443 ─────┼══tunnel══► foreign B ──► xray
            (pool)       └══tunnel══► foreign C ──► xray (standby)
```

### What happens to one connection

1. A user connects to the Iran server's public IP, port 443.
2. The Linux kernel (not the panel) looks at the pool's rules and picks a foreign server, according to the pool's mode.
3. The connection is sent (DNAT) to that server's relay on the Iran server. Each pooled relay (`frps` / `backhaul-server`) listens on its own private address, `169.254.77.N`, instead of the public one.
4. The relay carries it through its tunnel to the foreign server, which hands it to xray.
5. The kernel remembers the choice (conntrack): every packet of this connection keeps going to the same server until it closes.

Because the kernel does the switching, there is no extra program in the path: no speed is lost, the user's real IP still reaches the relay (PROXY protocol keeps working), and restarting or updating the panel drops no connection.

### How a failure is noticed

Every second, the panel checks each foreign server three ways:

| Check | Catches |
|---|---|
| **Tunnel session:** is the foreign client still connected to its relay? | foreign server down, frpc/backhaul-client stopped, tunnel cut |
| **Ping on the tunnel's own path** (only for servers that answer ping) | the path breaking before the session times out |
| **Service check** (optional): a real connection through the tunnel to xray | xray crashed while the tunnel is fine |

One bad check is not enough: a server is taken out after **3 failed checks in a row**, and put back after **3 good ones**. That way a short hiccup does not move everyone back and forth.

### What happens when a foreign server dies

```text
t = 0 s     foreign A dies
t ≈ 3 s     3 failed checks: A is out. The kernel rules are rewritten at once:
            new connections go to B (and C, by the mode)
            the Cluster map turns A's line red; an event and a Telegram alert go out
t ≈ 3-10 s  users who were on A see their connection drop; their app reconnects
            by itself and lands on B
later       A comes back, passes 3 checks, and gets new connections again
            (or stays out until you press Fail Back Now, with manual failback)
```

Users already on B never notice anything. Users on A see a short reconnect, which VPN apps do by themselves.

### Several Iran servers

Two more pieces cover the Iran side:

- **One foreign server can serve several Iran servers** (`join-hub`). If one Iran server dies, the users connected to the other ones keep working.
- **Linked Iran hubs** exchange a signed heartbeat every 3 seconds. If every foreign server of a pool is down on one Iran hub, that hub forwards the port to another Iran hub where the same pool works.
- **DNS failover:** users connect to a name (`vpn.example.com`) instead of an IP, and the name always lists only the Iran hubs that work.

```text
            ┌──► Iran 1 ══╗
vpn.example.com           ╠══► foreign A, B, C
            └──► Iran 2 ══╝      (each foreign server joined both hubs)
     DNS keeps only the working Iran hubs
```

---

## Part 2: Tutorial

You need:

- **Hashem 2.5.0 or later** on every server.
- A **Hashem Pro** license on the Iran servers (and on foreign servers that join a second hub).
- **One Iran server and two foreign servers** to start. A third foreign server and a second Iran server are needed for the later lessons.
- A service on each foreign server, on the same port. The examples assume xray / 3x-ui on **443**.

The lessons use the panel. Each one also shows the terminal command that does the same thing.

### Lesson 1: The first tunnel

1. On the **Iran** server, open **Setup** and add foreign server A as usual, with port `443` (GRE + FRP or Backhaul, as you like). Copy the bundle it prints and paste it in **Setup** on server A. If A is your main tunnel, it is already there.
2. Open **Tunnel** on the Iran server and check that the tunnel is up.

```bash
hashem peer-list      # on the Iran server: the tunnels, with their ids (0 = main, N = peer N)
```

### Lesson 2: Your first pool, and a second server on the same port

1. Open **Cluster**. The map shows this Iran hub in the middle and A on the right.
2. Click **+ New Pool**: port `443`, protocol **TCP** (or TCP and UDP), mode **Failover**. A is already ticked because it carries port 443. Click **Save Pool**. Wait a few seconds while A's relay restarts once to move behind the pool.
3. Now add foreign server B in **Setup**, also with port `443`, and paste its bundle on B. Before the pool existed, port 443 belonged to A alone and B would have been refused. Now the pool covers it, so B is accepted and joins the pool by itself.
4. Click the line from pool 443 to B, set **Priority** to `1`, and **Save**. The map now shows a thick green line to A (100% of new connections) and a thin grey line to B (healthy, idle).
5. Connect with your VPN app as usual. Nothing changes for the user: same IP, same port.

```bash
hashem cluster pool add 443 --mode failover       # after A exists
# add B in Setup (or hashem add-peer ... --ports "443"), then:
hashem cluster member set 443 2 --priority 1
hashem cluster status
```

### Lesson 3: Break it, watch it recover

1. Keep the Cluster tab open, and stay connected with your VPN app.
2. On foreign server **A**, stop its tunnel client:

   ```bash
   systemctl stop frpc                # Backhaul: systemctl stop backhaul-client
   ```

3. Watch the map. Within about 3 seconds:
   - A's dot and line turn red;
   - the green line moves to B;
   - the pool says **Degraded**;
   - the Events list says A is down and traffic goes to B.
4. Your VPN app reconnects by itself, through B. Check that browsing still works.
5. Start A again with `systemctl start frpc`. After 3 good checks, new connections go back to A.

> **Tip:** Settings → Alerts sends these events to Telegram or a webhook, so you hear about a failover without looking at the panel.

### Lesson 4: Spread the load

1. Click pool **443** on the map. In the inspector, pick **Least connections** (or **Balance**), then **Save Pool**.
2. Click the **line** from pool 443 to A. Move the **Weight** slider to `2` and **Save**. A now takes about twice as many users as B.
3. Watch the map: both lines are green, their thickness shows each server's share, and each server shows its open connections.

Which mode to pick:

| You want | Mode |
|---|---|
| One main server, the others only as backup | Failover |
| Every user to keep the same exit IP | Sticky per user |
| Many users, long connections (VLESS, VMess) | Least connections |
| Many short connections | Balance |
| Always the fastest path | Lowest latency |

### Lesson 5: Catch a dead xray (service check)

1. Click pool 443, tick **Service check: connect through the tunnel to the service**, keep **Check every** at `3`, and click **Save Pool**.
2. On foreign server A, stop the service only, and leave the tunnel up:

   ```bash
   systemctl stop x-ui        # or: systemctl stop xray
   ```

3. Within about 10 seconds, A shows **Service down** with the reason, and its line turns red. Without the service check, the tunnel would still look healthy, and users sent to A would get nothing.
4. Start the service again: A comes back after 3 good checks.

```bash
hashem cluster pool set 443 --check tcp --check-every 3
```

### Lesson 6: Standby, limits and maintenance

1. Add a third foreign server C with port 443 in Setup. It joins the pool by itself. Click its line and tick **Standby**: C gets traffic only when A and B are both down (or full).
2. Click A's line, set **Max connections** to `500`, and **Save**. When A reaches 500 open connections, new ones go to B, then to C.
3. **Maintenance on B:** click B's line, tick **Drain**, and **Save**. B gets no new users, and the ones on it finish what they are doing. Update or reboot B, then untick **Drain**.

```bash
hashem cluster member set 443 3 --backup yes
hashem cluster member set 443 0 --max-conn 500
hashem cluster member drain 443 2      # later: member resume 443 2
```

### Lesson 7: A second Iran server

1. On the second Iran server (Iran 2), open **Setup** and add foreign server A as a peer, with the same port 443. Copy the bundle.
2. On foreign server A, go to **Cluster → + Join Another Iran Hub**, paste the bundle, and press **Join Hub**. A now serves both Iran servers; its map shows both hubs.
3. On Iran 2, make the same pool on port 443 (Lesson 2), then add B (and C) on Iran 2 and join them the same way.
4. Users of Iran 1 and of Iran 2 now share the same foreign servers. If Iran 1 dies, Iran 2's users are untouched.

```bash
hashem join-hub --bundle hsh1_... --name iran-2     # on each foreign server
hashem hubs
```

### Lesson 8: Iran hubs that back each other up

1. On Iran 1: click **This Iran hub** on the map, then **Show Join Code**, and copy it.
2. On Iran 2: click **+ Link a Hub** and paste the code. Both maps now show the other hub on the left, with a blue dashed line.
3. Test: on each foreign server, stop only its client for Iran 1 (`systemctl stop frpc` when Iran 1 was its first hub, else `frpc-hN`; `hashem hubs` lists them). Pool 443 on Iran 1 shows **Forwarded to Another Hub**: users who still reach Iran 1 are sent through Iran 2.

### Lesson 9: One name for everyone (DNS failover)

1. In Cloudflare, create an `A` record `vpn.example.com` with the IP of Iran 1, **DNS only** (grey cloud). Create an API token with *Zone → DNS → Edit*.
2. On each Iran hub, click **DNS Failover** on the map, then fill in:
   - **Provider:** Cloudflare;
   - **Record name:** `vpn.example.com`;
   - **API token:** the token from step 1;
   - **TTL:** `60`.

   Press **Test**, tick **Keep the record pointed at the working hubs**, and **Save**.
3. Give your users `vpn.example.com` instead of an IP. The record now lists both hubs. Stop Iran 2's panel, and within about a minute, `dig +short vpn.example.com` shows only Iran 1.

Another DNS provider? Choose **Webhook** and let your own script set the record. See the [Cluster guide](CLUSTER.md#92-webhook).

### Lesson 10: Keep an eye on it

- **The map** answers "is everything fine?" at a glance. **List** shows the same data as tables.
- **Events** (under the map) keeps the last 200 failovers and changes.
- **Alerts:** Settings → Alerts, Telegram or webhook.
- **Prometheus:** `/metrics` includes pool state, member health, share and connections.
- **Terminal:**

  ```bash
  hashem cluster status
  hashem cluster events
  hashem cluster rules
  ```

---

## Checklist before production

- [ ] Every server runs the same Hashem version, and clocks are synced (`timedatectl set-ntp true`).
- [ ] Each pool has at least two members that are really independent (different providers or data centers).
- [ ] The service check is on for TCP pools.
- [ ] Alerts go to Telegram or a webhook.
- [ ] Linked hubs can reach each other's panel port; DNS records are DNS only.
- [ ] You tested a failover once (Lesson 3) and saw the alert arrive.
- [ ] Maintenance uses **Drain** first, never a plain reboot under load.

Questions, or something behaved differently from this page? Look at **Events** first, then [Troubleshooting](CLUSTER.md#14-troubleshooting).
