#!/usr/bin/env python3
"""E2E: run the real panel binary in an isolated dir and verify the ledger.

Uses a throwaway GRE_PANEL_DIR on a spare port. The live panel on :7777 and
/etc/gre-panel are never touched. Because this host has a real gre-tunnel
interface, the binary will record that interface's real counters, which is
exactly what we want to prove end to end.
"""
import json, os, shutil, signal, subprocess, sys, tempfile, time, urllib.request, urllib.error, http.cookiejar

BIN = sys.argv[1]
PORT = 7791
d = tempfile.mkdtemp(prefix="panel-e2e-")
env = dict(os.environ, GRE_PANEL_DIR=d, GRE_PANEL_PORT=str(PORT), GRE_PANEL_PASSWORD="E2e-Test-Pass-12345!",
           GRE_SKIP_PANEL="1", HASHEM_NO_SDNOTIFY="1")
env.pop("NOTIFY_SOCKET", None)

def start():
    p = subprocess.Popen([BIN], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    return p

def base_path():
    return json.load(open(os.path.join(d, "panel.json")))["base_path"]

def login():
    cj = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    bp = base_path()
    req = urllib.request.Request(f"http://127.0.0.1:{PORT}/{bp}/api/login",
        data=json.dumps({"username": "admin", "password": env["GRE_PANEL_PASSWORD"]}).encode(),
        headers={"Content-Type": "application/json"})
    op.open(req, timeout=10).read()
    return op, bp

def get(op, bp, path):
    return json.load(op.open(f"http://127.0.0.1:{PORT}/{bp}{path}", timeout=10))

def wait_up():
    for _ in range(60):
        try:
            if os.path.exists(os.path.join(d, "panel.json")):
                bp = base_path()
                urllib.request.urlopen(f"http://127.0.0.1:{PORT}/{bp}/api/health", timeout=2).read()
                return
        except Exception:
            pass
        time.sleep(0.5)
    raise SystemExit("panel did not come up")

fails = []
def check(name, ok, extra=""):
    extra = str(extra) if extra != "" else ""
    print(("PASS " if ok else "FAIL ") + name + (("  " + str(extra)) if extra else ""))
    if not ok: fails.append(name)

p = start()
try:
    wait_up()
    # unauthenticated must be refused
    bp = base_path()
    try:
        urllib.request.urlopen(f"http://127.0.0.1:{PORT}/{bp}/api/traffic/usage", timeout=5)
        check("unauthenticated usage is refused", False)
    except urllib.error.HTTPError as e:
        check("unauthenticated usage is refused", e.code == 401, e.code)

    op, bp = login()
    # let two snapshot ticks happen so a baseline + delta exist
    time.sleep(14)
    u = get(op, bp, "/api/traffic/usage?range=7d")
    check("api reports 7-day retention", u.get("keep_days") == 7, u.get("keep_days"))
    keys = [l["key"] for l in u["links"]]
    check("hub total present first", keys and keys[0] == "total", keys)
    print("   links:", [(l["key"], l["name"], l["rx"], l["tx"]) for l in u["links"]])

    # force a save by SIGTERM (graceful) and check the file is on disk
    p.send_signal(signal.SIGTERM)
    p.wait(timeout=15)
    f = os.path.join(d, "traffic_peers.json")
    check("ledger file written on graceful stop", os.path.exists(f))
    if os.path.exists(f):
        mode = oct(os.stat(f).st_mode & 0o777)
        check("ledger file is mode 0600", mode == "0o600", mode)
        disk = json.load(open(f))
        check("ledger file is valid and versioned", disk.get("v") == 1 and isinstance(disk.get("links"), dict))
        before = {k: sum(x["rx"] + x["tx"] for x in v["points"]) for k, v in disk["links"].items()}
        print("   bytes on disk per link:", before)

        # restart and confirm history was loaded (not reset)
        p = start(); wait_up(); op, bp = login()
        time.sleep(3)
        u2 = get(op, bp, "/api/traffic/usage?range=7d")
        after = {l["key"]: l["rx"] + l["tx"] for l in u2["links"] if l["key"] != "total"}
        for k, v in before.items():
            check(f"history for {k} survives restart (>= before)", after.get(k, 0) >= v, f"{v} -> {after.get(k)}")

        # hard kill (no graceful flush): at most one minute may be lost, never the whole history
        time.sleep(62)
        p.kill(); p.wait(timeout=10)
        disk2 = json.load(open(f))
        total2 = sum(x["rx"] + x["tx"] for v in disk2["links"].values() for x in v["points"])
        total1 = sum(before.values())
        check("hard kill keeps the history (periodic flush)", total2 >= total1, f"{total1} -> {total2}")
finally:
    try: p.kill()
    except Exception: pass
    shutil.rmtree(d, ignore_errors=True)

print("RESULT", "FAILED: " + ", ".join(fails) if fails else "ALL PASSED")
sys.exit(1 if fails else 0)
