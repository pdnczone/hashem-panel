#!/usr/bin/env python3
"""E2E for panel-access steps 1-3: isolated binary + temp config dir only."""
import json, os, subprocess, sys, tempfile, time, urllib.request, urllib.error, http.cookiejar

BIN = sys.argv[1]
PORT = 7793
d = tempfile.mkdtemp(prefix="panel-access-e2e-")
env = dict(os.environ, GRE_PANEL_DIR=d, GRE_PANEL_PORT=str(PORT),
           GRE_PANEL_PASSWORD="E2e-Access-Pass-12345!", GRE_SKIP_PANEL="1",
           HASHEM_NO_SDNOTIFY="1")
env.pop("NOTIFY_SOCKET", None)

fails = []
def check(name, ok, extra=""):
    extra = str(extra) if extra != "" else ""
    print(("PASS " if ok else "FAIL ") + name + (("  " + extra) if extra else ""))
    if not ok: fails.append(name)

p = subprocess.Popen([BIN], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    bp = None
    for _ in range(60):
        try:
            if os.path.exists(os.path.join(d, "panel.json")):
                bp = json.load(open(os.path.join(d, "panel.json")))["base_path"]
                urllib.request.urlopen(f"http://127.0.0.1:{PORT}/{bp}/api/health", timeout=2).read()
                break
        except Exception:
            pass
        time.sleep(0.5)
    else:
        print("FAIL panel did not come up"); sys.exit(1)

    cj = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    def api(path, body=None, method=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(f"http://127.0.0.1:{PORT}/{bp}{path}", data=data,
            headers={"Content-Type": "application/json"}, method=method or ("POST" if body is not None else "GET"))
        # attach CSRF for POST
        for c in cj:
            if c.name == "gre_csrf" and c.value:
                req.add_header("X-CSRF-Token", c.value)
        try:
            return 200, json.load(op.open(req, timeout=10))
        except urllib.error.HTTPError as e:
            try: return e.code, json.load(e)
            except Exception: return e.code, {}

    # login needs username+password
    r = urllib.request.Request(f"http://127.0.0.1:{PORT}/{bp}/api/login",
        data=json.dumps({"username": "admin", "password": env["GRE_PANEL_PASSWORD"]}).encode(),
        headers={"Content-Type": "application/json"})
    op.open(r, timeout=10).read()
    check("login", True)

    # --- step 1: access GET (no secrets) ---
    c, a = api("/api/access")
    check("access GET 200 + no pass_hash", c == 200 and "pass_hash" not in a, a)
    check("access GET has username/port/path", all(k in a for k in ("username", "http_port", "base_path")), list(a))

    # wrong password refused
    c, o = api("/api/access", {"current_password": "wrong", "port": 18888})
    check("access wrong password 401", c == 401, c)
    # tunnel-port clash refused (no tunnel here, so use reserved 80)
    c, o = api("/api/access", {"current_password": env["GRE_PANEL_PASSWORD"], "port": 80})
    check("access port 80 refused 409", c == 409, c)
    # success: username only (no restart side-effect assertion beyond save)
    c, o = api("/api/access", {"current_password": env["GRE_PANEL_PASSWORD"], "username": "e2eops"})
    check("access username change 200 + restart flag", c == 200 and o.get("restarting") is True, o)
    time.sleep(2.5)  # let gre-panel-only restart fire (fails silently in sandbox — file is the proof)
    saved = json.load(open(os.path.join(d, "panel.json")))
    check("access username persisted", saved.get("username") == "e2eops", saved.get("username"))

    # --- step 2: custom cert validation ---
    c, o = api("/api/tls/custom", {"cert": "junk", "key": "junk"})
    check("custom cert garbage 400", c == 400 and o.get("error_code") == "E-TLS-12", (c, o.get("error_code")))
    c, o = api("/api/tls/custom", {"cert_path": "/nonexistent/x", "key_path": "/nonexistent/y"})
    check("custom cert missing files 400", c == 400, c)

    # --- step 3: IP cert ---
    c, o = api("/api/tls/ip", {"ip": "not-an-ip"})
    check("ip cert garbage 400", c == 400 and o.get("error_code") == "E-TLS-13", (c, o.get("error_code")))
    c, o = api("/api/tls/ip", {"ip": "127.0.0.2"})
    check("ip cert issue 200", c == 200 and o.get("tls_status") == "valid", (c, o))
    check("ip cert files on disk", os.path.exists(os.path.join(d, "tls", "server.crt"))
          and os.path.exists(os.path.join(d, "tls", "hashem-ca.crt")))

    # CA download (authed GET through cookie jar)
    try:
        resp = op.open(f"http://127.0.0.1:{PORT}/{bp}/api/tls/ip/ca", timeout=10)
        body = resp.read()
        check("CA download 200 + PEM", resp.status == 200 and b"BEGIN CERTIFICATE" in body, resp.status)
    except urllib.error.HTTPError as e:
        check("CA download 200 + PEM", False, e.code)

    # unauthenticated access refused
    try:
        urllib.request.urlopen(f"http://127.0.0.1:{PORT}/{bp}/api/access", timeout=5)
        check("unauth access refused", False)
    except urllib.error.HTTPError as e:
        check("unauth access refused", e.code == 401, e.code)
finally:
    try: p.kill()
    except Exception: pass
    import shutil; shutil.rmtree(d, ignore_errors=True)

print("RESULT", "FAILED: " + ", ".join(fails) if fails else "ALL PASSED")
sys.exit(1 if fails else 0)
