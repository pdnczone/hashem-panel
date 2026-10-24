#!/usr/bin/env bash
# The terminal app (hashem with no arguments): arrow keys, Enter, number jump
# and Esc in a real pseudo-terminal, and the plain numbered fallback without one.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
export HASHEM_NO_ROOT_CHECK=1 GRE_PANEL_DIR="$T/panel"
fail=0
has() { grep -qF -- "$2" <<< "$1" || { echo "FAIL $3: no \"$2\""; fail=1; }; }

# 1. no terminal: numbered prompts, EOF leaves cleanly
out=$(printf '3\n0\n0\n' | bash "$ROOT/hashem.sh" menu 2>&1); rc=$?
[[ $rc -eq 0 ]] || { echo "FAIL plain: exit $rc"; fail=1; }
has "$out" "12) Settings" "plain main menu"
has "$out" "0) Exit" "plain main menu exit"
has "$out" "Status and GRE ping" "plain tunnel menu"
out=$(bash "$ROOT/hashem.sh" menu < /dev/null 2>&1); rc=$?
[[ $rc -eq 0 ]] || { echo "FAIL plain EOF: exit $rc"; fail=1; }

# 2. a terminal: drive keys and read the last screen after each one
command -v python3 >/dev/null || { echo "SKIP pty part (no python3)"; [[ $fail -eq 0 ]] && echo "PASS test_tui"; exit $fail; }
cat > "$T/drive.py" <<'PY'
import os, pty, re, select, sys, time
KEYS = {"down": "\x1b[B", "up": "\x1b[A", "enter": "\r", "esc": "\x1b", "left": "\x1b[D"}
def read_all(fd, wait):
    out, end = b"", time.time() + wait
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.05)
        if not r:
            continue
        try:
            chunk = os.read(fd, 65536)
        except OSError:
            break
        if not chunk:
            break
        out += chunk
        end = max(end, time.time() + 0.3)
    return out.decode("utf-8", "replace")
def screen(raw):
    last = raw.rsplit("\x1b[H\x1b[2J", 1)[-1]
    return re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", last).replace("\r", "")
pid, fd = pty.fork()
if pid == 0:
    os.environ.update({"TERM": "xterm", "LANG": "C.UTF-8"})
    os.execvp("bash", ["bash", sys.argv[1], "menu"])
print(screen(read_all(fd, 3)))
for k in sys.argv[2:]:
    os.write(fd, KEYS.get(k, k).encode())
    print("@@", k)
    print(screen(read_all(fd, 1.2)))
_, status = os.waitpid(pid, os.WNOHANG)
print("@@ alive" if _ == 0 else "@@ exited")
PY
out=$(python3 "$T/drive.py" "$ROOT/hashem.sh" down enter esc 12 esc 6 esc q 2>&1)
[[ -n "${TUI_DEBUG:-}" ]] && echo "$out"
step() { awk -v k="@@ $1" '$0 == k {p=1; next} /^@@ / {p=0} p' <<< "$out"; }
has "$(step down)" "›  2  Setup" "arrow down moves the selection"
has "$(step enter)" "From a bundle (recommended)" "enter opens Setup"
has "$(step esc)" "›  2  Setup" "esc goes back and keeps the row"
has "$(step 12)" "Two-factor sign-in" "number 12 opens Settings"
has "$(step 6)" "Performance needs a Hashem Pro license" "a Pro menu without a license offers the key"
has "$(step q)" "Bye." "q leaves the app"
has "$out" "@@ exited" "the app exits"

[[ $fail -eq 0 ]] && echo "PASS test_tui" || exit 1
