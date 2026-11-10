#!/usr/bin/env python3
"""Differential check: sends every request of h1_rfc_requirements.yaml to Bastion and to nginx and
prints where the two statuses differ. It is for a person to read: it never fails (exit 0 always),
because nginx is not the standard and some differences are Bastion being stricter on purpose.

    python3 tests/conformance/h1_vs_nginx.py [path/to/bastion]

nginx must be on PATH (or NGINX=/path/to/nginx); without it the script says so and stops. Bastion
is the binary given, $BASTION_BIN, or the first of build/{asan,debug,release}/bastion."""
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "tests" / "integration"))
from test_h1_rfc import ENTRIES, build_request  # noqa: E402


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_port(port, timeout=10):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            socket.create_connection(("127.0.0.1", port), 0.2).close()
            return True
        except OSError:
            time.sleep(0.05)
    return False


def status_of(port, raw):
    """The status of the first response, 0 when the server closes without one."""
    with socket.create_connection(("127.0.0.1", port), 3) as s:
        s.settimeout(2)
        s.sendall(raw)
        data = b""
        try:
            while b"\r\n" not in data:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
        except (socket.timeout, ConnectionResetError):
            pass
    parts = data.split(b" ", 2)
    return int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0


def main():
    nginx = os.environ.get("NGINX") or shutil.which("nginx")
    if not nginx:
        print("nginx not found: nothing to compare against (set NGINX=/path/to/nginx)")
        return 0
    binary = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("BASTION_BIN")
    if not binary:
        binary = next((str(p) for b in ("asan", "debug", "release")
                       if (p := ROOT / "build" / b / "bastion").exists()), None)
    if not binary:
        print("bastion binary not found")
        return 0
    work = Path(tempfile.mkdtemp(prefix="h1-vs-nginx-"))
    bp, np_ = free_port(), free_port()
    (work / "bastion.conf").write_text(
        f'workers 1;\nserver {{ listen 127.0.0.1:{bp}; return 200 "ok"; }}\n'
        f"error_log {work}/bastion.log warn;\n")
    (work / "nginx.conf").write_text(
        f"daemon off; pid {work}/nginx.pid; error_log {work}/nginx.log;\n"
        f"events {{}}\nhttp {{ access_log off; server {{ listen 127.0.0.1:{np_}; "
        f'location / {{ return 200 "ok"; }} }} }}\n')
    procs = [subprocess.Popen([binary, "-c", str(work / "bastion.conf")]),
             subprocess.Popen([nginx, "-p", str(work), "-c", str(work / "nginx.conf")])]
    try:
        if not (wait_port(bp) and wait_port(np_)):
            print("a server did not start; see", work)
            return 0
        diffs = 0
        for e in ENTRIES:
            if "server" in e or "server_return" in e:
                continue  # these need a different configuration on each side
            raw = build_request(e)
            b, n = status_of(bp, raw), status_of(np_, raw)
            if b != n:
                diffs += 1
                print(f"{e['id']:50} bastion {b:3} nginx {n:3}  {e['rfc']}")
        print(f"{diffs} differences in {len(ENTRIES)} entries")
    finally:
        for p in procs:
            p.terminate()
        for p in procs:
            p.wait(10)
        shutil.rmtree(work, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
