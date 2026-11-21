"""Static files on a stock kernel with the full sandbox (seccomp on, Landlock) on both backends,
with the packaged default config's shape: `user`, a per-IP limit, the challenge and an index.

Written while chasing v0.1.0's `static: opening "/" failed: Function not implemented`, which came
from systemd's RestrictSUIDSGID=yes hiding openat2 (tests/integration/test_openat2_blocked.py
covers that): this pins that Bastion's own seccomp filter and Landlock leave the aio pool's
openat2 working on a real kernel, through the challenge and the index lookup."""
import hashlib
import json
import os
import platform
import pwd
import re
import signal
import socket
import subprocess
import tempfile
import time
import urllib.parse
from pathlib import Path

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BUILD = os.environ.get("BST_VM_UNIT_BUILD", "debug")
HTML = "Accept: text/html,application/xhtml+xml\r\n"


@pytest.fixture(autouse=True, scope="module")
def _in_guest():
    assert "linuxkit" not in platform.release(), "running on the host kernel, not the VM guest"
    assert os.path.exists("/run/bastion-vm"), "not inside the VM guest (use make test-vm)"


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def raw(port, data):
    s = socket.create_connection(("127.0.0.1", port), 10)
    s.sendall(data)
    out = b""
    try:
        while True:
            d = s.recv(65536)
            if not d:
                break
            out += d
    except OSError:
        pass
    s.close()
    head, _, body = out.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    status = int(lines[0].split()[1]) if lines and lines[0] else 0
    hdrs = {}
    for ln in lines[1:]:
        k, _, v = ln.partition(":")
        hdrs.setdefault(k.strip().lower(), []).append(v.strip())
    return status, hdrs, body


def get(port, path="/", extra=""):
    return raw(port, f"GET {path} HTTP/1.1\r\nHost: localhost\r\n{HTML}{extra}"
                     "Connection: close\r\n\r\n".encode())


def solve(token, bits):
    n = 0
    while True:
        h = hashlib.sha256(f"{token}.{n}".encode()).digest()
        z = 0
        for b in h:
            if b == 0:
                z += 8
                continue
            z += 8 - b.bit_length()
            break
        if z >= bits:
            return str(n)
        n += 1


def pass_challenge(port):
    st, _, page = get(port)
    assert st == 403, (st, page[:200])
    m = re.search(rb"window\.BASTION=(\{.*?\});</script>", page)
    assert m, page[:400]
    b = json.loads(m.group(1))
    body = urllib.parse.urlencode({"token": b["token"], "nonce": solve(b["token"], b["difficulty"]),
                                   "redirect": b["redirect"]}).encode()
    st, h, _ = raw(port, ("POST /.bastion/challenge HTTP/1.1\r\nHost: localhost\r\n"
                          "Content-Type: application/x-www-form-urlencoded\r\n"
                          f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() + body)
    assert st == 303, (st, h)
    cookie = next(c for c in h.get("set-cookie", []) if c.startswith("bastion_pass="))
    return cookie.split(";")[0]


@pytest.mark.parametrize("backend", ["epoll", "uring"])
def test_index_under_full_sandbox(backend, tmp_path):
    exe = os.path.join(ROOT, "build", BUILD, "bastion")
    assert os.path.exists(exe), f"{exe} missing: make test-vm builds it before booting"
    # Landlock rules are added by path after the uid drop: `user` must reach the root, which
    # pytest's 0700 tmp_path does not let it do.
    www = Path(tempfile.mkdtemp(dir="/tmp"))
    os.chmod(www, 0o755)
    (www / "index.html").write_text("<p>hello</p>\n")
    os.chmod(www / "index.html", 0o644)
    user = pwd.getpwnam("nobody").pw_name
    log = tmp_path / "error.log"
    port = free_port()
    conf = tmp_path / "b.conf"
    conf.write_text(f"workers 1;\nuser {user};\nerror_log {log} info;\n"
                    f"io {{ backend {backend}; }}\n"
                    "limit_zone per_ip { rate 100/s burst=50; }\n"
                    f"server {{ listen 127.0.0.1:{port}; limit per_ip; challenge on; "
                    f"challenge_difficulty 4; root {www}; index index.html; }}\n")
    p = subprocess.Popen([exe, "-c", str(conf)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        text = lambda: log.read_text() if log.exists() else "no log"
        deadline = time.monotonic() + 20
        while " master INFO ready: " not in text():
            assert p.poll() is None and time.monotonic() < deadline, text()
            time.sleep(0.02)
        assert re.search(r"worker/0 INFO sandbox: seccomp=on landlock=abi\d+ ", text()), text()
        cookie = pass_challenge(port)
        for _ in range(3):  # the second and third may come from the open-file cache
            st, _, body = get(port, "/", f"Cookie: {cookie}\r\n")
            assert (st, body) == (200, b"<p>hello</p>\n"), (st, body, text())
        st, _, body = get(port, "/index.html", f"Cookie: {cookie}\r\n")
        assert st == 200, (st, body, text())
        assert "failed" not in text(), text()
    finally:
        p.send_signal(signal.SIGTERM)
        p.wait(10)
