"""systemd integration without systemd (src/proc/systemd.c): the notify messages master sends
over NOTIFY_SOCKET, watchdog pings, and socket activation from fd 3. The same under a real
systemd is tests/vm/test_systemd.py; the upgrade's MAINPID hand-over is
test_upgrade.py::test_systemd_mainpid."""
import re
import signal
import socket
import sys
import time

import pytest

CONF = ("workers 2;\nserver { listen 127.0.0.1:@HTTP_PORT@; "
        "location = /v { return 200 \"ok\"; } }\n")


class Notify:
    def __init__(self, tmp_path):
        self.path = tmp_path / "notify"
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.sock.bind(str(self.path))
        self.sock.settimeout(0.2)
        self.got = []

    def until(self, pred, timeout=20):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                self.got.append(self.sock.recv(4096).decode())
            except socket.timeout:
                continue
            if pred(self.got[-1]):
                return self.got[-1]
        pytest.fail(f"no matching message on NOTIFY_SOCKET: {self.got}")


def get(port):
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
        s.sendall(b"GET /v HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        data = b""
        while True:
            b = s.recv(65536)
            if not b:
                return data
            data += b


def test_ready_reload_stopping(bastion, tmp_path):
    n = Notify(tmp_path)
    srv = bastion(CONF, env={"NOTIFY_SOCKET": str(n.path)})
    msg = n.until(lambda m: "READY=1" in m)
    assert "STATUS=serving: generation 0" in msg
    assert get(srv.ports["http"]).startswith(b"HTTP/1.1 200")
    srv.proc.send_signal(signal.SIGHUP)
    msg = n.until(lambda m: "RELOADING=1" in m)
    assert re.search(r"MONOTONIC_USEC=\d+", msg), msg
    assert "STATUS=serving: generation 1" in n.until(lambda m: "READY=1" in m)
    srv.proc.send_signal(signal.SIGQUIT)  # graceful; SIGTERM is the fast stop
    assert "STATUS=graceful stop" in n.until(lambda m: "STOPPING=1" in m)
    assert srv.proc.wait(30) == 0


def test_failed_reload_reports_ready_again(bastion, tmp_path):
    n = Notify(tmp_path)
    srv = bastion(CONF, env={"NOTIFY_SOCKET": str(n.path)})
    n.until(lambda m: "READY=1" in m)
    conf = srv.workdir / "bastion.conf"
    conf.write_text(conf.read_text() + "\nnot a directive;\n")
    srv.proc.send_signal(signal.SIGHUP)
    n.until(lambda m: "RELOADING=1" in m)
    assert "reload failed" in n.until(lambda m: "READY=1" in m)  # systemd leaves "reloading"
    assert get(srv.ports["http"]).startswith(b"HTTP/1.1 200")


def test_watchdog_pings(bastion, tmp_path):
    n = Notify(tmp_path)
    bastion(CONF, env={"NOTIFY_SOCKET": str(n.path), "WATCHDOG_USEC": "400000"})
    start = time.monotonic()
    for _ in range(4):  # every 200 ms: half the interval
        n.until(lambda m: m == "WATCHDOG=1", timeout=2)
    assert time.monotonic() - start < 3


def test_watchdog_of_another_process_is_ignored(bastion, tmp_path):
    n = Notify(tmp_path)
    bastion(CONF, env={"NOTIFY_SOCKET": str(n.path), "WATCHDOG_USEC": "200000",
                       "WATCHDOG_PID": "1"})
    n.until(lambda m: "READY=1" in m)
    time.sleep(1)
    try:
        while True:
            n.got.append(n.sock.recv(4096).decode())
    except socket.timeout:
        pass
    assert "WATCHDOG=1" not in n.got


# Binds the configuration's first listen address, puts the socket on fd 3 and execs bastion
# with LISTEN_PID naming itself, as systemd does. The socket has no SO_REUSEPORT, so a bastion
# that bound its own socket instead would fail with EADDRINUSE.
ACTIVATE = r"""
import os, re, socket, sys
conf = open(sys.argv[sys.argv.index("-c", 2) + 1]).read()  # argv[0] is python's own -c
port = int(re.search(r"listen 127\.0\.0\.1:(\d+)", conf).group(1))
s = socket.socket()
s.bind(("127.0.0.1", port))
s.listen(64)
os.dup2(s.fileno(), 3)
os.set_inheritable(3, True)
os.environ.update(LISTEN_FDS="1", LISTEN_PID=str(os.getpid()), LISTEN_FDNAMES="http")
os.execv(sys.argv[1], sys.argv[1:])
"""


def test_socket_activation(bastion):
    srv = bastion(CONF, wrap=[sys.executable, "-c", ACTIVATE])
    assert re.search(r"socket activation: listen \d+ uses the socket systemd passed as fd 3",
                     srv.logs()), srv.logs()[-2000:]
    assert get(srv.ports["http"]).startswith(b"HTTP/1.1 200")
    srv.proc.send_signal(signal.SIGHUP)  # carried across a reload like any listener
    srv.wait_log(r"reload: generation 1 ready")
    assert get(srv.ports["http"]).startswith(b"HTTP/1.1 200")
