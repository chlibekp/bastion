"""Busy polling on a stock kernel (docs/tuning.md): SO_BUSY_POLL on the listener with NAPI busy
polling on io_uring, or epoll busy polling, still serves correctly. Run with make test-vm."""
import os
import platform
import re
import socket
import subprocess
import time

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BIN = os.path.join(ROOT, "build", os.environ.get("BST_VM_UNIT_BUILD", "debug"), "bastion")


@pytest.fixture(autouse=True, scope="module")
def _in_guest():
    assert "linuxkit" not in platform.release(), "running on the host kernel, not the VM guest"
    assert os.path.exists("/run/bastion-vm"), "not inside the VM guest (use make test-vm)"


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.mark.parametrize("backend,io_extra", [("io_uring", "uring_napi on;"),
                                              ("epoll", "epoll_busy_poll 50us;")])
def test_busy_poll_mode(tmp_path, backend, io_extra):
    (tmp_path / "www").mkdir()
    (tmp_path / "www" / "index.html").write_text("busy\n")
    port = free_port()
    log = tmp_path / "error.log"
    conf = tmp_path / "b.conf"
    conf.write_text(f"""io {{ backend {backend}; {io_extra} }}
tcp_profile bp {{ busy_poll 50us; prefer_busy_poll on; busy_poll_budget 8; }}
workers 2;
error_log {log} info;
server {{ listen 127.0.0.1:{port} tcp_profile=bp; root {tmp_path}/www; }}
""")
    proc = subprocess.Popen([BIN, "-c", str(conf)], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    try:
        deadline = time.monotonic() + 20
        while " master INFO ready: " not in (log.read_text() if log.exists() else ""):
            assert proc.poll() is None and time.monotonic() < deadline, log.read_text()
            time.sleep(0.05)
        for _ in range(200):
            with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
                s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                data = b""
                while chunk := s.recv(4096):
                    data += chunk
            assert data.startswith(b"HTTP/1.1 200") and data.endswith(b"busy\n")
        text = log.read_text()
        assert not re.search(r"(busy_poll|NAPI).*not applied", text), text
    finally:
        proc.terminate()
        proc.wait(10)
