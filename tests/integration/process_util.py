"""Helpers shared by the test_process*.py files."""
import os
import re
import socket
import time
from datetime import datetime
from pathlib import Path

import pytest

ECHO = {"BST_TEST_RAW_MODE": "echo"}
FAST_RESPAWN = {"BST_TEST_RESPAWN_SCALE": "100"}
RESPOND_LINE = b"bastion raw response\n"
BUILD = os.environ.get("BASTION_BUILD", "")


AS_NOBODY = ["setpriv", "--reuid", "65534", "--regid", "65534", "--clear-groups"]


def need_root():
    if os.geteuid() != 0:
        pytest.skip("needs root")


def conf(workers=2, extra=""):
    return f"workers {workers};\n{extra}\nserver {{ listen 127.0.0.1:@HTTP_PORT@; }}\n"


def connect(port, timeout=5):
    s = socket.create_connection(("127.0.0.1", port), timeout)
    s.settimeout(timeout)
    return s


def echo_ok(port, payload=b"ping", timeout=5):
    with connect(port, timeout) as s:
        s.sendall(payload)
        return s.recv(len(payload)) == payload


def status(pid):
    return Path(f"/proc/{pid}/status").read_text()


def field(pid, name):
    return re.search(rf"^{name}:\s*(.*)$", status(pid), re.M).group(1)


def tids(pid):
    return [int(t) for t in os.listdir(f"/proc/{pid}/task")]


def task_field(pid, tid, name):
    text = Path(f"/proc/{pid}/task/{tid}/status").read_text()
    return re.search(rf"^{name}:\s*(.*)$", text, re.M).group(1)


def gone(pid):
    try:
        text = Path(f"/proc/{pid}/stat").read_text()
    except (FileNotFoundError, ProcessLookupError):
        return True
    return text[text.rindex(")") + 2] == "Z"  # reparented to a PID 1 that does not reap


def wait_gone(pids, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if all(gone(p) for p in pids):
            return True
        time.sleep(0.01)
    return False


def stamp(line):
    return datetime.strptime(line.split()[0], "%Y-%m-%dT%H:%M:%S.%fZ").timestamp()


def respawns(text, who="worker/0"):
    """[(crash, backoff_ms, time)] from master's crash lines for one child."""
    out = []
    for line in text.splitlines():
        m = re.search(rf" master ERROR {who} \(pid \d+\) .*; respawn after backoff_ms=(\d+) "
                      r"\(crash (\d+)\)$", line)
        if m:
            out.append((int(m.group(2)), int(m.group(1)), stamp(line)))
    return out


def slow_env(total=4 << 20, chunk=64 << 10, interval_ms=10):
    return {"BST_TEST_RAW_MODE": "slow", "BST_TEST_RAW_SLOW": f"{total}:{chunk}:{interval_ms}"}


def read_pattern(s, total):
    got = 0
    while got < total:
        chunk = s.recv(1 << 20)
        if not chunk:
            break
        for i in range(0, len(chunk), 4093):
            assert chunk[i] == (got + i) % 251, (got, i)
        got += len(chunk)
    return got


def read_pattern_from(s, start, total):
    got = start
    while got < total:
        chunk = s.recv(1 << 20)
        if not chunk:
            break
        for i in range(0, len(chunk), 4093):
            assert chunk[i] == (got + i) % 251
        got += len(chunk)
    return got


def stuck_client(port):
    """Connected, past accept, and never reading: the worker's send can not finish."""
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    s.connect(("127.0.0.1", port))
    s.settimeout(5)
    assert s.recv(1)
    return s
