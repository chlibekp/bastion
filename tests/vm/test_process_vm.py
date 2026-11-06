"""Worker start order on a stock kernel. kernel.io_uring_disabled=1 lets only a privileged
process create a ring, so a worker that drops privileges first would lose io_uring. The sysctl
is global, so this runs only in the VM guest."""
import os
import platform
import re
import signal
import socket
import subprocess
import time
from pathlib import Path

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BUILD = os.environ.get("BST_VM_UNIT_BUILD", "debug")
KNOB = "/proc/sys/kernel/io_uring_disabled"


@pytest.fixture(autouse=True, scope="module")
def _in_guest():
    assert "linuxkit" not in platform.release(), "running on the host kernel, not the VM guest"
    assert os.path.exists("/run/bastion-vm"), "not inside the VM guest (use make test-vm)"


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def start(tmp_path, extra=""):
    exe = os.path.join(ROOT, "build", BUILD, "bastion")
    assert os.path.exists(exe), f"{exe} missing: make test-vm builds it before booting the guest"
    log = tmp_path / "error.log"
    conf = tmp_path / "b.conf"
    conf.write_text(f"workers 2;\nerror_log {log} info;\n{extra}\n"
                    f"server {{ listen 127.0.0.1:{free_port()}; }}\n")
    p = subprocess.Popen([exe, "-c", str(conf)], stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if log.exists() and " master INFO ready: " in log.read_text():
            return p, log
        assert p.poll() is None, log.read_text() if log.exists() else "no log"
        time.sleep(0.02)
    p.kill()
    pytest.fail("not ready in 20s")


def worker_uids(master):
    out = []
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        try:
            s = Path(f"/proc/{name}/status").read_text()
        except OSError:
            continue
        if re.search(rf"^PPid:\s+{master}$", s, re.M) and re.search(r"^Name:\s+bst:worker", s, re.M):
            out.append(int(re.search(r"^Uid:\s+(\d+)", s, re.M).group(1)))
    return out


def test_ring_is_created_before_the_privilege_drop(tmp_path):
    if not os.path.exists(KNOB):
        pytest.skip(f"kernel.io_uring_disabled needs Linux 6.6; this is {platform.release()}")
    old = open(KNOB).read().strip()
    try:
        with open(KNOB, "w") as f:
            f.write("1")
        p, log = start(tmp_path, "user nobody;\nio { backend uring; }")
        text = log.read_text()
        assert re.search(r"master INFO ready: 2 workers on uring$", text, re.M), text
        uids = worker_uids(p.pid)
        assert len(uids) == 2 and all(u != 0 for u in uids), uids
        p.send_signal(signal.SIGTERM)
        assert p.wait(10) == 0
    finally:
        with open(KNOB, "w") as f:
            f.write(old)


def test_workers_start_on_this_kernel(tmp_path):
    p, log = start(tmp_path, "user nobody;")
    assert re.search(r"master INFO ready: 2 workers on uring$", log.read_text(), re.M)
    p.send_signal(signal.SIGQUIT)
    assert p.wait(10) == 0
