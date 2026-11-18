"""The XDP filter in native (driver) mode on a stock kernel (Phase 13, Task 6): veth has driver XDP,
so `mode native require` must attach, and the same drop checks as the generic-mode integration
tests must hold. Runs in the guest as root (make test-vm K=xdp_native)."""
import os
import platform
import re
import socket
import subprocess
import sys
import time

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "tests", "integration"))
from xdp_util import Net, ensure_bpffs  # noqa: E402

BIN = os.path.join(ROOT, "build", "debug", "bastion")


@pytest.fixture(autouse=True, scope="module")
def _in_guest():
    assert "linuxkit" not in platform.release(), "running on the host kernel, not the VM guest"
    assert os.path.exists("/run/bastion-vm"), "not inside the VM guest (use make test-vm)"


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def test_native_veth(tmp_path):
    ensure_bpffs()
    subprocess.run(["modprobe", "veth"], check=False)  # a module on Debian's kernel
    n = Net()
    pin = f"/sys/fs/bpf/bst-vm-{os.getpid()}"
    port = free_port()
    log = tmp_path / "error.log"
    conf = tmp_path / "bastion.conf"
    conf.write_text(f"workers 1;\nerror_log {log} info;\n"
                    f"xdp {{ interface {n.host}; mode native require; pin_path {pin}; deny {n.bad}; }}\n"
                    f"server {{ listen {n.ip}:{port}; location / {{ return 200 \"ok\"; }} }}\n")
    proc = subprocess.Popen([BIN, "-c", str(conf)], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    try:
        deadline = time.monotonic() + 120  # TCG: the verifier alone can take tens of seconds
        while time.monotonic() < deadline:
            text = log.read_text() if log.exists() else ""
            if re.search(r" master INFO ready: ", text) or proc.poll() is not None:
                break
            time.sleep(0.05)
        text = log.read_text() if log.exists() else ""
        assert proc.poll() is None, f"{platform.release()}: exited\n{text}"
        assert f"xdp: attached to {n.host} (native mode)" in text, text
        assert n.get(n.good, port, timeout=3) == "200"
        assert n.get(n.bad, port, timeout=1) == "timeout"
        assert n.get(n.good, port, timeout=3) == "200"
    finally:
        proc.terminate()
        proc.wait(timeout=30)
        n.close()
    assert not os.path.exists(f"{pin}/link_{n.host}")
