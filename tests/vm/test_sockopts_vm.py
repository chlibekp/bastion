"""Socket options a stock kernel supports and Docker Desktop's does not (BBR, busy polling).
Runs in the QEMU guest (make test-vm). Uses `bastion --test-listeners`, which reads every option
back with getsockopt (tests/integration/test_sockopts.py has the harness)."""
import os
import platform
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "tests", "integration"))
from test_sockopts import free_port, listen_once, server  # noqa: E402

BUILD = os.environ.get("BST_VM_UNIT_BUILD", "debug")


@pytest.fixture(autouse=True, scope="module")
def _in_guest():
    assert "linuxkit" not in platform.release(), "running on the host kernel, not the VM guest"
    assert os.path.exists("/run/bastion-vm"), "not inside the VM guest (use make test-vm)"


@pytest.fixture
def exe():
    p = os.path.join(ROOT, "build", BUILD, "bastion")
    assert os.path.exists(p), f"{p} missing: make test-vm builds it before booting the guest"
    return p


def test_bbr_applied(exe, tmp_path):
    r = subprocess.run(["modprobe", "tcp_bbr"], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    port = free_port()
    conf = "tcp_profile b { congestion bbr require; }\n" + server(port, "b")
    run, rc = listen_once(exe, tmp_path, conf, slots=2)
    assert rc == 0, run.err
    for s in run.listening["listeners"][0]["sockets"]:
        assert s["opts"]["congestion"] == "bbr"
    assert "WARN" not in run.err


def test_busy_poll_applied(exe, tmp_path):
    port = free_port()
    conf = ("tcp_profile p { busy_poll 50us require; prefer_busy_poll on require;"
            " busy_poll_budget 64 require; }\n" + server(port, "p"))
    run, rc = listen_once(exe, tmp_path, conf, slots=2)
    assert rc == 0, run.err
    for s in run.listening["listeners"][0]["sockets"]:
        o = s["opts"]
        assert o["busy_poll"] == 50
        assert o["prefer_busy_poll"] == 1
        # `require` made the setsockopt succeed; not every kernel can read the budget back.
        if "busy_poll_budget" in o:
            assert o["busy_poll_budget"] == 64


def test_fastopen_server_sysctl_default_warns(exe, tmp_path):
    # Stock kernels ship tcp_fastopen=1 (client only): the listener's TFO is inert until the
    # server bit is set, and bastion says so instead of starting with a silent no-op.
    path = "/proc/sys/net/ipv4/tcp_fastopen"
    old = open(path).read().strip()
    try:
        open(path, "w").write("1")
        port = free_port()
        run, rc = listen_once(exe, tmp_path, "tcp_profile t { fastopen 256; }\n" + server(port, "t"))
        assert rc == 0, run.err
        assert "net.ipv4.tcp_fastopen" in run.err
        open(path, "w").write("3")
        run, rc = listen_once(exe, tmp_path, "tcp_profile t { fastopen 256; }\n" + server(port, "t"))
        assert rc == 0 and "net.ipv4.tcp_fastopen" not in run.err
    finally:
        open(path, "w").write(old)
