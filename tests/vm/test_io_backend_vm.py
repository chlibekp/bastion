"""Backend selection under kernel.io_uring_disabled. The sysctl is global to the kernel, so this
only ever runs in the VM guest (make test-vm), never in Docker, where writing it would affect
every container on the host."""
import os
import platform
import re
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BUILD = os.environ.get("BST_VM_UNIT_BUILD", "debug")
KNOB = "/proc/sys/kernel/io_uring_disabled"


@pytest.fixture(autouse=True, scope="module")
def _in_guest():
    assert "linuxkit" not in platform.release(), "running on the host kernel, not the VM guest"
    assert os.path.exists("/run/bastion-vm"), "not inside the VM guest (use make test-vm)"


def _t(tmp_path, text):
    conf = tmp_path / "b.conf"
    conf.write_text(text + "server { listen 8080; }\n")
    exe = os.path.join(ROOT, "build", BUILD, "bastion")
    assert os.path.exists(exe), f"{exe} missing: make test-vm builds it before booting the guest"
    return subprocess.run([exe, "-c", str(conf), "-t"], capture_output=True, text=True, timeout=60)


@pytest.mark.parametrize("value", ["2"])  # 1 still allows root (CAP_SYS_ADMIN)
def test_sysctl_disabled(tmp_path, value):
    if not os.path.exists(KNOB):
        pytest.skip(f"kernel.io_uring_disabled needs Linux 6.6; this is {platform.release()}")
    old = open(KNOB).read().strip()
    try:
        with open(KNOB, "w") as f:
            f.write(value)
        auto = _t(tmp_path, "")
        assert auto.returncode == 0, auto.stderr
        m = re.search(r"^io backend: epoll \((.+)\)$", auto.stdout, re.M)
        assert m, auto.stdout
        assert f"kernel.io_uring_disabled={value}" in m.group(1)
        forced = _t(tmp_path, "io { backend uring; }\n")
        assert forced.returncode == 1, (forced.stdout, forced.stderr)
        assert f"kernel.io_uring_disabled={value}" in forced.stderr
    finally:
        with open(KNOB, "w") as f:
            f.write(old)
    assert open(KNOB).read().strip() == old
