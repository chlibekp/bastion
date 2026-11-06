"""The io_uring backend on a stock kernel: KERNEL=floor proves Linux 6.1, the plan's floor.

The unit binaries are built in the dev container before the guest boots (make test-vm builds
them) and run here with BST_TEST_BACKEND=uring. test_uring_only checks each kernel feature
it relies on, so a kernel lacking one fails here instead of passing silently. Cold-file
readahead tests need a disk filesystem that honours RWF_NOWAIT; the guest's shared /work is
9p, so they may skip here (Docker covers them), but every other test must run.
"""
import os
import platform
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BUILD = os.environ.get("BST_VM_UNIT_BUILD", "debug")


@pytest.fixture(autouse=True, scope="module")
def _in_guest():
    assert "linuxkit" not in platform.release(), "running on the host kernel, not the VM guest"
    assert os.path.exists("/run/bastion-vm"), "not inside the VM guest (use make test-vm)"


@pytest.mark.parametrize("suite", ["uring_only", "uring_net", "io_fair", "loop", "io_tcp", "udp"])
def test_unit_suite_on_uring(suite, tmp_path):
    exe = os.path.join(ROOT, "build", BUILD, "unit", f"test_{suite}")
    assert os.path.exists(exe), f"{exe} missing: make test-vm builds it before booting the guest"
    env = dict(os.environ, BST_TEST_BACKEND="uring", BST_ALLOW_COLD_SKIP="1",
               BST_TEST_TMPDIR=str(tmp_path))
    run = subprocess.run([exe], cwd=ROOT, env=env, capture_output=True, text=True, timeout=500)
    out = run.stdout + run.stderr
    assert run.returncode == 0, f"{platform.release()}:\n{out}"
    assert "not ok" not in run.stdout, out
