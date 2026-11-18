"""The XDP filter on a stock kernel: KERNEL=floor proves the 6.1 verifier accepts the embedded
object (xdp/xdp_bastion.bpf.c), and KERNEL=current the newer one.

The test_xdp_* unit binaries (built in the dev container by make test-vm) load the object and
run packets through BPF_PROG_TEST_RUN. In the guest they run as root, so a SKIP is a failure.
"""
import os
import platform
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BUILD = os.environ.get("BST_VM_UNIT_BUILD", "debug")
SUITES = ["xdp_basic", "xdp_parse", "xdp_lists", "xdp_rate", "xdp_udp", "xdp_loader"]


@pytest.fixture(autouse=True, scope="module")
def _in_guest():
    assert "linuxkit" not in platform.release(), "running on the host kernel, not the VM guest"
    assert os.path.exists("/run/bastion-vm"), "not inside the VM guest (use make test-vm)"


@pytest.mark.parametrize("suite", SUITES)
def test_xdp_verifier(suite):
    exe = os.path.join(ROOT, "build", BUILD, "unit", f"test_{suite}")
    assert os.path.exists(exe), f"{exe} missing: make test-vm builds it before booting the guest"
    run = subprocess.run([exe], cwd=ROOT, capture_output=True, text=True, timeout=300)
    out = run.stdout + run.stderr
    assert run.returncode == 0, f"{platform.release()}:\n{out}"
    assert "not ok" not in run.stdout and "SKIP" not in run.stdout, out
