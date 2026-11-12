"""The QUIC sk_reuseport program on a stock kernel: KERNEL=floor proves the 6.1 verifier accepts it.

test_reuseport_bpf (built in the dev container by make test-vm) loads the embedded program, attaches
it to a real UDP reuseport group and checks where crafted datagrams land. In the guest it runs as
root, so a skip is a failure here.
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


def test_quic_routing_bpf_verifier():
    exe = os.path.join(ROOT, "build", BUILD, "unit", "test_reuseport_bpf")
    assert os.path.exists(exe), f"{exe} missing: make test-vm builds it before booting the guest"
    run = subprocess.run([exe], cwd=ROOT, capture_output=True, text=True, timeout=300)
    out = run.stdout + run.stderr
    assert run.returncode == 0, f"{platform.release()}:\n{out}"
    assert "not ok" not in run.stdout and "SKIP" not in run.stdout, out
    assert run.stdout.count("\nok ") == 4, out
