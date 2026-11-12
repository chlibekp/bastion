"""The QUIC send path on a stock kernel: tests/integration/test_quic_udp.py run in the VM guest,
where netem, veth and network namespaces are certain to exist. In the guest the link tests
(loss, reordering, a 1280-byte MTU) must run, so a skip is a failure here; the GSO tests also
run against a stock kernel's UDP_SEGMENT.

make test-vm builds build/debug/bastion and the h3client fixture before booting the guest."""
import os
import platform
import re
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BUILD = os.environ.get("BST_VM_UNIT_BUILD", "debug")


@pytest.fixture(autouse=True, scope="module")
def _in_guest():
    assert "linuxkit" not in platform.release(), "running on the host kernel, not the VM guest"
    assert os.path.exists("/run/bastion-vm"), "not inside the VM guest (use make test-vm)"


def run_file(k):
    exe = os.path.join(ROOT, "build", BUILD, "bastion")
    client = os.path.join(ROOT, "build", BUILD, "fixtures", "h3client")
    for p in (exe, client):
        assert os.path.exists(p), f"{p} missing: make test-vm builds it before booting the guest"
    env = dict(os.environ, BASTION_BUILD=BUILD, BASTION_BIN=exe, H3CLIENT=client, PYTHONDONTWRITEBYTECODE="1")
    run = subprocess.run(["python3", "-m", "pytest", "-p", "no:cacheprovider", "-q", "-rs", "-k", k,
                          os.path.join(ROOT, "tests", "integration", "test_quic_udp.py")],
                         cwd=ROOT, env=env, capture_output=True, text=True, timeout=1800)
    out = run.stdout + run.stderr
    assert run.returncode == 0, f"{platform.release()}:\n{out[-4000:]}"
    return out


def test_quic_udp_link_vm():
    """Loss, reordering and a small MTU, on both backends: all must run."""
    out = run_file("loss_recovery or reorder or low_mtu")
    assert re.search(r"\b6 passed\b", out) and "skipped" not in out, out[-4000:]


def test_quic_udp_gso_vm():
    """GSO, its EIO fallback and ECN on the stock kernel (a kernel without UDP_SEGMENT may skip)."""
    run_file("gso or ecn")
