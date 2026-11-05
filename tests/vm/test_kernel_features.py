"""Kernel features Docker Desktop's kernel lacks. Runs inside the QEMU guest (make test-vm)."""
import ctypes
import os
import platform
import subprocess

import pytest


@pytest.fixture(autouse=True, scope="session")
def _in_guest():
    # These tests are meaningless on the Docker Desktop kernel; refuse to run there.
    assert "linuxkit" not in platform.release(), "running on the host kernel, not the VM guest"
    assert os.path.exists("/run/bastion-vm"), "not inside the VM guest (use make test-vm)"


def _read(path):
    with open(path) as f:
        return f.read().split()


def _modprobe(name):
    r = subprocess.run(["modprobe", name], capture_output=True, text=True)
    assert r.returncode == 0, f"modprobe {name}: {r.stderr}"


def test_ktls_module():
    _modprobe("tls")
    assert "tls" in _read("/proc/sys/net/ipv4/tcp_available_ulp")


def test_bbr_available():
    _modprobe("tcp_bbr")
    assert "bbr" in _read("/proc/sys/net/ipv4/tcp_available_congestion_control")


def test_busy_poll_sysctl():
    assert os.path.exists("/proc/sys/net/core/busy_poll")


def test_io_uring_works():
    # The io_uring_disabled sysctl appeared in 6.6; a kernel without it never restricts io_uring.
    knob = "/proc/sys/kernel/io_uring_disabled"
    if os.path.exists(knob):
        assert _read(knob) == ["0"]
    # The sysctl alone is not proof: set up a ring for real.
    libc = ctypes.CDLL(None, use_errno=True)
    nr_io_uring_setup = 425  # same number on x86_64 and aarch64
    params = ctypes.create_string_buffer(120)
    fd = libc.syscall(nr_io_uring_setup, 4, params)
    assert fd >= 0, os.strerror(ctypes.get_errno())
    os.close(fd)


def test_landlock_active():
    assert "landlock" in open("/sys/kernel/security/lsm").read().split(",")
