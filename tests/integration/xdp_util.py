"""Shared pieces of the XDP integration tests (Phase 13): a veth pair whose far end lives in a test
network namespace, a client that runs inside that namespace from a chosen source address, and
the bpffs mount the loader pins into.

Every address here is in 10.77.0.0/16 on veths created by the test and removed at teardown;
nothing reaches a real network. Needs root (CAP_NET_ADMIN, CAP_SYS_ADMIN, CAP_BPF): the dev
container is privileged. Without it the tests skip, loudly."""
import itertools
import os
import subprocess
import uuid

import pytest

_seq = itertools.count()

CLIENT = r"""
import socket, sys
src, host, port, timeout = sys.argv[1], sys.argv[2], int(sys.argv[3]), float(sys.argv[4])
s = socket.socket()
s.settimeout(timeout)
try:
    s.bind((src, 0))
    s.connect((host, port))
    s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    out = b""
    while True:
        d = s.recv(65536)
        if not d:
            break
        out += d
    print(out.split(b" ", 2)[1].decode() if out else "closed")
except socket.timeout:
    print("timeout")
except OSError as e:
    print("error:" + str(e.errno))
"""


def sh(*cmd, check=True):
    return subprocess.run(list(cmd), capture_output=True, text=True, check=check)


def need_root():
    if os.geteuid() != 0:
        pytest.skip("needs root for veth, netns and XDP (run through ./dev)")


def ensure_bpffs():
    """bpffs at /sys/fs/bpf (the loader's default pin root); mounted when missing."""
    if sh("stat", "-f", "-c", "%T", "/sys/fs/bpf", check=False).stdout.strip() != "bpf_fs":
        sh("mount", "-t", "bpf", "bpf", "/sys/fs/bpf")


class Net:
    """One veth pair: `host` side (Bastion listens on 10.77.<n>.1) and its peer inside namespace
    `ns`, which has 10.77.<n>.2 and 10.77.<n>.3 (two clients, one usually denied)."""

    def __init__(self):
        n = next(_seq) % 200 + 1
        tag = uuid.uuid4().hex[:6]
        self.ns, self.host, self.peer = f"bxn{tag}", f"bxh{tag}", f"bxp{tag}"
        self.ip = f"10.77.{n}.1"
        self.good, self.bad = f"10.77.{n}.2", f"10.77.{n}.3"
        sh("ip", "netns", "add", self.ns)
        sh("ip", "link", "add", self.host, "type", "veth", "peer", "name", self.peer)
        sh("ip", "link", "set", self.peer, "netns", self.ns)
        sh("ip", "addr", "add", f"{self.ip}/24", "dev", self.host)
        sh("ip", "link", "set", self.host, "up")
        for a in (self.good, self.bad):
            sh("ip", "-n", self.ns, "addr", "add", f"{a}/24", "dev", self.peer)
        sh("ip", "-n", self.ns, "link", "set", self.peer, "up")
        sh("ip", "-n", self.ns, "link", "set", "lo", "up")

    def get(self, src, port, timeout=1.0):
        """'200', 'timeout', 'closed' or 'error:<errno>' for one HTTP request from src."""
        r = sh("ip", "netns", "exec", self.ns, "python3", "-c", CLIENT, src, self.ip, str(port),
               str(timeout), check=False)
        return r.stdout.strip() or r.stderr.strip()

    def xdp_attached(self):
        return "xdp" in sh("ip", "link", "show", self.host).stdout

    def close(self):
        sh("ip", "link", "del", self.host, check=False)
        sh("ip", "netns", "del", self.ns, check=False)


@pytest.fixture
def net():
    need_root()
    ensure_bpffs()
    nets = []

    def make():
        n = Net()
        nets.append(n)
        return n

    yield make
    for n in nets:
        n.close()


@pytest.fixture
def pin(tmp_path):
    """A fresh pin directory under /sys/fs/bpf, removed (with whatever is left) at teardown."""
    need_root()
    ensure_bpffs()
    p = f"/sys/fs/bpf/bst-test-{uuid.uuid4().hex[:8]}"
    yield p
    if os.path.isdir(p):
        for f in os.listdir(p):
            os.unlink(os.path.join(p, f))
        os.rmdir(p)


def xdp_conf(net_, pin_, extra="", ifaces=None, workers=1):
    ifs = " ".join(ifaces or [net_.host])
    return (f"workers {workers};\n"
            f"xdp {{ interface {ifs}; mode generic; pin_path {pin_}; deny {net_.bad}; {extra} }}\n"
            f"server {{ listen {net_.ip}:@HTTP_PORT@; location / {{ return 200 \"ok\"; }} }}\n")
