"""Worker start order on a stock kernel. kernel.io_uring_disabled=1 lets only a privileged
process create a ring, so a worker that drops privileges first would lose io_uring. The sysctl
is global, so this runs only in the VM guest."""
import os
import platform
import re
import signal
import socket
import subprocess
import tempfile
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


def start(tmp_path, extra="", env=None):
    exe = os.path.join(ROOT, "build", BUILD, "bastion")
    assert os.path.exists(exe), f"{exe} missing: make test-vm builds it before booting the guest"
    log = tmp_path / "error.log"
    conf = tmp_path / "b.conf"
    conf.write_text(f"workers 2;\nerror_log {log} info;\n{extra}\n"
                    f"server {{ listen 127.0.0.1:{free_port()}; }}\n")
    p = subprocess.Popen([exe, "-c", str(conf)], stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, env=dict(os.environ, **(env or {})))
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if log.exists() and " master INFO ready: " in log.read_text():
            return p, log
        assert p.poll() is None, log.read_text() if log.exists() else "no log"
        time.sleep(0.02)
    p.kill()
    pytest.fail("not ready in 20s")


def children(master):
    out = []
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        try:
            s = Path(f"/proc/{name}/status").read_text()
        except OSError:
            continue
        if re.search(rf"^PPid:\s+{master}$", s, re.M):
            out.append(int(name))
    return out


def task_fields(pid):
    """[(name, uid line, CapEff)] for every thread, kernel SQ thread included."""
    out = []
    for tid in os.listdir(f"/proc/{pid}/task"):
        s = Path(f"/proc/{pid}/task/{tid}/status").read_text()
        out.append((re.search(r"^Name:\s+(\S+)", s, re.M).group(1),
                    re.search(r"^Uid:\s+(.*)$", s, re.M).group(1).split(),
                    int(re.search(r"^CapEff:\s+(\S+)", s, re.M).group(1), 16)))
    return out


def assert_no_root_task(master, want_sq):
    kids = children(master)
    assert len(kids) == 3
    for pid in kids:
        tasks = task_fields(pid)
        assert any(n.startswith("iou-sqp-") for n, _, _ in tasks) == want_sq, tasks
        for name, uids, cap in tasks:
            assert set(uids) == {"65534"} and cap == 0, (name, uids, cap)


def unix_listeners():
    """As in tests/integration/test_process_security.py: the ring's restrictions refuse an open
    whoever runs it, and leave CONNECT to the credentials behind the request."""
    d = tempfile.mkdtemp(dir="/tmp")
    os.chmod(d, 0o755)
    socks = []
    for name, mode in (("secret", 0o600), ("open", 0o666)):
        s = socket.socket(socket.AF_UNIX)
        path = os.path.join(d, name)
        s.bind(path)
        s.listen(4)
        os.chmod(path, mode)
        socks.append(s)
    return socks, [s.getsockname() for s in socks]


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


def test_plain_ring_is_created_before_the_privilege_drop(tmp_path):
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


def test_sqpoll_ring_holds_no_privilege(tmp_path):
    # Created as root, the SQ thread would run every request of the worker as root.
    socks, (secret, anyone) = unix_listeners()
    p, log = start(tmp_path, "user nobody;\nio { backend uring; uring_sqpoll 50ms; }",
                   env={"BST_TEST_WORKER_SQ_CONNECT": f"{secret},{anyone}",
                        "BST_TEST_WORKER_REPORT": "1"})
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and log.read_text().count("sq_connect") < 2:
        time.sleep(0.02)
    text = log.read_text()
    assert re.search(rf"test report: sq_connect {secret} res=-13 sqpoll=1$", text, re.M), text
    assert re.search(rf"test report: sq_connect {anyone} res=0 sqpoll=1$", text, re.M), text
    assert_no_root_task(p.pid, True)
    p.send_signal(signal.SIGQUIT)
    assert p.wait(10) == 0


def _with_disabled_1(fn, group=None):
    old = open(KNOB).read().strip()
    gknob = "/proc/sys/kernel/io_uring_group"
    oldg = open(gknob).read().strip()
    try:
        with open(KNOB, "w") as f:
            f.write("1")
        if group is not None:
            with open(gknob, "w") as f:
                f.write(group)
        fn()
    finally:
        with open(gknob, "w") as f:
            f.write(oldg)
        with open(KNOB, "w") as f:
            f.write(old)


def _need_knob():
    if not os.path.exists(KNOB):
        pytest.skip(f"kernel.io_uring_disabled needs Linux 6.6; this is {platform.release()}")


def test_sqpoll_disabled_1_auto_keeps_a_plain_ring(tmp_path):
    _need_knob()

    def body():
        p, log = start(tmp_path, "user nobody;\nio { backend auto; uring_sqpoll 50ms; }")
        text = log.read_text()
        assert re.search(r"master WARN uring_sqpoll ignored: ", text), text
        assert re.search(r"master INFO ready: 2 workers on uring$", text, re.M), text
        assert_no_root_task(p.pid, False)
        p.send_signal(signal.SIGTERM)
        assert p.wait(10) == 0
    _with_disabled_1(body)


def test_sqpoll_disabled_1_forced_is_a_startup_error(tmp_path):
    _need_knob()
    exe = os.path.join(ROOT, "build", BUILD, "bastion")

    def body():
        conf = tmp_path / "b.conf"
        conf.write_text(f"user nobody;\nio {{ backend uring; uring_sqpoll 50ms; }}\n"
                        f"server {{ listen 127.0.0.1:{free_port()}; }}\n")
        r = subprocess.run([exe, "-c", str(conf)], capture_output=True, text=True, timeout=20)
        assert r.returncode == 1, (r.stdout, r.stderr)
        assert "kernel.io_uring_group" in r.stderr, r.stderr
    _with_disabled_1(body)


def test_sqpoll_with_io_uring_group(tmp_path):
    _need_knob()

    def body():
        p, log = start(tmp_path, "user nobody;\nio { backend uring; uring_sqpoll 50ms; }")
        assert_no_root_task(p.pid, True)
        p.send_signal(signal.SIGTERM)
        assert p.wait(10) == 0
    _with_disabled_1(body, group="65534")


def test_workers_start_on_this_kernel(tmp_path):
    p, log = start(tmp_path, "user nobody;")
    assert re.search(r"master INFO ready: 2 workers on uring$", log.read_text(), re.M)
    p.send_signal(signal.SIGQUIT)
    assert p.wait(10) == 0
