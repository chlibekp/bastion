"""Landlock enforcement and the other things only a stock kernel decides. Docker Desktop's kernel
has no Landlock, so the integration tier covers only its absence.

`seccomp log` keeps the filter on and lets the probe's openat reach Landlock: with `on` the open
would die in seccomp first. KERNEL=floor proves the 6.1 ABI, KERNEL=current the 6.12 one."""
import os
import platform
import re
import signal
import socket
import subprocess
import time
from pathlib import Path

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BUILD = os.environ.get("BST_VM_UNIT_BUILD", "debug")
EACCES = 13


@pytest.fixture(autouse=True, scope="module")
def _in_guest():
    assert "linuxkit" not in platform.release(), "running on the host kernel, not the VM guest"
    assert os.path.exists("/run/bastion-vm"), "not inside the VM guest (use make test-vm)"


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Server:
    def __init__(self, tmp_path, sandbox, env=None, extra="", wait=True):
        exe = os.path.join(ROOT, "build", BUILD, "bastion")
        assert os.path.exists(exe), f"{exe} missing: make test-vm builds it before booting"
        self.log = tmp_path / "error.log"
        conf = tmp_path / "b.conf"
        self.port = free_port()
        conf.write_text(f"workers 1;\nerror_log {self.log} info;\n{extra}\n"
                        f"sandbox {{ {sandbox} }}\n"
                        f"server {{ listen 127.0.0.1:{self.port}; }}\n")
        self.p = subprocess.Popen([exe, "-c", str(conf)], stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL,
                                  env={k: v for k, v in dict(os.environ, **(env or {})).items()})
        if not wait:
            return
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if self.log.exists() and " master INFO ready: " in self.log.read_text():
                return
            assert self.p.poll() is None, self.text()
            time.sleep(0.02)
        self.p.kill()
        pytest.fail("not ready in 20s: " + self.text())

    def text(self):
        return self.log.read_text() if self.log.exists() else "no log"

    def result(self, name):
        pat = rf" sandbox probe: {re.escape(name)} res=(-?\d+) errno=(\d+)$"
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            m = re.search(pat, self.text(), re.M)
            if m:
                return int(m.group(1)), int(m.group(2))
            time.sleep(0.02)
        pytest.fail(f"no result for {name}: " + self.text())

    def stop(self):
        self.p.send_signal(signal.SIGTERM)
        assert self.p.wait(10) == 0


@pytest.fixture
def server(tmp_path):
    started = []

    def make(*args, **kw):
        s = Server(tmp_path, *args, **kw)
        started.append(s)
        return s
    yield make
    for s in started:
        if s.p.poll() is None:
            s.stop()


def tree(tmp_path):
    www = tmp_path / "www"
    www.mkdir()
    (www / "index.html").write_text("hello\n")
    cache = tmp_path / "cache"
    cache.mkdir()
    return www, cache


def env_of(*probes):
    return {"BST_TEST_SANDBOX_PROBE": "0:" + ",".join(probes)}


def test_landlock_read(server, tmp_path):
    www, _ = tree(tmp_path)
    good = f"read_file:{www}/index.html"
    s = server(f"seccomp log; extra_read {www};", env_of("read_file:/etc/passwd", good))
    assert s.result("read_file:/etc/passwd") == (-1, EACCES)
    assert s.result(good)[0] == 6
    assert re.search(r"worker/0 INFO sandbox: seccomp=log landlock=abi\d+ ", s.text()), s.text()


def test_landlock_write(server, tmp_path):
    www, cache = tree(tmp_path)
    in_cache = f"write_file:{cache}/new"
    in_www = f"write_file:{www}/new"
    in_tmp = f"write_file:{tmp_path}/outside"
    s = server(f"seccomp log; extra_read {www}; extra_write {cache};",
               env_of(in_cache, in_www, in_tmp))
    assert s.result(in_cache)[0] >= 0
    assert (cache / "new").exists()
    assert s.result(in_www) == (-1, EACCES)
    assert s.result(in_tmp) == (-1, EACCES)
    assert not (www / "new").exists() and not (tmp_path / "outside").exists()


def test_landlock_covers_pool_threads(server, tmp_path):
    # landlock_restrict_self binds one thread, and pool threads do all the file work.
    www, _ = tree(tmp_path)
    s = server(f"seccomp log; extra_read {www};", env_of("pool:read_file:/etc/passwd"),
               extra="io { aio_threads 4; }")
    assert s.result("read_file:/etc/passwd") == (-1, EACCES)


def test_landlock_covers_the_helper(server, tmp_path):
    www, _ = tree(tmp_path)
    s = server(f"seccomp log; extra_read {www};",
               {"BST_TEST_SANDBOX_PROBE": "helper:read_file:/etc/passwd"})
    assert s.result("read_file:/etc/passwd") == (-1, EACCES)


@pytest.mark.parametrize("env,sig", [({"BST_TEST_WORKER_CRASH": "0:segv"}, 11),
                                     ({"BST_TEST_WORKER_CRASH": "0:abort"}, 6),
                                     ({"BST_TEST_AIO_CRASH": "0:segv"}, 11),
                                     ({"BST_TEST_AIO_CRASH": "0:abort"}, 6)],
                         ids=["main_segv", "main_abort", "pool_segv", "pool_abort"])
def test_crash_report_under_every_step(server, env, sig):
    # Each thread has a Landlock domain of its own, and ABI 6 scopes signals to a domain: the
    # handler's re-raise must still reach the thread that crashed.
    s = server("", dict(env, BST_TEST_RESPAWN_SCALE="100"), wait=False)
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        t = s.text()
        if "ERROR crash: end" in t and f"killed by signal {sig};" in t:
            return
        time.sleep(0.02)
    pytest.fail(s.text())


def test_log_file_is_written_with_no_rule_for_it(server, tmp_path):
    # Workers hold their own description of the log, so no path rule names it.
    www, _ = tree(tmp_path)
    log = tmp_path / "error.log"
    s = server(f"seccomp log; extra_read {www};", env_of(f"read_file:{log}", "log_line"))
    assert s.result(f"read_file:{log}") == (-1, EACCES)
    assert s.result("log_line")[0] == 0


def test_landlock_require_passes_here(server, tmp_path):
    s = server("landlock on require;")
    assert re.search(r"worker/0 INFO sandbox: seccomp=on landlock=abi\d+ ", s.text()), s.text()


def test_seccomp_enforced_with_landlock(server, tmp_path):
    # All steps at once, on a stock kernel, as root and with the real filter.
    www, _ = tree(tmp_path)
    s = server(f"extra_read {www};", extra="user nobody;")
    pids = [p for p in os.listdir("/proc") if p.isdigit()]
    found = 0
    for p in pids:
        try:
            st = Path(f"/proc/{p}/status").read_text()
        except OSError:
            continue
        if re.search(r"^Name:\s+bst:worker/0$", st, re.M):
            found += 1
            assert re.search(r"^Seccomp:\s+2$", st, re.M), st
            assert re.search(r"^NoNewPrivs:\s+1$", st, re.M), st
            for cap in ("CapEff", "CapPrm", "CapBnd"):
                assert int(re.search(rf"^{cap}:\s+(\S+)$", st, re.M).group(1), 16) == 0, st
    assert found == 1


def test_seccomp_log_leaves_an_audit_record(server, tmp_path):
    since = int(time.time()) - 1
    s = server("seccomp log;", env_of("memfd"))
    assert s.result("memfd")[0] >= 0
    nr = re.search(r"sandbox probe: memfd_nr (\d+)$", s.text(), re.M).group(1)
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        out = subprocess.run(["dmesg"], capture_output=True, text=True).stdout
        if re.search(rf'type=1326 .*comm="bst:worker/0".* syscall={nr} ', out):
            return
        time.sleep(0.05)
    pytest.fail("no audit record for the logged syscall")


@pytest.mark.parametrize("sqpoll", ["", "uring_sqpoll 50ms;"], ids=["plain", "sqpoll"])
def test_restricted_ring_on_this_kernel(server, tmp_path, sqpoll):
    # The floor kernel lacks opcodes the backend knows of: the restriction list is filtered
    # through the probe, or registering it would fail here.
    s = server("seccomp log;", env_of("uring_socket", "uring_nop", "uring_register_buffers"),
               extra=f"user nobody;\nio {{ backend uring; {sqpoll} }}")
    assert s.result("uring_socket")[0] == -EACCES
    assert s.result("uring_nop")[0] == 0
    assert s.result("uring_register_buffers")[0] == -EACCES


def test_uring_async_under_sandbox_with_landlock(server, tmp_path):
    (tmp_path / "www").mkdir()
    cold = tmp_path / "www" / "cold"
    data = bytes(i % 251 for i in range(1 << 20))
    cold.write_bytes(data)
    name = f"uring_async:{cold}"
    s = server(f"extra_read {tmp_path}/www;", env_of(name), extra="io { backend uring; }")
    assert s.result(name)[0] == len(data)


def test_namespaces_on_a_stock_kernel(server, tmp_path):
    www, _ = tree(tmp_path)
    good = f"read_file:{www}/index.html"
    s = server(f"namespaces on require; seccomp log; extra_read {www};",
               env_of(good, "read_file:/etc/passwd"))
    assert s.result(good)[0] == 6
    assert s.result("read_file:/etc/passwd") == (-1, 2)  # ENOENT: not in this root
