"""Server settings as processes see them: the pid file, backend agreement, CPU pinning, the allocator."""
import os
import re
import signal
import subprocess
import time
from pathlib import Path

import pytest

from process_util import *  # noqa: F401,F403


# ---- pid file ----


def test_pid_file(bastion, tmp_path):
    srv = bastion(conf(1, "pid @WORKDIR@/b.pid;"))
    path = srv.workdir / "b.pid"
    assert path.read_text().strip() == str(srv.proc.pid)
    srv.proc.send_signal(signal.SIGTERM)
    assert srv.proc.wait(10) == 0
    assert not path.exists()


def test_stale_pid_file_is_replaced(bastion, tmp_path):
    (tmp_path / "b.pid").write_text("999999\n")
    srv = bastion(conf(1, "pid @WORKDIR@/b.pid;"))
    assert (tmp_path / "b.pid").read_text().strip() == str(srv.proc.pid)


def test_second_instance_refused(bastion, tmp_path):
    # SO_REUSEPORT would let a second master bind the same port and take half the traffic.
    first = bastion(conf(1, f"pid {tmp_path}/b.pid;"))
    second = bastion(conf(1, f"pid {tmp_path}/b.pid;"), wait=None)
    assert second.proc.wait(10) == 1
    assert "already running" in second.stdout()
    assert first.proc.poll() is None
    assert (tmp_path / "b.pid").read_text().strip() == str(first.proc.pid)


# ---- backend agreement ----


@pytest.mark.parametrize("spec", ["setup:1", "setup:12"], ids=["unavailable", "hard_error"])
def test_auto_every_worker_ends_on_one_backend(bastion, spec):
    # Master's probe saw uring; one worker cannot get it. All of them must end up on epoll.
    srv = bastion(conf(3, "io { backend auto; }"),
                  env=ECHO | {"BST_TEST_WORKER_URING_FAIL": f"1:{spec}"})
    srv.wait_log(r"master INFO ready: 3 workers on epoll$")
    srv.wait_workers(3)
    last = {}
    for m in re.finditer(r" worker/(\d) INFO io backend: (\w+) \((.+)\)$", srv.logs(), re.M):
        last[m.group(1)] = m.group(2)
    assert last == {"0": "epoll", "1": "epoll", "2": "epoll"}, srv.logs()
    assert re.search(r"worker/1 WARN .*fell back", srv.logs()), srv.logs()
    assert "respawn after" not in srv.logs()  # a planned change, not a crash
    assert echo_ok(srv.ports["http"])


def test_auto_epoll_keeps_the_probe_reason(bastion):
    srv = bastion(conf(2, "io { backend auto; }"), env={"BST_TEST_URING_FAIL": "setup:1"})
    lines = re.findall(r"worker/\d INFO io backend: epoll \((.+)\)$", srv.logs(), re.M)
    assert len(lines) == 2 and all("EPERM" in r for r in lines), srv.logs()


def test_forced_uring_worker_failure_is_startup_failure(bastion):
    srv = bastion(conf(3, "io { backend uring; }"), wait=None,
                  env={"BST_TEST_WORKER_URING_FAIL": "1:setup:1"})
    assert srv.proc.wait(15) == 1
    assert re.search(r"master ERROR startup failed: worker/1", srv.logs()), srv.logs()
    assert "respawn after" not in srv.logs()
    assert srv.children() == {}


def test_helper_startup_failure_ends_the_server(bastion):
    # Held back so every worker is ready first: the helper counts towards a finished startup.
    srv = bastion(conf(2, "io { backend uring; }"), wait=None,
                  env={"BST_TEST_WORKER_URING_FAIL": "helper:setup:1",
                       "BST_TEST_HELPER_DELAY_MS": "500"})
    srv.wait_log(r"master INFO worker/1 ready$")
    srv.wait_log(r"master INFO worker/0 ready$")
    assert srv.proc.wait(15) == 1
    assert re.search(r"master ERROR startup failed: helper", srv.logs()), srv.logs()


def test_forced_uring_probe_failure(bastion):
    srv = bastion(conf(2, "io { backend uring; }"), wait=None,
                  env={"BST_TEST_URING_FAIL": "setup:1"})
    assert srv.proc.wait(10) == 1
    assert "uring" in srv.stdout() and "EPERM" in srv.stdout()


# ---- CPU pinning ----


STEER = """tcp_profile edge { steering incoming_cpu; }
workers 3;
server { listen 127.0.0.1:@HTTP_PORT@ tcp_profile=edge; }
"""


def test_incoming_cpu_pins_workers(bastion):
    srv = bastion(STEER)
    ncpu = os.sysconf("SC_NPROCESSORS_ONLN")
    for slot, pid in srv.workers().items():
        assert field(pid, "Cpus_allowed_list") == str(slot % ncpu)
        # Every thread: pinning comes before the loop, so the aio pool inherits it.
        assert len(tids(pid)) > 1
        for tid in tids(pid):
            assert task_field(pid, tid, "Cpus_allowed_list") == str(slot % ncpu)
    assert field(srv.helper(), "Cpus_allowed_list") == field(srv.proc.pid, "Cpus_allowed_list")


def test_no_pin_without_steering(bastion):
    srv = bastion(conf(2))
    for pid in srv.workers().values():
        assert field(pid, "Cpus_allowed_list") == field(srv.proc.pid, "Cpus_allowed_list")


def test_aio_auto_is_computed_before_pinning(bastion, backend):
    ncpu = len(os.sched_getaffinity(0))
    if ncpu < 2:
        pytest.skip("needs more than one CPU")
    srv = bastion(STEER)  # aio_threads defaults to auto
    for pid in srv.workers().values():
        # The loop thread plus the pool; a pinned worker counting CPUs would see 1.
        assert len(tids(pid)) >= 1 + min(ncpu, 8), status(pid)


# ---- allocator ----


def test_mimalloc_registered(bastion):
    srv = bastion(conf(1), env={"BST_TEST_WORKER_REPORT": "1"})
    m = srv.wait_log(r"worker/0 INFO test report: mem registered=(\d) malloc=(\d) realloc=(\d) "
                     r"free=(\d) openssl_in_mimalloc=(\d) libc_malloc_in_mimalloc=(\d)$")
    assert m.groups()[:5] == ("1",) * 5, m.group(0)
    # Sanitizers must keep the libc allocator; musl builds run on mimalloc.
    expected = "1" if BUILD in ("musltest", "release") else "0"
    assert m.group(6) == expected, (BUILD, m.group(0))


def test_late_mimalloc_registration_is_fatal(bastion_bin):
    p = subprocess.run([bastion_bin, "--version"], capture_output=True, text=True, timeout=30,
                       env=dict(os.environ, BST_TEST_MEM_LATE="1"))
    assert p.returncode == 1, (p.stdout, p.stderr)
    assert "OpenSSL allocated before mimalloc was registered" in p.stderr


# ---- configuration ----


def test_shutdown_timeout_default_in_dump(bastion_bin, tmp_path):
    c = tmp_path / "c.conf"
    c.write_text("server { listen 8080; }\n")
    p = subprocess.run([bastion_bin, "-c", str(c), "-T"], capture_output=True, text=True,
                       timeout=30)
    assert p.returncode == 0, p.stderr
    assert re.search(r"^shutdown_timeout 30s;$", p.stdout, re.M), p.stdout
