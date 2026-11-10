"""What contains a compromised worker: seccomp, capabilities, ring restrictions, namespaces.

BST_TEST_SANDBOX_PROBE=<slot|helper>:<probe>[,<probe>...] (tests/fixtures/sandbox_probe.c, in every
build but release) makes a child attempt something after its sandbox is on and READY has gone
out, on its main thread, or on a pool thread with `pool:` before the probe's name. Each probe logs
`sandbox probe: <name> res=<n> errno=<e>` if it survives. BST_TEST_SANDBOX_PROBE_ONCE=<path>
fires it only in the child that finds and removes path, so a replacement serves normally.

Landlock enforcement needs a kernel that has it: tests/vm/test_sandbox_vm.py. No test here skips
by libc: `make test-int BUILD=musltest K=sandbox` is how the musl binary's needs are found."""
import os
import re
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

from conftest import sanitized
from process_util import *  # noqa: F401,F403

SIGSYS = 31


def probe(name, slot="0"):
    return {"BST_TEST_SANDBOX_PROBE": f"{slot}:{name}"}


def once(tmp_path, name):
    flag = tmp_path / "probe.once"
    flag.write_text("")
    return probe(name) | {"BST_TEST_SANDBOX_PROBE_ONCE": str(flag)}


def killed_line(what="worker/0", sig=SIGSYS):
    return rf"master ERROR {what} \(pid \d+\) killed by signal {sig}; respawn after"


def result(srv, name):
    """(res, errno) of a probe that survived."""
    m = srv.wait_log(rf" sandbox probe: {re.escape(name)} res=(-?\d+) errno=(\d+)$")
    return int(m.group(1)), int(m.group(2))


def assert_killed(bastion, tmp_path, name):
    """The probe dies with SIGSYS, master says so, and a replacement serves."""
    srv = bastion(conf(1), env=ECHO | FAST_RESPAWN | once(tmp_path, name))
    srv.wait_log(killed_line())
    assert f"sandbox probe: {name} " not in srv.logs()
    srv.wait_workers(1)
    assert echo_ok(srv.ports["http"])


# ---- forbidden syscalls ----


def test_execve_killed(bastion, tmp_path):
    assert_killed(bastion, tmp_path, "execve")


def test_ptrace_blocked(bastion, tmp_path):
    assert_killed(bastion, tmp_path, "ptrace")


def test_socket_raw_blocked(bastion, tmp_path):
    assert_killed(bastion, tmp_path, "socket_raw")


def test_bpf_blocked(bastion, tmp_path):
    assert_killed(bastion, tmp_path, "bpf")


def test_mount_blocked(bastion, tmp_path):
    assert_killed(bastion, tmp_path, "mount")


@pytest.mark.parametrize("name", ["memfd", "socket_packet", "socket_netlink", "socket_unix",
                                  "socket_inet_raw_type", "mmap_exec", "mprotect_exec", "prctl",
                                  "ioctl_tiocsti", "fcntl_setown", "setsockopt_ulp", "futex_pi",
                                  "tgkill_other", "setuid", "chroot", "unshare", "seccomp",
                                  "io_uring_setup", "kill"])
def test_forbidden_form_is_killed(bastion, tmp_path, name):
    assert_killed(bastion, tmp_path, name)


def test_open_is_refused(bastion, bastion_bin, tmp_path):
    # Nothing opens a file from inside yet. In a sanitizer build it answers ENOENT rather than
    # killing, because ASan reads /proc in the middle of a report (seccomp_tables.c): either
    # way nothing is opened, and the release list is proved clean by `make check-release`.
    if not sanitized(bastion_bin):
        assert_killed(bastion, tmp_path, "open")
        return
    srv = bastion(conf(1), env=ECHO | probe("open"))
    assert result(srv, "open") == (-1, 2)
    assert echo_ok(srv.ports["http"])


@pytest.mark.parametrize("name", ["socket_tcp", "socket_udp", "mmap_rw", "fcntl_getfl",
                                  "tgkill_self", "sigaltstack", "signal_handler_returns"])
def test_permitted_form_survives(bastion, name):
    # The other half of an argument filter: the form a worker needs gets through.
    srv = bastion(conf(1), env=ECHO | probe(name))
    assert result(srv, name)[0] >= 0
    assert echo_ok(srv.ports["http"])


def test_helper_is_filtered_too(bastion, tmp_path):
    flag = tmp_path / "probe.once"
    flag.write_text("")
    srv = bastion(conf(1), env=ECHO | FAST_RESPAWN | probe("execve", "helper") |
                  {"BST_TEST_SANDBOX_PROBE_ONCE": str(flag)})
    srv.wait_log(killed_line("helper"))
    srv.wait_for(srv.helper, what="a new helper")


def test_helper_list_is_narrower_than_a_workers(bastion, tmp_path):
    # Per role: a helper has no listeners, so accept4 is a worker's alone.
    flag = tmp_path / "probe.once"
    flag.write_text("")
    srv = bastion(conf(1), env=ECHO | FAST_RESPAWN | probe("accept4", "helper") |
                  {"BST_TEST_SANDBOX_PROBE_ONCE": str(flag)})
    srv.wait_log(killed_line("helper"))
    srv = bastion(conf(1), env=ECHO | probe("accept4"))
    assert result(srv, "accept4")[1] != 0  # EBADF: the call itself is allowed


def test_no_new_threads(bastion, backend, tmp_path):
    for name in ("fork", "clone_thread", "clone_vfork"):
        (tmp_path / name).mkdir()
        srv = bastion(conf(1), workdir=tmp_path / name,
                      env=ECHO | FAST_RESPAWN | once(tmp_path / name, name))
        srv.wait_log(killed_line())
        srv.wait_workers(1)
    (tmp_path / "pool").mkdir()
    srv = bastion(conf(1, f"io {{ backend {backend}; aio_threads 2; }}"), workdir=tmp_path / "pool",
                  env=ECHO | probe("clone3,aio"))
    assert result(srv, "clone3") == (-1, 38)  # ENOSYS
    assert result(srv, "aio")[0] == 0
    assert len(tids(srv.workers()[0])) >= 3
    assert echo_ok(srv.ports["http"])


def test_stop_and_continue_restarts_a_timed_wait(bastion):
    # A timed futex interrupted by a stop comes back through restart_syscall, not the original
    # number, so without it a plain SIGSTOP and SIGCONT would kill the worker.
    srv = bastion(conf(1, "io { aio_threads 2; }"), env=ECHO | probe("pool:futex_wait_1500ms"))
    w = srv.workers()[0]
    srv.wait_log(r"sandbox probe: waiting")
    time.sleep(0.2)
    os.kill(w, signal.SIGSTOP)
    time.sleep(0.2)
    os.kill(w, signal.SIGCONT)
    assert result(srv, "futex_wait_1500ms") == (-1, 110)  # ETIMEDOUT, after the restart
    assert srv.workers()[0] == w
    assert echo_ok(srv.ports["http"])


# ---- the crash path, inside the filter ----


def order_of(text, *needles):
    at = [text.find(n) for n in needles]
    assert all(a >= 0 for a in at) and at == sorted(at), (needles, at, text)


@pytest.mark.parametrize("how,sig", [("segv", 11), ("abort", 6), ("stack", 11), ("frames", 11)])
def test_crash_report_works_inside_the_sandbox(bastion, how, sig):
    # A handler the filter killed would hide the crash: the report must be complete, and the
    # death the real one.
    srv = bastion(conf(1), wait=None, env=FAST_RESPAWN | {"BST_TEST_WORKER_CRASH": f"0:{how}"})
    srv.wait_log(r"worker/0 ERROR crash: end$", timeout=20)
    srv.wait_log(killed_line(sig=sig))
    assert not re.search(killed_line(), srv.logs()), srv.logs()
    order_of(srv.logs(), "worker/0 INFO sandbox: ", f"worker/0 ERROR crash: signal {sig} ",
             "worker/0 ERROR crash: end")


@pytest.mark.parametrize("how,sig", [("segv", 11), ("abort", 6)])
def test_crash_report_from_a_pool_thread_inside_the_sandbox(bastion, how, sig):
    srv = bastion(conf(1), wait=None, env=FAST_RESPAWN | {"BST_TEST_AIO_CRASH": f"0:{how}"})
    srv.wait_log(r"worker/0 ERROR crash: end$", timeout=20)
    srv.wait_log(killed_line(sig=sig))
    assert not re.search(killed_line(), srv.logs()), srv.logs()


def test_tsync_failure_is_fatal(bastion):
    # Pool threads outside the filter would be free: there is no running on after that.
    srv = bastion(conf(1), wait=None, env={"BST_TEST_SANDBOX_FAIL": "tsync:1234"})
    assert srv.proc.wait(15) == 1
    assert "TSYNC" in srv.logs()
    assert srv.children() == {}


# ---- capabilities and process hardening ----


def assert_status(pid, uid=None):
    for tid in tids(pid):
        name = task_field(pid, tid, "Name")
        for cap in ("CapEff", "CapPrm", "CapBnd", "CapInh", "CapAmb"):
            assert int(task_field(pid, tid, cap), 16) == 0, (name, cap)
        assert task_field(pid, tid, "NoNewPrivs") == "1", name
        assert task_field(pid, tid, "Seccomp") == "2", name
        if uid is not None:
            assert task_field(pid, tid, "Uid").split() == [str(uid)] * 4, name


@pytest.mark.parametrize("extra,uid", [("", None), ("user nobody;", 65534)],
                         ids=["as_root", "as_nobody"])
def test_no_caps(bastion, backend, extra, uid):
    need_root()
    srv = bastion(conf(2, f"{extra}\nio {{ backend {backend}; aio_threads 2; }}"), env=ECHO)
    for pid in list(srv.workers().values()) + [srv.helper()]:
        assert len(tids(pid)) >= 3  # the pool started before the drop: every thread counts
        assert_status(pid, uid)
    # Master stays outside: it needs what the children gave up.
    assert field(srv.proc.pid, "Seccomp") == "0"
    assert int(field(srv.proc.pid, "CapEff"), 16) != 0
    assert field(srv.proc.pid, "NoNewPrivs") == "0"


def test_sqpoll_thread_of_a_root_worker_holds_no_caps(bastion):
    # With no `user` the SQ thread would keep the full set of the ring's creator.
    need_root()
    srv = bastion(conf(1, "io { backend uring; uring_sqpoll 50ms; }"), env=ECHO)
    w = srv.workers()[0]
    names = [task_field(w, t, "Name") for t in tids(w)]
    assert any(n.startswith("iou-sqp-") for n in names), names
    assert_status(w)
    assert echo_ok(srv.ports["http"])


def test_not_dumpable(bastion):
    need_root()
    srv = bastion(conf(1, "user nobody;"))
    w = srv.workers()[0]
    limits = Path(f"/proc/{w}/limits").read_text()
    assert re.search(r"^Max core file size\s+0\s+0\s", limits, re.M), limits
    # /proc/<pid> of a process that may not dump belongs to root, whoever it runs as.
    assert field(w, "Uid").split()[0] == "65534"
    assert os.stat(f"/proc/{w}/fd").st_uid == 0


def test_dumpable_as_the_process_reads_it(bastion):
    srv = bastion(conf(1, "sandbox { seccomp log; }"), env=probe("dumpable"))
    assert result(srv, "dumpable")[0] == 0


def test_rlimit_nproc_is_left_alone(bastion):
    # io_uring's kernel workers are subject to it: architecture section 8.
    srv = bastion(conf(1))
    limits = Path(f"/proc/{srv.workers()[0]}/limits").read_text()
    m = re.search(r"^Max processes\s+(\S+)\s+(\S+)\s", limits, re.M)
    assert m.group(1) != "0", limits


# ---- each step can be turned off, and says so ----


def test_steps_are_reported(bastion):
    srv = bastion(conf(1))
    assert re.search(r"worker/0 INFO sandbox: seccomp=on landlock=\S+ namespaces=off "
                     r"capabilities=dropped$", srv.logs(), re.M), srv.logs()
    assert re.search(r"helper INFO sandbox: seccomp=on ", srv.logs()), srv.logs()


def test_seccomp_off(bastion_bin, bastion, tmp_path):
    srv = bastion(conf(1, "sandbox { seccomp off; }"), env=ECHO | probe("memfd"))
    w = srv.workers()[0]
    assert field(w, "Seccomp") == "0"
    assert int(field(w, "CapEff"), 16) == 0
    assert field(w, "NoNewPrivs") == "1"
    assert result(srv, "memfd")[0] >= 0
    assert echo_ok(srv.ports["http"])
    # -t warns: this is a hole a reader of the config should see.
    path = tmp_path / "t.conf"
    path.write_text(conf(1, "sandbox { seccomp off; }").replace("@HTTP_PORT@", "1"))
    p = subprocess.run([bastion_bin, "-c", str(path), "-t"], capture_output=True, text=True)
    assert p.returncode == 0 and "warning" in p.stderr and "seccomp" in p.stderr, p.stderr


def test_drop_capabilities_off(bastion):
    need_root()
    srv = bastion(conf(1, "sandbox { drop_capabilities off; }"), env=ECHO)
    w = srv.workers()[0]
    assert int(field(w, "CapEff"), 16) != 0
    assert field(w, "Seccomp") == "2"
    assert echo_ok(srv.ports["http"])


def test_defaults_apply_when_the_block_is_absent(bastion_bin, tmp_path):
    path = tmp_path / "t.conf"
    path.write_text(conf(1).replace("@HTTP_PORT@", "1"))
    p = subprocess.run([bastion_bin, "-c", str(path), "-T"], capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    m = re.search(r"^sandbox \{(.*?)^\}", p.stdout, re.M | re.S)
    assert m, p.stdout
    body = m.group(1)
    for line in ("seccomp on;", "landlock on;", "namespaces off;", "drop_capabilities on;"):
        assert line in body, body


@pytest.mark.parametrize("text", ["seccomp maybe;", "landlock maybe;", "namespaces maybe;",
                                  "drop_capabilities maybe;", "seccomp off require;",
                                  "landlock off require;", "extra_read;",
                                  "extra_read relative/path;", "extra_write relative/path;"])
def test_bad_sandbox_config(bastion_bin, tmp_path, text):
    path = tmp_path / "t.conf"
    path.write_text(conf(1, f"sandbox {{ {text} }}").replace("@HTTP_PORT@", "1"))
    p = subprocess.run([bastion_bin, "-c", str(path), "-t"], capture_output=True, text=True)
    assert p.returncode == 1, (text, p.stdout, p.stderr)


# ---- seccomp log ----


def audit_records(comm, nr, since):
    """Kernel records (type 1326) of comm's syscall nr, stamped at or after since."""
    out = subprocess.run(["dmesg"], capture_output=True, text=True).stdout
    found = []
    for m in re.finditer(r"audit: type=1326 audit\((\d+)\.\d+:\d+\):.*$", out, re.M):
        line = m.group(0)
        if int(m.group(1)) >= since and f'comm="{comm}"' in line and f" syscall={nr} " in line:
            found.append(line)
    return found


def test_log_mode(bastion):
    since = int(time.time()) - 1
    srv = bastion(conf(1, "sandbox { seccomp log; }"), env=ECHO | probe("socket_raw,memfd"))
    w = srv.workers()[0]
    assert field(w, "Seccomp") == "2"
    result(srv, "socket_raw")  # it came back, whatever the kernel said
    assert result(srv, "memfd")[0] >= 0  # it went through
    assert srv.workers()[0] == w
    assert echo_ok(srv.ports["http"])
    assert re.search(r"worker/0 WARN sandbox: seccomp log", srv.logs()), srv.logs()
    m = srv.wait_log(r"sandbox probe: memfd_nr (\d+)$")
    srv.wait_for(lambda: audit_records("bst:worker/0", m.group(1), since), what="audit record")


def test_log_mode_keeps_the_arch_check(bastion_bin, tmp_path):
    # `log` eases debugging of the list. It does not open the other syscall ABI: the unit test
    # runs the filter on foreign architectures, here it only needs to start.
    path = tmp_path / "t.conf"
    path.write_text(conf(1, "sandbox { seccomp log; }").replace("@HTTP_PORT@", "1"))
    p = subprocess.run([bastion_bin, "-c", str(path), "-t"], capture_output=True, text=True)
    assert p.returncode == 0 and "seccomp log" in p.stderr, p.stderr


# ---- io_uring ----


@pytest.mark.parametrize("extra", ["", "user nobody;\nio { backend uring; uring_sqpoll 50ms; }"],
                         ids=["plain", "sqpoll"])
def test_uring_restricted(bastion, extra):
    # Ring operations are not syscalls, so seccomp cannot see them: only the ring's own
    # restrictions stop IORING_OP_SOCKET. Registered before enabling, on both kinds of ring.
    need_root()
    srv = bastion(conf(1, extra), backend="uring", env=ECHO | probe("uring_socket,uring_nop"))
    assert result(srv, "uring_socket")[0] == -13  # EACCES
    assert result(srv, "uring_nop")[0] == 0  # the same path, an allowed opcode
    assert echo_ok(srv.ports["http"])


@pytest.mark.parametrize("name", ["uring_register_restrictions", "uring_register_buffers"])
def test_uring_register_is_refused_by_the_ring(bastion, name):
    # `seccomp log` lets the syscall through, so this is the ring's own refusal: a plain ring
    # created as root would otherwise pin memory past RLIMIT_MEMLOCK.
    need_root()
    srv = bastion(conf(1, "user nobody;\nsandbox { seccomp log; }"), backend="uring",
                  env=ECHO | probe(name))
    assert result(srv, name)[0] == -13


@pytest.mark.parametrize("name", ["uring_register_restrictions", "uring_register_buffers"])
def test_uring_register_is_killed_by_the_filter(bastion, tmp_path, name):
    srv = bastion(conf(1), backend="uring", env=ECHO | FAST_RESPAWN | once(tmp_path, name))
    srv.wait_log(killed_line())


def test_restrictions_keep_a_serving_ring_working(bastion):
    srv = bastion(conf(2), backend="uring", env=slow_env(256 << 10, 64 << 10, 5))
    with connect(srv.ports["http"]) as s:
        assert read_pattern(s, 256 << 10) == 256 << 10


def test_uring_async_under_sandbox(bastion, tmp_path):
    # A read the ring cannot finish inline goes to a kernel worker thread. Seccomp must not see
    # it and RLIMIT_NPROC must not stop it.
    data = bytes(i % 251 for i in range(1 << 20))
    path = tmp_path / "cold"
    path.write_bytes(data)
    srv = bastion(conf(1), backend="uring", env=ECHO | probe(f"uring_async:{path}"))
    w = srv.workers()[0]
    res, _ = result(srv, f"uring_async:{path}")
    assert res == len(data)
    assert srv.wait_log(r"sandbox probe: uring_async_sum (\d+)$").group(1) == str(sum(data))
    assert any(task_field(w, t, "Name").startswith("iou-wrk-") for t in tids(w)), \
        [task_field(w, t, "Name") for t in tids(w)]


# ---- sanitizer builds ----


def test_exit_path_is_not_killed_in_a_sandboxed_child(bastion, tmp_path):
    # LSan's exit check clones a thread and reads /proc: a sandboxed child must skip it, or the
    # filter kills it on the way out and hides what it was exiting for.
    srv = bastion(conf(1), wait=None, env=FAST_RESPAWN | once(tmp_path, "exit"))
    srv.wait_log(r"master ERROR worker/0 \(pid \d+\) exited with status 7; ")
    assert not re.search(killed_line(), srv.logs()), srv.logs()


def test_heap_overflow_inner(bastion):
    # Run only by the test below. It must fail, at teardown.
    if os.environ.get("BST_PROVE_TEARDOWN") != "1":
        pytest.skip("run by test_heap_overflow_in_a_sandboxed_worker_fails_the_test")
    srv = bastion(conf(1, "user nobody;"), wait=None,
                  env=FAST_RESPAWN | {"BST_TEST_WORKER_CRASH": "0:heap"})
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if any(r.stat().st_size for r in srv.report_dir.glob("sanitizer*")):
            break
        time.sleep(0.05)


def test_heap_overflow_in_a_sandboxed_worker_fails_the_test(bastion_bin):
    if not sanitized(bastion_bin):
        pytest.skip("not an ASan build")
    env = dict(os.environ, BST_PROVE_TEARDOWN="1")
    p = subprocess.run([sys.executable, "-m", "pytest", "-q", "-x", "--no-header", "-p",
                        "no:cacheprovider", f"{__file__}::test_heap_overflow_inner"],
                       capture_output=True, text=True, env=env, cwd=Path(__file__).parent,
                       timeout=60)
    assert p.returncode == 1, p.stdout + p.stderr
    assert "heap-buffer-overflow" in p.stdout, p.stdout + p.stderr


def test_heap_report_in_a_sandboxed_worker(bastion, bastion_bin):
    if not sanitized(bastion_bin):
        pytest.skip("not an ASan build")
    srv = bastion(conf(1), wait=None, env=FAST_RESPAWN | {"BST_TEST_WORKER_CRASH": "0:heap"})
    deadline = time.monotonic() + 15
    text = ""
    while "SUMMARY" not in text and time.monotonic() < deadline:
        text = "".join(r.read_text() for r in srv.report_dir.glob("sanitizer*"))
        time.sleep(0.05)
    assert "heap-buffer-overflow" in text and "SUMMARY" in text, srv.logs()
    assert "Sandbox" not in text and not re.search(killed_line(), srv.logs()), srv.logs()
    srv.proc.terminate()
    srv.proc.wait(10)
    for r in srv.report_dir.glob("sanitizer*"):  # the test took the reports: teardown fails on one
        r.unlink()


def test_master_keeps_its_leak_check(bastion, bastion_bin):
    if not sanitized(bastion_bin):
        pytest.skip("not an ASan build")
    srv = bastion(conf(1), env={"BST_TEST_MASTER_LEAK": "1"})
    srv.proc.terminate()
    srv.proc.wait(10)
    reports = [r for r in srv.report_dir.glob("sanitizer*") if r.stat().st_size]
    assert reports and "LeakSanitizer" in reports[0].read_text()
    for r in srv.report_dir.glob("sanitizer*"):
        r.unlink()


# ---- namespaces ----


NS = "sandbox { namespaces on; }"


def ns_of(pid, kind):
    return os.readlink(f"/proc/{pid}/ns/{kind}")


def test_namespaces(bastion):
    need_root()
    srv = bastion(conf(2, "user nobody;\n" + NS), env=ECHO)
    for pid in list(srv.workers().values()) + [srv.helper()]:
        for kind in ("mnt", "pid", "ipc", "uts"):
            assert ns_of(pid, kind) != ns_of(srv.proc.pid, kind), kind
        assert ns_of(pid, "net") == ns_of(srv.proc.pid, "net")  # listeners are in this one
        assert field(pid, "NSpid").split()[-1] == "1"
        assert_status(pid, 65534)
    pids = {ns_of(p, "pid") for p in srv.workers().values()}
    assert len(pids) == 2  # one each: a worker's death takes nothing else with it
    assert re.search(r"worker/0 INFO sandbox: seccomp=on landlock=\S+ namespaces=on ",
                     srv.logs()), srv.logs()
    for _ in range(10):
        assert echo_ok(srv.ports["http"])


def test_namespaces_keep_logs_and_declared_paths(bastion, tmp_path):
    need_root()
    www = tmp_path / "www"
    www.mkdir()
    (www / "index.html").write_text("hello\n")
    cache = tmp_path / "cache"
    cache.mkdir()
    cache.chmod(0o777)
    tmp_path.chmod(0o755)
    www.chmod(0o755)
    (www / "index.html").chmod(0o644)
    srv = bastion(conf(1, f"user nobody;\nsandbox {{ namespaces on; seccomp log; "
                          f"extra_read {www}; extra_write {cache}; }}"),
                  env=ECHO | probe(f"read_file:{www}/index.html,read_file:/etc/passwd,"
                                   f"write_file:{cache}/new,write_file:{www}/new"))
    assert result(srv, f"read_file:{www}/index.html")[0] == 6
    assert result(srv, "read_file:/etc/passwd") == (-1, 2)  # ENOENT: not in this root
    assert result(srv, f"write_file:{cache}/new")[0] >= 0
    assert (cache / "new").exists()
    assert result(srv, f"write_file:{www}/new")[1] == 30  # EROFS: a read-only bind
    assert not (www / "new").exists()
    assert echo_ok(srv.ports["http"])


@pytest.mark.parametrize("env", [{}, {"BST_TEST_NO_PDEATHSIG": "1"},
                                 {"BST_TEST_NO_CHANNEL_EOF": "1"}],
                         ids=["both", "channel_eof_alone", "pdeathsig_alone"])
def test_master_death_with_namespaces(bastion, env):
    # PR_SET_PDEATHSIG reaches a PID namespace's init: a signal from an ancestor namespace is not
    # filtered the way one from inside is. getppid is 0 there, so the recheck cannot use it.
    need_root()
    srv = bastion(conf(3, NS), env=ECHO | env)
    kids = list(srv.children())
    assert len(kids) == 4
    srv.proc.kill()
    srv.proc.wait(5)
    assert wait_gone(kids), [p for p in kids if not gone(p)]


def test_master_dies_before_pdeathsig_is_set_with_namespaces(bastion):
    need_root()
    srv = bastion(conf(1, NS), wait=None, env={"BST_TEST_NO_CHANNEL_EOF": "1",
                                               "BST_TEST_WORKER_WATCH_DELAY_MS": "1500"})
    w = srv.wait_workers(1)[0]
    time.sleep(0.2)
    srv.proc.kill()
    srv.proc.wait(5)
    assert wait_gone([w], 5)
    assert re.search(r"worker/0 \S+ master is gone", srv.logs()), srv.logs()


def test_a_live_master_is_not_taken_for_gone_in_a_namespace(bastion):
    # getppid is 0 for as long as master lives, too.
    need_root()
    srv = bastion(conf(1, NS), env=ECHO)
    time.sleep(0.3)
    assert "master is gone" not in srv.logs()
    assert echo_ok(srv.ports["http"])


@pytest.mark.parametrize("how,sig", [("segv", 11), ("abort", 6)])
def test_crash_in_a_pid_namespace(bastion, how, sig):
    # A namespace's init is immune to its own raise(): the report still comes, master still sees
    # a crash and respawns. Dead by the signal or by 128 + signal, never silent.
    need_root()
    srv = bastion(conf(1, NS), wait=None, env=FAST_RESPAWN | {"BST_TEST_WORKER_CRASH": f"0:{how}"})
    srv.wait_log(r"worker/0 ERROR crash: end$", timeout=20)
    srv.wait_log(rf"master ERROR worker/0 \(pid \d+\) (killed by signal {sig}|exited with status "
                 rf"{128 + sig}); ")


def test_probe_killed_in_a_pid_namespace(bastion, tmp_path):
    need_root()
    srv = bastion(conf(1, NS), env=ECHO | FAST_RESPAWN | once(tmp_path, "execve"))
    srv.wait_log(killed_line())
    srv.wait_workers(1)
    assert echo_ok(srv.ports["http"])


def test_namespace_not_permitted_warns(bastion):
    srv = bastion(conf(1, NS), env=ECHO | {"BST_TEST_SANDBOX_FAIL": "namespaces:1"})
    assert re.search(r"WARN sandbox: namespaces: ", srv.logs()), srv.logs()
    assert re.search(r"worker/0 INFO sandbox: seccomp=on landlock=\S+ namespaces=off ",
                     srv.logs()), srv.logs()
    assert echo_ok(srv.ports["http"])


def test_namespace_not_permitted_with_require_stops_startup(bastion):
    srv = bastion(conf(1, "sandbox { namespaces on require; }"), wait=None,
                  env={"BST_TEST_SANDBOX_FAIL": "namespaces:1"})
    assert srv.proc.wait(15) == 1
    assert "namespaces" in srv.logs()
    assert srv.children() == {}


def test_namespaces_as_a_user_who_may_not(bastion):
    # Not root and no capabilities: this is the real refusal, not an injected one.
    need_root()
    srv = bastion(conf(1, NS), wait=None, wrap=AS_NOBODY, workdir=nobody_dir_for_test(), env=ECHO)
    srv.wait_log(r"WARN sandbox: namespaces: ")
    srv.wait_log(r"worker/0 INFO sandbox: seccomp=on ")  # wait=None: it may only just exist
    assert field(srv.wait_workers(1)[0], "Seccomp") == "2"
    assert echo_ok(srv.ports["http"])


def nobody_dir_for_test():
    d = Path(tempfile.mkdtemp(dir="/tmp"))
    os.chmod(d, 0o755)
    os.chown(d, 65534, 65534)
    return d


# ---- Landlock, where the kernel decides ----


def test_missing_landlock_warns(bastion):
    srv = bastion(conf(1), env=ECHO | {"BST_TEST_SANDBOX_FAIL": "landlock:38"})
    assert re.search(r"worker/0 WARN sandbox: landlock unavailable", srv.logs()), srv.logs()
    assert re.search(r"worker/0 INFO sandbox: seccomp=on landlock=unavailable ", srv.logs())
    assert echo_ok(srv.ports["http"])


def test_missing_landlock_with_require_stops_startup(bastion):
    srv = bastion(conf(1, "sandbox { landlock on require; }"), wait=None,
                  env={"BST_TEST_SANDBOX_FAIL": "landlock:38"})
    assert srv.proc.wait(15) == 1
    assert "landlock" in srv.logs()
    assert "respawn after" not in srv.logs()
    assert srv.children() == {}


# ---- what else the environment can refuse ----


def test_missing_seccomp_warns(bastion):
    srv = bastion(conf(1), env=ECHO | {"BST_TEST_SANDBOX_FAIL": "seccomp:38"})
    assert re.search(r"worker/0 WARN sandbox: seccomp unavailable", srv.logs()), srv.logs()
    assert re.search(r"worker/0 INFO sandbox: seccomp=unavailable ", srv.logs()), srv.logs()
    assert echo_ok(srv.ports["http"])


def test_missing_seccomp_with_require_stops_startup(bastion):
    srv = bastion(conf(1, "sandbox { seccomp on require; }"), wait=None,
                  env={"BST_TEST_SANDBOX_FAIL": "seccomp:38"})
    assert srv.proc.wait(15) == 1
    assert "seccomp" in srv.logs()
    assert srv.children() == {}


def test_seccomp_refused_for_any_other_reason_stops_startup(bastion):
    # ENOSYS means the kernel has no filters. Anything else means this one was not installed,
    # and silently running without it is not on offer.
    srv = bastion(conf(1), wait=None, env={"BST_TEST_SANDBOX_FAIL": "seccomp:1"})
    assert srv.proc.wait(15) == 1
    assert "seccomp" in srv.logs()
    assert srv.children() == {}


def test_bounding_set_needs_root_warns(bastion):
    need_root()
    srv = bastion(conf(1), wait=None, wrap=AS_NOBODY, workdir=nobody_dir_for_test(), env=ECHO)
    srv.wait_log(r"worker/0 WARN sandbox: the capability bounding set is kept")
    srv.wait_log(r"worker/0 INFO sandbox: seccomp=on ")  # wait=None: it may only just exist
    w = srv.wait_workers(1)[0]
    assert int(field(w, "CapEff"), 16) == 0 and field(w, "NoNewPrivs") == "1"
    assert echo_ok(srv.ports["http"])


def test_bounding_set_with_require_stops_startup(bastion):
    need_root()
    srv = bastion(conf(1, "sandbox { drop_capabilities on require; }"), wait=None, wrap=AS_NOBODY,
                  workdir=nobody_dir_for_test())
    assert srv.proc.wait(15) == 1
    assert "bounding" in srv.logs()


# ---- the fixture that keeps all of this true ----


def test_all_tests_sandboxed(bastion):
    # The check conftest.py runs for every server started through the `bastion` fixture.
    srv = bastion(conf(1))
    srv.assert_sandboxed()
    bare = bastion(conf(1, "sandbox { seccomp off; }"))
    with pytest.raises(pytest.fail.Exception, match="Seccomp"):
        bare.assert_sandboxed(timeout=0.2)


def test_opting_out_is_by_name(request):
    from conftest import UNSANDBOXED
    assert request.node.originalname not in UNSANDBOXED
    assert "test_seccomp_off" in UNSANDBOXED
