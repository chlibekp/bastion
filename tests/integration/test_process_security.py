"""What a worker can and cannot do.

Privileges, descriptors, the tty, the channel, crash reports and the log."""
import fcntl
import grp
import os
import pty
import pwd
import re
import select
import signal
import socket
import stat as statmod
import subprocess
import tempfile
import termios
import time
from pathlib import Path

import pytest

from process_util import *  # noqa: F401,F403


# ---- privileges ----


def test_privilege_drop(bastion, backend):
    need_root()
    nobody = pwd.getpwnam("nobody")
    srv = bastion(conf(2, f"user nobody;\nio {{ backend {backend}; aio_threads 2; }}"), env=ECHO)
    assert field(srv.proc.pid, "Uid").split() == ["0"] * 4  # master stays root
    for pid in list(srv.workers().values()) + [srv.helper()]:
        assert len(tids(pid)) >= 1
        for tid in tids(pid):  # every thread: the aio pool started before the drop
            assert task_field(pid, tid, "Uid").split() == [str(nobody.pw_uid)] * 4
            assert task_field(pid, tid, "Gid").split() == [str(nobody.pw_gid)] * 4
        assert field(pid, "Groups").split() == [str(nobody.pw_gid)]
    assert len(tids(srv.workers()[0])) >= 3
    assert echo_ok(srv.ports["http"])


def test_loop_is_created_before_the_privilege_drop(bastion):
    # SINGLE_ISSUER binds the ring at enable and kernel.io_uring_disabled=1 lets only root create
    # one (the VM tier runs that for real). Here, the order itself.
    need_root()
    nobody = pwd.getpwnam("nobody")
    srv = bastion(conf(1, "user nobody;"), env={"BST_TEST_WORKER_REPORT": "1"})
    m = srv.wait_log(r"worker/0 INFO test report: order loop_euid=(\d+) euid=(\d+)$")
    assert m.groups() == ("0", str(nobody.pw_uid)), m.group(0)


def test_group_directive(bastion, backend):
    need_root()
    nobody = pwd.getpwnam("nobody")
    other = grp.getgrnam("daemon")
    srv = bastion(conf(1, "user nobody;\ngroup daemon;"))
    w = srv.workers()[0]
    assert field(w, "Uid").split()[0] == str(nobody.pw_uid)
    assert field(w, "Gid").split() == [str(other.gr_gid)] * 4


def test_unknown_user_is_startup_error(bastion):
    need_root()
    srv = bastion(conf(1, "user no_such_user_here;"), wait=None)
    assert srv.proc.wait(10) == 1
    assert "no_such_user_here" in srv.stdout()
    assert srv.children() == {}


def test_root_without_user_warns(bastion):
    need_root()
    srv = bastion(conf(1))
    assert re.search(r"master WARN workers run as root: set \"user\"", srv.logs()), srv.logs()


@pytest.mark.parametrize("step", ["setgroups", "setgid", "setuid", "regain"])
def test_failed_drop_never_runs_on(bastion, step):
    need_root()
    srv = bastion(conf(2, "user nobody;"), wait=None, env={"BST_TEST_DROP_FAIL": step})
    assert srv.proc.wait(15) == 1
    assert re.search(r"master ERROR startup failed: ", srv.logs()), srv.logs()
    assert "respawn after" not in srv.logs()
    assert srv.children() == {}


# ---- SQPOLL ----


def unix_listeners():
    """A socket only root may connect to, and one anybody may. An open through the ring would be
    refused by the ring's restrictions whoever ran it. CONNECT stays open, and a socket file's
    mode is checked against the credentials of whatever runs the request."""
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


def sqpoll_conf(backend="uring"):
    return conf(2, f"user nobody;\nio {{ backend {backend}; uring_sqpoll 50ms; }}")


def assert_unprivileged(srv, sq_threads):
    nobody = pwd.getpwnam("nobody")
    kids = list(srv.workers().values()) + [srv.helper()]
    assert len(kids) == 3
    for pid in kids:
        names = []
        for tid in tids(pid):
            names.append(task_field(pid, tid, "Name"))
            assert task_field(pid, tid, "Uid").split() == [str(nobody.pw_uid)] * 4, names[-1]
            assert task_field(pid, tid, "Gid").split() == [str(nobody.pw_gid)] * 4, names[-1]
            for cap in ("CapEff", "CapPrm", "CapInh", "CapAmb"):
                assert int(task_field(pid, tid, cap), 16) == 0, (names[-1], cap)
        assert any(n.startswith("iou-sqp-") for n in names) == sq_threads, names


def test_sqpoll_ring_holds_no_privilege(bastion):
    # The SQ thread keeps the credentials of the ring's creator, and runs what the worker writes
    # to the SQ ring. Made as root, every request would run as root after the drop.
    need_root()
    socks, (secret, anyone) = unix_listeners()
    srv = bastion(sqpoll_conf(), env={"BST_TEST_WORKER_SQ_CONNECT": f"{secret},{anyone}",
                                      "BST_TEST_WORKER_REPORT": "1"})
    assert_unprivileged(srv, True)
    m = srv.wait_log(rf"worker/0 INFO test report: sq_connect {secret} res=(-?\d+) sqpoll=(\d)$")
    assert m.groups() == ("-13", "1"), m.group(0)
    m = srv.wait_log(rf"worker/0 INFO test report: sq_connect {anyone} res=(-?\d+) sqpoll=(\d)$")
    assert m.groups() == ("0", "1"), m.group(0)  # the ring runs it: the refusal above is the kernel's
    m = srv.wait_log(r"worker/0 INFO test report: order loop_euid=(\d+) euid=(\d+)$")
    assert m.group(1) == m.group(2) == str(pwd.getpwnam("nobody").pw_uid)


def test_sqpoll_refused_after_the_drop_auto_keeps_a_plain_ring(bastion):
    need_root()
    srv = bastion(sqpoll_conf("auto"), env={"BST_TEST_DROPPED_URING_FAIL": "setup:1",
                                            "BST_TEST_WORKER_REPORT": "1"})
    assert re.search(r"master WARN uring_sqpoll ignored: ", srv.logs()), srv.logs()
    srv.wait_log(r"master INFO ready: 2 workers on uring$")
    assert_unprivileged(srv, False)
    m = srv.wait_log(r"worker/0 INFO test report: order loop_euid=(\d+) euid=(\d+)$")
    assert m.group(1) == "0"  # the plain ring keeps its place before the drop


def test_sqpoll_refused_after_the_drop_forced_is_a_startup_error(bastion):
    need_root()
    srv = bastion(sqpoll_conf("uring"), wait=None,
                  env={"BST_TEST_DROPPED_URING_FAIL": "setup:1"})
    assert srv.proc.wait(10) == 1
    assert "kernel.io_uring_group" in srv.stdout(), srv.stdout()
    assert "respawn after" not in srv.logs()
    assert srv.children() == {}


# ---- descriptors and the tty ----


def links(pid):
    out = {}
    for fd in os.listdir(f"/proc/{pid}/fd"):
        try:
            out[int(fd)] = os.readlink(f"/proc/{pid}/fd/{fd}")
        except OSError:
            pass
    return out


def listener_inodes(port):
    want = f"{port:04X}"
    inodes = set()
    for line in Path("/proc/net/tcp").read_text().splitlines()[1:]:
        f = line.split()
        if f[1].endswith(":" + want) and f[3] == "0A":
            inodes.add(f[9])
    return inodes


def check_fds(pid, srv, backend, listeners):
    """An allowlist: everything open in a child is named here, with how many of it."""
    found = links(pid)
    assert [found.get(n) for n in (0, 1, 2)] == ["/dev/null"] * 3, found
    rest = [v for n, v in found.items() if n > 2]
    count = {}
    for v in rest:
        if v == str(srv.error_log):
            kind = "log"
        elif v.startswith(f"{srv.report_dir}/sanitizer"):
            kind = "report"  # a sanitizer build holds this open from before the sandbox
        elif v.startswith("socket:["):
            kind = "listener" if v[8:-1] in srv.inodes else "unix"
        elif v.startswith("pipe:["):
            kind = "pipe"
        elif v in ("anon_inode:[io_uring]", "anon_inode:[eventpoll]", "anon_inode:[eventfd]"):
            kind = "loop"
        else:
            pytest.fail(f"{pid} holds {v}: {found}")
        count[kind] = count.get(kind, 0) + 1
    assert count.get("log") == 1, found          # its own description, not master's as well
    assert count.get("unix") == 1, found         # its own channel
    assert count.get("pipe") == 2, found         # the crash handler's probe
    assert count.get("listener", 0) == listeners, found


def test_fd_allowlist(bastion, backend):
    srv = bastion(conf(3, "pid @WORKDIR@/b.pid;"))
    srv.inodes = listener_inodes(srv.ports["http"])
    assert len(srv.inodes) == 3
    held = set()
    for pid in srv.workers().values():
        check_fds(pid, srv, backend, 1)
        held |= {v[8:-1] for v in links(pid).values() if v.startswith("socket:[")} & srv.inodes
    assert held == srv.inodes  # each worker its own slot
    check_fds(srv.helper(), srv, backend, 0)
    master = {v[8:-1] for v in links(srv.proc.pid).values() if v.startswith("socket:[")}
    assert srv.inodes <= master  # master keeps every queue alive


def controlling_tty(pid):
    """(session, tty_nr) from /proc/<pid>/stat."""
    stat = Path(f"/proc/{pid}/stat").read_text()
    rest = stat[stat.rindex(")") + 2:].split()
    return int(rest[3]), int(rest[4])


def on_a_pty():
    master, slave = pty.openpty()

    def take_tty():
        os.setsid()
        fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
    return master, slave, take_tty


def test_children_have_no_controlling_tty(bastion):
    # Sharing root's terminal would let a compromised worker type into root's shell (TIOCSTI).
    need_root()
    pm, ps, take_tty = on_a_pty()
    srv = bastion(conf(2, "user nobody;"), stdio=ps, preexec=take_tty,
                  env={"BST_TEST_WORKER_REPORT": "1"})
    assert controlling_tty(srv.proc.pid)[1] != 0  # the test's own setup
    for pid in list(srv.workers().values()) + [srv.helper()]:
        session, tty = controlling_tty(pid)
        assert tty == 0 and session == pid, (pid, session, tty)
        assert [links(pid).get(n) for n in (0, 1, 2)] == ["/dev/null"] * 3
    m = srv.wait_log(r"test report: tty tiocsti_ok=(\d+) tried=(\d+) dev_tty_errno=(\d+)$")
    assert m.group(1) == "0", m.group(0)
    assert m.group(3) == "6", m.group(0)  # ENXIO: no controlling terminal to open
    r, _, _ = select.select([pm], [], [], 0.2)
    assert not r or b"x" not in os.read(pm, 4096)
    os.close(ps)
    os.close(pm)


def test_log_on_a_tty_still_arrives(bastion):
    need_root()
    pm, ps, take_tty = on_a_pty()
    # The worker holds the tty for logging, as nobody and without it being its controlling tty,
    # so it still cannot type into it.
    srv = bastion(conf(1, "user nobody;"), stdio=ps, preexec=take_tty, wait=None, error_log=False,
                  env=NOISY | {"BST_TEST_WORKER_REPORT": "1"})
    srv.wait_workers(1)
    got = read_until(pm, b"dev_tty_errno", 5)
    m = re.search(rb"tiocsti_ok=(\d+) tried=(\d+)", got)
    assert m and m.group(1) == b"0" and m.group(2) == b"1", got
    echo_rounds(srv.ports["http"], 2)
    got = read_until(pm, b"raw log noise", 5)
    assert b"raw log noise" in got, got
    os.close(ps)
    os.close(pm)


# ---- crash handler ----


def crash_lines(text):
    return re.findall(r"^\S+Z \d+ worker/0 ERROR crash: (.*)$", text, re.M)


def symbol_range(binary, name):
    out = subprocess.run(["nm", "-n", binary], capture_output=True, text=True, check=True).stdout
    syms = [(int(a, 16), n) for a, t, n in
            (line.split() for line in out.splitlines() if len(line.split()) == 3)]
    for i, (addr, n) in enumerate(syms):
        if n == name:
            return addr, next(a for a, _ in syms[i + 1:] if a > addr)
    pytest.fail(f"{name} not in {binary}")


def test_crash_handler_reports_and_reraises(bastion, bastion_bin):
    srv = bastion(conf(1), wait=None, env=FAST_RESPAWN | {"BST_TEST_WORKER_CRASH": "0:segv"})
    srv.wait_log(r"master ERROR worker/0 \(pid \d+\) killed by signal 11; ")
    srv.wait_log(r"ERROR crash: end$")
    first = crash_lines(srv.logs())
    first = first[:first.index("end") + 1]
    assert first[0].startswith("signal 11 ")
    assert re.search(r"signal 11 code \d+ addr 0x10\b", first[0]), first
    anchor = int(re.fullmatch(r"anchor bst_crash_install 0x([0-9a-f]+)", first[1]).group(1), 16)
    frames = [int(m.group(1), 16) for m in
              (re.fullmatch(r"#\d+ 0x([0-9a-f]+)", line) for line in first[2:-1]) if m]
    assert len(frames) >= 2, first
    # The walk found the caller: a return address inside bst_worker_main, after relocation.
    slide = anchor - symbol_range(bastion_bin, "bst_crash_install")[0]
    lo, hi = symbol_range(bastion_bin, "bst_worker_main")
    assert any(lo <= f - slide < hi for f in frames), (first, hex(lo), hex(hi), hex(slide))


def test_crash_handler_survives_stack_overflow(bastion):
    srv = bastion(conf(1), wait=None, env=FAST_RESPAWN | {"BST_TEST_WORKER_CRASH": "0:stack"})
    srv.wait_log(r"ERROR crash: end$", timeout=20)
    srv.wait_log(r"master ERROR worker/0 \(pid \d+\) killed by signal 11; ")
    lines = crash_lines(srv.logs())
    lines = lines[:lines.index("end") + 1]
    assert lines[0].startswith("signal 11 ")
    assert len(lines) <= 70  # the walk is bounded


def test_crash_handler_survives_corrupt_frame_pointer(bastion):
    srv = bastion(conf(1), wait=None, env=FAST_RESPAWN | {"BST_TEST_WORKER_CRASH": "0:frames"})
    srv.wait_log(r"ERROR crash: end$")  # it finished, so it did not fault itself
    srv.wait_log(r"master ERROR worker/0 \(pid \d+\) killed by signal 11; ")
    assert "signal 7" not in srv.logs()


@pytest.mark.parametrize("how,sig", [("segv", 11), ("abort", 6), ("stack", 11)])
def test_crash_report_from_a_pool_thread(bastion, how, sig):
    # Pool threads run all disk and CPU-heavy work, and block every signal they do not need.
    # ASan gives every thread an alternate stack of its own, which would hide a missing one.
    srv = bastion(conf(1), wait=None, env=FAST_RESPAWN | {"BST_TEST_AIO_CRASH": f"0:{how}",
                                                          "ASAN_OPTIONS": "use_sigaltstack=0"})
    srv.wait_log(rf"ERROR crash: signal {sig} ", timeout=20)
    srv.wait_log(r"ERROR crash: end$")
    srv.wait_log(rf"master ERROR worker/0 \(pid \d+\) killed by signal {sig}; ")


# ---- channel ----


@pytest.mark.parametrize("kind", ["magic", "type", "short", "long", "oversize", "backend",
                                  "duplicate", "stop"])
def test_hostile_channel_message(bastion, kind):
    # Master is root and a worker is not trusted: garbage costs the sender its life, nothing else.
    srv = bastion(conf(2), env=ECHO | FAST_RESPAWN | {"BST_TEST_CHANNEL_GARBAGE": f"0:{kind}"},
                  wait=None)
    srv.wait_log(r"master ERROR worker/0 \(pid \d+\) sent a bad channel message")
    srv.wait_log(r"master ERROR worker/0 \(pid \d+\) killed by signal 9; ")
    assert srv.proc.poll() is None
    assert field(srv.proc.pid, "Uid").split()[0] == str(os.geteuid())
    srv.wait_for(lambda: 1 in srv.workers(), what="worker 1")


def test_ready_while_being_replaced_is_bad(bastion):
    # A worker told to drain for a backend change has nothing to report.
    srv = bastion(conf(3, "io { backend auto; }"), wait=None,
                  env=ECHO | {"BST_TEST_WORKER_URING_FAIL": "1:setup:1",
                              "BST_TEST_CHANNEL_GARBAGE": "0:ready_on_stop"})
    srv.wait_log(r"master ERROR worker/0 \(pid \d+\) sent a bad channel message")
    srv.wait_log(r"master INFO ready: 3 workers on epoll$")


def test_channel_closed_by_live_worker(bastion):
    srv = bastion(conf(1), env=ECHO | FAST_RESPAWN | {"BST_TEST_CHANNEL_GARBAGE": "0:close"},
                  wait=None)
    srv.wait_log(r"master ERROR worker/0 \(pid \d+\) closed its channel")
    srv.wait_log(r"killed by signal 9; ")


# ---- logging ----


NOISY = ECHO | {"BST_TEST_RAW_LOG_LINES": "64"}


def echo_rounds(port, n):
    for _ in range(n):
        assert echo_ok(port, timeout=3)


def test_stderr_pipe_keeps_its_flags_and_never_blocks(bastion):
    r, w = os.pipe()
    try:
        srv = bastion(conf(2), env=NOISY, wait=None, error_log=False, stderr=w)
        srv.wait_workers(2)
        echo_rounds(srv.ports["http"], 3)  # both started and past their log setup
        assert not fcntl.fcntl(w, fcntl.F_GETFL) & os.O_NONBLOCK  # the description we hold
        echo_rounds(srv.ports["http"], 200)  # far more than 64 KiB of unread log
        assert srv.proc.poll() is None
    finally:
        os.close(r)
        os.close(w)


def test_stderr_socket_never_blocks(bastion):
    a, b = socket.socketpair()
    try:
        srv = bastion(conf(2), env=NOISY, wait=None, error_log=False, stderr=b.fileno())
        srv.wait_workers(2)
        echo_rounds(srv.ports["http"], 3)
        assert b.getblocking() and not fcntl.fcntl(b, fcntl.F_GETFL) & os.O_NONBLOCK
        echo_rounds(srv.ports["http"], 300)
    finally:
        a.close()
        b.close()


def test_stderr_regular_file_is_shared_by_append(bastion, tmp_path):
    # Without O_APPEND on every description, each process would overwrite the others' lines.
    path = tmp_path / "plain.log"
    with open(path, "w") as f:  # O_TRUNC, not O_APPEND, as a shell `2> file` does
        srv = bastion(conf(2), wait=None, error_log=False, stderr=f.fileno(),
                      env=NOISY)
        srv.wait_workers(2)
        echo_rounds(srv.ports["http"], 20)
    text = path.read_text()
    assert len(re.findall(r" worker/\d WARN raw log noise", text)) >= 20 * 64
    for line in text.splitlines():
        assert re.match(r"^\S+Z \d+ \S+ (INFO|WARN|ERROR) ", line), line


def nobody_dir():
    d = Path(tempfile.mkdtemp(dir="/tmp"))
    os.chmod(d, 0o755)
    os.chown(d, 65534, 65534)
    return d


def read_until(fd, needle, timeout):
    """What fd delivers until needle shows up or timeout passes."""
    got = b""
    deadline = time.monotonic() + timeout
    while needle not in got and time.monotonic() < deadline:
        r, _, _ = select.select([fd], [], [], 0.05)
        if r:
            try:
                got += os.read(fd, 1 << 16)
            except OSError:
                break
    return got


def test_foreign_pipe_gets_lines_and_crash_reports(bastion):
    # A gosu or su-exec entrypoint: the process is nobody, its stderr a pipe root made. It cannot
    # reopen that pipe and must not set O_NONBLOCK on a description it shares.
    need_root()
    r, w = os.pipe()
    srv = bastion(conf(1), wait=None, error_log=False, stderr=w, wrap=AS_NOBODY,
                  workdir=nobody_dir(), env=FAST_RESPAWN | {"BST_TEST_WORKER_CRASH": "0:segv"})
    got = read_until(r, b"crash: end", 10)
    assert re.search(rb" worker/0 ERROR crash: signal 11 ", got), got
    assert b"log lines are dropped" not in got
    got += read_until(r, b"killed by signal 11", 10)
    assert re.search(rb" master ERROR worker/0 ", got), got
    srv.proc.terminate()
    srv.proc.wait(10)
    os.close(r)
    os.close(w)


def test_foreign_pipe_full_never_blocks(bastion):
    need_root()
    r, w = os.pipe()
    srv = bastion(conf(2), wait=None, error_log=False, stderr=w, wrap=AS_NOBODY,
                  workdir=nobody_dir(), env=NOISY)
    srv.wait_workers(2)
    echo_rounds(srv.ports["http"], 100)  # nobody reads: far more than the pipe holds
    assert not fcntl.fcntl(w, fcntl.F_GETFL) & os.O_NONBLOCK
    assert srv.proc.poll() is None
    assert b"raw log noise" in read_until(r, b"raw log noise", 5)
    srv.proc.terminate()
    srv.proc.wait(10)
    os.close(r)
    os.close(w)


def test_foreign_pty_says_it_drops_lines(bastion):
    # A pty cannot take a private pipe's splice without risking a block, and this user cannot
    # reopen it. The honest answer: say so once, and serve.
    need_root()
    pm, ps = pty.openpty()
    srv = bastion(conf(1), wait=None, error_log=False, stderr=ps, wrap=AS_NOBODY,
                  workdir=nobody_dir(), env=ECHO)
    assert b"log lines are dropped" in read_until(pm, b"log lines are dropped", 5)
    srv.wait_workers(1)
    echo_rounds(srv.ports["http"], 3)
    srv.proc.terminate()
    srv.proc.wait(10)
    os.close(ps)
    os.close(pm)


def test_error_log_file_is_created_with_private_mode(bastion, tmp_path):
    srv = bastion(conf(1))
    mode = statmod.S_IMODE(os.stat(srv.error_log).st_mode)
    assert mode == 0o640, oct(mode)


def test_sanitizer_report_from_nobody_child_is_kept(bastion, bastion_bin):
    # A child opens its report file before the drop, or a heap error in a worker that dropped to
    # nobody would pass silently. The test takes the report away itself: teardown fails on one.
    need_root()
    if b"__asan_init" not in Path(bastion_bin).read_bytes():
        pytest.skip("not an ASan build")
    srv = bastion(conf(1, "user nobody;"), wait=None,
                  env=FAST_RESPAWN | {"BST_TEST_WORKER_CRASH": "0:heap"})
    deadline = time.monotonic() + 15
    reports = []
    while not reports and time.monotonic() < deadline:
        reports = [r for r in srv.report_dir.glob("sanitizer*") if r.stat().st_size]
        time.sleep(0.05)
    assert reports, srv.logs()
    assert "heap-buffer-overflow" in reports[0].read_text()
    for r in reports:
        r.unlink()
    srv.proc.terminate()
    srv.proc.wait(10)
    for r in srv.report_dir.glob("sanitizer*"):  # more crashes before it stopped
        r.unlink()
