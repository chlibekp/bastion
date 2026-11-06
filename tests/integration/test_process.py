"""Master, workers and helper as real processes, on both backends.

Raw test mode (BST_TEST_RAW_MODE, test builds only) gives workers something to serve until
Phase 4: echo copies bytes back, respond writes a fixed line and closes, slow sends a patterned
body slowly. Processes are told apart by comm (bst:worker/N, bst:helper). Backoff tests scale
real delays down with BST_TEST_RESPAWN_SCALE; the log still states the nominal value."""
import fcntl
import os
import pwd
import re
import grp
import signal
import socket
import stat as statmod
import subprocess
import time
from datetime import datetime
from pathlib import Path

import pytest

ECHO = {"BST_TEST_RAW_MODE": "echo"}
FAST_RESPAWN = {"BST_TEST_RESPAWN_SCALE": "100"}
RESPOND_LINE = b"bastion raw response\n"
BUILD = os.environ.get("BASTION_BUILD", "")


def need_root():
    if os.geteuid() != 0:
        pytest.skip("needs root")


def conf(workers=2, extra=""):
    return f"workers {workers};\n{extra}\nserver {{ listen 127.0.0.1:@HTTP_PORT@; }}\n"


def connect(port, timeout=5):
    s = socket.create_connection(("127.0.0.1", port), timeout)
    s.settimeout(timeout)
    return s


def echo_ok(port, payload=b"ping", timeout=5):
    with connect(port, timeout) as s:
        s.sendall(payload)
        return s.recv(len(payload)) == payload


def status(pid):
    return Path(f"/proc/{pid}/status").read_text()


def field(pid, name):
    return re.search(rf"^{name}:\s*(.*)$", status(pid), re.M).group(1)


def tids(pid):
    return [int(t) for t in os.listdir(f"/proc/{pid}/task")]


def task_field(pid, tid, name):
    text = Path(f"/proc/{pid}/task/{tid}/status").read_text()
    return re.search(rf"^{name}:\s*(.*)$", text, re.M).group(1)


def gone(pid):
    try:
        text = Path(f"/proc/{pid}/stat").read_text()
    except (FileNotFoundError, ProcessLookupError):
        return True
    return text[text.rindex(")") + 2] == "Z"  # reparented to a PID 1 that does not reap


def wait_gone(pids, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if all(gone(p) for p in pids):
            return True
        time.sleep(0.01)
    return False


def stamp(line):
    return datetime.strptime(line.split()[0], "%Y-%m-%dT%H:%M:%S.%fZ").timestamp()


def respawns(text, who="worker/0"):
    """[(crash, backoff_ms, time)] from master's crash lines for one child."""
    out = []
    for line in text.splitlines():
        m = re.search(rf" master ERROR {who} \(pid \d+\) .*; respawn after backoff_ms=(\d+) "
                      r"\(crash (\d+)\)$", line)
        if m:
            out.append((int(m.group(2)), int(m.group(1)), stamp(line)))
    return out


# ---- the process tree ----


def test_worker_count(bastion):
    srv = bastion(conf(4))
    kids = srv.children()
    assert len(kids) == 5, kids
    assert sorted(srv.workers()) == [0, 1, 2, 3]
    assert srv.helper() is not None
    assert srv.proc.poll() is None


def test_log_tags(bastion):
    srv = bastion(conf(2))
    logs = srv.logs()
    for tag in ("master", "worker/0", "worker/1", "helper"):
        assert re.search(rf"^\S+Z \d+ {tag} INFO ", logs, re.M), (tag, logs)


def test_fd_isolation(bastion):
    srv = bastion(conf(3))

    def listeners_of(pid, inodes):
        got = set()
        for fd in os.listdir(f"/proc/{pid}/fd"):
            try:
                link = os.readlink(f"/proc/{pid}/fd/{fd}")
            except OSError:
                continue
            m = re.fullmatch(r"socket:\[(\d+)\]", link)
            if m and m.group(1) in inodes:
                got.add(m.group(1))
        return got

    port = f"{srv.ports['http']:04X}"
    inodes = set()
    for line in Path("/proc/net/tcp").read_text().splitlines()[1:]:
        f = line.split()
        if f[1].endswith(":" + port) and f[3] == "0A":
            inodes.add(f[9])
    assert len(inodes) == 3
    assert listeners_of(srv.proc.pid, inodes) == inodes  # master keeps every queue alive
    held = [listeners_of(pid, inodes) for pid in srv.workers().values()]
    assert all(len(h) == 1 for h in held), held  # a worker holds its own slot only
    assert set().union(*held) == inodes
    assert listeners_of(srv.helper(), inodes) == set()


def test_worker_rlimit_nofile(bastion):
    srv = bastion(conf(1, "worker_rlimit_nofile 4096;"))
    limits = Path(f"/proc/{srv.workers()[0]}/limits").read_text()
    assert re.search(r"^Max open files\s+4096\s+4096", limits, re.M), limits


def test_bind_conflict_is_startup_error(bastion):
    with socket.socket() as busy:
        busy.bind(("127.0.0.1", 0))
        busy.listen(1)
        port = busy.getsockname()[1]
        srv = bastion(f"workers 1;\nserver {{ listen 127.0.0.1:{port}; }}\n", wait=None)
        assert srv.proc.wait(10) == 1
        assert "bind" in srv.stdout() and "127.0.0.1" in srv.stdout()


# ---- raw test mode ----


def test_raw_echo(bastion):
    srv = bastion(conf(2), env=ECHO)
    with connect(srv.ports["http"]) as s:
        for i in range(20):
            data = b"x%d" % i * 100
            s.sendall(data)
            got = b""
            while len(got) < len(data):
                got += s.recv(65536)
            assert got == data


def test_raw_respond(bastion):
    srv = bastion(conf(2), env={"BST_TEST_RAW_MODE": "respond"})
    with connect(srv.ports["http"]) as s:
        got = b""
        while chunk := s.recv(4096):
            got += chunk
    assert got == RESPOND_LINE


def slow_env(total=4 << 20, chunk=64 << 10, interval_ms=10):
    return {"BST_TEST_RAW_MODE": "slow", "BST_TEST_RAW_SLOW": f"{total}:{chunk}:{interval_ms}"}


def read_pattern(s, total):
    got = 0
    while got < total:
        chunk = s.recv(1 << 20)
        if not chunk:
            break
        for i in range(0, len(chunk), 4093):
            assert chunk[i] == (got + i) % 251, (got, i)
        got += len(chunk)
    return got


def test_raw_slow(bastion):
    srv = bastion(conf(1), env=slow_env(256 << 10, 64 << 10, 5))
    with connect(srv.ports["http"]) as s:
        assert read_pattern(s, 256 << 10) == 256 << 10
        assert s.recv(1) == b""


# ---- crashes and respawn ----


def test_worker_crash_respawn(bastion):
    srv = bastion(conf(4), env=ECHO)
    before = srv.workers()
    helper = srv.helper()
    victim = 2
    t0 = time.monotonic()
    os.kill(before[victim], signal.SIGKILL)
    after = srv.wait_for(lambda: (lambda w: w if w.get(victim, before[victim]) != before[victim]
                                  and len(w) == 4 else None)(srv.workers()),
                         timeout=1, what="replacement within 1s")
    assert time.monotonic() - t0 < 1
    for slot in (0, 1, 3):
        assert after[slot] == before[slot]  # the others never restarted
    assert srv.helper() == helper
    for _ in range(40):
        assert echo_ok(srv.ports["http"])  # every slot answers, the new one too
    srv.wait_log(rf"master ERROR worker/2 \(pid {before[victim]}\) killed by signal 9; "
                 r"respawn after backoff_ms=0 \(crash 1\)$")


def test_connections_survive_sibling_crash(bastion):
    srv = bastion(conf(3), env=ECHO)
    conns = [connect(srv.ports["http"]) for _ in range(30)]
    for s in conns:
        s.sendall(b"a")
        assert s.recv(1) == b"a"
    os.kill(srv.workers()[1], signal.SIGKILL)
    alive = 0
    for s in conns:
        try:
            s.sendall(b"b")
            alive += s.recv(1) == b"b"
        except OSError:
            pass
        s.close()
    assert 0 < alive < 30, alive  # the victim's are gone, the others carry on


def test_queue_survives_worker_death(bastion):
    # Master holds the socket: a connection queued on a slot with no worker is served by the
    # replacement, not reset.
    srv = bastion(conf(1), env=ECHO | {"BST_TEST_RESPAWN_SCALE": "1"})
    w = srv.workers()[0]
    os.kill(w, signal.SIGSTOP)
    s = connect(srv.ports["http"])  # queued: the worker is stopped
    s.sendall(b"queued")
    os.kill(w, signal.SIGKILL)
    assert s.recv(6) == b"queued"
    s.close()


def test_respawn_loses_no_wakeup(bastion):
    # A dead worker's ring is torn down after the process is gone, and until then its multishot
    # accept sits on the socket as an exclusive waiter: a connection in that window wakes it
    # instead of the replacement's. Nothing may hang on that. One worker, so every connection
    # lands on the slot being replaced.
    srv = bastion(conf(1), env=ECHO | FAST_RESPAWN)
    for _ in range(8):
        os.kill(srv.workers()[0], signal.SIGKILL)
        conns = []
        for _ in range(25):
            s = connect(srv.ports["http"], 3)
            conns.append(s)
            try:
                s.sendall(b"x")
            except OSError:
                pass
        for s in conns:
            try:
                assert s.recv(1) == b"x"
            except ConnectionError:
                pass  # taken by the dying worker: that one is lost, and the client knows
            s.close()
        srv.wait_workers(1)
        srv.wait_for(lambda: echo_ok(srv.ports["http"]), what="a live worker")


def test_crash_loop_backoff(bastion):
    srv = bastion(conf(2), env=FAST_RESPAWN | ECHO | {"BST_TEST_WORKER_CRASH": "0:abort"},
                  wait=None)
    srv.wait_for(lambda: len(respawns(srv.logs())) >= 11, timeout=30, what="11 crashes")
    seen = respawns(srv.logs())
    assert [c for c, _, _ in seen[:11]] == list(range(1, 12))
    assert [b for _, b, _ in seen[:11]] == [0, 250, 500, 1000, 2000, 4000, 8000, 16000, 30000,
                                            30000, 30000]  # capped at 30 s
    # The delays really happen: a scaled 30 s is 300 ms between the capped crashes.
    assert seen[10][2] - seen[9][2] >= 0.29
    assert seen[6][2] - seen[5][2] >= 0.03
    # A slot in backoff is named at error level, with what it means for its connections.
    assert re.search(r"master ERROR slot 0 has no worker for backoff_ms=30000: connections "
                     r"hashing to it wait in its accept queue$", srv.logs(), re.M), srv.logs()
    srv.wait_for(lambda: 1 in srv.workers(), what="worker 1")
    w = srv.workers()[1]
    assert srv.proc.poll() is None
    assert srv.workers().get(1) == w  # the other slot never restarted


def test_backoff_delay_is_real(bastion):
    srv = bastion(conf(1), env={"BST_TEST_WORKER_CRASH": "0:abort"}, wait=None)
    srv.wait_for(lambda: len(respawns(srv.logs())) >= 3, timeout=10, what="3 crashes")
    seen = respawns(srv.logs())
    assert seen[1][1] == 250 and seen[2][1] == 500
    assert seen[2][2] - seen[1][2] >= 0.24


def test_backoff_resets_after_stable_run(bastion):
    srv = bastion(conf(1), env=ECHO | FAST_RESPAWN | {"BST_TEST_RESPAWN_STABLE_MS": "500"})
    os.kill(srv.workers()[0], signal.SIGKILL)  # crash 1: immediate
    srv.wait_for(lambda: len(respawns(srv.logs())) == 1, what="crash 1")
    first = srv.wait_workers(1)[0]
    os.kill(first, signal.SIGKILL)  # crash 2, straight away: backed off
    srv.wait_for(lambda: len(respawns(srv.logs())) == 2, what="crash 2")
    assert respawns(srv.logs())[1][:2] == (2, 250)
    srv.wait_for(lambda: srv.workers().get(0) not in (None, first), what="respawn")
    time.sleep(0.7)  # past the stable-run time
    os.kill(srv.workers()[0], signal.SIGKILL)
    srv.wait_for(lambda: len(respawns(srv.logs())) == 3, what="crash 3")
    assert respawns(srv.logs())[2][:2] == (1, 0)  # counted from one again, respawned at once


def test_helper_crash_respawn(bastion):
    srv = bastion(conf(2), env=ECHO)
    workers = srv.workers()
    old = srv.helper()
    t0 = time.monotonic()
    os.kill(old, signal.SIGKILL)
    srv.wait_for(lambda: srv.helper() not in (None, old), timeout=1, what="new helper in 1s")
    assert time.monotonic() - t0 < 1
    assert srv.workers() == workers  # a helper crash does not touch workers
    assert echo_ok(srv.ports["http"])
    srv.wait_log(rf"master ERROR helper \(pid {old}\) killed by signal 9; respawn after "
                 r"backoff_ms=0 \(crash 1\)$")


def test_helper_crash_loop_backoff(bastion):
    srv = bastion(conf(2), env=ECHO | FAST_RESPAWN | {"BST_TEST_WORKER_CRASH": "helper:abort"})
    srv.wait_for(lambda: len(respawns(srv.logs(), "helper")) >= 9, timeout=30, what="9 crashes")
    assert [b for _, b, _ in respawns(srv.logs(), "helper")[:9]] == \
        [0, 250, 500, 1000, 2000, 4000, 8000, 16000, 30000]
    assert echo_ok(srv.ports["http"])  # workers serve throughout


def test_no_zombies(bastion):
    srv = bastion(conf(3), env=ECHO | FAST_RESPAWN)
    kills = 0
    while kills < 12:
        # Several at once: SIGCHLD coalesces, so one wakeup must reap them all.
        for pid in srv.wait_workers(3, timeout=20).values():
            os.kill(pid, signal.SIGKILL)
            kills += 1
    srv.wait_workers(3, timeout=20)
    srv.wait_for(lambda: len(srv.children()) == 4, what="exactly 4 children")
    time.sleep(0.2)
    assert all(state != "Z" for _, state in srv.children().values()), srv.children()
    assert len(re.findall(r"killed by signal 9", srv.logs())) >= 10


# ---- stopping ----


def test_graceful_stop(bastion):
    total = 8 << 20
    srv = bastion(conf(2), env=slow_env(total, 64 << 10, 5))
    workers = list(srv.workers().values())
    with connect(srv.ports["http"], 20) as s:
        got = s.recv(1024)
        assert got
        for i, b in enumerate(got):
            assert b == i % 251
        srv.proc.send_signal(signal.SIGQUIT)
        t0 = time.monotonic()
        rest = read_pattern_from(s, len(got), total)
        assert rest == total  # the transfer in flight finished
        assert s.recv(1) == b""
    assert srv.proc.wait(10) == 0
    assert time.monotonic() - t0 > 0.1  # it really waited for the transfer
    assert wait_gone(workers)
    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", srv.ports["http"]), 1)
    assert not re.search(r"\bERROR\b", srv.logs()), srv.logs()


def read_pattern_from(s, start, total):
    got = start
    while got < total:
        chunk = s.recv(1 << 20)
        if not chunk:
            break
        for i in range(0, len(chunk), 4093):
            assert chunk[i] == (got + i) % 251
        got += len(chunk)
    return got


def test_graceful_stop_serves_queued_connections(bastion):
    # Connections the kernel already completed are accepted before the listener goes.
    srv = bastion(conf(1), env={"BST_TEST_RAW_MODE": "respond"})
    w = srv.workers()[0]
    os.kill(w, signal.SIGSTOP)
    # More than one wakeup's accept budget, so some are still queued when the worker gets to
    # stopping its listener, and must be taken then.
    conns = [connect(srv.ports["http"], 20) for _ in range(400)]
    srv.proc.send_signal(signal.SIGQUIT)
    srv.wait_log(r"master INFO graceful stop")
    os.kill(w, signal.SIGCONT)
    for s in conns:
        got = b""
        while chunk := s.recv(4096):
            got += chunk
        assert got == RESPOND_LINE
        s.close()
    assert srv.proc.wait(10) == 0


def stuck_client(port):
    """Connected, past accept, and never reading: the worker's send can not finish."""
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    s.connect(("127.0.0.1", port))
    s.settimeout(5)
    assert s.recv(1)
    return s


def test_shutdown_timeout(bastion):
    srv = bastion(conf(2, "shutdown_timeout 1s;"), env=slow_env(1 << 30, 1 << 20, 1))
    workers = list(srv.workers().values())
    with stuck_client(srv.ports["http"]):
        time.sleep(0.2)
        t0 = time.monotonic()
        srv.proc.send_signal(signal.SIGQUIT)
        assert srv.proc.wait(10) == 0
        took = time.monotonic() - t0
    assert 0.9 <= took < 5, took
    assert wait_gone(workers)
    srv.wait_log(r"master WARN shutdown_timeout reached: killing worker/\d+ \(pid \d+\) "
                 r"with 1 connections$")


@pytest.mark.parametrize("sig", [signal.SIGTERM, signal.SIGINT])
def test_fast_stop(bastion, sig):
    total = 1 << 30
    srv = bastion(conf(2), env=slow_env(total, 1 << 20, 1))
    workers = list(srv.workers().values())
    helper = srv.helper()
    with connect(srv.ports["http"], 10) as s:
        s.recv(1024)
        t0 = time.monotonic()
        srv.proc.send_signal(sig)
        assert srv.proc.wait(10) == 0
        assert time.monotonic() - t0 < 3
        with pytest.raises(OSError):
            while s.recv(1 << 20):
                pass
            raise ConnectionError("eof")  # cut short either way: not 1 GiB of data
    assert wait_gone(workers + [helper])


def test_term_during_graceful_stop_goes_fast(bastion):
    srv = bastion(conf(1), env=slow_env(1 << 30, 1 << 20, 1))
    with stuck_client(srv.ports["http"]):
        srv.proc.send_signal(signal.SIGQUIT)
        srv.wait_log(r"master INFO graceful stop")
        t0 = time.monotonic()
        srv.proc.send_signal(signal.SIGTERM)
        assert srv.proc.wait(10) == 0
        assert time.monotonic() - t0 < 3


@pytest.mark.parametrize("sig", [signal.SIGHUP, signal.SIGUSR2])
def test_reload_signals_are_logged_and_ignored(bastion, sig):
    srv = bastion(conf(2), env=ECHO)
    workers = srv.workers()
    srv.proc.send_signal(sig)
    srv.wait_log(rf"master WARN signal {int(sig)} ignored: reload and upgrade arrive in Phase 14")
    assert srv.workers() == workers and srv.proc.poll() is None
    assert echo_ok(srv.ports["http"])


# ---- master death ----


@pytest.mark.parametrize("env", [{}, {"BST_TEST_NO_PDEATHSIG": "1"},
                                 {"BST_TEST_NO_CHANNEL_EOF": "1"}],
                         ids=["both", "channel_eof_alone", "pdeathsig_alone"])
def test_master_death(bastion, env):
    srv = bastion(conf(3), env=ECHO | env)
    kids = list(srv.children())
    assert len(kids) == 4
    srv.proc.kill()
    srv.proc.wait(5)
    assert wait_gone(kids), [p for p in kids if not gone(p)]


def test_channel_eof_is_not_hidden_by_a_sibling(bastion):
    # Slot 0 forks last, so it would inherit master's end of every other channel if a child did
    # not close them. Stopped, it could not exit either, and nobody else would ever see EOF.
    srv = bastion(conf(3), env=ECHO | {"BST_TEST_NO_PDEATHSIG": "1"})
    workers = srv.workers()
    os.kill(workers[0], signal.SIGSTOP)
    others = [workers[1], workers[2], srv.helper()]
    srv.proc.kill()
    srv.proc.wait(5)
    try:
        assert wait_gone(others, 3), [p for p in others if not gone(p)]
    finally:
        os.kill(workers[0], signal.SIGKILL)


def test_pdeathsig_survives_the_privilege_drop(bastion):
    # Changing user clears PDEATHSIG, which is why it is set after the drop.
    need_root()
    srv = bastion(conf(2, "user nobody;"), env=ECHO | {"BST_TEST_NO_CHANNEL_EOF": "1"})
    kids = list(srv.children())
    srv.proc.kill()
    srv.proc.wait(5)
    assert wait_gone(kids), [p for p in kids if not gone(p)]


def test_master_dies_before_pdeathsig_is_set(bastion):
    # The window the getppid recheck closes: the parent is gone before prctl, so no signal ever
    # comes. The channel is out of the picture too.
    srv = bastion(conf(1), wait=None, env={"BST_TEST_NO_CHANNEL_EOF": "1",
                                           "BST_TEST_WORKER_WATCH_DELAY_MS": "1500"})
    w = srv.wait_workers(1)[0]
    time.sleep(0.2)
    srv.proc.kill()
    srv.proc.wait(5)
    assert wait_gone([w], 5)
    assert re.search(r"worker/0 \S+ master is gone", srv.logs()), srv.logs()


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
    srv = bastion(conf(2, "io { backend uring; }"), wait=None,
                  env={"BST_TEST_WORKER_URING_FAIL": "helper:setup:1"})
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


def test_error_log_file_is_created_with_private_mode(bastion, tmp_path):
    srv = bastion(conf(1))
    mode = statmod.S_IMODE(os.stat(srv.error_log).st_mode)
    assert mode == 0o640, oct(mode)


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
