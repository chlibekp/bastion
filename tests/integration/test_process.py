"""Master, workers and helper as real processes, on both backends: the process tree, respawn, stopping and master death.

Raw test mode (BST_TEST_RAW_MODE, test builds only) gives workers something to serve until
Phase 4: echo copies bytes back, respond writes a fixed line and closes, slow sends a patterned
body slowly. Processes are told apart by comm (bst:worker/N, bst:helper). Backoff tests scale
real delays down with BST_TEST_RESPAWN_SCALE; the log still states the nominal value."""
import os
import re
import signal
import socket
import time
from pathlib import Path

import pytest

from process_util import *  # noqa: F401,F403


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


def test_queue_survives_worker_death(bastion, backend):
    # Master holds the socket: a connection queued on a slot with no worker is served by the
    # replacement, not reset.
    srv = bastion(conf(1), env=ECHO | {"BST_TEST_RESPAWN_SCALE": "1"})
    w = srv.workers()[0]
    os.kill(w, signal.SIGSTOP)
    s = connect(srv.ports["http"])  # queued: the worker is stopped
    s.sendall(b"queued")
    os.kill(w, signal.SIGKILL)
    try:
        assert s.recv(6) == b"queued"
    except ConnectionError:
        # io_uring only. The dying worker's multishot accept is still armed, and SIGKILL does
        # not stop the kernel running it, so it can take this connection and lose it with the
        # process. What is still queued survives; what it took does not. epoll has no accept
        # that runs by itself, so there a reset is a real loss.
        assert backend == "uring"
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


def test_replacement_exiting_78_is_a_crash(bastion):
    # 78 ends a startup. On a running server the others are serving, so it must not end them.
    flag = "/tmp/bst-exit78-%d" % os.getpid()
    srv = bastion(conf(2), env=ECHO | FAST_RESPAWN | {"BST_TEST_WORKER_EXIT78": flag})
    other = srv.workers()[1]
    Path(flag).touch()
    victim = srv.workers()[0]
    os.kill(victim, signal.SIGKILL)
    srv.wait_log(r"master ERROR worker/0 \(pid \d+\) exited with status 78; respawn after")
    srv.wait_for(lambda: srv.workers().get(0) not in (None, victim), what="the slot back")
    assert not Path(flag).exists()
    srv.wait_for(lambda: len(re.findall(r"master INFO worker/0 ready$", srv.logs(), re.M)) >= 2,
                 what="the slot ready again")
    assert srv.proc.poll() is None and srv.workers()[1] == other


def test_startup_deadline_ends_the_startup_window(bastion):
    # A slot crash looping from the start must not keep the server in "starting" for ever, where
    # a later 78 would end a server that is serving on its other slots.
    flag = "/tmp/bst-exit78-d-%d" % os.getpid()
    srv = bastion(conf(2), wait=None,
                  env=ECHO | FAST_RESPAWN | {"BST_TEST_WORKER_CRASH": "0:abort",
                                             "BST_TEST_STARTUP_DEADLINE_MS": "300",
                                             "BST_TEST_WORKER_EXIT78": flag})
    srv.wait_log(r"master ERROR startup deadline passed: worker/0 is not ready$")
    srv.wait_log(r"master INFO worker/1 ready$")
    Path(flag).touch()
    srv.wait_log(r"master ERROR worker/0 \(pid \d+\) exited with status 78; respawn after")
    assert srv.proc.poll() is None
    assert "startup failed" not in srv.logs()


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
    srv = bastion(conf(2), env=ECHO | FAST_RESPAWN | {"BST_TEST_WORKER_CRASH": "helper:abort"},
                  wait=None)
    srv.wait_log(r"master INFO worker/1 ready$")
    srv.wait_for(lambda: len(respawns(srv.logs(), "helper")) >= 9, timeout=30, what="9 crashes")
    assert [b for _, b, _ in respawns(srv.logs(), "helper")[:9]] == \
        [0, 250, 500, 1000, 2000, 4000, 8000, 16000, 30000]
    assert echo_ok(srv.ports["http"])  # workers serve throughout


def test_no_zombies(bastion):
    srv = bastion(conf(3), env=ECHO | FAST_RESPAWN)
    killed = set()

    def fresh():  # all three slots live, and none is a process already killed and still dying
        w = srv.workers()
        return w if len(w) == 3 and not set(w.values()) & killed else None

    while len(killed) < 12:
        # Several at once: SIGCHLD coalesces, so one wakeup must reap them all.
        for pid in srv.wait_for(fresh, timeout=20, what="three new workers").values():
            os.kill(pid, signal.SIGKILL)
            killed.add(pid)
    srv.wait_for(fresh, timeout=20, what="three new workers")
    srv.wait_for(lambda: len(srv.children()) == 4, what="exactly 4 children")
    time.sleep(0.2)
    assert all(state != "Z" for _, state in srv.children().values()), srv.children()
    assert len(re.findall(r"killed by signal 9", srv.logs())) == len(killed)


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
