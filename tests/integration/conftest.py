"""Fixtures for integration tests against a real bastion process."""
import os
import re
import socket
import subprocess
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
BACKENDS = ["uring", "epoll"]


def pytest_configure(config):
    # Tests that pin behaviour a later phase replaces: they carry one of these markers so the
    # phase that registers the directive can find and rewrite them (see the plan amendments).
    config.addinivalue_line("markers", "until_phase5: pins `root` as unknown; rewrite in Phase 5")
    config.addinivalue_line("markers", "until_phase9: pins `proxy` as unknown; rewrite in Phase 9")


def _find_binary():
    env = os.environ.get("BASTION_BIN")
    if env:
        return Path(env)
    for build in ("asan", "debug", "release"):
        p = ROOT / "build" / build / "bastion"
        if p.exists():
            return p
    pytest.fail("bastion binary not found; run `make` or set BASTION_BIN")


def _free_port(kind):
    with socket.socket(socket.AF_INET, kind) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def bastion_bin():
    return str(_find_binary())


class Server:
    """A running bastion: its master process, ports, scratch directory and logs."""

    def __init__(self, proc, ports, workdir, error_log, stdout_log):
        self.proc = proc
        self.ports = ports
        self.workdir = workdir
        self.error_log = error_log
        self.stdout_log = stdout_log

    def logs(self):
        try:
            return Path(self.error_log).read_text()
        except FileNotFoundError:
            return ""

    def stdout(self):
        return Path(self.stdout_log).read_text()

    def children(self):
        """{pid: (comm, state)} of the master's direct children, zombies included."""
        return {pid: (comm, state) for pid, comm, state, ppid in _processes()
                if ppid == self.proc.pid}

    def workers(self):
        """{slot: pid} of live workers."""
        out = {}
        for pid, (comm, state) in self.children().items():
            if comm.startswith("bst:worker/") and state != "Z":
                out[int(comm.split("/")[1])] = pid
        return out

    def helper(self):
        for pid, (comm, state) in self.children().items():
            if comm == "bst:helper" and state != "Z":
                return pid
        return None

    def wait_for(self, predicate, timeout=10, what="condition"):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = predicate()
            if value:
                return value
            time.sleep(0.01)
        pytest.fail(f"timed out after {timeout}s waiting for {what}\n--- log ---\n{self.logs()}"
                    f"\n--- stdout ---\n{self.stdout()}")

    def wait_log(self, pattern, timeout=10):
        return self.wait_for(lambda: re.search(pattern, self.logs(), re.M), timeout,
                             f"log line {pattern!r}")

    def wait_workers(self, n, timeout=10):
        return self.wait_for(lambda: (lambda w: w if len(w) == n else None)(self.workers()),
                             timeout, f"{n} workers")


def _processes():
    """(pid, comm, state, ppid) of every process, from /proc (no `ps` dependency)."""
    out = []
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        try:
            stat = Path(f"/proc/{name}/stat").read_bytes().decode("utf-8", "replace")
        except OSError:
            continue
        rest = stat[stat.rindex(")") + 2:].split()
        out.append((int(name), stat[stat.index("(") + 1:stat.rindex(")")], rest[0], int(rest[1])))
    return out


@pytest.fixture(params=BACKENDS)
def backend(request):
    return request.param


@pytest.fixture
def bastion(bastion_bin, backend, tmp_path):
    """Factory: bastion(config_text, backend=None, env=None, wait="ready", error_log=True,
    stderr=None) starts a server and returns a Server.

    The config may contain @HTTP_PORT@, @HTTPS_PORT@, @QUIC_PORT@, @ADMIN_PORT@ and
    @WORKDIR@, replaced with free loopback ports and a scratch directory. If the text has no
    `io {` block, one selecting the backend is appended, and without `error_log` (unless
    error_log=False) one at info level is, so tests read the log with Server.logs().

    Listening proves nothing here: master holds every socket, so the port accepts before any
    worker runs. wait="ready" waits for master's `ready:` line. wait=None returns as soon as
    the process exists (crash loops, startup failures). env adds to the environment; stderr
    is an fd to use instead of the stdout log. Tests are parametrized over both backends;
    backend= pins one. Every server is stopped at teardown, and a child that outlives its
    master fails the test.
    """
    started = []

    def start(config_text, backend=backend, env=None, wait="ready", error_log=True, stderr=None):
        workdir = tmp_path if not started else tmp_path / f"s{len(started)}"
        workdir.mkdir(exist_ok=True)
        ports = {
            "http": _free_port(socket.SOCK_STREAM),
            "https": _free_port(socket.SOCK_STREAM),
            "admin": _free_port(socket.SOCK_STREAM),
            "quic": _free_port(socket.SOCK_DGRAM),
        }
        text = (config_text.replace("@HTTP_PORT@", str(ports["http"]))
                .replace("@HTTPS_PORT@", str(ports["https"]))
                .replace("@QUIC_PORT@", str(ports["quic"]))
                .replace("@ADMIN_PORT@", str(ports["admin"]))
                .replace("@WORKDIR@", str(workdir)))
        if "io {" not in text:
            text += f"\nio {{ backend {backend}; }}\n"
        err = workdir / "error.log"
        if error_log and "error_log" not in text:
            text += f"\nerror_log {err} info;\n"
        conf = workdir / "bastion.conf"
        conf.write_text(text)
        stdout_log = workdir / "stdout.log"
        full_env = {k: v for k, v in os.environ.items() if not k.startswith("BST_TEST_")}
        full_env.update(env or {})
        with open(stdout_log, "w") as out:
            proc = subprocess.Popen([bastion_bin, "-c", str(conf)], stdout=out,
                                    stderr=stderr if stderr is not None else subprocess.STDOUT,
                                    cwd=workdir, env=full_env)
        srv = Server(proc, ports, workdir, err, stdout_log)
        started.append(srv)
        if wait == "ready":
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                if proc.poll() is not None:
                    pytest.fail(f"bastion exited early ({proc.returncode}):\n{srv.stdout()}"
                                f"\n--- log ---\n{srv.logs()}")
                if re.search(r" master INFO ready: ", srv.logs()):
                    return srv
                time.sleep(0.01)
            pytest.fail(f"bastion not ready within 20s\n{srv.logs()}\n{srv.stdout()}")
        return srv

    yield start
    for srv in started:
        kids = list(srv.children())
        if srv.proc.poll() is None:
            srv.proc.terminate()
            try:
                srv.proc.wait(10)
            except subprocess.TimeoutExpired:
                srv.proc.kill()
                srv.proc.wait(10)
        deadline = time.monotonic() + 5
        alive = list(kids)
        while alive and time.monotonic() < deadline:
            alive = [p for p, _, state, _ in _processes() if p in kids and state != "Z"]
            time.sleep(0.01)
        for pid in alive:
            os.kill(pid, 9)
        assert not alive, f"children outlived the master: {alive}\n{srv.logs()}"
