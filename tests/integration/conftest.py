"""Fixtures for integration tests against a real bastion process."""
import os
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
    def __init__(self, proc, ports, workdir, error_log):
        self.proc = proc
        self.ports = ports
        self.workdir = workdir
        self.error_log = error_log

    def logs(self):
        try:
            return Path(self.error_log).read_text()
        except FileNotFoundError:
            return ""


@pytest.fixture(params=BACKENDS)
def backend(request):
    return request.param


@pytest.fixture
def bastion(bastion_bin, backend, tmp_path):
    """Factory: bastion(config_text, backend=None) starts a server and returns a Server.

    The config may contain @HTTP_PORT@, @HTTPS_PORT@, @QUIC_PORT@, @ADMIN_PORT@ and
    @WORKDIR@, replaced with free loopback ports and a scratch directory. If the text
    has no `io {` block, one selecting the backend is appended. Tests are parametrized
    over both backends; passing backend= pins one. All servers are stopped at teardown.
    A server exists only from Phase 3; until then only --version is exercised.
    """
    started = []

    def start(config_text, backend=backend):
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
                .replace("@WORKDIR@", str(tmp_path)))
        if "io {" not in text:
            text += f"\nio {{ backend {backend}; }}\n"
        conf = tmp_path / "bastion.conf"
        conf.write_text(text)
        err = tmp_path / "error.log"
        out = open(tmp_path / "stdout.log", "w")
        proc = subprocess.Popen([bastion_bin, "-c", str(conf)], stdout=out,
                                stderr=subprocess.STDOUT, cwd=tmp_path)
        srv = Server(proc, ports, tmp_path, err)
        started.append(srv)
        deadline = time.time() + 10
        while time.time() < deadline:
            if proc.poll() is not None:
                pytest.fail(f"bastion exited early ({proc.returncode}):\n"
                            + (tmp_path / "stdout.log").read_text())
            try:
                socket.create_connection(("127.0.0.1", ports["http"]), 0.2).close()
                return srv
            except OSError:
                time.sleep(0.05)
        pytest.fail("bastion did not start listening within 10s")

    yield start
    for srv in started:
        if srv.proc.poll() is None:
            srv.proc.terminate()
            try:
                srv.proc.wait(5)
            except subprocess.TimeoutExpired:
                srv.proc.kill()
