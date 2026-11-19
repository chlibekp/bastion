"""Live binary upgrade (src/proc/upgrade.h): USR2 starts the binary installed at master's path as
a second master beside the old one, WINCH drains the old workers, QUIT commits and HUP rolls
back. `bastionctl upgrade` drives the sequence. Each test runs the server from a private copy of
the binary, so it can install another one (a broken build, a script) at the same path, as an
operator would, without touching the build tree."""
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import time

import pytest

import quic_util
from conftest import _processes
from test_reload import Load, conf, get, session_reused, www  # noqa: F401  (www: fixture)
from upstream_util import Upstream
from xdp_util import net, pin  # noqa: F401  (fixtures)

PID = "pid @WORKDIR@/bastion.pid;"


def state(pid):
    """The /proc state letter of pid, None when it is gone."""
    try:
        text = open(f"/proc/{pid}/stat").read()
    except (FileNotFoundError, ProcessLookupError):
        return None
    return text[text.rindex(")") + 2]


def alive(pid):
    return state(pid) not in (None, "Z")


def read_pid(path):
    try:
        text = path.read_text().strip()
    except FileNotFoundError:
        return None
    return int(text) if text else 0


def wait(pred, timeout, what):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        v = pred()
        if v:
            return v
        time.sleep(0.02)
    pytest.fail(f"timed out waiting for {what}")


class Installed:
    def __init__(self, d, bastion_bin):
        self.dir, self.real = d, bastion_bin
        self.exe = d / "bastion"
        shutil.copy2(bastion_bin, self.exe)
        self.exe.chmod(0o755)
        self.ctl = d / "bastionctl"  # same binary, chosen by argv[0]
        self.ctl.symlink_to(bastion_bin)
        self.masters = []

    def install(self, text, mode=0o755):
        """Replaces the binary at master's path, as a package upgrade would (rename over it)."""
        tmp = self.dir / "bastion.new"
        tmp.write_text(text)
        tmp.chmod(mode)
        os.replace(tmp, self.exe)

    def run_ctl(self, *args, timeout=120):
        return subprocess.run([str(self.ctl), "upgrade", *map(str, args)], capture_output=True,
                              text=True, timeout=timeout)


def stop_master(pid):
    if not alive(pid):
        return
    kids = [p for p, _, _, ppid in _processes() if ppid == pid]
    os.kill(pid, signal.SIGTERM)
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline and (alive(pid) or any(alive(k) for k in kids)):
        time.sleep(0.02)
    for p in [pid, *kids]:
        if alive(p):
            os.kill(p, signal.SIGKILL)


@pytest.fixture
def up(bastion_bin, tmp_path):
    """A private install directory (owner only, as the upgrade checks require); every new
    master a test starts is stopped at teardown (it is not the fixture's process)."""
    d = tmp_path / "bin"
    d.mkdir(mode=0o700)
    u = Installed(d, bastion_bin)
    yield u
    for pid in u.masters:
        stop_master(pid)


def begin(srv, u):
    """USR2, then the new master's PID once it is ready (the PID file names it)."""
    pidf = srv.workdir / "bastion.pid"
    old = srv.proc.pid
    srv.proc.send_signal(signal.SIGUSR2)
    new = wait(lambda: (lambda p: p if p and p != old else None)(read_pid(pidf)), 30,
               "the new master in the PID file")
    u.masters.append(new)
    assert read_pid(srv.workdir / "bastion.pid.oldbin") == old
    return new


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_upgrade_happy(bastion, certs, www, up):  # noqa: F811
    """bastionctl upgrade under load: the new master takes over, the old one exits, the PID file
    names the new one, and no request fails."""
    srv = bastion(conf(certs, www, glob=PID), binary=up.exe)
    pidf, old = srv.workdir / "bastion.pid", srv.proc.pid
    assert read_pid(pidf) == old
    with Load(srv) as load:
        r = up.run_ctl("-p", pidf, "--timeout", 30)
        new = read_pid(pidf)
        if new and new != old:
            up.masters.append(new)
        time.sleep(0.5)  # served by the new master alone for a while
    assert r.returncode == 0, f"{r.stdout}{r.stderr}\n{srv.logs()[-4000:]}"
    assert f"upgraded: master pid {old} -> {new}" in r.stdout
    assert srv.proc.wait(30) == 0
    assert alive(new) and read_pid(pidf) == new
    assert not (srv.workdir / "bastion.pid.oldbin").exists()
    assert load.fail == [], f"{load.fail[:5]}\n{srv.logs()[-6000:]}"
    if "routing by connection ID" in srv.logs():
        assert load.h3_fail == [], load.h3_fail[:3]
    assert load.ok > 50
    assert get(srv.ports["http"]).startswith(b"HTTP/1.1 200")
    logs = srv.logs()
    assert "upgrade: new master ready" in logs and "upgrade: committed" in logs, logs[-3000:]


def test_upgrade_rollback(bastion, certs, www, up):  # noqa: F811
    """HUP after WINCH and before QUIT: the old master starts its workers again, takes the PID
    file back, and the new master exits; requests keep succeeding throughout."""
    srv = bastion(conf(certs, www, glob=PID), binary=up.exe)
    pidf, old = srv.workdir / "bastion.pid", srv.proc.pid
    with Load(srv, h3=False) as load:
        new = begin(srv, up)
        srv.proc.send_signal(signal.SIGWINCH)
        wait(lambda: len(re.findall(r"drained for the upgrade", srv.logs())) == 2, 20,
             "the old workers drained")
        assert srv.workers() == {}
        time.sleep(0.3)  # the new master serves alone
        srv.proc.send_signal(signal.SIGHUP)
        srv.wait_log(r"upgrade: rolled back: new master \(pid \d+\) exited", timeout=30)
        srv.wait_workers(2)
        time.sleep(0.3)
    assert not alive(new)
    assert srv.proc.poll() is None
    assert read_pid(pidf) == old and not (srv.workdir / "bastion.pid.oldbin").exists()
    assert load.fail == [], load.fail[:5]
    assert get(srv.ports["http"]).startswith(b"HTTP/1.1 200")


def test_ctl_rolls_back(bastion, certs, www, up):  # noqa: F811
    """bastionctl rolls back by itself when the health check fails."""
    srv = bastion(conf(certs, www, glob=PID), binary=up.exe)
    pidf, old = srv.workdir / "bastion.pid", srv.proc.pid
    r = up.run_ctl("-p", pidf, "--timeout", 30, "--check", f"127.0.0.1:{free_port()}")
    assert r.returncode == 1, r.stdout + r.stderr
    assert "no connection" in r.stderr and f"rolled back: master pid {old}" in r.stderr, r.stderr
    srv.wait_log(r"upgrade: rolled back: new master", timeout=30)
    assert srv.proc.poll() is None and read_pid(pidf) == old
    assert get(srv.ports["http"]).startswith(b"HTTP/1.1 200")
    news = [int(m) for m in re.findall(r"upgrade: new master started, pid (\d+)", srv.logs())]
    assert len(news) == 1 and not alive(news[0])


def test_bad_binary(bastion, certs, www, up):  # noqa: F811
    """A binary that fails its config check, one that crashes at start and one that others may
    write: the old master refuses or survives it, reports why, and keeps serving."""
    srv = bastion(conf(certs, www, glob=PID), binary=up.exe)
    pidf, old = srv.workdir / "bastion.pid", srv.proc.pid
    p = srv.ports["http"]

    up.install("#!/bin/sh\necho 'broken build: bad config' >&2\nexit 1\n")
    r = up.run_ctl("-p", pidf, "--timeout", 3)
    assert r.returncode == 1 and "refused" in r.stderr, r.stderr
    srv.wait_log(r"upgrade refused, still serving with this binary: .*broken build")

    up.install("#!/bin/sh\nfor a in \"$@\"; do [ \"$a\" = -t ] && exec "
               f"{up.real} \"$@\"; done\nkill -SEGV $$\n")
    srv.proc.send_signal(signal.SIGUSR2)
    srv.wait_log(r"upgrade failed: new master \(pid \d+\) was killed by signal 11; still serving",
                 timeout=30)

    up.install("#!/bin/sh\nexit 0\n", mode=0o775)  # group-writable: never run
    srv.proc.send_signal(signal.SIGUSR2)
    srv.wait_log(r"upgrade refused, .*writable by no one else")

    assert srv.proc.poll() is None and read_pid(pidf) == old
    assert not (srv.workdir / "bastion.pid.oldbin").exists()
    assert len(srv.workers()) == 2
    assert get(p).startswith(b"HTTP/1.1 200")


def test_state_version_mismatch(bastion, certs, www, up):  # noqa: F811
    """A new binary that reads another state format refuses the hand-over before it touches
    anything; the old master reports it and keeps serving."""
    srv = bastion(conf(certs, www, glob=PID), binary=up.exe,
                  env={"BST_TEST_INHERIT_VERSION": "999"})  # read by the new image only
    pidf, old = srv.workdir / "bastion.pid", srv.proc.pid
    srv.proc.send_signal(signal.SIGUSR2)
    srv.wait_log(r"upgrade failed: new master \(pid \d+\) refused the handed-over state", timeout=30)
    assert "state format version 1, this binary reads 999" in srv.logs()
    assert srv.proc.poll() is None and read_pid(pidf) == old
    assert not (srv.workdir / "bastion.pid.oldbin").exists()
    assert get(srv.ports["http"]).startswith(b"HTTP/1.1 200")


def test_xdp_continuity(bastion, net, pin, up):  # noqa: F811
    """The XDP program stays attached across a committed upgrade, and both the static deny list
    and a dynamic (escalation) block keep dropping."""
    n = net()
    text = (f"workers 2;\n{PID}\n"
            f"xdp {{ interface {n.host}; mode generic; pin_path {pin}; deny {n.bad}; }}\n"
            f"limit_zone z {{ rate 1/m; escalate after=3 window=10s block=120s; }}\n"
            f"server {{ listen {n.ip}:@HTTP_PORT@;\n"
            "location / { limit z; return 200 \"ok\"; } }\n")
    srv = bastion(text, binary=up.exe)
    p, pidf = srv.ports["http"], srv.workdir / "bastion.pid"
    for _ in range(4):
        n.get(n.good, p)
    srv.wait_log(re.escape(f"escalate: blocked {n.good}/32 for 120s"), timeout=5)
    time.sleep(0.3)
    assert n.get(n.good, p, timeout=0.5) == "timeout" and n.get(n.bad, p, timeout=0.5) == "timeout"
    r = up.run_ctl("-p", pidf, "--timeout", 30)
    new = read_pid(pidf)
    if new and new != srv.proc.pid:
        up.masters.append(new)
    assert r.returncode == 0, r.stderr + srv.logs()[-3000:]
    assert srv.proc.wait(30) == 0
    assert n.xdp_attached() and os.path.exists(f"{pin}/link_{n.host}")
    assert "xdp: adopting 1 pinned link(s)" in srv.logs()
    assert n.get(n.bad, p, timeout=0.5) == "timeout"   # static list
    assert n.get(n.good, p, timeout=0.5) == "timeout"  # dynamic block entry survived
    with socket.create_connection((n.ip, p), timeout=5) as s:  # from the host: not via XDP
        s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        assert s.recv(100).startswith(b"HTTP/1.1 200")


def test_quic_across_upgrade(bastion, certs, www, up):  # noqa: F811
    """A QUIC download on an old worker finishes across USR2, WINCH and QUIT, while new
    connections reach the new master."""
    events = 24

    def slow(req, c):
        c.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
        for i in range(events):
            ev = f"e{i};".encode()
            c.sendall(b"%x\r\n" % len(ev) + ev + b"\r\n")
            time.sleep(0.25)
        c.sendall(b"0\r\n\r\n")
    u = Upstream(slow)
    try:
        srv = bastion(conf(certs, www, glob=PID, extra=f"location /slow {{ proxy {u.url}; }}"),
                      binary=up.exe)
        if "routing by connection ID" not in srv.logs():
            pytest.skip("quic_routing ebpf unavailable here: the hash fallback has no handoff")
        p = subprocess.Popen([quic_util.h3client_bin(), "--timeout", "20000", "--chunks",
                              "127.0.0.1", str(srv.ports["quic"]), "/slow"],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(0.5)
        begin(srv, up)
        srv.proc.send_signal(signal.SIGWINCH)
        assert p.poll() is None, "the stream should still be running on the old worker"
        for _ in range(3):
            rc, lines = quic_util.h3(srv, "/v", timeout_ms=5000)
            assert rc == 0 and [ln.get("status") for ln in lines if "status" in ln] == [200], \
                f"{lines}\n{srv.logs()[-4000:]}"
        srv.proc.send_signal(signal.SIGQUIT)
        out, err = p.communicate(timeout=60)
        assert p.returncode == 0, err[-500:]
        lines = [json.loads(ln) for ln in out.decode().splitlines() if ln.startswith("{")]
        assert [ln.get("status") for ln in lines if "status" in ln] == [200], lines
        body = "".join(ln["data"] for ln in lines if ln.get("type") == "chunk")
        assert body == "".join(f"e{i};" for i in range(events))
        assert srv.proc.wait(30) == 0
        rc, lines = quic_util.h3(srv, "/v", timeout_ms=5000)
        assert rc == 0 and [ln.get("status") for ln in lines if "status" in ln] == [200], lines
    finally:
        u.close()


def test_tickets_across_upgrade(bastion, certs, www, up, tmp_path):  # noqa: F811
    """A session ticket issued by the old master resumes on the new one: the ticket keys are
    handed over, and the old master's exit does not wipe them."""
    srv = bastion(conf(certs, www, glob=PID), binary=up.exe)
    sess = tmp_path / "sess.pem"
    session_reused(srv.ports["https"], sess, out=True)
    assert sess.exists() and sess.stat().st_size > 0
    pidf = srv.workdir / "bastion.pid"
    r = up.run_ctl("-p", pidf, "--timeout", 30)
    new = read_pid(pidf)
    if new and new != srv.proc.pid:
        up.masters.append(new)
    assert r.returncode == 0, r.stderr
    assert srv.proc.wait(30) == 0
    assert session_reused(srv.ports["https"], sess, out=False)


def test_systemd_mainpid(bastion, certs, www, up, tmp_path):  # noqa: F811
    """The old master, still the unit's main process, announces the new MAINPID on commit (so
    NotifyAccess=main suffices), and its own again on a rollback."""
    path = tmp_path / "notify"
    ns = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    ns.bind(str(path))
    ns.settimeout(0.2)

    def messages(until, timeout=30):
        got = []
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                got.append(ns.recv(4096).decode())
            except socket.timeout:
                continue
            if until in got[-1]:
                return got
        pytest.fail(f"no {until!r} on NOTIFY_SOCKET: {got}")
    try:
        srv = bastion(conf(certs, www, glob=PID), binary=up.exe, env={"NOTIFY_SOCKET": str(path)})
        old = srv.proc.pid
        new = begin(srv, up)
        srv.proc.send_signal(signal.SIGHUP)  # rollback first
        messages(f"MAINPID={old}")
        srv.wait_log(r"upgrade: rolled back: new master", timeout=30)
        assert not alive(new)
        new = begin(srv, up)
        srv.proc.send_signal(signal.SIGQUIT)
        messages(f"MAINPID={new}")
        assert srv.proc.wait(30) == 0
        assert alive(new)
    finally:
        ns.close()
