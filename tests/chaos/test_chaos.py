"""Fault injection (Phase 15, Task 2): the real server under load while something breaks.

Faults: random worker and helper kills under load, origin kills, packet loss and reordering
(tc netem on the loopback of the container's own network namespace), a full disk under the
cache, the cache directory removed, wall-clock jumps, memory pressure through a cgroup v2
memory.high limit, file descriptor exhaustion, and simultaneous reloads.

Every test asserts the same four things:
  * no crash except the injected ones: the master stays up (same PID) and the log has no
    "killed by signal" line beyond the kills the test made; sanitizer reports from any process
    fail the test at teardown (tests/integration/conftest.py);
  * no corrupted response: a response whose framing completed (Content-Length reached, last
    chunk seen) has exactly the expected bytes. A response cut short by an injected fault is
    counted as an error, never as a pass, and only while the fault is active;
  * recovery within RECOVERY_S once the fault is gone: every path answers correctly again;
  * no leak afterwards: the master's descriptor count and the number of children return to
    their values before the fault.

Faults that need privileges (netem, tmpfs mounts, cgroups, settimeofday) run in the
privileged ./dev container. Where the privilege is missing the test is skipped with the reason
and the operation that failed; it is never skipped for a fault it could inject."""
import os
import random
import re
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from quic_util import h3

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import origin  # noqa: E402

RECOVERY_S = 10
SMALL = b"chaos small file\n" * 4
BIG = random.Random(15).randbytes(1 << 20)


# --- helpers -----------------------------------------------------------------------------------

def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Origin:
    """origin.py in its own process, so it can be SIGKILLed and started again on its port."""

    def __init__(self):
        self.port = free_port()
        self.proc = None
        self.start()

    def start(self):
        deadline = time.monotonic() + 10
        while True:
            self.proc = subprocess.Popen([sys.executable, str(HERE / "origin.py"), str(self.port)],
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if self.proc.stdout.readline().strip() == b"ready":
                return
            self.proc.wait()
            if time.monotonic() > deadline:
                pytest.fail(f"origin did not start: {self.proc.stderr.read()!r}")
            time.sleep(0.1)  # the port is still held by the killed one's sockets

    def kill(self):
        self.proc.kill()
        self.proc.wait()

    def close(self):
        if self.proc.poll() is None:
            self.kill()


def expected(path):
    if path == "/small.txt":
        return SMALL
    if path == "/big.bin":
        return BIG
    return origin.body(path)


def get1(port, path, timeout=10, extra=""):
    """One GET over its own connection. ("ok", None), ("err", why) for a refused, reset, short or
    non-200 response, or ("corrupt", why) for a complete response with the wrong bytes."""
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout)
        s.settimeout(timeout)
        s.sendall(f"GET {path} HTTP/1.1\r\nHost: localhost\r\n{extra}Connection: close\r\n\r\n".encode())
        out = bytearray()
        while True:
            d = s.recv(1 << 20)
            if not d:
                break
            out += d
        s.close()
    except OSError as e:
        return "err", repr(e)
    head, sep, rest = bytes(out).partition(b"\r\n\r\n")
    if not sep:
        return "err", f"short head {bytes(out[:80])!r}"
    lines = head.decode("latin-1").split("\r\n")
    m = re.match(r"HTTP/1\.1 (\d{3}) ", lines[0] + " ")
    if not m:
        return "corrupt", f"status line {lines[0]!r}"
    hdrs = {}
    for ln in lines[1:]:
        k, _, v = ln.partition(":")
        hdrs[k.strip().lower()] = v.strip()
    if m.group(1) != "200":
        return "err", f"status {m.group(1)}"
    if "content-length" in hdrs:
        n = int(hdrs["content-length"])
        if len(rest) < n:
            return "err", f"short body {len(rest)}/{n}"
        if len(rest) > n:
            return "corrupt", f"{len(rest) - n} bytes past Content-Length"
        body = rest
    elif hdrs.get("transfer-encoding") == "chunked":
        body, pos = b"", 0
        while True:
            end = rest.find(b"\r\n", pos)
            if end < 0:
                return "err", "short chunked body"
            size = int(rest[pos:end].split(b";")[0], 16)
            pos = end + 2
            if size == 0:
                break
            if len(rest) < pos + size + 2:
                return "err", "short chunk"
            body += rest[pos:pos + size]
            pos += size + 2
    else:
        return "corrupt", "no framing on a 200"
    if body != expected(path):
        return "corrupt", f"{path}: {len(body)} bytes differ from the expected {len(expected(path))}"
    return "ok", None


class Load:
    """Threads issuing GETs over paths until stop(); counts outcomes."""

    def __init__(self, port, paths, threads=4):
        self.port, self.paths = port, paths
        self.counts = {"ok": 0, "err": 0, "corrupt": 0}
        self.corrupt = []
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._threads = [threading.Thread(target=self._run, args=(i,), daemon=True) for i in range(threads)]
        for t in self._threads:
            t.start()

    def _run(self, i):
        rnd = random.Random(i)
        while not self._stop.is_set():
            path = rnd.choice(self.paths)
            kind, why = get1(self.port, path, timeout=5)
            with self._lock:
                self.counts[kind] += 1
                if kind == "corrupt":
                    self.corrupt.append(why)

    def stop(self):
        self._stop.set()
        for t in self._threads:
            t.join(30)
        assert not self.corrupt, self.corrupt[:5]
        assert self.counts["ok"] > 0, self.counts
        return self.counts


def recover(srv, paths, timeout=RECOVERY_S):
    """Seconds until every path answers correctly twice in a row; fails after timeout."""
    t0 = time.monotonic()
    last = None
    while time.monotonic() - t0 < timeout:
        res = [get1(srv.ports["http"], p, timeout=5) for p in paths * 2]
        bad = [r for r in res if r[0] != "ok"]
        assert not [r for r in bad if r[0] == "corrupt"], bad
        if not bad:
            return time.monotonic() - t0
        last = bad
        time.sleep(0.1)
    pytest.fail(f"no recovery within {timeout}s: {last}\n{srv.logs()[-3000:]}")


def nfds(pid):
    try:
        return len(os.listdir(f"/proc/{pid}/fd"))
    except OSError:
        return -1


def snapshot(srv):
    kids = srv.children()
    return {"master_fds": nfds(srv.proc.pid),
            "workers": len(srv.workers()),
            "others": sorted(c for c, s in kids.values() if s != "Z" and not c.startswith("bst:worker/"))}


def _describe_children(srv):
    out = []
    for pid, (comm, state) in srv.children().items():
        try:
            cmd = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace")
            wchan = Path(f"/proc/{pid}/wchan").read_text()
        except OSError:
            cmd = wchan = "?"
        out.append(f"{pid} {comm} {state} wchan={wchan} cmd={cmd}")
    return "\n".join(out)


def assert_no_leak(srv, before):
    deadline = time.monotonic() + RECOVERY_S
    while snapshot(srv) != before:
        if time.monotonic() > deadline:
            pytest.fail(f"descriptors and children not back to {before}: now {snapshot(srv)}\n"
                        f"{_describe_children(srv)}\n--- log tail ---\n{srv.logs()[-4000:]}")
        time.sleep(0.05)


def kills(srv):
    return len(re.findall(r"killed by signal", srv.logs()))


def assert_alive(srv, pid, injected=0):
    assert srv.proc.poll() is None and srv.proc.pid == pid, "the master died"
    assert kills(srv) <= injected, srv.logs()[-3000:]


@pytest.fixture
def www(tmp_path):
    d = tmp_path / "www"
    d.mkdir()
    (d / "small.txt").write_bytes(SMALL)
    (d / "big.bin").write_bytes(BIG)
    return d


@pytest.fixture
def up():
    o = Origin()
    yield o
    o.close()


def conf(www, up, certs, cache_dir, workers=2, glob="", extra=""):
    return (f"workers {workers};\n{glob}\n"
            f"cache_store main {{ disk {cache_dir} size=100m; }}\n"
            f"server {{ listen 127.0.0.1:@HTTP_PORT@; listen 127.0.0.1:@HTTPS_PORT@ tls http2;\n"
            f"  listen 127.0.0.1:@QUIC_PORT@ http3; tls_cert {certs}/ecdsa-chain.crt {certs}/ecdsa.key;\n"
            f"  root {www};\n"
            f"  location /up/ {{ proxy http://127.0.0.1:{up.port}; }}\n"
            f"  location /c/ {{ proxy http://127.0.0.1:{up.port}; cache main; }}\n"
            f"  {extra} }}\n")


PATHS = ["/small.txt", "/big.bin", "/up/a", "/c/a", "/c/b"]


def need(cmd, what):
    """Runs a privileged setup command; skips the test, naming it, when the container can not."""
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode != 0:
        pytest.skip(f"{what} needs privileges this environment lacks: {' '.join(cmd)}: {p.stderr.strip()}")


# --- the faults --------------------------------------------------------------------------------

def test_worker_and_helper_kills_under_load(bastion, www, up, certs, tmp_path):
    srv = bastion(conf(www, up, certs, tmp_path / "cache", workers=3))
    pid, before = srv.proc.pid, snapshot(srv)
    load = Load(srv.ports["http"], PATHS)
    rnd = random.Random(7)
    injected = 0
    for _ in range(4):
        time.sleep(0.4)
        w = srv.wait_workers(3)
        os.kill(rnd.choice(list(w.values())), signal.SIGKILL)
        injected += 1
    helper = srv.wait_for(srv.helper, what="the helper")
    os.kill(helper, signal.SIGKILL)
    injected += 1
    srv.wait_for(lambda: (lambda h: h is not None and h != helper)(srv.helper()), timeout=RECOVERY_S,
                 what="a new helper")
    time.sleep(0.5)
    load.stop()
    recover(srv, PATHS)
    srv.wait_workers(3, timeout=RECOVERY_S)
    srv.assert_sandboxed()
    assert_alive(srv, pid, injected)
    assert_no_leak(srv, before)


def test_origin_kills_under_load(bastion, www, up, certs, tmp_path):
    srv = bastion(conf(www, up, certs, tmp_path / "cache"))
    pid = srv.proc.pid
    assert recover(srv, PATHS) < RECOVERY_S
    before = snapshot(srv)
    load = Load(srv.ports["http"], ["/up/a", "/up/b", "/c/a", "/c/fresh", "/small.txt"])
    for _ in range(3):
        time.sleep(0.5)
        up.kill()  # mid-response for some: the proxy must not pass a cut body off as whole
        time.sleep(0.5)
        up.start()
    time.sleep(0.5)
    counts = load.stop()
    recover(srv, PATHS)
    assert_alive(srv, pid)
    assert_no_leak(srv, before)
    assert counts["ok"] > 0


def test_netem_loss_and_reorder(bastion, www, up, certs, tmp_path):
    srv = bastion(conf(www, up, certs, tmp_path / "cache"))
    pid = srv.proc.pid
    need(["tc", "qdisc", "add", "dev", "lo", "root", "netem", "delay", "2ms", "1ms",
          "reorder", "25%", "50%", "loss", "3%"], "tc netem on lo")
    try:
        for path in PATHS:
            kind, why = get1(srv.ports["http"], path, timeout=60)
            assert kind == "ok", (path, why)
        p = subprocess.run(["curl", "-sk", "--http2", "--max-time", "60", "-o", str(tmp_path / "h2.out"),
                            "-w", "%{http_version}", f"https://127.0.0.1:{srv.ports['https']}/big.bin"],
                           capture_output=True, text=True, timeout=90)
        assert p.returncode == 0 and p.stdout == "2", (p.returncode, p.stderr)
        assert (tmp_path / "h2.out").read_bytes() == BIG
        rc, lines = h3(srv, "/big.bin", "/c/q", timeout_ms=60000)
        resp = {ln["path"]: ln for ln in lines if ln.get("type") == "resp"}
        assert rc == 0, lines
        import hashlib
        assert resp["/big.bin"]["status"] == 200 and resp["/big.bin"]["sha256"] == hashlib.sha256(BIG).hexdigest()
        assert resp["/c/q"]["sha256"] == hashlib.sha256(origin.body("/c/q")).hexdigest()
        load = Load(srv.ports["http"], PATHS, threads=2)
        time.sleep(3)
        load.stop()
    finally:
        subprocess.run(["tc", "qdisc", "del", "dev", "lo", "root"], capture_output=True)
    recover(srv, PATHS)
    assert_alive(srv, pid)


def test_disk_full_under_cache(bastion, www, up, certs, tmp_path):
    full = tmp_path / "full"
    full.mkdir()
    need(["mount", "-t", "tmpfs", "-o", "size=256k", "tmpfs", str(full)], "a 256 KiB tmpfs")
    try:
        srv = bastion(conf(www, up, certs, full / "cache"))
        pid = srv.proc.pid
        before = snapshot(srv)
        # 40 distinct 64 KiB objects into 256 KiB: the store runs out of space early
        for i in range(40):
            kind, why = get1(srv.ports["http"], f"/c/obj{i}", timeout=10)
            assert kind == "ok", (i, why)
        for i in range(40):  # and again: hits where it stored, misses where it could not
            kind, why = get1(srv.ports["http"], f"/c/obj{i}", timeout=10)
            assert kind == "ok", (i, why)
        recover(srv, PATHS)
        assert_alive(srv, pid)
        assert_no_leak(srv, before)
        srv.proc.terminate()
        srv.proc.wait(10)
    finally:
        subprocess.run(["umount", "-l", str(full)], capture_output=True)


def test_cache_dir_removed(bastion, www, up, certs, tmp_path):
    cache = tmp_path / "cache"
    srv = bastion(conf(www, up, certs, cache))
    pid = srv.proc.pid
    assert recover(srv, PATHS) < RECOVERY_S  # /c/a and /c/b stored
    before = snapshot(srv)
    load = Load(srv.ports["http"], ["/c/a", "/c/b", "/c/x", "/small.txt"])
    time.sleep(0.5)
    shutil.rmtree(cache)
    time.sleep(1)
    load.stop()
    for i in range(10):  # new objects after the removal
        kind, why = get1(srv.ports["http"], f"/c/after{i}")
        assert kind == "ok", why
    recover(srv, PATHS)
    assert_alive(srv, pid)
    assert_no_leak(srv, before)


def _clock_jump(delta):
    time.clock_settime(time.CLOCK_REALTIME, time.clock_gettime(time.CLOCK_REALTIME) + delta)


def test_clock_jumps(bastion, www, up, certs, tmp_path):
    srv = bastion(conf(www, up, certs, tmp_path / "cache"))
    pid = srv.proc.pid
    assert recover(srv, PATHS) < RECOVERY_S
    before = snapshot(srv)
    t0_mono = time.monotonic()
    t0_real = time.time()
    try:
        _clock_jump(0)
    except PermissionError as e:
        pytest.skip(f"clock jumps need CAP_SYS_TIME, which this environment lacks: {e}")
    try:
        load = Load(srv.ports["http"], PATHS)
        for delta in (3 * 3600, -6 * 3600, 3600):
            time.sleep(0.7)
            _clock_jump(delta)
        time.sleep(0.7)
        load.stop()
        recover(srv, PATHS)
        # the Date header follows the wall clock as it is now (two hours behind)
        s = socket.create_connection(("127.0.0.1", srv.ports["http"]), 10)
        s.sendall(b"GET /small.txt HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        head = s.recv(65536).decode("latin-1")
        s.close()
        date = re.search(r"\r\nDate: (.+?)\r\n", head, re.I).group(1)
        import email.utils
        assert abs(email.utils.parsedate_to_datetime(date).timestamp() - time.time()) < 5, date
    finally:
        time.clock_settime(time.CLOCK_REALTIME, t0_real + (time.monotonic() - t0_mono))
    recover(srv, PATHS)
    assert_alive(srv, pid)
    assert_no_leak(srv, before)


CG = Path("/sys/fs/cgroup")


def _cgroup_with_memory(name):
    """A cgroup v2 child with the memory controller on. In a container the root cgroup holds the
    processes, so they move to a leaf first (no internal processes rule)."""
    if "memory" not in (CG / "cgroup.controllers").read_text().split():
        pytest.skip("cgroup v2 memory controller not available here")
    try:
        if "memory" not in (CG / "cgroup.subtree_control").read_text().split():
            leaf = CG / "chaos-init"
            leaf.mkdir(exist_ok=True)
            for pid in (CG / "cgroup.procs").read_text().split():
                try:
                    (leaf / "cgroup.procs").write_text(pid)
                except OSError:
                    pass  # kernel threads, exited processes
            (CG / "cgroup.subtree_control").write_text("+memory")
        g = CG / name
        g.mkdir(exist_ok=True)
        return g
    except OSError as e:
        pytest.skip(f"memory pressure needs a writable cgroup v2 tree, which this environment lacks: {e}")


def test_memory_pressure(bastion, www, up, certs, tmp_path):
    g = _cgroup_with_memory("chaos-bst")
    srv = bastion(conf(www, up, certs, tmp_path / "cache"),
                  preexec=lambda: (g / "cgroup.procs").write_text(str(os.getpid())))
    pid = srv.proc.pid
    try:
        assert recover(srv, PATHS) < RECOVERY_S
        before = snapshot(srv)
        high0 = int(re.search(r"^high (\d+)", (g / "memory.events").read_text(), re.M).group(1))
        cur = int((g / "memory.current").read_text())
        (g / "memory.high").write_text(str(max(cur - (8 << 20), 16 << 20)))  # below use: reclaim now
        load = Load(srv.ports["http"], PATHS)
        time.sleep(3)
        load.stop()
        high1 = int(re.search(r"^high (\d+)", (g / "memory.events").read_text(), re.M).group(1))
        assert high1 > high0, "memory.high never throttled: no pressure was applied"
        (g / "memory.high").write_text("max")
        recover(srv, PATHS)
        assert_alive(srv, pid)
        assert_no_leak(srv, before)
    finally:
        (g / "memory.high").write_text("max")
        srv.proc.terminate()
        srv.proc.wait(10)
        deadline = time.monotonic() + 10
        while (g / "cgroup.procs").read_text().strip() and time.monotonic() < deadline:
            time.sleep(0.05)
        try:
            g.rmdir()
        except OSError:
            pass


def test_fd_exhaustion(bastion, www, up, certs, tmp_path):
    srv = bastion(conf(www, up, certs, tmp_path / "cache", workers=1, glob="worker_rlimit_nofile 128;"))
    pid = srv.proc.pid
    assert recover(srv, PATHS) < RECOVERY_S
    worker = srv.workers()[0]
    before, wfds = snapshot(srv), nfds(worker)
    idle = []
    for _ in range(400):  # far past the worker's 128
        try:
            idle.append(socket.create_connection(("127.0.0.1", srv.ports["http"]), 2))
        except OSError:
            break
    time.sleep(0.5)
    # while exhausted: requests may be shed, never answered wrongly
    for path in PATHS:
        kind, why = get1(srv.ports["http"], path, timeout=3)
        assert kind != "corrupt", why
    for s in idle:
        s.close()
    recover(srv, PATHS)
    assert srv.workers()[0] == worker, "the worker died at EMFILE"
    assert_alive(srv, pid)
    assert_no_leak(srv, before)
    srv.wait_for(lambda: nfds(worker) <= wfds, timeout=RECOVERY_S, what=f"worker fds back to {wfds}")


def test_simultaneous_reloads(bastion, www, up, certs, tmp_path):
    cache = tmp_path / "cache"
    text = conf(www, up, certs, cache, workers=2, extra='location = /ver { return 200 "v1"; }')
    srv = bastion(text)
    pid = srv.proc.pid
    assert recover(srv, PATHS) < RECOVERY_S
    # The first generation holds a few descriptors from startup that a reload does not keep, so
    # the baseline is taken after one quiet reload: after the storm the count must equal it.
    os.kill(pid, signal.SIGHUP)
    srv.wait_log(r"reload: generation 1 ready", timeout=RECOVERY_S)
    srv.wait_for(lambda: len(srv.children()) == 3, timeout=RECOVERY_S, what="old generation gone")
    assert recover(srv, PATHS) < RECOVERY_S
    before = snapshot(srv)
    load = Load(srv.ports["http"], PATHS)
    conf_path = srv.workdir / "bastion.conf"
    final = conf_path.read_text().replace('"v1"', '"v2"')

    def hup():
        for _ in range(5):
            os.kill(pid, signal.SIGHUP)
            time.sleep(0.05)

    hs = [threading.Thread(target=hup) for _ in range(4)]
    for t in hs:
        t.start()
    time.sleep(0.1)
    conf_path.write_text(final)  # mid-storm: the last reload must see it
    for t in hs:
        t.join()
    time.sleep(1)
    os.kill(pid, signal.SIGHUP)
    load.stop()

    def ver():
        s = socket.create_connection(("127.0.0.1", srv.ports["http"]), 5)
        s.sendall(b"GET /ver HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        out = b""
        while True:
            d = s.recv(4096)
            if not d:
                break
            out += d
        s.close()
        return out.endswith(b"v2")

    srv.wait_for(ver, timeout=RECOVERY_S * 2, what="the final config live")
    recover(srv, PATHS)
    srv.wait_workers(2, timeout=RECOVERY_S)
    srv.assert_sandboxed()
    assert_alive(srv, pid)
    assert_no_leak(srv, before)
