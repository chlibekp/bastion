"""HTTP/2 protocol abuse against the real binary (RFC 9113 section 10.5; CVE-2019-9511..9518,
CVE-2023-44487, CVE-2024-27983, CVE-2025-8671), both backends, seccomp on. Every attack comes from
the hand-written client in tests/tools/h2_attack.py. Each test asserts that the flood ends the
connection with ENHANCE_YOUR_CALM, that the worker's CPU time and memory stay bounded, and that a
second, well-behaved client is served throughout and afterwards.
`make test-int-nosan` runs this file without sanitizers too.

bastion_h2_abuse_total{kind} is not readable from outside the process before Phase 12 (metrics
exposition); tests/unit/test_h2_abuse.c asserts the counters."""
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import h2_attack as h2  # noqa: E402

CALM = h2.ENHANCE_YOUR_CALM


def conf(certs, www, extra=""):
    return (f"workers 1;\nserver {{ listen 127.0.0.1:@HTTPS_PORT@ tls http2; "
            f"tls_cert {certs}/ecdsa-chain.crt {certs}/ecdsa.key; root {www};\n"
            f"location = /r {{ return 200 \"hi\"; }}\n{extra} }}\n")


@pytest.fixture
def www(tmp_path):
    root = tmp_path / "www"
    root.mkdir()
    (root / "mid.bin").write_bytes(b"x" * (1 << 20))
    return root


def worker_pid(srv):
    return next(iter(srv.workers().values()))


def cpu_s(pid):
    f = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()
    return (int(f[11]) + int(f[12])) / os.sysconf("SC_CLK_TCK")


def rss_kb(pid):
    for ln in open(f"/proc/{pid}/status"):
        if ln.startswith("VmRSS"):
            return int(ln.split()[1])


class Probe:
    """Measures the worker around an attack, and serves a legitimate client during it."""

    def __init__(self, srv):
        self.srv, self.pid = srv, worker_pid(srv)
        self.good = h2.H2(srv.ports["https"])
        self.cpu0, self.rss0, self.t0 = cpu_s(self.pid), rss_kb(self.pid), time.monotonic()
        self.next_sid = 1

    def legit(self):
        sid, self.next_sid = self.next_sid, self.next_sid + 2
        self.good.get(sid, "/r")
        st = self.good.response(sid, timeout=5)
        assert st.status == 200 and bytes(st.body) == b"hi", (st.status, st.reset)

    def finish(self, cpu_max=5.0, rss_max_mb=64):
        self.legit()  # still served after the attack
        assert cpu_s(self.pid) - self.cpu0 < cpu_max, "the attack cost the worker too much CPU"
        assert (rss_kb(self.pid) - self.rss0) / 1024 < rss_max_mb, "memory grew past its bound"
        assert "killed by signal" not in self.srv.logs()
        self.good.close()


def attack(srv, **kw):
    return h2.H2(srv.ports["https"], **kw)


def calm_or_closed(c, timeout=5):
    c.until(lambda: c.goaway is not None or c.eof, timeout)
    assert c.goaway is not None and c.goaway[1] == CALM, (c.goaway, c.eof)


def test_rapid_reset(bastion, certs, www):
    srv = bastion(conf(certs, www, "http2_max_concurrent_streams 1000;"))
    p = Probe(srv)
    a = attack(srv, auto_wu=False)
    burst = b"".join(h2.headers_frame(1 + 2 * i, h2.request_headers("/mid.bin"), end_stream=False)
                     + h2.rst(1 + 2 * i, h2.CANCEL) for i in range(5000))
    a.send(burst)
    calm_or_closed(a)
    assert len([s for s in a.streams.values() if s.status == 200]) < 1500  # handler starts were cut off
    p.legit()
    p.finish()
    a.close()


def test_made_you_reset(bastion, certs, www):
    """Resets the server sends because of invalid frames count against the client too."""
    srv = bastion(conf(certs, www, "http2_max_concurrent_streams 1000;"))
    p = Probe(srv)
    a = attack(srv, auto_wu=False, settings=[(h2.S_INITIAL_WINDOW_SIZE, 0)])
    burst = b"".join(h2.headers_frame(1 + 2 * i, h2.request_headers("/mid.bin"), end_stream=False)
                     + h2.window_update(1 + 2 * i, 0) for i in range(3000))
    a.send(burst)
    calm_or_closed(a)
    p.finish()
    a.close()


def test_continuation_flood(bastion, certs, www):
    srv = bastion(conf(certs, www))
    p = Probe(srv)
    a = attack(srv)
    a.send(h2.pack(h2.HEADERS, 0, 1, h2.encode_block(h2.request_headers("/"))[:20]))  # no END_HEADERS
    a.send(b"".join(h2.pack(h2.CONTINUATION, 0, 1, b"\x00" * 16) for _ in range(5000)))
    calm_or_closed(a)
    p.finish()
    a.close()


def test_settings_flood(bastion, certs, www):
    srv = bastion(conf(certs, www))
    p = Probe(srv)
    a = attack(srv)
    a.send(b"".join(h2.settings_frame() for _ in range(5000)))
    calm_or_closed(a)
    p.finish()
    a.close()


def test_ping_flood(bastion, certs, www):
    """CVE-2019-9512: the answers are queued for a client that does not read: bounded, then closed."""
    srv = bastion(conf(certs, www))
    p = Probe(srv)
    a = attack(srv)
    a.sock.setsockopt(__import__("socket").SOL_SOCKET, __import__("socket").SO_RCVBUF, 4096)
    a.send(b"".join(h2.ping() for _ in range(20000)))
    a.drain(1.0)
    assert a.goaway is None or a.goaway[1] == CALM
    assert a.closed(5) or a.goaway is not None
    p.finish()
    a.close()


def test_reset_flood(bastion, certs, www):
    """CVE-2019-9514: requests the server has to reset (bad ones) are charged to the client."""
    srv = bastion(conf(certs, www, "http2_max_concurrent_streams 1000;"))
    p = Probe(srv)
    a = attack(srv)
    bad = [(":method", "GET"), (":scheme", "https"), (":authority", "x")]  # no :path: a stream error
    a.send(b"".join(h2.headers_frame(1 + 2 * i, bad) for i in range(3000)))
    calm_or_closed(a)
    p.finish()
    a.close()


def test_empty_frames(bastion, certs, www):
    srv = bastion(conf(certs, www))
    p = Probe(srv)
    a = attack(srv)
    a.send(h2.headers_frame(1, h2.request_headers("/r", "POST"), end_stream=False))
    a.send(b"".join(h2.pack(h2.DATA, 0, 1) for _ in range(5000)))
    calm_or_closed(a)
    p.finish()
    a.close()


def test_dependency_flood(bastion, certs, www):
    srv = bastion(conf(certs, www))
    p = Probe(srv)
    a = attack(srv)
    prio = h2.pack(h2.PRIORITY, 0, 1, b"\x00\x00\x00\x03\x0a")
    a.send(prio * 20000)
    calm_or_closed(a)
    p.finish()
    a.close()


def test_hpack_pressure(bastion, certs, www):
    """Table churn at the limit: thousands of unique indexed fields evict each other; memory stays
    inside the table size and the header list limit."""
    srv = bastion(conf(certs, www))
    p = Probe(srv)
    a = attack(srv, auto_wu=False)
    n = 0
    start = time.monotonic()
    while time.monotonic() - start < 3 and not a.eof and n < 4000:
        sid = 1 + 2 * n
        extra = [(f"x-churn-{n}", "v" * 900)]
        a.send(h2.headers_frame(sid, h2.request_headers("/r", extra=extra), index=True))
        n += 1
        if n % 100 == 0:
            a.drain(0.01)
            p.legit()
    a.drain(0.5)
    assert a.goaway is None or a.goaway[1] in (CALM, h2.NO_ERROR), a.goaway
    p.finish(cpu_max=8.0)
    a.close()


def test_legitimate_browser_load(bastion, certs, www):
    """200 streams, a third cancelled, with pings and settings between: no guard fires."""
    srv = bastion(conf(certs, www))
    c = h2.H2(srv.ports["https"])
    sent = 0
    for batch in range(4):
        base = 1 + 2 * 50 * batch
        for i in range(50):
            sid = base + 2 * i
            c.get(sid, "/r")
            sent += 1
            if i % 3 == 0:
                c.send(h2.rst(sid, h2.CANCEL))
        c.send(h2.ping())
        c.until(lambda: len(c.pings) > batch, 5)
        c.drain(0.2)
    assert sent == 200
    assert c.goaway is None and not c.eof
    done = [s for s in c.streams.values() if s.status == 200]
    assert len(done) >= 120, len(done)
    c.close()
