"""Health checks, passive ejection, retries, the circuit breaker and panic_threshold (Phase 9,
Task 5), against scriptable upstreams."""
import re
import socket
import threading
import time

import pytest

from upstream_util import Upstream, get, http, ok, wait_until


@pytest.fixture
def ups():
    made = []

    def make(handler=None):
        u = Upstream() if handler is None else Upstream(handler)
        made.append(u)
        return u

    yield make
    for u in made:
        u.close()


def dead_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()  # nothing listens: connections are refused
    return p


def conf(servers, opts="", workers=1):
    sv = "".join(f"server 127.0.0.1:{p}; " for p in servers)
    return (f"workers {workers};\nupstream u {{ {sv}{opts} }}\n"
            "server { listen 127.0.0.1:@HTTP_PORT@; location / { proxy u; } }\n")


def count_log(srv, pattern):
    return len(re.findall(pattern, srv.logs()))


def status(r):
    return int(r.split(b" ", 2)[1])


def post(port, path="/p", body=b"data"):
    return http(port, f"POST {path} HTTP/1.1\r\nHost: a\r\nConnection: close\r\n"
                f"Content-Length: {len(body)}\r\n\r\n".encode() + body)


def test_active_eject_recover(bastion, ups):
    healthy = {"ok": True}

    def h(req, c):
        if req.target == "/health":
            return ok("", status=200 if healthy["ok"] else 500)
        return ok("a")

    a = ups(h)
    b = ups(lambda req, c: ok("b"))
    srv = bastion(conf([a.port, b.port], "health_check path=/health interval=100ms "
                       "timeout=500ms fails=2 passes=3;"))
    port = srv.ports["http"]
    assert {get(port).split(b"\r\n\r\n")[1] for _ in range(6)} == {b"a", b"b"}
    healthy["ok"] = False
    srv.wait_log(r"failed 2 health checks .*: down")
    assert {get(port).split(b"\r\n\r\n")[1] for _ in range(10)} == {b"b"}
    healthy["ok"] = True
    srv.wait_log(r"passed 3 health checks: up")
    assert wait_until(lambda: get(port).split(b"\r\n\r\n")[1] == b"a", 3)


def test_health_probe_count(bastion, ups):
    a = ups()
    srv = bastion(conf([a.port], "health_check path=/hc interval=200ms;", workers=4))
    time.sleep(0.3)
    n0 = sum(1 for r in a.requests if r.target == "/hc")
    time.sleep(2.0)
    n = sum(1 for r in a.requests if r.target == "/hc") - n0
    assert 5 <= n <= 14, f"{n} probes in 2 s at 200 ms: one prober, not one per worker"
    assert all(r.get("connection") == "close" for r in a.requests if r.target == "/hc")
    assert srv.ports["http"]


def test_passive_eject(bastion, ups):
    bad = ups(lambda req, c: ok("no", status=500))
    good = ups(lambda req, c: ok("yes"))
    srv = bastion(conf([bad.port, good.port], "passive_eject fails=3 window=10s for=30s; "
                       "retry attempts=0;", workers=2))
    port = srv.ports["http"]
    for _ in range(12):
        get(port)
    srv.wait_log(r"ejected for 30000 ms after 3 failures")
    before = len(bad.requests)
    # the ejection is shared: whichever worker takes these, none reaches the bad server
    for _ in range(20):
        assert get(port).endswith(b"yes")
    assert len(bad.requests) == before


def test_retry_get_connect_error(bastion, ups):
    good = ups(lambda req, c: ok("fine"))
    srv = bastion(conf([dead_port(), good.port], "balance round_robin;"))
    port = srv.ports["http"]
    for _ in range(6):
        r = get(port)
        assert status(r) == 200 and r.endswith(b"fine"), r


def test_no_retry_post(bastion, ups):
    """A POST whose bytes reached an upstream is never sent again, even with on=5xx/error."""
    first = ups(lambda req, c: ok("boom", status=502))
    second = ups(lambda req, c: ok("ok"))
    srv = bastion(conf([first.port, second.port], "retry attempts=2 on=error,timeout,5xx;"))
    port = srv.ports["http"]
    sts = [status(post(port)) for _ in range(4)]
    assert 502 in sts
    total = len(first.requests) + len(second.requests)
    assert total == 4, f"{total} upstream requests for 4 POSTs: a POST was replayed"


def test_no_retry_post_after_close(bastion, ups):
    def drop(req, c):
        req.close = True  # read the request, answer nothing
        return None

    first = ups(drop)
    second = ups(lambda req, c: ok("ok"))
    srv = bastion(conf([first.port, second.port], "keepalive 0; retry attempts=2;"))
    port = srv.ports["http"]
    sts = [status(post(port)) for _ in range(4)]
    assert 502 in sts
    assert len(first.requests) + len(second.requests) == 4


def test_retry_5xx_get(bastion, ups):
    first = ups(lambda req, c: ok("boom", status=503))
    second = ups(lambda req, c: ok("ok"))
    srv = bastion(conf([first.port, second.port], "retry attempts=1 on=5xx budget=100%;"))
    port = srv.ports["http"]
    for _ in range(4):
        assert status(get(port)) == 200


def test_retry_budget(bastion, ups):
    """Every server refuses: retries stay within the budget, never one per request."""
    ports = [dead_port() for _ in range(3)]
    srv = bastion(conf(ports, "retry attempts=2 budget=10%;"))
    port = srv.ports["http"]
    n = 100
    for _ in range(n):
        assert status(get(port)) == 502
    retries = count_log(srv, r"retrying on another server")
    assert retries <= n * 0.10 + 3, f"{retries} retries for {n} requests"


def test_no_retry_after_client_bytes(bastion, ups):
    def cut(req, c):
        c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\npartial")
        req.close = True
        return None

    first = ups(cut)
    second = ups(lambda req, c: ok("x" * 100))
    srv = bastion(conf([first.port, second.port], "retry attempts=2 on=error,timeout,5xx; "
                       "balance round_robin; keepalive 0;"))
    port = srv.ports["http"]
    for _ in range(2):
        r = get(port)
        if b"partial" in r:
            assert len(r.split(b"\r\n\r\n", 1)[1]) < 100  # aborted, never completed elsewhere
    assert len(second.requests) <= 1


def test_circuit_open(bastion, ups):
    release = threading.Event()

    def slow(req, c):
        release.wait(5)
        return ok("late")

    a = ups(slow)
    srv = bastion(conf([a.port], "circuit_breaker max_pending=1;"))
    port = srv.ports["http"]
    t = threading.Thread(target=get, args=(port,))
    t.start()
    assert wait_until(lambda: len(a.requests) == 1, 3)
    t0 = time.monotonic()
    r = get(port)
    assert time.monotonic() - t0 < 1.0
    assert status(r) == 503 and b"\r\nretry-after: " in r.lower(), r
    assert len(a.requests) == 1  # nothing queued behind the pending one
    release.set()
    t.join()


def test_circuit_breaker_opens(bastion, ups):
    bad = ups(lambda req, c: ok("no", status=500))
    srv = bastion(conf([bad.port], "circuit_breaker fails=3 for=5s;"))
    port = srv.ports["http"]
    assert [status(get(port)) for _ in range(3)] == [500] * 3
    r = get(port)
    assert status(r) == 503 and b"retry-after:" in r.lower()
    assert len(bad.requests) == 3


def test_all_down(bastion, ups):
    a = ups(lambda req, c: ok("", status=500))
    b = ups(lambda req, c: ok("", status=500))
    srv = bastion(conf([a.port, b.port], "health_check path=/h interval=100ms fails=1;"))
    port = srv.ports["http"]
    assert wait_until(lambda: count_log(srv, r": down") >= 2, 5)
    t0 = time.monotonic()
    for _ in range(50):
        r = get(port)
        assert status(r) == 503 and b"retry-after:" in r.lower()
    assert time.monotonic() - t0 < 5.0  # fast and deterministic, no waiting or spinning
    assert not [r for r in a.requests + b.requests if r.target != "/h"]


def test_all_down_panic(bastion, ups):
    a = ups(lambda req, c: ok("panic", status=200) if req.target != "/h" else ok("", status=500))
    srv = bastion(conf([a.port], "health_check path=/h interval=100ms fails=1; panic_threshold 50%;"))
    port = srv.ports["http"]
    assert wait_until(lambda: count_log(srv, r": down") >= 1, 5)
    r = get(port)
    assert status(r) == 200 and r.endswith(b"panic")
