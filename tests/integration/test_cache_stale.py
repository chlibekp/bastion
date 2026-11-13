"""Stampede protection and stale serving (Phase 10, Task 6): one upstream fetch for many
concurrent misses across workers, bounded waiting, recovery from a fill whose worker died,
private responses never shared, stale-while-revalidate and stale-if-error (RFC 5861)."""
import asyncio
import os
import signal
import threading
import time

import pytest

from test_cache import req
from upstream_util import Upstream, ok


@pytest.fixture
def up():
    u = Upstream()
    yield u
    u.close()


def conf(up, store="", loc="", workers=2):
    return (f"workers {workers};\nworker_rlimit_nofile 20000;\n"
            f"cache_store main {{ disk @WORKDIR@/cache size=100m; lock_max_waiters 10000; {store} }}\n"
            f"server {{ listen 127.0.0.1:@HTTP_PORT@;\n"
            f"location / {{ proxy {up.url}; cache main; {loc} }} }}\n")


def slow(delay, body=b"filled", headers=(("Cache-Control", "max-age=60"),)):
    def h(r, c):
        time.sleep(delay)
        return ok(body if not callable(body) else body(), 200, headers)
    return h


async def one(port, path):
    for _ in range(20):
        try:
            r, w = await asyncio.open_connection("127.0.0.1", port)
            break
        except OSError:
            await asyncio.sleep(0.05)
    else:
        return None
    w.write(f"GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".encode())
    await w.drain()
    data = await asyncio.wait_for(r.read(), 60)
    w.close()
    return data


def burst(srv, path, n):
    async def go():
        return await asyncio.gather(*(one(srv.ports["http"], path) for _ in range(n)))
    return asyncio.run(go())


def test_stampede(bastion, up):
    up.handler = slow(1.0)
    srv = bastion(conf(up))
    n = int(os.environ.get("STAMPEDE_N", "5000"))
    out = burst(srv, "/hot", n)
    good = [o for o in out if o is not None and o.startswith(b"HTTP/1.1 200") and o.endswith(b"filled")]
    assert len(good) == n, f"{n - len(good)} requests failed: {[o[:60] for o in out if o not in good][:3]}"
    assert len(up.requests) == 1, f"{len(up.requests)} upstream fetches for one key"


def test_lock_timeout(bastion, up):
    up.handler = slow(3.0)
    srv = bastion(conf(up, store="lock_timeout 500ms;"))
    t0 = time.monotonic()
    out = burst(srv, "/slow", 20)
    assert all(o is not None and o.endswith(b"filled") for o in out)
    assert 1 < len(up.requests) <= 21, "waiters did not pass through, or more than one each"
    assert time.monotonic() - t0 < 10


def test_lock_owner_crash(bastion, up):
    up.handler = slow(30.0)
    srv = bastion(conf(up, store="lock_timeout 2s;", workers=1))
    t = threading.Thread(target=lambda: req(srv, "/crash"), daemon=True)
    t.start()
    assert srv.wait_for(lambda: len(up.requests) == 1, what="the fill to start")
    os.kill(srv.workers()[0], signal.SIGKILL)  # the fill's worker dies holding the lock
    srv.wait_workers(1)
    up.handler = slow(0, body=b"recovered")
    t0 = time.monotonic()
    st, h, b = req(srv, "/crash")
    assert b == b"recovered" and time.monotonic() - t0 < 5, "the dead owner's lock never expired"


def test_uncacheable_after_lock(bastion, up):
    n = [0]
    lock = threading.Lock()

    def private(r, c):
        time.sleep(0.5)
        with lock:
            n[0] += 1
            mine = n[0]
        return ok(f"user-{mine}", 200, (("Cache-Control", "private"),))
    up.handler = private
    srv = bastion(conf(up, store="lock_timeout 30s;"))
    t0 = time.monotonic()
    out = burst(srv, "/me", 10)
    bodies = [o.split(b"\r\n\r\n", 1)[1] for o in out]
    assert len(set(bodies)) == 10, "a private body was shared"
    assert len(up.requests) == 10
    assert time.monotonic() - t0 < 10, "waiters were held until the lock timed out"


def test_swr(bastion, up):
    gen = [0]

    def h(r, c):
        gen[0] += 1
        time.sleep(0.3)
        age = 1 if gen[0] == 1 else 60  # the refreshed copy stays fresh for the last check
        return ok(f"v{gen[0]}", 200, (("Cache-Control", f"max-age={age}, stale-while-revalidate=30"),))
    up.handler = h
    srv = bastion(conf(up))
    assert req(srv, "/s")[2] == b"v1"
    time.sleep(2.2)
    t0 = time.monotonic()
    for _ in range(5):
        st, hd, b = req(srv, "/s")
        assert b == b"v1" and "stale-while-revalidate" in hd["cache-status"], hd
    assert time.monotonic() - t0 < 1, "stale responses waited for the upstream"
    time.sleep(1)
    assert len(up.requests) == 2, "not exactly one background revalidation"
    st, hd, b = req(srv, "/s")
    assert b == b"v2" and hd["cache-status"].startswith("bastion; hit")


def test_stale_if_error(bastion, up):
    up.handler = slow(0, body=b"good", headers=(("Cache-Control", "max-age=1, stale-if-error=4"),))
    srv = bastion(conf(up))
    req(srv, "/e")
    time.sleep(1.5)
    up.handler = lambda r, c: ok(b"broken", 503)
    st, hd, b = req(srv, "/e")
    assert st == 200 and b == b"good" and "stale-if-error" in hd["cache-status"], hd
    assert "fwd-status=503" in hd["cache-status"]
    up.close()  # connection refused
    st, hd, b = req(srv, "/e")
    assert st == 200 and b == b"good" and "stale-if-error" in hd["cache-status"], hd
    time.sleep(4)
    st, _, _ = req(srv, "/e")
    assert st in (502, 503), "stale-if-error outlived its window"  # 503: no healthy server left


def test_must_revalidate_no_stale(bastion, up):
    up.handler = slow(0, body=b"good",
                      headers=(("Cache-Control", "max-age=1, must-revalidate, stale-if-error=60, "
                                                 "stale-while-revalidate=60"),))
    srv = bastion(conf(up, loc="stale_if_error 1h; stale_while_revalidate 1h;"))
    req(srv, "/m")
    time.sleep(1.5)
    up.handler = lambda r, c: ok(b"broken", 500)
    st, _, b = req(srv, "/m")
    assert st == 500 and b == b"broken", "a must-revalidate response was served stale"
