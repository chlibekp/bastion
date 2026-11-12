"""The upstream connection pool (Phase 9, Task 2), seen through the proxy: reuse, idle timeout,
stale connections and the close-while-sending race."""
import socket
import time

import pytest

from upstream_util import Upstream, http, ok, wait_until


@pytest.fixture
def up():
    u = Upstream()
    yield u
    u.close()


def conf(up, opts=""):
    return (f"workers 1;\nupstream u {{ server 127.0.0.1:{up.port}; {opts} }}\n"
            "server { listen 127.0.0.1:@HTTP_PORT@; location / { proxy u; } }\n")


def keepalive_requests(port, n, method="GET", body=b""):
    """n requests on one client connection; the statuses."""
    s = socket.create_connection(("127.0.0.1", port), 10)
    out = []
    f = s.makefile("rb")
    for i in range(n):
        s.sendall(f"{method} /{i} HTTP/1.1\r\nHost: a\r\nContent-Length: {len(body)}\r\n\r\n".encode() + body)
        line = f.readline()
        out.append(int(line.split()[1]))
        length = 0
        while True:
            h = f.readline()
            if h in (b"\r\n", b""):
                break
            if h.lower().startswith(b"content-length:"):
                length = int(h.split(b":")[1])
        f.read(length)
    s.close()
    return out


def test_pool_reuse(bastion, up):
    srv = bastion(conf(up))
    st = keepalive_requests(srv.ports["http"], 1000)
    assert st == [200] * 1000
    assert up.connections <= 2, f"{up.connections} upstream connections for 1000 requests"


def test_pool_idle_timeout(bastion, up):
    srv = bastion(conf(up, "keepalive_timeout 300ms;"))
    assert keepalive_requests(srv.ports["http"], 1) == [200]
    assert wait_until(lambda: up.closed >= 1, 3), "the idle connection was not closed"


def test_pool_stale_detect(bastion, up):
    def close_after(req, c):
        req.close = True  # answer, then close the connection while it sits idle in the pool
        c.sendall(ok("bye"))
        return None

    up.handler = close_after
    srv = bastion(conf(up))
    assert keepalive_requests(srv.ports["http"], 1) == [200]
    time.sleep(0.3)  # the pool sees the close on its read watch
    up.handler = lambda req, c: ok("hi")
    assert keepalive_requests(srv.ports["http"], 1) == [200]
    assert "retrying on a fresh one" not in srv.logs(), "a stale connection was handed out"
    assert up.requests[-1].conn_id == 2


def test_pool_race(bastion, up):
    """The upstream closes a pooled connection as the request arrives, before any response byte:
    an idempotent request is retried on a fresh connection, a POST gets 502."""
    seen = {}

    def h(req, c):
        n = seen[req.conn_id] = seen.get(req.conn_id, 0) + 1
        if n == 2:
            req.close = True  # a pooled connection's next request: read it, answer nothing, close
            return None
        return ok("fine")

    up.handler = h
    srv = bastion(conf(up))
    assert keepalive_requests(srv.ports["http"], 1) == [200]  # conn 1 is now pooled
    assert keepalive_requests(srv.ports["http"], 1) == [200]  # GET: retried on conn 2
    srv.wait_log(r"retrying on a fresh one")
    assert up.requests[-1].conn_id == 2
    # conn 2 is pooled now and fails the same way: a POST is never retried
    st = keepalive_requests(srv.ports["http"], 1, method="POST", body=b"x")
    assert st == [502]
    assert up.connections == 2
