"""Request and response spooling (Phase 9, Task 10): request_buffering, response_buffering,
spool_memory_limit, temp_path, retry_buffered_body."""
import hashlib
import os
import socket
import time

import pytest

from upstream_util import Upstream, ok, wait_until


@pytest.fixture
def up():
    u = Upstream()
    yield u
    u.close()


def conf(ports, tmp, extra="", up_extra=""):
    servers = " ".join(f"server 127.0.0.1:{p};" for p in ports)
    return (f"workers 1;\ntemp_path {tmp};\nupstream u {{ {servers} {up_extra} }}\n"
            f"server {{ listen 127.0.0.1:@HTTP_PORT@; client_max_body_size 0; {extra}\n"
            "location / { proxy u; } }\n")


@pytest.fixture
def tmp(tmp_path):
    d = tmp_path / "spool"
    d.mkdir()
    os.chmod(d, 0o777)  # workers may run as another user
    return d


def read_response(s):
    f = s.makefile("rb")
    line = f.readline()
    status = int(line.split()[1])
    length = None
    while True:
        h = f.readline()
        if h in (b"\r\n", b""):
            break
        if h.lower().startswith(b"content-length:"):
            length = int(h.split(b":")[1])
    body = f.read(length) if length is not None else f.read()
    return status, body


def post(port, body, chunked=False, timeout=20):
    s = socket.create_connection(("127.0.0.1", port), timeout)
    if chunked:
        s.sendall(b"POST /up HTTP/1.1\r\nHost: a\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\n")
        for i in range(0, len(body), 65536):
            part = body[i:i + 65536]
            s.sendall(f"{len(part):x}\r\n".encode() + part + b"\r\n")
        s.sendall(b"0\r\n\r\n")
    else:
        s.sendall(f"POST /up HTTP/1.1\r\nHost: a\r\nConnection: close\r\nContent-Length: {len(body)}\r\n\r\n".encode()
                  + body)
    r = read_response(s)
    s.close()
    return r


def echo_digest(req, c):
    return ok(hashlib.sha256(req.body).hexdigest())


def test_request_buffered(bastion, up, tmp):
    up.handler = echo_digest
    srv = bastion(conf([up.port], tmp, "request_buffering on;"))
    body = os.urandom(300000)
    s = socket.create_connection(("127.0.0.1", srv.ports["http"]), 10)
    s.sendall(f"POST /up HTTP/1.1\r\nHost: a\r\nConnection: close\r\nContent-Length: {len(body)}\r\n\r\n".encode()
              + body[:200000])
    time.sleep(0.5)
    assert up.connections == 0 and up.partial == [], "the upstream saw bytes before the upload finished"
    s.sendall(body[200000:])
    status, got = read_response(s)
    s.close()
    assert status == 200 and got == hashlib.sha256(body).hexdigest().encode()
    assert up.requests[-1].get("content-length") == str(len(body))


def test_request_buffered_chunked(bastion, up, tmp):
    """A chunked upload reaches the upstream with a Content-Length."""
    up.handler = echo_digest
    srv = bastion(conf([up.port], tmp, "request_buffering on;"))
    body = os.urandom(150000)
    status, got = post(srv.ports["http"], body, chunked=True)
    assert status == 200 and got == hashlib.sha256(body).hexdigest().encode()
    req = up.requests[-1]
    assert req.get("content-length") == str(len(body)) and req.get("transfer-encoding") is None


def test_spill(bastion, up, tmp):
    big = os.urandom(3 << 20)

    def h(req, c):
        if req.method == "GET":
            return ok(big)
        return ok(hashlib.sha256(req.body).hexdigest())

    up.handler = h
    srv = bastion(conf([up.port], tmp, "request_buffering on; response_buffering on; spool_memory_limit 4k;"))
    body = os.urandom(2 << 20)
    status, got = post(srv.ports["http"], body)
    assert status == 200 and got == hashlib.sha256(body).hexdigest().encode(), "request content changed"
    s = socket.create_connection(("127.0.0.1", srv.ports["http"]), 20)
    s.sendall(b"GET /big HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n")
    status, got = read_response(s)
    s.close()
    assert status == 200 and got == big, ("response content changed", len(got), next((i for i in range(min(len(got), len(big))) if got[i] != big[i]), None))
    assert os.listdir(tmp) == []


def test_response_buffering_frees_upstream(bastion, up, tmp):
    """A client that reads nothing does not hold the upstream: the whole response is taken from
    it (more than every socket buffer on the way holds) before the client reads a byte."""
    big = os.urandom(32 << 20)
    done = []

    def h(req, c):
        c.sendall(ok(big))
        done.append(True)
        return None

    up.handler = h
    srv = bastion(conf([up.port], tmp, "response_buffering on; spool_memory_limit 64k;"))
    s = socket.create_connection(("127.0.0.1", srv.ports["http"]), 30)
    s.sendall(b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n")
    assert wait_until(lambda: done, 15), "the upstream was held by the slow client"
    status, got = read_response(s)
    s.close()
    assert status == 200 and got == big


def test_disk_full(bastion, up, tmp):
    srv = bastion(conf([up.port], tmp, "request_buffering on; spool_memory_limit 1k;"),
                  env={"BST_TEST_SPOOL_ENOSPC": "1"})
    status, _ = post(srv.ports["http"], os.urandom(100000))
    assert status == 507
    srv.wait_log(r"spooling the request body failed: No space left on device")
    assert up.connections == 0


def test_no_temp_leak(bastion, up, tmp):
    srv = bastion(conf([up.port], tmp, "request_buffering on; spool_memory_limit 1k;"))
    for _ in range(3):
        s = socket.create_connection(("127.0.0.1", srv.ports["http"]), 10)
        s.sendall(b"POST /up HTTP/1.1\r\nHost: a\r\nContent-Length: 1000000\r\n\r\n" + os.urandom(300000))
        time.sleep(0.2)
        s.close()  # abort mid-upload
    time.sleep(0.3)
    assert os.listdir(tmp) == [], "a spooled body was left on disk"
    assert up.connections == 0
    # the server still works
    status, _ = post(srv.ports["http"], b"x" * 5000)
    assert status == 200


def flaky_pair():
    """A server that reads the request and closes without answering, and one that answers."""
    bad, good = Upstream(), Upstream()

    def drop(req, c):
        req.close = True
        return None

    bad.handler = drop
    good.handler = echo_digest
    return bad, good


@pytest.mark.parametrize("replay", [False, True])
def test_retry_with_buffered_body(bastion, tmp, replay):
    bad, good = flaky_pair()
    try:
        extra = "request_buffering on; spool_memory_limit 1k;" + (" retry_buffered_body on;" if replay else "")
        srv = bastion(conf([bad.port, good.port], tmp, extra, "retry attempts=1 on=error budget=100%;"))
        body = os.urandom(20000)
        statuses = [post(srv.ports["http"], body)[0] for _ in range(4)]
        assert len(bad.requests) >= 1, "the failing server was never picked"
        if replay:
            assert statuses == [200] * 4
            assert all(r.body == body for r in good.requests)
            assert len(good.requests) == 4
        else:
            assert 502 in statuses, statuses
            assert len(good.requests) == statuses.count(200), "a POST was replayed by default"
    finally:
        bad.close()
        good.close()
