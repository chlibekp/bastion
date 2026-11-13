"""WebSocket tunnels through the proxy (Phase 9, Task 7): HTTP/1.1 clients, and HTTP/2 clients by
RFC 8441 extended CONNECT reaching the same HTTP/1.1 upstream."""
import base64
import os
import socket
import sys
import threading
import time

import pytest

from upstream_util import Upstream, get, ok, wait_until
from ws_util import echo_handler, frame, read_frame, ws_connect

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import h2_attack as h2  # noqa: E402


@pytest.fixture
def up():
    u = Upstream(echo_handler)
    yield u
    u.close()


def conf(up, extra=""):
    return (f"workers 1;\nserver {{ listen 127.0.0.1:@HTTP_PORT@; {extra}\n"
            f"location / {{ proxy {up.url}; }} }}\n")


def test_ws_h1(bastion, up):
    srv = bastion(conf(up))
    s, st, head, buf = ws_connect(srv.ports["http"])
    assert st == 101, head
    assert b"upgrade: websocket" in head.lower() and b"sec-websocket-accept:" in head.lower()
    s.sendall(frame(0x1, b"hello", True))
    assert read_frame(s, buf) == (0x1, b"hello")
    big = os.urandom(200000)
    s.sendall(frame(0x2, big, True))
    assert read_frame(s, buf) == (0x2, big)
    s.sendall(frame(0x9, b"p", True))
    assert read_frame(s, buf) == (0xA, b"p")
    s.sendall(frame(0x8, b"\x03\xe8", True))
    assert read_frame(s, buf) == (0x8, b"\x03\xe8")
    s.settimeout(5)
    assert s.recv(10) == b""  # the upstream closed: so does the tunnel
    s.close()
    req = up.requests[-1]
    assert req.get("upgrade") == "websocket" and "upgrade" in req.get("connection").lower()


@pytest.mark.parametrize("key,version", [(None, "8"), ("short", "13"), ("", "13")])
def test_ws_bad_upgrade(bastion, up, key, version):
    """A bad key or version: passed on as a plain request (no upgrade), so a normal answer."""
    srv = bastion(conf(up))
    s, st, head, _ = ws_connect(srv.ports["http"], key=key, version=version)
    assert st == 400, head
    assert up.requests[-1].get("upgrade") is None
    s.close()


def test_ws_upstream_refuses(bastion):
    """An upstream that answers 200 to an upgrade: relayed as a response; the connection stays
    HTTP, so what the client sends next is parsed as a request, never tunneled."""
    u = Upstream(lambda req, c: ok("no tunnel here"))
    try:
        srv = bastion(conf(u))
        s, st, head, buf = ws_connect(srv.ports["http"])
        assert st == 200, head
        # a second request on the same connection is answered as HTTP
        s.sendall(b"GET /second HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n")
        data = buf[0]
        s.settimeout(5)
        while True:
            d = s.recv(65536)
            if not d:
                break
            data += d
        assert b"HTTP/1.1 200" in data and data.endswith(b"/second") or b"no tunnel here" in data
        assert [r.target for r in u.requests] == ["/", "/second"]
    finally:
        u.close()


def test_ws_smuggle_failed_upgrade(bastion):
    """The known smuggling pattern: the upstream refuses the upgrade (here with a 426) and the
    client then sends a request meant for a hidden path inside the would-be tunnel. It must be
    parsed by bastion as a request of its own (and routed by its rules), not relayed raw."""
    u = Upstream(lambda req, c: ok("", status=426) if req.get("upgrade") else ok(req.target))
    try:
        srv = bastion(f"workers 1;\nserver {{ listen 127.0.0.1:@HTTP_PORT@;\n"
                      f"location /internal {{ return 403; }}\n"
                      f"location / {{ proxy {u.url}; }} }}\n")
        s, st, head, buf = ws_connect(srv.ports["http"])
        assert st == 426, head
        s.sendall(b"GET /internal HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n")
        data = buf[0]
        s.settimeout(5)
        while True:
            d = s.recv(65536)
            if not d:
                break
            data += d
        assert b"403" in data.split(b"\r\n", 1)[0], data[:200]
        assert all(r.target != "/internal" for r in u.requests)
    finally:
        u.close()


def test_ws_unrequested_101(bastion):
    """An upstream 101 to a request that asked for no upgrade: 502, no tunnel."""
    u = Upstream(lambda req, c: b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                 b"Connection: Upgrade\r\n\r\n")
    try:
        srv = bastion(conf(u))
        r = get(srv.ports["http"])
        assert r.startswith(b"HTTP/1.1 502"), r[:100]
    finally:
        u.close()


def test_ws_off(bastion, up):
    srv = bastion(conf(up, "websocket off;"))
    s, st, head, _ = ws_connect(srv.ports["http"])
    assert st == 400  # the upstream saw a plain GET
    assert up.requests[-1].get("upgrade") is None
    s.close()


def test_ws_idle_timeout(bastion, up):
    srv = bastion(conf(up, "tunnel_idle_timeout 300ms;"))
    s, st, _, buf = ws_connect(srv.ports["http"])
    assert st == 101
    s.sendall(frame(0x1, b"x", True))
    assert read_frame(s, buf) == (0x1, b"x")
    s.settimeout(5)
    t0 = time.monotonic()
    assert s.recv(10) == b""
    assert time.monotonic() - t0 < 3
    s.close()


def test_ws_half_close(bastion):
    """The client shuts its write side: the upstream sees EOF and can still answer."""
    got = {}

    def h(req, c):
        key = req.get("sec-websocket-key")
        from ws_util import accept_for
        c.sendall(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                   f"Sec-WebSocket-Accept: {accept_for(key)}\r\n\r\n").encode())
        data = b""
        while True:
            d = c.recv(65536)
            if not d:
                break
            data += d
        got["data"] = data
        c.sendall(b"after-eof")
        req.close = True
        return None

    u = Upstream(h)
    try:
        srv = bastion(conf(u))
        s, st, _, buf = ws_connect(srv.ports["http"])
        assert st == 101
        s.sendall(b"raw-bytes")
        s.shutdown(socket.SHUT_WR)
        s.settimeout(5)
        data = buf[0]
        while True:
            d = s.recv(65536)
            if not d:
                break
            data += d
        assert data == b"after-eof"
        assert got["data"] == b"raw-bytes"
    finally:
        u.close()


def test_ws_backpressure(bastion):
    """The client stops reading: the upstream is slowed (its writes block), memory bounded."""
    sent = [0]
    stop = threading.Event()

    def h(req, c):
        key = req.get("sec-websocket-key")
        from ws_util import accept_for
        c.sendall(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                   f"Sec-WebSocket-Accept: {accept_for(key)}\r\n\r\n").encode())
        chunk = b"z" * 65536
        c.settimeout(10)
        try:
            while not stop.is_set() and sent[0] < (512 << 20):
                c.sendall(chunk)
                sent[0] += len(chunk)
        except OSError:
            pass
        req.close = True
        return None

    u = Upstream(h)
    try:
        srv = bastion(conf(u))
        s, st, _, _ = ws_connect(srv.ports["http"])
        assert st == 101
        time.sleep(2)
        n1 = sent[0]
        time.sleep(1)
        n2 = sent[0]
        assert n2 == n1, "the upstream kept writing to a client that reads nothing"
        assert n1 < (64 << 20), f"{n1} bytes buffered on the way"
        stop.set()
        s.close()
    finally:
        u.close()


def h2_conf(up, extra=""):
    return (f"workers 1;\nserver {{ listen 127.0.0.1:@HTTP_PORT@ h2c; http2_connect_protocol on;\n"
            f"{extra}\nlocation / {{ proxy {up.url}; }} }}\n")


def parse_frames(data):
    """Unmasked server frames from a byte string: [(opcode, payload)], and the rest."""
    out = []
    while len(data) >= 2:
        n, off = data[1] & 0x7F, 2
        if n == 126:
            if len(data) < 4:
                break
            n, off = int.from_bytes(data[2:4], "big"), 4
        elif n == 127:
            if len(data) < 10:
                break
            n, off = int.from_bytes(data[2:10], "big"), 10
        if len(data) < off + n:
            break
        out.append((data[0] & 0x0F, data[off:off + n]))
        data = data[off + n:]
    return out, data


def ext_connect(c, sid, path="/chat"):
    c.send(h2.headers_frame(sid, [(":method", "CONNECT"), (":protocol", "websocket"),
                                  (":scheme", "http"), (":path", path),
                                  (":authority", "localhost"), ("sec-websocket-version", "13")],
                            end_stream=False))
    assert c.until(lambda: c.stream(sid).status is not None or c.stream(sid).reset is not None, 5)
    return c.stream(sid)


def send_data(c, sid, data, end=False):
    for i in range(0, len(data), 16384):
        last = i + 16384 >= len(data)
        c.send(h2.pack(h2.DATA, h2.END_STREAM if end and last else 0, sid, data[i:i + 16384]))


def test_ws_over_h2(bastion, up):
    srv = bastion(h2_conf(up))
    c = h2.H2(srv.ports["http"], tls=False)
    assert c.server_settings.get(0x8) == 1  # SETTINGS_ENABLE_CONNECT_PROTOCOL
    st = ext_connect(c, 1)
    assert st.status == 200, st.headers  # RFC 8441: a 2xx, not 101
    assert st.header("sec-websocket-accept") is None and st.header("upgrade") is None
    req = up.requests[-1]  # the upstream saw a plain HTTP/1.1 Upgrade with a key of ours
    assert (req.method, req.target, req.version) == ("GET", "/chat", "HTTP/1.1")
    assert req.get("upgrade") == "websocket" and "upgrade" in req.get("connection").lower()
    assert len(req.get("sec-websocket-key")) == 24 and req.get("sec-websocket-version") == "13"
    msgs = [(0x1, b"hello"), (0x2, os.urandom(40000)), (0x9, b"p")]
    for op, payload in msgs:
        send_data(c, 1, frame(op, payload, True))
    want = [(0x1, b"hello"), (0x2, msgs[1][1]), (0xA, b"p")]
    assert c.until(lambda: len(parse_frames(bytes(st.body))[0]) >= 3, 10), st.body[:64]
    assert parse_frames(bytes(st.body))[0] == want
    send_data(c, 1, frame(0x8, b"\x03\xe8", True))
    assert c.until(lambda: st.ended or st.reset is not None, 5)  # the upstream closed: so does
    assert st.reset is None, st.reset  # the stream, cleanly (END_STREAM)
    assert parse_frames(bytes(st.body))[0][-1] == (0x8, b"\x03\xe8")
    c.close()


def test_ws_over_h2_refused(bastion):
    """An upstream answering the translated Upgrade with anything but 101 is relayed as a normal
    response on the stream: no tunnel."""
    u = Upstream(lambda req, c: ok(b"no", 403))
    try:
        srv = bastion(h2_conf(u))
        c = h2.H2(srv.ports["http"], tls=False)
        st = ext_connect(c, 1)
        assert st.status == 403
        assert c.until(lambda: st.ended, 5) and bytes(st.body) == b"no"
        c.close()
    finally:
        u.close()


def test_ws_over_h2_off(bastion, up):
    srv = bastion(h2_conf(up, "websocket off;"))
    c = h2.H2(srv.ports["http"], tls=False)
    st = ext_connect(c, 1)
    assert st.status == 501
    c.close()


@pytest.mark.skip(reason="RFC 9220 over HTTP/3 needs an HTTP/3 client with extended CONNECT "
                         "(none in the test image); the HTTP/3 bridge still answers 501")
def test_ws_over_h3():
    pass


def test_max_tunnels(bastion, up):
    srv = bastion(conf(up, "max_tunnels 1;"))
    s1, st1, _, _ = ws_connect(srv.ports["http"])
    assert st1 == 101
    s2, st2, head, _ = ws_connect(srv.ports["http"])
    assert st2 == 503, head
    s1.close()
    s2.close()
