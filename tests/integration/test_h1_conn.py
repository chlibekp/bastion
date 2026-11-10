"""HTTP/1.1 connection behaviour (src/http/h1/conn.c) against the real binary, on both backends.

One worker per server, so every connection meets the same state. The `return` handler answers;
in test builds `X-Bst-Test-Delay: <ms>` holds an answer back, which is how handlers that finish
out of order are made."""
import re
import select
import socket
import time
from email.utils import parsedate_to_datetime

import pytest

from process_util import connect


def conf(extra="", ret='return 200 "hello";', server_extra=""):
    return (f"workers 1;\n{extra}\nserver {{ listen 127.0.0.1:@HTTP_PORT@; {server_extra} "
            f"{ret} }}\n")


def req(path="/", extra="", method="GET", version="1.1", host=True, body=b""):
    head = f"{method} {path} HTTP/{version}\r\n"
    if host:
        head += "Host: localhost\r\n"
    return (head + extra + "\r\n").encode() + body


class Reader:
    """Reads HTTP/1.1 responses off a socket without ever consuming the next one."""

    def __init__(self, sock):
        self.s = sock
        self.buf = b""

    def _fill(self, timeout=5):
        if not select.select([self.s], [], [], timeout)[0]:
            raise TimeoutError(f"no data; have {self.buf!r}")
        try:
            data = self.s.recv(65536)
        except ConnectionResetError:
            data = b""
        if not data:
            raise EOFError(self.buf)
        self.buf += data

    def response(self, head_only=False, timeout=5):
        while b"\r\n\r\n" not in self.buf:
            self._fill(timeout)
        head, _, rest = self.buf.partition(b"\r\n\r\n")
        lines = head.decode("latin-1").split("\r\n")
        status = int(lines[0].split()[1])
        headers = {}
        for ln in lines[1:]:
            k, _, v = ln.partition(":")
            headers.setdefault(k.strip().lower(), []).append(v.strip())
        self.buf = rest
        body = b""
        if head_only or status in (204, 304) or status < 200:
            pass
        elif "content-length" in headers:
            n = int(headers["content-length"][0])
            while len(self.buf) < n:
                self._fill(timeout)
            body, self.buf = self.buf[:n], self.buf[n:]
        elif headers.get("transfer-encoding") == ["chunked"]:
            while True:
                while b"\r\n" not in self.buf:
                    self._fill(timeout)
                size_line, _, self.buf = self.buf.partition(b"\r\n")
                n = int(size_line.split(b";")[0], 16)
                while len(self.buf) < n + 2:
                    self._fill(timeout)
                body += self.buf[:n]
                self.buf = self.buf[n + 2:]
                if n == 0:
                    break
        return status, headers, body

    def closed(self, timeout=3):
        """True when the peer closes (EOF or reset) before sending anything more."""
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if self.buf:
                return False
            if select.select([self.s], [], [], 0.05)[0]:
                try:
                    data = self.s.recv(65536)
                except ConnectionResetError:
                    return True
                if not data:
                    return True
                self.buf += data
        return False


def open_reader(srv):
    s = connect(srv.ports["http"])
    return s, Reader(s)


def test_keepalive_reuse(bastion):
    srv = bastion(conf())
    s, r = open_reader(srv)
    for _ in range(2):
        s.sendall(req())
        status, h, body = r.response()
        assert (status, body) == (200, b"hello")
        assert h["content-length"] == ["5"]
        assert "connection" not in h
    s.close()


def test_http10_closes(bastion):
    srv = bastion(conf())
    s, r = open_reader(srv)
    s.sendall(req(version="1.0", host=False))
    status, h, body = r.response()
    assert (status, body) == (200, b"hello")
    assert h["connection"] == ["close"]
    assert r.closed()
    # with keep-alive it stays open and the framing is a Content-Length
    s2, r2 = open_reader(srv)
    for _ in range(2):
        s2.sendall(req(version="1.0", host=False, extra="Connection: keep-alive\r\n"))
        status, h, body = r2.response()
        assert (status, body) == (200, b"hello")
        assert h["connection"] == ["keep-alive"] and h["content-length"] == ["5"]


def test_connection_close(bastion):
    srv = bastion(conf())
    s, r = open_reader(srv)
    s.sendall(req(extra="Connection: close\r\n"))
    status, h, _ = r.response()
    assert status == 200 and h["connection"] == ["close"]
    assert r.closed()


def test_pipeline_order(bastion):
    srv = bastion(conf(ret='return 200 "ok";'))
    s, r = open_reader(srv)
    delays = [(i * 37) % 60 for i in range(100)]
    s.sendall(b"".join(req(f"/{i}", extra=(f"X-Bst-Test-Delay: {d}\r\n" if d else ""))
                       for i, d in enumerate(delays)))
    assert [r.response()[0] for _ in delays] == [200] * 100
    # a slow handler first, then a fast one, then a request refused outright: still in order
    s.sendall(req("/slow", extra="X-Bst-Test-Delay: 300\r\n") + req("/fast") +
              req("/bad", method="TRACE"))
    assert [r.response()[0] for _ in range(3)] == [200, 200, 405]


def test_pipeline_limit(bastion):
    srv = bastion(conf(server_extra="http1_max_pipeline 2;", ret='return 200 "ok";'))
    s, r = open_reader(srv)
    s.sendall(b"".join(req(f"/{i}", extra="X-Bst-Test-Delay: 200\r\n") for i in range(20)))
    time.sleep(0.1)
    start = time.monotonic()
    for _ in range(20):
        assert r.response(timeout=10)[0] == 200
    # twenty requests, two at a time, 200 ms each: the limit made them wait for each other
    assert time.monotonic() - start > 1.5


def test_expect_100(bastion):
    srv = bastion(conf(server_extra="client_max_body_size 100;"))
    s, r = open_reader(srv)
    s.sendall(req(method="POST", extra="Content-Length: 5\r\nExpect: 100-continue\r\n"))
    assert r.response()[0] == 100
    s.sendall(b"hello")
    assert r.response()[0:2][0] == 200
    # over the limit: 413 and no 100
    s, r = open_reader(srv)
    s.sendall(req(method="POST", extra="Content-Length: 500\r\nExpect: 100-continue\r\n"))
    status, h, _ = r.response()
    assert status == 413
    assert r.closed()


def test_head_no_body(bastion):
    srv = bastion(conf())
    s, r = open_reader(srv)
    s.sendall(req())
    _, hg, _ = r.response()
    s.sendall(req(method="HEAD"))
    status, hh, body = r.response(head_only=True)
    assert status == 200 and body == b""
    assert hh["content-length"] == hg["content-length"]
    s.sendall(req())  # the connection is still in step
    assert r.response()[2] == b"hello"


def test_204_304_no_body(bastion):
    srv = bastion(conf(ret="return 204;"))
    s, r = open_reader(srv)
    s.sendall(req())
    status, h, body = r.response()
    assert status == 204 and "content-length" not in h and body == b""
    s.sendall(req())
    assert r.response()[0] == 204
    srv2 = bastion(conf(ret="return 304;"))
    s, r = open_reader(srv2)
    s.sendall(req())
    status, h, _ = r.response()
    assert status == 304 and "content-length" not in h


def test_date_server(bastion):
    srv = bastion(conf())
    s, r = open_reader(srv)
    s.sendall(req())
    _, h, _ = r.response()
    assert re.fullmatch(r"[A-Z][a-z]{2}, \d\d [A-Z][a-z]{2} \d{4} \d\d:\d\d:\d\d GMT", h["date"][0])
    assert abs(parsedate_to_datetime(h["date"][0]).timestamp() - time.time()) < 5
    assert re.fullmatch(r"bastion/\S+", h["server"][0])
    srv2 = bastion(conf(server_extra="server_tokens off;"))
    s, r = open_reader(srv2)
    s.sendall(req())
    assert r.response()[1]["server"] == ["bastion"]


def test_slowloris_header(bastion):
    srv = bastion(conf(server_extra="client_header_timeout 1s;"))
    s, r = open_reader(srv)
    start = time.monotonic()
    for b in b"GET / HTTP/1.1\r\nHost: x\r\nX-A: ":
        s.sendall(bytes([b]))
        time.sleep(0.2)
        if select.select([s], [], [], 0)[0]:
            break
    status, h, _ = r.response(timeout=5)
    assert status == 408 and h["connection"] == ["close"]
    # one deadline for the whole head, not one per byte
    assert time.monotonic() - start < 2.5
    assert r.closed()


def test_slow_body(bastion):
    srv = bastion(conf(server_extra="client_body_timeout 1s; client_body_min_rate 1k;"))
    s, r = open_reader(srv)
    s.sendall(req(method="POST", extra="Content-Length: 100000\r\n"))
    start = time.monotonic()
    for _ in range(50):
        try:
            s.sendall(b"x")
        except OSError:
            break
        time.sleep(0.1)
        if select.select([s], [], [], 0)[0]:
            break
    status, _, _ = r.response()
    assert status == 408
    assert time.monotonic() - start < 4


def rss_kb(pid):
    for ln in open(f"/proc/{pid}/status"):
        if ln.startswith("VmRSS"):
            return int(ln.split()[1])


def test_slow_reader(bastion):
    srv = bastion(conf(server_extra="send_timeout 1s; send_min_rate 1m;",
                       ret='return 200 "' + "a" * 500000 + '";'))
    pid = srv.workers()[0]
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    s.connect(("127.0.0.1", srv.ports["http"]))
    s.sendall(req() * 30)  # asks for 15 MB and never reads
    time.sleep(0.5)
    before = rss_kb(pid)
    time.sleep(3.5)  # past send_timeout: the server must have cut the connection
    s.settimeout(2)
    got = 0
    try:
        while True:
            data = s.recv(1 << 16)
            if not data:
                break
            got += len(data)
    except ConnectionResetError:
        pass
    assert got < 15_000_000  # it never got everything
    assert rss_kb(pid) - before < 20000  # memory stayed bounded
    s2, r2 = open_reader(srv)  # the worker is still serving
    s2.sendall(req())
    assert r2.response(timeout=15)[0] == 200


def test_abort_during_handler(bastion):
    srv = bastion(conf(ret='return 200 "x";'))
    for _ in range(5):
        s, _r = open_reader(srv)
        s.sendall(req(extra="X-Bst-Test-Delay: 500\r\n"))
        time.sleep(0.05)
        s.close()
    time.sleep(0.8)  # the delay timers would fire into freed streams: ASan reports it at teardown
    s, r = open_reader(srv)
    s.sendall(req())
    assert r.response()[0] == 200
    assert srv.workers()  # the worker did not crash


def test_lingering_close(bastion):
    srv = bastion(conf(server_extra="client_max_body_size 10;"))
    s, r = open_reader(srv)
    s.sendall(req(method="POST", extra="Content-Length: 50000\r\n", body=b"x" * 40000))
    status, h, _ = r.response()
    assert status == 413 and h["connection"] == ["close"]
    s.sendall(b"y" * 5000)  # more request bytes after the answer: no RST must eat it


def test_trace_connect(bastion):
    srv = bastion(conf())
    s, r = open_reader(srv)
    s.sendall(req(method="TRACE"))
    status, h, _ = r.response()
    assert status == 405 and "GET" in h["allow"][0]
    s, r = open_reader(srv)
    s.sendall(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
    status, h, _ = r.response()
    assert status == 405 and "allow" in h


def test_chunked_request_body(bastion):
    srv = bastion(conf())
    s, r = open_reader(srv)
    s.sendall(req(method="POST", extra="Transfer-Encoding: chunked\r\n",
                  body=b"5\r\nhello\r\n6;x=y\r\n world\r\n0\r\nX-T: 1\r\n\r\n"))
    assert r.response()[0] == 200
    s.sendall(req())  # in step after the trailer section
    assert r.response()[0] == 200


def test_smuggling_is_refused(bastion):
    srv = bastion(conf())
    s, r = open_reader(srv)
    s.sendall(req(method="POST", extra="Content-Length: 5\r\nTransfer-Encoding: chunked\r\n",
                  body=b"0\r\n\r\n"))
    status, h, _ = r.response()
    assert status == 400 and h["connection"] == ["close"]
    assert r.closed()


def test_return_redirect_and_text(bastion):
    srv = bastion(conf(ret="return 301 /elsewhere;"))
    s, r = open_reader(srv)
    s.sendall(req())
    status, h, _ = r.response()
    assert status == 301 and h["location"] == ["/elsewhere"]


def test_graceful_stop_closes_idle(bastion):
    srv = bastion(conf())
    s, r = open_reader(srv)
    s.sendall(req())
    assert r.response()[0] == 200  # idle keep-alive connection
    t0 = time.monotonic()
    srv.proc.terminate()
    srv.proc.wait(10)
    assert time.monotonic() - t0 < 5  # did not wait out shutdown_timeout
    assert r.closed()
