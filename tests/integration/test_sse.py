"""Server-sent events through the proxy (Phase 9, Task 7): each event reaches the client as it is
sent, with no buffering, on HTTP/1.1, HTTP/2 and HTTP/3."""
import json
import shutil
import socket
import subprocess
import threading
import time

import pytest

from upstream_util import Upstream

EVENTS = 5
GAP = 0.3


def sse_handler(times):
    def h(req, c):
        c.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"
                  b"Cache-Control: no-cache\r\nTransfer-Encoding: chunked\r\n\r\n")
        for i in range(EVENTS):
            ev = f"data: event {i}\n\n".encode()
            times.append(time.monotonic())
            c.sendall(b"%x\r\n" % len(ev) + ev + b"\r\n")
            time.sleep(GAP)
        c.sendall(b"0\r\n\r\n")
        return None
    return h


def check(sent, seen):
    assert len(seen) == EVENTS, seen
    for i in range(EVENTS):
        lag = seen[i] - sent[i]
        assert lag < 0.05, f"event {i} took {lag * 1000:.0f} ms"


def test_sse_no_buffering_h1(bastion):
    sent = []
    u = Upstream(sse_handler(sent))
    try:
        srv = bastion(f"workers 1;\nserver {{ listen 127.0.0.1:@HTTP_PORT@; "
                      f"location / {{ proxy {u.url}; }} }}\n")
        s = socket.create_connection(("127.0.0.1", srv.ports["http"]), 10)
        s.sendall(b"GET /events HTTP/1.1\r\nHost: a\r\nAccept: text/event-stream\r\n"
                  b"Connection: close\r\n\r\n")
        seen, data = [], b""
        while len(seen) < EVENTS:
            d = s.recv(65536)
            if not d:
                break
            data += d
            now = time.monotonic()
            while data.count(b"\n\n") > len(seen):  # each complete event, as it arrives
                seen.append(now)
        s.close()
        check(sent, seen)
    finally:
        u.close()


@pytest.mark.skipif(shutil.which("curl") is None, reason="curl is needed")
def test_sse_no_buffering_h2(bastion, certs):
    sent = []
    u = Upstream(sse_handler(sent))
    try:
        srv = bastion(f"workers 1;\nserver {{ listen 127.0.0.1:@HTTPS_PORT@ tls http2; "
                      f"tls_cert {certs}/ecdsa-chain.crt {certs}/ecdsa.key;\n"
                      f"location / {{ proxy {u.url}; }} }}\n")
        p = subprocess.Popen(["curl", "-sk", "-N", "--http2",
                              f"https://127.0.0.1:{srv.ports['https']}/events"],
                             stdout=subprocess.PIPE)
        seen = []
        for line in p.stdout:
            if line.startswith(b"data: event"):
                seen.append(time.monotonic())
            if len(seen) == EVENTS:
                break
        p.kill()
        p.wait()
        check(sent, seen)
    finally:
        u.close()


def test_sse_no_buffering_h3(bastion, certs):
    from quic_util import h3client_bin
    sent = []
    u = Upstream(sse_handler(sent))
    try:
        srv = bastion(f"workers 1;\nserver {{ listen 127.0.0.1:@QUIC_PORT@ http3; "
                      f"tls_cert {certs}/ecdsa-chain.crt {certs}/ecdsa.key;\n"
                      f"location / {{ proxy {u.url}; }} }}\n")
        p = subprocess.Popen([h3client_bin(), "--timeout", "10000", "--chunks", "127.0.0.1",
                              str(srv.ports["quic"]), "/events"], stdout=subprocess.PIPE)
        seen, data = [], ""
        for line in p.stdout:  # one line per piece of body, printed as it arrives
            if not line.startswith(b'{"type":"chunk"'):
                continue
            data += json.loads(line)["data"]
            now = time.monotonic()
            while data.count("\n\n") > len(seen):
                seen.append(now)
            if len(seen) == EVENTS:
                break
        p.kill()
        p.wait()
        check(sent, seen)
    finally:
        u.close()
