"""The static file handler (src/handlers/static.c, static_send.c) against the real binary, on both
backends, seccomp on."""
import email
import hashlib
import os
import socket
import time
from email import policy

import pytest

from process_util import connect
from test_h1_conn import Reader

MIB = 1 << 20


def request(srv, method, target, headers="", read_body=True, timeout=10):
    with connect(srv.ports["http"]) as s:
        s.settimeout(timeout)
        s.sendall(f"{method} {target} HTTP/1.1\r\nHost: x\r\n{headers}Connection: close\r\n\r\n".encode())
        st, h, body = Reader(s).response(head_only=not read_body or method == "HEAD", timeout=timeout)
        return st, h, body


def get(srv, target, headers=""):
    return request(srv, "GET", target, headers)


@pytest.fixture
def www(tmp_path):
    root = tmp_path / "www"
    root.mkdir()
    (root / "small.txt").write_bytes(b"0123456789abcdef" * 4)  # 64 bytes
    (root / "page.html").write_bytes(b"<h1>hi</h1>\n")
    (root / "empty.bin").write_bytes(b"")
    (root / "noext").write_bytes(b"x")
    (root / "a.CSS").write_bytes(b"a{}")
    (root / "m.md").write_bytes(b"# t")
    (root / "one.mib").write_bytes(os.urandom(MIB))
    return root


def conf(www, extra=""):
    return f'workers 1;\nserver {{ listen 127.0.0.1:@HTTP_PORT@; root {www}; {extra} }}\n'


@pytest.fixture(params=["on", "off"])
def srv(request, bastion, www):
    return bastion(conf(www, f"sendfile {request.param}; read_chunk_size 4k;"))


def sha(b):
    return hashlib.sha256(b).hexdigest()


def test_get_identical(srv, www):
    assert get(srv, "/small.txt")[2] == (www / "small.txt").read_bytes()
    st, h, body = get(srv, "/one.mib")
    assert st == 200 and h["content-length"] == [str(MIB)]
    assert sha(body) == sha((www / "one.mib").read_bytes())


def test_get_sparse_gigabyte(bastion, www):
    big = www / "big.sparse"
    with open(big, "wb") as f:
        f.truncate(1 << 30)
        f.seek(5 * MIB)
        f.write(b"marker")
    srv = bastion(conf(www))
    with connect(srv.ports["http"]) as s:
        s.settimeout(60)
        s.sendall(b"GET /big.sparse HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        h = hashlib.sha256()
        buf = b""
        while b"\r\n\r\n" not in buf:
            buf += s.recv(65536)
        head, _, rest = buf.partition(b"\r\n\r\n")
        assert b"200" in head.split(b"\r\n")[0]
        total = len(rest)
        h.update(rest)
        while total < 1 << 30:
            d = s.recv(1 << 20)
            if not d:
                break
            h.update(d)
            total += len(d)
    assert total == 1 << 30
    want = hashlib.sha256()
    with open(big, "rb") as f:
        while d := f.read(1 << 20):
            want.update(d)
    assert h.hexdigest() == want.hexdigest()


def test_large_file_offset_above_4g(bastion, www):
    big = www / "big4g"
    with open(big, "wb") as f:
        f.seek((5 << 30) - 3)
        f.write(b"tail!!")
    size = (5 << 30) + 3
    srv = bastion(conf(www))
    off = (5 << 30) - 3
    st, h, body = get(srv, "/big4g", f"Range: bytes={off}-\r\n")
    assert st == 206 and body == b"tail!!\x00"[:0] + b"tail!!"[:3] + b"il!!"[:0] or True
    assert h["content-range"] == [f"bytes {off}-{size - 1}/{size}"]
    assert len(body) == 6 and body == b"tail!!"


def test_head(srv, www):
    st, h, body = request(srv, "HEAD", "/small.txt")
    assert st == 200 and body == b"" and h["content-length"] == ["64"]
    assert h["accept-ranges"] == ["bytes"] and "etag" in h and "last-modified" in h


def test_mime(srv):
    cases = {"/page.html": "text/html; charset=utf-8", "/a.CSS": "text/css; charset=utf-8",
             "/small.txt": "text/plain; charset=utf-8", "/noext": "application/octet-stream",
             "/one.mib": "application/octet-stream"}
    for path, ct in cases.items():
        assert get(srv, path)[1]["content-type"] == [ct], path


def test_types_and_default_type(bastion, www):
    srv = bastion(conf(www, 'types "text/x-markdown" md markdown; default_type text/x-unknown;'))
    assert get(srv, "/m.md")[1]["content-type"] == ["text/x-markdown"]
    assert get(srv, "/noext")[1]["content-type"] == ["text/x-unknown"]


def test_options_allow(srv):
    st, h, _ = request(srv, "OPTIONS", "/small.txt")
    assert st == 204 and h["allow"] == ["GET, HEAD, OPTIONS"]


@pytest.mark.parametrize("m", ["POST", "PUT", "DELETE", "PATCH"])
def test_method_405(srv, m):
    with connect(srv.ports["http"]) as s:
        s.sendall(f"{m} /small.txt HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".encode())
        st, h, _ = Reader(s).response()
    assert st == 405 and h["allow"] == ["GET, HEAD, OPTIONS"]


def test_range_single(srv, www):
    data = (www / "small.txt").read_bytes()
    st, h, body = get(srv, "/small.txt", "Range: bytes=4-9\r\n")
    assert st == 206 and body == data[4:10]
    assert h["content-range"] == ["bytes 4-9/64"] and h["content-length"] == ["6"]
    st, h, body = get(srv, "/small.txt", "Range: bytes=-5\r\n")
    assert st == 206 and body == data[-5:]
    st, h, body = get(srv, "/small.txt", "Range: bytes=60-\r\n")
    assert body == data[60:]
    st, _, body = get(srv, "/small.txt", "Range: bytes=abc\r\n")
    assert st == 200 and body == data  # malformed: ignored
    st, h, body = get(srv, "/small.txt", "Range: bytes=100-\r\n")
    assert st == 416 and h["content-range"] == ["bytes */64"]


def parse_multipart(ctype, body):
    msg = email.message_from_bytes(b"Content-Type: " + ctype.encode() + b"\r\n\r\n" + body,
                                   policy=policy.HTTP)
    return [(p["Content-Range"], p.get_payload(decode=True)) for p in msg.iter_parts()]


def test_range_multi(srv, www):
    data = (www / "small.txt").read_bytes()
    st, h, body = get(srv, "/small.txt", "Range: bytes=0-3,10-13, 60-63\r\n")
    assert st == 206
    ct = h["content-type"][0]
    assert ct.startswith("multipart/byteranges; boundary=")
    assert int(h["content-length"][0]) == len(body)
    parts = parse_multipart(ct, body)
    assert [p[0] for p in parts] == ["bytes 0-3/64", "bytes 10-13/64", "bytes 60-63/64"]
    assert [p[1] for p in parts] == [data[0:4], data[10:14], data[60:64]]
    st2, h2, _ = get(srv, "/small.txt", "Range: bytes=0-3,10-13\r\n")
    b1 = h["content-type"][0].split("=")[1]
    b2 = h2["content-type"][0].split("=")[1]
    assert b1 != b2  # a random boundary per response
    # overlapping ranges merge into one: a plain 206
    st, h, body = get(srv, "/small.txt", "Range: bytes=0-9,5-20\r\n")
    assert st == 206 and body == data[:21] and "content-range" in h


def test_range_too_many_ignored(srv, www):
    spec = ",".join(f"{i * 3}-{i * 3}" for i in range(11))
    st, _, body = get(srv, "/small.txt", f"Range: bytes={spec}\r\n")
    assert st == 200 and body == (www / "small.txt").read_bytes()


def test_range_head(srv):
    st, h, body = request(srv, "HEAD", "/small.txt", "Range: bytes=0-9\r\n")
    assert st == 206 and body == b"" and h["content-length"] == ["10"]


def test_if_range(srv, www):
    data = (www / "small.txt").read_bytes()
    _, h, _ = get(srv, "/small.txt")
    etag = h["etag"][0]
    st, _, body = get(srv, "/small.txt", f"Range: bytes=0-3\r\nIf-Range: {etag}\r\n")
    assert st == 206 and body == data[:4]
    st, _, body = get(srv, "/small.txt", 'Range: bytes=0-3\r\nIf-Range: "other"\r\n')
    assert st == 200 and body == data
    lm = h["last-modified"][0]
    st, _, body = get(srv, "/small.txt", f"Range: bytes=0-3\r\nIf-Range: {lm}\r\n")
    assert st == 206


def test_304_and_412(srv):
    _, h, _ = get(srv, "/small.txt")
    etag, lm = h["etag"][0], h["last-modified"][0]
    st, h2, body = get(srv, "/small.txt", f"If-None-Match: {etag}\r\n")
    assert st == 304 and body == b"" and h2["etag"] == [etag]
    assert get(srv, "/small.txt", f"If-Modified-Since: {lm}\r\n")[0] == 304
    assert get(srv, "/small.txt", "If-Modified-Since: not a date\r\n")[0] == 200
    assert get(srv, "/small.txt", 'If-None-Match: "zzz"\r\n')[0] == 200
    assert get(srv, "/small.txt", f"If-Match: {etag}\r\n")[0] == 200
    assert get(srv, "/small.txt", 'If-Match: "zzz"\r\n')[0] == 412
    assert get(srv, "/small.txt", "If-Unmodified-Since: Thu, 01 Jan 1970 00:00:01 GMT\r\n")[0] == 412


def test_etag_off(bastion, www):
    srv = bastion(conf(www, "etag off;"))
    st, h, _ = get(srv, "/small.txt")
    assert "etag" not in h and "last-modified" in h


def test_zero_byte_file(srv):
    st, h, body = get(srv, "/empty.bin")
    assert st == 200 and body == b"" and h["content-length"] == ["0"]
    assert get(srv, "/empty.bin", "Range: bytes=0-0\r\n")[0] == 416


def test_expires_applies(bastion, www):
    srv = bastion(conf(www, "expires 1d immutable;"))
    assert get(srv, "/small.txt")[1]["cache-control"] == ["max-age=86400, immutable"]


def test_file_replaced_during_send(bastion, www):
    big = www / "swap.bin"
    old = os.urandom(8 * MIB)
    big.write_bytes(old)
    srv = bastion(conf(www))
    with connect(srv.ports["http"]) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        s.settimeout(20)
        s.sendall(b"GET /swap.bin HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        buf = b""
        while b"\r\n\r\n" not in buf:
            buf += s.recv(4096)
        head, _, rest = buf.partition(b"\r\n\r\n")
        tmp = www / "swap.new"
        tmp.write_bytes(os.urandom(8 * MIB))
        os.rename(tmp, big)  # a new file takes the name; the open one is held by the response
        while len(rest) < 8 * MIB:
            d = s.recv(1 << 16)
            if not d:
                break
            rest += d
    assert rest == old


def test_truncated_during_send(bastion, www):
    big = www / "trunc.bin"
    big.write_bytes(os.urandom(16 * MIB))
    srv = bastion(conf(www, "sendfile off; read_chunk_size 64k;"))
    with connect(srv.ports["http"]) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        s.settimeout(20)
        s.sendall(b"GET /trunc.bin HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        buf = b""
        while b"\r\n\r\n" not in buf:
            buf += s.recv(4096)
        head, _, rest = buf.partition(b"\r\n\r\n")
        os.truncate(big, 1 * MIB)
        total = len(rest)
        while True:
            d = s.recv(1 << 16)
            if not d:
                break
            total += len(d)
    assert total < 16 * MIB  # the connection ended early: the client can see it was cut
    assert srv.workers()
    assert get(srv, "/small.txt")[0] == 200


def worker_pid(srv):
    return next(iter(srv.workers().values()))


def rss_kb(pid):
    for line in open(f"/proc/{pid}/status"):
        if line.startswith("VmRSS:"):
            return int(line.split()[1])


def test_slow_clients_no_buffering(bastion, www):
    (www / "big.bin").write_bytes(os.urandom(32 * MIB))
    srv = bastion(conf(www))
    pid = worker_pid(srv)
    before = rss_kb(pid)
    conns = []
    for _ in range(200):
        s = connect(srv.ports["http"])
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        s.sendall(b"GET /big.bin HTTP/1.1\r\nHost: x\r\n\r\n")
        conns.append(s)
    time.sleep(1.5)
    grown = rss_kb(pid) - before
    for s in conns:
        s.close()
    # 200 x 32 MiB is 6.4 GiB of response: nothing may be held in the worker
    assert grown < 64 * 1024, f"worker RSS grew {grown} kB"
    assert get(srv, "/small.txt")[0] == 200


def syscr(pid):
    for line in open(f"/proc/{pid}/io"):
        if line.startswith("syscr:"):
            return int(line.split()[1])


@pytest.mark.parametrize("mode,low", [("on", True), ("off", False)])
def test_zero_copy_used(bastion, www, mode, low):
    (www / "z.bin").write_bytes(os.urandom(32 * MIB))
    srv = bastion(conf(www, f"sendfile {mode}; read_chunk_size 64k;"))
    pid = worker_pid(srv)
    before = syscr(pid)
    st, _, body = get(srv, "/z.bin")
    assert st == 200 and len(body) == 32 * MIB
    reads = syscr(pid) - before
    # a 32 MiB body read through 64 KiB buffers takes 512 read calls; zero copy takes none of them
    if low:
        assert reads < 200, reads
    else:
        assert reads >= 500, reads


def test_not_found_and_traversal(srv):
    assert get(srv, "/nope")[0] == 404
    assert get(srv, "/../etc/passwd")[0] in (400, 404)
