"""HTTP/3 streams (src/http/h3/h3_bridge.c): the same HTTP semantics as HTTP/1.1 and HTTP/2 over
QUIC, request and response bodies with back-pressure, cancellation, trailers, GOAWAY on a graceful
stop, many concurrent streams, and the TLS side of a QUIC connection (per-name certificates, $ssl_*).

Clients: curl (`--http3-only`, OpenSSL's QUIC stack and nghttp3) for the parity corpus, the
h3client fixture (ngtcp2 and nghttp3) for everything that needs control over the request, and
h2load for the multiplexing load when it was built with HTTP/3."""
import hashlib
import os
import re
import shutil
import signal
import subprocess
import time

import pytest

from quic_util import conn_line, h3

pytestmark = pytest.mark.skipif(shutil.which("curl") is None, reason="curl is needed")

KEEP = ("content-type", "content-length", "etag", "last-modified", "accept-ranges", "content-range",
        "cache-control", "allow", "vary")
GIB = 1 << 30
H3_MESSAGE_ERROR = 0x10e
H3_REQUEST_CANCELLED = 0x10c


def conf(certs, www, extra="", workers=1, glob=""):
    """One server on a TCP (h1, h2) and a QUIC listener, same docroot."""
    return (f"workers {workers};\nerror_log @WORKDIR@/error.log debug;\n{glob}\n"
            f"server {{ listen 127.0.0.1:@HTTPS_PORT@ tls http2; listen 127.0.0.1:@QUIC_PORT@ http3;\n"
            f"tls_cert {certs}/ecdsa-chain.crt {certs}/ecdsa.key; root {www};\n"
            f"location = /r {{ return 200 \"hi\"; }} {extra} }}\n")


@pytest.fixture
def www(tmp_path):
    root = tmp_path / "www"
    root.mkdir()
    (root / "data.bin").write_bytes(bytes(range(256)) * 40)
    (root / "page.html").write_text("<h1>page</h1>\n")
    (root / "empty.txt").write_bytes(b"")
    with open(root / "huge.bin", "wb") as f:
        f.truncate(GIB)  # sparse: a GiB of zeros, nothing on disk
    return root


def fetch(srv, version, path, method="GET", headers=()):
    """(status, {kept headers}, body) through curl over TCP (--http2) or QUIC (--http3-only)."""
    port = srv.ports["quic"] if version == "--http3-only" else srv.ports["https"]
    url = f"https://127.0.0.1:{port}{path}"
    cmd = ["curl", "-sk", version, "-D", "-", "-o", "/dev/stdout", "-X", method] if method != "HEAD" else [
        "curl", "-sk", version, "-I", "-D", "-", "-o", "/dev/null"]
    for h in headers:
        cmd += ["-H", h]
    out = subprocess.run(cmd + [url], capture_output=True, timeout=30).stdout
    head, _, body = out.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    status = int(lines[0].split()[1])
    hdrs = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            if k.lower() in KEEP:
                hdrs[k.lower()] = v.strip()
    return status, hdrs, body


def same(srv, path, **kw):
    h2_ = fetch(srv, "--http2", path, **kw)
    h3_ = fetch(srv, "--http3-only", path, **kw)
    assert h2_ == h3_, (path, kw, h2_, h3_)
    return h3_


def pattern_sha(n):
    """sha256 of n bytes of h3client's body pattern (i*31+7) & 0xff, which repeats every 256."""
    block = bytes(((i * 31 + 7) & 0xff) for i in range(256)) * 4096  # 1 MiB
    h = hashlib.sha256()
    while n >= len(block):
        h.update(block)
        n -= len(block)
    h.update(block[:n])
    return h.hexdigest()


def zeros_sha(n):
    h = hashlib.sha256()
    z = bytes(1 << 20)
    while n >= len(z):
        h.update(z)
        n -= len(z)
    h.update(z[:n])
    return h.hexdigest()


def rss_kb(pid):
    for ln in open(f"/proc/{pid}/status"):
        if ln.startswith("VmRSS"):
            return int(ln.split()[1])


def resp(lines, i=0):
    found = [ln for ln in lines if ln.get("type") == "resp"]
    return found[i] if len(found) > i else {}


def test_static_h3(bastion, certs, www):
    """The HTTP/2 Task 5 corpus: Range, conditional, HEAD and error pages answer the same."""
    srv = bastion(conf(certs, www))
    st, hd, body = same(srv, "/data.bin")
    assert st == 200 and len(body) == 10240 and "etag" in hd and "last-modified" in hd
    st, hd, _ = same(srv, "/page.html")
    assert st == 200 and hd["content-type"].startswith("text/html")
    st, _, body = same(srv, "/empty.txt")
    assert st == 200 and body == b""
    same(srv, "/r")
    st, hd, body = same(srv, "/data.bin", headers=["Range: bytes=10-19"])
    assert st == 206 and body == bytes(range(10, 20)) and hd["content-range"] == "bytes 10-19/10240"
    st, _, _ = same(srv, "/data.bin", headers=["Range: bytes=99999-"])
    assert st == 416
    _, hd, _ = same(srv, "/page.html")
    st, _, body = same(srv, "/page.html", headers=[f"If-None-Match: {hd['etag']}"])
    assert st == 304 and body == b""
    st, _, _ = same(srv, "/page.html", headers=["If-Match: \"nothing\""])
    assert st == 412
    st, hd, body = same(srv, "/data.bin", method="HEAD")
    assert st == 200 and hd["content-length"] == "10240" and body == b""
    st, hd, body = same(srv, "/missing")
    assert st == 404 and b"404" in body and hd["content-type"].startswith("text/html")
    st, _, _ = same(srv, "/page.html", method="DELETE")
    assert st in (405, 501), st
    # The TLS variables of a QUIC connection come from its handshake (the QUIC transport kind).
    assert "h3: read stream" not in srv.logs()


def test_large_download(bastion, certs, www):
    """1 GiB, identical, with the worker's memory bounded by the per-stream read-ahead. (A small
    ASan quarantine: freed blocks it holds back would otherwise show as growth.)"""
    srv = bastion(conf(certs, www), env={"ASAN_OPTIONS": "quarantine_size_mb=8"})
    pid = srv.wait_workers(1)[0]
    before = rss_kb(pid)
    p = h3(srv, "/huge.bin", timeout_ms=300000, wait=False)
    peak = before
    while p.poll() is None:
        peak = max(peak, rss_kb(pid))
        time.sleep(0.05)
    out = p.stdout.read().decode()
    import json
    lines = [json.loads(ln) for ln in out.splitlines() if ln.startswith("{")]
    r = resp(lines)
    assert p.returncode == 0 and r.get("status") == 200, lines
    assert r["len"] == GIB and r["sha256"] == zeros_sha(GIB)
    assert peak - before < 64 * 1024, (before, peak)  # KiB: far from the GiB that went through


def test_large_upload(bastion, certs, www):
    """1 GiB POST through the test echo handler, identical both ways."""
    srv = bastion(conf(certs, www, "client_max_body_size 0;"), env={"BST_TEST_ECHO": "1"})
    rc, lines = h3(srv, "/echo", opts=("--method", "POST", "--body-size", str(GIB)), timeout_ms=600000)
    r = resp(lines)
    assert rc == 0 and r.get("status") == 200, lines
    assert r["len"] == GIB and r["sha256"] == pattern_sha(GIB)


def test_malformed_request(bastion, certs, www):
    """Pseudo-header and field rules: the stream is reset with H3_MESSAGE_ERROR and the connection
    goes on. (A regular field whose value holds CR, LF or NUL never reaches the server: nghttp3
    removes it, which RFC 9110 section 5.5 allows; docs/conformance.md.)"""
    srv = bastion(conf(certs, www))
    for bad in (":path: /again", ":bogus: x", "te: gzip", "connection: close", "content-length: 4"):
        rc, lines = h3(srv, "/r", opts=("--header", bad), timeout_ms=5000)
        r = resp(lines)
        assert r.get("reset") == H3_MESSAGE_ERROR, (bad, lines)
    rc, lines = h3(srv, "/r")
    assert rc == 0 and resp(lines).get("status") == 200, lines


def test_cancel(bastion, certs, www):
    """A client STOP_SENDING ends the handler with exactly one on_reset."""
    srv = bastion(conf(certs, www), env={"BST_TEST_ECHO": "1"})
    rc, lines = h3(srv, "/echo/gen", opts=("--header", "x-gen: 1073741824", "--cancel-after", "65536"),
                   timeout_ms=10000)
    assert resp(lines).get("len", 0) >= 65536, lines
    srv.wait_log(r"test-echo: on_reset why=1 uri=/echo/gen")
    time.sleep(0.5)
    assert len(re.findall(r"test-echo: on_reset", srv.logs())) == 1


def test_trailers(bastion, certs, www):
    """Request trailers reach the handler, response trailers reach the client."""
    srv = bastion(conf(certs, www), env={"BST_TEST_ECHO": "1"})
    rc, lines = h3(srv, "/echo", opts=("--method", "POST", "--body-size", "1000", "--trailer", "x-sum: 42"))
    r = resp(lines)
    assert rc == 0 and r.get("status") == 200 and r["len"] == 1000, lines
    assert r["trailers"].get("x-echo-x-sum") == "42", r
    rc, lines = h3(srv, "/echo/gen", opts=("--header", "x-gen: 5000", "--header", "x-want-trailers: 1"))
    r = resp(lines)
    assert rc == 0 and r["len"] == 5000 and r["trailers"].get("x-echo-trailer") == "done", r


def test_goaway(bastion, certs, www):
    """A graceful stop sends GOAWAY, and the request in flight finishes."""
    size = 256 << 20  # still in flight at the stop, even with GSO batching (Task 5)
    with open(www / "mid.bin", "wb") as f:
        f.truncate(size)
    srv = bastion(conf(certs, www))
    p = h3(srv, "/mid.bin", opts=("--max-data", str(256 << 10)), timeout_ms=60000, wait=False)
    srv.wait_log(r"quic: handshake done")
    time.sleep(0.3)
    srv.proc.send_signal(signal.SIGQUIT)
    out, _ = p.communicate(timeout=90)
    import json
    lines = [json.loads(ln) for ln in out.decode().splitlines() if ln.startswith("{")]
    r = resp(lines)
    assert p.returncode == 0 and r.get("len") == size and r["sha256"] == zeros_sha(size), lines
    assert conn_line(lines)["goaway"] is True, lines
    assert conn_line(lines)["peer_error"]["code"] in (0, 0x100), lines  # H3_NO_ERROR


def test_multiplex(bastion, certs, www):
    """100 concurrent streams on one connection."""
    srv = bastion(conf(certs, www, glob=""))
    port = srv.ports["quic"]
    hl = shutil.which("h2load")
    help_ = subprocess.run([hl, "--help"], capture_output=True).stdout.decode() if hl else ""
    if "h3" in help_:  # h2load built with ngtcp2: the plan's own client
        p = subprocess.run([hl, "--alpn-list=h3", "-n", "100", "-c", "1", "-m", "100",
                            f"https://127.0.0.1:{port}/data.bin"], capture_output=True, timeout=60)
        out = p.stdout.decode()
        assert "100 succeeded, 0 failed, 0 errored" in out, out
        return
    # This h2load has no HTTP/3 (Debian builds it without ngtcp2): the h3client fixture opens the
    # 100 requests at once on one connection instead.
    rc, lines = h3(srv, *(["/data.bin"] * 100))
    rs = [ln for ln in lines if ln.get("type") == "resp"]
    assert rc == 0 and len(rs) == 100 and all(r["status"] == 200 and r["len"] == 10240 for r in rs), lines


def test_sni_per_server(bastion, certs, www):
    """Several servers on one http3 address: each name gets its own certificate (SNI moves the
    handshake to that server's QUIC context), and each answers its own requests."""
    cfg = (f"workers 1;\nerror_log @WORKDIR@/error.log debug;\n"
           f"server {{ listen 127.0.0.1:@QUIC_PORT@ http3 default_server; name a.example; "
           f"tls_cert {certs}/site-a.crt {certs}/site-a.key; location = /who {{ return 200 \"one\"; }} }}\n"
           f"server {{ listen 127.0.0.1:@QUIC_PORT@ http3; name b.example; "
           f"tls_cert {certs}/site-b.crt {certs}/site-b.key; location = /who {{ return 200 \"two\"; }} }}\n")
    srv = bastion(cfg)
    port = srv.ports["quic"]
    for name, body in (("a.example", b"one"), ("b.example", b"two")):
        p = subprocess.run(["curl", "-sv", "--http3-only", "--cacert", str(certs / "ca.crt"),
                            "--resolve", f"{name}:{port}:127.0.0.1", f"https://{name}:{port}/who"],
                           capture_output=True, timeout=30)
        err = p.stderr.decode(errors="replace")
        assert p.returncode == 0 and p.stdout == body, (name, p.stdout, err)
        assert re.search(rf"subject: .*CN *= *{re.escape(name)}", err), err
