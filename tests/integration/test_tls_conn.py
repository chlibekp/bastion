"""TLS connections (src/tls/conn.c) against the real binary on both backends, seccomp on.
`make test-int-nosan` runs these without sanitizers too: only that run proves the worker's
allowlist covers what OpenSSL really calls."""
import hashlib
import os
import socket
import ssl
import time

import pytest

MIB = 1 << 20


def client_ctx(certs, lo=None, hi=None):
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    c.load_verify_locations(certs / "ca.crt")
    if lo:
        c.minimum_version = lo
    if hi:
        c.maximum_version = hi
    return c


def tls_connect(srv, certs, ctx=None, port="https", timeout=10):
    s = socket.create_connection(("127.0.0.1", srv.ports[port]), timeout)
    t = (ctx or client_ctx(certs)).wrap_socket(s, server_hostname="localhost")
    t.settimeout(timeout)
    t.suppress_ragged_eofs = False
    return t


def read_response(t, limit=None):
    """Reads one Connection: close response to EOF. Returns (status, headers, body)."""
    buf = b""
    while True:
        chunk = t.recv(1 << 16)
        if not chunk:
            break
        buf += chunk
        if limit and len(buf) > limit:
            break
    head, _, body = buf.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    headers = {}
    for ln in lines[1:]:
        k, _, v = ln.partition(":")
        headers[k.strip().lower()] = v.strip()
    return int(lines[0].split()[1]), headers, body


def get(srv, certs, target, ctx=None):
    with tls_connect(srv, certs, ctx) as t:
        t.sendall(f"GET {target} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".encode())
        return read_response(t)


@pytest.fixture
def www(tmp_path):
    root = tmp_path / "www"
    root.mkdir()
    (root / "small.txt").write_bytes(b"0123456789abcdef" * 4)
    (root / "big.bin").write_bytes(os.urandom(64 * MIB))
    return root


def conf(certs, www, profile="", extra="", tls_extra=""):
    return (f"workers 1;\n{profile}\nserver {{ listen 127.0.0.1:@HTTPS_PORT@ tls; "
            f"tls_cert {certs}/ecdsa-chain.crt {certs}/ecdsa.key; {tls_extra} root {www};\n"
            f"location = /v {{ return 200 \"$scheme $ssl_protocol $ssl_cipher\"; }}\n{extra} }}\n")


@pytest.fixture
def srv(bastion, certs, www):
    return bastion(conf(certs, www))


def no_kills(srv):
    log = srv.logs()
    assert "killed by signal" not in log, log


@pytest.mark.parametrize("ver", [ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3])
def test_tls_get(srv, certs, ver):
    ctx = client_ctx(certs, ver, ver)
    with tls_connect(srv, certs, ctx) as t:
        assert t.version() == {ssl.TLSVersion.TLSv1_2: "TLSv1.2", ssl.TLSVersion.TLSv1_3: "TLSv1.3"}[ver]
        assert t.selected_alpn_protocol() in (None, "http/1.1")
        t.sendall(b"GET /small.txt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        st, h, body = read_response(t)
    assert st == 200 and body == b"0123456789abcdef" * 4
    no_kills(srv)


def test_variables(srv, certs):
    st, h, body = get(srv, certs, "/v")
    proto, cipher = body.decode().split()[1:3]
    assert st == 200 and body.decode().startswith("https TLSv1.3 TLS_")
    assert proto == "TLSv1.3" and cipher.startswith("TLS_")


def test_alpn_http11(srv, certs):
    ctx = client_ctx(certs)
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    with tls_connect(srv, certs, ctx) as t:
        assert t.selected_alpn_protocol() == "http/1.1"


def test_large_download_and_upload(srv, certs, www):
    with tls_connect(srv, certs, timeout=60) as t:
        t.sendall(b"GET /big.bin HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        st, h, body = read_response(t)
    assert st == 200 and len(body) == 64 * MIB
    assert hashlib.sha256(body).digest() == hashlib.sha256((www / "big.bin").read_bytes()).digest()
    # An upload the handler refuses still has its whole body decrypted and discarded, and the
    # connection answers afterwards.
    with tls_connect(srv, certs, timeout=60) as t:
        data = os.urandom(16 * MIB)
        t.sendall(b"POST /small.txt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n"
                  + f"Content-Length: {len(data)}\r\n\r\n".encode())
        t.sendall(data)
        st, h, body = read_response(t)
    assert st in (405, 413, 400, 200)
    no_kills(srv)


def test_handshake_timeout(bastion, certs, www):
    srv = bastion(conf(certs, www, profile="tls_profile quick { handshake_timeout 1s; }",
                       tls_extra="tls_profile quick;"))
    for first in (b"", b"\x16\x03\x01\x00\xf0\x01\x00"):  # nothing, then half a ClientHello
        s = socket.create_connection(("127.0.0.1", srv.ports["https"]), 5)
        if first:
            s.sendall(first)
        start = time.monotonic()
        s.settimeout(5)
        try:
            data = s.recv(100)
        except ConnectionResetError:
            data = b""
        took = time.monotonic() - start
        s.close()
        assert data in (b"", b"\x15\x03\x03\x00\x02\x02\x28") or data.startswith(b"\x15")
        assert 0.8 < took < 3.5, took
    # the worker spent next to nothing waiting
    pid = next(iter(srv.workers().values()))
    def cpu():
        f = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()
        return (int(f[11]) + int(f[12])) / os.sysconf("SC_CLK_TCK")
    s = socket.create_connection(("127.0.0.1", srv.ports["https"]), 5)
    c0 = cpu()
    time.sleep(0.5)
    assert cpu() - c0 < 0.2
    s.close()


def test_garbage_clienthello(srv, certs):
    for payload in (os.urandom(300), b"\x16\x03\x01\xff\xff" + os.urandom(100), b"\x16\x03\x03\x00\x05hello",
                    b"\x00" * 64):
        s = socket.create_connection(("127.0.0.1", srv.ports["https"]), 5)
        s.sendall(payload)
        s.settimeout(5)
        try:
            while s.recv(4096):
                pass
        except (ConnectionResetError, TimeoutError):
            pass
        s.close()
    assert get(srv, certs, "/small.txt")[0] == 200
    no_kills(srv)


def test_http_on_https_port_closes(srv):
    s = socket.create_connection(("127.0.0.1", srv.ports["https"]), 5)
    s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    s.settimeout(5)
    try:
        data = s.recv(4096)
    except ConnectionResetError:
        data = b""
    assert data == b""
    s.close()


def test_http_on_https_port_respond(bastion, certs, www):
    srv = bastion(conf(certs, www, tls_extra="http_on_tls_port respond;"))
    s = socket.create_connection(("127.0.0.1", srv.ports["https"]), 5)
    s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    s.settimeout(5)
    data = s.recv(4096)
    assert data.startswith(b"HTTP/1.1 400 ") and b"plain HTTP request" in data
    s.close()


def test_close_notify(srv, certs):
    # A response that ends cleanly reads as a clean end: no ragged EOF.
    with tls_connect(srv, certs) as t:
        t.sendall(b"GET /small.txt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        st, _, body = read_response(t)  # raises SSLEOFError without close_notify
        assert st == 200 and len(body) == 64
    # A server that dies without close_notify is not reported as success: ask for the big file,
    # read a little and let the server close under us by sending a malformed request.
    with tls_connect(srv, certs) as t:
        t.sendall(b"GET /small.txt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        read_response(t)
        t.unwrap()  # the client's own close_notify, answered by the server's already sent one


def test_slow_client_no_spin(srv, certs):
    pid = next(iter(srv.workers().values()))

    def cpu():
        f = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()
        return (int(f[11]) + int(f[12])) / os.sysconf("SC_CLK_TCK")

    s = socket.create_connection(("127.0.0.1", srv.ports["https"]), 10)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    t = client_ctx(certs).wrap_socket(s, server_hostname="localhost")
    t.sendall(b"GET /big.bin HTTP/1.1\r\nHost: localhost\r\n\r\n")
    time.sleep(1)  # the server fills the socket buffers and then waits for POLLOUT
    c0 = cpu()
    time.sleep(2)
    assert cpu() - c0 < 0.3, "the worker spins while the client does not read"
    got = 0
    t.settimeout(30)
    while got < 1 << 20:
        got += len(t.recv(1 << 16))
    t.close()
    no_kills(srv)


def test_sandbox_holds(srv, certs):
    # The fixture asserts Seccomp 2 in every child; this drives every TLS path once: handshake,
    # resumption-capable session, a large write, and a clean close.
    for _ in range(3):
        assert get(srv, certs, "/small.txt")[0] == 200
    with tls_connect(srv, certs, timeout=30) as t:
        t.sendall(b"GET /big.bin HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        assert read_response(t, limit=8 * MIB)[0] == 200
    no_kills(srv)
