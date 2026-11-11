"""$ja4 (src/tls/ja4.c): the fingerprint the server logs equals one computed independently, in
Python from the ClientHello bytes the same client puts on the wire."""
import hashlib
import socket
import ssl
import threading

import pytest

from test_tls_conn import client_ctx, read_response


def grease(v):
    return (v & 0x0F0F) == 0x0A0A and (v >> 8) == (v & 0xFF)


def ja4_reference(msg):
    """JA4 of a ClientHello handshake message, from technical_details/JA4.md; written
    independently of src/tls/ja4.c."""
    p = 4 + 2 + 32
    p += 1 + msg[p]
    cl = int.from_bytes(msg[p:p + 2], "big")
    ciphers = [int.from_bytes(msg[p + 2 + i:p + 4 + i], "big") for i in range(0, cl, 2)]
    p += 2 + cl
    p += 1 + msg[p]
    exts, end = [], len(msg)
    p += 2
    while p < end:
        t = int.from_bytes(msg[p:p + 2], "big")
        n = int.from_bytes(msg[p + 2:p + 4], "big")
        exts.append((t, msg[p + 4:p + 4 + n]))
        p += 4 + n
    ciphers = [c for c in ciphers if not grease(c)]
    types = [t for t, _ in exts if not grease(t)]
    body = dict(exts)
    version = int.from_bytes(msg[4:6], "big")
    if 0x2B in body:
        vs = [int.from_bytes(body[0x2B][1 + i:3 + i], "big") for i in range(0, body[0x2B][0], 2)]
        version = max(v for v in vs if not grease(v))
    ver = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10"}.get(version, "00")
    alpn = "00"
    if 0x10 in body and len(body[0x10]) > 3:
        name = body[0x10][3:3 + body[0x10][2]]
        alpn = chr(name[0]) + chr(name[-1])
    sigs = []
    if 0x0D in body:
        b = body[0x0D]
        sigs = [f"{int.from_bytes(b[2 + i:4 + i], 'big'):04x}" for i in range(0, len(b) - 2, 2)
                if not grease(int.from_bytes(b[2 + i:4 + i], "big"))]
    h = lambda s: hashlib.sha256(s.encode()).hexdigest()[:12]
    cs = ",".join(f"{c:04x}" for c in sorted(ciphers))
    es = ",".join(f"{t:04x}" for t in sorted(types) if t not in (0, 0x10))
    if sigs or 0x0D in body:
        es += "_" + ",".join(sigs)
    return (f"t{ver}{'d' if 0 in body else 'i'}{min(len(ciphers), 99):02d}{min(len(types), 99):02d}"
            f"{alpn}_{h(cs) if cs else '0' * 12}_{h(es) if es else '0' * 12}")


def captured_hello(ctx, sni):
    """The ClientHello message ctx sends, caught by a listener that never answers."""
    ls = socket.socket()
    ls.bind(("127.0.0.1", 0))
    ls.listen(1)
    got = []

    def serve():
        c, _ = ls.accept()
        c.settimeout(5)
        data = b""
        while len(data) < 5 or len(data) < 5 + int.from_bytes(data[3:5], "big"):
            d = c.recv(4096)
            if not d:
                break
            data += d
        got.append(data[5:5 + int.from_bytes(data[3:5], "big")])
        c.close()

    th = threading.Thread(target=serve)
    th.start()
    s = socket.create_connection(ls.getsockname(), 5)
    try:
        ctx.wrap_socket(s, server_hostname=sni)
    except (ssl.SSLError, OSError):
        pass
    th.join(10)
    ls.close()
    return got[0]


def conf(certs, on=True):
    return (f"workers 1;\nserver {{ listen 127.0.0.1:@HTTPS_PORT@ tls; "
            f"tls_cert {certs}/ecdsa-chain.crt {certs}/ecdsa.key; {'tls_ja4 on;' if on else ''}\n"
            f'location / {{ return 200 "$ja4"; }} }}\n')


def fetch(srv, ctx):
    s = socket.create_connection(("127.0.0.1", srv.ports["https"]), 10)
    t = ctx.wrap_socket(s, server_hostname="localhost")
    t.settimeout(10)
    t.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
    st, _, body = read_response(t)
    t.close()
    return st, body.decode()


def variants(certs):
    both = client_ctx(certs)
    tls12 = client_ctx(certs, ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2)
    alpn = client_ctx(certs)
    alpn.set_alpn_protocols(["http/1.1"])
    return {"default": both, "tls12": tls12, "alpn": alpn}


def test_ja4_var(bastion, certs):
    srv = bastion(conf(certs))
    seen = set()
    for name, ctx in variants(certs).items():
        want = ja4_reference(captured_hello(ctx, "localhost"))
        st, got = fetch(srv, ctx)
        assert st == 200 and got == want, name
        seen.add(got)
    assert len(seen) == 3  # three different clients, three fingerprints


def test_ja4_off_by_default(bastion, certs):
    srv = bastion(conf(certs, on=False))
    assert fetch(srv, client_ctx(certs)) == (200, "")


def test_ja4_stable_across_connections(bastion, certs):
    srv = bastion(conf(certs))
    ctx = client_ctx(certs)
    assert len({fetch(srv, ctx)[1] for _ in range(4)}) == 1
