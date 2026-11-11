"""SNI certificate selection and the host mismatch policy (src/tls/sni.c)."""
import socket
import ssl
import subprocess

import pytest

from test_tls_conn import client_ctx, read_response


def site(certs, name, cert, default=False, extra=""):
    flags = " default_server" if default else ""
    return (f'server {{ listen 127.0.0.1:@HTTPS_PORT@ tls{flags}; name {name};\n'
            f'  tls_cert {certs}/{cert}.crt {certs}/{cert}.key; {extra}\n'
            f'  location / {{ return 200 "{name}"; }} }}\n')


def conf(certs, default_extra="", a_extra=""):
    return ("workers 1;\n" + site(certs, "default.example", "default", True, default_extra)
            + site(certs, "a.example", "site-a", extra=a_extra) + site(certs, "b.example", "site-b")
            + site(certs, "*.wild.example", "wild"))


def handshake(srv, certs, sni, host=None, send=True):
    """Connects, returns (peer CN, status, body). sni None sends no server_name."""
    ctx = client_ctx(certs)
    ctx.check_hostname = False
    s = socket.create_connection(("127.0.0.1", srv.ports["https"]), 10)
    t = ctx.wrap_socket(s, server_hostname=sni)
    cn = dict(x[0] for x in t.getpeercert()["subject"])["commonName"]
    st = body = None
    if send:
        t.sendall(f"GET / HTTP/1.1\r\nHost: {host or sni or 'x'}\r\nConnection: close\r\n\r\n".encode())
        st, _, body = read_response(t)
    t.close()
    return cn, st, body


def test_sni_selects_cert(bastion, certs):
    srv = bastion(conf(certs))
    assert handshake(srv, certs, "a.example")[0] == "a.example"
    assert handshake(srv, certs, "b.example")[0] == "b.example"
    cn, st, body = handshake(srv, certs, "x.wild.example")
    assert cn == "*.wild.example" and st == 200 and body == b"*.wild.example"
    assert handshake(srv, certs, "a.example")[2] == b"a.example"


def test_sni_case_trailing_dot(bastion, certs):
    srv = bastion(conf(certs))
    assert handshake(srv, certs, "A.EXAMPLE", host="a.example")[0] == "a.example"
    assert handshake(srv, certs, "a.example.", host="a.example")[0] == "a.example"


def test_no_sni_default(bastion, certs):
    srv = bastion(conf(certs))
    cn, st, body = handshake(srv, certs, None, host="default.example")
    assert cn == "default.example" and body == b"default.example"
    # unknown names get the default certificate too
    assert handshake(srv, certs, "nobody.example", host="default.example")[0] == "default.example"


def test_tls_default_cert(bastion, certs):
    srv = bastion(conf(certs, default_extra=f"tls_default_cert {certs}/ecdsa.crt {certs}/ecdsa.key;"))
    assert handshake(srv, certs, None, host="default.example")[0] == "localhost"
    assert handshake(srv, certs, "nobody.example", host="default.example")[0] == "localhost"
    assert handshake(srv, certs, "a.example")[0] == "a.example"


def test_sni_required(bastion, certs):
    srv = bastion(conf(certs, default_extra="sni_required on;"))
    with pytest.raises(ssl.SSLError):
        handshake(srv, certs, None, send=False)
    assert handshake(srv, certs, "a.example")[0] == "a.example"


def test_unknown_sni_reject(bastion, certs):
    srv = bastion(conf(certs, default_extra="sni_mismatch reject;"))
    with pytest.raises(ssl.SSLError) as e:
        handshake(srv, certs, "nobody.example", send=False)
    assert "unrecognized" in str(e.value).lower()
    assert handshake(srv, certs, "b.example")[0] == "b.example"


def test_host_sni_mismatch(bastion, certs):
    srv = bastion(conf(certs))
    cn, st, _ = handshake(srv, certs, "a.example", host="b.example")
    assert st == 421
    assert handshake(srv, certs, "a.example", host="a.example")[1] == 200
    allow = bastion(conf(certs, a_extra="host_sni_mismatch allow;"))
    assert handshake(allow, certs, "a.example", host="b.example")[1:] == (200, b"b.example")


def raw_hello(name: bytes) -> bytes:
    """A minimal TLS 1.3 ClientHello carrying `name` as the SNI, whatever its length or bytes:
    the OpenSSL client refuses to send the bad ones."""
    def ext(t, body):
        return t.to_bytes(2, "big") + len(body).to_bytes(2, "big") + body
    entry = b"\x00" + len(name).to_bytes(2, "big") + name
    sni = ext(0, len(entry).to_bytes(2, "big") + entry)
    exts = (sni + ext(43, b"\x02\x03\x04") + ext(10, b"\x00\x02\x00\x1d")
            + ext(13, b"\x00\x02\x04\x03")
            + ext(51, b"\x00\x24\x00\x1d\x00\x20" + b"\x09" + bytes(31)))
    body = (b"\x03\x03" + bytes(32) + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00"
            + len(exts).to_bytes(2, "big") + exts)
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs


def first_record_type(srv, hello):
    s = socket.create_connection(("127.0.0.1", srv.ports["https"]), 5)
    s.sendall(hello)
    s.settimeout(5)
    try:
        data = s.recv(100)
    except ConnectionResetError:
        data = b""
    s.close()
    return data[0] if data else None


def test_oversized_sni(bastion, certs):
    srv = bastion(conf(certs))
    assert first_record_type(srv, raw_hello(b"a.example")) == 0x16  # control: a ServerHello
    for bad in (b".".join([b"a" * 60] * 5), b"a" * 254, b"bad..name", b"bad name", b"a.example\x00x",
                b"*.wild.example"):
        assert first_record_type(srv, raw_hello(bad)) in (0x15, None), bad  # an alert or a close
    assert handshake(srv, certs, "a.example")[0] == "a.example"  # the server is still fine
