"""PROXY protocol v1 and v2 (Phase 9, Task 9): accepting a header from a trusted balancer, before
TLS too, and sending one to an upstream."""
import socket
import ssl
import struct
import threading

import pytest

SIG = b"\r\n\r\n\x00\r\nQUIT\n"


def v2(src, sport, dst, dport):
    body = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!HH", sport, dport)
    return SIG + b"\x21\x11" + struct.pack("!H", len(body)) + body


def conf(trusted="127.0.0.0/8", tls="", certs=None, timeout=""):
    cert = f"tls_cert {certs}/ecdsa-chain.crt {certs}/ecdsa.key;" if tls else ""
    port = "@HTTPS_PORT@" if tls else "@HTTP_PORT@"
    return (f"workers 1;\nserver {{ listen 127.0.0.1:{port} {tls} proxy_protocol; "
            f"proxy_protocol_from {trusted}; {timeout} {cert}\n"
            "location / { return 200 \"$remote_addr\"; } }\n")


def exchange(port, prefix, timeout=5):
    s = socket.create_connection(("127.0.0.1", port), timeout)
    s.sendall(prefix + b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n")
    out = b""
    try:
        while True:
            d = s.recv(65536)
            if not d:
                break
            out += d
    except (ConnectionResetError, socket.timeout):
        pass
    s.close()
    return out


def test_trusted_sets_remote(bastion):
    srv = bastion(conf())
    port = srv.ports["http"]
    r = exchange(port, b"PROXY TCP4 203.0.113.9 127.0.0.1 5555 80\r\n")
    assert r.startswith(b"HTTP/1.1 200") and r.endswith(b"203.0.113.9"), r
    r = exchange(port, v2("198.51.100.4", 1234, "127.0.0.1", 80))
    assert r.endswith(b"198.51.100.4"), r
    r = exchange(port, b"PROXY UNKNOWN\r\n")
    assert r.endswith(b"127.0.0.1"), r  # no client named: the socket's peer


def test_untrusted_source(bastion):
    srv = bastion(conf(trusted="10.0.0.0/8"))
    r = exchange(srv.ports["http"], b"PROXY TCP4 203.0.113.9 127.0.0.1 5555 80\r\n")
    assert r == b"", r
    srv.wait_log(r"outside proxy_protocol_from")


def test_no_header_required(bastion):
    srv = bastion(conf())
    assert exchange(srv.ports["http"], b"") == b""
    assert exchange(srv.ports["http"], b"PROXY TCP4 1.2.3.4 5.6.7.8 1 99999\r\n") == b""


def test_header_timeout(bastion):
    srv = bastion(conf(timeout="proxy_protocol_timeout 200ms;"))
    s = socket.create_connection(("127.0.0.1", srv.ports["http"]), 5)
    s.sendall(b"PROXY TCP4")  # never finished
    assert s.recv(10) == b""
    s.close()


def test_before_tls(bastion, certs):
    srv = bastion(conf(tls="tls", certs=certs))
    s = socket.create_connection(("127.0.0.1", srv.ports["https"]), 5)
    s.sendall(v2("192.0.2.77", 4000, "127.0.0.1", 443))  # the header precedes the ClientHello
    ctx = ssl.create_default_context(cafile=str(certs / "ca.crt"))
    t = ctx.wrap_socket(s, server_hostname="localhost")
    t.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
    out = b""
    while True:
        d = t.recv(65536)
        if not d:
            break
        out += d
    t.close()
    assert out.startswith(b"HTTP/1.1 200") and out.endswith(b"192.0.2.77"), out


def test_config_errors(bastion_bin, tmp_path):
    import subprocess

    def check(text):
        p = tmp_path / "c.conf"
        p.write_text(text)
        return subprocess.run([str(bastion_bin), "-t", "-c", str(p)], capture_output=True, text=True)

    r = check("server { listen 127.0.0.1:8080 proxy_protocol; }\n")
    assert r.returncode != 0 and "proxy_protocol_from" in r.stderr, r.stderr
    r = check("upstream u { server 127.0.0.1:1; protocol http2; send_proxy_protocol v1; }\n"
              "server { listen 127.0.0.1:8080; location / { proxy u; } }\n")
    assert r.returncode != 0 and "send_proxy_protocol" in r.stderr, r.stderr


class RawUpstream:
    """Records the first bytes of every connection, then answers one HTTP response."""

    def __init__(self):
        self.lsock = socket.socket()
        self.lsock.bind(("127.0.0.1", 0))
        self.lsock.listen(16)
        self.port = self.lsock.getsockname()[1]
        self.seen = []
        self.closed = False
        threading.Thread(target=self.run, daemon=True).start()

    def run(self):
        while not self.closed:
            try:
                c, _ = self.lsock.accept()
            except OSError:
                return
            data = b""
            c.settimeout(5)
            try:
                while not (b"HTTP/1.1\r\n" in data and data.endswith(b"\r\n\r\n")):  # the v2 signature holds CRLFCRLF
                    d = c.recv(4096)
                    if not d:
                        break
                    data += d
                self.seen.append(data)
                c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            except OSError:
                pass
            c.close()

    def close(self):
        self.closed = True
        self.lsock.close()


@pytest.mark.parametrize("ver", ["v1", "v2"])
def test_send_to_upstream(bastion, ver):
    up = RawUpstream()
    try:
        srv = bastion(f"workers 1;\nupstream u {{ server 127.0.0.1:{up.port}; send_proxy_protocol {ver}; }}\n"
                      "server { listen 127.0.0.1:@HTTP_PORT@; location / { proxy u; } }\n")
        port = srv.ports["http"]
        for _ in range(2):
            s = socket.create_connection(("127.0.0.1", port), 5)
            client_port = s.getsockname()[1]
            s.sendall(b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n")
            r = b""
            while True:
                d = s.recv(4096)
                if not d:
                    break
                r += d
            s.close()
            assert r.startswith(b"HTTP/1.1 200"), r
            got = up.seen[-1]
            if ver == "v1":
                want = f"PROXY TCP4 127.0.0.1 127.0.0.1 {client_port} {port}\r\nGET / HTTP/1.1".encode()
                assert got.startswith(want), got
            else:
                hdr = v2("127.0.0.1", client_port, "127.0.0.1", port)
                assert got.startswith(hdr + b"GET / HTTP/1.1"), got
        assert len(up.seen) == 2  # one connection per request: never pooled
    finally:
        up.close()
