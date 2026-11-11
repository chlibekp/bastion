"""TLS 1.3 0-RTT (src/tls/early.c, conn.c, h1/conn.c) and the TCP Fast Open policy that mirrors it.
The client is `openssl s_client -sess_in/-early_data`: Python's ssl module cannot send early data."""
import os
import re
import select
import socket
import subprocess
import threading
import time

import pytest

GET = b"GET /e HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
POST = b"POST /e HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"


def conf(certs, early=True, workers=1, extra_profile="", srv_extra="", dbg=True):
    prof = f"tls_profile e {{ {'early_data on;' if early else ''} {extra_profile} }}\n"
    log = "error_log @WORKDIR@/error.log debug;\n" if dbg else ""
    return (f"workers {workers};\n{log}{prof}server {{ listen 127.0.0.1:@HTTPS_PORT@ tls; tls_profile e; "
            f"tls_cert {certs}/ecdsa-chain.crt {certs}/ecdsa.key; {srv_extra}\n"
            f'location /e {{ return 200 "early=$ssl_early_data reused=$ssl_session_reused"; }} }}\n')


def s_client(srv, certs, sess_out=None, sess_in=None, early=None, stdin=b"", extra=(), timeout=15):
    cmd = ["openssl", "s_client", "-connect", f"127.0.0.1:{srv.ports['https']}", "-servername", "localhost",
           "-CAfile", str(certs / "ca.crt"), "-tls1_3", "-ign_eof", *extra]
    if sess_out:
        cmd += ["-sess_out", str(sess_out)]
    if sess_in:
        cmd += ["-sess_in", str(sess_in)]
    if early:
        cmd += ["-early_data", str(early)]
    p = subprocess.run(cmd, input=stdin, capture_output=True, timeout=timeout)
    return p.stdout.decode(errors="replace") + p.stderr.decode(errors="replace")


def first(srv, certs, tmp_path, name="sess", extra=()):
    """A full handshake that leaves a session ticket in a file."""
    f = tmp_path / name
    out = s_client(srv, certs, sess_out=f, stdin=GET, extra=extra)
    assert "early=" in out, out
    return f, out


def max_early(out):
    m = re.search(r"Max Early Data:\s*(\d+)", out)
    return int(m.group(1)) if m else 0


def write(tmp_path, name, data):
    f = tmp_path / name
    f.write_bytes(data)
    return f


def accepted(log):
    return log.count("early data accepted")


def test_off_by_default(bastion, certs, tmp_path):
    srv = bastion(conf(certs, early=False))
    _, out = first(srv, certs, tmp_path)
    assert max_early(out) == 0, out
    on = bastion(conf(certs, early=True))
    _, out = first(on, certs, tmp_path, "sess2")
    assert max_early(out) == 16384, out


def test_early_get(bastion, certs, tmp_path):
    srv = bastion(conf(certs))
    sess, _ = first(srv, certs, tmp_path)
    out = s_client(srv, certs, sess_in=sess, early=write(tmp_path, "req", GET))
    assert "Early data was accepted" in out, out
    assert "early=1 reused=r" in out, out  # the handler sees the flag, and the session was resumed
    assert accepted(srv.logs()) == 1


def test_early_post_425_then_retry(bastion, certs, tmp_path):
    srv = bastion(conf(certs))
    sess, _ = first(srv, certs, tmp_path)
    out = s_client(srv, certs, sess_in=sess, early=write(tmp_path, "req", POST))
    assert "HTTP/1.1 425" in out and "Too Early" in out, out
    assert "early=" not in out  # the handler never ran
    # the retry, after the handshake, on a fresh resumption without early data
    sess2, _ = first(srv, certs, tmp_path, "sess2")
    out = s_client(srv, certs, sess_in=sess2, stdin=POST)
    assert "HTTP/1.1 200" in out and "early= reused=r" in out, out


def test_early_methods_directive(bastion, certs, tmp_path):
    srv = bastion(conf(certs, extra_profile="early_data_methods GET HEAD POST;"))
    sess, _ = first(srv, certs, tmp_path)
    out = s_client(srv, certs, sess_in=sess, early=write(tmp_path, "req", POST))
    assert "HTTP/1.1 200" in out and "early=1" in out, out


@pytest.mark.parametrize("workers", [1, 3])
def test_ticket_reuse_refused(bastion, certs, tmp_path, workers):
    srv = bastion(conf(certs, workers=workers))
    sess, _ = first(srv, certs, tmp_path)
    req = write(tmp_path, "req", GET)
    out = s_client(srv, certs, sess_in=sess, early=req)
    assert "Early data was accepted" in out, out
    # the same ticket again, whatever worker the kernel picks: no early data, still a handshake
    for _ in range(6 * workers):
        out = s_client(srv, certs, sess_in=sess, early=req, stdin=GET)  # s_client resends it itself
        assert "Early data was rejected" in out, out
        assert "early= reused=r" in out, out
    assert accepted(srv.logs()) == 1


class Tap:
    """A TCP relay that records what the client sent."""

    def __init__(self, port):
        self.up = port
        self.ls = socket.socket()
        self.ls.bind(("127.0.0.1", 0))
        self.ls.listen(4)
        self.port = self.ls.getsockname()[1]
        self.sent = []
        threading.Thread(target=self.run, daemon=True).start()

    def pipe(self, a, b, record):
        try:
            while True:
                d = a.recv(65536)
                if not d:
                    break
                if record is not None:
                    record.append(d)
                b.sendall(d)
        except OSError:
            pass
        finally:
            for s in (a, b):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def run(self):
        while True:
            try:
                c, _ = self.ls.accept()
            except OSError:
                return
            u = socket.create_connection(("127.0.0.1", self.up))
            rec = []
            self.sent.append(rec)
            threading.Thread(target=self.pipe, args=(c, u, rec), daemon=True).start()
            threading.Thread(target=self.pipe, args=(u, c, None), daemon=True).start()


def test_replay_rejected(bastion, certs, tmp_path):
    srv = bastion(conf(certs, workers=3))
    sess, _ = first(srv, certs, tmp_path)
    tap = Tap(srv.ports["https"])

    class Via:  # s_client talks to the relay
        ports = {"https": tap.port}

    out = s_client(Via, certs, sess_in=sess, early=write(tmp_path, "req", GET))
    assert "Early data was accepted" in out, out
    flight = b"".join(tap.sent[0])
    assert len(flight) > 100
    log0 = srv.logs()
    assert accepted(log0) == 1
    def replay():
        s = socket.create_connection(("127.0.0.1", srv.ports["https"]), 5)
        s.sendall(flight)
        s.settimeout(0.15)  # the server waits for the client's Finished, which a replay never has
        try:
            while s.recv(65536):
                pass
        except OSError:
            pass
        s.close()

    for _ in range(12):  # new source ports: the kernel spreads them over the 3 workers
        replay()
    time.sleep(0.3)
    log = srv.logs()
    assert accepted(log) == 1, log  # not one replay was served: acceptance is where early data starts
    # Every one of them reaches the ticket check, and every one is refused there. (The earlier
    # threshold of 9 of 12 came from replays spaced 1 s apart: the last three came after
    # OpenSSL's own ticket-age freshness window and were refused before the table was asked.)
    assert log.count("the ticket was used before") == 12, log
    # An old replay is refused by that freshness check, before the table: still no second acceptance.
    time.sleep(12)
    replay()
    time.sleep(0.3)
    log2 = srv.logs()
    assert accepted(log2) == 1, log2
    assert log2.count("the ticket was used before") == 12, log2


def test_early_never_for_mtls(bastion, certs, tmp_path):
    keys = tmp_path / "t.keys"
    keys.write_text(os.urandom(80).hex() + "\n")
    os.chmod(keys, 0o600)
    prof = f"tickets file={keys};"
    plain = bastion(conf(certs, extra_profile=prof))
    sess, _ = first(plain, certs, tmp_path)
    mtls_conf = conf(certs, extra_profile=prof, srv_extra=f"tls_client_auth optional; tls_client_ca {certs}/ca.crt;")
    mtls = bastion(mtls_conf)
    # a ticket of the mTLS server carries no early data allowance
    f = tmp_path / "msess"
    out = s_client(mtls, certs, sess_out=f, stdin=GET, extra=["-cert", str(certs / "client.crt"),
                                                              "-key", str(certs / "client.key")])
    assert "early=" in out and max_early(out) == 0, out
    # and a ticket of the other server is no ticket here: a full handshake, early data rejected
    out = s_client(mtls, certs, sess_in=sess, early=write(tmp_path, "req", GET), stdin=GET)
    assert "Early data was accepted" not in out and "early=1" not in out, out
    assert accepted(mtls.logs()) == 0


def test_early_needs_tickets(bastion, certs):
    srv = bastion(conf(certs, extra_profile="tickets off;"), wait=None)
    assert srv.proc.wait(10) != 0
    assert "early_data needs tickets" in srv.stdout() + srv.logs()


def fastopen_conf(name, www):
    return (f"workers 1;\ntcp_profile {name} {{ fastopen 16; }}\n"
            f"server {{ listen 127.0.0.1:@HTTP_PORT@ tcp_profile={name}; root {www};\n"
            'location /e { return 200 "early=$ssl_early_data"; } }\n')


def tfo_request(port, data, cookie_first):
    """Connects with data in the SYN (MSG_FASTOPEN); the first call of a pair only gets the cookie."""
    s = socket.socket()
    s.settimeout(5)
    try:
        s.sendto(data, socket.MSG_FASTOPEN, ("127.0.0.1", port))
    except BlockingIOError:
        # no cookie cached for this destination yet: the kernel opens an ordinary connection (the
        # cookie round) and sends nothing in the SYN; finish it as a plain connect and send
        select.select([], [s], [], 5)
        s.sendall(data)
    out = b""
    try:
        while True:
            d = s.recv(65536)
            if not d:
                break
            out += d
    except OSError:
        pass
    s.close()
    return out.decode(errors="replace")


def test_fastopen_policy(bastion, tmp_path):
    try:
        with open("/proc/sys/net/ipv4/tcp_fastopen") as f:
            if int(f.read()) & 3 != 3:
                pytest.skip("net.ipv4.tcp_fastopen lacks the client and server bits")
    except OSError:
        pytest.skip("no TCP Fast Open here")
    srv = bastion(fastopen_conf("tfo", tmp_path))
    port = srv.ports["http"]
    get = b"GET /e HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    post = b"POST /e HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    assert "early=" in tfo_request(port, get, True)  # the cookie round: an ordinary connection
    out = tfo_request(port, get, False)
    assert "200" in out and "early=1" in out, out  # data in the SYN: a safe method runs, flagged
    out = tfo_request(port, post, False)
    assert "425" in out, out  # data in the SYN: an unsafe one is told to retry
    # the same POST on an ordinary connection (no data in the SYN) is fine
    s = socket.create_connection(("127.0.0.1", port), 5)
    s.sendall(post)
    s.settimeout(5)
    out = b""
    while True:
        d = s.recv(65536)
        if not d:
            break
        out += d
    assert b"200" in out and b"early=" in out and b"early=1" not in out
