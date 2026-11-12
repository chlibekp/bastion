"""The QUIC endpoint (src/http/h3/quic.c): handshake, the stateless answers to datagrams for no
connection (Version Negotiation, Retry, stateless reset, refusal), the amplification limit and the
idle timeout. Raw datagrams are built here; real client Initials come from `openssl s_client -quic`
(one X25519 key share, so one Initial), replayed from fresh sockets that never answer."""
import os
import re
import signal
import subprocess
import time

import pytest

from quic_util import (capture_initials, conf, conn_line, h3, is_retry, recv_all, udp, wait_count)


def test_handshake(bastion, certs):
    srv = bastion(conf(certs))
    rc, lines = h3(srv)
    c = conn_line(lines)
    assert rc == 0 and c.get("handshake") is True, lines
    assert c["alpn"] == "h3"
    srv.wait_log(r"quic: handshake done slot=0 version=0x1")
    # curl's own QUIC stack (OpenSSL's) completes the handshake; no HTTP/3 answer exists before
    # Task 4, so the request itself times out after the connection is up.
    port = srv.ports["quic"]
    p = subprocess.run(["curl", "-sv", "--http3-only", "--max-time", "3", "--cacert", str(certs / "ca.crt"),
                        "--resolve", f"localhost:{port}:127.0.0.1", f"https://localhost:{port}/"],
                       capture_output=True, timeout=20)
    err = p.stderr.decode(errors="replace")
    assert re.search(r"(?i)connected to localhost .*port %d" % port, err) and "HTTP/3" in err, err
    assert len(re.findall(r"quic: handshake done", srv.logs())) >= 2


def _long_header(version, dcid, scid, size):
    pkt = bytes([0xc0 | 0x0a]) + version.to_bytes(4, "big") + bytes([len(dcid)]) + dcid + \
        bytes([len(scid)]) + scid
    return pkt + os.urandom(size - len(pkt))


def test_version_negotiation(bastion, certs):
    srv = bastion(conf(certs))
    s = udp(srv)
    dcid, scid = os.urandom(8), os.urandom(8)
    trigger = _long_header(0x1a2a3a4a, dcid, scid, 1200)
    s.send(trigger)
    got = recv_all(s, 1.0)
    assert len(got) == 1, got
    vn = got[0]
    assert vn[0] & 0x80 and vn[1:5] == b"\0\0\0\0", vn[:8].hex()
    assert len(vn) < len(trigger)  # no amplification
    # The VN echoes the IDs swapped (RFC 9000 section 17.2.1) and lists v1 and v2.
    assert vn[5] == 8 and vn[6:14] == scid and vn[14] == 8 and vn[15:23] == dcid
    versions = {int.from_bytes(vn[i:i + 4], "big") for i in range(23, len(vn), 4)}
    assert versions == {0x00000001, 0x6b3343cf}
    # A small datagram with an unknown version gets nothing at all.
    s.send(_long_header(0x1a2a3a4a, dcid, scid, 200))
    assert recv_all(s, 0.5) == []
    srv.wait_log(r"dropped datagram len=200: ")
    assert "quic: open" not in srv.logs()


def test_small_initial_dropped(bastion, certs):
    srv = bastion(conf(certs, "quic_retry never;"))
    initial = capture_initials(1)[0]
    assert len(initial) >= 1200
    s = udp(srv)
    s.send(initial[:1100])
    assert recv_all(s, 0.7) == []
    srv.wait_log(r"dropped datagram len=1100: Initial under 1200 bytes")
    assert "quic: open" not in srv.logs()
    # The same Initial whole is a connection (the control).
    s2 = udp(srv)
    s2.send(initial)
    assert recv_all(s2, 1.0), "the full Initial got no answer"
    srv.wait_log(r"quic: open slot=0 live=1")


def test_retry_always(bastion, certs):
    srv = bastion(conf(certs, "quic_retry always;"))
    initial = capture_initials(1)[0]
    s = udp(srv)
    s.send(initial)
    got = recv_all(s, 1.0)
    assert len(got) == 1 and is_retry(got[0]), [g[:6].hex() for g in got]
    srv.wait_log(r"quic: Retry slot=0")
    assert "quic: open" not in srv.logs()  # no state before the token comes back
    # A real client echoes the token and completes the handshake.
    rc, lines = h3(srv)
    assert rc == 0 and conn_line(lines).get("handshake") is True, lines
    assert re.search(r"quic: open slot=0", srv.logs())


def test_retry_auto(bastion, certs):
    srv = bastion(conf(certs, "quic_retry auto; quic_retry_threshold 2; quic_handshake_timeout 4s;"))
    initials = capture_initials(5)
    socks = []

    def first_answer(pkt):
        s = udp(srv)
        socks.append(s)
        s.send(pkt)
        got = recv_all(s, 0.5)
        assert got, "no answer"
        return got[0]

    # Two half-open handshakes are within the budget; the next ones must prove their address.
    assert not is_retry(first_answer(initials[0]))
    assert not is_retry(first_answer(initials[1]))
    assert is_retry(first_answer(initials[2]))
    assert is_retry(first_answer(initials[3]))
    # The half-open ones time out, and with the pressure gone a new client is served at once.
    wait_count(srv, r"quic: closed slot=0 .* live=0", 1, timeout=15)
    assert not is_retry(first_answer(initials[4]))
    for s in socks:
        s.close()


def test_amplification_limit(bastion, certs):
    """An unvalidated client that never answers gets at most 3x the bytes it sent, retransmissions
    included, measured on the wire."""
    srv = bastion(conf(certs, "quic_retry never;"))
    initial = capture_initials(1)[0]
    s = udp(srv)
    s.send(initial)
    got = recv_all(s, 2.5)  # long enough for several PTO retransmissions
    total = sum(len(g) for g in got)
    assert 0 < total <= 3 * len(initial), (total, len(initial), [len(g) for g in got])


def test_idle_timeout(bastion, certs):
    srv = bastion(conf(certs, "quic_idle_timeout 1s;"))
    # The request is never answered before Task 4, so the client stays connected until killed.
    p = h3(srv, "/", timeout_ms=30000, wait=False)
    try:
        srv.wait_log(r"quic: handshake done")
        p.send_signal(signal.SIGKILL)
    finally:
        p.wait(10)
    started = time.monotonic()
    srv.wait_log(r"quic: closed slot=0 rx=\d+ tx=\d+ live=0", timeout=10)
    assert time.monotonic() - started < 6


def test_stateless_reset(bastion, certs):
    srv = bastion(conf(certs))
    s = udp(srv)
    dcid = os.urandom(16)
    trigger = bytes([0x41]) + dcid + os.urandom(60)
    s.send(trigger)
    got = recv_all(s, 1.0)
    assert len(got) == 1, got
    r1 = got[0]
    assert 21 <= len(r1) < len(trigger)
    assert r1[0] & 0xc0 == 0x40  # looks like a short header (RFC 9000 section 10.3)
    # The token (last 16 bytes) is a function of the connection ID: the same ID gives the same
    # token, another ID another one.
    s.send(trigger)
    r2 = recv_all(s, 1.0)[0]
    assert r2[-16:] == r1[-16:]
    s.send(bytes([0x41]) + os.urandom(16) + os.urandom(60))
    r3 = recv_all(s, 1.0)[0]
    assert r3[-16:] != r1[-16:]
    # Too small to be answered with a smaller reset: nothing.
    s.send(bytes([0x41]) + dcid + os.urandom(3))
    assert recv_all(s, 0.5) == []
    assert "quic: open" not in srv.logs()


def test_stateless_reset_off(bastion, certs):
    srv = bastion(conf(certs, "quic_stateless_reset off;"))
    s = udp(srv)
    s.send(bytes([0x41]) + os.urandom(16) + os.urandom(60))
    assert recv_all(s, 0.7) == []


def test_max_connections(bastion, certs):
    srv = bastion(conf(certs, "quic_max_connections 1; quic_retry never; quic_handshake_timeout 10s;"))
    held = udp(srv)
    held.send(capture_initials(1)[0])  # one half-open connection, kept
    srv.wait_log(r"quic: open slot=0 live=1")
    rc, lines = h3(srv, timeout_ms=5000)
    c = conn_line(lines)
    assert rc != 0 and c.get("handshake") is False, lines
    assert c["peer_error"]["code"] == 2, c  # CONNECTION_REFUSED
    srv.wait_log(r"quic: refused slot=0 live=1")
    held.close()
