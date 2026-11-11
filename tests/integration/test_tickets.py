"""Shared session ticket keys (src/tls/tickets.c): resumption across workers, rotation, the
non-dumpable region, and a key file shared by two instances."""
import os
import re
import socket
import ssl
import time

import pytest

from test_tls_conn import client_ctx, conf, read_response, www  # noqa: F401


_CTX = {}


def fetch(srv, certs, session=None, version=ssl.TLSVersion.TLSv1_3):
    """One request; returns (session, reused). The ticket of TLS 1.3 arrives after the handshake,
    so the response is read before the session is taken."""
    # a session only resumes through the context that got it
    ctx = _CTX.setdefault((str(certs), version), client_ctx(certs, version, version))
    s = socket.create_connection(("127.0.0.1", srv.ports["https"]), 10)
    t = ctx.wrap_socket(s, server_hostname="localhost", session=session)
    t.settimeout(10)
    t.sendall(b"GET /v HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
    st, _, body = read_response(t)
    assert st == 200
    sess, reused = t.session, t.session_reused
    t.close()
    return sess, reused


def serve(bastion, certs, www, tickets, workers=2, env=None):  # noqa: F811
    text = conf(certs, www, profile=f"tls_profile t {{ tickets {tickets}; }}", tls_extra="tls_profile t;")
    return bastion(text.replace("workers 1;", f"workers {workers};"), env=env)


def test_resume_across_workers(bastion, certs, www):  # noqa: F811
    srv = serve(bastion, certs, www, "rotate=12h keep=3", workers=4)
    assert len(srv.workers()) == 4
    sess, reused = fetch(srv, certs)
    assert not reused and sess is not None
    # Connections spread over the workers: without shared keys most of these would be full
    # handshakes.
    results = [fetch(srv, certs, sess)[1] for _ in range(24)]
    assert all(results), results


def test_resume_tls12(bastion, certs, www):  # noqa: F811
    srv = serve(bastion, certs, www, "rotate=12h keep=3", workers=3)
    sess, reused = fetch(srv, certs, version=ssl.TLSVersion.TLSv1_2)
    assert not reused
    assert all(fetch(srv, certs, sess, ssl.TLSVersion.TLSv1_2)[1] for _ in range(12))


def test_resume_after_rotation(bastion, certs, www):  # noqa: F811
    # the config floor for `rotate` is 60 s; test builds let the helper rotate every second
    srv = serve(bastion, certs, www, "rotate=60s keep=2", env={"BST_TEST_TICKET_ROTATE_MS": "1000"})
    old, _ = fetch(srv, certs)
    time.sleep(1.5)  # one rotation: the old key is still among the newest two
    assert fetch(srv, certs, old)[1], "a ticket under the previous key must still resume"
    time.sleep(3.5)  # three more rotations: the old key has aged out
    sess, reused = fetch(srv, certs, old)
    assert not reused, "a ticket under a key older than `keep` must not resume"
    assert sess is not None  # and a full handshake issued a new one
    assert fetch(srv, certs, sess)[1]


def test_tickets_off(bastion, certs, www):  # noqa: F811
    srv = serve(bastion, certs, www, "off")
    sess, _ = fetch(srv, certs)
    assert not fetch(srv, certs, sess)[1]


def test_keys_not_dumpable(bastion, certs, www):  # noqa: F811
    srv = serve(bastion, certs, www, "rotate=12h keep=3")
    pids = list(srv.workers().values()) + [srv.helper(), srv.proc.pid]
    for pid in pids:
        maps = open(f"/proc/{pid}/smaps").read()
        m = re.search(r"^[0-9a-f]+-[0-9a-f]+ \S+ .*bastion-tickets.*\n(?:[A-Za-z_]+:.*\n)*?VmFlags:([^\n]*)",
                      maps, re.M)
        assert m, f"no ticket region in {pid}"
        assert " dd" in m.group(1), f"{pid}: ticket keys are dumpable: {m.group(1)}"


def test_ticket_file_cluster(bastion, certs, www, tmp_path):  # noqa: F811
    keys = tmp_path / "tickets.keys"
    keys.write_text("\n".join(os.urandom(80).hex() for _ in range(2)) + "\n")
    os.chmod(keys, 0o600)
    a = serve(bastion, certs, www, f"rotate=12h keep=3 file={keys}")
    b = serve(bastion, certs, www, f"rotate=12h keep=3 file={keys}")
    sess, reused = fetch(a, certs)
    assert not reused
    assert fetch(b, certs, sess)[1], "an instance with the same key file must resume the ticket"
    # an instance with its own keys does not
    other = serve(bastion, certs, www, "rotate=12h keep=3")
    assert not fetch(other, certs, sess)[1]


def test_ticket_file_permissions(bastion, certs, www, tmp_path):  # noqa: F811
    keys = tmp_path / "bad.keys"
    keys.write_text(os.urandom(80).hex() + "\n")
    os.chmod(keys, 0o644)
    text = conf(certs, www, profile=f"tls_profile t {{ tickets file={keys}; }}", tls_extra="tls_profile t;")
    srv = bastion(text, wait=None)
    assert srv.proc.wait(10) != 0
    assert "chmod 600" in srv.stdout() + srv.logs()
