"""Client certificate authentication (src/tls/ctx.c, conn.c): tls_client_auth, CA, CRL, the
$ssl_client_* variables, auth_mtls, resumption identity and the cross-host bypass."""
import hashlib
import os
import socket
import ssl

import pytest

from test_tls_conn import client_ctx, read_response

REJECTED = (ssl.SSLError, ConnectionResetError, BrokenPipeError, EOFError, TimeoutError)


def srv_conf(certs, auth="required", extra="", ca="ca.crt", crl=None, locs=None):
    crl_line = f"tls_client_crl {certs}/{crl};" if crl else ""
    locs = locs or '''location / { return 200 "$ssl_client_verify|$ssl_client_s_dn|$ssl_client_san_dns|$ssl_client_fingerprint"; }'''
    return (f"workers 1;\nserver {{ listen 127.0.0.1:@HTTPS_PORT@ tls; tls_cert {certs}/ecdsa-chain.crt "
            f"{certs}/ecdsa.key; tls_client_auth {auth}; tls_client_ca {certs}/{ca}; {crl_line} {extra}\n{locs} }}\n")


def request(srv, certs, client=None, path="/", sni="localhost", host=None, session=None, ctx=None,
            ver=None):
    ctx = ctx or client_ctx(certs, ver, ver)
    if client:
        ctx.load_cert_chain(certs / f"{client}.crt", certs / f"{client}.key")
    s = socket.create_connection(("127.0.0.1", srv.ports["https"]), 10)
    t = ctx.wrap_socket(s, server_hostname=sni, session=session)
    t.settimeout(10)
    try:
        t.sendall(f"GET {path} HTTP/1.1\r\nHost: {host or sni}\r\nConnection: close\r\n\r\n".encode())
        st, _, body = read_response(t)
        return st, body.decode(), t.session, t.session_reused
    finally:
        t.close()


def rejected(fn):
    """True when the server refused: an exception, or no response."""
    try:
        r = fn()
    except REJECTED:
        return True
    return r[0] != 200 and r[0] is None


def test_required_no_cert(bastion, certs):
    srv = bastion(srv_conf(certs))
    for ver in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
        with pytest.raises(REJECTED):
            request(srv, certs, ver=ver)


def test_required_good_cert_and_variables(bastion, certs):
    srv = bastion(srv_conf(certs))
    st, body, _, _ = request(srv, certs, "client")
    verify, dn, san, fp = body.split("|")
    der = ssl.PEM_cert_to_DER_cert((certs / "client.crt").read_text())
    assert st == 200 and verify == "SUCCESS" and dn == "CN=client one"
    assert fp == hashlib.sha256(der).hexdigest() and san == ""


@pytest.mark.parametrize("client", ["client-other", "client-expired", "client-revoked"])
def test_bad_client_cert_rejected(bastion, certs, client):
    srv = bastion(srv_conf(certs, crl="crl.pem"))
    with pytest.raises(REJECTED):
        request(srv, certs, client)
    assert request(srv, certs, "client")[0] == 200  # and the good one still works


def test_revoked_needs_the_crl(bastion, certs):
    # without tls_client_crl the revoked (but unexpired, CA-signed) certificate is accepted: the
    # CRL is what rejects it
    srv = bastion(srv_conf(certs))
    assert request(srv, certs, "client-revoked")[0] == 200


def test_optional_location_required(bastion, certs):
    locs = ('location = /private { auth_mtls on; return 200 "secret"; }\n'
            'location / { return 200 "$ssl_client_verify"; }')
    srv = bastion(srv_conf(certs, auth="optional", locs=locs))
    assert request(srv, certs)[:2] == (200, "NONE")
    assert request(srv, certs, path="/private")[0] == 403
    assert request(srv, certs, "client", path="/private")[:2] == (200, "secret")
    # a certificate that does not verify is refused at the TLS layer even when optional
    with pytest.raises(REJECTED):
        request(srv, certs, "client-other")


def test_session_resumption_keeps_identity(bastion, certs):
    srv = bastion(srv_conf(certs))
    ctx = client_ctx(certs)
    ctx.load_cert_chain(certs / "client.crt", certs / "client.key")
    _, body, sess, reused = request(srv, certs, ctx=ctx)
    assert not reused
    st, body2, _, reused = request(srv, certs, ctx=ctx, session=sess)
    assert reused and st == 200
    assert body2 == body and body2.startswith("SUCCESS|CN=client one")


def test_ticket_not_valid_on_other_auth_setup(bastion, certs, tmp_path):
    keys = tmp_path / "t.keys"
    keys.write_text(os.urandom(80).hex() + "\n")
    os.chmod(keys, 0o600)
    prof = f"tls_profile p {{ tickets file={keys}; }}\n"
    plain = (f"workers 1;\n{prof}server {{ listen 127.0.0.1:@HTTPS_PORT@ tls; tls_profile p; "
             f'tls_cert {certs}/ecdsa-chain.crt {certs}/ecdsa.key; location / {{ return 200 "plain"; }} }}\n')
    mtls = srv_conf(certs).replace("workers 1;\n", f"workers 1;\n{prof}").replace(
        "tls_client_auth", "tls_profile p; tls_client_auth")
    a = bastion(plain)
    b = bastion(mtls)
    ctx = client_ctx(certs)
    ctx.load_cert_chain(certs / "client.crt", certs / "client.key")
    _, _, sess, reused = request(a, certs, ctx=ctx)
    assert not reused
    # same ticket keys, but another client-auth setup: another session id context, no resumption
    st, body, _, reused = request(b, certs, ctx=ctx, session=sess)
    assert st == 200 and not reused and body.startswith("SUCCESS|")


def test_cross_vhost_cert_bypass(bastion, certs):
    text = ("workers 1;\n"
            f"server {{ listen 127.0.0.1:@HTTPS_PORT@ tls default_server; name a.example; "
            f'tls_cert {certs}/site-a.crt {certs}/site-a.key; location / {{ return 200 "a"; }} }}\n'
            f"server {{ listen 127.0.0.1:@HTTPS_PORT@ tls; name b.example; tls_cert {certs}/site-b.crt "
            f"{certs}/site-b.key; tls_client_auth required; tls_client_ca {certs}/ca.crt;\n"
            f'location / {{ return 200 "b"; }} }}\n')
    srv = bastion(text)
    # a handshake for a.example (no client certificate asked) must not reach b.example
    assert request(srv, certs, sni="a.example", host="b.example")[0] == 421
    assert request(srv, certs, sni="a.example", host="a.example")[:2] == (200, "a")
    # a connection with no SNI lands on the default server, and Host cannot move it to b
    ctx = client_ctx(certs)
    ctx.check_hostname = False
    s = socket.create_connection(("127.0.0.1", srv.ports["https"]), 10)
    t = ctx.wrap_socket(s, server_hostname=None)
    t.sendall(b"GET / HTTP/1.1\r\nHost: b.example\r\nConnection: close\r\n\r\n")
    assert read_response(t)[0] == 421
    t.close()
    # the real thing works with the right SNI and a certificate
    assert request(srv, certs, "client", sni="b.example")[:2] == (200, "b")
    with pytest.raises(REJECTED):
        request(srv, certs, sni="b.example")


def test_client_auth_config_errors(bastion, certs):
    for bad in (f"tls_client_ca {certs}/nonexistent.crt;", ):
        text = (f"workers 1;\nserver {{ listen 127.0.0.1:@HTTPS_PORT@ tls; tls_cert {certs}/ecdsa.crt "
                f"{certs}/ecdsa.key; tls_client_auth required; {bad} }}\n")
        srv = bastion(text, wait=None)
        assert srv.proc.wait(10) != 0
        assert "tls_client_ca" in srv.stdout() + srv.logs()
