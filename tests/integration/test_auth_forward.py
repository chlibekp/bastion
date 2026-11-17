"""Forward auth and location mTLS enforcement (Phase 11, Task 6): allow, deny with the service's
own answer, failing closed on a slow or absent service, X-Original-* that clients can not spoof,
the request body kept for the upstream only, auth_require all with JWT and mTLS, and a cached
response never served before authentication."""
import socket
import time

import pytest

from test_auth_jwt import keys, token  # noqa: F401  (fixture)
from test_mtls import request as tls_request
from upstream_util import Upstream, ok


def raw(port, path="/p/x", extra="", body=b"", method="GET"):
    s = socket.create_connection(("127.0.0.1", port), 15)
    cl = f"Content-Length: {len(body)}\r\n" if body else ""
    s.sendall(f"{method} {path} HTTP/1.1\r\nHost: app\r\n{extra}{cl}Connection: close\r\n\r\n".encode()
              + body)
    out = b""
    s.settimeout(15)
    try:
        while True:
            d = s.recv(65536)
            if not d:
                break
            out += d
    except OSError:
        pass
    s.close()
    return (int(out.split(b" ", 2)[1]) if out else 0), out


@pytest.fixture
def auth():
    u = Upstream()
    yield u
    u.close()


@pytest.fixture
def app():
    u = Upstream()
    u.handler = lambda r, c: ok(b"app:" + (r.get("x-user") or "-").encode() + b":" + r.body,
                                200, (("Cache-Control", "max-age=60"),))
    yield u
    u.close()


def conf(auth, app, opts="", extra="", cache=False):
    store = "cache_store main { disk @WORKDIR@/cache size=10m; }\n" if cache else ""
    return (f"workers 1;\n{store}upstream authsvc {{ server {auth.url[7:]}; }}\n"
            f"server {{ listen 127.0.0.1:@HTTP_PORT@;\n"
            f"location /p/ {{ auth_forward authsvc path=/check response_headers=X-User {opts}; "
            f"{extra} {'cache main;' if cache else ''} proxy {app.url}; }} }}\n")


def test_allow(bastion, auth, app):
    auth.handler = lambda r, c: ok("", 200, (("X-User", "alice"),))
    srv = bastion(conf(auth, app))
    st, r = raw(srv.ports["http"], extra="Authorization: Bearer t\r\n")
    assert st == 200 and r.endswith(b"app:alice:"), (r, srv.logs()[-2000:])
    a = auth.requests[-1]
    assert a.target == "/check" and a.get("authorization") == "Bearer t"


def test_deny(bastion, auth, app):
    for code, hdrs in ((401, (("WWW-Authenticate", "Bearer"),)), (403, ()),
                       (302, (("Location", "https://login/"),))):
        auth.handler = lambda r, c, code=code, hdrs=hdrs: ok("go away", code, hdrs)
        srv = bastion(conf(auth, app))
        st, r = raw(srv.ports["http"])
        assert st == code and r.endswith(b"go away"), r
        for k, v in hdrs:
            assert f"{k}: {v}".encode() in r
    assert app.requests == []


def test_timeout_fails_closed(bastion, auth, app):
    def slow(r, c):
        time.sleep(3)
        return ok("", 200)
    auth.handler = slow
    srv = bastion(conf(auth, app, "timeout=500ms"))
    t = time.monotonic()
    st, _ = raw(srv.ports["http"])
    assert st == 503 and time.monotonic() - t < 2.5
    assert app.requests == []


class _Dead:
    def __init__(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        self.url = "http://127.0.0.1:%d" % s.getsockname()[1]
        s.close()  # nothing listens there: connection refused


def test_down_fails_closed(bastion, app):
    srv = bastion(conf(_Dead(), app))
    assert raw(srv.ports["http"])[0] == 503
    assert app.requests == []


def test_original_uri_passed(bastion, auth, app):
    auth.handler = lambda r, c: ok("", 200)
    srv = bastion(conf(auth, app))
    raw(srv.ports["http"], "/p/x?q=1", "X-Original-URI: /public\r\nX-Original-Method: GET\r\n",
        method="DELETE")
    a = auth.requests[-1]
    assert a.all("x-original-uri") == ["/p/x?q=1"] and a.all("x-original-method") == ["DELETE"]
    assert a.get("x-original-host") == "app" and a.get("x-original-proto") == "http"


def test_response_header_spoof(bastion, auth, app):
    auth.handler = lambda r, c: ok("", 200)  # sets no X-User
    srv = bastion(conf(auth, app))
    st, r = raw(srv.ports["http"], extra="X-User: root\r\n")
    assert st == 200 and r.endswith(b"app:-:")


def test_body_not_sent(bastion, auth, app):
    auth.handler = lambda r, c: ok("", 200, (("X-User", "bob"),))
    srv = bastion(conf(auth, app))
    st, r = raw(srv.ports["http"], body=b"payload", method="POST")
    assert st == 200 and r.endswith(b"app:bob:payload")
    assert auth.requests[-1].body == b"" and auth.requests[-1].method == "GET"


def test_auth_before_cache(bastion, auth, app):
    allowed = {"v": True}
    auth.handler = lambda r, c: ok("", 200, (("X-User", "a"),)) if allowed["v"] else ok("no", 401)
    srv = bastion(conf(auth, app, cache=True))
    assert raw(srv.ports["http"])[0] == 200  # stored
    allowed["v"] = False
    st, r = raw(srv.ports["http"])
    assert st == 401 and b"app:" not in r  # the cached copy is not served


def test_fail_open_rejected(bastion, auth, app):
    with pytest.raises(pytest.fail.Exception, match="no fail-open"):
        bastion(conf(auth, app, "fail=open"))


# ---- mTLS per location, and combinations ----

def mtls_conf(certs, locs):
    return (f"workers 1;\nserver {{ listen 127.0.0.1:@HTTPS_PORT@ tls; tls_cert {certs}/ecdsa-chain.crt "
            f"{certs}/ecdsa.key; tls_client_auth optional; tls_client_ca {certs}/ca.crt;\n{locs} }}\n")


def test_mtls_location(bastion, certs):
    srv = bastion(mtls_conf(certs, 'location / { auth_mtls "CN=client one"; return 200 "in $auth_user"; }\n'
                                   'location /any/ { auth_mtls on; return 200 "any"; }'))
    st, body, _, _ = tls_request(srv, certs, "client")
    assert st == 200 and body == "in CN=client one"
    assert tls_request(srv, certs, None)[0] == 403
    assert tls_request(srv, certs, "client", path="/any/")[0] == 200


def test_auth_combination(bastion, certs, keys):  # noqa: F811
    k, pub = keys
    srv = bastion(mtls_conf(certs, f"location / {{ auth_require all; auth_mtls on; auth_jwt keys={pub}; "
                                   f"return 200 \"both\"; }}"))
    tok = token(k, {"sub": "u", "exp": int(time.time()) + 60})
    import ssl
    from test_tls_conn import client_ctx, read_response

    def go(client, auth_hdr):
        ctx = client_ctx(certs, None, None)
        if client:
            ctx.load_cert_chain(certs / "client.crt", certs / "client.key")
        s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", srv.ports["https"]), 10),
                            server_hostname="localhost")
        s.sendall(f"GET / HTTP/1.1\r\nHost: localhost\r\n{auth_hdr}Connection: close\r\n\r\n".encode())
        st = read_response(s)[0]
        s.close()
        return st
    bear = f"Authorization: Bearer {tok}\r\n"
    assert go(True, bear) == 200
    assert go(False, bear) == 403  # JWT alone is not enough
    assert go(True, "") == 401     # nor the certificate alone
    assert ssl  # imported for client_ctx's sake
