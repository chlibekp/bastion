"""JWT auth through the real server (Phase 11, Task 5). Tokens are ES256, signed with the
openssl CLI (the image has no Python JOSE library); the edge cases of verification itself are in
tests/unit/test_jwt.c."""
import base64
import json
import socket
import subprocess
import time

import pytest

from upstream_util import Upstream, ok


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def der_to_raw(der, n=32):
    """ECDSA DER signature to JOSE r||s."""
    assert der[0] == 0x30
    i = 2 if der[1] < 0x80 else 3
    out = b""
    for _ in range(2):
        assert der[i] == 0x02
        ln = der[i + 1]
        v = der[i + 2:i + 2 + ln]
        out += v.lstrip(b"\0").rjust(n, b"\0")
        i += 2 + ln
    return out


@pytest.fixture
def keys(tmp_path):
    k = tmp_path / "ec.key"
    subprocess.run(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(k)],
                   check=True)
    pub = tmp_path / "ec.pub"
    subprocess.run(["openssl", "ec", "-in", str(k), "-pubout", "-out", str(pub)], check=True,
                   capture_output=True)
    return k, pub


def token(key, claims, header=None):
    h = b64u(json.dumps(header or {"alg": "ES256", "typ": "JWT"}).encode())
    p = b64u(json.dumps(claims).encode())
    der = subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(key)], input=f"{h}.{p}".encode(),
                         capture_output=True, check=True).stdout
    return f"{h}.{p}.{b64u(der_to_raw(der))}"


def get(port, extra=""):
    s = socket.create_connection(("127.0.0.1", port), 10)
    s.sendall(f"GET /api/x HTTP/1.1\r\nHost: x\r\n{extra}Connection: close\r\n\r\n".encode())
    out = b""
    while True:
        d = s.recv(65536)
        if not d:
            break
        out += d
    s.close()
    return int(out.split(b" ", 2)[1]), out


@pytest.fixture
def up():
    u = Upstream()
    u.handler = lambda r, c: ok("up:" + str(r.get("x-user")))
    yield u
    u.close()


def conf(pub, up, extra=""):
    return (f"workers 1;\nserver {{ listen 127.0.0.1:@HTTP_PORT@;\n"
            f"location /api/ {{ auth_jwt keys={pub} alg=ES256 iss=https://idp aud=api leeway=5s; "
            f"auth_jwt_claim_header sub X-User; {extra} proxy {up.url}; }} }}\n")


def bearer(t):
    return f"Authorization: Bearer {t}\r\n"


def test_jwt_allow_deny(bastion, keys, up):
    k, pub = keys
    srv = bastion(conf(pub, up))
    now = int(time.time())
    good = {"sub": "u1", "iss": "https://idp", "aud": ["api"], "exp": now + 60}
    st, r = get(srv.ports["http"], bearer(token(k, good)))
    assert st == 200 and r.endswith(b"up:u1")
    for bad in (dict(good, exp=now - 60), dict(good, iss="https://evil"), dict(good, aud="web")):
        st, r = get(srv.ports["http"], bearer(token(k, bad)))
        assert st == 401 and b"WWW-Authenticate: Bearer" in r
    assert get(srv.ports["http"])[0] == 401
    # alg none, with the same claims
    none = b64u(b'{"alg":"none"}') + "." + b64u(json.dumps(good).encode()) + "."
    assert get(srv.ports["http"], bearer(none))[0] == 401
    assert len(up.requests) == 1


def test_claim_header_injection(bastion, keys, up):
    k, pub = keys
    srv = bastion(conf(pub, up))
    now = int(time.time())
    evil = {"sub": "a\r\nX-Admin: 1", "iss": "https://idp", "aud": "api", "exp": now + 60}
    st, r = get(srv.ports["http"], bearer(token(k, evil)) + "X-User: spoofed\r\n")
    assert st == 200 and r.endswith(b"up:None")  # never a header, and the client's copy gone
    assert up.requests[-1].get("x-admin") is None


def test_jwks_file_and_url(bastion, keys, up, tmp_path):
    k, pub = keys
    with pytest.raises(pytest.fail.Exception, match="not supported yet"):
        bastion(conf("https://idp/jwks.json", up))
    with pytest.raises(pytest.fail.Exception, match="can not load"):
        bastion(conf(tmp_path / "missing.json", up))
