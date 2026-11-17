"""The proof-of-work challenge (Phase 12, Task 5): the page and its token, the verify endpoint,
the pass cookie, custom pages, non-browser clients, the allowlist, open redirects, CSP under
security_headers strict, a flood of junk answers, cookie flags and the cache.

The browser itself is simulated: Python reads window.BASTION from the page, does the same work
the script does and posts the same form. test_browser_flow needs a headless browser and is
skipped when none is installed."""
import hashlib
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import time
import urllib.parse
from pathlib import Path

import pytest

from test_tls_conn import client_ctx
from upstream_util import Upstream, ok

ROOT = Path(__file__).resolve().parents[2]
HTML = "Accept: text/html,application/xhtml+xml\r\n"


def raw(port, data, tls_ctx=None, timeout=10):
    s = socket.create_connection(("127.0.0.1", port), timeout)
    if tls_ctx is not None:
        s = tls_ctx.wrap_socket(s, server_hostname="localhost")
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
    head, _, body = out.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    status = int(lines[0].split()[1]) if lines and lines[0] else 0
    hdrs = {}
    for ln in lines[1:]:
        k, _, v = ln.partition(":")
        hdrs.setdefault(k.strip().lower(), []).append(v.strip())
    return status, hdrs, body


def get(port, path="/", extra=HTML, tls_ctx=None):
    return raw(port, f"GET {path} HTTP/1.1\r\nHost: localhost\r\n{extra}Connection: close\r\n\r\n".encode(),
               tls_ctx)


def post(port, fields, extra="", tls_ctx=None, path="/.bastion/challenge"):
    body = urllib.parse.urlencode(fields).encode()
    return raw(port, (f"POST {path} HTTP/1.1\r\nHost: localhost\r\n{extra}"
                      "Content-Type: application/x-www-form-urlencoded\r\n"
                      f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() + body, tls_ctx)


def bastion_obj(page):
    m = re.search(rb"window\.BASTION=(\{.*?\});</script>", page)
    assert m, page[:400]
    return json.loads(m.group(1))


def zero_bits(h):
    n = 0
    for b in h:
        if b == 0:
            n += 8
            continue
        return n + (8 - b.bit_length())
    return n


def solve(token, bits):
    n = 0
    while zero_bits(hashlib.sha256(f"{token}.{n}".encode()).digest()) < bits:
        n += 1
    return str(n)


def pass_cookie(hdrs, name="bastion_pass"):
    for c in hdrs.get("set-cookie", []):
        if c.startswith(name + "="):
            return c
    return None


def browser(port, path="/", tls_ctx=None):
    """What the default page's script does, in Python: the cookie it ends with."""
    st, h, page = get(port, path, tls_ctx=tls_ctx)
    assert st == 403 and h["cache-control"] == ["no-store"], (st, h)
    b = bastion_obj(page)
    nonce = solve(b["token"], b["difficulty"])
    st, h, _ = post(port, {"token": b["token"], "nonce": nonce, "redirect": b["redirect"]}, tls_ctx=tls_ctx)
    assert st == 303, (st, h)
    return h, pass_cookie(h)


CONF = ("workers 1;\nserver {{ listen 127.0.0.1:@HTTP_PORT@; challenge on; challenge_difficulty 10; {extra}\n"
        "location / {{ return 200 \"secret page\"; }}\n"
        "location /api/ {{ challenge off; return 200 \"api\"; }} }}\n")


def test_valid_flow(bastion):
    srv = bastion(CONF.format(extra=""))
    p = srv.ports["http"]
    st, h, page = get(p, "/docs/a?x=1")
    assert st == 403 and b"Checking your browser" in page
    b = bastion_obj(page)
    assert b["difficulty"] == 10 and b["verifyUrl"] == "/.bastion/challenge" and b["redirect"] == "/docs/a?x=1"
    assert b"BASTION.solve" in page or b"B.solve" in page  # the client script is inlined
    h, cookie = browser(p, "/docs/a?x=1")
    assert h["location"] == ["/docs/a?x=1"]
    value = cookie.split(";")[0]
    st, _, body = get(p, "/docs/a?x=1", extra=f"Cookie: {value}\r\n")
    assert st == 200 and body == b"secret page"
    # a forged or stale pass is challenged again
    st, _, _ = get(p, "/", extra="Cookie: bastion_pass=9999999999.00000000000000000000000000000000\r\n")
    assert st == 403
    assert get(p, "/api/x")[0] == 200  # `challenge off` in a location
    # wrong nonce, a GET to the endpoint
    st, _, _ = post(p, {"token": b["token"], "nonce": "x", "redirect": "/"})
    assert st == 403
    assert get(p, "/.bastion/challenge")[0] == 405


def test_non_html_client(bastion):
    srv = bastion(CONF.format(extra=""))
    st, h, body = get(srv.ports["http"], extra="Accept: application/json\r\n")
    assert st == 403 and h["content-type"][0].startswith("text/plain")
    assert h["bastion-challenge"] == ["required"] and h["cache-control"] == ["no-store"]
    assert b"<script" not in body


def test_challenge_allow(bastion):
    srv = bastion(CONF.format(extra="challenge_allow 127.0.0.0/8;"))
    st, _, body = get(srv.ports["http"])
    assert st == 200 and body == b"secret page"


def test_open_redirect(bastion):
    srv = bastion(CONF.format(extra=""))
    p = srv.ports["http"]
    for evil in ("https://evil.example/", "//evil.example/x", "/\\evil.example", "javascript:alert(1)",
                 "/ok\r\nSet-Cookie: x=1"):
        _, _, page = get(p)
        b = bastion_obj(page)
        st, h, _ = post(p, {"token": b["token"], "nonce": solve(b["token"], 10), "redirect": evil})
        assert st == 303 and h["location"] == ["/"], (evil, h)


def test_challenge_csp(bastion):
    srv = bastion(CONF.format(extra="security_headers strict;"))
    st, h, page = get(srv.ports["http"])
    assert st == 403
    csp = h["content-security-policy"]
    assert len(csp) == 1, csp  # ours, not the preset as well
    nonce = re.search(r"script-src 'nonce-([0-9a-f]{32})'", csp[0]).group(1)
    scripts = re.findall(rb"<script([^>]*)>", page)
    assert scripts and all(f'nonce="{nonce}"'.encode() in s for s in scripts), scripts
    assert "worker-src blob:" in csp[0]
    # a second response gets another nonce
    _, h2, _ = get(srv.ports["http"])
    assert h2["content-security-policy"] != csp
    # the rest of the strict preset is still there
    assert h["x-frame-options"] == ["DENY"]


def test_verify_endpoint_flood(bastion):
    srv = bastion(CONF.format(extra="challenge_escalate after=50 window=10s block=60s;"))
    p = srv.ports["http"]
    t0 = time.monotonic()
    codes = []
    for i in range(60):
        st, _, _ = post(p, {"token": f"{i}.junk.junk", "nonce": "1", "redirect": "/"})
        codes.append(st)
    elapsed = time.monotonic() - t0
    assert codes[:50] == [403] * 50, codes
    assert elapsed < 10, elapsed  # each junk answer is a MAC check, no work
    srv.wait_log(re.escape("escalate: blocked 127.0.0.1/32 for 60s (challenge)"), timeout=5)
    for _ in range(3):
        st, _, _ = post(p, {"token": "x", "nonce": "1", "redirect": "/"})
        if st == 0:
            break
        time.sleep(0.1)
    assert st == 0  # closed at accept
    # an oversized body is refused before any work
    srv2 = bastion(CONF.format(extra=""))
    st, _, _ = post(srv2.ports["http"], {"token": "x" * 5000, "nonce": "1", "redirect": "/"})
    assert st == 413


def test_cookie_flags(bastion, certs):
    srv = bastion(CONF.format(extra=""))
    _, cookie = browser(srv.ports["http"])
    attrs = [a.strip() for a in cookie.split(";")]
    assert "HttpOnly" in attrs and "SameSite=Lax" in attrs and "Path=/" in attrs
    assert "Secure" not in attrs  # cleartext
    tls = (f"workers 1;\nserver {{ listen 127.0.0.1:@HTTPS_PORT@ tls; tls_cert {certs}/ecdsa-chain.crt "
           f"{certs}/ecdsa.key; challenge on; challenge_difficulty 8; challenge_cookie_name gate;\n"
           "location / { return 200 \"ok\"; } }\n")
    srv = bastion(tls)
    ctx = client_ctx(certs)
    st, h, page = get(srv.ports["https"], tls_ctx=ctx)
    b = bastion_obj(page)
    st, h, _ = post(srv.ports["https"], {"token": b["token"], "nonce": solve(b["token"], 8), "redirect": "/"},
                    tls_ctx=ctx)
    c = pass_cookie(h, "gate")
    assert c and "Secure" in [a.strip() for a in c.split(";")], h


def test_not_cached(bastion):
    up = Upstream()
    try:
        up.handler = lambda r, c: ok(b"origin", 200, (("Cache-Control", "max-age=60"),))
        srv = bastion(f"workers 1;\ncache_store main {{ disk @WORKDIR@/cache size=100m; }}\n"
                      f"server {{ listen 127.0.0.1:@HTTP_PORT@; challenge on; challenge_difficulty 8;\n"
                      f"location / {{ proxy {up.url}; cache main; }} }}\n")
        p = srv.ports["http"]
        st, h, page = get(p, "/c")
        assert st == 403 and "cache-status" not in h  # answered before the cache
        assert len(up.requests) == 0
        _, cookie = browser(p, "/c")
        value = cookie.split(";")[0]
        st, h, body = get(p, "/c", extra=f"Cookie: {value}\r\n")
        assert st == 200 and body == b"origin"
        # the stored object is the origin's, never a challenge
        st, h, body = get(p, "/c", extra=f"Cookie: {value}\r\n")
        assert st == 200 and body == b"origin" and h["cache-status"][0].startswith("bastion; hit")
        # and an unchallenged client still gets the challenge, not the cached page
        assert get(p, "/c")[0] == 403
    finally:
        up.close()


def test_custom_page(bastion):
    page = ROOT / "examples" / "challenge" / "custom.html"
    srv = bastion(CONF.format(extra=f"challenge_page {page};"))
    p = srv.ports["http"]
    st, h, body = get(p)
    assert st == 403 and b"custom-challenge" in body  # the example's own markup
    assert b"{{bastion_challenge}}" not in body and b"{{bastion_nonce}}" not in body
    nonce = re.search(r"'nonce-([0-9a-f]{32})'", h["content-security-policy"][0]).group(1)
    assert f'nonce="{nonce}"'.encode() in body  # the page's own script carries the nonce
    # the page computes the proof itself from window.BASTION (the documented steps)
    b = bastion_obj(body)
    st, h, _ = post(p, {"token": b["token"], "nonce": solve(b["token"], b["difficulty"]), "redirect": b["redirect"]})
    assert st == 303 and pass_cookie(h)


def test_missing_placeholder(bastion_bin, tmp_path):
    page = tmp_path / "plain.html"
    page.write_text("<html><body>no placeholder</body></html>\n")
    conf = tmp_path / "c.conf"
    conf.write_text(f"server {{ listen 127.0.0.1:1; challenge on; challenge_page {page}; }}\n")
    r = subprocess.run([str(bastion_bin), "-t", "-c", str(conf)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert "warning" in r.stderr and "{{bastion_challenge}}" in r.stderr, r.stderr


def test_waf_action_challenge(bastion):
    rules = "waf_rule bots { match user_agent ~ (?i)bot; action challenge; }"
    srv = bastion(f"workers 1;\n{rules}\nserver {{ listen 127.0.0.1:@HTTP_PORT@; waf bots; challenge_difficulty 8;\n"
                  "location / { return 200 \"ok\"; } }\n")
    p = srv.ports["http"]
    assert get(p)[0] == 200  # challenge off: only the rule challenges
    ua = "User-Agent: somebot/1.0\r\n"
    st, _, page = get(p, extra=HTML + ua)
    assert st == 403
    b = bastion_obj(page)
    st, h, _ = post(p, {"token": b["token"], "nonce": solve(b["token"], 8), "redirect": "/"}, extra=ua)
    assert st == 303
    value = pass_cookie(h).split(";")[0]
    assert get(p, extra=HTML + ua + f"Cookie: {value}\r\n")[0] == 200


def find_browser():
    for b in ("chromium", "chromium-browser", "google-chrome", "headless_shell"):
        if shutil.which(b):
            return shutil.which(b)
    return None


@pytest.mark.skipif(find_browser() is None, reason="no headless browser installed: NOT executed")
def test_browser_flow(bastion):
    srv = bastion(CONF.format(extra=""))
    url = f"http://127.0.0.1:{srv.ports['http']}/"
    r = subprocess.run([find_browser(), "--headless", "--disable-gpu", "--no-sandbox",
                        "--virtual-time-budget=20000", "--dump-dom", url],
                       capture_output=True, text=True, timeout=60)
    assert "secret page" in r.stdout, r.stdout[-500:]
