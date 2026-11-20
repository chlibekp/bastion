"""Feature matrix (Phase 15, Task 2): pairwise combinations of the features a request can meet,
each cell one real front server (and, for the proxy handlers, a real Bastion upstream), each
asserting the exact body, the headers the features promise, and correct framing.

Factors: backend (uring, epoll); protocol (h1, h1+TLS, h1+kTLS, h2, h3); handler (static,
proxy-h1, proxy-h2); cache (off, miss, hit, stale); compression (off, gzip, br, zstd); auth
(off, basic, JWT); filter (WAF, limit, challenge). A cache state other than off needs a proxy
handler (the cache sits in front of upstreams only), the one constraint. The cells come from a
deterministic greedy all-pairs cover; `test_cover_is_pairwise` proves every allowed pair of
values meets in at least one cell.

h1+kTLS asks for `ktls tx`. Docker Desktop's kernel has no TLS ULP, so there the cell exercises
the user-space fallback after a kTLS request; tests/vm/test_ktls.py covers kTLS proper.

Every cell also checks the feature's refusal on the same protocol: no credentials is 401, the
WAF rule's trigger header is 403, no challenge pass is the 403 challenge page; a limit cell checks
the RateLimit headers. Body bytes are compared exactly after the coding is removed (gzip by
Python, zstd by the zstd CLI, br by libbrotlidec through ctypes)."""
import base64
import ctypes
import ctypes.util
import gzip
import hashlib
import itertools
import json
import re
import shutil
import socket
import ssl
import subprocess
import time
import urllib.parse

import pytest

from quic_util import h3client_bin

FACTORS = [
    ("backend", ["uring", "epoll"]),
    ("protocol", ["h1", "h1tls", "h1ktls", "h2", "h3"]),
    ("handler", ["static", "proxy_h1", "proxy_h2"]),
    ("cache", ["off", "miss", "hit", "stale"]),
    ("compression", ["off", "gzip", "br", "zstd"]),
    ("auth", ["off", "basic", "jwt"]),
    ("filter", ["waf", "limit", "challenge"]),
]
NAMES = [n for n, _ in FACTORS]

BODY = ("".join(f"line {i:04d}: the quick brown fox jumps over the lazy dog\n" for i in range(52))).encode()
assert 2500 < len(BODY) < 4096  # h3client --print-body keeps 4096 bytes
PW = "matrix pw"
HOP = ("connection", "keep-alive", "transfer-encoding", "upgrade", "proxy-connection")


def allowed(cell):
    """The one constraint: a cache state needs a proxy handler."""
    return not (cell.get("cache", "off") != "off" and cell.get("handler") == "static")


def pairwise():
    """A deterministic greedy all-pairs cover of FACTORS under `allowed`."""
    def pairs_of(cell):
        return {((a, cell[a]), (b, cell[b])) for a, b in itertools.combinations(NAMES, 2)}

    todo = set()
    for (a, va), (b, vb) in itertools.combinations(FACTORS, 2):
        for x in va:
            for y in vb:
                if allowed({a: x, b: y}):
                    todo.add(((a, x), (b, y)))
    cells = []
    while todo:
        (a, x), (b, y) = min(todo, key=lambda p: (NAMES.index(p[0][0]), NAMES.index(p[1][0]), str(p)))
        cell = {a: x, b: y}
        for name, values in FACTORS:
            if name in cell:
                continue
            best, gain = None, -1
            for v in values:
                trial = dict(cell, **{name: v})
                if not allowed(trial):
                    continue
                g = sum(1 for (p, q) in todo if (p[0] == name and p[1] == v and trial.get(q[0]) == q[1])
                        or (q[0] == name and q[1] == v and trial.get(p[0]) == p[1]))
                if g > gain:
                    best, gain = v, g
            cell[name] = best
        cells.append(cell)
        todo -= pairs_of(cell)
    return cells


CELLS = pairwise()


def cell_id(c):
    return "-".join(c[n] for n in NAMES)


def test_cover_is_pairwise():
    for (a, va), (b, vb) in itertools.combinations(FACTORS, 2):
        for x in va:
            for y in vb:
                if allowed({a: x, b: y}):
                    assert any(c[a] == x and c[b] == y for c in CELLS), (a, x, b, y)
    assert all(allowed(c) for c in CELLS)
    assert len(CELLS) <= 40, len(CELLS)


# --- decoding --------------------------------------------------------------------------------

_brotli = None


def unbrotli(data):
    global _brotli
    if _brotli is None:
        path = ctypes.util.find_library("brotlidec")
        if path is None:
            pytest.fail("libbrotlidec is needed to check br bodies")
        _brotli = ctypes.CDLL(path)
    out = ctypes.create_string_buffer(1 << 20)
    n = ctypes.c_size_t(len(out))
    rc = _brotli.BrotliDecoderDecompress(ctypes.c_size_t(len(data)), data, ctypes.byref(n), out)
    assert rc == 1, "br body does not decode"
    return out.raw[:n.value]


def decode(coding, data):
    if coding is None:
        return data
    if coding == "gzip":
        return gzip.decompress(data)
    if coding == "zstd":
        p = subprocess.run(["zstd", "-dcq"], input=data, capture_output=True, timeout=30)
        assert p.returncode == 0, p.stderr
        return p.stdout
    if coding == "br":
        return unbrotli(data)
    pytest.fail(f"unexpected content-coding {coding!r}")


# --- clients: each returns (status, {name: [values]}, body bytes as received) -----------------

def h1_strict(raw):
    """Parses one HTTP/1.1 response read to EOF, failing on any framing error: both
    Content-Length and Transfer-Encoding, a body longer or shorter than declared, a malformed
    chunk, or bytes after the last chunk."""
    head, sep, rest = raw.partition(b"\r\n\r\n")
    assert sep, f"no end of head in {raw[:200]!r}"
    lines = head.decode("latin-1").split("\r\n")
    m = re.match(r"HTTP/1\.1 (\d{3}) ", lines[0] + " ")
    assert m, lines[0]
    hdrs = {}
    for ln in lines[1:]:
        k, colon, v = ln.partition(":")
        assert colon and k == k.strip() and k, f"bad header line {ln!r}"
        hdrs.setdefault(k.lower(), []).append(v.strip())
    te, cl = hdrs.get("transfer-encoding"), hdrs.get("content-length")
    assert not (te and cl), hdrs
    if te:
        assert te == ["chunked"], te
        body, pos = b"", 0
        while True:
            end = rest.index(b"\r\n", pos)
            size = int(rest[pos:end].split(b";")[0], 16)
            pos = end + 2
            if size == 0:
                assert rest[pos:] == b"\r\n", f"after last chunk: {rest[pos:]!r}"
                break
            body += rest[pos:pos + size]
            assert rest[pos + size:pos + size + 2] == b"\r\n", "chunk not followed by CRLF"
            pos += size + 2
    elif cl:
        assert len(cl) == 1 and len(rest) == int(cl[0]), (cl, len(rest))
        body = rest
    else:
        body = rest  # close-delimited
    return int(m.group(1)), hdrs, body


def h1_fetch(port, path, headers, tls_ctx=None):
    s = socket.create_connection(("127.0.0.1", port), 30)
    if tls_ctx is not None:
        s = tls_ctx.wrap_socket(s, server_hostname="localhost")
    extra = "".join(f"{k}: {v}\r\n" for k, v in headers)
    s.sendall(f"GET {path} HTTP/1.1\r\nHost: localhost\r\n{extra}Connection: close\r\n\r\n".encode())
    out = b""
    while True:
        d = s.recv(65536)
        if not d:
            break
        out += d
    s.close()
    return h1_strict(out)


def h1_post(port, path, form):
    body = urllib.parse.urlencode(form).encode()
    s = socket.create_connection(("127.0.0.1", port), 30)
    s.sendall((f"POST {path} HTTP/1.1\r\nHost: localhost\r\n"
               "Content-Type: application/x-www-form-urlencoded\r\n"
               f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() + body)
    out = b""
    while True:
        d = s.recv(65536)
        if not d:
            break
        out += d
    s.close()
    return h1_strict(out)


def h2_fetch(port, path, headers, tmp):
    hfile, bfile = tmp / "h2.head", tmp / "h2.body"
    args = ["curl", "-sk", "--http2", "--max-time", "30", "-D", str(hfile), "-o", str(bfile),
            "-w", "%{http_version}"]
    for k, v in headers:
        args += ["-H", f"{k}: {v}"]
    p = subprocess.run(args + [f"https://127.0.0.1:{port}{path}"], capture_output=True, text=True, timeout=60)
    assert p.returncode == 0, f"curl rc={p.returncode} (a framing error is 8, 18 or 92): {p.stderr}"
    assert p.stdout == "2", p.stdout
    lines = hfile.read_text("latin-1").splitlines()
    m = re.match(r"HTTP/2 (\d{3})", lines[0])
    assert m, lines[0]
    hdrs = {}
    for ln in lines[1:]:
        if ln:
            k, _, v = ln.partition(":")
            hdrs.setdefault(k.lower(), []).append(v.strip())
    return int(m.group(1)), hdrs, bfile.read_bytes()


def h3_fetch(port, path, headers, whole=True):
    opts = ["--print-body"]
    for k, v in headers:
        opts += ["--header", f"{k.lower()}: {v}"]
    cmd = [h3client_bin(), "--timeout", "20000", *opts, "127.0.0.1", str(port), path]
    p = subprocess.run(cmd, capture_output=True, timeout=40)
    lines = [json.loads(ln) for ln in p.stdout.decode().splitlines() if ln.startswith("{")]
    resp = [ln for ln in lines if ln.get("type") == "resp"]
    assert p.returncode == 0 and len(resp) == 1, (p.returncode, lines, p.stderr[-2000:])
    r = resp[0]
    assert r["reset"] is None and not r["cancelled"], r
    body = r["body"].encode("latin-1")
    if whole:
        assert r["len"] == len(body) and hashlib.sha256(body).hexdigest() == r["sha256"], "body over 4096 bytes"
    hdrs = {k.lower(): [x.strip() for x in v.split(",")] if k.lower() in ("vary",) else [v]
            for k, v in r["headers"].items()}
    return r["status"], hdrs, body


# --- fixtures --------------------------------------------------------------------------------

def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def der_to_raw(der, n=32):
    i = 2 if der[1] < 0x80 else 3
    out = b""
    for _ in range(2):
        ln = der[i + 1]
        out += der[i + 2:i + 2 + ln].lstrip(b"\0").rjust(n, b"\0")
        i += 2 + ln
    return out


@pytest.fixture(scope="module")
def assets(tmp_path_factory, bastion_bin):
    d = tmp_path_factory.mktemp("matrix")
    www = d / "www"
    www.mkdir()
    (www / "page.txt").write_bytes(BODY)
    p = subprocess.run([bastion_bin, "passwd", "-m", "19456", "-t", "2", "alice"], input=PW + "\n",
                       capture_output=True, text=True, timeout=60)
    assert p.returncode == 0, p.stderr
    (d / "users").write_text(p.stdout.strip() + "\n")
    key = d / "ec.key"
    subprocess.run(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(key)],
                   check=True, capture_output=True)
    subprocess.run(["openssl", "ec", "-in", str(key), "-pubout", "-out", str(d / "ec.pub")], check=True,
                   capture_output=True)
    h = b64u(json.dumps({"alg": "ES256", "typ": "JWT"}).encode())
    c = b64u(json.dumps({"sub": "u1", "iss": "https://idp", "aud": "api",
                         "exp": int(time.time()) + 3600}).encode())
    der = subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(key)], input=f"{h}.{c}".encode(),
                         capture_output=True, check=True).stdout
    return {"dir": d, "www": www, "users": d / "users", "pub": d / "ec.pub",
            "jwt": f"{h}.{c}.{b64u(der_to_raw(der))}"}


def zero_bits(h):
    n = 0
    for b in h:
        if b == 0:
            n += 8
            continue
        return n + (8 - b.bit_length())
    return n


def challenge_cookie(port):
    """Passes the proof-of-work challenge on the plain listener, as the page's script would."""
    st, h, page = h1_fetch(port, "/page.txt", [("Accept", "text/html")])
    assert st == 403, (st, h)
    m = re.search(rb"window\.BASTION=(\{.*?\});</script>", page)
    assert m, page[:300]
    b = json.loads(m.group(1))
    n = 0
    while zero_bits(hashlib.sha256(f"{b['token']}.{n}".encode()).digest()) < b["difficulty"]:
        n += 1
    st, h, _ = h1_post(port, "/.bastion/challenge", {"token": b["token"], "nonce": str(n),
                                                     "redirect": b["redirect"]})
    assert st == 303, (st, h)
    for c in h.get("set-cookie", []):
        if c.startswith("bastion_pass="):
            return c.split(";")[0]
    pytest.fail(f"no pass cookie in {h}")


def upstream_conf(cell, www):
    # public: a shared cache stores a response to a request with Authorization only when the
    # origin says so (RFC 9111 section 3.5), and the auth cells send one
    cc = "public, max-age=1, stale-while-revalidate=60" if cell["cache"] == "stale" else "public, max-age=60"
    flag = " h2c" if cell["handler"] == "proxy_h2" else ""
    return (f"workers 1;\nserver {{ listen 127.0.0.1:@HTTP_PORT@{flag}; root {www}; "
            f"header_set Cache-Control \"{cc}\"; }}\n")


def front_conf(cell, assets, certs, up_port):
    glob, srv, loc = [], [], []
    proto, f = cell["protocol"], cell["filter"]
    srv.append("listen 127.0.0.1:@HTTP_PORT@;")
    if proto in ("h1tls", "h1ktls", "h2"):
        srv.append(f"listen 127.0.0.1:@HTTPS_PORT@ tls{' http2' if proto == 'h2' else ''};")
    if proto == "h3":
        srv.append("listen 127.0.0.1:@QUIC_PORT@ http3;")
    if proto != "h1":
        srv.append(f"tls_cert {certs}/ecdsa-chain.crt {certs}/ecdsa.key;")
    if proto == "h1ktls":
        glob.append("tls_profile k { ktls tx; }")
        srv.append("tls_profile k;")
    if cell["compression"] != "off":
        srv.append("compress zstd br gzip; compress_types text/plain;")
        if cell["auth"] != "off" or f == "challenge":
            # requests with credentials or a cookie are sent uncompressed by default (BREACH);
            # the cell is about the combination, so it opts in
            srv.append("compress_sensitive on;")
    if f == "waf":
        glob.append("waf_rule evil { match header:x-evil exists; action deny 403; }")
        srv.append("waf evil;")
    elif f == "limit":
        glob.append("limit_zone z { rate 100/s burst=50; }")
        srv.append("limit_headers on;")
        loc.append("limit z;")
    else:
        srv.append("challenge on; challenge_difficulty 4;")
    if cell["auth"] == "basic":
        loc.append(f"auth_basic \"Matrix\"; auth_basic_file {assets['users']};")
    elif cell["auth"] == "jwt":
        loc.append(f"auth_jwt keys={assets['pub']} alg=ES256 iss=https://idp aud=api leeway=5s;")
    if cell["handler"] == "static":
        srv.append(f"root {assets['www']};")
    else:
        h2 = " protocol http2;" if cell["handler"] == "proxy_h2" else ""
        glob.append(f"upstream u {{ server 127.0.0.1:{up_port};{h2} }}")
        loc.append("proxy u;")
    if cell["cache"] != "off":
        glob.append("cache_store main { disk @WORKDIR@/cache size=100m; }")
        loc.append("cache main;")
    return ("workers 1;\n" + "\n".join(glob) + "\nserver {\n  " + "\n  ".join(srv)
            + "\n  location / { " + " ".join(loc) + " }\n}\n")


# --- the matrix ------------------------------------------------------------------------------

@pytest.mark.skipif(shutil.which("curl") is None, reason="curl is needed for the h2 cells")
@pytest.mark.parametrize("cell", CELLS, ids=cell_id)
def test_cell(cell, bastion, certs, assets, tmp_path):
    up_port = None
    if cell["handler"] != "static":
        up = bastion(upstream_conf(cell, assets["www"]), backend=cell["backend"],
                     workdir=tmp_path / "upstream")
        up_port = up.ports["http"]
    srv = bastion(front_conf(cell, assets, certs, up_port), backend=cell["backend"], workdir=tmp_path / "front")
    proto = cell["protocol"]
    tls_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    tls_ctx.load_verify_locations(certs / "ca.crt")

    def fetch(headers, whole=True):
        if proto == "h1":
            return h1_fetch(srv.ports["http"], "/page.txt", headers)
        if proto in ("h1tls", "h1ktls"):
            return h1_fetch(srv.ports["https"], "/page.txt", headers, tls_ctx)
        if proto == "h2":
            return h2_fetch(srv.ports["https"], "/page.txt", headers, tmp_path)
        return h3_fetch(srv.ports["quic"], "/page.txt", headers, whole)

    creds = []
    if cell["auth"] == "basic":
        creds = [("Authorization", "Basic " + base64.b64encode(f"alice:{PW}".encode()).decode())]
    elif cell["auth"] == "jwt":
        creds = [("Authorization", f"Bearer {assets['jwt']}")]
    cookie = [("Cookie", challenge_cookie(srv.ports["http"]))] if cell["filter"] == "challenge" else []
    coding = None if cell["compression"] == "off" else cell["compression"]
    ae = [("Accept-Encoding", coding)] if coding else []
    headers = creds + cookie + ae

    if cell["cache"] in ("hit", "stale"):
        st, h, _ = fetch(headers)
        assert st == 200 and h["cache-status"][0].startswith("bastion; fwd=miss"), (st, h)
        if cell["cache"] == "stale":
            time.sleep(1.6)  # past max-age=1, inside stale-while-revalidate=60

    st, h, raw = fetch(headers)
    assert st == 200, (st, h, raw[:300])
    assert "date" in h, h
    enc = h.get("content-encoding")
    assert enc == ([coding] if coding else None), h
    if coding:
        assert any("accept-encoding" in v.lower() for v in h.get("vary", [])), h
    assert decode(coding, raw) == BODY
    if "content-length" in h:
        assert h["content-length"] == [str(len(raw))], (h, len(raw))
    if proto in ("h2", "h3"):
        assert not [k for k in HOP if k in h], h
    cs = h.get("cache-status", [""])[0]
    if cell["cache"] == "off":
        assert "cache-status" not in h, h
    elif cell["cache"] == "miss":
        assert cs.startswith("bastion; fwd=miss"), h
    elif cell["cache"] == "hit":
        assert cs.startswith("bastion; hit"), h
    else:
        assert "stale-while-revalidate" in cs, h
    if cell["filter"] == "limit":
        assert any(k == "ratelimit" for k in h), h

    # the refusals, on the same protocol
    if cell["auth"] != "off":
        st, h, _ = fetch(cookie + ae)
        assert st == 401 and "www-authenticate" in h, (st, h)
    if cell["filter"] == "waf":
        st, _, _ = fetch(headers + [("X-Evil", "1")])
        assert st == 403
    elif cell["filter"] == "challenge":
        st, h, body = fetch(creds + [("Accept", "text/html")], whole=False)
        assert st == 403 and h.get("cache-control") == ["no-store"], (st, h)
        assert b"window.BASTION=" in body
    assert "killed by signal" not in srv.logs(), srv.logs()
