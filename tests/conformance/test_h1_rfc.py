"""HTTP/1.1 conformance: every entry of h1_rfc_requirements.yaml against the real binary, on both
backends. A failing entry is either a bug (fix the code) or a deliberate deviation, which carries
`deviation:` in the corpus and is explained in docs/conformance.md."""
import re
from pathlib import Path

import pytest

from process_util import connect
from test_h1_conn import Reader, conf

CORPUS = Path(__file__).with_name("h1_rfc_requirements.yaml")


def parse_corpus(text):
    """The corpus is a list of flat mappings with integer, boolean or double-quoted values: a
    subset of YAML read here so the suite needs no YAML library."""
    entries, cur = [], None
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        m = re.fullmatch(r"(- |  )([a-z_0-9]+): (.*)", line)
        if not m:
            raise ValueError(f"{CORPUS.name}:{n}: cannot parse {line!r}")
        if m.group(1) == "- ":
            cur = {}
            entries.append(cur)
        cur[m.group(2)] = scalar(m.group(3), n)
    return entries


def scalar(v, n):
    if re.fullmatch(r"-?\d+", v):
        return int(v)
    if v in ("true", "false"):
        return v == "true"
    if len(v) >= 2 and v[0] == v[-1] == '"':
        out, i, body = [], 0, v[1:-1]
        while i < len(body):
            c = body[i]
            if c != "\\":
                out.append(ord(c))
                i += 1
                continue
            e = body[i + 1]
            if e == "x":
                out.append(int(body[i + 2:i + 4], 16))
                i += 4
                continue
            out.append({"r": 13, "n": 10, "t": 9, "0": 0, "\\": 92, '"': 34}[e])
            i += 2
        return bytes(out).decode("latin-1")
    if re.fullmatch(r"[A-Za-z0-9._-]+", v):
        return v  # a plain scalar: the ids
    raise ValueError(f"{CORPUS.name}:{n}: bad value {v!r}")


ENTRIES = parse_corpus(CORPUS.read_text())


def test_corpus_is_well_formed():
    ids = [e["id"] for e in ENTRIES]
    assert len(ids) == len(set(ids)), "duplicate ids"
    for e in ENTRIES:
        for key in ("id", "rfc", "level", "text", "request", "status", "close"):
            assert key in e, f"{e.get('id')}: missing {key}"
        assert e["level"] in ("MUST", "MUST NOT", "SHOULD", "SHOULD NOT", "MAY"), e["id"]
        assert re.search(r"RFC \d+", e["rfc"]), e["id"]
    assert len(ENTRIES) >= 50


def build_request(e):
    req = e["request"]
    if "pad" in e:
        req = req.replace("{pad}", "a" * e["pad"])
    if "headers" in e:
        req = req.replace("{headers}", "".join(f"X-H{i}: v\r\n" for i in range(e["headers"])))
    return req.encode("latin-1")


@pytest.mark.parametrize("entry", ENTRIES, ids=[e["id"] for e in ENTRIES])
def test_requirement(bastion, entry):
    ret = entry.get("server_return", 'return 200 "ok";')
    srv = bastion(conf(ret=ret, server_extra=entry.get("server", "")))
    s = connect(srv.ports["http"])
    r = Reader(s)
    s.sendall(build_request(entry))
    head = entry.get("head", False)
    last = None
    for _ in range(entry.get("responses", 1)):
        last = r.response(head_only=head)
        assert last[0] == entry["status"], (entry["text"], last)
    status, headers, body = last
    for name in filter(None, entry.get("present", "").split(",")):
        assert name in headers, f"{entry['id']}: response lacks {name}: {headers}"
    for name in filter(None, entry.get("absent", "").split(",")):
        assert name not in headers, f"{entry['id']}: response has {name}: {headers}"
    if head:
        assert body == b""
    if entry["close"]:
        assert r.closed(), f"{entry['id']}: connection stayed open"
        if entry.get("only_one_response"):
            assert r.buf == b""
    else:
        assert not r.closed(timeout=0.2), f"{entry['id']}: connection was closed"
        follow = entry.get("then", "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        s.sendall(follow.encode("latin-1"))
        assert r.response()[0] == entry.get("then_status", 200), "connection out of step"
    s.close()
