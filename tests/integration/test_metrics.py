"""Prometheus metrics (src/ops/metrics.c, Phase 14 Task 4): the helper serves the text format from
per-process counter slots in shared memory. Off by default and never on a public listener; totals
are exact across workers and survive worker crashes and reloads; labels are bounded by the
configuration; the XDP stats and the `challenge auto` state are exported.

promtool is not in the dev image, so parse() below is a strict parser of the text exposition
format 0.0.4: it rejects anything the format does not allow rather than skipping it."""
import math
import os
import re
import signal
import socket
import statistics
import subprocess
import threading
import time

import pytest

from test_challenge_auto import Load as AttackLoad
from xdp_util import net, pin  # noqa: F401  (fixtures)

SYN = os.environ.get("SYNFLOOD", "")

METRIC_NAME = re.compile(r"[a-zA-Z_:][a-zA-Z0-9_:]*\Z")
LABEL_NAME = re.compile(r"[a-zA-Z_][a-zA-Z0-9_]*\Z")
SAMPLE = re.compile(r"([a-zA-Z_:][a-zA-Z0-9_:]*)(\{[^\n]*\})? (\S+)\Z")
TYPES = {"counter", "gauge", "histogram", "summary", "untyped"}


def parse_labels(text):
    """'{a="x",b="y\\"z"}' -> (('a', 'x'), ('b', 'y"z')). Raises on anything malformed."""
    assert text[0] == "{" and text[-1] == "}", text
    body, out, i = text[1:-1], [], 0
    while i < len(body):
        eq = body.index("=", i)
        name = body[i:eq]
        assert LABEL_NAME.match(name) and not name.startswith("__"), name
        assert body[eq + 1] == '"', text
        j, val = eq + 2, []
        while body[j] != '"':
            if body[j] == "\\":
                esc = body[j + 1]
                assert esc in '\\"n', f"bad escape in {text}"
                val.append("\n" if esc == "n" else esc)
                j += 2
            else:
                val.append(body[j])
                j += 1
        out.append((name, "".join(val)))
        i = j + 1
        if i < len(body):
            assert body[i] == ",", text
            i += 1
    names = [n for n, _ in out]
    assert len(names) == len(set(names)), f"duplicate label in {text}"
    return tuple(out)


def parse_value(v):
    if v in ("+Inf", "-Inf", "NaN"):
        return float(v.replace("Inf", "inf").replace("NaN", "nan"))
    assert re.fullmatch(r"-?[0-9]+(\.[0-9]+)?([eE][-+]?[0-9]+)?", v), v
    return float(v)


def parse(text):
    """Strict text-format parse: {(name, labels): value} plus {family: type}. Checks HELP/TYPE
    order, one TYPE per family before its samples, families contiguous, unique series, and
    histogram consistency (cumulative buckets, +Inf bucket == _count)."""
    assert text.endswith("\n"), "the exposition ends with a newline"
    samples, types, helped, seen_families, current = {}, {}, set(), [], None
    for line in text[:-1].split("\n"):
        assert line != "", "no blank lines"
        if line.startswith("# HELP "):
            name = line.split(" ", 3)[2]
            assert METRIC_NAME.match(name) and name not in helped, line
            helped.add(name)
            continue
        if line.startswith("# TYPE "):
            _, _, name, typ = line.split(" ")
            assert METRIC_NAME.match(name) and typ in TYPES and name not in types, line
            assert name not in seen_families, f"TYPE after samples of {name}"
            types[name] = typ
            current = name
            seen_families.append(name)
            continue
        assert not line.startswith("#"), line
        m = SAMPLE.match(line)
        assert m, f"not a sample line: {line!r}"
        name, labels = m.group(1), parse_labels(m.group(2)) if m.group(2) else ()
        family = name
        if current is not None and types.get(current) == "histogram":
            for sfx in ("_bucket", "_sum", "_count"):
                if name == current + sfx:
                    family = current
        assert family == current, f"{name} outside its family block (current {current})"
        key = (name, labels)
        assert key not in samples, f"duplicate series {key}"
        samples[key] = parse_value(m.group(3))
    for fam, typ in types.items():
        if typ != "histogram":
            continue
        series = {}
        for (name, labels), v in samples.items():
            if name == fam + "_bucket":
                base = tuple(x for x in labels if x[0] != "le")
                le = dict(labels)["le"]
                series.setdefault(base, []).append((parse_value(le), v))
        for base, buckets in series.items():
            buckets.sort()
            assert buckets[-1][0] == math.inf, f"{fam}{base} has no +Inf bucket"
            counts = [v for _, v in buckets]
            assert counts == sorted(counts), f"{fam}{base} buckets not cumulative"
            assert counts[-1] == samples[(fam + "_count", base)], f"{fam}{base} +Inf != _count"
            assert (fam + "_sum", base) in samples
    return samples, types


def scrape(srv, path="/metrics", headers="", port=None):
    """(status, headers text, body) of one scrape."""
    with socket.create_connection(("127.0.0.1", port or srv.ports["admin"]), timeout=10) as s:
        s.sendall(f"GET {path} HTTP/1.1\r\nHost: m\r\n{headers}\r\n".encode())
        data = b""
        while True:
            b = s.recv(65536)
            if not b:
                break
            data += b
    head, _, body = data.partition(b"\r\n\r\n")
    return int(head.split(b" ")[1]), head.decode(), body.decode()


def metrics(srv):
    status, _, body = scrape(srv)
    assert status == 200, body
    return parse(body)[0]


def value(samples, name, **labels):
    want = tuple(sorted(labels.items()))
    return sum(v for (n, l), v in samples.items() if n == name and tuple(sorted(x for x in l if x[0] in labels)) == want)


def conf(extra_metrics="", workers=2, glob=""):
    return (f"workers {workers};\n{glob}\n"
            f"metrics {{ listen 127.0.0.1:@ADMIN_PORT@; {extra_metrics} }}\n"
            "server { listen 127.0.0.1:@HTTP_PORT@; name a.test;\n"
            "location = /v { return 200 \"hello\"; }\nlocation /e { return 404; } }\n")


def get(port, path="/v", host="a.test"):
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
        s.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
        data = b""
        while True:
            b = s.recv(65536)
            if not b:
                break
            data += b
    return int(data.split(b" ")[1])


def requests_keepalive(port, n, host="a.test", allow_close=False):
    """n requests over one keep-alive connection, pipelined in batches; returns how many got 200.
    allow_close: a close before all are answered returns the count so far instead of failing."""
    ok = 0
    with socket.create_connection(("127.0.0.1", port), timeout=10) as s:
        sent = 0
        buf = b""
        while sent < n:
            batch = min(50, n - sent)
            s.sendall(f"GET /v HTTP/1.1\r\nHost: {host}\r\n\r\n".encode() * batch)
            sent += batch
            got = 0
            while got < batch:
                while b"hello" not in buf:
                    d = s.recv(65536)
                    if not d and allow_close:
                        return ok
                    assert d, "connection closed"
                    buf += d
                head, _, buf = buf.partition(b"hello")
                ok += head.startswith(b"HTTP/1.1 200") or b"HTTP/1.1 200" in head
                got += 1
    return ok


def wait_value(srv, want, name, **labels):
    return srv.wait_for(lambda: value(metrics(srv), name, **labels) == want, timeout=10,
                        what=f"{name}{labels} == {want}")


def test_format_valid(bastion):
    srv = bastion(conf())
    p = srv.ports["http"]
    assert get(p) == 200 and get(p, "/e") == 404 and get(p, host="nope.test") == 200
    srv.wait_for(lambda: value(metrics(srv), "bastion_http_requests_total") >= 3)
    status, head, body = scrape(srv)
    assert status == 200 and "text/plain; version=0.0.4" in head
    samples, types = parse(body)
    assert types["bastion_http_requests_total"] == "counter"
    assert types["bastion_http_request_duration_seconds"] == "histogram"
    assert types["bastion_config_reload_success"] == "gauge"
    assert value(samples, "bastion_http_requests_total", server="a.test", code="2xx", protocol="http1") == 1
    assert value(samples, "bastion_http_requests_total", server="a.test", code="4xx", protocol="http1") == 1
    assert value(samples, "bastion_http_requests_total", server="_other", code="2xx", protocol="http1") == 1
    assert value(samples, "bastion_build_info") == 1
    assert value(samples, "bastion_config_reload_success") == 1
    assert ("bastion_tls_handshakes_total", (("result", "ok"),)) in samples
    assert value(samples, "bastion_http_request_duration_seconds_count", protocol="http1") == 3
    # HEAD answers without a body; other paths and methods do not expose anything
    status, head, body = scrape(srv, path="/other")
    assert status == 404 and "bastion_" not in body


def test_counts_accurate(bastion):
    srv = bastion(conf(workers=4))
    srv.wait_workers(4)
    p = srv.ports["http"]
    results = []
    # 8 clients x 5 connections x 250 requests, under keepalive_requests
    threads = [threading.Thread(target=lambda: results.append(
        sum(requests_keepalive(p, 250) for _ in range(5)))) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sum(results) == 10000
    wait_value(srv, 10000, "bastion_http_requests_total", server="a.test", code="2xx", protocol="http1")
    samples = metrics(srv)
    assert value(samples, "bastion_http_request_duration_seconds_count", protocol="http1") == 10000


def test_survives_worker_crash(bastion):
    srv = bastion(conf(workers=2), env={"BST_TEST_RESPAWN_SCALE": "100"})
    srv.wait_workers(2)
    p = srv.ports["http"]
    assert requests_keepalive(p, 200) == 200
    wait_value(srv, 200, "bastion_http_requests_total", server="a.test", code="2xx")
    before = metrics(srv)
    victim = srv.workers()[0]
    os.kill(victim, signal.SIGKILL)
    srv.wait_for(lambda: srv.workers().get(0) not in (None, victim), what="worker 0 respawned")
    after = metrics(srv)
    for key, v in before.items():  # no counter goes down
        if key[0].endswith("_total") or key[0].endswith("_count"):
            assert after.get(key, 0) >= v, key
    assert value(after, "bastion_http_requests_total", server="a.test", code="2xx") == 200
    assert value(after, "bastion_worker_restarts_total") >= 1
    assert requests_keepalive(p, 50) == 50
    wait_value(srv, 250, "bastion_http_requests_total", server="a.test", code="2xx")


def test_counters_survive_reload(bastion):
    srv = bastion(conf(workers=2))
    p = srv.ports["http"]
    assert requests_keepalive(p, 100) == 100
    wait_value(srv, 100, "bastion_http_requests_total", server="a.test", code="2xx")
    n = len(re.findall(r"reload: generation \d+ ready", srv.logs()))
    srv.proc.send_signal(signal.SIGHUP)
    srv.wait_for(lambda: len(re.findall(r"reload: generation \d+ ready", srv.logs())) > n,
                 timeout=20, what="reload done")
    samples = srv.wait_for(lambda: (lambda s: s if s[0] == 200 else None)(scrape(srv)), timeout=10,
                           what="a scrape after the reload")
    assert value(parse(samples[2])[0], "bastion_http_requests_total", server="a.test", code="2xx") == 100
    # The connection can still land on the draining old generation, which answers what it has
    # read and closes: a client retries the rest, and every answered request is counted once.
    done = 0
    for _ in range(3):
        done += requests_keepalive(p, 10 - done, allow_close=True)
        if done == 10:
            break
    assert done == 10
    wait_value(srv, 110, "bastion_http_requests_total", server="a.test", code="2xx")
    # a failed reload sets the gauge to 0, and the old generation keeps serving metrics
    conf_path = srv.workdir / "bastion.conf"
    good = conf_path.read_text()
    conf_path.write_text(good + "\nthis is not valid;\n")
    srv.proc.send_signal(signal.SIGHUP)
    srv.wait_log("reload failed, still serving the old configuration")
    wait_value(srv, 0, "bastion_config_reload_success")


def test_cardinality_bounded(bastion):
    srv = bastion(conf(workers=1))
    p = srv.ports["http"]
    get(p)
    srv.wait_for(lambda: value(metrics(srv), "bastion_http_requests_total") >= 1)
    series = set(metrics(srv))
    for i in range(200):
        get(p, path=f"/random/{i}/x?y={i}", host=f"h{i}.evil.test")
    srv.wait_for(lambda: value(metrics(srv), "bastion_http_requests_total", server="_other") >= 200)
    after = metrics(srv)
    assert set(after) == series, set(after) ^ series  # no new series: only values moved
    assert value(after, "bastion_http_requests_total", server="_other", code="4xx") == 200  # no location
    labels = {v for (_, ls) in after for (_, v) in ls}
    assert not any("evil" in v or "random" in v for v in labels)


def test_per_location(bastion):
    srv = bastion(conf("per_location on;", workers=1))
    p = srv.ports["http"]
    get(p, "/e/1")
    get(p, "/e/2")
    srv.wait_for(lambda: value(metrics(srv), "bastion_http_location_requests_total",
                               server="a.test", location="/e") == 2)


def test_default_not_public(bastion, bastion_bin, tmp_path):
    srv = bastion("workers 1;\nserver { listen 127.0.0.1:@HTTP_PORT@; location / { return 200 \"x\"; } }\n")
    with pytest.raises(OSError):  # no metrics block: nothing listens
        scrape(srv)
    with socket.create_connection(("127.0.0.1", srv.ports["http"]), timeout=5) as s:  # not on the server
        s.sendall(b"GET /metrics HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        assert b"bastion_" not in s.recv(65536)
    c = tmp_path / "public.conf"
    c.write_text("metrics { listen 0.0.0.0:9145; }\nserver { listen 127.0.0.1:8080; }\n")
    r = subprocess.run([bastion_bin, "-c", str(c), "-t"], capture_output=True, text=True, timeout=20)
    assert r.returncode == 0, r.stderr
    assert "not a loopback address" in r.stdout + r.stderr
    c.write_text("metrics { listen 127.0.0.1:9145; }\nserver { listen 127.0.0.1:8080; }\n")
    r = subprocess.run([bastion_bin, "-c", str(c), "-t"], capture_output=True, text=True, timeout=20)
    assert r.returncode == 0 and "loopback" not in r.stdout + r.stderr


def test_allow_and_auth(bastion, bastion_bin, tmp_path):
    srv = bastion(conf("allow 10.9.9.0/24;", workers=1))
    assert scrape(srv)[0] == 403
    pw = subprocess.run([bastion_bin, "passwd", "-m", "8", "-t", "1", "prom"], input="s3cret\n",
                        capture_output=True, text=True, timeout=30)
    assert pw.returncode == 0, pw.stderr
    users = tmp_path / "users"
    users.write_text(pw.stdout)
    srv = bastion(conf(f"allow 127.0.0.1; auth_basic {users};", workers=1))
    status, head, _ = scrape(srv)
    assert status == 401 and 'WWW-Authenticate: Basic realm="metrics"' in head
    assert scrape(srv, headers="Authorization: Basic cHJvbTp3cm9uZw==\r\n")[0] == 401  # prom:wrong
    good = "Authorization: Basic cHJvbTpzM2NyZXQ=\r\n"  # prom:s3cret
    assert scrape(srv, headers=good)[0] == 200
    assert scrape(srv, headers=good)[0] == 200  # the remembered credentials


def test_scrape_low_cost(bastion):
    srv = bastion(conf(workers=2))
    srv.wait_workers(2)
    p = srv.ports["http"]

    def latencies(n):
        out = []
        for _ in range(n):
            t = time.monotonic()
            assert get(p) == 200
            out.append(time.monotonic() - t)
        return out

    base = statistics.median(latencies(200))
    stop, scrapes = threading.Event(), []

    def scraper():
        while not stop.is_set():
            scrapes.append(scrape(srv)[0])

    t = threading.Thread(target=scraper)
    t.start()
    try:
        loaded = statistics.median(latencies(200))
    finally:
        stop.set()
        t.join()
    assert len(scrapes) >= 10 and set(scrapes) == {200}
    # Workers never take part in a scrape: the median request latency stays in the same range.
    assert loaded < base * 3 + 0.005, (base, loaded)


def test_under_attack_gauge(bastion):
    srv = bastion("workers 4;\nchallenge_auto_rps 40;\nchallenge_auto_hold 2s;\n"
                  "metrics { listen 127.0.0.1:@ADMIN_PORT@; }\n"
                  "server { listen 127.0.0.1:@HTTP_PORT@; challenge auto; challenge_difficulty 8;\n"
                  "location /open/ { challenge off; return 200 \"open\"; } }\n")
    srv.wait_workers(4)
    assert value(metrics(srv), "bastion_under_attack") == 0
    load = AttackLoad(srv.ports["http"], 120)
    try:
        srv.wait_for(lambda: value(metrics(srv), "bastion_under_attack") == 1, timeout=10,
                     what="under_attack 1")
    finally:
        load.end()
    srv.wait_for(lambda: value(metrics(srv), "bastion_under_attack") == 0, timeout=15,
                 what="under_attack back to 0")
    assert value(metrics(srv), "bastion_under_attack_total") >= 1


def test_xdp_metrics(bastion, net, pin):  # noqa: F811
    assert SYN, "make test-int passes SYNFLOOD"
    n = net()
    srv = bastion(f"workers 1;\nxdp {{ interface {n.host}; mode generic; pin_path {pin}; deny {n.bad}; }}\n"
                  "metrics { listen 127.0.0.1:@ADMIN_PORT@; }\n"
                  f"server {{ listen {n.ip}:@HTTP_PORT@; location / {{ return 200 \"ok\"; }} }}\n")
    r = subprocess.run(["ip", "netns", "exec", n.ns, SYN, "-d", n.ip, "-p", str(srv.ports["http"]),
                        "-n", "5000", "-s", n.bad], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    sent = int(r.stdout.strip())
    srv.wait_for(lambda: value(metrics(srv), "bastion_xdp_packets_total", reason="deny") >= sent * 0.99,
                 timeout=10, what="xdp deny metric")
    srv.wait_log(r"xdp: stats ")  # the 1 Hz log line stays
