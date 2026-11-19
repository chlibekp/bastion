"""Access logs (src/ops/logger.c): workers render lines into shared rings, the helper writes the
files, USR1 reopens them, and nothing a client sends can split a line or break its JSON."""
import json
import os
import shutil
import signal
import socket
import subprocess
import time

import pytest

import quic_util

CURL = shutil.which("curl")


def conf(certs, alog, glob="", workers=1, extra="", flush="50ms"):
    return (f"workers {workers};\nlog_flush_interval {flush};\n{glob}\n"
            f"server {{ listen 127.0.0.1:@HTTP_PORT@; listen 127.0.0.1:@HTTPS_PORT@ tls http2; "
            f"listen 127.0.0.1:@QUIC_PORT@ http3; "
            f"tls_cert {certs}/ecdsa-chain.crt {certs}/ecdsa.key;\n{alog}\n"
            f"location = /v {{ return 200 \"hello\"; }}\n"
            f"location = /e {{ return 404; }}\n{extra} }}\n")


def raw(port, head):
    """Sends a raw HTTP/1.1 request (bytes) and returns the whole response."""
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
        s.sendall(head)
        data = b""
        while True:
            b = s.recv(65536)
            if not b:
                break
            data += b
    return data


def get(port, path="/v", headers=""):
    return raw(port, f"GET {path} HTTP/1.1\r\nHost: x\r\n{headers}Connection: close\r\n\r\n"
               .encode())


def lines(path):
    try:
        with open(path, "rb") as f:
            return f.read().splitlines()
    except FileNotFoundError:
        return []


def wait_lines(srv, path, n, timeout=10):
    return srv.wait_for(lambda: (lambda x: x if len(x) >= n else None)(lines(path)), timeout,
                        f"{n} access log lines in {path}")


def records(srv, path, n):
    return [json.loads(x) for x in wait_lines(srv, path, n)]


def test_json_line_per_request(bastion, certs):
    srv = bastion(conf(certs, "access_log @WORKDIR@/a.log;"))
    path = os.path.join(srv.workdir, "a.log")
    assert get(srv.ports["http"]).startswith(b"HTTP/1.1 200")
    (r,) = records(srv, path, 1)
    assert r["method"] == "GET" and r["uri"] == "/v" and r["status"] == "200"
    assert r["protocol"] == "HTTP/1.1" and r["body_bytes_sent"] == "5"
    assert r["remote_addr"] == "127.0.0.1" and r["time"].endswith("+00:00")
    assert float(r["request_time"]) >= 0
    assert oct(os.stat(path).st_mode & 0o777) == "0o640"


def test_every_protocol(bastion, certs):
    srv = bastion(conf(certs, "access_log @WORKDIR@/a.log;"), backend="epoll")
    path = os.path.join(srv.workdir, "a.log")
    get(srv.ports["http"])
    if CURL:
        subprocess.run([CURL, "-sk", "--http2", "-o", "/dev/null",
                        f"https://127.0.0.1:{srv.ports['https']}/v"], check=True, timeout=10)
    rc, _ = quic_util.h3(srv, "/v")
    assert rc == 0
    want = {"HTTP/1.1", "HTTP/3.0"} | ({"HTTP/2.0"} if CURL else set())
    recs = records(srv, path, len(want))
    assert {r["protocol"] for r in recs} == want
    assert all(r["status"] == "200" and r["body_bytes_sent"] == "5" for r in recs)


def test_injection_stays_one_valid_line(bastion, certs):
    srv = bastion(conf(certs, "access_log @WORKDIR@/a.log; access_log @WORKDIR@/t.log combined;"))
    # Raw control bytes are refused by the parser (unit tests cover them in values); quotes,
    # backslashes, invalid UTF-8 and U+2028 reach the log.
    evil_ua = 'x"}\xc3\x28\xe2\x80\xa8 \\ end'
    head = (b"GET /v?q=%0d%0a%22 HTTP/1.1\r\nHost: x\r\nUser-Agent: "
            + evil_ua.encode("latin-1") + b"\r\nConnection: close\r\n\r\n")
    raw(srv.ports["http"], head)
    (j,) = wait_lines(srv, os.path.join(srv.workdir, "a.log"), 1)
    r = json.loads(j)  # valid JSON despite quotes, controls, invalid UTF-8 and U+2028
    assert b"\xe2\x80\xa8" not in j and b"\xc3\x28" not in j
    assert r["user_agent"].startswith('x"}') and "�" in r["user_agent"]
    assert r["uri"] == "/v?q=%0d%0a%22"
    (t,) = wait_lines(srv, os.path.join(srv.workdir, "t.log"), 1)
    assert b"\xe2\x80\xa8" not in t and b'x\\x22}' in t and b"\\xe2\\x80\\xa8" in t
    assert t.count(b'"') == 6  # only the format's own quotes


def test_text_escaping_no_split(bastion, certs):
    srv = bastion(conf(certs, 'access_log @WORKDIR@/t.log plain;',
                       glob='log_format plain text "$http_x_a|$status";'))
    get(srv.ports["http"], headers="X-A: one\\two\"three\r\n")
    get(srv.ports["http"], headers="X-A: two\r\n")
    got = wait_lines(srv, os.path.join(srv.workdir, "t.log"), 2)
    assert got == [b'one\\x5ctwo\\x22three|200', b"two|200"]


def test_secrets_redacted(bastion, certs):
    srv = bastion(conf(certs, 'access_log @WORKDIR@/a.log s;',
                       glob='log_redact_query_params token;\n'
                            'log_format s json { a $http_authorization; c $cookie_sid; '
                            'p $http_proxy_authorization; u $request_uri; q $args; '
                            't $arg_token; k $arg_keep; }'))
    get(srv.ports["http"], "/v?token=sekrit&keep=1&To%6Ben=sekrit2",
        headers="Authorization: Bearer sekrit\r\nCookie: sid=sekrit\r\n"
                "Proxy-Authorization: Basic sekrit\r\n")
    (line,) = wait_lines(srv, os.path.join(srv.workdir, "a.log"), 1)
    assert b"sekrit" not in line
    r = json.loads(line)
    assert r["a"] == r["c"] == r["p"] == r["t"] == "[REDACTED]"
    assert r["k"] == "1"
    assert r["u"] == "/v?token=[REDACTED]&keep=1&To%6Ben=[REDACTED]"


def test_sampling_and_errors_only(bastion, certs):
    srv = bastion(conf(certs, "access_log @WORKDIR@/s.log main sample=0.1; "
                              "access_log @WORKDIR@/e.log main errors_only=on; "
                              "access_log @WORKDIR@/c.log main if=$arg_log;"))
    port = srv.ports["http"]
    for _ in range(400):
        get(port)
    for _ in range(20):
        get(port, "/e")
    get(port, "/v?log=1")
    get(port, "/v?log=0")
    errors = records(srv, os.path.join(srv.workdir, "e.log"), 20)
    assert len(errors) == 20 and all(r["status"] == "404" for r in errors)
    time.sleep(0.3)
    s = [json.loads(x) for x in lines(os.path.join(srv.workdir, "s.log"))]
    oks = [r for r in s if r["status"] == "200"]
    assert sum(r["status"] == "404" for r in s) == 20  # errors bypass sampling
    assert 10 <= len(oks) <= 80, len(oks)  # 10% of 402, loosely
    c = [json.loads(x) for x in lines(os.path.join(srv.workdir, "c.log"))]
    assert [r["uri"] for r in c] == ["/v?log=1"]


def test_logrotate_usr1(bastion, certs):
    srv = bastion(conf(certs, "access_log @WORKDIR@/a.log;"))
    path = os.path.join(srv.workdir, "a.log")
    get(srv.ports["http"])
    wait_lines(srv, path, 1)
    os.rename(path, path + ".1")
    srv.proc.send_signal(signal.SIGUSR1)
    srv.wait_log(r"USR1: reopened 1 access log")
    get(srv.ports["http"], "/v?after")
    (r,) = records(srv, path, 1)
    assert r["uri"] == "/v?after"
    assert len(lines(path + ".1")) == 1
    assert srv.proc.poll() is None and len(srv.workers()) == 1


def test_disk_full_counts_drops(bastion, certs):
    if not os.path.exists("/dev/full"):
        pytest.skip("no /dev/full")
    srv = bastion(conf(certs, "access_log /dev/full;"))
    for _ in range(5):
        assert get(srv.ports["http"]).startswith(b"HTTP/1.1 200")
    srv.wait_log(r"access log: \d+ line\(s\) dropped")
    assert srv.proc.poll() is None and srv.helper() is not None


def test_ring_overflow_drops_counted(bastion, certs):
    # A huge flush interval stalls the writer: the smallest ring fills, lines are dropped and
    # counted, and requests keep being served without waiting.
    big = "y" * 2000
    srv = bastion(conf(certs, 'access_log @WORKDIR@/a.log big;', workers=1,
                       glob=f'log_buffer 64k;\nlog_format big text "{big}$request_uri";',
                       flush="60s"))
    t0 = time.monotonic()
    for _ in range(200):
        assert get(srv.ports["http"]).startswith(b"HTTP/1.1 200")
    assert time.monotonic() - t0 < 30
    srv.proc.send_signal(signal.SIGTERM)  # the helper drains on stop and reports the drops
    srv.proc.wait(timeout=20)
    assert 0 < len(lines(os.path.join(srv.workdir, "a.log"))) < 200
    assert "line(s) dropped" in srv.logs()


def test_survives_reload_without_loss(bastion, certs):
    srv = bastion(conf(certs, "access_log @WORKDIR@/a.log;", workers=2, flush="10s"))
    path = os.path.join(srv.workdir, "a.log")
    for i in range(30):
        get(srv.ports["http"], f"/v?before={i}")
    n = len(__import__("re").findall(r"reload: generation \d+ ready", srv.logs()))
    srv.proc.send_signal(signal.SIGHUP)
    srv.wait_for(lambda: len(__import__("re").findall(r"reload: generation \d+ ready",
                                                      srv.logs())) > n, 20, "reload")
    for i in range(30):
        get(srv.ports["http"], f"/v?after={i}")
    # The old helper flushed on its STOP; the new one flushes on ours.
    wait_lines(srv, path, 30)
    srv.proc.send_signal(signal.SIGTERM)
    srv.proc.wait(timeout=20)
    uris = [json.loads(x)["uri"] for x in lines(path)]
    assert sorted(uris) == sorted([f"/v?before={i}" for i in range(30)]
                                  + [f"/v?after={i}" for i in range(30)])


def test_bad_format_name_rejected(bastion, certs):
    srv = bastion(conf(certs, "access_log @WORKDIR@/a.log nosuch;"), wait=None)
    assert srv.proc.wait(timeout=10) != 0
    assert "no log_format named 'nosuch'" in srv.logs() + srv.stdout()
