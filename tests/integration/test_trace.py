"""W3C Trace Context (src/filters/trace.c, Phase 14 Task 5): traceparent is validated, continued
from trusted peers only, and forwarded upstream with a new parent ID; $trace_id and $span_id are
the values the upstream saw."""
import os
import re
import socket

import pytest

from upstream_util import Upstream, ok

TP = re.compile(r"^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$")
IN_TRACE = "4bf92f3577b34da6a3ce929d0e0e4736"
IN_PARENT = "00f067aa0ba902b7"
IN_TP = f"00-{IN_TRACE}-{IN_PARENT}-01"


@pytest.fixture
def up():
    u = Upstream()
    u.handler = lambda r, c: ok("x")
    yield u
    u.close()


def conf(up, extra="", glob=""):
    return (f"workers 1;\nlog_flush_interval 50ms;\n{glob}\n"
            f"server {{ listen 127.0.0.1:@HTTP_PORT@; trace_context on; {extra}\n"
            f"location / {{ proxy {up.url}; }} }}\n")


def get(port, extra=""):
    with socket.create_connection(("127.0.0.1", port), timeout=10) as s:
        s.sendall(f"GET / HTTP/1.1\r\nHost: x\r\n{extra}Connection: close\r\n\r\n".encode())
        out = b""
        while True:
            d = s.recv(65536)
            if not d:
                break
            out += d
    assert out.startswith(b"HTTP/1.1 200"), out[:200]
    return out


def sent(up):
    """The traceparent the upstream got for the last request, parsed."""
    v = up.requests[-1].all("traceparent")
    assert len(v) == 1, v
    m = TP.match(v[0])
    assert m, v
    return m.groups()


def test_propagates(bastion, up):
    srv = bastion(conf(up, "trace_trust 127.0.0.1/32;"))
    get(srv.ports["http"], f"traceparent: {IN_TP}\r\ntracestate: congo=t61rcWkgMzE\r\n")
    trace, parent, flags = sent(up)
    assert trace == IN_TRACE and flags == "01"
    assert parent != IN_PARENT and parent != "0" * 16  # our own span
    assert up.requests[-1].all("tracestate") == ["congo=t61rcWkgMzE"]


def test_generates(bastion, up):
    srv = bastion(conf(up))
    seen = set()
    for _ in range(5):
        get(srv.ports["http"])
        trace, parent, _ = sent(up)
        assert trace != "0" * 32 and parent != "0" * 16
        seen.add(trace)
    assert len(seen) == 5


def test_untrusted_regenerates(bastion, up):
    srv = bastion(conf(up, "trace_trust 10.9.9.0/24;"))
    get(srv.ports["http"], f"traceparent: {IN_TP}\r\ntracestate: evil=1\r\n")
    trace, _, _ = sent(up)
    assert trace != IN_TRACE
    assert up.requests[-1].all("tracestate") == []
    # no trace_trust at all: nobody is trusted
    srv2 = bastion(conf(up))
    get(srv2.ports["http"], f"traceparent: {IN_TP}\r\n")
    assert sent(up)[0] != IN_TRACE


def test_invalid_regenerates_when_trusted(bastion, up):
    srv = bastion(conf(up, "trace_trust 127.0.0.1/32;"))
    for bad in (f"00-{'0' * 32}-{IN_PARENT}-01", f"ff-{IN_TRACE}-{IN_PARENT}-01",
                f"00-{IN_TRACE.upper()}-{IN_PARENT}-01", f"00-{IN_TRACE}-{IN_PARENT}"):
        get(srv.ports["http"], f"traceparent: {bad}\r\n")
        assert sent(up)[0] != IN_TRACE


def test_off_by_default(bastion, up):
    srv = bastion(f"workers 1;\nserver {{ listen 127.0.0.1:@HTTP_PORT@; "
                  f"location / {{ proxy {up.url}; }} }}\n")
    get(srv.ports["http"], f"traceparent: {IN_TP}\r\n")
    assert up.requests[-1].all("traceparent") == [IN_TP]  # passed through untouched


def test_in_logs(bastion, up):
    srv = bastion(conf(up, "trace_trust 127.0.0.1/32; access_log @WORKDIR@/t.log tr;",
                       glob='log_format tr text "$trace_id $span_id";'))
    get(srv.ports["http"], f"traceparent: {IN_TP}\r\n")
    trace, parent, _ = sent(up)
    path = os.path.join(srv.workdir, "t.log")

    def line():
        try:
            with open(path, "rb") as f:
                return f.read().splitlines() or None
        except FileNotFoundError:
            return None

    (ln,) = srv.wait_for(line, 10, "an access log line")
    assert ln.decode() == f"{trace} {parent}"
