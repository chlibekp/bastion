"""Phase 8 Task 6: Alt-Svc on TCP responses (src/http/h3/altsvc.c), HTTP/3 0-RTT through the
Phase 6 early-data policy (tls/early.c, h3_bridge.c), and the HTTP/3 abuse guards (h3_bridge.c on
the shared http/h2/guard.c buckets).

Clients: curl for Alt-Svc discovery (`--alt-svc` cache file), the h3client fixture for 0-RTT,
Rapid Reset and closing the control stream."""
import shutil
import subprocess

import pytest

from quic_util import conn_line, h3

H3_EXCESSIVE_LOAD = 0x107
H3_CLOSED_CRITICAL_STREAM = 0x104


def conf(certs, extra="", prof="", glob=""):
    """One server on a TCP (h1, h2) and a QUIC listener."""
    return (f"workers 1;\nerror_log @WORKDIR@/error.log debug;\n{glob}\n{prof}\n"
            f"server {{ listen 127.0.0.1:@HTTPS_PORT@ tls http2; listen 127.0.0.1:@QUIC_PORT@ http3;\n"
            f"tls_cert {certs}/ecdsa-chain.crt {certs}/ecdsa.key; {extra}\n"
            f'location /e {{ return 200 "early=$ssl_early_data"; }}\n'
            f'location / {{ return 200 "hi"; }} }}\n')


def resp(lines, i=0):
    found = [ln for ln in lines if ln.get("type") == "resp"]
    return found[i] if len(found) > i else {}


def curl(*args):
    if shutil.which("curl") is None:
        pytest.skip("curl is needed")
    p = subprocess.run(["curl", "-sk", *args], capture_output=True, timeout=30)
    return p.returncode, p.stdout.decode(errors="replace")


def alt_svc(out):
    return [ln.split(":", 1)[1].strip() for ln in out.splitlines() if ln.lower().startswith("alt-svc:")]


# ---- Alt-Svc ----

def test_alt_svc(bastion, certs, tmp_path):
    """TCP responses advertise the QUIC port; curl follows it to HTTP/3 from its Alt-Svc cache."""
    srv = bastion(conf(certs))
    port, qport = srv.ports["https"], srv.ports["quic"]
    want = f'h3=":{qport}"; ma=86400'
    for v in ("--http1.1", "--http2"):
        rc, out = curl(v, "-D", "-", "-o", "/dev/null", f"https://localhost:{port}/")
        assert rc == 0 and alt_svc(out) == [want], out
    cache = tmp_path / "altsvc.txt"
    rc, out = curl("--alt-svc", str(cache), "-o", "/dev/null", f"https://localhost:{port}/")
    assert rc == 0 and f" h3 localhost {qport} " in cache.read_text(), cache.read_text()
    rc, out = curl("--alt-svc", str(cache), "-w", "%{http_version}", f"https://localhost:{port}/")
    assert rc == 0 and out == "hi3", out  # body "hi", then the HTTP version: 3
    # HTTP/3 responses carry none
    rc, out = curl("--http3-only", "-D", "-", "-o", "/dev/null", f"https://localhost:{qport}/")
    assert rc == 0 and out.startswith("HTTP/3 200") and alt_svc(out) == [], out


def test_alt_svc_off_and_value(bastion, certs):
    """`alt_svc off` sends none, a written value is sent as written, and a server without an
    http3 listener advertises nothing."""
    srv = bastion(conf(certs, extra="alt_svc off;"))
    rc, out = curl("--http1.1", "-D", "-", "-o", "/dev/null", f"https://localhost:{srv.ports['https']}/")
    assert rc == 0 and alt_svc(out) == [], out
    srv = bastion(conf(certs, extra='alt_svc "h3=\\"alt.example:443\\"; ma=60";'))
    rc, out = curl("--http2", "-D", "-", "-o", "/dev/null", f"https://localhost:{srv.ports['https']}/")
    assert rc == 0 and alt_svc(out) == ['h3="alt.example:443"; ma=60'], out
    tcp_only = (f"workers 1;\nserver {{ listen 127.0.0.1:@HTTPS_PORT@ tls; "
                f"tls_cert {certs}/ecdsa-chain.crt {certs}/ecdsa.key; location / {{ return 200 \"x\"; }} }}\n")
    srv = bastion(tcp_only)
    rc, out = curl("--http1.1", "-D", "-", "-o", "/dev/null", f"https://localhost:{srv.ports['https']}/")
    assert rc == 0 and alt_svc(out) == [], out


# ---- 0-RTT ----

EARLY = "tls_profile e { early_data on; }"


def ticket(srv, tmp_path, name="s"):
    sess = tmp_path / name
    rc, lines = h3(srv, "/e", opts=("--session", str(sess), "--wait-ticket"))
    assert rc == 0 and conn_line(lines).get("ticket"), lines
    return sess


def test_h3_early_get(bastion, certs, tmp_path):
    """A resumed connection sends its GET as 0-RTT; it is served from early data, and the same
    ticket is refused early data the second time (the shared anti-replay table)."""
    srv = bastion(conf(certs, extra="tls_profile e;", prof=EARLY))
    sess = ticket(srv, tmp_path)
    rc, lines = h3(srv, "/e", opts=("--session", str(sess), "--early", "--print-body"))
    c = conn_line(lines)
    assert rc == 0 and c.get("resumed") and c.get("early_accepted"), lines
    assert resp(lines).get("status") == 200 and resp(lines).get("body") == "early=1", lines
    rc, lines = h3(srv, "/e", opts=("--session", str(sess), "--early", "--print-body"))
    c = conn_line(lines)
    assert rc == 0 and c.get("early_attempted") and not c.get("early_accepted"), lines
    assert resp(lines).get("body") == "early=", lines  # served after the handshake instead


def test_h3_early_post_425(bastion, certs, tmp_path):
    """A POST in 0-RTT is answered 425 Too Early; the handler never runs."""
    srv = bastion(conf(certs, extra="tls_profile e;", prof=EARLY))
    sess = ticket(srv, tmp_path)
    rc, lines = h3(srv, "/e", opts=("--session", str(sess), "--early", "--method", "POST", "--print-body"))
    assert conn_line(lines).get("early_accepted"), lines
    assert resp(lines).get("status") == 425, lines
    assert "early=" not in (resp(lines).get("body") or ""), lines


def test_h3_early_off(bastion, certs, tmp_path):
    """Without early_data the ticket allows no 0-RTT at all."""
    srv = bastion(conf(certs))
    sess = ticket(srv, tmp_path)
    rc, lines = h3(srv, "/e", opts=("--session", str(sess), "--early", "--print-body"))
    c = conn_line(lines)
    assert rc == 0 and c.get("resumed") and not c.get("early_accepted"), lines
    assert resp(lines).get("status") == 200, lines


# ---- abuse guards ----

def test_h3_rapid_reset(bastion, certs):
    """An open-and-cancel flood closes the connection with H3_EXCESSIVE_LOAD and is counted."""
    srv = bastion(conf(certs, extra="http2_abuse { rst_rate 20; }"))
    rc, lines = h3(srv, "/", opts=("--rapid-reset", "400"), timeout_ms=10000)
    c = conn_line(lines)
    assert c.get("peer_error", {}).get("code") == H3_EXCESSIVE_LOAD, lines
    srv.wait_log(r"used up its stream_reset budget")


def test_h3_cancel_within_budget(bastion, certs):
    """A burst of cancels inside the budget is harmless: the request after it is served."""
    srv = bastion(conf(certs))
    rc, lines = h3(srv, "/", opts=("--rapid-reset", "20"))
    assert rc == 0 and resp(lines).get("status") == 200, lines
    assert conn_line(lines).get("peer_error", {}).get("code") in (0, 0x100), lines


def test_h3_critical_stream_close(bastion, certs):
    """Closing the client's control stream is a connection error H3_CLOSED_CRITICAL_STREAM
    (RFC 9114 section 6.2.1)."""
    srv = bastion(conf(certs))
    rc, lines = h3(srv, "/", opts=("--close-control",), timeout_ms=5000)
    assert conn_line(lines).get("peer_error", {}).get("code") == H3_CLOSED_CRITICAL_STREAM, lines
