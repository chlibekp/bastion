"""Helpers for the QUIC tests: the h3client fixture, captured client Initials, raw datagrams."""
import json
import os
import socket
import struct
import subprocess
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def h3client_bin():
    p = os.environ.get("H3CLIENT") or str(ROOT / "build" / "debug" / "fixtures" / "h3client")
    if not Path(p).exists():
        pytest.skip("h3client fixture not built (make test-int builds it)")
    return p


def conf(certs, extra="", workers=1, glob=""):
    """One server with an `http3` listener on @QUIC_PORT@ and a debug log."""
    return (f"workers {workers};\nerror_log @WORKDIR@/error.log debug;\n{glob}\n"
            f"server {{ listen 127.0.0.1:@QUIC_PORT@ http3; "
            f"tls_cert {certs}/ecdsa-chain.crt {certs}/ecdsa.key; {extra} }}\n")


def h3(srv, *paths, opts=(), timeout_ms=10000, wait=True):
    """Runs h3client against the server's QUIC port. Returns (exit status, [json lines]) or the
    Popen when wait is False."""
    cmd = [h3client_bin(), "--timeout", str(timeout_ms), *opts, "127.0.0.1", str(srv.ports["quic"]), *paths]
    if not wait:
        return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    p = subprocess.run(cmd, capture_output=True, timeout=timeout_ms / 1000 + 10)
    lines = [json.loads(ln) for ln in p.stdout.decode().splitlines() if ln.startswith("{")]
    return p.returncode, lines


def conn_line(lines):
    found = [ln for ln in lines if ln.get("type") == "conn"]
    return found[-1] if found else {}


def capture_initials(n, groups="X25519"):
    """n first-flight datagrams of `openssl s_client -quic`, each from a fresh run (so each has its
    own random destination ID). With one X25519 key share the ClientHello fits in one Initial, so
    the server needs no Retry to read it. Skips when openssl has no QUIC client."""
    out = []
    for _ in range(n):
        cap = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        cap.bind(("127.0.0.1", 0))
        cap.settimeout(5)
        port = cap.getsockname()[1]
        p = subprocess.Popen(["openssl", "s_client", "-quic", "-alpn", "h3", "-groups", groups,
                              "-servername", "localhost", "-connect", f"127.0.0.1:{port}"],
                             stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            data, _ = cap.recvfrom(65536)
        except socket.timeout:
            p.kill()
            err = p.stderr.read().decode(errors="replace")
            pytest.skip(f"openssl s_client -quic sent nothing: {err[:200]}")
        finally:
            cap.close()
        p.kill()
        p.wait()
        out.append(data)
    return out


def is_retry(pkt, version=1):
    """Long header, type Retry (0x3 in v1)."""
    return len(pkt) > 5 and pkt[0] & 0x80 and struct.unpack("!I", pkt[1:5])[0] == version and \
        (pkt[0] & 0x30) == 0x30


def recv_all(sock, wait=1.0):
    """Every datagram arriving within `wait` seconds of the last one."""
    got = []
    sock.settimeout(wait)
    while True:
        try:
            got.append(sock.recv(65536))
        except socket.timeout:
            return got


def udp(srv):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    s.connect(("127.0.0.1", srv.ports["quic"]))
    return s


def wait_count(srv, pattern, n, timeout=10):
    import re
    srv.wait_for(lambda: len(re.findall(pattern, srv.logs())) >= n, timeout, f"{n} x {pattern!r}")
    return len(re.findall(pattern, srv.logs()))


def settle(seconds=0.3):
    time.sleep(seconds)
