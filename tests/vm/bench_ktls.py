"""kTLS throughput by mode in the QEMU guest. Not collected by `make test-vm`: run it with

    scripts/vm-run.sh python3 -m pytest tests/vm/bench_ktls.py -s -q

It prints one row per mode (`ktls off`, `tx`, `tx+rx`) in the shape docs/tuning.md records. The
guest is emulated (TCG): absolute numbers say nothing about hardware, only the trend between modes."""
import os
import ssl
import time

import pytest

from test_ktls import MIB, _in_guest, bastion, bastion_bin, backend, certs, client_ctx, conf, read_response, serve, tls_connect, www  # noqa: F401,E501

REQS, DOWN, UP = 500, 8 * MIB, 4 * MIB
ROWS = []


@pytest.fixture(autouse=True)
def _bigfile(www):
    (www / "big.bin").write_bytes(os.urandom(DOWN))


def drain(t, want):
    got = 0
    head = b""
    while got < want or b"\r\n\r\n" not in head:
        d = t.recv(1 << 16)
        if not d:
            break
        if b"\r\n\r\n" not in head:
            head += d
            if b"\r\n\r\n" in head:
                got += len(head.partition(b"\r\n\r\n")[2])
        else:
            got += len(d)
    return got


@pytest.mark.parametrize("mode", ["off", "tx", "tx+rx"])
def test_bench(bastion, certs, www, mode):
    srv = serve(bastion, certs, www, mode)
    print('START', mode, flush=True)
    ctx = client_ctx(certs, ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2)
    with tls_connect(srv, certs, ctx, timeout=300) as t:
        small = b"GET /small.txt HTTP/1.1\r\nHost: localhost\r\n\r\n"
        t0 = time.perf_counter()
        for _ in range(REQS):
            t.sendall(small)
            buf = b""
            while b"\r\n\r\n" not in buf or not buf.endswith(b"0123456789abcdef"):
                buf += t.recv(4096)
        rps = REQS / (time.perf_counter() - t0)
    with tls_connect(srv, certs, ctx, timeout=300) as t:
        t0 = time.perf_counter()
        t.sendall(b"GET /big.bin HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        assert drain(t, DOWN) == DOWN
        down = DOWN / MIB / (time.perf_counter() - t0)
    with tls_connect(srv, certs, ctx, timeout=300) as t:
        data = os.urandom(UP)
        t0 = time.perf_counter()
        t.sendall(b"POST /small.txt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n"
                  + f"Content-Length: {UP}\r\n\r\n".encode())
        t.sendall(data)
        read_response(t)
        up = UP / MIB / (time.perf_counter() - t0)
    assert "killed by signal" not in srv.logs()
    print(f"\nBENCH | ktls {mode} | {rps:.0f} req/s | {down:.1f} MiB/s | {up:.1f} MiB/s |")
