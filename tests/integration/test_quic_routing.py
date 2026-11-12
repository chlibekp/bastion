"""Worker-aware QUIC routing (src/xdp/reuseport*, master attachment, `quic_routing`): a client that
moves to a new port keeps reaching the worker that holds its connection."""
import hashlib
import re

import pytest

from quic_util import conf, conn_line, h3

CLIENTS = 8


def _routing_ebpf(srv):
    log = srv.logs()
    if "quic_routing ebpf unavailable" in log:
        pytest.skip("sk_reuseport program refused here (no CAP_BPF/CAP_NET_ADMIN): "
                    + re.search(r"unavailable \(([^)]*)\)", log).group(1))
    assert re.search(r"master INFO quic: routing by connection ID over 4 workers", log), log


@pytest.fixture
def big(tmp_path):
    """A docroot with a 4 MiB file: long enough a transfer for a move to land in the middle of it."""
    root = tmp_path / "www"
    root.mkdir()
    (root / "big.bin").write_bytes(bytes(range(256)) * 16384)
    return root


def test_migration_same_worker(bastion, certs, big):
    """NAT rebinding right after the handshake, with a download running: every packet from the new
    port must reach the worker holding the connection, which validates the new path. A packet
    reaching another worker would find no connection there and draw a stateless reset instead."""
    srv = bastion(conf(certs, f"root {big};", workers=4))
    _routing_ebpf(srv)
    procs = [h3(srv, "/big.bin", opts=("--rebind-after-handshake",), timeout_ms=10000, wait=False)
             for _ in range(CLIENTS)]
    for p in procs:
        p.wait(30)
    srv.wait_for(lambda: len(re.findall(r"quic: path validation succeeded", srv.logs())) >= CLIENTS,
                 15, f"{CLIENTS} validated paths")
    log = srv.logs()
    assert "stateless reset" not in log, log
    assert "path validation failed" not in log, log
    # The connections were spread over the workers, and each one's new path was validated by the
    # worker that opened it: per worker, as many validations as handshakes.
    for slot in range(4):
        opened = len(re.findall(rf"worker/{slot} DEBUG quic: handshake done", log))
        moved = len(re.findall(rf"worker/{slot} DEBUG quic: path validation succeeded", log))
        assert opened == moved, (slot, opened, moved)


def test_migration_mid_transfer(bastion, certs, big):
    """The plan's version: the client moves after the first 64 KiB of a 4 MiB response, and the
    download completes, identical, on the new path."""
    srv = bastion(conf(certs, f"root {big};", workers=4))
    _routing_ebpf(srv)
    rc, lines = h3(srv, "/big.bin", opts=("--rebind-after", "65536"), timeout_ms=20000)
    resp = [ln for ln in lines if ln.get("type") == "resp"]
    assert rc == 0 and conn_line(lines)["rebound"] is True, lines
    want = hashlib.sha256((big / "big.bin").read_bytes()).hexdigest()
    assert resp[0]["status"] == 200 and resp[0]["len"] == 4 << 20 and resp[0]["sha256"] == want, resp
    assert "stateless reset" not in srv.logs()


def test_routing_hash(bastion, certs):
    """quic_routing hash: no program, the kernel's hash; connections still work."""
    srv = bastion(conf(certs, workers=2, glob="quic_routing hash;"))
    assert "quic: quic_routing hash" in srv.logs()
    assert "routing by connection ID" not in srv.logs()
    rc, lines = h3(srv)
    assert rc == 0 and conn_line(lines).get("handshake") is True, lines
