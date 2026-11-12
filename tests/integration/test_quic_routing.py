"""Worker-aware QUIC routing (src/xdp/reuseport*, master attachment, `quic_routing`): a client that
moves to a new port keeps reaching the worker that holds its connection."""
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


def test_migration_same_worker(bastion, certs):
    """NAT rebinding right after the handshake: every packet from the new port must reach the worker
    holding the connection, which validates the new path. A packet reaching another worker would
    find no connection there and draw a stateless reset instead.

    The plan's version rebinds mid-transfer (h3client --rebind-after N); that needs HTTP/3 responses
    (Task 4), and test_migration_mid_transfer below runs it once they exist."""
    srv = bastion(conf(certs, workers=4))
    _routing_ebpf(srv)
    procs = [h3(srv, "/", opts=("--rebind-after-handshake",), timeout_ms=3000, wait=False)
             for _ in range(CLIENTS)]
    for p in procs:
        p.wait(20)
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


def test_migration_mid_transfer(bastion, certs):
    srv = bastion(conf(certs, workers=4))
    _routing_ebpf(srv)
    rc, lines = h3(srv, "/", opts=("--rebind-after", "1"), timeout_ms=3000)
    if not [ln for ln in lines if ln.get("type") == "resp"]:
        pytest.skip("no HTTP/3 responses before Phase 8 Task 4 (h3_bridge)")
    assert rc == 0 and conn_line(lines)["rebound"] is True, lines
    assert "stateless reset" not in srv.logs()


def test_routing_hash(bastion, certs):
    """quic_routing hash: no program, the kernel's hash; connections still work."""
    srv = bastion(conf(certs, workers=2, glob="quic_routing hash;"))
    assert "quic: quic_routing hash" in srv.logs()
    assert "routing by connection ID" not in srv.logs()
    rc, lines = h3(srv)
    assert rc == 0 and conn_line(lines).get("handshake") is True, lines
