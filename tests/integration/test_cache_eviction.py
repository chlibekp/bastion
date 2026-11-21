"""The shared index and the helper's jobs on a disk store (Phase 10, Task 3): the size limit,
least-recently-used eviction, `inactive`, and the startup scan that rebuilds the index from disk
while traffic is served. BST_TEST_CACHE_EVICT_MS runs eviction every few ms instead of once a
second; BST_TEST_CACHE_SCAN_DELAY_MS slows the scan to one file per step."""
import os
import time

import pytest

from test_cache import req
from upstream_util import Upstream, ok

FAST = {"BST_TEST_CACHE_EVICT_MS": "100"}
BODY = b"e" * 60000


@pytest.fixture
def up():
    u = Upstream(handler=lambda r, c: ok(BODY, 200, (("Cache-Control", "max-age=600"),)))
    yield u
    u.close()


def conf(up, disk, store=""):
    return (f"workers 2;\ncache_store main {{ disk {disk} size=1m; {store} }}\n"
            f"server {{ listen 127.0.0.1:@HTTP_PORT@;\n"
            f"location / {{ proxy {up.url}; cache main; }} }}\n")


def disk_bytes(d):
    total = 0
    for root, _, files in os.walk(d):
        for f in files:
            total += os.path.getsize(os.path.join(root, f))
    return total


def hit(srv, path):
    _, h, b = req(srv, path)
    assert b == BODY
    return h.get("cache-status", "").startswith("bastion; hit")


def stop(srv):
    srv.proc.terminate()
    srv.proc.wait(10)


def test_size_limit(bastion, up, tmp_path):
    srv = bastion(conf(up, tmp_path / "c"), env=FAST)
    for i in range(40):
        req(srv, f"/o{i}")
    time.sleep(1)
    assert disk_bytes(tmp_path / "c") <= 1024 * 1024 + 64 * 1024, "the store grew past size="


def test_lru_prefers_cold(bastion, up, tmp_path):
    srv = bastion(conf(up, tmp_path / "c"), env=FAST)
    hot = [f"/hot{i}" for i in range(4)]
    for p in hot:
        req(srv, p)
    time.sleep(1.1)
    for i in range(6):
        req(srv, f"/cold{i}")
    time.sleep(1.1)
    for p in hot:  # used again: now the most recent
        assert hit(srv, p)
    time.sleep(1.1)
    for i in range(6, 14):
        req(srv, f"/cold{i}")
    time.sleep(1)
    assert all(hit(srv, p) for p in hot), "eviction removed hot objects before cold ones"


def test_restart_survives(bastion, up, tmp_path):
    disk = tmp_path / "c"
    srv = bastion(conf(up, disk))
    for i in range(5):
        req(srv, f"/keep{i}")
    stop(srv)
    assert "killed by signal" not in srv.logs(), "a worker died while finishing its writes"
    n = len(up.requests)
    srv = bastion(conf(up, disk))
    srv.wait_log(r"cache_store main: index rebuilt: 5 files")
    for i in range(5):
        assert hit(srv, f"/keep{i}")
    assert len(up.requests) == n, "a stored object was fetched again after the restart"


def test_scan_background(bastion, up, tmp_path):
    disk = tmp_path / "c"
    srv = bastion(conf(up, disk))
    for i in range(12):
        req(srv, f"/s{i}")
    stop(srv)
    srv = bastion(conf(up, disk), env={"BST_TEST_CACHE_SCAN_DELAY_MS": "300"})
    t0 = time.monotonic()
    first = [hit(srv, f"/s{i}") for i in range(12)]  # served meanwhile, misses included
    assert time.monotonic() - t0 < 5, "the slow scan held up traffic"
    assert not all(first), "the scan finished before traffic: nothing was tested"
    srv.wait_log(r"cache_store main: index rebuilt", timeout=30)
    assert all(hit(srv, f"/s{i}") for i in range(12))


def test_expired_inactive(bastion, up, tmp_path):
    srv = bastion(conf(up, tmp_path / "c", "inactive 1s;"), env=FAST)
    req(srv, "/idle")
    assert hit(srv, "/idle")
    time.sleep(3)
    assert not hit(srv, "/idle"), "an unused object outlived `inactive`"
