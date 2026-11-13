"""Purge (Phase 10, Task 7): by URL, tag, host and all, in O(1) through the shared purge table,
seen by every worker at once (RAM tier included), kept across restarts, and safe against a fill
that began before the purge. PURGE comes from purge_method_allow addresses only."""
import threading
import time

import pytest

from test_cache import req
from upstream_util import Upstream, ok


@pytest.fixture
def up():
    u = Upstream(handler=tagged)
    yield u
    u.close()


def tagged(r, c):
    path = r.target
    tags = "shared" if path.startswith("/t/") else "other"
    return ok(f"body{path}", 200, (("Cache-Control", "max-age=600"), ("Cache-Tag", f"{tags}, all-items")))


def conf(up, disk="@WORKDIR@/cache", workers=1, store="", allow="127.0.0.1/32"):
    return (f"workers {workers};\ncache_store main {{ disk {disk} size=200m; ram 8m; {store} }}\n"
            f"server {{ listen 127.0.0.1:@HTTP_PORT@;\n"
            f"location / {{ proxy {up.url}; cache main; purge_method_allow {allow}; }} }}\n")


def hit(srv, path, host="localhost"):
    _, h, b = req(srv, path, host=host)
    assert b == f"body{path}".encode(), b
    return h.get("cache-status", "").startswith("bastion; hit")


def purge(srv, path="/", extra="", host="localhost"):
    st, _, b = req(srv, path, method="PURGE", extra=extra, host=host)
    return st, b


def test_purge_url(bastion, up):
    srv = bastion(conf(up))
    req(srv, "/u")
    assert hit(srv, "/u")
    assert purge(srv, "/u") == (200, b"purged url\n")
    time.sleep(0.01)  # a fill in the purge's own millisecond counts as purged (safe side)
    assert not hit(srv, "/u")
    assert hit(srv, "/u")


def test_purge_tag(bastion, up):
    srv = bastion(conf(up))
    for i in range(1000):
        req(srv, f"/t/{i}")
    for i in range(20):
        req(srv, f"/o/{i}")
    t0 = time.monotonic()
    assert purge(srv, extra="Purge-Tag: shared\r\n")[0] == 200
    assert time.monotonic() - t0 < 1
    assert not any(hit(srv, f"/t/{i}") for i in range(0, 1000, 37))
    assert all(hit(srv, f"/o/{i}") for i in range(20)), "untagged objects were purged too"


def test_purge_host(bastion, up):
    srv = bastion(conf(up))
    req(srv, "/h", host="a.example")
    req(srv, "/h", host="b.example")
    assert purge(srv, extra="Purge-Scope: host\r\n", host="A.example:80")[0] == 200
    assert not hit(srv, "/h", host="a.example")
    assert hit(srv, "/h", host="b.example")
    assert purge(srv, extra="Purge-Scope: all\r\n")[0] == 200
    assert not hit(srv, "/h", host="b.example")


def test_purge_all_workers(bastion, up):
    srv = bastion(conf(up, workers=2))
    for _ in range(20):  # many connections: both workers hold copies (RAM tier included)
        req(srv, "/w")
    assert purge(srv, extra="Purge-Tag: other\r\n")[0] == 200
    n = len(up.requests)
    statuses = [hit(srv, "/w") for _ in range(20)]
    assert statuses[0] is False and len(up.requests) >= n + 1
    for _ in range(20):
        assert hit(srv, "/w")


def test_purge_refused(bastion, up):
    srv = bastion(conf(up, allow="10.0.0.0/8"))
    req(srv, "/r")
    assert purge(srv, "/r")[0] == 403
    assert hit(srv, "/r")


def test_purge_survives_restart(bastion, up, tmp_path):
    disk = tmp_path / "c"
    srv = bastion(conf(up, disk=disk, store="purge_save_interval 200ms;"))
    for i in range(5):
        req(srv, f"/t/{i}")
    req(srv, "/o/keep")
    assert purge(srv, extra="Purge-Tag: shared\r\n")[0] == 200
    srv.wait_for(lambda: (disk / "purge.table").exists(), what="the purge table to be saved")
    time.sleep(0.5)
    srv.proc.terminate()
    srv.proc.wait(10)
    srv = bastion(conf(up, disk=disk))
    srv.wait_log(r"cache_store main: index rebuilt")
    assert not any(hit(srv, f"/t/{i}") for i in range(5)), "purged objects came back"
    assert hit(srv, "/o/keep")


def test_refill_after_purge(bastion, up):
    srv = bastion(conf(up))
    req(srv, "/t/x")
    purge(srv, extra="Purge-Tag: shared\r\n")
    time.sleep(0.01)
    assert not hit(srv, "/t/x")  # refilled now: its fill began after the purge
    assert hit(srv, "/t/x")


def test_purge_race(bastion, up):
    def slow(r, c):
        time.sleep(1.0)
        return tagged(r, c)
    up.handler = slow
    srv = bastion(conf(up))
    t = threading.Thread(target=lambda: req(srv, "/race"))
    t.start()
    time.sleep(0.3)
    assert purge(srv, "/race")[0] == 200  # while the fill is in flight
    t.join()
    up.handler = tagged
    n = len(up.requests)
    assert not hit(srv, "/race"), "a fill that began before the purge was served"
    assert len(up.requests) == n + 1


def test_tag_header_stripped(bastion, up):
    srv = bastion(conf(up))
    _, h1, _ = req(srv, "/t/s")
    _, h2, _ = req(srv, "/t/s")
    assert "cache-tag" not in h1 and "cache-tag" not in h2
    assert h2["cache-status"].startswith("bastion; hit")


def test_purge_no_cache_is_501(bastion, up):
    srv = bastion(f"workers 1;\nserver {{ listen 127.0.0.1:@HTTP_PORT@;\n"
                  f"location / {{ proxy {up.url}; }} }}\n")
    assert req(srv, "/x", method="PURGE")[0] == 501
    assert len(up.requests) == 0
