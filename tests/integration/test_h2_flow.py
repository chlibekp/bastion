"""HTTP/2 flow control against the real binary, on both backends, seccomp on. The client is the
hand-written one in tests/tools/h2_attack.py: it chooses the windows and when to open them.
`make test-int-nosan` runs this file without sanitizers too."""
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import h2_attack as h2  # noqa: E402

BIG = 100 << 20  # the plan's "100 MiB file": sparse, so it costs no disk


def conf(certs, www, extra=""):
    return (f"workers 1;\nserver {{ listen 127.0.0.1:@HTTPS_PORT@ tls http2; "
            f"tls_cert {certs}/ecdsa-chain.crt {certs}/ecdsa.key; root {www};\n{extra} }}\n")


@pytest.fixture
def www(tmp_path):
    root = tmp_path / "www"
    root.mkdir()
    with open(root / "big.bin", "wb") as f:
        f.truncate(BIG)
    with open(root / "mid.bin", "wb") as f:
        f.truncate(1 << 20)
    return root


def rss_kb(pid):
    for ln in open(f"/proc/{pid}/status"):
        if ln.startswith("VmRSS"):
            return int(ln.split()[1])


def test_big_file_small_window(bastion, certs, www):
    """A 100 MiB body through a 16 KiB stream window arrives whole: every byte waits for a
    WINDOW_UPDATE and none is lost or duplicated."""
    srv = bastion(conf(certs, www))
    c = h2.H2(srv.ports["https"], timeout=30, settings=[(h2.S_INITIAL_WINDOW_SIZE, 16384)])
    c.get(1, "/big.bin")
    st = c.response(1, timeout=120)
    assert st.status == 200 and st.ended, (st.status, st.reset)
    assert len(st.body) == BIG
    assert st.header("content-length") == str(BIG)
    assert st.body.count(0) == BIG  # a sparse file reads as zeros
    assert "killed by signal" not in srv.logs()
    c.close()


def test_zero_window_timeout(bastion, certs, www):
    """A client that never opens its window is cut off by send_timeout, with a stream reset, and
    the connection stays usable for others."""
    srv = bastion(conf(certs, www, "send_timeout 2s;"))
    c = h2.H2(srv.ports["https"], settings=[(h2.S_INITIAL_WINDOW_SIZE, 0)])
    c.get(1, "/mid.bin")
    start = time.monotonic()
    st = c.response(1, timeout=10)
    elapsed = time.monotonic() - start
    assert st.reset == h2.CANCEL, (st.reset, st.status, st.ended)
    assert 1.0 <= elapsed < 6.0, elapsed
    assert not st.body
    # the connection itself is alive: a small request on a fresh stream is answered
    c.send(h2.settings_frame([(h2.S_INITIAL_WINDOW_SIZE, 65535)]))
    c.get(3, "/mid.bin")
    st3 = c.response(3, timeout=10)
    assert st3.status == 200
    c.close()


def test_window_drip_is_cut_off(bastion, certs, www):
    """One byte of window every 300 ms is not progress: the stall timer is not reset by it."""
    srv = bastion(conf(certs, www, "send_timeout 2s;"))
    c = h2.H2(srv.ports["https"], settings=[(h2.S_INITIAL_WINDOW_SIZE, 0)], auto_wu=False)
    c.get(1, "/mid.bin")
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and c.stream(1).reset is None and not c.eof:
        c.send(h2.window_update(1, 1))
        c.pump(0.3)
    assert c.stream(1).reset == h2.CANCEL or c.eof
    c.close()


def test_memory_bound(bastion, certs, www):
    """256 streams, each waiting on a closed window for a 1 MiB body, hold only what the windows
    and queues allow: the worker's memory stays far below 256 x 1 MiB."""
    srv = bastion(conf(certs, www, "http2_max_concurrent_streams 256;"))
    pid = next(iter(srv.workers().values()))
    before = rss_kb(pid)
    c = h2.H2(srv.ports["https"], settings=[(h2.S_INITIAL_WINDOW_SIZE, 0)], auto_wu=False)
    for i in range(256):
        c.get(1 + 2 * i, "/mid.bin")
    c.drain(1.0)
    assert sum(1 for s in c.streams.values() if s.status == 200) == 256
    grown_mb = (rss_kb(pid) - before) / 1024
    assert grown_mb < 64, grown_mb  # 256 MiB if a body were buffered per stream
    c.close()
    assert "killed by signal" not in srv.logs()
