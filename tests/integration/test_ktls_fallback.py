"""kTLS asked for where the kernel cannot do it (Docker Desktop's LinuxKit has no `tls` module):
user-space TLS with one warning, or a startup error under `require`. Skipped where the kernel
has kTLS, since there the fallback cannot be provoked; tests/vm/test_ktls.py covers that side."""
import os
import socket
import ssl
import subprocess

import pytest

from test_tls_conn import client_ctx, conf, get, tls_connect, www  # noqa: F401

def kernel_has_ktls():
    """True when the tls ULP attaches here. /proc/net/tls_stat appears only once the module is
    loaded, and the kernel loads it on demand at the first TCP_ULP "tls" (as the server's does)."""
    if os.path.exists("/proc/net/tls_stat"):
        return True
    TCP_ULP = 31
    with socket.socket() as ls:
        ls.bind(("127.0.0.1", 0))
        ls.listen(1)
        with socket.create_connection(ls.getsockname()) as c:
            try:
                c.setsockopt(socket.IPPROTO_TCP, TCP_ULP, b"tls")
                return True
            except OSError:
                return False


pytestmark = pytest.mark.skipif(kernel_has_ktls(),
                                reason="this kernel has kTLS; the fallback needs one without")


def test_ktls_fallback_warns(bastion, certs, www):  # noqa: F811
    srv = bastion(conf(certs, www, profile="tls_profile k { ktls tx; }", tls_extra="tls_profile k;"))
    for _ in range(3):
        assert get(srv, certs, "/small.txt")[0] == 200
    log = srv.logs()
    assert log.count("kernel TLS did not activate") == 1, log


def test_ktls_off_is_silent(bastion, certs, www):  # noqa: F811
    srv = bastion(conf(certs, www, profile="tls_profile k { ktls off; }", tls_extra="tls_profile k;"))
    assert get(srv, certs, "/small.txt")[0] == 200
    assert "kernel TLS" not in srv.logs()


def test_ktls_require_fails(bastion, certs, www, bastion_bin):  # noqa: F811
    srv = bastion(conf(certs, www, profile="tls_profile k { ktls tx require; }",
                       tls_extra="tls_profile k;"), wait=None)
    assert srv.proc.wait(10) != 0
    assert "ktls:" in srv.stdout() + srv.logs()
