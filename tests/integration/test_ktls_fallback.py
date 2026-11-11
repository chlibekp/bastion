"""kTLS asked for where the kernel cannot do it (Docker Desktop's LinuxKit has no `tls` module):
user-space TLS with one warning, or a startup error under `require`. Skipped where the kernel
has kTLS, since there the fallback cannot be provoked; tests/vm/test_ktls.py covers that side."""
import os
import ssl
import subprocess

import pytest

from test_tls_conn import client_ctx, conf, get, tls_connect, www  # noqa: F401

pytestmark = pytest.mark.skipif(os.path.exists("/proc/net/tls_stat"),
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
