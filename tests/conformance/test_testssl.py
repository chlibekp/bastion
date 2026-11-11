"""TLS scan gate: testssl.sh against the default configuration. Fails on any finding of severity
HIGH or CRITICAL, on any protocol other than TLS 1.2 and 1.3 being offered, and on any cipher
outside the allowed list.

testssl.sh is not part of the development image and nothing here fetches it. The test runs only
when the tool is found (in this order): the TESTSSL environment variable, `testssl.sh` or `testssl`
on PATH, or build/tools/testssl.sh*/testssl.sh. Otherwise it SKIPS with that reason: a skipped gate
is not a passed gate (see docs/conformance.md). The parsing below follows testssl.sh's documented
JSON (a list of {id, severity, finding}) and has not been run against real output."""
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SEVERE = {"HIGH", "CRITICAL"}
BAD_PROTOCOLS = ["SSLv2", "SSLv3", "TLS1", "TLS1_1"]
ALLOWED_CIPHER = re.compile(
    r"ECDHE-(ECDSA|RSA)-AES(128|256)-GCM-SHA(256|384)|ECDHE-(ECDSA|RSA)-CHACHA20-POLY1305"
    r"|TLS_AES_(128|256)_GCM_SHA(256|384)|TLS_CHACHA20_POLY1305_SHA256"
    r"|TLS_AES_128_CCM|TLS13_AES|TLS13_CHACHA")


def find_testssl():
    cands = [os.environ.get("TESTSSL"), shutil.which("testssl.sh"), shutil.which("testssl")]
    cands += sorted(str(p) for p in (ROOT / "build" / "tools").glob("testssl.sh*/testssl.sh"))
    return next((c for c in cands if c and os.access(c, os.X_OK)), None)


def conf(certs, www):
    return (f"workers 1;\nserver {{ listen 127.0.0.1:@HTTPS_PORT@ tls; "
            f"tls_cert {certs}/ecdsa-chain.crt {certs}/ecdsa.key; root {www}; }}\n")


def test_testssl_default_config(bastion, certs, tmp_path):
    tool = find_testssl()
    if tool is None:
        pytest.skip("testssl.sh not found (set TESTSSL, put it on PATH, or unpack it under "
                    "build/tools/): the TLS scan gate was NOT executed")
    www = tmp_path / "www"
    www.mkdir()
    (www / "index.html").write_text("ok")
    srv = bastion(conf(certs, www))
    out = tmp_path / "scan.json"
    r = subprocess.run([tool, "--jsonfile", str(out), "--warnings", "batch", "--quiet", "--protocols",
                        "--std", "--fs", "--vulnerable", f"127.0.0.1:{srv.ports['https']}"],
                       capture_output=True, text=True, timeout=900)
    assert out.exists(), r.stdout + r.stderr
    rows = json.loads(out.read_text())
    severe = [x for x in rows if x.get("severity") in SEVERE]
    assert not severe, severe
    byid = {x["id"]: x for x in rows}
    for p in BAD_PROTOCOLS:
        f = byid.get(p, {}).get("finding", "")
        assert "not offered" in f, (p, f)
    for p in ("TLS1_2", "TLS1_3"):
        f = byid.get(p, {}).get("finding", "")
        assert f.startswith("offered"), (p, f)
    stray = [x for x in rows if x["id"].startswith("cipher-") and not ALLOWED_CIPHER.search(x.get("finding", ""))]
    assert not stray, stray
    assert "killed by signal" not in srv.logs()
