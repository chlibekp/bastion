"""openat2 hidden by a seccomp filter around bastion (ENOSYS), as systemd's RestrictSUIDSGID=yes
does. Every file below a root opens with openat2(RESOLVE_BENEATH) and there is no fallback that
keeps that confinement, so `-t` and a real start must refuse with a clear message instead of
answering 500 to every request (the v0.1.0 bug: `static: opening "/" failed: Function not
implemented`)."""
import os
import subprocess
from pathlib import Path

import pytest

WRAP = os.environ.get("SECCOMP_WRAP", "")
MSG = "openat2 is blocked (ENOSYS)"


def wrapped(bastion_bin, tmp_path, *args):
    if not WRAP or not Path(WRAP).exists():
        pytest.fail("SECCOMP_WRAP not set: run through make test-int")
    www = tmp_path / "www"
    www.mkdir()
    (www / "index.html").write_text("hi\n")
    conf = tmp_path / "b.conf"
    conf.write_text(f"workers 1;\nerror_log {tmp_path}/error.log;\n"
                    f"server {{ listen 127.0.0.1:0; root {www}; index index.html; }}\n")
    return subprocess.run([WRAP, "--no-openat2", bastion_bin, "-c", str(conf), *args],
                          capture_output=True, text=True, timeout=30)


def test_check_reports_it(bastion_bin, tmp_path):
    p = wrapped(bastion_bin, tmp_path, "-t")
    assert p.returncode == 1, (p.stdout, p.stderr)
    assert MSG in p.stderr and "RestrictSUIDSGID" in p.stderr, p.stderr
    assert "configuration ok" not in p.stdout


def test_start_refuses(bastion_bin, tmp_path):
    p = wrapped(bastion_bin, tmp_path)
    assert p.returncode != 0, (p.stdout, p.stderr)
    log = tmp_path / "error.log"
    out = p.stderr + (log.read_text() if log.exists() else "")
    assert MSG in out, out


def test_unwrapped_check_passes(bastion_bin, tmp_path):
    conf = tmp_path / "b.conf"
    conf.write_text("server { listen 127.0.0.1:0; }\n")
    p = subprocess.run([bastion_bin, "-c", str(conf), "-t"], capture_output=True, text=True,
                       timeout=30)
    assert p.returncode == 0 and MSG not in p.stderr, p.stderr
