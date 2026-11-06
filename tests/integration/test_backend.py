"""Runtime I/O backend selection, driven through `bastion -t`, which probes exactly as a
worker would (it creates and frees a loop with the configured io { } settings).
test_sysctl_disabled needs the global kernel.io_uring_disabled sysctl and lives in tests/vm."""
import os
import re
import subprocess
from pathlib import Path

import pytest

SRV = "server { listen 8080; }\n"
WRAP = os.environ.get("SECCOMP_WRAP", "")
LINE = re.compile(r"^io backend: (\w+) \((.+)\)$", re.M)


def run_t(binary, tmp_path, io_text, env=None, wrap=False):
    conf = tmp_path / "b.conf"
    conf.write_text(io_text + SRV)
    cmd = [binary, "-c", str(conf), "-t"]
    if wrap:
        if not WRAP or not Path(WRAP).exists():
            pytest.fail("SECCOMP_WRAP not set: run through make test-int")
        cmd = [WRAP] + cmd
    e = dict(os.environ)
    e.pop("BST_TEST_URING_FAIL", None)
    e.update(env or {})
    return subprocess.run(cmd, capture_output=True, text=True, timeout=30, env=e)


def backend_line(p):
    m = LINE.search(p.stdout)
    assert m, (p.stdout, p.stderr)
    return m.group(1), m.group(2)


def test_auto_prefers_uring(bastion_bin, tmp_path):
    p = run_t(bastion_bin, tmp_path, "")
    assert p.returncode == 0, p.stderr
    assert "configuration ok" in p.stdout
    name, reason = backend_line(p)
    assert name == "uring", p.stdout
    assert "SINGLE_ISSUER" in reason


def test_fallback_seccomp_blocked(bastion_bin, tmp_path):
    p = run_t(bastion_bin, tmp_path, "io { backend auto; }\n", wrap=True)
    assert p.returncode == 0, p.stderr
    name, reason = backend_line(p)
    assert name == "epoll"
    assert "EPERM" in reason and "io_uring_setup" in reason


def test_forced_uring_fails(bastion_bin, tmp_path):
    p = run_t(bastion_bin, tmp_path, "io { backend uring; }\n", wrap=True)
    assert p.returncode == 1, (p.stdout, p.stderr)
    assert "io backend: " not in p.stdout
    assert "uring" in p.stderr and "EPERM" in p.stderr
    assert p.stderr.count("\n") == 1, p.stderr


def test_forced_epoll_ignores_uring(bastion_bin, tmp_path):
    p = run_t(bastion_bin, tmp_path, "io { backend epoll; }\n", wrap=True)
    assert p.returncode == 0, p.stderr
    assert backend_line(p)[0] == "epoll"


def test_flag_ladder(bastion_bin, tmp_path):
    p = run_t(bastion_bin, tmp_path, "", env={"BST_TEST_URING_FAIL": "defer_taskrun:22"})
    assert p.returncode == 0, p.stderr
    name, reason = backend_line(p)
    assert name == "uring"
    assert "DEFER_TASKRUN refused" in reason


def test_missing_opcode_falls_back(bastion_bin, tmp_path):
    p = run_t(bastion_bin, tmp_path, "", env={"BST_TEST_URING_FAIL": "probe:95"})
    assert p.returncode == 0, p.stderr
    name, reason = backend_line(p)
    assert name == "epoll" and "opcode" in reason


def test_napi_require_is_an_error(bastion_bin, tmp_path):
    p = run_t(bastion_bin, tmp_path, "io { uring_napi on require; backend uring; }\n",
              env={"BST_TEST_URING_FAIL": "napi:95"})
    assert p.returncode == 1, (p.stdout, p.stderr)
    assert "NAPI" in p.stderr


def test_entries_warning(bastion_bin, tmp_path):
    p = run_t(bastion_bin, tmp_path, "io { uring_entries 300; }\n")
    assert p.returncode == 0, p.stderr
    assert "warning" in p.stderr and "rounded up to 512" in p.stderr


def test_bad_backend_value(bastion_bin, tmp_path):
    p = run_t(bastion_bin, tmp_path, "io { backend iouring; }\n")
    assert p.returncode == 1
    assert "backend" in p.stderr or "iouring" in p.stderr



def test_einval_after_every_flag_set_falls_back(bastion_bin, tmp_path):
    env = {"BST_TEST_URING_FAIL": "setup:22"}
    p = run_t(bastion_bin, tmp_path, "", env=env)
    assert p.returncode == 0, p.stderr
    name, reason = backend_line(p)
    assert name == "epoll" and "refused every flag set (EINVAL)" in reason
    p = run_t(bastion_bin, tmp_path, "io { backend uring; }\n", env=env)
    assert p.returncode == 1
    assert "refused every flag set (EINVAL)" in p.stderr


def test_eperm_after_setup_is_not_a_fallback(bastion_bin, tmp_path):
    p = run_t(bastion_bin, tmp_path, "", env={"BST_TEST_URING_FAIL": "enable:1"})
    assert p.returncode == 1, (p.stdout, p.stderr)
    assert "io backend: " not in p.stdout


def test_napi_require_with_epoll_is_rejected(bastion_bin, tmp_path):
    p = run_t(bastion_bin, tmp_path, "io { uring_napi on require; backend epoll; }\n")
    assert p.returncode == 1, (p.stdout, p.stderr)
    assert "NAPI" in p.stderr and "epoll" in p.stderr
    # auto would fall back to epoll without NAPI: also an error
    p = run_t(bastion_bin, tmp_path, "io { uring_napi on require; }\n",
              env={"BST_TEST_URING_FAIL": "setup:1"})
    assert p.returncode == 1 and "NAPI" in p.stderr


def test_line_says_whether_napi_is_active(bastion_bin, tmp_path):
    p = run_t(bastion_bin, tmp_path, "")
    assert "NAPI off" in backend_line(p)[1]
    p = run_t(bastion_bin, tmp_path, "io { uring_napi on; }\n",
              env={"BST_TEST_URING_FAIL": "napi:95"})
    assert p.returncode == 0, p.stderr
    assert "NAPI unavailable" in backend_line(p)[1]
