import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def test_version_output(bastion_bin):
    p = subprocess.run([bastion_bin, "--version"], capture_output=True, text=True, timeout=10)
    assert p.returncode == 0
    assert re.match(r"^bastion \d+\.\d+\.\d+ .*OpenSSL 3\.5\.\d+", p.stdout), p.stdout


def test_dev_path_with_spaces():
    if shutil.which("docker") is None:
        pytest.skip("docker CLI not available inside the test container; "
                    "run tests/host/test_dev_paths.sh on the host")
    p = subprocess.run(["bash", str(ROOT / "tests/host/test_dev_paths.sh")],
                       capture_output=True, text=True, timeout=600)
    assert p.returncode == 0, p.stdout + p.stderr
