import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
DOC = (ROOT / "docs/quickstart.md").read_text()
BLOCKS = re.findall(r"```conf\n(.*?)```", DOC, re.S)


def test_quickstart_has_examples():
    assert len(BLOCKS) >= 5


@pytest.mark.parametrize("idx", range(len(BLOCKS)))
def test_quickstart_config_checks(bastion_bin, tmp_path, idx):
    (tmp_path / "public").mkdir()
    (tmp_path / "public" / "index.html").write_text("ok\n")
    cfg = tmp_path / "bastion.conf"
    cfg.write_text(BLOCKS[idx].replace("/srv/www", str(tmp_path / "public")))
    p = subprocess.run([bastion_bin, "-c", str(cfg), "-t"], cwd=tmp_path,
                       capture_output=True, text=True, timeout=30)
    assert p.returncode == 0, p.stderr
    assert "configuration ok" in p.stdout + p.stderr
