"""The feature matrix reuses the integration fixtures (the `bastion` server factory, `certs`, the
sandbox, sanitizer and leaked-child checks at teardown) from tests/integration/conftest.py.

Each matrix cell names its own I/O backend, so `backend` is not parametrized here: the cells
already spread uring and epoll pairwise across the other features."""
import importlib.util
import sys
from pathlib import Path

import pytest

INTEGRATION = Path(__file__).resolve().parents[1] / "integration"
sys.path.insert(0, str(INTEGRATION))  # quic_util, upstream_util

_spec = importlib.util.spec_from_file_location("bst_integration_conftest", INTEGRATION / "conftest.py")
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
globals().update({k: v for k, v in vars(_mod).items() if not k.startswith("__")})


@pytest.fixture
def backend():
    return "uring"  # only the default; each cell passes backend= itself
