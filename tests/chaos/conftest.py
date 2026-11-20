"""The fault injection suite reuses the integration fixtures (the `bastion` server factory,
`certs`, and the sandbox, sanitizer and leaked-child checks at teardown) from
tests/integration/conftest.py. `backend` stays parametrized: every fault runs on uring and epoll."""
import importlib.util
import sys
from pathlib import Path

INTEGRATION = Path(__file__).resolve().parents[1] / "integration"
sys.path.insert(0, str(INTEGRATION))  # quic_util, upstream_util

_spec = importlib.util.spec_from_file_location("bst_integration_conftest", INTEGRATION / "conftest.py")
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
globals().update({k: v for k, v in vars(_mod).items() if not k.startswith("__")})
