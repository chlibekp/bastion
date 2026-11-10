"""The conformance tests start the real binary exactly like the integration tests do, so they
share its fixtures (the `bastion` factory, both backends, the sandbox check)."""
import importlib.util
import sys
from pathlib import Path

INTEGRATION = Path(__file__).resolve().parents[1] / "integration"
sys.path.insert(0, str(INTEGRATION))

_spec = importlib.util.spec_from_file_location("integration_conftest", INTEGRATION / "conftest.py")
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
globals().update({k: v for k, v in vars(_mod).items() if not k.startswith("__")})
