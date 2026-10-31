"""promptshield: prompt-injection and LLM output leak scanner."""

__version__ = "0.1.0"

from .canary import embed, make_canary  # noqa: E402
from .finding import Finding, Severity  # noqa: E402
from .policy import Policy, PolicyError  # noqa: E402
from .scanner import Scanner, ScanResult  # noqa: E402

__all__ = [
    "Finding",
    "Policy",
    "PolicyError",
    "ScanResult",
    "Scanner",
    "Severity",
    "__version__",
    "embed",
    "make_canary",
]
