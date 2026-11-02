"""promptshield: prompt-injection and LLM output leak scanner."""

__version__ = "0.2.1"

from .canary import embed, make_canary  # noqa: E402
from .finding import Finding, Severity  # noqa: E402
from .policy import Policy, PolicyError  # noqa: E402
from .scanner import Scanner, ScanResult  # noqa: E402
from .scrub import ScrubResult, scrub  # noqa: E402
from .session import Session  # noqa: E402
from .spotlight import Spotlight  # noqa: E402
from .stream import StreamGuard  # noqa: E402
from .toolguard import Decision, ToolGuard, ToolRule  # noqa: E402

__all__ = [
    "Decision",
    "Finding",
    "Policy",
    "PolicyError",
    "ScanResult",
    "Scanner",
    "ScrubResult",
    "Session",
    "Severity",
    "Spotlight",
    "StreamGuard",
    "ToolGuard",
    "ToolRule",
    "__version__",
    "embed",
    "make_canary",
    "scrub",
]
