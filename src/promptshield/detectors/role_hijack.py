"""Attempts to give the model a new identity with fewer restrictions."""

from ..detector import PatternDetector, register
from ..finding import Severity


@register
class RoleHijack(PatternDetector):
    name = "role_hijack"
    description = "Text that reassigns the assistant's identity or removes its restrictions."
    patterns = (
        (
            r"\b(act|behave|respond|answer|operate)\s+as\s+(if\s+you\s+(were|are)\s+)?(an?\s+)?"
            r"(unrestricted|unfiltered|uncensored|unaligned|evil|rogue|jailbroken)\b",
            Severity.HIGH,
            "Asks the model to act as an unrestricted persona",
        ),
        (
            r"\bpretend\s+(that\s+)?you\s+(are|have)\s+no\s+(rules|restrictions|limits|guidelines|filters|policies)\b",
            Severity.HIGH,
            "Asks the model to pretend it has no restrictions",
        ),
        (
            r"\byou\s+(are|will\s+be|become)\b[^.\n]{0,60}?\b(with\s+no|without\s+(any\s+)?)\s*"
            r"(restrictions|rules|filters|limits|guidelines|censorship|content\s+polic(y|ies))\b",
            Severity.HIGH,
            "Gives the model an identity without restrictions",
        ),
        (
            r"\b(role-?play|roleplay)\s+as\b[^.\n]{0,50}?\b(without|no)\s+(rules|restrictions|limits|filters)\b",
            Severity.HIGH,
            "Role-play framing used to drop restrictions",
        ),
        (
            r"\byou\s+are\s+(now|no\s+longer)\s+(an?\s+)?([a-z]+\s+)?(ai|assistant|chatbot|model|bound|restricted|limited|[a-z]+gpt)\b",
            Severity.MEDIUM,
            "Tries to reassign the assistant's identity",
        ),
    )
