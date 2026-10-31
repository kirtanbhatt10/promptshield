"""Well-known jailbreak personas and 'special mode' framings."""

from ..detector import PatternDetector, register
from ..finding import Severity


@register
class JailbreakPersona(PatternDetector):
    name = "jailbreak_persona"
    description = "Known jailbreak personas (DAN and friends) and fake 'developer mode' switches."
    patterns = (
        (
            r"\b(do anything now|dan mode|jailbreak(ed)? mode|stan mode|dude mode|aim mode)\b",
            Severity.HIGH,
            "References a known jailbreak persona",
        ),
        (
            r"\b(developer|god|admin|debug|maintenance|sudo|unrestricted)\s+mode\b[^.\n]{0,30}?\b(enabled|activated|on|unlocked)\b",
            Severity.HIGH,
            "Claims a special unrestricted mode has been enabled",
        ),
        (
            r"\b(no|without|free (of|from))\s+(any\s+)?(ethical|moral|safety|content)\s+"
            r"(guidelines|restrictions|filters|constraints|limitations|policies)\b",
            Severity.MEDIUM,
            "Asks for answers without safety guidelines",
        ),
        (
            r"\b(hypothetical|fictional|imaginary)\s+(scenario|story|world)\b[^.\n]{0,80}?\b(no rules|no restrictions|anything goes)\b",
            Severity.LOW,
            "Uses fiction framing to remove restrictions",
        ),
    )
