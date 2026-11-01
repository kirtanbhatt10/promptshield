"""Attempts to break out of a data block and speak as the user or system.

Indirect-injection payloads in retrieved documents often try to "close" the
wrapper they expect to be inside (``</document>``, ``END OF CONTEXT``) and then
open a fake instruction section. Pairs well with :class:`promptshield.Spotlight`.
"""

from ..detector import INPUT, PatternDetector, register
from ..finding import Severity


@register
class BoundaryEscape(PatternDetector):
    name = "boundary_escape"
    kind = INPUT
    description = "Fake closing tags or end-of-document markers used to escape a data block."
    patterns = (
        (r"<</?\s*untrusted", Severity.HIGH, "Tries to forge a spotlight boundary"),
        (
            r"</\s*(untrusted|document|documents|context|retrieved|search_results?|tool_(output|result)|email|webpage|data)\s*>",
            Severity.MEDIUM,
            "Closes a data wrapper tag",
        ),
        (
            r"\b(end|close) of (the )?(untrusted |retrieved |external )?(document|context|data|email|web ?page|search results?|tool output)\b.{0,40}\b(new|real|actual|updated|system|user)\b.{0,20}\b(instruction|task|prompt|message)s?\b",
            Severity.HIGH,
            "Declares the data block over and starts new instructions",
        ),
        (
            r"(^|\s)[-=#*]{3,}\s*(end|stop)\s*(of\s*)?(document|context|data|input)\s*[-=#*]{3,}",
            Severity.MEDIUM,
            "Fake end-of-document separator",
        ),
    )
