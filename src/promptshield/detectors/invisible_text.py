"""Invisible characters used to hide instructions from human reviewers."""

from ..detector import BOTH, Detector, register
from ..finding import Finding, Severity
from ..normalize import BIDI_CONTROLS, ZERO_WIDTH, is_tag_char


def decode_tag_text(text: str) -> str:
    """Recover ASCII smuggled as Unicode tag characters (U+E0020..U+E007E)."""
    return "".join(chr(ord(ch) - 0xE0000) for ch in text if 0xE0020 <= ord(ch) <= 0xE007E)


@register
class InvisibleText(Detector):
    name = "invisible_text"
    kind = BOTH
    description = "Unicode tag characters, bidi overrides and zero-width characters that hide content."

    def __init__(self, zero_width_threshold: int = 3, **options) -> None:
        super().__init__(**options)
        self.zero_width_threshold = zero_width_threshold

    def scan(self, text: str, normalized: str) -> list[Finding]:
        findings = []
        if any(is_tag_char(ch) for ch in text):
            hidden = decode_tag_text(text)
            findings.append(
                Finding(self.name, Severity.CRITICAL, "Contains invisible Unicode tag characters (ASCII smuggling)", hidden[:120])
            )
        bidi = sum(ch in BIDI_CONTROLS for ch in text)
        if bidi:
            findings.append(
                Finding(self.name, Severity.MEDIUM, "Contains bidirectional override characters", f"{bidi} character(s)")
            )
        zero_width = sum(ch in ZERO_WIDTH for ch in text)
        if zero_width >= self.zero_width_threshold:
            findings.append(Finding(self.name, Severity.LOW, "Contains many zero-width characters", f"{zero_width} character(s)"))
        return findings
