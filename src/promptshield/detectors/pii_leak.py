"""Personal data in model output, with Indian identifiers validated by checksum."""

import re

from ..checksums import luhn_valid, verhoeff_valid
from ..detector import OUTPUT, Detector, register
from ..finding import Finding, Severity
from ..redact import redact

_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_IN_MOBILE = re.compile(r"(?<![\d+])(?:\+91[\s-]?|0)?([6-9]\d{4}[\s-]?\d{5})(?!\d)")
_AADHAAR = re.compile(r"(?<!\d)([2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4})(?!\d)")
_PAN = re.compile(r"\b[A-Z]{3}[PCHABGJLFT][A-Z]\d{4}[A-Z]\b")
_CARD = re.compile(r"(?<!\d)(\d(?:[ -]?\d){12,18})(?!\d)")


def _digits(value: str) -> str:
    return re.sub(r"\D", "", value)


@register
class PiiLeak(Detector):
    name = "pii_leak"
    kind = OUTPUT
    description = "Emails, Indian mobile numbers, Aadhaar, PAN and payment card numbers in model output."

    def __init__(self, include_email: bool = True, **options) -> None:
        super().__init__(**options)
        self.include_email = include_email

    def scan(self, text: str, normalized: str) -> list[Finding]:
        findings = []
        aadhaar_digits = set()
        for match in _AADHAAR.finditer(text):
            digits = _digits(match.group(1))
            if verhoeff_valid(digits):
                aadhaar_digits.add(digits)
                findings.append(Finding(self.name, Severity.HIGH, "Aadhaar number in output", redact(digits, 0, 4)))
        for match in _PAN.finditer(text):
            findings.append(Finding(self.name, Severity.HIGH, "PAN number in output", redact(match.group(0), 2, 1)))
        for match in _CARD.finditer(text):
            digits = _digits(match.group(1))
            if digits not in aadhaar_digits and luhn_valid(digits):
                findings.append(Finding(self.name, Severity.HIGH, "Payment card number in output", redact(digits, 0, 4)))
        for match in _IN_MOBILE.finditer(text):
            digits = _digits(match.group(1))
            if not any(digits in a for a in aadhaar_digits):
                findings.append(Finding(self.name, Severity.MEDIUM, "Indian mobile number in output", redact(digits, 2, 2)))
        if self.include_email:
            for match in _EMAIL.finditer(text):
                findings.append(Finding(self.name, Severity.LOW, "Email address in output", redact(match.group(0), 2, 4)))
        return findings
