"""Canary tokens from the system prompt appearing in model output."""

from __future__ import annotations

import re

from ..detector import OUTPUT, Detector, register
from ..finding import Finding, Severity


def _loose(canary: str) -> re.Pattern[str]:
    """Match the canary even if the model spaced it out or changed case."""
    chars = [re.escape(ch) for ch in canary if ch.isalnum()]
    return re.compile(r"[\W_]{0,3}".join(chars), re.IGNORECASE)


@register
class CanaryLeak(Detector):
    name = "canary_leak"
    kind = OUTPUT
    description = "A canary token planted in the system prompt shows up in the output."

    def __init__(self, canaries: tuple[str, ...] | list[str] = (), **options) -> None:
        super().__init__(**options)
        self.canaries = tuple(c for c in canaries if c)
        self._patterns = [(c, _loose(c)) for c in self.canaries]

    def scan(self, text: str, normalized: str) -> list[Finding]:
        findings = []
        for canary, pattern in self._patterns:
            if canary in text:
                findings.append(Finding(self.name, Severity.CRITICAL, "System prompt canary leaked verbatim", canary))
            elif pattern.search(text):
                findings.append(Finding(self.name, Severity.CRITICAL, "System prompt canary leaked (obfuscated)", canary))
        return findings
