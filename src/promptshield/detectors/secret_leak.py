"""Credentials appearing in model output."""

import re

from ..detector import OUTPUT, Detector, register
from ..finding import Finding, Severity
from ..redact import redact

SECRET_PATTERNS: tuple[tuple[str, str, Severity], ...] = (
    ("AWS access key ID", r"\b(AKIA|ASIA)[0-9A-Z]{16}\b", Severity.CRITICAL),
    ("GitHub token", r"\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b", Severity.CRITICAL),
    ("Anthropic API key", r"\bsk-ant-[A-Za-z0-9_-]{20,}", Severity.CRITICAL),
    ("OpenAI API key", r"\bsk-(proj-)?[A-Za-z0-9_-]{20,}", Severity.CRITICAL),
    ("Google API key", r"\bAIza[0-9A-Za-z_-]{35}\b", Severity.HIGH),
    ("Slack token", r"\bxox[abposr]-[A-Za-z0-9-]{10,}", Severity.HIGH),
    ("Stripe secret key", r"\b(sk|rk)_live_[A-Za-z0-9]{20,}\b", Severity.CRITICAL),
    ("Private key block", r"-----BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----", Severity.CRITICAL),
    ("JSON Web Token", r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b", Severity.HIGH),
)


@register
class SecretLeak(Detector):
    name = "secret_leak"
    kind = OUTPUT
    description = "API keys, tokens and private keys in model output."

    def __init__(self, **options) -> None:
        super().__init__(**options)
        self._compiled = [(label, re.compile(p), sev) for label, p, sev in SECRET_PATTERNS]

    def scan(self, text: str, normalized: str) -> list[Finding]:
        findings = []
        seen = set()
        for label, regex, severity in self._compiled:
            for match in regex.finditer(text):
                value = match.group(0)
                if any(value in s or s in value for s in seen):
                    continue
                seen.add(value)
                findings.append(Finding(self.name, severity, f"{label} in output", redact(value)))
        return findings
