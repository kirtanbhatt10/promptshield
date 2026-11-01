"""Repair model output instead of throwing it away.

Blocking a whole reply because it contains one phone number is a poor user
experience. ``scrub`` keeps the reply and surgically removes what must not be
shown: secrets, checksum-valid personal identifiers, canary tokens, invisible
smuggling characters and Markdown images that would beacon data off-site.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from urllib.parse import urlsplit

from .checksums import luhn_valid, verhoeff_valid
from .detectors.canary_leak import _loose
from .detectors.markdown_exfil import _IMAGE, _carries_data, _host_allowed
from .detectors.pii_leak import _AADHAAR, _CARD, _EMAIL, _IN_MOBILE, _PAN
from .detectors.secret_leak import SECRET_PATTERNS
from .normalize import is_invisible

_SECRETS = [(label, re.compile(pattern)) for label, pattern, _ in SECRET_PATTERNS]


@dataclass(frozen=True)
class ScrubResult:
    text: str
    removed: dict[str, int]

    @property
    def changed(self) -> bool:
        return bool(self.removed)

    def to_dict(self) -> dict:
        return {"text": self.text, "removed": dict(self.removed)}


def _digits(value: str) -> str:
    return re.sub(r"\D", "", value)


def scrub(
    text: str,
    canaries: Iterable[str] = (),
    allowed_domains: Iterable[str] = (),
    emails: bool = True,
    placeholder: str = "[{kind} removed]",
) -> ScrubResult:
    """Return ``text`` with sensitive values replaced by placeholders."""
    removed: Counter[str] = Counter()
    allowed = tuple(d.lower().lstrip(".") for d in allowed_domains)

    def sub(pattern: re.Pattern[str], kind: str, text: str, valid=lambda m: True) -> str:
        def repl(match: re.Match[str]) -> str:
            if not valid(match):
                return match.group(0)
            removed[kind] += 1
            return placeholder.format(kind=kind)

        return pattern.sub(repl, text)

    invisible = sum(1 for ch in text if is_invisible(ch))
    if invisible:
        removed["invisible character"] += invisible
        text = "".join(ch for ch in text if not is_invisible(ch))

    for canary in canaries:
        if canary:
            text = sub(_loose(canary), "canary", text)

    def exfil(match: re.Match[str]) -> bool:
        url = match.group(1)
        return not _host_allowed(urlsplit(url).hostname or "", allowed) and _carries_data(url, 16)

    text = sub(_IMAGE, "tracking image", text, exfil)
    for label, pattern in _SECRETS:
        text = sub(pattern, label, text)
    text = sub(_AADHAAR, "Aadhaar number", text, lambda m: verhoeff_valid(_digits(m.group(1))))
    text = sub(_CARD, "card number", text, lambda m: luhn_valid(_digits(m.group(1))))
    text = sub(_PAN, "PAN", text)
    text = sub(_IN_MOBILE, "phone number", text)
    if emails:
        text = sub(_EMAIL, "email", text)
    return ScrubResult(text, dict(removed))
