"""Injection instructions hidden inside base64 or hex blobs."""

from __future__ import annotations

import base64
import binascii
import re

from ..detector import Detector, register
from ..finding import Finding, Severity
from ..normalize import normalize
from .instruction_override import InstructionOverride
from .jailbreak_persona import JailbreakPersona
from .role_hijack import RoleHijack
from .system_prompt_extraction import SystemPromptExtraction

_BASE64 = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")
_HEX = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}){16,}(?![0-9a-fA-F])")


def _printable(data: bytes) -> str | None:
    try:
        decoded = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not decoded or sum(ch.isprintable() or ch.isspace() for ch in decoded) / len(decoded) < 0.9:
        return None
    return decoded


def decode_candidates(text: str) -> list[tuple[str, str]]:
    """Return ``(encoding, decoded_text)`` for every blob that decodes to readable text."""
    results = []
    for match in _BASE64.finditer(text):
        blob = match.group(0)
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
        except (binascii.Error, ValueError):
            continue
        decoded = _printable(raw)
        if decoded:
            results.append(("base64", decoded))
    for match in _HEX.finditer(text):
        decoded = _printable(bytes.fromhex(match.group(0)))
        if decoded:
            results.append(("hex", decoded))
    return results


@register
class EncodedPayload(Detector):
    name = "encoded_payload"
    description = "Base64 or hex blobs that decode to injection instructions."

    def __init__(self, **options) -> None:
        super().__init__(**options)
        self._inner = [InstructionOverride(), RoleHijack(), SystemPromptExtraction(), JailbreakPersona()]

    def scan(self, text: str, normalized: str) -> list[Finding]:
        findings = []
        for encoding, decoded in decode_candidates(text):
            inner_norm = normalize(decoded)
            hits = [f for detector in self._inner for f in detector.scan(decoded, inner_norm)]
            if hits:
                findings.append(
                    Finding(
                        self.name,
                        Severity.HIGH,
                        f"{encoding} blob decodes to an injection attempt ({hits[0].detector})",
                        decoded[:120],
                    )
                )
        return findings
