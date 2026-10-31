"""Detector base classes and the detector registry."""

from __future__ import annotations

import importlib
import re
from abc import ABC, abstractmethod
from typing import Any, ClassVar

from .finding import Finding, Severity

INPUT = "input"
OUTPUT = "output"
BOTH = "both"


class Detector(ABC):
    """Base class. Subclasses set ``name``, ``kind`` and implement ``scan``."""

    name: ClassVar[str]
    kind: ClassVar[str] = INPUT
    description: ClassVar[str] = ""

    def __init__(self, **options: Any) -> None:
        self.options = options

    def applies_to(self, mode: str) -> bool:
        return self.kind == BOTH or self.kind == mode

    @abstractmethod
    def scan(self, text: str, normalized: str) -> list[Finding]:
        """Return findings for ``text``; ``normalized`` is the de-obfuscated form."""


Pattern = tuple[str, Severity, str]


class PatternDetector(Detector):
    """A detector driven by a table of ``(regex, severity, message)`` rows.

    Patterns run against the normalized text unless ``use_raw`` is set.
    """

    patterns: ClassVar[tuple[Pattern, ...]] = ()
    use_raw: ClassVar[bool] = False
    flags: ClassVar[int] = re.IGNORECASE

    def __init__(self, **options: Any) -> None:
        super().__init__(**options)
        self._compiled = [(re.compile(p, self.flags), sev, msg) for p, sev, msg in self.patterns]

    def scan(self, text: str, normalized: str) -> list[Finding]:
        target = text if self.use_raw else normalized
        findings = []
        for regex, severity, message in self._compiled:
            match = regex.search(target)
            if match:
                findings.append(Finding(self.name, severity, message, match.group(0)[:120]))
        return findings


_REGISTRY: dict[str, type[Detector]] = {}


def register(cls: type[Detector]) -> type[Detector]:
    """Class decorator that adds a detector to the registry."""
    if not getattr(cls, "name", None):
        raise ValueError(f"{cls.__name__} must define a name")
    if cls.name in _REGISTRY and _REGISTRY[cls.name] is not cls:
        raise ValueError(f"duplicate detector name: {cls.name}")
    _REGISTRY[cls.name] = cls
    return cls


def registry() -> dict[str, type[Detector]]:
    """Return all registered detectors, loading the built-in ones first."""
    importlib.import_module("promptshield.detectors")
    return dict(sorted(_REGISTRY.items()))
