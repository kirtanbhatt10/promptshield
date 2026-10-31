"""Finding and severity types shared by every detector."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import IntEnum


class Severity(IntEnum):
    """How serious a finding is. Ordered so that comparisons work."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str | int | Severity) -> Severity:
        """Accept a Severity, an int, or a case-insensitive name."""
        if isinstance(value, Severity):
            return value
        if isinstance(value, int):
            return cls(value)
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:
            raise ValueError(f"unknown severity: {value!r}") from exc


@dataclass(frozen=True)
class Finding:
    """A single issue reported by a detector."""

    detector: str
    severity: Severity
    message: str
    evidence: str = ""

    def to_dict(self) -> dict:
        data = asdict(self)
        data["severity"] = self.severity.name.lower()
        return data
