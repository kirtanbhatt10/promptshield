"""Scanner policy: thresholds, enabled detectors and detector options."""

from __future__ import annotations

import json
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .finding import Severity


class PolicyError(ValueError):
    """Raised when a policy file is invalid."""


@dataclass(frozen=True)
class Policy:
    review_threshold: int = 25
    block_threshold: int = 50
    min_severity: Severity = Severity.LOW
    disabled: frozenset[str] = frozenset()
    allowed_domains: tuple[str, ...] = ()
    detector_options: dict[str, dict[str, Any]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name in ("review_threshold", "block_threshold"):
            value = getattr(self, name)
            if not isinstance(value, int) or not 0 <= value <= 100:
                raise PolicyError(f"{name} must be an integer between 0 and 100")
        if self.review_threshold > self.block_threshold:
            raise PolicyError("review_threshold must not exceed block_threshold")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Policy:
        known = {"review_threshold", "block_threshold", "min_severity", "disabled", "allowed_domains", "detectors"}
        unknown = set(data) - known
        if unknown:
            raise PolicyError(f"unknown policy keys: {', '.join(sorted(unknown))}")
        try:
            return cls(
                review_threshold=data.get("review_threshold", 25),
                block_threshold=data.get("block_threshold", 50),
                min_severity=Severity.parse(data.get("min_severity", "low")),
                disabled=frozenset(data.get("disabled", ())),
                allowed_domains=tuple(data.get("allowed_domains", ())),
                detector_options=dict(data.get("detectors", {})),
            )
        except ValueError as exc:
            raise PolicyError(str(exc)) from exc

    @classmethod
    def from_file(cls, path: str | Path) -> Policy:
        path = Path(path)
        try:
            if path.suffix == ".toml":
                data = tomllib.loads(path.read_text(encoding="utf-8"))
            elif path.suffix == ".json":
                data = json.loads(path.read_text(encoding="utf-8"))
            else:
                raise PolicyError(f"unsupported policy format: {path.suffix or path.name}")
        except (OSError, tomllib.TOMLDecodeError, json.JSONDecodeError) as exc:
            raise PolicyError(f"cannot read policy {path}: {exc}") from exc
        return cls.from_dict(data.get("promptshield", data))
