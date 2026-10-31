"""The scanner: runs detectors, scores findings and decides a verdict."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from .detector import INPUT, OUTPUT, Detector, registry
from .finding import Finding, Severity
from .normalize import normalize
from .policy import Policy

ALLOW = "allow"
REVIEW = "review"
BLOCK = "block"
VERDICTS = (ALLOW, REVIEW, BLOCK)

SEVERITY_WEIGHT = {
    Severity.INFO: 0,
    Severity.LOW: 10,
    Severity.MEDIUM: 25,
    Severity.HIGH: 50,
    Severity.CRITICAL: 100,
}


def risk_score(findings: Iterable[Finding]) -> int:
    """Sum severity weights, capped at 100."""
    return min(100, sum(SEVERITY_WEIGHT[f.severity] for f in findings))


@dataclass(frozen=True)
class ScanResult:
    mode: str
    findings: tuple[Finding, ...]
    score: int
    verdict: str

    @property
    def blocked(self) -> bool:
        return self.verdict == BLOCK

    @property
    def max_severity(self) -> Severity | None:
        return max((f.severity for f in self.findings), default=None)

    def to_dict(self) -> dict:
        return {
            "mode": self.mode,
            "verdict": self.verdict,
            "score": self.score,
            "findings": [f.to_dict() for f in self.findings],
        }


class Scanner:
    """Scan untrusted input before it reaches a model, and output after it leaves."""

    def __init__(self, policy: Policy | None = None, canaries: Iterable[str] = ()) -> None:
        self.policy = policy or Policy()
        self.canaries = tuple(canaries)
        self.detectors = self._build_detectors()

    def _build_detectors(self) -> list[Detector]:
        detectors = []
        for name, cls in registry().items():
            if name in self.policy.disabled:
                continue
            options = dict(self.policy.detector_options.get(name, {}))
            if name == "canary_leak":
                options.setdefault("canaries", self.canaries)
            if name == "markdown_exfil":
                options.setdefault("allowed_domains", self.policy.allowed_domains)
            detectors.append(cls(**options))
        return detectors

    def _verdict(self, score: int) -> str:
        if score >= self.policy.block_threshold:
            return BLOCK
        if score >= self.policy.review_threshold:
            return REVIEW
        return ALLOW

    def scan(self, text: str, mode: str = INPUT) -> ScanResult:
        if mode not in (INPUT, OUTPUT):
            raise ValueError(f"mode must be {INPUT!r} or {OUTPUT!r}")
        normalized = normalize(text)
        findings = [
            finding
            for detector in self.detectors
            if detector.applies_to(mode)
            for finding in detector.scan(text, normalized)
            if finding.severity >= self.policy.min_severity
        ]
        findings.sort(key=lambda f: (-f.severity, f.detector))
        score = risk_score(findings)
        return ScanResult(mode, tuple(findings), score, self._verdict(score))

    def scan_input(self, text: str) -> ScanResult:
        return self.scan(text, INPUT)

    def scan_output(self, text: str) -> ScanResult:
        return self.scan(text, OUTPUT)
