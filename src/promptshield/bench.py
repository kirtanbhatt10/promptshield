"""Measure detection quality and speed on a labelled corpus.

Guardrails are usually sold on claims. ``promptshield bench`` turns them into
numbers you can gate CI on: precision, recall, F1, the false positives and
negatives behind them, and per-scan latency. A built-in corpus ships with the
package; pass your own JSONL (``{"text", "label": "attack"|"benign", "mode"}``)
to measure the policy you actually run.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path

from .scanner import ALLOW, Scanner


@dataclass(frozen=True)
class Sample:
    text: str
    label: str
    mode: str = "input"


@dataclass
class BenchReport:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    latencies_ms: list[float] = field(default_factory=list)
    false_positives: list[str] = field(default_factory=list)
    false_negatives: list[str] = field(default_factory=list)

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else 1.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if p + r else 0.0

    def _percentile(self, q: float) -> float:
        if not self.latencies_ms:
            return 0.0
        ordered = sorted(self.latencies_ms)
        return ordered[min(len(ordered) - 1, int(q * len(ordered)))]

    def to_dict(self) -> dict:
        return {
            "samples": self.tp + self.fp + self.tn + self.fn,
            "tp": self.tp,
            "fp": self.fp,
            "tn": self.tn,
            "fn": self.fn,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "latency_ms": {"p50": round(self._percentile(0.5), 3), "p99": round(self._percentile(0.99), 3)},
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
        }

    def to_text(self) -> str:
        d = self.to_dict()
        lines = [
            f"samples: {d['samples']}  tp={self.tp} fp={self.fp} tn={self.tn} fn={self.fn}",
            f"precision: {self.precision:.3f}  recall: {self.recall:.3f}  f1: {self.f1:.3f}",
            f"latency: p50 {d['latency_ms']['p50']} ms  p99 {d['latency_ms']['p99']} ms",
        ]
        for title, items in (("missed attacks", self.false_negatives), ("false alarms", self.false_positives)):
            if items:
                lines.append(f"{title}:")
                lines += [f"  - {item}" for item in items]
        return "\n".join(lines)


def load_corpus(path: str | Path | None = None) -> list[Sample]:
    """Load a JSONL corpus, or the built-in one when ``path`` is None."""
    if path is None:
        raw = resources.files("promptshield").joinpath("data/bench.jsonl").read_text(encoding="utf-8")
        where = "built-in corpus"
    else:
        raw = Path(path).read_text(encoding="utf-8")
        where = str(path)
    samples = []
    for number, line in enumerate(raw.splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
            sample = Sample(str(row["text"]), str(row["label"]), str(row.get("mode", "input")))
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise ValueError(f"{where}:{number}: invalid sample ({exc})") from exc
        if sample.label not in ("attack", "benign") or sample.mode not in ("input", "output"):
            raise ValueError(f"{where}:{number}: label must be attack|benign and mode input|output")
        samples.append(sample)
    if not samples:
        raise ValueError(f"{where}: no samples")
    return samples


def run_bench(scanner: Scanner, samples: list[Sample]) -> BenchReport:
    """Score every sample. Anything other than ``allow`` counts as a detection."""
    report = BenchReport()
    for sample in samples:
        start = time.perf_counter()
        result = scanner.scan(sample.text, sample.mode)
        report.latencies_ms.append((time.perf_counter() - start) * 1000)
        flagged = result.verdict != ALLOW
        preview = sample.text.replace("\n", " ")[:80]
        if sample.label == "attack":
            if flagged:
                report.tp += 1
            else:
                report.fn += 1
                report.false_negatives.append(preview)
        elif flagged:
            report.fp += 1
            report.false_positives.append(f"{preview}  ({result.verdict}, {result.findings[0].detector})")
        else:
            report.tn += 1
    return report
