"""Guard a streamed model response token by token.

Most guardrails only look at a finished reply, but chat UIs stream. By the time
a full reply is available the leaked API key has already been painted on the
user's screen. ``StreamGuard`` sits between the model stream and the client:
it scans incrementally, holds back a short tail so a secret split across two
chunks is never half-emitted, and halts the stream the moment the verdict
reaches ``block``::

    guard = StreamGuard(Scanner(canaries=[canary]))
    for chunk in llm.stream(prompt):
        yield guard.feed(chunk)
    yield guard.close()
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator

from .detector import OUTPUT
from .finding import Finding
from .scanner import BLOCK, Scanner, ScanResult

DEFAULT_REPLACEMENT = "\n[response withheld by promptshield]"
_SPACE = re.compile(r"\s")


class StreamGuard:
    """Incremental output scanner with a hold-back buffer.

    Text is only released once it has been scanned as complete tokens (up to
    the last whitespace), so a key that arrives one character at a time is never
    partly shown. ``holdback`` keeps an extra tail unreleased on top of that.
    ``overlap`` is how much already-released text is re-scanned together with
    new text so that multi-token patterns straddling the boundary still match.
    """

    def __init__(
        self,
        scanner: Scanner | None = None,
        holdback: int = 160,
        overlap: int = 512,
        replacement: str = DEFAULT_REPLACEMENT,
    ) -> None:
        if holdback < 0 or overlap < holdback:
            raise ValueError("holdback must be >= 0 and overlap must be >= holdback")
        self.scanner = scanner or Scanner()
        self.holdback = holdback
        self.overlap = overlap
        self.replacement = replacement
        self._text = ""
        self._released = 0
        self._scanned = 0
        self._findings: dict[tuple[str, str, str], Finding] = {}
        self._result = self.scanner.decide((), OUTPUT)
        self._closed = False

    @property
    def result(self) -> ScanResult:
        """The verdict over everything seen so far."""
        return self._result

    @property
    def blocked(self) -> bool:
        return self._result.verdict == BLOCK

    @property
    def text(self) -> str:
        """The full text received so far, including anything withheld."""
        return self._text

    def _rescan(self, final: bool = False) -> None:
        start = max(0, self._released - self.overlap)
        if start:
            # Begin on a token boundary so a half-cut token is not reported.
            space = _SPACE.search(self._text, start, self._released)
            start = space.end() if space else start
        if final:
            end = len(self._text)
        else:
            last = max(self._text.rfind(ch, start) for ch in " \n\t\r")
            end = last + 1 if last >= start else start
        if end > start:
            for finding in self.scanner.scan(self._text[start:end], OUTPUT).findings:
                self._findings.setdefault((finding.detector, finding.message, finding.evidence), finding)
            self._result = self.scanner.decide(self._findings.values(), OUTPUT)
        self._scanned = max(self._scanned, end)

    def _release(self, upto: int) -> str:
        if upto <= self._released:
            return ""
        out = self._text[self._released : upto]
        self._released = upto
        return out

    def feed(self, chunk: str) -> str:
        """Add a chunk from the model and return the text that is safe to show now."""
        if self._closed:
            raise RuntimeError("stream already closed")
        if self.blocked or not chunk:
            return ""
        self._text += chunk
        self._rescan()
        if self.blocked:
            return self.replacement
        return self._release(min(len(self._text) - self.holdback, self._scanned))

    def close(self) -> str:
        """Flush the held-back tail once the model stream has ended."""
        if self._closed:
            return ""
        self._closed = True
        if self.blocked:
            return ""
        self._rescan(final=True)
        if self.blocked:
            return self.replacement
        return self._release(len(self._text))

    def wrap(self, chunks: Iterable[str]) -> Iterator[str]:
        """Convenience generator: ``for piece in guard.wrap(stream): send(piece)``."""
        for chunk in chunks:
            out = self.feed(chunk)
            if out:
                yield out
            if self.blocked:
                return
        tail = self.close()
        if tail:
            yield tail
