"""A firewall for agent tool calls, with taint tracking.

Prompt injection only becomes dangerous when the model can *act*: send an
email, fetch a URL, write a file. ``ToolGuard`` checks every tool call your
agent proposes before you execute it:

* per-tool allow / confirm / deny rules and call budgets,
* egress allowlists for any URL in the arguments, and path jails for file tools,
* secrets, PII and canaries in arguments (exfiltration),
* injection text being passed on to another system,
* **taint tracking**: content you mark as untrusted (a fetched web page, an
  email body) is fingerprinted. If a later tool call copies that content into a
  side-effecting tool, or the agent calls such a tool after reading a poisoned
  source, the call is escalated to human confirmation or denied.

::

    guard = ToolGuard({
        "search": ToolRule(),
        "fetch": ToolRule(allowed_domains=("docs.python.org",)),
        "send_email": ToolRule(sink=True, confirm=True),
        "read_file": ToolRule(allowed_paths=("/srv/data",)),
    })
    guard.taint(page_html, source="fetch:docs.python.org")
    decision = guard.check("send_email", {"to": "...", "body": "..."})
    if decision.action == "deny": ...
"""

from __future__ import annotations

import posixpath
import re
from collections import Counter
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from .finding import Finding, Severity
from .normalize import normalize
from .scanner import BLOCK, REVIEW, Scanner

ALLOW = "allow"
CONFIRM = "confirm"
DENY = "deny"
ACTIONS = (ALLOW, CONFIRM, DENY)

_URL = re.compile(r"\b(?:https?|ftp|wss?)://[^\s\"'<>)]+", re.IGNORECASE)
_PATH_KEYS = re.compile(r"(^|_)(path|file|filename|dir|directory|folder|dest|destination|src|source)s?$", re.IGNORECASE)
_SHINGLE = 6


@dataclass(frozen=True)
class ToolRule:
    """Policy for one tool.

    ``sink`` marks tools whose arguments leave your trust boundary (email, HTTP,
    chat, payments); tainted content flowing into them needs confirmation.
    """

    allow: bool = True
    confirm: bool = False
    sink: bool = False
    allowed_domains: tuple[str, ...] = ()
    allowed_paths: tuple[str, ...] = ()
    max_calls: int | None = None


@dataclass(frozen=True)
class Decision:
    tool: str
    action: str
    reasons: tuple[str, ...] = ()
    findings: tuple[Finding, ...] = ()

    @property
    def allowed(self) -> bool:
        return self.action == ALLOW

    def to_dict(self) -> dict:
        return {
            "tool": self.tool,
            "action": self.action,
            "reasons": list(self.reasons),
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class _Source:
    name: str
    shingles: frozenset[int]
    risky: bool


@dataclass
class _Verdict:
    action: str = ALLOW
    reasons: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    def raise_to(self, action: str, reason: str) -> None:
        if ACTIONS.index(action) > ACTIONS.index(self.action):
            self.action = action
        self.reasons.append(reason)


def _shingles(text: str) -> frozenset[int]:
    words = normalize(text).split()
    if len(words) < _SHINGLE:
        return frozenset()
    return frozenset(hash(tuple(words[i : i + _SHINGLE])) for i in range(len(words) - _SHINGLE + 1))


def _strings(value: Any, key: str = "") -> Iterator[tuple[str, str]]:
    """Yield ``(key, string)`` for every string nested anywhere in ``value``."""
    if isinstance(value, str):
        yield key, value
    elif isinstance(value, Mapping):
        for k, v in value.items():
            yield from _strings(v, str(k))
    elif isinstance(value, (list, tuple, set, frozenset)):
        for v in value:
            yield from _strings(v, key)
    elif value is not None:
        yield key, str(value)


def _host_allowed(host: str, allowed: tuple[str, ...]) -> bool:
    host = host.lower().rstrip(".")
    return any(host == d or host.endswith("." + d) for d in allowed)


def _path_allowed(path: str, roots: tuple[str, ...]) -> bool:
    if "\x00" in path:
        return False
    clean = posixpath.normpath(path.replace("\\", "/"))
    if not clean.startswith("/"):
        return False
    return any(clean == r or clean.startswith(r.rstrip("/") + "/") for r in roots)


class ToolGuard:
    """Check tool calls proposed by an LLM agent before executing them."""

    def __init__(
        self,
        rules: Mapping[str, ToolRule] | None = None,
        default: str = DENY,
        scanner: Scanner | None = None,
        canaries: tuple[str, ...] | list[str] = (),
    ) -> None:
        if default not in ACTIONS:
            raise ValueError(f"default must be one of {', '.join(ACTIONS)}")
        self.rules = dict(rules or {})
        self.default = default
        self.scanner = scanner or Scanner(canaries=canaries)
        self.calls: Counter[str] = Counter()
        self._sources: list[_Source] = []

    @property
    def compromised(self) -> bool:
        """True once the agent has read a tainted source that contained an attack."""
        return any(s.risky for s in self._sources)

    def taint(self, text: str, source: str = "untrusted") -> bool:
        """Register untrusted content the agent has read. Returns True if it looked malicious."""
        risky = self.scanner.scan_input(text).verdict in (REVIEW, BLOCK)
        self._sources.append(_Source(source, _shingles(text), risky))
        return risky

    def _tainted_by(self, text: str) -> list[_Source]:
        shingles = _shingles(text)
        if not shingles:
            return []
        return [s for s in self._sources if s.shingles & shingles]

    def check(self, tool: str, arguments: Mapping[str, Any] | None = None) -> Decision:
        """Decide whether ``tool(**arguments)`` may run: allow, confirm or deny."""
        verdict = _Verdict()
        rule = self.rules.get(tool)
        if rule is None:
            verdict.raise_to(self.default, f"no rule for tool {tool!r} (default: {self.default})")
            if self.default == DENY:
                return self._finish(tool, verdict)
            rule = ToolRule()
        if not rule.allow:
            verdict.raise_to(DENY, f"tool {tool!r} is disabled by policy")
            return self._finish(tool, verdict)

        self.calls[tool] += 1
        if rule.max_calls is not None and self.calls[tool] > rule.max_calls:
            verdict.raise_to(DENY, f"call budget exceeded ({rule.max_calls}) for {tool!r}")
        if rule.confirm:
            verdict.raise_to(CONFIRM, f"tool {tool!r} always requires confirmation")
        if rule.sink and self.compromised:
            names = ", ".join(s.name for s in self._sources if s.risky)
            verdict.raise_to(CONFIRM, f"agent previously read a source with injection signals ({names})")

        for key, value in _strings(arguments or {}):
            label = key or "argument"
            self._check_urls(label, value, rule, verdict)
            if rule.allowed_paths and _PATH_KEYS.search(key) and not _path_allowed(value, rule.allowed_paths):
                verdict.raise_to(DENY, f"{label}: path outside allowed roots")

            leak = self.scanner.scan_output(value)
            if leak.findings:
                verdict.findings.extend(leak.findings)
                if leak.verdict == BLOCK:
                    verdict.raise_to(DENY, f"{label}: carries sensitive data ({leak.findings[0].message})")
                elif leak.verdict == REVIEW:
                    verdict.raise_to(CONFIRM, f"{label}: may carry sensitive data")

            injected = self.scanner.scan_input(value)
            if injected.verdict in (REVIEW, BLOCK):
                verdict.findings.extend(injected.findings)
                verdict.raise_to(
                    DENY if injected.verdict == BLOCK and rule.sink else CONFIRM,
                    f"{label}: contains injection-like text ({injected.findings[0].message})",
                )

            for source in self._tainted_by(value):
                if source.risky:
                    verdict.raise_to(DENY, f"{label}: copies content from poisoned source {source.name!r}")
                elif rule.sink:
                    verdict.raise_to(CONFIRM, f"{label}: forwards untrusted content from {source.name!r}")
        return self._finish(tool, verdict)

    def _check_urls(self, label: str, value: str, rule: ToolRule, verdict: _Verdict) -> None:
        if not rule.allowed_domains:
            return
        for url in _URL.findall(value):
            host = urlsplit(url).hostname or ""
            if not _host_allowed(host, rule.allowed_domains):
                verdict.raise_to(DENY, f"{label}: egress to non-allowlisted host {host or url[:40]!r}")
                verdict.findings.append(Finding("tool_egress", Severity.HIGH, f"URL to {host} not in allowlist", url[:120]))

    @staticmethod
    def _finish(tool: str, verdict: _Verdict) -> Decision:
        unique = list(dict.fromkeys(verdict.findings))
        return Decision(tool, verdict.action, tuple(dict.fromkeys(verdict.reasons)), tuple(unique))
