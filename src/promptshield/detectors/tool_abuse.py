"""Indirect-injection payloads that try to drive an agent's tools."""

from ..detector import PatternDetector, register
from ..finding import Severity


@register
class ToolAbuse(PatternDetector):
    name = "tool_abuse"
    description = "Text that tries to make an agent run tools, send data or execute commands without the user."
    patterns = (
        (
            r"\b(call|invoke|use|run|execute|trigger)\b[^.\n]{0,30}?\b(tool|function|plugin|action|command)\b[^.\n]{0,40}?"
            r"\b(without|don't|do not|never)\b[^.\n]{0,20}?\b(ask|asking|confirm|confirmation|tell|telling|notify|informing)\b",
            Severity.HIGH,
            "Asks the agent to act without user confirmation",
        ),
        (
            r"\b(send|forward|email|post|upload|exfiltrate|transmit)\b[^.\n]{0,40}?"
            r"\b(conversation|chat history|messages|api keys?|credentials|passwords?|secrets?|tokens?|cookies|env(ironment)? variables)\b"
            r"[^.\n]{0,40}?\bto\b",
            Severity.HIGH,
            "Asks the agent to send sensitive data somewhere",
        ),
        (
            r"(rm\s+-rf\s+[/~]|curl\s[^|\n]*\|\s*(sh|bash)\b|wget\s[^|\n]*\|\s*(sh|bash)\b|powershell\s+-enc)",
            Severity.HIGH,
            "Contains a destructive or download-and-execute shell command",
        ),
        (
            r"\b(when|if)\s+(you|the (assistant|agent|ai))\s+(read|see|process|summari[sz]e)s?\s+this\b",
            Severity.MEDIUM,
            "Addresses the AI that will later read this content (indirect injection)",
        ),
    )
