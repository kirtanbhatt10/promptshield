"""Attempts to make the model disclose its hidden system prompt."""

from ..detector import PatternDetector, register
from ..finding import Severity


@register
class SystemPromptExtraction(PatternDetector):
    name = "system_prompt_extraction"
    description = "Requests to reveal, repeat or summarise the hidden system prompt."
    patterns = (
        (
            r"\b(reveal|show|print|display|output|repeat|leak|dump|share|tell me|give me|what is|what are)\b[^.\n]{0,30}?"
            r"\b(your|the)\s+(system|initial|hidden|original|developer|secret|pre-?prompt)\s+"
            r"(prompt|instructions?|message|rules|configuration)\b",
            Severity.HIGH,
            "Asks for the system prompt",
        ),
        (
            r"\brepeat\s+(the|all|everything|the\s+text|the\s+words)\b[^.\n]{0,30}?\b(above|before\s+this|verbatim|word\s+for\s+word)\b",
            Severity.HIGH,
            "Asks the model to repeat its preceding context verbatim",
        ),
        (
            r"\b(what|which)\s+(were|are)\s+you\s+(told|instructed|programmed|configured)\s+(to\s+do|before|initially)\b",
            Severity.MEDIUM,
            "Probes for the model's original instructions",
        ),
    )
