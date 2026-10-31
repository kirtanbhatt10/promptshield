"""Fake chat-template tokens and role headers smuggled into user content."""

import re

from ..detector import PatternDetector, register
from ..finding import Severity


@register
class DelimiterInjection(PatternDetector):
    name = "delimiter_injection"
    description = "Chat-template control tokens or fake system/assistant headers inside user text."
    use_raw = True
    flags = re.IGNORECASE | re.MULTILINE
    patterns = (
        (
            r"<\|(im_start|im_end|system|user|assistant|endoftext|eot_id|start_header_id|end_header_id)\|>",
            Severity.CRITICAL,
            "Contains a chat-template control token",
        ),
        (
            r"\[/?INST\]|<<\s*/?SYS\s*>>",
            Severity.HIGH,
            "Contains Llama-style instruction delimiters",
        ),
        (
            r"^\s*(#{1,6}\s*|\*\*)?(system|assistant|developer)(\s+(prompt|message))?\s*(\*\*)?\s*:\s*\S",
            Severity.HIGH,
            "Starts a line with a fake system/assistant header",
        ),
        (
            r"</?\s*(system|system_prompt|instructions|admin|developer)\s*>",
            Severity.MEDIUM,
            "Contains pseudo-XML role tags",
        ),
    )
