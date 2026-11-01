"""Attempts to cancel or replace the instructions an LLM was given."""

from ..detector import PatternDetector, register
from ..finding import Severity


@register
class InstructionOverride(PatternDetector):
    name = "instruction_override"
    description = "Text that tells the model to ignore or replace its earlier instructions."
    patterns = (
        (
            r"\b(ignore|disregard|forget|override|bypass|skip)\b[^.\n]{0,40}?\b(previous|prior|above|earlier|preceding|initial|original|all)\b"
            r"[^.\n]{0,25}?\b(instructions?|prompts?|rules?|directions?|guidelines?|directives?|context)\b",
            Severity.HIGH,
            "Tries to override earlier instructions",
        ),
        (
            r"\b(ignore|disregard|forget)\s+(all\s+|everything\s+)?(of\s+)?(the\s+|that\s+)?(above|previous|prior|preceding)\b"
            r"[^.\n]{0,10}?\b(and|then|now|instead)\s+(tell|give|show|print|reveal|output|say|write|do|act|respond|list|send)\b",
            Severity.HIGH,
            "Tells the model to drop the preceding context and do something else",
        ),
        (
            r"\b(do not|don't|never|stop)\s+(follow|obey|listen to|following|obeying)\s+(your|the|any)\s+"
            r"(rules|instructions|guidelines|system prompt|developers?)\b",
            Severity.HIGH,
            "Tells the model to stop following its rules",
        ),
        (
            r"\b(new|updated|real|actual|revised)\s+(instructions?|rules|system prompt|directives?)\s*(:|are\b|is\b|follow\b)",
            Severity.MEDIUM,
            "Introduces replacement instructions",
        ),
        (
            r"\bfrom now on\b[^.\n]{0,60}?\b(you will|you must|you are|always|never|only)\b",
            Severity.MEDIUM,
            "Redefines behaviour for the rest of the conversation",
        ),
    )
