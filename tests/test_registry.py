import pytest

from promptshield.detector import Detector, PatternDetector, register, registry
from promptshield.finding import Severity

EXPECTED = {
    "canary_leak",
    "delimiter_injection",
    "encoded_payload",
    "instruction_override",
    "invisible_text",
    "jailbreak_persona",
    "markdown_exfil",
    "pii_leak",
    "role_hijack",
    "secret_leak",
    "system_prompt_extraction",
    "tool_abuse",
}


def test_all_builtin_detectors_registered():
    assert set(registry()) >= EXPECTED


def test_every_detector_has_description_and_kind():
    for cls in registry().values():
        assert cls.description
        assert cls.kind in {"input", "output", "both"}


def test_duplicate_names_rejected():
    class Dupe(Detector):
        name = "instruction_override"

        def scan(self, text, normalized):
            return []

    with pytest.raises(ValueError):
        register(Dupe)


def test_pattern_detector_reports_evidence():
    class Demo(PatternDetector):
        name = "demo_pattern"
        patterns = ((r"secret word", Severity.LOW, "found it"),)

    findings = Demo().scan("The Secret Word", "the secret word")
    assert findings[0].evidence == "secret word"
