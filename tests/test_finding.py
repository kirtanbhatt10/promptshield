import pytest

from promptshield.finding import Finding, Severity


def test_severity_ordering():
    assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW > Severity.INFO


@pytest.mark.parametrize("value", ["high", "HIGH", " High ", 3, Severity.HIGH])
def test_severity_parse(value):
    assert Severity.parse(value) is Severity.HIGH


def test_severity_parse_rejects_unknown():
    with pytest.raises(ValueError):
        Severity.parse("urgent")


def test_finding_to_dict_uses_lowercase_severity():
    data = Finding("x", Severity.MEDIUM, "msg", "ev").to_dict()
    assert data == {"detector": "x", "severity": "medium", "message": "msg", "evidence": "ev"}
