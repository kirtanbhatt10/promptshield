from promptshield.redact import redact


def test_redacts_middle():
    assert redact("sk-abcdefghijklmnop") == "sk-a…op"


def test_short_values_fully_masked():
    assert redact("abc") == "***"


def test_custom_keep():
    assert redact("234567890124", 0, 4) == "…0124"
