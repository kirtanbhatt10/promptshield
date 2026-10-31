from promptshield.detectors.pii_leak import PiiLeak


def _messages(findings):
    return {f.message for f in findings}


def test_aadhaar_with_valid_checksum(run):
    assert "Aadhaar number in output" in _messages(run(PiiLeak(), "Aadhaar: 2345 6789 0124"))


def test_aadhaar_invalid_checksum_ignored(run):
    assert "Aadhaar number in output" not in _messages(run(PiiLeak(), "ID 2345 6789 0123"))


def test_pan(run):
    assert "PAN number in output" in _messages(run(PiiLeak(), "PAN ABCPE1234F"))


def test_indian_mobile(run):
    assert "Indian mobile number in output" in _messages(run(PiiLeak(), "call +91 98765 43210"))


def test_card_number_luhn(run):
    assert "Payment card number in output" in _messages(run(PiiLeak(), "card 4111 1111 1111 1111"))


def test_email_toggle(run):
    assert run(PiiLeak(), "mail me at kirtan@example.com")
    assert not run(PiiLeak(include_email=False), "mail me at kirtan@example.com")


def test_evidence_redacted(run):
    finding = next(f for f in run(PiiLeak(), "2345 6789 0124") if "Aadhaar" in f.message)
    assert finding.evidence == "…0124"
