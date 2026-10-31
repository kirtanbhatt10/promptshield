import pytest

from promptshield.detectors.secret_leak import SecretLeak

SAMPLES = {
    "AWS access key ID": "AKIAIOSFODNN7EXAMPLE",
    "GitHub token": "ghp_" + "a" * 36,
    "Anthropic API key": "sk-ant-api03-" + "b" * 30,
    "OpenAI API key": "sk-proj-" + "c" * 30,
    "Google API key": "AIza" + "d" * 35,
    "Private key block": "-----BEGIN RSA PRIVATE KEY-----",
    "JSON Web Token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
}


@pytest.mark.parametrize("label,secret", SAMPLES.items())
def test_detects_secret(run, label, secret):
    findings = run(SecretLeak(), f"here you go: {secret}")
    assert findings[0].message == f"{label} in output"


def test_evidence_is_redacted(run):
    finding = run(SecretLeak(), "AKIAIOSFODNN7EXAMPLE")[0]
    assert "IOSFODNN7" not in finding.evidence


def test_anthropic_key_reported_once(run):
    assert len(run(SecretLeak(), "sk-ant-api03-" + "b" * 30)) == 1


def test_clean_text(run):
    assert not run(SecretLeak(), "The answer is 42.")
