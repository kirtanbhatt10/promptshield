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

