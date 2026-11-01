# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-11-01

### Added

- `ToolGuard`: a firewall for agent tool calls with allow / confirm / deny rules,
  call budgets, egress allowlists, path jails, exfiltration and injection checks
  on every nested argument, and taint tracking of untrusted content.
- `StreamGuard`: incremental scanning of streamed model output that never
  releases an unscanned or partly received token and halts on `block`.
- `Session`: multi-turn defence that reassembles split payloads, scores
  escalation with a decaying running risk and locks after repeated blocks.
- `Spotlight`: per-instance unforgeable boundaries for untrusted content with
  delimit, datamark and base64 modes, plus matching system-prompt text.
- `boundary_escape` detector for fake closing tags and end-of-document markers.
- `scrub()`: redact secrets, checksum-valid PII, canaries, tracking images and
  invisible characters while keeping the rest of a reply.
- `promptshield serve`: zero-dependency HTTP sidecar with bearer auth, body
  limits and JSON logs; Dockerfile running as an unprivileged user.
- `promptshield bench`: precision, recall, F1 and latency on a labelled JSONL
  corpus (built-in smoke corpus included) with a `--min-f1` CI gate.
- SARIF 2.1.0 output (`--format sarif`) for GitHub code scanning.
- `promptshield scrub` and `promptshield spotlight` commands.
- `Scanner.decide()` to score any combination of findings.
- Release workflow: GitHub release with wheel and sdist, GHCR image, optional PyPI.

### Fixed

- Missed "disregard the above and tell me…", "what were your initial
  instructions" and "you are no longer a helpful assistant…" phrasings.

## [0.1.0] - 2026-10-31

### Added

- Input detectors: instruction override, role hijack, system-prompt extraction,
  delimiter injection, jailbreak personas, tool abuse / indirect injection,
  invisible text (Unicode tag smuggling, bidi, zero-width) and encoded payloads.
- Output detectors: canary leaks, secret leaks, PII leaks (Aadhaar with Verhoeff
  check, PAN, Indian mobile numbers, Luhn-validated cards, email) and Markdown
  exfiltration.
- Text normalization against full-width, homoglyph, zero-width and leetspeak obfuscation.
- Risk scoring with allow / review / block verdicts and TOML/JSON policies.
- Canary token helpers.
- CLI with text, JSON and HTML reports and CI-friendly exit codes.
- ASGI middleware for FastAPI and Starlette.
