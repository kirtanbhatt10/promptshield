# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

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
