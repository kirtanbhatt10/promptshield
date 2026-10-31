# Contributing

Thanks for helping make LLM apps safer.

## Setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest -q
ruff check . && ruff format --check .
```

## Adding a detector

1. Create `src/promptshield/detectors/<name>.py`. Subclass `PatternDetector` for
   regex rules or `Detector` for custom logic, and decorate it with `@register`.
   Modules in that package are discovered automatically.
2. Set `name`, `kind` (`input`, `output` or `both`) and a one-line `description`.
3. Add `tests/test_<name>.py` with **both** attack samples and benign look-alikes.
   False positives matter as much as detections.
4. Mention it in the detector table in `README.md` and in `CHANGELOG.md`.

## Ground rules

- Keep the core dependency-free.
- Test samples must be harmless: they demonstrate the *shape* of an attack, never
  real credentials or working malware.
