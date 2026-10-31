"""Helpers for showing evidence without re-leaking it."""


def redact(value: str, keep_start: int = 4, keep_end: int = 2) -> str:
    """Mask the middle of a sensitive value: ``sk-abcdef123456`` -> ``sk-a…56``."""
    if len(value) <= keep_start + keep_end + 2:
        return "*" * len(value)
    return f"{value[:keep_start]}…{value[-keep_end:]}"
