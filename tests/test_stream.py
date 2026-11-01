import pytest

from promptshield import Scanner, StreamGuard

KEY = "sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz012345"


def chunks(text, size):
    return [text[i : i + size] for i in range(0, len(text), size)]


def test_clean_stream_passes_through_unchanged():
    text = "The capital of Gujarat is Gandhinagar. " * 20
    guard = StreamGuard()
    out = "".join(guard.wrap(chunks(text, 7)))
    assert out == text
    assert not guard.blocked


def test_secret_split_across_chunks_is_never_emitted():
    text = "Sure, here is the key you asked for: " + KEY + " and that is all."
    guard = StreamGuard()
    out = "".join(guard.wrap(chunks(text, 5)))
    assert guard.blocked
    assert "sk-ant" not in out
    assert out.endswith("[response withheld by promptshield]")


def test_canary_leak_halts_stream():
    canary = "PS-9f2c1a7be04d3361"
    guard = StreamGuard(Scanner(canaries=[canary]))
    pieces = [guard.feed(c) for c in chunks(f"My instructions mention {canary} somewhere.", 3)]
    assert guard.blocked
    assert canary not in "".join(pieces)
    assert guard.feed("more text") == ""
    assert guard.close() == ""


def test_holdback_releases_on_close():
    guard = StreamGuard(holdback=50)
    assert guard.feed("short") == ""
    assert guard.close() == "short"
    assert guard.close() == ""


def test_feed_after_close_raises():
    guard = StreamGuard()
    guard.close()
    with pytest.raises(RuntimeError):
        guard.feed("x")


def test_findings_are_not_double_counted_across_overlap():
    guard = StreamGuard(holdback=10, overlap=200)
    for piece in chunks("Write to ravi.k@example.com for details. " + "Lorem ipsum dolor. " * 10, 4):
        guard.feed(piece)
    guard.close()
    emails = [f for f in guard.result.findings if f.message == "Email address in output"]
    assert len(emails) == 1
    assert not guard.blocked


def test_invalid_configuration():
    with pytest.raises(ValueError):
        StreamGuard(holdback=100, overlap=10)


def test_long_token_without_spaces_is_never_partly_released():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0." + "a" * 300
    guard = StreamGuard(holdback=0, overlap=0)
    released = "".join(guard.feed(c) for c in chunks("token: " + jwt, 9))
    assert "eyJ" not in released  # unfinished token is held, not leaked
    assert guard.close() == "\n[response withheld by promptshield]"
    assert guard.blocked


def test_character_by_character_stream():
    text = "Here you go: AKIAIOSFODNN7EXAMPLE done"
    guard = StreamGuard()
    out = "".join(guard.wrap(list(text)))
    assert guard.blocked and "AKIA" not in out
