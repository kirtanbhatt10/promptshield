import re

import pytest

from promptshield.canary import embed, make_canary
from promptshield.detectors.canary_leak import CanaryLeak

CANARY = "PS-1a2b3c4d5e6f7a8b"


def test_make_canary_format():
    assert re.fullmatch(r"PS-[0-9a-f]{16}", make_canary())
    assert make_canary("Acme").startswith("Acme-")


def test_make_canary_is_unique():
    assert make_canary() != make_canary()


@pytest.mark.parametrize("prefix", ["", "1bad", "has space", "x" * 17])
def test_make_canary_rejects_bad_prefix(prefix):
    with pytest.raises(ValueError):
        make_canary(prefix)


def test_embed_appends_canary():
    prompt = embed("You are a helpful bot.", CANARY)
    assert prompt.startswith("You are a helpful bot.")
    assert CANARY in prompt


def test_verbatim_leak(run):
    assert run(CanaryLeak(canaries=[CANARY]), f"My secret line is {CANARY}")


def test_obfuscated_leak(run):
    spaced = " ".join(CANARY.upper())
    assert "obfuscated" in run(CanaryLeak(canaries=[CANARY]), spaced)[0].message


def test_no_canaries_no_findings(run):
    assert not run(CanaryLeak(), CANARY)
