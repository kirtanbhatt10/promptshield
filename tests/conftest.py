import pytest

from promptshield import Scanner
from promptshield.normalize import normalize


@pytest.fixture
def scanner():
    return Scanner()


@pytest.fixture
def run():
    """Run a single detector on text and return its findings."""

    def _run(detector, text):
        return detector.scan(text, normalize(text))

    return _run
