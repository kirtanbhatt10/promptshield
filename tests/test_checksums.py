import pytest

from promptshield.checksums import luhn_valid, verhoeff_valid


def test_verhoeff_valid_number():
    assert verhoeff_valid("234567890124")


@pytest.mark.parametrize("number", ["234567890123", "12ab", ""])
def test_verhoeff_rejects(number):
    assert not verhoeff_valid(number)


def test_luhn_known_test_card():
    assert luhn_valid("4111111111111111")


@pytest.mark.parametrize("number", ["4111111111111112", "1234", "abcd"])
def test_luhn_rejects(number):
    assert not luhn_valid(number)
