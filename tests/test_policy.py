import json

import pytest

from promptshield.finding import Severity
from promptshield.policy import Policy, PolicyError


def test_defaults():
    policy = Policy()
    assert (policy.review_threshold, policy.block_threshold) == (25, 50)
    assert policy.min_severity is Severity.LOW


def test_from_dict():
    policy = Policy.from_dict({"block_threshold": 75, "disabled": ["pii_leak"], "min_severity": "medium"})
    assert policy.block_threshold == 75
    assert "pii_leak" in policy.disabled
    assert policy.min_severity is Severity.MEDIUM


@pytest.mark.parametrize(
    "data",
    [{"block_threshold": 101}, {"review_threshold": 80, "block_threshold": 50}, {"nonsense": 1}, {"min_severity": "huge"}],
)
def test_invalid_policies(data):
    with pytest.raises(PolicyError):
        Policy.from_dict(data)


def test_toml_file_with_section(tmp_path):
    path = tmp_path / "policy.toml"
    path.write_text('[promptshield]\nblock_threshold = 60\nallowed_domains = ["example.com"]\n')
    policy = Policy.from_file(path)
    assert policy.block_threshold == 60
    assert policy.allowed_domains == ("example.com",)


def test_json_file_with_detector_options(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({"detectors": {"invisible_text": {"zero_width_threshold": 10}}}))
    assert Policy.from_file(path).detector_options["invisible_text"]["zero_width_threshold"] == 10


def test_unsupported_extension(tmp_path):
    path = tmp_path / "policy.yaml"
    path.write_text("a: 1")
    with pytest.raises(PolicyError):
        Policy.from_file(path)
