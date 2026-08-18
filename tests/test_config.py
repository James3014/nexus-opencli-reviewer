import json

import pytest

from reviewer.config import BootstrapPolicy, ConfigError, ReviewerConfig, load_config, save_config


def test_safe_defaults_are_single_repo_serial_and_advisory():
    config = ReviewerConfig()
    assert config.repositories == ("James3014/Nexus-new",)
    assert config.semantic_concurrency == 1
    assert config.publication_enabled is True
    assert config.bootstrap == BootstrapPolicy("new_only", 0)
    assert config.opencli_executable == "opencli"


def test_explicit_opencli_executable_is_preserved():
    config = ReviewerConfig.from_mapping({"opencli_executable": "/custom/bin/opencli"})
    assert config.opencli_executable == "/custom/bin/opencli"


def test_mapping_accepts_operator_friendly_aliases(tmp_path):
    config = ReviewerConfig.from_mapping(
        {
            "repos": ["James3014/Nexus-new"],
            "poll_interval": 30,
            "publication": {"enabled": False},
            "concurrency": 1,
            "bootstrap": {"mode": "bounded", "max_reviews": 2},
            "state_root": str(tmp_path / "state"),
            "log_path": str(tmp_path / "reviewer.log"),
        }
    )
    assert config.poll_interval_seconds == 30
    assert config.publication_enabled is False
    assert config.bootstrap.to_dict() == {"mode": "bounded", "max_reviews": 2}


def test_round_trip_is_inspectable_and_private(tmp_path):
    path = tmp_path / "config.json"
    original = ReviewerConfig(state_root=tmp_path / "state", log_path=tmp_path / "reviewer.log")
    assert save_config(original, path) == path
    assert json.loads(path.read_text()) == original.to_dict()
    assert load_config(path) == original
    assert oct(path.stat().st_mode & 0o777) == "0o600"


@pytest.mark.parametrize(
    "field,value",
    [
        ("repositories", []),
        ("repositories", ["not-a-repository"]),
        ("poll_interval_seconds", 1),
        ("poll_interval_seconds", 90000),
        ("semantic_concurrency", 2),
        ("state_root", "relative-state"),
    ],
)
def test_unsafe_values_fail_closed(field, value):
    with pytest.raises(ConfigError):
        ReviewerConfig(**{field: value})


def test_bootstrap_new_only_cannot_review_historical_backlog():
    with pytest.raises(ConfigError):
        BootstrapPolicy("new_only", 1)


def test_missing_file_returns_defaults(tmp_path):
    config = load_config(tmp_path / "missing.json")
    assert config == ReviewerConfig()
