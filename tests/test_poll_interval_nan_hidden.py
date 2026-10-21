"""poll_interval_seconds must reject NaN (and keep rejecting infinities)."""

from __future__ import annotations

import json

import pytest

from reviewer.config import ConfigError, ReviewerConfig, load_config


def test_nan_via_mapping_is_rejected() -> None:
    with pytest.raises(ConfigError, match="poll_interval_seconds"):
        ReviewerConfig.from_mapping({"poll_interval_seconds": float("nan")})


def test_nan_via_alias_key_is_rejected() -> None:
    with pytest.raises(ConfigError, match="poll_interval_seconds"):
        ReviewerConfig.from_mapping({"poll_interval": float("nan")})


def test_nan_string_is_rejected() -> None:
    with pytest.raises(ConfigError, match="poll_interval_seconds"):
        ReviewerConfig.from_mapping({"poll_interval_seconds": "nan"})


def test_nan_direct_construction_is_rejected() -> None:
    with pytest.raises(ConfigError, match="poll_interval_seconds"):
        ReviewerConfig(poll_interval_seconds=float("nan"))


def test_nan_literal_in_json_file_is_rejected_by_from_file_and_load_config(
    tmp_path,
) -> None:
    path = tmp_path / "config.json"
    path.write_text('{"poll_interval_seconds": NaN}', encoding="utf-8")
    with pytest.raises(ConfigError, match="poll_interval_seconds"):
        ReviewerConfig.from_file(path)
    with pytest.raises(ConfigError, match="poll_interval_seconds"):
        load_config(path)


@pytest.mark.parametrize("value", [float("inf"), float("-inf")])
def test_infinities_are_still_rejected(value: float) -> None:
    with pytest.raises(ConfigError, match="poll_interval_seconds"):
        ReviewerConfig.from_mapping({"poll_interval_seconds": value})


@pytest.mark.parametrize("value", [5, 60, 86400])
def test_valid_values_still_load(value: int, tmp_path) -> None:
    assert ReviewerConfig.from_mapping({
        "poll_interval_seconds": value
    }).poll_interval_seconds == float(value)
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"poll_interval_seconds": value}), encoding="utf-8")
    assert ReviewerConfig.from_file(path).poll_interval_seconds == float(value)
    assert load_config(path).poll_interval_seconds == float(value)


@pytest.mark.parametrize("value", [4.9, 86400.1, 0, -1])
def test_out_of_range_values_still_rejected(value: float) -> None:
    with pytest.raises(ConfigError, match="poll_interval_seconds"):
        ReviewerConfig.from_mapping({"poll_interval_seconds": value})
