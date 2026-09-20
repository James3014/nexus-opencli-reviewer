from __future__ import annotations

import json
import os
from pathlib import Path
import pytest

from reviewer.hosted_risk_config import (
    HostedPreflightStatus,
    HostedProviderConfigV1,
    HostedProviderPreflightV1,
    load_hosted_provider_config_from_dict,
    load_hosted_provider_config_from_root,
    run_hosted_provider_zero_call_preflight,
)


def _valid_data() -> dict[str, object]:
    return {
        "endpoint_origin": "https://provider.example.invalid",
        "api_key_env_var_name": "SYNTHETIC_PROVIDER_API_KEY",
        "max_canary_quota": 3,
        "allowed_hosts_whitelist": ["provider.example.invalid"],
    }


def test_valid_config_loading() -> None:
    data = _valid_data()
    cfg = load_hosted_provider_config_from_dict(data)

    assert cfg.endpoint_origin == "https://provider.example.invalid"
    assert cfg.api_key_env_var_name == "SYNTHETIC_PROVIDER_API_KEY"
    assert cfg.max_canary_quota == 3
    assert cfg.allowed_hosts_whitelist == ("provider.example.invalid",)
    assert len(cfg.canonical_config_hash()) == 64


@pytest.mark.parametrize(
    "missing_key",
    [
        "endpoint_origin",
        "api_key_env_var_name",
        "max_canary_quota",
        "allowed_hosts_whitelist",
    ],
)
def test_missing_required_fields_rejected(missing_key: str) -> None:
    data = _valid_data()
    del data[missing_key]

    with pytest.raises(ValueError, match="missing required fields"):
        load_hosted_provider_config_from_dict(data)


def test_unknown_field_rejected() -> None:
    data = _valid_data()
    data["extra_unknown_field"] = "malicious_or_unexpected"

    with pytest.raises(ValueError, match="unknown fields forbidden"):
        load_hosted_provider_config_from_dict(data)


@pytest.mark.parametrize(
    "bad_origin",
    [
        "http://provider.example.invalid",
        "ftp://provider.example.invalid",
        "file:///path/to/file",
        "unix:///var/run/sock",
        "https://user:pass@provider.example.invalid",
        "https://provider.example.invalid/api/v1",
        "https://provider.example.invalid?query=param",
        "https://provider.example.invalid#frag",
    ],
)
def test_invalid_endpoint_origin_rejected(bad_origin: str) -> None:
    data = _valid_data()
    data["endpoint_origin"] = bad_origin

    with pytest.raises(ValueError):
        load_hosted_provider_config_from_dict(data)


def test_host_not_in_whitelist_rejected() -> None:
    data = _valid_data()
    data["endpoint_origin"] = "https://unauthorized.example.invalid"
    data["allowed_hosts_whitelist"] = ["provider.example.invalid"]

    with pytest.raises(ValueError, match="not in allowed_hosts_whitelist"):
        load_hosted_provider_config_from_dict(data)


@pytest.mark.parametrize(
    "suffix_attack",
    [
        "provider.example.invalid.evil.com",
        "evilprovider.example.invalid",
        "sub.provider.example.invalid",
    ],
)
def test_suffix_confusion_host_rejected(suffix_attack: str) -> None:
    data = _valid_data()
    data["endpoint_origin"] = f"https://{suffix_attack}"
    data["allowed_hosts_whitelist"] = ["provider.example.invalid"]

    with pytest.raises(ValueError, match="not in allowed_hosts_whitelist"):
        load_hosted_provider_config_from_dict(data)


@pytest.mark.parametrize(
    "wildcard_entry",
    [
        "*.example.invalid",
        ".example.invalid",
        "provider.example.invalid/*",
        "provider.example.invalid:443",
    ],
)
def test_wildcard_or_malformed_whitelist_rejected(wildcard_entry: str) -> None:
    data = _valid_data()
    data["allowed_hosts_whitelist"] = [wildcard_entry]

    with pytest.raises(ValueError):
        load_hosted_provider_config_from_dict(data)


def test_duplicate_whitelist_values_rejected() -> None:
    data = _valid_data()
    data["allowed_hosts_whitelist"] = ["provider.example.invalid", "provider.example.invalid"]

    with pytest.raises(ValueError, match="duplicate entries"):
        load_hosted_provider_config_from_dict(data)


@pytest.mark.parametrize(
    "bad_env_name",
    [
        "lowercase_env",
        "ENV-WITH-DASH",
        "ENV WITH SPACE",
        "ENV=VALUE",
        "ENV;rm -rf",
        "${INJECTION}",
        "1_STARTS_WITH_NUMBER",
    ],
)
def test_invalid_api_key_env_var_name_rejected(bad_env_name: str) -> None:
    data = _valid_data()
    data["api_key_env_var_name"] = bad_env_name

    with pytest.raises(ValueError):
        load_hosted_provider_config_from_dict(data)


@pytest.mark.parametrize("bad_quota", [True, False, 0, -1, -5, "10", 1.5])
def test_invalid_max_canary_quota_rejected(bad_quota: object) -> None:
    data = _valid_data()
    data["max_canary_quota"] = bad_quota

    with pytest.raises(ValueError):
        load_hosted_provider_config_from_dict(data)


def test_deterministic_config_hash() -> None:
    data1 = _valid_data()
    data2 = _valid_data()

    cfg1 = load_hosted_provider_config_from_dict(data1)
    cfg2 = load_hosted_provider_config_from_dict(data2)

    assert cfg1.canonical_config_hash() == cfg2.canonical_config_hash()

    # Mutation test: changing any field changes hash
    data_mutated = _valid_data()
    data_mutated["max_canary_quota"] = 99
    cfg_mutated = load_hosted_provider_config_from_dict(data_mutated)

    assert cfg1.canonical_config_hash() != cfg_mutated.canonical_config_hash()


def test_secret_value_isolation_in_preflight(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    synthetic_secret = "super-secret-test-value-12345"
    monkeypatch.setenv("SYNTHETIC_PROVIDER_API_KEY", synthetic_secret)

    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps(_valid_data()), encoding="utf-8")

    preflight = run_hosted_provider_zero_call_preflight(tmp_path)

    assert preflight.status is HostedPreflightStatus.VALID
    assert preflight.credential_name_present is True
    assert preflight.config_hash is not None

    # Verify synthetic secret never appears in preflight result or hash
    preflight_repr = repr(preflight)
    assert synthetic_secret not in preflight_repr
    assert synthetic_secret not in preflight.config_hash


def test_filesystem_missing_config_returns_config_unavailable(tmp_path: Path) -> None:
    # Empty directory without config.json
    preflight = run_hosted_provider_zero_call_preflight(tmp_path)

    assert preflight.status is HostedPreflightStatus.CONFIG_UNAVAILABLE
    assert preflight.config_hash is None
    assert "not found" in (preflight.error_message or "")


def test_filesystem_invalid_json_returns_config_invalid(tmp_path: Path) -> None:
    config_file = tmp_path / "config.json"
    config_file.write_text("malformed-not-json", encoding="utf-8")

    preflight = run_hosted_provider_zero_call_preflight(tmp_path)

    assert preflight.status is HostedPreflightStatus.CONFIG_INVALID
    assert preflight.config_hash is None
    assert "not valid JSON" in (preflight.error_message or "")


def test_symlink_escape_rejected(tmp_path: Path) -> None:
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    secret_file = outside_dir / "secret_config.json"
    secret_file.write_text(json.dumps(_valid_data()), encoding="utf-8")

    eval_root = tmp_path / "eval_root"
    eval_root.mkdir()
    symlink_file = eval_root / "config.json"
    symlink_file.symlink_to(secret_file)

    preflight = run_hosted_provider_zero_call_preflight(eval_root)

    assert preflight.status is HostedPreflightStatus.CONFIG_INVALID
    assert "symlink pointing outside" in (preflight.error_message or "")


def test_code_in_data_attack_rejected(tmp_path: Path) -> None:
    canary_marker = tmp_path / "pwned_marker.txt"
    malicious_data = _valid_data()
    malicious_data["plugin"] = f"__import__('os').system('touch {canary_marker}')"

    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps(malicious_data), encoding="utf-8")

    preflight = run_hosted_provider_zero_call_preflight(tmp_path)

    assert preflight.status is HostedPreflightStatus.CONFIG_INVALID
    assert not canary_marker.exists()
