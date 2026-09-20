from __future__ import annotations

import json
import pytest

from reviewer.hosted_risk_config import HostedProviderConfigV1
from reviewer.hosted_wire_contract import (
    HostedAuthMode,
    HostedCanaryDryRun,
    HostedProviderWireDescriptorV1,
    LiveCanaryAuthorizationV1,
    assemble_hosted_canary_dry_run,
    load_wire_descriptor_from_dict,
)
from reviewer.risk_model_adapter import (
    F4QuestionContractV1,
    ProviderVisibleRiskStateV1,
)


def _valid_config() -> HostedProviderConfigV1:
    return HostedProviderConfigV1(
        endpoint_origin="https://provider.example.invalid",
        api_key_env_var_name="SYNTHETIC_API_KEY",
        max_canary_quota=1,
        allowed_hosts_whitelist=("provider.example.invalid",),
    )


def _valid_wire_data() -> dict[str, object]:
    return {
        "contract_schema_version": "f4-hosted-wire-v1",
        "http_method": "POST",
        "request_path": "/v1/decision",
        "auth_mode": "BEARER",
        "auth_header_name": "Authorization",
        "content_type": "application/json",
        "expected_model_identifier": "test-model-v1",
        "request_template_kind": "systemone_choice",
        "response_probability_path": "answers.decision.probabilities.ESCALATE",
        "api_version_source": "HEADER_OR_PAYLOAD",
        "provider_schema_identity": "test-provider-v1",
    }


def _state() -> ProviderVisibleRiskStateV1:
    return ProviderVisibleRiskStateV1(
        action_type="TASK_RUN",
        mutation_domain="REPOSITORY",
        permission_profile="MUTATE_BOUNDED",
        is_mutation=True,
        allowed_path_extensions=(".py",),
        allowed_path_count=1,
    )


def test_valid_wire_descriptor_parsing() -> None:
    data = _valid_wire_data()
    wire = load_wire_descriptor_from_dict(data)

    assert wire.http_method == "POST"
    assert wire.request_path == "/v1/decision"
    assert wire.auth_mode == HostedAuthMode.BEARER
    assert wire.auth_header_name == "Authorization"
    assert len(wire.canonical_wire_hash()) == 64


def test_unknown_key_in_wire_descriptor_rejected() -> None:
    data = _valid_wire_data()
    data["unknown_key"] = "forbidden"

    with pytest.raises(ValueError, match="unknown keys forbidden"):
        load_wire_descriptor_from_dict(data)


@pytest.mark.parametrize(
    "bad_path",
    [
        "relative_no_slash",
        "//evil.com/path",
        "http://evil.com/path",
        "https://evil.com/path",
        "/v1/../traversal",
        "/v1/path?query=1",
        "/v1/path#frag",
        "/v1/path\r\nInjection: 1",
    ],
)
def test_invalid_or_injected_request_path_rejected(bad_path: str) -> None:
    data = _valid_wire_data()
    data["request_path"] = bad_path

    with pytest.raises(ValueError):
        load_wire_descriptor_from_dict(data)


@pytest.mark.parametrize(
    "bad_header",
    [
        "Auth Header With Space",
        "Header\r\nInjected: evil",
        "Header:Value",
    ],
)
def test_invalid_header_name_rejected(bad_header: str) -> None:
    data = _valid_wire_data()
    data["auth_header_name"] = bad_header

    with pytest.raises(ValueError):
        load_wire_descriptor_from_dict(data)


def test_authorization_requires_exact_hash_bindings() -> None:
    cfg = _valid_config()
    wire = load_wire_descriptor_from_dict(_valid_wire_data())
    contract = F4QuestionContractV1()

    auth = LiveCanaryAuthorizationV1(
        config_hash=cfg.canonical_config_hash(),
        wire_contract_hash=wire.canonical_wire_hash(),
        endpoint_host="provider.example.invalid",
        question_contract_hash=contract.contract_hash,
        max_calls=1,
    )

    dry_run = assemble_hosted_canary_dry_run(
        cfg, wire, auth, _state(), contract, "req-dry-1"
    )
    assert dry_run.target_origin == "https://provider.example.invalid"
    assert dry_run.target_path == "/v1/decision"
    assert dry_run.config_hash == cfg.canonical_config_hash()
    assert dry_run.wire_contract_hash == wire.canonical_wire_hash()


def test_authorization_hash_mismatch_rejected() -> None:
    cfg = _valid_config()
    wire = load_wire_descriptor_from_dict(_valid_wire_data())
    contract = F4QuestionContractV1()

    # Tampered config hash
    tampered_auth = LiveCanaryAuthorizationV1(
        config_hash="0" * 64,
        wire_contract_hash=wire.canonical_wire_hash(),
        endpoint_host="provider.example.invalid",
        question_contract_hash=contract.contract_hash,
        max_calls=1,
    )

    with pytest.raises(ValueError, match="Authorization config_hash mismatch"):
        assemble_hosted_canary_dry_run(
            cfg, wire, tampered_auth, _state(), contract, "req-dry-mismatch"
        )


def test_authorization_host_mismatch_rejected() -> None:
    cfg = _valid_config()
    wire = load_wire_descriptor_from_dict(_valid_wire_data())
    contract = F4QuestionContractV1()

    tampered_auth = LiveCanaryAuthorizationV1(
        config_hash=cfg.canonical_config_hash(),
        wire_contract_hash=wire.canonical_wire_hash(),
        endpoint_host="different.host.invalid",
        question_contract_hash=contract.contract_hash,
        max_calls=1,
    )

    with pytest.raises(ValueError, match="Authorization endpoint_host mismatch"):
        assemble_hosted_canary_dry_run(
            cfg, wire, tampered_auth, _state(), contract, "req-dry-host-mismatch"
        )


def test_dry_run_does_not_call_network(monkeypatch: pytest.MonkeyPatch) -> None:
    import socket

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("Zero network calls permitted in dry-run!")

    monkeypatch.setattr(socket, "socket", forbidden)

    cfg = _valid_config()
    wire = load_wire_descriptor_from_dict(_valid_wire_data())
    contract = F4QuestionContractV1()
    auth = LiveCanaryAuthorizationV1(
        config_hash=cfg.canonical_config_hash(),
        wire_contract_hash=wire.canonical_wire_hash(),
        endpoint_host="provider.example.invalid",
        question_contract_hash=contract.contract_hash,
        max_calls=1,
    )

    dry_run = assemble_hosted_canary_dry_run(
        cfg, wire, auth, _state(), contract, "req-no-net"
    )
    assert dry_run.body_payload_hash is not None
    assert dry_run.method == "POST"
