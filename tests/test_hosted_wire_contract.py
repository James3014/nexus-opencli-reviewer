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
        "request_path": "/v1/systemone",
        "auth_mode": "BEARER",
        "auth_header_name": "Authorization",
        "content_type": "application/json",
        "expected_model_identifier": "jev-latest",
        "request_template_kind": "systemone_noul",
        "response_probability_path": "answers.decision.noul",
        "api_version_source": "OPENAPI_INFO_0.2.0_PATH_V1",
        "provider_schema_identity": "typesafe-openapi-0.2.0-systemone-v1",
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
    assert wire.request_path == "/v1/systemone"
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
    assert len(dry_run.endpoint_host_hash) == 64
    assert dry_run.header_names == (
        "Accept",
        "Authorization",
        "Content-Type",
    )
    assert not hasattr(dry_run, "target_origin")
    assert not hasattr(dry_run, "target_path")
    assert not hasattr(dry_run, "headers")
    assert not hasattr(dry_run, "body_payload")
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



def test_wire_descriptor_rejects_implicit_string_coercion() -> None:
    data = _valid_wire_data()
    data["expected_model_identifier"] = 123

    with pytest.raises(ValueError, match="expected_model_identifier must be a JSON string"):
        load_wire_descriptor_from_dict(data)


def test_authorization_cannot_exceed_configured_quota() -> None:
    cfg = _valid_config()
    wire = load_wire_descriptor_from_dict(_valid_wire_data())
    contract = F4QuestionContractV1()
    auth = LiveCanaryAuthorizationV1(
        config_hash=cfg.canonical_config_hash(),
        wire_contract_hash=wire.canonical_wire_hash(),
        endpoint_host="provider.example.invalid",
        question_contract_hash=contract.contract_hash,
        max_calls=2,
    )

    with pytest.raises(ValueError, match="exceeds configured canary quota"):
        assemble_hosted_canary_dry_run(
            cfg, wire, auth, _state(), contract, "req-over-quota"
        )


@pytest.mark.parametrize(
    "request_id",
    ["", "has space", "line\nbreak", "tab\tvalue", "x" * 129],
)
def test_provider_request_id_must_be_bounded_visible_token(request_id: str) -> None:
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

    with pytest.raises(ValueError, match="provider_request_id"):
        assemble_hosted_canary_dry_run(
            cfg, wire, auth, _state(), contract, request_id
        )


def test_dry_run_has_no_secret_materialization_parameter() -> None:
    import inspect

    signature = inspect.signature(assemble_hosted_canary_dry_run)
    assert "synthetic_key" not in signature.parameters



def test_f4_dry_run_hash_matches_authoritative_noul_systemone_body() -> None:
    import hashlib

    cfg = _valid_config()
    wire = load_wire_descriptor_from_dict(_valid_wire_data())
    contract = F4QuestionContractV1()
    state = _state()
    auth = LiveCanaryAuthorizationV1(
        config_hash=cfg.canonical_config_hash(),
        wire_contract_hash=wire.canonical_wire_hash(),
        endpoint_host="provider.example.invalid",
        question_contract_hash=contract.contract_hash,
        max_calls=1,
    )

    dry_run = assemble_hosted_canary_dry_run(
        cfg, wire, auth, state, contract, "req-authoritative-noul"
    )

    expected_body = {
        "model": "jev-latest",
        "questions": {
            "decision": {
                "type": "noul",
                "instructions": contract.question_statement,
            }
        },
        "state": state.as_payload(),
    }
    encoded = json.dumps(
        expected_body, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")

    assert dry_run.body_payload_hash == hashlib.sha256(encoded).hexdigest()


@pytest.mark.parametrize(
    ("field_name", "bad_value", "message"),
    [
        (
            "request_template_kind",
            "systemone_choice",
            "systemone_noul",
        ),
        (
            "response_probability_path",
            "answers.decision.probabilities.ESCALATE",
            "answers.decision.noul",
        ),
    ],
)
def test_f4_dry_run_rejects_historical_choice_wire_mapping(
    field_name: str,
    bad_value: str,
    message: str,
) -> None:
    cfg = _valid_config()
    data = _valid_wire_data()
    data[field_name] = bad_value
    wire = load_wire_descriptor_from_dict(data)
    contract = F4QuestionContractV1()
    auth = LiveCanaryAuthorizationV1(
        config_hash=cfg.canonical_config_hash(),
        wire_contract_hash=wire.canonical_wire_hash(),
        endpoint_host="provider.example.invalid",
        question_contract_hash=contract.contract_hash,
        max_calls=1,
    )

    with pytest.raises(ValueError, match=message):
        assemble_hosted_canary_dry_run(
            cfg, wire, auth, _state(), contract, "req-reject-historical-choice"
        )
