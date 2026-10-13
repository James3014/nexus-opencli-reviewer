from __future__ import annotations

import ast
import inspect
import socket

import pytest

import reviewer.risk_model_adapter as adapter_module
from reviewer.risk_model_adapter import (
    F4QuestionContractV1,
    MockRiskModelAdapter,
    ProviderCallStatus,
    ProviderVisibleRiskStateV1,
    RiskModelResult,
    canonical_provider_payload_hash,
)


def _state(*, count: int = 2) -> ProviderVisibleRiskStateV1:
    return ProviderVisibleRiskStateV1(
        action_type="TASK_RUN",
        mutation_domain="REPOSITORY",
        permission_profile="MUTATE_BOUNDED",
        is_mutation=True,
        allowed_path_extensions=(".py", ".json"),
        allowed_path_count=count,
    )


def test_provider_visible_state_is_exact_canonical_subset() -> None:
    payload = _state().as_payload()

    assert set(payload) == {
        "action_type",
        "mutation_domain",
        "permission_profile",
        "is_mutation",
        "allowed_path_extensions",
        "allowed_path_count",
    }
    assert "approval_scope" not in payload
    assert "contract_kind" not in payload
    assert "observation_id" not in payload
    assert "source_action_digest" not in payload
    assert "payload_checksum" not in payload


def test_question_contract_keeps_frozen_h0_identity() -> None:
    contract = F4QuestionContractV1()

    assert contract.primitive == "NOUL"
    assert (
        contract.input_schema_hash
        == "c74f56f34e6e6512b9d29c89456cb04c32d43be98514582f3471bbcf594fa35b"
    )
    assert (
        contract.contract_hash
        == "e9124408bb39fa2799c8524458d341bcf027415e9858348bb921473be9857912"
    )


def test_mock_returns_raw_probability_without_operating_decision() -> None:
    result = MockRiskModelAdapter(fixed_probability=0.73).evaluate(
        _state(),
        F4QuestionContractV1(),
        "request-1",
    )

    assert result.status is ProviderCallStatus.OK
    assert result.probability == pytest.approx(0.73)
    assert not hasattr(result, "decision")


@pytest.mark.parametrize("probability", [0.49, 0.51])
def test_mock_does_not_convert_probability_to_hidden_cutoff(
    probability: float,
) -> None:
    result = MockRiskModelAdapter(fixed_probability=probability).evaluate(
        _state(),
        F4QuestionContractV1(),
        f"request-{probability}",
    )

    assert result.probability == pytest.approx(probability)
    assert result.status is ProviderCallStatus.OK
    assert not hasattr(result, "decision")


def test_provider_failure_is_not_a_model_prediction() -> None:
    result = MockRiskModelAdapter(
        fixed_probability=0.99,
        simulate_status=ProviderCallStatus.TIMEOUT,
    ).evaluate(
        _state(),
        F4QuestionContractV1(),
        "request-timeout",
    )

    assert result.status is ProviderCallStatus.TIMEOUT
    assert result.probability is None
    assert result.error_message


def test_result_rejects_probability_on_provider_failure() -> None:
    with pytest.raises(ValueError, match="provider failures"):
        RiskModelResult(
            status=ProviderCallStatus.TIMEOUT,
            probability=0.9,
            provider_payload_hash="a" * 64,
            adapter_id="mock",
            adapter_revision="h0",
            question_contract_hash="b" * 64,
            provider_schema_version="mock-v1",
        )


def test_payload_hash_is_deterministic_and_state_bound() -> None:
    contract = F4QuestionContractV1()

    first = canonical_provider_payload_hash(_state(count=2), contract)
    replay = canonical_provider_payload_hash(_state(count=2), contract)
    changed = canonical_provider_payload_hash(_state(count=3), contract)

    assert first == replay
    assert first != changed
    assert len(first) == 64


def test_h0_mock_uses_no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden_socket(*args: object, **kwargs: object) -> None:
        raise AssertionError("H0 must not create sockets")

    monkeypatch.setattr(socket, "socket", forbidden_socket)

    result = MockRiskModelAdapter(fixed_probability=0.2).evaluate(
        _state(),
        F4QuestionContractV1(),
        "request-zero-network",
    )

    assert result.status is ProviderCallStatus.OK


def test_adapter_module_has_no_network_client_imports() -> None:
    source = inspect.getsource(adapter_module)
    tree = ast.parse(source)
    imported_roots: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_roots.add(node.module.split(".", 1)[0])

    assert imported_roots.isdisjoint(
        {"socket", "http", "urllib", "requests", "httpx", "aiohttp"}
    )


def test_adapter_contains_no_private_provider_binding_details() -> None:
    source = inspect.getsource(adapter_module).lower()

    assert "typesafe" not in source
    assert "typesafe_api_key" not in source
    assert "api.typesafe" not in source
    assert "jev" not in source


def test_adapter_layer_does_not_import_family_policy() -> None:
    source = inspect.getsource(adapter_module)

    assert "risk_policy" not in source
    assert "FamilyCalibrationPolicy" not in source
