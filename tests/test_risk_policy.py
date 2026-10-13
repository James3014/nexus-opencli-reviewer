from __future__ import annotations

import pytest

from reviewer.risk_model_adapter import (
    F4QuestionContractV1,
    MockRiskModelAdapter,
    ProviderCallStatus,
    ProviderVisibleRiskStateV1,
)
from reviewer.risk_policy import (
    FamilyCalibrationPolicy,
    FamilyPolicyOutcome,
    apply_family_policy,
)


def _state() -> ProviderVisibleRiskStateV1:
    return ProviderVisibleRiskStateV1(
        action_type="TASK_RUN",
        mutation_domain="REPOSITORY",
        permission_profile="MUTATE_BOUNDED",
        is_mutation=True,
        allowed_path_extensions=(".py",),
        allowed_path_count=1,
    )


def _raw(probability: float):
    return MockRiskModelAdapter(fixed_probability=probability).evaluate(
        _state(),
        F4QuestionContractV1(),
        f"request-{probability}",
    )


def test_family_policy_requires_explicit_operating_point() -> None:
    with pytest.raises(TypeError):
        FamilyCalibrationPolicy(  # type: ignore[call-arg]
            family_id="completion_reflex",
            calibration_id="synthetic-test-calibration",
        )


def test_same_raw_result_can_have_different_family_operating_points() -> None:
    raw = _raw(0.75)
    stricter = FamilyCalibrationPolicy(
        family_id="completion_reflex",
        calibration_id="synthetic-completion-v1",
        escalation_threshold=0.80,
    )
    looser = FamilyCalibrationPolicy(
        family_id="semantic_grep",
        calibration_id="synthetic-grep-v1",
        escalation_threshold=0.70,
    )

    assert apply_family_policy(raw, stricter).outcome is FamilyPolicyOutcome.SAME
    assert apply_family_policy(raw, looser).outcome is FamilyPolicyOutcome.ESCALATE
    assert raw.probability == pytest.approx(0.75)
    assert not hasattr(raw, "decision")


def test_provider_failure_never_becomes_same_or_escalate_prediction() -> None:
    raw = MockRiskModelAdapter(
        fixed_probability=0.99,
        simulate_status=ProviderCallStatus.NETWORK_UNAVAILABLE,
    ).evaluate(
        _state(),
        F4QuestionContractV1(),
        "request-failure",
    )
    policy = FamilyCalibrationPolicy(
        family_id="context_write_time_sieve",
        calibration_id="synthetic-context-v1",
        escalation_threshold=0.60,
    )

    result = apply_family_policy(raw, policy)

    assert result.provider_status is ProviderCallStatus.NETWORK_UNAVAILABLE
    assert result.probability is None
    assert result.outcome is FamilyPolicyOutcome.PROVIDER_UNAVAILABLE
