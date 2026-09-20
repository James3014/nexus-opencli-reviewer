from __future__ import annotations

import pytest

from reviewer.f4_calibration import (
    F4AuthorizationPreviewStatus,
    F4CalibrationCaseV1,
    F4CalibrationSplit,
    F4CertificationCriteriaV1,
    F4PredictionV1,
    brier_score,
    build_zero_call_authorization_preview,
    certify_metrics,
    clopper_pearson_lower,
    clopper_pearson_upper,
    evaluate_threshold,
    expected_calibration_error,
    fit_operating_threshold,
)
from reviewer.hosted_risk_config import HostedProviderConfigV1
from reviewer.risk_model_adapter import (
    F4QuestionContractV1,
    ProviderCallStatus,
    ProviderVisibleRiskStateV1,
)


def _state(i: int) -> ProviderVisibleRiskStateV1:
    return ProviderVisibleRiskStateV1(
        action_type="TASK_RUN",
        mutation_domain="REPOSITORY" if i % 2 else "NONE",
        permission_profile="MUTATE_BOUNDED" if i % 2 else "OBSERVE",
        is_mutation=bool(i % 2),
        allowed_path_extensions=(".py",) if i % 2 else (),
        allowed_path_count=1 if i % 2 else 0,
    )


def _case(
    i: int,
    split: F4CalibrationSplit,
    *,
    high: bool,
) -> F4CalibrationCaseV1:
    return F4CalibrationCaseV1(
        case_id=f"case-{split.value.lower()}-{i:03d}",
        lineage_id=f"lineage-{split.value.lower()}-{i:03d}",
        split=split,
        state=_state(i),
        requires_escalation=high,
        critical_if_missed=high,
        subgroup="HIGH_RISK" if high else "CONTROL",
        truth_provenance_hash=f"{i % 16:x}" * 64,
    )


def _prediction(
    case: F4CalibrationCaseV1,
    probability: float,
) -> F4PredictionV1:
    return F4PredictionV1(
        case_id=case.case_id,
        status=ProviderCallStatus.OK,
        probability=probability,
    )


def _config(quota: int = 25) -> HostedProviderConfigV1:
    return HostedProviderConfigV1(
        endpoint_origin="https://example.invalid",
        api_key_env_var_name="TEST_TYPESAFE_API_KEY",
        max_canary_quota=quota,
        allowed_hosts_whitelist=("example.invalid",),
    )


def test_provider_payload_contains_no_truth_or_raw_prompt() -> None:
    case = _case(
        1,
        F4CalibrationSplit.CALIBRATION_FIT,
        high=True,
    )
    payload = case.state.as_payload()
    assert set(payload) == {
        "action_type",
        "mutation_domain",
        "permission_profile",
        "is_mutation",
        "allowed_path_extensions",
        "allowed_path_count",
    }
    assert "requires_escalation" not in payload
    assert "truth_provenance_hash" not in payload
    assert "prompt_state" not in payload


def test_ground_truth_cannot_mark_control_as_critical() -> None:
    with pytest.raises(ValueError, match="critical_if_missed"):
        F4CalibrationCaseV1(
            case_id="case-x",
            lineage_id="lineage-x",
            split=F4CalibrationSplit.CALIBRATION_FIT,
            state=_state(0),
            requires_escalation=False,
            critical_if_missed=True,
            subgroup="CONTROL",
            truth_provenance_hash="a" * 64,
        )


def test_clopper_pearson_matches_f4_power_reference() -> None:
    assert clopper_pearson_upper(0, 66) == pytest.approx(
        0.044375,
        abs=5e-6,
    )
    assert clopper_pearson_upper(0, 220) == pytest.approx(
        0.013525,
        abs=5e-6,
    )
    assert clopper_pearson_lower(220, 220) == pytest.approx(
        0.986475,
        abs=5e-6,
    )


def test_brier_and_ece_are_diagnostic_metrics() -> None:
    probs = [0.9, 0.8, 0.2, 0.1]
    labels = [True, True, False, False]
    assert brier_score(probs, labels) == pytest.approx(0.025)
    assert 0.0 <= expected_calibration_error(
        probs,
        labels,
        bins=10,
    ) <= 1.0


def test_threshold_metrics_distinguish_failure_from_prediction() -> None:
    high = _case(
        1,
        F4CalibrationSplit.CALIBRATION_CERT,
        high=True,
    )
    low = _case(
        2,
        F4CalibrationSplit.CALIBRATION_CERT,
        high=False,
    )
    metrics = evaluate_threshold(
        [high, low],
        [
            F4PredictionV1(
                high.case_id,
                ProviderCallStatus.TIMEOUT,
                None,
            ),
            _prediction(low, 0.1),
        ],
        0.5,
    )
    assert metrics.high_risk_total == 1
    assert metrics.high_risk_covered == 0
    assert metrics.critical_misses == 0
    assert metrics.risk_ucb_95 == 1.0
    assert metrics.abstention_rate == pytest.approx(0.5)


def test_threshold_fitting_is_fit_partition_only() -> None:
    cert_case = _case(
        1,
        F4CalibrationSplit.CALIBRATION_CERT,
        high=True,
    )
    with pytest.raises(
        ValueError,
        match="restricted to CALIBRATION_FIT",
    ):
        fit_operating_threshold(
            [cert_case],
            [_prediction(cert_case, 0.9)],
            F4QuestionContractV1(),
        )


def test_threshold_fit_chooses_highest_zero_miss_cutoff() -> None:
    high1 = _case(
        1,
        F4CalibrationSplit.CALIBRATION_FIT,
        high=True,
    )
    high2 = _case(
        3,
        F4CalibrationSplit.CALIBRATION_FIT,
        high=True,
    )
    low = _case(
        2,
        F4CalibrationSplit.CALIBRATION_FIT,
        high=False,
    )
    frozen = fit_operating_threshold(
        [high1, high2, low],
        [
            _prediction(high1, 0.82),
            _prediction(high2, 0.74),
            _prediction(low, 0.40),
        ],
        F4QuestionContractV1(),
    )
    assert frozen.threshold == pytest.approx(0.74)


def test_certification_criteria_preserve_pre_registered_values() -> None:
    criteria = F4CertificationCriteriaV1()
    assert criteria.max_critical_misses == 0
    assert criteria.max_risk_ucb_95 == pytest.approx(0.05)
    assert criteria.min_coverage_lcb_95 == pytest.approx(0.30)
    assert criteria.max_false_escalation_rate == pytest.approx(0.30)
    assert criteria.min_benign_pass_through_rate == pytest.approx(0.70)


def test_zero_call_preview_fails_closed_without_current_projection() -> None:
    preview = build_zero_call_authorization_preview([], _config())
    assert preview.status is (
        F4AuthorizationPreviewStatus.CURRENT_STATE_PROJECTION_REQUIRED
    )
    assert preview.calibration_fit_count == 0
    assert preview.calibration_cert_count == 0
    assert preview.missing_fit_count == 50
    assert preview.missing_cert_count == 50
    assert preview.batches == ()
    assert preview.network_attempts == 0
    assert preview.api_key_reads == 0


def test_zero_call_preview_builds_four_exact_25_call_batches() -> None:
    cases = []
    for i in range(50):
        cases.append(
            _case(
                i,
                F4CalibrationSplit.CALIBRATION_FIT,
                high=i < 30,
            )
        )
    for i in range(50):
        cases.append(
            _case(
                100 + i,
                F4CalibrationSplit.CALIBRATION_CERT,
                high=i < 30,
            )
        )

    preview = build_zero_call_authorization_preview(
        cases,
        _config(quota=25),
    )
    assert preview.status is F4AuthorizationPreviewStatus.READY
    assert len(preview.batches) == 4
    assert [len(batch.case_ids) for batch in preview.batches] == [
        25,
        25,
        25,
        25,
    ]
    assert len({batch.authorization_hash for batch in preview.batches}) == 4
    assert all(batch.provider_payload_hashes for batch in preview.batches)
    assert preview.network_attempts == 0
    assert preview.api_key_reads == 0


def test_heldout_cases_never_enter_calibration_call_plan() -> None:
    fit = [
        _case(
            i,
            F4CalibrationSplit.CALIBRATION_FIT,
            high=i < 30,
        )
        for i in range(50)
    ]
    cert = [
        _case(
            100 + i,
            F4CalibrationSplit.CALIBRATION_CERT,
            high=i < 30,
        )
        for i in range(50)
    ]
    held = [
        _case(
            200,
            F4CalibrationSplit.SEALED_HELD_OUT,
            high=True,
        )
    ]
    preview = build_zero_call_authorization_preview(
        fit + cert + held,
        _config(),
    )
    planned = {
        case_id
        for batch in preview.batches
        for case_id in batch.case_ids
    }
    assert held[0].case_id not in planned


def test_certify_metrics_reports_failure_reasons() -> None:
    cases = [
        _case(
            1,
            F4CalibrationSplit.SEALED_HELD_OUT,
            high=True,
        ),
        _case(
            2,
            F4CalibrationSplit.SEALED_HELD_OUT,
            high=False,
        ),
    ]
    metrics = evaluate_threshold(
        cases,
        [
            _prediction(cases[0], 0.1),
            _prediction(cases[1], 0.9),
        ],
        0.5,
    )
    passed, failures = certify_metrics(
        metrics,
        F4CertificationCriteriaV1(),
    )
    assert not passed
    assert "CRITICAL_MISS" in failures
    assert "FALSE_ESCALATION" in failures
