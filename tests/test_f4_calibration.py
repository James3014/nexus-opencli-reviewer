from __future__ import annotations

import pytest

from reviewer.f4_calibration import (
    F4AuthorizationPreviewStatus,
    F4CalibrationCaseV1,
    F4CalibrationSplit,
    F4CertificationCriteriaV1,
    F4PredictionV1,
    F4SelectiveOperatingPointV1,
    brier_score,
    build_zero_call_authorization_preview,
    canonical_corpus_manifest_hash,
    certify_metrics,
    clopper_pearson_lower,
    clopper_pearson_upper,
    evaluate_selective_operating_point,
    expected_calibration_error,
    fit_selective_operating_point,
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
        projection_provenance_hash=f"{(i + 1) % 16:x}" * 64,
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
    assert "projection_provenance_hash" not in payload
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
            projection_provenance_hash="b" * 64,
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


def test_selective_metrics_distinguish_unavailable_from_safe_prediction() -> None:
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
    metrics = evaluate_selective_operating_point(
        [high, low],
        [
            F4PredictionV1(
                high.case_id,
                ProviderCallStatus.TIMEOUT,
                None,
            ),
            _prediction(low, 0.1),
        ],
        F4SelectiveOperatingPointV1(
            same_threshold=0.3,
            escalation_threshold=0.7,
        ),
    )
    assert metrics.provider_unavailable_cases == 1
    assert metrics.high_risk_decisions == 0
    assert metrics.critical_misses == 0
    assert metrics.risk_ucb_95 == 1.0
    assert metrics.abstention_rate == pytest.approx(0.5)
    assert metrics.benign_pass_through_rate == pytest.approx(1.0)


def test_selective_operating_point_fitting_is_fit_partition_only() -> None:
    cert_case = _case(
        1,
        F4CalibrationSplit.CALIBRATION_CERT,
        high=True,
    )
    with pytest.raises(
        ValueError,
        match="restricted to CALIBRATION_FIT",
    ):
        fit_selective_operating_point(
            [cert_case],
            [_prediction(cert_case, 0.9)],
            F4QuestionContractV1(),
            prediction_source_hash="b" * 64,
            calibration_contract_revision="c" * 40,
        )


def test_selective_fit_freezes_abstention_region_and_evidence_identity() -> None:
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
    frozen = fit_selective_operating_point(
        [high1, high2, low],
        [
            _prediction(high1, 0.82),
            _prediction(high2, 0.74),
            _prediction(low, 0.40),
        ],
        F4QuestionContractV1(),
        prediction_source_hash="b" * 64,
        calibration_contract_revision="c" * 40,
    )
    assert frozen.same_threshold == pytest.approx(0.74)
    assert frozen.escalation_threshold == pytest.approx(0.74)
    assert frozen.fit_corpus_manifest_hash == canonical_corpus_manifest_hash(
        [high1, high2, low],
        F4QuestionContractV1(),
    )
    assert frozen.prediction_source_hash == "b" * 64
    assert frozen.calibration_contract_revision == "c" * 40


def test_selective_middle_band_is_abstention_and_reduces_coverage() -> None:
    high = _case(1, F4CalibrationSplit.CALIBRATION_CERT, high=True)
    low = _case(2, F4CalibrationSplit.CALIBRATION_CERT, high=False)
    metrics = evaluate_selective_operating_point(
        [high, low],
        [_prediction(high, 0.60), _prediction(low, 0.40)],
        F4SelectiveOperatingPointV1(
            same_threshold=0.30,
            escalation_threshold=0.70,
        ),
    )
    assert metrics.semantic_abstentions == 2
    assert metrics.decision_cases == 0
    assert metrics.decision_coverage == 0.0
    assert metrics.high_risk_coverage == 0.0
    assert metrics.coverage_lcb_95 == 0.0
    assert metrics.benign_pass_through_rate == 0.0


def test_selective_risk_uses_non_abstained_high_risk_decisions() -> None:
    high1 = _case(1, F4CalibrationSplit.CALIBRATION_CERT, high=True)
    high2 = _case(3, F4CalibrationSplit.CALIBRATION_CERT, high=True)
    metrics = evaluate_selective_operating_point(
        [high1, high2],
        [_prediction(high1, 0.9), _prediction(high2, 0.2)],
        F4SelectiveOperatingPointV1(
            same_threshold=0.3,
            escalation_threshold=0.7,
        ),
    )
    assert metrics.high_risk_decisions == 2
    assert metrics.high_risk_errors == 1
    assert metrics.critical_misses == 1
    assert metrics.selective_risk == pytest.approx(0.5)


def test_certification_criteria_preserve_pre_registered_values() -> None:
    criteria = F4CertificationCriteriaV1()
    assert criteria.max_critical_misses == 0
    assert criteria.max_risk_ucb_95 == pytest.approx(0.05)
    assert criteria.min_coverage_lcb_95 == pytest.approx(0.30)
    assert criteria.max_false_escalation_rate == pytest.approx(0.30)
    assert criteria.min_benign_pass_through_rate == pytest.approx(0.70)


def test_zero_call_preview_fails_closed_without_current_projection() -> None:
    preview = build_zero_call_authorization_preview(
        [],
        _config(),
        calibration_contract_revision="c" * 40,
    )
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
        calibration_contract_revision="c" * 40,
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
        calibration_contract_revision="c" * 40,
    )
    planned = {
        case_id
        for batch in preview.batches
        for case_id in batch.case_ids
    }
    assert held[0].case_id not in planned


def test_certify_metrics_reports_selective_failure_reasons() -> None:
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
    metrics = evaluate_selective_operating_point(
        cases,
        [
            _prediction(cases[0], 0.1),
            _prediction(cases[1], 0.9),
        ],
        F4SelectiveOperatingPointV1(
            same_threshold=0.3,
            escalation_threshold=0.7,
        ),
    )
    passed, failures = certify_metrics(
        metrics,
        F4CertificationCriteriaV1(),
    )
    assert not passed
    assert "CRITICAL_MISS" in failures
    assert "FALSE_ESCALATION" in failures


def test_truth_change_changes_corpus_commitment_not_provider_payload() -> None:
    contract = F4QuestionContractV1()
    state = _state(1)
    high = F4CalibrationCaseV1(
        case_id="case-same",
        lineage_id="lineage-same",
        split=F4CalibrationSplit.CALIBRATION_FIT,
        state=state,
        requires_escalation=True,
        critical_if_missed=False,
        subgroup="AMBIGUOUS",
        projection_provenance_hash="b" * 64,
        truth_provenance_hash="a" * 64,
    )
    low = F4CalibrationCaseV1(
        case_id="case-same",
        lineage_id="lineage-same",
        split=F4CalibrationSplit.CALIBRATION_FIT,
        state=state,
        requires_escalation=False,
        critical_if_missed=False,
        subgroup="AMBIGUOUS",
        projection_provenance_hash="b" * 64,
        truth_provenance_hash="a" * 64,
    )
    assert high.provider_payload_hash(contract) == low.provider_payload_hash(contract)
    assert canonical_corpus_manifest_hash([high], contract) != canonical_corpus_manifest_hash([low], contract)


def test_batch_authorization_binds_ground_truth_corpus_commitment() -> None:
    fit = [_case(i, F4CalibrationSplit.CALIBRATION_FIT, high=i < 30) for i in range(50)]
    cert = [_case(100 + i, F4CalibrationSplit.CALIBRATION_CERT, high=i < 30) for i in range(50)]
    first = build_zero_call_authorization_preview(
        fit + cert,
        _config(),
        calibration_contract_revision="c" * 40,
    )

    original = fit[0]
    altered = F4CalibrationCaseV1(
        case_id=original.case_id,
        lineage_id=original.lineage_id,
        split=original.split,
        state=original.state,
        requires_escalation=False,
        critical_if_missed=False,
        subgroup=original.subgroup,
        projection_provenance_hash=original.projection_provenance_hash,
        truth_provenance_hash=original.truth_provenance_hash,
    )
    second = build_zero_call_authorization_preview(
        [altered] + fit[1:] + cert,
        _config(),
        calibration_contract_revision="c" * 40,
    )

    assert first.corpus_manifest_hash != second.corpus_manifest_hash
    assert [b.authorization_hash for b in first.batches] != [
        b.authorization_hash for b in second.batches
    ]


def test_wave1_module_has_no_network_or_credential_read_surface() -> None:
    import ast
    import inspect
    import reviewer.f4_calibration as module

    source = inspect.getsource(module)
    tree = ast.parse(source)
    imported_roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_roots.add(node.module.split(".", 1)[0])

    assert imported_roots.isdisjoint(
        {"socket", "http", "urllib", "requests", "httpx", "aiohttp"}
    )
    assert "os.environ" not in source
    assert "TYPESAFE_API_KEY" not in source


def test_freeze_manifest_is_bound_to_current_contract() -> None:
    import json
    from pathlib import Path
    from reviewer.f4_calibration import (
        F4_FROZEN_ADAPTER_ID,
        F4_FROZEN_ADAPTER_REVISION,
        F4_FROZEN_MODEL_ALIAS,
        F4_FROZEN_PROVIDER_SCHEMA_IDENTITY,
        F4_FROZEN_SOURCE_REVISION,
        F4_FROZEN_WIRE_CONTRACT_HASH,
    )

    manifest = json.loads(
        Path("evidence/f4-risk-wave1-freeze.json").read_text()
    )
    frozen = manifest["frozen_source"]
    contract = F4QuestionContractV1()

    assert frozen["revision"] == F4_FROZEN_SOURCE_REVISION
    assert frozen["wire_contract_hash"] == F4_FROZEN_WIRE_CONTRACT_HASH
    assert frozen["question_contract_hash"] == contract.contract_hash
    assert frozen["input_schema_hash"] == contract.input_schema_hash
    assert frozen["provider_schema_identity"] == F4_FROZEN_PROVIDER_SCHEMA_IDENTITY
    assert frozen["model_alias"] == F4_FROZEN_MODEL_ALIAS
    assert frozen["adapter_id"] == F4_FROZEN_ADAPTER_ID
    assert frozen["adapter_revision"] == F4_FROZEN_ADAPTER_REVISION
    assert manifest["lineage_separation"]["current_noul_operating_point"] == (
        "UNBOUND_UNTIL_CALIBRATION_FIT"
    )


def test_authorization_preview_binds_calibration_contract_revision() -> None:
    fit = [
        _case(i, F4CalibrationSplit.CALIBRATION_FIT, high=i < 30)
        for i in range(50)
    ]
    cert = [
        _case(100 + i, F4CalibrationSplit.CALIBRATION_CERT, high=i < 30)
        for i in range(50)
    ]
    first = build_zero_call_authorization_preview(
        fit + cert,
        _config(),
        calibration_contract_revision="c" * 40,
    )
    second = build_zero_call_authorization_preview(
        fit + cert,
        _config(),
        calibration_contract_revision="d" * 40,
    )
    assert first.plan_hash != second.plan_hash
    assert [b.authorization_hash for b in first.batches] != [
        b.authorization_hash for b in second.batches
    ]


def test_projection_provenance_change_changes_corpus_commitment() -> None:
    contract = F4QuestionContractV1()
    original = _case(
        1,
        F4CalibrationSplit.CALIBRATION_FIT,
        high=True,
    )
    changed = F4CalibrationCaseV1(
        case_id=original.case_id,
        lineage_id=original.lineage_id,
        split=original.split,
        state=original.state,
        requires_escalation=original.requires_escalation,
        critical_if_missed=original.critical_if_missed,
        subgroup=original.subgroup,
        projection_provenance_hash="f" * 64,
        truth_provenance_hash=original.truth_provenance_hash,
    )
    assert original.provider_payload_hash(contract) == changed.provider_payload_hash(contract)
    assert canonical_corpus_manifest_hash([original], contract) != (
        canonical_corpus_manifest_hash([changed], contract)
    )


def test_no_legacy_single_threshold_certification_path_remains() -> None:
    import reviewer.f4_calibration as module

    assert not hasattr(module, "F4ThresholdMetricsV1")
    assert not hasattr(module, "F4FrozenThresholdV1")
    assert not hasattr(module, "evaluate_threshold")
    assert not hasattr(module, "fit_operating_threshold")
