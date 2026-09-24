import copy
import hashlib
import json

import pytest

from reviewer.experiment_handoff import (
    build_experiment_handoff,
    verify_experiment_handoff,
    project_nexus_experiment_integrity_input,
    project_nexus_quality_workflow_row,
    HANDOFF_SCHEMA,
    HANDOFF_CLAIM_CEILING,
    INDEPENDENCE_UNIT_ROW,
    INDEPENDENCE_UNIT_BASE,
    CALIBRATED,
    INSUFFICIENT_CALIBRATION,
    EXPLORATORY_UNCALIBRATED,
    FROZEN_REJECT_ALL,
    TERMINAL_PASS,
    TERMINAL_STOP,
    TERMINAL_DEFER,
    TERMINAL_NEGATIVE,
    DATA_PURPOSE_TRAINING_CANDIDATE,
    DATA_PURPOSE_EVALUATION_ONLY,
    DATA_PURPOSE_LEARNING_POLICY_EVIDENCE,
    TRAINING_ADMISSION_FORBIDDEN,
    TRAINING_ADMISSION_QUALITY_GATED,
    QUALITY_QUALIFIED,
    QUALITY_SUPERIOR,
    QUALITY_FLOOR_FAILED,
    INSUFFICIENT_COST_EVIDENCE,
    NEXUS_INTEGRITY_SCHEMA,
    NEXUS_ECONOMICS_SCHEMA,
    EFFECT_OUTCOME_UNKNOWN,
    EFFECT_SUCCEEDED,
    LOCAL_FAKE_PROVIDER,
    MOCK_TRANSPORT,
    PHYSICAL_LOCAL_MODEL,
    REMOTE_PROVIDER_OBSERVED,
    SIMULATION_ONLY,
    UNKNOWN_ORIGIN,
    build_evidence_origin_compat,
    require_live_provider_observation,
    verify_evidence_origin_compat,
)


def cal_identity(i):
    return {"identity": f"cal-{i}", "evidence": {"x": i}}


def hold_identity(i):
    return {"identity": f"hold-{i}", "evidence": {"x": i}}


def valid_handoff(**overrides):
    kwargs = dict(
        experiment_id="exp-001",
        experiment_version="v7",
        providers=[
            {
                "provider": "openai",
                "model": "gpt-4o",
                "model_revision": "2024-08-06",
                "adapter_version": "r7",
                "transport": "api",
            }
        ],
        calibration_members=[cal_identity(i) for i in range(5)],
        heldout_members=[hold_identity(i) for i in range(5)],
        independence_unit=INDEPENDENCE_UNIT_ROW,
        policy_derivation_ref="ref-7",
        frozen_policy={"strategy": "frozen-v7", "reject_delta_above": 0.2},
        freeze_generation=7,
        heldout_evaluation_start_generation=8,
        calibration_status=CALIBRATED,
        workflow_identity="cascade",
        workflow_revision="r7",
        task_fingerprint="task-family-001",
        attempt_count=100,
        qualified_success_count=98,
        semantic_failure_count=1,
        provider_failure_count=1,
        false_allow_count=0,
        human_intervention_count=0,
        required_quality_floor=0.95,
        sealed_input_digest="aa" * 32,
        sealed_truth_digest="bb" * 32,
        terminal_outcome=TERMINAL_PASS,
        model_invocation_count=120,
        provider_invocation_count=110,
        fallback_count=3,
        required_quality_floor_passed=True,
        critical_failure_count=1,
        critical_failure_ceiling=2,
        quality_gate_result=QUALITY_SUPERIOR,
        economics_compared=True,
        cost_telemetry_complete=True,
        latency_ms_p50=9.5,
        latency_ms_p95=11.0,
        token_usage=500000,
        monetary_cost_usd=1.25,
        wall_time_seconds=90.0,
        data_purpose=DATA_PURPOSE_TRAINING_CANDIDATE,
    )
    kwargs.update(overrides)
    return build_experiment_handoff(**kwargs)


def test_valid_handoff_verifies_and_is_serializable():
    artifact = valid_handoff()
    manifest = verify_experiment_handoff(artifact)
    assert artifact["schema"] == HANDOFF_SCHEMA
    assert artifact["claim_ceiling"] == HANDOFF_CLAIM_CEILING
    canonical = json.dumps(artifact, sort_keys=True, separators=(",", ":")).encode("utf-8")
    assert manifest["content_sha256"] == hashlib.sha256(canonical).hexdigest()
    assert manifest["handoff_id"]
    assert json.loads(json.dumps(artifact)) == artifact


def test_claim_ceiling_is_verification_bound_not_result_bound():
    artifact = valid_handoff(terminal_outcome=TERMINAL_NEGATIVE)
    assert artifact["claim_ceiling"] == HANDOFF_CLAIM_CEILING
    assert artifact["nexus_projection"]["negative_terminal_preserved"] is True
    verify_experiment_handoff(artifact)


def test_population_hash_mismatch_fails_closed():
    artifact = valid_handoff()
    artifact["populations"]["calibration"]["population_hash"] = "00" * 32
    with pytest.raises(ValueError, match="HANDOFF_CALIBRATION_POPULATION_HASH_MISMATCH"):
        verify_experiment_handoff(artifact)


def test_member_identity_edit_rejects_hash():
    artifact = valid_handoff()
    artifact["populations"]["heldout"]["members"][0]["identity"] = "hold-abc"
    with pytest.raises(ValueError, match="HANDOFF_HELDOUT_MEMBERS_HASH_MISMATCH"):
        verify_experiment_handoff(artifact)


def test_overlap_between_calibration_and_heldout_rejected():
    shared = [cal_identity(i) for i in range(5)]
    with pytest.raises(ValueError, match="^HANDOFF_POPULATION_OVERLAP"):
        valid_handoff(heldout_members=shared)


def test_overlap_proof_tamper_rejected():
    artifact = valid_handoff()
    artifact["populations"]["overlap_proof"]["overlap"] = True
    with pytest.raises(ValueError, match="HANDOFF_OVERLAP_PROOF_TAMPERED"):
        verify_experiment_handoff(artifact)


def test_base_independence_unit_supported():
    cal = [{"base_identity": f"b{i}", "evidence": {"x": i}} for i in range(5)]
    hold = [{"base_identity": f"h{i}", "evidence": {"x": i}} for i in range(5)]
    artifact = valid_handoff(
        independence_unit=INDEPENDENCE_UNIT_BASE,
        calibration_members=cal,
        heldout_members=hold,
    )
    verify_experiment_handoff(artifact)
    assert artifact["populations"]["independence_unit"] == INDEPENDENCE_UNIT_BASE


def test_policy_hash_mismatch_rejected():
    artifact = valid_handoff()
    artifact["policy_freeze"]["frozen_policy"]["policy"]["strategy"] = "mutated"
    with pytest.raises(ValueError, match="HANDOFF_POLICY_HASH_MISMATCH"):
        verify_experiment_handoff(artifact)


def test_freeze_must_precede_evaluation_start():
    with pytest.raises(ValueError, match="HANDOFF_GENERATION_MUST_BE_INTEGER"):
        valid_handoff(freeze_generation="8", heldout_evaluation_start_generation=8)
    with pytest.raises(ValueError, match="HANDOFF_POLICY_FROZEN_AFTER_EVALUATION_START"):
        valid_handoff(freeze_generation=9, heldout_evaluation_start_generation=8)
    with pytest.raises(ValueError, match="HANDOFF_POLICY_FROZEN_AFTER_EVALUATION_START"):
        valid_handoff(freeze_generation=8, heldout_evaluation_start_generation=8)


def test_freeze_order_proof_tamper_rejected():
    artifact = valid_handoff()
    artifact["policy_freeze"]["freeze_order_proof"]["policy_frozen_before_heldout_evaluation"] = False
    with pytest.raises(ValueError, match="HANDOFF_FREEZE_ORDER_PROOF_TAMPERED"):
        verify_experiment_handoff(artifact)


def test_calibrated_with_insufficient_reasons_rejected():
    with pytest.raises(ValueError, match="HANDOFF_CALIBRATED_WITH_INSUFFICIENT_REASONS"):
        valid_handoff(calibration_status=CALIBRATED, insufficient_calibration_reasons=["slow drift"])


def test_uncalibrated_requires_reasons():
    with pytest.raises(ValueError, match="HANDOFF_UNCALIBRATED_WITHOUT_REASONS"):
        valid_handoff(calibration_status=INSUFFICIENT_CALIBRATION)
    with pytest.raises(ValueError, match="HANDOFF_UNCALIBRATED_WITHOUT_REASONS"):
        valid_handoff(calibration_status=EXPLORATORY_UNCALIBRATED)


def test_reject_all_status_requires_reject_all_policy():
    with pytest.raises(ValueError, match="HANDOFF_REJECT_ALL_POLICY_REQUIRED"):
        valid_handoff(calibration_status=FROZEN_REJECT_ALL)
    artifact = valid_handoff(
        calibration_status=FROZEN_REJECT_ALL,
        reject_all_policy={
            "target_policy_delta": "reject_all_until_manual",
            "model_success_claim": False,
        },
        terminal_outcome=TERMINAL_STOP,
    )
    verify_experiment_handoff(artifact)
    assert artifact["terminal"]["outcome"] == TERMINAL_STOP


def test_pass_requires_prefrozen_calibration():
    with pytest.raises(ValueError, match="HANDOFF_PASS_WITHOUT_PREFROZEN_CALIBRATION"):
        valid_handoff(
            calibration_status=EXPLORATORY_UNCALIBRATED,
            insufficient_calibration_reasons=["not yet calibrated"],
        )


def test_negative_terminal_cannot_be_rewritten_to_pass():
    with pytest.raises(ValueError, match="HANDOFF_PASS_WITHOUT_PREFROZEN_CALIBRATION"):
        valid_handoff(
            calibration_status=EXPLORATORY_UNCALIBRATED,
            insufficient_calibration_reasons=["frozen reject"],
            terminal_outcome=TERMINAL_PASS,
        )
    artifact = valid_handoff(terminal_outcome=TERMINAL_NEGATIVE)
    assert artifact["terminal"]["negative_terminal"] is True
    assert artifact["nexus_projection"]["negative_terminal_preserved"] is True
    verify_experiment_handoff(artifact)


def test_negative_terminal_flag_tamper_rejected():
    artifact = valid_handoff(terminal_outcome=TERMINAL_NEGATIVE)
    artifact["terminal"]["negative_terminal"] = False
    with pytest.raises(ValueError, match="HANDOFF_TERMINAL_NEGATIVE_FLAG_MISMATCH"):
        verify_experiment_handoff(artifact)


def test_terminal_taxonomy_kind_required():
    with pytest.raises(ValueError, match="HANDOFF_TAXONOMY_KIND_MISSING"):
        valid_handoff(failure_taxonomy=[{"count": 1}])
    artifact = valid_handoff(
        failure_taxonomy=[
            {"kind": "provider_error", "count": 2, "description": "timeout"},
            {"kind": "semantic_failure", "count": 1, "description": "hallucination"},
        ]
    )
    verify_experiment_handoff(artifact)
    assert artifact["terminal"]["failure_taxonomy"][0]["kind"] == "provider_error"


def test_evaluation_only_forbids_training():
    artifact = valid_handoff(data_purpose=DATA_PURPOSE_EVALUATION_ONLY)
    assert artifact["training"]["training_admission"] == TRAINING_ADMISSION_FORBIDDEN
    assert artifact["training"]["training_forbidden"] is True
    verify_experiment_handoff(artifact)


def test_learning_policy_evidence_forbids_training():
    artifact = valid_handoff(data_purpose=DATA_PURPOSE_LEARNING_POLICY_EVIDENCE)
    assert artifact["training"]["training_admission"] == TRAINING_ADMISSION_FORBIDDEN
    verify_experiment_handoff(artifact)


def test_training_candidate_is_quality_gated():
    artifact = valid_handoff(data_purpose=DATA_PURPOSE_TRAINING_CANDIDATE)
    assert artifact["training"]["training_admission"] == TRAINING_ADMISSION_QUALITY_GATED
    assert artifact["training"]["training_forbidden"] is False
    verify_experiment_handoff(artifact)


def test_unknown_data_purpose_fails_closed():
    with pytest.raises(ValueError, match="HANDOFF_UNKNOWN_DATA_PURPOSE"):
        valid_handoff(data_purpose="authored_novelty_testing")


def test_training_admission_tamper_rejected():
    artifact = valid_handoff(data_purpose=DATA_PURPOSE_EVALUATION_ONLY)
    artifact["training"]["training_admission"] = TRAINING_ADMISSION_QUALITY_GATED
    with pytest.raises(ValueError, match="HANDOFF_TRAINING_ADMISSION_MISMATCH"):
        verify_experiment_handoff(artifact)


def test_missing_cost_fields_require_explicit_missingness():
    with pytest.raises(ValueError, match="HANDOFF_COST_MISSING_REASON_REQUIRED"):
        valid_handoff(
            cost_telemetry_complete=False,
            latency_ms_p50=None,
            latency_ms_p95=None,
            token_usage=None,
            monetary_cost_usd=None,
            wall_time_seconds=None,
        )
    artifact = valid_handoff(
        cost_telemetry_complete=False,
        missingness=["latency_ms_p50", "latency_ms_p95", "token_usage", "monetary_cost_usd", "wall_time_seconds"],
        latency_ms_p50=None,
        latency_ms_p95=None,
        token_usage=None,
        monetary_cost_usd=None,
        wall_time_seconds=None,
        economics_compared=False,
        quality_gate_result=QUALITY_QUALIFIED,
    )
    verify_experiment_handoff(artifact)
    assert artifact["cost"]["cost_telemetry_complete"] is False


def test_cost_missing_never_zero_filled():
    artifact = valid_handoff(
        cost_telemetry_complete=False,
        missingness=["latency_ms_p50", "latency_ms_p95", "token_usage", "monetary_cost_usd", "wall_time_seconds"],
        latency_ms_p50=None,
        latency_ms_p95=None,
        token_usage=None,
        monetary_cost_usd=None,
        wall_time_seconds=None,
        economics_compared=False,
        quality_gate_result=QUALITY_QUALIFIED,
    )
    for name in ("latency_ms_p50", "latency_ms_p95", "token_usage", "monetary_cost_usd", "wall_time_seconds"):
        assert artifact["cost"][name] is None
    verify_experiment_handoff(artifact)


def test_cost_telemetry_complete_requires_no_missingness():
    with pytest.raises(ValueError, match="HANDOFF_COST_TELEMETRY_INCOMPLETE_WHILE_COMPLETE"):
        valid_handoff(
            latency_ms_p95=None,
            missingness=["latency_ms_p95"],
        )
    with pytest.raises(ValueError, match="HANDOFF_COST_TELEMETRY_COMPLETE_WITH_MISSINGNESS"):
        valid_handoff(missingness=["latency_ms_p50"])


def test_cost_telemetry_incomplete_requires_no_values():
    with pytest.raises(ValueError, match="HANDOFF_COST_TELEMETRY_INCOMPLETE_WITH_VALUES"):
        valid_handoff(
            cost_telemetry_complete=False,
            latency_ms_p95=None,
            token_usage=None,
            monetary_cost_usd=None,
            wall_time_seconds=None,
            missingness=["latency_ms_p50", "latency_ms_p95", "token_usage", "monetary_cost_usd", "wall_time_seconds"],
            latency_ms_p50=7.0,
        )


def test_economics_comparison_requires_quality_floor():
    with pytest.raises(ValueError, match="HANDOFF_ECONOMICS_COMPARED_BEFORE_QUALITY"):
        valid_handoff(
            qualified_success_count=80,
            required_quality_floor_passed=False,
            quality_gate_result=QUALITY_QUALIFIED,
        )


def test_economics_comparison_requires_quality_eligible_gate():
    with pytest.raises(ValueError, match="HANDOFF_ECONOMICS_COMPARED_BEFORE_QUALITY"):
        valid_handoff(required_quality_floor_passed=True, quality_gate_result=QUALITY_FLOOR_FAILED)


def test_quality_gate_precedes_economics_on_telemetry_complete():
    artifact = valid_handoff(
        quality_gate_result=QUALITY_FLOOR_FAILED,
        economics_compared=False,
        cost_telemetry_complete=False,
        missingness=["latency_ms_p50", "latency_ms_p95", "token_usage", "monetary_cost_usd", "wall_time_seconds"],
        latency_ms_p50=None,
        latency_ms_p95=None,
        token_usage=None,
        monetary_cost_usd=None,
        wall_time_seconds=None,
    )
    verify_experiment_handoff(artifact)
    artifact["cost"]["cost_telemetry_complete"] = True
    artifact["cost"]["missingness"] = []
    artifact["cost"].update(
        latency_ms_p50=9.5,
        latency_ms_p95=11.0,
        token_usage=500000,
        monetary_cost_usd=1.25,
        wall_time_seconds=90.0,
    )
    artifact["quality_gate"]["economics_compared"] = True
    with pytest.raises(ValueError, match="HANDOFF_QUALITY_GATE_FAILED_BEFORE_COMPARISON"):
        verify_experiment_handoff(artifact)


def test_critical_failures_above_ceiling_reject_eligible_gate():
    with pytest.raises(ValueError, match="HANDOFF_CRITICAL_FAILURES_ABOVE_CEILING"):
        valid_handoff(critical_failure_count=3, critical_failure_ceiling=2)
    artifact = valid_handoff(critical_failure_count=2, critical_failure_ceiling=2)
    verify_experiment_handoff(artifact)


def test_insufficient_cost_evidence_is_valid_non_compared_state():
    artifact = valid_handoff(
        quality_gate_result=INSUFFICIENT_COST_EVIDENCE,
        economics_compared=False,
        cost_telemetry_complete=False,
        missingness=["latency_ms_p50", "latency_ms_p95", "token_usage", "monetary_cost_usd", "wall_time_seconds"],
        latency_ms_p50=None,
        latency_ms_p95=None,
        token_usage=None,
        monetary_cost_usd=None,
        wall_time_seconds=None,
    )
    verify_experiment_handoff(artifact)
    assert artifact["quality_gate"]["economics_compared"] is False


def test_nexus_schema_projection_is_bound():
    artifact = valid_handoff()
    assert artifact["nexus_projection"]["experiment_integrity_schema"] == NEXUS_INTEGRITY_SCHEMA
    assert artifact["nexus_projection"]["economics_schema"] == NEXUS_ECONOMICS_SCHEMA
    assert artifact["nexus_projection"]["deterministically_translatable"] is True
    verify_experiment_handoff(artifact)


def test_nexus_schema_projection_tamper_rejected():
    artifact = valid_handoff()
    artifact["nexus_projection"]["experiment_integrity_schema"] = "nexus.learning_user_defined.v1"
    with pytest.raises(ValueError, match="HANDOFF_NEXUS_INTEGRITY_SCHEMA_INVALID"):
        verify_experiment_handoff(artifact)


def test_usage_counts_must_be_non_negative_integers():
    with pytest.raises(ValueError, match="HANDOFF_MODEL_INVOCATION_COUNT_INVALID"):
        valid_handoff(model_invocation_count=-1)
    with pytest.raises(ValueError, match="HANDOFF_FALLBACK_COUNT_INVALID"):
        valid_handoff(fallback_count=1.5)
    artifact = valid_handoff(model_invocation_count=0, fallback_count=0)
    assert artifact["usage"]["fallback_count"] == 0


def test_provider_identity_required():
    with pytest.raises(ValueError, match="HANDOFF_PROVIDER_IDENTITY_INCOMPLETE"):
        valid_handoff(providers=[{"provider": "openai", "model": "", "model_revision": "x"}])


def test_independence_unit_invalid_rejected():
    with pytest.raises(ValueError, match="HANDOFF_INDEPENDENCE_UNIT_INVALID"):
        valid_handoff(independence_unit="sha256_identity")


def test_empty_population_rejected():
    with pytest.raises(ValueError, match="HANDOFF_EMPTY_POPULATION"):
        valid_handoff(heldout_members=[])


def test_schema_and_ceiling_enforced_on_verify():
    artifact = valid_handoff()
    artifact["claim_ceiling"] = "PRE_REVIEW_ONLY"
    with pytest.raises(ValueError, match="HANDOFF_CLAIM_CEILING_INVALID"):
        verify_experiment_handoff(artifact)
    artifact2 = valid_handoff()
    artifact2["schema"] = "reviewer.semantic_response.v1"
    with pytest.raises(ValueError, match="HANDOFF_SCHEMA_INVALID"):
        verify_experiment_handoff(artifact2)


def test_provider_private_boundary_flags():
    artifact = valid_handoff(provider_private_required=True, public_safe=True)
    verify_experiment_handoff(artifact)
    assert artifact["boundary"]["provider_private_required"] is True
    assert artifact["boundary"]["public_safe"] is True


def test_member_order_independence():
    first = valid_handoff()
    reversed_artifact = valid_handoff(
        calibration_members=[cal_identity(i) for i in range(4, -1, -1)],
        heldout_members=[hold_identity(i) for i in range(4, -1, -1)],
    )
    assert (
        first["populations"]["calibration"]["members_hash"]
        == reversed_artifact["populations"]["calibration"]["members_hash"]
    )
    assert (
        first["populations"]["heldout"]["members_hash"]
        == reversed_artifact["populations"]["heldout"]["members_hash"]
    )


def test_content_sha256_rejections_do_not_mutate(capsys):
    artifact = valid_handoff()
    artifact["policy_freeze"]["frozen_policy"]["policy"]["strategy"] = "mutated"
    with pytest.raises(ValueError, match="HANDOFF_POLICY_HASH_MISMATCH"):
        verify_experiment_handoff(artifact)
    assert artifact["terminal"]["outcome"] == TERMINAL_PASS

def test_nexus_projection_matches_explicit_translators():
    artifact = valid_handoff()
    assert artifact["nexus_projection"]["experiment_integrity_input"] == (
        project_nexus_experiment_integrity_input(artifact)
    )
    assert artifact["nexus_projection"]["quality_workflow_input"] == (
        project_nexus_quality_workflow_row(artifact)
    )
    row = artifact["nexus_projection"]["quality_workflow_input"]
    assert row["workflow_identity"] == "cascade"
    assert row["attempt_count"] == 100
    assert row["qualified_success_count"] == 98


def test_quality_floor_flag_is_derived_from_bound_workflow_counts():
    with pytest.raises(ValueError, match="HANDOFF_QUALITY_FLOOR_FLAG_MISMATCH"):
        valid_handoff(
            attempt_count=100,
            qualified_success_count=80,
            required_quality_floor=0.95,
            required_quality_floor_passed=True,
        )


def test_nexus_projection_tamper_rejected():
    artifact = valid_handoff()
    artifact["nexus_projection"]["quality_workflow_input"]["attempt_count"] = 99
    with pytest.raises(ValueError, match="HANDOFF_NEXUS_ECONOMICS_PROJECTION_MISMATCH"):
        verify_experiment_handoff(artifact)



def _provider_receipt(*, outcome=EFFECT_SUCCEEDED, transport_class="REMOTE_PROVIDER", provider="jev", model="jev-latest", revision="jev-r1"):
    return {
        "receipt_id": "receipt:42:1",
        "effect_identity": "effect:42:1",
        "operation_id": "operation:42:1",
        "transport_class": transport_class,
        "external_effect_started": True,
        "outcome": outcome,
        "observed_provider": provider,
        "observed_model": model,
        "observed_revision": revision,
        "source_receipt_ref": "provider-journal:42:1",
        "source_receipt_sha256": "sha256:" + ("c" * 64),
    }


def test_default_handoff_binds_unknown_origin_and_never_self_promotes_configured_provider():
    artifact = valid_handoff(
        providers=[{
            "provider": "jev",
            "model": "jev-latest",
            "model_revision": "configured-r1",
            "adapter_version": "v1",
            "transport": "api",
        }]
    )
    assert artifact["evidence_origin"]["origin_class"] == UNKNOWN_ORIGIN
    assert artifact["evidence_origin"]["configured_identity"]["model"] == "jev-latest"
    assert artifact["evidence_origin"]["observed_identity"]["model"] is None
    assert artifact["live_provider_claim"]["verified"] is False
    with pytest.raises(ValueError, match="HANDOFF_LIVE_PROVIDER_REMOTE_OBSERVATION_REQUIRED"):
        require_live_provider_observation(artifact)


def test_heuristic_probability_with_configured_jev_remains_simulation_only():
    evidence = build_evidence_origin_compat(
        origin_class=SIMULATION_ONLY,
        requested_provider="jev",
        requested_model="jev-latest",
        configured_provider="jev",
        configured_model="jev-latest",
    )
    artifact = valid_handoff(evidence_origin=evidence)
    assert artifact["live_provider_claim"]["verified"] is False
    with pytest.raises(ValueError, match="HANDOFF_LIVE_PROVIDER_REMOTE_OBSERVATION_REQUIRED"):
        require_live_provider_observation(artifact)


def test_localhost_mock_model_label_cannot_satisfy_live_provider_claim():
    with pytest.raises(ValueError, match="HANDOFF_EVIDENCE_ORIGIN_PRIVATE_RECEIPT_FIELD_FORBIDDEN"):
        build_evidence_origin_compat(
            origin_class=MOCK_TRANSPORT,
            configured_provider="jev",
            configured_model="jev-latest",
            observation_receipt={
                "receipt_id": "mock",
                "effect_identity": "mock-effect",
                "operation_id": "mock-operation",
                "transport_class": "MOCK",
                "external_effect_started": False,
                "outcome": "NOT_STARTED",
                "observed_provider": "jev",
                "observed_model": "jev-latest",
                "observed_revision": None,
                "source_receipt_ref": "localhost:8123",
                "source_receipt_sha256": "sha256:" + ("d" * 64),
                "raw_response": {"model": "jev-latest"},
            },
        )

    evidence = build_evidence_origin_compat(
        origin_class=MOCK_TRANSPORT,
        configured_provider="jev",
        configured_model="jev-latest",
    )
    assert verify_evidence_origin_compat(evidence)["live_provider_observed"] is False


def test_provider_invoked_false_cannot_be_remote_observed():
    receipt = _provider_receipt()
    receipt["external_effect_started"] = False
    with pytest.raises(ValueError, match="HANDOFF_EVIDENCE_ORIGIN_RECEIPT_EFFECT_NOT_STARTED"):
        build_evidence_origin_compat(
            origin_class=REMOTE_PROVIDER_OBSERVED,
            observed_provider="jev",
            observed_model="jev-latest",
            observed_revision="jev-r1",
            external_effect_started=True,
            effect_outcome=EFFECT_SUCCEEDED,
            effect_identity=receipt["effect_identity"],
            operation_id=receipt["operation_id"],
            observation_receipt=receipt,
        )


def test_missing_observed_model_is_never_filled_from_configured_model():
    receipt = _provider_receipt()
    with pytest.raises(ValueError, match="HANDOFF_EVIDENCE_ORIGIN_REMOTE_OBSERVED_IDENTITY_MISSING"):
        build_evidence_origin_compat(
            origin_class=REMOTE_PROVIDER_OBSERVED,
            configured_provider="jev",
            configured_model="jev-latest",
            observed_provider="jev",
            observed_model=None,
            observed_revision="jev-r1",
            external_effect_started=True,
            effect_outcome=EFFECT_SUCCEEDED,
            effect_identity=receipt["effect_identity"],
            operation_id=receipt["operation_id"],
            observation_receipt=receipt,
        )


def test_valid_remote_receipt_supports_bounded_live_observation_projection():
    receipt = _provider_receipt()
    evidence = build_evidence_origin_compat(
        origin_class=REMOTE_PROVIDER_OBSERVED,
        requested_provider="jev",
        requested_model="jev-latest",
        configured_provider="jev",
        configured_model="jev-latest",
        observed_provider="jev",
        observed_model="jev-latest",
        observed_revision="jev-r1",
        external_effect_started=True,
        effect_outcome=EFFECT_SUCCEEDED,
        effect_identity=receipt["effect_identity"],
        operation_id=receipt["operation_id"],
        observation_receipt=receipt,
    )
    artifact = valid_handoff(evidence_origin=evidence)
    assert artifact["live_provider_claim"]["verified"] is True
    assert require_live_provider_observation(artifact)["observed_identity"]["model"] == "jev-latest"
    assert artifact["nexus_projection"]["experiment_integrity_input"]["evidence_origin"] == evidence


def test_outcome_unknown_never_becomes_live_provider_success():
    receipt = _provider_receipt(outcome=EFFECT_OUTCOME_UNKNOWN)
    evidence = build_evidence_origin_compat(
        origin_class=REMOTE_PROVIDER_OBSERVED,
        observed_provider="jev",
        observed_model="jev-latest",
        observed_revision="jev-r1",
        external_effect_started=True,
        effect_outcome=EFFECT_OUTCOME_UNKNOWN,
        effect_identity=receipt["effect_identity"],
        operation_id=receipt["operation_id"],
        observation_receipt=receipt,
    )
    artifact = valid_handoff(evidence_origin=evidence)
    assert artifact["live_provider_claim"]["verified"] is False
    with pytest.raises(ValueError, match="HANDOFF_LIVE_PROVIDER_SUCCESSFUL_OUTCOME_REQUIRED"):
        require_live_provider_observation(artifact)


def test_receipt_substitution_and_tampering_fail_closed():
    receipt = _provider_receipt()
    evidence = build_evidence_origin_compat(
        origin_class=REMOTE_PROVIDER_OBSERVED,
        observed_provider="jev",
        observed_model="jev-latest",
        observed_revision="jev-r1",
        external_effect_started=True,
        effect_outcome=EFFECT_SUCCEEDED,
        effect_identity=receipt["effect_identity"],
        operation_id=receipt["operation_id"],
        observation_receipt=receipt,
    )
    evidence["observation_receipt"]["payload"]["operation_id"] = "operation:substituted"
    with pytest.raises(ValueError, match="HANDOFF_EVIDENCE_ORIGIN_RECEIPT_HASH_MISMATCH"):
        verify_evidence_origin_compat(evidence)


def test_physical_local_model_remains_distinct_from_remote_live_provider():
    receipt = _provider_receipt(
        transport_class="LOCAL_MODEL", provider=None, model="mlx-local", revision=None
    )
    evidence = build_evidence_origin_compat(
        origin_class=PHYSICAL_LOCAL_MODEL,
        observed_model="mlx-local",
        external_effect_started=True,
        effect_outcome=EFFECT_SUCCEEDED,
        effect_identity=receipt["effect_identity"],
        operation_id=receipt["operation_id"],
        observation_receipt=receipt,
    )
    artifact = valid_handoff(evidence_origin=evidence)
    assert artifact["live_provider_claim"]["verified"] is False
    with pytest.raises(ValueError, match="HANDOFF_LIVE_PROVIDER_REMOTE_OBSERVATION_REQUIRED"):
        require_live_provider_observation(artifact)


def test_local_fake_provider_remains_nonphysical():
    evidence = build_evidence_origin_compat(
        origin_class=LOCAL_FAKE_PROVIDER,
        configured_provider="jev",
        configured_model="jev-latest",
    )
    assert verify_evidence_origin_compat(evidence)["live_provider_observed"] is False


def test_negative_terminal_remains_negative_with_valid_remote_provenance():
    receipt = _provider_receipt()
    evidence = build_evidence_origin_compat(
        origin_class=REMOTE_PROVIDER_OBSERVED,
        observed_provider="jev",
        observed_model="jev-latest",
        observed_revision="jev-r1",
        external_effect_started=True,
        effect_outcome=EFFECT_SUCCEEDED,
        effect_identity=receipt["effect_identity"],
        operation_id=receipt["operation_id"],
        observation_receipt=receipt,
    )
    artifact = valid_handoff(terminal_outcome=TERMINAL_NEGATIVE, evidence_origin=evidence)
    assert artifact["terminal"]["negative_terminal"] is True
    assert artifact["nexus_projection"]["negative_terminal_preserved"] is True
    assert artifact["live_provider_claim"]["verified"] is True

