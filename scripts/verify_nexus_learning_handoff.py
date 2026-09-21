"""Verify Reviewer experiment handoff projections against canonical Nexus Learning.

This is an explicit cross-repository compatibility check.  It imports the
canonical Nexus Learning contracts from a caller-supplied checkout and proves
that Reviewer projections are accepted as canonical builder/row inputs.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from reviewer.experiment_handoff import (
    CALIBRATED,
    DATA_PURPOSE_EVALUATION_ONLY,
    INDEPENDENCE_UNIT_ROW,
    QUALITY_QUALIFIED,
    TERMINAL_PASS,
    build_experiment_handoff,
    project_nexus_experiment_integrity_input,
    project_nexus_quality_workflow_row,
)


def sample_handoff() -> dict:
    return build_experiment_handoff(
        experiment_id="issue-40-compat",
        experiment_version="v1",
        providers=[
            {
                "provider": "compat-provider",
                "model": "compat-model",
                "model_revision": "compat-revision",
                "adapter_version": "v1",
                "transport": "offline",
            }
        ],
        calibration_members=[
            {"identity": f"cal-{i}", "evidence": {"x": i}} for i in range(4)
        ],
        heldout_members=[
            {"identity": f"hold-{i}", "evidence": {"x": i}} for i in range(4)
        ],
        independence_unit=INDEPENDENCE_UNIT_ROW,
        policy_derivation_ref="compat-calibration",
        frozen_policy={"strategy": "frozen"},
        freeze_generation=1,
        heldout_evaluation_start_generation=2,
        calibration_status=CALIBRATED,
        workflow_identity="compat-workflow",
        workflow_revision="v1",
        task_fingerprint="compat-task-family",
        attempt_count=20,
        qualified_success_count=20,
        semantic_failure_count=0,
        provider_failure_count=0,
        false_allow_count=0,
        human_intervention_count=0,
        required_quality_floor=0.95,
        sealed_input_digest="aa" * 32,
        sealed_truth_digest="bb" * 32,
        terminal_outcome=TERMINAL_PASS,
        model_invocation_count=10,
        provider_invocation_count=10,
        fallback_count=0,
        required_quality_floor_passed=True,
        critical_failure_count=0,
        critical_failure_ceiling=0,
        quality_gate_result=QUALITY_QUALIFIED,
        economics_compared=True,
        cost_telemetry_complete=True,
        latency_ms_p50=10.0,
        latency_ms_p95=12.0,
        token_usage=1000,
        monetary_cost_usd=0.5,
        wall_time_seconds=10.0,
        data_purpose=DATA_PURPOSE_EVALUATION_ONLY,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--nexus-learning", type=Path, required=True)
    args = parser.parse_args()
    learning = args.nexus_learning.resolve()
    if not (learning / "nexus_learning").is_dir():
        raise SystemExit("nexus-learning package directory not found")

    sys.path.insert(0, str(learning))
    from nexus_learning.experiment_integrity import (
        EXPERIMENT_INTEGRITY_SCHEMA,
        build_experiment_integrity,
        validate_experiment_integrity,
    )
    from nexus_learning.effectiveness_measurement import (
        QUALITY_QUALIFIED_ECONOMICS_SCHEMA,
        QualityWorkflowRow,
        compare_workflows_at_required_quality,
    )

    artifact = sample_handoff()

    integrity_input = project_nexus_experiment_integrity_input(artifact)
    integrity = build_experiment_integrity(**integrity_input)
    validate_experiment_integrity(integrity)

    workflow_row = project_nexus_quality_workflow_row(artifact)
    canonical_row = QualityWorkflowRow.from_mapping(workflow_row).to_dict()
    economics = compare_workflows_at_required_quality(
        [workflow_row],
        required_quality_floor=artifact["quality_gate"]["required_quality_floor"],
        critical_failure_ceiling=artifact["quality_gate"]["critical_failure_ceiling"],
        baseline_workflow=workflow_row["workflow_identity"],
        baseline_workflow_revision=workflow_row["workflow_revision"],
    )

    revision = subprocess.check_output(
        ["git", "-C", str(learning), "rev-parse", "HEAD"], text=True
    ).strip()
    result = {
        "nexus_learning_revision": revision,
        "experiment_integrity_schema": integrity["schema"],
        "experiment_integrity_expected_schema": EXPERIMENT_INTEGRITY_SCHEMA,
        "quality_economics_schema": economics["schema"],
        "quality_economics_expected_schema": QUALITY_QUALIFIED_ECONOMICS_SCHEMA,
        "canonical_workflow_identity": canonical_row["workflow_identity"],
        "integrity_projection_accepted": True,
        "quality_workflow_projection_accepted": True,
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
