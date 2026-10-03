"""Run and verify the canonical query-assist paired economics experiment (#45).

Execution and verification script for Issue #45 acceptance closure.
Measures token, call, and wall-time economics across the frozen paired population,
verifies that quality is non-inferior against the quality oracle, and atomically
persists the validated evidence artifact.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from reviewer.query_assist import (
    QUERY_ASSIST_CLAIM_CEILING,
    validate_paired_experiment,
)
from reviewer.query_assist_evaluation import (
    FROZEN_POPULATION_V1,
    ORACLE_ID_V1,
    POPULATION_ID_V1,
    execute_paired_simulation,
    run_paired_evaluation,
    save_experiment_artifact,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        default="evidence/query_assist_paired_economics_v1.json",
        help="Path to write the evidence artifact (default: %(default)s)",
    )
    args = parser.parse_args()

    print("=== Query-Assist Paired Economics Evaluation (Issue #45) ===")
    print(f"Population ID: {POPULATION_ID_V1} ({len(FROZEN_POPULATION_V1)} frozen PRs)")
    print(f"Oracle ID:     {ORACLE_ID_V1}")
    print(f"Claim Ceiling: {QUERY_ASSIST_CLAIM_CEILING}\n")

    # Run paired simulation and display table
    print(
        f"{'PR ID':<38} {'Base In':>8} {'Asst In':>8} {'Tok Saved':>10} {'Recall':>8} {'Base s':>7} {'Asst s':>7}"
    )
    print("-" * 92)

    total_base_in = 0
    total_asst_in = 0
    for fixture in FROZEN_POPULATION_V1:
        res = execute_paired_simulation(fixture)
        b_in = res["baseline"]["input_tokens"]
        a_in = res["assisted"]["input_tokens"]
        saved = b_in - a_in
        recall = res["assisted"]["finding_recall"]
        b_time = res["baseline"]["wall_seconds"]
        a_time = res["assisted"]["wall_seconds"]

        total_base_in += b_in
        total_asst_in += a_in
        print(
            f"{fixture.pr_id:<38} {b_in:>8} {a_in:>8} {saved:>10} {recall:>8.2f} {b_time:>7.3f} {a_time:>7.3f}"
        )

    print("-" * 92)
    tot_saved = total_base_in - total_asst_in
    pct_saved = (tot_saved / total_base_in) * 100.0 if total_base_in else 0
    print(
        f"{'TOTALS':<38} {total_base_in:>8} {total_asst_in:>8} {tot_saved:>10} (saved: {pct_saved:.1f}%)\n"
    )

    # Build and validate experiment
    experiment = run_paired_evaluation()
    issues = validate_paired_experiment(experiment)
    if issues:
        print(f"[ERROR] Experiment validation failed: {issues}", file=sys.stderr)
        return 1

    if not experiment.get("quality_non_inferior"):
        print("[ERROR] Quality inferior gate failed!", file=sys.stderr)
        return 1

    if not experiment.get("savings_claim_allowed"):
        print("[ERROR] Savings claim not allowed!", file=sys.stderr)
        return 1

    # Persist artifact
    out_path = Path(args.output)
    save_experiment_artifact(experiment, target_path=out_path)
    print(f"[OK] Experiment evidence verified and saved to: {out_path}")
    print(f"[OK] Experiment Digest: {experiment['experiment_hash']}")
    print(f"[OK] Quality Non-Inferior: {experiment['quality_non_inferior']}")
    print(f"[OK] Token Savings: {experiment['token_savings']} tokens")
    print(f"[OK] Call Savings: {experiment['call_savings']} calls")
    print(f"[OK] Claim Ceiling: {experiment['claim_ceiling']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
