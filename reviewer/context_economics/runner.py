"""Execution script and reporting for Wave 1 Context Economics Matrix.

Runs all 9 architectures under ~200K and ~1M windows and outputs markdown summary tables.
Derives semantic value via evaluate_semantic_value against deterministic baseline.
"""

from __future__ import annotations

import subprocess

from reviewer.context_economics.fixtures import SessionFixtureGenerator
from reviewer.context_economics.models import ArchitectureId, SyntheticRankerMode
from reviewer.context_economics.simulation import (
    ArchitectureRunResult,
    evaluate_semantic_value,
    generate_wave1_live_authorization_proposal,
    run_session_simulation,
)


def _get_current_git_sha() -> str:
    try:
        out = subprocess.check_output(["git", "rev-parse", "HEAD"], stderr=subprocess.DEVNULL)
        return out.decode("utf-8").strip()
    except Exception:
        return "UNKNOWN_CANDIDATE"


def run_full_wave1_matrix(candidate_sha: str | None = None) -> tuple[list[ArchitectureRunResult], dict]:
    resolved_sha = candidate_sha or _get_current_git_sha()
    generator = SessionFixtureGenerator(seed="EXP_C_WAVE1_V2")
    turns, anchors, fixture_hash = generator.generate_1000_turn_session()

    architectures = [
        ("No trimming", ArchitectureId.NO_TRIMMING, None),
        ("Host summary + retrieval", ArchitectureId.HOST_SUMMARY, None),
        ("Deterministic pruning", ArchitectureId.DETERMINISTIC_PRUNING, None),
        ("Semantic retroactive PERFECTISH", ArchitectureId.SEMANTIC_RETROACTIVE_PERFECTISH, SyntheticRankerMode.PERFECTISH),
        ("Semantic retroactive NOISY", ArchitectureId.SEMANTIC_RETROACTIVE_NOISY, SyntheticRankerMode.NOISY),
        ("Semantic retroactive NO_VALUE", ArchitectureId.SEMANTIC_RETROACTIVE_NO_VALUE, SyntheticRankerMode.NO_VALUE),
        ("Semantic write-time PERFECTISH", ArchitectureId.SEMANTIC_WRITE_TIME_PERFECTISH, SyntheticRankerMode.PERFECTISH),
        ("Semantic write-time NOISY", ArchitectureId.SEMANTIC_WRITE_TIME_NOISY, SyntheticRankerMode.NOISY),
        ("Semantic write-time NO_VALUE", ArchitectureId.SEMANTIC_WRITE_TIME_NO_VALUE, SyntheticRankerMode.NO_VALUE),
    ]

    results: list[ArchitectureRunResult] = []

    # Run for 200K window
    det_200k_res: ArchitectureRunResult | None = None
    for display_name, arch_key, ranker_mode in architectures:
        res = run_session_simulation(
            turns,
            anchors,
            arch_key,
            window_size_tokens=200_000,
            visible_tool_budget_tokens=60_000,
            synthetic_ranker_mode=ranker_mode,
        )
        res.architecture_name = display_name
        if arch_key == ArchitectureId.DETERMINISTIC_PRUNING:
            det_200k_res = res
        results.append(res)

    # Evaluate semantic value for 200K
    assert det_200k_res is not None
    semantic_arch_ids = {
        ArchitectureId.SEMANTIC_RETROACTIVE_PERFECTISH,
        ArchitectureId.SEMANTIC_RETROACTIVE_NOISY,
        ArchitectureId.SEMANTIC_RETROACTIVE_NO_VALUE,
        ArchitectureId.SEMANTIC_WRITE_TIME_PERFECTISH,
        ArchitectureId.SEMANTIC_WRITE_TIME_NOISY,
        ArchitectureId.SEMANTIC_WRITE_TIME_NO_VALUE,
    }
    for r in results:
        if r.window_class == "~200K" and r.architecture_id in semantic_arch_ids:
            r.semantic_value_status = evaluate_semantic_value(r, det_200k_res)

    # Run for 1M window
    det_1m_res: ArchitectureRunResult | None = None
    results_1m_start = len(results)
    for display_name, arch_key, ranker_mode in architectures:
        res = run_session_simulation(
            turns,
            anchors,
            arch_key,
            window_size_tokens=1_000_000,
            visible_tool_budget_tokens=60_000,
            synthetic_ranker_mode=ranker_mode,
        )
        res.architecture_name = display_name
        if arch_key == ArchitectureId.DETERMINISTIC_PRUNING:
            det_1m_res = res
        results.append(res)

    # Evaluate semantic value for 1M
    assert det_1m_res is not None
    for r in results[results_1m_start:]:
        if r.window_class == "~1M" and r.architecture_id in semantic_arch_ids:
            r.semantic_value_status = evaluate_semantic_value(r, det_1m_res)

    # Generate proposal
    proposal = generate_wave1_live_authorization_proposal(
        candidate_sha=resolved_sha,
        fixture_hash=fixture_hash,
        simulation_results=results,
    )

    return results, proposal


def format_markdown_table(results: list[ArchitectureRunResult], window_filter: str = "~200K") -> str:
    filtered = [r for r in results if r.window_class == window_filter]
    header = (
        "| Architecture | Task success | Critical recall | Context peak / final | Cache inv / tokens | Compactions | Cost (est) | Hard stop | Semantic value |\n"
        "| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |\n"
    )
    rows = []
    for r in filtered:
        overflow_flag = f"OVERFLOW (turn {r.first_overflow_turn})" if r.window_overflow else ("YES" if r.structural_hard_stop else "NO")
        tokens_str = f"{r.peak_context_tokens:,} / {r.final_context_tokens:,}"
        cache_str = f"{r.prefix_invalidations} ({r.tokens_invalidated_by_rewrite:,})"
        row = (
            f"| {r.architecture_name} | {r.task_success_rate:.2f} | {r.critical_anchor_recall:.2f} | "
            f"{tokens_str} | {cache_str} | {r.compaction_count} | "
            f"{r.estimated_total_cost:,.0f} | {overflow_flag} | {r.semantic_value_status} |"
        )
        rows.append(row)
    return header + "\n".join(rows)


if __name__ == "__main__":
    results, proposal = run_full_wave1_matrix()
    print("### Window Class: ~200K\n")
    print(format_markdown_table(results, "~200K"))
    print("\n### Window Class: ~1M\n")
    print(format_markdown_table(results, "~1M"))
    print("\n### Live Authorization Proposal:")
    import json
    print(json.dumps(proposal, indent=2))
