"""Execution script and reporting for Wave 1 Context Economics Matrix.

Runs all 9 architectures under ~200K and ~1M windows and outputs markdown summary tables.
"""

from __future__ import annotations

from reviewer.context_economics.fixtures import SessionFixtureGenerator
from reviewer.context_economics.models import SyntheticRankerMode
from reviewer.context_economics.simulation import (
    ArchitectureRunResult,
    run_session_simulation,
)


def run_full_wave1_matrix() -> list[ArchitectureRunResult]:
    generator = SessionFixtureGenerator(seed="EXP_C_WAVE1_V1")
    turns, anchors, fixture_hash = generator.generate_1000_turn_session()

    architectures = [
        ("No trimming", "no_trimming", None),
        ("Host summary + retrieval", "host_summary", None),
        ("Deterministic pruning", "deterministic_pruning", None),
        ("Semantic retroactive PERFECTISH", "semantic_retroactive", SyntheticRankerMode.PERFECTISH),
        ("Semantic retroactive NOISY", "semantic_retroactive", SyntheticRankerMode.NOISY),
        ("Semantic retroactive NO_VALUE", "semantic_retroactive", SyntheticRankerMode.NO_VALUE),
        ("Semantic write-time PERFECTISH", "semantic_write_time", SyntheticRankerMode.PERFECTISH),
        ("Semantic write-time NOISY", "semantic_write_time", SyntheticRankerMode.NOISY),
        ("Semantic write-time NO_VALUE", "semantic_write_time", SyntheticRankerMode.NO_VALUE),
    ]

    results: list[ArchitectureRunResult] = []

    # Run for 200K window
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
        results.append(res)

    # Run for 1M window
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
        results.append(res)

    return results


def format_markdown_table(results: list[ArchitectureRunResult], window_filter: str = "~200K") -> str:
    filtered = [r for r in results if r.window_class == window_filter]
    header = (
        "| Architecture | Task success | Critical recall | Context tokens | Cache invalidations | Compactions | Total cost (est) | Hard stop |\n"
        "| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |\n"
    )
    rows = []
    for r in filtered:
        row = (
            f"| {r.architecture_name} | {r.task_success_rate:.2f} | {r.critical_anchor_recall:.2f} | "
            f"{r.final_context_tokens:,} | {r.prefix_invalidations} | {r.compaction_count} | "
            f"{r.estimated_total_cost:,.0f} | {'YES' if r.structural_hard_stop else 'NO'} |"
        )
        rows.append(row)
    return header + "\n".join(rows)


if __name__ == "__main__":
    results = run_full_wave1_matrix()
    print("### Window Class: ~200K\n")
    print(format_markdown_table(results, "~200K"))
    print("\n### Window Class: ~1M\n")
    print(format_markdown_table(results, "~1M"))
