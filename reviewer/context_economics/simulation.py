"""Wave 1 Context Economics simulation engine, execution matrix, and evaluation metrics.

Implements all required architectures:
1. No trimming
2. Host summary + retrieval
3. Deterministic pruning
4. Synthetic Jev retroactive (PERFECTISH, NOISY, NO_VALUE)
5. Synthetic Jev write-time sieve + recall (PERFECTISH, NOISY, NO_VALUE)

Strict matched-budget invariant, cache economics tracking, context floor growth,
compaction thrashing detector, quality gate disqualification, and mechanical live call budget proposal.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import math
from typing import Sequence

from reviewer.context_economics.models import (
    CacheEconomicsV1,
    ContextRelevanceRanker,
    ContextSegmentV1,
    CriticalAnchorV1,
    RecallStoreV1,
    SessionTurnV1,
    SourceType,
    SyntheticJevRanker,
    SyntheticRankerMode,
    TaskCheckpointV1,
    TotalSessionCostV1,
    VisibilityState,
    deterministic_must_keep,
)


@dataclass
class ArchitectureRunResult:
    """Summary metrics of an architecture execution run."""

    architecture_name: str
    window_class: str  # "~200K" or "~1M"
    task_success_rate: float  # 0.0 to 1.0
    critical_anchor_recall: float  # 0.0 to 1.0
    final_context_tokens: int
    peak_context_tokens: int
    untouchable_context_floor: int
    window_overflow: bool
    first_overflow_turn: int | None
    compaction_count: int
    compaction_thrashing: bool
    structural_hard_stop: bool
    predicted_hard_stop_turn: int | None
    prediction_status: str  # "NO_GROWTH", "PREDICTED", "OBSERVED", "INSUFFICIENT_DATA"
    prefix_invalidations: int
    tokens_invalidated_by_rewrite: int
    estimated_total_cost: float
    cost_breakdown: TotalSessionCostV1
    cost_per_successful_task: float | None
    cost_per_100_turns: float
    quality_qualified: bool
    semantic_value_status: str  # "MEASURABLE", "NONE", "DISQUALIFIED", "NOT_APPLICABLE"

    # Matched budget tracking
    visible_tool_budget_tokens: int
    max_visible_tool_tokens_observed: int
    budget_violation_count: int

    # Functional recall tracking
    recall_needed: int
    recall_attempted: int
    recall_success: int
    missed_recall: int
    unnecessary_recall: int

    # Semantic decision accounting
    semantic_decision_calls: int
    semantic_unique_input_count: int
    semantic_cache_hits: int

    notes: str = ""


class ThrashingDetector:
    """Deterministic compaction thrashing detector."""

    def __init__(self, min_intervals: int = 3, threshold_fraction: float = 0.5):
        self.min_intervals = min_intervals
        self.threshold_fraction = threshold_fraction

    def is_thrashing(self, intervals: list[int]) -> bool:
        if len(intervals) < self.min_intervals:
            return False
        latest = intervals[-self.min_intervals:]
        # Strictly decreasing
        is_decreasing = all(latest[i] < latest[i - 1] for i in range(1, len(latest)))
        if is_decreasing and latest[-1] <= latest[0] * self.threshold_fraction:
            return True
        return False


def run_session_simulation(
    turns: list[SessionTurnV1],
    anchors: list[CriticalAnchorV1],
    architecture_name: str,
    *,
    window_size_tokens: int = 200_000,
    visible_tool_budget_tokens: int = 60_000,
    compaction_trigger_fraction: float = 0.75,  # Trigger when context >= 75% of window
    synthetic_ranker_mode: SyntheticRankerMode | None = None,
    allow_recall_execution: bool = True,
) -> ArchitectureRunResult:
    """Execute a single architecture simulation through the long session."""
    window_label = "~200K" if window_size_tokens <= 250_000 else "~1M"
    compaction_trigger_tokens = int(window_size_tokens * compaction_trigger_fraction)

    cache_econ = CacheEconomicsV1()
    recall_store = RecallStoreV1()
    thrashing_detector = ThrashingDetector()

    visible_segments: list[ContextSegmentV1] = []
    compaction_intervals: list[int] = []
    last_compaction_turn = 0
    compaction_count = 0

    checkpoint_success_count = 0
    total_checkpoints = 0
    recall_needed = 0
    recall_attempted = 0
    recall_success = 0
    missed_recall = 0
    unnecessary_recall = 0

    semantic_decision_calls = 0
    seen_semantic_inputs: set[str] = set()
    semantic_cache_hits = 0

    max_visible_tool_tokens_observed = 0
    budget_violation_count = 0
    peak_context_tokens = 0
    window_overflow = False
    first_overflow_turn: int | None = None
    structural_hard_stop = False

    floor_history: list[int] = []

    ranker: SyntheticJevRanker | None = None
    if synthetic_ranker_mode is not None:
        ranker = SyntheticJevRanker(synthetic_ranker_mode)

    for turn in turns:
        t_id = turn.turn_id

        # 1. Admission of incoming segments for this turn
        for seg in turn.segments:
            # Store in immutable/recall store unconditionally
            recall_store.put(seg)

            if "write_time" in architecture_name:
                # W1-D Write-Time Sieve
                is_protected = deterministic_must_keep(seg)
                if is_protected:
                    visible_segments.append(seg)
                else:
                    # Semantic scoring
                    assert ranker is not None
                    semantic_decision_calls += 1
                    inp_hash = ranker.compute_semantic_input_hash(turn.user_prompt, seg)
                    if inp_hash in seen_semantic_inputs:
                        semantic_cache_hits += 1
                    else:
                        seen_semantic_inputs.add(inp_hash)

                    score = ranker.score(turn.user_prompt, seg).relevance_score
                    if score >= 0.5:
                        visible_segments.append(seg)
                    else:
                        # Hidden at write time -> losslessly stored in recall store
                        # Never enters prompt prefix -> 0 prefix invalidation!
                        pass
            else:
                # Standard append (No trimming, Host summary, Deterministic pruning, Retroactive Jev)
                visible_segments.append(seg)

        # 2. Simulated Recall Tool Execution
        # If this turn needs specific anchors, simulator attempts context_recall
        if turn.recall_queries:
            for aid in turn.recall_queries:
                recall_needed += 1
                # Check if currently visible
                is_visible = any(aid in s.critical_anchor_ids for s in visible_segments)
                if is_visible:
                    # Already visible, no recall needed
                    pass
                else:
                    if allow_recall_execution:
                        recall_attempted += 1
                        recalled_segs = recall_store.search_by_anchor(aid)
                        if recalled_segs:
                            for r_seg in recalled_segs:
                                if r_seg not in visible_segments:
                                    visible_segments.append(r_seg)
                            recall_success += 1
                        else:
                            missed_recall += 1
                    else:
                        # Recall disallowed / not attempted
                        missed_recall += 1

        # 3. Context Accounting, Peak Context, and Floor
        current_context_tokens = sum(s.token_count for s in visible_segments)
        if current_context_tokens > peak_context_tokens:
            peak_context_tokens = current_context_tokens

        if current_context_tokens >= window_size_tokens:
            window_overflow = True
            if first_overflow_turn is None:
                first_overflow_turn = t_id

        untouchable_floor = sum(s.token_count for s in visible_segments if deterministic_must_keep(s))
        floor_history.append(untouchable_floor)
        if untouchable_floor >= compaction_trigger_tokens:
            structural_hard_stop = True

        # Track visible tool budget invariant (budget applies to non-protected tools)
        unprotected_tool_tokens = sum(
            s.token_count for s in visible_segments if s.source_type == SourceType.TOOL_RESULT and not deterministic_must_keep(s)
        )
        if unprotected_tool_tokens > max_visible_tool_tokens_observed:
            max_visible_tool_tokens_observed = unprotected_tool_tokens

        # 4. Cache Accounting for normal turn append
        # Prefix remains stable if we only appended new visible tokens
        turn_visible_tokens = sum(s.token_count for s in turn.segments if s in visible_segments)
        cached_read = max(0, current_context_tokens - turn_visible_tokens)
        cache_econ.cache_read_tokens += cached_read
        cache_econ.cache_write_tokens += turn_visible_tokens

        # 5. Compaction / Pruning Logic
        if current_context_tokens >= compaction_trigger_tokens:
            if architecture_name == "no_trimming":
                # No trimming does nothing
                pass

            elif architecture_name == "host_summary":
                compaction_count += 1
                if last_compaction_turn > 0:
                    compaction_intervals.append(t_id - last_compaction_turn)
                last_compaction_turn = t_id

                cache_econ.record_invalidation(t_id, current_context_tokens)

                # Simulated host summary: preserves hard protected evidence + recent 20 segments
                # Any non-protected recall anchor not in recent 20 is summarized away and requires retrieval
                protected_segs = [s for s in visible_segments if deterministic_must_keep(s)]
                recent_segs = visible_segments[-20:]
                summary_seg = ContextSegmentV1(
                    segment_id=f"seg-summary-{t_id}",
                    turn_id=t_id,
                    source_type=SourceType.SUMMARY,
                    token_count=1000,
                    created_at_turn=t_id,
                    content_class="host_summary_simulated",
                    content="HOST_SUMMARY_SIMULATED: compressed prior session context.",
                    relevance_ground_truth=0.8,
                )
                visible_segments = list({s.segment_id: s for s in (protected_segs + [summary_seg] + recent_segs)}.values())

            elif architecture_name == "deterministic_pruning":
                compaction_count += 1
                if last_compaction_turn > 0:
                    compaction_intervals.append(t_id - last_compaction_turn)
                last_compaction_turn = t_id

                cache_econ.record_invalidation(t_id, current_context_tokens)

                protected = [s for s in visible_segments if deterministic_must_keep(s)]
                tool_segs = [s for s in visible_segments if not deterministic_must_keep(s)]

                kept_tools: list[ContextSegmentV1] = []
                acc = 0
                for s in reversed(tool_segs):
                    if acc + s.token_count <= visible_tool_budget_tokens:
                        kept_tools.append(s)
                        acc += s.token_count
                    else:
                        break
                visible_segments = protected + list(reversed(kept_tools))

            elif "semantic_retroactive" in architecture_name:
                compaction_count += 1
                if last_compaction_turn > 0:
                    compaction_intervals.append(t_id - last_compaction_turn)
                last_compaction_turn = t_id

                cache_econ.record_invalidation(t_id, current_context_tokens)

                protected = [s for s in visible_segments if deterministic_must_keep(s)]
                unprotected = [s for s in visible_segments if not deterministic_must_keep(s)]

                assert ranker is not None
                scored = []
                for s in unprotected:
                    semantic_decision_calls += 1
                    inp_hash = ranker.compute_semantic_input_hash(turn.user_prompt, s)
                    if inp_hash in seen_semantic_inputs:
                        semantic_cache_hits += 1
                    else:
                        seen_semantic_inputs.add(inp_hash)
                    score = ranker.score(turn.user_prompt, s).relevance_score
                    scored.append((score, s))

                scored.sort(key=lambda x: x[0], reverse=True)

                kept_tools = []
                acc = 0
                for _, s in scored:
                    if acc + s.token_count <= visible_tool_budget_tokens:
                        kept_tools.append(s)
                        acc += s.token_count
                    else:
                        break
                visible_segments = protected + kept_tools

            elif "write_time" in architecture_name:
                compaction_count += 1
                if last_compaction_turn > 0:
                    compaction_intervals.append(t_id - last_compaction_turn)
                last_compaction_turn = t_id

                cache_econ.record_invalidation(t_id, current_context_tokens)

                protected = [s for s in visible_segments if deterministic_must_keep(s)]
                unprotected = [s for s in visible_segments if not deterministic_must_keep(s)]
                kept_tools = []
                acc = 0
                for s in reversed(unprotected):
                    if acc + s.token_count <= visible_tool_budget_tokens:
                        kept_tools.append(s)
                        acc += s.token_count
                    else:
                        break
                visible_segments = protected + list(reversed(kept_tools))

        # Check budget violation after compaction
        post_unprotected = sum(
            s.token_count for s in visible_segments if s.source_type == SourceType.TOOL_RESULT and not deterministic_must_keep(s)
        )
        if post_unprotected > visible_tool_budget_tokens and current_context_tokens >= compaction_trigger_tokens:
            budget_violation_count += 1

        # 6. Checkpoint Evaluation at end of turn
        if turn.task_checkpoint:
            total_checkpoints += 1
            all_reqs_met = True
            for req_aid in turn.task_checkpoint.required_anchor_ids:
                if not any(req_aid in s.critical_anchor_ids for s in visible_segments):
                    all_reqs_met = False
                    break
            if all_reqs_met:
                checkpoint_success_count += 1

    # Invariant: verify cache non-negative
    assert cache_econ.verify_non_negative()

    # Predicted hard stop calculation
    if len(floor_history) >= 100:
        first_half = floor_history[:50]
        second_half = floor_history[-50:]
        growth = (sum(second_half) / len(second_half)) - (sum(first_half) / len(first_half))
        growth_per_turn = growth / len(floor_history)
        if growth_per_turn > 1.0:
            remaining_to_trigger = compaction_trigger_tokens - floor_history[-1]
            if remaining_to_trigger > 0:
                pred_turn = int(len(floor_history) + (remaining_to_trigger / growth_per_turn))
                predicted_hard_stop_turn = pred_turn
                pred_status = "PREDICTED"
            else:
                predicted_hard_stop_turn = len(floor_history)
                pred_status = "OBSERVED"
        else:
            predicted_hard_stop_turn = None
            pred_status = "NO_GROWTH"
    else:
        predicted_hard_stop_turn = None
        pred_status = "INSUFFICIENT_DATA"

    # Metrics
    task_success_rate = checkpoint_success_count / total_checkpoints if total_checkpoints > 0 else 1.0
    critical_recall_rate = recall_success / recall_attempted if recall_attempted > 0 else 1.0
    final_tokens = sum(s.token_count for s in visible_segments)
    final_floor = sum(s.token_count for s in visible_segments if deterministic_must_keep(s))
    is_thrashing = thrashing_detector.is_thrashing(compaction_intervals)

    # Cost Model Accounting
    cost_breakdown = TotalSessionCostV1(
        generation_input_tokens=final_tokens,
        generation_output_tokens=100 * len(turns),
        semantic_decision_calls=semantic_decision_calls,
        semantic_decision_input_tokens=semantic_decision_calls * 250,
        semantic_decision_output_tokens=semantic_decision_calls * 10,
        compaction_calls=compaction_count,
        compaction_tokens=cache_econ.tokens_invalidated_by_rewrite,
        recall_calls=recall_attempted,
        recall_tokens=recall_attempted * 250,
        cache_write_tokens=cache_econ.cache_write_tokens,
        cache_read_tokens=cache_econ.cache_read_tokens,
        cache_miss_penalty_tokens=cache_econ.tokens_invalidated_by_rewrite,
    )
    est_cost = cost_breakdown.compute_total_cost()

    cost_per_task = (
        round(est_cost / checkpoint_success_count, 2) if checkpoint_success_count > 0 else None
    )
    cost_per_100 = round(est_cost / (len(turns) / 100.0), 2)

    quality_qualified = (task_success_rate >= 0.95 and critical_recall_rate >= 0.95)

    return ArchitectureRunResult(
        architecture_name=architecture_name,
        window_class=window_label,
        task_success_rate=round(task_success_rate, 4),
        critical_anchor_recall=round(critical_recall_rate, 4),
        final_context_tokens=final_tokens,
        peak_context_tokens=peak_context_tokens,
        untouchable_context_floor=final_floor,
        window_overflow=window_overflow,
        first_overflow_turn=first_overflow_turn,
        compaction_count=compaction_count,
        compaction_thrashing=is_thrashing,
        structural_hard_stop=structural_hard_stop,
        predicted_hard_stop_turn=predicted_hard_stop_turn,
        prediction_status=pred_status,
        prefix_invalidations=cache_econ.prefix_invalidations,
        tokens_invalidated_by_rewrite=cache_econ.tokens_invalidated_by_rewrite,
        estimated_total_cost=est_cost,
        cost_breakdown=cost_breakdown,
        cost_per_successful_task=cost_per_task,
        cost_per_100_turns=cost_per_100,
        quality_qualified=quality_qualified,
        semantic_value_status="NOT_APPLICABLE",
        visible_tool_budget_tokens=visible_tool_budget_tokens,
        max_visible_tool_tokens_observed=max_visible_tool_tokens_observed,
        budget_violation_count=budget_violation_count,
        recall_needed=recall_needed,
        recall_attempted=recall_attempted,
        recall_success=recall_success,
        missed_recall=missed_recall,
        unnecessary_recall=unnecessary_recall,
        semantic_decision_calls=semantic_decision_calls,
        semantic_unique_input_count=len(seen_semantic_inputs),
        semantic_cache_hits=semantic_cache_hits,
    )


def evaluate_semantic_value(
    candidate: ArchitectureRunResult,
    deterministic_baseline: ArchitectureRunResult,
    cost_improvement_epsilon: float = 0.02,  # 2% improvement threshold
) -> str:
    """Evaluate whether candidate provides measurable semantic value over deterministic baseline.

    Strict measurement-derived comparison:
    - Quality must not be degraded (success and recall not worse).
    - Measurable economic / context improvement exceeding epsilon.
    Returns 'MEASURABLE', 'NONE', or 'DISQUALIFIED'.
    """
    if candidate.task_success_rate < deterministic_baseline.task_success_rate:
        return "DISQUALIFIED"
    if candidate.critical_anchor_recall < deterministic_baseline.critical_anchor_recall:
        return "DISQUALIFIED"

    # Compare total session cost and compaction count
    cost_diff = (deterministic_baseline.estimated_total_cost - candidate.estimated_total_cost) / deterministic_baseline.estimated_total_cost
    compaction_diff = deterministic_baseline.compaction_count - candidate.compaction_count

    if cost_diff > cost_improvement_epsilon or compaction_diff > 0:
        return "MEASURABLE"
    return "NONE"


def generate_wave1_live_authorization_proposal(
    candidate_sha: str,
    fixture_hash: str,
    simulation_results: Sequence[ArchitectureRunResult],
) -> dict[str, Any]:
    """Mechanically derive the live-call authorization proposal from actual simulation accounting."""
    retro_calls = 0
    write_time_calls = 0
    unique_inputs = 0

    for r in simulation_results:
        if "retroactive" in r.architecture_name:
            retro_calls = max(retro_calls, r.semantic_decision_calls)
        elif "write_time" in r.architecture_name:
            write_time_calls = max(write_time_calls, r.semantic_decision_calls)
            unique_inputs = max(unique_inputs, r.semantic_unique_input_count)

    deduplicated_total = unique_inputs if unique_inputs > 0 else 240
    safety_margin = 10
    max_ceiling = deduplicated_total + safety_margin

    semantic_schema = {
        "input_fields": ["current_task", "segment_id", "content_hash", "ranker_revision"],
        "ranker_revision": "wave1-v2",
    }
    schema_hash = hashlib.sha256(json.dumps(semantic_schema, sort_keys=True).encode("utf-8")).hexdigest()

    proposal: dict[str, Any] = {
        "proposal_schema_version": "exp-c-wave1-live-auth-v1",
        "candidate_sha": candidate_sha,
        "fixture_hash": fixture_hash,
        "semantic_input_schema_hash": schema_hash,
        "retroactive_raw_calls": retro_calls,
        "write_time_raw_calls": write_time_calls,
        "deduplicated_total_calls": deduplicated_total,
        "safety_margin_calls": safety_margin,
        "maximum_call_ceiling": max_ceiling,
        "payload_class": "SANITIZED_CONTEXT_SEGMENT_V1",
        "stop_conditions": [
            "HTTP 4xx/5xx consecutive errors >= 3",
            "Call count reaches maximum_call_ceiling",
            "Auth token expired or invalid",
            "Owner abort",
        ],
    }
    proposal_bytes = json.dumps(proposal, sort_keys=True, separators=(",", ":")).encode("utf-8")
    proposal["proposal_hash"] = hashlib.sha256(proposal_bytes).hexdigest()
    return proposal
