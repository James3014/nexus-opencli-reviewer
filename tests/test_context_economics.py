from __future__ import annotations

import copy
import pytest

from reviewer.context_economics.fixtures import SessionFixtureGenerator
from reviewer.context_economics.models import (
    AnchorType,
    ArchitectureId,
    CacheEconomicsV1,
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
from reviewer.context_economics.simulation import (
    ArchitectureRunResult,
    ThrashingDetector,
    evaluate_semantic_value,
    generate_wave1_live_authorization_proposal,
    run_session_simulation,
)


def _sample_segment(content: str = "some tool log", is_tool: bool = True) -> ContextSegmentV1:
    return ContextSegmentV1(
        segment_id="seg-test-1",
        turn_id=1,
        source_type=SourceType.TOOL_RESULT if is_tool else SourceType.USER,
        token_count=100,
        created_at_turn=1,
        content_class="test",
        content=content,
        relevance_ground_truth=0.5,
    )


def test_deterministic_must_keep_protections() -> None:
    # 1. User messages unconditionally protected
    assert deterministic_must_keep(_sample_segment("hello", is_tool=False)) is True

    # 2. Hard protected critical anchors explicitly protected
    seg_hard_anchor = ContextSegmentV1(
        segment_id="seg-hard",
        turn_id=1,
        source_type=SourceType.TOOL_RESULT,
        token_count=50,
        created_at_turn=1,
        content_class="test",
        content="normal looking content with hard anchor",
        relevance_ground_truth=0.1,
        critical_anchor_ids=("anchor-hard-1",),
        has_hard_protected_anchor=True,
    )
    assert deterministic_must_keep(seg_hard_anchor) is True

    # 2b. Recall-required critical anchors NOT protected by deterministic_must_keep alone
    seg_recall_anchor = ContextSegmentV1(
        segment_id="seg-recall",
        turn_id=1,
        source_type=SourceType.TOOL_RESULT,
        token_count=50,
        created_at_turn=1,
        content_class="test",
        content="normal looking content with recall anchor",
        relevance_ground_truth=0.1,
        critical_anchor_ids=("anchor-recall-1",),
        has_hard_protected_anchor=False,
    )
    assert deterministic_must_keep(seg_recall_anchor) is False

    # 3. Regex matches
    assert deterministic_must_keep(_sample_segment("Build ERROR: failed")) is True
    assert deterministic_must_keep(_sample_segment("Assertion FAILED")) is True
    assert deterministic_must_keep(_sample_segment("Traceback (most recent call last)")) is True
    assert deterministic_must_keep(_sample_segment("file.py:42: in test_foo")) is True
    assert deterministic_must_keep(_sample_segment("command exited with exit code 1")) is True
    assert deterministic_must_keep(_sample_segment("commit 7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a")) is True
    assert deterministic_must_keep(_sample_segment("operation op-canary-1234")) is True
    assert deterministic_must_keep(_sample_segment("task task-abc-987")) is True
    assert deterministic_must_keep(_sample_segment("ROOT_CAUSE: socket leak")) is True

    # 4. Normal tool log not protected
    assert deterministic_must_keep(_sample_segment("pytest running: 10 passed in 0.1s")) is False


def test_storage_losslessness_in_recall_store() -> None:
    store = RecallStoreV1()
    seg = _sample_segment("very important hidden log")
    store.put(seg)

    # Retrieval by id
    retrieved = store.get(seg.segment_id)
    assert retrieved is not None
    assert store.verify_storage_losslessness(seg) is True

    # Retrieval by anchor
    seg_with_anchor = ContextSegmentV1(
        segment_id="seg-anchor-1",
        turn_id=5,
        source_type=SourceType.TOOL_RESULT,
        token_count=100,
        created_at_turn=5,
        content_class="test",
        content="anchor content",
        relevance_ground_truth=1.0,
        critical_anchor_ids=("aid-100",),
    )
    store.put(seg_with_anchor)
    by_anchor = store.search_by_anchor("aid-100")
    assert len(by_anchor) == 1
    assert by_anchor[0].segment_id == "seg-anchor-1"


def test_thrashing_detector_discrimination() -> None:
    detector = ThrashingDetector(min_intervals=3, threshold_fraction=0.5)

    # Strictly decreasing with final <= 0.5 * first -> THRASHING
    assert detector.is_thrashing([100, 80, 40]) is True
    assert detector.is_thrashing([200, 150, 100, 50]) is True

    # Steady or increasing -> NOT THRASHING
    assert detector.is_thrashing([100, 100, 100]) is False
    assert detector.is_thrashing([50, 60, 70]) is False
    assert detector.is_thrashing([100, 90, 80]) is False  # 80 > 100 * 0.5


def test_synthetic_jev_ranker_modes() -> None:
    p_ranker = SyntheticJevRanker(SyntheticRankerMode.PERFECTISH)
    n_ranker = SyntheticJevRanker(SyntheticRankerMode.NOISY)
    zero_ranker = SyntheticJevRanker(SyntheticRankerMode.NO_VALUE)

    seg_high = ContextSegmentV1(
        segment_id="s1",
        turn_id=1,
        source_type=SourceType.TOOL_RESULT,
        token_count=10,
        created_at_turn=1,
        content_class="c",
        content="c",
        relevance_ground_truth=0.9,
    )
    seg_low = ContextSegmentV1(
        segment_id="s2",
        turn_id=1,
        source_type=SourceType.TOOL_RESULT,
        token_count=10,
        created_at_turn=1,
        content_class="c",
        content="c",
        relevance_ground_truth=0.1,
    )

    # Perfectish discriminates
    assert p_ranker.score("task", seg_high).relevance_score > p_ranker.score("task", seg_low).relevance_score

    # No-value returns constant 0.5 for all
    assert zero_ranker.score("task", seg_high).relevance_score == 0.5
    assert zero_ranker.score("task", seg_low).relevance_score == 0.5


def test_fixture_determinism_and_reproducibility() -> None:
    gen1 = SessionFixtureGenerator(seed="EXP_C_WAVE1_V1")
    t1, a1, h1 = gen1.generate_1000_turn_session()

    gen2 = SessionFixtureGenerator(seed="EXP_C_WAVE1_V1")
    t2, a2, h2 = gen2.generate_1000_turn_session()

    assert h1 == h2
    assert len(t1) == 1000
    assert len(t2) == 1000
    assert len(a1) == 20
    assert len(a2) == 20
    assert t1[10].segments[0].content == t2[10].segments[0].content


# --- Mutation / Negative Controls M1 - M8 ---


def test_m1_negative_control_semantic_ranker_cannot_hide_protected_evidence() -> None:
    """M1: Even if ranker score is 0.0, deterministic_must_keep prevents hiding."""
    seg_err = ContextSegmentV1(
        segment_id="seg-err",
        turn_id=1,
        source_type=SourceType.TOOL_RESULT,
        token_count=10,
        created_at_turn=1,
        content_class="c",
        content="ERROR: critical system failure",
        relevance_ground_truth=0.0,  # ground truth 0.0
    )
    assert deterministic_must_keep(seg_err) is True


def test_m2_negative_control_matched_budget_invariant() -> None:
    """M2: In simulation, both deterministic pruning and semantic retroactive must enforce the exact matched budget.

    If one architecture were evaluated with 90K and the other with 60K, the harness must detect
    the budget asymmetry.
    """
    gen = SessionFixtureGenerator(seed="TEST_SEED_M2")
    turns, anchors, _ = gen.generate_1000_turn_session()

    # Matched run with 60K budget
    res_det_60k = run_session_simulation(turns[:50], anchors, ArchitectureId.DETERMINISTIC_PRUNING, visible_tool_budget_tokens=60_000)
    res_sem_60k = run_session_simulation(
        turns[:50],
        anchors,
        ArchitectureId.SEMANTIC_RETROACTIVE_PERFECTISH,
        visible_tool_budget_tokens=60_000,
        synthetic_ranker_mode=SyntheticRankerMode.PERFECTISH,
    )
    # Both observe exact same configured visible tool budget
    assert res_det_60k.visible_tool_budget_tokens == res_sem_60k.visible_tool_budget_tokens == 60_000
    assert res_det_60k.budget_violation_count == 0
    assert res_sem_60k.budget_violation_count == 0

    # Asymmetric run: if semantic were granted 90K while baseline has 60K, budgets do not match
    res_sem_90k = run_session_simulation(
        turns[:50],
        anchors,
        ArchitectureId.SEMANTIC_RETROACTIVE_PERFECTISH,
        visible_tool_budget_tokens=90_000,
        synthetic_ranker_mode=SyntheticRankerMode.PERFECTISH,
    )
    assert res_det_60k.visible_tool_budget_tokens != res_sem_90k.visible_tool_budget_tokens


def test_m3_negative_control_hidden_store_loss_detected() -> None:
    """M3: If store fails to return segment, storage losslessness fails."""
    store = RecallStoreV1()
    seg = _sample_segment("some log")
    # Not put into store
    assert store.verify_storage_losslessness(seg) is False


def test_m4_negative_control_missed_recall_fails_checkpoint() -> None:
    """M4: When an anchor is hidden at write time and not recalled when needed, checkpoint and availability fail."""
    # Segment with critical anchor hidden by write-time sieve (relevance = 0.1, not protected)
    aid = "aid-test-m4"
    seg = ContextSegmentV1(
        segment_id="seg-m4",
        turn_id=1,
        source_type=SourceType.TOOL_RESULT,
        token_count=100,
        created_at_turn=1,
        content_class="test",
        content="some non-protected output containing anchor",
        relevance_ground_truth=0.1,
        critical_anchor_ids=(aid,),
        has_hard_protected_anchor=False,
    )
    chk = TaskCheckpointV1("chk-m4", 2, (aid,), "verify anchor aid-test-m4")
    turn1 = SessionTurnV1(1, "task", [seg])
    # Turn 2 needs the anchor but recall is disallowed or fails
    turn2 = SessionTurnV1(2, "task", [_sample_segment("turn 2 log")], task_checkpoint=chk, recall_queries=[aid])

    res = run_session_simulation(
        [turn1, turn2],
        [],
        ArchitectureId.SEMANTIC_WRITE_TIME_PERFECTISH,
        synthetic_ranker_mode=SyntheticRankerMode.PERFECTISH,
        allow_recall_execution=False,  # Disallow recall -> simulated missed recall
    )
    assert res.task_success_rate == 0.0
    assert res.critical_information_available_rate == 0.0
    assert res.missed_recall == 1
    assert res.quality_qualified is False


def test_m5_negative_control_cache_rewrite_invalidation_recorded() -> None:
    """M5: Compaction rewrites must record non-zero prefix invalidations."""
    econ = CacheEconomicsV1()
    econ.record_invalidation(current_turn=50, invalidated_tokens=150_000)
    assert econ.prefix_invalidations == 1
    assert econ.tokens_invalidated_by_rewrite == 150_000
    assert econ.turns_between_invalidations == [50]


def test_m6_negative_control_low_recall_disqualifies_savings() -> None:
    """M6: If recall is below 0.95, quality gate disqualifies savings."""
    chk = TaskCheckpointV1("chk-1", 1, ("missing-aid",), "desc")
    turn = SessionTurnV1(1, "p", [_sample_segment("log")], task_checkpoint=chk)
    res = run_session_simulation([turn], [], "deterministic_pruning")
    assert res.quality_qualified is False


def test_m7_negative_control_decreasing_intervals_must_detect_thrashing() -> None:
    """M7: Decreasing compaction intervals must trigger thrashing detector."""
    detector = ThrashingDetector(min_intervals=3, threshold_fraction=0.5)
    # [100, 70, 40]
    assert detector.is_thrashing([100, 70, 40]) is True


def test_m8_negative_control_semantic_no_value_detected() -> None:
    """M8: SyntheticRankerMode.NO_VALUE produces semantic_value_status = 'NONE'."""
    gen = SessionFixtureGenerator(seed="TEST_SEED_M8")
    turns, anchors, _ = gen.generate_1000_turn_session()
    res_det = run_session_simulation(
        turns[:20],
        anchors,
        "deterministic_pruning",
    )
    res_sem = run_session_simulation(
        turns[:20],
        anchors,
        "semantic_retroactive",
        synthetic_ranker_mode=SyntheticRankerMode.NO_VALUE,
    )
    status = evaluate_semantic_value(res_sem, res_det)
    assert status == "NONE"


def test_false_positive_control_critical_info_drop_disqualified() -> None:
    """False-positive control: Even if semantic looks cheaper, critical information degradation must result in DISQUALIFIED."""
    gen = SessionFixtureGenerator(seed="TEST_FP_SEED")
    turns, anchors, _ = gen.generate_1000_turn_session()
    res_det = run_session_simulation(turns[:30], anchors, "deterministic_pruning")

    # Manually create a run result that is cheaper but with degraded critical info availability
    res_cheaper_bad_info = copy.deepcopy(res_det)
    object.__setattr__(res_cheaper_bad_info, "critical_information_available_rate", res_det.critical_information_available_rate - 0.1)
    object.__setattr__(res_cheaper_bad_info, "estimated_total_cost", res_det.estimated_total_cost * 0.5)

    status = evaluate_semantic_value(res_cheaper_bad_info, res_det)
    assert status == "DISQUALIFIED"


def test_canonical_fixture_hash_sensitivity() -> None:
    """Canonical fixture hash must be sensitive to seeds, turns, segments, and anchors."""
    gen1 = SessionFixtureGenerator(seed="SEED_ALPHA")
    turns1, anchors1, hash1 = gen1.generate_1000_turn_session()

    gen2 = SessionFixtureGenerator(seed="SEED_BETA")
    turns2, anchors2, hash2 = gen2.generate_1000_turn_session()

    assert hash1 != hash2

    # Modifying even a single turn's prompt in the session changes the canonical hash
    from reviewer.context_economics.fixtures import compute_canonical_fixture_hash
    mutated_turns = copy.deepcopy(turns1)
    mutated_turns[42] = SessionTurnV1(
        turn_id=mutated_turns[42].turn_id,
        user_prompt="MUTATED PROMPT",
        segments=mutated_turns[42].segments,
        task_checkpoint=mutated_turns[42].task_checkpoint,
        recall_queries=mutated_turns[42].recall_queries,
    )
    mutated_hash = compute_canonical_fixture_hash(mutated_turns, anchors1, "SEED_ALPHA")
    assert mutated_hash != hash1


def test_window_overflow_early_break_and_censorship() -> None:
    """Test that window overflow halts session execution accurately and flags incomplete session."""
    # Run NO_TRIMMING with a small window of 5,000 tokens
    gen = SessionFixtureGenerator(seed="TEST_OVERFLOW")
    turns, anchors, _ = gen.generate_1000_turn_session()
    res = run_session_simulation(
        turns,
        anchors,
        ArchitectureId.NO_TRIMMING,
        window_size_tokens=5_000,
    )
    assert res.window_overflow is True
    assert res.session_completed is False
    assert res.completed_turns < len(turns)
    assert res.first_overflow_turn is not None
    assert res.first_overflow_turn == res.completed_turns


def test_proposal_fails_closed_without_semantic_inputs() -> None:
    """Test that live authorization proposal generation fails closed if no semantic inputs were observed."""
    gen = SessionFixtureGenerator(seed="TEST_NO_INPUTS")
    turns, anchors, fhash = gen.generate_1000_turn_session()
    res = run_session_simulation(turns[:5], anchors, ArchitectureId.DETERMINISTIC_PRUNING)

    with pytest.raises(ValueError, match="LIVE_AUTHORIZATION_PROPOSAL_BLOCKED"):
        generate_wave1_live_authorization_proposal("dummy_sha", fhash, [res])


def test_proposal_stratified_diagnostic_live_plan_and_hash_recomputation() -> None:
    """Test that proposal contains MINIMUM_DIAGNOSTIC_LIVE_PLAN and proposal_hash verifies correctly."""
    gen = SessionFixtureGenerator(seed="TEST_DIAG_PLAN")
    turns, anchors, fhash = gen.generate_1000_turn_session()
    res_write = run_session_simulation(
        turns[:30],
        anchors,
        ArchitectureId.SEMANTIC_WRITE_TIME_PERFECTISH,
        synthetic_ranker_mode=SyntheticRankerMode.PERFECTISH,
        fixture_hash=fhash,
    )
    res_retro = run_session_simulation(
        turns[:30],
        anchors,
        ArchitectureId.SEMANTIC_RETROACTIVE_PERFECTISH,
        synthetic_ranker_mode=SyntheticRankerMode.PERFECTISH,
        compaction_trigger_fraction=0.01,  # trigger compaction so retroactive arm evaluates segments
        fixture_hash=fhash,
    )
    proposal = generate_wave1_live_authorization_proposal("c6bda4d97384cedfb3ea2150cd7a9754c1a4d834", fhash, [res_write, res_retro])

    assert "full_replay_required_calls" in proposal
    assert proposal["full_replay_required_calls"] == proposal["union_unique_calls"]
    assert proposal["diagnostic_sample_size"] > 0
    assert proposal["diagnostic_unique_calls"] > 0
    assert proposal["diagnostic_claim_ceiling"] == "REAL_JEV_RANKING_SIGNAL_MEASURED"

    # Verify proposal_hash recomputation
    import hashlib
    import json
    p_copy = dict(proposal)
    claimed_hash = p_copy.pop("proposal_hash")
    p_bytes = json.dumps(p_copy, sort_keys=True, separators=(",", ":")).encode("utf-8")
    expected_hash = hashlib.sha256(p_bytes).hexdigest()
    assert claimed_hash == expected_hash


# ---------------------------------------------------------------------------
# Tests P1 to P10: Strengthened proposal and comparison oracle verification
# ---------------------------------------------------------------------------

def test_p1_p2_p3_cross_arm_union_and_deduplication() -> None:
    """P1, P2, P3: Retroactive-only and write-time-only IDs exist in union, and duplicates are counted once."""
    gen = SessionFixtureGenerator(seed="TEST_P123")
    _, _, fhash = gen.generate_1000_turn_session()

    # Create synthetic run results with controlled semantic IDs
    res_retro = ArchitectureRunResult(
        architecture_name="Retroactive",
        architecture_id=ArchitectureId.SEMANTIC_RETROACTIVE_PERFECTISH,
        window_class="~200K",
        task_success_rate=1.0,
        critical_anchor_recall=1.0,
        critical_information_available_rate=1.0,
        final_context_tokens=1000,
        peak_context_tokens=1000,
        untouchable_context_floor=500,
        window_overflow=False,
        first_overflow_turn=None,
        completed_turns=1000,
        session_completed=True,
        compaction_count=1,
        compaction_thrashing=False,
        structural_hard_stop=False,
        predicted_hard_stop_turn=None,
        prediction_status="NO_GROWTH",
        prefix_invalidations=0,
        tokens_invalidated_by_rewrite=0,
        estimated_total_cost=100.0,
        cost_breakdown=TotalSessionCostV1(),
        cost_per_successful_task=5.0,
        cost_per_100_turns=10.0,
        quality_qualified=True,
        semantic_value_status="NOT_APPLICABLE",
        visible_tool_budget_tokens=60_000,
        max_visible_tool_tokens_observed=10_000,
        budget_violation_count=0,
        recall_needed=0,
        recall_attempted=0,
        recall_success=0,
        missed_recall=0,
        unnecessary_recall=0,
        semantic_decision_calls=2,
        semantic_unique_input_count=2,
        semantic_cache_hits=0,
        semantic_unique_input_ids=["shared_id_1", "retro_only_id_2"],
        semantic_records=[
            {"semantic_input_id": "shared_id_1", "stratum": "high_relevance", "segment_id": "s1", "turn_id": 1, "content_hash": "c1"},
            {"semantic_input_id": "retro_only_id_2", "stratum": "recall_required", "segment_id": "s2", "turn_id": 2, "content_hash": "c2"},
        ],
    )

    res_write = copy.deepcopy(res_retro)
    object.__setattr__(res_write, "architecture_id", ArchitectureId.SEMANTIC_WRITE_TIME_PERFECTISH)
    object.__setattr__(res_write, "semantic_unique_input_ids", ["shared_id_1", "write_only_id_3"])
    object.__setattr__(res_write, "semantic_records", [
        {"semantic_input_id": "shared_id_1", "stratum": "high_relevance", "segment_id": "s1", "turn_id": 1, "content_hash": "c1"},
        {"semantic_input_id": "write_only_id_3", "stratum": "low_relevance", "segment_id": "s3", "turn_id": 3, "content_hash": "c3"},
    ])

    proposal = generate_wave1_live_authorization_proposal("test_candidate_sha", fhash, [res_retro, res_write])

    # Check P1: Retroactive-only ID is in union
    # Check P2: Write-time-only ID is in union
    # Check P3: Duplicate ID counted once
    assert proposal["retroactive_unique_calls"] == 2
    assert proposal["write_time_unique_calls"] == 2
    assert proposal["cross_arm_duplicates"] == 1
    assert proposal["union_unique_calls"] == 3
    assert proposal["full_replay_required_calls"] == 3

    union_sample_ids = {s["semantic_input_id"] for s in proposal["diagnostic_sample"]}
    assert "shared_id_1" in union_sample_ids
    assert "retro_only_id_2" in union_sample_ids
    assert "write_only_id_3" in union_sample_ids


def test_p4_stratified_diagnostic_plan_samples_all_five_strata() -> None:
    """P4: Stratified diagnostic plan samples actual IDs across all 5 strata."""
    gen = SessionFixtureGenerator(seed="TEST_P4")
    _, _, fhash = gen.generate_1000_turn_session()

    strata_names = ["high_relevance", "medium_relevance", "low_relevance", "recall_required", "stale_or_repeated_noise"]
    records = []
    unique_ids = []
    for i, s_name in enumerate(strata_names):
        s_id = f"test_id_stratum_{i}"
        unique_ids.append(s_id)
        records.append({
            "semantic_input_id": s_id,
            "stratum": s_name,
            "segment_id": f"seg_{i}",
            "turn_id": i + 1,
            "content_hash": f"hash_{i}",
        })

    res_retro = ArchitectureRunResult(
        architecture_name="Retro",
        architecture_id=ArchitectureId.SEMANTIC_RETROACTIVE_PERFECTISH,
        window_class="~200K",
        task_success_rate=1.0,
        critical_anchor_recall=1.0,
        critical_information_available_rate=1.0,
        final_context_tokens=1000,
        peak_context_tokens=1000,
        untouchable_context_floor=500,
        window_overflow=False,
        first_overflow_turn=None,
        completed_turns=1000,
        session_completed=True,
        compaction_count=1,
        compaction_thrashing=False,
        structural_hard_stop=False,
        predicted_hard_stop_turn=None,
        prediction_status="NO_GROWTH",
        prefix_invalidations=0,
        tokens_invalidated_by_rewrite=0,
        estimated_total_cost=100.0,
        cost_breakdown=TotalSessionCostV1(),
        cost_per_successful_task=5.0,
        cost_per_100_turns=10.0,
        quality_qualified=True,
        semantic_value_status="NOT_APPLICABLE",
        visible_tool_budget_tokens=60_000,
        max_visible_tool_tokens_observed=10_000,
        budget_violation_count=0,
        recall_needed=0,
        recall_attempted=0,
        recall_success=0,
        missed_recall=0,
        unnecessary_recall=0,
        semantic_decision_calls=len(unique_ids),
        semantic_unique_input_count=len(unique_ids),
        semantic_cache_hits=0,
        semantic_unique_input_ids=unique_ids[:3],
        semantic_records=records[:3],
    )
    res_write = copy.deepcopy(res_retro)
    object.__setattr__(res_write, "architecture_id", ArchitectureId.SEMANTIC_WRITE_TIME_PERFECTISH)
    object.__setattr__(res_write, "semantic_unique_input_ids", unique_ids[2:])
    object.__setattr__(res_write, "semantic_records", records[2:])

    proposal = generate_wave1_live_authorization_proposal("sha_p4", fhash, [res_retro, res_write])
    assert proposal["diagnostic_claim_ceiling"] == "REAL_JEV_RANKING_SIGNAL_MEASURED"

    sample_strata = {s["stratum"] for s in proposal["diagnostic_sample"]}
    for expected_s in strata_names:
        assert expected_s in sample_strata
        assert proposal["diagnostic_strata_summary"][expected_s] >= 1


def test_p5_missing_retroactive_trace_blocks_proposal() -> None:
    """P5: Missing retroactive trace blocks proposal."""
    gen = SessionFixtureGenerator(seed="TEST_P5")
    _, _, fhash = gen.generate_1000_turn_session()

    res_write = ArchitectureRunResult(
        architecture_name="WriteTime",
        architecture_id=ArchitectureId.SEMANTIC_WRITE_TIME_PERFECTISH,
        window_class="~200K",
        task_success_rate=1.0,
        critical_anchor_recall=1.0,
        critical_information_available_rate=1.0,
        final_context_tokens=1000,
        peak_context_tokens=1000,
        untouchable_context_floor=500,
        window_overflow=False,
        first_overflow_turn=None,
        completed_turns=1000,
        session_completed=True,
        compaction_count=1,
        compaction_thrashing=False,
        structural_hard_stop=False,
        predicted_hard_stop_turn=None,
        prediction_status="NO_GROWTH",
        prefix_invalidations=0,
        tokens_invalidated_by_rewrite=0,
        estimated_total_cost=100.0,
        cost_breakdown=TotalSessionCostV1(),
        cost_per_successful_task=5.0,
        cost_per_100_turns=10.0,
        quality_qualified=True,
        semantic_value_status="NOT_APPLICABLE",
        visible_tool_budget_tokens=60_000,
        max_visible_tool_tokens_observed=10_000,
        budget_violation_count=0,
        recall_needed=0,
        recall_attempted=0,
        recall_success=0,
        missed_recall=0,
        unnecessary_recall=0,
        semantic_decision_calls=1,
        semantic_unique_input_count=1,
        semantic_cache_hits=0,
        semantic_unique_input_ids=["id_w1"],
        semantic_records=[{"semantic_input_id": "id_w1", "stratum": "high_relevance", "segment_id": "s1", "turn_id": 1, "content_hash": "c1"}],
    )

    with pytest.raises(ValueError, match="LIVE_AUTHORIZATION_PROPOSAL_BLOCKED: missing retroactive trace"):
        generate_wave1_live_authorization_proposal("sha_p5", fhash, [res_write])


def test_p6_missing_write_time_trace_blocks_proposal() -> None:
    """P6: Missing write-time trace blocks proposal."""
    gen = SessionFixtureGenerator(seed="TEST_P6")
    _, _, fhash = gen.generate_1000_turn_session()

    res_retro = ArchitectureRunResult(
        architecture_name="Retro",
        architecture_id=ArchitectureId.SEMANTIC_RETROACTIVE_PERFECTISH,
        window_class="~200K",
        task_success_rate=1.0,
        critical_anchor_recall=1.0,
        critical_information_available_rate=1.0,
        final_context_tokens=1000,
        peak_context_tokens=1000,
        untouchable_context_floor=500,
        window_overflow=False,
        first_overflow_turn=None,
        completed_turns=1000,
        session_completed=True,
        compaction_count=1,
        compaction_thrashing=False,
        structural_hard_stop=False,
        predicted_hard_stop_turn=None,
        prediction_status="NO_GROWTH",
        prefix_invalidations=0,
        tokens_invalidated_by_rewrite=0,
        estimated_total_cost=100.0,
        cost_breakdown=TotalSessionCostV1(),
        cost_per_successful_task=5.0,
        cost_per_100_turns=10.0,
        quality_qualified=True,
        semantic_value_status="NOT_APPLICABLE",
        visible_tool_budget_tokens=60_000,
        max_visible_tool_tokens_observed=10_000,
        budget_violation_count=0,
        recall_needed=0,
        recall_attempted=0,
        recall_success=0,
        missed_recall=0,
        unnecessary_recall=0,
        semantic_decision_calls=1,
        semantic_unique_input_count=1,
        semantic_cache_hits=0,
        semantic_unique_input_ids=["id_r1"],
        semantic_records=[{"semantic_input_id": "id_r1", "stratum": "high_relevance", "segment_id": "s1", "turn_id": 1, "content_hash": "c1"}],
    )

    with pytest.raises(ValueError, match="LIVE_AUTHORIZATION_PROPOSAL_BLOCKED: missing write-time trace"):
        generate_wave1_live_authorization_proposal("sha_p6", fhash, [res_retro])


def test_p7_overflow_candidate_vs_baseline_returns_non_comparable_overflow() -> None:
    """P7: Window overflow candidate vs baseline returns NON_COMPARABLE_WINDOW_OVERFLOW."""
    gen = SessionFixtureGenerator(seed="TEST_P7")
    turns, anchors, _ = gen.generate_1000_turn_session()
    res_det = run_session_simulation(turns[:30], anchors, "deterministic_pruning")

    res_overflow = copy.deepcopy(res_det)
    object.__setattr__(res_overflow, "window_overflow", True)
    object.__setattr__(res_overflow, "session_completed", False)

    # Candidate overflow
    assert evaluate_semantic_value(res_overflow, res_det) == "NON_COMPARABLE_WINDOW_OVERFLOW"
    # Baseline overflow
    assert evaluate_semantic_value(res_det, res_overflow) == "NON_COMPARABLE_WINDOW_OVERFLOW"


def test_p8_mismatched_budget_returns_non_comparable_budget() -> None:
    """P8: 60K vs 90K budget comparison returns NON_COMPARABLE_BUDGET."""
    gen = SessionFixtureGenerator(seed="TEST_P8")
    turns, anchors, _ = gen.generate_1000_turn_session()
    res_60k = run_session_simulation(turns[:30], anchors, "deterministic_pruning", visible_tool_budget_tokens=60_000)
    res_90k = run_session_simulation(turns[:30], anchors, "deterministic_pruning", visible_tool_budget_tokens=90_000)

    assert evaluate_semantic_value(res_60k, res_90k) == "NON_COMPARABLE_BUDGET"
    assert evaluate_semantic_value(res_90k, res_60k) == "NON_COMPARABLE_BUDGET"


def test_p9_critical_information_available_rate_regression_returns_disqualified() -> None:
    """P9: critical_information_available_rate regression returns DISQUALIFIED."""
    gen = SessionFixtureGenerator(seed="TEST_P9")
    turns, anchors, _ = gen.generate_1000_turn_session()
    res_baseline = run_session_simulation(turns[:30], anchors, "deterministic_pruning")

    res_cand = copy.deepcopy(res_baseline)
    object.__setattr__(res_cand, "critical_information_available_rate", res_baseline.critical_information_available_rate - 0.05)
    object.__setattr__(res_cand, "estimated_total_cost", res_baseline.estimated_total_cost * 0.5)

    assert evaluate_semantic_value(res_cand, res_baseline) == "DISQUALIFIED"


def test_p10_compaction_and_recall_tokens_affect_total_cost() -> None:
    """P10: Compaction_tokens and recall_tokens rate consumption directly affects compute_total_cost()."""
    base_cost = TotalSessionCostV1(
        generation_input_tokens=10_000,
        generation_output_tokens=1_000,
        compaction_tokens=0,
        recall_tokens=0,
    )
    c0 = base_cost.compute_total_cost()

    cost_with_compaction = TotalSessionCostV1(
        generation_input_tokens=10_000,
        generation_output_tokens=1_000,
        compaction_tokens=10_000,
        recall_tokens=0,
    )
    c1 = cost_with_compaction.compute_total_cost()
    # 10_000 tokens * (0.5 / 1000) = 5.0 normalized cost increase
    assert round(c1 - c0, 2) == 5.0

    cost_with_recall = TotalSessionCostV1(
        generation_input_tokens=10_000,
        generation_output_tokens=1_000,
        compaction_tokens=0,
        recall_tokens=10_000,
    )
    c2 = cost_with_recall.compute_total_cost()
    # 10_000 tokens * (0.5 / 1000) = 5.0 normalized cost increase
    assert round(c2 - c0, 2) == 5.0
