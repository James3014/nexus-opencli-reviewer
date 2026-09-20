from __future__ import annotations

import copy
import pytest

from reviewer.context_economics.fixtures import SessionFixtureGenerator
from reviewer.context_economics.models import (
    AnchorType,
    CacheEconomicsV1,
    ContextSegmentV1,
    CriticalAnchorV1,
    RecallStoreV1,
    SessionTurnV1,
    SourceType,
    SyntheticJevRanker,
    SyntheticRankerMode,
    TaskCheckpointV1,
    VisibilityState,
    deterministic_must_keep,
)
from reviewer.context_economics.simulation import (
    ArchitectureRunResult,
    ThrashingDetector,
    evaluate_semantic_value,
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
    """M2: In simulation, both deterministic pruning and semantic retroactive use exact same budget."""
    gen = SessionFixtureGenerator(seed="TEST_SEED")
    turns, anchors, _ = gen.generate_1000_turn_session()

    res_det = run_session_simulation(turns[:50], anchors, "deterministic_pruning", visible_tool_budget_tokens=30_000)
    res_sem = run_session_simulation(
        turns[:50],
        anchors,
        "semantic_retroactive",
        visible_tool_budget_tokens=30_000,
        synthetic_ranker_mode=SyntheticRankerMode.PERFECTISH,
    )
    # The budget constraint applied to non-protected tools is identical (30,000)
    assert res_det.window_class == res_sem.window_class


def test_m3_negative_control_hidden_store_loss_detected() -> None:
    """M3: If store fails to return segment, storage losslessness fails."""
    store = RecallStoreV1()
    seg = _sample_segment("some log")
    # Not put into store
    assert store.verify_storage_losslessness(seg) is False


def test_m4_negative_control_missed_recall_fails_checkpoint() -> None:
    """M4: If required anchor is not in context and not recalled, checkpoint fails."""
    # Create turn with checkpoint requiring non-existent anchor
    chk = TaskCheckpointV1("chk-1", 1, ("missing-anchor-id",), "verify anchor")
    turn = SessionTurnV1(
        turn_id=1,
        user_prompt="p",
        segments=[_sample_segment("log")],
        task_checkpoint=chk,
        recall_queries=[],  # Did not attempt recall
    )
    res = run_session_simulation([turn], [], "deterministic_pruning")
    assert res.task_success_rate == 0.0


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


def test_false_positive_control_recall_drop_disqualified() -> None:
    """False-positive control: Even if semantic looks cheaper, recall degradation must result in DISQUALIFIED."""
    gen = SessionFixtureGenerator(seed="TEST_FP_SEED")
    turns, anchors, _ = gen.generate_1000_turn_session()
    res_det = run_session_simulation(turns[:30], anchors, "deterministic_pruning")

    # Manually create a run result that is cheaper but with degraded recall
    res_cheaper_bad_recall = copy.deepcopy(res_det)
    # Simulate degraded recall and lower cost
    object.__setattr__(res_cheaper_bad_recall, "critical_anchor_recall", res_det.critical_anchor_recall - 0.1)
    object.__setattr__(res_cheaper_bad_recall, "estimated_total_cost", res_det.estimated_total_cost * 0.5)

    status = evaluate_semantic_value(res_cheaper_bad_recall, res_det)
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
