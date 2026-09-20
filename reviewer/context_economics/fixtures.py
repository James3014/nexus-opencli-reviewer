"""Deterministic long session generator and fixtures for Wave 1 Context Economics.

Produces a canonical reproducible 1000-turn session fixture with:
- Canonical complete fixture hashing across every turn, segment, anchor, and checkpoint.
- Separation of HARD_PROTECTED anchors vs RECALL_REQUIRED anchors.
- 20 Task Checkpoints exercising exact anchor retention and recall.
"""

from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
import random
from typing import Sequence

from reviewer.context_economics.models import (
    AnchorProtectionClass,
    AnchorType,
    ContextSegmentV1,
    CriticalAnchorV1,
    SessionTurnV1,
    SourceType,
    TaskCheckpointV1,
)

FIXTURE_SCHEMA_VERSION = "exp-c-wave1-v2-canonical"


def _hash_str(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


class SessionFixtureGenerator:
    """Generates deterministic long-session fixtures with exact ground truth."""

    def __init__(self, seed: str = "EXP_C_WAVE1_V2"):
        self.seed = seed
        self.rng = random.Random(seed)

    def generate_1000_turn_session(self) -> tuple[list[SessionTurnV1], list[CriticalAnchorV1], str]:
        """Generate 1000 turns with exact anchors, checkpoints, and deterministic token counts."""
        anchors: list[CriticalAnchorV1] = []
        turns: list[SessionTurnV1] = []

        # 1. HARD_PROTECTED ANCHORS (10 total):
        # Anchor 1: Root cause (Turn 10, needed Turn 250)
        anchors.append(
            CriticalAnchorV1(
                anchor_id="anchor-hard-rc-1",
                anchor_type=AnchorType.ROOT_CAUSE,
                exact_value_hash=_hash_str("ROOT_CAUSE: deadlock in connection pool under high concurrency"),
                origin_turn=10,
                needed_again_turn=250,
                protection_class=AnchorProtectionClass.HARD_PROTECTED,
                must_recall_exactly=True,
            )
        )
        # Anchor 2: Commit SHA (Turn 45, needed Turn 500)
        anchors.append(
            CriticalAnchorV1(
                anchor_id="anchor-hard-sha-1",
                anchor_type=AnchorType.COMMIT_SHA,
                exact_value_hash=_hash_str("7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a"),
                origin_turn=45,
                needed_again_turn=500,
                protection_class=AnchorProtectionClass.HARD_PROTECTED,
                must_recall_exactly=True,
            )
        )
        # Anchor 3: User constraint (Turn 2, needed Turn 900)
        anchors.append(
            CriticalAnchorV1(
                anchor_id="anchor-hard-uc-1",
                anchor_type=AnchorType.USER_CONSTRAINT,
                exact_value_hash=_hash_str("USER_CONSTRAINT: zero external network calls allowed during replay"),
                origin_turn=2,
                needed_again_turn=900,
                protection_class=AnchorProtectionClass.HARD_PROTECTED,
                must_recall_exactly=True,
            )
        )
        # Anchor 4-10: Additional hard protected anchors (config keys, errors, task IDs)
        for i in range(4, 11):
            orig_t = 30 + i * 40
            anchors.append(
                CriticalAnchorV1(
                    anchor_id=f"anchor-hard-auto-{i}",
                    anchor_type=AnchorType.CONFIG_KEY if i % 2 == 0 else AnchorType.ERROR_STRING,
                    exact_value_hash=_hash_str(f"hard-protected-fact-token-{i}-turn-{orig_t}"),
                    origin_turn=orig_t,
                    needed_again_turn=min(990, orig_t + 200),
                    protection_class=AnchorProtectionClass.HARD_PROTECTED,
                    must_recall_exactly=True,
                )
            )

        # 2. RECALL_REQUIRED ANCHORS (10 total: >= 8 required):
        # These are important findings, failed approach rationales, and diagnostic facts
        # that do NOT match deterministic error regexes and CAN be hidden by write-time sieve / pruning,
        # requiring functional recall when needed later.
        for i in range(10):
            orig_t = 60 + i * 40
            need_t = min(995, orig_t + 180)
            anchors.append(
                CriticalAnchorV1(
                    anchor_id=f"anchor-recall-req-{i + 1}",
                    anchor_type=AnchorType.DIAGNOSTIC_FINDING if i % 2 == 0 else AnchorType.DEPENDENCY_FACT,
                    exact_value_hash=_hash_str(f"recall-required-diagnostic-observation-{i + 1}-turn-{orig_t}"),
                    origin_turn=orig_t,
                    needed_again_turn=need_t,
                    protection_class=AnchorProtectionClass.RECALL_REQUIRED,
                    must_recall_exactly=True,
                )
            )

        anchor_map_by_origin = {a.origin_turn: a for a in anchors}
        anchor_map_by_need: dict[int, list[CriticalAnchorV1]] = {}
        for a in anchors:
            anchor_map_by_need.setdefault(a.needed_again_turn, []).append(a)

        # 20 Task Checkpoints
        checkpoint_turns = sorted(list({a.needed_again_turn for a in anchors}))[:20]
        while len(checkpoint_turns) < 20:
            checkpoint_turns.append(900 + len(checkpoint_turns))
        checkpoint_set = set(checkpoint_turns)

        # Generate 1000 turns
        for t in range(1, 1001):
            user_prompt = f"Turn {t} instruction: perform scheduled analysis and checks."
            segments: list[ContextSegmentV1] = []

            # User segment
            segments.append(
                ContextSegmentV1(
                    segment_id=f"seg-u-{t}",
                    turn_id=t,
                    source_type=SourceType.USER,
                    token_count=50,
                    created_at_turn=t,
                    content_class="user_prompt",
                    content=user_prompt,
                    relevance_ground_truth=0.9,
                    has_hard_protected_anchor=False,
                )
            )

            # Assistant response segment
            segments.append(
                ContextSegmentV1(
                    segment_id=f"seg-a-{t}",
                    turn_id=t,
                    source_type=SourceType.ASSISTANT,
                    token_count=100,
                    created_at_turn=t,
                    content_class="assistant_thought",
                    content=f"Planning steps for turn {t} execution.",
                    relevance_ground_truth=0.5,
                    has_hard_protected_anchor=False,
                )
            )

            # Tool segments: 1 to 3 tool calls per turn
            tool_count = self.rng.randint(1, 3)
            for tool_idx in range(tool_count):
                seg_id = f"seg-tool-{t}-{tool_idx}"
                anchor = anchor_map_by_origin.get(t) if tool_idx == 0 else None

                if anchor:
                    is_hard = anchor.protection_class == AnchorProtectionClass.HARD_PROTECTED
                    if is_hard:
                        content = f"Hard-protected evidence: {anchor.anchor_type.value} [hash={anchor.exact_value_hash}]"
                        if anchor.anchor_type == AnchorType.ROOT_CAUSE:
                            content += " ROOT_CAUSE: deadlock in connection pool under high concurrency"
                        elif anchor.anchor_type == AnchorType.COMMIT_SHA:
                            content += " commit 7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a"
                        elif anchor.anchor_type == AnchorType.USER_CONSTRAINT:
                            content += " USER_CONSTRAINT: zero external network calls allowed during replay"
                        else:
                            content += f" ERROR: test failed with error status code in file.py:42"

                        segments.append(
                            ContextSegmentV1(
                                segment_id=seg_id,
                                turn_id=t,
                                source_type=SourceType.TOOL_RESULT,
                                token_count=250,
                                created_at_turn=t,
                                content_class="hard_protected_evidence",
                                content=content,
                                relevance_ground_truth=1.0,
                                critical_anchor_ids=(anchor.anchor_id,),
                                has_hard_protected_anchor=True,
                            )
                        )
                    else:
                        # RECALL_REQUIRED anchor: clean diagnostic observation without error keywords
                        content = (
                            f"Diagnostic observation {anchor.anchor_id}: confirmed cache line size is 64 bytes "
                            f"and latency budget is 5ms [hash={anchor.exact_value_hash}]"
                        )
                        # Ground truth high, but not automatically protected by deterministic keywords!
                        segments.append(
                            ContextSegmentV1(
                                segment_id=seg_id,
                                turn_id=t,
                                source_type=SourceType.TOOL_RESULT,
                                token_count=250,
                                created_at_turn=t,
                                content_class="recall_required_finding",
                                content=content,
                                relevance_ground_truth=0.85,
                                critical_anchor_ids=(anchor.anchor_id,),
                                has_hard_protected_anchor=False,
                            )
                        )
                else:
                    # Generic tool noise / logs
                    is_noisy = self.rng.random() < 0.75
                    if is_noisy:
                        content = f"Standard build log line {t}:{tool_idx} [PASS ok 200 ms] verbose trace payload data..."
                        tokens = self.rng.randint(200, 800)
                        gt = 0.1
                        cls_name = "noisy_log"
                    else:
                        content = f"Intermediate diagnostic result {t}:{tool_idx} key=value metrics"
                        tokens = self.rng.randint(100, 300)
                        gt = 0.6
                        cls_name = "diagnostic"

                    segments.append(
                        ContextSegmentV1(
                            segment_id=seg_id,
                            turn_id=t,
                            source_type=SourceType.TOOL_RESULT,
                            token_count=tokens,
                            created_at_turn=t,
                            content_class=cls_name,
                            content=content,
                            relevance_ground_truth=gt,
                            has_hard_protected_anchor=False,
                        )
                    )

            # Checkpoint check
            chk: TaskCheckpointV1 | None = None
            recall_queries: list[str] = []
            if t in checkpoint_set:
                needed_anchors = anchor_map_by_need.get(t, [])
                req_ids = tuple(a.anchor_id for a in needed_anchors)
                if not req_ids and anchors:
                    earlier = [a for a in anchors if a.origin_turn < t]
                    if earlier:
                        req_ids = (earlier[-1].anchor_id,)
                chk = TaskCheckpointV1(
                    checkpoint_id=f"chk-{t}",
                    turn_id=t,
                    required_anchor_ids=req_ids,
                    description=f"Task verification at turn {t} verifying {len(req_ids)} critical facts.",
                )
                recall_queries = list(req_ids)

            turns.append(
                SessionTurnV1(
                    turn_id=t,
                    user_prompt=user_prompt,
                    segments=segments,
                    task_checkpoint=chk,
                    recall_queries=recall_queries,
                )
            )

        fixture_hash = compute_canonical_fixture_hash(turns, anchors, self.seed)
        return turns, anchors, fixture_hash


def compute_canonical_fixture_hash(
    turns: Sequence[SessionTurnV1],
    anchors: Sequence[CriticalAnchorV1],
    seed: str,
) -> str:
    """Compute deterministic SHA-256 hash over the entire canonical fixture payload."""
    canonical_dict = {
        "fixture_schema_version": FIXTURE_SCHEMA_VERSION,
        "seed": seed,
        "anchors": [
            {
                "anchor_id": a.anchor_id,
                "anchor_type": a.anchor_type.value,
                "exact_value_hash": a.exact_value_hash,
                "origin_turn": a.origin_turn,
                "needed_again_turn": a.needed_again_turn,
                "protection_class": a.protection_class.value,
                "must_recall_exactly": a.must_recall_exactly,
            }
            for a in anchors
        ],
        "turns": [
            {
                "turn_id": t.turn_id,
                "user_prompt": t.user_prompt,
                "task_checkpoint": (
                    {
                        "checkpoint_id": t.task_checkpoint.checkpoint_id,
                        "turn_id": t.task_checkpoint.turn_id,
                        "required_anchor_ids": list(t.task_checkpoint.required_anchor_ids),
                        "description": t.task_checkpoint.description,
                    }
                    if t.task_checkpoint
                    else None
                ),
                "recall_queries": list(t.recall_queries),
                "segments": [
                    {
                        "segment_id": s.segment_id,
                        "turn_id": s.turn_id,
                        "source_type": s.source_type.value,
                        "token_count": s.token_count,
                        "created_at_turn": s.created_at_turn,
                        "content_class": s.content_class,
                        "content": s.content,
                        "relevance_ground_truth": s.relevance_ground_truth,
                        "critical_anchor_ids": list(s.critical_anchor_ids),
                        "has_hard_protected_anchor": s.has_hard_protected_anchor,
                    }
                    for s in t.segments
                ],
            }
            for t in turns
        ],
    }
    encoded = json.dumps(canonical_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
