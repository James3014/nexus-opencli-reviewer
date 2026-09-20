"""Deterministic long session generator and fixtures for Wave 1 Context Economics.

Produces a reproducible 1000-turn session fixture with exact anchors,
varying noise, intermittent errors, repeated commands, and 20 task checkpoints.
"""

from __future__ import annotations

import hashlib
import json
import random
from typing import Sequence

from reviewer.context_economics.models import (
    AnchorType,
    ContextSegmentV1,
    CriticalAnchorV1,
    SessionTurnV1,
    SourceType,
    TaskCheckpointV1,
)


def _hash_str(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


class SessionFixtureGenerator:
    """Generates deterministic long-session fixtures with exact ground truth."""

    def __init__(self, seed: str = "EXP_C_WAVE1_V1"):
        self.seed = seed
        self.rng = random.Random(seed)

    def generate_1000_turn_session(self) -> tuple[list[SessionTurnV1], list[CriticalAnchorV1], str]:
        """Generate 1000 turns with exact anchors, checkpoints, and deterministic token counts."""
        anchors: list[CriticalAnchorV1] = []
        turns: list[SessionTurnV1] = []

        # Create 20 critical anchors across the session
        # Anchor 1: Root cause early in session (Turn 10, needed at Turn 250, 750)
        rc_anchor = CriticalAnchorV1(
            anchor_id="anchor-rc-1",
            anchor_type=AnchorType.ROOT_CAUSE,
            exact_value_hash=_hash_str("ROOT_CAUSE: deadlock in connection pool under high concurrency"),
            origin_turn=10,
            needed_again_turn=250,
            must_recall_exactly=True,
        )
        anchors.append(rc_anchor)

        # Anchor 2: Commit SHA (Turn 45, needed Turn 500)
        sha_anchor = CriticalAnchorV1(
            anchor_id="anchor-sha-1",
            anchor_type=AnchorType.COMMIT_SHA,
            exact_value_hash=_hash_str("7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a"),
            origin_turn=45,
            needed_again_turn=500,
            must_recall_exactly=True,
        )
        anchors.append(sha_anchor)

        # Anchor 3: User constraint (Turn 2, needed Turn 900)
        uc_anchor = CriticalAnchorV1(
            anchor_id="anchor-uc-1",
            anchor_type=AnchorType.USER_CONSTRAINT,
            exact_value_hash=_hash_str("USER_CONSTRAINT: zero external network calls allowed during replay"),
            origin_turn=2,
            needed_again_turn=900,
            must_recall_exactly=True,
        )
        anchors.append(uc_anchor)

        # Generate 17 more anchors spread across turns 50-800
        for i in range(4, 21):
            orig_t = 50 + i * 35
            need_t = min(995, orig_t + 150)
            a = CriticalAnchorV1(
                anchor_id=f"anchor-auto-{i}",
                anchor_type=AnchorType.CONFIG_KEY if i % 2 == 0 else AnchorType.ERROR_STRING,
                exact_value_hash=_hash_str(f"critical-fact-token-{i}-value-{orig_t}"),
                origin_turn=orig_t,
                needed_again_turn=need_t,
                must_recall_exactly=True,
            )
            anchors.append(a)

        anchor_map_by_origin = {a.origin_turn: a for a in anchors}
        anchor_map_by_need = {}
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
                )
            )

            # Tool segments: 1 to 3 tool calls per turn
            tool_count = self.rng.randint(1, 3)
            for tool_idx in range(tool_count):
                seg_id = f"seg-tool-{t}-{tool_idx}"
                # Check if this turn originates a critical anchor
                anchor = anchor_map_by_origin.get(t) if tool_idx == 0 else None
                if anchor:
                    content = f"Critical anchor content: {anchor.anchor_type.value} [hash={anchor.exact_value_hash}]"
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
                            content_class="critical_anchor_evidence",
                            content=content,
                            relevance_ground_truth=1.0,
                            critical_anchor_ids=(anchor.anchor_id,),
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
                        )
                    )

            # Checkpoint check
            chk: TaskCheckpointV1 | None = None
            recall_queries: list[str] = []
            if t in checkpoint_set:
                needed_anchors = anchor_map_by_need.get(t, [])
                req_ids = tuple(a.anchor_id for a in needed_anchors)
                if not req_ids and anchors:
                    # Fallback pick one earlier anchor
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

        # Compute deterministic fixture hash
        summary_payload = {
            "seed": self.seed,
            "turns_count": len(turns),
            "anchors_count": len(anchors),
            "first_anchor": anchors[0].anchor_id if anchors else None,
            "last_anchor": anchors[-1].anchor_id if anchors else None,
        }
        fixture_hash = hashlib.sha256(json.dumps(summary_payload, sort_keys=True).encode("utf-8")).hexdigest()

        return turns, anchors, fixture_hash
