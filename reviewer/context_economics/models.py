"""Context Economics Wave 1 experimental models, contracts, and interfaces.

This module provides data classes, enums, protocols, and deterministic protection
functions for the F4 Context Economics benchmark and simulation harness.
Strictly research and experiment only. No production context or runtime authority.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
import hashlib
import json
import re
from typing import Any, Protocol, Sequence


class SourceType(str, Enum):
    USER = "USER"
    ASSISTANT = "ASSISTANT"
    TOOL_CALL = "TOOL_CALL"
    TOOL_RESULT = "TOOL_RESULT"
    SUMMARY = "SUMMARY"
    SYSTEM_EVIDENCE = "SYSTEM_EVIDENCE"


class VisibilityState(str, Enum):
    VISIBLE = "VISIBLE"
    HIDDEN_BUT_RECALLABLE = "HIDDEN_BUT_RECALLABLE"


class AnchorProtectionClass(str, Enum):
    HARD_PROTECTED = "HARD_PROTECTED"
    RECALL_REQUIRED = "RECALL_REQUIRED"


class AnchorType(str, Enum):
    EXACT_FILE_PATH = "EXACT_FILE_PATH"
    ERROR_STRING = "ERROR_STRING"
    CONFIG_KEY = "CONFIG_KEY"
    ROOT_CAUSE = "ROOT_CAUSE"
    COMMIT_SHA = "COMMIT_SHA"
    OPERATION_ID = "OPERATION_ID"
    TASK_ID = "TASK_ID"
    DELEGATION_ID = "DELEGATION_ID"
    USER_CONSTRAINT = "USER_CONSTRAINT"
    FAILED_APPROACH = "FAILED_APPROACH"
    TEST_RESULT = "TEST_RESULT"
    AUTHORITY_DECISION = "AUTHORITY_DECISION"
    DIAGNOSTIC_FINDING = "DIAGNOSTIC_FINDING"
    DEPENDENCY_FACT = "DEPENDENCY_FACT"


@dataclass(frozen=True)
class CriticalAnchorV1:
    """Exact anchor in session context that must be preserved or recalled losslessly."""

    anchor_id: str
    anchor_type: AnchorType
    exact_value_hash: str
    origin_turn: int
    needed_again_turn: int
    protection_class: AnchorProtectionClass = AnchorProtectionClass.HARD_PROTECTED
    must_recall_exactly: bool = True

    def __post_init__(self) -> None:
        if not self.anchor_id or not isinstance(self.anchor_id, str):
            raise ValueError("anchor_id must be a non-empty string")
        if not isinstance(self.anchor_type, AnchorType):
            raise ValueError("anchor_type must be an AnchorType")
        if not isinstance(self.protection_class, AnchorProtectionClass):
            raise ValueError("protection_class must be an AnchorProtectionClass")
        if len(self.exact_value_hash) != 64:
            raise ValueError("exact_value_hash must be a 64-char sha256 hash")
        if self.origin_turn < 0 or self.needed_again_turn < self.origin_turn:
            raise ValueError("Invalid turn range for anchor")


@dataclass(frozen=True)
class ContextSegmentV1:
    """A single segment of session history."""

    segment_id: str
    turn_id: int
    source_type: SourceType
    token_count: int
    created_at_turn: int
    content_class: str
    content: str
    relevance_ground_truth: float  # 0.0 to 1.0
    critical_anchor_ids: tuple[str, ...] = ()
    has_hard_protected_anchor: bool = False
    visibility_state: VisibilityState = VisibilityState.VISIBLE
    recallable: bool = True

    def __post_init__(self) -> None:
        if not self.segment_id or not isinstance(self.segment_id, str):
            raise ValueError("segment_id must be a non-empty string")
        if self.token_count < 0:
            raise ValueError("token_count must be non-negative")
        if not (0.0 <= self.relevance_ground_truth <= 1.0):
            raise ValueError("relevance_ground_truth must be in [0.0, 1.0]")


# Deterministic Protection Patterns for HARD_PROTECTED evidence
_PROTECTION_REGEXES = [
    re.compile(r"\bERROR\b", re.IGNORECASE),
    re.compile(r"\bFAILED\b", re.IGNORECASE),
    re.compile(r"\bException\b"),
    re.compile(r"\bTraceback\b"),
    re.compile(r"[a-zA-Z0-9_\-\./]+\.(?:py|rs|go|ts|js|json|yaml|yml|toml|md):\d+"),  # file:line
    re.compile(r"\bexit\s+status\s+[1-9]\d*\b", re.IGNORECASE),
    re.compile(r"\bexit\s+code\s+[1-9]\d*\b", re.IGNORECASE),
    re.compile(r"\b[0-9a-f]{40}\b"),  # commit SHA
    re.compile(r"\bop-[A-Za-z0-9_-]+\b"),  # operation ID
    re.compile(r"\btask-[A-Za-z0-9_-]+\b"),  # task ID
    re.compile(r"\bROOT_CAUSE\b"),
    re.compile(r"\bAUTHORITY_DECISION\b"),
    re.compile(r"\bUSER_CONSTRAINT\b"),
]


def deterministic_must_keep(segment: ContextSegmentV1) -> bool:
    """Check if segment is unconditionally protected by deterministic safety rules.

    Semantic models have ZERO authority to delete or hide protected segments.
    Non-tool content (USER, SYSTEM, SUMMARY) and hard-protected anchors are untouchable.
    """
    if segment.source_type in (SourceType.USER, SourceType.SYSTEM_EVIDENCE, SourceType.SUMMARY):
        return True

    if segment.has_hard_protected_anchor:
        return True

    text = segment.content
    for pattern in _PROTECTION_REGEXES:
        if pattern.search(text):
            return True

    return False


@dataclass(frozen=True)
class RankerResult:
    """Provider-neutral ranker relevance scoring result."""

    relevance_score: float  # 0.0 to 1.0
    ranker_id: str
    ranker_revision: str
    status: str = "OK"

    def __post_init__(self) -> None:
        if not (0.0 <= self.relevance_score <= 1.0):
            raise ValueError("relevance_score must be in [0.0, 1.0]")


class ContextRelevanceRanker(Protocol):
    """Provider-neutral interface for segment relevance rankers."""

    ranker_id: str
    ranker_revision: str

    def score(
        self,
        current_task: str,
        segment: ContextSegmentV1,
    ) -> RankerResult:
        ...


class SyntheticRankerMode(str, Enum):
    PERFECTISH = "PERFECTISH"
    NOISY = "NOISY"
    NO_VALUE = "NO_VALUE"


class SyntheticJevRanker:
    """Deterministic synthetic ranker with verifiable noise and stable input identity."""

    ranker_id = "synthetic-jev-ranker"
    ranker_revision = "wave1-v2"

    def __init__(self, mode: SyntheticRankerMode, seed: str = "SYNTH_JEV_V2"):
        self.mode = mode
        self.seed = seed

    def compute_semantic_input_hash(self, current_task: str, segment: ContextSegmentV1) -> str:
        payload = {
            "task": current_task,
            "segment_id": segment.segment_id,
            "content_hash": hashlib.sha256(segment.content.encode("utf-8")).hexdigest(),
            "ranker_revision": self.ranker_revision,
        }
        return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()

    def score(self, current_task: str, segment: ContextSegmentV1) -> RankerResult:
        inp_hash = self.compute_semantic_input_hash(current_task, segment)
        # Deterministic float in [0.0, 1.0] from hash
        hash_float = int(inp_hash[:8], 16) / 0xFFFFFFFF

        if self.mode == SyntheticRankerMode.PERFECTISH:
            # High correlation, small deterministic perturbation ±0.05
            perturbation = (hash_float - 0.5) * 0.1
            raw = segment.relevance_ground_truth + perturbation
        elif self.mode == SyntheticRankerMode.NOISY:
            # Substantial perturbation causing true ranking inversions
            # Invert 40% of signal with hash noise
            raw = 0.5 * segment.relevance_ground_truth + 0.5 * hash_float
        elif self.mode == SyntheticRankerMode.NO_VALUE:
            # Constant 0.5: zero discriminative signal compared to baseline
            raw = 0.5
        else:
            raise ValueError(f"Unknown mode: {self.mode}")

        score = max(0.0, min(1.0, float(raw)))
        return RankerResult(
            relevance_score=round(score, 4),
            ranker_id=self.ranker_id,
            ranker_revision=self.ranker_revision,
            status="OK",
        )


class RecallStoreV1:
    """Provider-neutral lossless storage for hidden-but-recallable context segments."""

    def __init__(self) -> None:
        self._segments: dict[str, ContextSegmentV1] = {}
        self._anchor_index: dict[str, list[str]] = {}

    def put(self, segment: ContextSegmentV1) -> None:
        self._segments[segment.segment_id] = segment
        for aid in segment.critical_anchor_ids:
            self._anchor_index.setdefault(aid, []).append(segment.segment_id)

    def get(self, segment_id: str) -> ContextSegmentV1 | None:
        return self._segments.get(segment_id)

    def search_by_anchor(self, anchor_id: str) -> list[ContextSegmentV1]:
        seg_ids = self._anchor_index.get(anchor_id, [])
        return [self._segments[sid] for sid in seg_ids if sid in self._segments]

    def total_stored_segments(self) -> int:
        return len(self._segments)

    def verify_storage_losslessness(self, segment: ContextSegmentV1) -> bool:
        stored = self.get(segment.segment_id)
        if stored is None:
            return False
        return (
            stored.segment_id == segment.segment_id
            and stored.content == segment.content
            and stored.token_count == segment.token_count
            and stored.critical_anchor_ids == segment.critical_anchor_ids
        )


@dataclass
class CacheEconomicsV1:
    """Deterministic cache economics tracker for session simulations."""

    cache_model_revision: str = "wave1-prefix-cache-v2"
    cached_input_tokens: int = 0
    uncached_input_tokens: int = 0
    cache_write_tokens: int = 0
    cache_read_tokens: int = 0
    prefix_invalidations: int = 0
    tokens_invalidated_by_rewrite: int = 0
    turns_between_invalidations: list[int] = field(default_factory=list)
    last_invalidation_turn: int = 0

    def record_invalidation(self, current_turn: int, invalidated_tokens: int) -> None:
        if invalidated_tokens < 0:
            raise ValueError("invalidated_tokens must be non-negative")
        self.prefix_invalidations += 1
        self.tokens_invalidated_by_rewrite += invalidated_tokens
        interval = current_turn - self.last_invalidation_turn
        self.turns_between_invalidations.append(interval)
        self.last_invalidation_turn = current_turn

    def verify_non_negative(self) -> bool:
        return (
            self.cached_input_tokens >= 0
            and self.uncached_input_tokens >= 0
            and self.cache_write_tokens >= 0
            and self.cache_read_tokens >= 0
            and self.tokens_invalidated_by_rewrite >= 0
            and self.prefix_invalidations >= 0
        )


@dataclass(frozen=True)
class TotalSessionCostV1:
    """Versioned full total session cost accounting in NORMALIZED_COST_UNITS."""

    cost_model_revision: str = "total-cost-v1"
    generation_input_tokens: int = 0
    generation_output_tokens: int = 0
    semantic_decision_calls: int = 0
    semantic_decision_input_tokens: int = 0
    semantic_decision_output_tokens: int = 0
    compaction_calls: int = 0
    compaction_tokens: int = 0
    recall_calls: int = 0
    recall_tokens: int = 0
    cache_write_tokens: int = 0
    cache_read_tokens: int = 0
    cache_miss_penalty_tokens: int = 0
    fallback_calls: int = 0

    # Rate assumptions in normalized units per 1K tokens / calls
    rate_generation_input_per_k: float = 1.0
    rate_generation_output_per_k: float = 3.0
    rate_semantic_call_fixed: float = 0.5
    rate_semantic_token_per_k: float = 0.8
    rate_compaction_call_fixed: float = 2.0
    rate_recall_call_fixed: float = 0.2
    rate_cache_read_per_k: float = 0.1
    rate_cache_write_per_k: float = 1.25
    rate_cache_miss_penalty_per_k: float = 0.5

    def compute_total_cost(self) -> float:
        cost = (
            (self.generation_input_tokens / 1000.0) * self.rate_generation_input_per_k
            + (self.generation_output_tokens / 1000.0) * self.rate_generation_output_per_k
            + self.semantic_decision_calls * self.rate_semantic_call_fixed
            + (self.semantic_decision_input_tokens / 1000.0) * self.rate_semantic_token_per_k
            + self.compaction_calls * self.rate_compaction_call_fixed
            + self.recall_calls * self.rate_recall_call_fixed
            + (self.cache_read_tokens / 1000.0) * self.rate_cache_read_per_k
            + (self.cache_write_tokens / 1000.0) * self.rate_cache_write_per_k
            + (self.cache_miss_penalty_tokens / 1000.0) * self.rate_cache_miss_penalty_per_k
        )
        return round(cost, 2)


@dataclass(frozen=True)
class TaskCheckpointV1:
    """A verification checkpoint within a long session."""

    checkpoint_id: str
    turn_id: int
    required_anchor_ids: tuple[str, ...]
    description: str


@dataclass
class SessionTurnV1:
    """A turn in the simulated long session."""

    turn_id: int
    user_prompt: str
    segments: list[ContextSegmentV1]
    task_checkpoint: TaskCheckpointV1 | None = None
    recall_queries: list[str] = field(default_factory=list)  # anchor_ids needed at this turn
