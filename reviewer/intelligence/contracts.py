"""Repository Intelligence Core V1 Contracts.

Pure, immutable advisory contracts for repository intelligence.
PR intelligence is bounded by PR_INTELLIGENCE_ONLY; CI evidence is bounded by CI_EVIDENCE_ONLY.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping

from .models import Disposition

CLAIM_CEILING = "PR_INTELLIGENCE_ONLY"
CI_EVIDENCE_CLAIM_CEILING = "CI_EVIDENCE_ONLY"


class EvidenceCompleteness(str, Enum):
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    INCOMPLETE = "INCOMPLETE"


@dataclass(frozen=True)
class RepositoryIntelligencePolicyV1:
    """Consumer-injected policy for generic repository intelligence."""

    protected_path_patterns: tuple[str, ...] = ()
    stale_labels: tuple[str, ...] = ("long-lived", "stale-long-lived")

    def __post_init__(self) -> None:
        if not isinstance(self.protected_path_patterns, tuple):
            object.__setattr__(self, "protected_path_patterns", tuple(self.protected_path_patterns))
        if not isinstance(self.stale_labels, tuple):
            object.__setattr__(self, "stale_labels", tuple(self.stale_labels))


TERMINAL_FAILURE_STATUSES: frozenset[str] = frozenset({
    "failure",
    "failed",
    "error",
    "cancelled",
    "timed_out",
    "action_required",
})


@dataclass(frozen=True)
class RevisionIdentity:
    """Deterministic repository revision identity with stale evidence detection."""

    repository: str
    pr_number: int
    head_sha: str
    base_sha: str
    current_main_sha: str
    declared_base_sha: str | None = None
    declared_head_sha: str | None = None
    declared_main_sha: str | None = None
    stale_base: bool = False
    stale_declared_base: bool = False
    stale_declared_head: bool = False
    stale_declared_main: bool = False
    stale_evidence: bool = False
    evidence_gaps: tuple[str, ...] = ()
    is_valid: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.evidence_gaps, tuple):
            object.__setattr__(self, "evidence_gaps", tuple(self.evidence_gaps))

    @property
    def review_identity(self) -> tuple[str, int, str, str, str]:
        return (
            self.repository,
            self.pr_number,
            self.head_sha,
            self.base_sha,
            self.current_main_sha,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "repository": self.repository,
            "pr_number": self.pr_number,
            "head_sha": self.head_sha,
            "base_sha": self.base_sha,
            "current_main_sha": self.current_main_sha,
            "declared_base_sha": self.declared_base_sha,
            "declared_head_sha": self.declared_head_sha,
            "declared_main_sha": self.declared_main_sha,
            "stale_base": self.stale_base,
            "stale_declared_base": self.stale_declared_base,
            "stale_declared_head": self.stale_declared_head,
            "stale_declared_main": self.stale_declared_main,
            "stale_evidence": self.stale_evidence,
            "review_identity": list(self.review_identity),
            "evidence_gaps": list(self.evidence_gaps),
            "is_valid": self.is_valid,
        }


@dataclass(frozen=True)
class ReadinessClassification:
    """Immutable advisory projection of existing reviewer classifier semantics."""

    identity: RevisionIdentity
    disposition: Disposition
    findings: tuple[str, ...] = ()
    reasons: tuple[str, ...] = ()
    risk: str = "MED"
    overlaps: Mapping[int, tuple[str, ...]] = field(default_factory=lambda: MappingProxyType({}))
    evidence_completeness: EvidenceCompleteness = EvidenceCompleteness.COMPLETE
    evidence_gaps: tuple[str, ...] = ()
    claim_ceiling: str = CLAIM_CEILING

    def __post_init__(self) -> None:
        if isinstance(self.overlaps, MappingProxyType):
            frozen = MappingProxyType({k: tuple(v) for k, v in self.overlaps.items()})
        elif isinstance(self.overlaps, Mapping):
            frozen = MappingProxyType({k: tuple(v) for k, v in self.overlaps.items()})
        else:
            frozen = MappingProxyType({})
        object.__setattr__(self, "overlaps", frozen)
        if not isinstance(self.findings, tuple):
            object.__setattr__(self, "findings", tuple(self.findings))
        if not isinstance(self.reasons, tuple):
            object.__setattr__(self, "reasons", tuple(self.reasons))
        if not isinstance(self.evidence_gaps, tuple):
            object.__setattr__(self, "evidence_gaps", tuple(self.evidence_gaps))

    @property
    def is_review_ready(self) -> bool:
        return (
            self.identity.is_valid
            and self.disposition == Disposition.REVIEW_READY
            and self.evidence_completeness != EvidenceCompleteness.INCOMPLETE
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "identity": self.identity.to_dict(),
            "repository": self.identity.repository,
            "pr_number": self.identity.pr_number,
            "disposition": (
                self.disposition.value
                if hasattr(self.disposition, "value")
                else str(self.disposition)
            ),
            "findings": list(self.findings),
            "reasons": list(self.reasons),
            "risk": self.risk,
            "overlaps": {k: list(v) for k, v in sorted(self.overlaps.items())},
            "is_review_ready": self.is_review_ready,
            "evidence_completeness": self.evidence_completeness.value,
            "evidence_gaps": list(self.evidence_gaps),
            "claim_ceiling": self.claim_ceiling,
        }


@dataclass(frozen=True)
class CrossPROverlapResult:
    """Deterministic immutable projection of cross-PR overlap semantics."""

    classifications: tuple[ReadinessClassification, ...]
    overlap_pairs: tuple[tuple[int, int, tuple[str, ...]], ...] = ()
    claim_ceiling: str = CLAIM_CEILING

    def __post_init__(self) -> None:
        if not isinstance(self.classifications, tuple):
            object.__setattr__(self, "classifications", tuple(self.classifications))
        if not isinstance(self.overlap_pairs, tuple):
            object.__setattr__(self, "overlap_pairs", tuple(self.overlap_pairs))

    def to_dict(self) -> dict[str, Any]:
        return {
            "classifications": [c.to_dict() for c in self.classifications],
            "overlap_pairs": [
                {"pr_a": a, "pr_b": b, "shared_paths": list(paths)}
                for a, b, paths in self.overlap_pairs
            ],
            "claim_ceiling": self.claim_ceiling,
        }


@dataclass(frozen=True)
class NormalizedCheckEvidence:
    """Deterministic generic check observation evidence record."""

    name: str
    status: str
    expected_failure: bool = False
    is_unexpected: bool = False
    check_run_id: int | None = None
    run_id: int | None = None
    external_id: str | None = None
    details_url: str | None = None
    html_url: str | None = None
    node_id: str | None = None
    workflow_name: str | None = None
    head_sha: str | None = None
    check_suite_id: int | None = None
    started_at: str | None = None
    completed_at: str | None = None
    artifact_identity: str | None = None
    annotation_count: int | None = None
    app_slug: str | None = None
    job_identity: str | None = None
    log_sha256: str | None = None
    log_truncated: bool | None = None
    artifact_sha256: str | None = None
    artifact_truncated: bool | None = None
    run_attempt: int | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "name": self.name,
            "status": self.status,
            "expected_failure": self.expected_failure,
            "is_unexpected": self.is_unexpected,
        }
        for attr in (
            "check_run_id",
            "run_id",
            "external_id",
            "details_url",
            "html_url",
            "node_id",
            "workflow_name",
            "head_sha",
            "check_suite_id",
            "started_at",
            "completed_at",
            "artifact_identity",
            "annotation_count",
            "app_slug",
            "job_identity",
            "log_sha256",
            "log_truncated",
            "artifact_sha256",
            "artifact_truncated",
            "run_attempt",
        ):
            val = getattr(self, attr)
            if val is not None:
                d[attr] = val
        return d


@dataclass(frozen=True)
class CIFailureFingerprint:
    """Hash-bound generic repository-intelligence CI failure evidence."""

    identity: RevisionIdentity
    fingerprint: str
    has_unexpected_failures: bool
    unexpected_failures: tuple[NormalizedCheckEvidence, ...]
    expected_failures: tuple[NormalizedCheckEvidence, ...]
    total_checks_count: int
    unexpected_count: int
    expected_count: int
    terminal_failure_count: int
    evidence_gaps: tuple[str, ...]
    is_complete: bool
    evidence_completeness: EvidenceCompleteness
    content_sha256: str
    expected_check_run_id: int | None = None
    expected_run_id: int | None = None
    expected_job_identity: str | None = None
    expected_artifact_identity: str | None = None
    schema: str = "reviewer.ci_failure_evidence.v1"
    claim_ceiling: str = CI_EVIDENCE_CLAIM_CEILING

    def __post_init__(self) -> None:
        if not isinstance(self.unexpected_failures, tuple):
            object.__setattr__(self, "unexpected_failures", tuple(self.unexpected_failures))
        if not isinstance(self.expected_failures, tuple):
            object.__setattr__(self, "expected_failures", tuple(self.expected_failures))
        if not isinstance(self.evidence_gaps, tuple):
            object.__setattr__(self, "evidence_gaps", tuple(self.evidence_gaps))

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "identity": self.identity.to_dict(),
            "fingerprint": self.fingerprint,
            "has_unexpected_failures": self.has_unexpected_failures,
            "unexpected_failures": [c.to_dict() for c in self.unexpected_failures],
            "expected_failures": [c.to_dict() for c in self.expected_failures],
            "total_checks_count": self.total_checks_count,
            "unexpected_count": self.unexpected_count,
            "expected_count": self.expected_count,
            "terminal_failure_count": self.terminal_failure_count,
            "expected_check_run_id": self.expected_check_run_id,
            "expected_run_id": self.expected_run_id,
            "expected_job_identity": self.expected_job_identity,
            "expected_artifact_identity": self.expected_artifact_identity,
            "evidence_gaps": list(self.evidence_gaps),
            "is_complete": self.is_complete,
            "evidence_completeness": self.evidence_completeness.value,
            "claim_ceiling": self.claim_ceiling,
            "content_sha256": self.content_sha256,
        }


@dataclass(frozen=True)
class ChangeImpactReportV1:
    """Hash-bound language-neutral downstream change-impact evidence."""

    identity: RevisionIdentity
    covered_files: tuple[str, ...]
    changed_files: tuple[str, ...]
    dependency_edges: tuple[tuple[str, str], ...] = ()
    observed_symbols: Mapping[str, tuple[str, ...]] = field(
        default_factory=lambda: MappingProxyType({})
    )
    direct_impacted_files: tuple[str, ...] = ()
    transitive_impacted_files: tuple[str, ...] = ()
    all_impacted_files: tuple[str, ...] = ()
    graph_complete: bool = False
    graph_errors: tuple[str, ...] = ()
    edge_count: int = 0
    graph_sha256: str = ""
    evidence_gaps: tuple[str, ...] = ()
    evidence_completeness: EvidenceCompleteness = EvidenceCompleteness.INCOMPLETE
    is_complete: bool = False
    content_sha256: str = ""
    schema: str = "reviewer.change_impact.v1"
    claim_ceiling: str = CLAIM_CEILING

    def __post_init__(self) -> None:
        object.__setattr__(self, "covered_files", tuple(self.covered_files))
        object.__setattr__(self, "changed_files", tuple(self.changed_files))
        object.__setattr__(self, "dependency_edges", tuple(tuple(edge) for edge in self.dependency_edges))
        if isinstance(self.observed_symbols, Mapping):
            frozen = MappingProxyType({
                str(path): tuple(symbols)
                for path, symbols in self.observed_symbols.items()
            })
        else:
            frozen = MappingProxyType({})
        object.__setattr__(self, "observed_symbols", frozen)
        object.__setattr__(self, "direct_impacted_files", tuple(self.direct_impacted_files))
        object.__setattr__(self, "transitive_impacted_files", tuple(self.transitive_impacted_files))
        object.__setattr__(self, "all_impacted_files", tuple(self.all_impacted_files))
        object.__setattr__(self, "graph_errors", tuple(self.graph_errors))
        object.__setattr__(self, "evidence_gaps", tuple(self.evidence_gaps))

    @property
    def direct_impacted_count(self) -> int:
        return len(self.direct_impacted_files)

    @property
    def transitive_impacted_count(self) -> int:
        return len(self.transitive_impacted_files)

    @property
    def total_impacted_count(self) -> int:
        return len(self.all_impacted_files)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "identity": self.identity.to_dict(),
            "covered_files": list(self.covered_files),
            "changed_files": list(self.changed_files),
            "dependency_edges": [
                {"consumer": consumer, "dependency": dependency}
                for consumer, dependency in self.dependency_edges
            ],
            "observed_symbols": {
                path: list(symbols)
                for path, symbols in sorted(self.observed_symbols.items())
            },
            "direct_impacted_files": list(self.direct_impacted_files),
            "transitive_impacted_files": list(self.transitive_impacted_files),
            "all_impacted_files": list(self.all_impacted_files),
            "direct_impacted_count": self.direct_impacted_count,
            "transitive_impacted_count": self.transitive_impacted_count,
            "total_impacted_count": self.total_impacted_count,
            "graph_complete": self.graph_complete,
            "graph_errors": list(self.graph_errors),
            "edge_count": self.edge_count,
            "graph_sha256": self.graph_sha256,
            "evidence_gaps": list(self.evidence_gaps),
            "evidence_completeness": self.evidence_completeness.value,
            "is_complete": self.is_complete,
            "claim_ceiling": self.claim_ceiling,
            "content_sha256": self.content_sha256,
        }


class CIFailureTriageStatus(str, Enum):
    NO_TERMINAL_FAILURE = "NO_TERMINAL_FAILURE"
    EXPECTED_FAILURE_ONLY = "EXPECTED_FAILURE_ONLY"
    UNEXPECTED_FAILURE_OBSERVED = "UNEXPECTED_FAILURE_OBSERVED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


@dataclass(frozen=True)
class CIFailureIntelligenceReportV1:
    """Deterministic CI-failure triage bounded to evidence, never root cause."""

    identity: RevisionIdentity
    failure_evidence: CIFailureFingerprint
    status: CIFailureTriageStatus
    diagnosis_eligible: bool
    reason_codes: tuple[str, ...] = ()
    failed_check_names: tuple[str, ...] = ()
    evidence_gaps: tuple[str, ...] = ()
    evidence_completeness: EvidenceCompleteness = EvidenceCompleteness.INCOMPLETE
    content_sha256: str = ""
    schema: str = "reviewer.ci_failure_intelligence.v1"
    claim_ceiling: str = CI_EVIDENCE_CLAIM_CEILING

    def __post_init__(self) -> None:
        object.__setattr__(self, "reason_codes", tuple(self.reason_codes))
        object.__setattr__(self, "failed_check_names", tuple(self.failed_check_names))
        object.__setattr__(self, "evidence_gaps", tuple(self.evidence_gaps))

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "identity": self.identity.to_dict(),
            "failure_evidence": self.failure_evidence.to_dict(),
            "status": self.status.value,
            "diagnosis_eligible": self.diagnosis_eligible,
            "reason_codes": list(self.reason_codes),
            "failed_check_names": list(self.failed_check_names),
            "evidence_gaps": list(self.evidence_gaps),
            "evidence_completeness": self.evidence_completeness.value,
            "claim_ceiling": self.claim_ceiling,
            "content_sha256": self.content_sha256,
        }


class ExternalIntelligenceDecision(str, Enum):
    READY = "READY"
    NO_ACTION = "NO_ACTION"
    BLOCKED = "BLOCKED"


@dataclass(frozen=True)
class ExternalIntelligenceAutomationEnvelopeV1:
    """Pure automation plan. It grants no dispatch, write, or merge authority."""

    identity: RevisionIdentity
    decision: ExternalIntelligenceDecision
    action_kind: str
    idempotency_key: str
    evidence_refs: tuple[str, ...] = ()
    reason_codes: tuple[str, ...] = ()
    evidence_gaps: tuple[str, ...] = ()
    content_sha256: str = ""
    schema: str = "reviewer.external_intelligence_automation.v1"
    claim_ceiling: str = "AUTOMATION_ADVISORY_ONLY"

    def __post_init__(self) -> None:
        object.__setattr__(self, "evidence_refs", tuple(self.evidence_refs))
        object.__setattr__(self, "reason_codes", tuple(self.reason_codes))
        object.__setattr__(self, "evidence_gaps", tuple(self.evidence_gaps))

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "identity": self.identity.to_dict(),
            "decision": self.decision.value,
            "action_kind": self.action_kind,
            "idempotency_key": self.idempotency_key,
            "evidence_refs": list(self.evidence_refs),
            "reason_codes": list(self.reason_codes),
            "evidence_gaps": list(self.evidence_gaps),
            "claim_ceiling": self.claim_ceiling,
            "content_sha256": self.content_sha256,
        }


@dataclass(frozen=True)
class RepositoryIntelligenceReportV1:
    """Canonical hash-bound V1 repository intelligence report."""

    repository: str
    current_main_sha: str
    observed_at: str
    items: tuple[ReadinessClassification, ...]
    evidence_completeness: EvidenceCompleteness
    evidence_gaps: tuple[str, ...]
    content_sha256: str
    schema: str = "reviewer.repository_intelligence.v1"
    claim_ceiling: str = CLAIM_CEILING

    def __post_init__(self) -> None:
        if not isinstance(self.items, tuple):
            object.__setattr__(self, "items", tuple(self.items))
        if not isinstance(self.evidence_gaps, tuple):
            object.__setattr__(self, "evidence_gaps", tuple(self.evidence_gaps))

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "repository": self.repository,
            "current_main_sha": self.current_main_sha,
            "observed_at": self.observed_at,
            "items": [item.to_dict() for item in self.items],
            "evidence_completeness": self.evidence_completeness.value,
            "evidence_gaps": list(self.evidence_gaps),
            "claim_ceiling": self.claim_ceiling,
            "content_sha256": self.content_sha256,
        }
