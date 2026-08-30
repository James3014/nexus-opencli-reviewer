"""Repository Intelligence Core V1.

Pure, deterministic, transport-neutral advisory intelligence facade.
"""
from __future__ import annotations

from reviewer.models import Disposition

from .contracts import (
    CLAIM_CEILING,
    CI_EVIDENCE_CLAIM_CEILING,
    TERMINAL_FAILURE_STATUSES,
    CIFailureFingerprint,
    ChangeImpactReportV1,
    CrossPROverlapResult,
    EvidenceCompleteness,
    NormalizedCheckEvidence,
    ReadinessClassification,
    RepositoryIntelligencePolicyV1,
    RepositoryIntelligenceReportV1,
    RevisionIdentity,
)
from .impact import analyze_change_impact, verify_change_impact_report
from .core import (
    analyze_cross_pr_overlap,
    build_repository_intelligence_report,
    classify_readiness,
    fingerprint_ci_failures,
    revision_identity,
    verify_ci_failure_evidence,
    verify_repository_intelligence_report,
)

__all__ = [
    "CLAIM_CEILING",
    "CI_EVIDENCE_CLAIM_CEILING",
    "TERMINAL_FAILURE_STATUSES",
    "Disposition",
    "EvidenceCompleteness",
    "RepositoryIntelligencePolicyV1",
    "RevisionIdentity",
    "ReadinessClassification",
    "CrossPROverlapResult",
    "NormalizedCheckEvidence",
    "CIFailureFingerprint",
    "ChangeImpactReportV1",
    "RepositoryIntelligenceReportV1",
    "revision_identity",
    "classify_readiness",
    "analyze_cross_pr_overlap",
    "fingerprint_ci_failures",
    "verify_ci_failure_evidence",
    "analyze_change_impact",
    "verify_change_impact_report",
    "build_repository_intelligence_report",
    "verify_repository_intelligence_report",
]
