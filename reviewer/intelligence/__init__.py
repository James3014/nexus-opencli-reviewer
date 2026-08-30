"""Repository Intelligence Core V1.

Pure, deterministic, transport-neutral advisory intelligence facade.
"""
from __future__ import annotations

from .models import Disposition

from .contracts import (
    CLAIM_CEILING,
    CI_EVIDENCE_CLAIM_CEILING,
    TERMINAL_FAILURE_STATUSES,
    CIFailureFingerprint,
    CIFailureIntelligenceReportV1,
    CIFailureTriageStatus,
    ChangeImpactReportV1,
    ExternalIntelligenceAutomationEnvelopeV1,
    ExternalIntelligenceDecision,
    CrossPROverlapResult,
    EvidenceCompleteness,
    NormalizedCheckEvidence,
    ReadinessClassification,
    RepositoryIntelligencePolicyV1,
    RepositoryIntelligenceReportV1,
    RevisionIdentity,
)
from .impact import analyze_change_impact, verify_change_impact_report
from .cfi import analyze_ci_failure_intelligence, verify_ci_failure_intelligence_report
from .eia import plan_external_intelligence_automation, verify_external_intelligence_automation_envelope
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
    "CIFailureTriageStatus",
    "CIFailureIntelligenceReportV1",
    "ChangeImpactReportV1",
    "ExternalIntelligenceDecision",
    "ExternalIntelligenceAutomationEnvelopeV1",
    "RepositoryIntelligenceReportV1",
    "revision_identity",
    "classify_readiness",
    "analyze_cross_pr_overlap",
    "fingerprint_ci_failures",
    "verify_ci_failure_evidence",
    "analyze_change_impact",
    "verify_change_impact_report",
    "analyze_ci_failure_intelligence",
    "verify_ci_failure_intelligence_report",
    "plan_external_intelligence_automation",
    "verify_external_intelligence_automation_envelope",
    "build_repository_intelligence_report",
    "verify_repository_intelligence_report",
]
