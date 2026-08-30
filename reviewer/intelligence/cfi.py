"""Repository Intelligence V1.1 CI Failure Intelligence.

This layer classifies exact, hash-bound CI failure evidence. It does not infer
root cause, regression attribution, repair correctness, merge readiness, or
production safety.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from typing import Any, Mapping

from .contracts import (
    CI_EVIDENCE_CLAIM_CEILING,
    CIFailureIntelligenceReportV1,
    CIFailureTriageStatus,
    EvidenceCompleteness,
)
from .core import fingerprint_ci_failures, verify_ci_failure_evidence


def _content_hash(payload: Mapping[str, Any]) -> str:
    unsigned = dict(payload)
    unsigned.pop("content_sha256", None)
    canonical = json.dumps(unsigned, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def analyze_ci_failure_intelligence(snapshot: Mapping[str, Any] | Any) -> CIFailureIntelligenceReportV1:
    """Produce deterministic CI-failure triage from normalized snapshot evidence."""
    evidence = fingerprint_ci_failures(snapshot)
    gaps = tuple(dict.fromkeys(evidence.evidence_gaps))

    if not evidence.is_complete:
        status = CIFailureTriageStatus.INSUFFICIENT_EVIDENCE
        eligible = False
        reasons = ("CI_EVIDENCE_INCOMPLETE",)
    elif evidence.unexpected_count > 0:
        status = CIFailureTriageStatus.UNEXPECTED_FAILURE_OBSERVED
        eligible = True
        reasons = ("UNEXPECTED_TERMINAL_FAILURE",)
    elif evidence.expected_count > 0:
        status = CIFailureTriageStatus.EXPECTED_FAILURE_ONLY
        eligible = False
        reasons = ("EXPECTED_FAILURE_ONLY",)
    else:
        status = CIFailureTriageStatus.NO_TERMINAL_FAILURE
        eligible = False
        reasons = ("NO_TERMINAL_FAILURE",)

    failed_names = tuple(sorted({
        check.name for check in (*evidence.unexpected_failures, *evidence.expected_failures)
    }))
    report = CIFailureIntelligenceReportV1(
        identity=evidence.identity,
        failure_evidence=evidence,
        status=status,
        diagnosis_eligible=eligible,
        reason_codes=reasons,
        failed_check_names=failed_names,
        evidence_gaps=gaps,
        evidence_completeness=evidence.evidence_completeness,
        content_sha256="",
        claim_ceiling=CI_EVIDENCE_CLAIM_CEILING,
    )
    return replace(report, content_sha256=_content_hash(report.to_dict()))


def verify_ci_failure_intelligence_report(payload: Mapping[str, Any]) -> bool:
    if not isinstance(payload, Mapping):
        return False
    if payload.get("schema") != "reviewer.ci_failure_intelligence.v1":
        return False
    if payload.get("claim_ceiling") != CI_EVIDENCE_CLAIM_CEILING:
        return False
    supplied = payload.get("content_sha256")
    if not isinstance(supplied, str) or len(supplied) != 64 or supplied != _content_hash(payload):
        return False

    evidence = payload.get("failure_evidence")
    identity = payload.get("identity")
    if not isinstance(evidence, Mapping) or not isinstance(identity, Mapping):
        return False
    if not verify_ci_failure_evidence(evidence):
        return False
    if evidence.get("identity") != identity:
        return False

    status = payload.get("status")
    if status not in {item.value for item in CIFailureTriageStatus}:
        return False
    completeness = payload.get("evidence_completeness")
    if completeness not in {item.value for item in EvidenceCompleteness}:
        return False
    if completeness != evidence.get("evidence_completeness"):
        return False

    expected_eligible = (
        status == CIFailureTriageStatus.UNEXPECTED_FAILURE_OBSERVED.value
        and evidence.get("is_complete") is True
        and int(evidence.get("unexpected_count", 0)) > 0
    )
    if payload.get("diagnosis_eligible") is not expected_eligible:
        return False

    if status == CIFailureTriageStatus.INSUFFICIENT_EVIDENCE.value:
        if evidence.get("is_complete") is True:
            return False
    elif status == CIFailureTriageStatus.UNEXPECTED_FAILURE_OBSERVED.value:
        if int(evidence.get("unexpected_count", 0)) <= 0:
            return False
    elif status == CIFailureTriageStatus.EXPECTED_FAILURE_ONLY.value:
        if int(evidence.get("unexpected_count", 0)) != 0 or int(evidence.get("expected_count", 0)) <= 0:
            return False
    elif status == CIFailureTriageStatus.NO_TERMINAL_FAILURE.value:
        if int(evidence.get("terminal_failure_count", 0)) != 0:
            return False

    names = payload.get("failed_check_names")
    if not isinstance(names, list) or names != sorted(set(names)):
        return False
    evidence_names = sorted({
        str(check.get("name"))
        for group in (evidence.get("unexpected_failures", []), evidence.get("expected_failures", []))
        if isinstance(group, list)
        for check in group
        if isinstance(check, Mapping) and isinstance(check.get("name"), str)
    })
    if names != evidence_names:
        return False
    return True
