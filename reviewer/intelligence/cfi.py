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
    TERMINAL_FAILURE_STATUSES,
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


def _expected_reason_codes(status: CIFailureTriageStatus) -> tuple[str, ...]:
    return {
        CIFailureTriageStatus.INSUFFICIENT_EVIDENCE: ("CI_EVIDENCE_INCOMPLETE",),
        CIFailureTriageStatus.UNEXPECTED_FAILURE_OBSERVED: ("UNEXPECTED_TERMINAL_FAILURE",),
        CIFailureTriageStatus.EXPECTED_FAILURE_ONLY: ("EXPECTED_FAILURE_ONLY",),
        CIFailureTriageStatus.NO_TERMINAL_FAILURE: ("NO_TERMINAL_FAILURE",),
    }[status]


def analyze_ci_failure_intelligence(snapshot: Mapping[str, Any] | Any) -> CIFailureIntelligenceReportV1:
    """Produce deterministic CI-failure triage from normalized snapshot evidence."""
    evidence = fingerprint_ci_failures(snapshot)
    gaps = tuple(dict.fromkeys(evidence.evidence_gaps))

    if not evidence.is_complete:
        status = CIFailureTriageStatus.INSUFFICIENT_EVIDENCE
        eligible = False
    elif evidence.unexpected_count > 0:
        status = CIFailureTriageStatus.UNEXPECTED_FAILURE_OBSERVED
        eligible = True
    elif evidence.expected_count > 0:
        status = CIFailureTriageStatus.EXPECTED_FAILURE_ONLY
        eligible = False
    else:
        status = CIFailureTriageStatus.NO_TERMINAL_FAILURE
        eligible = False

    failed_names = tuple(sorted({
        check.name for check in (*evidence.unexpected_failures, *evidence.expected_failures)
    }))
    report = CIFailureIntelligenceReportV1(
        identity=evidence.identity,
        failure_evidence=evidence,
        status=status,
        diagnosis_eligible=eligible,
        reason_codes=_expected_reason_codes(status),
        failed_check_names=failed_names,
        evidence_gaps=gaps,
        evidence_completeness=evidence.evidence_completeness,
        content_sha256="",
        claim_ceiling=CI_EVIDENCE_CLAIM_CEILING,
    )
    return replace(report, content_sha256=_content_hash(report.to_dict()))


def verify_ci_failure_intelligence_report(payload: Mapping[str, Any]) -> bool:
    """Verify hash binding and all derivable CFI semantics.

    The verifier intentionally rejects a payload that is merely re-hashed after
    changing status, eligibility, reasons, evidence gaps, or failed-check names.
    """
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

    unexpected = evidence.get("unexpected_failures")
    expected = evidence.get("expected_failures")
    if not isinstance(unexpected, list) or not isinstance(expected, list):
        return False
    if evidence.get("unexpected_count") != len(unexpected):
        return False
    if evidence.get("expected_count") != len(expected):
        return False
    if evidence.get("terminal_failure_count") != len(unexpected) + len(expected):
        return False
    if evidence.get("has_unexpected_failures") is not bool(unexpected):
        return False
    for group, should_be_unexpected in ((unexpected, True), (expected, False)):
        for check in group:
            if not isinstance(check, Mapping):
                return False
            status_value = check.get("status")
            if not isinstance(status_value, str) or status_value.lower() not in TERMINAL_FAILURE_STATUSES:
                return False
            if check.get("is_unexpected") is not should_be_unexpected:
                return False

    fingerprint_payload = {
        "review_identity": identity.get("review_identity"),
        "unexpected_failures": unexpected,
        "expected_failures": expected,
        "expected_check_run_id": evidence.get("expected_check_run_id"),
        "expected_run_id": evidence.get("expected_run_id"),
        "expected_job_identity": evidence.get("expected_job_identity"),
        "expected_artifact_identity": evidence.get("expected_artifact_identity"),
        "total_checks_count": evidence.get("total_checks_count"),
        "unexpected_count": len(unexpected),
        "expected_count": len(expected),
    }
    expected_fingerprint = hashlib.sha256(
        json.dumps(fingerprint_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    if evidence.get("fingerprint") != expected_fingerprint:
        return False

    status_raw = payload.get("status")
    try:
        status = CIFailureTriageStatus(status_raw)
    except (TypeError, ValueError):
        return False

    completeness = payload.get("evidence_completeness")
    if completeness not in {item.value for item in EvidenceCompleteness}:
        return False
    if completeness != evidence.get("evidence_completeness"):
        return False

    unexpected_count = int(evidence.get("unexpected_count", 0))
    expected_count = int(evidence.get("expected_count", 0))
    terminal_count = int(evidence.get("terminal_failure_count", 0))
    evidence_complete = evidence.get("is_complete") is True

    if not evidence_complete:
        expected_status = CIFailureTriageStatus.INSUFFICIENT_EVIDENCE
    elif unexpected_count > 0:
        expected_status = CIFailureTriageStatus.UNEXPECTED_FAILURE_OBSERVED
    elif expected_count > 0:
        expected_status = CIFailureTriageStatus.EXPECTED_FAILURE_ONLY
    else:
        expected_status = CIFailureTriageStatus.NO_TERMINAL_FAILURE
    if status is not expected_status:
        return False

    expected_eligible = (
        status is CIFailureTriageStatus.UNEXPECTED_FAILURE_OBSERVED
        and evidence_complete
        and unexpected_count > 0
    )
    if payload.get("diagnosis_eligible") is not expected_eligible:
        return False

    if status is CIFailureTriageStatus.EXPECTED_FAILURE_ONLY:
        if unexpected_count != 0 or expected_count <= 0:
            return False
    elif status is CIFailureTriageStatus.NO_TERMINAL_FAILURE:
        if terminal_count != 0:
            return False

    reasons = payload.get("reason_codes")
    if reasons != list(_expected_reason_codes(status)):
        return False

    gaps = payload.get("evidence_gaps")
    expected_gaps = list(dict.fromkeys(
        str(gap) for gap in evidence.get("evidence_gaps", []) if isinstance(gap, str)
    ))
    if gaps != expected_gaps:
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
