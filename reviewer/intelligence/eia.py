"""Repository Intelligence V1.1 External Intelligence Automation envelope.

The envelope is a deterministic advisory gate for unattended/cloud consumers.
It never dispatches workers, writes GitHub, comments, approves, merges, or grants
repository authority.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from typing import Any, Mapping

from .cfi import analyze_ci_failure_intelligence, verify_ci_failure_intelligence_report
from .contracts import (
    CIFailureTriageStatus,
    ExternalIntelligenceAutomationEnvelopeV1,
    ExternalIntelligenceDecision,
)

AUTOMATION_CLAIM_CEILING = "AUTOMATION_ADVISORY_ONLY"


def _content_hash(payload: Mapping[str, Any]) -> str:
    unsigned = dict(payload)
    unsigned.pop("content_sha256", None)
    canonical = json.dumps(unsigned, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _idempotency_key(identity: tuple[str, int, str, str, str], action_kind: str, evidence_ref: str) -> str:
    payload = {
        "review_identity": list(identity),
        "action_kind": action_kind,
        "evidence_ref": evidence_ref,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def plan_external_intelligence_automation(data: Mapping[str, Any]) -> ExternalIntelligenceAutomationEnvelopeV1:
    """Plan a bounded unattended action from exact CI evidence.

    Accepted input:
      - {"snapshot": <normalized PR snapshot>}; or
      - {"cfi_report": <verified reviewer.ci_failure_intelligence.v1 payload>}

    READY only means a downstream consumer may *consider* a CI failure diagnosis
    action using the exact evidence reference. It grants no execution authority.
    """
    if not isinstance(data, Mapping):
        raise TypeError("external automation input must be a mapping")

    supplied_report = data.get("cfi_report")
    if supplied_report is not None:
        if not isinstance(supplied_report, Mapping) or not verify_ci_failure_intelligence_report(supplied_report):
            raise ValueError("cfi_report is invalid or tampered")
        report = supplied_report
    else:
        snapshot = data.get("snapshot")
        if not isinstance(snapshot, Mapping):
            raise ValueError("snapshot or verified cfi_report is required")
        report = analyze_ci_failure_intelligence(snapshot).to_dict()

    identity_payload = report["identity"]
    identity = (
        str(identity_payload["repository"]),
        int(identity_payload["pr_number"]),
        str(identity_payload["head_sha"]),
        str(identity_payload["base_sha"]),
        str(identity_payload["current_main_sha"]),
    )
    evidence_ref = str(report["content_sha256"])
    status = str(report["status"])

    identity_stale = bool(identity_payload.get("stale_base")) or bool(identity_payload.get("stale_evidence"))
    if identity_stale:
        decision = ExternalIntelligenceDecision.BLOCKED
        action_kind = "NONE"
        reasons = ("IDENTITY_STALE_FOR_AUTOMATION",)
        raw_gaps = report.get("evidence_gaps", [])
        gaps = tuple(dict.fromkeys([*(str(gap) for gap in raw_gaps if isinstance(gap, str)), "identity_stale_for_automation"]))
    elif status == CIFailureTriageStatus.UNEXPECTED_FAILURE_OBSERVED.value and report.get("diagnosis_eligible") is True:
        decision = ExternalIntelligenceDecision.READY
        action_kind = "CI_FAILURE_DIAGNOSIS"
        reasons = ("UNEXPECTED_FAILURE_WITH_COMPLETE_EVIDENCE",)
        gaps = ()
    elif status in {
        CIFailureTriageStatus.NO_TERMINAL_FAILURE.value,
        CIFailureTriageStatus.EXPECTED_FAILURE_ONLY.value,
    }:
        decision = ExternalIntelligenceDecision.NO_ACTION
        action_kind = "NONE"
        reasons = (status,)
        gaps = ()
    else:
        decision = ExternalIntelligenceDecision.BLOCKED
        action_kind = "NONE"
        reasons = ("EVIDENCE_INSUFFICIENT_FOR_AUTOMATION",)
        raw_gaps = report.get("evidence_gaps", [])
        gaps = tuple(str(gap) for gap in raw_gaps if isinstance(gap, str))

    key = _idempotency_key(identity, action_kind, evidence_ref)
    from .contracts import RevisionIdentity
    ident = RevisionIdentity(
        repository=identity[0],
        pr_number=identity[1],
        head_sha=identity[2],
        base_sha=identity[3],
        current_main_sha=identity[4],
        declared_base_sha=identity_payload.get("declared_base_sha"),
        declared_head_sha=identity_payload.get("declared_head_sha"),
        declared_main_sha=identity_payload.get("declared_main_sha"),
        stale_base=bool(identity_payload.get("stale_base")),
        stale_declared_base=bool(identity_payload.get("stale_declared_base")),
        stale_declared_head=bool(identity_payload.get("stale_declared_head")),
        stale_declared_main=bool(identity_payload.get("stale_declared_main")),
        stale_evidence=bool(identity_payload.get("stale_evidence")),
        evidence_gaps=tuple(identity_payload.get("evidence_gaps", ())),
        is_valid=bool(identity_payload.get("is_valid")),
    )
    envelope = ExternalIntelligenceAutomationEnvelopeV1(
        identity=ident,
        decision=decision,
        action_kind=action_kind,
        idempotency_key=key,
        evidence_refs=(evidence_ref,),
        reason_codes=reasons,
        evidence_gaps=gaps,
        content_sha256="",
        claim_ceiling=AUTOMATION_CLAIM_CEILING,
    )
    return replace(envelope, content_sha256=_content_hash(envelope.to_dict()))


def verify_external_intelligence_automation_envelope(payload: Mapping[str, Any]) -> bool:
    if not isinstance(payload, Mapping):
        return False
    if payload.get("schema") != "reviewer.external_intelligence_automation.v1":
        return False
    if payload.get("claim_ceiling") != AUTOMATION_CLAIM_CEILING:
        return False
    supplied = payload.get("content_sha256")
    if not isinstance(supplied, str) or len(supplied) != 64 or supplied != _content_hash(payload):
        return False
    identity = payload.get("identity")
    if not isinstance(identity, Mapping) or identity.get("is_valid") is not True:
        return False
    decision = payload.get("decision")
    if decision not in {item.value for item in ExternalIntelligenceDecision}:
        return False
    action_kind = payload.get("action_kind")
    refs = payload.get("evidence_refs")
    if not isinstance(action_kind, str) or not isinstance(refs, list) or len(refs) != 1:
        return False
    if not isinstance(refs[0], str) or len(refs[0]) != 64:
        return False
    review_identity = identity.get("review_identity")
    if not isinstance(review_identity, list) or len(review_identity) != 5:
        return False
    expected_key = _idempotency_key(
        (str(review_identity[0]), int(review_identity[1]), str(review_identity[2]), str(review_identity[3]), str(review_identity[4])),
        action_kind,
        refs[0],
    )
    if payload.get("idempotency_key") != expected_key:
        return False
    if decision == ExternalIntelligenceDecision.READY.value:
        if action_kind != "CI_FAILURE_DIAGNOSIS":
            return False
        if identity.get("stale_base") is True or identity.get("stale_evidence") is True:
            return False
    if decision != ExternalIntelligenceDecision.READY.value and action_kind != "NONE":
        return False
    return True
